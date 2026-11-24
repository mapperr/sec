use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use crate::platform;

pub const CONFIG: usize = 1024 * 1024;
pub const SECRET: usize = 16 * CONFIG;
pub const CIPHER: usize = 24 * CONFIG;

pub fn var(name: &str) -> Option<OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

pub fn on(name: &str) -> bool {
    env::var(name).as_deref() == Ok("1")
}

pub fn home() -> Result<PathBuf> {
    var(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("home directory is unavailable"))
}

pub fn base(unix: &str, fallback: &str, windows: &str) -> Result<PathBuf> {
    if cfg!(windows) {
        return Ok(PathBuf::from(
            var(windows).ok_or_else(|| anyhow!("{windows} is unset"))?,
        ));
    }
    if let Some(path) = var(unix) {
        return Ok(PathBuf::from(path));
    }
    Ok(home()?.join(fallback))
}

pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let path = std::path::absolute(path)?;
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            _ => result.push(part.as_os_str()),
        }
    }
    Ok(result)
}

pub fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("path is not valid UTF-8"))
}

pub fn managed(value: &str) -> Result<&str> {
    for part in value.split('/') {
        ensure!(
            !matches!(part, "" | "." | "..") && !part.eq_ignore_ascii_case(".git")
                && !part.contains(['\\', ':']) && !part.chars().any(|c| c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
            "invalid managed path {value:?}",
        );
        if cfg!(windows) {
            let reserved = part
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            ensure!(
                !part.ends_with(['.', ' '])
                    && !part.contains(['<', '>', '"', '|', '?', '*'])
                    && !matches!(
                        reserved.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    )
                    && !(reserved.len() == 4
                        && (reserved.starts_with("LPT") || reserved.starts_with("COM"))
                        && reserved.as_bytes()[3].is_ascii_digit()),
                "unsupported Windows path {value:?}",
            );
        }
    }
    Ok(value)
}

pub fn bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(maximum as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= maximum, "input exceeds the size limit");
    Ok(data)
}

pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    bounded(platform::open_read(path)?, maximum).with_context(|| format!("read {path:?}"))
}

pub fn optional(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>> {
    match platform::open_read(path) {
        Ok(file) => Ok(Some(bounded(file, maximum)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("open {path:?}")),
    }
}

pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    platform::atomic_replace(path, None, data)
}

pub fn utf8(data: &[u8]) -> Result<&str> {
    std::str::from_utf8(data).context("expected UTF-8 input")
}

pub fn sha(data: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub fn canonical(data: &impl Serialize) -> Result<Vec<u8>> {
    let json = serde_json::to_string(&serde_json::to_value(data)?)?;
    let mut ascii = String::with_capacity(json.len());
    use std::fmt::Write as _;
    for c in json.chars() {
        if c.is_ascii() && c != '\u{007f}' {
            ascii.push(c);
        } else {
            for part in c.encode_utf16(&mut [0; 2]) {
                write!(ascii, "\\u{part:04x}")?;
            }
        }
    }
    Ok(ascii.into_bytes())
}

fn record_path(kind: &str, key: &impl Serialize) -> Result<PathBuf> {
    let dir = if matches!(kind, "cipher" | "git-cipher" | "remote-head") {
        base("XDG_STATE_HOME", ".local/state", "LOCALAPPDATA")?.join("sec/attestations")
    } else if let Some(dir) = var("SEC_APPROVAL_DIR") {
        PathBuf::from(dir)
    } else {
        base("XDG_CONFIG_HOME", ".config", "APPDATA")?.join("sec/approvals")
    };
    Ok(dir.join(format!("{kind}-{}.json", sha(canonical(key)?))))
}

fn record_parent(path: &Path) -> &Path {
    path.parent()
        .expect("record path has its registry directory")
}

pub fn record<T: DeserializeOwned>(kind: &str, key: &impl Serialize) -> Result<Option<T>> {
    let path = record_path(kind, key)?;
    let _parent = match platform::private_dir(record_parent(&path)) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match platform::open_identity(&path) {
        Ok(file) => Ok(Some(serde_json::from_slice(&bounded(file, CONFIG)?)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn write_record(kind: &str, key: &impl Serialize, value: &impl Serialize) -> Result<()> {
    let path = record_path(kind, key)?;
    platform::create_dirs(record_parent(&path))?;
    let _parent = platform::private_dir(record_parent(&path))?;
    let previous = optional(&path, CONFIG)?;
    let mut bytes = canonical(value)?;
    bytes.push(b'\n');
    platform::atomic_replace(&path, previous.as_deref(), &bytes)
}

pub fn remove_record(kind: &str, key: &impl Serialize) -> Result<()> {
    let path = record_path(kind, key)?;
    let _parent = platform::private_dir(record_parent(&path))?;
    platform::remove_file(&path)?;
    Ok(())
}

pub fn terminal() -> Result<(BufReader<File>, File)> {
    let path = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    let output = if cfg!(windows) { "CONOUT$" } else { "/dev/tty" };
    let input = File::open(path).context("interactive confirmation requires a terminal")?;
    Ok((
        BufReader::new(input),
        OpenOptions::new().write(true).open(output)?,
    ))
}

pub fn confirm(title: &str, lines: impl IntoIterator<Item = String>) -> Result<()> {
    let (mut input, mut output) = terminal()?;
    writeln!(output, "{title}")?;
    for line in lines {
        writeln!(output, "  {line}")?;
    }
    write!(output, "Approve? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    ensure!(
        matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "approval declined"
    );
    Ok(())
}

pub fn workspace(configured: Option<OsString>) -> Result<tempfile::TempDir> {
    let dir = configured.map(PathBuf::from).unwrap_or_else(env::temp_dir);
    #[cfg(target_os = "macos")]
    let dir = if dir == Path::new("/tmp") || dir.starts_with("/var") {
        fs::canonicalize(dir)?
    } else {
        dir
    };
    let temp = tempfile::Builder::new().prefix("sec-").tempdir_in(dir)?;
    platform::private_dir(temp.path())?;
    Ok(temp)
}

pub fn edit(_path: &Path, input: &[u8], editor_setting: &str, secret: bool) -> Result<Vec<u8>> {
    let temp = workspace(var("XDG_RUNTIME_DIR"))?;
    let directory = std::path::absolute(temp.path())?;
    let file = directory.join("entry");
    write_new(&file, input)?;
    let preferred = var(editor_setting).or_else(|| {
        if secret {
            var("EDITOR")
        } else {
            var("VISUAL").or_else(|| var("EDITOR"))
        }
    });
    let mut command = if let Some(executable) = preferred {
        Command::new(executable)
    } else if secret {
        let mut vi = Command::new(which::which("vi").context("vi is unavailable. Set EDITOR")?);
        // Keep default vi configuration and recovery files inside the private workspace.
        let recovery_dir = path_string(&directory)?;
        ensure!(
            !recovery_dir
                .chars()
                .any(|ch| ch == '|' || (ch.is_control() && ch != '\t')),
            "this temporary directory path cannot be passed to vi. Set EDITOR"
        );
        let recovery_dir = recovery_dir
            .replace('\\', "\\\\")
            .replace(' ', "\\ ")
            .replace('\t', "\\\t");
        vi.current_dir(&directory)
            .envs(
                [
                    "HOME",
                    "TMPDIR",
                    "XDG_CONFIG_HOME",
                    "XDG_DATA_HOME",
                    "XDG_CACHE_HOME",
                    "XDG_STATE_HOME",
                ]
                .map(|name| (name, &directory)),
            )
            .env_remove("EXINIT")
            .env("NEXINIT", format!("set recdir={recovery_dir}"))
            .env("VIMINIT", "set noswapfile nobackup nowritebackup");
        vi
    } else if cfg!(windows) {
        Command::new("notepad.exe")
    } else {
        Command::new("vi")
    };
    let status = command
        .arg(&file)
        .status()
        .with_context(|| format!("start editor {:?}", command.get_program()))?;
    ensure!(
        status.success(),
        "editor {:?} exited with {status}",
        command.get_program()
    );
    bounded(
        platform::open_identity(&file)?,
        if secret { SECRET } else { CONFIG },
    )
}

pub struct Captured {
    pub status: ExitStatus,
    pub out: Vec<u8>,
}

pub fn capture(
    command: &mut Command,
    data: Option<Vec<u8>>,
    maximum: usize,
    timeout: u64,
) -> Result<Captured> {
    let description = format!("{:?}", command.get_program());
    let mut process = command
        .stdin(if data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {description}"))?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let stdout = process.stdout.take().unwrap();
    let (send_output, output) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = send_output.send(bounded(stdout, maximum));
    });
    let writer = data.map(|data| {
        let mut stdin = process.stdin.take().unwrap();
        let (send_input, input) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = send_input.send(stdin.write_all(&zeroize::Zeroizing::new(data)));
        });
        input
    });
    #[cfg(unix)]
    let group = {
        let pid = process.id() as i32;
        // Commands such as an isolated Git fetch can have their own process group.
        unsafe { libc::getpgid(pid) == pid }.then_some(pid)
    };
    let status = process.wait_timeout(deadline.saturating_duration_since(Instant::now()))?;
    if status.is_none() {
        #[cfg(unix)]
        if let Some(group) = group {
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
        let _ = process.kill();
        let _ = process.wait();
    }
    let Some(status) = status else {
        bail!("{description} timed out");
    };
    if let Some(writer) = writer {
        let written = writer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("helper input did not close")?;
        if status.success() {
            written?;
        }
    }
    let out = match output.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(data) => data?,
        Err(error) => {
            #[cfg(unix)]
            if let Some(group) = group {
                unsafe { libc::kill(-group, libc::SIGKILL) };
            }
            return Err(error).context("helper output did not close");
        }
    };
    Ok(Captured { status, out })
}

pub fn run(command: &mut Command, input: Option<Vec<u8>>, limit: usize) -> Result<Vec<u8>> {
    let result = capture(command, input, limit, 60)?;
    ensure!(
        result.status.success(),
        "{:?} exited with {}",
        command.get_program(),
        result.status
    );
    Ok(result.out)
}

pub fn lines(tree: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(base: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for item in fs::read_dir(dir)? {
            let item = item?;
            let path = item.path();
            let kind = item.file_type()?;
            let name = path
                .strip_prefix(base)?
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            managed(&name)?;
            ensure!(!kind.is_symlink(), "symlink in managed directory: {name:?}");
            if kind.is_dir() {
                walk(base, &path, files)?;
            } else {
                ensure!(kind.is_file(), "non-regular managed file: {name:?}");
                files.push((name, path));
            }
        }
        Ok(())
    }
    let metadata = fs::symlink_metadata(tree)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "expected a real directory {tree:?}"
    );
    let mut files = Vec::new();
    walk(tree, tree, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

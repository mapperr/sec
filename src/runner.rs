use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use crate::{
    common as c, platform, remote,
    store::{self, Store},
    supervisor,
};

struct Injection {
    mode: String,
    name: String,
    value: String,
    store: Option<Store>,
    alias: Option<String>,
}

impl Injection {
    fn describe(&self) -> String {
        match &self.store {
            Some(source) => format!(
                "{} {}{} from {:?}",
                self.mode,
                if self.name.is_empty() {
                    String::new()
                } else {
                    format!("{}=", self.name)
                },
                format_args!("{:?}", self.value),
                source.origin
            ),
            None => format!("set {}=<literal>", self.name),
        }
    }
}

struct Runner {
    base: Store,
    stores: BTreeMap<String, Store>,
    leases: Vec<File>,
    project_only: bool,
}

impl Runner {
    fn new() -> Result<Self> {
        let base = store::selected()?;
        let project_only = c::on("SEC_STORE_PROJECT_ONLY")
            || store::project()
                .ok()
                .flatten()
                .is_some_and(|root| base.root == root);
        Ok(Self {
            base,
            stores: BTreeMap::new(),
            leases: Vec::new(),
            project_only,
        })
    }

    fn resolve(&mut self, alias: Option<&str>) -> Result<Store> {
        let Some(alias) = alias else {
            return Ok(self.base.clone());
        };
        if let Some(source) = self.stores.get(alias) {
            return Ok(source.clone());
        }
        let source = store::resolve(&self.base, alias, self.project_only)?;
        if source.remote {
            self.leases.push(remote::lease(&source)?);
        }
        self.stores.insert(alias.into(), source.clone());
        Ok(source)
    }

    fn path<'a>(
        &mut self,
        reference: &'a str,
        mutable: bool,
    ) -> Result<(Store, Option<&'a str>, PathBuf)> {
        let direct = Path::new(reference);
        if !mutable
            && (direct.is_absolute() || reference.starts_with("./") || reference.starts_with("../"))
        {
            let path = c::absolute_path(direct)?;
            return Ok((self.base.clone(), None, path));
        }
        let (alias, name) = store::reference(reference)?;
        ensure!(
            !mutable || alias.is_none(),
            "aliased manifests are read-only"
        );
        c::managed(name)?;
        let source = self.resolve(alias)?;
        let path = source.root.join("manifests").join(name);
        Ok((source, alias, path))
    }

    fn instruction(
        &mut self,
        mode: &str,
        value: &str,
        primary: Option<(&Store, Option<&str>)>,
    ) -> Result<Injection> {
        if mode == "set" {
            let (name, value) = value.split_once('=').context("set expects NAME=VALUE")?;
            variable(name)?;
            ensure!(!value.contains('\0'), "NUL in literal");
            return Ok(Injection {
                mode: mode.into(),
                name: name.into(),
                value: value.into(),
                store: None,
                alias: None,
            });
        }
        let (name, value) = if mode == "env" {
            (Some(""), value)
        } else if let Some((name, value)) = value.split_once('=') {
            variable(name)?;
            (Some(name), value)
        } else if mode == "file" {
            (None, value)
        } else {
            bail!("var expects NAME=ENTRY");
        };
        let (alias, name_value) = store::reference(value)?;
        let value = store::entry(name_value)?.to_owned();
        let name = if let Some(name) = name {
            name.to_owned()
        } else {
            let mut name = value
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_uppercase()
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            if name.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                name.insert(0, '_');
            }
            variable(&name)?;
            name
        };
        let (source, alias) = match (alias, primary) {
            (None, Some((source, alias))) => (source.clone(), alias),
            (alias, _) => (self.resolve(alias)?, alias),
        };
        ensure!(
            !primary.is_some_and(|(primary, _)| primary.remote) || !store::is_personal(&source),
            "compose a personal manifest explicitly at the call site"
        );
        Ok(Injection {
            mode: mode.into(),
            name,
            value,
            store: Some(source),
            alias: alias.map(str::to_owned),
        })
    }

    fn manifest(
        &mut self,
        reference: &str,
        optional: bool,
    ) -> Result<(PathBuf, Option<Vec<Injection>>)> {
        let (source, alias, path) = self.path(reference, false)?;
        let Some(data) = c::optional(&path, c::CONFIG)? else {
            ensure!(optional, "manifest {reference:?} does not exist");
            if c::var("SEC_RUN_DEBUG").is_some() {
                eprintln!("sec run: skipping absent optional manifest {reference:?}");
            }
            return Ok((path, None));
        };
        let mut commands = Vec::new();
        for (number, line) in c::utf8(&data)?.lines().enumerate() {
            let line = line.trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (mode, value) = line
                .split_once(char::is_whitespace)
                .with_context(|| format!("invalid directive at {reference:?}:{}", number + 1))?;
            let mode = match mode {
                "-e" => "env",
                "-v" => "var",
                "-f" => "file",
                value => value,
            };
            ensure!(
                matches!(mode, "env" | "var" | "file" | "set"),
                "invalid directive at {reference:?}:{}",
                number + 1
            );
            let value = if mode == "set" {
                value.trim_start()
            } else {
                let value = value.trim();
                ensure!(
                    !value.chars().any(char::is_whitespace),
                    "whitespace in manifest reference"
                );
                value
            };
            commands.push(self.instruction(mode, value, Some((&source, alias)))?);
            ensure!(commands.len() <= 128, "manifest exceeds 128 directives");
        }
        Ok((path, Some(commands)))
    }
}

fn variable(name: &str) -> Result<()> {
    let forbidden = [
        "BASH_ENV",
        "ENV",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG",
        "IFS",
        "PATH",
        "HOME",
        "SHELL",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "RUBYLIB",
        "RUBYOPT",
        "NODE_OPTIONS",
        "PERL5LIB",
        "PERL5OPT",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "SSH_AUTH_SOCK",
        "ZDOTDIR",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "LOCPATH",
        "GIT_DIR",
        "GIT_WORK_TREE",
    ];
    ensure!(
        name.as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "invalid environment variable: {name:?}",
    );
    let normalized = if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.into()
    };
    ensure!(
        !forbidden.contains(&normalized.as_str())
            && !["SEC_", "LD_", "DYLD_", "GIT_CONFIG_", "XDG_"]
                .iter()
                .any(|prefix| normalized.starts_with(prefix)),
        "reserved environment variable: {name:?}",
    );
    Ok(())
}

fn pinned(path: &Path) -> Result<Option<File>> {
    let Some(hash) = c::var("SEC_RUN_EXEC_SHA256") else {
        return Ok(None);
    };
    let hash = hash.to_str().context("invalid SHA-256 pin")?;
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')),
        "invalid SHA-256 executable pin"
    );
    let file = platform::open_trusted(path)?;
    let digest = c::sha(c::bounded(file.try_clone()?, 64 * c::CONFIG)?);
    ensure!(
        digest == hash,
        "executable differs from trusted SHA-256 pin"
    );
    Ok(Some(file))
}

fn manage(runner: &mut Runner, options: &[String]) -> Result<()> {
    let (action, args) = options
        .split_first()
        .context("specify a manifest command")?;
    let action = action.as_str();
    match action {
        "ls" | "l" if args.is_empty() => {
            let folder = runner.base.root.join("manifests");
            match c::lines(&folder) {
                Ok(files) => {
                    for (name, _) in files {
                        println!("{name}");
                    }
                }
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        "edit" | "e" | "rm" | "r" if !args.is_empty() => {
            let editing = matches!(action, "edit" | "e");
            ensure!(
                !editing || args.len() == 1,
                "edit requires exactly one manifest"
            );
            for name in args {
                let (_, _, path) = runner.path(name, true)?;
                if editing {
                    platform::create_dirs(path.parent().unwrap())?;
                    let before = c::optional(&path, c::CONFIG)?;
                    let new = c::edit(
                        &path,
                        before.as_deref().unwrap_or_default(),
                        "SEC_RUN_EDITOR",
                        false,
                    )?;
                    platform::atomic_replace(&path, before.as_deref(), &new)?;
                } else {
                    platform::remove_file(&path)?;
                }
            }
        }
        _ => bail!("invalid manifest command or arguments. Run sec run manifest --help"),
    }
    Ok(())
}

type Values = indexmap::IndexMap<String, Zeroizing<Vec<u8>>>;

fn dotenv(data: &[u8]) -> Result<Values> {
    ensure!(
        !data.contains(&0) && !data.contains(&b'\r'),
        "invalid bytes in environment entry"
    );
    let mut values = Values::new();
    for line in data.split(|c| *c == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) || line.first() == Some(&b'#') {
            continue;
        }
        let equal = line
            .iter()
            .position(|&byte| byte == b'=')
            .context("expected NAME=VALUE")?;
        let name = c::utf8(&line[..equal])?;
        ensure!(
            variable(name).is_ok(),
            "invalid or reserved variable name in environment entry"
        );
        values.insert(name.into(), Zeroizing::new(line[equal + 1..].to_vec()));
    }
    Ok(values)
}

fn normalized(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.to_owned()
    }
}

fn destination(item: &Injection) -> String {
    match &item.alias {
        Some(alias) => format!("{alias}/{}", item.value),
        None => item.value.clone(),
    }
}

fn prepare(plan: &[Injection], runtime: Option<&Path>) -> Result<Values> {
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for item in plan {
        if item.mode != "env" {
            ensure!(
                names.insert(normalized(&item.name)),
                "duplicate injection variable: {:?}",
                item.name
            );
        }
        if item.mode == "file" {
            let target = normalized(&destination(item));
            ensure!(
                !paths.iter().any(|old: &String| old == &target
                    || old.starts_with(&(target.clone() + "/"))
                    || target.starts_with(&(old.clone() + "/"))),
                "conflicting file destinations"
            );
            paths.insert(target);
        }
    }
    let mut values = Values::new();
    let mut total = 0;
    let debug = c::var("SEC_RUN_DEBUG").is_some();
    for item in plan {
        if debug {
            eprintln!("sec run: {}", item.describe());
        }
        if item.mode == "set" {
            values.insert(
                item.name.clone(),
                Zeroizing::new(item.value.as_bytes().to_vec()),
            );
            continue;
        }
        let data = store::get(
            item.store.as_ref().unwrap(),
            &item.value,
            if item.mode == "file" {
                c::SECRET
            } else {
                c::CONFIG
            },
        )?;
        total += data.len();
        ensure!(
            total <= 64 * c::CONFIG,
            "injection plan exceeds the total size limit"
        );
        match item.mode.as_str() {
            "env" => {
                let decoded = dotenv(&data)?;
                for (name, value) in decoded {
                    ensure!(
                        !names.contains(&normalized(&name)),
                        "conflicting variable {name:?}"
                    );
                    if cfg!(windows) {
                        values.retain(|key, _| !key.eq_ignore_ascii_case(&name));
                    }
                    values.insert(name, value);
                }
            }
            "var" => {
                ensure!(!data.contains(&0), "NUL in environment variable");
                values.insert(item.name.clone(), data);
            }
            "file" => {
                if let Some(runtime) = runtime {
                    let file = runtime.join(destination(item));
                    platform::create_dirs(file.parent().unwrap())?;
                    c::write_new(&file, &data)?;
                    values.insert(
                        item.name.clone(),
                        Zeroizing::new(c::path_string(&file)?.into_bytes()),
                    );
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(values)
}

fn workspace() -> Result<(tempfile::TempDir, File)> {
    let runtime = c::var("SEC_RUN_TMPDIR").or_else(|| c::var("XDG_RUNTIME_DIR"));
    let base = match runtime {
        Some(path) => PathBuf::from(path),
        None if cfg!(windows) => {
            c::base("XDG_RUNTIME_DIR", "", "LOCALAPPDATA")?.join("sec/runtime")
        }
        None if cfg!(target_os = "macos") => env::temp_dir().canonicalize()?,
        None => bail!("set SEC_RUN_TMPDIR or XDG_RUNTIME_DIR to a private directory"),
    };
    if cfg!(windows) {
        platform::create_dirs(&base)?;
    }
    platform::private_dir(&base)?;
    let folder = base.join("sec-run-workspaces");
    platform::create_dirs(&folder)?;
    platform::private_dir(&folder)?;
    let lock_path = folder.join(".lock");
    if c::optional(&lock_path, c::CONFIG)?.is_none() {
        let _ = c::write_new(&lock_path, b"");
    }
    platform::open_identity(&lock_path)?;
    let gate = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    gate.lock()?;
    for existing in fs::read_dir(&folder)? {
        let existing = existing?;
        if !existing.file_name().to_string_lossy().starts_with("run.") {
            continue;
        }
        let path = existing.path();
        if platform::private_dir(&path).is_err() {
            continue;
        }
        if let Ok(lease) = platform::open_identity(&path.join(".lease"))
            && lease.try_lock().is_ok()
        {
            #[cfg(windows)]
            drop(lease);
            fs::remove_dir_all(path)?;
        }
    }
    let temp = tempfile::Builder::new().prefix("run.").tempdir_in(folder)?;
    platform::private_dir(temp.path())?;
    let lease = temp.path().join(".lease");
    c::write_new(&lease, b"")?;
    let lease = OpenOptions::new().read(true).write(true).open(lease)?;
    lease.lock()?;
    Ok((temp, lease))
}

fn environment(value: &[u8]) -> Result<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(value.to_vec()))
    }
    #[cfg(windows)]
    {
        Ok(c::utf8(value)?.into())
    }
}

pub fn cli(args: &[String]) -> Result<i32> {
    if args
        .first()
        .is_some_and(|first| matches!(first.as_str(), "--version" | "-V" | "version"))
    {
        println!("sec-run {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    let split = args.iter().position(|arg| arg == "--");
    let (options, command) = split.map_or((args, &[][..]), |split| {
        (&args[..split], &args[split + 1..])
    });
    ensure!(
        split.is_none() || !command.is_empty(),
        "missing command after --"
    );
    let mut runner = Runner::new()?;
    if options
        .first()
        .is_some_and(|first| matches!(first.as_str(), "manifest" | "m"))
    {
        ensure!(
            command.is_empty(),
            "manifest commands take a manifest reference. Omit -- COMMAND"
        );
        manage(&mut runner, &options[1..])?;
        return Ok(0);
    }
    let mut output = None;
    let mut plan = Vec::new();
    let mut manifest_refs = Vec::new();
    let mut options = options.iter().map(String::as_str);
    while let Some(option) = options.next() {
        let mode = match option {
            "--print" | "--env-only" => {
                ensure!(output.replace(option).is_none(), "use only one output mode");
                continue;
            }
            "-m" | "--manifest" | "-M" | "--optional-manifest" => {
                let name = options.next().context("missing manifest reference")?;
                let (path, found) =
                    runner.manifest(name, matches!(option, "-M" | "--optional-manifest"))?;
                manifest_refs.push((name, path, found.is_some()));
                plan.extend(found.into_iter().flatten());
                continue;
            }
            "-e" | "--env" => "env",
            "-v" | "--var" => "var",
            "-s" | "--set" => "set",
            "-f" | "--file" => "file",
            _ => bail!("invalid injection flag {option:?}. Run sec run --help"),
        };
        let value = options.next().context("missing injection argument")?;
        plan.push(runner.instruction(mode, value, None)?);
    }
    ensure!(
        !manifest_refs.is_empty() || !plan.is_empty(),
        "specify at least one injection or manifest"
    );
    ensure!(plan.len() <= 128, "injection plan exceeds 128 directives");
    if output.is_none() && command.is_empty() {
        let values = prepare(&plan, None)?;
        println!("Store: {:?}", runner.base.root);
        for (name, path, present) in manifest_refs {
            let status = if present { "" } else { " (absent, optional)" };
            println!("Manifest {name:?}: {path:?}{status}");
        }
        for item in &plan {
            println!("{}", item.describe());
            if item.mode == "file" {
                println!("  {}=<SEC_RUN_DIR>/{}", item.name, destination(item));
            }
            if item.mode == "var" {
                let value = &values[&item.name];
                if value.ends_with(b"\r\n") {
                    println!("  {} ends with CRLF", item.name);
                } else if value.ends_with(b"\n") {
                    println!("  {} ends with LF", item.name);
                }
            }
        }
        if !values.is_empty() {
            println!(
                "Environment: {}",
                values.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        return Ok(0);
    }
    ensure!(
        output.is_none() || command.is_empty(),
        "output modes cannot be combined with a command"
    );
    if let Some(mode) = output {
        ensure!(
            mode != "--env-only" || !plan.iter().any(|item| item.mode == "file"),
            "--env-only does not accept file entries"
        );
        let env = prepare(&plan, None)?;
        let mut stdout = io::stdout().lock();
        for (name, value) in env {
            write!(stdout, "{name}=")?;
            stdout.write_all(&value)?;
            stdout.write_all(b"\n")?;
        }
        if mode == "--print" {
            for item in &plan {
                if item.mode == "file" {
                    writeln!(stdout, "{}=<SEC_RUN_DIR>/{}", item.name, destination(item))?;
                }
            }
            writeln!(stdout, "SEC_RUN_DIR=<temporary directory>")?;
        }
        return Ok(0);
    }
    let first = &command[0];
    let target = which::which(first)
        .with_context(|| format!("command {first:?} is unavailable"))?
        .canonicalize()?;
    let program = c::path_string(&target)?;
    pinned(&target)?;
    let (workspace, lease) = workspace()?;
    let runtime = workspace.path().join("files");
    platform::create_dirs(&runtime)?;
    let env = prepare(&plan, Some(&runtime))?;
    let executable = pinned(&target)?;
    let mut child = Command::new(supervisor::program(&program, executable.as_ref()));
    child
        .args(&command[1..])
        .env("SEC_STORE_DIR", &runner.base.root)
        .env("SEC_RUN_DIR", &runtime);
    #[cfg(unix)]
    std::os::unix::process::CommandExt::arg0(&mut child, &command[0]);
    for (name, value) in env {
        child.env(name, environment(&value)?);
    }
    let result = supervisor::spawn(&mut child, &lease, executable.as_ref());
    drop(lease);
    drop(workspace);
    result
}

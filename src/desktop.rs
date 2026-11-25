use std::{
    env,
    io::{self, Write},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

use crate::{common as c, store};

pub fn first_line(data: &[u8]) -> &[u8] {
    if let Some(position) = data.iter().position(|&byte| byte == b'\n') {
        data[..position]
            .strip_suffix(b"\r")
            .unwrap_or(&data[..position])
    } else {
        data
    }
}

fn entry(name: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let base = store::selected()?;
    let (alias, name) = store::reference(name)?;
    let source = if let Some(alias) = alias {
        store::resolve(&base, alias, c::on("SEC_STORE_PROJECT_ONLY"))?
    } else {
        base
    };
    store::get(&source, name, limit)
}

fn custom(command: std::ffi::OsString) -> Command {
    let mut program = if cfg!(windows) {
        Command::new("cmd.exe")
    } else {
        Command::new("/bin/sh")
    };
    program
        .arg(if cfg!(windows) { "/C" } else { "-c" })
        .arg(command);
    program
}

fn otp(data: &[u8]) -> Result<Vec<u8>> {
    let mut fields = c::utf8(data)?
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("totp:"));
    let field = fields
        .next()
        .context("OTP entry has no 'totp:' line. Use totp: BASE32_SEED")?
        .trim();
    ensure!(
        fields.next().is_none(),
        "OTP entry has multiple 'totp:' lines. Keep exactly one"
    );
    ensure!(!field.is_empty(), "OTP entry has an empty 'totp:' field");
    let encoded = Zeroizing::new(field.to_ascii_uppercase());
    let bare = encoded.trim_end_matches('=');
    if bare.len() != encoded.len() {
        let pads = (8 - bare.len() % 8) % 8;
        ensure!(pads == encoded.len() - bare.len(), "invalid OTP padding");
    }
    let seed = Zeroizing::new(
        BASE32_NOPAD
            .decode(bare.as_bytes())
            .context("OTP entry contains an invalid Base32 seed")?,
    );
    ensure!(!seed.is_empty(), "empty OTP seed");
    if let Some(command) = c::var("SEC_STORE_OTP_CMD") {
        let mut input = encoded.as_bytes().to_vec();
        input.push(b'\n');
        let code = c::run(&mut custom(command), Some(input), 128)?;
        let trimmed = code.strip_suffix(b"\n").unwrap_or(&code);
        ensure!(
            matches!(trimmed.len(), 6..=8) && trimmed.iter().all(u8::is_ascii_digit),
            "invalid OTP generator output"
        );
        return Ok([trimmed, b"\n"].concat());
    }
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    Ok(format!("{:06}\n", totp(&seed, counter)?).into_bytes())
}

fn totp(seed: &[u8], counter: u64) -> Result<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(seed)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 15) as usize;
    let number = u32::from_be_bytes(result[offset..offset + 4].try_into()?) & 0x7fff_ffff;
    Ok(number % 1_000_000)
}

fn send_input(command: &mut Command, data: &[u8]) -> Result<(Child, io::Result<()>)> {
    let mut child = command
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {:?}", command.get_program()))?;
    let written = child.stdin.take().unwrap().write_all(data);
    Ok((child, written))
}

fn consume(command: &mut Command, data: &[u8]) -> Result<()> {
    let (mut child, written) = send_input(command, data)?;
    let status = child.wait()?;
    written?;
    ensure!(status.success(), "{:?} failed", command.get_program());
    Ok(())
}

fn timed_wayland_copy(command: &mut Command, data: &[u8]) -> Result<()> {
    // The timeout stops this particular offer, even after sec exits.
    let (mut child, written) =
        send_input(command.stdout(Stdio::null()).stderr(Stdio::null()), data)?;
    if let Some(status) = child.wait_timeout(Duration::from_millis(150))? {
        ensure!(status.success(), "wl-copy failed with {status}");
    } else {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    written.context("send data to wl-copy")
}

fn clipboard(data: &[u8]) -> Result<()> {
    if let Some(command) = c::var("SEC_STORE_FZF_CLIP_CMD") {
        return consume(&mut custom(command), data);
    }
    if cfg!(windows) {
        let value = c::utf8(data)?;
        let utf16 = [0xfeff]
            .into_iter()
            .chain(value.encode_utf16())
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        return consume(&mut Command::new("clip.exe"), &utf16);
    }
    if cfg!(target_os = "macos") {
        return consume(&mut Command::new("pbcopy"), data);
    }
    let mode = c::var("SEC_STORE_FZF_PASTE_ONCE");
    let once = mode.as_deref().is_none_or(|value| value != "0");
    let wayland = c::var("WAYLAND_DISPLAY").is_some() || c::var("WAYLAND_SOCKET").is_some();
    if (wayland || c::var("DISPLAY").is_none())
        && let Ok(program) = which::which("wl-copy")
    {
        let sensitive = c::capture(Command::new(&program).arg("--help"), None, c::CONFIG, 5)
            .is_ok_and(|result| String::from_utf8_lossy(&result.out).contains("--sensitive"));
        if mode.is_none()
            && sensitive
            && let Ok(timeout) = which::which("timeout")
        {
            return timed_wayland_copy(
                Command::new(timeout)
                    .arg("30")
                    .arg(&program)
                    .args(["--foreground", "--sensitive"]),
                data,
            );
        }
        let mut command = Command::new(program);
        if once {
            command.arg("--paste-once");
        }
        if sensitive {
            command.arg("--sensitive");
        }
        return consume(&mut command, data);
    }
    if let Ok(program) = which::which("xclip") {
        let mut command = Command::new(program);
        command.args(["-selection", "clipboard"]);
        if once {
            command.args(["-loops", "1"]);
        }
        return consume(&mut command, data);
    }
    if c::on("SEC_STORE_FZF_ALLOW_PERSISTENT_CLIPBOARD") {
        return consume(Command::new("xsel").args(["--clipboard", "--input"]), data);
    }
    bail!("no supported clipboard helper")
}

fn display(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| {
            if c.is_control() && !matches!(c, '\n' | '\t') {
                '�'
            } else {
                c
            }
        })
        .collect::<String>()
        .into_bytes()
}

fn type_entry(name: &str, default_delay: f64) -> Result<()> {
    let (_, name_only) = store::reference(name)?;
    let canonical = store::entry(name_only)?;
    let base = canonical.rsplit('/').next().unwrap_or_default();
    let data = entry(name, c::SECRET)?;
    let first = c::utf8(first_line(&data))?;
    ensure!(
        !first.chars().any(char::is_control) && !base.chars().any(char::is_control),
        "control bytes are not supported in typed text"
    );
    let delay = match c::var("SEC_STORE_TYPE_WAIT") {
        Some(value) => value.to_str().context("invalid typing delay")?.parse()?,
        None => default_delay,
    };
    ensure!(
        (0.0..=60.0).contains(&delay),
        "typing delay must be between 0 and 60 seconds"
    );
    std::thread::sleep(Duration::from_secs_f64(delay));
    platform_type(base, first)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_type(base: &str, data: &str) -> Result<()> {
    let tool = c::var("SEC_STORE_TYPING_TOOL").unwrap_or_else(|| {
        if c::var("WAYLAND_DISPLAY").is_some() {
            "wtype".into()
        } else {
            "xdotool".into()
        }
    });
    let program = which::which(&tool)?;
    if tool == "xdotool" {
        let active = || -> Result<String> {
            let value = c::run(Command::new(&program).arg("getactivewindow"), None, 64)?;
            let result = c::utf8(&value)?.trim().to_owned();
            ensure!(
                !result.is_empty() && result.bytes().all(|c| c.is_ascii_digit()),
                "cannot verify active X11 window"
            );
            Ok(result)
        };
        let window = active()?;
        for (value, key) in [(base, false), ("Tab", true), (data, false)] {
            ensure!(active()? == window, "active window changed; typing stopped");
            let mut command = Command::new(&program);
            if key {
                consume(
                    command.args(["key", "--clearmodifiers", "--window", &window, value]),
                    b"",
                )?;
            } else {
                consume(
                    command.args([
                        "type",
                        "--clearmodifiers",
                        "--window",
                        &window,
                        "--file",
                        "-",
                    ]),
                    value.as_bytes(),
                )?;
            }
        }
    } else if tool == "wtype" {
        ensure!(
            c::on("SEC_STORE_TYPE_ALLOW_UNVERIFIED"),
            "Wayland requires an explicit opt-in for unverified typing"
        );
        consume(Command::new(&program).arg("-"), base.as_bytes())?;
        consume(Command::new(&program).args(["-k", "Tab"]), b"")?;
        consume(Command::new(&program).arg("-"), data.as_bytes())?;
    } else {
        bail!("expected wtype or xdotool");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_type(base: &str, data: &str) -> Result<()> {
    use std::ffi::c_void;
    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightPostEventAccess() -> bool;
        fn CGEventCreateKeyboardEvent(
            source: *const c_void,
            keycode: u16,
            down: bool,
        ) -> *mut c_void;
        fn CGEventKeyboardSetUnicodeString(event: *mut c_void, length: usize, text: *const u16);
        fn CGEventPostToPid(pid: i32, event: *mut c_void);
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: *const c_void);
    }

    let active = || -> Result<i32> {
        const QUERY: &str = "tell application \"System Events\" to get unix id of the first application process whose frontmost is true";
        let value = c::run(Command::new("osascript").args(["-e", QUERY]), None, 64)?;
        let pid: i32 = c::utf8(&value)?.trim().parse()?;
        ensure!(pid > 0, "cannot verify focused process");
        Ok(pid)
    };
    ensure!(
        unsafe { CGPreflightPostEventAccess() },
        "macOS Accessibility permission is required"
    );
    let target = active()?;
    for (value, code) in [(base, 0), ("", 48), (data, 0)] {
        if value.is_empty() && code == 0 {
            continue;
        }
        ensure!(active()? == target, "focus changed; typing stopped");
        // CoreGraphics accepts short Unicode sequences per keyboard event.
        let utf16 = value.encode_utf16().collect::<Vec<_>>();
        let mut rest = utf16.as_slice();
        loop {
            let mut length = rest.len().min(16);
            if length < rest.len() && matches!(rest[length - 1], 0xd800..=0xdbff) {
                length -= 1;
            }
            let text = &rest[..length];
            for down in [true, false] {
                let event = unsafe { CGEventCreateKeyboardEvent(std::ptr::null(), code, down) };
                ensure!(!event.is_null(), "cannot create macOS typing event");
                unsafe {
                    if !text.is_empty() {
                        CGEventKeyboardSetUnicodeString(event, text.len(), text.as_ptr());
                    }
                    CGEventPostToPid(target, event);
                    CFRelease(event);
                }
            }
            rest = &rest[length..];
            if rest.is_empty() {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn platform_type(base: &str, data: &str) -> Result<()> {
    use windows_sys::Win32::UI::{
        Input::KeyboardAndMouse::{
            INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
            SendInput, VK_TAB,
        },
        WindowsAndMessaging::GetForegroundWindow,
    };
    ensure!(
        c::on("SEC_STORE_TYPE_ALLOW_UNVERIFIED"),
        "Windows cannot pin SendInput to a window; an explicit opt-in is required"
    );
    let target = unsafe { GetForegroundWindow() };
    ensure!(!target.is_null(), "no focused window");
    for (value, tab) in [(base, false), ("", true), (data, false)] {
        let emit = |key: u16, scan, flags| -> Result<()> {
            ensure!(
                unsafe { GetForegroundWindow() } == target,
                "focus changed; typing stopped"
            );
            let make = |up| INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: key,
                        wScan: scan,
                        dwFlags: flags | up,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let events = [make(0), make(KEYEVENTF_KEYUP)];
            ensure!(
                unsafe { SendInput(2, events.as_ptr(), std::mem::size_of::<INPUT>() as i32) } == 2,
                "Windows declined synthesized input"
            );
            Ok(())
        };
        if tab {
            emit(VK_TAB, 0, 0)?;
        } else {
            for code in value.encode_utf16() {
                emit(0, code, KEYEVENTF_UNICODE)?;
            }
        }
    }
    Ok(())
}

fn view(name: &str) -> Result<()> {
    let data = entry(name, c::SECRET)?;
    let text = display(&data);
    if let Some(pager) = c::var("SEC_STORE_FZF_PAGER") {
        return consume(&mut custom(pager), &text);
    }
    if let Ok(less) = which::which("less") {
        return consume(
            Command::new(less)
                .env("LESSHISTFILE", "-")
                .env("LESSSECURE", "1"),
            &text,
        );
    }
    io::stdout().write_all(&text)?;
    Ok(())
}

fn dispatch(action: &str, name: &str, in_menu: bool) -> Result<()> {
    let (_, path) = store::reference(name)?;
    let path = store::entry(path)?;
    match action {
        "--copy-first" => clipboard(first_line(&entry(name, c::SECRET)?)),
        "--copy-full" => clipboard(&entry(name, c::SECRET)?),
        "--otp" => clipboard(first_line(&otp(&entry(name, 65536)?)?)),
        "--copy-name" => clipboard(path.rsplit('/').next().unwrap_or(path).as_bytes()),
        "--copy-path" => clipboard(name.as_bytes()),
        "--view" => view(name),
        "--preview" => {
            io::stdout().write_all(&display(&entry(name, c::SECRET)?))?;
            Ok(())
        }
        "--type" => type_entry(name, if in_menu { 2.0 } else { 0.0 }),
        "--policy" => {
            store::cli(&["policy".into(), "path".into(), name.into()])?;
            Ok(())
        }
        "--edit" | "--rekey" | "--remove" => {
            let command = if action == "--remove" {
                c::confirm("Remove encrypted entry", [format!("{name:?}")])?;
                "rm"
            } else {
                &action[2..]
            };
            store::cli(&[command.into(), name.into()])?;
            Ok(())
        }
        _ => bail!("unknown interactive action"),
    }
}

const FZF_ACTIONS: &[(&str, &str)] = &[
    ("ctrl-i", "--copy-first"),
    ("ctrl-u", "--copy-name"),
    ("ctrl-b", "--copy-path"),
    ("ctrl-y", "--copy-full"),
    ("ctrl-o", "--otp"),
    ("ctrl-v", "--view"),
    ("ctrl-e", "--edit"),
    ("ctrl-t", "--type"),
    ("ctrl-h", "--policy"),
    ("ctrl-r", "--rekey"),
    ("ctrl-d", "--remove"),
    ("ctrl-a", "--new"),
];

fn new_entry() -> Result<()> {
    use std::io::BufRead;
    let (mut input, mut output) = c::terminal()?;
    write!(output, "new entry name: ")?;
    output.flush()?;
    let mut name = String::new();
    input.read_line(&mut name)?;
    let name = name.trim_end_matches(['\r', '\n']);
    if !name.is_empty() {
        dispatch("--edit", name, true)?;
    }
    Ok(())
}

fn pause() -> Result<()> {
    use std::io::BufRead;
    let (mut input, mut output) = c::terminal()?;
    write!(output, "\nPress Enter to return to fzf... ")?;
    output.flush()?;
    input.read_line(&mut String::new())?;
    Ok(())
}

fn fzf(args: &[String]) -> Result<()> {
    match args {
        [action, ..] if action == "--list" && args.len() <= 2 => {
            let prefix = args.get(1).map_or("", String::as_str);
            for name in store::list(&store::selected()?, prefix)? {
                println!("{name}");
            }
        }
        [action] if action == "--new" => new_entry()?,
        #[cfg(unix)]
        [flag, action, rest @ ..] if flag == "--menu-action" => {
            let result = match (action.as_str(), rest) {
                ("--new", []) => new_entry(),
                (action, [name]) => dispatch(action, name, true),
                _ => bail!("invalid fzf action arguments"),
            };
            match result {
                Ok(()) if matches!(action.as_str(), "--view" | "--policy") => pause()?,
                Ok(()) => {}
                Err(error) => {
                    eprintln!("sec store fzf: {error:#}");
                    pause()?;
                }
            }
        }
        [action, name] if action.starts_with("--") => dispatch(action, name, false)?,
        [] => fzf_menu("")?,
        [prefix] if !prefix.starts_with("--") => fzf_menu(prefix)?,
        _ => bail!("invalid fzf arguments. Run sec store fzf --help"),
    }
    Ok(())
}

fn fzf_command(prefix: &str) -> Command {
    let program = c::var("SEC_STORE_FZF_FZF").unwrap_or_else(|| "fzf".into());
    if c::var("SEC_STORE_FZF_DEBUG").is_some() {
        eprintln!("sec store fzf: starting {program:?} for prefix {prefix:?}");
    }
    Command::new(program)
}

const FZF_HEADER: &str = "Ctrl-I:first  Ctrl-U:name  Ctrl-B:path  Ctrl-Y:full  Ctrl-O:TOTP
Ctrl-V:view  Ctrl-T:type  Ctrl-H:policy  Ctrl-R:rekey  Ctrl-E:edit  Ctrl-A:new  Ctrl-D:remove";

#[cfg(unix)]
fn fzf_menu(prefix: &str) -> Result<()> {
    let executable = env::current_exe()?;
    let subcommand = if executable
        .file_stem()
        .is_some_and(|name| name == "sec-store-fzf")
    {
        ""
    } else {
        " store fzf"
    };
    // Keep the shell syntax fixed. fzf quotes the full entry placeholder for this shell.
    let sec = format!("\"$SEC_STORE_FZF_SELF\"{subcommand}");
    let reload = format!("+reload({sec} --list \"$SEC_STORE_FZF_PREFIX\")");
    let mut command = fzf_command(prefix);
    command
        .env("SEC_STORE_FZF_SELF", executable)
        .env("SEC_STORE_FZF_PREFIX", prefix)
        .args([
            "--with-shell=/bin/sh -c",
            "--no-multi",
            "--cycle",
            "--prompt",
            "sec> ",
            "--header",
            &format!("{FZF_HEADER}  Ctrl-/:preview"),
            "--preview",
            &format!("{sec} --preview {{}}"),
            "--preview-window",
            "right:60%:wrap:hidden",
            "--bind",
            "ctrl-/:toggle-preview",
        ]);
    for &(key, action) in FZF_ACTIONS {
        let selected = if action == "--new" { "" } else { " {}" };
        let reload = if matches!(action, "--new" | "--remove") {
            reload.as_str()
        } else {
            ""
        };
        command.arg(format!(
            "--bind={key}:execute({sec} --menu-action {action}{selected}){reload}"
        ));
    }
    let entries = store::list(&store::selected()?, prefix)?;
    let result = c::capture(&mut command, Some(fzf_input(&entries)), c::CONFIG, 3600)?;
    if result.status.success() {
        io::stdout().write_all(&result.out)?;
    } else if !matches!(result.status.code(), Some(1 | 130)) {
        bail!("fzf exited with {}", result.status);
    }
    Ok(())
}

fn fzf_input(entries: &[String]) -> Vec<u8> {
    if entries.is_empty() {
        Vec::new()
    } else {
        (entries.join("\n") + "\n").into_bytes()
    }
}

#[cfg(windows)]
fn fzf_menu(prefix: &str) -> Result<()> {
    // Dispatch from the selected line directly, without passing it through cmd.exe.
    let shortcuts = FZF_ACTIONS.iter().copied().chain([("ctrl-/", "--view")]);
    let keys = shortcuts
        .clone()
        .map(|(key, _)| key)
        .collect::<Vec<_>>()
        .join(",");
    let mut query = String::new();
    let mut entries = store::list(&store::selected()?, prefix)?;
    loop {
        let result = c::capture(
            fzf_command(prefix).args([
                "--no-multi",
                "--no-read0",
                "--no-print0",
                "--cycle",
                "--print-query",
                "--query",
                &query,
                "--expect",
                &keys,
                "--prompt",
                "sec> ",
                "--header",
                FZF_HEADER,
            ]),
            Some(fzf_input(&entries)),
            c::CONFIG,
            3600,
        )?;
        if !result.status.success() {
            if matches!(result.status.code(), Some(1 | 130)) {
                return Ok(());
            }
            bail!("fzf exited with {}", result.status);
        }
        let mut lines = c::utf8(&result.out)?.lines();
        query = lines.next().unwrap_or_default().to_owned();
        let key = lines.next().unwrap_or_default();
        let result = if key == "ctrl-a" {
            new_entry()
        } else if let Some((_, action)) = shortcuts.clone().find(|(name, _)| *name == key) {
            if let Some(name) = lines
                .next()
                .filter(|name| entries.iter().any(|entry| entry == name))
            {
                dispatch(action, name, true).and_then(|()| {
                    if matches!(action, "--view" | "--policy") {
                        pause()
                    } else {
                        Ok(())
                    }
                })
            } else {
                Ok(())
            }
        } else {
            if let Some(name) = lines.next().filter(|v| !v.is_empty()) {
                println!("{name}");
            }
            return Ok(());
        };
        if let Err(error) = result {
            eprintln!("sec store fzf: {error:#}");
            pause()?;
        }
        if matches!(key, "ctrl-d" | "ctrl-a") {
            entries = store::list(&store::selected()?, prefix)?;
        }
    }
}

pub fn cli(component: &str, args: &[String]) -> Result<i32> {
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "--version" | "-V" | "version"))
    {
        println!("sec-store-{component} {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    match (component, args) {
        ("otp", [name]) => {
            if c::var("SEC_STORE_OTP_DEBUG").is_some() {
                eprintln!("sec store otp: reading {name:?}");
            }
            io::stdout().write_all(&otp(&entry(name, 65536)?)?)?;
        }
        ("type", [name]) => type_entry(name, 0.0)?,
        ("fzf", args) => fzf(args)?,
        _ => {
            return Err(anyhow!(
                "sec store {component} requires one entry. Run sec store {component} --help"
            ));
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn totp_matches_the_rfc_6238_sha1_vector() {
        assert_eq!(
            super::totp(b"12345678901234567890", 59 / 30).unwrap(),
            287082
        );
    }
}

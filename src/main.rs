mod common;
mod config;
mod crypto;
mod desktop;
mod git;
mod help;
mod platform;
mod remote;
mod runner;
mod security;
mod store;
mod supervisor;

use std::{
    env,
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::Path,
    process,
};

use anyhow::{Context, Result, bail};

fn run(mut args: impl Iterator<Item = OsString>) -> Result<bool> {
    let command = args.next().context("missing command")?;
    let args: Vec<_> = args.collect();
    match command.to_str() {
        Some("version" | "--version" | "-V") if args.is_empty() => {
            println!("sec {}", env!("CARGO_PKG_VERSION"));
        }
        Some("identity") if args.is_empty() || args == ["--all"] => {
            let paths = config::identity_paths()?;
            for path in paths
                .iter()
                .take(if args.is_empty() { 1 } else { paths.len() })
            {
                println!("{}", path.display());
            }
        }
        Some("recipient") if args.is_empty() => {
            for value in config::public_recipients()? {
                println!("{value}");
            }
        }
        Some("e") => {
            let legacy = config::legacy_self()?;
            let recipients = if legacy.is_none() {
                config::recipients()?
            } else {
                Vec::new()
            };
            let armor = env::var("SEC_ARMOR").as_deref() == Ok("1");
            if args.is_empty() {
                if !armor && io::stdout().is_terminal() {
                    bail!("redirect encrypted output or set SEC_ARMOR=1");
                }
                crypto::encrypt_to(
                    io::stdin().lock(),
                    io::stdout().lock(),
                    &recipients,
                    legacy.as_deref(),
                    armor,
                )?;
            } else {
                return apply_paths(&args, "encrypted", |path| {
                    platform::transform_in_place(path, |input, output| {
                        crypto::encrypt_to(input, output, &recipients, legacy.as_deref(), armor)
                    })
                });
            }
        }
        Some("d") => {
            let identities = config::decryption()?;
            if args.is_empty() {
                if io::stdout().is_terminal() {
                    bail!("redirect decrypted output to a private file or trusted consumer");
                }
                crypto::decrypt_from(io::stdin().lock(), io::stdout().lock(), &identities)?;
            } else {
                return apply_paths(&args, "decrypted", |path| {
                    platform::transform_in_place(path, |input, output| {
                        crypto::decrypt_from(input, output, &identities)
                    })
                });
            }
        }
        _ => bail!("unknown command or invalid arguments. Run sec --help for available commands"),
    }
    Ok(true)
}

fn apply_paths(
    args: &[OsString],
    operation: &str,
    mut transform: impl FnMut(&Path) -> Result<()>,
) -> Result<bool> {
    let mut ok = true;
    let mut stderr = io::stderr().lock();
    for filename in args {
        let path = Path::new(filename);
        match transform(path).with_context(|| format!("process {:?}", path)) {
            Ok(()) => writeln!(stderr, "sec: {path:?} {operation}")?,
            Err(error) => {
                ok = false;
                writeln!(stderr, "sec: {error:#}")?;
            }
        }
    }
    Ok(ok)
}

fn dispatch() -> Result<i32> {
    let mut all = env::args_os();
    let called = all.next().unwrap_or_else(|| "sec".into());
    let name = Path::new(&called)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("sec");
    let prefix: &[&str] = match name {
        "sec-run" => &["run"],
        "sec-store" => &["store"],
        "sec-git" => &["git"],
        "sec-security" => &["security"],
        "sec-store-remote-git" => &["store", "remote-git"],
        "sec-store-type" => &["store", "type"],
        "sec-store-fzf" => &["store", "fzf"],
        "sec-store-otp" => &["store", "otp"],
        _ => &[],
    };
    let args: Vec<_> = prefix.iter().map(OsString::from).chain(all).collect();
    if help::show(&args)? {
        return Ok(0);
    }
    let Some((first, rest)) = args.split_first() else {
        unreachable!("no arguments are handled by help");
    };
    let Some(command @ ("run" | "store" | "git" | "security")) = first.to_str() else {
        return Ok(if run(args.into_iter())? { 0 } else { 1 });
    };

    let args = rest
        .iter()
        .map(|arg| {
            arg.to_str()
                .map(str::to_owned)
                .context("command argument is not valid UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    match command {
        "run" => runner::cli(&args),
        "store" => store::cli(&args),
        "git" => git::cli(&args),
        "security" => security::cli(&args),
        _ => unreachable!(),
    }
}

fn main() {
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    let code = match dispatch() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sec: {error:#}");
            1
        }
    };
    if code != 0 {
        process::exit(code);
    }
}

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::{
    common as c,
    git::{self, Git},
    platform,
    store::{self, Store},
};

fn parse(source: &str) -> Result<(&str, String)> {
    let (base, pin) = source.split_once('#').unwrap_or((source, ""));
    let url = base
        .strip_prefix("git+ssh://")
        .or_else(|| base.strip_prefix("git+https://"))
        .context("unsupported Git store URL")?;
    ensure!(
        !base
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '?'),
        "invalid Git URL characters"
    );
    let (host, path) = url.split_once('/').context("Git URL needs a path")?;
    let (user, server) = host.rsplit_once('@').unwrap_or(("", host));
    ensure!(
        !server.is_empty()
            && !server.starts_with('-')
            && !server.contains('%')
            && !path.is_empty()
            && !user.starts_with('-')
            && !user.contains([':', '%', '@'])
            && (!base.starts_with("git+https://") || !host.contains('@')),
        "invalid host or user in Git URL"
    );
    ensure!(
        !source.contains('#') || git::valid_oid(pin),
        "pin a full Git commit ID"
    );
    Ok((base, pin.to_ascii_lowercase()))
}

fn authorization(origin: &str, pin: &str) -> Result<Value> {
    c::record("remote", &[origin, pin])?
        .or(c::record("remote", &[origin, "signed"])?)
        .with_context(|| {
            format!("unapproved remote {origin:?}; use sec store remote-git trust SOURCE")
        })
}

fn cache() -> Result<PathBuf> {
    let directory = c::var("SEC_STORE_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or(c::base("XDG_CACHE_HOME", ".cache", "LOCALAPPDATA")?.join("sec/stores"));
    platform::create_dirs(&directory)?;
    platform::private_dir(&directory)?;
    Ok(directory.canonicalize()?)
}

fn cache_lock(root: &Path) -> Result<File> {
    let file = root.join(".lock");
    match platform::open_identity(&file) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let _ = c::write_new(&file, b"");
        }
        Err(error) => return Err(error.into()),
    }
    let lock = OpenOptions::new().read(true).write(true).open(&file)?;
    lock.lock()?;
    Ok(lock)
}

fn snapshot_name(name: &str) -> bool {
    name.strip_prefix("snap.")
        .is_some_and(|token| !token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn pointer(path: &Path) -> Result<Option<String>> {
    let Some(current) = c::optional(&path.join("current"), 128)? else {
        return Ok(None);
    };
    let current = c::utf8(&current)?.trim_end_matches(['\r', '\n']);
    ensure!(snapshot_name(current), "invalid snapshot pointer");
    Ok(Some(current.into()))
}

fn cache_size(root: &Path) -> Result<u64> {
    let mut size = 0u64;
    for item in fs::read_dir(root)? {
        let item = item?;
        let metadata = fs::symlink_metadata(item.path())?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "symlink in remote cache"
        );
        if metadata.is_dir() {
            size = size.saturating_add(cache_size(&item.path())?);
        } else {
            size = size.saturating_add(metadata.len());
        }
    }
    Ok(size)
}

pub fn lease(store: &Store) -> Result<File> {
    let file = platform::lease_file(&store.root)?;
    file.lock_shared()?;
    ensure!(
        store.root.is_dir(),
        "snapshot changed while it was acquired"
    );
    Ok(file)
}

fn verify(
    origin: &str,
    pin: &str,
    trust: &Value,
    path: &Path,
    materialize: bool,
) -> Result<String> {
    platform::private_dir(path)?;
    let repository = path.join(".sec-remote-git");
    platform::private_dir(&repository)?;
    let git = Git::isolated(&repository);
    let commit = if materialize {
        git.text(&["rev-parse", "FETCH_HEAD^{commit}"])?
    } else {
        ensure!(
            c::utf8(&c::read(&path.join(".sec-remote-source"), c::CONFIG)?)?.trim_end() == origin,
            "snapshot origin mismatch"
        );
        c::utf8(&c::read(&path.join(".sec-remote-commit"), 128)?)?
            .trim_end()
            .to_owned()
    };
    ensure!(
        git::valid_oid(&commit) && (pin.is_empty() || commit == pin),
        "snapshot commit does not match its pin"
    );
    if let Some(keys) = trust["signers"].as_str() {
        git::verify_commit(&git, &commit, &STANDARD.decode(keys)?)?;
    } else {
        ensure!(trust["pin"] == commit, "snapshot has an unapproved commit");
    }
    let files = git::tree(&git, &commit, "")?;
    ensure!(
        files.iter().any(|(name, _)| name.starts_with("secrets/")),
        "verified remote has no managed secrets"
    );
    if materialize {
        for (name, data) in &files {
            let target = path.join(name);
            platform::create_dirs(target.parent().unwrap())?;
            c::write_new(&target, data)?;
        }
        c::write_new(
            &path.join(".sec-remote-source"),
            format!("{origin}\n").as_bytes(),
        )?;
        c::write_new(
            &path.join(".sec-remote-commit"),
            format!("{commit}\n").as_bytes(),
        )?;
    } else {
        let expected = files
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>();
        let mut actual = BTreeSet::new();
        for item in fs::read_dir(path)? {
            let item = item?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF-8 snapshot path"))?;
            let kind = item.file_type()?;
            ensure!(!kind.is_symlink(), "symlink in verified snapshot");
            match name.as_str() {
                ".sec-remote-git" if kind.is_dir() => {}
                ".sec-remote-source" | ".sec-remote-commit" if kind.is_file() => {}
                "secrets" | "manifests" if kind.is_dir() => {
                    for (entry, _) in c::lines(&item.path())? {
                        actual.insert(format!("{name}/{entry}"));
                    }
                }
                _ if kind.is_file() => {
                    actual.insert(name);
                }
                _ => bail!("unverified directory in remote snapshot: {name:?}"),
            }
        }
        ensure!(
            actual.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected,
            "snapshot has unexpected or missing files"
        );
        for (name, bytes) in &files {
            ensure!(
                c::read(&path.join(name), c::CIPHER)? == *bytes,
                "snapshot differs from its verified tree at {name:?}"
            );
        }
        let store = Store {
            root: path.to_owned(),
            origin: origin.into(),
            remote: true,
        };
        for (name, bytes) in files {
            if name.starts_with("secrets/") && name.ends_with(".age") {
                store::certify(&store, &path.join(name), &bytes, None)?;
            }
        }
    }
    Ok(commit)
}

fn fetch(
    origin: &str,
    pin: &str,
    trust: &Value,
    path: &Path,
    previous: Option<&str>,
) -> Result<String> {
    ensure!(
        !c::on("SEC_STORE_OFFLINE"),
        "remote store unavailable in offline mode"
    );
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "snapshot destination must be empty"
    );
    let repository = path.join(".sec-remote-git");
    let mut init = vec!["init", "--quiet", "--bare", "--template="];
    if pin.len() == 64 {
        init.push("--object-format=sha256");
    }
    let name = c::path_string(&repository)?;
    init.push(&name);
    Git::isolated(path).run(&init)?;
    platform::private_dir(&repository)?;
    let git = Git::isolated(&repository);
    let depth = if pin.is_empty() && previous.is_some() {
        "64"
    } else {
        "1"
    };
    let target = if pin.is_empty() { "HEAD" } else { pin };
    git.run(&[
        "fetch",
        "--quiet",
        "--force",
        "--no-tags",
        "--depth",
        depth,
        "--",
        &origin[4..],
        target,
    ])?;
    let commit = verify(origin, pin, trust, path, true)?;
    if pin.is_empty()
        && let Some(old) = previous
    {
        ensure!(
            git::valid_oid(old) && git.status(&["merge-base", "--is-ancestor", old, &commit])?,
            "remote history does not advance the last accepted snapshot"
        );
    }
    Ok(commit)
}

pub fn resolve(source: &str, update: bool) -> Result<Store> {
    let (origin, pin) = parse(source)?;
    let trust = authorization(origin, &pin)?;
    let root = cache()?;
    let _lock = cache_lock(&root)?;
    // Match the cache identifier used by the existing scripts.
    let id = Git::local(&env::current_dir()?)
        .input(&["hash-object", "--stdin"], source.as_bytes().to_vec())?;
    let id = c::utf8(&id)?.trim_end();
    ensure!(git::valid_oid(id), "invalid source identifier");
    let parent = root.join(id);
    platform::create_dirs(&parent)?;
    platform::private_dir(&parent)?;
    let current = pointer(&parent)?;
    if !update && let Some(name) = current {
        let path = parent.join(name);
        verify(origin, &pin, &trust, &path, false)?;
        return Ok(Store {
            root: path,
            origin: origin.into(),
            remote: true,
        });
    }
    ensure!(
        cache_size(&root)? < 256 * c::CONFIG as u64,
        "remote cache quota reached; run sec store cache prune"
    );
    let mut previous = c::record::<Value>("remote-head", &origin)?
        .and_then(|record| record["commit"].as_str().map(str::to_owned));
    if previous.is_none()
        && let Some(name) = &current
    {
        let value = c::read(&parent.join(name).join(".sec-remote-commit"), 128)?;
        previous = Some(c::utf8(&value)?.trim_end().to_owned());
    }
    let temporary = tempfile::Builder::new()
        .prefix(".fetch.")
        .tempdir_in(&parent)?;
    let commit = fetch(origin, &pin, &trust, temporary.path(), previous.as_deref())?;
    ensure!(
        cache_size(&root)? <= 256 * c::CONFIG as u64,
        "new snapshot would exceed the cache quota"
    );
    let token = temporary.path().file_name().unwrap().to_string_lossy();
    let name = format!(
        "snap.{}",
        token
            .strip_prefix(".fetch.")
            .context("invalid snapshot token")?
    );
    ensure!(snapshot_name(&name), "invalid snapshot name");
    let path = parent.join(&name);
    fs::rename(temporary.path(), &path)?;
    verify(origin, &pin, &trust, &path, false)?;
    if pin.is_empty() {
        c::write_record("remote-head", &origin, &json!({"commit": commit}))?;
    }
    let pointer = parent.join("current");
    let previous = c::optional(&pointer, 128)?;
    platform::atomic_replace(
        &pointer,
        previous.as_deref(),
        format!("{name}\n").as_bytes(),
    )?;
    Ok(Store {
        root: path,
        origin: origin.into(),
        remote: true,
    })
}

pub fn prune() -> Result<()> {
    prune_path(&cache()?)
}

fn prune_path(cache: &Path) -> Result<()> {
    platform::private_dir(cache)?;
    let _lock = cache_lock(cache)?;
    for item in fs::read_dir(cache)? {
        let item = item?;
        if !git::valid_oid(&item.file_name().to_string_lossy()) {
            continue;
        }
        let parent = item.path();
        platform::private_dir(&parent)?;
        let Some(current) = pointer(&parent)? else {
            continue;
        };
        for snapshot in fs::read_dir(parent)? {
            let snapshot = snapshot?;
            let name = snapshot.file_name();
            let name = name.to_string_lossy();
            if name == current || !snapshot_name(&name) {
                continue;
            }
            let path = snapshot.path();
            platform::private_dir(&path)?;
            let file = platform::lease_file(&path)?;
            match file.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => continue,
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                Ok(()) => {}
            }
            #[cfg(windows)]
            drop(file); // The cache lock prevents concurrent resolution throughout removal.
            fs::remove_dir_all(&path)?;
            println!("removed {}", path.display());
        }
    }
    Ok(())
}

pub fn cli(args: &[String]) -> Result<i32> {
    match args {
        [flag] if matches!(flag.as_str(), "--version" | "-V" | "version") => {
            println!("sec-store-remote-git {}", env!("CARGO_PKG_VERSION"))
        }
        [cmd, source] | [cmd, source, _] if cmd == "trust" => {
            let (origin, pin) = parse(source)?;
            if args.get(2).is_some_and(|arg| arg == "--signed") {
                let signers = git::signers()?;
                c::confirm(
                    "Trust SSH-signed remote revisions",
                    [
                        format!("{origin:?}"),
                        format!("signers SHA-256: {}", c::sha(&signers)),
                    ],
                )?;
                c::write_record(
                    "remote",
                    &[origin, "signed"],
                    &json!({"signers": STANDARD.encode(signers)}),
                )?;
            } else {
                ensure!(
                    args.len() == 2 && !pin.is_empty(),
                    "use an exact commit pin or --signed"
                );
                c::confirm(
                    "Trust this exact Git store revision",
                    [format!("{origin:?}"), pin.clone()],
                )?;
                c::write_record("remote", &[origin, &pin], &json!({"pin": pin}))?;
            }
        }
        [cmd, source, path] if matches!(cmd.as_str(), "fetch" | "update" | "check") => {
            let (origin, pin) = parse(source)?;
            let trust = authorization(origin, &pin)?;
            let path = PathBuf::from(path).canonicalize()?;
            platform::private_dir(&path)?;
            if cmd == "check" {
                verify(origin, &pin, &trust, &path, false)?;
            } else {
                let previous = c::record::<Value>("remote-head", &origin)?
                    .and_then(|r| r["commit"].as_str().map(str::to_owned));
                let commit = fetch(origin, &pin, &trust, &path, previous.as_deref())?;
                if pin.is_empty() {
                    c::write_record("remote-head", &origin, &json!({"commit": commit}))?;
                }
            }
        }
        _ => bail!("invalid remote Git command or arguments. Run sec store remote-git --help"),
    }
    Ok(0)
}

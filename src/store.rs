use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{common as c, config, crypto, git, platform, remote};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store {
    pub root: PathBuf,
    pub origin: String,
    pub remote: bool,
}

impl Store {
    pub fn local(root: PathBuf) -> Result<Self> {
        Ok(Self {
            origin: c::path_string(&root)?,
            root,
            remote: false,
        })
    }

    pub fn path(&self, name: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("secrets")
            .join(format!("{}.age", entry(name)?)))
    }

    pub fn relative(&self, path: &Path) -> Result<String> {
        path.strip_prefix(&self.root)?
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .ok_or_else(|| anyhow!("invalid store path"))
            })
            .collect::<Result<Vec<_>>>()
            .map(|parts| parts.join("/"))
    }

    pub fn check_root(&self) -> Result<()> {
        ensure!(
            fs::symlink_metadata(self.root.join("secrets"))
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()),
            "store has no real secrets directory; run sec store init",
        );
        Ok(())
    }
}

pub fn personal() -> Result<PathBuf> {
    let path = c::base("XDG_DATA_HOME", ".local/share", "APPDATA")?.join("sec");
    physical(path)
}

fn physical(path: PathBuf) -> Result<PathBuf> {
    match fs::canonicalize(&path) {
        Ok(value) => Ok(value),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(std::path::absolute(path)?),
        Err(error) => Err(error.into()),
    }
}

pub fn project() -> Result<Option<PathBuf>> {
    let cwd = env::current_dir()?.canonicalize()?;
    for folder in cwd.ancestors() {
        let path = folder.join(".sec");
        match fs::symlink_metadata(&path) {
            Ok(info) if info.is_dir() && !info.file_type().is_symlink() => return Ok(Some(path)),
            Ok(_) => bail!(
                "project .sec must be a real directory; use SEC_STORE_DIR for an explicit path"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

pub fn selected() -> Result<Store> {
    let path = if let Some(path) = c::var("SEC_STORE_DIR") {
        physical(path.into())?
    } else if let Some(path) = project()? {
        path
    } else {
        ensure!(
            !c::on("SEC_STORE_REQUIRE_PROJECT"),
            "no project store found"
        );
        personal()?
    };
    Store::local(path)
}

pub fn is_personal(store: &Store) -> bool {
    personal().is_ok_and(|root| store.root == root)
}

pub fn alias_ok(alias: &str) -> bool {
    let mut s = alias.bytes();
    s.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

pub fn reference(value: &str) -> Result<(Option<&str>, &str)> {
    if let Some((alias, path)) = value.split_once("::") {
        ensure!(
            alias_ok(alias) && !path.contains(':'),
            "invalid store reference {value:?}"
        );
        Ok((Some(alias), path))
    } else {
        ensure!(!value.contains(':'), "invalid store reference {value:?}");
        Ok((None, value))
    }
}

pub fn entry(value: &str) -> Result<&str> {
    let value = value.strip_suffix(".age").unwrap_or(value);
    c::managed(value)?;
    ensure!(
        !value.ends_with(".age") && value.rsplit('/').next() != Some(".recipients"),
        "invalid secret name {value:?}"
    );
    Ok(value)
}

fn aliases_file(data: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut aliases = BTreeMap::new();
    for (number, line) in c::utf8(data)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2 && alias_ok(fields[0]) && fields[0] != "personal",
            "invalid store declaration at line {}",
            number + 1
        );
        let source = fields[1];
        ensure!(
            source.starts_with("file:///")
                || source == "file://~"
                || source.starts_with("file://~/")
                || source.starts_with("git+ssh://")
                || source.starts_with("git+https://"),
            "unsupported store source at line {}",
            number + 1
        );
        ensure!(
            aliases.insert(fields[0].into(), source.into()).is_none(),
            "duplicate store alias at line {}",
            number + 1
        );
    }
    Ok(aliases)
}

pub fn aliases(store: &Store, project_only: bool) -> Result<BTreeMap<String, String>> {
    let mut list = BTreeMap::new();
    if !project_only && !is_personal(store) {
        let data = c::optional(&personal()?.join("stores"), c::CONFIG)?.unwrap_or_default();
        list.extend(aliases_file(&data)?);
    }
    let data = c::optional(&store.root.join("stores"), c::CONFIG)?.unwrap_or_default();
    list.extend(aliases_file(&data)?);
    Ok(list)
}

pub fn source(store: &Store, alias: &str, project_only: bool) -> Result<String> {
    ensure!(alias_ok(alias), "invalid store alias {alias:?}");
    if alias == "personal" {
        return Ok("builtin-personal".into());
    }
    aliases(store, project_only)?
        .remove(alias)
        .ok_or_else(|| anyhow!("unknown store alias {alias:?}"))
}

pub fn resolve(store: &Store, alias: &str, project_only: bool) -> Result<Store> {
    resolve_source(&source(store, alias, project_only)?, false)
}

fn resolve_source(source: &str, update: bool) -> Result<Store> {
    if source == "builtin-personal" {
        return Store::local(personal()?);
    }
    if let Some(location) = source.strip_prefix("file://") {
        let root = if location == "~" {
            c::home()?
        } else if let Some(relative) = location.strip_prefix("~/") {
            c::home()?.join(relative)
        } else {
            #[cfg(windows)]
            let location = location.trim_start_matches('/');
            PathBuf::from(location)
        };
        ensure!(
            root.is_absolute(),
            "file:// requires an absolute store path"
        );
        let store = Store::local(physical(root)?)?;
        store.check_root()?;
        return Ok(store);
    }
    remote::resolve(source, update)
}

pub fn recipient_lines(value: &[u8]) -> Result<Vec<String>> {
    let values = c::utf8(value)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(!values.is_empty(), "recipient policy is empty");
    for key in &values {
        config::validate_recipient(key)?;
    }
    Ok(values)
}

fn recipient_key(store: &Store, path: &Path, kind: &str) -> Result<Value> {
    let target = if path.starts_with(&store.root) {
        store.relative(path)?
    } else {
        c::path_string(path)?
    };
    Ok(json!([kind, c::path_string(&store.root)?, target]))
}

pub fn require_policy(store: &Store, path: &Path, kind: &str, approve: bool) -> Result<Vec<u8>> {
    let data = c::read(path, c::CONFIG)?;
    let recipients = recipient_lines(&data)?;
    let key = recipient_key(store, path, kind)?;
    let digest = c::sha(&data);
    if approve {
        c::confirm(
            "Approve recipient policy",
            std::iter::once(format!("{path:?}"))
                .chain(recipients.into_iter().map(|v| format!("{v:?}"))),
        )?;
        c::write_record(
            "policy",
            &key,
            &json!({"policy": digest, "path": c::path_string(path)?}),
        )?;
    } else {
        let record = c::record::<Value>("policy", &key)?.unwrap_or_default();
        ensure!(
            record["policy"] == digest,
            "recipient policy requires approval: {path:?}"
        );
    }
    Ok(data)
}

pub fn effective_policy(store: &Store, target: &Path) -> Result<Option<(PathBuf, Vec<u8>)>> {
    let secrets = store.root.join("secrets");
    ensure!(
        target.starts_with(&secrets),
        "recipient path escaped the store"
    );
    for directory in target
        .ancestors()
        .take_while(|path| path.starts_with(&secrets))
    {
        let path = directory.join(".recipients");
        if let Some(data) = c::optional(&path, c::CONFIG)? {
            return Ok(Some((path, data)));
        }
    }
    Ok(None)
}

fn encryption_policy(store: &Store, path: &Path) -> Result<Vec<u8>> {
    if let Some((file, data)) = effective_policy(store, path.parent().context("missing parent")?)? {
        if is_personal(store) {
            recipient_lines(&data)?;
            return Ok(data);
        }
        return require_policy(store, &file, "store", false);
    }
    ensure!(
        is_personal(store) || c::on("SEC_STORE_ALLOW_SELF"),
        "a project or team store needs an approved recipient policy"
    );
    platform::private_dir(&store.root)?;
    Ok(Vec::new())
}

pub fn cipher_key(store: &Store, path: &Path) -> Result<Value> {
    Ok(json!([c::path_string(&store.root)?, store.relative(path)?]))
}

pub fn certify(store: &Store, path: &Path, value: &[u8], policy: Option<&[u8]>) -> Result<()> {
    let mut record = json!({"digest": c::sha(value)});
    if let Some(policy) = policy {
        record["policy"] = json!(c::sha(policy));
    }
    let key = cipher_key(store, path)?;
    if c::record::<Value>("cipher", &key)? != Some(record.clone()) {
        c::write_record("cipher", &key, &record)?;
    }
    Ok(())
}

pub fn attest(store: &Store, path: &Path, data: &[u8], staging: bool) -> Result<()> {
    crypto::validate_cipher(data)?;
    if is_personal(store) {
        platform::private_dir(&store.root)?;
        return Ok(());
    }
    let policy = staging
        .then(|| encryption_policy(store, path))
        .transpose()?;
    let record = c::record::<Value>("cipher", &cipher_key(store, path)?)?.unwrap_or_default();
    if record["digest"] == c::sha(data)
        && policy
            .as_ref()
            .is_none_or(|p| record["policy"] == c::sha(p))
    {
        return Ok(());
    }
    if c::var("SEC_GIT_ALLOWED_SIGNERS").is_some()
        && git::attests_blob(store, path, data, policy.as_deref())?
    {
        return Ok(());
    }
    bail!(
        "unattested ciphertext {path:?}; verify provenance or run sec store check --attest after review"
    );
}

pub fn get(store: &Store, name: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    store.check_root()?;
    let _lease = if store.remote {
        Some(remote::lease(store)?)
    } else {
        None
    };
    let path = store.path(name)?;
    let cipher = c::read(&path, c::CIPHER)?;
    attest(store, &path, &cipher, false)?;
    crypto::decrypt_data(&cipher, limit)
}

fn encrypt(store: &Store, path: &Path, expected: Option<&[u8]>, data: &[u8]) -> Result<()> {
    let policy = encryption_policy(store, path)?;
    let legacy = if policy.is_empty() {
        config::legacy_self()?
    } else {
        None
    };
    let values = if policy.is_empty() {
        if legacy.is_none() {
            config::public_recipients()?
        } else {
            Vec::new()
        }
    } else {
        recipient_lines(&policy)?
    };
    let value = crypto::encrypt_keys(data, &values, legacy.as_deref(), c::on("SEC_ARMOR"))?;
    ensure!(
        encryption_policy(store, path)? == policy,
        "recipient policy changed during encryption"
    );
    platform::atomic_replace(path, expected, &value)?;
    certify(store, path, &value, Some(&policy))
}

fn initialize(store: &Store) -> Result<()> {
    platform::create_dirs(&store.root.join("secrets"))?;
    store.check_root()?;
    eprintln!("sec-store: store initialized at {:?}", store.root);
    Ok(())
}

fn read_store(store: &Store, value: &str) -> Result<(Store, String)> {
    let (alias, path) = reference(value)?;
    let selected = if let Some(alias) = alias {
        resolve(store, alias, c::on("SEC_STORE_PROJECT_ONLY"))?
    } else {
        store.clone()
    };
    Ok((selected, path.to_owned()))
}

pub fn list(store: &Store, prefix: &str) -> Result<Vec<String>> {
    let (alias, prefix) = reference(prefix)?;
    let store = if let Some(alias) = alias {
        resolve(store, alias, c::on("SEC_STORE_PROJECT_ONLY"))?
    } else {
        store.clone()
    };
    let _lease = if store.remote {
        Some(remote::lease(&store)?)
    } else {
        None
    };
    store.check_root()?;
    let prefix = if prefix.is_empty() {
        ""
    } else {
        entry(prefix.trim_end_matches('/'))?
    };
    let qualify =
        |name: &str| alias.map_or_else(|| name.to_owned(), |alias| format!("{alias}::{name}"));
    if !prefix.is_empty() && c::optional(&store.path(prefix)?, c::CIPHER)?.is_some() {
        return Ok(vec![qualify(prefix)]);
    }
    let root = store.root.join("secrets");
    let folder = root.join(prefix);
    let files = c::lines(&folder)?;
    Ok(files
        .iter()
        .filter_map(|(name, _)| name.strip_suffix(".age"))
        .map(|name| {
            qualify(&if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            })
        })
        .collect())
}

fn scope(store: &Store, target: &str) -> Result<PathBuf> {
    let root = store.root.join("secrets");
    if target == "." {
        return Ok(root);
    }
    let (target, forced_directory) = target
        .strip_suffix('/')
        .map_or((target, false), |n| (n, true));
    let forced_entry = !forced_directory && target.ends_with(".age");
    let name = entry(target)?;
    let path = store.path(name)?;
    let directory = root.join(name);
    let secret = c::optional(&path, c::CIPHER)?.is_some();
    let exists = fs::symlink_metadata(&directory).ok();
    if let Some(info) = &exists {
        ensure!(
            info.is_dir() && !info.file_type().is_symlink(),
            "invalid policy directory: {directory:?}"
        );
    }
    if forced_entry || (secret && !forced_directory) {
        ensure!(secret, "unknown secret {target:?}");
        ensure!(
            forced_entry || exists.is_none(),
            "ambiguous scope; use NAME/ or NAME.age"
        );
        Ok(path.parent().unwrap().to_owned())
    } else {
        Ok(directory)
    }
}

fn policy(store: &Store, args: &[String]) -> Result<()> {
    store.check_root()?;
    let what = args
        .first()
        .map(String::as_str)
        .context("specify a policy command")?;
    let target = args.get(1).map(String::as_str).unwrap_or(".");
    if matches!(what, "show" | "path")
        || !matches!(
            what,
            "approve" | "add" | "rm" | "edit" | "delete" | "del" | "d"
        )
    {
        let value = if matches!(what, "show" | "path") {
            target
        } else {
            what
        };
        let (store, name) = read_store(store, value)?;
        let root = store.root.join("secrets");
        let directory = if name == "." {
            root
        } else {
            let force_entry = name.ends_with(".age");
            let trimmed = name.trim_end_matches('/');
            let name = entry(trimmed)?;
            let dir = root.join(name);
            if !force_entry && fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
                dir
            } else {
                store.path(name)?.parent().unwrap().to_owned()
            }
        };
        if let Some((path, bytes)) = effective_policy(&store, &directory)? {
            if what == "show" {
                io::stdout().write_all(&bytes)?;
            } else {
                println!("{}", path.display());
            }
        } else if what == "show" {
            for key in config::public_recipients()? {
                println!("{key}");
            }
        } else {
            println!("self");
        }
        return Ok(());
    }
    let path = scope(store, target)?.join(".recipients");
    if what == "approve" {
        require_policy(store, &path, "store", true)?;
        return Ok(());
    }
    if matches!(what, "delete" | "del" | "d") {
        platform::remove_file(&path)?;
        return Ok(());
    }
    if matches!(what, "edit" | "add") {
        platform::create_dirs(path.parent().unwrap())?;
    }
    let before = c::optional(&path, c::CONFIG)?;
    let old = before.as_deref().unwrap_or_default();
    let changed = if what == "edit" {
        c::edit(&path, old, "SEC_STORE_EDITOR", false)?
    } else {
        let key = args.get(2).context("specify SCOPE and RECIPIENT")?;
        ensure!(args.len() == 3, "expected a single recipient");
        let key = if key == "self" {
            let values = config::public_recipients()?;
            ensure!(values.len() == 1, "self needs exactly one recipient");
            values[0].clone()
        } else {
            let values = recipient_lines(key.as_bytes())?;
            ensure!(values.len() == 1, "expected a single recipient");
            values[0].clone()
        };
        if before.is_some() {
            recipient_lines(old)?;
        }
        let mut lines = c::utf8(old)?.lines().map(str::to_owned).collect::<Vec<_>>();
        if what == "add" {
            if lines.contains(&key) {
                return Ok(());
            }
            lines.push(key);
        } else {
            ensure!(lines.contains(&key), "recipient is absent from exact scope");
            lines.retain(|line| line != &key);
        }
        (lines.join("\n") + "\n").into_bytes()
    };
    if old == changed {
        return Ok(());
    }
    recipient_lines(&changed)?;
    platform::atomic_replace(&path, before.as_deref(), &changed)?;
    Ok(())
}

fn rekey(store: &Store, prefix: &str) -> Result<()> {
    ensure!(
        reference(prefix)?.0.is_none(),
        "aliased entries are read-only"
    );
    let mut failures = 0;
    for name in list(store, prefix)? {
        let result = (|| {
            let path = store.path(&name)?;
            let current = c::read(&path, c::CIPHER)?;
            attest(store, &path, &current, false)?;
            let plaintext = crypto::decrypt_data(&current, c::SECRET)?;
            encrypt(store, &path, Some(&current), &plaintext)
        })();
        if let Err(error) = result {
            eprintln!("sec-store: cannot rekey {name:?}: {error:#}");
            failures += 1;
        } else {
            eprintln!("sec-store: {name:?} rekeyed");
        }
    }
    ensure!(failures == 0, "{failures} entries could not be rekeyed");
    Ok(())
}

fn check(store: &Store, args: &[String]) -> Result<()> {
    let mut strict = false;
    let mut adopt = false;
    let mut decrypt = c::on("SEC_STORE_CHECK_DECRYPT");
    for flag in args {
        match flag.as_str() {
            "--strict" => strict = true,
            "--decrypt" => decrypt = true,
            "--attest" => {
                adopt = true;
                strict = true;
                decrypt = true;
            }
            _ => bail!("unknown check option {flag:?}. Run sec store check --help"),
        }
    }
    let mut errors = 0;
    for (name, path) in c::lines(&store.root.join("secrets"))? {
        let result = (|| -> Result<()> {
            if name.rsplit('/').next() == Some(".recipients") {
                recipient_lines(&c::read(&path, c::CONFIG)?)?;
            } else {
                ensure!(name.ends_with(".age"), "unmanaged file");
                let data = c::read(&path, c::CIPHER)?;
                crypto::validate_cipher(&data)?;
                if decrypt {
                    match crypto::decrypt_data(&data, c::SECRET) {
                        Err(error) if !strict => {
                            println!("WARN   {name}  cannot decrypt: {error}");
                            return Ok(());
                        }
                        outcome => {
                            outcome?;
                        }
                    }
                }
                if adopt {
                    certify(store, &path, &data, None)?;
                }
            }
            println!("OK     {name}");
            Ok(())
        })();
        if let Err(error) = result {
            println!("ERROR  {name}  {error:#}");
            errors += 1;
        }
    }
    ensure!(errors == 0, "{errors} store checks failed");
    Ok(())
}

pub fn cli(args: &[String]) -> Result<i32> {
    let (action, args) = args.split_first().context("specify a store command")?;
    let action = action.as_str();
    if matches!(action, "version" | "--version" | "-V") {
        println!("sec-store {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if action == "remote-git" {
        return remote::cli(args);
    }
    if matches!(action, "fzf" | "otp" | "type") {
        return crate::desktop::cli(action, args);
    }
    let store = if action == "init" && args == ["--project"] {
        Store::local(env::current_dir()?.canonicalize()?.join(".sec"))?
    } else {
        selected()?
    };
    match (action, args) {
        ("init", [] | [_]) if args.is_empty() || args == ["--project"] => initialize(&store)?,
        ("dir", []) => println!("{}", store.root.display()),
        ("dir", [flag]) if flag == "--source" => {
            println!(
                "{}",
                if c::var("SEC_STORE_DIR").is_some() {
                    "explicit"
                } else if is_personal(&store) {
                    "personal"
                } else {
                    "project"
                }
            );
        }
        ("dir", [flag]) if flag == "--project" => {
            ensure!(
                project()?.is_some_and(|root| root == store.root),
                "selected store is not the current project's .sec"
            );
            println!("{}", store.root.display());
        }
        ("dir", [flag, alias]) if flag == "--source-url" => println!(
            "{}",
            source(&store, alias, c::on("SEC_STORE_PROJECT_ONLY"))?
        ),
        ("dir", [alias]) => println!(
            "{}",
            resolve(&store, alias, c::on("SEC_STORE_PROJECT_ONLY"))?
                .root
                .display()
        ),
        ("put", [name] | [name, _]) => {
            store.check_root()?;
            let path = store.path(name)?;
            platform::create_dirs(path.parent().unwrap())?;
            let current = c::optional(&path, c::CIPHER)?;
            let plaintext = Zeroizing::new(if let Some(file) = args.get(1) {
                c::read(Path::new(file), c::SECRET)?
            } else {
                c::bounded(io::stdin().lock(), c::SECRET)?
            });
            encrypt(&store, &path, current.as_deref(), &plaintext)?;
            eprintln!("sec-store: {name:?} stored");
        }
        ("get" | "get1", [name]) => {
            let (store, path) = read_store(&store, name)?;
            let data = get(&store, &path, c::SECRET)?;
            io::stdout().write_all(if action == "get1" {
                crate::desktop::first_line(&data)
            } else {
                &data
            })?;
        }
        ("edit", [name]) => {
            store.check_root()?;
            let path = store.path(name)?;
            platform::create_dirs(path.parent().unwrap())?;
            let current = c::optional(&path, c::CIPHER)?;
            let plain = if let Some(cipher) = &current {
                attest(&store, &path, cipher, false)?;
                crypto::decrypt_data(cipher, c::SECRET)?
            } else {
                Zeroizing::new(Vec::new())
            };
            let changed = Zeroizing::new(c::edit(&path, &plain, "SEC_STORE_EDITOR", true)?);
            if changed != plain {
                encrypt(&store, &path, current.as_deref(), &changed)?;
            }
        }
        ("ls", [] | [_]) => {
            for name in list(&store, args.first().map(String::as_str).unwrap_or(""))? {
                println!("{name}");
            }
        }
        ("search" | "s", [pattern] | [pattern, _]) => {
            let regex = regex::Regex::new(pattern)?;
            let mut any = false;
            for name in list(&store, args.get(1).map(String::as_str).unwrap_or(""))? {
                if regex.is_match(&name) {
                    println!("{name}");
                    any = true;
                }
            }
            return Ok(i32::from(!any));
        }
        ("rm", [_, ..]) => {
            store.check_root()?;
            for name in args {
                platform::remove_file(&store.path(name)?)?;
            }
        }
        ("policy", args) => policy(&store, args)?,
        ("rekey", [] | [_]) => rekey(&store, args.first().map(String::as_str).unwrap_or(""))?,
        ("check", args) => check(&store, args)?,
        ("stores", [cmd]) if cmd == "ls" || cmd == "l" => {
            for (alias, source) in aliases(&store, c::on("SEC_STORE_PROJECT_ONLY"))? {
                println!("{alias} {source}");
            }
            println!("personal file://{}", personal()?.display());
        }
        ("stores", [cmd]) if cmd == "path" => println!("{}", store.root.join("stores").display()),
        ("stores", [cmd]) if cmd == "edit" => {
            let target = store.root.join("stores");
            let before = c::optional(&target, c::CONFIG)?;
            let changed = c::edit(
                &target,
                before.as_deref().unwrap_or_default(),
                "SEC_STORE_EDITOR",
                false,
            )?;
            aliases_file(&changed)?;
            platform::atomic_replace(&target, before.as_deref(), &changed)?;
        }
        ("update", [alias]) if alias == "--all" => {
            let data = c::optional(&store.root.join("stores"), c::CONFIG)?.unwrap_or_default();
            for (alias, source) in aliases_file(&data)? {
                if source.starts_with("git+") {
                    resolve_source(&source, true)?;
                    eprintln!("sec-store: updated {alias:?}");
                }
            }
        }
        ("update", [alias]) => {
            resolve_source(
                &source(&store, alias, c::on("SEC_STORE_PROJECT_ONLY"))?,
                true,
            )?;
        }
        ("cache", [cmd]) if cmd == "prune" => remote::prune()?,
        ("git" | "g", args) => {
            let defaults = ["status".into()];
            return git::forward(&store.root, if args.is_empty() { &defaults } else { args });
        }
        ("y", args) => git::sync_store(&store, args)?,
        _ => bail!("invalid store command or arguments. Run sec store --help"),
    }
    Ok(0)
}

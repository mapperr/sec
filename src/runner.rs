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
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    common as c, platform, remote,
    store::{self, Store},
    supervisor,
};

type Prefix = (String, String, Option<String>, Option<String>);
type Row = Vec<String>;
type EnvNames = BTreeMap<String, Vec<String>>;

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Approval {
    plan: Vec<Row>,
    env_names: EnvNames,
    prefixes: Vec<Prefix>,
}

#[derive(Clone)]
struct Injection {
    mode: String,
    name: String,
    value: String,
    store: Option<Store>,
}

impl Injection {
    fn record(&self) -> Row {
        match &self.store {
            Some(source) => vec![
                self.mode.clone(),
                self.name.clone(),
                source.origin.clone(),
                self.value.clone(),
            ],
            None => vec![
                self.mode.clone(),
                self.name.clone(),
                c::sha(self.value.as_bytes()),
            ],
        }
    }

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

struct Manifest {
    refname: String,
    source: Store,
    path: String,
    commands: Vec<Injection>,
}

impl Manifest {
    fn plan(&self) -> Vec<Row> {
        let mut env = Vec::new();
        let mut other = Vec::new();
        for command in &self.commands {
            if command.mode == "env" {
                env.push(command.record());
            } else {
                other.push(command.record());
            }
        }
        other.sort();
        env.extend(other);
        env
    }

    fn key(&self, base: &Store, argv: &[String]) -> Result<[String; 4]> {
        Ok([
            c::path_string(&base.root)?,
            self.source.origin.clone(),
            self.path.clone(),
            c::sha(c::canonical(&argv)?),
        ])
    }

    fn allowed(&self, base: &Store, argv: &[String]) -> Result<EnvNames> {
        let binding = self.key(base, argv)?;
        let previous = c::record::<Approval>("manifest", &binding)?.with_context(|| {
            format!(
                "manifest {:?} requires approval; use sec run manifest approve",
                self.refname
            )
        })?;
        let plan = self.plan();
        if previous.plan != plan {
            let originals = plan
                .iter()
                .filter(|row| previous.plan.contains(row))
                .cloned()
                .collect::<Vec<_>>();
            let mut additions = plan
                .iter()
                .filter(|row| !previous.plan.contains(row))
                .peekable();
            let covered = additions.peek().is_some()
                && additions.all(|row| {
                    matches!(row[0].as_str(), "var" | "file")
                        && previous
                            .prefixes
                            .iter()
                            .any(|(origin, prefix, mode, name)| {
                                row[2] == *origin
                                    && row[3].starts_with(prefix)
                                    && mode.as_ref().is_none_or(|mode| row[0] == *mode)
                                    && name.as_ref().is_none_or(|name| row[1] == *name)
                            })
                });
            ensure!(
                originals == previous.plan && covered,
                "manifest {:?} requires approval; use sec run manifest approve",
                self.refname
            );
        }
        Ok(previous.env_names)
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

    fn path(&mut self, reference: &str, mutable: bool) -> Result<(Store, String, PathBuf)> {
        let direct = Path::new(reference);
        if !mutable
            && (direct.is_absolute() || reference.starts_with("./") || reference.starts_with("../"))
        {
            let path = c::absolute_path(direct)?;
            return Ok((self.base.clone(), c::path_string(&path)?, path));
        }
        let (alias, name) = store::reference(reference)?;
        ensure!(
            !mutable || alias.is_none(),
            "aliased manifests are read-only"
        );
        c::managed(name)?;
        let source = self.resolve(alias)?;
        Ok((
            source.clone(),
            format!("manifests/{name}"),
            source.root.join("manifests").join(name),
        ))
    }

    fn instruction(
        &mut self,
        mode: &str,
        value: &str,
        primary: Option<&Store>,
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
        let source = if alias.is_none()
            && let Some(primary) = primary
        {
            primary.clone()
        } else {
            self.resolve(alias)?
        };
        ensure!(
            !primary.is_some_and(|primary| primary.remote) || !store::is_personal(&source),
            "compose a personal manifest explicitly at the call site"
        );
        Ok(Injection {
            mode: mode.into(),
            name,
            value,
            store: Some(source),
        })
    }

    fn manifest(
        &mut self,
        reference: &str,
        optional: bool,
        load: bool,
    ) -> Result<Option<Manifest>> {
        let (source, id, path) = self.path(reference, false)?;
        let mut commands = Vec::new();
        if load {
            let Some(data) = c::optional(&path, c::CONFIG)? else {
                if optional {
                    return Ok(None);
                }
                bail!("manifest {reference:?} does not exist");
            };
            for (number, line) in c::utf8(&data)?.lines().enumerate() {
                let line = line.trim_start();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (mode, value) = line.split_once(char::is_whitespace).with_context(|| {
                    format!("invalid directive at {reference:?}:{}", number + 1)
                })?;
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
                commands.push(self.instruction(mode, value, Some(&source))?);
                ensure!(commands.len() <= 128, "manifest exceeds 128 directives");
            }
        }
        Ok(Some(Manifest {
            refname: reference.into(),
            source,
            path: id,
            commands,
        }))
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

fn target(command: &[String], output: Option<&str>) -> Result<Vec<String>> {
    if let Some(mode) = output {
        ensure!(
            command.is_empty(),
            "output modes cannot be combined with a command"
        );
        return Ok(vec!["output".into(), mode.into()]);
    }
    let first = command
        .first()
        .context("specify a command after -- or an output mode")?;
    let path = which::which(first)
        .with_context(|| format!("command {first:?} is unavailable"))?
        .canonicalize()?;
    if let Some(digest) = c::var("SEC_RUN_EXEC_SHA256") {
        pinned(&path, digest.to_str().context("invalid SHA-256 pin")?)?;
    }
    let mut binding = vec![c::path_string(&path)?];
    binding.extend_from_slice(command);
    Ok(binding)
}

fn pinned(path: &Path, hash: &str) -> Result<File> {
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
    Ok(file)
}

fn env_key(item: &Injection) -> Result<String> {
    Ok(c::sha(c::canonical(&item.record())?))
}

struct Arguments<'a> {
    flags: BTreeMap<&'a str, Vec<&'a str>>,
    output: Option<&'a str>,
}
impl<'a> Arguments<'a> {
    fn parse(args: &'a [String]) -> Result<Self> {
        let mut flags: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut output = None;
        let mut args = args.iter().map(String::as_str);
        while let Some(flag) = args.next() {
            match flag {
                "--print" | "--env-only" => {
                    ensure!(output.replace(flag).is_none(), "use only one output mode");
                }
                "--env-name" | "--entry" | "--prefix" | "--as" | "--mode" => {
                    flags
                        .entry(flag)
                        .or_default()
                        .push(args.next().context("missing flag argument")?);
                }
                _ => bail!("invalid approval argument {flag:?}"),
            }
        }
        Ok(Self { flags, output })
    }
    fn one(&self, name: &str) -> Result<Option<&'a str>> {
        let value = self.flags.get(name).map(Vec::as_slice).unwrap_or_default();
        ensure!(value.len() <= 1, "{name} may only be specified once");
        Ok(value.first().copied())
    }
}

fn manage(runner: &mut Runner, options: &[String], command: &[String]) -> Result<()> {
    let (action, args) = options
        .split_first()
        .context("specify a manifest command")?;
    let action = action.as_str();
    match action {
        "ls" | "l" if args.is_empty() && command.is_empty() => {
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
        "edit" | "e" | "rm" | "r" if !args.is_empty() && command.is_empty() => {
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
        "approve" | "revoke" | "grant" | "approvals" => {
            let (reference, args) = args.split_first().context("specify a manifest reference")?;
            let flags = Arguments::parse(args)?;
            let target = target(command, flags.output)?;
            let manifest = runner
                .manifest(reference, false, matches!(action, "approve" | "grant"))?
                .unwrap();
            let binding = manifest.key(&runner.base, &target)?;
            let previous = c::record::<Approval>("manifest", &binding)?;
            match action {
                "approvals" => {
                    ensure!(flags.flags.is_empty(), "unexpected approval arguments");
                    if let Some(record) = previous {
                        for row in record.plan {
                            println!("{:?}", if row[0] == "set" { &row[..2] } else { &row });
                        }
                        for prefix in record.prefixes {
                            println!("prefix {prefix:?}");
                        }
                    }
                }
                "approve" => {
                    ensure!(
                        flags.flags.keys().all(|name| *name == "--env-name"),
                        "unexpected approval arguments"
                    );
                    let existing = previous.is_some();
                    let mut record = previous.unwrap_or_default();
                    let plan = manifest.plan();
                    let names = flags
                        .flags
                        .get("--env-name")
                        .into_iter()
                        .flatten()
                        .map(|name| {
                            variable(name)?;
                            Ok(name.to_string())
                        })
                        .collect::<Result<BTreeSet<_>>>()?
                        .into_iter()
                        .collect::<Vec<_>>();
                    let mut envs = BTreeMap::new();
                    for entry in manifest.commands.iter().filter(|entry| entry.mode == "env") {
                        let key = env_key(entry)?;
                        let names = if names.is_empty() {
                            record
                                .env_names
                                .get(&key)
                                .cloned()
                                .context("approve env entries with --env-name NAME")?
                        } else {
                            names.clone()
                        };
                        envs.insert(key, names);
                    }
                    if existing && record.plan == plan && record.env_names == envs {
                        return Ok(());
                    }
                    let mut changes = vec![
                        format!("{:?}/{}", manifest.source.origin, manifest.path),
                        format!("command: {:?}", &target[1..]),
                    ];
                    for entry in &manifest.commands {
                        if !record.plan.contains(&entry.record()) {
                            changes.push(format!("+ {}", entry.describe()));
                        }
                    }
                    for row in &record.plan {
                        if !plan.contains(row) {
                            changes.push(format!(
                                "- {:?}",
                                if row[0] == "set" { &row[..2] } else { row }
                            ));
                        }
                    }
                    if envs != record.env_names {
                        let names = envs.values().flatten().cloned().collect::<BTreeSet<_>>();
                        changes.push(format!("allowed env names: {names:?}"));
                    }
                    if changes.len() == 2 && existing && record.plan != plan {
                        changes.push("environment import order changed".into());
                    }
                    c::confirm("Approve manifest injection", changes)?;
                    record.plan = plan;
                    record.env_names = envs;
                    c::write_record("manifest", &binding, &record)?;
                }
                "grant" | "revoke" => {
                    ensure!(
                        !flags.flags.contains_key("--env-name"),
                        "unexpected approval arguments"
                    );
                    let entry = flags.one("--entry")?;
                    let prefix = flags.one("--prefix")?;
                    let mode = flags.one("--mode")?;
                    let name = flags.one("--as")?;
                    ensure!(
                        entry.is_none() || prefix.is_none(),
                        "choose one of --entry or --prefix"
                    );
                    if let Some(mode) = mode {
                        ensure!(matches!(mode, "var" | "file"), "expected var or file");
                    }
                    if let Some(name) = name {
                        variable(name)?;
                    }
                    let Some(mut record) = previous else {
                        ensure!(action == "revoke", "approve the manifest's plan first");
                        return Ok(());
                    };
                    if let Some(prefix) = prefix {
                        let (alias, path) = store::reference(prefix.trim_end_matches('/'))?;
                        ensure!(alias.is_some(), "prefix grant requires ALIAS::PREFIX");
                        let origin = runner.resolve(alias)?;
                        ensure!(
                            !store::is_personal(&origin),
                            "personal entries require an explicit list"
                        );
                        let scope = (
                            origin.origin,
                            format!("{}/", c::managed(path)?),
                            mode.map(str::to_owned),
                            name.map(str::to_owned),
                        );
                        if action == "grant" {
                            if record.prefixes.contains(&scope) {
                                return Ok(());
                            }
                            c::confirm(
                                "Allow future entries under this team prefix",
                                [format!("{scope:?}")],
                            )?;
                            record.prefixes.push(scope);
                        } else {
                            record.prefixes.retain(|item| item != &scope);
                        }
                    } else if let Some(entry) = entry {
                        let mode = mode.context("an entry grant needs --mode")?;
                        let name = name.context("an entry grant needs --as")?;
                        let row = runner
                            .instruction(mode, &format!("{name}={entry}"), None)?
                            .record();
                        if action == "grant" {
                            let plan = manifest.plan();
                            ensure!(plan.contains(&row), "grant is absent from the manifest");
                            let mut updated = record.plan.clone();
                            if updated.contains(&row) {
                                return Ok(());
                            }
                            updated.push(row.clone());
                            updated.sort();
                            let mut observed = plan.clone();
                            observed.sort();
                            ensure!(
                                observed == updated,
                                "other plan changes require collective approval"
                            );
                            c::confirm("Approve additional manifest entry", [format!("{row:?}")])?;
                            record.plan = plan;
                        } else {
                            record.plan.retain(|item| item != &row);
                        }
                    } else {
                        ensure!(
                            action == "revoke" && flags.flags.is_empty(),
                            "specify --entry or --prefix"
                        );
                        return c::remove_record("manifest", &binding);
                    }
                    c::write_record("manifest", &binding, &record)?;
                }
                _ => unreachable!(),
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
        variable(name)?;
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

fn destination(item: &Injection, base: &Store) -> String {
    let source = item.store.as_ref().unwrap();
    if source.root == base.root {
        item.value.clone()
    } else {
        format!("{}/{}", &c::sha(source.origin.as_bytes())[..16], item.value)
    }
}

fn prepare(
    plan: &[(Injection, Option<usize>)],
    approvals: &[EnvNames],
    base: &Store,
    runtime: Option<&Path>,
) -> Result<Values> {
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (item, _) in plan {
        if item.mode != "env" {
            ensure!(
                names.insert(normalized(&item.name)),
                "duplicate injection variable: {:?}",
                item.name
            );
        }
        if item.mode == "file" {
            let target = normalized(&destination(item, base));
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
    for (item, manifest) in plan {
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
                if let Some(manifest) = manifest {
                    let key = env_key(item)?;
                    let names = approvals[*manifest]
                        .get(&key)
                        .context("environment entry has no approved names")?;
                    ensure!(
                        decoded.keys().all(|key| names.contains(key)),
                        "environment entry contains an unapproved variable"
                    );
                }
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
                    let file = runtime.join(destination(item, base));
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
        manage(&mut runner, &options[1..], command)?;
        return Ok(0);
    }
    let mut output = None;
    let mut plan = Vec::new();
    let mut manifest_refs = Vec::new();
    let mut manifests = Vec::new();
    let mut options = options.iter().map(String::as_str);
    while let Some(option) = options.next() {
        let mode = match option {
            "--print" | "--env-only" => {
                ensure!(output.replace(option).is_none(), "use only one output mode");
                continue;
            }
            "-m" | "--manifest" | "-M" | "--optional-manifest" => {
                let name = options.next().context("missing manifest reference")?;
                let found =
                    runner.manifest(name, matches!(option, "-M" | "--optional-manifest"), true)?;
                manifest_refs.push((name, found.is_some()));
                if let Some(found) = found {
                    plan.extend(
                        found
                            .commands
                            .iter()
                            .cloned()
                            .map(|item| (item, Some(manifests.len()))),
                    );
                    manifests.push(found);
                }
                continue;
            }
            "-e" | "--env" => "env",
            "-v" | "--var" => "var",
            "-s" | "--set" => "set",
            "-f" | "--file" => "file",
            _ => bail!("invalid injection flag {option:?}. Run sec run --help"),
        };
        let value = options.next().context("missing injection argument")?;
        plan.push((runner.instruction(mode, value, None)?, None));
    }
    ensure!(
        !manifest_refs.is_empty() || !plan.is_empty(),
        "specify at least one injection or manifest"
    );
    ensure!(plan.len() <= 128, "injection plan exceeds 128 directives");
    if output.is_none() && command.is_empty() {
        for (name, present) in manifest_refs {
            println!(
                "Manifest {name:?} ({})",
                if present {
                    "approval checked when launching"
                } else {
                    "absent (optional)"
                }
            );
        }
        for (item, _) in plan {
            println!("{}", item.describe());
        }
        return Ok(0);
    }
    let target = target(command, output)?;
    let approvals = manifests
        .iter()
        .map(|manifest| manifest.allowed(&runner.base, &target))
        .collect::<Result<Vec<_>>>()?;
    if command.is_empty() {
        ensure!(
            output != Some("--env-only") || !plan.iter().any(|(item, _)| item.mode == "file"),
            "--env-only does not accept file entries"
        );
        let env = prepare(&plan, &approvals, &runner.base, None)?;
        let mut stdout = io::stdout().lock();
        for (name, value) in env {
            write!(stdout, "{name}=")?;
            stdout.write_all(&value)?;
            stdout.write_all(b"\n")?;
        }
        if output == Some("--print") {
            for (item, _) in &plan {
                if item.mode == "file" {
                    writeln!(stdout, "{}=<SEC_RUN_DIR>/{}", item.name, item.value)?;
                }
            }
            writeln!(stdout, "SEC_RUN_DIR=<temporary directory>")?;
        }
        return Ok(0);
    }
    let (workspace, lease) = workspace()?;
    let runtime = workspace.path().join("files");
    platform::create_dirs(&runtime)?;
    let env = prepare(&plan, &approvals, &runner.base, Some(&runtime))?;
    let executable = c::var("SEC_RUN_EXEC_SHA256")
        .map(|hash| {
            pinned(
                Path::new(&target[0]),
                hash.to_str().context("invalid SHA-256 pin")?,
            )
        })
        .transpose()?;
    let mut child = Command::new(supervisor::program(&target[0], executable.as_ref()));
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

use std::{
    env,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use globset::{Glob, GlobSetBuilder};
use serde_json::{Value, json};

use crate::{
    common as c, crypto, platform,
    store::{self, Store},
};

pub struct Git<'a> {
    pub root: &'a Path,
    pub isolated: bool,
}

impl<'a> Git<'a> {
    pub fn local(root: &'a Path) -> Self {
        Self {
            root,
            isolated: false,
        }
    }
    pub fn isolated(root: &'a Path) -> Self {
        Self {
            root,
            isolated: true,
        }
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command.arg("--no-replace-objects").arg("-C").arg(self.root);
        if self.isolated {
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                // Constrain each incoming pack or blob file while Git is running.
                unsafe {
                    command.process_group(0).pre_exec(|| {
                        let mut limit = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        if libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        limit.rlim_cur = limit.rlim_cur.min(80 * 1024 * 1024);
                        if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            command.env_clear();
            for name in [
                "PATH",
                "HOME",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "SystemRoot",
                "TEMP",
                "TMP",
                "SSH_AUTH_SOCK",
            ] {
                if let Some(value) = c::var(name) {
                    command.env(name, value);
                }
            }
            let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", null)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("LC_ALL", "C");
            for (source, name) in [
                ("SEC_STORE_GIT_CAINFO", "GIT_SSL_CAINFO"),
                ("SEC_STORE_GIT_ASKPASS", "GIT_ASKPASS"),
            ] {
                if let Some(value) = c::var(source) {
                    command.env(name, value);
                }
            }
            command.args([
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.ssh.allow=always",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "-c",
                "fetch.fsckObjects=true",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.sshCommand=ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes",
            ]);
        }
        command.args(args);
        command
    }

    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        c::run(&mut self.command(args), None, c::CIPHER)
    }

    pub fn input(&self, args: &[&str], input: Vec<u8>) -> Result<Vec<u8>> {
        c::run(&mut self.command(args), Some(input), c::CIPHER)
    }

    pub fn text(&self, args: &[&str]) -> Result<String> {
        Ok(c::utf8(&self.run(args)?)?
            .trim_end_matches(['\r', '\n'])
            .to_owned())
    }

    pub fn optional(&self, args: &[&str]) -> Result<Option<Vec<u8>>> {
        let result = c::capture(&mut self.command(args), None, c::CIPHER, 60)?;
        Ok(result.status.success().then_some(result.out))
    }

    pub fn status(&self, args: &[&str]) -> Result<bool> {
        Ok(self.optional(args)?.is_some())
    }
}

pub fn forward(root: &Path, args: &[String]) -> Result<i32> {
    let status = Git::local(root)
        .command(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .status()?;
    Ok(status.code().unwrap_or(1))
}

pub fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn signers() -> Result<Vec<u8>> {
    let path =
        PathBuf::from(c::var("SEC_GIT_ALLOWED_SIGNERS").context("set SEC_GIT_ALLOWED_SIGNERS")?);
    ensure!(path.is_absolute(), "signer policy must be an absolute path");
    // Owners can publish public trust roots, but group/other writers cannot.
    crate::platform::read_trusted(&path, c::CONFIG)
}

pub fn verify_commit(git: &Git<'_>, oid: &str, signers: &[u8]) -> Result<()> {
    ensure!(valid_oid(oid), "invalid commit identifier");
    let commit = git.run(&["cat-file", "commit", oid])?;
    let headers = commit
        .split(|b| *b == b'\n')
        .take_while(|line| !line.is_empty());
    ensure!(
        headers.into_iter().any(
            |line| line.starts_with(b"gpgsig -----BEGIN SSH SIGNATURE-----")
                || line.starts_with(b"gpgsig-sha256 -----BEGIN SSH SIGNATURE-----")
        ),
        "commit has no SSH signature"
    );
    let temporary = c::workspace(None)?;
    let allowed = temporary.path().join("allowed");
    c::write_new(&allowed, signers)?;
    let argument = format!("gpg.ssh.allowedSignersFile={}", allowed.display());
    ensure!(
        git.status(&[
            "-c",
            &argument,
            "-c",
            "gpg.ssh.program=ssh-keygen",
            "verify-commit",
            oid
        ])?,
        "commit signature is not trusted"
    );
    Ok(())
}

fn root_path() -> Result<PathBuf> {
    let cwd = env::current_dir()?;
    Ok(PathBuf::from(Git::local(&cwd).text(&["rev-parse", "--show-toplevel"])?).canonicalize()?)
}

enum Kind {
    Cipher,
    Policy,
    Metadata,
}

fn layout(path: &str) -> Result<Kind> {
    c::managed(path)?;
    if path.starts_with("secrets/") && path.rsplit('/').next() == Some(".recipients") {
        Ok(Kind::Policy)
    } else if path.starts_with("secrets/") && path.ends_with(".age") && !path.ends_with(".age.age")
    {
        Ok(Kind::Cipher)
    } else if path.starts_with("manifests/")
        || matches!(path, "stores" | "README.md" | "LICENSE" | ".gitignore")
    {
        Ok(Kind::Metadata)
    } else {
        bail!("unmanaged file in store: {path:?}");
    }
}

fn validate(kind: &Kind, data: &[u8]) -> Result<()> {
    match kind {
        Kind::Cipher => crypto::validate_cipher(data)?,
        Kind::Policy => {
            store::recipient_lines(data)?;
        }
        Kind::Metadata => {
            c::utf8(data)?;
            ensure!(
                !data.contains(&0) && !data.starts_with(b"AGE-SECRET-KEY-"),
                "unexpected binary or private key data in metadata"
            );
        }
    }
    Ok(())
}

fn limit(kind: &Kind) -> usize {
    if matches!(kind, Kind::Cipher) {
        c::CIPHER
    } else {
        c::CONFIG
    }
}

fn names(data: &[u8]) -> Result<Vec<&str>> {
    data.split(|&byte| byte == 0)
        .filter(|name| !name.is_empty())
        .map(c::utf8)
        .collect()
}

pub fn tree(git: &Git<'_>, oid: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
    ensure!(valid_oid(oid), "invalid commit identifier");
    let mut args = vec!["ls-tree", "-rz", "--full-tree", oid];
    if !prefix.is_empty() {
        args.extend(["--", prefix.trim_end_matches('/')]);
    }
    let data = git.run(&args)?;
    ensure!(data.len() <= c::CONFIG, "tree exceeds the path limit");
    let mut total = 0;
    let mut result = Vec::new();
    for row in names(&data)? {
        let (info, path) = row.split_once('\t').context("invalid tree entry")?;
        let info = info.split(' ').collect::<Vec<_>>();
        ensure!(
            info.len() == 3
                && matches!(info[0], "100644" | "100755")
                && info[1] == "blob"
                && valid_oid(info[2]),
            "store contains a symlink, submodule or unsupported mode"
        );
        let path = path
            .strip_prefix(prefix)
            .context("tree path escaped the store")?;
        let kind = layout(path)?;
        let size: usize = git.text(&["cat-file", "-s", info[2]])?.parse()?;
        total += size.min(64 * c::CONFIG + 1);
        ensure!(
            size <= limit(&kind) && total <= 64 * c::CONFIG,
            "store exceeds the size limit"
        );
        let bytes = git.run(&["cat-file", "blob", info[2]])?;
        validate(&kind, &bytes)?;
        result.push((path.into(), bytes));
    }
    Ok(result)
}

pub fn attests_blob(
    store: &Store,
    path: &Path,
    data: &[u8],
    policy: Option<&[u8]>,
) -> Result<bool> {
    let git = Git::local(&store.root);
    let Some(oid) = git.optional(&["rev-parse", "--verify", "HEAD^{commit}"])? else {
        return Ok(false);
    };
    let oid = c::utf8(&oid)?.trim();
    verify_commit(&git, oid, &signers()?)?;
    let prefix = git.text(&["rev-parse", "--show-prefix"])?;
    let path = store.relative(path)?;
    if git
        .optional(&["show", &format!("{oid}:{prefix}{path}")])?
        .as_deref()
        != Some(data)
    {
        return Ok(false);
    }
    if let Some(policy) = policy {
        let mut directory = Path::new(&path).parent();
        while let Some(parent) = directory.filter(|p| p.starts_with("secrets")) {
            let relative = parent
                .join(".recipients")
                .to_string_lossy()
                .replace('\\', "/");
            if let Some(bytes) = git.optional(&["show", &format!("{oid}:{prefix}{relative}")])? {
                return Ok(bytes == policy);
            }
            directory = parent.parent();
        }
        return Ok(policy.is_empty());
    }
    Ok(true)
}

fn protect_policy(root: &Store, path: &Path, value: &[u8]) -> Result<()> {
    if !store::is_personal(root) {
        ensure!(
            store::require_policy(root, path, "store", false)? == value,
            "policy changed during validation"
        );
    }
    Ok(())
}

pub fn stage_store(store: &Store) -> Result<()> {
    let git = Git::local(&store.root);
    let list = git.run(&[
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        ".",
    ])?;
    ensure!(list.len() <= c::CONFIG, "too many paths in store");
    let mut files = names(&list)?;
    files.sort_unstable();
    files.dedup();
    let mut tree = Vec::new();
    let mut total = 0;
    for name in files {
        let kind = layout(name)?;
        let path = store.root.join(name);
        let value = c::optional(&path, limit(&kind))?;
        if let Some(value) = &value {
            total += value.len();
            ensure!(
                total <= 64 * c::CONFIG,
                "store exceeds the staging size limit"
            );
            validate(&kind, value)?;
            match kind {
                Kind::Cipher => store::attest(store, &path, value, true)?,
                Kind::Policy => protect_policy(store, &path, value)?,
                Kind::Metadata => {}
            }
        }
        tree.push((name, value));
    }
    let length = if git.text(&["rev-parse", "--show-object-format"])? == "sha256" {
        64
    } else {
        40
    };
    let prefix = git.text(&["rev-parse", "--show-prefix"])?;
    let mut updates = Vec::new();
    for (path, value) in tree {
        let (mode, oid) = if let Some(bytes) = value {
            (
                "100644",
                c::utf8(&git.input(&["hash-object", "-w", "--stdin"], bytes)?)?
                    .trim()
                    .to_owned(),
            )
        } else {
            ("0", "0".repeat(length))
        };
        write!(updates, "{mode} {oid}\t{prefix}{path}\0")?;
    }
    if !updates.is_empty() {
        let top = PathBuf::from(git.text(&["rev-parse", "--show-toplevel"])?);
        Git::local(&top).input(&["update-index", "-z", "--index-info"], updates)?;
    }
    Ok(())
}

fn verify_outgoing(store: &Store, upstream: &str, remote: &str) -> Result<()> {
    let git = Git::local(&store.root);
    let prefix = git.text(&["rev-parse", "--show-prefix"])?;
    let exclude = git
        .optional(&["rev-parse", "--verify", upstream])?
        .map(|oid| format!("^{}", String::from_utf8_lossy(&oid).trim()));
    let alternative = format!("--remotes={remote}");
    let mut args = vec!["rev-list", "--max-count=101", "HEAD"];
    if let Some(exclude) = &exclude {
        args.push(exclude);
    } else {
        args.extend(["--not", &alternative]);
    }
    let commits = git.text(&args)?;
    if commits.is_empty() {
        return Ok(());
    }
    ensure!(commits.lines().count() <= 100, "too many outgoing commits");
    let signers = (!store::is_personal(store)).then(signers).transpose()?;
    for commit in commits.lines() {
        if !prefix.is_empty() {
            let data = git.run(&[
                "diff-tree",
                "--root",
                "-m",
                "--no-commit-id",
                "-r",
                "-z",
                "--name-only",
                commit,
            ])?;
            ensure!(
                names(&data)?.iter().all(|path| path.starts_with(&prefix)),
                "outgoing commit has changes outside the store"
            );
        }
        if let Some(signers) = &signers {
            verify_commit(&git, commit, signers)?;
        }
        tree(&git, commit, &prefix)?;
    }
    Ok(())
}

pub fn sync_store(store: &Store, message: &[String]) -> Result<()> {
    store.check_root()?;
    let git = Git::local(&store.root);
    let top = PathBuf::from(git.text(&["rev-parse", "--show-toplevel"])?);
    let prefix = git.text(&["rev-parse", "--show-prefix"])?;
    let end = prefix.trim_end_matches('/');
    let exclusions = [
        format!(":(exclude,top){end}"),
        format!(":(exclude,top){end}/**"),
    ];
    let repo = Git::local(&top);
    if !prefix.is_empty() {
        ensure!(
            repo.run(&[
                "status",
                "--porcelain",
                "--",
                ".",
                &exclusions[0],
                &exclusions[1]
            ])?
            .is_empty(),
            "working tree contains changes outside the store"
        );
    }
    stage_store(store)?;
    if !prefix.is_empty() {
        ensure!(
            repo.status(&[
                "diff",
                "--cached",
                "--quiet",
                "--",
                ".",
                &exclusions[0],
                &exclusions[1]
            ])?,
            "Git index has changes outside the store"
        );
    }
    if !git.status(&["diff", "--cached", "--quiet", "--", "."])? {
        let message = if message.is_empty() {
            "sync".into()
        } else {
            message.join(" ")
        };
        let args = if store::is_personal(store) {
            vec!["commit", "-m", &message]
        } else {
            vec!["-c", "gpg.format=ssh", "commit", "-S", "-m", &message]
        };
        git.run(&args)?;
    }
    let branch = git.text(&["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    let configured = git.optional(&["config", "--get", &format!("branch.{branch}.remote")])?;
    let remotes = git.text(&["remote"])?;
    let remote = match configured
        .as_ref()
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::trim)
    {
        Some(value) if value != "." && !value.is_empty() => value,
        _ if remotes.lines().any(|name| name == "origin") => "origin",
        _ => {
            let names = remotes.lines().collect::<Vec<_>>();
            ensure!(names.len() == 1, "no unambiguous Git remote");
            names[0]
        }
    };
    ensure!(!remote.starts_with('-'), "invalid Git remote");
    let previous = git.status(&["rev-parse", "--verify", "@{upstream}"])?;
    let destination = if previous {
        git.run(&["pull", "--rebase"])?;
        git.text(&["config", "--get", &format!("branch.{branch}.merge")])?
    } else {
        format!("refs/heads/{branch}")
    };
    ensure!(
        destination.starts_with("refs/heads/"),
        "upstream must be a branch"
    );
    let upstream = if previous {
        "@{upstream}".into()
    } else {
        format!("refs/remotes/{remote}/{branch}")
    };
    verify_outgoing(store, &upstream, remote)?;
    let refspec = format!("HEAD:{destination}");
    let args = if previous {
        vec!["push", "--", remote, &refspec]
    } else {
        vec!["push", "-u", "--", remote, &refspec]
    };
    git.run(&args)?;
    Ok(())
}

pub fn pre_receive(root: &Path, mode: &str, argument: &str) -> Result<()> {
    let git = Git::local(root);
    let signers = signers()?;
    let mut patterns = GlobSetBuilder::new();
    let prefix = match mode {
        "--store" if argument.is_empty() => String::new(),
        "--store" => {
            c::managed(argument.trim_matches('/'))?;
            format!("{}/", argument.trim_matches('/'))
        }
        "--filters" => {
            let path = Path::new(argument);
            ensure!(
                path.is_absolute(),
                "supply an absolute protected-paths file"
            );
            for line in c::utf8(&crate::platform::read_trusted(path, c::CONFIG)?)?
                .lines()
                .map(str::trim)
            {
                if !line.is_empty() && !line.starts_with('#') {
                    patterns.add(Glob::new(line)?);
                }
            }
            String::new()
        }
        _ => bail!("expected --store or --filters"),
    };
    let patterns = patterns.build()?;
    ensure!(
        mode != "--filters" || !patterns.is_empty(),
        "protected-path list is empty"
    );
    let mut seen = std::collections::BTreeSet::new();
    let stdin = c::bounded(io::stdin().lock(), c::CONFIG)?;
    for line in c::utf8(&stdin)?.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            parts.len() == 3 && valid_oid(parts[0]) && valid_oid(parts[1]),
            "invalid receive-hook record"
        );
        let (old, new) = (parts[0], parts[1]);
        if new.bytes().all(|b| b == b'0') {
            continue;
        }
        let exclude = format!("^{old}");
        let mut args = vec!["rev-list", "--max-count=101", new];
        if old.bytes().all(|b| b == b'0') {
            args.extend(["--not", "--all"]);
        } else {
            args.push(&exclude);
        }
        let commits = git.text(&args)?;
        for commit in std::iter::once(new).chain(commits.lines()) {
            if !seen.insert(commit.to_owned()) {
                continue;
            }
            ensure!(seen.len() <= 100, "too many incoming commits");
            verify_commit(&git, commit, &signers)?;
            if mode == "--store" {
                tree(&git, commit, &prefix)?;
            } else {
                let rows = git.run(&["ls-tree", "-rz", "--full-tree", commit])?;
                for row in names(&rows)? {
                    let (info, path) = row.split_once('\t').context("invalid tree entry")?;
                    if !patterns.is_match(path) {
                        continue;
                    }
                    let info = info.split(' ').collect::<Vec<_>>();
                    ensure!(
                        info.len() == 3
                            && matches!(info[0], "100644" | "100755")
                            && info[1] == "blob"
                            && valid_oid(info[2]),
                        "protected path is not a regular blob"
                    );
                    crypto::validate_cipher(&git.run(&["cat-file", "blob", info[2]])?)?;
                }
            }
        }
    }
    Ok(())
}

fn recipient_path(root: &Path) -> PathBuf {
    root.join(c::var("SEC_GIT_RECIPIENTS_FILE").unwrap_or_else(|| ".sec-recipients".into()))
}

fn configured_filter() -> Result<String> {
    if let Some(program) = c::var("SEC_GIT_FILTER_CMD") {
        let program = program.to_str().context("invalid filter executable")?;
        ensure!(
            !program.contains(['\n', '\r', '\0']),
            "invalid filter executable"
        );
        return Ok(shell_quote(program));
    }
    let path = env::current_exe()?;
    let already_git = path.file_stem().is_some_and(|name| name == "sec-git");
    let name = c::path_string(&path)?.replace('\\', "/");
    let location = if let Some(unc) = name.strip_prefix("//?/UNC/") {
        format!("//{unc}")
    } else {
        name.strip_prefix("//?/").unwrap_or(&name).to_owned()
    };
    let quoted = shell_quote(&location);
    Ok(if already_git {
        quoted
    } else {
        format!("{quoted} git")
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn active(git: &Git<'_>) -> Result<bool> {
    let value = |key: &str| -> Result<String> {
        let bytes = git.optional(&["config", "--get", key])?.unwrap_or_default();
        Ok(c::utf8(&bytes)?.trim_end_matches(['\r', '\n']).to_owned())
    };
    let required = git.optional(&["config", "--get", "--bool", "filter.sec.required"])?;
    if !required
        .as_ref()
        .is_some_and(|value| c::utf8(value).is_ok_and(|value| value.trim() == "true"))
        || git.status(&["config", "--get", "filter.sec.process"])?
    {
        return Ok(false);
    }
    let clean = value("filter.sec.clean")?;
    let smudge = value("filter.sec.smudge")?;
    let configured = configured_filter()?;
    Ok([configured.as_str(), "sec-git", "'sec-git'"]
        .iter()
        .any(|filter| {
            clean == format!("{filter} clean %f") && smudge == format!("{filter} smudge %f")
        }))
}

fn tracking_line(pattern: &str) -> Result<String> {
    ensure!(
        !pattern.is_empty() && !pattern.chars().any(char::is_control),
        "invalid attribute pattern"
    );
    Ok(format!(
        "{} filter=sec diff=sec -text",
        serde_json::to_string(pattern)?
    ))
}

fn filtered(git: &Git<'_>, others: bool) -> Result<Vec<String>> {
    let mut args = vec!["ls-files", "-z", "--cached"];
    if others {
        args.extend(["--others", "--exclude-standard"]);
    }
    args.extend(["--", ":(attr:filter=sec)"]);
    let bytes = git.run(&args)?;
    let mut names = names(&bytes)?;
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .map(|name| Ok(c::managed(name)?.to_owned()))
        .collect()
}

fn guard(git: &Git<'_>) -> Result<()> {
    for name in filtered(git, true)? {
        if let Some(data) = c::optional(&git.root.join(&name), c::CIPHER)? {
            crypto::validate_cipher(&data).with_context(|| {
                format!("working tree still contains protected plaintext: {name:?}")
            })?;
        }
    }
    Ok(())
}

fn filter(mode: &str, root: &Path, recipients: &Path, name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let encrypted = data.starts_with(b"age-encryption.org/v1\n")
        || data.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----");
    if encrypted {
        crypto::validate_cipher(data)?;
    }
    if matches!(mode, "smudge" | "text") {
        if !encrypted {
            ensure!(
                c::on("SEC_GIT_ALLOW_PLAINTEXT"),
                "filtered Git blob is not encrypted"
            );
        } else if mode == "text" || c::on("SEC_GIT_SMUDGE_PLAINTEXT") {
            return Ok(crypto::decrypt_data(data, c::SECRET)?.to_vec());
        }
        return Ok(data.to_vec());
    }
    let store = Store::local(root.to_owned())?;
    let policy = store::require_policy(&store, recipients, "git", false)?;
    let plaintext = if encrypted {
        crypto::decrypt_data(data, c::SECRET)?
    } else {
        zeroize::Zeroizing::new(data.to_vec())
    };
    let key = json!([c::path_string(root)?, name]);
    if !name.is_empty() {
        c::managed(name)?;
        if !c::on("SEC_GIT_FORCE") {
            let previous = c::record::<Value>("git-cipher", &key)?.unwrap_or_default();
            if previous["policy"] == c::sha(&policy)
                && let Some(old) = Git::local(root).optional(&["show", &format!(":{name}")])?
                && previous["digest"] == c::sha(&old)
                && crypto::decrypt_data(&old, c::SECRET)
                    .is_ok_and(|existing| *existing == *plaintext)
            {
                return Ok(old);
            }
        }
    }
    let keys = store::recipient_lines(&policy)?;
    let result = crypto::encrypt_keys(&plaintext, &keys, None, c::on("SEC_GIT_ARMOR"))?;
    if !name.is_empty() {
        c::write_record(
            "git-cipher",
            &key,
            &json!({"policy": c::sha(&policy), "digest": c::sha(&result)}),
        )?;
    }
    Ok(result)
}

fn refresh(git: &Git<'_>, write_files: bool) -> Result<()> {
    ensure!(
        git.status(&["diff", "--cached", "--quiet", "--", ":(attr:filter=sec)"])?,
        "filtered paths have staged changes"
    );
    for name in filtered(git, false)? {
        let path = git.root.join(&name);
        let cipher = git.run(&["show", &format!(":{name}")])?;
        crypto::validate_cipher(&cipher)?;
        let plaintext = crypto::decrypt_data(&cipher, c::SECRET)?;
        let current = c::optional(&path, c::CIPHER)?;
        ensure!(
            current
                .as_deref()
                .is_none_or(|current| current == cipher || current == plaintext.as_slice()),
            "filtered path has local changes: {name:?}"
        );
        if write_files {
            platform::create_dirs(path.parent().unwrap())?;
            platform::atomic_replace(&path, current.as_deref(), &plaintext)?;
        }
    }
    Ok(())
}

fn recipients(store: &Store, args: &[String]) -> Result<()> {
    let path = recipient_path(&store.root);
    let action = args
        .first()
        .map(String::as_str)
        .context("expected a recipient command")?;
    if action == "approve" && args.len() == 1 {
        store::require_policy(store, &path, "git", true)?;
    } else if matches!(action, "list" | "ls" | "l") && args.len() == 1 {
        if let Some(data) = c::optional(&path, c::CONFIG)? {
            io::stdout().write_all(&data)?;
        }
    } else if matches!(action, "add" | "a" | "rm" | "r" | "remove") {
        let before = c::optional(&path, c::CONFIG)?;
        let current = c::utf8(before.as_deref().unwrap_or_default())?;
        let mut old = current.lines().map(str::to_owned).collect::<Vec<_>>();
        let mut keys = args[1..].to_vec();
        if keys.is_empty() && !io::stdin().is_terminal() {
            keys = c::utf8(&c::bounded(io::stdin().lock(), c::CONFIG)?)?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect();
        }
        ensure!(!keys.is_empty(), "no recipients supplied");
        for key in keys {
            let valid = store::recipient_lines(key.as_bytes())?;
            ensure!(valid.len() == 1, "expected one recipient per line");
            let key = &valid[0];
            if matches!(action, "add" | "a") {
                if !old.contains(key) {
                    old.push(key.clone());
                }
            } else {
                old.retain(|existing| existing != key);
            }
        }
        if old.is_empty() {
            if before.is_some() {
                platform::remove_file(&path)?;
            }
        } else {
            let data = (old.join("\n") + "\n").into_bytes();
            store::recipient_lines(&data)?;
            platform::atomic_replace(&path, before.as_deref(), &data)?;
        }
    } else {
        bail!("invalid recipient command or arguments. Run sec git recipient --help");
    }
    Ok(())
}

pub fn cli(args: &[String]) -> Result<i32> {
    let (action, args) = args.split_first().context("specify a Git command")?;
    let action = action.as_str();
    if matches!(action, "version" | "--version" | "-V") {
        println!("sec-git {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    let root = root_path()?;
    let git = Git::local(&root);
    let store = Store::local(root.clone())?;
    let attrs = root.join(".gitattributes");
    let policy = recipient_path(&root);
    match (action, args) {
        ("on", [] | [_]) if args.is_empty() || args == ["--textconv"] => {
            let filter = configured_filter()?;
            ensure!(
                !git.status(&["config", "--get", "filter.sec.process"])?,
                "remove incompatible filter.sec.process first"
            );
            if c::optional(&attrs, c::CONFIG)?
                .is_some_and(|data| data.windows(10).any(|w| w == b"filter=sec"))
            {
                store::require_policy(&store, &policy, "git", false)?;
            }
            for (key, setting) in [
                ("filter.sec.required", "true".into()),
                ("filter.sec.clean", format!("{filter} clean %f")),
                ("filter.sec.smudge", format!("{filter} smudge %f")),
                ("diff.sec.cachetextconv", "false".into()),
            ] {
                git.run(&["config", "--local", key, &setting])?;
            }
            if !args.is_empty() {
                git.run(&[
                    "config",
                    "--local",
                    "diff.sec.textconv",
                    &format!("{filter} textconv"),
                ])?;
            } else {
                git.optional(&["config", "--local", "--unset-all", "diff.sec.textconv"])?;
            }
        }
        ("off", []) => {
            guard(&git)?;
            for key in [
                "filter.sec.clean",
                "filter.sec.smudge",
                "filter.sec.required",
                "diff.sec.textconv",
                "diff.sec.cachetextconv",
            ] {
                git.optional(&["config", "--local", "--unset-all", key])?;
            }
        }
        ("status" | "l", []) => {
            let enabled = active(&git)?;
            println!(
                "state: {}\nrecipients-file: {}",
                if enabled { "on" } else { "off" },
                policy.display()
            );
            println!("# recipients");
            if let Some(data) = c::optional(&policy, c::CONFIG)? {
                for line in c::utf8(&data)?.lines() {
                    println!("r: {line}");
                }
            }
            println!("# tracked patterns");
            if let Some(data) = c::optional(&attrs, c::CONFIG)? {
                for line in c::utf8(&data)?
                    .lines()
                    .filter(|line| line.contains("filter=sec"))
                {
                    println!("t: {line}");
                }
            }
            println!("# tracked files");
            for name in filtered(&git, false)? {
                println!("f: {name}");
            }
        }
        ("recipient", args) => recipients(&store, args)?,
        ("a" | "r", args) => {
            let mut combined = vec![action.to_owned()];
            combined.extend_from_slice(args);
            recipients(&store, &combined)?;
        }
        ("track" | "t" | "untrack" | "u", [_, ..]) => {
            let adding = matches!(action, "track" | "t");
            if adding {
                store::recipient_lines(&c::read(&policy, c::CONFIG)?)?;
            } else {
                guard(&git)?;
            }
            let before = c::optional(&attrs, c::CONFIG)?;
            let mut lines = c::utf8(before.as_deref().unwrap_or_default())?
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            for pattern in args {
                let line = tracking_line(pattern)?;
                if adding {
                    if !lines.contains(&line) {
                        lines.push(line);
                    }
                } else {
                    let previous = format!("{pattern}  filter=sec diff=sec");
                    let previous_single = format!("{pattern} filter=sec diff=sec");
                    lines.retain(|value| {
                        value != &line && value != &previous && value != &previous_single
                    });
                }
            }
            if lines.is_empty() {
                if before.is_some() {
                    platform::remove_file(&attrs)?;
                }
            } else {
                platform::atomic_replace(
                    &attrs,
                    before.as_deref(),
                    (lines.join("\n") + "\n").as_bytes(),
                )?;
            }
        }
        ("rekey" | "f", []) => {
            ensure!(
                active(&git)?,
                "activate the required filter with sec git on before rekeying"
            );
            store::require_policy(&store, &policy, "git", false)?;
            refresh(&git, false)?;
            c::run(
                git.command(&["add", "--renormalize", "--", ":(attr:filter=sec)"])
                    .env("SEC_GIT_FORCE", "1"),
                None,
                c::CONFIG,
            )?;
        }
        ("refresh", []) => {
            ensure!(
                active(&git)?,
                "activate the required filter with sec git on before refresh"
            );
            refresh(&git, true)?;
        }
        ("clean" | "smudge", [] | [_]) => {
            let input = c::bounded(io::stdin().lock(), c::CIPHER)?;
            io::stdout().write_all(&filter(
                action,
                &root,
                &policy,
                args.first().map(String::as_str).unwrap_or(""),
                &input,
            )?)?;
        }
        ("textconv", [filename]) => {
            let input = c::read(Path::new(filename), c::CIPHER)?;
            io::stdout().write_all(&filter("text", &root, &policy, "", &input)?)?;
        }
        _ => bail!("invalid Git command or arguments. Run sec git --help"),
    }
    Ok(0)
}

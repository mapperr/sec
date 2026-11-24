use std::{
    env,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use age::{Identity, IdentityFile, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

use crate::platform;

const CONFIG_LIMIT: u64 = 1024 * 1024;

fn setting(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home() -> Option<PathBuf> {
    #[cfg(unix)]
    let name = "HOME";
    #[cfg(windows)]
    let name = "USERPROFILE";
    setting(name)
}

fn config_dir() -> Option<PathBuf> {
    setting("SEC_CONFIG_DIR").or_else(|| {
        #[cfg(unix)]
        let local = setting("XDG_CONFIG_HOME").or_else(|| home().map(|home| home.join(".config")));
        #[cfg(windows)]
        let local = setting("APPDATA");
        local.map(|config| config.join("sec"))
    })
}

fn bounded(mut reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(CONFIG_LIMIT + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > CONFIG_LIMIT {
        bail!("configuration exceeds 1 MiB");
    }
    Ok(data)
}

fn configured_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match platform::open_read(path) {
        Ok(file) => Ok(Some(
            bounded(file).with_context(|| format!("read {}", path.display()))?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("open {}", path.display())),
    }
}

fn add_identity(result: &mut Vec<PathBuf>, path: PathBuf, required: bool) -> Result<()> {
    let path = std::path::absolute(path)?;
    match platform::open_identity(&path) {
        Ok(_) if !result.contains(&path) => result.push(path),
        Ok(_) => {}
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("open identity {}", path.display()));
        }
    }
    Ok(())
}

pub fn identity_paths() -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    if let Some(identity) = setting("SEC_IDENTITY") {
        add_identity(&mut result, identity, true)?;
    }
    let config = config_dir();
    if let Some(config) = &config {
        add_identity(&mut result, config.join("identity"), false)?;
    }
    if crate::common::on("SEC_ALLOW_SSH_IDENTITIES")
        && let Some(home) = home()
    {
        for name in ["id_ed25519", "id_rsa"] {
            add_identity(&mut result, home.join(".ssh").join(name), false)?;
        }
    }
    if let Some(config) = config
        && let Some(list) = configured_file(&config.join("identities"))?
    {
        for line in std::str::from_utf8(&list)?.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let path = if let Some(rest) = line.strip_prefix("~/") {
                home()
                    .ok_or_else(|| {
                        anyhow!("cannot expand an identity path without a home directory")
                    })?
                    .join(rest)
            } else {
                PathBuf::from(line)
            };
            add_identity(&mut result, path, true)?;
        }
    }
    if result.is_empty() {
        bail!("no private identity found");
    }
    Ok(result)
}

fn identity_data(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let source = platform::open_identity(path)
        .with_context(|| format!("open identity {}", path.display()))?;
    bounded(source)
}

pub struct Decryption {
    pub paths: Vec<PathBuf>,
    pub identities: Vec<Box<dyn Identity + Send + Sync>>,
    pub external: bool,
}

fn legacy_identity(data: &[u8]) -> bool {
    data.starts_with(b"age-encryption.org/v1\n")
        || data.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
        || data.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN RSA PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
}

fn allowed_plugin(plugin: &str) -> Result<()> {
    anyhow::ensure!(
        env::var("SEC_AGE_PLUGINS")
            .unwrap_or_default()
            .split(',')
            .any(|name| name == plugin),
        "age plugin {plugin:?} is not allowlisted in SEC_AGE_PLUGINS"
    );
    Ok(())
}

fn check_identity_plugins(data: &[u8]) -> Result<()> {
    for line in crate::common::utf8(data)?.lines() {
        if line.starts_with("AGE-PLUGIN-") {
            let plugin: age::plugin::Identity = line
                .parse()
                .map_err(|_| anyhow!("invalid age plugin identity"))?;
            allowed_plugin(plugin.plugin())?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct TerminalCallbacks;

impl age::Callbacks for TerminalCallbacks {
    fn display_message(&self, message: &str) {
        let _ = writeln!(std::io::stderr(), "age plugin: {message:?}");
    }

    fn confirm(&self, message: &str, yes: &str, no: Option<&str>) -> Option<bool> {
        let (mut input, mut output) = crate::common::terminal().ok()?;
        write!(
            output,
            "{message:?} ({yes:?}/{:?}) [y/N] ",
            no.unwrap_or("no")
        )
        .ok()?;
        output.flush().ok()?;
        let mut answer = String::new();
        input.read_line(&mut answer).ok()?;
        Some(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }

    fn request_public_string(&self, description: &str) -> Option<String> {
        let (mut input, mut output) = crate::common::terminal().ok()?;
        write!(output, "{description:?} ").ok()?;
        output.flush().ok()?;
        let mut answer = String::new();
        input.read_line(&mut answer).ok()?;
        Some(answer.trim_end_matches(['\r', '\n']).into())
    }

    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        crate::common::terminal().ok()?;
        rpassword::prompt_password(format!("{description:?} "))
            .ok()
            .map(Into::into)
    }
}

pub fn decryption() -> Result<Decryption> {
    let paths = identity_paths()?;
    let mut identities = Vec::new();
    let mut external = false;
    for path in &paths {
        let data = identity_data(path)?;
        if legacy_identity(&data) {
            external = true;
            continue;
        }
        check_identity_plugins(&data)?;
        let list = IdentityFile::from_buffer(BufReader::new(data.as_slice()))
            .map_err(|_| anyhow!("unsupported identity file {}", path.display()))?;
        identities.extend(
            list.with_callbacks(TerminalCallbacks)
                .into_identities()
                .map_err(|_| anyhow!("unsupported age identity in {}", path.display()))?,
        );
    }
    anyhow::ensure!(
        external || !identities.is_empty(),
        "no identities in configured identity files"
    );
    Ok(Decryption {
        paths,
        identities,
        external,
    })
}

fn read_recipients(data: &str, values: &mut Vec<String>) {
    values.extend(
        data.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned),
    );
}

pub fn self_recipients() -> Result<Vec<String>> {
    let mut values = Vec::new();
    if let Ok(value) = env::var("SEC_RECIPIENT")
        && !value.is_empty()
    {
        read_recipients(&value, &mut values);
        return nonempty(values);
    }
    if let Some(config) = config_dir()
        && let Some(value) = configured_file(&config.join("recipient"))?
    {
        read_recipients(std::str::from_utf8(&value)?, &mut values);
        return nonempty(values);
    }
    let paths = identity_paths()?;
    let path = &paths[0];
    let data = identity_data(path)?;
    if data.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN RSA PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN PRIVATE KEY-----")
        || data.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        let binary =
            which::which("ssh-keygen").context("SSH recipient derivation needs ssh-keygen")?;
        let public = crate::common::run(
            Command::new(binary).args(["-y", "-f"]).arg(path),
            None,
            crate::common::CONFIG,
        )?;
        read_recipients(crate::common::utf8(&public)?, &mut values);
        return nonempty(values);
    }
    check_identity_plugins(&data)?;
    let identity = IdentityFile::from_buffer(BufReader::new(data.as_slice()))
        .map_err(|_| anyhow!("unsupported identity file {}", path.display()))?;
    let mut output = Vec::new();
    identity
        .with_callbacks(TerminalCallbacks)
        .write_recipients_file(&mut output)
        .map_err(|_| anyhow!("cannot derive public recipients"))?;
    read_recipients(std::str::from_utf8(&output)?, &mut values);
    nonempty(values)
}

pub fn public_recipients() -> Result<Vec<String>> {
    let values = self_recipients()?;
    for value in &values {
        validate_recipient(value)?;
    }
    Ok(values)
}

fn nonempty(values: Vec<String>) -> Result<Vec<String>> {
    if values.is_empty() {
        bail!("recipient configuration has no recipients");
    }
    Ok(values)
}

pub fn parse_recipient(value: &str) -> Result<Box<dyn Recipient + Send>> {
    if let Ok(recipient) = value.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(recipient));
    }
    if let Ok(recipient) = value.parse::<age::tag::Recipient>() {
        return Ok(Box::new(recipient));
    }
    if let Ok(recipient) = value.parse::<age::tagpq::Recipient>() {
        return Ok(Box::new(recipient));
    }
    if let Ok(recipient) = value.parse::<age::plugin::Recipient>() {
        allowed_plugin(recipient.plugin())?;
        return Ok(Box::new(age::plugin::RecipientPluginV1::new(
            recipient.plugin(),
            std::slice::from_ref(&recipient),
            &[],
            TerminalCallbacks,
        )?));
    }
    bail!("invalid or unsupported public recipient")
}

pub fn ssh_recipient(value: &str) -> bool {
    matches!(
        value.split_ascii_whitespace().next(),
        Some("ssh-ed25519" | "ssh-rsa")
    )
}

pub fn validate_recipient(value: &str) -> Result<()> {
    if ssh_recipient(value) {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut fields = value.split_ascii_whitespace();
        let format = fields.next().unwrap();
        let contents = STANDARD.decode(fields.next().context("missing SSH public key bytes")?)?;
        let prefix = (format.len() as u32).to_be_bytes();
        anyhow::ensure!(
            contents.starts_with(&prefix)
                && contents.get(4..4 + format.len()) == Some(format.as_bytes())
                && contents.len() > 4 + format.len(),
            "invalid SSH public key"
        );
    } else if let Ok(plugin) = value.parse::<age::plugin::Recipient>() {
        let _ = plugin; // Parsing a policy never launches a plugin.
    } else {
        parse_recipient(value)?;
    }
    Ok(())
}

fn recipient_list_file(value: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    // Long native recipients and comma lists can exceed a filesystem component.
    if value.is_ascii() && value.len() > 255 && !value.contains(['/', '\\']) {
        return Ok(None);
    }
    configured_file(Path::new(value))
}

pub fn recipients() -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut explicit = false;
    if let Some(path) = setting("SEC_RECIPIENTS_FILE") {
        explicit = true;
        let entries = configured_file(&path)?
            .ok_or_else(|| anyhow!("recipient file {} is missing", path.display()))?;
        read_recipients(std::str::from_utf8(&entries)?, &mut values);
    }
    if let Ok(value) = env::var("SEC_RECIPIENTS")
        && !value.is_empty()
    {
        explicit = true;
        if let Some(entries) = recipient_list_file(&value)? {
            read_recipients(std::str::from_utf8(&entries)?, &mut values);
        } else {
            for item in value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                if let Some(entries) = recipient_list_file(item)? {
                    read_recipients(std::str::from_utf8(&entries)?, &mut values);
                } else {
                    read_recipients(item, &mut values);
                }
            }
        }
    }
    let values = if explicit {
        nonempty(values)?
    } else {
        self_recipients()?
    };
    for value in &values {
        validate_recipient(value)?;
    }
    Ok(values)
}

pub fn legacy_self() -> Result<Option<PathBuf>> {
    if setting("SEC_RECIPIENT").is_some()
        || setting("SEC_RECIPIENTS").is_some()
        || setting("SEC_RECIPIENTS_FILE").is_some()
        || config_dir().is_some_and(|dir| dir.join("recipient").exists())
    {
        return Ok(None);
    }
    let path = identity_paths()?.remove(0);
    let data = identity_data(&path)?;
    if data.starts_with(b"age-encryption.org/v1\n")
        || data.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
    {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

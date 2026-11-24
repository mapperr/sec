use std::io::{self, BufReader, Cursor, Read, Write};

use age::{
    Decryptor, Encryptor, Identity, Recipient,
    armor::{ArmoredReader, ArmoredWriter, Format},
};
use anyhow::{Result, bail};
use zeroize::Zeroizing;

const ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----\n";
const BINARY: &[u8] = b"age-encryption.org/v1\n";

fn starts_encrypted(prefix: &[u8]) -> bool {
    prefix.starts_with(ARMOR)
        || prefix.starts_with(BINARY)
        || prefix.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\r\n")
}

pub fn encrypt(
    mut input: impl Read,
    output: impl Write,
    recipients: &[Box<dyn Recipient + Send>],
    armor: bool,
) -> Result<()> {
    let mut prefix = Zeroizing::new(Vec::new());
    input
        .by_ref()
        .take((ARMOR.len() + 1) as u64)
        .read_to_end(&mut prefix)?;
    if starts_encrypted(&prefix) {
        bail!("input is already age-encrypted");
    }
    let format = if armor {
        Format::AsciiArmor
    } else {
        Format::Binary
    };
    let encryptor = Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient.as_ref() as &dyn Recipient),
    )?;
    let output = ArmoredWriter::wrap_output(output, format)?;
    let mut encrypted = encryptor.wrap_output(output)?;
    io::copy(
        &mut Cursor::new(prefix.as_slice()).chain(input),
        &mut encrypted,
    )?;
    encrypted.finish()?.finish()?.flush()?;
    Ok(())
}

pub fn decrypt(
    input: impl Read,
    mut output: impl Write,
    identities: &[Box<dyn Identity + Send + Sync>],
) -> Result<()> {
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(BufReader::new(input)))?;
    let mut plaintext = decryptor.decrypt(
        identities
            .iter()
            .map(|identity| identity.as_ref() as &dyn Identity),
    )?;
    io::copy(&mut plaintext, &mut output)?;
    output.flush()?;
    Ok(())
}

pub fn decrypt_data(cipher: &[u8], maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let decryption = crate::config::decryption()?;
    if decryption.external {
        return Ok(Zeroizing::new(external_decrypt(
            cipher.to_vec(),
            &decryption.paths,
            maximum,
        )?));
    }
    let identities = decryption.identities;
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(cipher))?;
    let plaintext = decryptor.decrypt(
        identities
            .iter()
            .map(|identity| identity.as_ref() as &dyn Identity),
    )?;
    let mut result = Zeroizing::new(Vec::new());
    plaintext
        .take(maximum as u64 + 1)
        .read_to_end(&mut result)?;
    anyhow::ensure!(result.len() <= maximum, "secret exceeds the size limit");
    Ok(result)
}

pub fn validate_cipher(bytes: &[u8]) -> Result<()> {
    let decoded = crate::common::bounded(ArmoredReader::new(bytes), crate::common::CIPHER)?;
    anyhow::ensure!(decoded.starts_with(BINARY), "not an age ciphertext");
    let header = &decoded[..decoded.len().min(2 * 1024 * 1024)];
    let end = header
        .windows(5)
        .position(|seq| seq == b"\n--- ")
        .ok_or_else(|| anyhow::anyhow!("invalid age header"))?;
    let footer = header[end + 5..]
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or_else(|| anyhow::anyhow!("incomplete age header"))?;
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    anyhow::ensure!(
        header[BINARY.len()..].starts_with(b"-> ")
            && STANDARD_NO_PAD
                .decode(&header[end + 5..end + 5 + footer])?
                .len()
                == 32
            && decoded.len() - (end + 6 + footer) >= 32,
        "invalid or incomplete age ciphertext"
    );
    Decryptor::new_buffered(decoded.as_slice())?;
    Ok(())
}

fn external() -> Result<(std::process::Command, tempfile::TempDir)> {
    use crate::common as c;
    use std::{env, process::Command};
    let program = which::which("age").map_err(|_| {
        anyhow::anyhow!("SSH and passphrase-encrypted identity files require the Go age executable")
    })?;
    let version = c::run(Command::new(&program).arg("--version"), None, 256)?;
    let digits = c::utf8(&version)?
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        matches!(digits.as_slice(), [major, minor, patch] if (*major, *minor, *patch) >= (1,2,1)),
        "the SSH compatibility backend requires age 1.2.1 or newer"
    );
    let directory = c::workspace(None)?;
    let mut helpers = vec!["pinentry".to_owned()];
    for name in env::var("SEC_AGE_PLUGINS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
    {
        anyhow::ensure!(
            name.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"+._-".contains(&byte)),
            "invalid age plugin name"
        );
        helpers.push(format!("age-plugin-{name}"));
    }
    helpers.sort();
    helpers.dedup();
    for helper in helpers {
        let Ok(path) = which::which(&helper) else {
            continue;
        };
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid helper executable"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&path, directory.path().join(name))?;
        #[cfg(windows)]
        std::fs::copy(&path, directory.path().join(name))?;
    }
    let mut command = Command::new(program);
    command.env("PATH", directory.path());
    Ok((command, directory))
}

fn external_decrypt(
    input: Vec<u8>,
    paths: &[std::path::PathBuf],
    maximum: usize,
) -> Result<Vec<u8>> {
    let (mut command, _helpers) = external()?;
    command.arg("-d");
    for path in paths {
        command.arg("-i").arg(path);
    }
    crate::common::run(&mut command, Some(input), maximum)
}

pub fn encrypt_to(
    mut input: impl Read,
    mut output: impl Write,
    keys: &[String],
    legacy: Option<&std::path::Path>,
    armor: bool,
) -> Result<()> {
    if legacy.is_none() && !keys.iter().any(|key| crate::config::ssh_recipient(key)) {
        let parsed = keys
            .iter()
            .map(|key| crate::config::parse_recipient(key))
            .collect::<Result<Vec<_>>>()?;
        return encrypt(input, output, &parsed, armor);
    }
    let (mut command, helpers) = external()?;
    if armor {
        command.arg("-a");
    }
    if let Some(identity) = legacy {
        command.args(["-e", "-i"]).arg(identity);
    } else {
        let file = helpers.path().join("recipients");
        crate::common::write_new(&file, (keys.join("\n") + "\n").as_bytes())?;
        command.arg("-R").arg(file);
    }
    let plaintext = crate::common::bounded(&mut input, crate::common::SECRET)?;
    anyhow::ensure!(
        !starts_encrypted(&plaintext),
        "input is already age-encrypted"
    );
    let encrypted = crate::common::run(&mut command, Some(plaintext), crate::common::CIPHER)?;
    output.write_all(&encrypted)?;
    Ok(())
}

pub fn encrypt_keys(
    input: &[u8],
    keys: &[String],
    legacy: Option<&std::path::Path>,
    armor: bool,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    encrypt_to(input, &mut output, keys, legacy, armor)?;
    Ok(output)
}

pub fn decrypt_from(
    input: impl Read,
    mut output: impl Write,
    selection: &crate::config::Decryption,
) -> Result<()> {
    if selection.external {
        let input = crate::common::bounded(input, crate::common::CIPHER)?;
        let plaintext = Zeroizing::new(external_decrypt(
            input,
            &selection.paths,
            crate::common::SECRET,
        )?);
        output.write_all(&plaintext)?;
        return Ok(());
    }
    decrypt(input, output, &selection.identities)
}

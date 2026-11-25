use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

use age::{armor::ArmoredReader, x25519};

fn command(configuration: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sec"));
    for name in [
        "SEC_ARMOR",
        "SEC_IDENTITY",
        "SEC_RECIPIENT",
        "SEC_RECIPIENTS",
        "SEC_RECIPIENTS_FILE",
        "SEC_ALLOW_SSH_IDENTITIES",
    ] {
        command.env_remove(name);
    }
    command.env("SEC_CONFIG_DIR", configuration).env("PATH", "");
    command
}

fn pipe(command: &mut Command, input: &[u8]) -> Output {
    // The output fixtures are small enough to fit in both pipes.
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn ok(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn help_covers_the_single_binary_without_accessing_a_store_or_git() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let help = |args: &[&str]| {
        let output = command(&root)
            .current_dir(&root)
            .env("SEC_STORE_DIR", root.join("missing"))
            .args(args)
            .output()
            .unwrap();
        ok(&output);
        assert!(output.stderr.is_empty());
        String::from_utf8(output.stdout).unwrap()
    };

    let overview = help(&[]);
    assert_eq!(overview, help(&["--help"]));
    for name in [
        "e",
        "d",
        "identity",
        "recipient",
        "store",
        "run",
        "git",
        "security",
    ] {
        assert!(
            overview
                .lines()
                .any(|line| line.starts_with(&format!("  {name}  ")))
        );
    }

    let manifest = help(&["help", "run", "manifest"]);
    assert_eq!(manifest, help(&["run", "m", "-h"]));
    assert!(manifest.contains("edit"));
    assert!(!manifest.contains("approve"));
    assert!(help(&["store", "policy", "approve", "--help"]).contains("interactive confirmation"));
    assert!(help(&["git", "recipient", "--help"]).contains(".sec-recipients"));
    assert!(help(&["security", "pre-receive", "--help"]).contains("--filters ABSOLUTE_PATH"));
    assert!(!root.join("missing").exists());
}

#[test]
fn encrypts_binary_and_armor_without_external_programs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let identity = x25519::Identity::generate();
    let plain = b"native fixture\x00\r\n";
    for armor in ["0", "1"] {
        let result = pipe(
            command(&root)
                .arg("e")
                .env("SEC_RECIPIENT", identity.to_public().to_string())
                .env("SEC_ARMOR", armor),
            plain,
        );
        ok(&result);
        let prefix = if armor == "1" {
            &b"-----BEGIN AGE ENCRYPTED FILE-----"[..]
        } else {
            &b"age-encryption.org/v1\n"[..]
        };
        assert!(result.stdout.starts_with(prefix));
        let decryptor = age::Decryptor::new(ArmoredReader::new(result.stdout.as_slice())).unwrap();
        let mut output = Vec::new();
        decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        assert_eq!(output, plain);
    }
}

#[test]
fn rejects_already_encrypted_input() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let recipient = x25519::Identity::generate().to_public().to_string();
    let result = pipe(
        command(&root).arg("e").env("SEC_RECIPIENT", recipient),
        b"age-encryption.org/v1\n",
    );
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn recipient_only_prints_valid_public_material() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let output = command(&root)
        .arg("recipient")
        .env("SEC_RECIPIENT", "invalid fixture")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    };

    fn write_key(path: &Path, identity: &x25519::Identity) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        writeln!(file, "{}", identity.to_string().expose_secret()).unwrap();
    }

    #[test]
    fn reads_private_identity_and_decrypts_an_age_stream() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let key = root.join("identity");
        let identity = x25519::Identity::generate();
        write_key(&key, &identity);
        let recipient = command(&root)
            .arg("recipient")
            .env("SEC_IDENTITY", &key)
            .output()
            .unwrap();
        ok(&recipient);
        assert_eq!(
            recipient.stdout,
            format!("{}\n", identity.to_public()).as_bytes()
        );
        let plain = b"synthetic plaintext";
        let cipher = age::encrypt(&identity.to_public(), plain).unwrap();
        let result = pipe(command(&root).arg("d").env("SEC_IDENTITY", key), &cipher);
        ok(&result);
        assert_eq!(result.stdout, plain);
    }

    #[test]
    fn replaces_in_place_only_after_success_with_private_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let key = root.join("identity");
        let path = root.join("message");
        let identity = x25519::Identity::generate();
        write_key(&key, &identity);
        fs::write(&path, "synthetic").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let encrypted = command(&root)
            .arg("e")
            .arg(&path)
            .env("SEC_IDENTITY", &key)
            .output()
            .unwrap();
        ok(&encrypted);
        let mut payload = fs::read(&path).unwrap();
        let decrypted = command(&root)
            .arg("d")
            .arg(&path)
            .env("SEC_IDENTITY", &key)
            .output()
            .unwrap();
        ok(&decrypted);
        assert_eq!(fs::read(&path).unwrap(), b"synthetic");
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);

        payload.pop();
        fs::write(&path, &payload).unwrap();
        let failed = command(&root)
            .arg("d")
            .arg(&path)
            .env("SEC_IDENTITY", &key)
            .output()
            .unwrap();
        assert!(!failed.status.success());
        assert_eq!(fs::read(&path).unwrap(), payload);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }

    #[test]
    fn refuses_a_public_identity_and_symlink_targets() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let key = root.join("identity");
        let path = root.join("message");
        let link = root.join("message-link");
        let identity = x25519::Identity::generate();
        write_key(&key, &identity);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let refused = command(&root)
            .arg("identity")
            .env("SEC_IDENTITY", &key)
            .output()
            .unwrap();
        assert!(!refused.status.success());

        fs::write(&path, "synthetic").unwrap();
        symlink(&path, &link).unwrap();
        let refused = command(&root)
            .arg("e")
            .arg(&link)
            .env("SEC_RECIPIENT", identity.to_public().to_string())
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert_eq!(fs::read(&path).unwrap(), b"synthetic");
    }
}

#[cfg(windows)]
#[test]
fn windows_decrypts_only_with_private_identity_dacl() {
    use age::secrecy::ExposeSecret;
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let key = root.join("identity");
    let identity = x25519::Identity::generate();
    fs::write(&key, format!("{}\n", identity.to_string().expose_secret())).unwrap();
    let account = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    ok(&account);
    let record = String::from_utf8_lossy(&account.stdout);
    let sid = record
        .trim()
        .rsplit_once(',')
        .unwrap()
        .1
        .trim()
        .trim_matches('"');
    assert!(sid.starts_with("S-1-"), "invalid account SID from whoami");
    let account = format!("*{sid}");
    ok(&Command::new("icacls.exe")
        .arg(&key)
        .args(["/setowner", &account, "/q"])
        .output()
        .unwrap());
    let grant = format!("{account}:(F)");
    ok(&Command::new("icacls.exe")
        .arg(&key)
        .args(["/inheritance:r", "/grant:r", &grant, "/q"])
        .output()
        .unwrap());

    let plain = b"Windows fixture";
    let cipher = age::encrypt(&identity.to_public(), plain).unwrap();
    let valid = pipe(command(&root).arg("d").env("SEC_IDENTITY", &key), &cipher);
    ok(&valid);
    assert_eq!(valid.stdout, plain);

    ok(&Command::new("icacls.exe")
        .arg(&key)
        .args(["/grant:r", "*S-1-1-0:(R)", "/q"])
        .output()
        .unwrap());
    let invalid = pipe(command(&root).arg("d").env("SEC_IDENTITY", &key), &cipher);
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
}

#[test]
fn runner_fixture() {
    if std::env::var_os("NATIVE_SEC_TEST_CHILD").is_none() {
        return;
    }
    assert_eq!(
        std::env::var("FIXTURE_NATIVE_TOKEN").unwrap(),
        "from store\n\n"
    );
    let resource = std::env::var_os("FIXTURE_NATIVE_FILE").unwrap();
    assert_eq!(std::fs::read(resource).unwrap(), b"from store\n\n");
    assert!(std::env::var_os("SEC_RUN_DIR").is_some());
}

#[test]
fn native_store_and_runner_work_without_a_scripting_runtime() {
    let mut workspace = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        workspace.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let temp = workspace.prefix("sec-test-").tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let store = root.join("store");
    let key = root.join("identity");
    let identity = x25519::Identity::generate();
    write_private_test_key(&key, &identity);
    let settings = [
        ("SEC_STORE_DIR", store.clone().into_os_string()),
        ("SEC_IDENTITY", key.into_os_string()),
        ("SEC_STORE_ALLOW_SELF", "1".into()),
        ("SEC_RUN_TMPDIR", root.clone().into_os_string()),
        ("SEC_APPROVAL_DIR", root.join("approvals").into_os_string()),
        ("XDG_STATE_HOME", root.join("state").into_os_string()),
        ("LOCALAPPDATA", root.join("local").into_os_string()),
    ];
    let make = || {
        let mut command = command(&root);
        command
            .current_dir(&root)
            .envs(settings.iter().map(|(name, value)| (name, value)));
        command
    };
    ok(&make().args(["store", "init"]).output().unwrap());
    ok(&pipe(
        make().args(["store", "put", "fixture"]),
        b"from store\n\n",
    ));
    let result = make().args(["store", "get1", "fixture"]).output().unwrap();
    ok(&result);
    assert_eq!(result.stdout, b"from store");

    let target = std::env::current_exe().unwrap();
    let result = make()
        .env("NATIVE_SEC_TEST_CHILD", "1")
        .args([
            "run",
            "-v",
            "FIXTURE_NATIVE_TOKEN=fixture",
            "-f",
            "FIXTURE_NATIVE_FILE=fixture",
            "--",
        ])
        .arg(target)
        .args(["--exact", "runner_fixture"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&[result.stdout, result.stderr].concat())
    );
    let forwarded = make()
        .args([
            "run",
            "-s",
            "FIXTURE=1",
            "--",
            env!("CARGO_BIN_EXE_sec"),
            "--help",
        ])
        .output()
        .unwrap();
    ok(&forwarded);
    assert_eq!(
        forwarded.stdout,
        make().arg("--help").output().unwrap().stdout
    );
    assert!(
        std::fs::read_dir(root.join("sec-run-workspaces"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("run."))
    );
}

#[cfg(unix)]
fn write_private_test_key(path: &Path, identity: &x25519::Identity) {
    use age::secrecy::ExposeSecret;
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    writeln!(file, "{}", identity.to_string().expose_secret()).unwrap();
}

#[cfg(windows)]
fn write_private_test_key(path: &Path, identity: &x25519::Identity) {
    use age::secrecy::ExposeSecret;
    std::fs::write(path, format!("{}\n", identity.to_string().expose_secret())).unwrap();
    let account = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    ok(&account);
    let record = String::from_utf8_lossy(&account.stdout);
    let sid = record
        .trim()
        .rsplit_once(',')
        .unwrap()
        .1
        .trim()
        .trim_matches('"');
    assert!(sid.starts_with("S-1-"));
    let account = format!("*{sid}");
    ok(&Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", &account, "/q"])
        .output()
        .unwrap());
    let grant = format!("{account}:(F)");
    ok(&Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant, "/q"])
        .output()
        .unwrap());
}

#[cfg(windows)]
#[test]
fn windows_replaces_a_file_inside_a_private_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let message = root.join("message");
    let key = root.join("identity");
    let identity = x25519::Identity::generate();
    write_private_test_key(&key, &identity);
    std::fs::write(&message, b"Windows fixture").unwrap();
    ok(&command(&root)
        .arg("e")
        .arg(&message)
        .env("SEC_IDENTITY", &key)
        .output()
        .unwrap());
    assert!(
        std::fs::read(&message)
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );
    ok(&command(&root)
        .arg("d")
        .arg(&message)
        .env("SEC_IDENTITY", &key)
        .output()
        .unwrap());
    assert_eq!(std::fs::read(&message).unwrap(), b"Windows fixture");
}

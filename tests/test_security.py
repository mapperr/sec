import base64
import fcntl
import hashlib
import http.server
import json
import multiprocessing
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import ssl
import subprocess
import tempfile
import time
import unittest
from urllib.parse import urlsplit

PROJECT = Path(__file__).resolve().parents[1]


class SecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("SEC_TEST_BINARY")
        if configured:
            binary = Path(configured).resolve()
        else:
            target = os.environ.get("CARGO_BUILD_TARGET") or "host-tuple"
            if target == "host-tuple":
                target = subprocess.check_output(
                    ["rustc", "--print", "host-tuple"], cwd=PROJECT, text=True
                ).strip()
            target_dir = os.environ.get("CARGO_TARGET_DIR") or os.environ.get("CARGO_BUILD_TARGET_DIR") or "target"
            binary = (PROJECT / target_dir / target / "debug/sec").resolve()
        if not binary.is_file():
            raise FileNotFoundError(f"{binary} is missing. Run cargo build --locked or set SEC_TEST_BINARY.")

        cls.addClassCleanup(os.umask, os.umask(0o077))
        directory = tempfile.TemporaryDirectory(prefix="sec-test-bin-")
        cls.addClassCleanup(directory.cleanup)
        cls.bin_dir = Path(directory.name)
        for name in ("sec", "sec-security", "sec-store-remote-git", "sec-store-fzf"):
            (cls.bin_dir / name).symlink_to(binary)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "project"
        self.runtime = self.root / "runtime"
        self.repo.mkdir()
        self.runtime.mkdir(mode=0o700)
        self.env = {
            "HOME": str(self.root), "PATH": f"{self.bin_dir}:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": str(self.runtime), "LC_ALL": "C",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
            "SEC_IDENTITY": str(self.root / "identity"),
        }
        self.command("age-keygen", "-o", self.env["SEC_IDENTITY"])
        self.recipient = self.command("sec", "recipient").strip()

    def command(self, *args, data=b"", ok=True, env=None, cwd=None):
        result = subprocess.run(args, env=dict(self.env, **(env or {})), cwd=cwd or self.repo,
                                input=data, capture_output=True, timeout=25)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        else:
            self.assertNotEqual(result.returncode, 0)
        return result.stdout

    def approve(self, *args, env=None):
        child, terminal = pty.fork()
        if child == 0:
            os.chdir(self.repo)
            os.execvpe(args[0], args, dict(self.env, **(env or {})))
        output = bytearray()
        status = None
        answered = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([terminal], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(terminal, 4096)
                    except OSError:
                        break
                    output.extend(chunk)
                    if not answered and b"[y/N]" in output:
                        os.write(terminal, b"y\n")
                        answered = True
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                pid, observed = os.waitpid(child, os.WNOHANG)
                if pid:
                    status = observed
                    break
                time.sleep(0.01)
            if status is None:
                self.fail("interactive approval did not terminate: " + output.decode(errors="replace"))
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors="replace"))
            return bytes(output)
        finally:
            os.close(terminal)
            if status is None:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)

    def project_store(self):
        self.command("sec", "store", "init", "--project")
        self.command("sec", "store", "policy", "add", ".", "self")
        self.approve("sec", "store", "policy", "approve")
        return self.repo / ".sec"

    def test_existing_policy_manifest_and_attestation_formats(self):
        def encode(value):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

        def digest(data):
            return hashlib.sha256(data).hexdigest()

        def record_path(directory, kind, key):
            return directory / f"{kind}-{digest(encode(key))}.json"

        self.command("sec", "store", "init", "--project")
        self.command("sec", "store", "policy", "add", ".", "self")
        store = self.repo / ".sec"
        policy = store / "secrets/.recipients"
        policy_digest = digest(policy.read_bytes())
        registry = self.root / ".config/sec/approvals"
        registry.mkdir(mode=0o700, parents=True)
        policy_key = ["store", str(store), "secrets/.recipients"]
        record_path(registry, "policy", policy_key).write_bytes(
            encode({"policy": policy_digest, "path": str(policy)}) + b"\n"
        )
        self.command("sec", "store", "put", "token", data=b"compatibility fixture\n")
        attestation = record_path(self.root / ".local/state/sec/attestations", "cipher",
                                  [str(store), "secrets/token.age"])
        self.assertEqual(
            attestation.read_bytes(),
            encode({"digest": digest((store / "secrets/token.age").read_bytes()),
                    "policy": policy_digest}) + b"\n",
        )

        manifest = store / "manifests/dev"
        manifest.parent.mkdir()
        manifest.write_text("var COMPAT_TOKEN=token\n")
        target = ["printenv", "COMPAT_TOKEN"]
        executable = Path(shutil.which(target[0], path=self.env["PATH"])).resolve()
        manifest_key = [str(store), str(store), "manifests/dev", digest(encode([str(executable), *target]))]
        record_path(registry, "manifest", manifest_key).write_bytes(
            encode({"env_names": {}, "plan": [["var", "COMPAT_TOKEN", str(store), "token"]], "prefixes": []}) + b"\n"
        )
        self.assertEqual(self.command("sec", "run", "-m", "dev", "--", *target), b"compatibility fixture\n\n")

    def test_ssh_age_compatibility(self):
        key = self.root / "ssh"
        self.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        settings = {"SEC_IDENTITY": str(key), "SEC_ARMOR": "1"}
        public = key.with_suffix(".pub").read_text().split()[:2]
        self.assertEqual(self.command("sec", "recipient", env=settings).decode().split()[:2], public)
        plaintext = b"ssh compatibility fixture\0\n"
        armored = self.command("sec", "e", env=settings, data=plaintext)
        self.assertTrue(armored.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"))
        self.assertEqual(self.command("sec", "d", env=settings, data=armored), plaintext)

    def test_git_rekey_requires_an_active_filter(self):
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Sec Test")
        self.command("git", "config", "user.email", "sec@example.invalid")
        content = b"fixture plaintext"
        encrypted = self.command("sec", "e", data=content)
        path = self.repo / "token"
        path.write_bytes(encrypted)
        (self.repo / ".gitattributes").write_text("token filter=sec diff=sec -text\n")
        self.command("git", "add", "token", ".gitattributes")
        self.command("git", "commit", "-qm", "encrypted fixture")
        path.write_bytes(content)
        self.command("sec", "git", "rekey", ok=False)
        self.assertEqual(self.command("git", "show", ":token"), encrypted)

    def test_core_stream_and_in_place_permissions(self):
        plaintext = b"synthetic fixture\n\n"
        for armor in ("0", "1"):
            ciphertext = self.command("sec", "e", data=plaintext, env={"SEC_ARMOR": armor})
            self.assertEqual(self.command("sec", "d", data=ciphertext), plaintext)
        path = self.repo / "example"
        path.write_bytes(plaintext)
        path.chmod(0o644)
        self.command("sec", "e", str(path))
        self.command("sec", "d", str(path))
        self.assertEqual(path.read_bytes(), plaintext)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        link = self.repo / "link"
        link.symlink_to(path)
        self.command("sec", "e", str(link), ok=False)

    def test_policy_and_attestation(self):
        self.command("sec", "store", "init", "--project")
        self.command("sec", "store", "policy", "add", ".", "self")
        self.command("sec", "store", "put", "value", data=b"sample", ok=False)
        self.approve("sec", "store", "policy", "approve")
        self.command("sec", "store", "put", "value", data=b"sample")
        self.assertEqual(self.command("sec", "store", "get", "value"), b"sample")
        file = self.repo / ".sec/secrets/value.age"
        file.write_bytes(self.command("sec", "e", data=b"separate age file"))
        self.assertEqual(self.command("sec", "store", "get", "value", ok=False), b"")
        self.command("sec", "store", "check", "--attest")
        self.assertEqual(self.command("sec", "store", "get", "value"), b"separate age file")
        self.command("sec", "store", "rekey")
        (self.repo / ".sec/secrets/.recipients").write_bytes(b"# new revision\n" + self.recipient + b"\n")
        self.command("sec", "store", "put", "value", data=b"new", ok=False)
        self.assertEqual(self.command("sec", "store", "get", "value"), b"separate age file")

    def test_group_approval_and_semantic_changes(self):
        store = self.project_store()
        self.command("sec", "store", "put", "token", data=b"example\n\n")
        self.command("sec", "store", "put", "settings", data=b"EXAMPLE_ONE=fixture\n")
        (store / "manifests").mkdir()
        manifest = store / "manifests/dev"
        manifest.write_text("var EXAMPLE_TOKEN=token\nenv settings\nset EXAMPLE_LABEL=test\n")
        launch = ("sec", "run", "-m", "dev", "--", "printenv", "EXAMPLE_TOKEN", "EXAMPLE_ONE")
        self.command(*launch, ok=False)
        preview = self.command("sec", "run", "-m", "dev")
        self.assertIn(b"EXAMPLE_TOKEN", preview)
        self.assertNotIn(b"fixture", preview)
        self.approve("sec", "run", "manifest", "approve", "dev", "--env-name", "EXAMPLE_ONE",
                     "--", "printenv", "EXAMPLE_TOKEN", "EXAMPLE_ONE")
        self.assertEqual(self.command(*launch), b"example\n\n\nfixture\n")
        manifest.write_text("# comment\nset EXAMPLE_LABEL=test\nenv settings\nvar EXAMPLE_TOKEN=token\n")
        self.assertEqual(self.command(*launch), b"example\n\n\nfixture\n")
        self.command("sec", "store", "put", "settings", data=b"EXAMPLE_ONE=fixture\nEXTRA=value\n")
        self.assertEqual(self.command(*launch, ok=False), b"")
        manifest.write_text("var EXAMPLE_TOKEN=token\nset EXAMPLE_LABEL=changed\n")
        self.command(*launch, ok=False)
        self.command("sec", "run", "-s", "PATH=/usr/bin", "--", "printenv", "PATH", ok=False)
        self.command("sec", "run", "manifest", "rm", str(manifest), ok=False)
        self.assertTrue(manifest.exists())

    def test_prefix_grant_and_revoke(self):
        store = self.project_store()
        team = self.root / "team"
        self.command("sec", "store", "init", env={"SEC_STORE_DIR": str(team)})
        team_env = {"SEC_STORE_DIR": str(team), "SEC_STORE_ALLOW_SELF": "1"}
        self.command("sec", "store", "put", "scope/one", data=b"first", env=team_env)
        self.command("sec", "store", "put", "scope/two", data=b"second", env=team_env)
        self.command("sec", "store", "put", "elsewhere/three", data=b"third", env=team_env)
        (store / "stores").write_text(f"team file://{team}\n")
        (store / "manifests").mkdir()
        manifest = store / "manifests/dev"
        manifest.write_text("var ONE=team::scope/one\n")
        target = ("--", "sh", "-c", 'printf "%s/%s" "$ONE" "${TWO:-none}"')
        self.approve("sec", "run", "manifest", "approve", "dev", *target)
        self.approve("sec", "run", "manifest", "grant", "dev", "--prefix", "team::scope/", *target)
        manifest.write_text("var ONE=team::scope/one\nvar TWO=team::scope/two\n")
        self.assertEqual(self.command("sec", "run", "-m", "dev", *target), b"first/second")
        manifest.write_text("var ONE=team::scope/one\nvar TWO=team::elsewhere/three\n")
        self.command("sec", "run", "-m", "dev", *target, ok=False)
        self.command("sec", "run", "manifest", "revoke", "dev", "--prefix", "team::scope/", *target)
        manifest.write_text("var ONE=team::scope/one\nvar TWO=team::scope/two\n")
        self.command("sec", "run", "-m", "dev", *target, ok=False)

    def test_file_injection_preserves_stdin(self):
        self.project_store()
        self.command("sec", "store", "put", "token", data=b"from file\n")
        code = 'test "$(stat -c %a "$EXAMPLE_FILE")" = 600 && cat "$EXAMPLE_FILE" -'
        self.assertEqual(self.command("sec", "run", "-f", "EXAMPLE_FILE=token", "--",
                                      "sh", "-c", code, data=b"stdin\n"), b"from file\nstdin\n")
        self.assertEqual(list((self.runtime / "sec-run-workspaces").glob("run.*")), [])
        self.command("sec", "run", "-M", "personal::missing", "--", "true")

    def test_staging_blocks_unmanaged_and_plaintext_files(self):
        store = self.project_store()
        self.command("git", "init", "-q")
        self.command("sec", "store", "put", "token", data=b"synthetic token")
        unexpected = store / "secrets" / "plaintext.age"
        unexpected.write_text("synthetic plaintext")
        self.command("sec-security", "stage-store", str(store), ok=False)
        self.assertEqual(self.command("git", "ls-files"), b"")
        unexpected.unlink()
        self.command("sec-security", "stage-store", str(store))
        self.assertEqual(self.command("git", "ls-files"), b".sec/secrets/.recipients\n.sec/secrets/token.age\n")

    def test_store_sync_pushes_a_verified_signed_commit(self):
        store = self.project_store()
        self.command("sec", "store", "put", "token", data=b"sync fixture")
        self.command("git", "init", "-q", cwd=store)
        self.command("git", "config", "user.name", "Sec Test", cwd=store)
        self.command("git", "config", "user.email", "sec@example.invalid", cwd=store)
        signer = self.root / "signer"
        self.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signer))
        allowed = self.root / "allowed-signers"
        allowed.write_bytes(b"sec@example.invalid " + signer.with_suffix(".pub").read_bytes())
        self.command("git", "config", "user.signingkey", str(signer), cwd=store)
        bare = self.root / "receiver.git"
        self.command("git", "init", "-q", "--bare", str(bare))
        self.command("git", "remote", "add", "origin", str(bare), cwd=store)
        self.command("sec", "store", "y", env={"SEC_GIT_ALLOWED_SIGNERS": str(allowed)}, cwd=store)
        revision = self.command("git", "rev-parse", "HEAD", cwd=store).strip()
        self.assertEqual(self.command("git", "rev-parse", "HEAD", cwd=bare).strip(), revision)
        self.assertIn(b"age-encryption.org/v1", self.command("git", "show", "HEAD:secrets/token.age", cwd=bare))

    def test_cache_pruning_preserves_current_and_leased_snapshots(self):
        cache = self.root / "cache"
        cache.mkdir(mode=0o700)
        source = cache / ("a" * 40)
        source.mkdir(mode=0o700)
        (source / "current").write_text("snap.current\n")
        for name in ("current", "live", "unused"):
            (source / f"snap.{name}").mkdir(mode=0o700)
        live = source / "snap.live"
        fd = os.open(live, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            self.command("sec", "store", "cache", "prune", env={"SEC_STORE_CACHE_DIR": str(cache)})
            self.assertFalse((source / "snap.unused").exists())
            self.assertTrue(live.is_dir())
        finally:
            os.close(fd)
        self.command("sec", "store", "cache", "prune", env={"SEC_STORE_CACHE_DIR": str(cache)})
        self.assertFalse(live.exists())
        self.assertTrue((source / "snap.current").is_dir())

    def test_git_filter_refuses_to_deactivate_with_plaintext(self):
        self.command("git", "init", "-q")
        self.command("sec", "git", "on")
        self.command("sec", "git", "recipient", "add", self.recipient.decode())
        self.approve("sec", "git", "recipient", "approve")
        self.command("sec", "git", "track", "secret")
        (self.repo / "secret").write_text("fixture")
        self.command("git", "add", "--", ".gitattributes", ".sec-recipients", "secret")
        cipher = self.command("git", "show", ":secret")
        self.assertEqual(self.command("sec", "d", data=cipher), b"fixture")
        self.command("git", "add", "--", "secret")
        self.assertEqual(self.command("git", "show", ":secret"), cipher)
        self.command("sec", "git", "off", ok=False)
        self.command("sec", "git", "untrack", "secret", ok=False)
        self.assertEqual(self.command("git", "config", "--get", "filter.sec.required"), b"true\n")
        self.assertEqual(self.command("sec", "git", "smudge", data=b"plaintext", ok=False), b"")
        self.assertEqual(self.command("sec", "git", "smudge", data=cipher), cipher)
        self.command("git", "config", "user.name", "Sec Test")
        self.command("git", "config", "user.email", "sec@example.invalid")
        self.command("git", "commit", "-qm", "initial")
        (self.repo / "secret").write_bytes(cipher)
        self.command("sec", "git", "refresh")
        self.assertEqual((self.repo / "secret").read_bytes(), b"fixture")
        self.assertEqual((self.repo / "secret").stat().st_mode & 0o777, 0o600)

    def test_otp_extracts_one_seed_from_a_multiline_entry(self):
        self.project_store()
        seed = base64.b32encode(b"test seed!")
        self.command("sec", "store", "put", "otp", data=b"totp: " + seed + b"\n")
        generator = {
            "SEC_STORE_OTP_CMD": 'touch "$HOME/otp-called"; test "$(cat)" = "$FIXTURE_SEED" && printf "012345\\n"',
            "FIXTURE_SEED": seed.decode(),
        }
        command = ("sec", "store", "otp", "otp")
        self.assertEqual(self.command(*command, env=generator), b"012345\n")
        entry = b"password fixture\r\nnote: totp: example\r\n  totp: " + seed.lower() + b" \r\nnotes"
        self.command("sec", "store", "put", "otp", data=entry)
        self.assertEqual(self.command(*command, env=generator), b"012345\n")
        self.assertRegex(self.command(*command), rb"^[0-9]{6}\n$")
        self.assertEqual(self.command("sec", "store", "fzf", "--otp", "otp",
                                      env={**generator, "SEC_STORE_FZF_CLIP_CMD": "cat"}), b"012345")

        marker = self.root / "otp-called"
        marker.unlink()
        invalid = {"missing": b"note: totp: example", "empty": b"notes\ntotp:  ",
                   "duplicate": entry + b"\ntotp: " + seed, "invalid seed": b"totp: 1234"}
        for label, data in invalid.items():
            with self.subTest(label=label):
                self.command("sec", "store", "put", "otp", data=data)
                self.assertEqual(self.command(*command, env=generator, ok=False), b"")
                self.assertFalse(marker.exists())

    def test_clipboard_and_autotype_release_only_valid_output(self):
        self.project_store()
        self.command("sec", "store", "put", "token", data=b"first\nsecond\n")
        clipboard = {"SEC_STORE_FZF_CLIP_CMD": "cat"}
        self.assertEqual(self.command("sec-store-fzf", "--copy-first", "token", env=clipboard), b"first")
        self.assertEqual(self.command("sec-store-fzf", "--copy-full", "token", env=clipboard), b"first\nsecond\n")
        self.assertEqual(self.command("sec-store-fzf", "--copy-full", "missing", env=clipboard, ok=False), b"")
        typing = self.root / "xdotool"
        typing.write_text('#!/bin/sh\ncase $1 in getactivewindow) echo 123;; key) printf "\\t";; type) cat;; esac\n')
        typing.chmod(0o700)
        settings = {"SEC_STORE_TYPING_TOOL": "xdotool", "PATH": f"{self.root}:{self.env['PATH']}"}
        self.assertEqual(self.command("sec", "store", "type", "token", env=settings), b"token\tfirst")
        self.command("sec", "store", "put", "token", data=b"bad\0text\n")
        self.assertEqual(self.command("sec", "store", "type", "token", env=settings, ok=False), b"")

    def test_clipboard_uses_a_timed_sensitive_offer_on_wayland(self):
        self.project_store()
        self.command("sec", "store", "put", "token", data=b"synthetic first line\nsecond line\n")

        helpers = self.root / "helpers"
        helpers.mkdir()
        scripts = {
            "wl-copy": 'if [ "${1:-}" = --help ]; then printf "%s\\n" --sensitive; exit; fi\n'
                       'printf "%s\\n" "$@" > "$HOME/wayland-args"\ncat > "$HOME/copied"\n',
            "timeout": 'printf "%s\\n" "$1" > "$HOME/copy-timeout"\nshift\nexec "$@"\n',
            "xclip": 'printf "%s\\n" "$@" > "$HOME/x11-args"\ncat > "$HOME/copied"\n',
        }
        for name, script in scripts.items():
            path = helpers / name
            path.write_text("#!/bin/sh\n" + script)
            path.chmod(0o700)

        command = ("sec", "store", "fzf", "--copy-first", "token")
        path = f"{helpers}:{self.env['PATH']}"
        settings = {"PATH": path, "WAYLAND_DISPLAY": "wayland-fixture"}
        self.command(*command, env=settings)
        self.assertEqual((self.root / "copied").read_bytes(), b"synthetic first line")
        self.assertEqual((self.root / "wayland-args").read_text().splitlines(),
                         ["--foreground", "--sensitive"])
        timeout = self.root / "copy-timeout"
        self.assertEqual(timeout.read_text().strip(), "30")
        timeout.unlink()

        self.command(*command, env={**settings, "SEC_STORE_FZF_PASTE_ONCE": "1"})
        self.assertEqual((self.root / "wayland-args").read_text().splitlines(),
                         ["--paste-once", "--sensitive"])
        self.assertFalse(timeout.exists())
        self.command(*command, env={**settings, "SEC_STORE_FZF_PASTE_ONCE": "0"})
        self.assertEqual((self.root / "wayland-args").read_text().splitlines(), ["--sensitive"])
        self.assertFalse(timeout.exists())

        self.command(*command, env={"PATH": path, "DISPLAY": ":99"})
        self.assertEqual((self.root / "x11-args").read_text().splitlines(),
                         ["-selection", "clipboard", "-loops", "1"])

    def test_signed_receiver_rejects_plaintext(self):
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Sec Test")
        self.command("git", "config", "user.email", "sec@example.invalid")
        signer = self.root / "signer"
        self.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signer))
        allowed = self.root / "allowed-signers"
        allowed.write_bytes(b"sec@example.invalid " + signer.with_suffix(".pub").read_bytes())
        self.command("git", "config", "gpg.format", "ssh")
        self.command("git", "config", "user.signingkey", str(signer))
        folder = self.repo / "secrets"
        folder.mkdir()
        path = folder / "token.age"
        path.write_bytes(self.command("sec", "e", data=b"fixture"))
        self.command("git", "add", ".")
        self.command("git", "commit", "-q", "-S", "-m", "ciphertext")
        first = self.command("git", "rev-parse", "HEAD").strip()
        receiver = ("sec-security", "pre-receive", str(self.repo), "--store")
        env = {"SEC_GIT_ALLOWED_SIGNERS": str(allowed)}
        self.command(*receiver, data=b"0" * len(first) + b" " + first + b" refs/heads/example\n", env=env)
        path.write_text("plaintext fixture")
        self.command("git", "add", ".")
        self.command("git", "commit", "-q", "-S", "-m", "invalid")
        last = self.command("git", "rev-parse", "HEAD").strip()
        self.command(*receiver, data=first + b" " + last + b" refs/heads/example\n", env=env, ok=False)

    def test_https_remote_manifest_composes_with_personal_store(self):
        store = self.project_store()
        origin = self.root / "upstream"
        origin.mkdir()
        (origin / "secrets").mkdir()
        (origin / "manifests").mkdir()
        (origin / "secrets/token.age").write_bytes(self.command("sec", "e", data=b"shared token"))
        manifest = origin / "manifests/dev"
        manifest.write_text("var SHARED_TOKEN=token\n")
        self.command("git", "init", "-q", cwd=origin)
        self.command("git", "-c", "user.name=Sec Test", "-c", "user.email=sec@example.invalid",
                     "add", ".", cwd=origin)
        self.command("git", "-c", "user.name=Sec Test", "-c", "user.email=sec@example.invalid",
                     "commit", "-qm", "remote manifest", cwd=origin)
        commit = self.command("git", "rev-parse", "HEAD", cwd=origin).decode().strip()
        self.command("git", "clone", "-q", "--bare", str(origin), str(self.root / "team.git"))

        cert = self.root / "cert.pem"
        key = self.root / "tls.key"
        self.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(key), "-out", str(cert), "-days", "1",
                     "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
        project_root = str(self.root)

        class GitHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle_git(self):
                url = urlsplit(self.path)
                environment = dict(
                    PATH="/usr/bin:/bin", GIT_PROJECT_ROOT=project_root, GIT_HTTP_EXPORT_ALL="1",
                    PATH_INFO=url.path, QUERY_STRING=url.query, REQUEST_METHOD=self.command,
                    CONTENT_TYPE=self.headers.get("Content-Type", ""),
                    CONTENT_LENGTH=self.headers.get("Content-Length", "0"),
                    HTTP_GIT_PROTOCOL=self.headers.get("Git-Protocol", ""),
                )
                data = self.rfile.read(int(environment["CONTENT_LENGTH"]))
                response = subprocess.run(["git", "http-backend"], env=environment,
                                          input=data, capture_output=True, check=True).stdout
                headers, _, body = response.partition(b"\r\n\r\n")
                self.send_response(200)
                for header in headers.decode().splitlines():
                    name, value = header.split(":", 1)
                    self.send_header(name, value.strip())
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = handle_git
            do_POST = handle_git

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GitHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = multiprocessing.get_context("fork").Process(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)

        def stop_server():
            worker.terminate()
            worker.join(timeout=5)

        self.addCleanup(stop_server)
        source = f"git+https://127.0.0.1:{server.server_port}/team.git#{commit}"
        (store / "stores").write_text("shared " + source + "\n")
        settings = {"SEC_STORE_GIT_CAINFO": str(cert)}
        self.command("sec", "store", "dir", "shared", env=settings, ok=False)
        self.approve("sec", "store", "remote-git", "trust", source)
        self.assertEqual(self.command("sec", "store", "get", "shared::token", env=settings), b"shared token")

        personal = self.root / ".local/share/sec"
        personal_env = {"SEC_STORE_DIR": str(personal)}
        self.command("sec", "store", "init", env=personal_env)
        self.command("sec", "store", "put", "token", data=b"personal token", env=personal_env)
        (personal / "manifests").mkdir()
        (personal / "manifests/dev").write_text("var PERSONAL_TOKEN=token\n")
        target = ("--", "printenv", "SHARED_TOKEN", "PERSONAL_TOKEN")
        self.approve("sec", "run", "manifest", "approve", "shared::dev", *target, env=settings)
        self.approve("sec", "run", "manifest", "approve", "personal::dev", *target, env=settings)
        self.assertEqual(
            self.command("sec", "run", "-m", "shared::dev", "-m", "personal::dev", *target, env=settings),
            b"shared token\npersonal token\n",
        )

    def test_remote_requires_authorized_origin_and_validates_the_snapshot(self):
        self.command("git", "init", "-q")
        self.command("git", "config", "user.name", "Sec Test")
        self.command("git", "config", "user.email", "sec@example.invalid")
        (self.repo / "secrets").mkdir()
        cipher = self.command("sec", "e", data=b"shared fixture")
        (self.repo / "secrets/token.age").write_bytes(cipher)
        self.command("git", "add", ".")
        self.command("git", "commit", "-qm", "Store fixture")
        commit = self.command("git", "rev-parse", "HEAD").decode().strip()
        origin = "git+https://example.invalid/team.git"
        snapshot = self.root / "snapshot"
        snapshot.mkdir(mode=0o700)
        backend = ("sec-store-remote-git", "check", f"{origin}#{commit}", str(snapshot))
        self.command(*backend, ok=False)
        self.approve("sec-store-remote-git", "trust", f"{origin}#{commit}")
        self.command("git", "clone", "--quiet", "--bare", str(self.repo),
                     str(snapshot / ".sec-remote-git"))
        (snapshot / ".sec-remote-source").write_text(origin + "\n")
        (snapshot / ".sec-remote-commit").write_text(commit + "\n")
        (snapshot / "secrets").mkdir()
        token = snapshot / "secrets/token.age"
        token.write_bytes(cipher)
        self.command(*backend)
        self.assertEqual(self.command("sec", "store", "get", "token", env={"SEC_STORE_DIR": str(snapshot)}),
                         b"shared fixture")
        token.write_bytes(self.command("sec", "e", data=b"edited fixture"))
        self.command(*backend, ok=False)


if __name__ == "__main__":
    unittest.main()

# sec

`sec` manages age-encrypted secrets with a single Rust executable for Linux, macOS and Windows. It provides automatic identity discovery, private in-place file operations, Git filters, personal and shared stores, and temporary secret injection into commands.

Standard age encryption, ASCII armor and TOTP are built in. The executable starts without a Python or shell runtime. The age format is shared with [age](https://github.com/FiloSottile/age).

## Install

From the repository root, with Rust 1.91 or newer, install `sec` into Cargo's bin directory or build the executable to copy to a trusted directory on `PATH`.

```sh
cargo install --path . --locked
cargo build --locked --release
```

Cargo builds for the host target by default. Find the target triple with `rustc --print host-tuple`. Release builds produce `target/<target-triple>/release/sec` or `target/<target-triple>/release/sec.exe` on Windows.

- Linux builds statically link the C runtime selected by the target (glibc or musl). Install the libc and compiler runtime static archives for your toolchain if your distribution packages them separately.
- Windows MSVC builds statically link the C runtime and use the platform's system DLLs.
- macOS builds use the system libraries and frameworks through dynamic linking.

Run `sec` to see the available commands. For detailed help, use `sec store --help` or `sec help run manifest edit`.

On Unix, run `just build` followed by `just link` to create `$HOME/bin/sec` as a symlink to the release build.

### Optional integrations

- SSH recipients and passphrase-encrypted identities use Go `age` 1.2.1 or newer. Deriving an SSH recipient from a private key uses `ssh-keygen`. Install any hardware plugins you need and list their names in `SEC_AGE_PLUGINS`.
- Git filters and Git-backed stores use Git. SSH transport and signature operations use OpenSSH.
- `sec store fzf` uses `fzf` and the available clipboard and desktop integrations. It reads `FZF_DEFAULT_OPTS` and `FZF_DEFAULT_OPTS_FILE`. On Unix, Ctrl-/ toggles an in-menu preview, Ctrl-V opens the pager, and the built-in bindings use `/bin/sh`. On Windows, Ctrl-/ and Ctrl-V open the pager. Explicit shell callbacks such as `SEC_STORE_FZF_CLIP_CMD` and `SEC_STORE_OTP_CMD` use the system shell.

On Wayland, `sec store fzf` marks copies as sensitive when `wl-copy` supports `--sensitive`. With `timeout` available, this offer lasts up to 30 seconds so a clipboard watcher or an XWayland app can make multiple requests. `SEC_STORE_FZF_PASTE_ONCE=1` limits the offer to one request. `SEC_STORE_FZF_PASTE_ONCE=0` keeps the offer until replaced. Clipboard history depends on how the manager handles the sensitivity hint.

### Upgrade from earlier installations

Use `sec git`, `sec run`, `sec store` and `sec security` in existing commands and hooks. Update calls to `sec-store-*` to use `sec store` and the corresponding subcommand. Unix users can also point symlinks with the previous tool names at the same `sec` executable. `sec security` keeps the `stage-store` and `pre-receive` commands. Use `sec git on` from each checkout that uses the Git filters to update its local filter commands. Include `--textconv` if you enabled plaintext diffs there.

Existing ciphertext, stores, recipient approvals and attestations use the same formats. The location of the store matters to path-bound recipient approvals and attestations. If you previously installed the scripts, remove the retired copies or replace their links in the directories you used, and check that `sec` resolves to the installed binary.

### Configuration and state

Keep the approval registry and signing policy outside project checkouts. The default registry is `${XDG_CONFIG_HOME:-$HOME/.config}/sec/approvals`. Local provenance records live in `${XDG_STATE_HOME:-$HOME/.local/state}/sec/attestations`. These private directories are owned by the current user. A CI runner can provision a private registry through `SEC_APPROVAL_DIR`. The controls rely on a trusted account, installed tools and executable. The launched application can read the secrets it receives.

On Windows, configuration and the personal store default to `%APPDATA%/sec`. Cache, attestations and runtime files default to `%LOCALAPPDATA%/sec`. Windows checks ownership and access control lists on private identities and destinations. In-place operations require a trusted private parent directory.

## Basic usage

```sh
# Encrypt/decrypt a stream. Encryption uses native (binary) age by default.
printf 'hi mom!\n' | sec e > greeting.age
sec d < greeting.age
# hi mom!

# Ask for ASCII armor when a text-only transport requires it.
SEC_ARMOR=1 sec e < greeting.txt > greeting-armored.age

# Encrypt/decrypt a file in place (the pathname stays the same).
sec e ./secret.txt
sec d ./secret.txt
```

`sec e` rejects input already recognized as age-encrypted; `sec d` rejects plaintext. Decryption accepts both native and armored age files. Avoid writing binary ciphertext directly to your terminal: redirect it to a file or another command.

### Identities and recipients

`sec` discovers decryption identities in this order:

1. `SEC_IDENTITY`
2. `identity` in `SEC_CONFIG_DIR` or the platform's default `sec` configuration directory
3. `~/.ssh/id_ed25519`, with `SEC_ALLOW_SSH_IDENTITIES=1`
4. `~/.ssh/id_rsa`, with the same opt-in
5. Additional identity **paths** listed in the config file `identities`, one per line (including explicitly configured plugin identities)

```sh
sec identity             # first discovered identity
sec identity --all       # all discovered identities
sec recipient            # your public self-recipient, if derivable
```

Identity files must be private, user-owned regular files. Configure `SEC_AGE_PLUGINS` with the names of trusted age plugins needed for your identities or recipients. Without explicit recipients, encryption falls back to your own recipient. To encrypt for other people or machines, use `SEC_RECIPIENTS` or `SEC_RECIPIENTS_FILE`:

```sh
SEC_RECIPIENTS_FILE=./team.recipients sec e < secret.txt > secret.age
```

An explicit recipient list is authoritative: **your own recipient is not added automatically**. Keep private identities out of the repository; public recipient files may be committed. `SEC_ARMOR=1` requests ASCII-armored output; the default is binary.

## Git integration

`sec git` uses Git clean/smudge filters and `.gitattributes` to keep age ciphertext in Git. Checkout keeps ciphertext by default. Use `sec git refresh` to materialize private plaintext files for editing.

```sh
cd /path/to/git/repo
sec git on
sec git recipient add 'ssh-ed25519 AAAA... alice@laptop'
sec git recipient approve
sec git track '.env' 'secrets/*.json'
git add .gitattributes .sec-recipients .env secrets/
git commit -m 'Add encrypted project secrets'
```

The generated `.gitattributes` entries use `filter=sec diff=sec -text`, so the binary ciphertext is not subject to text normalization. A subsequent `git add` of unchanged plaintext can reuse the indexed ciphertext under an unchanged approved policy, avoiding noisy changes caused by age's randomized encryption.

```sh
sec git status           # state, recipients and tracked paths
sec git recipient list
sec git recipient rm 'ssh-ed25519 AAAA... alice@laptop'
sec git rekey            # re-encrypt filtered tracked files and stage new blobs
sec git refresh          # materialize plaintext with mode 0600
sec git off
```

Aliases include `sec git l`, `a`, `r`, `t`, `u`, and `f`; see `sec git --help` for the full interface. Git's filter configuration is local to each checkout. Approve the recipient policy before enabling filters in an existing checkout. `SEC_GIT_SMUDGE_PLAINTEXT=1` enables plaintext on checkout for a trusted private working tree with Git running under `umask 077`. `sec git on --textconv` enables plaintext diffs. `off` and `untrack` refuse to leave protected plaintext behind. **Commit `.sec-recipients` in plaintext**: its recipient entries are public, and encrypting the policy complicates bootstrap and recovery. Removing a recipient and re-encrypting does not revoke access to older Git history or credentials they already knew; rotate underlying credentials when revoking access.

## Encrypted store

`sec store` keeps each secret as an encrypted `.age` entry. It can be used as a personal store, a project store committed with the application, or a shared store referenced from other stores.

```sh
sec store init
printf '%s\n' 'example-password' | sec store put personal/example
sec store get personal/example
sec store edit personal/example
sec store ls
sec store search github
```

### Store model

A **store** is one directory with this canonical layout:

```text
store-root/
├── secrets/                 # required
│   ├── .recipients
│   └── accounts/github.age
├── manifests/               # optional, used by sec run
│   └── dev
└── stores                   # optional references to other stores
```

The same format is used everywhere:

```text
# Personal store
~/.local/share/sec/
├── secrets/
├── manifests/
└── stores

# Project store
myproject/.sec/
├── secrets/
├── manifests/
└── stores

# Root of a shared Git repository
shared-secrets/
├── secrets/
├── manifests/
└── stores
```

`SEC_STORE_DIR` always points to the **store root**, never to `secrets/`:

```sh
SEC_STORE_DIR="$HOME/src/secrets" sec store ls
```

The default store selection order is:

1. `SEC_STORE_DIR`, if set.
2. The nearest `.sec/`, searching upward from the current directory.
3. `${XDG_DATA_HOME:-$HOME/.local/share}/sec` on Unix or `%APPDATA%/sec` on Windows.

`SEC_STORE_REQUIRE_PROJECT=1` disables the personal fallback. `sec store dir` prints the selected store root:

```sh
sec store dir
sec store dir --source            # explicit / project / personal
sec store dir --project           # current project's selected .sec store
sec store dir shared              # resolve an aliased store
```

A store root can be a symlink when selected explicitly with `SEC_STORE_DIR`, for example:

```text
project/.sec -> /home/me/shared/project-store
```

`secrets/` must be a real directory inside the store. Automatic project discovery and managed secret and policy paths refuse symlinks.

Initialize stores with:

```sh
sec store init                    # selected/personal store
sec store init --project          # creates .sec/secrets in current directory
```

### Breaking change from the previous 0.9 layout

There is no legacy-layout fallback. Existing stores must be renamed:

```text
old                         new

store/                  ->  secrets/
run/                    ->  manifests/
stores                   ->  stores
```

For example:

```sh
cd ~/.local/share/sec
mv store secrets
mv run manifests                 # if present
```

and for a project:

```sh
cd myproject/.sec
mv store secrets
mv run manifests                 # if present
```

Remote Git stores need the same rename at repository root.

`SEC_STORE_DIR` also changed meaning:

```sh
# old
SEC_STORE_DIR=/path/to/sec/store

# new
SEC_STORE_DIR=/path/to/sec
```

The old `sec store root` command is removed because `sec store dir` now returns the store root directly. `sec store dir --project-sec` is replaced by `sec store dir --project`.

If you previously symlinked only the old `store/` directory, prefer symlinking the entire store root in the new model.

### Secret entries

Secret names are relative to `secrets/` and are stored as `<name>.age`:

```sh
sec store put dev/database.env < ./database.env
sec store get dev/database.env
sec store edit dev/database.env

sec store ls
sec store ls dev
sec store search 'token$'
sec store search database dev

sec store rm dev/database.env
```

`search|s` filters the logical entry list with `grep` basic regular expressions on Unix and Rust regular expressions on Windows:

```sh
sec store s '^dev/'
sec store search 'token$' shared::
```

Plaintext secret contents are never written inside `secrets/` during normal store operations.

### Type an entry into the focused window

`sec store type` types the entry's **basename** (without `.age`), presses **Tab**, and types the **first decrypted line** as text. It leaves the form ready for you to submit:

```sh
sec store type accounts/example.age
sec store type personal::accounts/example
```

If the entry is `accounts/example.age` and its first decrypted line is `my-password`, the focused application receives `example`, Tab, `my-password`.

On X11, `xdotool` verifies and addresses the active window. On macOS, Accessibility permission allows `sec` to send events to a verified foreground process. Wayland with `wtype` and Windows require `SEC_STORE_TYPE_ALLOW_UNVERIFIED=1`. `SEC_STORE_TYPE_WAIT=1` allows one second to switch focus from a terminal or launcher. External typing helpers receive the secret over standard input. The first line must be UTF-8 text without control characters. Typing preserves trailing spaces and omits the line terminator.

**Be careful which window has focus:** simulated typing sends the secret to the active window, potentially exposing it in a terminal, chat or browser address bar. `wtype` also requires virtual-keyboard support from the Wayland compositor.

### Recipient policies

A `.recipients` file contains one age or SSH recipient per non-empty line. Blank lines and `#` comments are ignored:

```text
# Development team
age1...
ssh-ed25519 AAAA... alice@example
```

A policy applies to its directory and descendants. The **nearest `.recipients` wins**; parent and child policies are not merged. If no policy exists, a private personal store uses its self recipient. Run `sec store policy add . self` and `sec store policy approve .` before the first write to a new project store. Project and team stores require an approved effective policy. `SEC_STORE_ALLOW_SELF=1` explicitly permits self fallback for a private, locally managed store directory.

For a team store, commit an explicit root policy:

```text
.sec/secrets/.recipients
```

Inspect effective policies:

```sh
sec store policy dev/database.env
sec store policy path dev/database.env
sec store policy show dev/database.env

sec store policy path .
sec store policy show .
```

Manage exact policy scopes:

```sh
sec store policy edit
sec store policy edit dev

sec store policy add . self
sec store policy approve .
sec store policy add dev 'age1...'
sec store policy rm dev 'age1...'

sec store policy delete dev
sec store policy del dev
sec store policy d dev
```

`.` means the root policy under `secrets/`. The special recipient `self` is resolved immediately through `sec recipient`; the literal word `self` is never written to `.recipients`.

`policy rm` removes one recipient and refuses to leave an empty policy. `policy delete` removes the exact `.recipients` file and therefore restores inheritance from the nearest parent policy (or the configured fallback for a private personal store at root).

For mutation targets, an existing entry selects the policy of its containing directory. Use a trailing `/` to force a prefix or `.age` to force an entry when a name is ambiguous:

```sh
sec store policy add dev/ self
sec store policy add dev.age self
```

### Store references: `stores`

A store may reference other local or remote stores through its plain-text `stores` file:

```text
# alias   source
office   file://~/src/company/secrets
shared   git+ssh://git@example.org/company/shared-secrets.git
infra    git+https://git.example.org/company/infra-secrets.git
```

The source always names a complete store root.

Manage the file with:

```sh
sec store stores ls
sec store stores edit
sec store stores path
```

Project aliases take precedence over personal aliases. `SEC_STORE_PROJECT_ONLY=1` disables fallback to declarations in the personal `stores` file. The reserved `personal` alias always resolves to the platform's default personal store. Remove existing `personal` declarations before upgrading.

`local` has **no implicit meaning**: inside a project, the selected `.sec/` store is local too. You can use `local` freely as a name for a configured alias.

Use aliases with read-only operations:

```sh
sec store get shared::databases/test.env
sec store ls shared::
sec store search database shared::
sec store policy show shared::databases/test.env
sec store dir shared
```

Aliased stores are intentionally read-only through `alias::entry`. To modify one, select that store directly with `SEC_STORE_DIR` or work inside its checkout.

#### Local stores: `file://`

A local reference is resolved directly, without a backend or cache:

```text
local file://~/secrets
```

`file://~/...` and `file://~` expand **only the current user's `$HOME`**, not `~otheruser`, and do not expand environment variables or URI percent escapes. `file:///absolute/path` is also supported. The target must have the canonical layout and a real `secrets/` directory. `personal::...` is available without configuring a `local` alias when the personal XDG store is what you need.

#### Git-backed remote stores

`sec store remote-git` handles `git+ssh://` and `git+https://` stores.

Authorize each remote before the first fetch. A pinned origin requires approval of the full commit ID. For a moving branch, supply an absolute `SEC_GIT_ALLOWED_SIGNERS` file from outside the checkout and use `--signed`.

```sh
sec store remote-git trust 'git+https://git.example.org/team/secrets.git#0123456789abcdef0123456789abcdef01234567'
sec store remote-git trust 'git+ssh://git@git.example.org/team/secrets.git' --signed
```

Authorized snapshots live under `${XDG_CACHE_HOME:-$HOME/.cache}/sec/stores/`. SSH uses strict known-host verification and can use an SSH agent. For HTTPS, a trusted `SEC_STORE_GIT_ASKPASS` can supply credentials, and `SEC_STORE_GIT_CAINFO` can supply a trusted CA bundle. The backend disables inherited Git URL rewrites, hooks and HTTP redirects.

Subsequent reads reuse the cached snapshot. Stores are **not automatically updated** on every use:

```sh
sec store update shared
sec store update --all
```

`update --all` skips `file://` aliases.

For reproducible use, a full Git commit can be pinned:

```text
shared git+ssh://git@example.org/company/shared-secrets.git#0123456789abcdef0123456789abcdef01234567
```

Only full 40- or 64-hex commit IDs are accepted. A pinned store remains on that revision until the `stores` declaration itself changes.

`SEC_STORE_OFFLINE=1` prevents fetching an unavailable/outdated remote revision. `SEC_STORE_CACHE_DIR` overrides the cache root.

Remote snapshots are built from exact Git blobs. The backend rejects symlinks, submodules and unmanaged paths, and checks snapshot files against the tree before use. Signed updates must advance the last accepted revision within the bounded fetch history. Run `sec store cache prune` to remove obsolete snapshots. It preserves current snapshots and active managed readers. Paths obtained from `sec store dir ALIAS` can become stale after an update and prune.

### Git commands and sync

Run Git directly from the selected store root:

```sh
sec store git status
sec store g log --oneline
```

`sec store y [message ...]` provides a small add/commit/pull/push workflow:

```sh
sec store y
sec store y 'rotate development credentials'
```

The command validates the selected files before staging and verifies outgoing commits before pushing the selected branch. For team stores, configure Git SSH signing and set `SEC_GIT_ALLOWED_SIGNERS` to a trusted absolute path. In an application repository, `y` refuses to publish unrelated history in the same push.

The default commit message is `sync`. If the current branch has no upstream, `y` prefers `origin`, otherwise the only unambiguous configured remote, and performs the initial `git push -u`.

### Validation and rekeying

```sh
sec store check
sec store check --strict --decrypt
sec store rekey
sec store rekey dev
```

`check` validates managed secret paths, age structure and recipient syntax. `--decrypt` (or a nonempty `SEC_STORE_CHECK_DECRYPT`) tests the configured identities. `--strict` makes a requested decryption failure fatal. Team reads require provenance from a trusted Git commit, an authorized remote snapshot or local encryption. Use `sec store check --attest` to adopt existing ciphertexts **after verifying their provenance**. Decryption alone does not identify the sender.

`rekey` decrypts and re-encrypts matching entries without writing plaintext files and reports per-entry failures. Rotate the underlying credentials when revoking a recipient who could already decrypt them.

On a Git receiver, install a pre-receive hook outside the checked-out tree. For a dedicated store, invoke `sec security pre-receive "$PWD" --store`. For an application store, supply `.sec` after `--store`. For repositories using Git filters, invoke `sec security pre-receive "$PWD" --filters /trusted/protected-paths` with shell-style path patterns, one per line. These hooks require trusted SSH signers and validate protected blob structure on incoming commits.

## Developer workflows

`sec run` launches one command with environment variables and temporary files obtained from `sec store`.

It uses the same store discovery, so from inside a project this usually requires no store-path configuration:

```sh
sec run \
    -e dev/app.env \
    -v API_TOKEN=dev/api-token \
    -s ENVIRONMENT=development \
    -f SSH_KEY=dev/client.key \
    -- ./myapp
```

The four injection types are deliberately small and distinct:

```text
env ENTRY                import literal NAME=VALUE lines from a secret
set NAME=VALUE          set a literal non-secret value
var NAME=ENTRY           set NAME to the exact contents of one secret
file ENTRY               materialize a secret file (variable derived from basename)
file NAME=ENTRY          materialize a secret file and export its path
```

`var` preserves the secret contents exactly, including trailing newlines. Unix environment variables cannot contain NUL bytes, so NUL is rejected.

`set` is literal data: it splits on the first `=` and performs no interpolation, shell quoting, variable expansion or command substitution. Use `-s NAME=VALUE` (or `--set NAME=VALUE`) on the CLI.

### Environment entries: `env`

An `env` entry contains literal `NAME=VALUE` lines:

```dotenv
DATABASE_HOST=localhost
DATABASE_PASSWORD=example value with spaces
API_TOKEN=example-token
```

Use it with:

```sh
sec run -e dev/app.env -- ./myapp
```

Blank lines and lines beginning with `#` are ignored. Multiple `-e` entries are processed in order; for variables defined by more than one `env`, the last assignment wins.

### Scalar secret values: `var`

Use a whole secret as one environment variable:

```sh
sec run \
    -v DNSIMPLE_TOKEN=personal::dnsimple.com/terraform-token \
    -- terraform plan
```

The stored bytes are preserved except that NUL is rejected by the environment model.

### Literal values: `set`

Non-secret configuration can live directly in the invocation or manifest:

```sh
sec run \
    -s DNSIMPLE_EMAIL=me@example.org \
    -s DNSIMPLE_ACCOUNT_ID=12345 \
    -- ./client
```

This avoids creating a separate `.env`/`.envrc` for small, static, non-sensitive values.

### Temporary files: `file`

```sh
sec run \
    -f SSH_KEY=infra/ssh/deploy.key \
    -- sh -c 'exec ssh -i "$SSH_KEY" -o IdentitiesOnly=yes user@server'
```

If the variable is omitted, it is derived from the entry basename. For example:

```text
dev/credentials.json -> CREDENTIALS_JSON
```

Files are materialized under a private runtime workspace with mode `0600` on Unix. `SEC_RUN_DIR` points to their private parent.

### Manifests

Named manifests live under the selected store's `manifests/` directory:

```text
myproject/.sec/
├── secrets/
│   └── dev/
│       ├── app.env.age
│       ├── api-token.age
│       └── client.key.age
├── manifests/
│   └── dev
└── stores
```

Manage local manifests with:

```sh
sec run manifest ls
sec run manifest edit dev
sec run manifest rm dev

# short namespace
sec run m l
sec run m e dev
sec run m r dev
```

`manifest edit` creates `manifests/` and any required parent directories automatically.

Example manifest:

```text
# Secret env file
env dev/app.env

# One secret -> one environment variable
var API_TOKEN=dev/api-token

# Non-secret static configuration
set ENVIRONMENT=development

# Secret temporary file
file SSH_KEY=dev/client.key
```

The aliases `-e`, `-v` and `-f` are also accepted as manifest directives. Manifest content is data, never shell code.

Run it with:

```sh
sec run -m dev -- ./myapp
```

A bare manifest name resolves under the selected store:

```text
<store>/manifests/dev
```

A manifest can also come from an aliased store:

```sh
sec run -m shared::terraform -- terraform plan
```

which resolves:

```text
shared-store/manifests/terraform
```

Inside an aliased manifest, unqualified `env`, `var` and `file` entries automatically inherit the manifest's alias. For example:

```text
# shared/manifests/terraform
var API_TOKEN=api/token
file CREDENTIALS=credentials.json
```

loaded as:

```sh
sec run -m shared::terraform -- ...
```

is equivalent to references to `shared::api/token` and `shared::credentials.json`. Already-qualified references are left unchanged. `set` needs no store context.

Explicit manifest paths (`./path`, `../path`, `/absolute/path`) are also accepted and do not inherit an alias.

Aliased manifests are read-only through `sec run`. `manifest edit` and `manifest rm` operate on the selected local store.

Manifests are intentionally atomic: they do not include/chaining other manifests. Compose multiple manifests explicitly at the call site:

```sh
sec run -m shared::dnsimple -m dev -- terraform plan
```

This keeps dependencies visible and troubleshooting straightforward.

### Running manifests

Load manifests from sources you trust. `sec run -m REF -- COMMAND` uses the current manifest directly and runs without a prompt, including in CI. Set `SEC_RUN_EXEC_SHA256` to require a specific executable digest for the launched command.

A remote manifest resolves its unqualified entries in the same verified snapshot. Compose a personal manifest at the call site when the command also needs personal credentials.

```sh
sec run -m shared::terraform -m personal::dnsimple -- terraform plan
```

### Optional manifests

Use **`-M` / `--optional-manifest`** to request a manifest that may legitimately be absent. Unlike `-m`, which always requires the manifest, `-M` skips only a missing file (or missing `manifests/` directory):

```sh
sec run -M personal::maven -m buildsecrets -- mvn install
```

This is useful in a shared `justfile`: one developer may have a personal Maven manifest and another may have Maven credentials already exported in their shell. The conventional `personal::` alias works without a `stores` declaration when the personal XDG store has not been initialized; the missing optional manifest is skipped. The application's inherited environment is not cleared.

An **unresolved alias, unavailable Git remote, malformed manifest, inaccessible file, or symlinked manifest is still an error**. Optionality applies to *absence*, not to failures. The `-M` option may be repeated, mixed with `-m`, and used alone with a command (an absent optional manifest performs no injection).

In no-command inspect mode, skipped optional manifests appear explicitly:

```text
Manifest "personal::maven": "/home/user/.local/share/sec/manifests/maven" (absent, optional)
```

No warning is printed during normal execution for an expected missing optional manifest.

### Inspect and troubleshooting

Omit the command to inspect what will be injected without revealing secret values:

```sh
sec run -m dev
```

Inspection validates entries and shows their origins, variable names, file destinations and the status of optional manifests. It also reports LF or CRLF endings for scalar values.

`--print` displays resolved values and is sensitive:

```sh
sec run -m dev --print
```

`--env-only` emits resolved `NAME=VALUE` assignments and accepts environment inputs:

```sh
sec run --env-only -e dev/app.env -v TOKEN=dev/token
```

These outputs are data, not shell scripts; do not `eval` or `source` them.

**Breaking change (0.9.0 grammar):** replace `val NAME=VALUE` with `set NAME=VALUE`,
`var NAME:ENTRY` with `var NAME=ENTRY`, and `file ENTRY:NAME` with
`file NAME=ENTRY`. In the CLI use `-s`/`--set` instead of `--val` and the same
`NAME=ENTRY` form with `-v` and `-f`. Old spellings are intentionally rejected.

### Lifetime and cleanup

`sec run` resolves and validates all requested inputs before starting the command. Invalid entries, failed decryption and variable/file collisions prevent launch.

Temporary files live under a private workspace and are removed when the supervised command exits. The base directory comes from `SEC_RUN_TMPDIR` or `XDG_RUNTIME_DIR`. On Linux, one of these must specify a private directory. On macOS, the fallback is the user's private system temporary directory. On Windows, the fallback is `%LOCALAPPDATA%/sec/runtime`.

The child receives `SEC_RUN_DIR` and any requested variables. Scope `sec run` around the smallest practical command because subprocesses inherit environment variables, and processes that outlive the supervised command may lose access to temporary files.

### Make, Just and direnv

A `justfile` can keep the project invocation short:

```just
run:
    @sec run -m dev -- ./myapp

inspect:
    @sec run -m dev
```

or compose reusable external manifests explicitly:

```just
plan:
    @sec run -m shared::dnsimple -m terraform-dev -- terraform plan

build:
    @sec run -M personal::maven -m buildsecrets -- mvn install
```

With a project `.sec/`, `direnv` is not required for store discovery. If you use it, keep secret values out of `.envrc`; prefer injecting them only when the target command starts.

## References

- [age](https://github.com/FiloSottile/age) — the encryption tool behind `sec`.
- [pa](https://github.com/biox/pa) — a minimal password manager in shell.
- [git-crypt](https://github.com/AGWA/git-crypt) — a related transparent Git-encryption workflow built around GPG.
- [shroudage](https://github.com/nxsy/shroudage) and [git-agecrypt](https://github.com/vlaci/git-agecrypt) — inspirations for Git-filter-based encryption.

## Development

Run the Rust tests with `cargo test --locked`. The GitHub workflow tests and builds on Linux, macOS on Intel and Apple Silicon, and Windows x64.

On Linux, the integration tests exercise the compiled binary with synthetic fixtures and a local HTTPS server. They need Python 3, Go `age` 1.2.1 or newer, `age-keygen`, Git with `git http-backend`, OpenSSH and OpenSSL.

```sh
cargo build --locked
python3 -B -m unittest discover -s tests -v
```

Set `SEC_TEST_BINARY` to test a different build, such as `target/$(rustc --print host-tuple)/release/sec`.

Sign the executable for each release target with a dedicated OpenSSH release key and the `sec-release` namespace. On Linux or macOS, run `ssh-keygen -Y sign -f RELEASE_SIGNING_KEY -n sec-release "target/$(rustc --print host-tuple)/release/sec"`. Distribute the executable and its detached `.sig` together. Users verify the signature against a release signer obtained independently.

[Source repository on SourceHut](https://git.sr.ht/~mapperr/sec)

The default SourceHut build runs `just test test-integration`. Submit `.build-mirror.yml` manually through builds.sr.ht after provisioning the GitHub SSH deploy key and verified host key. The mirror job tests its `master` checkout, checks the current SourceHut `master` tip and pushes that exact revision to GitHub with a fast-forward push. If SourceHut `master` has advanced by the time the check runs, submit a new mirror job.

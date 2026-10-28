# sec

`sec` is a small wrapper around the already easy-to-use [age](https://github.com/FiloSottile/age).

Why wrap something simple? For a few extra ergonomics, automatic identity discovery, safer in-place operations, and tiny, composable Unix workflows. The core stays focused on encryption and decryption; companion scripts provide a Git filter, an encrypted personal/team store, and temporary secret injection into arbitrary commands.

The tools are POSIX `sh` scripts: easy to read, easy to hack on, and no daemon or database required.

## Install

Install `age` (or `rage`), then put the executable scripts you want in your `PATH`. `sec` discovers companions by their executable names:

```sh
# For example, if ~/.local/bin is already in PATH:
install -m 755 sec sec-git sec-store sec-store-remote-git sec-run ~/.local/bin/
```

The resulting commands are `sec e`, `sec d`, `sec git`, `sec store`, and `sec run`. Install only the companions you need. `sec-run` requires `sec-store`; remote Git stores additionally require `sec-store-remote-git`, Git, tar, `flock`, and a working Git SSH/HTTPS authentication setup.

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
2. `${SEC_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/sec}/identity`
3. `~/.ssh/id_ed25519`
4. `~/.ssh/id_rsa`
5. Additional identity **paths** listed in the config file `identities`, one per line (including explicitly configured plugin identities)

```sh
sec identity             # first discovered identity
sec identity --all       # all discovered identities
sec recipient            # your public self-recipient, if derivable
```

Without explicit recipients, encryption falls back to your own recipient. To encrypt for other people or machines, use `SEC_RECIPIENTS` or `SEC_RECIPIENTS_FILE`:

```sh
SEC_RECIPIENTS_FILE=./team.recipients sec e < secret.txt > secret.age
```

An explicit recipient list is authoritative: **your own recipient is not added automatically**. Keep private identities out of the repository; public recipient files may be committed. `SEC_ARMOR=1` requests ASCII-armored output; the default is binary.

## Git integration: sec-git

`sec-git` uses Git clean/smudge filters and `.gitattributes` to keep *plaintext in the working tree* and *age ciphertext in Git's index and repository*. This is a different workflow from `sec-store`, which keeps ciphertext in its store even locally.

```sh
cd /path/to/git/repo
sec git on
sec git recipient add 'ssh-ed25519 AAAA... alice@laptop'
sec git track '.env' 'secrets/*.json'
git add .gitattributes .sec-recipients .env secrets/
git commit -m 'Add encrypted project secrets'
```

The generated `.gitattributes` entries use `filter=sec diff=sec -text`, so the binary ciphertext is not subject to text normalization. A subsequent `git add` of unchanged plaintext reuses the indexed ciphertext, avoiding noisy changes caused by age's randomized encryption.

```sh
sec git status           # state, recipients and tracked paths
sec git recipient list
sec git recipient rm 'ssh-ed25519 AAAA... alice@laptop'
sec git rekey            # re-encrypt filtered tracked files and stage new blobs
sec git refresh          # restore a plaintext working tree after enabling filters
sec git off
```

Aliases include `sec git l`, `a`, `r`, `t`, `u`, and `f`; see `sec git --help` for the full interface. Git's filter configuration is local to each checkout, so run `sec git on` after cloning. **Commit `.sec-recipients` in plaintext**: its recipient entries are public, and encrypting the policy complicates bootstrap and recovery. Removing a recipient and re-encrypting does not revoke access to older Git history or credentials they already knew; rotate underlying credentials when revoking access.

## Encrypted store: sec-store

`sec-store` keeps each secret as an encrypted `.age` entry. It can be used as a personal store, a project store committed with the application, or a shared store referenced from other stores.

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
├── manifests/               # optional, used by sec-run
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
3. `${XDG_DATA_HOME:-$HOME/.local/share}/sec`.

`SEC_STORE_REQUIRE_PROJECT=1` disables the personal fallback. `sec store dir` prints the selected store root:

```sh
sec store dir
sec store dir --source            # explicit / project / personal
sec store dir --project           # current project's selected .sec store
sec store dir shared              # resolve an aliased store
```

A store root may itself be a symlink, for example:

```text
project/.sec -> /home/me/shared/project-store
```

`secrets/` itself is not a symlink boundary: it must be a real directory inside the store, and managed secret/policy paths may not contain symlinks.

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

`search|s` filters the logical entry list with `grep`:

```sh
sec store s '^dev/'
sec store search 'token$' shared::
```

Plaintext secret contents are never written inside `secrets/` during normal store operations.

### Recipient policies

A `.recipients` file contains one age or SSH recipient per non-empty line. Blank lines and `#` comments are ignored:

```text
# Development team
age1...
ssh-ed25519 AAAA... alice@example
```

A policy applies to its directory and descendants. The **nearest `.recipients` wins**; parent and child policies are not merged. If no policy exists, `sec` falls back to its self recipient.

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
sec store policy add dev 'age1...'
sec store policy rm dev 'age1...'

sec store policy delete dev
sec store policy del dev
sec store policy d dev
```

`.` means the root policy under `secrets/`. The special recipient `self` is resolved immediately through `sec recipient`; the literal word `self` is never written to `.recipients`.

`policy rm` removes one recipient and refuses to leave an empty policy. `policy delete` removes the exact `.recipients` file and therefore restores inheritance from the nearest parent policy (or self fallback at root).

For mutation targets, an existing entry selects the policy of its containing directory. Use a trailing `/` to force a prefix or `.age` to force an entry when a name is ambiguous:

```sh
sec store policy add dev/ self
sec store policy add dev.age self
```

### Store references: `stores`

A store may reference other local or remote stores through its plain-text `stores` file:

```text
# alias   source
personal file:///home/mapperr/src/git.sr.ht/~mapperr/secrets
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

Project aliases override personal aliases of the same name. `SEC_STORE_PROJECT_ONLY=1` disables personal alias fallback.

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
local file:///home/me/secrets
```

The target must have the canonical layout and a real `secrets/` directory.

#### Git-backed remote stores

`git+ssh://` and `git+https://` are implemented by the separate `sec-store-remote-git` backend.

The first access fetches a missing store into a private ciphertext cache:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/sec/stores/
```

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

Remote repositories are fetched without a normal working-tree checkout, so clean/smudge filters are not executed. Symlinks and submodules in remote stores are rejected.

Future transports can be added as separate backends (for example HTTP or SFTP) without changing `sec-run`.

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

It stages only the selected store. If `.sec/` lives inside a larger application repository, unrelated files outside `.sec/` are not staged; the command refuses to start when outside changes would make `git pull --rebase` unsafe.

The default commit message is `sync`. If the current branch has no upstream, `y` prefers `origin`, otherwise the only unambiguous configured remote, and performs the initial `git push -u`.

### Validation and rekeying

```sh
sec store check
sec store rekey
sec store rekey dev
```

`check` validates managed secret paths, age ciphertexts and recipient policies. Set `SEC_STORE_CHECK_DECRYPT=1` to additionally attempt decryption with the current identities.

`rekey` decrypts and re-encrypts matching entries through a FIFO, without writing plaintext regular files.

## Developer workflows: sec-run

`sec-run` launches one command with environment variables and/or temporary files obtained from `sec-store`.

It uses the same store discovery, so from inside a project this usually requires no store-path configuration:

```sh
sec run \
    -e dev/app.env \
    -v API_TOKEN:dev/api-token \
    --val ENVIRONMENT=development \
    -f dev/client.key:SSH_KEY \
    -- ./myapp
```

The four injection types are deliberately small and distinct:

```text
env ENTRY                import literal NAME=VALUE lines from a secret
var NAME:ENTRY           set NAME to the exact contents of one secret
val NAME=VALUE           set a literal non-secret value
file ENTRY[:NAME]        materialize a secret file and export its path
```

`var` preserves the secret contents exactly, including trailing newlines. Unix environment variables cannot contain NUL bytes, so NUL is rejected. Inspect mode warns about a trailing LF or CRLF without altering the value.

`val` is literal data: it splits on the first `=` and performs no interpolation, shell quoting, variable expansion or command substitution.

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
    -v DNSIMPLE_TOKEN:personal::dnsimple.com/terraform-token \
    -- terraform plan
```

The stored bytes are preserved except that NUL is rejected by the environment model.

### Literal values: `val`

Non-secret configuration can live directly in the invocation or manifest:

```sh
sec run \
    --val DNSIMPLE_EMAIL=me@example.org \
    --val DNSIMPLE_ACCOUNT_ID=12345 \
    -- ./client
```

This avoids creating a separate `.env`/`.envrc` for small, static, non-sensitive values.

### Temporary files: `file`

```sh
sec run \
    -f infra/ssh/deploy.key:SSH_KEY \
    -- sh -c 'exec ssh -i "$SSH_KEY" -o IdentitiesOnly=yes user@server'
```

If the variable is omitted, it is derived from the entry basename. For example:

```text
dev/credentials.json -> CREDENTIALS_JSON
```

Files are materialized under a private runtime workspace with mode `0600`; `SEC_RUN_DIR` points to their private parent.

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
var API_TOKEN:dev/api-token

# Non-secret static configuration
val ENVIRONMENT=development

# Secret temporary file
file dev/client.key:SSH_KEY
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
var API_TOKEN:api/token
file credentials.json:CREDENTIALS
```

loaded as:

```sh
sec run -m shared::terraform -- ...
```

is equivalent to references to `shared::api/token` and `shared::credentials.json`. Already-qualified references are left unchanged. `val` needs no store context.

Explicit manifest paths (`./path`, `../path`, `/absolute/path`) are also accepted and do not inherit an alias.

Aliased manifests are read-only through `sec-run`; `manifest edit/rm` operate only on the selected local store.

Manifests are intentionally atomic: they do not include/chaining other manifests. Compose multiple manifests explicitly at the call site:

```sh
sec run -m shared::dnsimple -m dev -- terraform plan
```

This keeps dependencies visible and troubleshooting straightforward.

### Inspect and troubleshooting

Omit the command to inspect what will be injected without revealing secret values:

```sh
sec run -m dev
```

Example:

```text
Context:
  store:   /home/me/project/.sec
  secrets: /home/me/project/.sec/secrets

Manifests:
  dev -> /home/me/project/.sec/manifests/dev

Environment:
  API_TOKEN=<secret>  var:dev/api-token  <- manifest dev:3
  REGION=<literal>  val  <- manifest dev:4

Files:
  SSH_KEY=<file>  file:dev/client.key -> <SEC_RUN_DIR>/dev/client.key  <- manifest dev:5

Runtime:
  SEC_RUN_DIR=<temporary directory>
```

For `var`, inspect mode appends `[trailing LF]` or `[trailing CRLF]` when appropriate. This is diagnostic only; the stored value is not trimmed.

For variables loaded from multiple `env` entries, inspect output shows the final source and how many earlier assignments were overridden.

`--print` displays resolved values and is sensitive:

```sh
sec run -m dev --print
```

`--env-only` emits only resolved `NAME=VALUE` assignments and does not allow `file` entries:

```sh
sec run --env-only -e dev/app.env -v TOKEN:dev/token
```

These outputs are data, not shell scripts; do not `eval` or `source` them.

### Lifetime and cleanup

`sec-run` resolves and validates all requested inputs before starting the command. Invalid entries, failed decryption and variable/file collisions prevent launch.

Temporary files live under a private `0700` workspace beneath `$XDG_RUNTIME_DIR` by default and are removed when the supervised command exits. There is no automatic `/tmp` fallback; set `SEC_RUN_TMPDIR` to another private directory when needed.

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
```

With a project `.sec/`, `direnv` is not required for store discovery. If you use it, keep secret values out of `.envrc`; prefer injecting them only when the target command starts.

## References

- [age](https://github.com/FiloSottile/age) — the encryption tool behind `sec`.
- [pa](https://github.com/biox/pa) — a minimal password manager in shell.
- [git-crypt](https://github.com/AGWA/git-crypt) — a related transparent Git-encryption workflow built around GPG.
- [shroudage](https://github.com/nxsy/shroudage) and [git-agecrypt](https://github.com/vlaci/git-agecrypt) — inspirations for Git-filter-based encryption.

## Development

Source: <https://git.sr.ht/~mapperr/sec>

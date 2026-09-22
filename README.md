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

`sec-store` keeps each secret as an encrypted `.age` entry, suitable for personal use or a Git-backed team store:

```sh
sec store init
printf '%s\n' 'example-password' | sec store put personal/example
sec store get personal/example
sec store edit personal/example
sec store ls
```

### One format for personal, project and remote stores

Every **sec container** has the same structure: a required `store/` directory with encrypted `.age` entries and `.recipients` policies, an optional plain-text `stores` file declaring other stores, and an optional `run/` directory with manifests.

```text
# Personal container (breaking change)
~/.local/share/sec/
├── store/
│   ├── .recipients
│   └── accounts/github.age
├── stores
└── run/default

# Project container
myproject/.sec/
├── store/
│   ├── .recipients
│   └── dev/app.env.age
├── stores
└── run/dev

# Root of a shared Git repository
shared-secrets/
├── store/
│   ├── .recipients
│   └── databases/test.env.age
├── stores                  # optional
└── run/                    # optional
```

There is **no automatic migration** from the old personal layout, where entries lived directly in `~/.local/share/sec/`. Move the existing encrypted entries, their directory structure, and their `.recipients` files into `~/.local/share/sec/store/` before using the new version. They do not need to be decrypted or re-encrypted. Leave any `stores` file and `run/` directory at the container level; inspect the existing directory before moving files to avoid overwriting anything. No legacy layout fallback is provided.

`sec-store` selects the default store in this order:

1. `SEC_STORE_DIR`, if set (points to the **store/** directory, not its container).
2. The nearest `.sec/store`, searching upward from the current directory.
3. `${XDG_DATA_HOME:-$HOME/.local/share}/sec/store` (personal).

The discovery is read-only. Existing symlinks to `.sec`, `.sec/store`, or the personal store directory are followed; broken links fail instead of triggering another fallback. Individual secrets and `.recipients` files inside `store/` may **not** be symlinks. `SEC_STORE_REQUIRE_PROJECT=1` prevents the implicit personal fallback; an explicit `SEC_STORE_DIR` still takes precedence. For the new layout, point an explicit `SEC_STORE_DIR` at a path ending in `/store` to give it an associated container for `stores` and `run/`.

```sh
cd /path/to/myproject
sec store init --project             # creates .sec/store here
sec store dir                        # path to the selected store/
sec store root                       # path to its enclosing .sec/
sec store dir --source               # project / explicit / personal
sec store put dev/database.env < ./database.env

# From anywhere beneath the project, the same store is discovered:
cd src/api
sec store ls
sec store get dev/database.env

# Outside any project:
sec store init                       # initializes the personal .../sec/store/
sec store root                       # ~/.local/share/sec
```

`.recipients` applies to its directory and descendants; the closest policy wins. Without a policy, the core's self-recipient fallback applies. **Commit an explicit `.sec/store/.recipients` for team stores** so each developer encrypts for the intended recipients rather than just themselves. Never commit plaintext secrets or private identities.

`sec store get` emits plaintext to stdout. `sec store git ...` / `sec store g ...` runs Git from the resolved physical store directory; if `store/` is symlinked outside the project checkout, Git operates in that destination repository. `sec store dir --project-sec` remains available for finding the associated project `.sec` directory.

### Shared stores via aliases and Git remotes

Add a public, declarative `stores` file to either the project container (`.sec/stores`) or the personal one (`~/.local/share/sec/stores`):

```text
# alias   remote source
shared git+ssh://git@example.org/company/shared-secrets.git
infra  git+https://git.example.org/company/infra-secrets.git
```

Edit it with your usual editor or retrieve its path:

```sh
sec store stores edit
sec store stores path
sec store sources                    # show effective aliases and sources
```

Both Git protocols use the separate `sec-store-remote-git` companion. A remote repository has exactly the same container layout as above, with `store/` at its root and optional `stores` and `run/`. Neither remote manifests nor transitive aliases are imported automatically by the first version. The personal `stores` file can supply interactive aliases not present in a project; a **named project manifest** intentionally uses project aliases only, so it cannot depend on one developer's private configuration. A project alias with the same name overrides the personal alias.

```sh
sec store get dev/app.env             # current project or personal store
sec store get shared::databases/test.env
sec store ls shared::                 # list entries with qualified names
sec store ls shared::databases
sec store policy shared::databases/test.env
```

The first access to an absent remote store automatically clones it into a private ciphertext cache under `${XDG_CACHE_HOME:-$HOME/.cache}/sec/stores/`. Subsequent reads reuse the cached snapshot without network access. **Nothing is automatically pulled on subsequent runs.** To update explicitly:

```sh
sec store update shared
sec store update --all               # all aliases declared in this container
SEC_STORE_OFFLINE=1 sec store get shared::databases/test.env
```

Remote entries are **read-only when accessed via an alias**: `put`, `edit`, `rm` and `rekey` act only on your selected local store. To change a shared secret, change it in the shared repository's own checkout and commit/push it there; then run `sec store update shared` in dependent projects. Updating publishes a new local snapshot without modifying an existing snapshot, so running commands can keep using the snapshot they already resolved. Older cached snapshots are retained; cache pruning is not yet provided.

For reproducible builds, optionally pin a full Git commit (40 or 64 hexadecimal characters):

```text
shared git+ssh://git@example.org/company/shared-secrets.git#0123456789abcdef0123456789abcdef01234567
```

A pinned alias keeps referring to that commit even after `update`; changing the pin requires updating the container's `stores` file. HTTPS authentication and SSH access use your normal Git configuration. Do not put credentials in remote URLs; `sec-store` does not grant access to secrets merely by downloading ciphertext. The reader still needs an age identity authorized by the remote store's `.recipients` policy. Remove access by rotating **underlying credentials**, not just by removing a recipient from the current Git version: older Git history and cached snapshots may remain decryptable.

A `stores` file is data, **not shell code**. Only `git+ssh://` and `git+https://` sources are supported initially; HTTP and SFTP backends can be added later. Remote repositories are downloaded without a working-tree checkout (and extracted from Git objects), so their clean/smudge filters are not executed. Repository symlinks and submodules are rejected by this backend. As with any repository, only use remotes you trust to supply the desired ciphertext and manifest data. `SEC_STORE_CACHE_DIR` overrides the cache location; `SEC_STORE_OFFLINE=1` prevents an initial fetch or explicit update if the source is not available at the requested cached revision.

## Developer workflows: sec-run

`sec-run` launches an arbitrary command with secret environment variables and/or temporary files obtained from **sec-store**. It uses the same automatic store discovery and also accepts `alias::entry` references for shared stores. Running it from a project subdirectory requires no local store-path setup. No plaintext needs to be checked into your project, and the calling shell's environment is left unchanged.

```sh
sec run \
    -e dev/app.env \
    -e shared/monitoring.env \
    -f dev/client.crt:TLS_CERT \
    -f dev/client.key:TLS_KEY \
    -f dev/credentials.json \
    -- ./myapp --port 8080
```

In this example, `sec-run` loads both environment entries, decrypts the certificate, key, and JSON file into a private temporary directory, and starts `./myapp`. The child receives `TLS_CERT`, `TLS_KEY`, and `CREDENTIALS_JSON`, each holding an **absolute temporary file path**, not the file contents. `SEC_RUN_DIR` points to the directory containing the materialized files.

### Project manifests: `-m` / `--manifest`

For projects that need several environment files and certificates, keep **references**, not secret values, in `.sec/run/` beside the project store. A named manifest resolves in the **selected container's `run/`** (`.sec/run/` for a project or `~/.local/share/sec/run/` outside projects). The selection is stable even if the project's `.sec` or `store/` is symlinked elsewhere. A project manifest only uses the project `stores` declarations, never accidental personal alias fallbacks.

```text
myproject/
├── .sec/
│   ├── store/
│   │   ├── .recipients
│   │   └── dev/
│   │       ├── app.env.age
│   │       ├── client.crt.age
│   │       └── client.key.age
│   ├── stores
│   └── run/
│       └── dev
├── justfile
└── src/
```

Example `.sec/run/dev` (one directive and one entry per line, blank lines and `#` comments allowed):

```text
# Project development environment
env dev/app.env
file dev/client.crt:TLS_CERT
file dev/client.key:TLS_KEY

# Shared store declared in .sec/stores
env shared::databases/test.env
file shared::certificates/company-ca.pem:TLS_CA
```

From **any directory inside the project**:

```sh
sec run -m dev                         # inspect without showing secret values
sec run -m dev -- ./myapp              # run with variables and temporary files
sec run -m dev --print                 # print sensitive values: do not log
sec run -m dev -e shared/extra.env -- ./myapp
```

A bare manifest name such as `dev` resolves to the current container's `run/dev`; `sec-run` does not independently search for manifests in parent directories. Explicit manifest paths (`./config/run`, `../config/run`, `/absolute/run`) work with any store. You can repeat `-m` and mix manifests with `-e`/`-f` options; they are processed in command-line order. Manifests contain only literal `env ENTRY` and `file ENTRY[:ENV_VAR]` directives (the aliases `-e ENTRY` and `-f ENTRY[:ENV_VAR]` also work). No `source`, `eval`, interpolation, shell quoting, or inline comments are executed. Entries in a manifest are whitespace-free; use direct CLI flags for names containing spaces.

For a team repository, commit `.sec/run/`, `.sec/stores`, and the **ciphertext** under `.sec/store/`. After an ordinary `git clone`, a developer with Git and age access can run `sec run -m dev -- ./myapp`: missing shared repositories are fetched automatically once. If the project store is missing, a named manifest fails instead of silently borrowing an unrelated personal manifest; use `SEC_STORE_REQUIRE_PROJECT=1` to prohibit personal fallback for ordinary commands too.

### Environment entries: `-e`

An environment entry is a secret in the store containing literal `NAME=VALUE` lines:

```dotenv
# dev/app.env (contents before encryption)
DATABASE_HOST=localhost
DATABASE_PASSWORD=example value with spaces
API_TOKEN=example-token
```

```sh
sec run -e dev/app.env -- ./myapp
```

Repeat `-e` to combine multiple entries; when the same variable appears in more than one, **the last definition wins**. The parser treats values literally: it does not `source` the entry, execute command substitutions, expand variables, or interpret shell quoting. Blank lines and lines beginning with `#` are ignored. Environment values must be single-line and cannot contain NUL bytes.

### Temporary files: `-f`

Each `-f` takes a store entry with an optional environment variable name:

```text
-f ENTRY
-f ENTRY:ENV_VAR
```

If the variable is omitted, it is derived from the entry's basename: `dev/credentials.json` becomes `CREDENTIALS_JSON`, and `shared::certificates/ca.pem` becomes `CA_PEM`. Paths within the temporary directory preserve the entry's relative structure; files from aliased stores are namespaced under the alias (for example `shared/certificates/ca.pem`). Duplicate destinations or variables are errors.

```sh
sec run \
    -f prod/frontend/credentials.json:FRONTEND_CREDENTIALS \
    -f prod/backend/credentials.json:BACKEND_CREDENTIALS \
    -- ./myapp
```

Duplicate file destinations, duplicate `-f` environment variable names, and collisions between `-e` variables and file-path variables are **errors**, detected before the command starts. `:` is reserved as the separator for an explicit variable name in `-f` arguments.

### Inspect before running

Omit the command to see what would be injected **without displaying secret values**:

```sh
sec run -e dev/app.env -f dev/client.key:TLS_KEY
```

Use `--print` to print the resolved environment, **including sensitive values**:

```sh
sec run --print -e dev/app.env -f dev/client.key:TLS_KEY
```

In this mode, file paths are **placeholders**, not reusable files; no application is started. Do not use `--print` in routine CI logs or paste its output into tickets or chat.

Use `--env-only` to emit only resolved `NAME=VALUE` assignments (no `-f` allowed):

```sh
sec run --env-only -e dev/app.env -e shared/monitoring.env
```

This output is sensitive, too. It is data for programs that accept env-file syntax, **not a script to evaluate with `eval` or `source`**. `--print` and `--env-only` cannot be combined with `-- command`.

### Lifetime, cleanup, and security

`sec-run` prepares **all** required secrets before launching the command; an invalid entry, failed decryption, or variable collision prevents launch. It supervises the child and returns its exit status. Temporary files have mode `0600` under a private `0700` workspace and are removed when the supervised command terminates.

The workspace's parent defaults to `$XDG_RUNTIME_DIR`. There is **no automatic `/tmp` fallback**: set `SEC_RUN_TMPDIR` if needed, to an existing, private directory owned by your user. Prefer a private tmpfs where available. Do not assume files remain available after the supervised command exits; subprocesses that outlive it may lose access. As with any environment injection, child processes can inherit secret variables, so scope `sec run` around the smallest practical command.

`sec-run` relies on `sec store dir` and `sec store root` for store selection; `SEC_STORE_DIR` is optional, and `SEC_STORE_REQUIRE_PROJECT=1` prevents unintended personal fallback. Runner-specific settings remain `SEC_RUN_SEC`, `SEC_RUN_TMPDIR`, and `SEC_RUN_DEBUG`, all with the `SEC_RUN_` prefix.

### Make, Just, and direnv

A Make target can give one command exactly the secrets it needs:

```makefile
.PHONY: run
run:
	@sec run -e dev/app.env -f dev/client.key:TLS_KEY -- ./myapp
```

Or put the same workflow in a `justfile`:

```just
run:
    @sec run -e dev/app.env -f dev/client.key:TLS_KEY -- ./myapp
```

With a project-local `.sec/store`, **direnv is optional**: `sec-store` and `sec-run` discover it from any project subdirectory. A `justfile` can use a versioned manifest without repeating secret arguments:

```just
run:
    @sec run -m dev -- ./myapp

inspect:
    @sec run -m dev
```

If you use direnv, you can keep `.envrc` free of secrets and use it for unrelated project settings. Prefer injecting secret values through `sec-run` at command launch rather than loading them automatically into your interactive shell when entering a directory.

## References

- [age](https://github.com/FiloSottile/age) — the encryption tool behind `sec`.
- [pa](https://github.com/biox/pa) — a minimal password manager in shell.
- [git-crypt](https://github.com/AGWA/git-crypt) — a related transparent Git-encryption workflow built around GPG.
- [shroudage](https://github.com/nxsy/shroudage) and [git-agecrypt](https://github.com/vlaci/git-agecrypt) — inspirations for Git-filter-based encryption.

## Development

Source: <https://git.sr.ht/~mapperr/sec>

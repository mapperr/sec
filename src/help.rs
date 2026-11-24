use std::ffi::OsString;

use anyhow::{Context, Result};

struct Topic {
    names: &'static str,
    syntax: &'static str,
    summary: &'static str,
    details: &'static str,
    children: &'static [Topic],
}

impl Topic {
    fn name(&self) -> &str {
        self.names.split('|').next().unwrap()
    }

    fn print(&self, path: &str) {
        if path == "sec" {
            println!("sec {}", env!("CARGO_PKG_VERSION"));
        }
        println!("{}\n\nUsage", self.summary);
        for line in self.syntax.split('\n') {
            if line.is_empty() {
                println!("  {path}");
            } else {
                println!("  {path} {line}");
            }
        }
        if !self.children.is_empty() {
            let width = self
                .children
                .iter()
                .map(|child| child.name().len())
                .max()
                .unwrap();
            println!("\nCommands");
            for child in self.children {
                println!("  {:width$}  {}", child.name(), child.summary);
            }
        }
        if let Some((_, aliases)) = self.names.split_once('|') {
            println!("\nAliases  {}", aliases.replace('|', ", "));
        }
        if !self.details.is_empty() {
            println!("\n{}", self.details);
        }
        if !self.children.is_empty() {
            println!("\nRun `{path} COMMAND --help` for command-specific help.");
        }
    }
}

const fn group(
    names: &'static str,
    syntax: &'static str,
    summary: &'static str,
    details: &'static str,
    children: &'static [Topic],
) -> Topic {
    Topic {
        names,
        syntax,
        summary,
        details,
        children,
    }
}

const fn command(
    names: &'static str,
    syntax: &'static str,
    summary: &'static str,
    details: &'static str,
) -> Topic {
    group(names, syntax, summary, details, &[])
}

fn find<'a>(path: impl IntoIterator<Item = &'a OsString>) -> Option<(&'static Topic, String)> {
    let mut topic = &SEC;
    let mut canonical = String::from("sec");
    for word in path {
        let word = word.to_str()?;
        topic = topic
            .children
            .iter()
            .find(|child| child.names.split('|').any(|name| name == word))?;
        canonical.push(' ');
        canonical.push_str(topic.name());
    }
    Some((topic, canonical))
}

pub fn show(args: &[OsString]) -> Result<bool> {
    // A help flag belongs to sec only when it follows a complete command path.
    if let Some((flag, path)) = args.split_last()
        && (flag == "--help" || flag == "-h")
        && let Some((topic, path)) = find(path)
    {
        topic.print(&path);
        return Ok(true);
    }
    if let Some(index) = args.iter().position(|arg| arg == "help")
        && let Some((parent, _)) = find(&args[..index])
        && (!parent.children.is_empty() || matches!(parent.name(), "fzf" | "otp" | "type"))
    {
        let suffix = &args[index + 1..];
        let suffix = match suffix.split_last() {
            Some((flag, rest)) if flag == "--help" || flag == "-h" => rest,
            _ => suffix,
        };
        let (topic, path) = find(args[..index].iter().chain(suffix))
            .context("unknown help topic. Run sec --help for available commands")?;
        topic.print(&path);
        return Ok(true);
    }
    if let Some((topic, path)) = find(args)
        && !topic.children.is_empty()
    {
        topic.print(&path);
        return Ok(true);
    }
    Ok(false)
}

const SEC: Topic = group(
    "sec",
    "[COMMAND] [ARGS...]\nhelp [COMMAND...]\n--help | --version",
    "Encrypt files and manage age-encrypted secrets from one executable.",
    "Examples
  sec e ./credentials.env
  sec store ls
  sec run -m dev -- ./myapp
  sec help store remote-git",
    &[
        command(
            "e",
            "[FILE...]",
            "Encrypt files in place or encrypt standard input.",
            "Supply file paths to replace them in place. With no paths, redirect standard
input and output. Binary age is the default. Set SEC_ARMOR=1 for ASCII armor.

Set SEC_RECIPIENTS_FILE to use a recipient list or SEC_RECIPIENTS to use
explicit recipients. By default sec uses your own public recipient.

Examples
  sec e ./credentials.env
  sec e < credentials.env > credentials.age",
        ),
        command(
            "d",
            "[FILE...]",
            "Decrypt files in place or decrypt standard input.",
            "Accepts binary and ASCII-armored age ciphertext. Supply file paths to
replace them in place. With no paths, redirect standard input and send
plaintext to a trusted consumer or private destination.

Set SEC_IDENTITY to select an explicit private identity. List discovery
results with sec identity --all.

Example
  sec d < credentials.age | ./consume-secret",
        ),
        command(
            "identity",
            "[--all]",
            "Show paths to available private identities.",
            "Prints the first discovered identity path. --all lists every path in
discovery order. Set SEC_IDENTITY for an explicit path. The configuration
directory contains identity and the optional identities list. Set
SEC_ALLOW_SSH_IDENTITIES=1 to include standard SSH identity paths.",
        ),
        command(
            "recipient",
            "",
            "Show your public encryption recipients.",
            "Reads SEC_RECIPIENT, the configured recipient file, or derives the
public recipients from your first discovered identity.

Example
  sec recipient | sec git recipient add",
        ),
        group(
            "store",
            "COMMAND [ARGS...]",
            "Manage encrypted entries, recipient policies and remote stores.",
            "Store selection uses SEC_STORE_DIR, the nearest project .sec directory,
or the personal store. Use ALIAS::ENTRY to read from another store and
ALIAS:: or ALIAS::PREFIX to list entries in it.

Examples
  sec store init --project
  sec store ls team::
  sec store policy --help",
            STORE,
        ),
        group(
            "run",
            "[OPTIONS] [-- COMMAND [ARGS...]]\nmanifest COMMAND [ARGS...]",
            "Run a command with secrets in its environment or in temporary files.",
            RUN_OPTIONS,
            MANIFEST,
        ),
        group(
            "git",
            "COMMAND [ARGS...]",
            "Configure Git filters for files stored as ciphertext in Git.",
            "Checkout keeps ciphertext by default. Use sec git refresh to prepare
plaintext files for editing. Review and approve .sec-recipients before
using the filter on existing tracked paths.

Examples
  sec git on
  sec recipient | sec git recipient add
  sec git recipient approve
  sec git track '.env'",
            GIT,
        ),
        group(
            "security",
            "COMMAND [ARGS...]",
            "Validate protected Git content before staging or accepting changes.",
            "Use sec security pre-receive from a trusted receiver hook. Keep the hook
and its trusted signer configuration outside the checked-out content.",
            SECURITY,
        ),
    ],
);

const STORE: &[Topic] = &[
    command(
        "init",
        "[--project]",
        "Initialize the selected store or create .sec in the current directory.",
        "With --project, initialize .sec in the current directory. For a new
project store, set and approve a recipient policy before the first write.

Example
  sec store init --project
  sec store policy add . self
  sec store policy approve .",
    ),
    command(
        "dir",
        "[ALIAS]\n--source\n--project\n--source-url ALIAS",
        "Show the selected store root or resolve a store alias.",
        "Options
  --source            Show the selection source (explicit, project, personal).
  --project           Require the selected store to be the project store.
  --source-url ALIAS  Print the alias source without resolving it.",
    ),
    command(
        "put",
        "ENTRY [FILE]",
        "Encrypt data into a local store entry.",
        "Reads FILE if supplied, or standard input. The applicable recipient
policy controls who can decrypt the entry.

Example
  sec store put dev/settings < settings.env",
    ),
    command(
        "get",
        "[ALIAS::]ENTRY",
        "Write the decrypted entry to standard output.",
        "",
    ),
    command(
        "get1",
        "[ALIAS::]ENTRY",
        "Write the first decrypted line to standard output.",
        "Outputs the line without its line ending.",
    ),
    command(
        "edit",
        "ENTRY",
        "Edit a local entry and encrypt the result.",
        "Set SEC_STORE_EDITOR to choose the editor.",
    ),
    command(
        "ls",
        "[[ALIAS::]PREFIX]",
        "List entries, optionally filtered by path prefix.",
        "Example\n  sec store ls team::dev/",
    ),
    command(
        "search|s",
        "REGEX [[ALIAS::]PREFIX]",
        "Search entry names with a regular expression.",
        "Searches names and paths. Returns status 1 when there are no matches.

Example
  sec store search 'token$' team::dev/",
    ),
    command(
        "rm",
        "ENTRY [ENTRY...]",
        "Remove one or more encrypted entries from the local store.",
        "",
    ),
    group(
        "policy",
        "COMMAND [ARGS...]\n[ALIAS::]SCOPE",
        "Inspect or change the recipients for a store path.",
        "Use . for the root policy, NAME/ for a directory or NAME.age for an
entry's policy scope. The nearest .recipients file applies. Read-only
queries can use ALIAS::SCOPE. Approval covers the exact policy contents.

Examples
  sec store policy show team::dev/token
  sec store policy add . self
  sec store policy approve .",
        STORE_POLICY,
    ),
    command(
        "check",
        "[--strict] [--decrypt | --attest]",
        "Validate store entries and recipient policies.",
        "Options
  --decrypt  Also try decrypting each entry with the configured identities.
  --strict   Treat a requested decryption failure as an error.
  --attest   Verify decryption strictly and record a local attestation.
             Use only after verifying the ciphertext's provenance.",
    ),
    command(
        "rekey",
        "[PREFIX]",
        "Re-encrypt local entries under their current approved policies.",
        "Specify PREFIX to limit which entries are re-encrypted.",
    ),
    group(
        "stores",
        "COMMAND",
        "Manage named references to other stores.",
        "The stores file contains one ALIAS SOURCE declaration per line. Sources
define local file:// stores or remote git+ssh:// and git+https:// stores.
The personal alias is built in.",
        &[
            command("ls|l", "", "List available aliases and their sources.", ""),
            command(
                "edit",
                "",
                "Edit the selected store's alias declarations.",
                "",
            ),
            command(
                "path",
                "",
                "Show the path to the selected store's alias file.",
                "",
            ),
        ],
    ),
    command(
        "update",
        "ALIAS | --all",
        "Refresh remote store snapshots.",
        "Use --all to update the Git-backed aliases declared in the selected
store. See sec store remote-git trust --help to authorize a source.",
    ),
    group(
        "cache",
        "COMMAND",
        "Manage cached snapshots of remote stores.",
        "",
        &[command(
            "prune",
            "",
            "Prune obsolete snapshots and keep current or in-use snapshots.",
            "",
        )],
    ),
    group(
        "remote-git",
        "COMMAND [ARGS...]",
        "Authorize and validate Git-backed remote snapshots.",
        "Sources use git+ssh:// or git+https://. Once a source is authorized and
listed in the stores file, use sec store update ALIAS for normal updates.",
        &[
            command(
                "trust",
                "SOURCE#COMMIT\nSOURCE --signed",
                "Authorize a pinned revision or an SSH-signed source.",
                "Use a full commit ID for a fixed snapshot. For signed updates, set
SEC_GIT_ALLOWED_SIGNERS to the absolute path of a trusted signer file.
Authorization requires interactive confirmation.

Example
  sec store remote-git trust git+ssh://git@git.example.org/team/secrets.git --signed",
            ),
            command(
                "fetch",
                "SOURCE DESTINATION",
                "Fetch an authorized snapshot into an existing private directory.",
                "",
            ),
            command(
                "update",
                "SOURCE DESTINATION",
                "Refresh an authorized snapshot in an existing private directory.",
                "",
            ),
            command(
                "check",
                "SOURCE DESTINATION",
                "Verify an existing snapshot against its authorized Git source.",
                "",
            ),
        ],
    ),
    command(
        "git|g",
        "[GIT_ARGS...]",
        "Run Git from the selected store directory.",
        "Defaults to git status. Use sec store git help COMMAND for Git's own
command documentation.

Example
  sec store git log --oneline",
    ),
    command(
        "y",
        "[MESSAGE...]",
        "Stage, sign, synchronize and push store changes with Git.",
        "Requires a configured Git remote, SSH signing key and trusted signers.
Set SEC_GIT_ALLOWED_SIGNERS to the trusted signer file.",
    ),
    command(
        "otp",
        "[ALIAS::]ENTRY",
        "Generate the current TOTP code.",
        "Include exactly one line of the form totp: BASE32_SEED. The entry can
also contain a password and notes on separate lines. The built-in
generator produces six digits in 30-second time steps.",
    ),
    command(
        "type",
        "[ALIAS::]ENTRY",
        "Type an entry name and its first decrypted line into the focused window.",
        "Types the basename, Tab, then the first decrypted line. Check the
active window before use. Set SEC_STORE_TYPE_WAIT to a delay in seconds
if you need to change focus. macOS requires Accessibility permission.
Wayland and Windows require SEC_STORE_TYPE_ALLOW_UNVERIFIED=1.",
    ),
    command(
        "fzf",
        "[[ALIAS::]PREFIX]\n--list [[ALIAS::]PREFIX]\n--new\nACTION [ALIAS::]ENTRY",
        "Browse entries and perform actions with fzf.",
        FZF_ACTIONS,
    ),
];

const STORE_POLICY: &[Topic] = &[
    command(
        "path",
        "[[ALIAS::]SCOPE]",
        "Show the path to the effective recipient policy.",
        "",
    ),
    command(
        "show",
        "[[ALIAS::]SCOPE]",
        "Show the effective public recipients.",
        "",
    ),
    command(
        "add",
        "SCOPE RECIPIENT",
        "Add a public recipient to a local policy.",
        "Use self to add your own recipient.",
    ),
    command(
        "rm",
        "SCOPE RECIPIENT",
        "Remove a public recipient from the exact local policy.",
        "Use self to select your own recipient.",
    ),
    command(
        "edit",
        "[SCOPE]",
        "Edit a local recipient policy.",
        "Set SEC_STORE_EDITOR to choose the editor.",
    ),
    command(
        "approve",
        "[SCOPE]",
        "Approve the exact contents of a local recipient policy.",
        "Requires interactive confirmation.",
    ),
    command(
        "delete|del|d",
        "[SCOPE]",
        "Delete the recipient policy at the exact local scope.",
        "Entries use the nearest remaining parent policy for future encryption.",
    ),
];

const FZF_ACTIONS: &str = "\
Enter prints the selected entry's name. Interactive browsing requires fzf.

Actions and shortcuts
  --copy-first  Ctrl-I          Copy the first line.
  --copy-full   Ctrl-Y          Copy the full entry.
  --copy-name   Ctrl-U          Copy the entry basename.
  --copy-path   Ctrl-B          Copy the entry path.
  --otp         Ctrl-O          Copy the current TOTP code.
  --view        Ctrl-V, Ctrl-/  View the decrypted entry.
  --preview                     Print the decrypted entry as display text.
  --type        Ctrl-T          Type into the focused window.
  --policy      Ctrl-H          Show the recipient policy path.
  --edit        Ctrl-E          Edit a local entry.
  --rekey       Ctrl-R          Re-encrypt entries under the selected prefix.
  --remove      Ctrl-D          Remove a local entry after confirmation.
  --new         Ctrl-A          Prompt for an entry name and edit it.
  --list                        List entries without opening fzf.

On Wayland, wl-copy with --sensitive support and timeout keeps the offer
for up to 30 seconds. X11 and older Wayland helpers default to one request.
Set SEC_STORE_FZF_PASTE_ONCE=1 for one request or 0 to keep the offer until
it is replaced. Clipboard managers control their own history.";

const RUN_OPTIONS: &str = "\
Options
  -m, --manifest REF          Load a required manifest.
  -M, --optional-manifest REF  Skip a manifest when its file is absent.
  -e, --env ENTRY              Import NAME=VALUE assignments from an entry.
  -v, --var NAME=ENTRY         Set one variable to an entry's contents.
  -s, --set NAME=VALUE         Pass a literal environment value.
  -f, --file [NAME=]ENTRY      Create a temporary file and export its path.
      --print                 Print resolved values and temporary file placeholders.
      --env-only              Print resolved assignments. Accepts environment inputs only.

Use ALIAS::ENTRY or ALIAS::REF for another store. Options may be repeated
for multiple inputs. With no command or output flag, sec previews the
plan without revealing secret values. --print and --env-only reveal
plaintext and each requires its own approval when a manifest is used.

Examples
  sec run -m dev
  sec run -m team::dev -M personal::extras -- ./myapp
  sec run -v TOKEN=dev/token -f TLS_KEY=dev/key -- ./myapp";

const MANIFEST: &[Topic] = &[group(
    "manifest|m",
    "COMMAND [ARGS...]",
    "Edit manifests and manage their approvals and grants.",
    "Approvals are bound to the manifest, its resolved plan and the exact
command and arguments, or to a particular output mode. To inspect a plan
before approving it, run sec run -m REF.

Example
  sec run manifest approve dev --env-name API_TOKEN -- ./myapp",
    &[
        command("ls|l", "", "List manifests in the selected store.", ""),
        command(
            "edit|e",
            "REF",
            "Create or edit a local manifest.",
            "Set SEC_RUN_EDITOR to choose the editor. A manifest supports env, var,
set and file directives. See sec run --help for the corresponding inputs.",
        ),
        command(
            "rm|r",
            "REF [REF...]",
            "Remove one or more local manifests.",
            "",
        ),
        command(
            "approve",
            "REF [--env-name NAME]... -- COMMAND [ARGS...]\nREF [--env-name NAME]... (--print | --env-only)",
            "Review and approve a manifest's complete injection plan.",
            "For manifests with env directives, repeat --env-name for each variable
permitted in those imports. Approval requires interactive confirmation.",
        ),
        command(
            "approvals",
            "REF -- COMMAND [ARGS...]\nREF (--print | --env-only)",
            "Show approved injections and prefix grants for the selected target.",
            "",
        ),
        command(
            "grant",
            "REF --entry ENTRY --as NAME --mode (var | file) TARGET
REF --prefix ALIAS::PREFIX/ [--as NAME] [--mode (var | file)] TARGET",
            "Approve one added entry or explicitly allow future additions under a team prefix.",
            "TARGET is -- COMMAND [ARGS...], --print, or --env-only. Approve the
manifest plan first. Prefix grants cover scalar and file injections from
a team store. Use --as or --mode to narrow a prefix grant.

Example
  sec run manifest grant dev --prefix team::dev/ --mode var -- ./myapp",
        ),
        command(
            "revoke",
            "REF TARGET
REF --entry ENTRY --as NAME --mode (var | file) TARGET
REF --prefix ALIAS::PREFIX/ [--as NAME] [--mode (var | file)] TARGET",
            "Remove a manifest approval or revoke a specific grant.",
            "TARGET is -- COMMAND [ARGS...], --print, or --env-only. Omit the
selector to remove the entire approval. For a prefix, repeat the same
--as and --mode restrictions used to grant it.",
        ),
    ],
)];

const GIT: &[Topic] = &[
    command(
        "on",
        "[--textconv]",
        "Enable required Git clean and smudge filters in the current checkout.",
        "Use --textconv to let Git display decrypted values in diffs. When the
checkout already tracks protected paths, approve its recipient policy first.",
    ),
    command(
        "off",
        "",
        "Disable the filters after checking for protected plaintext.",
        "",
    ),
    command(
        "status|l",
        "",
        "Show filter state, recipients, tracking patterns and protected paths.",
        "",
    ),
    group(
        "recipient",
        "COMMAND [ARGS...]",
        "Manage the checkout's public recipient policy.",
        "Recipients are stored in .sec-recipients. Approve any changes before\nusing the filter again.",
        &[
            command("list|ls|l", "", "Print .sec-recipients.", ""),
            command(
                "add|a",
                "[RECIPIENT...]",
                "Add one or more public recipients.",
                "With no recipient arguments, reads one public recipient per line from
redirected standard input. Also available as sec git a.

Example
  sec recipient | sec git recipient add",
            ),
            command(
                "rm|r|remove",
                "[RECIPIENT...]",
                "Remove one or more public recipients.",
                "With no recipient arguments, reads one public recipient per line from
redirected standard input. Also available as sec git r. Existing Git
history remains readable with the old keys.",
            ),
            command(
                "approve",
                "",
                "Approve the current .sec-recipients policy.",
                "Requires interactive confirmation.",
            ),
        ],
    ),
    command(
        "track|t",
        "PATTERN [PATTERN...]",
        "Add Git attributes that mark paths for encryption.",
        "Quote patterns so that Git, rather than the shell, interprets them.",
    ),
    command(
        "untrack|u",
        "PATTERN [PATTERN...]",
        "Remove tracking patterns after checking for protected plaintext.",
        "",
    ),
    command(
        "rekey|f",
        "",
        "Re-encrypt filtered tracked files and stage new ciphertext.",
        "Requires an active filter and an approved recipient policy.",
    ),
    command(
        "refresh",
        "",
        "Materialize protected files as private plaintext for editing.",
        "Requires an active filter.",
    ),
    command(
        "clean",
        "[PATH]",
        "Encrypt input for Git's index and write ciphertext to standard output.",
        "Intended for use as Git's clean filter.",
    ),
    command(
        "smudge",
        "[PATH]",
        "Verify checked-out ciphertext and write it to standard output.",
        "With SEC_GIT_SMUDGE_PLAINTEXT=1, Git can check out plaintext in a\ntrusted private working tree.",
    ),
    command(
        "textconv",
        "FILE",
        "Decrypt a protected file for Git's diff driver.",
        "Writes plaintext to standard output.",
    ),
    command(
        "a",
        "[RECIPIENT...]",
        "Add public recipients (shortcut for recipient add).",
        "See sec git recipient add --help.",
    ),
    command(
        "r",
        "[RECIPIENT...]",
        "Remove public recipients (shortcut for recipient rm).",
        "See sec git recipient rm --help.",
    ),
];

const SECURITY: &[Topic] = &[
    command(
        "stage-store",
        "ROOT",
        "Validate and stage managed store files in Git.",
        "ROOT is the store directory that contains secrets/.\n\nExample\n  sec security stage-store .sec",
    ),
    command(
        "pre-receive",
        "ROOT --store [PREFIX]\nROOT --filters ABSOLUTE_PATH",
        "Verify incoming Git revisions, trusted signatures and protected blobs.",
        "Reads pre-receive update records from standard input. Set
SEC_GIT_ALLOWED_SIGNERS to the absolute path of your trusted signer file.
Use --store for a dedicated store or --store .sec for a project store.
With --filters, supply a trusted file of protected path glob patterns.

Example
  sec security pre-receive \"$PWD\" --store .sec",
    ),
];

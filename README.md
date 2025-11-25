# sec

`sec` is a wrapper for the already easy-to-use age.  

But, if age is already easy to use, then, why a *wrapper*?  
For few additional ergonomics and a minimal git clean/smudge integration.  
Moreover, `sec` and its companion `git-sec` are just tiny POSIX-ish shell scripts,
very easy to hack on.

Usage:

```
sec
    a tiny wrapper for age

commands:
    e  - encrypts from stdin and prints result to stdout
    e <path> [<path> ...] - (re-)encrypts paths inline

    d  - decrypts from stdin and prints result to stdout
    d <path> [<path> ...] - decrypts paths inline

env vars:
    SEC_IDENTITY  - path to an age or ssh identity file (needed to decrypt)
    SEC_RECIPIENTS  - a comma-separated list of recipients,
        they can be age pubkeys, age pubkey files or ssh pubkey files (needed to encrypt)
```

# git-sec

`git-sec` provides the sec integration with git:  
using git clean/smudge filters and the .gitattributes file inside your repo,
it can encrypt/decrypt tracked files transparently.  
This way you can work with decrypted files on your working copy and
encrypted files on your remote.  

After you link or place it in your PATH you can also use it as a git subcommand: `git sec <stuff>`

Usage:

```
git-sec
    handles git configs to transparently use sec in your repo

    on  - activates sec in your git repo
    off  - deactivates sec from your git repo

    l  - lists infos about recipients, tracked paths, etc.

    a '<recipient>' [ '<recipient>'... ]  - adds recipients (you can also pipe them in)
    r '<recipient>' [ '<recipient>'... ]  - removes recipients (you can also pipe them in)

    t '<path>' [ '<path>'... ]  - tracks paths to .gitattributes (remember to quote globbings)
    u '<path>' [ '<path>'... ]  - untracks paths from .gitattributes (remember to quote globbings)

    f  - try to force git to (re-)encrypt your tracked files (works only on a clean git status)
        useful if you have just changed recipients and want to re-encrypt files only for the current ones

env vars:
    SEC_IDENTITY  - path to an age or ssh identity file (needed for decrypt)

files:
    <repo-root>/.sec-recipients  - this file will store the recipient list for your repo.
        Remember to add the recipient of your identity file.
        You can track and encrypt this file too.
```

## References

- [age](https://github.com/FiloSottile/age): the awesome encryption tool by Filippo Valsorda
- [pa](https://github.com/biox/pa): an amazing password manager writter in a few lines of POSIX shell
- [git-crypt](https://github.com/AGWA/git-crypt): a long standing tool, same concept as git-sec, but using GPG
- [shroudage](https://github.com/nxsy/shroudage): the inspiration for git-sec, written in bash
- [git-agecrypt](https://github.com/vlaci/git-agecrypt): another inspiration for git-sec, written in rust

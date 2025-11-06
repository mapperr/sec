# sec

`sec` is a wrapper for the already easy-to-use age.  

But, if age is already easy to use, then, why a *wrapper*?  
For few additional ergonomics and a minimal git clean/smudge integration.  
Moreover, `sec` and its companion `sec-git` are just tiny POSIX-ish shell scripts,
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
    SEC_IDENTITY  - path to an age identity file (needed to decrypt)
    SEC_RECIPIENTS  - can be a path to an age recipient file
        or a comma-separated list of age recipients (needed to encrypt)
```

# sec-git

`sec-git` provides the sec integration with git:  
using git clean/smudge filters and the .gitattributes file inside your repo,
it can encrypt/decrypt tracked files transparently.  
This way you can work with decrypted files on your working copy and
encrypted files on your remote.  


Usage:

```
sec-git
    handles git configs to transparently use sec in your repo

    on  - activates sec in your git repo
    off  - deactivates sec from your git repo

    l  - lists infos about recipients, tracked paths, etc.

    # recipients
    a '<recipient>' [ '<recipient>'... ]  - adds recipients
    r '<recipient>' [ '<recipient>'... ]  - removes recipients

    t '<path>' [ '<path>'... ]  - tracks paths to .gitattributes (remember to quote globbings)
    u '<path>' [ '<path>'... ]  - untracks paths from .gitattributes (remember to quote globbings)

    # utilities:
    f  - try to force git to (re-)encrypt your fresh-tracked file (works only on a clean git status)

env vars:
    SEC_IDENTITY  - path to an age identity file (needed for decrypt)

files:
    <repo-root-dir>/.sec-recipients  - this file will store the recipient list for your repo
        remember to add the recipient of your identity file!
```

## References

- [age](https://github.com/FiloSottile/age): the awesome encryption tool by Filippo Valsorda
- [pa](https://github.com/biox/pa): an amazing password manager writter in a few lines of POSIX shell
- [git-crypt](https://github.com/AGWA/git-crypt): a long standing tool, same concept as sec-git, but using GPG
- [shroudage](https://github.com/nxsy/shroudage): the inspiration for sec-git, written in bash
- [git-agecrypt](https://github.com/vlaci/git-agecrypt): another inspiration for sec-git, written in rust

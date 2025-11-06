# sec

`sec` is a wrapper for the already easy-to-use age.  

But, if age is already easy to use, then, why a *wrapper*?  
For few additional ergonomics and a minimal git clean/smudge integration.  
Moreover, `sec` and its companion `sec-git` are just tiny POSIX-ish shell scripts,
very easy to hack on.

Usage:

```
${SEC_USAGE}
```

# sec-git

`sec-git` provides the sec integration with git:  
using git clean/smudge filters and the .gitattributes file inside your repo,
it can encrypt/decrypt tracked files transparently.  
This way you can work with decrypted files on your working copy and
encrypted files on your remote.  


Usage:

```
${SECGIT_USAGE}
```

## References

- [age](https://github.com/FiloSottile/age): the awesome encryption tool by Filippo Valsorda
- [pa](https://github.com/biox/pa): an amazing password manager writter in a few lines of POSIX shell
- [git-crypt](https://github.com/AGWA/git-crypt): a long standing tool, same concept as sec-git, but using GPG
- [shroudage](https://github.com/nxsy/shroudage): the inspiration for sec-git, written in bash
- [git-agecrypt](https://github.com/vlaci/git-agecrypt): another inspiration for sec-git, written in rust

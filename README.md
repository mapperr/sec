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

# Basic usage

```
# setup

# copy/link sec and git-sec in your PATH

$ export SEC_IDENTITY=~/path/to/my_personal_age.key
# or
$ export SEC_IDENTITY=~/.ssh/id_my_personal_ssh.key

$ export SEC_RECIPIENTS="~/.ssh/id_my_personal_ssh.pub,age1hx25sge85krrprcfa6vd2rr4t9u33s8lrkzz5khaxurjpddk5syqptgm3c"
# or
$ export SEC_RECIPIENTS="$( {echo "~/.ssh/id_my_personal_ssh.pub" ; cat ~/path/to/my_usual_age_recipients.pub } |paste -sd,)"

$ echo 'hi mom!' | sec e
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnbU5JN3VyV3IxSDhzOXdL
RSt4UWF5K3o1Z2VmeE9UYVJQMG1OQWE3ejJnCjUzV21kZStlMWllZ1FqWDVkY0tx
VVoxbmk1WVJUQ09QVUxBam9xbkRPTTAKLT4gWDI1NTE5IGFYbHd5SGd5RStkaS9j
WXhtbzF4MzM1VGdHa3M0WFhnRWZJQzhhUGQ0a0kKS1YxQjdEaVpkVkJUMHJuVXBr
MDdMemdUNjFTcU95V0s2TjdvMlRYT0tmbwotPiBzc2gtZWQyNTUxOSAxZDVpdncg
aldLakwwTW5ZUWxXUTdXRGN1NDNpeXBEZFJRWW5VTEhFM3QzU1l0b1d5WQpZZGFh
K0RuYVlzeXUwNENocGNLcTdCQW1iK1VaN0ZmazJWWTNoU2E4UVJvCi0tLSBPcGc5
NFBZV1huY1MxdUp5UEFqZ3I5Wi9MZWRkdUd0bDAwVFQvbVFxSUhNCjExthpBXQeM
A5dfDwDLrB0aHCT7V/Uyvz6mJ3YxmetXMZrRScx20g==
-----END AGE ENCRYPTED FILE-----

$ echo 'hi mom!' | sec e | sec d
hi mom!

$ echo 'hi mom!' > /tmp/himom
$ sec e /tmp/himom
sec: [/tmp/himom] encrypted

$ cat /tmp/himom
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBYSWF4UnpmKzIxT3czZE9q
KzVNdFpPVkFudi9iUUlVcVMyZ2lVd05TL25ZCkNwV1dhZ0VwSVZtaDdDQ2Y5aklH
bldIZlM4L29BaUJXSGU0T0JoQ0w3cUkKLT4gWDI1NTE5IEFtSHJDUHV1VHFtbVhZ
a2ljazFnbyt0N1ZFYUE5SVJsYTRtZTZ2OFhlVmsKQnI1eWFGdWVzOVByelU3RWNP
NDJtS2tWMnB1YzExWUQxMllmRkxyR0JuQQotPiBzc2gtZWQyNTUxOSAxZDVpdncg
bHkwb0FkNFkva21JbENlOTNMNW5kNWJtc3p4cU1VYWxEWkk0dGtCUHVHVQorVU9N
cDRqbVl5bDlCbG1veW9wZFpwdmNMMkpkMU9xdG52bUVoOUNRZUZvCi0tLSBvUUNi
OU9ETWpGUnlZQ1F4V21CcXpUdW40V2lBbGtoaDlvU2VDaXNWK1JNCoBqK8plkLME
wUtWdy0/AylhkMQSECWYoBS363aFza9OYMl4pegf9g==
-----END AGE ENCRYPTED FILE-----

$ sec d /tmp/himom
sec: [/tmp/himom] decrypted
$ cat /tmp/himom
hi mom!
```

## Git repo usage

```
# let's go to a git repo
$ cd /path/to/git/repo
$ git sec l
2025-11-25T13:12:46 git-sec warn: sec git is not active!
# r: recipient, t: tracking, f: file tracked -> grep as you wish

2025-11-25T13:12:46 git-sec warn: no recipients yet!

2025-11-25T13:12:46 git-sec warn: no trackings yet!

2025-11-25T13:12:46 git-sec warn: no tracked files!

# ok, there is nothing yet, let's add something to be encrypted on remote

$ cat ~/.ssh/id_my_personal_ssh.pub | git sec a
2025-11-25T13:22:18 git-sec: added recipient [ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIORfYBrvJ40V6W4rvYJ4y9r4Ccwy48DBobjXwGUUYZR0 my_ssh_key]

$ git status --short
 M .sec-recipients

$ git sec t '.sec-recipients' '**/*.secret.yaml' '**/*.tfstate'
025-11-25T13:24:27 git-sec: paths [.sec-recipients **/*.secret.yaml **/*.tfstate] tracked
$ git status --short
 M .gitattributes
 M .sec-recipients

$ git diff
...
+**/*.secret.yaml  filter=sec diff=sec
+**/*.tfstate  filter=sec diff=sec
...
...
+ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIORfYBrvJ40V6W4rvYJ4y9r4Ccwy48DBobjXwGUUYZR0 my_ssh_key
...

$ git sec on
2025-11-25T13:25:14 git-sec: activated \o/

$ git sec l
# r: recipient, t: tracking, f: file tracked -> grep as you wish

r: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIORfYBrvJ40V6W4rvYJ4y9r4Ccwy48DBobjXwGUUYZR0 my_ssh_key

t: **/*.tfstate
t: **/secret.yaml
t: .sec-recipients

f: .sec-recipients
f: homelab/my_very_secret.yaml
f: cloud/terraform.tfstate
f: work/terraform.tfstate
f: work/work_secret.yaml

$ git add . && git ci -m 'setup git sec'
# let's force an encryption on tracked files
$ git sec f
$ git add . && git ci -m 'encrypt secret files!' && git push
# from now on, file tracked are transparently encrypted when they are pushed to any remote
# yay \o/!
```
## References

- [age](https://github.com/FiloSottile/age): the awesome encryption tool by Filippo Valsorda
- [pa](https://github.com/biox/pa): an amazing password manager writter in a few lines of POSIX shell
- [git-crypt](https://github.com/AGWA/git-crypt): a long standing tool, same concept as git-sec, but using GPG
- [shroudage](https://github.com/nxsy/shroudage): the inspiration for git-sec, written in bash
- [git-agecrypt](https://github.com/vlaci/git-agecrypt): another inspiration for git-sec, written in rust

## Development

The source is hosted on https://git.sr.ht/~mapperr/sec

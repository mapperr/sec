@_default:
    just -f {{justfile()}} --list

doc:
    #!/bin/sh
    SEC_USAGE="$(./sec)" SECGIT_USAGE="$(./git-sec)" \
        envsubst '$SEC_USAGE $SECGIT_USAGE' <README.tpl.md >README.md

link bindir='$HOME/bin':
    #!/bin/sh
    bindir="{{bindir}}"
    [ ! -d "$bindir" ] &&
        echo "bindir does not exists" &&
        exit 1
    for f in sec*; do
        [ -x "$f" ] || continue
        [ -h "$bindir/$f" ] &&
            echo "[$f] is already a symlink" &&
            continue
        [ -e "$bindir/$f" ] &&
            echo "warn: [$f] is not a symlink" &&
            continue
        ln -s "$PWD/$f" "$bindir/$f"
        echo "symlinked [$f]"
    done

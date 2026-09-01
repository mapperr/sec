core_name := "sec"

@_default:
    just -f {{justfile()}} --list

link bindir='$HOME/bin':
    #!/bin/sh
    bindir="{{bindir}}"
    [ ! -d "$bindir" ] &&
        echo "bindir does not exists" &&
        exit 1
    for f in {{core_name}}*; do
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

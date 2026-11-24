@_default:
    just --list

build:
    cargo build --locked --release

[unix]
link:
    #!/bin/sh
    set -eu
    target_dir=${CARGO_TARGET_DIR:-${CARGO_BUILD_TARGET_DIR:-target}}
    case "$target_dir" in
        /*) ;;
        *) target_dir="$PWD/$target_dir" ;;
    esac
    binary="$target_dir/<target-triple>/release/sec"
    trap 'if [ "$?" -ne 0 ]; then printf "Release executable to link\n  %s\n" "$binary" >&2; fi' EXIT
    target=${CARGO_BUILD_TARGET:-host-tuple}
    if [ "$target" = host-tuple ]; then
        target=$(rustc --print host-tuple)
    fi
    binary="$target_dir/$target/release/sec"
    destination="$HOME/bin/sec"
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
        printf '%s\n' 'Missing release executable. Run just build first.' >&2
        exit 1
    fi
    if [ -L "$destination" ]; then
        current=$(readlink "$destination")
        if [ "$current" = "$binary" ]; then
            exit 0
        fi
        if [ "$current" = "$PWD/target/release/sec" ]; then
            ln -sfn "$binary" "$destination"
            exit 0
        fi
    fi
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        printf 'Destination already exists: %s\n' "$destination" >&2
        exit 1
    fi
    mkdir -p "$HOME/bin"
    ln -s "$binary" "$destination"

test:
    cargo test --locked --all-targets

test-integration:
    cargo build --locked
    python3 -B -m unittest discover -s tests -v

install:
    cargo install --path . --locked

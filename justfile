@_default:
    just -f {{justfile()}} --list

doc:
    #!/bin/sh
    SEC_USAGE="$(sec)" SECGIT_USAGE="$(sec-git)" \
        envsubst '$SEC_USAGE $SECGIT_USAGE' <README.tpl.md >README.md

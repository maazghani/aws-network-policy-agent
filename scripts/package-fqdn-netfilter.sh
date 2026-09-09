#!/usr/bin/env bash
# Build-stage only: copy the installed distribution's xtables tools, extensions
# and their actual shared-library dependencies into a minimal runtime root.
set -euo pipefail
root=${1:?runtime root required}
mkdir -p "$root"
copy_elf() {
    local object=$1 dependency
    cp --parents -L "$object" "$root"
    while IFS= read -r dependency; do
        cp --parents -L "$dependency" "$root"
    done < <(ldd "$object" | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }')
}
for name in iptables ip6tables; do
    copy_elf "$(command -v "$name")"
done
# iptables dynamically loads extensions; ldd on the binary alone misses them.
for directory in /usr/lib64/xtables /usr/lib/xtables; do
    if [[ -d "$directory" ]]; then
        for extension in "$directory"/*.so; do copy_elf "$extension"; done
    fi
done

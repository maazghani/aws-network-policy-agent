#!/usr/bin/env bash
# Build-stage only: copy the installed distribution's xtables tools, extensions
# and their actual shared-library dependencies into a minimal runtime root.
set -euo pipefail
root=${1:?runtime root required}
mkdir -p "$root"
copy_file() {
    local source=$1 destination
    # The runtime's /lib64, /lib, /bin and /sbin are usr-merge symlinks.
    # Preserve those links: copying a directory over one fails in BuildKit.
    # Resolve parent-directory aliases, retaining library SONAME filenames.
    destination=$(readlink -f "$(dirname "$source")")/$(basename "$source")
    case "$destination" in
        /lib/*|/lib64/*|/bin/*|/sbin/*) destination=/usr$destination ;;
    esac
    mkdir -p "$root$(dirname "$destination")"
    cp -L "$source" "$root$destination"
}
copy_elf() {
    local object=$1 dependency
    copy_file "$object"
    while IFS= read -r dependency; do
        copy_file "$dependency"
    done < <(ldd "$object" | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }')
}
for name in iptables ip6tables; do
    # Retain both entrypoint names: xtables selects its protocol from argv[0].
    copy_elf "$(command -v "$name")"
done
# iptables dynamically loads extensions; ldd on the binary alone misses them.
for directory in /usr/lib64/xtables /usr/lib/xtables; do
    if [[ -d "$directory" ]]; then
        for extension in "$directory"/*.so; do copy_elf "$extension"; done
    fi
done

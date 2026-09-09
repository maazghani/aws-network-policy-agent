#!/usr/bin/env bash
# Runs on a disposable Linux host. All BPF pins/routes/interfaces live in private
# mount/network namespaces; it never modifies a running nodeagent's maps.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"

if [[ ${1:-} == --isolated ]]; then
    family=$2
    test_binary=$3
    mount --make-rprivate /
    mount -t bpf bpf /sys/fs/bpf
    mkdir -p /sys/fs/bpf/globals/aws/{maps,programs}
    ip link set lo up
    export FQDN_TEST_ISOLATED=1 FQDN_TEST_FAMILY="$family" FQDN_TEST_REPO="$repo"
    mkdir -p "$repo/test-results"
    export AWS_EBPF_SDK_LOG_FILE="$repo/test-results/sdk-ipv${family}.jsonl"
    test_status=0
    "$test_binary" -test.v -test.timeout=180s || test_status=$?
    # These logs contain only synthetic test endpoints. Lumberjack creates them
    # root-only; make this explicitly created artifact readable by the CI user.
    if [[ -f "$AWS_EBPF_SDK_LOG_FILE" ]]; then chmod 0644 "$AWS_EBPF_SDK_LOG_FILE"; fi
    if [[ $test_status != 0 ]]; then
        # SDK defaults to a private file. Decode its verifier tail rather than
        # lose the decisive failure behind an errno; retain the full artifact.
        python3 - "$AWS_EBPF_SDK_LOG_FILE" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.exists():
    for line in path.read_text(errors='replace').splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        message = record.get('msg', '')
        if 'Load prog done' in message or 'Verifier log:' in message:
            print(message[-131072:])
PY
    fi
    exit "$test_status"
fi

if [[ $EUID != 0 ]]; then
    echo 'FQDN kernel qualification requires root with CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF and CAP_PERFMON (or older-kernel CAP_SYS_ADMIN). Run on a disposable privileged Linux host.' >&2
    exit 1
fi
command -v python3 >/dev/null || { echo 'Missing prerequisite: python3' >&2; exit 1; }
python3 - <<'PY'
import re, sys
status = open('/proc/self/status').read()
caps = int(re.search(r'^CapEff:\s*(\w+)', status, re.M)[1], 16)
missing = [name for bit, name in [(12, 'CAP_NET_ADMIN'), (13, 'CAP_NET_RAW'), (21, 'CAP_SYS_ADMIN')]
           if not caps & (1 << bit)]
if missing:
    sys.exit('Cannot qualify FQDN datapath: missing ' + ', '.join(missing) +
             '; uid 0 alone is insufficient. No tests were skipped or passed.')
PY
for command in go clang ip iptables ip6tables mount unshare; do
    command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done

if [[ ! -s pkg/ebpf/c/vmlinux.h ]]; then
    command -v bpftool >/dev/null || { echo 'bpftool is required to generate vmlinux.h' >&2; exit 1; }
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/c/vmlinux.h
fi
make build-bpf
test_binary=$(mktemp /tmp/fqdn-kernel-tests.XXXXXX)
trap 'rm -f "$test_binary"' EXIT
go test -tags=fqdn_integration -c -o "$test_binary" ./test/fqdn
qualification_status=0
for family in 4 6; do
    # Each family owns independent namespaces and pins. Collect both results
    # even when the first fails, while preserving an overall failing exit code.
    unshare --mount --net --propagation private "$0" --isolated "$family" "$test_binary" || qualification_status=1
done
exit "$qualification_status"

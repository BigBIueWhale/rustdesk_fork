#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

[ "$#" -eq 1 ] \
    || { echo 'usage: test-windows-helper-vm-runtime.sh PROBE_RUNTIME_IMAGE_ID' >&2; exit 2; }
readonly PROBE_RUNTIME_IMAGE_ID=$1
[[ "$PROBE_RUNTIME_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo 'Windows helper VM runtime test runtime image ID is malformed' >&2; exit 2; }
readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || { echo 'Windows helper VM runtime test refuses root execution' >&2; exit 1; }
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || { echo 'Windows helper VM runtime test refuses a root primary group' >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
/usr/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
# shellcheck source=scripts/windows-helper-runtime.sh
source "$SCRIPT_DIR/windows-helper-runtime.sh"

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WINDOWS_HELPER_RUNTIME_ROOT" ]; then
        windows_helper_authority_close || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

expect_mount_refusal() {
    local label=$1 expected=$2 output status=0
    shift 2
    output="$(windows_helper_parse_mounts "$@" 2>&1)" || status=$?
    [ "$status" -ne 0 ] || die "Windows helper mount fixture passed: $label"
    [ "${#output}" -le 4096 ] || die "Windows helper mount diagnostic exceeded its bound: $label"
    case "$output" in
        *"$expected"*) ;;
        *) die "Windows helper mount diagnostic differs for $label: $output" ;;
    esac
}

windows_helper_authority_open
readonly RUNTIME_ROOT=$WINDOWS_HELPER_RUNTIME_ROOT
readonly INPUT=$RUNTIME_ROOT/input
readonly OUTPUT=$RUNTIME_ROOT/output
/usr/bin/install -d -m 0700 "$OUTPUT"
printf 'windows-helper-vm-input\n' >"$INPUT"
/usr/bin/chmod 0400 "$INPUT"

WINDOWS_HELPER_EXTRACTOR_SHA256="$(
    windows_helper_snapshot_program \
        "$SCRIPT_DIR/windows-helper-extract-kernel.py" \
        windows-helper-extract-kernel.py
)"
WINDOWS_HELPER_INSPECTOR_SHA256="$(
    windows_helper_snapshot_program \
        "$SCRIPT_DIR/windows-golden-inspect.sh" \
        windows-golden-inspect.sh
)"
printf 'synthetic-kernel-for-runtime-envelope\n' \
    >"$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz"
/usr/bin/chmod 0400 "$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz"
SHA256_WIN_HELPER_KERNEL="$(
    /usr/bin/sha256sum "$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz" \
        | /usr/bin/awk '{print $1}'
)"
WIN_HELPER_CONFIG_ID=$PROBE_RUNTIME_IMAGE_ID
WINDOWS_HELPER_RUNTIME_READY=1
windows_helper_assert_runtime

expect_mount_refusal traversal 'bind target must be lexically canonical' \
    --mount "type=bind,source=$INPUT,target=/safe/../escape,readonly" -- /bin/true
expect_mount_refusal protected 'bind target overlaps fixed runtime authority' \
    --mount "type=bind,source=$INPUT,target=/proc/status,readonly" -- /bin/true
expect_mount_refusal duplicate 'bind target is duplicated' \
    --mount "type=bind,source=$INPUT,target=/input,readonly" \
    --mount "type=bind,source=$INPUT,target=/input,readonly" -- /bin/true
/usr/bin/mkfifo "$RUNTIME_ROOT/fifo"
expect_mount_refusal special 'bind source must be a regular file or directory' \
    --mount "type=bind,source=$RUNTIME_ROOT/fifo,target=/input,readonly" -- /bin/true
printf 'unsafe\n' >"$RUNTIME_ROOT/unsafe"
/usr/bin/chmod 0622 "$RUNTIME_ROOT/unsafe"
expect_mount_refusal writable-mode 'bind source must not be group/world writable' \
    --mount "type=bind,source=$RUNTIME_ROOT/unsafe,target=/out" -- /bin/true
printf 'linked\n' >"$RUNTIME_ROOT/linked"
/usr/bin/ln "$RUNTIME_ROOT/linked" "$RUNTIME_ROOT/linked-alias"
expect_mount_refusal hard-link 'writable Windows helper file must be single-link' \
    --mount "type=bind,source=$RUNTIME_ROOT/linked,target=/out" -- /bin/true
/usr/bin/ln -s "$INPUT" "$RUNTIME_ROOT/symlink"
expect_mount_refusal symlink 'bind source must exist without a terminal symlink' \
    --mount "type=bind,source=$RUNTIME_ROOT/symlink,target=/input,readonly" -- /bin/true
/usr/bin/rm -- \
    "$RUNTIME_ROOT/fifo" \
    "$RUNTIME_ROOT/unsafe" \
    "$RUNTIME_ROOT/linked" \
    "$RUNTIME_ROOT/linked-alias" \
    "$RUNTIME_ROOT/symlink"

windows_helper_small_run \
    --mount "type=bind,source=$INPUT,target=/input,readonly" \
    --mount "type=bind,source=$OUTPUT,target=/out" \
    -- -euc '
        IFS= read -r input </input
        [ "$input" = windows-helper-vm-input ]
        uid= gid= cap= nnp= seccomp=
        while IFS=":" read -r key value; do
            set -- $value
            case "$key" in
                Uid) uid="$1:$2:$3:$4" ;;
                Gid) gid="$1:$2:$3:$4" ;;
                CapEff) cap=$1 ;;
                NoNewPrivs) nnp=$1 ;;
                Seccomp) seccomp=$1 ;;
            esac
        done </proc/self/status
        [ "$uid" = 4000:4000:4000:4000 ]
        [ "$gid" = 4000:4000:4000:4000 ]
        [ "$cap" = 0000000000000000 ]
        [ "$nnp" = 1 ]
        [ "$seccomp" = 2 ]
        IFS= read -r pids_max </sys/fs/cgroup/pids.max
        IFS= read -r memory_max </sys/fs/cgroup/memory.max
        IFS= read -r swap_max </sys/fs/cgroup/memory.swap.max
        IFS=" " read -r cpu_quota cpu_period </sys/fs/cgroup/cpu.max
        [ "$pids_max" = 64 ]
        [ "$memory_max" = 1073741824 ]
        [ "$swap_max" = 0 ]
        [ "$cpu_quota:$cpu_period" = 100000:100000 ]
        [ "$(ulimit -c)" = 0 ]
        [ "$(ulimit -n)" = 4096 ]
        set -- /sys/class/net/*
        [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
        if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
        if (: >>/input) 2>/dev/null; then exit 92; fi
        : >/tmp/private-write
        printf "profile=small uid=4000 network=none root=readonly input=readonly output=writable caps=none nnp=on seccomp=filter\n" >/out/receipt
    '

readonly RECEIPT="$(<"$OUTPUT/receipt")"
[ "$RECEIPT" = \
  'profile=small uid=4000 network=none root=readonly input=readonly output=writable caps=none nnp=on seccomp=filter' ] \
    || die "Windows helper runtime receipt differs: $RECEIPT"
windows_helper_authority_close
[ ! -e "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] \
    || die "Windows helper runtime root remains after exact close"
printf 'WINDOWS_HELPER_VM_RUNTIME=pass uid=%s gid=%s decisions=8 profile=small docker=real cleanup=joined\n' \
    "$WINDOWS_HELPER_BUILD_UID" "$WINDOWS_HELPER_BUILD_GID"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
uid=$(/usr/bin/id -u)
gid=$(/usr/bin/id -g)
[ "$uid" -ne 0 ] && [ "$gid" -ne 0 ] || exit 1
umask 077
/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null
workspace=$(/usr/bin/mktemp -d /tmp/verifier-run-admission.XXXXXXXXXX)
workspace_id=$(/usr/bin/stat -c '%d:%i' -- "$workspace")
success=0
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$workspace" --expected-identity "$workspace_id" \
        || status=1
    if [ "$status" -eq 0 ] && [ "$success" -eq 1 ]; then
        printf 'VERIFIER_VM_RUN_ADMISSION=pass retained=refused file=refused symlink=refused lock=refused unsafe=refused concurrent=16 winners=1 cleanup=joined\n'
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

/usr/bin/awk '
    /^reserve_verifier_run\(\) \{$/ { found++; copy = 1 }
    copy { print; if ($0 == "}") copy = 0 }
    END { if (found != 1 || copy) exit 1 }
' "$SCRIPT_DIR/smoke-verifier-vm-authority.sh" >"$workspace/function.sh"

invoke() {
    /bin/bash --noprofile --norc -c '
        set -euo pipefail
        fail() { printf "%s\n" "$*" >&2; exit 1; }
        source "$1"
        RUN_ROOT=$2
        HOST_UID=$(/usr/bin/id -u)
        HOST_GID=$(/usr/bin/id -g)
        MODE=${3:-authority-smoke}
        ANDROID_ARTIFACT_STATE_ROOT=${4:-}
        reserve_verifier_run
        for descriptor in /proc/$$/fd/*; do
            if [ "$descriptor" -ef "$RUN_ROOT" ]; then
                fail "run-admission descriptor remains open"
            fi
        done
        printf "%s %s\n" "$RUN" "$RUN_ID"
    ' run-admission "$workspace/function.sh" "$1" "${2:-authority-smoke}" "${3:-}"
}

require_refusal() {
    local root=$1 expected=$2
    if invoke "$root" "${3:-authority-smoke}" "${4:-}" >"$workspace/refusal.out" 2>"$workspace/refusal.err"; then
        printf 'Unexpected run admission: %s\n' "$root" >&2
        exit 1
    fi
    [ ! -s "$workspace/refusal.out" ]
    /usr/bin/grep -Fq -- "$expected" "$workspace/refusal.err"
}

root=$workspace/retained
/usr/bin/mkdir -m 0700 -- "$root"
result=$(invoke "$root")
run=${result% *}
run_id=${result##* }
[[ "$run" == "$root"/run.* ]]
[ "$run_id" = "$(/usr/bin/stat -c '%d:%i' -- "$run")" ]
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$run")" = "$uid:$gid:700" ]
require_refusal "$root" 'earlier verifier run remains'
[ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -name 'run.*' | /usr/bin/wc -l)" -eq 1 ]
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"
result=$(invoke "$root")
run=${result% *}
run_id=${result##* }
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"

for kind in file symlink; do
    root=$workspace/$kind
    /usr/bin/mkdir -m 0700 -- "$root"
    if [ "$kind" = file ]; then
        : >"$root/run.retained"
    else
        /usr/bin/ln -s -- missing "$root/run.retained"
    fi
    require_refusal "$root" 'earlier verifier run remains'
    [ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
done

for kind in directory file symlink; do
    root=$workspace/peer-run-$kind
    capsule=$workspace/peer-capsule-$kind
    /usr/bin/mkdir -m 0700 -- "$root" "$capsule"
    case "$kind" in
        directory) /usr/bin/mkdir -m 0700 -- "$capsule/retained" ;;
        file) : >"$capsule/retained" ;;
        symlink) /usr/bin/ln -s -- missing "$capsule/retained" ;;
    esac
    require_refusal "$root" 'an earlier Android peer artifact remains' android-peer-build "$capsule"
    [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
    [ "$(/usr/bin/find "$capsule" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
done

root=$workspace/locked
/usr/bin/mkdir -m 0700 -- "$root"
exec {lock_fd}<"$root"
/usr/bin/flock --exclusive --nonblock "$lock_fd"
require_refusal "$root" 'another verifier is reserving a run'
[ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
exec {lock_fd}<&-

root=$workspace/unsafe
/usr/bin/mkdir -m 0755 -- "$root"
require_refusal "$root" 'run-root authority differs'
[ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]

root=$workspace/concurrent
/usr/bin/mkdir -m 0700 -- "$root"
pids=()
for index in $(/usr/bin/seq 1 16); do
    invoke "$root" >"$workspace/concurrent.$index.out" \
        2>"$workspace/concurrent.$index.err" &
    pids+=("$!")
done
winners=0
for pid in "${pids[@]}"; do
    if wait "$pid"; then winners=$((winners + 1)); fi
done
[ "$winners" -eq 1 ]
[ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -name 'run.*' | /usr/bin/wc -l)" -eq 1 ]
for index in $(/usr/bin/seq 1 16); do
    if [ -s "$workspace/concurrent.$index.out" ]; then
        [ ! -s "$workspace/concurrent.$index.err" ]
    else
        /usr/bin/grep -Eq \
            'earlier verifier run remains|another verifier is reserving a run' \
            "$workspace/concurrent.$index.err"
    fi
done
success=1

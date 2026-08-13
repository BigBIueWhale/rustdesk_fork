#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C
readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || { printf 'build-windows-vm refuses host or container-root execution\n' >&2; exit 1; }
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || { printf 'build-windows-vm refuses a root primary group\n' >&2; exit 1; }

SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
# shellcheck source=scripts/windows-helper-runtime.sh
source "$SCRIPT_DIR/windows-helper-runtime.sh"

STATE_DIR="${HARNESS_STATE_DIR:-$REPO_ROOT/.harness-state}"
GOLDEN="${WINDOWS_GOLDEN_IMAGE:-$REPO_ROOT/.harness-state/win11-golden.qcow2}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
WINDOWS_BUILD_SOURCE="${WINDOWS_BUILD_SOURCE:-head}"
RELEASE_SRC_COMMIT="${RELEASE_SRC_COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf invalid)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_PIN}"
export SOURCE_DATE_EPOCH

DOMAIN_PREFIX="${HARNESS_PREFIX:-rustdesk-fork-harness}"
VM_TIMEOUT_SECONDS=7200
CREATE_TIMEOUT_SECONDS=300
CONTROL_TIMEOUT_SECONDS=30
PROCESS_ADMISSION_SECONDS=10
PROCESS_STOP_SECONDS=10
FAILURE_EVIDENCE_MAX_BYTES=$((64 * 1024 * 1024))
FAILURE_EVIDENCE_FILE_MAX_BYTES=$((16 * 1024 * 1024))
RUN_STORAGE_FIXED_ALLOWANCE_BYTES=$((24 * 1024 * 1024 * 1024))
RUN_STORAGE_EMERGENCY_RESERVE_BYTES=$((32 * 1024 * 1024 * 1024))
BUILD_ONLINE_SNAPSHOT_ALLOWANCE_BYTES=$((48 * 1024 * 1024 * 1024))
TARGET_ID="windows-x86_64"
FRB_OUTPUTS=(
    src/bridge_generated.rs
    src/bridge_generated.io.rs
    flutter/lib/generated_bridge.dart
    flutter/lib/generated_bridge.freezed.dart
)

RUN_ROOT=""
RUN_ROOT_ID=""
BUILD_LEASE=""
BUILD_LEASE_ID=""
OUT_PARENT=""
OUT_PARENT_ID=""
RUN_ID=""
SOURCE_SNAPSHOT=""
SOURCE_COMMIT=""
SOURCE_TREE=""
SOURCE_MODE=""
FORK_VERSION_VALUE=""
BASE_MANIFEST_SHA256=""
OFFLINE_MANIFEST_SHA256=""
DEB_BUILDER_IMAGE=""
GOLDEN_IDENTITY=""
GOLDEN_EDGE=""
ONLINE_SNAPSHOT_PARENT=""
ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED=0
ONLINE_SNAPSHOT_TRANSACTION=""
ONLINE_SNAPSHOT_TRANSACTION_ID=""
FAILURE_EVIDENCE_TRANSACTION=""
FAILURE_EVIDENCE_TRANSACTION_ID=""
CURRENT_DOMAIN=""
CURRENT_DOMAIN_UUID=""
CURRENT_DOMAIN_CREATION_STARTED=0
CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0
CURRENT_VIRT_PID=""
CURRENT_VIRT_START=""
CURRENT_VM_DEADLINE=""
CURRENT_PASS_ROOT=""
RUN_COMPLETE=0
CLEANUP_ACTIVE=0
CLEANUP_FAILED=0
FRB_REFERENCE=""
RUN_PHASE="startup"

assert_safe_path() {
    local value="$1" label="$2"
    [ -n "$value" ] || die "$label is empty"
    [ "${value#/}" != "$value" ] || die "$label must be absolute: $value"
    case "$value" in
        *','*|*':'*) die "$label contains a Docker/libvirt option delimiter: $value" ;;
    esac
    if LC_ALL=C printf '%s' "$value" | grep -q '[[:cntrl:]]'; then
        die "$label contains a control character"
    fi
}

assert_disjoint_paths() {
    local first="$1" first_label="$2" second="$3" second_label="$4"
    { [ "$first" != / ] && [ "$second" != / ]; } \
        || die "$first_label and $second_label cannot be disjoint from the filesystem root"
    [ "$first" != "$second" ] \
        || die "$first_label and $second_label must be disjoint"
    case "$first/" in
        "$second/"*) die "$first_label must not be beneath $second_label" ;;
    esac
    case "$second/" in
        "$first/"*) die "$second_label must not be beneath $first_label" ;;
    esac
}

record_run_root_identity() {
    local resolved metadata owner group mode device inode extra
    [ -n "$RUN_ROOT" ] || die "private Windows run root is empty"
    [ -d "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ] \
        || die "private Windows run root is not a real directory"
    resolved="$(/usr/bin/readlink -f -- "$RUN_ROOT" 2>/dev/null)" \
        || die "private Windows run root cannot be resolved"
    [ "$resolved" = "$RUN_ROOT" ] \
        || die "private Windows run root is not canonical"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$RUN_ROOT" 2>/dev/null)" \
        || die "private Windows run-root identity is unavailable"
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$group" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ "$mode" = 700 ] \
        || die "private Windows run root is not current-principal mode 0700"
    [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "private Windows run-root identity is malformed"
    RUN_ROOT_ID="$device:$inode"
}

record_output_parent_identity() {
    local resolved metadata owner group mode device inode extra
    [ -n "$OUT_PARENT" ] || die "Windows output parent is empty"
    [ -d "$OUT_PARENT" ] && [ ! -L "$OUT_PARENT" ] \
        || die "Windows output parent is not a real directory"
    resolved="$(/usr/bin/readlink -f -- "$OUT_PARENT" 2>/dev/null)" \
        || die "Windows output parent cannot be resolved"
    [ "$resolved" = "$OUT_PARENT" ] \
        || die "Windows output parent is not canonical"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$OUT_PARENT" 2>/dev/null)" \
        || die "Windows output-parent identity is unavailable"
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$group" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ $((8#$mode & 8#700)) -eq $((8#700)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        || die "Windows output parent does not grant only current-principal write authority"
    [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "Windows output-parent identity is malformed"
    OUT_PARENT_ID="$device:$inode"
}

remove_private_root_exact() {
    [ "$#" -eq 2 ] && [ -n "$1" ] && [ -n "$2" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$1" --expected-identity "$2"
}

remove_completed_run_root() {
    [ -n "$RUN_ROOT" ] && [ -n "$RUN_ROOT_ID" ] || return 1
    remove_private_root_exact "$RUN_ROOT" "$RUN_ROOT_ID" || return 1
    { [ ! -e "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ]; } || return 1
    RUN_ROOT=""
    RUN_ROOT_ID=""
}

acquire_build_lease() {
    [ -z "$BUILD_LEASE" ] && [ -z "$BUILD_LEASE_ID" ] \
        || die "Windows build lease is already held"
    BUILD_LEASE="$STATE_DIR/windows-build.lease"
    mkdir -m 0700 -- "$BUILD_LEASE" \
        || die "another Windows build may be active or unreconciled: $BUILD_LEASE"
    BUILD_LEASE_ID="$(/usr/bin/stat -c '%d:%i' -- "$BUILD_LEASE")" \
        || die "cannot bind the Windows build-lease identity"
    [[ "$BUILD_LEASE_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || die "Windows build-lease identity is malformed"
}

release_build_lease() {
    [ -z "$BUILD_LEASE" ] && [ -z "$BUILD_LEASE_ID" ] && return 0
    [ -n "$BUILD_LEASE" ] && [ -n "$BUILD_LEASE_ID" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-empty-private-root "$BUILD_LEASE" \
            --expected-identity "$BUILD_LEASE_ID" \
        || return 1
    { [ ! -e "$BUILD_LEASE" ] && [ ! -L "$BUILD_LEASE" ]; } || return 1
    BUILD_LEASE=""
    BUILD_LEASE_ID=""
}

require_no_retained_windows_runs() {
    local retained
    retained="$(find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
        \( -name 'windows-build-*' -o -name '.windows-failure-*' \
            -o -name '.windows-online-snapshot-*' \
            -o -name 'windows-online-snapshot-*' \) -print -quit)" \
        || die "cannot inspect prior Windows build state"
    [ -z "$retained" ] \
        || die "prior Windows build state or transaction must be explicitly reconciled before another allocation: $retained"
}

verify_wix_nuget_packages() {
    local root="$ONLINE_DIR/wix-nuget-packages"
    local file name expected_size expected_sha metadata i
    local -a actual=()
    local -a expected=(
        "wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg"
        "wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg"
        "wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg"
        "wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg"
        "wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg"
        "wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg"
    )
    local -a records=(
        "${expected[0]}|$SIZE_WIX_NUGET_FIREWALL|$SHA256_WIX_NUGET_FIREWALL"
        "${expected[1]}|$SIZE_WIX_NUGET_HEAT|$SHA256_WIX_NUGET_HEAT"
        "${expected[2]}|$SIZE_WIX_NUGET_NETFX|$SHA256_WIX_NUGET_NETFX"
        "${expected[3]}|$SIZE_WIX_NUGET_SDK|$SHA256_WIX_NUGET_SDK"
        "${expected[4]}|$SIZE_WIX_NUGET_UI|$SHA256_WIX_NUGET_UI"
        "${expected[5]}|$SIZE_WIX_NUGET_UTIL|$SHA256_WIX_NUGET_UTIL"
    )

    [ -d "$root" ] && [ ! -L "$root" ] \
        || die "exact WiX local-package source is missing or not a real directory"
    mapfile -t actual < <(
        find "$root" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
    )
    [ "${#actual[@]}" -eq "${#expected[@]}" ] \
        || die "WiX local-package source must contain exactly six entries"
    for ((i = 0; i < ${#expected[@]}; i++)); do
        [ "${actual[i]}" = "${expected[i]}" ] \
            || die "WiX local-package source inventory differs at entry $i"
    done
    for metadata in "${records[@]}"; do
        IFS='|' read -r name expected_size expected_sha <<<"$metadata"
        file="$root/$name"
        [ -f "$file" ] && [ ! -L "$file" ] \
            || die "WiX local-package source entry is not an ordinary file: $name"
        [ "$(stat -c '%s' "$file")" = "$expected_size" ] \
            || die "WiX local-package source entry has the wrong size: $name"
        verify_sha256 "$file" "$expected_sha"
    done
}

assert_uuid() {
    [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
        || die "kernel random UUID is malformed: $1"
}

monotonic_seconds() {
    local uptime
    IFS=' ' read -r uptime _ </proc/uptime
    printf '%s\n' "${uptime%%.*}"
}

process_identity() {
    local pid="$1" stat
    [ -r "/proc/$pid/stat" ] || return 1
    stat="$(<"/proc/$pid/stat")" || return 1
    stat="${stat##*) }"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    printf '%s %s %s %s\n' "$1" "${20}" "$3" "$4"
}

process_start_time() {
    local identity
    identity="$(process_identity "$1")" || return 1
    set -- $identity
    printf '%s\n' "$2"
}

owned_process_matches() {
    local identity state start group session
    [ -n "$CURRENT_VIRT_PID" ] && [ -n "$CURRENT_VIRT_START" ] || return 1
    identity="$(process_identity "$CURRENT_VIRT_PID" 2>/dev/null)" || return 1
    read -r state start group session <<< "$identity"
    [ "$start" = "$CURRENT_VIRT_START" ] \
        && [ "$group" = "$CURRENT_VIRT_PID" ] \
        && [ "$session" = "$CURRENT_VIRT_PID" ]
}

wait_for_owned_process_group() {
    local deadline identity state start group session
    [ -n "$CURRENT_VIRT_PID" ] && [ -n "$CURRENT_VIRT_START" ] || return 1
    deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))
    while true; do
        identity="$(process_identity "$CURRENT_VIRT_PID" 2>/dev/null)" || return 1
        read -r state start group session <<< "$identity"
        [ "$start" = "$CURRENT_VIRT_START" ] || return 1
        [ "$state" != Z ] && [ "$state" != X ] || return 1
        if [ "$group" = "$CURRENT_VIRT_PID" ] \
            && [ "$session" = "$CURRENT_VIRT_PID" ]; then
            return 0
        fi
        [ "$(monotonic_seconds)" -lt "$deadline" ] || return 1
        sleep 0.05
    done
}

owned_process_is_live() {
    local identity state start group session
    [ -n "$CURRENT_VIRT_PID" ] && [ -n "$CURRENT_VIRT_START" ] || return 1
    identity="$(process_identity "$CURRENT_VIRT_PID" 2>/dev/null)" || return 1
    read -r state start group session <<< "$identity"
    [ "$start" = "$CURRENT_VIRT_START" ] \
        && [ "$group" = "$CURRENT_VIRT_PID" ] \
        && [ "$session" = "$CURRENT_VIRT_PID" ] \
        && [ "$state" != Z ] && [ "$state" != X ]
}

owned_process_group_is_live() {
    local path stat state group session
    [ -n "$CURRENT_VIRT_PID" ] || return 1
    for path in /proc/[0-9]*/stat; do
        [ -r "$path" ] || continue
        stat="$(<"$path")" || continue
        stat="${stat##*) }"
        set -- $stat
        [ "$#" -ge 4 ] || continue
        state="$1"
        group="$3"
        session="$4"
        if [ "$group" = "$CURRENT_VIRT_PID" ] \
            && [ "$session" = "$CURRENT_VIRT_PID" ] \
            && [ "$state" != Z ] && [ "$state" != X ]; then
            return 0
        fi
    done
    return 1
}

stop_owned_process() {
    [ -n "$CURRENT_VIRT_PID" ] || return 0
    [ -n "$CURRENT_VIRT_START" ] || return 1
    if ! owned_process_matches; then
        [ ! -e "/proc/$CURRENT_VIRT_PID" ] || return 1
        owned_process_group_is_live && return 1
        wait "$CURRENT_VIRT_PID" 2>/dev/null || :
        CURRENT_VIRT_PID=""
        CURRENT_VIRT_START=""
        return 0
    fi
    if owned_process_is_live; then
        kill -TERM -- "-$CURRENT_VIRT_PID" || return 1
        local deadline
        deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
        while owned_process_group_is_live \
            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            sleep 1
        done
        if owned_process_group_is_live; then
            owned_process_matches || return 1
            kill -KILL -- "-$CURRENT_VIRT_PID" || return 1
            wait "$CURRENT_VIRT_PID" 2>/dev/null || :
            deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
            while owned_process_group_is_live \
                && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                sleep 1
            done
            owned_process_group_is_live && return 1
        fi
    fi
    owned_process_group_is_live && return 1
    if owned_process_matches; then
        local identity state
        identity="$(process_identity "$CURRENT_VIRT_PID")" || return 1
        state="${identity%% *}"
        [ "$state" = Z ] || [ "$state" = X ] || return 1
    fi
    wait "$CURRENT_VIRT_PID" 2>/dev/null || :
    CURRENT_VIRT_PID=""
    CURRENT_VIRT_START=""
}

virsh_bounded() {
    setsid --wait \
        timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \
        virsh --connect qemu:///session "$@" </dev/null
}

domain_name_is_listed() {
    local names
    names="$(virsh_bounded list --all --name)" || return 2
    printf '%s\n' "$names" \
        | awk -v wanted="$CURRENT_DOMAIN" '$0 == wanted { found=1 } END { exit !found }'
}

domain_uuid_is_listed() {
    local uuids
    uuids="$(virsh_bounded list --all --uuid)" || return 2
    printf '%s\n' "$uuids" \
        | awk -v wanted="$CURRENT_DOMAIN_UUID" '$0 == wanted { found=1 } END { exit !found }'
}

require_domain_identity_absent() {
    local status
    if domain_name_is_listed; then
        die "generated domain name already exists; refusing to mutate it"
    else
        status=$?
        [ "$status" = 1 ] \
            || die "cannot prove generated domain-name absence"
    fi
    if domain_uuid_is_listed; then
        die "generated domain UUID already exists; refusing to mutate it"
    else
        status=$?
        [ "$status" = 1 ] \
            || die "cannot prove generated domain-UUID absence"
    fi
}

prove_owned_domain() {
    local actual_name
    [ -n "$CURRENT_DOMAIN" ] && [ -n "$CURRENT_DOMAIN_UUID" ] || return 1
    actual_name="$(virsh_bounded domname "$CURRENT_DOMAIN_UUID" 2>/dev/null)" \
        || return 1
    [ "$actual_name" = "$CURRENT_DOMAIN" ]
}

clear_domain_authority() {
    CURRENT_DOMAIN=""
    CURRENT_DOMAIN_UUID=""
    CURRENT_DOMAIN_CREATION_STARTED=0
    CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0
    CURRENT_VM_DEADLINE=""
}

stop_and_undefine_owned_domain() {
    [ -n "$CURRENT_DOMAIN_UUID" ] || return 0
    if [ "$CURRENT_DOMAIN_CREATION_STARTED" = 0 ]; then
        clear_domain_authority
        return 0
    fi
    if [ "$CURRENT_DOMAIN_OWNERSHIP_COMMITTED" = 0 ]; then
        if domain_uuid_is_listed; then
            warn "uncommitted provision UUID exists after an ambiguous launch; preserving it"
            return 1
        else
            local listed_status=$?
            if [ "$listed_status" = 1 ]; then
                clear_domain_authority
                return 0
            fi
            return 1
        fi
    fi
    if ! prove_owned_domain; then
        if domain_uuid_is_listed; then
            warn "owned UUID exists under an unexpected name; preserving run state"
            return 1
        else
            local listed_status=$?
            if [ "$listed_status" = 1 ]; then
                clear_domain_authority
                return 0
            fi
            return 1
        fi
    fi

    local state deadline
    state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" || return 1
    case "$state" in
        "shut off") ;;
        *)
            virsh_bounded destroy "$CURRENT_DOMAIN_UUID" >/dev/null || return 1
            deadline=$(( $(monotonic_seconds) + 60 ))
            while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                if ! domain_uuid_is_listed; then
                    local listed_status=$?
                    if [ "$listed_status" = 1 ]; then
                        clear_domain_authority
                        return 0
                    fi
                    return 1
                fi
                prove_owned_domain || return 1
                state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" || return 1
                [ "$state" = "shut off" ] && break
                sleep 1
            done
            prove_owned_domain || return 1
            [ "$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" = "shut off" ] \
                || return 1
            ;;
    esac
    virsh_bounded undefine "$CURRENT_DOMAIN_UUID" --nvram >/dev/null || return 1
    if domain_uuid_is_listed; then
        return 1
    else
        local listed_status=$?
        [ "$listed_status" = 1 ] || return 1
        clear_domain_authority
        return 0
    fi
}

FAILURE_EVIDENCE_BYTES=0

copy_failure_evidence_file() {
    local source="$1" destination="$2" outcome size
    [ -e "$source" ] || [ -L "$source" ] || return 0
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 0
    outcome="$(python3 - "$source" "$destination" \
        "$WINDOWS_HELPER_BUILD_UID" "$FAILURE_EVIDENCE_FILE_MAX_BYTES" \
        "$((FAILURE_EVIDENCE_MAX_BYTES - FAILURE_EVIDENCE_BYTES))" <<'PY'
import os
import stat
import sys

source, destination, uid_text, file_limit_text, remaining_text = sys.argv[1:]
uid = int(uid_text)
file_limit = int(file_limit_text)
remaining = int(remaining_text)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(source, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1:
        raise SystemExit("failure-evidence source is not a current-UID single-link regular file")
    if before.st_size > file_limit or before.st_size > remaining:
        print(f"omitted:{before.st_size}")
        raise SystemExit(0)
    output = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0),
        0o400,
    )
    try:
        copied = 0
        while copied < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - copied))
            if not chunk:
                raise SystemExit("failure-evidence source ended before its recorded size")
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise SystemExit("failure-evidence copy made no progress")
                view = view[written:]
            copied += len(chunk)
        if os.read(descriptor, 1):
            raise SystemExit("failure-evidence source grew during its bounded copy")
        after = os.fstat(descriptor)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise SystemExit("failure-evidence source identity changed during copy")
        os.fchmod(output, 0o400)
        os.fsync(output)
    finally:
        os.close(output)
    print(f"copied:{before.st_size}")
finally:
    os.close(descriptor)
PY
)" || return 1
    case "$outcome" in
        copied:[0-9]*)
            size="${outcome#copied:}"
            [[ "$size" =~ ^[0-9]+$ ]] || return 1
            FAILURE_EVIDENCE_BYTES=$((FAILURE_EVIDENCE_BYTES + size))
            ;;
        omitted:[0-9]*)
            warn "omitting oversized bounded failure diagnostic: $source (${outcome#omitted:} bytes)"
            ;;
        *) return 1 ;;
    esac
}

preserve_failure_evidence() {
    [ -n "$RUN_ID" ] && [ -n "$RUN_ROOT" ] && [ -n "$RUN_ROOT_ID" ] \
        || return 1
    local pending final pending_id pass root diagnostic
    local -a extracted=()
    FAILURE_EVIDENCE_BYTES=0
    pending="$(mktemp -d "$STATE_DIR/.windows-failure-$RUN_ID.XXXXXXXX")" \
        || return 1
    chmod 0700 "$pending" || return 1
    pending_id="$(stat -c '%d:%i' -- "$pending")" || return 1
    FAILURE_EVIDENCE_TRANSACTION="$pending"
    FAILURE_EVIDENCE_TRANSACTION_ID="$pending_id"
    final="$STATE_DIR/windows-failure-$RUN_ID"
    { [ ! -e "$final" ] && [ ! -L "$final" ]; } || return 1

    copy_failure_evidence_file \
        "$RUN_ROOT/base-source-manifest.json" "$pending/base-source-manifest.json" || return 1
    copy_failure_evidence_file \
        "$RUN_ROOT/offline-input-manifest.json" "$pending/offline-input-manifest.json" || return 1
    for pass in A B; do
        copy_failure_evidence_file \
            "$RUN_ROOT/pass-$pass/domain.xml" "$pending/pass-$pass-domain.xml" || return 1
        copy_failure_evidence_file \
            "$RUN_ROOT/pass-$pass/source-media/.source-identity.json" \
            "$pending/pass-$pass-source-identity.json" || return 1
        extracted=()
        if [ -d "$RUN_ROOT/pass-$pass" ] && [ ! -L "$RUN_ROOT/pass-$pass" ]; then
            mapfile -d '' extracted < <(find "$RUN_ROOT/pass-$pass" \
                -mindepth 1 -maxdepth 1 -type d -name 'extract.*' -print0)
        fi
        [ "${#extracted[@]}" -le 1 ] || return 1
        for root in "$RUN_ROOT/pass-$pass/result" "${extracted[@]}"; do
            [ -d "$root" ] && [ ! -L "$root" ] || continue
            for diagnostic in build-log.txt build-windows.stdout.txt build-windows.stderr.txt \
                run-build-progress.txt \
                windows-installed-service-probe.stdout.txt windows-installed-service-probe.stderr.txt \
                windows-installed-service-result.json \
                windows-full-peer-presentation.stdout.txt windows-full-peer-presentation.stderr.txt \
                windows-full-peer-server.stdout.txt windows-full-peer-server.stderr.txt \
                windows-full-peer-viewer.stdout.txt windows-full-peer-viewer.stderr.txt \
                windows-full-peer-probe-build-receipt.json \
                windows-full-peer-presentation-result.json; do
                copy_failure_evidence_file \
                    "$root/$diagnostic" "$pending/pass-$pass-$diagnostic" || return 1
            done
        done
    done
    python3 - "$pending/failure.json" "$RUN_ID" "$RUN_PHASE" "$SOURCE_COMMIT" \
        "$SOURCE_TREE" "$FAILURE_EVIDENCE_BYTES" <<'PY'
import json
import os
import sys

output, run_id, phase, source_commit, source_tree, copied_text = sys.argv[1:]
payload = {
    "format": "rustdesk-windows-failure-evidence-v1",
    "run_id": run_id,
    "phase": phase,
    "source_commit": source_commit,
    "source_tree": source_tree,
    "copied_bytes": int(copied_text),
    "bulk_run_state_retirement_required": True,
}
descriptor = os.open(
    output,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
    0o400,
)
try:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit("failure-evidence receipt write made no progress")
        view = view[written:]
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    [ "$(stat -c '%u:%g:%a:%d:%i' -- "$pending")" = \
        "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:700:$pending_id" ] \
        || return 1
    mv -T -- "$pending" "$final" || return 1
    FAILURE_EVIDENCE_TRANSACTION=""
    FAILURE_EVIDENCE_TRANSACTION_ID=""
    python3 - "$STATE_DIR" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    log "bounded Windows failure evidence retained at $final ($FAILURE_EVIDENCE_BYTES copied bytes)"
}

remove_failure_evidence_transaction() {
    [ -z "$FAILURE_EVIDENCE_TRANSACTION" ] \
        && [ -z "$FAILURE_EVIDENCE_TRANSACTION_ID" ] && return 0
    [ -n "$FAILURE_EVIDENCE_TRANSACTION" ] \
        && [ -n "$FAILURE_EVIDENCE_TRANSACTION_ID" ] || return 1
    remove_private_root_exact \
        "$FAILURE_EVIDENCE_TRANSACTION" "$FAILURE_EVIDENCE_TRANSACTION_ID" || return 1
    { [ ! -e "$FAILURE_EVIDENCE_TRANSACTION" ] \
        && [ ! -L "$FAILURE_EVIDENCE_TRANSACTION" ]; } || return 1
    FAILURE_EVIDENCE_TRANSACTION=""
    FAILURE_EVIDENCE_TRANSACTION_ID=""
}

cleanup() {
    local status=$?
    local bounded_transaction_failed=0
    local external_authority_reconciled=1
    [ "$CLEANUP_ACTIVE" = 0 ] || exit "$status"
    CLEANUP_ACTIVE=1
    trap - EXIT HUP INT TERM

    if ! stop_owned_process; then
        CLEANUP_FAILED=1
        external_authority_reconciled=0
        warn "preserving the domain because the owned virt-install process group did not terminate conclusively"
    elif ! stop_and_undefine_owned_domain; then
        CLEANUP_FAILED=1
        external_authority_reconciled=0
    fi

    if ! windows_helper_authority_close; then
        CLEANUP_FAILED=1
        external_authority_reconciled=0
    fi
    if [ "$external_authority_reconciled" = 1 ] \
        && [ "$RUN_COMPLETE" != 1 ] && [ -n "$RUN_ROOT" ]; then
        if ! preserve_failure_evidence; then
            warn "bounded Windows failure evidence could not be retained; bulk run state will still retire"
        fi
    fi
    if ! remove_failure_evidence_transaction; then
        bounded_transaction_failed=1
        warn "bounded Windows failure-evidence transaction could not be retired"
    fi
    if [ "$external_authority_reconciled" = 1 ] && [ -n "$RUN_ROOT" ]; then
        if ! remove_completed_run_root; then
            CLEANUP_FAILED=1
            warn "preserving Windows harness state because exact private-tree cleanup failed"
        fi
    elif [ -n "$RUN_ROOT" ]; then
        warn "retaining unreconciled Windows harness state at $RUN_ROOT; the persistent lease blocks another run"
    fi
    if [ "$external_authority_reconciled" = 1 ]; then
        if ! remove_online_snapshot_transaction; then
            CLEANUP_FAILED=1
            warn "Windows build-scoped online-snapshot transaction could not be retired"
        fi
    elif [ -n "$ONLINE_SNAPSHOT_TRANSACTION" ]; then
        warn "retaining the unreconciled Windows build-scoped online-snapshot transaction; the persistent lease blocks another run"
    fi
    if [ "$bounded_transaction_failed" != 0 ]; then
        CLEANUP_FAILED=1
    fi
    if [ "$CLEANUP_FAILED" = 0 ]; then
        if ! release_build_lease; then
            CLEANUP_FAILED=1
            warn "Windows build lease could not be retired"
        fi
    fi
    if [ "$CLEANUP_FAILED" != 0 ] && [ "$status" = 0 ]; then
        status=1
    fi
    exit "$status"
}

signal_exit() {
    local status="$1"
    trap - HUP INT TERM
    exit "$status"
}

trap cleanup EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

verify_sha512_file() {
    local file="$1" expected="$2"
    [ -f "$file" ] && [ ! -L "$file" ] || die "required SHA512-pinned file is not regular: $file"
    [ "$(sha512sum "$file" | awk '{print $1}')" = "$expected" ] || die "SHA512 mismatch for $file"
}

verify_libvpx_windows_tools() {
    local hash name extra count=0
    [ "$(sha256sum "$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512" | awk '{print $1}')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST" ] \
        || die "libvpx Windows tool manifest does not match its pin"
    while read -r hash name extra; do
        [ -n "$hash" ] && [ -n "$name" ] && [ -z "$extra" ] \
            || die "malformed libvpx Windows tool manifest entry"
        [[ "$hash" =~ ^[0-9a-f]{128}$ ]] || die "malformed libvpx Windows tool SHA512"
        [[ "$name" =~ ^[A-Za-z0-9._~+-]+$ ]] || die "malformed libvpx Windows tool name"
        verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/windows-tools/$name" "$hash"
        count=$((count + 1))
    done <"$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512"
    [ "$count" = 32 ] || die "libvpx Windows tool manifest must contain exactly 32 entries"
}

assert_head_source() {
    local current resolved dirt
    current="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" || die "cannot resolve current HEAD"
    resolved="$(git -C "$REPO_ROOT" rev-parse --verify "${RELEASE_SRC_COMMIT}^{commit}")" \
        || die "cannot resolve RELEASE_SRC_COMMIT"
    [ "$current" = "$resolved" ] || die "head mode requires RELEASE_SRC_COMMIT to equal current HEAD"
    dirt="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" \
        || die "cannot inspect the source worktree"
    [ -z "$dirt" ] || die "head mode requires a clean source worktree"
    RELEASE_SRC_COMMIT="$resolved"
}

activate_release_online_snapshot() {
    [ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] || return 1
    [ "$WINDOWS_BUILD_SOURCE" = head ] \
        || die "release online snapshot requires head source mode"
    ONLINE_SNAPSHOT_PARENT="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
    case "$ONLINE_SNAPSHOT_PARENT" in
        /*) ;;
        *) die "release online snapshot path must be absolute" ;;
    esac
    [ -d "$ONLINE_SNAPSHOT_PARENT" ] && [ ! -L "$ONLINE_SNAPSHOT_PARENT" ] \
        || die "release online snapshot parent is not a real directory"
    [ "$(realpath -e "$ONLINE_SNAPSHOT_PARENT")" = "$ONLINE_SNAPSHOT_PARENT" ] \
        || die "release online snapshot path is not canonical"
    [ "$(stat -c '%u:%a' "$ONLINE_SNAPSHOT_PARENT")" = "$(id -u):700" ] \
        || die "release online snapshot parent is not current-UID mode 0700"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
    [ -d "$ONLINE_DIR" ] && [ ! -L "$ONLINE_DIR" ] \
        || die "release online snapshot tree is not a real directory"
    [ "$(stat -c '%u:%a' "$ONLINE_DIR")" = "$(id -u):500" ] \
        || die "release online snapshot tree is not current-UID mode 0500"
    verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED=0
}

verify_active_online_snapshot() {
    [ -n "$ONLINE_SNAPSHOT_PARENT" ] || die "Windows online snapshot is not initialized"
    verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

materialize_build_online_snapshot() {
    [ "$ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED" = 1 ] \
        || die "Windows build-scoped online snapshot was not authorized"
    [ -z "$ONLINE_SNAPSHOT_TRANSACTION" ] \
        && [ -z "$ONLINE_SNAPSHOT_TRANSACTION_ID" ] \
        && [ -z "$ONLINE_SNAPSHOT_PARENT" ] \
        || die "Windows build-scoped online snapshot authority is already occupied"
    [ -n "$SHA256_ONLINE_CLOSURE_V1" ] \
        || die "Windows build-scoped online snapshot digest is unavailable"
    local canonical_online="$ONLINE_DIR"
    ONLINE_SNAPSHOT_TRANSACTION="$(mktemp -d \
        "$STATE_DIR/.windows-online-snapshot-$SHA256_ONLINE_CLOSURE_V1.XXXXXXXX")" \
        || die "cannot create the Windows build-scoped online-snapshot transaction"
    ONLINE_SNAPSHOT_TRANSACTION_ID="$(stat -c '%d:%i' -- "$ONLINE_SNAPSHOT_TRANSACTION")" \
        || die "cannot bind the Windows build-scoped online-snapshot transaction identity"
    [[ "$ONLINE_SNAPSHOT_TRANSACTION_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || die "Windows build-scoped online-snapshot transaction identity is malformed"
    ONLINE_SNAPSHOT_PARENT="$ONLINE_SNAPSHOT_TRANSACTION/snapshot"
    create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
    export ONLINE_DIR
    verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED=0
    [ "$canonical_online" != "$ONLINE_DIR" ] \
        || die "Windows build-scoped online snapshot did not separate canonical and private paths"
}

remove_online_snapshot_transaction() {
    [ -z "$ONLINE_SNAPSHOT_TRANSACTION" ] \
        && [ -z "$ONLINE_SNAPSHOT_TRANSACTION_ID" ] && return 0
    [ -n "$ONLINE_SNAPSHOT_TRANSACTION" ] \
        && [ -n "$ONLINE_SNAPSHOT_TRANSACTION_ID" ] || return 1
    [ "$ONLINE_SNAPSHOT_PARENT" = "$ONLINE_SNAPSHOT_TRANSACTION/snapshot" ] \
        || return 1
    remove_private_root_exact \
        "$ONLINE_SNAPSHOT_TRANSACTION" "$ONLINE_SNAPSHOT_TRANSACTION_ID" || return 1
    { [ ! -e "$ONLINE_SNAPSHOT_TRANSACTION" ] \
        && [ ! -L "$ONLINE_SNAPSHOT_TRANSACTION" ]; } || return 1
    ONLINE_SNAPSHOT_TRANSACTION=""
    ONLINE_SNAPSHOT_TRANSACTION_ID=""
    ONLINE_SNAPSHOT_PARENT=""
    ONLINE_DIR=""
}

parse_golden_virtual_size() {
    python3 -c '
import json
import sys

try:
    document = json.load(sys.stdin)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
value = document.get("virtual-size") if type(document) is dict else None
if type(value) is not int or value <= 0:
    raise SystemExit(1)
print(value)
'
}

golden_virtual_size() {
    qemu-img info --output=json "$GOLDEN" | parse_golden_virtual_size
}

available_storage_bytes() {
    python3 - "$STATE_DIR" <<'PY'
import os
import sys

stats = os.statvfs(sys.argv[1])
print(stats.f_bavail * stats.f_frsize)
PY
}

require_available_storage_bytes() {
    local required="$1" available
    [[ "$required" =~ ^[1-9][0-9]*$ ]] \
        || die "Windows harness required-byte count is malformed"
    available="$(available_storage_bytes)" \
        || die "cannot determine unprivileged Windows harness free space"
    [[ "$available" =~ ^[0-9]+$ ]] \
        || die "Windows harness available-byte count is malformed"
    [ "$available" -ge "$required" ] \
        || die "Windows harness storage preflight requires $required available bytes but found $available"
    log "Windows harness storage preflight OK: available=$available required=$required"
}

require_storage_capacity() {
    local virtual required snapshot_allowance=0
    virtual="$(golden_virtual_size)" \
        || die "cannot determine the Windows golden virtual size"
    [[ "$virtual" =~ ^[1-9][0-9]*$ ]] \
        || die "Windows golden virtual size is malformed"
    if [ "$ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED" = 1 ]; then
        snapshot_allowance="$BUILD_ONLINE_SNAPSHOT_ALLOWANCE_BYTES"
    fi
    required=$((virtual + RUN_STORAGE_FIXED_ALLOWANCE_BYTES \
        + RUN_STORAGE_EMERGENCY_RESERVE_BYTES + snapshot_allowance))
    require_available_storage_bytes "$required"
}

preflight() {
    local planned_state planned_output
    require_cmd qemu-img virt-install virsh xorriso git python3 realpath sha256sum sha512sum timeout setsid awk find
    assert_no_build_host_network_residual
    [ "$SOURCE_DATE_EPOCH" = "$SOURCE_DATE_EPOCH_PIN" ] \
        || die "SOURCE_DATE_EPOCH must equal the pinned canonical value $SOURCE_DATE_EPOCH_PIN"
    [[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH is malformed"
    case "$WINDOWS_BUILD_SOURCE" in
        head) assert_head_source ;;
        worktree) ;;
        *) die "WINDOWS_BUILD_SOURCE must be head or worktree" ;;
    esac
    [[ "$DOMAIN_PREFIX" =~ ^[A-Za-z0-9._-]+$ ]] || die "HARNESS_PREFIX contains an invalid domain-name character"
    [ "${#DOMAIN_PREFIX}" -le 32 ] || die "HARNESS_PREFIX is too long"

    planned_state="$(realpath -m -- "$STATE_DIR")" \
        || die "cannot canonicalize the planned Windows harness state path"
    planned_output="$(realpath -m -- "$OUT_DIR")" \
        || die "cannot canonicalize the planned Windows output path"
    assert_safe_path "$planned_state" "planned state directory"
    assert_safe_path "$planned_output" "planned output directory"
    assert_disjoint_paths "$planned_state" "Windows harness state" \
        "$planned_output" "Windows output"
    mkdir -p "$STATE_DIR"
    STATE_DIR="$(realpath -e "$STATE_DIR")"
    [ "$(stat -c '%u:%a' "$STATE_DIR")" = "$(id -u):700" ] \
        || die "Windows harness state directory must be current-UID mode 0700"
    acquire_build_lease
    require_no_retained_windows_runs
    GOLDEN="$(realpath -e "$GOLDEN")"
    record_golden_identity
    if ! activate_release_online_snapshot; then
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT+x}" ] \
            || die "release online snapshot must not be empty"
        ONLINE_DIR="$(realpath -e "$ONLINE_DIR")"
        require_online_complete
        ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED=1
    fi
    export ONLINE_DIR
    OUT_PARENT="$(dirname "$OUT_DIR")"
    mkdir -p "$OUT_PARENT"
    OUT_PARENT="$(realpath -e "$OUT_PARENT")"
    OUT_DIR="$OUT_PARENT/$(basename "$OUT_DIR")"
    record_output_parent_identity
    for pair in "$STATE_DIR|state directory" "$GOLDEN|golden image" "$ONLINE_DIR|online cache" "$OUT_DIR|output directory"; do
        assert_safe_path "${pair%%|*}" "${pair#*|}"
    done
    assert_disjoint_paths "$STATE_DIR" "Windows harness state" "$OUT_DIR" "Windows output"
    { [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; } \
        || die "Windows output directory must be absent for atomic publication: $OUT_DIR"
    require_storage_capacity
    if [ "$ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED" = 1 ]; then
        RUN_PHASE="build-online-snapshot"
        materialize_build_online_snapshot
    fi
    verify_golden_backing
    [ -d "$ONLINE_DIR/cargo-vendor" ] && [ ! -L "$ONLINE_DIR/cargo-vendor" ] || die "cargo-vendor cache is missing"
    [ -d "$ONLINE_DIR/pub-cache" ] && [ ! -L "$ONLINE_DIR/pub-cache" ] || die "pub-cache is missing"
    verify_wix_nuget_packages
    verify_sha256 "$ONLINE_DIR/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" "$SHA256_OLEFILE_0_47"
    verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" "$SHA512_LIBVPX_SOURCE"
    verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch" "$SHA512_LIBVPX_PATCH"
    verify_libvpx_windows_tools
    [ -f "$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt" ] \
        && [ ! -L "$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt" ] \
        || die "libvpx native key is missing"
    windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"
    require_pinned_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID"
    DEB_BUILDER_IMAGE="$DEB_BUILDER_IMAGE_ID"
}

golden_identity() {
    [ "$#" -eq 1 ] || die "golden_identity requires one path"
    python3 - "$1" "$WINDOWS_HELPER_BUILD_UID" "$WINDOWS_HELPER_BUILD_GID" <<'PY'
import hashlib
import os
import stat
import sys

source, uid_text, gid_text = sys.argv[1:]
uid = int(uid_text)
gid = int(gid_text)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
source_fd = os.open(source, flags)
try:
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != uid
        or before.st_gid != gid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o400
    ):
        raise SystemExit(
            "golden backing must be a current-principal mode-0400 single-link regular file"
        )
    digest = hashlib.sha256()
    while True:
        chunk = os.read(source_fd, 8 * 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(source_fd)
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise SystemExit("golden backing changed while its identity was sampled")
    values = [str(getattr(after, field)) for field in fields]
    values.append(digest.hexdigest())
    print(":".join(values))
finally:
    os.close(source_fd)
PY
}

record_golden_identity() {
    GOLDEN_IDENTITY="$(golden_identity "$GOLDEN")" \
        || die "cannot record the sealed Windows golden identity"
    [ "${GOLDEN_IDENTITY##*:}" = "$SHA256_WIN11_GOLDEN_QCOW2" ] \
        || die "sealed Windows golden does not match its pinned SHA-256"
}

bind_golden_backing() {
    [ -n "$RUN_ROOT" ] || die "private run root is not initialized"
    [ -n "$GOLDEN_IDENTITY" ] || die "sealed Windows golden identity is not recorded"
    GOLDEN_EDGE="$RUN_ROOT/golden.qcow2"
    ln -s -- "$GOLDEN" "$GOLDEN_EDGE"
    [ "$(readlink -- "$GOLDEN_EDGE")" = "$GOLDEN" ] \
        || die "private golden backing edge does not target the sealed golden"
    verify_golden_backing
}

verify_golden_backing() {
    local current
    [ -n "$GOLDEN_IDENTITY" ] || die "sealed Windows golden identity is not recorded"
    current="$(golden_identity "$GOLDEN")" \
        || die "cannot revalidate the sealed Windows golden"
    [ "$current" = "$GOLDEN_IDENTITY" ] \
        || die "sealed Windows golden identity or bytes changed during the transaction"
    if [ -n "$RUN_ROOT" ]; then
        [ -n "$GOLDEN_EDGE" ] && [ -L "$GOLDEN_EDGE" ] \
            && [ "$(readlink -- "$GOLDEN_EDGE")" = "$GOLDEN" ] \
            || die "private golden backing edge changed"
    fi
}

write_manifest() {
    local root="$1" output="$2" allow_internal="${3:-0}"
    [ "$allow_internal" = 0 ] || [ "$allow_internal" = 1 ] \
        || die "write_manifest internal-name policy is invalid"
    python3 - "$root" "$output" "$allow_internal" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

root = os.path.realpath(sys.argv[1])
output = os.path.realpath(sys.argv[2])
allow_internal = sys.argv[3] == "1"
internal_metadata = {
    ".source-manifest.json",
    ".source-identity.json",
    ".source-date-epoch",
    ".build-run-id",
}
internal_temporary = {
    ".source-manifest.json.tmp",
    ".source-identity.json.tmp",
}
generated = internal_metadata | internal_temporary | {"run-build.ps1"}
generated_folded = {name.casefold(): name for name in generated}
dos_device = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)
files = []
directories = set()
file_parents = set()
case_paths = {}

def validate_relative(relative, kind):
    try:
        encoded = relative.encode("ascii")
    except UnicodeEncodeError:
        raise SystemExit(f"source {kind} path is not ASCII: {relative!r}")
    components = relative.split("/")
    if (not relative or any(component in ("", ".", "..") for component in components)
            or any(byte < 0x20 or byte == 0x7f for byte in encoded)
            or any(c in relative for c in '\\,:<>"|?*')
            or any(component.endswith((" ", ".")) for component in components)
            or any(dos_device.fullmatch(component) for component in components)):
        raise SystemExit(f"source {kind} path is not Windows/manifest safe: {relative!r}")
    folded = relative.casefold()
    previous = case_paths.get(folded)
    if previous is not None and previous != relative:
        raise SystemExit(f"source paths collide on Windows: {previous!r} and {relative!r}")
    case_paths[folded] = relative

for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
    names.sort()
    filenames.sort()
    for name in list(names):
        path = os.path.join(directory, name)
        info = os.lstat(path)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        validate_relative(relative, "directory")
        if relative.casefold() in generated_folded:
            raise SystemExit(f"source directory occupies a generated Windows namespace: {relative}")
        if not stat.S_ISDIR(info.st_mode):
            raise SystemExit(f"source directory entry is not a real directory: {relative}")
        directories.add(relative)
    for name in filenames:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        validate_relative(relative, "file")
        reserved = generated_folded.get(relative.casefold())
        if reserved is not None:
            if not allow_internal or relative != reserved or relative in internal_temporary:
                raise SystemExit(f"source file occupies a generated Windows namespace: {relative}")
            if relative in internal_metadata:
                continue
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"source entry is not a regular file: {relative}")
        digest = hashlib.sha256()
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if any(getattr(opened, field) != getattr(info, field) for field in
                   ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")):
                raise SystemExit(f"source file changed before hashing: {relative}")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            if any(getattr(after, field) != getattr(opened, field) for field in
                   ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")):
                raise SystemExit(f"source file changed while hashing: {relative}")
        components = relative.split("/")[:-1]
        for index in range(1, len(components) + 1):
            file_parents.add("/".join(components[:index]))
        files.append({
            "path": relative,
            "sha256": digest.hexdigest(),
            "size": info.st_size,
        })
empty = sorted(directories - file_parents)
if empty:
    raise SystemExit(f"source tree contains an unmanifested empty directory: {empty[0]}")
manifest = {
    "files": files,
    "format": "rustdesk-windows-source-manifest-v1",
}
temporary = output + ".tmp"
if os.path.lexists(output) or os.path.lexists(temporary):
    raise SystemExit("source manifest output or temporary path already exists")
with open(temporary, "x", encoding="ascii", newline="\n") as handle:
    json.dump(manifest, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.link(temporary, output, follow_symlinks=False)
os.unlink(temporary)
PY
}

verify_manifest() {
    local root="$1" expected="$2" allow_internal="${3:-0}" check_root actual
    check_root="$(mktemp -d "$RUN_ROOT/manifest-check.XXXXXXXX")"
    actual="$check_root/manifest.json"
    write_manifest "$root" "$actual" "$allow_internal"
    cmp -s "$expected" "$actual" || die "source snapshot changed after its manifest was recorded"
    rm -rf -- "$check_root"
}

verify_frb_outputs() {
    local root="$1" expected
    [ -f "$root/.frb-manifest.sha256" ] && [ ! -L "$root/.frb-manifest.sha256" ] \
        || die "FRB manifest is not a regular file"
    expected="$(mktemp "$RUN_ROOT/frb-manifest-check.XXXXXXXX")"
    (
        cd "$root"
        local relative
        for relative in "${FRB_OUTPUTS[@]}"; do
            [ -f "$relative" ] && [ ! -L "$relative" ] && [ -s "$relative" ] \
                || die "FRB output is missing or invalid: $relative"
            sha256sum "$relative"
        done
    ) >"$expected"
    cmp -s "$root/.frb-manifest.sha256" "$expected" \
        || die "FRB manifest does not describe exactly the four canonical outputs"
    rm -f "$expected"
}

capture_worktree_tree() {
    local suffix="$1" index source_index tree
    index="$RUN_ROOT/index-$suffix"
    source_index="$(git -C "$REPO_ROOT" rev-parse --git-path index)"
    [ -f "$source_index" ] || die "Git index is missing"
    cp -- "$source_index" "$index"
    GIT_INDEX_FILE="$index" git -C "$REPO_ROOT" -c core.hooksPath=/dev/null add -A -- . \
        || die "could not capture the worktree into an isolated Git index"
    tree="$(GIT_INDEX_FILE="$index" git -C "$REPO_ROOT" write-tree)" \
        || die "could not write the isolated worktree tree"
    [[ "$tree" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || die "worktree tree ID is malformed"
    printf '%s\n' "$tree"
}

materialize_source_snapshot() {
    SOURCE_SNAPSHOT="$RUN_ROOT/source-snapshot"
    mkdir "$SOURCE_SNAPSHOT"
    case "$WINDOWS_BUILD_SOURCE" in
        head)
            SOURCE_MODE="head"
            SOURCE_COMMIT="$RELEASE_SRC_COMMIT"
            SOURCE_TREE="$(git -C "$REPO_ROOT" rev-parse "${SOURCE_COMMIT}^{tree}")" \
                || die "cannot resolve release source tree"
            git -C "$REPO_ROOT" archive --format=tar "$SOURCE_COMMIT" \
                | tar -x -C "$SOURCE_SNAPSHOT"
            ;;
        worktree)
            SOURCE_MODE="worktree"
            SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
                || die "cannot resolve worktree base commit"
            local first second
            first="$(capture_worktree_tree first)"
            second="$(capture_worktree_tree second)"
            [ "$first" = "$second" ] || die "worktree changed while the immutable source tree was captured"
            SOURCE_TREE="$first"
            git -C "$REPO_ROOT" archive --format=tar "$SOURCE_TREE" \
                | tar -x -C "$SOURCE_SNAPSHOT"
            ;;
    esac
    [[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || die "source commit ID is malformed"
    [[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || die "source tree ID is malformed"
    [ -f "$SOURCE_SNAPSHOT/scripts/run-build.ps1" ] \
        && [ -f "$SOURCE_SNAPSHOT/scripts/build-windows.ps1" ] \
        && [ ! -L "$SOURCE_SNAPSHOT/scripts/run-build.ps1" ] \
        || die "source snapshot lacks the Windows guest scripts"
    mapfile -t fork_lines <"$SOURCE_SNAPSHOT/FORK_VERSION"
    [ "${#fork_lines[@]}" = 1 ] || die "FORK_VERSION must contain exactly one line"
    FORK_VERSION_VALUE="${fork_lines[0]}"
    [[ "$FORK_VERSION_VALUE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-hardened\.[0-9]+$ ]] \
        || die "FORK_VERSION is malformed"
    write_manifest "$SOURCE_SNAPSHOT" "$RUN_ROOT/base-source-manifest.json"
    BASE_MANIFEST_SHA256="$(sha256sum "$RUN_ROOT/base-source-manifest.json" | awk '{print $1}')"
    chmod -R a-w "$SOURCE_SNAPSHOT"
}

libvpx_native_key_for_tree() {
    local root="$1"
    (
        printf 'VCPKG_BASELINE=%s\n' "$VCPKG_BASELINE"
        printf 'LIBVPX_SOURCE_REF=%s\n' "$LIBVPX_SOURCE_REF"
        printf 'SHA512_LIBVPX_SOURCE=%s\n' "$SHA512_LIBVPX_SOURCE"
        printf 'LIBVPX_FIX_COMMIT=%s\n' "$LIBVPX_FIX_COMMIT"
        printf 'SHA512_LIBVPX_PATCH=%s\n' "$SHA512_LIBVPX_PATCH"
        cd "$root"
        find res/vcpkg/libvpx -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            sha256sum "$file"
        done
    ) | sha256sum | awk '{print $1}'
}

write_offline_manifest() {
    local output="$1"
    python3 "$SOURCE_SNAPSHOT/scripts/windows-offline-manifest.py" \
        --online-root "$ONLINE_DIR" \
        --wix-root "$ONLINE_DIR/wix-nuget-packages" \
        --olefile-version "$OLEFILE_VERSION" \
        --libvpx-source-ref "$LIBVPX_SOURCE_REF" \
        --libvpx-fix-commit "$LIBVPX_FIX_COMMIT" \
        --output "$output"
}

build_offline_media() {
    local manifest="$RUN_ROOT/offline-input-manifest.json"
    local after="$RUN_ROOT/offline-input-manifest.after.json"
    write_offline_manifest "$manifest"
    OFFLINE_MANIFEST_SHA256="$(sha256sum "$manifest" | awk '{print $1}')"
    local offline_iso="$RUN_ROOT/offline.iso"
    local media_output="$RUN_ROOT/offline-output"
    [ ! -e "$offline_iso" ] && [ ! -L "$offline_iso" ] \
        || die "offline UDF media output path is occupied"
    mkdir -m 0700 "$media_output"
    windows_helper_media_run \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly" \
        --mount "type=bind,source=$manifest,target=/authority/offline-input-manifest.json,readonly" \
        --mount "type=bind,source=$media_output,target=/out" \
        -- /usr/bin/genisoimage -udf -D -r -f -quiet -V OFFLINE \
            -o /out/offline.iso -graft-points \
            /cargo-vendor=/online/cargo-vendor \
            /cargo-vendor-config.toml=/online/cargo-vendor-config.toml \
            /pub-cache=/online/pub-cache \
            "/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz=/online/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" \
            "/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch=/online/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch" \
            /vcpkg-distfiles/libvpx-native-key.txt=/online/vcpkg-distfiles/libvpx-native-key.txt \
            /vcpkg-distfiles/windows-tools=/online/vcpkg-distfiles/windows-tools \
            "/python-wheels/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl=/online/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" \
            /wix-nuget-packages=/online/wix-nuget-packages \
            /.offline-input-manifest.json=/authority/offline-input-manifest.json
    [ -s "$media_output/offline.iso" ] \
        || die "confined Windows helper did not produce offline UDF media"
    mv -- "$media_output/offline.iso" "$offline_iso"
    rmdir -- "$media_output"
    [ -s "$offline_iso" ] || die "offline UDF media was not produced"
    write_offline_manifest "$after"
    cmp -s "$manifest" "$after" || die "offline inputs changed while the immutable UDF media was created"
    rm -f "$after"
}

create_source_identity() {
    local media_root="$1" run_id="$2" final_manifest_sha="$3" frb_manifest_sha="$4"
    python3 - "$media_root/.source-identity.json" \
        "$SOURCE_MODE" "$SOURCE_COMMIT" "$SOURCE_TREE" "$SOURCE_DATE_EPOCH" \
        "$FORK_VERSION_VALUE" "$TARGET_ID" "$BASE_MANIFEST_SHA256" \
        "$final_manifest_sha" "$frb_manifest_sha" "$OFFLINE_MANIFEST_SHA256" "$run_id" <<'PY'
import json
import os
import sys

(output, mode, commit, tree, epoch, fork_version, target, base_manifest,
 source_manifest, frb_manifest, offline_manifest, run_id) = sys.argv[1:]
identity = {
    "base_manifest_sha256": base_manifest,
    "build_run_id": run_id,
    "fork_version": fork_version,
    "format": "rustdesk-windows-source-identity-v1",
    "frb_manifest_sha256": frb_manifest,
    "offline_manifest_sha256": offline_manifest,
    "source_commit": commit,
    "source_date_epoch": epoch,
    "source_manifest_sha256": source_manifest,
    "source_mode": mode,
    "source_tree": tree,
    "target": target,
}
temporary = output + ".tmp"
with open(temporary, "w", encoding="ascii", newline="\n") as handle:
    json.dump(identity, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.link(temporary, output, follow_symlinks=False)
os.unlink(temporary)
PY
}

build_pass_media() {
    local pass="$1"
    local frb_root="$CURRENT_PASS_ROOT/frb"
    local media_root="$CURRENT_PASS_ROOT/source-media"
    local frb_manifest_sha final_manifest_sha staged_key source_key
    local identity_sha epoch_sha run_id_sha manifest_sha
    verify_manifest "$SOURCE_SNAPSHOT" "$RUN_ROOT/base-source-manifest.json"
    FRB_IMAGE_ID="$DEB_BUILDER_IMAGE" bash "$SOURCE_SNAPSHOT/scripts/frb-codegen.sh" \
        --source-root "$SOURCE_SNAPSHOT" --online-root "$ONLINE_DIR" --output-root "$frb_root"
    verify_manifest "$SOURCE_SNAPSHOT" "$RUN_ROOT/base-source-manifest.json"
    verify_frb_outputs "$frb_root"
    frb_manifest_sha="$(sha256sum "$frb_root/.frb-manifest.sha256" | awk '{print $1}')"
    if [ -z "$FRB_REFERENCE" ]; then
        FRB_REFERENCE="$frb_manifest_sha"
    else
        [ "$FRB_REFERENCE" = "$frb_manifest_sha" ] \
            || die "FRB reproducibility mismatch between Windows passes"
    fi

    mkdir "$media_root"
    cp -a --reflink=auto "$SOURCE_SNAPSHOT/." "$media_root/"
    chmod -R u+rwX "$media_root"
    local relative
    for relative in "${FRB_OUTPUTS[@]}"; do
        mkdir -p "$media_root/$(dirname "$relative")"
        install -m 0644 "$frb_root/$relative" "$media_root/$relative"
    done
    local generated
    for generated in run-build.ps1 .source-date-epoch .build-run-id \
        .source-manifest.json .source-manifest.json.tmp \
        .source-identity.json .source-identity.json.tmp; do
        [ ! -e "$media_root/$generated" ] && [ ! -L "$media_root/$generated" ] \
            || die "generated source-media path is already occupied: $generated"
    done
    cp --no-clobber -- "$media_root/scripts/run-build.ps1" "$media_root/run-build.ps1"
    chmod 0644 "$media_root/run-build.ps1"
    cmp -s "$media_root/scripts/run-build.ps1" "$media_root/run-build.ps1" \
        || die "generated root run-build.ps1 does not match its source"
    (set -o noclobber; printf '%s\n' "$SOURCE_DATE_EPOCH" >"$media_root/.source-date-epoch")
    (set -o noclobber; printf '%s\n' "$RUN_ID-$pass" >"$media_root/.build-run-id")
    write_manifest "$media_root" "$media_root/.source-manifest.json" 1
    final_manifest_sha="$(sha256sum "$media_root/.source-manifest.json" | awk '{print $1}')"
    create_source_identity "$media_root" "$RUN_ID-$pass" "$final_manifest_sha" "$frb_manifest_sha"
    verify_manifest "$media_root" "$media_root/.source-manifest.json" 1

    source_key="$(libvpx_native_key_for_tree "$media_root")"
    staged_key="$(<"$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt")"
    [ "$source_key" = "$staged_key" ] \
        || die "libvpx offline key does not match the immutable source snapshot"
    identity_sha="$(sha256sum "$media_root/.source-identity.json" | awk '{print $1}')"
    epoch_sha="$(sha256sum "$media_root/.source-date-epoch" | awk '{print $1}')"
    run_id_sha="$(sha256sum "$media_root/.build-run-id" | awk '{print $1}')"
    manifest_sha="$(sha256sum "$media_root/.source-manifest.json" | awk '{print $1}')"
    chmod -R a-w "$media_root"
    (
        cd "$media_root"
        xorriso -as mkisofs -quiet -o "$CURRENT_PASS_ROOT/source.iso" -V BUILD -J -R .
    )
    [ -s "$CURRENT_PASS_ROOT/source.iso" ] || die "source ISO was not produced"
    verify_manifest "$media_root" "$media_root/.source-manifest.json" 1
    [ "$(sha256sum "$media_root/.source-identity.json" | awk '{print $1}')" = "$identity_sha" ] \
        || die "source identity changed while source media was created"
    [ "$(sha256sum "$media_root/.source-date-epoch" | awk '{print $1}')" = "$epoch_sha" ] \
        || die "source epoch stamp changed while source media was created"
    [ "$(sha256sum "$media_root/.build-run-id" | awk '{print $1}')" = "$run_id_sha" ] \
        || die "source run-ID stamp changed while source media was created"
    [ "$(sha256sum "$media_root/.source-manifest.json" | awk '{print $1}')" = "$manifest_sha" ] \
        || die "source manifest changed while source media was created"
}

create_output_disk() {
    qemu-img create -f raw "$CURRENT_PASS_ROOT/output.img" 3G >/dev/null
    windows_helper_guestfish_run \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img" \
        -- /usr/bin/guestfish -a /authority/output.img run : \
            part-disk /dev/sda mbr : \
            part-set-mbr-id /dev/sda 1 0x0c : \
            mkfs vfat /dev/sda1 label:OUTPUT
}

prepare_overlay() {
    verify_golden_backing
    (
        cd "$CURRENT_PASS_ROOT"
        qemu-img create -f qcow2 -F qcow2 -b ../golden.qcow2 overlay.qcow2 >/dev/null
    )
    windows_helper_guestfish_run \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/overlay.qcow2,target=/authority/pass/overlay.qcow2" \
        --mount "type=bind,source=$GOLDEN,target=/authority/golden.qcow2,readonly" \
        -- /usr/bin/guestfish --rw -a /authority/pass/overlay.qcow2 run : \
            mount /dev/sda1 / : \
            mkdir-p /EFI/BOOT : \
            cp /EFI/Microsoft/Boot/bootmgfw.efi /EFI/BOOT/BOOTX64.EFI
}

verify_domain_xml() {
    local xml="$CURRENT_PASS_ROOT/domain.xml"
    virsh_bounded dumpxml "$CURRENT_DOMAIN_UUID" >"$xml" \
        || die "cannot read the created domain XML"
    python3 - "$xml" "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID" \
        "$CURRENT_PASS_ROOT/overlay.qcow2" "$CURRENT_PASS_ROOT/source.iso" \
        "$RUN_ROOT/offline.iso" "$CURRENT_PASS_ROOT/output.img" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

xml, expected_name, expected_uuid, *expected_disks = sys.argv[1:]
root = ET.parse(xml).getroot()
if root.findtext("name") != expected_name or root.findtext("uuid") != expected_uuid:
    raise SystemExit("domain name/UUID identity mismatch")
if root.findall("./devices/interface"):
    raise SystemExit("Windows build domain unexpectedly has a network interface")
graphics = root.findall("./devices/graphics")
if len(graphics) != 1:
    raise SystemExit("Windows build domain does not have exactly one graphics device")
graphic = graphics[0]
if graphic.get("type") != "vnc" or graphic.get("listen") != "127.0.0.1":
    raise SystemExit("Windows build domain VNC graphics is not bound to 127.0.0.1")
listeners = graphic.findall("./listen")
if (len(listeners) != 1 or listeners[0].get("type") != "address"
        or listeners[0].get("address") != "127.0.0.1"):
    raise SystemExit("Windows build domain VNC listen child is not exactly loopback-addressed")
actual = []
for disk in root.findall("./devices/disk"):
    source = disk.find("source")
    if source is not None and "file" in source.attrib:
        actual.append(os.path.realpath(source.attrib["file"]))
if sorted(actual) != sorted(os.path.realpath(path) for path in expected_disks):
    raise SystemExit(f"domain disk set mismatch: {actual!r}")
PY
}

launch_domain() {
    CURRENT_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"
    assert_uuid "$CURRENT_DOMAIN_UUID"
    CURRENT_DOMAIN="$DOMAIN_PREFIX-win-${RUN_ID:0:8}-${CURRENT_PASS_ROOT##*-}"
    [[ "$CURRENT_DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "generated domain name contains an invalid character"
    [ "${#CURRENT_DOMAIN}" -le 63 ] || die "generated domain name is too long"
    CURRENT_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))
    require_domain_identity_absent

    CURRENT_DOMAIN_CREATION_STARTED=1
    setsid --wait virt-install --connect qemu:///session --name "$CURRENT_DOMAIN" --uuid "$CURRENT_DOMAIN_UUID" \
        --osinfo win11 --memory 16384 --vcpus 8 --import \
        --disk "path=$CURRENT_PASS_ROOT/overlay.qcow2,format=qcow2,bus=sata" \
        --disk "path=$CURRENT_PASS_ROOT/source.iso,device=cdrom" \
        --disk "path=$RUN_ROOT/offline.iso,device=cdrom" \
        --disk "path=$CURRENT_PASS_ROOT/output.img,format=raw,bus=sata" \
        --boot uefi --network none --graphics vnc,listen=127.0.0.1 \
        --noautoconsole &
    CURRENT_VIRT_PID=$!
    CURRENT_VIRT_START="$(process_start_time "$CURRENT_VIRT_PID")" \
        || die "could not bind the virt-install process identity"
    wait_for_owned_process_group \
        || die "could not prove virt-install process-group admission"

    local deadline rc
    deadline=$(( $(monotonic_seconds) + CREATE_TIMEOUT_SECONDS ))
    while owned_process_group_is_live \
        && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        sleep 1
    done
    if owned_process_group_is_live; then
        stop_owned_process || die "virt-install did not stop after its creation deadline"
        die "virt-install exceeded its creation deadline"
    fi
    if ! owned_process_matches && [ -e "/proc/$CURRENT_VIRT_PID" ]; then
        die "virt-install process identity changed before it could be reaped"
    fi
    if wait "$CURRENT_VIRT_PID"; then rc=0; else rc=$?; fi
    CURRENT_VIRT_PID=""
    CURRENT_VIRT_START=""
    [ "$rc" = 0 ] || die "virt-install failed with exit $rc"
    domain_uuid_is_listed \
        || die "virt-install completed without the exact requested domain UUID"
    prove_owned_domain || die "virt-install did not create the exact UUID-bound domain"
    verify_domain_xml
    CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1
    [ "$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" = "running" ] \
        || die "created Windows domain is not running"
}

wait_for_domain() {
    local state
    [ -n "$CURRENT_VM_DEADLINE" ] || die "Windows VM deadline was not initialized"
    while :; do
        prove_owned_domain || die "owned Windows domain disappeared before authoritative shutdown"
        state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" \
            || die "cannot read owned Windows domain state"
        case "$state" in
            "shut off") break ;;
            crashed) die "Windows build domain crashed" ;;
            running|blocked|paused|"in shutdown"|pmsuspended) ;;
            *) die "Windows build domain entered an unknown state: $state" ;;
        esac
        if [ "$(monotonic_seconds)" -ge "$CURRENT_VM_DEADLINE" ]; then
            stop_and_undefine_owned_domain || die "timed-out domain could not be destroyed and undefined safely"
            die "Windows build exceeded the monotonic two-hour deadline"
        fi
        sleep 10
    done
    stop_and_undefine_owned_domain || die "completed domain could not be undefined safely"
}

validate_guest_progress() {
    local progress="$1" expected_source_marker="$2" expected_offline_marker="$3"
    [ -f "$progress" ] && [ ! -L "$progress" ] || die "guest completion marker is absent"
    python3 - "$progress" "$expected_source_marker" "$expected_offline_marker" <<'PY' \
        || die "guest progress validation failed"
import pathlib
import re
import sys

progress_path, expected_source, expected_offline = sys.argv[1:]
data = pathlib.Path(progress_path).read_bytes()
if not data or len(data) > 65536:
    raise SystemExit("guest completion marker is empty or oversized")
if not data.endswith(b"\r\n"):
    raise SystemExit("guest progress does not end with canonical CRLF")
raw_lines = data.split(b"\r\n")
if raw_lines[-1] != b"":
    raise SystemExit("guest progress CRLF split is not terminal")
lines = []
for raw in raw_lines[:-1]:
    if not raw or b"\r" in raw or b"\n" in raw:
        raise SystemExit("guest progress contains an empty line or a bare newline byte")
    try:
        lines.append(raw.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise SystemExit("guest progress is not strict ASCII") from exc

timestamp = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}[+-]\d{2}:\d{2}")
payloads = []
for line in lines:
    stamp, separator, payload = line.partition(" ")
    if not separator or not timestamp.fullmatch(stamp) or not payload:
        raise SystemExit("guest progress line is not canonical timestamp plus payload")
    payloads.append(payload)

exit_markers = [payload for payload in payloads if payload.startswith("build-windows.ps1 exit=")]
if len(exit_markers) != 1:
    raise SystemExit("guest completion marker count is not exactly one")
if exit_markers[0] != "build-windows.ps1 exit=0":
    raise SystemExit(f"guest build failed: {exit_markers[0].removeprefix('build-windows.ps1 ')}")
source_markers = [payload for payload in payloads if payload.startswith("source-verified ")]
if len(source_markers) != 1:
    raise SystemExit("guest source-verification marker count is not exactly one")
if source_markers[0] != expected_source:
    raise SystemExit("guest source-verification marker is incorrect")
offline_markers = [payload for payload in payloads if payload.startswith("offline-verified ")]
if len(offline_markers) != 1:
    raise SystemExit("guest OFFLINE-verification marker count is not exactly one")
if offline_markers[0] != expected_offline:
    raise SystemExit("guest OFFLINE-verification marker is incorrect")
installed_markers = [payload for payload in payloads if payload.startswith("windows-installed-service-probe.ps1 exit=")]
if len(installed_markers) != 1:
    raise SystemExit("guest installed-service marker count is not exactly one")
if installed_markers[0] != "windows-installed-service-probe.ps1 exit=0":
    raise SystemExit(f"guest installed-service probe failed: {installed_markers[0]}")
full_peer_markers = [payload for payload in payloads if payload.startswith("windows-full-peer-presentation-controller.ps1 exit=")]
if len(full_peer_markers) != 1:
    raise SystemExit("guest full-peer presentation marker count is not exactly one")
if full_peer_markers[0] != "windows-full-peer-presentation-controller.ps1 exit=0":
    raise SystemExit(f"guest full-peer presentation probe failed: {full_peer_markers[0]}")
ordered_markers = [expected_source, expected_offline, exit_markers[0], full_peer_markers[0], installed_markers[0]]
positions = [payloads.index(marker) for marker in ordered_markers]
if positions != sorted(positions) or len(set(positions)) != len(positions):
    raise SystemExit("guest source/offline/build/full-peer/installed markers are not in canonical order")
PY
}

extract_and_validate() {
    local result="$CURRENT_PASS_ROOT/result"
    local extracted
    extracted="$(mktemp -d "$CURRENT_PASS_ROOT/extract.XXXXXXXX")"
    windows_helper_guestfish_run \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img,readonly" \
        --mount "type=bind,source=$extracted,target=/out" \
        -- /usr/bin/guestfish --ro -a /authority/output.img run : \
            mount /dev/sda1 / : \
            glob copy-out '/*' /out

    for system_dir in "System Volume Information" '$RECYCLE.BIN'; do
        if [ -e "$extracted/$system_dir" ] || [ -L "$extracted/$system_dir" ]; then
            [ -d "$extracted/$system_dir" ] && [ ! -L "$extracted/$system_dir" ] \
                || die "unexpected non-directory output-disk system entry: $system_dir"
            rm -rf -- "$extracted/$system_dir"
        fi
    done
    local progress="$extracted/run-build-progress.txt"
    local expected_source_marker expected_offline_marker
    expected_source_marker="source-verified commit=$SOURCE_COMMIT tree=$SOURCE_TREE manifest=$(sha256sum "$CURRENT_PASS_ROOT/source-media/.source-manifest.json" | awk '{print $1}')"
    expected_offline_marker="offline-verified manifest=$OFFLINE_MANIFEST_SHA256"
    validate_guest_progress "$progress" "$expected_source_marker" "$expected_offline_marker"

    for artifact in rustdesk-setup.exe rustdesk.msi; do
        [ -f "$extracted/$artifact" ] && [ ! -L "$extracted/$artifact" ] && [ -s "$extracted/$artifact" ] \
            || die "guest artifact is missing or invalid: $artifact"
    done
    [ -f "$extracted/windows-installed-service-result.json" ] \
        && [ ! -L "$extracted/windows-installed-service-result.json" ] \
        && [ -s "$extracted/windows-installed-service-result.json" ] \
        || die "guest installed-service result is missing or invalid"
    for full_peer_evidence in windows-full-peer-probe-build-receipt.json \
        windows-full-peer-presentation-result.json; do
        [ -f "$extracted/$full_peer_evidence" ] \
            && [ ! -L "$extracted/$full_peer_evidence" ] \
            && [ -s "$extracted/$full_peer_evidence" ] \
            || die "guest full-peer presentation evidence is missing or invalid: $full_peer_evidence"
    done
    local setup_input="$extracted/.canonicalize-input-rustdesk-setup.exe"
    [ ! -e "$setup_input" ] && [ ! -L "$setup_input" ] \
        || die "private PE canonicalizer input path is occupied"
    ln -- "$extracted/rustdesk-setup.exe" "$setup_input"
    rm -f -- "$extracted/rustdesk-setup.exe"
    python3 "$SOURCE_SNAPSHOT/scripts/canonicalize-pe.py" \
        --output "$extracted/rustdesk-setup.exe" "$setup_input"
    rm -f -- "$setup_input"
    local msi_input="$extracted/.canonicalize-input-rustdesk.msi"
    local msi_stage="$CURRENT_PASS_ROOT/msi-canonicalize"
    [ ! -e "$msi_stage" ] && [ ! -L "$msi_stage" ] \
        || die "private MSI canonicalizer output path is occupied"
    mkdir -m 0700 "$msi_stage"
    local msi_contract="$msi_stage/contract.json"
    local msi_output="$msi_stage/rustdesk.msi"
    for path in "$msi_input" "$msi_contract" "$msi_output"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] \
            || die "private MSI canonicalizer path is occupied: $path"
    done
    local msi_input_sha256
    msi_input_sha256="$(sha256sum "$extracted/rustdesk.msi" | awk '{print $1}')"
    mv -- "$extracted/rustdesk.msi" "$msi_input"
    windows_helper_small_run \
        --mount "type=bind,source=$msi_input,target=/authority/input.msi,readonly" \
        --mount "type=bind,source=$SOURCE_SNAPSHOT/scripts/canonicalize-msi.py,target=/authority/canonicalize-msi.py,readonly" \
        --mount "type=bind,source=$msi_stage,target=/out" \
        -- /usr/bin/python3 /authority/canonicalize-msi.py /authority/input.msi \
            --output /out/rustdesk.msi \
            --contract-out /out/contract.json \
            --fork-version "$FORK_VERSION_VALUE" \
            --source-commit "$SOURCE_COMMIT" \
            --source-tree "$SOURCE_TREE" \
            --target "$TARGET_ID"
    [ -f "$msi_input" ] && [ ! -L "$msi_input" ] \
        && [ "$(stat -c %h "$msi_input")" = 1 ] \
        || die "private MSI canonicalizer input is no longer one ordinary file"
    [ -f "$msi_contract" ] && [ ! -L "$msi_contract" ] \
        && [ "$(stat -c %h "$msi_contract")" = 1 ] && [ -s "$msi_contract" ] \
        || die "host MSI cabinet contract is missing or invalid"
    local msi_output_sha256
    [ -f "$msi_output" ] && [ ! -L "$msi_output" ] \
        && [ "$(stat -c %h "$msi_output")" = 1 ] && [ -s "$msi_output" ] \
        || die "host MSI canonical output is missing or invalid"
    msi_output_sha256="$(sha256sum "$msi_output" | awk '{print $1}')"
    [ "$msi_input_sha256" = "$(sha256sum "$msi_input" | awk '{print $1}')" ] \
        || die "guest MSI changed during host canonical validation"
    [ "$msi_output_sha256" = "$msi_input_sha256" ] \
        || die "guest MSI was not already in exact canonical form"
    mv -- "$msi_output" "$extracted/rustdesk.msi"
    rm -f -- "$msi_input" "$msi_contract"
    rmdir -- "$msi_stage"
    windows_helper_small_run \
        --mount "type=bind,source=$SOURCE_SNAPSHOT/scripts/verify-windows-installed-service-result.py,target=/authority/verify.py,readonly" \
        --mount "type=bind,source=$extracted,target=/evidence,readonly" \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/source-media/.source-identity.json,target=/authority/source-identity.json,readonly" \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/domain.xml,target=/authority/domain.xml,readonly" \
        -- /usr/bin/python3 /authority/verify.py \
            --result /evidence/windows-installed-service-result.json \
            --identity /authority/source-identity.json \
            --setup /evidence/rustdesk-setup.exe \
            --msi /evidence/rustdesk.msi \
            --domain-xml /authority/domain.xml
    windows_helper_small_run \
        --mount "type=bind,source=$SOURCE_SNAPSHOT/scripts/verify-windows-full-peer-presentation-result.py,target=/authority/verify.py,readonly" \
        --mount "type=bind,source=$extracted,target=/evidence,readonly" \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/source-media/.source-identity.json,target=/authority/source-identity.json,readonly" \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/domain.xml,target=/authority/domain.xml,readonly" \
        -- /usr/bin/python3 -I -S /authority/verify.py \
            --result /evidence/windows-full-peer-presentation-result.json \
            --build-receipt /evidence/windows-full-peer-probe-build-receipt.json \
            --identity /authority/source-identity.json \
            --setup /evidence/rustdesk-setup.exe \
            --msi /evidence/rustdesk.msi \
            --domain-xml /authority/domain.xml
    mkdir "$result"
    install -m 0644 "$extracted/rustdesk-setup.exe" "$result/rustdesk-setup.exe"
    install -m 0644 "$extracted/rustdesk.msi" "$result/rustdesk.msi"
    (
        cd "$result"
        sha256sum rustdesk-setup.exe >rustdesk-setup.exe.sha256
        sha256sum rustdesk.msi >rustdesk.msi.sha256
        chmod 0644 -- rustdesk-setup.exe.sha256 rustdesk.msi.sha256
    )
    install -m 0644 "$CURRENT_PASS_ROOT/domain.xml" "$result/domain.xml"
    for diagnostic in build-log.txt build-windows.stdout.txt build-windows.stderr.txt \
        run-build-progress.txt \
        windows-installed-service-probe.stdout.txt windows-installed-service-probe.stderr.txt \
        windows-installed-service-result.json \
        windows-full-peer-presentation.stdout.txt windows-full-peer-presentation.stderr.txt \
        windows-full-peer-server.stdout.txt windows-full-peer-server.stderr.txt \
        windows-full-peer-viewer.stdout.txt windows-full-peer-viewer.stderr.txt \
        windows-full-peer-probe-build-receipt.json \
        windows-full-peer-presentation-result.json; do
        if [ -f "$extracted/$diagnostic" ] && [ ! -L "$extracted/$diagnostic" ]; then
            install -m 0644 "$extracted/$diagnostic" "$result/$diagnostic"
        fi
    done
    rm -rf -- "$extracted"
}

run_pass() {
    local pass="$1"
    CURRENT_PASS_ROOT="$RUN_ROOT/pass-$pass"
    mkdir "$CURRENT_PASS_ROOT"
    build_pass_media "$pass"
    create_output_disk
    prepare_overlay
    launch_domain
    wait_for_domain
    extract_and_validate
    rm -f -- "$CURRENT_PASS_ROOT/overlay.qcow2" "$CURRENT_PASS_ROOT/source.iso" "$CURRENT_PASS_ROOT/output.img"
    chmod -R u+rwX "$CURRENT_PASS_ROOT/source-media"
    rm -rf -- "$CURRENT_PASS_ROOT/source-media" "$CURRENT_PASS_ROOT/frb"
}

publish_result() {
    local result="$1"
    local destination="${OUT_DIR##*/}"
    local authority pending pending_identity extra
    [ "$result" = "$RUN_ROOT/pass-A/result" ] \
        || die "Windows publication source is not the pass-A result"
    [ -n "$RUN_ROOT_ID" ] && [ -n "$OUT_PARENT_ID" ] \
        || die "Windows publication authority is incomplete"
    [ "$OUT_DIR" = "$OUT_PARENT/$destination" ] \
        || die "Windows output destination is not one retained parent edge"
    authority="$(/usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py" \
            --prepare \
            --run-root "$RUN_ROOT" \
            --run-root-identity "$RUN_ROOT_ID" \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --destination "$destination")" \
        || die "Windows output candidate preparation failed"
    read -r pending pending_identity extra <<<"$authority"
    [[ "$pending" =~ ^\.windows-output-pending-[0-9a-f]{64}$ ]] \
        && [[ "$pending_identity" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        && [ -z "$extra" ] \
        || die "Windows output candidate authority is malformed"
    remove_completed_run_root \
        || die "Windows private run state could not retire before final publication"
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py" \
            --commit \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --pending "$pending" \
            --pending-identity "$pending_identity" \
            --destination "$destination"
}

run_root_cleanup_self_test() {
    local fixture="$RUN_ROOT/run-root-cleanup-authority"
    local edge="$fixture/created"
    local retained="$fixture/created.retained"
    local original_id replacement_id
    mkdir -m 0700 "$fixture" "$edge"
    printf 'created\n' >"$edge/created.txt"
    original_id="$(/usr/bin/stat -c '%d:%i' -- "$edge")"
    mv -- "$edge" "$retained"
    mkdir -m 0700 "$edge"
    printf 'replacement\n' >"$edge/replacement.txt"
    if remove_private_root_exact "$edge" "$original_id" >/dev/null 2>&1; then
        die "run-root substitution self-test deleted a replacement edge"
    fi
    [ -f "$retained/created.txt" ] && [ -f "$edge/replacement.txt" ] \
        || die "run-root substitution self-test did not preserve both identities"
    replacement_id="$(/usr/bin/stat -c '%d:%i' -- "$edge")"
    remove_private_root_exact "$edge" "$replacement_id" \
        || die "run-root substitution self-test could not retire the replacement independently"
    remove_private_root_exact "$retained" "$original_id" \
        || die "run-root substitution self-test could not retire the created tree independently"
    rmdir -- "$fixture"
}

online_snapshot_cleanup_self_test() {
    local saved_parent="$ONLINE_SNAPSHOT_PARENT"
    local saved_online_dir="$ONLINE_DIR"
    local saved_required="$ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED"
    local transaction retained replacement_id external external_id

    transaction="$STATE_DIR/.windows-online-snapshot-cleanup.XXXXXXXX"
    transaction="$(mktemp -d "$transaction")"
    ONLINE_SNAPSHOT_TRANSACTION="$transaction"
    ONLINE_SNAPSHOT_TRANSACTION_ID="$(stat -c '%d:%i' -- "$transaction")"
    ONLINE_SNAPSHOT_PARENT="$transaction/snapshot"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
    mkdir -m 0700 -- "$ONLINE_SNAPSHOT_PARENT"
    mkdir -m 0500 -- "$ONLINE_DIR"
    printf 'sealed fixture\n' >"$ONLINE_SNAPSHOT_PARENT/input.txt"
    chmod 0400 -- "$ONLINE_SNAPSHOT_PARENT/input.txt"
    remove_online_snapshot_transaction \
        || die "build-scoped online-snapshot cleanup self-test could not retire its exact transaction"
    [ ! -e "$transaction" ] && [ ! -L "$transaction" ] \
        || die "build-scoped online-snapshot cleanup self-test retained its transaction"

    transaction="$(mktemp -d "$STATE_DIR/.windows-online-snapshot-partial.XXXXXXXX")"
    ONLINE_SNAPSHOT_TRANSACTION="$transaction"
    ONLINE_SNAPSHOT_TRANSACTION_ID="$(stat -c '%d:%i' -- "$transaction")"
    ONLINE_SNAPSHOT_PARENT="$transaction/snapshot"
    ONLINE_DIR="$saved_online_dir"
    mkdir -m 0700 -- "$ONLINE_SNAPSHOT_PARENT"
    remove_online_snapshot_transaction \
        || die "partially materialized online-snapshot cleanup self-test could not retire its exact transaction"
    [ ! -e "$transaction" ] && [ ! -L "$transaction" ] \
        || die "partially materialized online-snapshot cleanup self-test retained its transaction"

    transaction="$(mktemp -d "$STATE_DIR/.windows-online-snapshot-substitution.XXXXXXXX")"
    ONLINE_SNAPSHOT_TRANSACTION="$transaction"
    ONLINE_SNAPSHOT_TRANSACTION_ID="$(stat -c '%d:%i' -- "$transaction")"
    ONLINE_SNAPSHOT_PARENT="$transaction/snapshot"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
    mkdir -m 0700 -- "$ONLINE_SNAPSHOT_PARENT" "$ONLINE_DIR"
    retained="$transaction.retained"
    mv -- "$transaction" "$retained"
    mkdir -m 0700 -- "$transaction" "$transaction/snapshot" "$transaction/snapshot/online"
    if remove_online_snapshot_transaction >/dev/null 2>&1; then
        die "build-scoped online-snapshot cleanup self-test deleted a substituted transaction"
    fi
    [ -d "$retained/snapshot/online" ] && [ -d "$transaction/snapshot/online" ] \
        || die "build-scoped online-snapshot cleanup self-test did not preserve both transaction identities"
    replacement_id="$(stat -c '%d:%i' -- "$transaction")"
    remove_private_root_exact "$transaction" "$replacement_id" \
        || die "build-scoped online-snapshot cleanup self-test could not retire the replacement"
    remove_private_root_exact "$retained" "$ONLINE_SNAPSHOT_TRANSACTION_ID" \
        || die "build-scoped online-snapshot cleanup self-test could not retire the original"
    ONLINE_SNAPSHOT_TRANSACTION=""
    ONLINE_SNAPSHOT_TRANSACTION_ID=""

    external="$STATE_DIR/release-online-snapshot-fixture"
    mkdir -m 0700 -- "$external" "$external/online"
    external_id="$(stat -c '%d:%i' -- "$external")"
    ONLINE_SNAPSHOT_PARENT="$external"
    ONLINE_DIR="$external/online"
    remove_online_snapshot_transaction \
        || die "release online-snapshot preservation self-test returned an error"
    [ -d "$external/online" ] \
        || die "release online-snapshot preservation self-test deleted borrowed input"
    remove_private_root_exact "$external" "$external_id" \
        || die "release online-snapshot preservation self-test could not retire its fixture"

    ONLINE_SNAPSHOT_PARENT="$saved_parent"
    ONLINE_DIR="$saved_online_dir"
    ONLINE_SNAPSHOT_MATERIALIZATION_REQUIRED="$saved_required"
}

harness_self_test() {
    require_cmd python3 qemu-img sha256sum setsid timeout
    RUN_ROOT="$(mktemp -d /tmp/rustdesk-windows-harness-test.XXXXXXXX)"
    chmod 0700 "$RUN_ROOT"
    record_run_root_identity

    STATE_DIR="$RUN_ROOT/failure-state"
    mkdir -m 0700 "$STATE_DIR"
    require_no_retained_windows_runs
    mkdir -m 0700 "$STATE_DIR/windows-build-retained.fixture"
    if (require_no_retained_windows_runs) >/dev/null 2>&1; then
        die "Windows retained-run self-test accepted prior bulk state"
    fi
    rmdir -- "$STATE_DIR/windows-build-retained.fixture"
    mkdir -m 0700 "$STATE_DIR/windows-online-snapshot-retained.fixture"
    if (require_no_retained_windows_runs) >/dev/null 2>&1; then
        die "Windows retained-run self-test accepted a legacy persistent online snapshot"
    fi
    rmdir -- "$STATE_DIR/windows-online-snapshot-retained.fixture"
    acquire_build_lease
    if (BUILD_LEASE="" BUILD_LEASE_ID="" acquire_build_lease) >/dev/null 2>&1; then
        die "Windows build-lease self-test accepted a concurrent invocation"
    fi
    release_build_lease || die "Windows build-lease self-test could not retire its exact lease"
    online_snapshot_cleanup_self_test
    require_available_storage_bytes 1
    local self_test_available
    self_test_available="$(available_storage_bytes)"
    if (require_available_storage_bytes "$((self_test_available + 1))") >/dev/null 2>&1; then
        die "Windows storage-capacity self-test accepted an unavailable byte budget"
    fi

    assert_disjoint_paths "$RUN_ROOT/state" "state" "$RUN_ROOT/output" "output"
    if (assert_disjoint_paths "$RUN_ROOT/state" "state" "$RUN_ROOT/state" "output") >/dev/null 2>&1; then
        die "Windows path-disjointness self-test accepted equal paths"
    fi
    if (assert_disjoint_paths "$RUN_ROOT/state" "state" "$RUN_ROOT/state/output" "output") >/dev/null 2>&1; then
        die "Windows path-disjointness self-test accepted output beneath state"
    fi
    if (assert_disjoint_paths "$RUN_ROOT/output/state" "state" "$RUN_ROOT/output" "output") >/dev/null 2>&1; then
        die "Windows path-disjointness self-test accepted state beneath output"
    fi
    if (assert_disjoint_paths / "state" "$RUN_ROOT/output" "output") >/dev/null 2>&1; then
        die "Windows path-disjointness self-test accepted the filesystem root"
    fi

    local safe_root="$RUN_ROOT/safe-source"
    mkdir "$safe_root"
    printf 'safe\n' >"$safe_root/file.txt"
    write_manifest "$safe_root" "$RUN_ROOT/safe-manifest.json" 0

    local counter=0 invalid fixture
    for invalid in '.SOURCE-MANIFEST.JSON' 'run-BUILD.ps1' 'CON' 'aux.txt' 'bad<name' 'trailing.'; do
        counter=$((counter + 1))
        fixture="$RUN_ROOT/invalid-$counter"
        mkdir "$fixture"
        printf 'invalid\n' >"$fixture/$invalid"
        if (write_manifest "$fixture" "$RUN_ROOT/invalid-$counter.json" 0) >/dev/null 2>&1; then
            die "Windows source namespace self-test accepted: $invalid"
        fi
    done
    fixture="$RUN_ROOT/case-collision"
    mkdir "$fixture"
    printf 'one\n' >"$fixture/Name"
    printf 'two\n' >"$fixture/name"
    if (write_manifest "$fixture" "$RUN_ROOT/case-collision.json" 0) >/dev/null 2>&1; then
        die "Windows source namespace self-test accepted a case collision"
    fi

    GOLDEN="$RUN_ROOT/golden-source.qcow2"
    qemu-img create -f qcow2 "$GOLDEN" 1M >/dev/null
    local parsed_virtual_size invalid_virtual_size
    parsed_virtual_size="$(golden_virtual_size)" \
        || die "Windows golden virtual-size self-test rejected a valid qcow2"
    [ "$parsed_virtual_size" = 1048576 ] \
        || die "Windows golden virtual-size self-test returned the wrong byte count"
    for invalid_virtual_size in \
        '{}' \
        '{"virtual-size":0}' \
        '{"virtual-size":-1}' \
        '{"virtual-size":true}' \
        '{"virtual-size":"1048576"}' \
        '[]' \
        'not-json'; do
        if printf '%s\n' "$invalid_virtual_size" \
            | parse_golden_virtual_size >/dev/null 2>&1; then
            die "Windows golden virtual-size self-test accepted invalid JSON: $invalid_virtual_size"
        fi
    done
    chmod 0400 "$GOLDEN"
    SHA256_WIN11_GOLDEN_QCOW2="$(sha256sum "$GOLDEN" | awk '{print $1}')"
    record_golden_identity
    bind_golden_backing
    verify_golden_backing
    chmod 0600 "$GOLDEN"
    if (verify_golden_backing) >/dev/null 2>&1; then
        die "sealed golden mutation self-test was accepted"
    fi

    local expected_marker='source-verified commit=1111111111111111111111111111111111111111 tree=2222222222222222222222222222222222222222 manifest=3333333333333333333333333333333333333333333333333333333333333333'
    local expected_offline_marker='offline-verified manifest=4444444444444444444444444444444444444444444444444444444444444444'
    local progress="$RUN_ROOT/progress.txt"
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n2026-07-16T12:00:03.0000000+00:00 windows-full-peer-presentation-controller.ps1 exit=0\r\n2026-07-16T12:00:04.0000000+00:00 windows-installed-service-probe.ps1 exit=0\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker"
    printf '2026-07-16T12:00:05.0000000+00:00 build-windows.ps1 exit=0\r\n' >>"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "duplicate guest completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "missing installed-service completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n2026-07-16T12:00:03.0000000+00:00 windows-installed-service-probe.ps1 exit=1\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "failed installed-service completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n2026-07-16T12:00:03.0000000+00:00 windows-installed-service-probe.ps1 exit=0\r\n2026-07-16T12:00:04.0000000+00:00 windows-full-peer-presentation-controller.ps1 exit=0\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "out-of-order full-peer completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n2026-07-16T12:00:03.0000000+00:00 windows-full-peer-presentation-controller.ps1 exit=1\r\n2026-07-16T12:00:04.0000000+00:00 windows-installed-service-probe.ps1 exit=0\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "failed full-peer completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\n2026-07-16T12:00:01.0000000+00:00 %s\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\n2026-07-16T12:00:03.0000000+00:00 windows-full-peer-presentation-controller.ps1 exit=0\n2026-07-16T12:00:04.0000000+00:00 windows-installed-service-probe.ps1 exit=0\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "non-CRLF guest progress self-test was accepted"
    fi

    local fake_bin="$RUN_ROOT/fake-bin"
    mkdir "$fake_bin"
    printf '#!/bin/sh\nsleep 5\n' >"$fake_bin/virsh"
    chmod 0700 "$fake_bin/virsh"
    if PATH="$fake_bin:$PATH" CONTROL_TIMEOUT_SECONDS=1 virsh_bounded domstate test >/dev/null 2>&1; then
        die "bounded virsh self-test accepted an unbounded control call"
    fi

    bash -c \
        'sleep 1; exec setsid --wait bash -c "$1"' \
        _ 'trap "" TERM; exec sleep 30' &
    CURRENT_VIRT_PID=$!
    CURRENT_VIRT_START="$(process_start_time "$CURRENT_VIRT_PID")" \
        || die "could not bind synthetic process-group identity"
    if owned_process_matches; then
        die "delayed process-group fixture skipped its pre-admission state"
    fi
    PROCESS_ADMISSION_SECONDS=3
    wait_for_owned_process_group \
        || die "delayed process-group fixture did not admit conclusively"
    PROCESS_STOP_SECONDS=1
    stop_owned_process || die "owned process-group deadline self-test did not terminate conclusively"
    [ -z "$CURRENT_VIRT_PID" ] && [ -z "$CURRENT_VIRT_START" ] \
        || die "owned process-group deadline self-test retained stale identity"

    printf '{"fixture":true}\n' >"$RUN_ROOT/base-source-manifest.json"
    mkdir -m 0700 "$RUN_ROOT/pass-A" "$RUN_ROOT/pass-A/extract.fixture"
    printf 'bounded diagnostic\n' >"$RUN_ROOT/pass-A/extract.fixture/build-windows.stderr.txt"
    printf 'artifact must not survive\n' >"$RUN_ROOT/pass-A/extract.fixture/rustdesk-setup.exe"
    truncate -s $((FAILURE_EVIDENCE_FILE_MAX_BYTES + 1)) \
        "$RUN_ROOT/pass-A/extract.fixture/windows-full-peer-viewer.stderr.txt"
    RUN_ID="11111111-1111-4111-8111-111111111111"
    RUN_PHASE="self-test"
    SOURCE_COMMIT="2222222222222222222222222222222222222222"
    SOURCE_TREE="3333333333333333333333333333333333333333"
    preserve_failure_evidence \
        || die "bounded Windows failure-evidence self-test could not publish"
    local failure_fixture="$STATE_DIR/windows-failure-$RUN_ID"
    [ -f "$failure_fixture/failure.json" ] \
        && [ -f "$failure_fixture/pass-A-build-windows.stderr.txt" ] \
        && [ ! -e "$failure_fixture/pass-A-rustdesk-setup.exe" ] \
        && [ ! -e "$failure_fixture/pass-A-windows-full-peer-viewer.stderr.txt" ] \
        || die "bounded Windows failure-evidence self-test inventory is incorrect"
    local failure_fixture_id
    failure_fixture_id="$(stat -c '%d:%i' -- "$failure_fixture")"
    remove_private_root_exact "$failure_fixture" "$failure_fixture_id" \
        || die "bounded Windows failure-evidence self-test could not retire its fixture"

    run_root_cleanup_self_test
    RUN_COMPLETE=1
    printf 'build-windows-vm self-test: ok\n'
}

main() {
    windows_helper_authority_open
    RUN_PHASE="preflight"
    preflight
    RUN_ID="$(</proc/sys/kernel/random/uuid)"
    assert_uuid "$RUN_ID"
    RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"
    record_run_root_identity
    assert_safe_path "$RUN_ROOT" "private Windows run state"
    bind_golden_backing
    verify_active_online_snapshot
    RUN_PHASE="source-snapshot"
    materialize_source_snapshot
    RUN_PHASE="offline-media"
    build_offline_media
    RUN_PHASE="pass-A"
    run_pass A
    verify_golden_backing
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        RUN_PHASE="pass-B"
        run_pass B
        verify_golden_backing
        local exe_a exe_b msi_a msi_b
        exe_a="$(awk '{print $1}' "$RUN_ROOT/pass-A/result/rustdesk-setup.exe.sha256")"
        exe_b="$(awk '{print $1}' "$RUN_ROOT/pass-B/result/rustdesk-setup.exe.sha256")"
        msi_a="$(awk '{print $1}' "$RUN_ROOT/pass-A/result/rustdesk.msi.sha256")"
        msi_b="$(awk '{print $1}' "$RUN_ROOT/pass-B/result/rustdesk.msi.sha256")"
        [ "$exe_a" = "$exe_b" ] || die "Windows double-build .exe SHA mismatch: $exe_a != $exe_b"
        [ "$msi_a" = "$msi_b" ] || die "Windows double-build .msi SHA mismatch: $msi_a != $msi_b"
    elif [ "${DOUBLE_BUILD:-1}" != "0" ]; then
        die "DOUBLE_BUILD must be 0 or 1"
    fi
    verify_active_online_snapshot
    verify_golden_backing
    windows_helper_authority_close \
        || die "Windows helper authority could not retire before artifact publication"
    RUN_PHASE="publication"
    publish_result "$RUN_ROOT/pass-A/result"
    RUN_COMPLETE=1
    log "Windows artifacts complete: $OUT_DIR"
}

case "${1:-}" in
    --self-test)
        [ "$#" -eq 1 ] || die "--self-test takes no arguments"
        harness_self_test
        ;;
    '') main ;;
    *) die "usage: scripts/build-windows-vm.sh [--self-test]" ;;
esac

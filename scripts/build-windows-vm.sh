#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
PROCESS_STOP_SECONDS=10
TARGET_ID="windows-x86_64"
FRB_OUTPUTS=(
    src/bridge_generated.rs
    src/bridge_generated.io.rs
    flutter/lib/generated_bridge.dart
    flutter/lib/generated_bridge.freezed.dart
)

RUN_ROOT=""
RUN_ID=""
SOURCE_SNAPSHOT=""
SOURCE_COMMIT=""
SOURCE_TREE=""
SOURCE_MODE=""
FORK_VERSION_VALUE=""
BASE_MANIFEST_SHA256=""
OFFLINE_MANIFEST_SHA256=""
DEB_BUILDER_IMAGE=""
PRIVATE_GOLDEN=""
ONLINE_SNAPSHOT_PARENT=""
CURRENT_DOMAIN=""
CURRENT_DOMAIN_UUID=""
CURRENT_VIRT_PID=""
CURRENT_VIRT_START=""
CURRENT_VM_DEADLINE=""
CURRENT_PASS_ROOT=""
RUN_COMPLETE=0
CLEANUP_ACTIVE=0
CLEANUP_FAILED=0
FRB_REFERENCE=""

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
    stat="$(<"/proc/$pid/stat")"
    stat="${stat#*) }"
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

stop_owned_process() {
    if ! owned_process_matches; then
        CURRENT_VIRT_PID=""
        CURRENT_VIRT_START=""
        return 0
    fi
    if owned_process_is_live; then
        kill -TERM -- "-$CURRENT_VIRT_PID" || return 1
        local deadline
        deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
        while owned_process_is_live && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            sleep 1
        done
        if owned_process_is_live; then
            kill -KILL -- "-$CURRENT_VIRT_PID" || return 1
            deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
            while owned_process_is_live && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                sleep 1
            done
            owned_process_is_live && return 1
        fi
    fi
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
    timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \
        virsh -c qemu:///session "$@"
}

domain_uuid_now() {
    [ -n "$CURRENT_DOMAIN" ] || return 1
    virsh_bounded domuuid "$CURRENT_DOMAIN" 2>/dev/null
}

prove_owned_domain() {
    local actual
    [ -n "$CURRENT_DOMAIN" ] && [ -n "$CURRENT_DOMAIN_UUID" ] || return 1
    actual="$(domain_uuid_now)" || return 1
    [ "$actual" = "$CURRENT_DOMAIN_UUID" ]
}

domain_is_listed() {
    local uuids
    uuids="$(virsh_bounded list --all --uuid)" || return 2
    printf '%s\n' "$uuids" | awk -v wanted="$CURRENT_DOMAIN_UUID" '$0 == wanted { found=1 } END { exit !found }'
}

stop_and_undefine_owned_domain() {
    [ -n "$CURRENT_DOMAIN_UUID" ] || return 0
    if ! prove_owned_domain; then
        if domain_is_listed; then
            warn "owned UUID exists under an unexpected name; preserving run state"
            return 1
        else
            local listed_status=$?
            if [ "$listed_status" = 1 ]; then
                CURRENT_DOMAIN=""
                CURRENT_DOMAIN_UUID=""
                CURRENT_VM_DEADLINE=""
                return 0
            fi
            return 1
        fi
    fi

    local state deadline
    state="$(virsh_bounded domstate "$CURRENT_DOMAIN")" || return 1
    case "$state" in
        "shut off") ;;
        *)
            virsh_bounded destroy "$CURRENT_DOMAIN" >/dev/null || return 1
            deadline=$(( $(monotonic_seconds) + 60 ))
            while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                prove_owned_domain || break
                state="$(virsh_bounded domstate "$CURRENT_DOMAIN")" || return 1
                [ "$state" = "shut off" ] && break
                sleep 1
            done
            prove_owned_domain || return 1
            [ "$(virsh_bounded domstate "$CURRENT_DOMAIN")" = "shut off" ] || return 1
            ;;
    esac
    virsh_bounded undefine "$CURRENT_DOMAIN" --nvram >/dev/null || return 1
    if domain_is_listed; then
        return 1
    else
        local listed_status=$?
        [ "$listed_status" = 1 ] || return 1
        CURRENT_DOMAIN=""
        CURRENT_DOMAIN_UUID=""
        CURRENT_VM_DEADLINE=""
        return 0
    fi
}

cleanup() {
    local status=$?
    [ "$CLEANUP_ACTIVE" = 0 ] || exit "$status"
    CLEANUP_ACTIVE=1
    trap - EXIT HUP INT TERM

    if ! stop_owned_process; then
        CLEANUP_FAILED=1
        warn "preserving the domain because the owned virt-install process group did not terminate conclusively"
    elif ! stop_and_undefine_owned_domain; then
        CLEANUP_FAILED=1
    fi

    if [ "$RUN_COMPLETE" = 1 ] && [ "$CLEANUP_FAILED" = 0 ] && [ -n "$RUN_ROOT" ]; then
        chmod -R u+rwX "$RUN_ROOT" 2>/dev/null || :
        rm -rf -- "$RUN_ROOT" || CLEANUP_FAILED=1
    elif [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
        warn "retaining failed Windows harness state at $RUN_ROOT"
    fi
    if ! windows_helper_authority_close; then
        CLEANUP_FAILED=1
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
}

verify_active_online_snapshot() {
    [ -n "$ONLINE_SNAPSHOT_PARENT" ] || die "Windows online snapshot is not initialized"
    verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

preflight() {
    local planned_state planned_output
    require_cmd qemu-img virt-install virsh xorriso docker git python3 realpath sha256sum sha512sum timeout setsid
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
    GOLDEN="$(realpath -e "$GOLDEN")"
    if activate_release_online_snapshot; then
        :
    else
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT+x}" ] \
            || die "release online snapshot must not be empty"
        ONLINE_DIR="$(realpath -e "$ONLINE_DIR")"
        require_online_complete
    fi
    export ONLINE_DIR
    OUT_PARENT="$(dirname "$OUT_DIR")"
    mkdir -p "$OUT_PARENT"
    OUT_PARENT="$(realpath -e "$OUT_PARENT")"
    OUT_DIR="$OUT_PARENT/$(basename "$OUT_DIR")"
    for pair in "$STATE_DIR|state directory" "$GOLDEN|golden image" "$ONLINE_DIR|online cache" "$OUT_DIR|output directory"; do
        assert_safe_path "${pair%%|*}" "${pair#*|}"
    done
    assert_disjoint_paths "$STATE_DIR" "Windows harness state" "$OUT_DIR" "Windows output"
    { [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; } \
        || die "Windows output directory must be absent for atomic publication: $OUT_DIR"
    [ -f "$GOLDEN" ] && [ ! -L "$GOLDEN" ] || die "golden image is not a regular file"
    verify_sha256 "$GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"
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

snapshot_golden() {
    [ -n "$RUN_ROOT" ] || die "private run root is not initialized"
    PRIVATE_GOLDEN="$RUN_ROOT/golden.qcow2"
    python3 - "$GOLDEN" "$PRIVATE_GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2" "$(id -u)" <<'PY'
import errno
import fcntl
import hashlib
import os
import stat
import sys

source, destination, expected, uid_text = sys.argv[1:]
uid = int(uid_text)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
source_fd = os.open(source, flags)
destination_fd = -1
try:
    before = os.fstat(source_fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022):
        raise SystemExit("golden source is not a current-UID, non-hardlinked, non-group/world-writable regular file")
    destination_fd = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o400,
    )
    try:
        fcntl.ioctl(destination_fd, 0x40049409, source_fd)
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EINVAL, errno.ENOTTY, errno.EOPNOTSUPP):
            raise
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 8 * 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short write while copying golden image")
                view = view[written:]
    os.fsync(destination_fd)
    after = os.fstat(source_fd)
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                     "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise SystemExit("golden source changed while its private snapshot was created")
    copied = os.fstat(destination_fd)
    if (not stat.S_ISREG(copied.st_mode) or copied.st_uid != uid
            or copied.st_nlink != 1 or copied.st_size != before.st_size):
        raise SystemExit("private golden snapshot metadata is invalid")
    os.lseek(destination_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(destination_fd, 8 * 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit("private golden snapshot does not match its pinned SHA-256")
    os.fchmod(destination_fd, 0o400)
    os.fsync(destination_fd)
finally:
    if destination_fd >= 0:
        os.close(destination_fd)
    os.close(source_fd)
directory_fd = os.open(os.path.dirname(destination), os.O_RDONLY | os.O_CLOEXEC)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
    verify_private_golden
}

verify_private_golden() {
    [ -n "$PRIVATE_GOLDEN" ] || die "private golden snapshot is not initialized"
    [ -f "$PRIVATE_GOLDEN" ] && [ ! -L "$PRIVATE_GOLDEN" ] \
        || die "private golden snapshot is not a regular file"
    [ "$(stat -c '%u:%a:%h' "$PRIVATE_GOLDEN")" = "$(id -u):400:1" ] \
        || die "private golden snapshot ownership, mode, or link count changed"
    verify_sha256 "$PRIVATE_GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"
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
    verify_private_golden
    (
        cd "$CURRENT_PASS_ROOT"
        qemu-img create -f qcow2 -F qcow2 -b ../golden.qcow2 overlay.qcow2 >/dev/null
    )
    windows_helper_guestfish_run \
        --mount "type=bind,source=$CURRENT_PASS_ROOT/overlay.qcow2,target=/authority/pass/overlay.qcow2" \
        --mount "type=bind,source=$PRIVATE_GOLDEN,target=/authority/golden.qcow2,readonly" \
        -- /usr/bin/guestfish --rw -a /authority/pass/overlay.qcow2 run : \
            mount /dev/sda1 / : \
            mkdir-p /EFI/BOOT : \
            cp /EFI/Microsoft/Boot/bootmgfw.efi /EFI/BOOT/BOOTX64.EFI
}

verify_domain_xml() {
    local xml="$CURRENT_PASS_ROOT/domain.xml"
    virsh_bounded dumpxml "$CURRENT_DOMAIN" >"$xml" || die "cannot read the created domain XML"
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
    [ "${#CURRENT_DOMAIN}" -le 63 ] || die "generated domain name is too long"
    if virsh_bounded domuuid "$CURRENT_DOMAIN" >/dev/null 2>&1; then
        die "generated domain name already exists"
    fi
    CURRENT_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))

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

    local deadline rc
    deadline=$(( $(monotonic_seconds) + CREATE_TIMEOUT_SECONDS ))
    while owned_process_is_live && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        sleep 1
    done
    if owned_process_is_live; then
        stop_owned_process || die "virt-install did not stop after its creation deadline"
        die "virt-install exceeded its creation deadline"
    fi
    if wait "$CURRENT_VIRT_PID"; then rc=0; else rc=$?; fi
    CURRENT_VIRT_PID=""
    CURRENT_VIRT_START=""
    [ "$rc" = 0 ] || die "virt-install failed with exit $rc"
    prove_owned_domain || die "virt-install did not create the exact UUID-bound domain"
    [ "$(virsh_bounded domstate "$CURRENT_DOMAIN")" = "running" ] \
        || die "created Windows domain is not running"
    verify_domain_xml
}

wait_for_domain() {
    local state
    [ -n "$CURRENT_VM_DEADLINE" ] || die "Windows VM deadline was not initialized"
    while :; do
        prove_owned_domain || die "owned Windows domain disappeared before authoritative shutdown"
        state="$(virsh_bounded domstate "$CURRENT_DOMAIN")" \
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
    mkdir "$result"
    install -m 0644 "$extracted/rustdesk-setup.exe" "$result/rustdesk-setup.exe"
    install -m 0644 "$extracted/rustdesk.msi" "$result/rustdesk.msi"
    (
        cd "$result"
        sha256sum rustdesk-setup.exe >rustdesk-setup.exe.sha256
        sha256sum rustdesk.msi >rustdesk.msi.sha256
    )
    for diagnostic in build-log.txt run-build-progress.txt; do
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
    local staging
    { [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; } \
        || die "Windows output directory appeared before atomic publication"
    staging="$(mktemp -d "$OUT_PARENT/.windows-publish.XXXXXXXX")"
    for name in rustdesk-setup.exe rustdesk-setup.exe.sha256 rustdesk.msi rustdesk.msi.sha256; do
        [ -f "$result/$name" ] && [ ! -L "$result/$name" ] && [ -s "$result/$name" ] \
            || die "validated result is missing $name"
        install -m 0644 "$result/$name" "$staging/$name"
    done
    for name in build-log.txt run-build-progress.txt; do
        if [ -f "$result/$name" ] && [ ! -L "$result/$name" ]; then
            install -m 0644 "$result/$name" "$staging/$name"
        fi
    done
    (
        cd "$staging"
        sha256sum -c rustdesk-setup.exe.sha256
        sha256sum -c rustdesk.msi.sha256
    )
    mv -T --no-clobber -- "$staging" "$OUT_DIR"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "Windows output directory appeared during atomic publication"
    (
        cd "$OUT_DIR"
        sha256sum -c rustdesk-setup.exe.sha256
        sha256sum -c rustdesk.msi.sha256
    )
}

harness_self_test() {
    require_cmd python3 sha256sum setsid timeout
    RUN_ROOT="$(mktemp -d /tmp/rustdesk-windows-harness-test.XXXXXXXX)"
    chmod 0700 "$RUN_ROOT"

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
    printf 'synthetic golden bytes\n' >"$GOLDEN"
    chmod 0600 "$GOLDEN"
    SHA256_WIN11_GOLDEN_QCOW2="$(sha256sum "$GOLDEN" | awk '{print $1}')"
    snapshot_golden
    chmod 0600 "$PRIVATE_GOLDEN"
    printf 'mutation\n' >>"$PRIVATE_GOLDEN"
    chmod 0400 "$PRIVATE_GOLDEN"
    if (verify_private_golden) >/dev/null 2>&1; then
        die "private golden mutation self-test was accepted"
    fi

    local expected_marker='source-verified commit=1111111111111111111111111111111111111111 tree=2222222222222222222222222222222222222222 manifest=3333333333333333333333333333333333333333333333333333333333333333'
    local expected_offline_marker='offline-verified manifest=4444444444444444444444444444444444444444444444444444444444444444'
    local progress="$RUN_ROOT/progress.txt"
    printf '2026-07-16T12:00:00.0000000+00:00 %s\r\n2026-07-16T12:00:01.0000000+00:00 %s\r\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\r\n' \
        "$expected_marker" "$expected_offline_marker" >"$progress"
    validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker"
    printf '2026-07-16T12:00:03.0000000+00:00 build-windows.ps1 exit=0\r\n' >>"$progress"
    if (validate_guest_progress "$progress" "$expected_marker" "$expected_offline_marker") >/dev/null 2>&1; then
        die "duplicate guest completion self-test was accepted"
    fi
    printf '2026-07-16T12:00:00.0000000+00:00 %s\n2026-07-16T12:00:01.0000000+00:00 %s\n2026-07-16T12:00:02.0000000+00:00 build-windows.ps1 exit=0\n' \
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

    setsid --wait bash -c 'trap "" TERM; exec sleep 30' &
    CURRENT_VIRT_PID=$!
    CURRENT_VIRT_START="$(process_start_time "$CURRENT_VIRT_PID")" \
        || die "could not bind synthetic process-group identity"
    PROCESS_STOP_SECONDS=1
    stop_owned_process || die "owned process-group deadline self-test did not terminate conclusively"
    [ -z "$CURRENT_VIRT_PID" ] && [ -z "$CURRENT_VIRT_START" ] \
        || die "owned process-group deadline self-test retained stale identity"

    RUN_COMPLETE=1
    printf 'build-windows-vm self-test: ok\n'
}

main() {
    windows_helper_authority_open
    preflight
    RUN_ID="$(</proc/sys/kernel/random/uuid)"
    assert_uuid "$RUN_ID"
    RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"
    assert_safe_path "$RUN_ROOT" "private Windows run state"
    snapshot_golden
    if [ -z "$ONLINE_SNAPSHOT_PARENT" ]; then
        ONLINE_SNAPSHOT_PARENT="$RUN_ROOT/online-snapshot"
        create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    fi
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
    export ONLINE_DIR
    verify_active_online_snapshot
    materialize_source_snapshot
    build_offline_media
    run_pass A
    verify_private_golden
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        run_pass B
        verify_private_golden
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
    verify_private_golden
    publish_result "$RUN_ROOT/pass-A/result"
    rm -f -- "$RUN_ROOT/offline.iso"
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

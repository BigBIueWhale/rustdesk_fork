#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
[ "$HOST_UID" -ne 0 ] \
    || { echo 'verifier-VM authority smoke: host or container-root execution is forbidden' >&2; exit 1; }
[ "$HOST_GID" -ne 0 ] \
    || { echo 'verifier-VM authority smoke: a root primary group is forbidden' >&2; exit 1; }
readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

MODE=authority-smoke
LIFECYCLE_ARTIFACT=
LIFECYCLE_ARTIFACT_SHA256=
LIFECYCLE_COMMIT=
DEV_CHECK_ARCHIVE=
case "$#:${1:-}" in
    0:)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'verifier-VM input/run overrides are lifecycle-internal' >&2; exit 2; }
        ;;
    1:--hbb-common-fs)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Rust-test input/run overrides are forbidden' >&2; exit 2; }
        MODE=hbb-common-fs
        ;;
    1:--flutter-model-tests)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Flutter-test input/run overrides are forbidden' >&2; exit 2; }
        MODE=flutter-model-tests
        ;;
    9:--debian-systemd-lifecycle)
        [ "$2" = --release-deb ] && [ "$4" = --sha256 ] \
            && [ "$6" = --commit ] && [ "$8" = --devcheck-archive ] \
            || { echo 'invalid Debian systemd lifecycle argument order' >&2; exit 2; }
        MODE=debian-systemd-lifecycle
        LIFECYCLE_ARTIFACT=$3
        LIFECYCLE_ARTIFACT_SHA256=$5
        LIFECYCLE_COMMIT=$7
        DEV_CHECK_ARCHIVE=$9
        [ -n "${VERIFIER_VM_INPUT_ROOT:-}" ] \
            && [ -n "${VERIFIER_VM_RUN_ROOT:-}" ] \
            || { echo 'Debian systemd lifecycle requires private VM input and run roots' >&2; exit 2; }
        ;;
    *)
        printf 'usage: %s [--hbb-common-fs | --flutter-model-tests | --debian-systemd-lifecycle --release-deb ABSOLUTE_DEB --sha256 SHA256 --commit COMMIT --devcheck-archive ABSOLUTE_ARCHIVE]\n' "${0##*/}" >&2
        exit 2
        ;;
esac
readonly MODE LIFECYCLE_ARTIFACT LIFECYCLE_ARTIFACT_SHA256 LIFECYCLE_COMMIT DEV_CHECK_ARCHIVE
readonly INPUT_ROOT="${VERIFIER_VM_INPUT_ROOT:-$REPO_ROOT/.harness-state/verifier-vm}"
readonly RUN_ROOT="${VERIFIER_VM_RUN_ROOT:-$INPUT_ROOT}"
readonly IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly BASE="$INPUT_ROOT/$IMAGE_NAME"
readonly DOCKER_BUNDLE="$INPUT_ROOT/docker-${VERIFIER_VM_DOCKER_VERSION}.tgz"
readonly GIT_PACKAGE="$INPUT_ROOT/git_${VERIFIER_VM_GIT_PACKAGE_FILENAME_VERSION}_amd64.deb"
readonly BOOT_ROOT="$INPUT_ROOT/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"
readonly KERNEL="$BOOT_ROOT/vmlinuz"
readonly INITRD="$BOOT_ROOT/initrd.img"
readonly VIRTIOFSD_PACKAGE="$INPUT_ROOT/virtiofsd_${VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION}_amd64.deb"
readonly VIRTIOFSD_LAUNCHER="$SCRIPT_DIR/launch-landlocked-virtiofsd.py"
readonly ONLINE_INPUTS="$REPO_ROOT/online/inputs"
readonly RUST_TEST_ARCHIVE="$ONLINE_INPUTS/rust-${RUST_VERSION}.tar.xz"
readonly FLUTTER_TEST_ARCHIVE="$ONLINE_INPUTS/flutter-${FLUTTER_VERSION}.tar.xz"
readonly LLVM_TEST_ARCHIVE="$ONLINE_INPUTS/llvm-${LLVM_VERSION}.tar.xz"
readonly FRB_CODEGEN="$ONLINE_INPUTS/frb-tool/bin/flutter_rust_bridge_codegen"
readonly PUB_CACHE_ROOT="$ONLINE_INPUTS/pub-cache"
readonly CARGO_VENDOR_ROOT="$ONLINE_INPUTS/cargo-vendor"
readonly CARGO_VENDOR_CONFIG="$ONLINE_INPUTS/cargo-vendor-config.toml"
readonly DEB_BUILDER_ARCHIVE="$ONLINE_INPUTS/build-images/deb-builder.docker.tar.gz"
readonly OUTER_SOURCE="${BASH_SOURCE[0]}"
readonly GUEST_SCRIPT="$SCRIPT_DIR/smoke-verifier-vm-authority-guest.sh"
readonly ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-vm-entry-preflight.sh"
readonly VERIFY_SCRIPT="$SCRIPT_DIR/verify.sh"
readonly VERIFY_RELEASE_SOURCE="$SCRIPT_DIR/verify-release.sh"
readonly RELEASE_PARENT_SOURCE="$SCRIPT_DIR/build-release.sh"
readonly RELEASE_PUBLISHER_SOURCE="$SCRIPT_DIR/publish-github-release.sh"
readonly RELEASE_FINALIZER_SOURCE="$SCRIPT_DIR/finalize-release-set.py"
readonly RELEASE_WORKSPACE_RUNTIME_TEST="$SCRIPT_DIR/verify-release-workspace-runtime.sh"
readonly FORK_VERSION_SOURCE="$SCRIPT_DIR/fork-version.sh"
readonly APPLE_CHECK_SOURCE="$SCRIPT_DIR/apple-conform-check.sh"
readonly FLUTTER_PEER_SOURCE="$SCRIPT_DIR/smoke-flutter-peer-presentation.sh"
readonly FLUTTER_TOOLS_FINALIZER_SOURCE="$SCRIPT_DIR/finalize-flutter-tools-offline.sh"
readonly VERIFY_SCAN_SOURCE="$SCRIPT_DIR/verify-scan.sh"
readonly FRB_CODEGEN_SOURCE="$SCRIPT_DIR/frb-codegen.sh"
readonly DART_VERIFY_SOURCE="$SCRIPT_DIR/dart-verify.sh"
readonly SMOKE_SERVER_SOURCE="$SCRIPT_DIR/smoke-server.sh"
readonly RUST_AUDIT_SOURCE="$SCRIPT_DIR/audit.sh"
readonly RUST_AUDIT_POLICY_SOURCE="$SCRIPT_DIR/rust-audit-policy.py"
readonly RUST_AUDIT_CHECKER="$SCRIPT_DIR/verify-rust-audit-authority.py"
readonly ANDROID_KEYSTORE_SOURCE="$SCRIPT_DIR/gen-android-keystore.sh"
readonly ANDROID_KEYSTORE_INNER="$SCRIPT_DIR/android-keystore-generate.sh"
readonly ANDROID_KEYSTORE_CHECKER="$SCRIPT_DIR/verify-android-keystore-authority.py"
readonly ANDROID_BUILDER_SOURCE="$SCRIPT_DIR/build-android.sh"
readonly ANDROID_APK_BUILD_SOURCE="$SCRIPT_DIR/android-apk-build.sh"
readonly ANDROID_BUILDER_CHECKER="$SCRIPT_DIR/verify-android-builder-authority.py"
readonly ANDROID_GRADLE_SOURCE="$SCRIPT_DIR/test-android-gradle-cache.sh"
readonly ANDROID_GRADLE_CHECKER="$SCRIPT_DIR/verify-android-gradle-authority.py"
readonly ANDROID_BUILDER_IMAGE_CHECKER="$SCRIPT_DIR/verify-android-builder-image-authority.py"
readonly DEB_BUILDER_IMAGE_CHECKER="$SCRIPT_DIR/verify-deb-builder-image-authority.py"
readonly DEBIAN_BUILDER_SOURCE="$SCRIPT_DIR/build-debian.sh"
readonly DEBIAN_BUILDER_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-debian-builder-authority.py"
readonly SYSTEMD_RUNTIME_LIBS_SOURCE="$SCRIPT_DIR/stage-debian-systemd-runtime-libs.sh"
readonly SYSTEMD_LIFECYCLE_GUEST_SOURCE="$SCRIPT_DIR/smoke-debian-systemd-lifecycle-guest.sh"
readonly SYSTEMD_LOGINCTL_SOURCE="$SCRIPT_DIR/smoke-debian-systemd-loginctl.sh"
readonly DEBIAN_PACKAGE_AUTHORITY_SOURCE="$SCRIPT_DIR/verify-debian-package-authority.py"
readonly SYSTEMD_UNIT_SOURCE="$REPO_ROOT/res/rustdesk.service"
readonly DEV_CHECK_DOCKERFILE_SOURCE="$SCRIPT_DIR/Dockerfile.devcheck"
readonly WIN_HELPER_IMAGE_CHECKER="$SCRIPT_DIR/verify-win-helper-image-authority.py"
readonly WINDOWS_HELPER_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-windows-helper-authority.py"
readonly WINDOWS_HELPER_RUNTIME_TEST="$SCRIPT_DIR/test-windows-helper-vm-runtime.sh"
readonly ANDROID_BUILDER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.android-builder"
readonly DEB_BUILDER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.deb-builder"
readonly WIN_HELPER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.win-helper"
readonly BUILDER_BOOTSTRAP_SEAL_DOCKERFILE="$SCRIPT_DIR/Dockerfile.builder-bootstrap-seal"
readonly ANDROID_BUILDER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.android-builder-certify"
readonly DEB_BUILDER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.deb-builder-certify"
readonly WIN_HELPER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.win-helper-certify"
readonly WINDOWS_HELPER_RUNTIME_SOURCE="$SCRIPT_DIR/windows-helper-runtime.sh"
readonly WINDOWS_HELPER_EXTRACTOR="$SCRIPT_DIR/windows-helper-extract-kernel.py"
readonly WINDOWS_GOLDEN_INSPECTOR="$SCRIPT_DIR/windows-golden-inspect.sh"
readonly WINDOWS_BUILD_SOURCE="$SCRIPT_DIR/build-windows-vm.sh"
readonly WINDOWS_PROVISION_SOURCE="$SCRIPT_DIR/provision-windows-vm.sh"
readonly WINDOWS_GOLDEN_SOURCE="$SCRIPT_DIR/verify-windows-golden.sh"
readonly ANDROID_RUST_SOURCE="$SCRIPT_DIR/android-rust-check.sh"
readonly OFFLINE_IMAGE_PROVENANCE_SOURCE="$SCRIPT_DIR/offline-image-provenance.py"
readonly ONLINE_FETCH_SOURCE="$SCRIPT_DIR/online-fetch.sh"
readonly DART_AUDIT_SOURCE="$SCRIPT_DIR/dart-audit.sh"
readonly DART_AUDIT_RESULT_SOURCE="$SCRIPT_DIR/dart-audit-result.py"
readonly DART_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-dart-verifier-authority.py"
readonly DART_AUDIT_CHECKER="$SCRIPT_DIR/verify-dart-audit-authority.py"
readonly REQUIREMENTS_SOURCE="$REPO_ROOT/requirements.html"
readonly HARDENING_SOURCE="$REPO_ROOT/HARDENING_STATUS.md"
readonly BOOT_DERIVER="$SCRIPT_DIR/derive-verifier-vm-boot-assets.sh"
readonly CAPTURE_HELPER="$SCRIPT_DIR/bounded-unix-stream-capture.py"
readonly CLEANUP_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly LIB_SOURCE="$SCRIPT_DIR/lib.sh"
readonly PIN_SOURCE="$SCRIPT_DIR/pins.env"
readonly SERIAL_LIMIT=8388608
if [ "$MODE" = debian-systemd-lifecycle ]; then
    readonly VM_TIMEOUT_SECONDS=480
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=2048
elif [ "$MODE" = hbb-common-fs ]; then
    readonly VM_TIMEOUT_SECONDS=1800
    readonly OVERLAY_SIZE=16G
    readonly VM_MEMORY=8192
elif [ "$MODE" = flutter-model-tests ]; then
    readonly VM_TIMEOUT_SECONDS=1800
    readonly OVERLAY_SIZE=24G
    readonly VM_MEMORY=8192
else
    readonly VM_TIMEOUT_SECONDS=90
    readonly OVERLAY_SIZE=6G
    readonly VM_MEMORY=2048
fi

RUN=
RUN_ID=
VM_OWNER_PID=
VM_OWNER_START=
VM_PID=
VM_START=
CAPTURE_PID=
CAPTURE_START=
KERNEL_FD=
INITRD_FD=
VIRTIOFSD_PID=
VIRTIOFSD_START=
VIRTIOFSD_BINARY=
RUN_COMPLETE=0

fail() {
    printf 'verifier-VM authority smoke: %s\n' "$*" >&2
    exit 1
}

git_closed() {
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
        GIT_NO_REPLACE_OBJECTS=1 \
        /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

process_start_time() {
    local pid=$1
    [ -r "/proc/$pid/stat" ] || return 1
    /usr/bin/awk '{ print $22 }' "/proc/$pid/stat"
}

is_exact_vm_process() {
    [ -n "$VM_PID" ] && [ -n "$VM_START" ] \
        && [ -r "/proc/$VM_PID/stat" ] \
        && [ "$(process_start_time "$VM_PID" 2>/dev/null)" = "$VM_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$VM_PID/exe" 2>/dev/null)" = \
             /usr/bin/qemu-system-x86_64 ]
}

is_exact_vm_owner_process() {
    [ -n "$VM_OWNER_PID" ] && [ -n "$VM_OWNER_START" ] \
        && [ -r "/proc/$VM_OWNER_PID/stat" ] \
        && [ "$(process_start_time "$VM_OWNER_PID" 2>/dev/null)" = "$VM_OWNER_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$VM_OWNER_PID/exe" 2>/dev/null)" = \
             /usr/bin/timeout ]
}

is_exact_capture_process() {
    [ -n "$CAPTURE_PID" ] && [ -n "$CAPTURE_START" ] \
        && [ -r "/proc/$CAPTURE_PID/stat" ] \
        && [ "$(process_start_time "$CAPTURE_PID" 2>/dev/null)" = "$CAPTURE_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$CAPTURE_PID/exe" 2>/dev/null)" = \
             "$(/usr/bin/readlink -f /usr/bin/python3)" ]
}

is_exact_virtiofsd_process() {
    [ -n "$VIRTIOFSD_PID" ] && [ -n "$VIRTIOFSD_START" ] \
        && [ -n "$VIRTIOFSD_BINARY" ] \
        && [ -r "/proc/$VIRTIOFSD_PID/stat" ] \
        && [ "$(process_start_time "$VIRTIOFSD_PID" 2>/dev/null)" = "$VIRTIOFSD_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$VIRTIOFSD_PID/exe" 2>/dev/null)" = \
             "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/awk '{ print $3 }' "/proc/$VIRTIOFSD_PID/stat" 2>/dev/null)" != Z ]
}

is_owned_virtiofsd_generation() {
    local executable
    [ -n "$VIRTIOFSD_PID" ] && [ -n "$VIRTIOFSD_START" ] \
        && [ -n "$VIRTIOFSD_BINARY" ] \
        && [ -r "/proc/$VIRTIOFSD_PID/stat" ] \
        && [ "$(process_start_time "$VIRTIOFSD_PID" 2>/dev/null)" = "$VIRTIOFSD_START" ] \
        && [ "$(/usr/bin/awk '{ print $3 }' "/proc/$VIRTIOFSD_PID/stat" 2>/dev/null)" != Z ] \
        || return 1
    executable="$(/usr/bin/readlink -f "/proc/$VIRTIOFSD_PID/exe" 2>/dev/null)" \
        || return 1
    [ "$executable" = "$VIRTIOFSD_BINARY" ] \
        || [ "$executable" = "$(/usr/bin/readlink -f /usr/bin/python3)" ]
}

virtiofsd_seccomp_enforced() {
    local task_status task_count=0
    is_exact_virtiofsd_process || return 1
    for task_status in /proc/"$VIRTIOFSD_PID"/task/[0-9]*/status; do
        [ -r "$task_status" ] || return 1
        [ "$(/usr/bin/awk '/^Seccomp:/ { print $2 }' "$task_status" 2>/dev/null)" = 2 ] \
            || return 1
        task_count=$((task_count + 1))
    done
    [ "$task_count" -ge 1 ]
}

terminate_owned_virtiofsd_generation() {
    local signal attempt
    [ -r "/proc/$VIRTIOFSD_PID/stat" ] || return 0
    [ "$(process_start_time "$VIRTIOFSD_PID" 2>/dev/null)" = "$VIRTIOFSD_START" ] \
        || return 0
    [ "$(/usr/bin/awk '{ print $3 }' "/proc/$VIRTIOFSD_PID/stat" 2>/dev/null)" != Z ] \
        || return 0
    is_owned_virtiofsd_generation || return 1
    for signal in TERM KILL; do
        /usr/bin/kill -"$signal" "$VIRTIOFSD_PID" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            [ -r "/proc/$VIRTIOFSD_PID/stat" ] || return 0
            [ "$(process_start_time "$VIRTIOFSD_PID" 2>/dev/null)" = "$VIRTIOFSD_START" ] \
                || return 0
            [ "$(/usr/bin/awk '{ print $3 }' "/proc/$VIRTIOFSD_PID/stat" 2>/dev/null)" != Z ] \
                || return 0
            is_owned_virtiofsd_generation || return 1
            /usr/bin/sleep 0.01
        done
    done
    return 1
}

start_sealed_input_virtiofsd() {
    local socket=$1 log=$2 shared_identity=$3 receipt ready=0
    /usr/bin/python3 -I -S "$VIRTIOFSD_LAUNCHER" \
        --binary "$VIRTIOFSD_BINARY" \
        --binary-sha256 "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY" \
        --authority sealed-input \
        --shared-dir "$ONLINE_INPUTS" --shared-identity "$shared_identity" \
        --socket "$socket" --uid "$HOST_UID" --gid "$HOST_GID" \
        >"$log" 2>&1 &
    VIRTIOFSD_PID=$!
    VIRTIOFSD_START="$(process_start_time "$VIRTIOFSD_PID")" \
        || fail 'cannot record sealed-input virtiofsd generation'
    for _ in $(/usr/bin/seq 1 600); do
        if is_exact_virtiofsd_process \
           && verify_private_socket "$socket" \
           && [ "$(/usr/bin/awk '/^NoNewPrivs:/ { print $2 }' "/proc/$VIRTIOFSD_PID/status")" = 1 ]; then
            ready=1
            break
        fi
        is_owned_virtiofsd_generation || break
        /usr/bin/sleep 0.05
    done
    [ "$ready" -eq 1 ] \
        || { /usr/bin/tail -n 120 "$log" >&2; fail 'sealed-input virtiofsd did not become ready'; }
    [ "$(/usr/bin/awk '/^Uid:/ { print $2":"$3":"$4":"$5 }' "/proc/$VIRTIOFSD_PID/status")" = \
      "$HOST_UID:$HOST_UID:$HOST_UID:$HOST_UID" ] \
        && [ "$(/usr/bin/awk '/^Gid:/ { print $2":"$3":"$4":"$5 }' "/proc/$VIRTIOFSD_PID/status")" = \
             "$HOST_GID:$HOST_GID:$HOST_GID:$HOST_GID" ] \
        || fail 'sealed-input virtiofsd process identity differs'
    receipt="$(/usr/bin/grep '^VIRTIOFSD_LANDLOCK=' "$log")" \
        || fail 'sealed-input virtiofsd Landlock receipt is absent'
    [[ "$receipt" =~ ^VIRTIOFSD_LANDLOCK=pass\ abi=([0-9]+)\ uid=$HOST_UID\ gid=$HOST_GID\ filesystem=sealed-input-only\ tcp=denied\ socket=prebound\ seccomp=kill$ ]] \
        && [ "${BASH_REMATCH[1]}" -ge 8 ] \
        || fail 'sealed-input virtiofsd Landlock receipt differs'
}

terminate_exact_vm_process() {
    local signal attempt
    is_exact_vm_process || return 0
    for signal in TERM KILL; do
        kill -"$signal" "$VM_PID" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            is_exact_vm_process || return 0
            /usr/bin/sleep 0.01
        done
    done
    ! is_exact_vm_process
}

capture_listeners() {
    /usr/bin/ss -H -lntu | LC_ALL=C /usr/bin/sort -u
}

require_exact_fixed_receipt() {
    local expected=$1 label=$2
    local -a receipts=()
    mapfile -t receipts < <(/usr/bin/grep -Fo -- "$expected" "$SERIAL_LOG" || true)
    [ "${#receipts[@]}" -eq 1 ] && [ "${receipts[0]}" = "$expected" ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail "$label is absent or duplicated"; }
}

reconcile_socket() {
    local path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        verify_private_socket "$path" || return 1
        /usr/bin/rm -- "$path" || return 1
    fi
}

verify_private_socket() {
    local path=$1 mode
    [ -S "$path" ] && [ ! -L "$path" ] || return 1
    [ "$(/usr/bin/stat -c '%u:%g' -- "$path")" = "$HOST_UID:$HOST_GID" ] \
        || return 1
    mode="$(/usr/bin/stat -c '%a' -- "$path")" || return 1
    [ $((8#$mode & 077)) -eq 0 ] || return 1
}

cleanup() {
    local status=$? cleanup_failed=0
    trap - EXIT HUP INT TERM
    if [ -n "$VM_OWNER_PID" ]; then
        if is_exact_vm_owner_process; then
            kill -TERM "$VM_OWNER_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$VM_OWNER_PID" 2>/dev/null || true
        VM_OWNER_PID=
        VM_OWNER_START=
    fi
    terminate_exact_vm_process || cleanup_failed=1
    VM_PID=
    VM_START=
    if [ -n "$VIRTIOFSD_PID" ]; then
        if terminate_owned_virtiofsd_generation; then
            wait "$VIRTIOFSD_PID" 2>/dev/null || true
        else
            cleanup_failed=1
        fi
        VIRTIOFSD_PID=
        VIRTIOFSD_START=
    fi
    if [ -n "$CAPTURE_PID" ]; then
        if is_exact_capture_process; then
            kill -TERM "$CAPTURE_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=
        CAPTURE_START=
    fi
    if [ -n "$KERNEL_FD" ]; then
        exec {KERNEL_FD}<&- || cleanup_failed=1
        KERNEL_FD=
    fi
    if [ -n "$INITRD_FD" ]; then
        exec {INITRD_FD}<&- || cleanup_failed=1
        INITRD_FD=
    fi
    if [ -n "$RUN" ] && [ -d "$RUN" ] && [ ! -L "$RUN" ] \
       && [ "$(/usr/bin/stat -c '%d:%i' -- "$RUN" 2>/dev/null)" = "$RUN_ID" ]; then
        reconcile_socket "$RUN/serial.sock" || cleanup_failed=1
        reconcile_socket "$RUN/qmp.sock" || cleanup_failed=1
        if [ "$RUN_COMPLETE" -eq 1 ] && [ "$status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
            /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
                --remove-private-root "$RUN" --expected-identity "$RUN_ID" \
                || cleanup_failed=1
        else
            printf 'verifier-VM authority smoke: retaining failed private evidence at %s\n' \
                "$RUN" >&2
        fi
    elif [ -n "$RUN" ]; then
        cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" = Linux:x86_64 ] \
    || fail 'verifier VM requires a Linux x86_64 orchestration host'
for tool in /usr/bin/awk /usr/bin/chmod /usr/bin/cmp /usr/bin/comm /usr/bin/find \
    /usr/bin/dpkg-deb /usr/bin/git /usr/bin/grep /usr/bin/id /usr/bin/mkdir /usr/bin/mktemp /usr/bin/python3 \
    /usr/bin/qemu-img /usr/bin/qemu-system-x86_64 /usr/bin/readlink /usr/bin/rm \
    /usr/bin/seq /usr/bin/sha256sum /usr/bin/sha512sum /usr/bin/sleep /usr/bin/sort \
    /usr/bin/ss /usr/bin/stat /usr/bin/tail /usr/bin/timeout /usr/bin/uname \
    /usr/bin/xorriso; do
    resolved="$(/usr/bin/readlink -f -- "$tool" 2>/dev/null)" \
        || fail "cannot resolve fixed host orchestration tool: $tool"
    [ -f "$resolved" ] && [ ! -L "$resolved" ] && [ -x "$resolved" ] \
        || fail "fixed host orchestration tool is unavailable: $tool"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$resolved")" = 0:0:755:1 ] \
        || fail "fixed host orchestration tool metadata changed: $tool"
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || fail '/dev/kvm is unavailable to the invoking non-root user'
[ -d "$INPUT_ROOT" ] && [ ! -L "$INPUT_ROOT" ] \
    || fail 'verifier-VM inputs are absent; run scripts/online-fetch.sh --verifier-vm-inputs'
for private_root in "$INPUT_ROOT" "$RUN_ROOT"; do
    [ -d "$private_root" ] && [ ! -L "$private_root" ] \
        || fail "verifier-VM private root is absent or ambiguous: $private_root"
    [ "$(/usr/bin/readlink -f -- "$private_root" 2>/dev/null)" = "$private_root" ] \
        || fail "verifier-VM private root is not absolute and canonical: $private_root"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$private_root")" = \
      "$HOST_UID:$HOST_GID:700" ] \
        || fail "verifier-VM private root is not current-user/current-group mode 0700: $private_root"
done
for input in "$BASE:$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" \
    "$DOCKER_BUNDLE:$SIZE_VERIFIER_VM_DOCKER_STATIC" \
    "$GIT_PACKAGE:$SIZE_VERIFIER_VM_GIT_PACKAGE"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "verifier-VM input is absent or symlinked: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
      "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "verifier-VM input metadata differs: $path"
done
verify_sha512 "$BASE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
verify_sha256 "$DOCKER_BUNDLE" "$SHA256_VERIFIER_VM_DOCKER_STATIC"
verify_sha256 "$GIT_PACKAGE" "$SHA256_VERIFIER_VM_GIT_PACKAGE"
[ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Package)" = git ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Version)" = \
         "$VERIFIER_VM_GIT_PACKAGE_VERSION" ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Architecture)" = amd64 ] \
    || fail 'authenticated verifier-VM Git package identity differs'
/usr/bin/qemu-img check -q "$BASE" || fail 'Debian verifier-VM base failed qcow2 validation'
if [ "$MODE" = hbb-common-fs ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed focused-test input root metadata differs'
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed focused-test input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
elif [ "$MODE" = flutter-model-tests ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed focused-test input root metadata differs'
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$FLUTTER_TEST_ARCHIVE:$SIZE_FLUTTER_3_24_5:$SHA256_FLUTTER_3_24_5" \
        "$LLVM_TEST_ARCHIVE:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed focused-test input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    [ -f "$FRB_CODEGEN" ] && [ ! -L "$FRB_CODEGEN" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$FRB_CODEGEN")" = \
             "$HOST_UID:$HOST_GID:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
        || fail "sealed focused-test executable metadata differs: $FRB_CODEGEN"
    verify_sha256 "$FRB_CODEGEN" "$SHA256_FLUTTER_PEER_FRB_CODEGEN"
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$PUB_CACHE_ROOT" ] && [ ! -L "$PUB_CACHE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$PUB_CACHE_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Pub-cache root metadata differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
fi
/usr/bin/python3 -I -S - "$BASE" <<'PY'
import json
import subprocess
import sys

data = json.loads(
    subprocess.check_output(
        ["/usr/bin/qemu-img", "info", "--output=json", sys.argv[1]],
        text=True,
    )
)
if data.get("format") != "qcow2" or data.get("backing-filename") is not None:
    raise SystemExit("verifier-VM base is not one standalone qcow2 image")
if data.get("virtual-size") != 3 * 1024 * 1024 * 1024:
    raise SystemExit("verifier-VM base virtual size differs")
PY
for source in "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" \
    "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" \
    "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" \
    "$ANDROID_BUILDER_SOURCE" "$ANDROID_BUILDER_CHECKER" \
    "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" \
    "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" \
    "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" \
    "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" \
    "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
    "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" \
    "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" \
    "$WINDOWS_HELPER_RUNTIME_TEST" \
    "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" \
    "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" \
    "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
    "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" \
    "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" \
    "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" \
    "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" \
    "$ANDROID_RUST_SOURCE" "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" \
    "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" \
    "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" \
    "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" \
    "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" \
    "$LIB_SOURCE" "$PIN_SOURCE"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "verifier-VM source is absent or symlinked: $source"
done
[ -x "$GUEST_SCRIPT" ] && [ -x "$ENTRY_PREFLIGHT" ] && [ -x "$VERIFY_SCRIPT" ] \
    && [ -x "$VERIFY_RELEASE_SOURCE" ] \
    && [ -x "$RELEASE_PARENT_SOURCE" ] \
    && [ -x "$RELEASE_PUBLISHER_SOURCE" ] \
    && [ -x "$RELEASE_FINALIZER_SOURCE" ] \
    && [ -x "$RELEASE_WORKSPACE_RUNTIME_TEST" ] \
    && [ -x "$FRB_CODEGEN_SOURCE" ] \
    && [ -x "$FLUTTER_PEER_SOURCE" ] \
    && [ -x "$DART_VERIFY_SOURCE" ] \
    && [ -x "$SMOKE_SERVER_SOURCE" ] \
    && [ -x "$RUST_AUDIT_SOURCE" ] \
    && [ -x "$ANDROID_KEYSTORE_SOURCE" ] \
    && [ -x "$ANDROID_BUILDER_SOURCE" ] \
    && [ -x "$ANDROID_GRADLE_SOURCE" ] \
    && [ -x "$DEBIAN_BUILDER_SOURCE" ] \
    && [ -x "$SYSTEMD_RUNTIME_LIBS_SOURCE" ] \
    && [ -x "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" ] \
    && [ -x "$SYSTEMD_LOGINCTL_SOURCE" ] \
    && [ -x "$ANDROID_RUST_SOURCE" ] \
    && [ -x "$DART_AUDIT_SOURCE" ] \
    && [ -x "$WINDOWS_HELPER_RUNTIME_TEST" ] \
    && [ -x "$CAPTURE_HELPER" ] && [ -x "$CLEANUP_HELPER" ] \
    || fail 'verifier-VM scripts must be executable'
[ -x "$BOOT_DERIVER" ] || fail 'verifier-VM boot deriver must be executable'
[ "$MODE" = authority-smoke ] || [ "$MODE" = debian-systemd-lifecycle ] \
    || [ -x "$VIRTIOFSD_LAUNCHER" ] \
    || fail 'sealed-input virtiofsd launcher must be executable'
VERIFIER_VM_INPUT_ROOT="$INPUT_ROOT" "$BOOT_DERIVER"
[ -d "$BOOT_ROOT" ] && [ ! -L "$BOOT_ROOT" ] \
    || fail 'direct-boot cache is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BOOT_ROOT")" = "$HOST_UID:$HOST_GID:500" ] \
    || fail 'direct-boot cache directory metadata differs'
[ "$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" = xx ] \
    || fail 'direct-boot cache inventory differs'
for input in "$KERNEL:$SIZE_VERIFIER_VM_KERNEL" "$INITRD:$SIZE_VERIFIER_VM_INITRD"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "direct-boot input is absent or symlinked: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
      "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "direct-boot input metadata differs: $path"
done
verify_sha256 "$KERNEL" "$SHA256_VERIFIER_VM_KERNEL"
verify_sha256 "$INITRD" "$SHA256_VERIFIER_VM_INITRD"

HBB_SOURCE_COMMIT=
HBB_SOURCE_TREE=
HBB_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = hbb-common-fs ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Rust tests require the one checked-out master authority'
    HBB_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Rust-test source commit'
    HBB_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Rust-test source tree'
    [ "$HBB_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$HBB_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Rust-test source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Rust tests require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

FLUTTER_SOURCE_COMMIT=
FLUTTER_SOURCE_TREE=
FLUTTER_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = flutter-model-tests ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Flutter tests require the one checked-out master authority'
    FLUTTER_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Flutter-test source commit'
    FLUTTER_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Flutter-test source tree'
    [ "$FLUTTER_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$FLUTTER_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Flutter-test source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Flutter tests require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

LIFECYCLE_ARTIFACT_ID=
DEV_CHECK_ARCHIVE_ID=
if [ "$MODE" = debian-systemd-lifecycle ]; then
    case "$LIFECYCLE_ARTIFACT:$DEV_CHECK_ARCHIVE" in
        /*:/*) ;;
        *) fail 'lifecycle artifact and devcheck archive paths must be absolute' ;;
    esac
    for lifecycle_input in "$LIFECYCLE_ARTIFACT" "$DEV_CHECK_ARCHIVE"; do
        [ -f "$lifecycle_input" ] && [ ! -L "$lifecycle_input" ] \
            || fail "lifecycle input is absent or ambiguous: $lifecycle_input"
        [ "$(/usr/bin/readlink -f -- "$lifecycle_input" 2>/dev/null)" = \
          "$lifecycle_input" ] \
            || fail "lifecycle input path is not canonical: $lifecycle_input"
    done
    [[ "$LIFECYCLE_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'lifecycle artifact SHA-256 is malformed'
    [[ "$LIFECYCLE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'lifecycle source commit is malformed'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'lifecycle artifact is not current-user/current-group mode 0400 with one link'
    [ "$(/usr/bin/sha256sum "$LIFECYCLE_ARTIFACT" | /usr/bin/awk '{ print $1 }')" = \
      "$LIFECYCLE_ARTIFACT_SHA256" ] \
        || fail 'lifecycle artifact digest differs'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$DEV_CHECK_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'devcheck archive metadata differs'
    verify_sha256 "$DEV_CHECK_ARCHIVE" "$SHA256_DEV_CHECK_IMAGE_ARCHIVE"
    [ "$(/usr/bin/dpkg-deb -f "$LIFECYCLE_ARTIFACT" Package 2>/dev/null)" = rustdesk ] \
        || fail 'lifecycle artifact package identity differs'
    [ "$(/usr/bin/dpkg-deb -f "$LIFECYCLE_ARTIFACT" Architecture 2>/dev/null)" = amd64 ] \
        || fail 'lifecycle artifact architecture differs'
    current_commit="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || fail 'cannot resolve lifecycle source commit'
    [ "$current_commit" = "$LIFECYCLE_COMMIT" ] \
        || fail 'lifecycle source does not equal the artifact commit'
    if git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD >/dev/null 2>&1; then
        fail 'lifecycle source must be one detached release snapshot'
    fi
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all 2>/dev/null)" ] \
        || fail 'lifecycle source snapshot is dirty'
    [ -z "$(git_closed -C "$REPO_ROOT" clean -nffdx 2>/dev/null)" ] \
        || fail 'lifecycle source snapshot retains generated state'
    [ "$(/usr/bin/sha256sum "$DEV_CHECK_DOCKERFILE_SOURCE" | /usr/bin/awk '{ print $1 }')" = \
      "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || fail 'current devcheck Dockerfile differs from its reviewed pin'
    historical_devcheck_sha="$(
        git_closed -C "$REPO_ROOT" cat-file blob \
            "$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck" \
            | /usr/bin/sha256sum | /usr/bin/awk '{ print $1 }'
    )" || fail 'cannot read the devcheck Dockerfile from its provenance commit'
    [ "$historical_devcheck_sha" = "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || fail 'devcheck provenance commit has different Dockerfile bytes'
    git_closed -C "$REPO_ROOT" merge-base --is-ancestor \
        "$DEV_CHECK_SOURCE_COMMIT" "$LIFECYCLE_COMMIT" \
        || fail 'devcheck provenance commit is not an ancestor of lifecycle source'
    /usr/bin/python3 -I -S "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
        --repo "$REPO_ROOT" --deb "$LIFECYCLE_ARTIFACT" \
        || fail 'lifecycle artifact failed independent package verification'
    LIFECYCLE_ARTIFACT_ID="$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")"
    DEV_CHECK_ARCHIVE_ID="$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$DEV_CHECK_ARCHIVE")"
fi

RUN="$(/usr/bin/mktemp -d "$RUN_ROOT/run.XXXXXXXXXX")" \
    || fail 'cannot create the private verifier-VM run'
RUN_ID="$(/usr/bin/stat -c '%d:%i' -- "$RUN")"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RUN")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'verifier-VM run is not current-user/current-group mode 0700'
readonly OVERLAY=$RUN/overlay.qcow2
readonly PAYLOAD=$RUN/payload.iso
readonly SEED=$RUN/seed.iso
readonly SERIAL_SOCKET=$RUN/serial.sock
readonly SERIAL_LOG=$RUN/serial.log
readonly CAPTURE_RECEIPT=$RUN/capture.receipt
readonly QMP_SOCKET=$RUN/qmp.sock
readonly QEMU_PIDFILE=$RUN/qemu.pid
readonly LISTENERS_BEFORE=$RUN/listeners.before
readonly LISTENERS_DURING=$RUN/listeners.during
readonly LISTENERS_AFTER=$RUN/listeners.after
readonly NEW_DURING=$RUN/listeners.new-during
readonly NEW_AFTER=$RUN/listeners.new-after
readonly HBB_SOURCE_ARCHIVE=$RUN/source.tar
readonly FLUTTER_SOURCE_ARCHIVE=$RUN/flutter-source.tar
readonly VIRTIOFS_SOCKET=$RUN/vfs-input.sock
readonly VIRTIOFSD_LOG=$RUN/virtiofsd-input.log

base_before="$(/usr/bin/sha512sum "$BASE")"
docker_before="$(/usr/bin/sha256sum "$DOCKER_BUNDLE")"
git_package_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$GIT_PACKAGE"):$(/usr/bin/sha256sum "$GIT_PACKAGE")"
boot_root_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")"
kernel_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")"
initrd_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")"
sources_before="$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" "$ANDROID_BUILDER_SOURCE" "$ANDROID_BUILDER_CHECKER" "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" "$WINDOWS_HELPER_RUNTIME_TEST" "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" "$ANDROID_RUST_SOURCE" "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" "$LIB_SOURCE" "$PIN_SOURCE")"
focused_inputs_before=
if [ "$MODE" = hbb-common-fs ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
elif [ "$MODE" = flutter-model-tests ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
fi
capture_listeners >"$LISTENERS_BEFORE"
/usr/bin/qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "$OVERLAY_SIZE"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OVERLAY")" = "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'pass-private overlay metadata differs'

if [ "$MODE" = hbb-common-fs ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$HBB_SOURCE_COMMIT" \
        >"$HBB_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Rust-test source archive'
    /usr/bin/chmod 0400 "$HBB_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$HBB_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Rust-test source archive metadata differs'
    HBB_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$HBB_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = flutter-model-tests ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$FLUTTER_SOURCE_COMMIT" \
        >"$FLUTTER_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Flutter-test source archive'
    /usr/bin/chmod 0400 "$FLUTTER_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Flutter-test source archive metadata differs'
    FLUTTER_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$FLUTTER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
fi

payload_identity=()
lifecycle_payload_grafts=()
if [ "$MODE" = debian-systemd-lifecycle ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=(
        "devcheck.docker.tar.gz=$DEV_CHECK_ARCHIVE"
        "artifact/rustdesk-x86_64.deb=$LIFECYCLE_ARTIFACT"
    )
elif [ "$MODE" = hbb-common-fs ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$HBB_SOURCE_ARCHIVE")
elif [ "$MODE" = flutter-model-tests ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$FLUTTER_SOURCE_ARCHIVE")
fi
/usr/bin/xorriso -as mkisofs -quiet -iso-level 3 -volid RD_VERIFIER_INPUTS \
    -joliet -rock "${payload_identity[@]}" -graft-points -output "$PAYLOAD" \
    "guest.sh=$GUEST_SCRIPT" \
    "repo/scripts/verify.sh=$VERIFY_SCRIPT" \
    "repo/scripts/verify-release.sh=$VERIFY_RELEASE_SOURCE" \
    "repo/scripts/build-release.sh=$RELEASE_PARENT_SOURCE" \
    "repo/scripts/publish-github-release.sh=$RELEASE_PUBLISHER_SOURCE" \
    "repo/scripts/finalize-release-set.py=$RELEASE_FINALIZER_SOURCE" \
    "repo/scripts/verify-release-workspace-runtime.sh=$RELEASE_WORKSPACE_RUNTIME_TEST" \
    "repo/scripts/fork-version.sh=$FORK_VERSION_SOURCE" \
    "repo/scripts/apple-conform-check.sh=$APPLE_CHECK_SOURCE" \
    "repo/scripts/smoke-flutter-peer-presentation.sh=$FLUTTER_PEER_SOURCE" \
    "repo/scripts/finalize-flutter-tools-offline.sh=$FLUTTER_TOOLS_FINALIZER_SOURCE" \
    "repo/scripts/frb-codegen.sh=$FRB_CODEGEN_SOURCE" \
    "repo/scripts/dart-verify.sh=$DART_VERIFY_SOURCE" \
    "repo/scripts/smoke-server.sh=$SMOKE_SERVER_SOURCE" \
    "repo/scripts/audit.sh=$RUST_AUDIT_SOURCE" \
    "repo/scripts/rust-audit-policy.py=$RUST_AUDIT_POLICY_SOURCE" \
    "repo/scripts/verify-rust-audit-authority.py=$RUST_AUDIT_CHECKER" \
    "repo/scripts/gen-android-keystore.sh=$ANDROID_KEYSTORE_SOURCE" \
    "repo/scripts/android-keystore-generate.sh=$ANDROID_KEYSTORE_INNER" \
    "repo/scripts/verify-android-keystore-authority.py=$ANDROID_KEYSTORE_CHECKER" \
    "repo/scripts/build-android.sh=$ANDROID_BUILDER_SOURCE" \
    "repo/scripts/android-apk-build.sh=$ANDROID_APK_BUILD_SOURCE" \
    "repo/scripts/verify-android-builder-authority.py=$ANDROID_BUILDER_CHECKER" \
    "repo/scripts/test-android-gradle-cache.sh=$ANDROID_GRADLE_SOURCE" \
    "repo/scripts/verify-android-gradle-authority.py=$ANDROID_GRADLE_CHECKER" \
    "repo/scripts/verify-android-builder-image-authority.py=$ANDROID_BUILDER_IMAGE_CHECKER" \
    "repo/scripts/verify-deb-builder-image-authority.py=$DEB_BUILDER_IMAGE_CHECKER" \
    "repo/scripts/build-debian.sh=$DEBIAN_BUILDER_SOURCE" \
    "repo/scripts/verify-debian-builder-authority.py=$DEBIAN_BUILDER_AUTHORITY_CHECKER" \
    "repo/scripts/stage-debian-systemd-runtime-libs.sh=$SYSTEMD_RUNTIME_LIBS_SOURCE" \
    "repo/scripts/smoke-debian-systemd-lifecycle-guest.sh=$SYSTEMD_LIFECYCLE_GUEST_SOURCE" \
    "repo/scripts/smoke-debian-systemd-loginctl.sh=$SYSTEMD_LOGINCTL_SOURCE" \
    "repo/scripts/verify-debian-package-authority.py=$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
    "repo/scripts/verify-win-helper-image-authority.py=$WIN_HELPER_IMAGE_CHECKER" \
    "repo/scripts/verify-windows-helper-authority.py=$WINDOWS_HELPER_AUTHORITY_CHECKER" \
    "repo/scripts/test-windows-helper-vm-runtime.sh=$WINDOWS_HELPER_RUNTIME_TEST" \
    "repo/scripts/Dockerfile.android-builder=$ANDROID_BUILDER_DOCKERFILE" \
    "repo/scripts/Dockerfile.deb-builder=$DEB_BUILDER_DOCKERFILE" \
    "repo/scripts/Dockerfile.win-helper=$WIN_HELPER_DOCKERFILE" \
    "repo/scripts/Dockerfile.builder-bootstrap-seal=$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" \
    "repo/scripts/Dockerfile.android-builder-certify=$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/Dockerfile.deb-builder-certify=$DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/Dockerfile.win-helper-certify=$WIN_HELPER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/windows-helper-runtime.sh=$WINDOWS_HELPER_RUNTIME_SOURCE" \
    "repo/scripts/windows-helper-extract-kernel.py=$WINDOWS_HELPER_EXTRACTOR" \
    "repo/scripts/windows-golden-inspect.sh=$WINDOWS_GOLDEN_INSPECTOR" \
    "repo/scripts/build-windows-vm.sh=$WINDOWS_BUILD_SOURCE" \
    "repo/scripts/provision-windows-vm.sh=$WINDOWS_PROVISION_SOURCE" \
    "repo/scripts/verify-windows-golden.sh=$WINDOWS_GOLDEN_SOURCE" \
    "repo/scripts/android-rust-check.sh=$ANDROID_RUST_SOURCE" \
    "repo/scripts/offline-image-provenance.py=$OFFLINE_IMAGE_PROVENANCE_SOURCE" \
    "repo/scripts/online-fetch.sh=$ONLINE_FETCH_SOURCE" \
    "repo/scripts/dart-audit.sh=$DART_AUDIT_SOURCE" \
    "repo/scripts/dart-audit-result.py=$DART_AUDIT_RESULT_SOURCE" \
    "repo/scripts/verify-dart-verifier-authority.py=$DART_AUTHORITY_CHECKER" \
    "repo/scripts/verify-dart-audit-authority.py=$DART_AUDIT_CHECKER" \
    "repo/scripts/verify-vm-entry-preflight.sh=$ENTRY_PREFLIGHT" \
    "repo/scripts/verify-scan.sh=$VERIFY_SCAN_SOURCE" \
    "repo/scripts/verify-private-tree-closure.py=$CLEANUP_HELPER" \
    "repo/scripts/smoke-verifier-vm-authority.sh=$OUTER_SOURCE" \
    "repo/scripts/smoke-verifier-vm-authority-guest.sh=$GUEST_SCRIPT" \
    "repo/scripts/lib.sh=$LIB_SOURCE" "repo/scripts/pins.env=$PIN_SOURCE" \
    "repo/requirements.html=$REQUIREMENTS_SOURCE" \
    "repo/HARDENING_STATUS.md=$HARDENING_SOURCE" \
    "repo/res/rustdesk.service=$SYSTEMD_UNIT_SOURCE" \
    "repo/scripts/Dockerfile.devcheck=$DEV_CHECK_DOCKERFILE_SOURCE" \
    "docker.tgz=$DOCKER_BUNDLE" \
    "git.deb=$GIT_PACKAGE" \
    "${lifecycle_payload_grafts[@]}"
/usr/bin/chmod 0400 "$PAYLOAD"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$PAYLOAD")" = \
  "$HOST_UID:$HOST_GID:400:1" ] \
    || fail 'read-only payload media metadata differs'
/usr/bin/mkdir "$RUN/seed"
/usr/bin/chmod 0700 "$RUN/seed"
guest_invocation="bash /mnt/rustdesk-verifier-inputs/guest.sh /mnt/rustdesk-verifier-inputs/docker.tgz /mnt/rustdesk-verifier-inputs/repo/scripts/verify-vm-entry-preflight.sh $VERIFIER_VM_DOCKER_VERSION $SIZE_VERIFIER_VM_DOCKER_STATIC $SHA256_VERIFIER_VM_DOCKER_STATIC $VERIFIER_VM_KERNEL_RELEASE $VERIFIER_VM_ROOT_FILESYSTEM_UUID"
if [ "$MODE" = debian-systemd-lifecycle ]; then
    guest_invocation+=" --debian-systemd-lifecycle /mnt/rustdesk-verifier-inputs/devcheck.docker.tar.gz /mnt/rustdesk-verifier-inputs/artifact/rustdesk-x86_64.deb $LIFECYCLE_ARTIFACT_SHA256 $LIFECYCLE_COMMIT"
elif [ "$MODE" = hbb-common-fs ]; then
    guest_invocation+=" --hbb-common-fs /mnt/rustdesk-verifier-inputs/source.tar $HBB_SOURCE_COMMIT $HBB_SOURCE_TREE $HBB_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = flutter-model-tests ]; then
    guest_invocation+=" --flutter-model-tests /mnt/rustdesk-verifier-inputs/source.tar $FLUTTER_SOURCE_COMMIT $FLUTTER_SOURCE_TREE $FLUTTER_SOURCE_ARCHIVE_SHA256"
fi
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'finish() {' \
    '    status=$?' \
    '    trap - EXIT' \
    '    if [ "$status" -eq 0 ]; then' \
    '        echo VERIFIER_VM_CLOUD_INIT=pass' \
    '    else' \
    '        echo VERIFIER_VM_CLOUD_INIT=fail status=$status' \
    '    fi' \
    '    sync' \
    '    systemctl poweroff --no-block || poweroff -f' \
    '    exit "$status"' \
    '}' \
    'trap finish EXIT' \
    'mkdir -p /mnt/rustdesk-verifier-inputs' \
    'mount -L RD_VERIFIER_INPUTS -o ro,nodev,nosuid,noexec /mnt/rustdesk-verifier-inputs' \
    "$guest_invocation" \
    >"$RUN/seed/user-data"
printf '%s\n' \
    'instance-id: rustdesk-verifier-authority-v1' \
    'local-hostname: rustdesk-verifier-authority' \
    >"$RUN/seed/meta-data"
printf '%s\n' 'version: 2' 'ethernets: {}' >"$RUN/seed/network-config"
(
    cd "$RUN/seed"
    /usr/bin/xorriso -as mkisofs -quiet -volid CIDATA -joliet -rock \
        -output "$SEED" user-data meta-data network-config
)
/usr/bin/chmod 0400 "$SEED"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SEED")" = \
  "$HOST_UID:$HOST_GID:400:1" ] \
    || fail 'read-only cloud-init media metadata differs'

exec {KERNEL_FD}<"$KERNEL" || fail 'cannot retain the exact verifier-VM kernel'
exec {INITRD_FD}<"$INITRD" || fail 'cannot retain the exact verifier-VM initramfs'
[ "$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "/proc/$$/fd/$KERNEL_FD")" = \
  "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL")" ] \
    || fail 'retained kernel descriptor identity differs'
[ "$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "/proc/$$/fd/$INITRD_FD")" = \
  "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD")" ] \
    || fail 'retained initramfs descriptor identity differs'
memory_args=(-m "$VM_MEMORY")
focused_qemu_args=()
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = flutter-model-tests ]; then
    start_sealed_input_virtiofsd \
        "$VIRTIOFS_SOCKET" "$VIRTIOFSD_LOG" \
        "$(/usr/bin/stat -c '%d:%i' -- "$ONLINE_INPUTS")"
    focused_qemu_args=(
        -chardev "socket,id=sealed-input,path=$VIRTIOFS_SOCKET"
        -device "vhost-user-fs-pci,chardev=sealed-input,tag=rustdesk-sealed-inputs,queue-size=1024"
    )
    memory_args=(
        -m "$VM_MEMORY"
        -object "memory-backend-memfd,id=mem,size=${VM_MEMORY}M,share=on"
        -numa node,memdev=mem
    )
    capture_listeners >"$LISTENERS_DURING"
    /usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_DURING" \
        || fail 'sealed-input virtiofsd changed the host INET listener inventory'
fi
vm_started_seconds=$SECONDS
/usr/bin/timeout --signal=TERM --kill-after=10s "${VM_TIMEOUT_SECONDS}s" \
    /usr/bin/qemu-system-x86_64 \
        -name rustdesk-verifier-authority \
        -machine q35 \
        -accel kvm \
        -cpu host \
        "${memory_args[@]}" \
        -smp 4 \
        -no-reboot \
        -no-user-config \
        -nodefaults \
        -display none \
        -parallel none \
        -nic none \
        -kernel "/proc/self/fd/$KERNEL_FD" \
        -initrd "/proc/self/fd/$INITRD_FD" \
        -append "root=UUID=$VERIFIER_VM_ROOT_FILESYSTEM_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.verifier_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=ssh.service systemd.mask=ssh.socket" \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
        -pidfile "$QEMU_PIDFILE" \
        -chardev "socket,id=serial0,path=$SERIAL_SOCKET,server=on,wait=on" \
        -device isa-serial,chardev=serial0 \
        -qmp "unix:$QMP_SOCKET,server=on,wait=off" \
        "${focused_qemu_args[@]}" \
        -drive "file=$OVERLAY,if=virtio,format=qcow2,cache=none" \
        -drive "file=$SEED,if=virtio,format=raw,media=cdrom,readonly=on" \
        -drive "file=$PAYLOAD,if=virtio,format=raw,media=cdrom,readonly=on" &
VM_OWNER_PID=$!
VM_OWNER_START="$(process_start_time "$VM_OWNER_PID")" \
    || fail 'cannot record QEMU timeout-owner process identity'

for _ in $(/usr/bin/seq 1 200); do
    [ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] && break
    kill -0 "$VM_OWNER_PID" 2>/dev/null || fail 'QEMU owner exited before creating private channels'
    /usr/bin/sleep 0.05
done
[ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] \
    || fail 'QEMU serial channel and process identity did not become ready'
is_exact_vm_owner_process || fail 'QEMU timeout-owner process identity changed'
verify_private_socket "$SERIAL_SOCKET" \
    || fail 'QEMU serial channel is not one current-user-private Unix socket'
[ -f "$QEMU_PIDFILE" ] && [ ! -L "$QEMU_PIDFILE" ] \
    || fail 'QEMU PID record is absent or symlinked'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$QEMU_PIDFILE")" = \
  "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'QEMU PID record metadata differs'
VM_PID="$(<"$QEMU_PIDFILE")"
[[ "$VM_PID" =~ ^[1-9][0-9]*$ ]] || fail 'QEMU PID file is malformed'
[ "$(/usr/bin/readlink -f "/proc/$VM_PID/exe")" = /usr/bin/qemu-system-x86_64 ] \
    || fail 'QEMU PID does not identify the fixed hypervisor'
VM_START="$(process_start_time "$VM_PID")" || fail 'cannot record QEMU process identity'
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = flutter-model-tests ]; then
    virtiofsd_seccomp_ready=0
    for _ in $(/usr/bin/seq 1 1000); do
        if virtiofsd_seccomp_enforced; then
            virtiofsd_seccomp_ready=1
            break
        fi
        is_exact_virtiofsd_process \
            || { /usr/bin/tail -n 120 "$VIRTIOFSD_LOG" >&2; fail 'sealed-input virtiofsd exited during QEMU startup'; }
        /usr/bin/sleep 0.01
    done
    [ "$virtiofsd_seccomp_ready" -eq 1 ] \
        || { /usr/bin/tail -n 120 "$VIRTIOFSD_LOG" >&2; fail 'sealed-input virtiofsd did not enforce seccomp after QEMU connected'; }
fi

/usr/bin/python3 -I -S "$CAPTURE_HELPER" \
    --socket "$SERIAL_SOCKET" --output "$SERIAL_LOG" --max-bytes "$SERIAL_LIMIT" \
    >"$CAPTURE_RECEIPT" &
CAPTURE_PID=$!
CAPTURE_START="$(process_start_time "$CAPTURE_PID")" \
    || fail 'cannot record bounded serial-capture process identity'
for _ in $(/usr/bin/seq 1 200); do
    [ -S "$QMP_SOCKET" ] && break
    kill -0 "$VM_OWNER_PID" 2>/dev/null || fail 'QEMU owner exited before creating its QMP channel'
    kill -0 "$CAPTURE_PID" 2>/dev/null || fail 'bounded serial capture exited during QEMU startup'
    /usr/bin/sleep 0.05
done
[ -S "$QMP_SOCKET" ] || fail 'QEMU private QMP channel did not become ready'
is_exact_capture_process || fail 'bounded serial-capture process identity changed'
verify_private_socket "$QMP_SOCKET" \
    || fail 'QEMU control channel is not one current-user-private Unix socket'
capture_listeners >"$LISTENERS_DURING"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$NEW_DURING"
[ ! -s "$NEW_DURING" ] || fail 'QEMU created an unexpected host INET listener'
vm_status=0
wait "$VM_OWNER_PID" || vm_status=$?
VM_OWNER_PID=
VM_OWNER_START=
vm_elapsed_seconds=$((SECONDS - vm_started_seconds))
capture_status=0
wait "$CAPTURE_PID" || capture_status=$?
CAPTURE_PID=
CAPTURE_START=
[ "$vm_status" -eq 0 ] || { tail -n 240 "$SERIAL_LOG" >&2; fail "networkless verifier VM exited with status $vm_status"; }
[ "$capture_status" -eq 0 ] || fail "bounded serial capture exited with status $capture_status"
if [ -n "$VIRTIOFSD_PID" ]; then
    for _ in $(/usr/bin/seq 1 1000); do
        [ -r "/proc/$VIRTIOFSD_PID/stat" ] || break
        [ "$(process_start_time "$VIRTIOFSD_PID" 2>/dev/null)" = "$VIRTIOFSD_START" ] \
            || break
        [ "$(/usr/bin/awk '{ print $3 }' "/proc/$VIRTIOFSD_PID/stat" 2>/dev/null)" != Z ] \
            || break
        is_exact_virtiofsd_process \
            || { /usr/bin/tail -n 120 "$VIRTIOFSD_LOG" >&2; fail 'sealed-input virtiofsd executable identity changed'; }
        /usr/bin/sleep 0.01
    done
    is_owned_virtiofsd_generation \
        && { /usr/bin/tail -n 120 "$VIRTIOFSD_LOG" >&2; fail 'sealed-input virtiofsd did not retire after QEMU disconnected'; }
    virtiofsd_status=0
    wait "$VIRTIOFSD_PID" || virtiofsd_status=$?
    [ "$virtiofsd_status" -eq 0 ] \
        || { /usr/bin/tail -n 120 "$VIRTIOFSD_LOG" >&2; fail "sealed-input virtiofsd exited with status $virtiofsd_status"; }
    VIRTIOFSD_PID=
    VIRTIOFSD_START=
fi
grep -Fxq "bounded-unix-stream-capture: PASS bytes=$(stat -c '%s' "$SERIAL_LOG")" "$CAPTURE_RECEIPT" \
    || fail 'bounded serial-capture receipt differs'
if [ -r "/proc/$VM_PID/stat" ] && [ "$(process_start_time "$VM_PID" 2>/dev/null)" = "$VM_START" ]; then
    fail 'exact QEMU process remains after joined VM completion'
fi
capture_listeners >"$LISTENERS_AFTER"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_AFTER" >"$NEW_AFTER"
[ ! -s "$NEW_AFTER" ] || fail 'verifier VM left an unexpected host INET listener'
reconcile_socket "$SERIAL_SOCKET" || fail 'serial channel cleanup is ambiguous'
reconcile_socket "$QMP_SOCKET" || fail 'QMP channel cleanup is ambiguous'
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = flutter-model-tests ]; then
    reconcile_socket "$VIRTIOFS_SOCKET" \
        || fail 'sealed-input virtiofsd channel cleanup is ambiguous'
fi
require_exact_fixed_receipt \
    'VERIFIER_VM_GIT_RUNTIME=pass source=pinned-deb version=2.39.5 root=vm-ephemeral network=none' \
    'authenticated verifier-VM Git runtime marker'

if [ "$MODE" = debian-systemd-lifecycle ]; then
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_NORMAL_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'normal systemd restart marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_STOP_START=pass generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd stop/start marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_CRASH_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36} nrestarts=[1-9][0-9]*' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd crash/restart marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=pass os=debian-12 systemd=252 seat_uid=4001 portable_uid=4000 crash_generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'installed Debian lifecycle marker is absent'; }
    require_exact_fixed_receipt \
        "DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=pass sha256=$LIFECYCLE_ARTIFACT_SHA256 commit=$LIFECYCLE_COMMIT" \
        'exact release-artifact lifecycle marker'
    require_exact_fixed_receipt \
        "VERIFIER_VM_DEBIAN_SYSTEMD_LIFECYCLE=pass artifact_sha256=$LIFECYCLE_ARTIFACT_SHA256 commit=$LIFECYCLE_COMMIT staging_uid=4000 root=refused foreign=refused docker=retired network=none cleanup=joined" \
        'verifier-VM installed-lifecycle marker'
    require_exact_fixed_receipt \
        "VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=$VERIFIER_VM_KERNEL_RELEASE direct_boot=on boot_masks=on docker=$VERIFIER_VM_DOCKER_VERSION vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off lifecycle=installed-debian-artifact" \
        'lifecycle guest authority marker'
elif [ "$MODE" = authority-smoke ]; then
/usr/bin/grep -Fq \
    "VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=$VERIFIER_VM_KERNEL_RELEASE direct_boot=on boot_masks=on docker=$VERIFIER_VM_DOCKER_VERSION vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest authority result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$VERIFIER_VM_DOCKER_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest verifier-entry authority marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused nofile=524544 workspace_fixtures=actual workspace_cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'main verifier exact-entry result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_FRB_ENTRY=pass uid=4000 gid=4000 foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'FRB verifier-VM entry result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_DART_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed frb=chained" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart verifier-VM entry result marker is absent'; }
/usr/bin/grep -Fq \
    'VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'release-parent verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 root=refused foreign=refused network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'release-workspace runtime marker is absent'; }
printf 'VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 root=refused foreign=refused network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Apple-check verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Flutter full-peer verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'server-smoke verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit result-behavior marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit compact source-gate marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit result-behavior marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed identity=untouched" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-keystore verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed identity=untouched\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-keystore compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed source=untouched signing=untouched output=untouched" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-builder verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched signing=untouched output=untouched\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-builder compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DEB_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DEB_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DEBIAN_BUILDER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian builder compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DEBIAN_BUILDER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian builder verifier-VM runtime marker is absent'; }
printf 'VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd runtime-library verifier-VM marker is absent'; }
printf 'VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_WIN_HELPER_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_WIN_HELPER_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_WINDOWS_HELPER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper compact source-gate marker is absent'; }
printf 'VERIFIER_VM_WINDOWS_HELPER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    'WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper runtime marker is absent'; }
printf 'WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined\n'
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android Gradle compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android Gradle verifier-VM runtime marker is absent'; }
printf 'VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    'VERIFIER_VM_OFFLINE_IMAGE_PROVENANCE=pass uid=4000 gid=4000 android_decisions=40 debian_decisions=9 windows_decisions=22' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'offline image-provenance behavior marker is absent'; }
printf 'VERIFIER_VM_OFFLINE_IMAGE_PROVENANCE=pass uid=4000 gid=4000 android_decisions=40 debian_decisions=9 windows_decisions=22\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed source=untouched online=untouched workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-Rust verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched online=untouched workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
mapfile -t dart_frb_source_gate_receipts < <(
    /usr/bin/grep -Eo 'VERIFIER_VM_DART_FRB_SOURCE_GATE=pass mutations=[1-9][0-9]*' "$SERIAL_LOG"
)
[ "${#dart_frb_source_gate_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart/FRB verifier-VM source-gate result marker is absent or duplicated'; }
printf '%s\n' "${dart_frb_source_gate_receipts[0]}"
/usr/bin/grep -Fq 'VERIFIER_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'cloud-init completion marker is absent'; }
elif [ "$MODE" = hbb-common-fs ]; then
    mapfile -t hbb_common_fs_receipts < <(
        /usr/bin/grep -Eo \
            "HBB_COMMON_FS_VM=pass commit=$HBB_SOURCE_COMMIT tree=$HBB_SOURCE_TREE tests=[1-9][0-9]* rust=1\\.75\\.0 vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 builder_index=$DEB_BUILDER_IMAGE_ID builder_runtime=$DEB_BUILDER_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#hbb_common_fs_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'focused hbb_common filesystem test receipt is absent or duplicated'; }
    printf '%s\n' "${hbb_common_fs_receipts[0]}"
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Rust-test cloud-init completion marker'
else
    require_exact_fixed_receipt \
        "FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=$FLUTTER_VERSION lock=$SHA256_FLUTTER_TOOLS_LOCK implicit_pub=prevented" \
        'focused Flutter-tools offline freshness receipt'
    require_exact_fixed_receipt \
        "FLUTTER_MODEL_TESTS_VM=pass commit=$FLUTTER_SOURCE_COMMIT tree=$FLUTTER_SOURCE_TREE suites=12 tests=103 flutter=$FLUTTER_VERSION rust=$RUST_VERSION llvm=$LLVM_VERSION frb=$SHA256_FLUTTER_PEER_FRB_CODEGEN cargo_vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 pub_cache=$SHA256_PUB_CACHE_CLOSURE_V1 builder_index=$DEB_BUILDER_IMAGE_ID builder_runtime=$DEB_BUILDER_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default evidence=generated-bridge-model-tests cleanup=joined" \
        'focused Flutter model-test receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Flutter-test cloud-init completion marker'
fi
[ "$MODE" != debian-systemd-lifecycle ] || /usr/bin/grep -Fq \
    'VERIFIER_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'lifecycle cloud-init completion marker is absent'; }
[ "$(/usr/bin/sha512sum "$BASE")" = "$base_before" ] \
    || fail 'read-only Debian base changed'
[ "$(/usr/bin/sha256sum "$DOCKER_BUNDLE")" = "$docker_before" ] \
    || fail 'read-only Docker bundle changed'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$GIT_PACKAGE"):$(/usr/bin/sha256sum "$GIT_PACKAGE")" = \
  "$git_package_before" ] \
    || fail 'read-only Git package changed'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")" = "$boot_root_before" ] \
    || fail 'direct-boot cache directory changed during execution'
[ "$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" = xx ] \
    || fail 'direct-boot cache inventory changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")" = "$kernel_before" ] \
    || fail 'direct-boot kernel changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")" = "$initrd_before" ] \
    || fail 'direct-boot initramfs changed during execution'
[ "$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" "$ANDROID_BUILDER_SOURCE" "$ANDROID_BUILDER_CHECKER" "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" "$WINDOWS_HELPER_RUNTIME_TEST" "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" "$ANDROID_RUST_SOURCE" "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" "$LIB_SOURCE" "$PIN_SOURCE")" = "$sources_before" ] \
    || fail 'verifier-VM harness source changed during execution'
if [ "$MODE" = hbb-common-fs ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed focused-test inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$HBB_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$HBB_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$HBB_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-test source archive changed during execution'
elif [ "$MODE" = flutter-model-tests ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed focused-test inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$FLUTTER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$FLUTTER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Flutter-test source archive changed during execution'
fi
if [ "$MODE" = debian-systemd-lifecycle ]; then
    [ "$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")" = \
      "$LIFECYCLE_ARTIFACT_ID" ] \
        || fail 'lifecycle artifact identity changed during execution'
    [ "$(/usr/bin/sha256sum "$LIFECYCLE_ARTIFACT" | /usr/bin/awk '{ print $1 }')" = \
      "$LIFECYCLE_ARTIFACT_SHA256" ] \
        || fail 'lifecycle artifact bytes changed during execution'
    [ "$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$DEV_CHECK_ARCHIVE")" = \
      "$DEV_CHECK_ARCHIVE_ID" ] \
        || fail 'devcheck archive identity changed during execution'
    verify_sha256 "$DEV_CHECK_ARCHIVE" "$SHA256_DEV_CHECK_IMAGE_ARCHIVE"
fi

RUN_COMPLETE=1
if [ "$MODE" = authority-smoke ]; then
    printf 'VERIFIER_VM_OUTER_AUTHORITY=pass host_uid=%s network=none boot=direct kernel=sha256 initrd=sha256 channels=unix listeners=unchanged base=sha512 docker=sha256 output_bound=%s cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$SERIAL_LIMIT" "$vm_elapsed_seconds"
elif [ "$MODE" = debian-systemd-lifecycle ]; then
    printf 'VERIFIER_VM_OUTER_AUTHORITY=pass host_uid=%s network=none boot=direct kernel=sha256 initrd=sha256 channels=unix listeners=unchanged base=sha512 docker=sha256 mode=debian-systemd-lifecycle output_bound=%s cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$SERIAL_LIMIT" "$vm_elapsed_seconds"
elif [ "$MODE" = hbb-common-fs ]; then
    printf 'HBB_COMMON_FS_VM_OUTER=pass host_uid=%s commit=%s tree=%s network=none listeners=unchanged inputs=readonly-landlocked docker=guest-only cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$HBB_SOURCE_COMMIT" "$HBB_SOURCE_TREE" "$vm_elapsed_seconds"
else
    printf 'FLUTTER_MODEL_TESTS_VM_OUTER=pass host_uid=%s commit=%s tree=%s network=none listeners=unchanged inputs=readonly-landlocked docker=guest-only evidence=generated-bridge-model-tests cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" "$vm_elapsed_seconds"
fi

#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
[ "$HOST_UID" -ne 0 ] \
    || { echo 'online-fetch VM: host or container-root execution is forbidden' >&2; exit 1; }
[ "$HOST_GID" -ne 0 ] \
    || { echo 'online-fetch VM: a root primary group is forbidden' >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

REQUEST=__full__
MODE=transaction
case "$#:${1:-}" in
    0:) ;;
    1:--self-test-vm-authority)
        MODE=authority-smoke
        REQUEST=__authority_smoke__
        ;;
    1:--rust-test-inputs|1:--flutter-test-inputs|1:--flutter-peer-inputs|1:--android-build-inputs|1:--libvpx-distfiles|1:--wix-nuget-packages|1:--dart-audit-inputs|1:--maintenance-discover-osv-pub-database|1:--maintenance-discover-android-emulator-inputs|1:--maintenance-stage-android-emulator-inputs|1:--maintenance-stage-flutter-presentation-candidate|1:--maintenance-discover-flutter-presentation-pub|\
    1:--maintenance-build-deb-builder-bootstrap-candidate|\
    1:--maintenance-build-android-builder-bootstrap-candidate|\
    1:--maintenance-build-win-helper-bootstrap-candidate|\
    1:--maintenance-promote-deb-builder-bootstrap-candidate|\
    1:--maintenance-promote-android-builder-bootstrap-candidate|\
    1:--maintenance-promote-win-helper-bootstrap-candidate|\
    1:--maintenance-build-deb-builder-certified-candidate|\
    1:--maintenance-promote-deb-builder-certified-candidate|\
    1:--maintenance-build-android-builder-certified-candidate|\
    1:--maintenance-promote-android-builder-certified-candidate|\
    1:--maintenance-build-win-helper-certified-candidate|\
    1:--maintenance-promote-win-helper-certified-candidate|\
    1:--maintenance-discover-devcheck-image|\
    1:--maintenance-build-devcheck-image-candidate|\
    1:--maintenance-promote-devcheck-image-candidate|\
    1:--maintenance-build-apple-check-image-candidate|\
    1:--maintenance-promote-apple-check-image-candidate|\
    1:--maintenance-build-dart-audit-image-candidate|\
    1:--maintenance-promote-dart-audit-image-candidate|\
    1:--maintenance-build-rust-audit-image-candidate|\
    1:--maintenance-promote-rust-audit-image-candidate|\
    1:--devcheck-image|1:--apple-check-image|1:--dart-audit-image|1:--rust-audit-image|\
    1:--maintenance-print-online-closure|1:--maintenance-print-cargo-vendor-candidate|\
    1:--maintenance-reproduce-vcpkg-x64|\
    1:--maintenance-write-online-closure|\
    1:--verify-offline-inputs|1:--debian-systemd-smoke-image)
        REQUEST=$1
        ;;
    *)
        printf 'usage: scripts/online-fetch.sh [--verifier-vm-inputs|--self-test-vm-authority|--rust-test-inputs|--flutter-test-inputs|--flutter-peer-inputs|--android-build-inputs|--libvpx-distfiles|--wix-nuget-packages|--dart-audit-inputs|--maintenance-discover-osv-pub-database|--maintenance-discover-android-emulator-inputs|--maintenance-stage-android-emulator-inputs|--maintenance-stage-flutter-presentation-candidate|--maintenance-discover-flutter-presentation-pub|--maintenance-build-deb-builder-bootstrap-candidate|--maintenance-build-android-builder-bootstrap-candidate|--maintenance-build-win-helper-bootstrap-candidate|--maintenance-promote-deb-builder-bootstrap-candidate|--maintenance-promote-win-helper-bootstrap-candidate|--maintenance-build-deb-builder-certified-candidate|--maintenance-promote-deb-builder-certified-candidate|--maintenance-build-android-builder-certified-candidate|--maintenance-promote-android-builder-certified-candidate|--maintenance-build-win-helper-certified-candidate|--maintenance-promote-win-helper-certified-candidate|--maintenance-discover-devcheck-image|--maintenance-build-devcheck-image-candidate|--maintenance-promote-devcheck-image-candidate|--maintenance-build-apple-check-image-candidate|--maintenance-promote-apple-check-image-candidate|--maintenance-build-dart-audit-image-candidate|--maintenance-promote-dart-audit-image-candidate|--maintenance-build-rust-audit-image-candidate|--maintenance-promote-rust-audit-image-candidate|--maintenance-reproduce-vcpkg-x64|--devcheck-image|--apple-check-image|--dart-audit-image|--rust-audit-image|--maintenance-print-online-closure|--maintenance-print-cargo-vendor-candidate|--maintenance-write-online-closure|--verify-offline-inputs|--debian-systemd-smoke-image]\n' >&2
        exit 2
        ;;
esac
readonly REQUEST MODE

readonly INPUT_ROOT="$REPO_ROOT/.harness-state/verifier-vm"
readonly RUN_ROOT="$INPUT_ROOT/online-fetch-runs"
readonly RECEIPT_ROOT="$INPUT_ROOT/online-fetch-receipts"
readonly IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly BASE="$INPUT_ROOT/$IMAGE_NAME"
readonly DOCKER_BUNDLE="$INPUT_ROOT/docker-${VERIFIER_VM_DOCKER_VERSION}.tgz"
readonly BUILDX_BINARY="$INPUT_ROOT/buildx-v${VERIFIER_VM_BUILDX_VERSION}.linux-amd64"
readonly BUILDKIT_BUNDLE="$INPUT_ROOT/buildkit-v${VERIFIER_VM_BUILDKIT_VERSION}.linux-amd64.tar.gz"
readonly GIT_PACKAGE="$INPUT_ROOT/git_${VERIFIER_VM_GIT_PACKAGE_FILENAME_VERSION}_amd64.deb"
readonly VIRTIOFSD_PACKAGE="$INPUT_ROOT/virtiofsd_${VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION}_amd64.deb"
readonly BOOT_ROOT="$INPUT_ROOT/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"
readonly KERNEL="$BOOT_ROOT/vmlinuz"
readonly INITRD="$BOOT_ROOT/initrd.img"
readonly GUEST_SCRIPT="$SCRIPT_DIR/online-fetch-vm-guest.sh"
readonly ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"
readonly BOOT_DERIVER="$SCRIPT_DIR/derive-verifier-vm-boot-assets.sh"
readonly CAPTURE_HELPER="$SCRIPT_DIR/bounded-unix-stream-capture.py"
readonly CLEANUP_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly VIRTIOFSD_LAUNCHER="$SCRIPT_DIR/launch-landlocked-virtiofsd.py"
readonly SERIAL_LIMIT=16777216
readonly SUCCESS_RECEIPT_LIMIT=65536
if [ "$MODE" = authority-smoke ]; then
    readonly VM_TIMEOUT_SECONDS=180
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=2048
else
    readonly VM_TIMEOUT_SECONDS=43200
    readonly OVERLAY_SIZE=64G
    readonly VM_MEMORY=20480
fi

RUN=
RUN_ID=
VM_OWNER_PID=
VM_OWNER_START=
VM_PID=
VM_START=
CAPTURE_PID=
CAPTURE_START=
VIRTIOFSD_PIDS=()
VIRTIOFSD_STARTS=()
VIRTIOFSD_LOGS=()
VIRTIOFS_SOCKETS=()
VIRTIOFSD_BINARY=
KERNEL_FD=
INITRD_FD=
CACHE_FD=
SYSTEMD_FD=
RESULT_FD=
RUN_COMPLETE=0
RECEIPT_ROOT_ID=
SUCCESS_RECEIPT_TMP=
SUCCESS_RECEIPT_TMP_ID=
SUCCESS_RECEIPT_FINAL=
VM_ELAPSED_SECONDS=

fail() {
    printf 'online-fetch VM: %s\n' "$*" >&2
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
    /usr/bin/awk '{print $22}' "/proc/$pid/stat"
}

is_exact_process() {
    [ "$#" -eq 3 ] || return 1
    local pid=$1 start=$2 executable=$3
    [ -n "$pid" ] && [ -n "$start" ] && [ -r "/proc/$pid/stat" ] \
        && [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$executable" ]
}

terminate_exact_vm() {
    local signal attempt
    is_exact_process "$VM_PID" "$VM_START" /usr/bin/qemu-system-x86_64 || return 0
    for signal in TERM KILL; do
        /usr/bin/kill -"$signal" "$VM_PID" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            is_exact_process "$VM_PID" "$VM_START" /usr/bin/qemu-system-x86_64 || return 0
            /usr/bin/sleep 0.01
        done
    done
    ! is_exact_process "$VM_PID" "$VM_START" /usr/bin/qemu-system-x86_64
}

is_virtiofsd_generation() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2
    [ -n "$pid" ] && [ -n "$start" ] \
        && [ -r "/proc/$pid/stat" ] \
        && [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
        && [ "$(/usr/bin/awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != Z ]
}

terminate_virtiofsd_generation() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2
    local signal attempt
    is_virtiofsd_generation "$pid" "$start" || return 0
    for signal in TERM KILL; do
        /usr/bin/kill -"$signal" "$pid" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            is_virtiofsd_generation "$pid" "$start" || return 0
            /usr/bin/sleep 0.01
        done
    done
    ! is_virtiofsd_generation "$pid" "$start"
}

capture_listeners() {
    /usr/bin/ss -H -lntu | LC_ALL=C /usr/bin/sort -u
}

verify_private_socket() {
    local path=$1 mode
    [ -S "$path" ] && [ ! -L "$path" ] || return 1
    [ "$(/usr/bin/stat -c '%u:%g' -- "$path")" = "$HOST_UID:$HOST_GID" ] || return 1
    mode="$(/usr/bin/stat -c '%a' -- "$path")" || return 1
    [ $((8#$mode & 077)) -eq 0 ]
}

retire_private_socket_path() {
    local path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        verify_private_socket "$path" || return 1
        /usr/bin/rm -- "$path" || return 1
    fi
    [ ! -e "$path" ] && [ ! -L "$path" ]
}

start_virtiofsd() {
    [ "$#" -eq 5 ] || fail 'internal virtiofsd launch argument count differs'
    local authority=$1 shared_dir=$2 shared_identity=$3 socket=$4 log=$5
    local index pid start ready=0 receipt
    /usr/bin/python3 -I -S "$VIRTIOFSD_LAUNCHER" \
        --binary "$VIRTIOFSD_BINARY" \
        --binary-sha256 "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY" \
        --authority "$authority" \
        --shared-dir "$shared_dir" --shared-identity "$shared_identity" \
        --socket "$socket" --uid "$HOST_UID" --gid "$HOST_GID" \
        >"$log" 2>&1 &
    pid=$!
    index=${#VIRTIOFSD_PIDS[@]}
    VIRTIOFSD_PIDS[index]=$pid
    VIRTIOFSD_STARTS[index]=
    VIRTIOFSD_LOGS[index]=$log
    VIRTIOFS_SOCKETS[index]=$socket
    start="$(process_start_time "$pid")" \
        || fail "cannot record the $authority virtiofsd launcher generation"
    VIRTIOFSD_STARTS[index]=$start
    for _ in $(/usr/bin/seq 1 600); do
        if is_exact_process "$pid" "$start" "$VIRTIOFSD_BINARY" \
           && verify_private_socket "$socket" \
           && [ "$(/usr/bin/awk '/^NoNewPrivs:/ {print $2}' "/proc/$pid/status")" = 1 ] \
           && [ "$(/usr/bin/awk '/^Seccomp:/ {print $2}' "/proc/$pid/status")" = 2 ]; then
            ready=1
            break
        fi
        is_virtiofsd_generation "$pid" "$start" || break
        /usr/bin/sleep 0.05
    done
    [ "$ready" -eq 1 ] \
        || { /usr/bin/tail -n 120 "$log" >&2; fail "$authority virtiofsd did not become ready"; }
    [ "$(/usr/bin/awk '/^Uid:/ {print $2":"$3":"$4":"$5}' "/proc/$pid/status")" \
      = "$HOST_UID:$HOST_UID:$HOST_UID:$HOST_UID" ] \
        && [ "$(/usr/bin/awk '/^Gid:/ {print $2":"$3":"$4":"$5}' "/proc/$pid/status")" \
             = "$HOST_GID:$HOST_GID:$HOST_GID:$HOST_GID" ] \
        || fail "$authority virtiofsd process identity differs"
    receipt="$(/usr/bin/grep '^VIRTIOFSD_LANDLOCK=' "$log")" \
        || fail "$authority virtiofsd Landlock enforcement receipt is absent"
    [[ "$receipt" =~ ^VIRTIOFSD_LANDLOCK=pass\ abi=([0-9]+)\ uid=$HOST_UID\ gid=$HOST_GID\ filesystem=$authority-only\ tcp=denied\ socket=prebound\ seccomp=kill$ ]] \
        && [ "${BASH_REMATCH[1]}" -ge 8 ] \
        || fail "$authority virtiofsd Landlock enforcement receipt differs"
}

remove_owned_large_file() {
    local path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$path" 2>/dev/null)" = "$HOST_UID:$HOST_GID:1" ] \
            || return 1
        /usr/bin/rm --force -- "$path"
    fi
}

remove_success_receipt_temporary() {
    if [ -n "$SUCCESS_RECEIPT_TMP" ] \
       && { [ -e "$SUCCESS_RECEIPT_TMP" ] || [ -L "$SUCCESS_RECEIPT_TMP" ]; }; then
        [ -f "$SUCCESS_RECEIPT_TMP" ] && [ ! -L "$SUCCESS_RECEIPT_TMP" ] \
            && [ "$(/usr/bin/stat -c '%d:%i' -- "$SUCCESS_RECEIPT_TMP" 2>/dev/null)" \
                 = "$SUCCESS_RECEIPT_TMP_ID" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$SUCCESS_RECEIPT_TMP" 2>/dev/null)" \
                 = "$HOST_UID:$HOST_GID:1" ] \
            || return 1
        /usr/bin/rm --force -- "$SUCCESS_RECEIPT_TMP" || return 1
    fi
    SUCCESS_RECEIPT_TMP=
    SUCCESS_RECEIPT_TMP_ID=
}

prepare_success_receipt() {
    [ "$#" -eq 1 ] || return 1
    local elapsed_seconds=$1 run_name listener_sha listener_bytes
    local serial_sha serial_bytes capture_sha capture_bytes
    local stdout_sha stdout_bytes stderr_sha stderr_bytes capture_line
    local guest_line entry_line buildx_line runtime_line outer_line
    run_name=${RUN##*/}
    [[ "$run_name" =~ ^run\.[A-Za-z0-9]{10}$ ]] || return 1
    [ -d "$RECEIPT_ROOT" ] && [ ! -L "$RECEIPT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$RECEIPT_ROOT")" = "$RECEIPT_ROOT_ID" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RECEIPT_ROOT")" \
             = "$HOST_UID:$HOST_GID:700" ] \
        || return 1
    SUCCESS_RECEIPT_FINAL="$RECEIPT_ROOT/$run_name.receipt"
    [ ! -e "$SUCCESS_RECEIPT_FINAL" ] && [ ! -L "$SUCCESS_RECEIPT_FINAL" ] \
        || return 1
    SUCCESS_RECEIPT_TMP="$(/usr/bin/mktemp "$RECEIPT_ROOT/.receipt.XXXXXXXXXX")" \
        || return 1
    SUCCESS_RECEIPT_TMP_ID="$(/usr/bin/stat -c '%d:%i' -- "$SUCCESS_RECEIPT_TMP")" \
        || return 1
    listener_sha="$(/usr/bin/sha256sum "$LISTENERS_BEFORE" | /usr/bin/awk '{print $1}')" \
        || return 1
    listener_bytes="$(/usr/bin/stat -c '%s' -- "$LISTENERS_BEFORE")" || return 1
    serial_sha="$(/usr/bin/sha256sum "$SERIAL_LOG" | /usr/bin/awk '{print $1}')" \
        || return 1
    serial_bytes="$(/usr/bin/stat -c '%s' -- "$SERIAL_LOG")" || return 1
    capture_sha="$(/usr/bin/sha256sum "$CAPTURE_RECEIPT" | /usr/bin/awk '{print $1}')" \
        || return 1
    capture_bytes="$(/usr/bin/stat -c '%s' -- "$CAPTURE_RECEIPT")" || return 1
    stdout_sha="$(/usr/bin/sha256sum "$RESULT_EXPORT/transaction.stdout" | /usr/bin/awk '{print $1}')" \
        || return 1
    stdout_bytes="$(/usr/bin/stat -c '%s' -- "$RESULT_EXPORT/transaction.stdout")" \
        || return 1
    stderr_sha="$(/usr/bin/sha256sum "$RESULT_EXPORT/transaction.stderr" | /usr/bin/awk '{print $1}')" \
        || return 1
    stderr_bytes="$(/usr/bin/stat -c '%s' -- "$RESULT_EXPORT/transaction.stderr")" \
        || return 1
    capture_line="bounded-unix-stream-capture: PASS bytes=$serial_bytes"
    guest_line="ONLINE_FETCH_VM_GUEST=pass uid=$HOST_UID gid=$HOST_GID source=$SOURCE_COMMIT network=qemu-user-only hostfwd=absent udp=denied docker=guest-unix image_store=containerd buildkit=guest-unix git=pinned-deb cache=virtiofs-atomic nofile=524544 result=16MiB cleanup=joined"
    entry_line="ONLINE_FETCH_VM_ENTRY_AUTHORITY=pass uid=$HOST_UID gid=$HOST_GID source=$SOURCE_COMMIT network=qemu-user-only udp=denied docker=guest-unix image_store=containerd buildkit=guest-unix git=pinned-deb cache=virtiofs-atomic"
    buildx_line="ONLINE_FETCH_BUILDX_AUTHORITY=pass version=$VERIFIER_VM_BUILDX_VERSION commit=$VERIFIER_VM_BUILDX_COMMIT plugin=private driver=remote buildkit=$VERIFIER_VM_BUILDKIT_VERSION endpoint=guest-unix network=bridge snapshotter=overlayfs process_sandbox=enabled builder=rustdesk-online-fetch managed_container=absent image_store=separate"
    runtime_line=not-applicable
    if [ "$MODE" = authority-smoke ]; then
        runtime_line="ONLINE_FETCH_VM_RUNTIME=pass network=qemu-user-only hostfwd=absent udp=denied docker=guest-bridge git=pinned-deb inner_uid=$HOST_UID https=sha256 cache=virtiofs-atomic cleanup=joined"
    fi
    outer_line="ONLINE_FETCH_VM_OUTER=pass host_uid=$HOST_UID source=$SOURCE_COMMIT network=qemu-user-only hostfwd=absent udp=denied listeners=unchanged docker=guest-only buildkit=guest-only git=pinned-deb cache=virtiofs-atomic cleanup=joined elapsed_seconds=$elapsed_seconds receipt=$SUCCESS_RECEIPT_FINAL"
    {
        /usr/bin/printf '%s\n' \
            'format=rustdesk-online-fetch-success-v2' \
            "run=$run_name" \
            "run_identity=$RUN_ID" \
            "request=$REQUEST" \
            "mode=$MODE" \
            "host_uid=$HOST_UID" \
            "host_gid=$HOST_GID" \
            "source_commit=$SOURCE_COMMIT" \
            "source_tree=$SOURCE_TREE" \
            "source_bundle_sha256=$SOURCE_BUNDLE_SHA256" \
            "elapsed_seconds=$elapsed_seconds" \
            "listener_inventory_sha256=$listener_sha" \
            "listener_inventory_bytes=$listener_bytes" \
            "serial_sha256=$serial_sha" \
            "serial_bytes=$serial_bytes" \
            "capture_receipt_sha256=$capture_sha" \
            "capture_receipt_bytes=$capture_bytes" \
            "transaction_stdout_sha256=$stdout_sha" \
            "transaction_stdout_bytes=$stdout_bytes" \
            "transaction_stderr_sha256=$stderr_sha" \
            "transaction_stderr_bytes=$stderr_bytes" \
            "capture_receipt=$capture_line" \
            "guest_receipt=$guest_line" \
            'cloud_init_receipt=ONLINE_FETCH_VM_CLOUD_INIT=pass' \
            "entry_receipt=$entry_line" \
            "buildx_receipt=$buildx_line" \
            "runtime_receipt=$runtime_line" \
            "outer_receipt=$outer_line"
    } >"$SUCCESS_RECEIPT_TMP" || return 1
    /usr/bin/chmod 0400 -- "$SUCCESS_RECEIPT_TMP" || return 1
    [ "$(/usr/bin/stat -c '%d:%i' -- "$SUCCESS_RECEIPT_TMP")" \
      = "$SUCCESS_RECEIPT_TMP_ID" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SUCCESS_RECEIPT_TMP")" \
             = "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/stat -c '%s' -- "$SUCCESS_RECEIPT_TMP")" \
             -le "$SUCCESS_RECEIPT_LIMIT" ]
}

publish_success_receipt() {
    [ -n "$SUCCESS_RECEIPT_TMP" ] && [ -n "$SUCCESS_RECEIPT_FINAL" ] \
        && [ -f "$SUCCESS_RECEIPT_TMP" ] && [ ! -L "$SUCCESS_RECEIPT_TMP" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$SUCCESS_RECEIPT_TMP")" \
             = "$SUCCESS_RECEIPT_TMP_ID" ] \
        && [ ! -e "$SUCCESS_RECEIPT_FINAL" ] && [ ! -L "$SUCCESS_RECEIPT_FINAL" ] \
        || return 1
    /usr/bin/mv -T --no-clobber -- "$SUCCESS_RECEIPT_TMP" "$SUCCESS_RECEIPT_FINAL" \
        || return 1
    [ ! -e "$SUCCESS_RECEIPT_TMP" ] && [ ! -L "$SUCCESS_RECEIPT_TMP" ] \
        && [ -f "$SUCCESS_RECEIPT_FINAL" ] && [ ! -L "$SUCCESS_RECEIPT_FINAL" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$SUCCESS_RECEIPT_FINAL")" \
             = "$SUCCESS_RECEIPT_TMP_ID" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SUCCESS_RECEIPT_FINAL")" \
             = "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/stat -c '%s' -- "$SUCCESS_RECEIPT_FINAL")" \
             -le "$SUCCESS_RECEIPT_LIMIT" ] \
        || return 1
    SUCCESS_RECEIPT_TMP=
    SUCCESS_RECEIPT_TMP_ID=
}

cleanup() {
    local status=$? cleanup_failed=0 index pid start publish_ready=0
    trap - EXIT HUP INT TERM
    if [ -n "$VM_OWNER_PID" ]; then
        if is_exact_process "$VM_OWNER_PID" "$VM_OWNER_START" /usr/bin/timeout; then
            /usr/bin/kill -TERM "$VM_OWNER_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$VM_OWNER_PID" 2>/dev/null || true
        VM_OWNER_PID=
        VM_OWNER_START=
    fi
    terminate_exact_vm || cleanup_failed=1
    VM_PID=
    VM_START=
    for index in "${!VIRTIOFSD_PIDS[@]}"; do
        pid=${VIRTIOFSD_PIDS[index]}
        start=${VIRTIOFSD_STARTS[index]}
        if [ -n "$pid" ]; then
            terminate_virtiofsd_generation "$pid" "$start" || cleanup_failed=1
            wait "$pid" 2>/dev/null || true
        fi
    done
    VIRTIOFSD_PIDS=()
    VIRTIOFSD_STARTS=()
    if [ -n "$CAPTURE_PID" ]; then
        if is_exact_process "$CAPTURE_PID" "$CAPTURE_START" "$(/usr/bin/readlink -f /usr/bin/python3)"; then
            /usr/bin/kill -TERM "$CAPTURE_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=
        CAPTURE_START=
    fi
    if [ -n "$KERNEL_FD" ]; then exec {KERNEL_FD}<&- || cleanup_failed=1; KERNEL_FD=; fi
    if [ -n "$INITRD_FD" ]; then exec {INITRD_FD}<&- || cleanup_failed=1; INITRD_FD=; fi
    if [ -n "$CACHE_FD" ]; then exec {CACHE_FD}<&- || cleanup_failed=1; CACHE_FD=; fi
    if [ -n "$SYSTEMD_FD" ]; then exec {SYSTEMD_FD}<&- || cleanup_failed=1; SYSTEMD_FD=; fi
    if [ -n "$RESULT_FD" ]; then exec {RESULT_FD}<&- || cleanup_failed=1; RESULT_FD=; fi
    if [ -n "$RUN" ] && [ -d "$RUN" ] && [ ! -L "$RUN" ] \
       && [ "$(/usr/bin/stat -c '%d:%i' -- "$RUN" 2>/dev/null)" = "$RUN_ID" ]; then
        for socket in "$RUN/serial.sock" "$RUN/vfs-c.sock" \
            "$RUN/vfs-s.sock" "$RUN/vfs-r.sock"; do
            retire_private_socket_path "$socket" || cleanup_failed=1
        done
        if [ "$RUN_COMPLETE" -eq 1 ] && [ "$status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
            if [ -n "$SUCCESS_RECEIPT_TMP" ] \
               && [ ! -e "$SUCCESS_RECEIPT_FINAL" ] && [ ! -L "$SUCCESS_RECEIPT_FINAL" ] \
               && /usr/bin/python3 -I -S "$CLEANUP_HELPER" \
                    --remove-private-root "$RUN" --expected-identity "$RUN_ID"; then
                publish_ready=1
            else
                cleanup_failed=1
            fi
        else
            for large in "$RUN/overlay.qcow2" "$RUN/payload.iso" "$RUN/seed.iso" \
                "$RUN/source.bundle"; do
                remove_owned_large_file "$large" || cleanup_failed=1
            done
            printf 'online-fetch VM: retained bounded failure evidence at %s\n' "$RUN" >&2
        fi
    elif [ -n "$RUN" ]; then
        cleanup_failed=1
    fi
    if [ "$publish_ready" -eq 1 ]; then
        publish_success_receipt || cleanup_failed=1
    fi
    if [ -n "$SUCCESS_RECEIPT_TMP" ]; then
        remove_success_receipt_temporary || cleanup_failed=1
    fi
    if [ "$RUN_COMPLETE" -eq 1 ] && [ "$status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
        /usr/bin/printf 'ONLINE_FETCH_VM_OUTER=pass host_uid=%s source=%s network=qemu-user-only hostfwd=absent udp=denied listeners=unchanged docker=guest-only buildkit=guest-only git=pinned-deb cache=virtiofs-atomic cleanup=joined elapsed_seconds=%s receipt=%s\n' \
            "$HOST_UID" "$SOURCE_COMMIT" "$VM_ELAPSED_SECONDS" "$SUCCESS_RECEIPT_FINAL"
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ -z "${RUSTDESK_ONLINE_FETCH_VM_GUEST+x}" ] \
    || fail 'guest authority environment is reserved for the disposable VM'
[ "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" = Linux:x86_64 ] \
    || fail 'online acquisition VM requires a Linux x86_64 orchestration host'
for tool in /usr/bin/awk /usr/bin/chmod /usr/bin/cmp /usr/bin/comm /usr/bin/dpkg-deb /usr/bin/find /usr/bin/findmnt /usr/bin/git \
    /usr/bin/grep /usr/bin/id /usr/bin/install /usr/bin/mkdir /usr/bin/mktemp \
    /usr/bin/mv /usr/bin/python3 /usr/bin/qemu-img /usr/bin/qemu-system-x86_64 \
    /usr/bin/readlink /usr/bin/rm /usr/bin/seq /usr/bin/sha256sum \
    /usr/bin/sha512sum /usr/bin/sleep /usr/bin/sort /usr/bin/ss /usr/bin/stat \
    /usr/bin/tail /usr/bin/timeout /usr/bin/uname /usr/bin/xorriso; do
    resolved="$(/usr/bin/readlink -f -- "$tool" 2>/dev/null)" \
        || fail "cannot resolve fixed host orchestration tool: $tool"
    [ -f "$resolved" ] && [ ! -L "$resolved" ] && [ -x "$resolved" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$resolved")" = 0:0:755:1 ] \
        || fail "fixed host orchestration tool metadata changed: $tool"
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || fail '/dev/kvm is unavailable to the invoking non-root user'
[ -d "$INPUT_ROOT" ] && [ ! -L "$INPUT_ROOT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$INPUT_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'authenticated VM inputs are absent; run scripts/online-fetch.sh --verifier-vm-inputs'
for input in "$BASE:$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" \
    "$DOCKER_BUNDLE:$SIZE_VERIFIER_VM_DOCKER_STATIC" \
    "$BUILDX_BINARY:$SIZE_VERIFIER_VM_BUILDX" \
    "$BUILDKIT_BUNDLE:$SIZE_VERIFIER_VM_BUILDKIT" \
    "$GIT_PACKAGE:$SIZE_VERIFIER_VM_GIT_PACKAGE" \
    "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
             "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "authenticated VM input metadata differs: $path"
done
verify_sha512 "$BASE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
verify_sha256 "$DOCKER_BUNDLE" "$SHA256_VERIFIER_VM_DOCKER_STATIC"
verify_sha256 "$BUILDX_BINARY" "$SHA256_VERIFIER_VM_BUILDX"
verify_sha256 "$BUILDKIT_BUNDLE" "$SHA256_VERIFIER_VM_BUILDKIT"
verify_sha256 "$GIT_PACKAGE" "$SHA256_VERIFIER_VM_GIT_PACKAGE"
verify_sha256 "$VIRTIOFSD_PACKAGE" "$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"
verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
[ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Package)" = git ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Version)" \
         = "$VERIFIER_VM_GIT_PACKAGE_VERSION" ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Architecture)" = amd64 ] \
    || fail 'authenticated Git package identity differs'
[ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
    && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" \
         = "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
    && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
    || fail 'authenticated virtiofsd package identity differs'
/usr/bin/qemu-img check -q "$BASE" || fail 'Debian acquisition-VM base failed qcow2 validation'
for source in "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$BOOT_DERIVER" \
    "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" \
    "$SCRIPT_DIR/discover-android-emulator-inputs.py" \
    "$SCRIPT_DIR/verify-online-fetch-virtiofs-rename.py"; do
    [ -f "$source" ] && [ ! -L "$source" ] || fail "VM source is absent or ambiguous: $source"
done
[ -x "$GUEST_SCRIPT" ] && [ -x "$ENTRY_PREFLIGHT" ] && [ -x "$BOOT_DERIVER" ] \
    && [ -x "$CAPTURE_HELPER" ] && [ -x "$CLEANUP_HELPER" ] \
    && [ -x "$VIRTIOFSD_LAUNCHER" ] \
    && [ -x "$SCRIPT_DIR/verify-online-fetch-virtiofs-rename.py" ] \
    || fail 'VM entry scripts must be executable'
VERIFIER_VM_INPUT_ROOT="$INPUT_ROOT" "$BOOT_DERIVER"
for input in "$KERNEL:$SIZE_VERIFIER_VM_KERNEL" "$INITRD:$SIZE_VERIFIER_VM_INITRD"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
             "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "authenticated direct-boot input metadata differs: $path"
done
verify_sha256 "$KERNEL" "$SHA256_VERIFIER_VM_KERNEL"
verify_sha256 "$INITRD" "$SHA256_VERIFIER_VM_INITRD"

[ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
    || fail 'online acquisition requires the one checked-out master authority'
SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
    || fail 'cannot resolve the acquisition source commit'
SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
    || fail 'cannot resolve the acquisition source tree'
[ "$SOURCE_COMMIT" = "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
    || fail 'checked-out source differs from master'
[ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
    || fail 'online acquisition requires a clean source tree'
[ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
    || fail 'Git replacement refs are forbidden'

if [ -e "$RUN_ROOT" ] || [ -L "$RUN_ROOT" ]; then
    [ -d "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RUN_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail 'online-fetch VM run root metadata differs'
else
    /usr/bin/install -d -m 0700 -- "$RUN_ROOT"
fi
if [ -e "$RECEIPT_ROOT" ] || [ -L "$RECEIPT_ROOT" ]; then
    [ -d "$RECEIPT_ROOT" ] && [ ! -L "$RECEIPT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RECEIPT_ROOT")" \
             = "$HOST_UID:$HOST_GID:700" ] \
        || fail 'online-fetch VM receipt root metadata differs'
else
    /usr/bin/install -d -m 0700 -- "$RECEIPT_ROOT"
fi
RECEIPT_ROOT_ID="$(/usr/bin/stat -c '%d:%i' -- "$RECEIPT_ROOT")"
RUN="$(/usr/bin/mktemp -d "$RUN_ROOT/run.XXXXXXXXXX")" \
    || fail 'cannot create the private online-fetch VM run'
RUN_ID="$(/usr/bin/stat -c '%d:%i' -- "$RUN")"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RUN")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'online-fetch VM run metadata differs'

readonly OVERLAY=$RUN/overlay.qcow2
readonly PAYLOAD=$RUN/payload.iso
readonly SEED=$RUN/seed.iso
readonly SOURCE_BUNDLE=$RUN/source.bundle
readonly REQUEST_FILE=$RUN/request
readonly SOURCE_TREE_FILE=$RUN/source.tree
readonly SOURCE_BUNDLE_SHA_FILE=$RUN/source.bundle.sha256
readonly SERIAL_SOCKET=$RUN/serial.sock
readonly CACHE_VIRTIOFS_SOCKET=$RUN/vfs-c.sock
readonly SYSTEMD_VIRTIOFS_SOCKET=$RUN/vfs-s.sock
readonly RESULT_VIRTIOFS_SOCKET=$RUN/vfs-r.sock
readonly CACHE_VIRTIOFSD_LOG=$RUN/virtiofsd-cache.log
readonly SYSTEMD_VIRTIOFSD_LOG=$RUN/virtiofsd-systemd.log
readonly RESULT_VIRTIOFSD_LOG=$RUN/virtiofsd-result.log
readonly SERIAL_LOG=$RUN/serial.log
readonly CAPTURE_RECEIPT=$RUN/capture.receipt
readonly QEMU_PIDFILE=$RUN/qemu.pid
readonly LISTENERS_BEFORE=$RUN/listeners.before
readonly LISTENERS_DURING=$RUN/listeners.during
readonly LISTENERS_DURING_DETAIL=$RUN/listeners.during.detail
readonly LISTENERS_AFTER=$RUN/listeners.after
readonly NEW_DURING=$RUN/listeners.new-during
readonly NEW_AFTER=$RUN/listeners.new-after
readonly RESULT_EXPORT=$RUN/result

if [ "$MODE" = authority-smoke ]; then
    CACHE_EXPORT=$RUN/cache
    SYSTEMD_EXPORT=$RUN/systemd
else
    CACHE_EXPORT=$REPO_ROOT/online
    SYSTEMD_EXPORT=$REPO_ROOT/.harness-state/debian-systemd-smoke
fi
for export_root in "$CACHE_EXPORT" "$SYSTEMD_EXPORT" "$RESULT_EXPORT"; do
    if [ -e "$export_root" ] || [ -L "$export_root" ]; then
        [ -d "$export_root" ] && [ ! -L "$export_root" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$export_root")" = "$HOST_UID:$HOST_GID:700" ] \
            || fail "writable export root metadata differs: $export_root"
    else
        /usr/bin/install -d -m 0700 -- "$export_root"
    fi
done
cache_child="$CACHE_EXPORT/inputs"
if [ -e "$cache_child" ] || [ -L "$cache_child" ]; then
    [ -d "$cache_child" ] && [ ! -L "$cache_child" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$cache_child")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail "cache-state child metadata differs: $cache_child"
else
    /usr/bin/install -d -m 0700 -- "$cache_child"
fi
RETIRED_EXPORT_ID=
CANDIDATE_EXPORT_ID=
if [ "$MODE" = authority-smoke ]; then
    cache_child="$CACHE_EXPORT/retired"
    if [ -e "$cache_child" ] || [ -L "$cache_child" ]; then
        [ -d "$cache_child" ] && [ ! -L "$cache_child" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$cache_child")" = "$HOST_UID:$HOST_GID:700" ] \
            || fail "cache-state child metadata differs: $cache_child"
    else
        /usr/bin/install -d -m 0700 -- "$cache_child"
    fi
    RETIRED_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$cache_child")"
elif [ -e "$CACHE_EXPORT/retired" ] || [ -L "$CACHE_EXPORT/retired" ]; then
    [ -d "$CACHE_EXPORT/retired" ] && [ ! -L "$CACHE_EXPORT/retired" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CACHE_EXPORT/retired")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail "cache-state child metadata differs: $CACHE_EXPORT/retired"
    RETIRED_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$CACHE_EXPORT/retired")"
fi
if [ "$MODE" != authority-smoke ]; then
    cache_child="$CACHE_EXPORT/candidates"
    if [ "$REQUEST" = --maintenance-stage-flutter-presentation-candidate ] \
       || [ "$REQUEST" = --maintenance-stage-android-emulator-inputs ] \
       || [ "$REQUEST" = --maintenance-discover-flutter-presentation-pub ] \
       || [ -e "$cache_child" ] || [ -L "$cache_child" ]; then
        if [ -e "$cache_child" ] || [ -L "$cache_child" ]; then
            [ -d "$cache_child" ] && [ ! -L "$cache_child" ] \
                && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$cache_child")" = "$HOST_UID:$HOST_GID:700" ] \
                || fail "cache-state child metadata differs: $cache_child"
        else
            /usr/bin/install -d -m 0700 -- "$cache_child"
        fi
        CANDIDATE_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$cache_child")"
    fi
fi
cache_inventory="$(
    /usr/bin/find "$CACHE_EXPORT" -mindepth 1 -maxdepth 1 -printf '%f\n' \
        | LC_ALL=C /usr/bin/sort
)"
if [ "$MODE" = authority-smoke ]; then
    [ "$cache_inventory" = $'inputs\nretired' ] \
        || fail 'focused cache state root differs from the inputs/retired layout'
else
    case "$cache_inventory" in
        inputs|$'candidates\ninputs'|$'inputs\nretired'|$'candidates\ninputs\nretired') ;;
        *) fail 'cache state root contains something other than inputs, candidates, and its optional retired transaction root' ;;
    esac
fi
[ "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT")" \
  = "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT/inputs")" ] \
    || fail 'host cache state and active-input roots do not share one filesystem'
if [ -n "$RETIRED_EXPORT_ID" ]; then
    [ "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT/inputs")" \
      = "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT/retired")" ] \
        || fail 'host active and retired cache roots do not share one filesystem'
fi
if [ -n "$CANDIDATE_EXPORT_ID" ]; then
    [ "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT/inputs")" \
      = "$(/usr/bin/stat -c '%d' -- "$CACHE_EXPORT/candidates")" ] \
        || fail 'host active and candidate cache roots do not share one filesystem'
fi
[ -z "$(/usr/bin/findmnt -rn -o TARGET --submounts "$CACHE_EXPORT")" ] \
    || fail 'cache state root contains a descendant mount'
CACHE_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$CACHE_EXPORT")"
ONLINE_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$CACHE_EXPORT/inputs")"
SYSTEMD_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$SYSTEMD_EXPORT")"
RESULT_EXPORT_ID="$(/usr/bin/stat -c '%d:%i' -- "$RESULT_EXPORT")"

git_closed -C "$REPO_ROOT" bundle create "$SOURCE_BUNDLE" refs/heads/master \
    || fail 'cannot create the exact committed acquisition source bundle'
git_closed -C "$REPO_ROOT" bundle verify "$SOURCE_BUNDLE" >/dev/null \
    || fail 'acquisition source bundle verification failed'
/usr/bin/chmod 0400 "$SOURCE_BUNDLE"
SOURCE_BUNDLE_SHA256="$(/usr/bin/sha256sum "$SOURCE_BUNDLE" | /usr/bin/awk '{print $1}')"
/usr/bin/printf '%s\n' "$REQUEST" >"$REQUEST_FILE"
/usr/bin/printf '%s\n' "$SOURCE_TREE" >"$SOURCE_TREE_FILE"
/usr/bin/printf '%s\n' "$SOURCE_BUNDLE_SHA256" >"$SOURCE_BUNDLE_SHA_FILE"
/usr/bin/chmod 0400 "$REQUEST_FILE" "$SOURCE_TREE_FILE" "$SOURCE_BUNDLE_SHA_FILE"
/usr/bin/qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "$OVERLAY_SIZE"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OVERLAY")" = "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'pass-private acquisition overlay metadata differs'
/usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
/usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
    || fail 'cannot extract the authenticated virtiofsd package privately'
VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
[ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" \
         = "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
    || fail 'extracted virtiofsd binary is absent or ambiguous'
/usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"

base_before="$(/usr/bin/sha512sum "$BASE")"
docker_before="$(/usr/bin/sha256sum "$DOCKER_BUNDLE")"
buildx_before="$(/usr/bin/sha256sum "$BUILDX_BINARY")"
buildkit_before="$(/usr/bin/sha256sum "$BUILDKIT_BUNDLE")"
git_package_before="$(/usr/bin/sha256sum "$GIT_PACKAGE")"
virtiofsd_package_before="$(/usr/bin/sha512sum "$VIRTIOFSD_PACKAGE")"
kernel_before="$(/usr/bin/sha256sum "$KERNEL")"
initrd_before="$(/usr/bin/sha256sum "$INITRD")"
source_before="$SOURCE_COMMIT:$SOURCE_TREE:$(/usr/bin/sha256sum "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$SCRIPT_DIR/online-fetch.sh" "$SCRIPT_DIR/online-fetch-vm.sh" "$VIRTIOFSD_LAUNCHER" "$SCRIPT_DIR/discover-android-emulator-inputs.py" "$SCRIPT_DIR/verify-online-fetch-virtiofs-rename.py")"
capture_listeners >"$LISTENERS_BEFORE"

/usr/bin/xorriso -as mkisofs -quiet -iso-level 3 -volid RD_ONLINE_FETCH \
    -joliet -rock -graft-points -output "$PAYLOAD" \
    "guest.sh=$GUEST_SCRIPT" "docker.tgz=$DOCKER_BUNDLE" \
    "docker-buildx=$BUILDX_BINARY" "buildkit.tgz=$BUILDKIT_BUNDLE" \
    "git.deb=$GIT_PACKAGE" \
    "source.bundle=$SOURCE_BUNDLE" "request=$REQUEST_FILE" \
    "source.tree=$SOURCE_TREE_FILE" \
    "source.bundle.sha256=$SOURCE_BUNDLE_SHA_FILE"
/usr/bin/chmod 0400 "$PAYLOAD"
/usr/bin/mkdir "$RUN/seed"
/usr/bin/chmod 0700 "$RUN/seed"
guest_invocation="bash /mnt/rustdesk-online-fetch-inputs/guest.sh /mnt/rustdesk-online-fetch-inputs/docker.tgz /mnt/rustdesk-online-fetch-inputs/docker-buildx /mnt/rustdesk-online-fetch-inputs/buildkit.tgz /mnt/rustdesk-online-fetch-inputs/source.bundle /mnt/rustdesk-online-fetch-inputs/git.deb $VERIFIER_VM_DOCKER_VERSION $SIZE_VERIFIER_VM_DOCKER_STATIC $SHA256_VERIFIER_VM_DOCKER_STATIC $VERIFIER_VM_BUILDX_VERSION $VERIFIER_VM_BUILDX_COMMIT $SIZE_VERIFIER_VM_BUILDX $SHA256_VERIFIER_VM_BUILDX $VERIFIER_VM_BUILDKIT_VERSION $VERIFIER_VM_BUILDKIT_COMMIT $SIZE_VERIFIER_VM_BUILDKIT $SHA256_VERIFIER_VM_BUILDKIT $VERIFIER_VM_GIT_PACKAGE_VERSION $SIZE_VERIFIER_VM_GIT_PACKAGE $SHA256_VERIFIER_VM_GIT_PACKAGE $SIZE_VERIFIER_VM_GIT_BINARY $SHA256_VERIFIER_VM_GIT_BINARY $VERIFIER_VM_KERNEL_RELEASE $VERIFIER_VM_ROOT_FILESYSTEM_UUID $HOST_UID $HOST_GID $SOURCE_COMMIT"
/usr/bin/printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'finish() {' \
    '    status=$?' \
    '    trap - EXIT' \
    '    if [ "$status" -eq 0 ]; then' \
    '        echo ONLINE_FETCH_VM_CLOUD_INIT=pass' \
    '    else' \
    '        echo ONLINE_FETCH_VM_CLOUD_INIT=fail status=$status' \
    '    fi' \
    '    sync' \
    '    systemctl poweroff --no-block || poweroff -f' \
    '    exit "$status"' \
    '}' \
    'trap finish EXIT' \
    'mkdir -p /mnt/rustdesk-online-fetch-inputs' \
    'mount -L RD_ONLINE_FETCH -o ro,nodev,nosuid,noexec /mnt/rustdesk-online-fetch-inputs' \
    "$guest_invocation" \
    >"$RUN/seed/user-data"
/usr/bin/printf '%s\n' \
    'instance-id: rustdesk-online-fetch-vm-v1' \
    'local-hostname: rustdesk-online-fetch-vm' \
    >"$RUN/seed/meta-data"
/usr/bin/printf '%s\n' 'version: 2' 'ethernets: {}' >"$RUN/seed/network-config"
(
    cd "$RUN/seed"
    /usr/bin/xorriso -as mkisofs -quiet -volid CIDATA -joliet -rock \
        -output "$SEED" user-data meta-data network-config
)
/usr/bin/chmod 0400 "$SEED"

exec {KERNEL_FD}<"$KERNEL" || fail 'cannot retain the exact acquisition kernel'
exec {INITRD_FD}<"$INITRD" || fail 'cannot retain the exact acquisition initramfs'
exec {CACHE_FD}<"$CACHE_EXPORT" || fail 'cannot retain the cache-state export'
exec {SYSTEMD_FD}<"$SYSTEMD_EXPORT" || fail 'cannot retain the systemd-cache export'
exec {RESULT_FD}<"$RESULT_EXPORT" || fail 'cannot retain the bounded result export'
for binding in "$CACHE_FD:$CACHE_EXPORT_ID" "$SYSTEMD_FD:$SYSTEMD_EXPORT_ID" \
    "$RESULT_FD:$RESULT_EXPORT_ID"; do
    fd=${binding%%:*}
    identity=${binding#*:}
    [ "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$fd")" = "$identity" ] \
        || fail 'retained writable-export descriptor identity differs'
done

start_virtiofsd cache "$CACHE_EXPORT" "$CACHE_EXPORT_ID" \
    "$CACHE_VIRTIOFS_SOCKET" "$CACHE_VIRTIOFSD_LOG"
start_virtiofsd systemd-cache "$SYSTEMD_EXPORT" "$SYSTEMD_EXPORT_ID" \
    "$SYSTEMD_VIRTIOFS_SOCKET" "$SYSTEMD_VIRTIOFSD_LOG"
start_virtiofsd bounded-result "$RESULT_EXPORT" "$RESULT_EXPORT_ID" \
    "$RESULT_VIRTIOFS_SOCKET" "$RESULT_VIRTIOFSD_LOG"
capture_listeners >"$LISTENERS_DURING"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$NEW_DURING"
/usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_DURING" \
    || fail 'virtiofsd changed the host INET listener inventory'

vm_started_seconds=$SECONDS
/usr/bin/timeout --signal=TERM --kill-after=10s "${VM_TIMEOUT_SECONDS}s" \
    /usr/bin/qemu-system-x86_64 \
        -name rustdesk-online-fetch-acquisition \
        -machine q35 \
        -accel kvm \
        -cpu host \
        -m "$VM_MEMORY" \
        -object "memory-backend-memfd,id=mem,size=${VM_MEMORY}M,share=on" \
        -numa node,memdev=mem \
        -smp 4 \
        -no-reboot \
        -no-user-config \
        -nodefaults \
        -display none \
        -parallel none \
        -kernel "/proc/self/fd/$KERNEL_FD" \
        -initrd "/proc/self/fd/$INITRD_FD" \
        -append "root=UUID=$VERIFIER_VM_ROOT_FILESYSTEM_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.online_fetch_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=systemd-timesyncd.service systemd.mask=systemd-resolved.service systemd.mask=apt-daily.service systemd.mask=apt-daily.timer systemd.mask=apt-daily-upgrade.service systemd.mask=apt-daily-upgrade.timer systemd.mask=unattended-upgrades.service systemd.mask=ssh.service systemd.mask=ssh.socket" \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
        -pidfile "$QEMU_PIDFILE" \
        -chardev "socket,id=serial0,path=$SERIAL_SOCKET,server=on,wait=on" \
        -device isa-serial,chardev=serial0 \
        -netdev user,id=acquisition,ipv4=on,ipv6=off,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15,restrict=off \
        -device virtio-net-pci,netdev=acquisition,mac=52:54:00:52:44:01 \
        -chardev "socket,id=cache-state,path=$CACHE_VIRTIOFS_SOCKET" \
        -device "vhost-user-fs-pci,chardev=cache-state,tag=rustdesk-cache-state,queue-size=1024" \
        -chardev "socket,id=systemd-cache,path=$SYSTEMD_VIRTIOFS_SOCKET" \
        -device "vhost-user-fs-pci,chardev=systemd-cache,tag=rustdesk-systemd-cache,queue-size=1024" \
        -chardev "socket,id=result,path=$RESULT_VIRTIOFS_SOCKET" \
        -device "vhost-user-fs-pci,chardev=result,tag=rustdesk-result,queue-size=1024" \
        -drive "file=$OVERLAY,if=virtio,format=qcow2,cache=none" \
        -drive "file=$SEED,if=virtio,format=raw,media=cdrom,readonly=on" \
        -drive "file=$PAYLOAD,if=virtio,format=raw,media=cdrom,readonly=on" &
VM_OWNER_PID=$!
VM_OWNER_START="$(process_start_time "$VM_OWNER_PID")" \
    || fail 'cannot record the QEMU timeout-owner process identity'
for _ in $(/usr/bin/seq 1 300); do
    [ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] && break
    /usr/bin/kill -0 "$VM_OWNER_PID" 2>/dev/null \
        || fail 'QEMU owner exited before creating its private serial channel'
    /usr/bin/sleep 0.05
done
[ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] \
    || fail 'QEMU private serial channel and process identity did not become ready'
is_exact_process "$VM_OWNER_PID" "$VM_OWNER_START" /usr/bin/timeout \
    || fail 'QEMU timeout-owner process identity changed'
verify_private_socket "$SERIAL_SOCKET" \
    || fail 'QEMU serial channel is not one current-user-private Unix socket'
VM_PID="$(/usr/bin/cat "$QEMU_PIDFILE")"
[[ "$VM_PID" =~ ^[1-9][0-9]*$ ]] || fail 'QEMU PID record is malformed'
[ "$(/usr/bin/readlink -f "/proc/$VM_PID/exe")" = /usr/bin/qemu-system-x86_64 ] \
    || fail 'QEMU PID does not identify the fixed hypervisor'
VM_START="$(process_start_time "$VM_PID")" || fail 'cannot record the exact QEMU generation'
/usr/bin/python3 -I -S "$CAPTURE_HELPER" \
    --socket "$SERIAL_SOCKET" --output "$SERIAL_LOG" --max-bytes "$SERIAL_LIMIT" \
    >"$CAPTURE_RECEIPT" &
CAPTURE_PID=$!
CAPTURE_START="$(process_start_time "$CAPTURE_PID")" \
    || fail 'cannot record the bounded serial-capture process identity'
for _ in $(/usr/bin/seq 1 300); do
    [ -r "/proc/$VM_PID/stat" ] || break
    if ! is_exact_process "$CAPTURE_PID" "$CAPTURE_START" "$(/usr/bin/readlink -f /usr/bin/python3)"; then
        [ -f "$CAPTURE_RECEIPT" ] \
            && /usr/bin/grep -Eq '^bounded-unix-stream-capture: PASS bytes=[0-9]+$' "$CAPTURE_RECEIPT" \
            || fail 'bounded serial capture exited without a completion receipt'
        break
    fi
    [ -f "$RESULT_EXPORT/transaction.stdout" ] && break
    /usr/bin/sleep 0.05
done
capture_listeners >"$LISTENERS_DURING"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$NEW_DURING"
if ! /usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_DURING"; then
    /usr/bin/ss -H -lntup >"$LISTENERS_DURING_DETAIL" 2>&1 || true
    /usr/bin/cat "$LISTENERS_DURING_DETAIL" >&2
    fail 'acquisition QEMU changed the host INET listener inventory'
fi

vm_status=0
wait "$VM_OWNER_PID" || vm_status=$?
VM_OWNER_PID=
VM_OWNER_START=
VM_ELAPSED_SECONDS=$((SECONDS - vm_started_seconds))
capture_status=0
wait "$CAPTURE_PID" || capture_status=$?
CAPTURE_PID=
CAPTURE_START=
[ "$vm_status" -eq 0 ] \
    || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail "acquisition VM exited with status $vm_status"; }
[ "$capture_status" -eq 0 ] || fail "bounded serial capture exited with status $capture_status"
for index in "${!VIRTIOFSD_PIDS[@]}"; do
    virtiofsd_pid=${VIRTIOFSD_PIDS[index]}
    virtiofsd_start=${VIRTIOFSD_STARTS[index]}
    virtiofsd_log=${VIRTIOFSD_LOGS[index]}
    for _ in $(/usr/bin/seq 1 1000); do
        is_virtiofsd_generation "$virtiofsd_pid" "$virtiofsd_start" || break
        /usr/bin/sleep 0.01
    done
    is_virtiofsd_generation "$virtiofsd_pid" "$virtiofsd_start" \
        && { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail 'virtiofsd did not retire after QEMU disconnected'; }
    virtiofsd_status=0
    wait "$virtiofsd_pid" || virtiofsd_status=$?
    [ "$virtiofsd_status" -eq 0 ] \
        || { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail "virtiofsd exited with status $virtiofsd_status"; }
done
VIRTIOFSD_PIDS=()
VIRTIOFSD_STARTS=()
/usr/bin/grep -Fxq "bounded-unix-stream-capture: PASS bytes=$(/usr/bin/stat -c '%s' "$SERIAL_LOG")" "$CAPTURE_RECEIPT" \
    || fail 'bounded serial-capture receipt differs'
if [ -r "/proc/$VM_PID/stat" ] \
   && [ "$(process_start_time "$VM_PID" 2>/dev/null)" = "$VM_START" ]; then
    fail 'exact QEMU process remains after joined acquisition-VM completion'
fi
capture_listeners >"$LISTENERS_AFTER"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_AFTER" >"$NEW_AFTER"
/usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_AFTER" \
    || fail 'acquisition VM changed the final host INET listener inventory'
retire_private_socket_path "$SERIAL_SOCKET" \
    || fail 'serial channel cleanup is ambiguous'
for socket in "${VIRTIOFS_SOCKETS[@]}"; do
    retire_private_socket_path "$socket" \
        || fail 'virtiofsd channel cleanup is ambiguous'
done

export_bindings=(
    "$CACHE_EXPORT|$CACHE_EXPORT_ID"
    "$CACHE_EXPORT/inputs|$ONLINE_EXPORT_ID"
    "$SYSTEMD_EXPORT|$SYSTEMD_EXPORT_ID"
    "$RESULT_EXPORT|$RESULT_EXPORT_ID"
)
if [ -n "$CANDIDATE_EXPORT_ID" ]; then
    export_bindings+=("$CACHE_EXPORT/candidates|$CANDIDATE_EXPORT_ID")
fi
for binding in "${export_bindings[@]}"; do
    path=${binding%%|*}
    identity=${binding#*|}
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$path")" = "$identity" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$path")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail "writable export root identity changed: $path"
done
if [ "$MODE" = authority-smoke ]; then
    [ -d "$CACHE_EXPORT/retired" ] && [ ! -L "$CACHE_EXPORT/retired" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$CACHE_EXPORT/retired")" = "$RETIRED_EXPORT_ID" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CACHE_EXPORT/retired")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail 'focused retired cache-transport authority changed'
fi
/usr/bin/grep -Fq \
    "ONLINE_FETCH_VM_GUEST=pass uid=$HOST_UID gid=$HOST_GID source=$SOURCE_COMMIT network=qemu-user-only hostfwd=absent udp=denied docker=guest-unix image_store=containerd buildkit=guest-unix git=pinned-deb cache=virtiofs-atomic nofile=524544 result=16MiB cleanup=joined" \
    "$SERIAL_LOG" || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'guest completion receipt is absent'; }
/usr/bin/grep -Fq 'ONLINE_FETCH_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'cloud-init completion receipt is absent'; }
[ -f "$RESULT_EXPORT/transaction.stdout" ] && [ ! -L "$RESULT_EXPORT/transaction.stdout" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$RESULT_EXPORT/transaction.stdout")" = "$HOST_UID:$HOST_GID:1" ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$RESULT_EXPORT/transaction.stdout")" -le 16777216 ] \
    || fail 'bounded transaction stdout is absent or ambiguous'
[ -f "$RESULT_EXPORT/transaction.stderr" ] && [ ! -L "$RESULT_EXPORT/transaction.stderr" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$RESULT_EXPORT/transaction.stderr")" = "$HOST_UID:$HOST_GID:1" ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$RESULT_EXPORT/transaction.stderr")" -le 16777216 ] \
    || fail 'bounded transaction stderr is absent or ambiguous'
/usr/bin/grep -Fq \
    "ONLINE_FETCH_VM_ENTRY_AUTHORITY=pass uid=$HOST_UID gid=$HOST_GID source=$SOURCE_COMMIT network=qemu-user-only udp=denied docker=guest-unix image_store=containerd buildkit=guest-unix git=pinned-deb cache=virtiofs-atomic" \
    "$RESULT_EXPORT/transaction.stdout" \
    || fail 'online-fetch guest-entry authority receipt is absent'
/usr/bin/grep -Fq \
    "ONLINE_FETCH_BUILDX_AUTHORITY=pass version=$VERIFIER_VM_BUILDX_VERSION commit=$VERIFIER_VM_BUILDX_COMMIT plugin=private driver=remote buildkit=$VERIFIER_VM_BUILDKIT_VERSION endpoint=guest-unix network=bridge snapshotter=overlayfs process_sandbox=enabled builder=rustdesk-online-fetch managed_container=absent image_store=separate" \
    "$RESULT_EXPORT/transaction.stdout" \
    || fail 'online-fetch Buildx authority receipt is absent'
if [ "$MODE" = authority-smoke ]; then
    /usr/bin/grep -Fq \
        "ONLINE_FETCH_VM_RUNTIME=pass network=qemu-user-only hostfwd=absent udp=denied docker=guest-bridge git=pinned-deb inner_uid=$HOST_UID https=sha256 cache=virtiofs-atomic cleanup=joined" \
        "$RESULT_EXPORT/transaction.stdout" \
        || fail 'focused acquisition runtime receipt is absent'
    for export_root in "$CACHE_EXPORT/inputs" "$CACHE_EXPORT/retired" "$SYSTEMD_EXPORT"; do
        fixture=$export_root/authority-smoke
        [ -f "$fixture" ] && [ ! -L "$fixture" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$fixture")" = \
                 "$HOST_UID:$HOST_GID:400:1:35" ] \
            && [ "$(/usr/bin/cat "$fixture")" = online-fetch-vm-cache-transport-v1 ] \
            || fail "focused cache-transport fixture differs: $fixture"
    done
else
    [ ! -e "$CACHE_EXPORT/retired" ] && [ ! -L "$CACHE_EXPORT/retired" ] \
        || fail 'successful acquisition left its retired transaction namespace behind'
fi
[ "$(/usr/bin/sha512sum "$BASE")" = "$base_before" ] \
    && [ "$(/usr/bin/sha256sum "$DOCKER_BUNDLE")" = "$docker_before" ] \
    && [ "$(/usr/bin/sha256sum "$BUILDX_BINARY")" = "$buildx_before" ] \
    && [ "$(/usr/bin/sha256sum "$BUILDKIT_BUNDLE")" = "$buildkit_before" ] \
    && [ "$(/usr/bin/sha256sum "$GIT_PACKAGE")" = "$git_package_before" ] \
    && [ "$(/usr/bin/sha512sum "$VIRTIOFSD_PACKAGE")" = "$virtiofsd_package_before" ] \
    && [ "$(/usr/bin/sha256sum "$VIRTIOFSD_BINARY" | /usr/bin/awk '{print $1}')" \
         = "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
    && [ "$(/usr/bin/sha256sum "$KERNEL")" = "$kernel_before" ] \
    && [ "$(/usr/bin/sha256sum "$INITRD")" = "$initrd_before" ] \
    || fail 'authenticated VM input changed during acquisition'
[ "$SOURCE_COMMIT:$SOURCE_TREE:$(/usr/bin/sha256sum "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$SCRIPT_DIR/online-fetch.sh" "$SCRIPT_DIR/online-fetch-vm.sh" "$VIRTIOFSD_LAUNCHER" "$SCRIPT_DIR/discover-android-emulator-inputs.py" "$SCRIPT_DIR/verify-online-fetch-virtiofs-rename.py")" = "$source_before" ] \
    || fail 'live orchestration source changed during acquisition'
[ "$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" = "$SOURCE_COMMIT" ] \
    && [ "$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
    && [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
    || fail 'live source tree changed during acquisition'

/usr/bin/cat "$RESULT_EXPORT/transaction.stdout"
if [ -s "$RESULT_EXPORT/transaction.stderr" ]; then
    /usr/bin/cat "$RESULT_EXPORT/transaction.stderr" >&2
fi
prepare_success_receipt "$VM_ELAPSED_SECONDS" \
    || fail 'cannot prepare the bounded online-fetch success receipt'
RUN_COMPLETE=1

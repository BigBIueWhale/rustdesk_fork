#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
readonly STATE_ROOT="$REPO_ROOT/.harness-state/verifier-vm"
readonly IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly BASE="$STATE_ROOT/$IMAGE_NAME"
readonly DOCKER_BUNDLE="$STATE_ROOT/docker-${VERIFIER_VM_DOCKER_VERSION}.tgz"
readonly BOOT_ROOT="$STATE_ROOT/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"
readonly KERNEL="$BOOT_ROOT/vmlinuz"
readonly INITRD="$BOOT_ROOT/initrd.img"
readonly OUTER_SOURCE="${BASH_SOURCE[0]}"
readonly GUEST_SCRIPT="$SCRIPT_DIR/smoke-verifier-vm-authority-guest.sh"
readonly ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-vm-entry-preflight.sh"
readonly VERIFY_SCRIPT="$SCRIPT_DIR/verify.sh"
readonly VERIFY_SCAN_SOURCE="$SCRIPT_DIR/verify-scan.sh"
readonly FRB_CODEGEN_SOURCE="$SCRIPT_DIR/frb-codegen.sh"
readonly DART_VERIFY_SOURCE="$SCRIPT_DIR/dart-verify.sh"
readonly SMOKE_SERVER_SOURCE="$SCRIPT_DIR/smoke-server.sh"
readonly DART_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-dart-verifier-authority.py"
readonly REQUIREMENTS_SOURCE="$REPO_ROOT/requirements.html"
readonly HARDENING_SOURCE="$REPO_ROOT/HARDENING_STATUS.md"
readonly BOOT_DERIVER="$SCRIPT_DIR/derive-verifier-vm-boot-assets.sh"
readonly CAPTURE_HELPER="$SCRIPT_DIR/bounded-unix-stream-capture.py"
readonly CLEANUP_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly LIB_SOURCE="$SCRIPT_DIR/lib.sh"
readonly PIN_SOURCE="$SCRIPT_DIR/pins.env"
readonly SERIAL_LIMIT=8388608
readonly VM_TIMEOUT_SECONDS=90

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
RUN_COMPLETE=0

fail() {
    printf 'verifier-VM authority smoke: %s\n' "$*" >&2
    exit 1
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

[ "$HOST_UID" -ne 0 ] || fail 'host or container-root execution is forbidden'
[ "$HOST_GID" -ne 0 ] || fail 'a root primary group is forbidden'
[ "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" = Linux:x86_64 ] \
    || fail 'verifier VM requires a Linux x86_64 orchestration host'
for tool in /usr/bin/awk /usr/bin/chmod /usr/bin/cmp /usr/bin/comm /usr/bin/find \
    /usr/bin/grep /usr/bin/id /usr/bin/mkdir /usr/bin/mktemp /usr/bin/python3 \
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
[ -d "$STATE_ROOT" ] && [ ! -L "$STATE_ROOT" ] \
    || fail 'verifier-VM inputs are absent; run scripts/online-fetch.sh --verifier-vm-inputs'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STATE_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'verifier-VM state root is not current-user/current-group mode 0700'
for input in "$BASE:$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" \
    "$DOCKER_BUNDLE:$SIZE_VERIFIER_VM_DOCKER_STATIC"; do
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
/usr/bin/qemu-img check -q "$BASE" || fail 'Debian verifier-VM base failed qcow2 validation'
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
for source in "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" \
    "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$DART_AUTHORITY_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" \
    "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" \
    "$LIB_SOURCE" "$PIN_SOURCE"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "verifier-VM source is absent or symlinked: $source"
done
[ -x "$GUEST_SCRIPT" ] && [ -x "$ENTRY_PREFLIGHT" ] && [ -x "$VERIFY_SCRIPT" ] \
    && [ -x "$FRB_CODEGEN_SOURCE" ] \
    && [ -x "$DART_VERIFY_SOURCE" ] \
    && [ -x "$SMOKE_SERVER_SOURCE" ] \
    && [ -x "$CAPTURE_HELPER" ] && [ -x "$CLEANUP_HELPER" ] \
    || fail 'verifier-VM scripts must be executable'
[ -x "$BOOT_DERIVER" ] || fail 'verifier-VM boot deriver must be executable'
"$BOOT_DERIVER"
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

RUN="$(/usr/bin/mktemp -d "$STATE_ROOT/run.XXXXXXXXXX")" \
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

base_before="$(/usr/bin/sha512sum "$BASE")"
docker_before="$(/usr/bin/sha256sum "$DOCKER_BUNDLE")"
boot_root_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")"
kernel_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")"
initrd_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")"
sources_before="$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$DART_AUTHORITY_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$LIB_SOURCE" "$PIN_SOURCE")"
capture_listeners >"$LISTENERS_BEFORE"
/usr/bin/qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" 6G
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OVERLAY")" = "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'pass-private overlay metadata differs'

/usr/bin/xorriso -as mkisofs -quiet -iso-level 3 -volid RD_VERIFIER_INPUTS \
    -joliet -rock -graft-points -output "$PAYLOAD" \
    "guest.sh=$GUEST_SCRIPT" \
    "repo/scripts/verify.sh=$VERIFY_SCRIPT" \
    "repo/scripts/frb-codegen.sh=$FRB_CODEGEN_SOURCE" \
    "repo/scripts/dart-verify.sh=$DART_VERIFY_SOURCE" \
    "repo/scripts/smoke-server.sh=$SMOKE_SERVER_SOURCE" \
    "repo/scripts/verify-dart-verifier-authority.py=$DART_AUTHORITY_CHECKER" \
    "repo/scripts/verify-vm-entry-preflight.sh=$ENTRY_PREFLIGHT" \
    "repo/scripts/verify-scan.sh=$VERIFY_SCAN_SOURCE" \
    "repo/scripts/verify-private-tree-closure.py=$CLEANUP_HELPER" \
    "repo/scripts/lib.sh=$LIB_SOURCE" "repo/scripts/pins.env=$PIN_SOURCE" \
    "repo/requirements.html=$REQUIREMENTS_SOURCE" \
    "repo/HARDENING_STATUS.md=$HARDENING_SOURCE" \
    "docker.tgz=$DOCKER_BUNDLE"
/usr/bin/chmod 0400 "$PAYLOAD"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$PAYLOAD")" = \
  "$HOST_UID:$HOST_GID:400:1" ] \
    || fail 'read-only payload media metadata differs'
/usr/bin/mkdir "$RUN/seed"
/usr/bin/chmod 0700 "$RUN/seed"
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
    "bash /mnt/rustdesk-verifier-inputs/guest.sh /mnt/rustdesk-verifier-inputs/docker.tgz /mnt/rustdesk-verifier-inputs/repo/scripts/verify-vm-entry-preflight.sh $VERIFIER_VM_DOCKER_VERSION $SIZE_VERIFIER_VM_DOCKER_STATIC $SHA256_VERIFIER_VM_DOCKER_STATIC $VERIFIER_VM_KERNEL_RELEASE $VERIFIER_VM_ROOT_FILESYSTEM_UUID" \
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
vm_started_seconds=$SECONDS
/usr/bin/timeout --signal=TERM --kill-after=10s "${VM_TIMEOUT_SECONDS}s" \
    /usr/bin/qemu-system-x86_64 \
        -name rustdesk-verifier-authority \
        -machine q35 \
        -accel kvm \
        -cpu host \
        -m 2048 \
        -smp 2 \
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

/usr/bin/grep -Fq \
    "VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=$VERIFIER_VM_KERNEL_RELEASE direct_boot=on boot_masks=on docker=$VERIFIER_VM_DOCKER_VERSION vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest authority result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$VERIFIER_VM_DOCKER_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest verifier-entry authority marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 foreign=refused nofile=524544 workspace_cleanup=joined" \
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
    "VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'server-smoke verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
mapfile -t dart_frb_source_gate_receipts < <(
    /usr/bin/grep -Eo 'VERIFIER_VM_DART_FRB_SOURCE_GATE=pass mutations=[1-9][0-9]*' "$SERIAL_LOG"
)
[ "${#dart_frb_source_gate_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart/FRB verifier-VM source-gate result marker is absent or duplicated'; }
printf '%s\n' "${dart_frb_source_gate_receipts[0]}"
/usr/bin/grep -Fq 'VERIFIER_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'cloud-init completion marker is absent'; }
[ "$(/usr/bin/sha512sum "$BASE")" = "$base_before" ] \
    || fail 'read-only Debian base changed'
[ "$(/usr/bin/sha256sum "$DOCKER_BUNDLE")" = "$docker_before" ] \
    || fail 'read-only Docker bundle changed'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")" = "$boot_root_before" ] \
    || fail 'direct-boot cache directory changed during execution'
[ "$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" = xx ] \
    || fail 'direct-boot cache inventory changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")" = "$kernel_before" ] \
    || fail 'direct-boot kernel changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")" = "$initrd_before" ] \
    || fail 'direct-boot initramfs changed during execution'
[ "$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$DART_AUTHORITY_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$LIB_SOURCE" "$PIN_SOURCE")" = "$sources_before" ] \
    || fail 'verifier-VM harness source changed during execution'

RUN_COMPLETE=1
printf 'VERIFIER_VM_OUTER_AUTHORITY=pass host_uid=%s network=none boot=direct kernel=sha256 initrd=sha256 channels=unix listeners=unchanged base=sha512 docker=sha256 output_bound=%s cleanup=joined elapsed_seconds=%s\n' \
    "$HOST_UID" "$SERIAL_LIMIT" "$vm_elapsed_seconds"

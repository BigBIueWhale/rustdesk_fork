#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 7 ] \
    || { echo 'usage: smoke-verifier-vm-authority-guest.sh DOCKER_TGZ ENTRY_PREFLIGHT VERSION SIZE SHA256 KERNEL_RELEASE ROOT_UUID' >&2; exit 2; }
readonly DOCKER_ARCHIVE=$1
readonly ENTRY_PREFLIGHT=$2
readonly EXPECTED_VERSION=$3
readonly EXPECTED_SIZE=$4
readonly EXPECTED_SHA256=$5
readonly EXPECTED_KERNEL_RELEASE=$6
readonly EXPECTED_ROOT_UUID=$7
readonly AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly MARKER=$AUTHORITY_ROOT/authority
readonly CONFIG_ROOT=$AUTHORITY_ROOT/docker-config
readonly CONFIG=$CONFIG_ROOT/config.json
readonly ROOT=/var/tmp/rustdesk-verifier-authority
readonly BIN=$ROOT/bin
readonly CLIENT=/usr/bin/docker
readonly DAEMON_PATH=$BIN:/usr/sbin:/usr/bin:/sbin:/bin
readonly DATA=$ROOT/data
readonly EXEC=$ROOT/exec
readonly SOCK=$AUTHORITY_ROOT/docker.sock
readonly PIDFILE=$AUTHORITY_ROOT/docker.pid
readonly DAEMON_IDENTITY=$AUTHORITY_ROOT/docker.identity
readonly LOG=$ROOT/dockerd.log
readonly VERIFY_REPO=/mnt/rustdesk-verifier-inputs/repo
readonly VERIFY_SCRIPT=$VERIFY_REPO/scripts/verify.sh
readonly FRB_SCRIPT=$VERIFY_REPO/scripts/frb-codegen.sh
readonly DART_SCRIPT=$VERIFY_REPO/scripts/dart-verify.sh
readonly SMOKE_SERVER_SCRIPT=$VERIFY_REPO/scripts/smoke-server.sh
readonly RUST_AUDIT_SCRIPT=$VERIFY_REPO/scripts/audit.sh
readonly ANDROID_KEYSTORE_SCRIPT=$VERIFY_REPO/scripts/gen-android-keystore.sh
readonly ANDROID_BUILDER_SCRIPT=$VERIFY_REPO/scripts/build-android.sh
readonly ANDROID_RUST_SCRIPT=$VERIFY_REPO/scripts/android-rust-check.sh
readonly DART_AUDIT_SCRIPT=$VERIFY_REPO/scripts/dart-audit.sh
readonly IMAGE=rustdesk-verifier-authority-probe:v1
readonly CONTAINER=rustdesk-verifier-authority-probe

DAEMON_PID=
CONTAINER_ID=

fail() {
    printf 'verifier-VM guest: %s\n' "$*" >&2
    exit 1
}

network_inventory() {
    awk 'FNR > 1 { print FILENAME ":" $2 ":" $4 }' \
        /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null \
        | LC_ALL=C sort -u
}

cleanup() {
    local status=$? daemon_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$CONTAINER_ID" ] && [ -x "$CLIENT" ]; then
        "$CLIENT" --host "unix://$SOCK" rm -f "$CONTAINER_ID" >/dev/null 2>&1 \
            || status=1
        CONTAINER_ID=
    fi
    if [ -n "$DAEMON_PID" ]; then
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -TERM "$DAEMON_PID" 2>/dev/null || daemon_status=1
        fi
        wait "$DAEMON_PID" 2>/dev/null || daemon_status=$?
        [ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] || status=1
        DAEMON_PID=
    fi
    if [ "$status" -ne 0 ] && [ -f "$LOG" ]; then
        tail -n 160 "$LOG" >&2 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || fail 'guest authority probe must run as VM-local root'
[ "$(cat /proc/1/comm)" = systemd ] || fail 'guest PID 1 is not systemd'
[ -r /etc/os-release ] || fail 'guest OS identity is absent'
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail 'guest is not the pinned Debian bookworm base'
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail 'Docker version pin is malformed'
case "$EXPECTED_SIZE" in 0|*[!0-9]*|'') fail 'Docker size pin is malformed' ;; esac
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'Docker digest pin is malformed'
[[ "$EXPECTED_KERNEL_RELEASE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-cloud-amd64$ ]] \
    || fail 'kernel-release pin is malformed'
[[ "$EXPECTED_ROOT_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || fail 'root-filesystem UUID pin is malformed'
[ "$(uname -r)" = "$EXPECTED_KERNEL_RELEASE" ] \
    || fail 'running guest kernel release differs'
expected_cmdline="root=UUID=$EXPECTED_ROOT_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.verifier_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=ssh.service systemd.mask=ssh.socket"
[ "$(< /proc/cmdline)" = "$expected_cmdline" ] \
    || fail 'running guest kernel command line differs'
for masked_unit in systemd-networkd-wait-online.service ssh.service ssh.socket; do
    mask="/run/systemd/generator.early/$masked_unit"
    [ -L "$mask" ] && [ "$(readlink -- "$mask")" = /dev/null ] \
        || fail "runtime boot mask is absent: $masked_unit"
done
[ -f "$DOCKER_ARCHIVE" ] && [ ! -L "$DOCKER_ARCHIVE" ] \
    || fail 'Docker bundle is not one regular payload file'
[ -f "$ENTRY_PREFLIGHT" ] && [ ! -L "$ENTRY_PREFLIGHT" ] \
    || fail 'verifier-entry preflight is not one regular payload file'
for verify_source in verify.sh frb-codegen.sh dart-verify.sh smoke-server.sh \
    audit.sh rust-audit-policy.py verify-rust-audit-authority.py \
    gen-android-keystore.sh android-keystore-generate.sh \
    verify-android-keystore-authority.py \
    build-android.sh verify-android-builder-authority.py android-rust-check.sh \
    dart-audit.sh dart-audit-result.py \
    verify-dart-verifier-authority.py verify-dart-audit-authority.py \
    smoke-verifier-vm-authority.sh smoke-verifier-vm-authority-guest.sh \
    verify-vm-entry-preflight.sh verify-scan.sh \
    verify-private-tree-closure.py lib.sh pins.env; do
    verify_path="$VERIFY_REPO/scripts/$verify_source"
    [ -f "$verify_path" ] && [ ! -L "$verify_path" ] \
        || fail "main verifier entry source is absent or ambiguous: $verify_source"
done
for repository_source in requirements.html HARDENING_STATUS.md; do
    [ -f "$VERIFY_REPO/$repository_source" ] && [ ! -L "$VERIFY_REPO/$repository_source" ] \
        || fail "FRB source-gate input is absent or ambiguous: $repository_source"
done
[ "$ENTRY_PREFLIGHT" = "$VERIFY_REPO/scripts/verify-vm-entry-preflight.sh" ] \
    || fail 'main verifier and guest probe use different entry-preflight paths'
entry_source_metadata="$(stat -c '%F:%u:%g:%a:%h' -- \
    "$VERIFY_REPO/scripts/verify-vm-entry-preflight.sh")" \
    || fail 'main verifier entry-preflight metadata cannot be read'
[ "$(stat -c '%s:%h' -- "$DOCKER_ARCHIVE")" = "$EXPECTED_SIZE:1" ] \
    || fail 'Docker bundle size or link count differs inside the guest'
[ "$(sha256sum "$DOCKER_ARCHIVE" | awk '{print $1}')" = "$EXPECTED_SHA256" ] \
    || fail 'Docker bundle digest differs inside the guest'
mount_options="$(findmnt -n -o OPTIONS --target "$DOCKER_ARCHIVE")" \
    || fail 'Docker bundle payload mount is absent'
case ",$mount_options," in *,ro,*) ;; *) fail 'Docker payload is not read-only' ;; esac
case ",$mount_options," in *,nodev,*) ;; *) fail 'Docker payload permits devices' ;; esac
case ",$mount_options," in *,nosuid,*) ;; *) fail 'Docker payload permits set-user-ID execution' ;; esac
case ",$mount_options," in *,noexec,*) ;; *) fail 'Docker payload permits direct execution' ;; esac
printf 'VERIFIER_VM_ENTRY_SOURCE=metadata=%s mount=noexec-readonly\n' \
    "$entry_source_metadata"

[ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ] \
    || fail 'AppArmor kernel enforcement is not enabled'
parser="$(PATH="$DAEMON_PATH" command -v apparmor_parser)" \
    || fail 'pinned cloud base AppArmor parser is not on the daemon search path'
parser="$(readlink -f -- "$parser")" \
    || fail 'pinned cloud base AppArmor parser cannot be resolved'
[ -f "$parser" ] && [ ! -L "$parser" ] && [ -x "$parser" ] \
    || fail 'pinned cloud base AppArmor parser is not one executable file'
[ "$(stat -c '%u:%g:%a:%h' -- "$parser")" = 0:0:755:1 ] \
    || fail 'pinned cloud base AppArmor parser metadata differs'
case "$("$parser" --version 2>&1 | head -n 1)" in
    'AppArmor parser version '*) ;;
    *) fail 'pinned cloud base AppArmor parser identity differs' ;;
esac

mapfile -t interfaces < <(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[ "${#interfaces[@]}" -eq 1 ] && [ "${interfaces[0]}" = lo ] \
    || fail "networkless VM has an unexpected interface inventory: ${interfaces[*]}"
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'guest IPv4 forwarding is enabled before Docker'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'guest IPv6 forwarding is enabled before Docker'
network_inventory >"$ROOT.network-before"

mkdir -p "$AUTHORITY_ROOT" "$BIN" "$CONFIG_ROOT" "$DATA" "$EXEC" \
    "$ROOT/rootfs/bin" "$ROOT/rootfs/lib" "$ROOT/rootfs/lib64"
chmod 0755 "$AUTHORITY_ROOT"
chmod 0755 "$ROOT"
chmod 0700 "$DATA" "$EXEC"
archive_inventory="$(tar -tzf "$DOCKER_ARCHIVE")" || fail 'Docker bundle inventory cannot be read'
[ "$archive_inventory" = $'docker/\ndocker/runc\ndocker/containerd\ndocker/docker-init\ndocker/dockerd\ndocker/containerd-shim-runc-v2\ndocker/docker-proxy\ndocker/docker\ndocker/ctr' ] \
    || fail 'Docker bundle has a noncanonical member inventory or order'
tar -xzf "$DOCKER_ARCHIVE" --strip-components=1 --no-same-owner --no-same-permissions \
    -C "$BIN" \
    docker/runc docker/containerd docker/docker-init docker/dockerd \
    docker/containerd-shim-runc-v2 docker/docker-proxy docker/docker docker/ctr
[ ! -e "$CLIENT" ] && [ ! -L "$CLIENT" ] \
    || fail 'pinned cloud base unexpectedly supplies a Docker client'
mv -- "$BIN/docker" "$CLIENT"
chmod 0555 "$BIN" "$BIN"/* "$CLIENT"
[ "$(find "$BIN" -mindepth 1 -maxdepth 1 -type f -perm 0555 | wc -l)" -eq 7 ] \
    || fail 'extracted Docker binary inventory differs'
[ -z "$(find "$BIN" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
    || fail 'extracted Docker bundle contains a non-regular entry'
[ "$(stat -c '%u:%g:%a:%h' -- "$CLIENT")" = 0:0:555:1 ] \
    || fail 'fixed VM Docker client metadata differs'

docker_version="$("$CLIENT" --version)"
dockerd_version="$($BIN/dockerd --version)"
case "$docker_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker client version differs: $docker_version" ;; esac
case "$dockerd_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker daemon version differs: $dockerd_version" ;; esac
printf '{}\n' >"$CONFIG"
printf 'rustdesk-verifier-vm-authority-v1 docker=%s\n' "$EXPECTED_VERSION" >"$MARKER"
chmod 0444 "$CONFIG" "$MARKER"
chmod 0555 "$CONFIG_ROOT"
[ "$(sha256sum "$CONFIG" | awk '{ print $1 }')" = \
  ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356 ] \
    || fail 'canonical empty Docker configuration digest differs'

PATH="$DAEMON_PATH" \
    "$BIN/dockerd" \
        --host "unix://$SOCK" \
        --pidfile "$PIDFILE" \
        --data-root "$DATA" \
        --exec-root "$EXEC" \
        --bridge none \
        --iptables=false \
        --ip6tables=false \
        --ip-forward=false \
        --ip-masq=false \
        --userland-proxy=false \
        --group root \
        --log-level error \
        >"$LOG" 2>&1 &
DAEMON_PID=$!
[[ "$DAEMON_PID" =~ ^[1-9][0-9]*$ ]] || fail 'Docker daemon PID is malformed'

ready=0
server_version=
for _ in $(seq 1 300); do
    server_version=
    if [ -S "$SOCK" ]; then
        server_version="$(
            "$CLIENT" --host "unix://$SOCK" info --format '{{.ServerVersion}}' \
                2>/dev/null
        )" || server_version=
    fi
    if [ "$server_version" = "$EXPECTED_VERSION" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
done
[ "$ready" -eq 1 ] || fail 'guest-only Docker daemon did not become ready'
[ "$server_version" = "$EXPECTED_VERSION" ] || fail 'Docker server version differs'
[ "$(<"$PIDFILE")" = "$DAEMON_PID" ] || fail 'Docker daemon PID file differs'
chown 0:4000 "$SOCK"
chmod 0660 "$SOCK"
chmod 0444 "$PIDFILE"
[ "$(stat -c '%u:%g:%a' -- "$SOCK")" = 0:4000:660 ] \
    || fail 'Docker Unix socket authority differs'
[ "$(readlink -f -- "/proc/$DAEMON_PID/exe")" = "$BIN/dockerd" ] \
    || fail 'Docker daemon executable identity differs before generation publication'
daemon_start="$(awk '{ print $22 }' "/proc/$DAEMON_PID/stat")" \
    || fail 'Docker daemon start time cannot be read'
[[ "$daemon_start" =~ ^[1-9][0-9]*$ ]] || fail 'Docker daemon start time is malformed'
printf 'pid=%s start=%s daemon_sha256=%s client_sha256=%s\n' \
    "$DAEMON_PID" "$daemon_start" \
    "$(sha256sum "$BIN/dockerd" | awk '{ print $1 }')" \
    "$(sha256sum "$CLIENT" | awk '{ print $1 }')" \
    >"$DAEMON_IDENTITY"
chmod 0444 "$DAEMON_IDENTITY"
[ ! -e /sys/class/net/docker0 ] || fail 'Docker created a guest bridge despite --bridge=none'
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'Docker enabled guest IPv4 forwarding'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'Docker enabled guest IPv6 forwarding'
network_inventory >"$ROOT.network-during"
cmp -s "$ROOT.network-before" "$ROOT.network-during" \
    || fail 'guest Docker created an INET listener'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$VERIFY_SCRIPT" --self-test-workspace \
    >"$ROOT/foreign-entry.out" 2>"$ROOT/foreign-entry.err"; then
    fail 'foreign numeric principal passed the main verifier entry'
fi
[ ! -s "$ROOT/foreign-entry.out" ] \
    || fail 'foreign main-verifier refusal produced standard output'
foreign_entry_error="$(<"$ROOT/foreign-entry.err")"
if [ "$foreign_entry_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-entry.err")" -le 4096 ] \
        || fail 'foreign main-verifier refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign main-verifier diagnostic was %q\n' \
        "$foreign_entry_error" >&2
    fail 'foreign main-verifier refusal diagnostic differs'
fi
ulimit -Hn 524544 || fail 'verifier descriptor hard limit cannot be established'
ulimit -Sn 524544 || fail 'verifier descriptor soft limit cannot be established'
[ "$(ulimit -Sn):$(ulimit -Hn)" = 524544:524544 ] \
    || fail 'verifier descriptor limit differs'
main_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$VERIFY_SCRIPT" --self-test-workspace
)" || fail 'numeric-nonroot main verifier entry failed'
expected_main_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
verify workspace self-test: OK"
[ "$main_entry_output" = "$expected_main_entry_output" ] \
    || fail "main verifier entry result differs: $main_entry_output"
printf '%s\n' "$main_entry_output"
printf 'VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 foreign=refused nofile=524544 workspace_cleanup=joined\n'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$FRB_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-frb-entry.out" 2>"$ROOT/foreign-frb-entry.err"; then
    fail 'foreign numeric principal passed the FRB verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-frb-entry.out" ] \
    || fail 'foreign FRB verifier-VM refusal produced standard output'
foreign_frb_error="$(<"$ROOT/foreign-frb-entry.err")"
if [ "$foreign_frb_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-frb-entry.err")" -le 4096 ] \
        || fail 'foreign FRB verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign FRB diagnostic was %q\n' \
        "$foreign_frb_error" >&2
    fail 'foreign FRB verifier-VM refusal diagnostic differs'
fi
frb_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$FRB_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot FRB verifier-VM entry failed'
expected_frb_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
FRB_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$frb_entry_output" = "$expected_frb_entry_output" ] \
    || fail "FRB verifier-VM entry result differs: $frb_entry_output"
printf '%s\n' "$frb_entry_output"
printf 'VERIFIER_VM_FRB_ENTRY=pass uid=4000 gid=4000 foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$DART_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-dart-entry.out" 2>"$ROOT/root-dart-entry.err"; then
    fail 'VM root passed the Dart verifier entry'
fi
[ ! -s "$ROOT/root-dart-entry.out" ] \
    || fail 'root Dart verifier refusal produced standard output'
[ "$(<"$ROOT/root-dart-entry.err")" = \
  'dart-verify refuses host or container-root execution' ] \
    || fail 'root Dart verifier refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$DART_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-dart-entry.out" 2>"$ROOT/foreign-dart-entry.err"; then
    fail 'foreign numeric principal passed the Dart verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-dart-entry.out" ] \
    || fail 'foreign Dart verifier-VM refusal produced standard output'
foreign_dart_error="$(<"$ROOT/foreign-dart-entry.err")"
if [ "$foreign_dart_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-dart-entry.err")" -le 4096 ] \
        || fail 'foreign Dart verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Dart diagnostic was %q\n' \
        "$foreign_dart_error" >&2
    fail 'foreign Dart verifier-VM refusal diagnostic differs'
fi
dart_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$DART_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Dart verifier-VM entry failed'
expected_dart_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DART_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed frb=chained"
[ "$dart_entry_output" = "$expected_dart_entry_output" ] \
    || fail "Dart verifier-VM entry result differs: $dart_entry_output"
printf '%s\n' "$dart_entry_output"
printf 'VERIFIER_VM_DART_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed frb=chained\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-smoke-server-entry.out" 2>"$ROOT/root-smoke-server-entry.err"; then
    fail 'VM root passed the server-smoke verifier entry'
fi
[ ! -s "$ROOT/root-smoke-server-entry.out" ] \
    || fail 'root server-smoke refusal produced standard output'
[ "$(<"$ROOT/root-smoke-server-entry.err")" = \
  'smoke: refuses host or container-root execution' ] \
    || fail 'root server-smoke refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-smoke-server-entry.out" 2>"$ROOT/foreign-smoke-server-entry.err"; then
    fail 'foreign numeric principal passed the server-smoke verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-smoke-server-entry.out" ] \
    || fail 'foreign server-smoke verifier-VM refusal produced standard output'
foreign_smoke_server_error="$(<"$ROOT/foreign-smoke-server-entry.err")"
if [ "$foreign_smoke_server_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-smoke-server-entry.err")" -le 4096 ] \
        || fail 'foreign server-smoke verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign server-smoke diagnostic was %q\n' \
        "$foreign_smoke_server_error" >&2
    fail 'foreign server-smoke verifier-VM refusal diagnostic differs'
fi
smoke_server_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot server-smoke verifier-VM entry failed'
expected_smoke_server_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
SMOKE_SERVER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$smoke_server_entry_output" = "$expected_smoke_server_entry_output" ] \
    || fail "server-smoke verifier-VM entry result differs: $smoke_server_entry_output"
printf '%s\n' "$smoke_server_entry_output"
printf 'VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-rust-audit-entry.out" 2>"$ROOT/root-rust-audit-entry.err"; then
    fail 'VM root passed the Rust-audit verifier entry'
fi
[ ! -s "$ROOT/root-rust-audit-entry.out" ] \
    || fail 'root Rust-audit refusal produced standard output'
[ "$(<"$ROOT/root-rust-audit-entry.err")" = \
  'audit.sh: refuses host or container-root execution' ] \
    || fail 'root Rust-audit refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-rust-audit-entry.out" 2>"$ROOT/foreign-rust-audit-entry.err"; then
    fail 'foreign numeric principal passed the Rust-audit verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-rust-audit-entry.out" ] \
    || fail 'foreign Rust-audit verifier-VM refusal produced standard output'
foreign_rust_audit_error="$(<"$ROOT/foreign-rust-audit-entry.err")"
if [ "$foreign_rust_audit_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-rust-audit-entry.err")" -le 4096 ] \
        || fail 'foreign Rust-audit refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Rust-audit diagnostic was %q\n' \
        "$foreign_rust_audit_error" >&2
    fail 'foreign Rust-audit refusal diagnostic differs'
fi
rust_audit_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Rust-audit verifier-VM entry failed'
expected_rust_audit_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
RUST_AUDIT_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$rust_audit_entry_output" = "$expected_rust_audit_entry_output" ] \
    || fail "Rust-audit verifier-VM entry result differs: $rust_audit_entry_output"
printf '%s\n' "$rust_audit_entry_output"
printf 'VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

rust_audit_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-rust-audit-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Rust-audit compact source gate failed'
[ "$rust_audit_source_gate_output" = 'verify-rust-audit-authority: ok' ] \
    || fail "Rust-audit compact source-gate result differs: $rust_audit_source_gate_output"
printf '%s\n' "$rust_audit_source_gate_output"
printf 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass\n'

rust_audit_result_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/rust-audit-policy.py" --self-test
)" || fail 'Rust-audit policy/result behavioral gate failed'
[ "$rust_audit_result_gate_output" = \
  'rust-audit-policy self-test: ok (20 policy/freshness/result decisions)' ] \
    || fail "Rust-audit policy/result result differs: $rust_audit_result_gate_output"
printf '%s\n' "$rust_audit_result_gate_output"
printf 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20\n'

if /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-keystore-entry.out" 2>"$ROOT/root-android-keystore-entry.err"; then
    fail 'VM root passed the Android-keystore verifier entry'
fi
[ ! -s "$ROOT/root-android-keystore-entry.out" ] \
    || fail 'root Android-keystore refusal produced standard output'
[ "$(<"$ROOT/root-android-keystore-entry.err")" = \
  'Android signing identity generation refuses host or container-root execution' ] \
    || fail 'root Android-keystore refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-keystore-entry.out" 2>"$ROOT/foreign-android-keystore-entry.err"; then
    fail 'foreign numeric principal passed the Android-keystore verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-keystore-entry.out" ] \
    || fail 'foreign Android-keystore verifier-VM refusal produced standard output'
foreign_android_keystore_error="$(<"$ROOT/foreign-android-keystore-entry.err")"
if [ "$foreign_android_keystore_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-keystore-entry.err")" -le 4096 ] \
        || fail 'foreign Android-keystore refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-keystore diagnostic was %q\n' \
        "$foreign_android_keystore_error" >&2
    fail 'foreign Android-keystore refusal diagnostic differs'
fi
android_keystore_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-keystore verifier-VM entry failed'
expected_android_keystore_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_KEYSTORE_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed identity=untouched"
[ "$android_keystore_entry_output" = "$expected_android_keystore_entry_output" ] \
    || fail "Android-keystore verifier-VM entry result differs: $android_keystore_entry_output"
printf '%s\n' "$android_keystore_entry_output"
printf 'VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed identity=untouched\n' \
    "$EXPECTED_VERSION"

android_keystore_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-android-keystore-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Android-keystore compact source gate failed'
[ "$android_keystore_source_gate_output" = 'verify-android-keystore-authority: ok' ] \
    || fail "Android-keystore compact source-gate result differs: $android_keystore_source_gate_output"
printf '%s\n' "$android_keystore_source_gate_output"
printf 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass\n'

if /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-builder-entry.out" 2>"$ROOT/root-android-builder-entry.err"; then
    fail 'VM root passed the Android-builder verifier entry'
fi
[ ! -s "$ROOT/root-android-builder-entry.out" ] \
    || fail 'root Android-builder refusal produced standard output'
[ "$(<"$ROOT/root-android-builder-entry.err")" = \
  'Android artifact building refuses host or container-root execution' ] \
    || fail 'root Android-builder refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-builder-entry.out" 2>"$ROOT/foreign-android-builder-entry.err"; then
    fail 'foreign numeric principal passed the Android-builder verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-builder-entry.out" ] \
    || fail 'foreign Android-builder verifier-VM refusal produced standard output'
foreign_android_builder_error="$(<"$ROOT/foreign-android-builder-entry.err")"
if [ "$foreign_android_builder_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-builder-entry.err")" -le 4096 ] \
        || fail 'foreign Android-builder refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-builder diagnostic was %q\n' \
        "$foreign_android_builder_error" >&2
    fail 'foreign Android-builder refusal diagnostic differs'
fi
android_builder_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-builder verifier-VM entry failed'
expected_android_builder_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_BUILDER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed source=untouched signing=untouched output=untouched"
[ "$android_builder_entry_output" = "$expected_android_builder_entry_output" ] \
    || fail "Android-builder verifier-VM entry result differs: $android_builder_entry_output"
printf '%s\n' "$android_builder_entry_output"
printf 'VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched signing=untouched output=untouched\n' \
    "$EXPECTED_VERSION"

android_builder_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-android-builder-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Android-builder compact source gate failed'
[ "$android_builder_source_gate_output" = 'verify-android-builder-authority: ok' ] \
    || fail "Android-builder compact source-gate result differs: $android_builder_source_gate_output"
printf '%s\n' "$android_builder_source_gate_output"
printf 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass\n'

if /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-rust-entry.out" 2>"$ROOT/root-android-rust-entry.err"; then
    fail 'VM root passed the Android-Rust verifier entry'
fi
[ ! -s "$ROOT/root-android-rust-entry.out" ] \
    || fail 'root Android-Rust refusal produced standard output'
[ "$(<"$ROOT/root-android-rust-entry.err")" = \
  'Android Rust release check refuses host or container-root execution' ] \
    || fail 'root Android-Rust refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-rust-entry.out" 2>"$ROOT/foreign-android-rust-entry.err"; then
    fail 'foreign numeric principal passed the Android-Rust verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-rust-entry.out" ] \
    || fail 'foreign Android-Rust verifier-VM refusal produced standard output'
foreign_android_rust_error="$(<"$ROOT/foreign-android-rust-entry.err")"
if [ "$foreign_android_rust_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-rust-entry.err")" -le 4096 ] \
        || fail 'foreign Android-Rust refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-Rust diagnostic was %q\n' \
        "$foreign_android_rust_error" >&2
    fail 'foreign Android-Rust refusal diagnostic differs'
fi
android_rust_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-Rust verifier-VM entry failed'
expected_android_rust_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_RUST_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed source=untouched online=untouched workload=unexecuted"
[ "$android_rust_entry_output" = "$expected_android_rust_entry_output" ] \
    || fail "Android-Rust verifier-VM entry result differs: $android_rust_entry_output"
printf '%s\n' "$android_rust_entry_output"
printf 'VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched online=untouched workload=unexecuted\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-dart-audit-entry.out" 2>"$ROOT/root-dart-audit-entry.err"; then
    fail 'VM root passed the Dart-audit verifier entry'
fi
[ ! -s "$ROOT/root-dart-audit-entry.out" ] \
    || fail 'root Dart-audit refusal produced standard output'
[ "$(<"$ROOT/root-dart-audit-entry.err")" = \
  'dart-audit.sh: refuses host or container-root execution' ] \
    || fail 'root Dart-audit refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-dart-audit-entry.out" 2>"$ROOT/foreign-dart-audit-entry.err"; then
    fail 'foreign numeric principal passed the Dart-audit verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-dart-audit-entry.out" ] \
    || fail 'foreign Dart-audit verifier-VM refusal produced standard output'
foreign_dart_audit_error="$(<"$ROOT/foreign-dart-audit-entry.err")"
if [ "$foreign_dart_audit_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-dart-audit-entry.err")" -le 4096 ] \
        || fail 'foreign Dart-audit refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Dart-audit diagnostic was %q\n' \
        "$foreign_dart_audit_error" >&2
    fail 'foreign Dart-audit refusal diagnostic differs'
fi
dart_audit_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Dart-audit verifier-VM entry failed'
expected_dart_audit_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DART_AUDIT_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$dart_audit_entry_output" = "$expected_dart_audit_entry_output" ] \
    || fail "Dart-audit verifier-VM entry result differs: $dart_audit_entry_output"
printf '%s\n' "$dart_audit_entry_output"
printf 'VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

dart_audit_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-dart-audit-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Dart-audit compact source gate failed'
[ "$dart_audit_source_gate_output" = 'verify-dart-audit-authority: ok' ] \
    || fail "Dart-audit compact source-gate result differs: $dart_audit_source_gate_output"
printf '%s\n' "$dart_audit_source_gate_output"
printf 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass\n'

dart_audit_result_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/dart-audit-result.py" --self-test
)" || fail 'Dart-audit result behavioral gate failed'
[ "$dart_audit_result_gate_output" = \
  'dart-audit-result self-test: ok (31 policy/freshness/status/schema decisions)' ] \
    || fail "Dart-audit result behavioral result differs: $dart_audit_result_gate_output"
printf '%s\n' "$dart_audit_result_gate_output"
printf 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31\n'

dart_frb_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-dart-verifier-authority.py" \
        --repo "$VERIFY_REPO" --self-test
)" || fail 'Dart/FRB verifier-VM focused source/mutation gate failed'
if [[ "$dart_frb_source_gate_output" =~ ^verify-dart-verifier-authority:\ ok\ \(([1-9][0-9]*)\ mutations\ rejected\)$ ]]; then
    dart_frb_source_gate_mutations=${BASH_REMATCH[1]}
else
    fail "Dart/FRB verifier-VM focused source/mutation result differs: $dart_frb_source_gate_output"
fi
printf '%s\n' "$dart_frb_source_gate_output"
printf 'VERIFIER_VM_DART_FRB_SOURCE_GATE=pass mutations=%s\n' "$dart_frb_source_gate_mutations"

cp --parents -L /bin/dash "$ROOT/rootfs"
while IFS= read -r library; do
    [ -f "$library" ] || fail "shell dependency is absent: $library"
    cp --parents -L "$library" "$ROOT/rootfs"
done < <(ldd /bin/dash | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' | LC_ALL=C sort -u)
ln -s dash "$ROOT/rootfs/bin/sh"
# The staging parent remains root-private, while the filesystem imported into
# the image must be traversable by its declared numeric non-root user. Make the
# entire minimal image root-owned and immutable before serialization.
find "$ROOT/rootfs" -type d -exec chmod 0555 {} +
find "$ROOT/rootfs" -type f -exec chmod 0555 {} +
[ -z "$(find "$ROOT/rootfs" \( -type d -o -type f \) -perm /0222 -print -quit)" ] \
    || fail 'probe root filesystem contains a writable directory or file'
[ "$(stat -c '%u:%g:%a' -- "$ROOT/rootfs")" = 0:0:555 ] \
    || fail 'probe root filesystem root metadata differs'
tar --numeric-owner --owner=0 --group=0 -C "$ROOT/rootfs" -cf - . \
    | "$CLIENT" --host "unix://$SOCK" import \
        --change 'USER 4000:4000' \
        --change 'ENTRYPOINT ["/bin/dash"]' \
        - "$IMAGE" >"$ROOT/image-id"
[[ "$(<"$ROOT/image-id")" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'probe image ID is malformed'

CONTAINER_ID="$(
    "$CLIENT" --host "unix://$SOCK" create \
        --name "$CONTAINER" \
        --pull=never \
        --network=none \
        --read-only \
        --pids-limit=16 \
        --memory=64m \
        --memory-swap=64m \
        --cpus=0.5 \
        --ulimit nofile=64:64 \
        --ulimit core=0:0 \
        --ulimit fsize=1048576:1048576 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --user 4000:4000 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=700,uid=4000,gid=4000 \
        "$IMAGE" -euc '
            [ "$$" = 1 ]
            uid= gid= cap= nnp= seccomp= apparmor=
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
            IFS= read -r apparmor </proc/self/attr/current
            case "$apparmor" in docker-default\ *) ;; *) exit 92 ;; esac
            IFS= read -r pids_max </sys/fs/cgroup/pids.max
            IFS= read -r memory_max </sys/fs/cgroup/memory.max
            IFS= read -r swap_max </sys/fs/cgroup/memory.swap.max
            IFS=" " read -r cpu_quota cpu_period </sys/fs/cgroup/cpu.max
            [ "$pids_max" = 16 ]
            [ "$memory_max" = 67108864 ]
            [ "$swap_max" = 0 ]
            [ "$cpu_quota:$cpu_period" = 50000:100000 ]
            [ "$(ulimit -c)" = 0 ]
            [ "$(ulimit -n)" = 64 ]
            [ "$(ulimit -f)" != unlimited ]
            set -- /sys/class/net/*
            [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
            if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
            : >/tmp/allowed-private-write
            [ -f /tmp/allowed-private-write ]
            printf "VERIFIER_INNER_CONTAINER=pass uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default\n"
        '
)"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'probe container ID is malformed'
inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
    "$CONTAINER_ID")"
[ "$inspect" = 'none|true|4000:4000|67108864|67108864|500000000|16|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
    || fail "probe container authority differs: $inspect"
namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.Binds}}|{{json .HostConfig.PortBindings}}' \
    "$CONTAINER_ID")"
[ "$namespace_inspect" = 'false||private||private|[]|null|{}' ] \
    || fail "probe container namespace/device/port authority differs: $namespace_inspect"
container_output="$("$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID")" \
    || fail 'probe container execution failed'
[ "$container_output" = 'VERIFIER_INNER_CONTAINER=pass uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default' ] \
    || fail "probe container result differs: $container_output"
[ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
    || fail 'probe container did not exit cleanly'
"$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=
"$CLIENT" --host "unix://$SOCK" image rm "$IMAGE" >/dev/null

kill -TERM "$DAEMON_PID"
daemon_status=0
wait "$DAEMON_PID" || daemon_status=$?
[ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] \
    || fail "Docker daemon shutdown returned $daemon_status"
DAEMON_PID=
[ ! -S "$SOCK" ] || fail 'Docker Unix socket remains after joined daemon shutdown'
network_inventory >"$ROOT.network-after"
cmp -s "$ROOT.network-before" "$ROOT.network-after" \
    || fail 'guest network state changed across Docker execution'
[ ! -e /sys/class/net/docker0 ] || fail 'Docker bridge remains after shutdown'

printf 'VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=%s direct_boot=on boot_masks=on docker=%s vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default\n' \
    "$EXPECTED_KERNEL_RELEASE" "$EXPECTED_VERSION"

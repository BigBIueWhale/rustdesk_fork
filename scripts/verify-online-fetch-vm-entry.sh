#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

fail() {
    printf 'online-fetch VM entry preflight: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail 'this preflight takes no arguments'
[ "${RUSTDESK_ONLINE_FETCH_VM_GUEST:-}" = 1 ] \
    || fail 'guest authority marker is absent'
[ "$(/usr/bin/id -u)" -ne 0 ] || fail 'online-fetch VM entry refuses root'

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly AUTHORITY_ROOT=/opt/rustdesk-online-fetch-vm
readonly AUTHORITY_RECORD="$AUTHORITY_ROOT/authority"
readonly RENAME_CONTRACT="$AUTHORITY_ROOT/rename.contract"
readonly DOCKER_CLIENT=/usr/bin/docker
readonly DOCKER_SOCKET=/var/run/docker.sock
readonly DOCKER_DAEMON="$AUTHORITY_ROOT/bin/dockerd"
readonly DOCKER_DAEMON_CONFIG="$AUTHORITY_ROOT/daemon.json"
readonly BUILDX_SOURCE="$AUTHORITY_ROOT/docker-buildx"
readonly BUILDKIT_ROOT=/opt/rustdesk-online-fetch-buildkit
readonly BUILDKIT_BIN="$BUILDKIT_ROOT/bin"
readonly BUILDKIT_CNI="$BUILDKIT_ROOT/cni"
readonly BUILDKIT_DATA=/var/lib/rustdesk-online-fetch-buildkit
readonly BUILDKIT_EXEC=/run/rustdesk-online-fetch-buildkit
readonly BUILDKIT_SOCKET="$BUILDKIT_EXEC/buildkitd.sock"
readonly BUILDKIT_CONFIG="$BUILDKIT_ROOT/buildkitd.toml"
readonly BUILDKIT_LOG="$BUILDKIT_ROOT/buildkitd.log"
readonly BUILDKIT_PIDFILE="$BUILDKIT_ROOT/buildkitd.pid"
readonly BUILDKIT_DAEMON="$BUILDKIT_BIN/buildkitd"
readonly BUILDKIT_RUNC="$BUILDKIT_BIN/buildkit-runc"
readonly GIT_RUNTIME_ROOT=/opt/rustdesk-online-fetch-git
readonly GIT_BIN=$GIT_RUNTIME_ROOT/usr/bin/git
readonly GIT_EXEC_PATH=$GIT_RUNTIME_ROOT/usr/lib/git-core
readonly GIT_TEMPLATE_DIR=$GIT_RUNTIME_ROOT/usr/share/git-core/templates
readonly EXPECTED_MAC=52:54:00:52:44:01
readonly EXPECTED_ADDRESS=10.0.2.15/24
readonly EXPECTED_GATEWAY=10.0.2.2
readonly EXPECTED_CMDLINE="root=UUID=$VERIFIER_VM_ROOT_FILESYSTEM_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.online_fetch_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=systemd-timesyncd.service systemd.mask=systemd-resolved.service systemd.mask=apt-daily.service systemd.mask=apt-daily.timer systemd.mask=apt-daily-upgrade.service systemd.mask=apt-daily-upgrade.timer systemd.mask=unattended-upgrades.service systemd.mask=ssh.service systemd.mask=ssh.socket"

[ "$(/usr/bin/cat /proc/1/comm)" = systemd ] \
    || fail 'guest PID 1 is not systemd'
[ "$(/usr/bin/cat /proc/cmdline)" = "$EXPECTED_CMDLINE" ] \
    || fail 'kernel command line is not the acquisition-VM authority'
[ "$(/usr/bin/uname -r)" = "$VERIFIER_VM_KERNEL_RELEASE" ] \
    || fail 'running kernel differs from the authenticated acquisition kernel'
[ -r /etc/os-release ] || fail 'guest OS identity is absent'
# shellcheck source=/dev/null
source /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail 'guest is not the pinned Debian bookworm base'

[ -d "$AUTHORITY_ROOT" ] && [ ! -L "$AUTHORITY_ROOT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$AUTHORITY_ROOT")" = 0:0:555 ] \
    || fail 'VM authority root metadata differs'
[ -f "$AUTHORITY_RECORD" ] && [ ! -L "$AUTHORITY_RECORD" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$AUTHORITY_RECORD")" = 0:0:444:1 ] \
    || fail 'VM authority record metadata differs'
[ -f "$RENAME_CONTRACT" ] && [ ! -L "$RENAME_CONTRACT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RENAME_CONTRACT")" = 0:0:444:1 ] \
    && [ "$(/usr/bin/cat "$RENAME_CONTRACT")" = \
      'VIRTIOFS_RENAME_CONTRACT=pass noreplace=cross-parent collision=no-clobber exchange=nonempty cleanup=complete' ] \
    || fail 'virtiofs flagged-rename authority receipt differs'
[ -d "$GIT_RUNTIME_ROOT" ] && [ ! -L "$GIT_RUNTIME_ROOT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$GIT_RUNTIME_ROOT")" = 0:0:555 ] \
    || fail 'fixed Git runtime root metadata differs'
[ -f "$GIT_BIN" ] && [ ! -L "$GIT_BIN" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GIT_BIN")" = \
         "0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY" ] \
    && [ "$(/usr/bin/sha256sum "$GIT_BIN" | /usr/bin/awk '{print $1}')" = \
         "$SHA256_VERIFIER_VM_GIT_BINARY" ] \
    || fail 'fixed Git runtime binary identity differs'
[ -d "$GIT_EXEC_PATH" ] && [ ! -L "$GIT_EXEC_PATH" ] \
    && [ -d "$GIT_TEMPLATE_DIR" ] && [ ! -L "$GIT_TEMPLATE_DIR" ] \
    || fail 'fixed Git runtime layout differs'
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
    GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
    "$GIT_BIN" --version)" = 'git version 2.39.5' ] \
    || fail 'fixed Git runtime version differs'

IFS=' ' read -r version_field uid_field gid_field commit_field tree_field udp_field \
    docker_pid_field docker_start_field docker_daemon_sha_field \
    docker_client_sha_field buildkit_pid_field buildkit_start_field \
    buildkitd_sha_field buildkit_runc_sha_field buildkit_cni_bridge_sha_field \
    buildkit_cni_firewall_sha_field buildkit_cni_host_local_sha_field \
    buildkit_cni_loopback_sha_field buildkit_config_sha_field extra \
    <"$AUTHORITY_RECORD" || fail 'cannot read the VM authority record'
[ -z "${extra:-}" ] || fail 'VM authority record has extra fields'
[ "$version_field" = version=2 ] || fail 'VM authority-record version differs'
for field in "$uid_field:uid=" "$gid_field:gid=" "$commit_field:commit=" \
    "$tree_field:tree=" "$udp_field:udp=" \
    "$docker_pid_field:docker_pid=" "$docker_start_field:docker_start=" \
    "$docker_daemon_sha_field:docker_daemon_sha256=" \
    "$docker_client_sha_field:docker_client_sha256=" \
    "$buildkit_pid_field:buildkit_pid=" "$buildkit_start_field:buildkit_start=" \
    "$buildkitd_sha_field:buildkitd_sha256=" \
    "$buildkit_runc_sha_field:buildkit_runc_sha256=" \
    "$buildkit_cni_bridge_sha_field:buildkit_cni_bridge_sha256=" \
    "$buildkit_cni_firewall_sha_field:buildkit_cni_firewall_sha256=" \
    "$buildkit_cni_host_local_sha_field:buildkit_cni_host_local_sha256=" \
    "$buildkit_cni_loopback_sha_field:buildkit_cni_loopback_sha256=" \
    "$buildkit_config_sha_field:buildkit_config_sha256="; do
    value=${field%%:*}
    prefix=${field#*:}
    case "$value" in "$prefix"*) ;; *) fail 'VM authority record field name differs' ;; esac
done
readonly EXPECTED_UID="${uid_field#uid=}"
readonly EXPECTED_GID="${gid_field#gid=}"
readonly EXPECTED_COMMIT="${commit_field#commit=}"
readonly EXPECTED_TREE="${tree_field#tree=}"
[ "$udp_field" = udp=denied ] || fail 'VM authority record does not bind TCP-only acquisition'
readonly DOCKER_PID="${docker_pid_field#docker_pid=}"
readonly DOCKER_START="${docker_start_field#docker_start=}"
readonly EXPECTED_DOCKER_DAEMON_SHA="${docker_daemon_sha_field#docker_daemon_sha256=}"
readonly EXPECTED_DOCKER_CLIENT_SHA="${docker_client_sha_field#docker_client_sha256=}"
readonly BUILDKIT_PID="${buildkit_pid_field#buildkit_pid=}"
readonly BUILDKIT_START="${buildkit_start_field#buildkit_start=}"
readonly EXPECTED_BUILDKITD_SHA="${buildkitd_sha_field#buildkitd_sha256=}"
readonly EXPECTED_BUILDKIT_RUNC_SHA="${buildkit_runc_sha_field#buildkit_runc_sha256=}"
readonly EXPECTED_BUILDKIT_CNI_BRIDGE_SHA="${buildkit_cni_bridge_sha_field#buildkit_cni_bridge_sha256=}"
readonly EXPECTED_BUILDKIT_CNI_FIREWALL_SHA="${buildkit_cni_firewall_sha_field#buildkit_cni_firewall_sha256=}"
readonly EXPECTED_BUILDKIT_CNI_HOST_LOCAL_SHA="${buildkit_cni_host_local_sha_field#buildkit_cni_host_local_sha256=}"
readonly EXPECTED_BUILDKIT_CNI_LOOPBACK_SHA="${buildkit_cni_loopback_sha_field#buildkit_cni_loopback_sha256=}"
readonly EXPECTED_BUILDKIT_CONFIG_SHA="${buildkit_config_sha_field#buildkit_config_sha256=}"

for identity in "$EXPECTED_UID" "$EXPECTED_GID" "$DOCKER_PID" "$DOCKER_START" \
    "$BUILDKIT_PID" "$BUILDKIT_START"; do
    [[ "$identity" =~ ^[1-9][0-9]*$ ]] || fail 'VM authority record has a malformed numeric identity'
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'VM authority record has a malformed source commit'
[[ "$EXPECTED_TREE" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'VM authority record has a malformed source tree'
for digest in "$EXPECTED_DOCKER_DAEMON_SHA" "$EXPECTED_DOCKER_CLIENT_SHA" \
    "$EXPECTED_BUILDKITD_SHA" "$EXPECTED_BUILDKIT_RUNC_SHA" \
    "$EXPECTED_BUILDKIT_CNI_BRIDGE_SHA" "$EXPECTED_BUILDKIT_CNI_FIREWALL_SHA" \
    "$EXPECTED_BUILDKIT_CNI_HOST_LOCAL_SHA" "$EXPECTED_BUILDKIT_CNI_LOOPBACK_SHA" \
    "$EXPECTED_BUILDKIT_CONFIG_SHA"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'VM authority record has a malformed executable or configuration digest'
done
[ "$(/usr/bin/id -u)" = "$EXPECTED_UID" ] \
    && [ "$(/usr/bin/id -g)" = "$EXPECTED_GID" ] \
    || fail 'caller is not the exact admitted acquisition principal'
[ "${RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT:-}" = "$EXPECTED_COMMIT" ] \
    && [ "${RUSTDESK_ONLINE_FETCH_VM_SOURCE_TREE:-}" = "$EXPECTED_TREE" ] \
    || fail 'source identity environment differs from the root-authored authority'

[ -f "$DOCKER_CLIENT" ] && [ ! -L "$DOCKER_CLIENT" ] && [ -x "$DOCKER_CLIENT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DOCKER_CLIENT")" = 0:0:755:1 ] \
    || fail 'fixed guest Docker client metadata differs'
[ -f "$DOCKER_DAEMON" ] && [ ! -L "$DOCKER_DAEMON" ] && [ -x "$DOCKER_DAEMON" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DOCKER_DAEMON")" = 0:0:555:1 ] \
    || fail 'fixed guest Docker daemon metadata differs'
[ -f "$DOCKER_DAEMON_CONFIG" ] && [ ! -L "$DOCKER_DAEMON_CONFIG" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DOCKER_DAEMON_CONFIG")" = 0:0:444:1 ] \
    && [ "$(/usr/bin/cat "$DOCKER_DAEMON_CONFIG")" = \
         '{"features":{"containerd-snapshotter":true}}' ] \
    || fail 'fixed guest Docker daemon configuration differs'
[ -f "$BUILDX_SOURCE" ] && [ ! -L "$BUILDX_SOURCE" ] && [ -x "$BUILDX_SOURCE" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$BUILDX_SOURCE")" = \
         "0:0:555:1:$SIZE_VERIFIER_VM_BUILDX" ] \
    && [ "$(/usr/bin/sha256sum "$BUILDX_SOURCE" | /usr/bin/awk '{print $1}')" = \
         "$SHA256_VERIFIER_VM_BUILDX" ] \
    || fail 'fixed guest Buildx source identity differs'
[ "$(/usr/bin/sha256sum "$DOCKER_CLIENT" | /usr/bin/awk '{print $1}')" = \
  "$EXPECTED_DOCKER_CLIENT_SHA" ] \
    && [ "$(/usr/bin/sha256sum "$DOCKER_DAEMON" | /usr/bin/awk '{print $1}')" = \
         "$EXPECTED_DOCKER_DAEMON_SHA" ] \
    || fail 'guest Docker executable bytes differ from the root-authored authority'
[ -S "$DOCKER_SOCKET" ] && [ ! -L "$DOCKER_SOCKET" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$DOCKER_SOCKET")" = "0:$EXPECTED_GID:660" ] \
    || fail 'guest Docker Unix-socket authority differs'
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
       "$DOCKER_CLIENT" --host "unix://$DOCKER_SOCKET" \
       info --format '{{json .DriverStatus}}')" = \
  '[["driver-type","io.containerd.snapshotter.v1"]]' ] \
    || fail 'guest Docker image-store authority differs'
[ -r "/proc/$DOCKER_PID/stat" ] \
    && [ "$(/usr/bin/awk '{print $22}' "/proc/$DOCKER_PID/stat")" = "$DOCKER_START" ] \
    || fail 'guest Docker daemon generation differs'
[ "$(/usr/bin/awk '/^Uid:/ {print $2":"$3":"$4":"$5}' "/proc/$DOCKER_PID/status")" = 0:0:0:0 ] \
    || fail 'guest Docker daemon is not VM-local root'
server_version="$(
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
        "$DOCKER_CLIENT" --host "unix://$DOCKER_SOCKET" \
        version --format '{{.Server.Version}}'
)" || fail 'cannot query the exact guest Docker daemon'
[ "$server_version" = "$VERIFIER_VM_DOCKER_VERSION" ] \
    || fail 'guest Docker server version differs'

[ "$EXPECTED_BUILDKITD_SHA:$EXPECTED_BUILDKIT_RUNC_SHA:$EXPECTED_BUILDKIT_CNI_BRIDGE_SHA:$EXPECTED_BUILDKIT_CNI_FIREWALL_SHA:$EXPECTED_BUILDKIT_CNI_HOST_LOCAL_SHA:$EXPECTED_BUILDKIT_CNI_LOOPBACK_SHA" = \
  "$SHA256_VERIFIER_VM_BUILDKITD:$SHA256_VERIFIER_VM_BUILDKIT_RUNC:$SHA256_VERIFIER_VM_BUILDKIT_CNI_BRIDGE:$SHA256_VERIFIER_VM_BUILDKIT_CNI_FIREWALL:$SHA256_VERIFIER_VM_BUILDKIT_CNI_HOST_LOCAL:$SHA256_VERIFIER_VM_BUILDKIT_CNI_LOOPBACK" ] \
    || fail 'root-authored BuildKit component authority differs from the committed pins'
[ -d "$BUILDKIT_ROOT" ] && [ ! -L "$BUILDKIT_ROOT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_ROOT")" = 0:0:555 ] \
    && [ "$(/usr/bin/find "$BUILDKIT_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\n' \
            | LC_ALL=C /usr/bin/sort)" = \
         $'bin\nbuildkitd.log\nbuildkitd.pid\nbuildkitd.toml\ncni' ] \
    || fail 'fixed BuildKit authority root differs'
[ -d "$BUILDKIT_BIN" ] && [ ! -L "$BUILDKIT_BIN" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_BIN")" = 0:0:555 ] \
    && [ "$(/usr/bin/find "$BUILDKIT_BIN" -mindepth 1 -maxdepth 1 -printf '%f\n' \
            | LC_ALL=C /usr/bin/sort)" = $'buildkit-runc\nbuildkitd' ] \
    || fail 'fixed BuildKit binary inventory differs'
[ -d "$BUILDKIT_CNI" ] && [ ! -L "$BUILDKIT_CNI" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_CNI")" = 0:0:555 ] \
    && [ "$(/usr/bin/find "$BUILDKIT_CNI" -mindepth 1 -maxdepth 1 -printf '%f\n' \
            | LC_ALL=C /usr/bin/sort)" = $'bridge\nfirewall\nhost-local\nloopback' ] \
    || fail 'fixed BuildKit CNI inventory differs'
verify_buildkit_component() {
    [ "$#" -eq 5 ] || fail 'internal BuildKit component-verification argument count differs'
    local path=$1 expected_size=$2 expected_sha=$3 authority_sha=$4 label=$5
    [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
             "0:0:555:1:$expected_size" ] \
        && [ "$(/usr/bin/sha256sum "$path" | /usr/bin/awk '{print $1}')" = \
             "$expected_sha" ] \
        && [ "$expected_sha" = "$authority_sha" ] \
        || fail "fixed BuildKit $label identity differs"
}
verify_buildkit_component "$BUILDKIT_DAEMON" "$SIZE_VERIFIER_VM_BUILDKITD" \
    "$SHA256_VERIFIER_VM_BUILDKITD" "$EXPECTED_BUILDKITD_SHA" daemon
verify_buildkit_component "$BUILDKIT_RUNC" "$SIZE_VERIFIER_VM_BUILDKIT_RUNC" \
    "$SHA256_VERIFIER_VM_BUILDKIT_RUNC" "$EXPECTED_BUILDKIT_RUNC_SHA" runtime
verify_buildkit_component "$BUILDKIT_CNI/bridge" \
    "$SIZE_VERIFIER_VM_BUILDKIT_CNI_BRIDGE" \
    "$SHA256_VERIFIER_VM_BUILDKIT_CNI_BRIDGE" \
    "$EXPECTED_BUILDKIT_CNI_BRIDGE_SHA" 'CNI bridge'
verify_buildkit_component "$BUILDKIT_CNI/firewall" \
    "$SIZE_VERIFIER_VM_BUILDKIT_CNI_FIREWALL" \
    "$SHA256_VERIFIER_VM_BUILDKIT_CNI_FIREWALL" \
    "$EXPECTED_BUILDKIT_CNI_FIREWALL_SHA" 'CNI firewall'
verify_buildkit_component "$BUILDKIT_CNI/host-local" \
    "$SIZE_VERIFIER_VM_BUILDKIT_CNI_HOST_LOCAL" \
    "$SHA256_VERIFIER_VM_BUILDKIT_CNI_HOST_LOCAL" \
    "$EXPECTED_BUILDKIT_CNI_HOST_LOCAL_SHA" 'CNI host-local'
verify_buildkit_component "$BUILDKIT_CNI/loopback" \
    "$SIZE_VERIFIER_VM_BUILDKIT_CNI_LOOPBACK" \
    "$SHA256_VERIFIER_VM_BUILDKIT_CNI_LOOPBACK" \
    "$EXPECTED_BUILDKIT_CNI_LOOPBACK_SHA" 'CNI loopback'
expected_buildkit_config="$(/usr/bin/printf '%s\n' \
    'root = "/var/lib/rustdesk-online-fetch-buildkit"' \
    'insecure-entitlements = []' \
    '' \
    '[grpc]' \
    '  address = ["unix:///run/rustdesk-online-fetch-buildkit/buildkitd.sock"]' \
    '  uid = 0' \
    "  gid = $EXPECTED_GID" \
    '' \
    '[worker.oci]' \
    '  enabled = true' \
    '  platforms = ["linux/amd64"]' \
    '  snapshotter = "overlayfs"' \
    '  rootless = false' \
    '  noProcessSandbox = false' \
    '  gc = false' \
    '  networkMode = "bridge"' \
    '  cniBinaryPath = "/opt/rustdesk-online-fetch-buildkit/cni"' \
    '  cniPoolSize = 0' \
    '  bridgeName = "rdbk0"' \
    '  bridgeSubnet = "172.31.0.0/24"' \
    '  binary = "/opt/rustdesk-online-fetch-buildkit/bin/buildkit-runc"' \
    '  max-parallelism = 4' \
    '' \
    '[worker.containerd]' \
    '  enabled = false')"
[ -f "$BUILDKIT_CONFIG" ] && [ ! -L "$BUILDKIT_CONFIG" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$BUILDKIT_CONFIG")" = 0:0:444:1 ] \
    && [ "$(/usr/bin/cat "$BUILDKIT_CONFIG")" = "$expected_buildkit_config" ] \
    && [ "$(/usr/bin/sha256sum "$BUILDKIT_CONFIG" | /usr/bin/awk '{print $1}')" = \
         "$EXPECTED_BUILDKIT_CONFIG_SHA" ] \
    || fail 'fixed guest BuildKit configuration differs'
[ -f "$BUILDKIT_LOG" ] && [ ! -L "$BUILDKIT_LOG" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$BUILDKIT_LOG")" = 0:0:400:1 ] \
    && [ -f "$BUILDKIT_PIDFILE" ] && [ ! -L "$BUILDKIT_PIDFILE" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$BUILDKIT_PIDFILE")" = 0:0:444:1 ] \
    && [ "$(/usr/bin/cat "$BUILDKIT_PIDFILE")" = "$BUILDKIT_PID" ] \
    || fail 'fixed BuildKit log or PID authority differs'
[ -d "$BUILDKIT_DATA" ] && [ ! -L "$BUILDKIT_DATA" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_DATA")" = 0:0:700 ] \
    && [ -d "$BUILDKIT_EXEC" ] && [ ! -L "$BUILDKIT_EXEC" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_EXEC")" = \
         "0:$EXPECTED_GID:710" ] \
    && [ -S "$BUILDKIT_SOCKET" ] && [ ! -L "$BUILDKIT_SOCKET" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BUILDKIT_SOCKET")" = \
         "0:$EXPECTED_GID:660" ] \
    || fail 'guest BuildKit filesystem or socket authority differs'
[ -r "/proc/$BUILDKIT_PID/stat" ] \
    && [ "$(/usr/bin/awk '{print $22}' "/proc/$BUILDKIT_PID/stat")" = "$BUILDKIT_START" ] \
    || fail 'guest BuildKit daemon generation differs'
[ "$(/usr/bin/awk '/^Uid:/ {print $2":"$3":"$4":"$5}' "/proc/$BUILDKIT_PID/status")" = 0:0:0:0 ] \
    || fail 'guest BuildKit daemon is not VM-local root'
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
       "$BUILDKIT_DAEMON" --version)" = \
  "buildkitd github.com/moby/buildkit v${VERIFIER_VM_BUILDKIT_VERSION} ${VERIFIER_VM_BUILDKIT_COMMIT}" ] \
    || fail 'guest BuildKit daemon version differs'

mapfile -t matching_interfaces < <(
    for address in /sys/class/net/*/address; do
        [ "$(/usr/bin/cat "$address")" = "$EXPECTED_MAC" ] \
            && /usr/bin/basename "$(/usr/bin/dirname "$address")"
    done
)
[ "${#matching_interfaces[@]}" -eq 1 ] \
    || fail 'acquisition NIC identity is absent or ambiguous'
readonly ACQUISITION_INTERFACE="${matching_interfaces[0]}"
[ "$(/usr/sbin/ip -4 -o address show dev "$ACQUISITION_INTERFACE" scope global \
      | /usr/bin/awk '{print $4}')" = "$EXPECTED_ADDRESS" ] \
    || fail 'acquisition NIC address differs'
mapfile -t default_routes < <(/usr/sbin/ip -4 -o route show default)
[ "${#default_routes[@]}" -eq 1 ] \
    || fail 'acquisition default route is absent or ambiguous'
read -r route_destination route_via route_gateway route_dev route_interface _ \
    <<<"${default_routes[0]}"
[ "$route_destination:$route_via:$route_gateway:$route_dev:$route_interface" = \
  "default:via:$EXPECTED_GATEWAY:dev:$ACQUISITION_INTERFACE" ] \
    || fail "acquisition default route differs: ${default_routes[0]}"
[ -d /sys/class/net/docker0 ] \
    && [ "$(/usr/sbin/ip -4 -o address show dev docker0 scope global \
          | /usr/bin/awk '{print $4}')" = 172.30.0.1/24 ] \
    || fail 'guest-only Docker bridge identity differs'
[ -d /sys/class/net/rdbk0 ] \
    && [ "$(/usr/sbin/ip -4 -o address show dev rdbk0 scope global \
          | /usr/bin/awk '{print $4}')" = 172.31.0.1/24 ] \
    || fail 'guest-only BuildKit bridge identity differs'
[ "$(/usr/bin/cat /proc/sys/net/ipv4/ip_forward)" = 1 ] \
    || fail 'guest-only build forwarding is not enabled'
[ "$(/usr/sbin/iptables -S OUTPUT | /usr/bin/awk 'NR == 2')" = \
  '-A OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    && [ "$(/usr/sbin/iptables -S DOCKER-USER | /usr/bin/awk 'NR == 2')" = \
         '-A DOCKER-USER -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    && [ "$(/usr/sbin/iptables -S FORWARD | /usr/bin/awk 'NR == 2')" = \
         '-A FORWARD -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    || fail 'TCP-only acquisition filter authority differs'

verify_cache_mount() {
    [ "$#" -eq 4 ] || fail 'internal cache-mount argument error'
    local path=$1 source=$2 expected_fstype=$3 executable=$4 options
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$path")" = "$EXPECTED_UID:$EXPECTED_GID:700" ] \
        || fail "cache export metadata differs: $path"
    [ "$(/usr/bin/findmnt -n -o FSTYPE --target "$path")" = "$expected_fstype" ] \
        || fail "cache export filesystem differs: $path"
    [ "$(/usr/bin/findmnt -n -o SOURCE --target "$path")" = "$source" ] \
        || fail "cache export source differs: $path"
    options=",$(/usr/bin/findmnt -n -o OPTIONS --target "$path"),"
    case "$options" in *,rw,*) ;; *) fail "cache export is not writable: $path" ;; esac
    case "$options" in *,nodev,*) ;; *) fail "cache export permits devices: $path" ;; esac
    case "$options" in *,nosuid,*) ;; *) fail "cache export permits set-user-ID execution: $path" ;; esac
    case "$executable:$options" in
        exec:*,noexec,*) fail "cache export unexpectedly forbids execution: $path" ;;
        exec:*) ;;
        noexec:*,noexec,*) ;;
        noexec:*) fail "cache export permits execution: $path" ;;
        *) fail 'internal cache-mount executable policy differs' ;;
    esac
}

verify_cache_mount "$REPO_ROOT/online" rustdesk-cache-state virtiofs exec
verify_cache_mount "$REPO_ROOT/.harness-state/debian-systemd-smoke" \
    rustdesk-systemd-cache virtiofs noexec
verify_cache_mount /run/rustdesk-online-fetch-result rustdesk-result virtiofs noexec
cache_inventory="$(
    /usr/bin/find "$REPO_ROOT/online" -mindepth 1 -maxdepth 1 -printf '%f\n' \
        | LC_ALL=C /usr/bin/sort
)"
[ "$cache_inventory" = $'inputs\nretired' ] \
    || fail 'cache state root contains something other than the one inputs/retired layout'
for path in "$REPO_ROOT/online/inputs" "$REPO_ROOT/online/retired"; do
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$path")" = "$EXPECTED_UID:$EXPECTED_GID:700" ] \
        || fail "cache-state child metadata differs: $path"
    [ "$(/usr/bin/findmnt -n -o FSTYPE --target "$path")" = virtiofs ] \
        && [ "$(/usr/bin/findmnt -n -o SOURCE --target "$path")" = rustdesk-cache-state ] \
        || fail "cache-state child escaped the common virtiofs mount: $path"
done
[ "$(/usr/bin/stat -c '%d' -- "$REPO_ROOT/online")" \
  = "$(/usr/bin/stat -c '%d' -- "$REPO_ROOT/online/inputs")" ] \
    && [ "$(/usr/bin/stat -c '%d' -- "$REPO_ROOT/online/inputs")" \
         = "$(/usr/bin/stat -c '%d' -- "$REPO_ROOT/online/retired")" ] \
    || fail 'active and retired cache roots do not share one atomic-rename filesystem'

current_commit="$(
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}'
)" || fail 'cannot resolve admitted source commit'
current_tree="$(
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}'
)" || fail 'cannot resolve admitted source tree'
[ "$current_commit:$current_tree" = "$EXPECTED_COMMIT:$EXPECTED_TREE" ] \
    || fail 'admitted source identity changed'
[ -z "$(
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=no
)" ] || fail 'tracked admitted source is dirty'

printf 'ONLINE_FETCH_VM_ENTRY_AUTHORITY=pass uid=%s gid=%s source=%s network=qemu-user-only udp=denied docker=guest-unix image_store=containerd buildkit=guest-unix git=pinned-deb cache=virtiofs-atomic\n' \
    "$EXPECTED_UID" "$EXPECTED_GID" "$EXPECTED_COMMIT"

#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 4 ] \
    || { echo 'usage: smoke-verifier-vm-authority-guest.sh DOCKER_TGZ VERSION SIZE SHA256' >&2; exit 2; }
readonly DOCKER_ARCHIVE=$1
readonly EXPECTED_VERSION=$2
readonly EXPECTED_SIZE=$3
readonly EXPECTED_SHA256=$4
readonly ROOT=/var/tmp/rustdesk-verifier-authority
readonly BIN=$ROOT/bin
readonly DAEMON_PATH=$BIN:/usr/sbin:/usr/bin:/sbin:/bin
readonly DATA=$ROOT/data
readonly EXEC=$ROOT/exec
readonly SOCK=$ROOT/docker.sock
readonly PIDFILE=$ROOT/docker.pid
readonly LOG=$ROOT/dockerd.log
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
    if [ -n "$CONTAINER_ID" ] && [ -x "$BIN/docker" ]; then
        "$BIN/docker" --host "unix://$SOCK" rm -f "$CONTAINER_ID" >/dev/null 2>&1 \
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
[ -f "$DOCKER_ARCHIVE" ] && [ ! -L "$DOCKER_ARCHIVE" ] \
    || fail 'Docker bundle is not one regular payload file'
[ "$(stat -c '%s:%h' -- "$DOCKER_ARCHIVE")" = "$EXPECTED_SIZE:1" ] \
    || fail 'Docker bundle size or link count differs inside the guest'
[ "$(sha256sum "$DOCKER_ARCHIVE" | awk '{print $1}')" = "$EXPECTED_SHA256" ] \
    || fail 'Docker bundle digest differs inside the guest'
mount_options="$(findmnt -n -o OPTIONS --target "$DOCKER_ARCHIVE")" \
    || fail 'Docker bundle payload mount is absent'
case ",$mount_options," in *,ro,*) ;; *) fail 'Docker payload is not read-only' ;; esac
case ",$mount_options," in *,nodev,*) ;; *) fail 'Docker payload permits devices' ;; esac
case ",$mount_options," in *,nosuid,*) ;; *) fail 'Docker payload permits set-user-ID execution' ;; esac

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

# A networkless verifier appliance has no use for an SSH daemon. Stop the
# cloud image's default service before recording the guest listener baseline.
systemctl stop ssh.service || fail 'cannot stop the unnecessary guest SSH service'

mapfile -t interfaces < <(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[ "${#interfaces[@]}" -eq 1 ] && [ "${interfaces[0]}" = lo ] \
    || fail "networkless VM has an unexpected interface inventory: ${interfaces[*]}"
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'guest IPv4 forwarding is enabled before Docker'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'guest IPv6 forwarding is enabled before Docker'
network_inventory >"$ROOT.network-before"

mkdir -p "$BIN" "$DATA" "$EXEC" "$ROOT/rootfs/bin" "$ROOT/rootfs/lib" "$ROOT/rootfs/lib64"
chmod 0700 "$ROOT" "$DATA" "$EXEC"
archive_inventory="$(tar -tzf "$DOCKER_ARCHIVE")" || fail 'Docker bundle inventory cannot be read'
[ "$archive_inventory" = $'docker/\ndocker/runc\ndocker/containerd\ndocker/docker-init\ndocker/dockerd\ndocker/containerd-shim-runc-v2\ndocker/docker-proxy\ndocker/docker\ndocker/ctr' ] \
    || fail 'Docker bundle has a noncanonical member inventory or order'
tar -xzf "$DOCKER_ARCHIVE" --strip-components=1 --no-same-owner --no-same-permissions \
    -C "$BIN" \
    docker/runc docker/containerd docker/docker-init docker/dockerd \
    docker/containerd-shim-runc-v2 docker/docker-proxy docker/docker docker/ctr
chmod 0500 "$BIN"/*
[ "$(find "$BIN" -mindepth 1 -maxdepth 1 -type f -perm 0500 | wc -l)" -eq 8 ] \
    || fail 'extracted Docker binary inventory differs'
[ -z "$(find "$BIN" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
    || fail 'extracted Docker bundle contains a non-regular entry'

docker_version="$($BIN/docker --version)"
dockerd_version="$($BIN/dockerd --version)"
case "$docker_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker client version differs: $docker_version" ;; esac
case "$dockerd_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker daemon version differs: $dockerd_version" ;; esac

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
            "$BIN/docker" --host "unix://$SOCK" info --format '{{.ServerVersion}}' \
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
[ "$(stat -c '%u:%g' -- "$SOCK")" = 0:0 ] || fail 'Docker Unix socket ownership differs'
[ ! -e /sys/class/net/docker0 ] || fail 'Docker created a guest bridge despite --bridge=none'
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'Docker enabled guest IPv4 forwarding'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'Docker enabled guest IPv6 forwarding'
network_inventory >"$ROOT.network-during"
cmp -s "$ROOT.network-before" "$ROOT.network-during" \
    || fail 'guest Docker created an INET listener'

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
    | "$BIN/docker" --host "unix://$SOCK" import \
        --change 'USER 4000:4000' \
        --change 'ENTRYPOINT ["/bin/dash"]' \
        - "$IMAGE" >"$ROOT/image-id"
[[ "$(<"$ROOT/image-id")" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'probe image ID is malformed'

CONTAINER_ID="$(
    "$BIN/docker" --host "unix://$SOCK" create \
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
inspect="$($BIN/docker --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
    "$CONTAINER_ID")"
[ "$inspect" = 'none|true|4000:4000|67108864|67108864|500000000|16|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
    || fail "probe container authority differs: $inspect"
namespace_inspect="$($BIN/docker --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.Binds}}|{{json .HostConfig.PortBindings}}' \
    "$CONTAINER_ID")"
[ "$namespace_inspect" = 'false||private||private|[]|null|{}' ] \
    || fail "probe container namespace/device/port authority differs: $namespace_inspect"
container_output="$($BIN/docker --host "unix://$SOCK" start --attach "$CONTAINER_ID")" \
    || fail 'probe container execution failed'
[ "$container_output" = 'VERIFIER_INNER_CONTAINER=pass uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default' ] \
    || fail "probe container result differs: $container_output"
[ "$($BIN/docker --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
    || fail 'probe container did not exit cleanly'
"$BIN/docker" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=
"$BIN/docker" --host "unix://$SOCK" image rm "$IMAGE" >/dev/null

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

printf 'VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 docker=%s vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default\n' \
    "$EXPECTED_VERSION"

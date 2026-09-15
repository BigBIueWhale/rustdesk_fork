#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

fail() {
    printf 'online-fetch acquisition VM: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 16 ] || fail 'guest bootstrap argument count differs'
readonly DOCKER_ARCHIVE=$1
readonly SOURCE_BUNDLE=$2
readonly GIT_PACKAGE=$3
readonly EXPECTED_DOCKER_VERSION=$4
readonly EXPECTED_DOCKER_SIZE=$5
readonly EXPECTED_DOCKER_SHA256=$6
readonly EXPECTED_GIT_PACKAGE_VERSION=$7
readonly EXPECTED_GIT_PACKAGE_SIZE=$8
readonly EXPECTED_GIT_PACKAGE_SHA256=$9
readonly EXPECTED_GIT_BINARY_SIZE=${10}
readonly EXPECTED_GIT_BINARY_SHA256=${11}
readonly EXPECTED_KERNEL_RELEASE=${12}
readonly EXPECTED_ROOT_UUID=${13}
readonly ACQUISITION_UID=${14}
readonly ACQUISITION_GID=${15}
readonly EXPECTED_SOURCE_COMMIT=${16}
readonly EXPECTED_SOURCE_TREE="$(/usr/bin/cat /mnt/rustdesk-online-fetch-inputs/source.tree)"
readonly EXPECTED_SOURCE_BUNDLE_SHA256="$(/usr/bin/cat /mnt/rustdesk-online-fetch-inputs/source.bundle.sha256)"
REQUEST="$(/usr/bin/cat /mnt/rustdesk-online-fetch-inputs/request)"

readonly ROOT=/opt/rustdesk-online-fetch-vm
readonly BIN=$ROOT/bin
readonly DATA=/var/lib/rustdesk-online-fetch-docker
readonly EXEC=/run/rustdesk-online-fetch-docker
readonly LOG=$ROOT/dockerd.log
readonly PIDFILE=$ROOT/dockerd.pid
readonly SOCKET=/var/run/docker.sock
readonly CLIENT=/usr/bin/docker
readonly GIT_RUNTIME_ROOT=/opt/rustdesk-online-fetch-git
readonly GIT_BIN=$GIT_RUNTIME_ROOT/usr/bin/git
readonly GIT_EXEC_PATH=$GIT_RUNTIME_ROOT/usr/lib/git-core
readonly GIT_TEMPLATE_DIR=$GIT_RUNTIME_ROOT/usr/share/git-core/templates
readonly AUTHORITY_RECORD=$ROOT/authority
readonly RENAME_CONTRACT=$ROOT/rename.contract
readonly WORK_ROOT=/var/tmp/rustdesk-online-fetch
readonly BUNDLE_VERIFY_REPO=$WORK_ROOT/bundle-verifier.git
readonly REPO=$WORK_ROOT/repo
readonly FOREIGN_PREFLIGHT_ROOT=/opt/rustdesk-online-fetch-preflight-probe
readonly RESULT_ROOT=/run/rustdesk-online-fetch-result
readonly RESULT_STDOUT=$RESULT_ROOT/transaction.stdout
readonly RESULT_STDERR=$RESULT_ROOT/transaction.stderr
readonly EXPECTED_MAC=52:54:00:52:44:01
readonly EXPECTED_ADDRESS=10.0.2.15/24
readonly EXPECTED_GATEWAY=10.0.2.2
readonly EXPECTED_CMDLINE="root=UUID=$EXPECTED_ROOT_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.online_fetch_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=systemd-timesyncd.service systemd.mask=systemd-resolved.service systemd.mask=apt-daily.service systemd.mask=apt-daily.timer systemd.mask=apt-daily-upgrade.service systemd.mask=apt-daily-upgrade.timer systemd.mask=unattended-upgrades.service systemd.mask=ssh.service systemd.mask=ssh.socket"

DAEMON_PID=
CONTAINER_ID=
PROBE_IMAGE_ID=
RUN_COMPLETE=0

docker_client() {
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
        "$CLIENT" --host "unix://$SOCKET" "$@"
}

verify_daemon_generation() {
    [ "$#" -eq 1 ] || return 1
    local expected_start=$1
    [ -n "$DAEMON_PID" ] && [ -r "/proc/$DAEMON_PID/stat" ] \
        && [ "$(/usr/bin/awk '{print $22}' "/proc/$DAEMON_PID/stat")" = "$expected_start" ] \
        && [ "$(/usr/bin/readlink -f -- "/proc/$DAEMON_PID/exe")" = "$BIN/dockerd" ] \
        && [ "$(/usr/bin/stat -Lc '%d:%i:%s' -- "/proc/$DAEMON_PID/exe")" = \
             "$(/usr/bin/stat -c '%d:%i:%s' -- "$BIN/dockerd")" ] \
        && [ "$(/usr/bin/sha256sum "/proc/$DAEMON_PID/exe" | /usr/bin/awk '{print $1}')" = \
             "$(/usr/bin/sha256sum "$BIN/dockerd" | /usr/bin/awk '{print $1}')" ]
}

stop_daemon() {
    local daemon_status=0
    [ -n "$DAEMON_PID" ] || fail 'guest Docker daemon identity is absent at shutdown'
    /usr/bin/kill -TERM "$DAEMON_PID" \
        || fail 'cannot signal the exact guest Docker daemon'
    wait "$DAEMON_PID" || daemon_status=$?
    [ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] \
        || fail "guest Docker daemon shutdown returned $daemon_status"
    [ ! -r "/proc/$DAEMON_PID/stat" ] \
        || fail 'guest Docker daemon remains after joined shutdown'
    [ ! -S "$SOCKET" ] || fail 'guest Docker Unix socket remains after daemon shutdown'
    DAEMON_PID=
}

cleanup() {
    local status=$? daemon_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$CONTAINER_ID" ] && [ -x "$CLIENT" ]; then
        docker_client rm -f "$CONTAINER_ID" >/dev/null 2>&1 || status=1
        CONTAINER_ID=
    fi
    if [ -n "$PROBE_IMAGE_ID" ] && [ -x "$CLIENT" ]; then
        docker_client image rm "$PROBE_IMAGE_ID" >/dev/null 2>&1 || status=1
        PROBE_IMAGE_ID=
    fi
    if [ -n "$DAEMON_PID" ]; then
        if /usr/bin/kill -0 "$DAEMON_PID" 2>/dev/null; then
            /usr/bin/kill -TERM "$DAEMON_PID" 2>/dev/null || daemon_status=1
        fi
        wait "$DAEMON_PID" 2>/dev/null || daemon_status=$?
        [ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] || status=1
        DAEMON_PID=
    fi
    if [ "$status" -ne 0 ] && [ -f "$LOG" ]; then
        /usr/bin/tail -n 200 "$LOG" >&2 || true
    fi
    /usr/bin/sync || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(/usr/bin/id -u)" = 0 ] || fail 'guest bootstrap must be VM-local root'
[ "$(/usr/bin/cat /proc/1/comm)" = systemd ] || fail 'guest PID 1 is not systemd'
[ "$(/usr/bin/cat /proc/cmdline)" = "$EXPECTED_CMDLINE" ] \
    || fail 'guest kernel command line differs'
[ "$(/usr/bin/uname -r)" = "$EXPECTED_KERNEL_RELEASE" ] \
    || fail 'guest kernel release differs'
[[ "$EXPECTED_DOCKER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail 'Docker version pin is malformed'
case "$EXPECTED_DOCKER_SIZE" in 0|*[!0-9]*|'') fail 'Docker size pin is malformed' ;; esac
[[ "$EXPECTED_DOCKER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'Docker digest pin is malformed'
case "$EXPECTED_GIT_PACKAGE_SIZE" in 0|*[!0-9]*|'') fail 'Git package size pin is malformed' ;; esac
[[ "$EXPECTED_GIT_PACKAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'Git package digest pin is malformed'
case "$EXPECTED_GIT_BINARY_SIZE" in 0|*[!0-9]*|'') fail 'Git binary size pin is malformed' ;; esac
[[ "$EXPECTED_GIT_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'Git binary digest pin is malformed'
[[ "$EXPECTED_SOURCE_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'source-bundle digest is malformed'
[[ "$EXPECTED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'source commit is malformed'
[[ "$EXPECTED_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'source tree is malformed'
for identity in "$ACQUISITION_UID" "$ACQUISITION_GID"; do
    [[ "$identity" =~ ^[1-9][0-9]*$ ]] \
        || fail 'acquisition principal is malformed or root'
done
case "$REQUEST" in
    __full__|--libvpx-distfiles|--wix-nuget-packages|--dart-audit-inputs|\
    --maintenance-build-image-candidates|\
    --maintenance-build-deb-builder-certified-candidate|\
    --maintenance-promote-deb-builder-certified-candidate|\
    --maintenance-build-android-builder-certified-candidate|\
    --maintenance-promote-android-builder-certified-candidate|\
    --maintenance-build-win-helper-certified-candidate|\
    --maintenance-promote-win-helper-certified-candidate|\
    --maintenance-build-apple-check-image-candidate|\
    --maintenance-build-dart-audit-image-candidate|\
    --maintenance-build-rust-audit-image-candidate|\
    --maintenance-capture-deb-builder-bootstrap-image|\
    --maintenance-capture-android-builder-bootstrap-image|\
    --maintenance-capture-win-helper-bootstrap-image|\
    --maintenance-capture-devcheck-image|--maintenance-capture-apple-check-image|\
    --maintenance-capture-dart-audit-image|--maintenance-capture-rust-audit-image|\
    --devcheck-image|--apple-check-image|--dart-audit-image|--rust-audit-image|\
    --maintenance-print-online-closure|--maintenance-write-online-closure|\
    --verify-offline-inputs|--debian-systemd-smoke-image|__authority_smoke__) ;;
    *) fail 'guest acquisition request is not one supported closed operation' ;;
esac

for input in "$DOCKER_ARCHIVE:$EXPECTED_DOCKER_SIZE" \
    "$GIT_PACKAGE:$EXPECTED_GIT_PACKAGE_SIZE" "$SOURCE_BUNDLE:"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] && [ "$(/usr/bin/stat -c '%h' -- "$path")" = 1 ] \
        || fail "guest input is absent or ambiguous: $path"
    [ -z "$size" ] || [ "$(/usr/bin/stat -c '%s' -- "$path")" = "$size" ] \
        || fail "guest input size differs: $path"
    options=",$(/usr/bin/findmnt -n -o OPTIONS --target "$path"),"
    case "$options" in *,ro,*) ;; *) fail "guest input is not read-only: $path" ;; esac
    case "$options" in *,nodev,*) ;; *) fail "guest input permits devices: $path" ;; esac
    case "$options" in *,nosuid,*) ;; *) fail "guest input permits set-user-ID execution: $path" ;; esac
    case "$options" in *,noexec,*) ;; *) fail "guest input permits direct execution: $path" ;; esac
done
[ "$(/usr/bin/sha256sum "$DOCKER_ARCHIVE" | /usr/bin/awk '{print $1}')" = "$EXPECTED_DOCKER_SHA256" ] \
    || fail 'Docker bundle digest differs inside the guest'
[ "$(/usr/bin/sha256sum "$GIT_PACKAGE" | /usr/bin/awk '{print $1}')" = "$EXPECTED_GIT_PACKAGE_SHA256" ] \
    || fail 'Git package digest differs inside the guest'
[ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Package)" = git ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Version)" = "$EXPECTED_GIT_PACKAGE_VERSION" ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Architecture)" = amd64 ] \
    || fail 'Git package identity differs inside the guest'
[ "$(/usr/bin/sha256sum "$SOURCE_BUNDLE" | /usr/bin/awk '{print $1}')" = "$EXPECTED_SOURCE_BUNDLE_SHA256" ] \
    || fail 'source-bundle digest differs inside the guest'

/usr/bin/install -d -m 0700 -- "$ROOT"
/usr/bin/install -d -m 0700 -- "$GIT_RUNTIME_ROOT"
/usr/bin/dpkg-deb --extract "$GIT_PACKAGE" "$GIT_RUNTIME_ROOT" \
    || fail 'cannot extract the authenticated Git runtime'
/usr/bin/chmod -R a-w -- "$GIT_RUNTIME_ROOT"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$GIT_RUNTIME_ROOT")" = 0:0:555 ] \
    || fail 'Git runtime root is not root-owned and read-only'
[ -f "$GIT_BIN" ] && [ ! -L "$GIT_BIN" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GIT_BIN")" = \
         "0:0:555:1:$EXPECTED_GIT_BINARY_SIZE" ] \
    && [ "$(/usr/bin/sha256sum "$GIT_BIN" | /usr/bin/awk '{print $1}')" \
         = "$EXPECTED_GIT_BINARY_SHA256" ] \
    || fail 'extracted Git binary identity differs'
[ -d "$GIT_EXEC_PATH" ] && [ ! -L "$GIT_EXEC_PATH" ] \
    && [ -d "$GIT_TEMPLATE_DIR" ] && [ ! -L "$GIT_TEMPLATE_DIR" ] \
    || fail 'extracted Git runtime layout differs'
[ -z "$(/usr/bin/find "$GIT_RUNTIME_ROOT" -xdev \
    \( \( ! -type d -a ! -type f -a ! -type l \) \
       -o \( ! -type l -a \( -perm /022 -o -perm /6000 \) \) \) \
    -print -quit)" ] || fail 'extracted Git runtime contains a special or writable entry'
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
    GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
    "$GIT_BIN" --version)" = 'git version 2.39.5' ] \
    || fail 'extracted Git runtime version differs'
/usr/bin/install -d -m 0700 -o "$ACQUISITION_UID" -g "$ACQUISITION_GID" -- "$WORK_ROOT"
/usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
    GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
    GIT_ALLOW_PROTOCOL=file \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -c init.defaultBranch=master init --bare "$BUNDLE_VERIFY_REPO" >/dev/null \
    || fail 'cannot create the private empty bundle-verification repository'
/usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
    GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
    GIT_ALLOW_PROTOCOL=file \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$BUNDLE_VERIFY_REPO" bundle verify "$SOURCE_BUNDLE" >/dev/null \
    || fail 'source bundle verification failed inside the guest'
/usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
    GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
    GIT_ALLOW_PROTOCOL=file \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
        clone --no-hardlinks --no-tags "$SOURCE_BUNDLE" "$REPO" \
    >/dev/null || fail 'cannot materialize the exact committed source bundle'
current_commit="$(
    /usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
        /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
            -C "$REPO" rev-parse --verify 'HEAD^{commit}'
)" || fail 'cannot resolve materialized source commit'
current_tree="$(
    /usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
        /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
        "$GIT_BIN" --no-replace-objects -c core.hooksPath=/dev/null \
            -C "$REPO" rev-parse --verify 'HEAD^{tree}'
)" || fail 'cannot resolve materialized source tree'
[ "$current_commit:$current_tree" = "$EXPECTED_SOURCE_COMMIT:$EXPECTED_SOURCE_TREE" ] \
    || fail 'materialized source identity differs'
[ "$(/usr/bin/sha256sum "$REPO/scripts/online-fetch-vm-guest.sh" | /usr/bin/awk '{print $1}')" \
  = "$(/usr/bin/sha256sum "${BASH_SOURCE[0]}" | /usr/bin/awk '{print $1}')" ] \
    || fail 'payload guest bootstrap differs from the committed source'
/usr/bin/install -d -m 0755 -- "$FOREIGN_PREFLIGHT_ROOT/scripts"
/usr/bin/install -m 0444 -- \
    "$REPO/scripts/verify-online-fetch-vm-entry.sh" \
    "$REPO/scripts/pins.env" "$FOREIGN_PREFLIGHT_ROOT/scripts/"
/usr/bin/chmod 0555 -- "$FOREIGN_PREFLIGHT_ROOT" "$FOREIGN_PREFLIGHT_ROOT/scripts"
for source in verify-online-fetch-vm-entry.sh pins.env; do
    [ "$([ -f "$FOREIGN_PREFLIGHT_ROOT/scripts/$source" ] \
          && /usr/bin/stat -c '%u:%g:%a:%h' -- "$FOREIGN_PREFLIGHT_ROOT/scripts/$source")" \
      = 0:0:444:1 ] \
        && [ "$(/usr/bin/sha256sum "$FOREIGN_PREFLIGHT_ROOT/scripts/$source" \
                    | /usr/bin/awk '{print $1}')" \
             = "$(/usr/bin/sha256sum "$REPO/scripts/$source" \
                    | /usr/bin/awk '{print $1}')" ] \
        || fail "foreign-principal preflight fixture differs: $source"
done

/usr/bin/install -d -m 0700 -o "$ACQUISITION_UID" -g "$ACQUISITION_GID" -- \
    "$REPO/online" "$REPO/.harness-state" \
    "$REPO/.harness-state/debian-systemd-smoke" "$RESULT_ROOT"
/usr/bin/mount -t virtiofs -o rw,nodev,nosuid \
    rustdesk-cache-state "$REPO/online" \
    || fail 'cannot mount the writable cache-state export'
/usr/bin/mount -t virtiofs -o rw,nodev,nosuid,noexec \
    rustdesk-systemd-cache "$REPO/.harness-state/debian-systemd-smoke" \
    || fail 'cannot mount the writable systemd-cache export'
/usr/bin/mount -t virtiofs -o rw,nodev,nosuid,noexec \
    rustdesk-result "$RESULT_ROOT" \
    || fail 'cannot mount the bounded result export'
cache_inventory="$(
    /usr/bin/find "$REPO/online" -mindepth 1 -maxdepth 1 -printf '%f\n' \
        | LC_ALL=C /usr/bin/sort
)"
[ "$cache_inventory" = $'inputs\nretired' ] \
    || fail 'cache-state export does not contain the exact inputs/retired layout'
for directory in "$REPO/online" "$REPO/online/inputs" "$REPO/online/retired" \
    "$REPO/.harness-state/debian-systemd-smoke" "$RESULT_ROOT"; do
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" = \
      "$ACQUISITION_UID:$ACQUISITION_GID:700" ] \
        || fail "writable export metadata differs: $directory"
done
/usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
    /usr/bin/python3 -I -S "$REPO/scripts/verify-online-fetch-virtiofs-rename.py" \
        --root "$REPO/online" >"$RENAME_CONTRACT" \
    || fail 'virtiofs flagged-rename contract failed'
[ "$(/usr/bin/cat "$RENAME_CONTRACT")" = \
  'VIRTIOFS_RENAME_CONTRACT=pass noreplace=cross-parent collision=no-clobber exchange=nonempty cleanup=complete' ] \
    || fail 'virtiofs flagged-rename receipt differs'
/usr/bin/chmod 0444 "$RENAME_CONTRACT"

/usr/bin/systemctl stop systemd-timesyncd.service systemd-resolved.service \
    systemd-networkd.service >/dev/null 2>&1 || true
/usr/sbin/iptables --wait -I OUTPUT 1 -p udp -j REJECT \
    --reject-with icmp-port-unreachable \
    || fail 'cannot deny guest-originated UDP before enabling acquisition networking'
[ "$(/usr/sbin/iptables -S OUTPUT | /usr/bin/awk 'NR == 2')" = \
  '-A OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    || fail 'guest-originated UDP denial rule differs'
mapfile -t acquisition_interfaces < <(
    for address in /sys/class/net/*/address; do
        [ "$(/usr/bin/cat "$address")" = "$EXPECTED_MAC" ] \
            && /usr/bin/basename "$(/usr/bin/dirname "$address")"
    done
)
[ "${#acquisition_interfaces[@]}" -eq 1 ] \
    || fail 'fixed acquisition NIC is absent or ambiguous'
readonly ACQUISITION_INTERFACE="${acquisition_interfaces[0]}"
/usr/sbin/ip link set dev "$ACQUISITION_INTERFACE" down
/usr/sbin/ip address flush dev "$ACQUISITION_INTERFACE"
/usr/sbin/ip link set dev "$ACQUISITION_INTERFACE" up
/usr/sbin/ip address add "$EXPECTED_ADDRESS" dev "$ACQUISITION_INTERFACE"
/usr/sbin/ip route replace default via "$EXPECTED_GATEWAY" dev "$ACQUISITION_INTERFACE"
if /usr/bin/mountpoint -q /etc/resolv.conf; then
    /usr/bin/umount /etc/resolv.conf || fail 'cannot retire inherited resolver mount'
fi
[ ! -L /etc/resolv.conf ] || /usr/bin/rm -- /etc/resolv.conf
/usr/bin/printf 'nameserver 10.0.2.3\noptions use-vc attempts:2 timeout:2\n' >/etc/resolv.conf
/usr/bin/chmod 0644 /etc/resolv.conf
/usr/sbin/sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
/usr/sbin/sysctl -q -w net.ipv6.conf.default.disable_ipv6=1

/usr/bin/install -d -m 0700 -- "$ROOT" "$DATA" "$EXEC"
/usr/bin/install -d -m 0555 -- "$BIN"
archive_inventory="$(/usr/bin/tar -tzf "$DOCKER_ARCHIVE")" \
    || fail 'Docker bundle inventory cannot be read'
[ "$archive_inventory" = $'docker/\ndocker/runc\ndocker/containerd\ndocker/docker-init\ndocker/dockerd\ndocker/containerd-shim-runc-v2\ndocker/docker-proxy\ndocker/docker\ndocker/ctr' ] \
    || fail 'Docker bundle inventory differs'
/usr/bin/tar -xzf "$DOCKER_ARCHIVE" --strip-components=1 \
    --no-same-owner --no-same-permissions -C "$BIN" \
    docker/runc docker/containerd docker/docker-init docker/dockerd \
    docker/containerd-shim-runc-v2 docker/docker-proxy docker/ctr \
    || fail 'cannot extract the guest Docker daemon bundle'
[ ! -e "$CLIENT" ] && [ ! -L "$CLIENT" ] \
    || fail 'pinned guest base unexpectedly supplies /usr/bin/docker'
/usr/bin/tar -xOf "$DOCKER_ARCHIVE" docker/docker >"$CLIENT" \
    || fail 'cannot install the fixed guest Docker client'
/usr/bin/chmod 0555 "$BIN" "$BIN"/*
/usr/bin/chmod 0755 "$CLIENT"
[ "$($CLIENT --version)" = "Docker version $EXPECTED_DOCKER_VERSION, build 0" ] \
    || case "$($CLIENT --version)" in
        "Docker version $EXPECTED_DOCKER_VERSION,"*) ;;
        *) fail 'guest Docker client version differs' ;;
    esac
group_name="$(/usr/bin/getent group "$ACQUISITION_GID" | /usr/bin/awk -F: 'NR == 1 {print $1}')"
if [ -z "$group_name" ]; then
    group_name="rustdesk-online-$ACQUISITION_GID"
    /usr/sbin/groupadd --gid "$ACQUISITION_GID" "$group_name" \
        || fail 'cannot create the VM-local acquisition group'
fi

listeners_before="$(/usr/bin/ss -H -lntu | /usr/bin/sort -u)"
PATH="$BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$BIN/dockerd" \
        --host "unix://$SOCKET" \
        --pidfile "$PIDFILE" \
        --data-root "$DATA" \
        --exec-root "$EXEC" \
        --bip 172.30.0.1/24 \
        --fixed-cidr 172.30.0.0/25 \
        --ip 127.0.0.1 \
        --iptables=true \
        --ip6tables=false \
        --ip-forward=true \
        --ip-masq=true \
        --icc=false \
        --userland-proxy=false \
        --dns-opt use-vc \
        --group "$group_name" \
        --log-level error \
        >"$LOG" 2>&1 &
DAEMON_PID=$!
[[ "$DAEMON_PID" =~ ^[1-9][0-9]*$ ]] || fail 'guest Docker daemon PID is malformed'
ready=0
for _ in $(/usr/bin/seq 1 600); do
    if [ -S "$SOCKET" ] \
       && [ "$(docker_client info --format '{{.ServerVersion}}' 2>/dev/null || true)" \
            = "$EXPECTED_DOCKER_VERSION" ] \
       && /usr/bin/kill -0 "$DAEMON_PID" 2>/dev/null; then
        ready=1
        break
    fi
    /usr/bin/kill -0 "$DAEMON_PID" 2>/dev/null || break
    /usr/bin/sleep 0.1
done
[ "$ready" -eq 1 ] || fail 'guest-only acquisition Docker daemon did not become ready'
[ "$(/usr/bin/cat "$PIDFILE")" = "$DAEMON_PID" ] \
    || fail 'guest Docker PID file differs'
/usr/bin/chown "0:$ACQUISITION_GID" "$SOCKET"
/usr/bin/chmod 0660 "$SOCKET"
/usr/sbin/iptables --wait -I DOCKER-USER 1 -p udp -j REJECT \
    --reject-with icmp-port-unreachable \
    || fail 'cannot deny acquisition-container UDP'
[ "$(/usr/sbin/iptables -S OUTPUT | /usr/bin/awk 'NR == 2')" = \
  '-A OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    && [ "$(/usr/sbin/iptables -S DOCKER-USER | /usr/bin/awk 'NR == 2')" = \
         '-A DOCKER-USER -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    || fail 'TCP-only acquisition filter differs'
daemon_start="$(/usr/bin/awk '{print $22}' "/proc/$DAEMON_PID/stat")" \
    || fail 'cannot read the guest Docker daemon generation'
[[ "$daemon_start" =~ ^[1-9][0-9]*$ ]] \
    || fail 'guest Docker daemon start time is malformed'
verify_daemon_generation "$daemon_start" \
    || fail 'root could not bind the live guest Docker daemon executable generation'
/usr/bin/printf 'version=1 uid=%s gid=%s commit=%s tree=%s udp=denied daemon_pid=%s daemon_start=%s daemon_sha256=%s client_sha256=%s\n' \
    "$ACQUISITION_UID" "$ACQUISITION_GID" "$EXPECTED_SOURCE_COMMIT" \
    "$EXPECTED_SOURCE_TREE" "$DAEMON_PID" "$daemon_start" \
    "$(/usr/bin/sha256sum "$BIN/dockerd" | /usr/bin/awk '{print $1}')" \
    "$(/usr/bin/sha256sum "$CLIENT" | /usr/bin/awk '{print $1}')" \
    >"$AUTHORITY_RECORD"
/usr/bin/chmod 0444 "$AUTHORITY_RECORD" "$PIDFILE" "$RENAME_CONTRACT"
/usr/bin/chmod 0555 "$ROOT"
[ -d /sys/class/net/docker0 ] \
    && [ "$(/usr/sbin/ip -4 -o address show dev docker0 scope global \
          | /usr/bin/awk '{print $4}')" = 172.30.0.1/24 ] \
    || fail 'guest-only Docker bridge differs'
[ "$(/usr/bin/cat /proc/sys/net/ipv4/ip_forward)" = 1 ] \
    || fail 'guest-only Docker forwarding is disabled'
listeners_after="$(/usr/bin/ss -H -lntu | /usr/bin/sort -u)"
[ "$listeners_after" = "$listeners_before" ] \
    || fail 'guest Docker daemon created an INET listener'

readonly INNER_ENV=(
    RUSTDESK_ONLINE_FETCH_VM_GUEST=1
    RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT"
    RUSTDESK_ONLINE_FETCH_VM_SOURCE_TREE="$EXPECTED_SOURCE_TREE"
)
if /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root "${INNER_ENV[@]}" \
    /bin/bash "$REPO/scripts/online-fetch.sh" --vm-authority-probe \
    >"$ROOT/root.out" 2>"$ROOT/root.err"; then
    fail 'VM-local root passed the online-fetch entry preflight'
fi
[ ! -s "$ROOT/root.out" ] \
    && [ "$(/usr/bin/cat "$ROOT/root.err")" = \
      'online-fetch VM entry preflight: online-fetch VM entry refuses root' ] \
    || fail 'VM-local root refusal result differs'
foreign_uid=4001
[ "$foreign_uid" != "$ACQUISITION_UID" ] || foreign_uid=4002
if /usr/bin/setpriv --reuid="$foreign_uid" --regid="$foreign_uid" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent "${INNER_ENV[@]}" \
    /bin/bash "$FOREIGN_PREFLIGHT_ROOT/scripts/verify-online-fetch-vm-entry.sh" \
    >"$ROOT/foreign.out" 2>"$ROOT/foreign.err"; then
    fail 'foreign VM principal passed the online-fetch entry preflight'
fi
[ ! -s "$ROOT/foreign.out" ] \
    && [ "$(/usr/bin/cat "$ROOT/foreign.err")" = \
      'online-fetch VM entry preflight: caller is not the exact admitted acquisition principal' ] \
    || fail 'foreign VM-principal refusal result differs'

run_online_fetch() {
    local -a command=(/bin/bash "$REPO/scripts/online-fetch.sh")
    [ "$REQUEST" = __full__ ] || command+=("$REQUEST")
    /usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
        /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
        "${INNER_ENV[@]}" \
        /bin/bash -c 'ulimit -f 32768; exec "$@"' online-fetch "${command[@]}" \
        >"$RESULT_STDOUT" 2>"$RESULT_STDERR"
}

run_authority_smoke() {
    local rootfs=$ROOT/probe-rootfs probe_output=$ROOT/probe.bin inspect interpreter
    local -a interpreters=()
    /usr/bin/install -d -m 0755 -- "$rootfs"
    copy_runtime_binary() {
        local binary=$1 dependency
        /usr/bin/cp --parents -L -- "$binary" "$rootfs"
        while IFS= read -r dependency; do
            [ -f "$dependency" ] || fail "probe dependency is absent: $dependency"
            /usr/bin/cp --parents -L -- "$dependency" "$rootfs"
        done < <(
            /usr/bin/ldd "$binary" \
                | /usr/bin/awk '/=> \// {print $3} $1 ~ /^\// {print $1}' \
                | /usr/bin/sort -u
        )
    }
    copy_runtime_binary /usr/bin/curl
    mapfile -t interpreters < <(
        /usr/bin/ldd /usr/bin/curl \
            | /usr/bin/awk '$1 ~ /^\// {print $1}' \
            | /usr/bin/sort -u
    )
    [ "${#interpreters[@]}" -eq 1 ] \
        || fail 'focused acquisition probe ELF interpreter is absent or ambiguous'
    [ -f /etc/ssl/certs/ca-certificates.crt ] \
        || fail 'pinned guest CA bundle is absent'
    /usr/bin/cp --parents -L -- /etc/ssl/certs/ca-certificates.crt "$rootfs"
    [ ! -f /etc/nsswitch.conf ] \
        || /usr/bin/cp --parents -L -- /etc/nsswitch.conf "$rootfs"
    for nss in /lib/x86_64-linux-gnu/libnss_dns.so.2 \
        /lib/x86_64-linux-gnu/libnss_files.so.2; do
        [ ! -f "$nss" ] || /usr/bin/cp --parents -L -- "$nss" "$rootfs"
    done
    /usr/bin/find "$rootfs" -type d -exec /usr/bin/chmod 0555 {} +
    /usr/bin/find "$rootfs" -type f -exec /usr/bin/chmod 0444 {} +
    /usr/bin/chmod 0555 "$rootfs/usr/bin/curl"
    for interpreter in "${interpreters[@]}"; do
        [ -f "$rootfs$interpreter" ] && [ ! -L "$rootfs$interpreter" ] \
            || fail 'focused acquisition probe ELF interpreter was not copied'
        /usr/bin/chmod 0555 "$rootfs$interpreter"
    done
    /usr/bin/tar --numeric-owner --owner=0 --group=0 -C "$rootfs" -cf - . \
        | docker_client import - rustdesk-online-fetch-authority-probe:v1 \
        >"$ROOT/image.id" \
        || fail 'cannot import the focused acquisition probe image'
    PROBE_IMAGE_ID="$(/usr/bin/cat "$ROOT/image.id")"
    [[ "$PROBE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail 'focused acquisition probe image ID is malformed'
    CONTAINER_ID="$(
        docker_client create --name rustdesk-online-fetch-authority-probe \
            --pull=never --network=bridge --read-only \
            --user "$ACQUISITION_UID:$ACQUISITION_GID" \
            --cap-drop=ALL --security-opt=no-new-privileges \
            --pids-limit=64 --memory=256m --memory-swap=256m --cpus=1 \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=700,uid="$ACQUISITION_UID",gid="$ACQUISITION_GID" \
            "$PROBE_IMAGE_ID" /usr/bin/curl --disable --proto '=https' --tlsv1.2 \
            --fail --silent --show-error --location --max-time 90 \
            --speed-time 30 --speed-limit 1024 --max-filesize 114565 \
            https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-0.47-py2.py3-none-any.whl
    )" || fail 'cannot create the focused acquisition container'
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused acquisition container ID is malformed'
    inspect="$(
        docker_client inspect --format \
          '{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}' \
          "$CONTAINER_ID"
    )" || fail 'cannot inspect the focused acquisition container'
    [ "$inspect" = \
      "$ACQUISITION_UID:$ACQUISITION_GID|bridge|true|false|64|268435456|268435456|[\"ALL\"]|[\"no-new-privileges\"]|{}" ] \
        || fail "focused acquisition container authority differs: $inspect"
    [ -z "$(docker_client port "$CONTAINER_ID")" ] \
        || fail 'focused acquisition container published a port'
    docker_client start --attach "$CONTAINER_ID" >"$probe_output" \
        || fail 'focused acquisition HTTPS container failed'
    [ "$(/usr/bin/stat -c '%s' -- "$probe_output")" = 114565 ] \
        && [ "$(/usr/bin/sha256sum "$probe_output" | /usr/bin/awk '{print $1}')" \
             = 543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f ] \
        || fail 'focused acquisition HTTPS bytes differ from the pin'
    [ "$(docker_client inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused acquisition container did not exit cleanly'
    docker_client rm "$CONTAINER_ID" >/dev/null \
        || fail 'cannot retire the focused acquisition container'
    CONTAINER_ID=
    docker_client image rm "$PROBE_IMAGE_ID" >/dev/null \
        || fail 'cannot retire the focused acquisition probe image'
    PROBE_IMAGE_ID=
    [ -z "$(docker_client ps -aq)" ] \
        || fail 'focused acquisition left a guest container behind'
    /usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
        /bin/bash -c 'set -e; umask 077; for root in "$@"; do printf "online-fetch-vm-cache-transport-v1\n" >"$root/authority-smoke"; chmod 0400 "$root/authority-smoke"; done' \
        cache-transport "$REPO/online/inputs" \
        "$REPO/online/retired" \
        "$REPO/.harness-state/debian-systemd-smoke" \
        || fail 'focused acquisition cache-transport write failed'
    /usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
        /bin/bash -c 'printf "ONLINE_FETCH_VM_RUNTIME=pass network=qemu-user-only hostfwd=absent udp=denied docker=guest-bridge git=pinned-deb inner_uid=%s https=sha256 cache=virtiofs-atomic cleanup=joined\n" "$1" >>"$2"' \
        smoke-result "$ACQUISITION_UID" "$RESULT_STDOUT" \
        || fail 'cannot record the focused acquisition runtime result'
}

if [ "$REQUEST" = __authority_smoke__ ]; then
    request_before=$REQUEST
    REQUEST=--vm-authority-probe
    run_online_fetch || fail 'authorized online-fetch VM entry probe failed'
    REQUEST=$request_before
    run_authority_smoke
else
    run_online_fetch || fail 'online-fetch transaction failed'
fi

/usr/bin/setpriv --reuid="$ACQUISITION_UID" --regid="$ACQUISITION_GID" --clear-groups \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK_ROOT" LC_ALL=C \
    "${INNER_ENV[@]}" "$REPO/scripts/verify-online-fetch-vm-entry.sh" \
    >/dev/null || fail 'online-fetch VM authority changed after the transaction'
[ "$(/usr/sbin/iptables -S OUTPUT | /usr/bin/awk 'NR == 2')" = \
  '-A OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    && [ "$(/usr/sbin/iptables -S DOCKER-USER | /usr/bin/awk 'NR == 2')" = \
         '-A DOCKER-USER -p udp -j REJECT --reject-with icmp-port-unreachable' ] \
    || fail 'TCP-only acquisition filter changed during the transaction'
verify_daemon_generation "$daemon_start" \
    || fail 'live guest Docker daemon executable generation changed during the transaction'
[ -z "$(docker_client ps -q)" ] \
    || fail 'online-fetch transaction left a running guest container'
[ "$(/usr/bin/stat -c '%s' -- "$RESULT_STDOUT")" -le 16777216 ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$RESULT_STDERR")" -le 16777216 ] \
    || fail 'online-fetch result exceeded its output bound'
/usr/bin/sync -f "$REPO/online"
/usr/bin/sync -f "$REPO/online/inputs"
/usr/bin/sync -f "$REPO/online/retired"
/usr/bin/sync -f "$REPO/.harness-state/debian-systemd-smoke"
/usr/bin/sync -f "$RESULT_ROOT"
stop_daemon
RUN_COMPLETE=1
printf 'ONLINE_FETCH_VM_GUEST=pass uid=%s gid=%s source=%s network=qemu-user-only hostfwd=absent udp=denied docker=guest-unix git=pinned-deb cache=virtiofs-atomic result=16MiB cleanup=joined\n' \
    "$ACQUISITION_UID" "$ACQUISITION_GID" "$EXPECTED_SOURCE_COMMIT"

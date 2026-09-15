#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly UID_NOW="$(/usr/bin/id -u)"
readonly GID_NOW="$(/usr/bin/id -g)"
readonly AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly MARKER=$AUTHORITY_ROOT/authority
readonly STATE_ROOT=/var/tmp/rustdesk-verifier-authority
readonly BIN=$STATE_ROOT/bin
readonly CLIENT=$BIN/docker
readonly DAEMON=$BIN/dockerd
readonly SOCKET=$AUTHORITY_ROOT/docker.sock
readonly PIDFILE=$AUTHORITY_ROOT/docker.pid
readonly DAEMON_IDENTITY=$AUTHORITY_ROOT/docker.identity
readonly CONFIG_ROOT=$AUTHORITY_ROOT/docker-config
readonly CONFIG=$CONFIG_ROOT/config.json

fail() {
    printf 'verifier-VM entry preflight: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail 'arguments are forbidden'
[ "$UID_NOW" -ne 0 ] || fail 'the verifier principal must not be root'
[ "$GID_NOW" -ne 0 ] || fail 'the verifier principal must not have a root primary group'

[ -d "$AUTHORITY_ROOT" ] && [ ! -L "$AUTHORITY_ROOT" ] \
    || fail 'VM authority root is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$AUTHORITY_ROOT")" = 0:0:755 ] \
    || fail 'VM authority root metadata differs'
[ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
    || fail 'VM authority marker is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$MARKER")" = 0:0:444:1 ] \
    || fail 'VM authority marker metadata differs'
mapfile -t marker_lines <"$MARKER" \
    || fail 'VM authority marker cannot be read'
[ "${#marker_lines[@]}" -eq 1 ] || fail 'VM authority marker line count differs'
IFS=' ' read -r marker_protocol marker_docker marker_extra <<<"${marker_lines[0]}"
[ "$marker_protocol" = rustdesk-verifier-vm-authority-v1 ] \
    || fail 'VM authority protocol differs'
[[ "$marker_docker" =~ ^docker=[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail 'VM authority Docker version is malformed'
[ -z "${marker_extra:-}" ] || fail 'VM authority marker has trailing fields'
readonly EXPECTED_DOCKER_VERSION=${marker_docker#docker=}

[ -d "$STATE_ROOT" ] && [ ! -L "$STATE_ROOT" ] \
    || fail 'VM execution-state root is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STATE_ROOT")" = 0:0:755 ] \
    || fail 'VM execution-state root metadata differs'
[ -d "$BIN" ] && [ ! -L "$BIN" ] \
    || fail 'VM authority binary root is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BIN")" = 0:0:555 ] \
    || fail 'VM authority binary root metadata differs'
for executable in "$CLIENT" "$DAEMON"; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
        || fail "VM authority executable is absent or ambiguous: $executable"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$executable")" = 0:0:555:1 ] \
        || fail "VM authority executable metadata differs: $executable"
done
[ -d "$CONFIG_ROOT" ] && [ ! -L "$CONFIG_ROOT" ] \
    || fail 'VM Docker configuration root is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CONFIG_ROOT")" = 0:0:555 ] \
    || fail 'VM Docker configuration root metadata differs'
[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] \
    || fail 'VM Docker configuration is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$CONFIG")" = 0:0:444:1:3 ] \
    || fail 'VM Docker configuration metadata differs'
[ "$(/usr/bin/sha256sum -- "$CONFIG" | /usr/bin/awk '{ print $1 }')" = \
  ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356 ] \
    || fail 'VM Docker configuration is not canonical empty JSON'

[ -S "$SOCKET" ] && [ ! -L "$SOCKET" ] \
    || fail 'VM Docker channel is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SOCKET")" = "0:$GID_NOW:660:1" ] \
    || fail 'VM Docker channel metadata differs'
[ -f "$PIDFILE" ] && [ ! -L "$PIDFILE" ] \
    || fail 'VM Docker PID record is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$PIDFILE")" = 0:0:444:1 ] \
    || fail 'VM Docker PID record metadata differs'
daemon_pid="$(<"$PIDFILE")" || fail 'VM Docker PID record cannot be read'
[[ "$daemon_pid" =~ ^[1-9][0-9]*$ ]] || fail 'VM Docker PID record is malformed'
[ -f "$DAEMON_IDENTITY" ] && [ ! -L "$DAEMON_IDENTITY" ] \
    || fail 'VM Docker generation record is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DAEMON_IDENTITY")" = 0:0:444:1 ] \
    || fail 'VM Docker generation record metadata differs'
mapfile -t identity_lines <"$DAEMON_IDENTITY" \
    || fail 'VM Docker generation record cannot be read'
[ "${#identity_lines[@]}" -eq 1 ] || fail 'VM Docker generation record line count differs'
IFS=' ' read -r identity_pid identity_start identity_sha identity_extra \
    <<<"${identity_lines[0]}"
[ "$identity_pid" = "pid=$daemon_pid" ] || fail 'VM Docker generation PID differs'
[[ "$identity_start" =~ ^start=[1-9][0-9]*$ ]] \
    || fail 'VM Docker generation start time is malformed'
[[ "$identity_sha" =~ ^sha256=[0-9a-f]{64}$ ]] \
    || fail 'VM Docker generation digest is malformed'
[ -z "${identity_extra:-}" ] || fail 'VM Docker generation record has trailing fields'
live_start="$(/usr/bin/awk '{ print $22 }' "/proc/$daemon_pid/stat" 2>/dev/null)" \
    || fail 'VM Docker live generation cannot be read'
[ "$identity_start" = "start=$live_start" ] || fail 'VM Docker live generation changed'
[ "$identity_sha" = "sha256=$(/usr/bin/sha256sum "$DAEMON" | /usr/bin/awk '{ print $1 }')" ] \
    || fail 'VM Docker daemon bytes differ from the generation record'
daemon_status="$(/usr/bin/awk '/^(Uid|Gid):/ { print $1, $2, $3, $4, $5 }' "/proc/$daemon_pid/status")" \
    || fail 'VM Docker process credentials cannot be read'
[ "$daemon_status" = $'Uid: 0 0 0 0\nGid: 0 0 0 0' ] \
    || fail 'VM Docker daemon is not VM-local root'
peer_receipt="$(
    /usr/bin/python3 -I -S - "$SOCKET" "$daemon_pid" <<'PY'
import os
import socket
import struct
import sys

path = os.fsencode(sys.argv[1])
expected_pid = int(sys.argv[2])
channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
channel.settimeout(5.0)
channel.connect(path)
peer_pid, peer_uid, peer_gid = struct.unpack(
    "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
)
if (peer_pid, peer_uid, peer_gid) != (expected_pid, 0, 0):
    raise SystemExit("Docker Unix peer generation differs")
channel.sendall(b"GET /_ping HTTP/1.0\r\nHost: docker\r\n\r\n")
reply = bytearray()
while len(reply) <= 4096:
    block = channel.recv(4097 - len(reply))
    if not block:
        break
    reply.extend(block)
if len(reply) > 4096:
    raise SystemExit("Docker ping response exceeded its bound")
head, separator, body = bytes(reply).partition(b"\r\n\r\n")
if not separator or not head.startswith(b"HTTP/1.0 200 OK\r\n") or body != b"OK":
    raise SystemExit("Docker ping response differs")
print("peer=pid-bound ping=ok")
PY
)" || fail 'VM Docker Unix peer proof failed'
[ "$peer_receipt" = 'peer=pid-bound ping=ok' ] \
    || fail 'VM Docker Unix peer receipt differs'

mapfile -t interfaces < <(
    /usr/bin/find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' \
        | /usr/bin/sort -u
)
[ "${#interfaces[@]}" -eq 1 ] && [ "${interfaces[0]}" = lo ] \
    || fail "verifier VM has an unexpected interface inventory: ${interfaces[*]}"
cmdline="$(< /proc/cmdline)"
marker_count=0
for word in $cmdline; do
    [ "$word" != rustdesk.verifier_vm=1 ] || marker_count=$((marker_count + 1))
done
[ "$marker_count" -eq 1 ] || fail 'verifier-VM kernel marker is absent or ambiguous'

client_version="$(
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$SOCKET" DOCKER_CONFIG="$CONFIG_ROOT" \
        "$CLIENT" --host "unix://$SOCKET" --config "$CONFIG_ROOT" \
        version --format '{{.Client.Version}}|{{.Server.Version}}'
)" || fail 'fixed VM Docker client cannot reach the guest-only daemon'
[ "$client_version" = "$EXPECTED_DOCKER_VERSION|$EXPECTED_DOCKER_VERSION" ] \
    || fail "VM Docker client/server version differs: $client_version"
final_live_start="$(/usr/bin/awk '{ print $22 }' "/proc/$daemon_pid/stat" 2>/dev/null)" \
    || fail 'VM Docker final generation cannot be read'
[ "$identity_start" = "start=$final_live_start" ] \
    || fail 'VM Docker generation changed during preflight'
final_daemon_status="$(/usr/bin/awk '/^(Uid|Gid):/ { print $1, $2, $3, $4, $5 }' "/proc/$daemon_pid/status")" \
    || fail 'VM Docker final process credentials cannot be read'
[ "$final_daemon_status" = "$daemon_status" ] \
    || fail 'VM Docker process credentials changed during preflight'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SOCKET")" = "0:$GID_NOW:660:1" ] \
    || fail 'VM Docker channel changed during preflight'

printf 'VERIFIER_VM_ENTRY_AUTHORITY=pass uid=%s gid=%s network=none docker=%s channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root\n' \
    "$UID_NOW" "$GID_NOW" "$EXPECTED_DOCKER_VERSION"

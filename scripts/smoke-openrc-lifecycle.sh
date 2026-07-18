#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT=/work
readonly SOURCE_BINARY=$ROOT/target/debug/rustdesk
readonly BINARY=/usr/bin/rustdesk
readonly OPENRC_SOURCE=$ROOT/res/service-managers/openrc/rustdesk
readonly OPENRC_SERVICE=/etc/init.d/rustdesk
readonly LOGINCTL_SOURCE=$ROOT/scripts/smoke-service-loginctl.sh
readonly READY=$ROOT/scripts/smoke-ready.sh
readonly PROCESS_GUARD=$ROOT/scripts/smoke-process-guard.py
readonly LAUNCHER_SOURCE=$ROOT/target/smoke-server-launcher
readonly PROBE=$ROOT/target/debug/examples/smoke_readiness
readonly PIDFILE=/run/rustdesk.pid
readonly RECORD=/run/rustdesk/service-child.record
readonly FIXTURE=/tmp/rustdesk-openrc-lifecycle
readonly LOGINCTL_STATE=/tmp/rd-service-loginctl-state
readonly OPENRC_VERSION=0.45.2-2+deb12u1
readonly RUNLEVEL=rustdesk-smoke
readonly PORTABLE_UID=4000

SERVICE_PID=
SERVICE_START=
SERVICE_CHILD=
SERVICE_CHILD_START=
SERVICE_GENERATION=
PORTABLE_PID=
PORTABLE_START=
PORTABLE_GID=
PORTABLE_EXE_ID=

fail() {
    printf 'OpenRC lifecycle smoke: %s\n' "$*" >&2
    exit 1
}

pidfd_signal_exact() {
    local pid=$1 expected_start=$2 signal_name=$3
    python3 - "$pid" "$expected_start" "$signal_name" <<'PY'
import os
import signal
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
signal_name = sys.argv[3]
signals = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
if pid <= 0 or expected_start <= 0 or signal_name not in signals:
    raise SystemExit("OpenRC lifecycle smoke: invalid retained signal authority")
pidfd = os.pidfd_open(pid, 0)
try:
    raw = open(f"/proc/{pid}/stat", "rb").read()
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20 or fields[0] in {b"Z", b"X", b"x"} or int(fields[19]) != expected_start:
        raise SystemExit("OpenRC lifecycle smoke: retained process identity changed before signal")
    signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)
finally:
    os.close(pidfd)
PY
}

crash_supervisor_and_wait_child() {
    local supervisor=$1 supervisor_start=$2 child=$3 child_start=$4
    python3 - "$supervisor" "$supervisor_start" "$child" "$child_start" <<'PY'
import os
import select
import signal
import sys
import time

supervisor = int(sys.argv[1])
supervisor_start = int(sys.argv[2])
child = int(sys.argv[3])
child_start = int(sys.argv[4])

def open_exact_pidfd(pid, expected_start, label):
    pidfd = os.pidfd_open(pid, 0)
    try:
        raw = open(f"/proc/{pid}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError):
        os.close(pidfd)
        raise
    if len(fields) < 20 or fields[0] in {b"Z", b"X", b"x"} or int(fields[19]) != expected_start:
        os.close(pidfd)
        raise SystemExit(f"OpenRC lifecycle smoke: retained {label} identity changed before crash")
    return pidfd

supervisor_pidfd = open_exact_pidfd(supervisor, supervisor_start, "supervisor")
child_pidfd = open_exact_pidfd(child, child_start, "service child")
started_ns = time.monotonic_ns()
try:
    signal.pidfd_send_signal(supervisor_pidfd, signal.SIGKILL, None, 0)
    poller = select.poll()
    poller.register(child_pidfd, select.POLLIN | select.POLLHUP)
    events = poller.poll(10000)
    if not events or not any(event & (select.POLLIN | select.POLLHUP) for _, event in events):
        raise SystemExit("OpenRC lifecycle smoke: exact child did not exit after supervisor crash")
    try:
        raw = open(f"/proc/{child}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError):
        fields = []
    if len(fields) >= 20 and int(fields[19]) == child_start and fields[0] not in {b"Z", b"X", b"x"}:
        raise SystemExit("OpenRC lifecycle smoke: service child remained live after supervisor crash")
    print((time.monotonic_ns() - started_ns) // 1_000_000)
finally:
    os.close(child_pidfd)
    os.close(supervisor_pidfd)
PY
}

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$SERVICE_PID" ] && [ -n "$SERVICE_START" ] \
        && "$READY" --is-running "$SERVICE_PID" "$SERVICE_START" 2>/dev/null; then
        if [ -x "$OPENRC_SERVICE" ] && [ -f "$PIDFILE" ] && [ ! -L "$PIDFILE" ] \
            && [ "$(sed -n '1p' "$PIDFILE" 2>/dev/null)" = "$SERVICE_PID" ]; then
            rc-service rustdesk stop >/dev/null 2>&1 || cleanup_status=1
        else
            pidfd_signal_exact "$SERVICE_PID" "$SERVICE_START" TERM >/dev/null 2>&1 \
                || cleanup_status=1
        fi
    fi
    if [ -n "$SERVICE_CHILD" ] && [ -n "$SERVICE_CHILD_START" ] \
        && "$READY" --is-running "$SERVICE_CHILD" "$SERVICE_CHILD_START" 2>/dev/null; then
        pidfd_signal_exact "$SERVICE_CHILD" "$SERVICE_CHILD_START" KILL >/dev/null 2>&1 \
            || cleanup_status=1
    fi
    if [ -n "$PORTABLE_PID" ] && [ -n "$PORTABLE_START" ] \
        && "$READY" --is-running "$PORTABLE_PID" "$PORTABLE_START" 2>/dev/null; then
        "$READY" --stop "$PORTABLE_PID" "$PORTABLE_START" >/dev/null 2>&1 \
            || pidfd_signal_exact "$PORTABLE_PID" "$PORTABLE_START" KILL >/dev/null 2>&1 \
            || cleanup_status=1
    fi
    [ -z "$PORTABLE_PID" ] || wait "$PORTABLE_PID" 2>/dev/null || true
    rm -rf -- "$FIXTURE"
    [ "$cleanup_status" -eq 0 ] || status=125
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wait_identity_gone() {
    local pid=$1 start=$2 label=$3
    local attempt=0
    while [ "$attempt" -lt 200 ]; do
        if ! "$READY" --is-running "$pid" "$start" 2>/dev/null; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    fail "$label remains live: $pid/$start"
}

assert_portable_alive() {
    "$READY" --is-running "$PORTABLE_PID" "$PORTABLE_START" \
        || fail 'unrelated portable RustDesk process stopped or changed identity'
    [ "$(stat -Lc '%d:%i' "/proc/$PORTABLE_PID/exe")" = "$PORTABLE_EXE_ID" ] \
        || fail 'unrelated portable RustDesk executable identity changed'
    python3 - "$PORTABLE_PID" "$PORTABLE_START" "$PORTABLE_UID" <<'PY'
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
expected_uid = sys.argv[3]
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("OpenRC lifecycle smoke: portable identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"rd-smoke-server", b"--server", b""
]:
    raise SystemExit("OpenRC lifecycle smoke: portable role is not exact")
lines = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("Uid", "").split() != [expected_uid] * 4:
    raise SystemExit("OpenRC lifecycle smoke: portable UID changed")
if status.get("NoNewPrivs") != "1":
    raise SystemExit("OpenRC lifecycle smoke: portable process lost no-new-privileges")
for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if int(status.get(capability_set, "1"), 16) != 0:
        raise SystemExit(f"OpenRC lifecycle smoke: portable process retained {capability_set}")
environment = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
if any(entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_") for entry in environment):
    raise SystemExit("OpenRC lifecycle smoke: portable process acquired service-owned authority")
PY
}

start_portable() {
    if ! id -u rdportable >/dev/null 2>&1; then
        useradd -M -u "$PORTABLE_UID" -U -s /usr/sbin/nologin rdportable
    fi
    [ "$(id -u rdportable)" = "$PORTABLE_UID" ] || fail 'portable user UID differs'
    PORTABLE_GID=$(id -g rdportable)
    local portable_root=$FIXTURE/portable
    install -d -o root -g root -m 0755 "$portable_root" "$portable_root/bin"
    install -d -o "$PORTABLE_UID" -g "$PORTABLE_GID" -m 0700 "$portable_root/home"
    install -o root -g root -m 0555 "$SOURCE_BINARY" "$portable_root/bin/rustdesk"
    install -o root -g root -m 0555 "$LAUNCHER_SOURCE" "$portable_root/bin/smoke-server-launcher"
    install -o root -g root -m 0555 "$READY" "$portable_root/bin/smoke-ready.sh"
    install -o root -g root -m 0555 "$PROBE" "$portable_root/bin/smoke_readiness"
    : >"$portable_root/portable.log"
    chown "$PORTABLE_UID:$PORTABLE_GID" "$portable_root/portable.log"
    chmod 0600 "$portable_root/portable.log"
    setpriv --reuid="$PORTABLE_UID" --regid="$PORTABLE_GID" --clear-groups \
        --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env -i HOME="$portable_root/home" USER=rdportable LOGNAME=rdportable \
        PATH=/usr/bin:/bin RUST_LOG=info \
        "$portable_root/bin/smoke-server-launcher" "$portable_root/bin/rustdesk" \
        >"$portable_root/portable.log" 2>&1 &
    PORTABLE_PID=$!
    PORTABLE_START=$($READY --identity "$PORTABLE_PID")
    "$PROCESS_GUARD" wait-server "$PORTABLE_PID" "$PORTABLE_START" \
        "$portable_root/bin/rustdesk"
    PORTABLE_EXE_ID=$(stat -Lc '%d:%i' "/proc/$PORTABLE_PID/exe")
    setpriv --reuid="$PORTABLE_UID" --regid="$PORTABLE_GID" --clear-groups \
        --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env -i HOME="$portable_root/home" USER=rdportable LOGNAME=rdportable PATH=/usr/bin:/bin \
        "$portable_root/bin/smoke-ready.sh" --wait-parked "$PORTABLE_PID" "$PORTABLE_START" \
        "$portable_root/portable.log" "$portable_root/bin/smoke_readiness" "$PORTABLE_UID"
    assert_portable_alive
}

capture_service() {
    local attempt=0 candidate= candidate_start=
    while [ "$attempt" -lt 200 ]; do
        if [ -f "$PIDFILE" ] && [ ! -L "$PIDFILE" ]; then
            IFS= read -r candidate <"$PIDFILE" || true
            if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] \
                && candidate_start=$($READY --identity "$candidate" 2>/dev/null); then
                SERVICE_PID=$candidate
                SERVICE_START=$candidate_start
                break
            fi
        fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ -n "$SERVICE_PID" ] && [ -n "$SERVICE_START" ] \
        || fail 'OpenRC did not publish a live canonical supervisor PID'
    [ "$(stat -c '%u:%g:%a:%h' -- "$PIDFILE")" = 0:0:644:1 ] \
        || fail 'OpenRC pidfile is not root-owned mode 0644 with one link'
    python3 - "$SERVICE_PID" "$SERVICE_START" "$BINARY" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
expected_executable = os.stat(sys.argv[3])
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("OpenRC lifecycle smoke: supervisor identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"/usr/bin/rustdesk", b"--service", b""
]:
    raise SystemExit("OpenRC lifecycle smoke: supervisor role is not exact")
actual_executable = os.stat(f"/proc/{pid}/exe")
if (actual_executable.st_dev, actual_executable.st_ino) != (
    expected_executable.st_dev, expected_executable.st_ino
):
    raise SystemExit("OpenRC lifecycle smoke: supervisor executable object differs")
lines = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("Uid", "").split() != ["0"] * 4:
    raise SystemExit("OpenRC lifecycle smoke: supervisor does not retain four root UIDs")
PY
    rc-service rustdesk status >/dev/null \
        || fail 'OpenRC status does not recognize the started service'
}

assert_parked_socket_surface() {
    local tcp_count udp_count output= attempt=0 ready=0
    local -a tcp_tables=(/proc/net/tcp) udp_tables=(/proc/net/udp)
    [ ! -r /proc/net/tcp6 ] || tcp_tables+=(/proc/net/tcp6)
    [ ! -r /proc/net/udp6 ] || udp_tables+=(/proc/net/udp6)
    tcp_count=$(awk 'FNR > 1 && $4 == "0A" {n++} END {print n + 0}' \
        "${tcp_tables[@]}")
    udp_count=$(awk 'FNR > 1 {n++} END {print n + 0}' "${udp_tables[@]}")
    [ "$tcp_count" = 0 ] || fail "networkless lifecycle has $tcp_count TCP listeners"
    [ "$udp_count" = 0 ] || fail "networkless lifecycle has $udp_count UDP sockets"
    while [ "$attempt" -lt 300 ]; do
        if output=$(timeout --signal=TERM --kill-after=1s 2s "$PROBE" parked \
            "$SERVICE_CHILD" "$SERVICE_CHILD_START" 1500 2>/dev/null) \
            && [ "$output" = 'SMOKE_TYPED_IPC_READY state=parked' ]; then
            ready=1
            break
        fi
        "$READY" --is-running "$SERVICE_CHILD" "$SERVICE_CHILD_START" \
            || fail 'service child exited before typed parked IPC became ready'
        attempt=$((attempt + 1))
        sleep 0.1
    done
    [ "$ready" -eq 1 ] || fail 'service child typed parked IPC timed out'
    [ "$output" = 'SMOKE_TYPED_IPC_READY state=parked' ] \
        || fail 'service child typed IPC did not report the parked state'
    tcp_count=$(awk 'FNR > 1 && $4 == "0A" {n++} END {print n + 0}' \
        "${tcp_tables[@]}")
    udp_count=$(awk 'FNR > 1 {n++} END {print n + 0}' "${udp_tables[@]}")
    [ "$tcp_count:$udp_count" = 0:0 ] \
        || fail 'service child socket surface changed during typed readiness proof'
}

capture_service_child() {
    local stale_hash=${1:-} current_hash= attempt=0
    while [ "$attempt" -lt 1200 ]; do
        if [ -f "$RECORD" ] && [ ! -L "$RECORD" ]; then
            current_hash=$(sha256sum -- "$RECORD" 2>/dev/null | awk '{print $1}' || true)
            if [ -n "$current_hash" ] && { [ -z "$stale_hash" ] || [ "$current_hash" != "$stale_hash" ]; }; then
                break
            fi
        fi
        "$READY" --is-running "$SERVICE_PID" "$SERVICE_START" \
            || fail 'OpenRC supervisor exited before publishing its service child'
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ -n "$current_hash" ] && { [ -z "$stale_hash" ] || [ "$current_hash" != "$stale_hash" ]; } \
        || fail 'service child record was not freshly published'
    read -r SERVICE_CHILD SERVICE_CHILD_START SERVICE_GENERATION < <(
        python3 - "$SERVICE_PID" "$RECORD" "$BINARY" <<'PY'
import os
import re
import stat
import sys
import uuid

supervisor = int(sys.argv[1])
record_path = sys.argv[2]
expected_executable = os.stat(sys.argv[3])
runtime = os.lstat(os.path.dirname(record_path))
if not stat.S_ISDIR(runtime.st_mode) or runtime.st_uid != 0 or stat.S_IMODE(runtime.st_mode) != 0o700:
    raise SystemExit("OpenRC lifecycle smoke: service runtime directory is untrusted")
metadata = os.lstat(record_path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("OpenRC lifecycle smoke: child record is not a single-linked regular file")
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 1024:
    raise SystemExit("OpenRC lifecycle smoke: child record metadata is invalid")
raw = open(record_path, "rb").read(1025)
pattern = re.compile(
    rb"version=1\n"
    rb"pid=([1-9][0-9]*)\n"
    rb"start_time=([1-9][0-9]*)\n"
    rb"boot_id=([0-9a-f-]{36})\n"
    rb"exe_dev=([0-9]+)\n"
    rb"exe_ino=([1-9][0-9]*)\n"
    rb"uid=([0-9]+)\n"
    rb"generation=([0-9a-f-]{36})\n"
    rb"role=--server\+--service-owned-server\n"
)
matched = pattern.fullmatch(raw)
if matched is None:
    raise SystemExit("OpenRC lifecycle smoke: child record is not strict and canonical")
pid, start, boot_id, exe_dev, exe_ino, uid, generation = [
    value.decode("ascii") for value in matched.groups()
]
if any(value != "0" and value.startswith("0") for value in (pid, start, exe_dev, exe_ino, uid)):
    raise SystemExit("OpenRC lifecycle smoke: child record decimal is noncanonical")
if str(uuid.UUID(boot_id)) != boot_id or str(uuid.UUID(generation)) != generation:
    raise SystemExit("OpenRC lifecycle smoke: child record UUID is noncanonical")
if open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii").read().strip() != boot_id:
    raise SystemExit("OpenRC lifecycle smoke: child record boot identity differs")
pid_number = int(pid)
raw_stat = open(f"/proc/{pid_number}/stat", "rb").read()
fields = raw_stat.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != int(start):
    raise SystemExit("OpenRC lifecycle smoke: child process identity differs")
lines = open(f"/proc/{pid_number}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("PPid") != str(supervisor) or status.get("Uid", "").split() != ["0"] * 4:
    raise SystemExit("OpenRC lifecycle smoke: child parent or root identity differs")
if uid != "0" or status.get("NoNewPrivs") != "1":
    raise SystemExit("OpenRC lifecycle smoke: child record UID or no-new-privileges state differs")
executable = os.stat(f"/proc/{pid_number}/exe")
if (executable.st_dev, executable.st_ino) != (int(exe_dev), int(exe_ino)):
    raise SystemExit("OpenRC lifecycle smoke: child executable differs from its record")
if (executable.st_dev, executable.st_ino) != (expected_executable.st_dev, expected_executable.st_ino):
    raise SystemExit("OpenRC lifecycle smoke: child did not execute the installed binary object")
if open(f"/proc/{pid_number}/cmdline", "rb").read().split(b"\0") != [
    b"/proc/self/exe", b"--server", b"--service-owned-server", b""
]:
    raise SystemExit("OpenRC lifecycle smoke: child role is not exact")
environment = open(f"/proc/{pid_number}/environ", "rb").read().split(b"\0")
expected_environment = {
    f"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT={supervisor}".encode("ascii"),
    f"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION={generation}".encode("ascii"),
}
if not expected_environment.issubset(set(environment)):
    raise SystemExit("OpenRC lifecycle smoke: child launch authority differs")
print(pid, start, generation)
PY
    )
    "$READY" --is-running "$SERVICE_CHILD" "$SERVICE_CHILD_START" \
        || fail 'captured OpenRC service child is not running'
    assert_parked_socket_surface
    assert_portable_alive
}

run_openrc() {
    local action=$1 log=$2
    if ! rc-service rustdesk "$action" >"$log" 2>&1; then
        sed -n '1,200p' "$log" >&2
        fail "OpenRC $action failed"
    fi
}

[ "$(id -u)" = 0 ] || fail 'must run as root inside the disposable container'
[ -r /etc/os-release ] || fail '/etc/os-release is absent'
. /etc/os-release
[ "${ID:-}" = debian ] || fail "container is not Debian: ${ID:-unknown}"
[ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail "container is not the audited Debian bookworm fixture: ${VERSION_CODENAME:-unknown}"
[ ! -e /run/systemd/system ] || fail 'systemd is active; native OpenRC was not selected'
[ "$(dpkg-query -W -f='${Version}' openrc)" = "$OPENRC_VERSION" ] \
    || fail 'installed OpenRC version differs from the audited Debian package'
for command in openrc rc-service start-stop-daemon setpriv timeout useradd; do
    command -v "$command" >/dev/null || fail "required command is absent: $command"
done
for path in "$SOURCE_BINARY" "$OPENRC_SOURCE" "$LOGINCTL_SOURCE" "$READY" \
    "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "required source fixture is not regular: $path"
done
[ -x "$SOURCE_BINARY" ] && [ -x "$OPENRC_SOURCE" ] && [ -x "$LOGINCTL_SOURCE" ] \
    && [ -x "$READY" ] && [ -x "$PROCESS_GUARD" ] && [ -x "$LAUNCHER_SOURCE" ] \
    && [ -x "$PROBE" ] || fail 'one or more lifecycle fixtures are not executable'
[ "$(stat -c '%u:%g:%a' -- "$SOURCE_BINARY")" = 0:0:755 ] \
    || fail 'the actual RustDesk binary is not root-owned mode 0755'

source_root_identity=$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")
source_hash=$(sha256sum "$SOURCE_BINARY" "$OPENRC_SOURCE" "$LOGINCTL_SOURCE" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE")
[ ! -e "$BINARY" ] && [ ! -L "$BINARY" ] \
    || fail 'container unexpectedly has an installed RustDesk executable'
[ ! -e "$OPENRC_SERVICE" ] && [ ! -L "$OPENRC_SERVICE" ] \
    || fail 'container unexpectedly has an installed RustDesk OpenRC service'

install -d -o root -g root -m 0711 "$FIXTURE"
install -o root -g root -m 0755 "$SOURCE_BINARY" "$BINARY"
install -o root -g root -m 0755 "$OPENRC_SOURCE" "$OPENRC_SERVICE"
install -o root -g root -m 0755 "$LOGINCTL_SOURCE" /usr/bin/loginctl
printf 'root\n' >"$LOGINCTL_STATE"
chmod 0600 "$LOGINCTL_STATE"
cmp -s "$SOURCE_BINARY" "$BINARY" || fail 'installed RustDesk bytes differ from source'
cmp -s "$OPENRC_SOURCE" "$OPENRC_SERVICE" || fail 'installed OpenRC service differs from source'
[ "$(stat -c '%u:%g:%a' -- "$BINARY")" = 0:0:755 ] \
    || fail 'installed RustDesk identity or mode differs'
[ "$(stat -c '%u:%g:%a' -- "$OPENRC_SERVICE")" = 0:0:755 ] \
    || fail 'installed OpenRC service identity or mode differs'
[ "$(stat -Lc '%d:%i' -- "$SOURCE_BINARY")" != "$(stat -Lc '%d:%i' -- "$BINARY")" ] \
    || fail 'installed RustDesk did not acquire a distinct executable identity'

install -d -o root -g root -m 0755 "/etc/runlevels/$RUNLEVEL" /run/openrc
printf '%s\n' "$RUNLEVEL" >/run/openrc/softlevel
openrc --no-stop "$RUNLEVEL" >"$FIXTURE/openrc-bootstrap.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/openrc-bootstrap.log" >&2; fail 'OpenRC bootstrap failed'; }
[ -d /run/openrc/started ] || fail 'OpenRC did not initialize its runtime state'
[ -z "$(find /run/openrc/started -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail 'the empty smoke runlevel unexpectedly started a service'

start_portable

run_openrc start "$FIXTURE/start.log"
capture_service
capture_service_child
first_pid=$SERVICE_PID
first_start=$SERVICE_START
first_child=$SERVICE_CHILD
first_child_start=$SERVICE_CHILD_START
first_generation=$SERVICE_GENERATION
first_record_hash=$(sha256sum -- "$RECORD" | awk '{print $1}')

run_openrc restart "$FIXTURE/restart.log"
SERVICE_PID=
SERVICE_START=
capture_service
wait_identity_gone "$first_pid" "$first_start" 'pre-restart supervisor'
wait_identity_gone "$first_child" "$first_child_start" 'pre-restart service child'
capture_service_child "$first_record_hash"
[ "$SERVICE_PID:$SERVICE_START" != "$first_pid:$first_start" ] \
    || fail 'OpenRC restart retained the prior supervisor identity'
[ "$SERVICE_CHILD:$SERVICE_CHILD_START" != "$first_child:$first_child_start" ] \
    || fail 'OpenRC restart retained the prior child identity'
[ "$SERVICE_GENERATION" != "$first_generation" ] \
    || fail 'OpenRC restart retained the prior child generation'
assert_portable_alive

restart_pid=$SERVICE_PID
restart_start=$SERVICE_START
restart_child=$SERVICE_CHILD
restart_child_start=$SERVICE_CHILD_START
run_openrc stop "$FIXTURE/stop.log"
wait_identity_gone "$restart_pid" "$restart_start" 'stopped OpenRC supervisor'
wait_identity_gone "$restart_child" "$restart_child_start" 'stopped OpenRC service child'
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ] \
    || fail 'graceful OpenRC stop left a service-child record'
[ -f "$PIDFILE" ] && [ ! -L "$PIDFILE" ] \
    || fail 'OpenRC normal stop did not leave its documented stale pidfile state'
[ "$(stat -c '%u:%g:%a:%h' -- "$PIDFILE")" = 0:0:644:1 ] \
    || fail 'stale OpenRC pidfile metadata changed after stop'
[ "$(sed -n '1p' "$PIDFILE")" = "$restart_pid" ] \
    || fail 'stale OpenRC pidfile did not retain the stopped supervisor PID'
set +e
rc-service rustdesk status >"$FIXTURE/stopped-status.log" 2>&1
stopped_status=$?
set -e
[ "$stopped_status" -ne 0 ] \
    || fail 'OpenRC reported a normally stopped service as started'
grep -Fq -- 'status: stopped' "$FIXTURE/stopped-status.log" \
    || fail 'OpenRC did not expose its stopped manager state'
assert_portable_alive

run_openrc start "$FIXTURE/start-over-stale-pidfile.log"
SERVICE_PID=
SERVICE_START=
capture_service
[ "$SERVICE_PID:$SERVICE_START" != "$restart_pid:$restart_start" ] \
    || fail 'OpenRC start over stale pidfile retained the stopped supervisor identity'
[ "$(sed -n '1p' "$PIDFILE")" = "$SERVICE_PID" ] \
    || fail 'OpenRC did not overwrite its stale pidfile with the new supervisor'
capture_service_child
assert_portable_alive

crashed_pid=$SERVICE_PID
crashed_start=$SERVICE_START
crashed_child=$SERVICE_CHILD
crashed_child_start=$SERVICE_CHILD_START
crashed_generation=$SERVICE_GENERATION
crashed_record_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")
crashed_record_hash=$(sha256sum -- "$RECORD" | awk '{print $1}')
crashed_child_exit_ms=$(crash_supervisor_and_wait_child \
    "$crashed_pid" "$crashed_start" "$crashed_child" "$crashed_child_start")
wait_identity_gone "$crashed_pid" "$crashed_start" 'crashed OpenRC supervisor'
wait_identity_gone "$crashed_child" "$crashed_child_start" 'parent-death-bound service child'
[ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")" = "$crashed_record_identity" ] \
    || fail 'supervisor crash changed the durable child record'
[ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$crashed_record_hash" ] \
    || fail 'supervisor crash changed durable child record bytes'
assert_portable_alive

set +e
rc-service rustdesk status >"$FIXTURE/crashed-status.log" 2>&1
crashed_status=$?
rc-service rustdesk restart >"$FIXTURE/crashed-restart.log" 2>&1
crashed_restart_status=$?
set -e
[ "$crashed_status" -eq 0 ] \
    || fail 'audited OpenRC background mode no longer retains started state after an unobserved crash'
grep -Fq -- 'status: started' "$FIXTURE/crashed-status.log" \
    || fail 'OpenRC crash-state observation differs'
[ "$crashed_restart_status" -ne 0 ] \
    || fail 'OpenRC unexpectedly restarted without first resetting its stale manager state'
grep -Fq -- 'Failed to stop rustdesk' "$FIXTURE/crashed-restart.log" \
    || fail 'OpenRC did not fail the ambiguous direct crash restart at its stop boundary'
[ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$crashed_record_hash" ] \
    || fail 'failed OpenRC crash restart changed the durable child record'
assert_portable_alive

run_openrc zap "$FIXTURE/crashed-zap.log"
grep -Fq -- 'Manually resetting rustdesk to stopped state' "$FIXTURE/crashed-zap.log" \
    || fail 'OpenRC did not explicitly report the crash-state reset'
run_openrc start "$FIXTURE/crash-recovery-start.log"
SERVICE_PID=
SERVICE_START=
capture_service
capture_service_child "$crashed_record_hash"
[ "$SERVICE_PID:$SERVICE_START" != "$crashed_pid:$crashed_start" ] \
    || fail 'OpenRC crash recovery retained the crashed supervisor identity'
[ "$SERVICE_CHILD:$SERVICE_CHILD_START" != "$crashed_child:$crashed_child_start" ] \
    || fail 'OpenRC crash recovery retained the crashed child identity'
[ "$SERVICE_GENERATION" != "$crashed_generation" ] \
    || fail 'OpenRC crash recovery retained the crashed generation'
assert_portable_alive

recovered_pid=$SERVICE_PID
recovered_start=$SERVICE_START
recovered_child=$SERVICE_CHILD
recovered_child_start=$SERVICE_CHILD_START
run_openrc stop "$FIXTURE/final-stop.log"
wait_identity_gone "$recovered_pid" "$recovered_start" 'recovered OpenRC supervisor'
wait_identity_gone "$recovered_child" "$recovered_child_start" 'recovered OpenRC child'
SERVICE_PID=
SERVICE_START=
SERVICE_CHILD=
SERVICE_CHILD_START=
assert_portable_alive
"$READY" --stop "$PORTABLE_PID" "$PORTABLE_START"
wait "$PORTABLE_PID"
PORTABLE_PID=
PORTABLE_START=

[ "$source_root_identity" = "$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")" ] \
    || fail 'read-only source mount identity changed'
[ "$source_hash" = "$(sha256sum "$SOURCE_BINARY" "$OPENRC_SOURCE" "$LOGINCTL_SOURCE" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE")" ] \
    || fail 'read-only source fixtures changed'

printf 'OPENRC_NATIVE_LIFECYCLE=pass os=debian-%s openrc=%s portable_uid=%s normal_restart=pass stale_pidfile=overwritten crash_recovery=zap-start child_exit_ms=%s\n' \
    "$VERSION_ID" "$OPENRC_VERSION" "$PORTABLE_UID" "$crashed_child_exit_ms"

trap - EXIT HUP INT TERM
rm -rf -- "$FIXTURE"

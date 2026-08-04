#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT=/work
readonly SOURCE_BINARY=/smoke-target/debug/rustdesk
readonly BINARY=/usr/bin/rustdesk
readonly RUNIT_SOURCE=$ROOT/res/service-managers/runit/run
readonly LOGINCTL_SOURCE=$ROOT/scripts/smoke-service-loginctl.sh
readonly READY=$ROOT/scripts/smoke-ready.sh
readonly PROCESS_GUARD=$ROOT/scripts/smoke-process-guard.py
readonly LAUNCHER_SOURCE=/smoke-target/smoke-server-launcher
readonly PROBE=/smoke-target/debug/examples/smoke_readiness
readonly RECORD=/run/rustdesk/service-child.record
readonly FIXTURE=/tmp/rustdesk-runit-lifecycle
readonly SERVICES=$FIXTURE/services
readonly SERVICE_DIR=$SERVICES/rustdesk
readonly RUNIT_VERSION=2.1.2-54
readonly PORTABLE_UID=4000

RUNSVDIR_PID=
RUNSVDIR_START=
RUNSV_PID=
RUNSV_START=
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
    printf 'runit lifecycle smoke: %s\n' "$*" >&2
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
signals = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "HUP": signal.SIGHUP}
if pid <= 0 or expected_start <= 0 or signal_name not in signals:
    raise SystemExit("runit lifecycle smoke: invalid retained signal authority")
pidfd = os.pidfd_open(pid, 0)
try:
    raw = open(f"/proc/{pid}/stat", "rb").read()
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20 or fields[0] in {b"Z", b"X", b"x"} or int(fields[19]) != expected_start:
        raise SystemExit("runit lifecycle smoke: retained process identity changed before signal")
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
        raise SystemExit(f"runit lifecycle smoke: retained {label} identity changed before crash")
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
        raise SystemExit("runit lifecycle smoke: exact child did not exit after supervisor crash")
    try:
        raw = open(f"/proc/{child}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError):
        fields = []
    if len(fields) >= 20 and int(fields[19]) == child_start and fields[0] not in {b"Z", b"X", b"x"}:
        raise SystemExit("runit lifecycle smoke: service child remained live after supervisor crash")
    print((time.monotonic_ns() - started_ns) // 1_000_000)
finally:
    os.close(child_pidfd)
    os.close(supervisor_pidfd)
PY
}

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$RUNSV_PID" ] && [ -n "$RUNSV_START" ] \
        && "$READY" --is-running "$RUNSV_PID" "$RUNSV_START" 2>/dev/null \
        && [ -p "$SERVICE_DIR/supervise/control" ]; then
        /usr/bin/sv -w 30 force-shutdown "$SERVICE_DIR" >/dev/null 2>&1 \
            || cleanup_status=1
    elif [ -n "$SERVICE_PID" ] && [ -n "$SERVICE_START" ] \
        && "$READY" --is-running "$SERVICE_PID" "$SERVICE_START" 2>/dev/null; then
        pidfd_signal_exact "$SERVICE_PID" "$SERVICE_START" TERM >/dev/null 2>&1 \
            || cleanup_status=1
    fi
    if [ -n "$SERVICE_CHILD" ] && [ -n "$SERVICE_CHILD_START" ] \
        && "$READY" --is-running "$SERVICE_CHILD" "$SERVICE_CHILD_START" 2>/dev/null; then
        pidfd_signal_exact "$SERVICE_CHILD" "$SERVICE_CHILD_START" KILL >/dev/null 2>&1 \
            || cleanup_status=1
    fi
    if [ -n "$RUNSVDIR_PID" ] && [ -n "$RUNSVDIR_START" ] \
        && "$READY" --is-running "$RUNSVDIR_PID" "$RUNSVDIR_START" 2>/dev/null; then
        pidfd_signal_exact "$RUNSVDIR_PID" "$RUNSVDIR_START" TERM >/dev/null 2>&1 \
            || cleanup_status=1
    fi
    [ -z "$RUNSVDIR_PID" ] || wait "$RUNSVDIR_PID" 2>/dev/null || true
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
    while [ "$attempt" -lt 600 ]; do
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
    raise SystemExit("runit lifecycle smoke: portable identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"rd-smoke-server", b"--server", b""
]:
    raise SystemExit("runit lifecycle smoke: portable role is not exact")
lines = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("Uid", "").split() != [expected_uid] * 4:
    raise SystemExit("runit lifecycle smoke: portable UID changed")
if status.get("NoNewPrivs") != "1":
    raise SystemExit("runit lifecycle smoke: portable process lost no-new-privileges")
for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if int(status.get(capability_set, "1"), 16) != 0:
        raise SystemExit(f"runit lifecycle smoke: portable process retained {capability_set}")
environment = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
if any(entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_") for entry in environment):
    raise SystemExit("runit lifecycle smoke: portable process acquired service-owned authority")
PY
}

wait_portable_parked() {
    local portable_root=$FIXTURE/portable output= attempt=0 ready=0 tcp_count udp_count
    local -a tcp_tables=(/proc/net/tcp) udp_tables=(/proc/net/udp)
    [ ! -r /proc/net/tcp6 ] || tcp_tables+=(/proc/net/tcp6)
    [ ! -r /proc/net/udp6 ] || udp_tables+=(/proc/net/udp6)
    tcp_count=$(awk 'FNR > 1 && $4 == "0A" {n++} END {print n + 0}' \
        "${tcp_tables[@]}")
    udp_count=$(awk 'FNR > 1 {n++} END {print n + 0}' "${udp_tables[@]}")
    [ "$tcp_count:$udp_count" = 0:0 ] \
        || fail 'portable process created a network socket before typed readiness'
    while [ "$attempt" -lt 300 ]; do
        if output=$(/usr/bin/setpriv --reuid="$PORTABLE_UID" --regid="$PORTABLE_GID" \
            --clear-groups --no-new-privs --inh-caps=-all --ambient-caps=-all \
            --bounding-set=-all env -i HOME="$portable_root/home" USER=rdportable \
            LOGNAME=rdportable PATH=/usr/bin:/bin \
            /usr/bin/timeout --signal=TERM --kill-after=1s 2s \
            "$portable_root/bin/smoke_readiness" parked \
            "$PORTABLE_PID" "$PORTABLE_START" 1500 2>/dev/null) \
            && [ "$output" = 'SMOKE_TYPED_IPC_READY state=parked' ]; then
            ready=1
            break
        fi
        assert_portable_alive
        attempt=$((attempt + 1))
        sleep 0.1
    done
    [ "$ready" -eq 1 ] || fail 'portable typed parked IPC timed out'
    tcp_count=$(awk 'FNR > 1 && $4 == "0A" {n++} END {print n + 0}' \
        "${tcp_tables[@]}")
    udp_count=$(awk 'FNR > 1 {n++} END {print n + 0}' "${udp_tables[@]}")
    [ "$tcp_count:$udp_count" = 0:0 ] \
        || fail 'portable process changed the networkless socket surface during readiness'
    assert_portable_alive
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
    wait_portable_parked
}

assert_runsv_tree() {
    "$READY" --is-running "$RUNSVDIR_PID" "$RUNSVDIR_START" \
        || fail 'retained runsvdir identity is not live'
    "$READY" --is-running "$RUNSV_PID" "$RUNSV_START" \
        || fail 'retained runsv identity is not live'
    python3 - "$$" "$RUNSVDIR_PID" "$RUNSVDIR_START" "$RUNSV_PID" "$RUNSV_START" "$SERVICES" <<'PY'
import os
import sys

harness = int(sys.argv[1])
runsvdir = int(sys.argv[2])
runsvdir_start = int(sys.argv[3])
runsv = int(sys.argv[4])
runsv_start = int(sys.argv[5])
services = sys.argv[6].encode("utf-8")

def check_process(pid, expected_start, expected_parent, expected_executable, expected_argv, label):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
        raise SystemExit(f"runit lifecycle smoke: {label} identity changed")
    status_lines = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
    status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status_lines if ":" in line}
    if status.get("PPid") != str(expected_parent) or status.get("Uid", "").split() != ["0"] * 4:
        raise SystemExit(f"runit lifecycle smoke: {label} parent or root identity differs")
    if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != expected_argv:
        raise SystemExit(f"runit lifecycle smoke: {label} argv differs")
    expected = os.stat(expected_executable)
    actual = os.stat(f"/proc/{pid}/exe")
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        raise SystemExit(f"runit lifecycle smoke: {label} executable object differs")

check_process(
    runsvdir,
    runsvdir_start,
    harness,
    "/usr/bin/runsvdir",
    [b"/usr/bin/runsvdir", services, b""],
    "runsvdir",
)
check_process(
    runsv,
    runsv_start,
    runsvdir,
    "/usr/bin/runsv",
    [b"runsv", b"rustdesk", b""],
    "runsv",
)
children = open(f"/proc/{runsvdir}/task/{runsvdir}/children", "r", encoding="ascii").read().split()
if children != [str(runsv)]:
    raise SystemExit("runit lifecycle smoke: runsvdir does not own exactly one runsv")
PY
    for path in "$SERVICE_DIR/supervise/control" "$SERVICE_DIR/supervise/ok"; do
        [ -p "$path" ] && [ ! -L "$path" ] \
            || fail "runit control authority is not a FIFO: $path"
        [ "$(stat -c '%u:%g' -- "$path")" = 0:0 ] \
            || fail "runit control authority is not root-owned: $path"
        [ $((8#$(stat -c '%a' -- "$path") & 0022)) -eq 0 ] \
            || fail "runit control authority is group/world writable: $path"
    done
}

capture_runsv() {
    local attempt=0 children= candidate= candidate_start=
    while [ "$attempt" -lt 200 ]; do
        if children=$(sed -n '1p' "/proc/$RUNSVDIR_PID/task/$RUNSVDIR_PID/children" 2>/dev/null); then
            read -r -a child_list <<<"$children"
            if [ "${#child_list[@]}" -eq 1 ]; then
                candidate=${child_list[0]}
                if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] \
                    && candidate_start=$($READY --identity "$candidate" 2>/dev/null); then
                    RUNSV_PID=$candidate
                    RUNSV_START=$candidate_start
                    break
                fi
            fi
        fi
        "$READY" --is-running "$RUNSVDIR_PID" "$RUNSVDIR_START" \
            || fail 'runsvdir exited before publishing one runsv child'
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ -n "$RUNSV_PID" ] && [ -n "$RUNSV_START" ] \
        || fail 'runsvdir did not publish exactly one live runsv child'
    attempt=0
    while [ "$attempt" -lt 200 ] && [ ! -p "$SERVICE_DIR/supervise/control" ]; do
        "$READY" --is-running "$RUNSV_PID" "$RUNSV_START" \
            || fail 'runsv exited before publishing its control interface'
        attempt=$((attempt + 1))
        sleep 0.05
    done
    assert_runsv_tree
}

capture_service() {
    local previous_pid=${1:-} previous_start=${2:-} attempt=0 candidate= candidate_start=
    while [ "$attempt" -lt 600 ]; do
        if [ -f "$SERVICE_DIR/supervise/pid" ] && [ ! -L "$SERVICE_DIR/supervise/pid" ]; then
            IFS= read -r candidate <"$SERVICE_DIR/supervise/pid" || true
            if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] \
                && candidate_start=$($READY --identity "$candidate" 2>/dev/null) \
                && { [ -z "$previous_pid" ] || [ "$candidate:$candidate_start" != "$previous_pid:$previous_start" ]; }; then
                SERVICE_PID=$candidate
                SERVICE_START=$candidate_start
                break
            fi
        fi
        assert_runsv_tree
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ -n "$SERVICE_PID" ] && [ -n "$SERVICE_START" ] \
        || fail 'runsv did not publish a live canonical RustDesk supervisor PID'
    python3 - "$SERVICE_PID" "$SERVICE_START" "$RUNSV_PID" "$BINARY" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
runsv = int(sys.argv[3])
expected_executable = os.stat(sys.argv[4])
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("runit lifecycle smoke: RustDesk supervisor identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"/usr/bin/rustdesk", b"--service", b""
]:
    raise SystemExit("runit lifecycle smoke: RustDesk supervisor role is not exact")
actual_executable = os.stat(f"/proc/{pid}/exe")
if (actual_executable.st_dev, actual_executable.st_ino) != (
    expected_executable.st_dev, expected_executable.st_ino
):
    raise SystemExit("runit lifecycle smoke: RustDesk supervisor executable object differs")
lines = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("PPid") != str(runsv) or status.get("Uid", "").split() != ["0"] * 4:
    raise SystemExit("runit lifecycle smoke: RustDesk supervisor parent or root identity differs")
PY
    /usr/bin/sv status "$SERVICE_DIR" | grep -Eq '^run: ' \
        || fail 'sv status does not recognize the started RustDesk service'
    assert_runsv_tree
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
            || fail 'RustDesk supervisor exited before publishing its service child'
        assert_runsv_tree
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
    raise SystemExit("runit lifecycle smoke: service runtime directory is untrusted")
metadata = os.lstat(record_path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("runit lifecycle smoke: child record is not a single-linked regular file")
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 1024:
    raise SystemExit("runit lifecycle smoke: child record metadata is invalid")
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
    raise SystemExit("runit lifecycle smoke: child record is not strict and canonical")
pid, start, boot_id, exe_dev, exe_ino, uid, generation = [
    value.decode("ascii") for value in matched.groups()
]
if any(value != "0" and value.startswith("0") for value in (pid, start, exe_dev, exe_ino, uid)):
    raise SystemExit("runit lifecycle smoke: child record decimal is noncanonical")
if str(uuid.UUID(boot_id)) != boot_id or str(uuid.UUID(generation)) != generation:
    raise SystemExit("runit lifecycle smoke: child record UUID is noncanonical")
if open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii").read().strip() != boot_id:
    raise SystemExit("runit lifecycle smoke: child record boot identity differs")
pid_number = int(pid)
raw_stat = open(f"/proc/{pid_number}/stat", "rb").read()
fields = raw_stat.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != int(start):
    raise SystemExit("runit lifecycle smoke: child process identity differs")
lines = open(f"/proc/{pid_number}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines if ":" in line}
if status.get("PPid") != str(supervisor) or status.get("Uid", "").split() != ["0"] * 4:
    raise SystemExit("runit lifecycle smoke: child parent or root identity differs")
if uid != "0" or status.get("NoNewPrivs") != "1":
    raise SystemExit("runit lifecycle smoke: child record UID or no-new-privileges state differs")
executable = os.stat(f"/proc/{pid_number}/exe")
if (executable.st_dev, executable.st_ino) != (int(exe_dev), int(exe_ino)):
    raise SystemExit("runit lifecycle smoke: child executable differs from its record")
if (executable.st_dev, executable.st_ino) != (expected_executable.st_dev, expected_executable.st_ino):
    raise SystemExit("runit lifecycle smoke: child did not execute the installed binary object")
if open(f"/proc/{pid_number}/cmdline", "rb").read().split(b"\0") != [
    b"/proc/self/exe", b"--server", b"--service-owned-server", b""
]:
    raise SystemExit("runit lifecycle smoke: child role is not exact")
environment = open(f"/proc/{pid_number}/environ", "rb").read().split(b"\0")
expected_environment = {
    f"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT={supervisor}".encode("ascii"),
    f"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION={generation}".encode("ascii"),
}
if not expected_environment.issubset(set(environment)):
    raise SystemExit("runit lifecycle smoke: child launch authority differs")
bootstrap_entries = [
    entry.split(b"=", 1)[1]
    for entry in environment
    if entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_BOOTSTRAP_FD=")
]
if len(bootstrap_entries) != 1 or not bootstrap_entries[0].isdigit() or int(bootstrap_entries[0]) <= 2:
    raise SystemExit("runit lifecycle smoke: child bootstrap descriptor authority differs")
print(pid, start, generation)
PY
    )
    "$READY" --is-running "$SERVICE_CHILD" "$SERVICE_CHILD_START" \
        || fail 'captured runit service child is not running'
    assert_parked_socket_surface
    assert_runsv_tree
    assert_portable_alive
}

run_runit() {
    local action=$1 log=$2
    if ! /usr/bin/sv -w 30 "$action" "$SERVICE_DIR" >"$log" 2>&1; then
        sed -n '1,200p' "$log" >&2
        fail "runit $action failed"
    fi
}

[ "$(id -u)" = 0 ] || fail 'must run as root inside the disposable container'
[ -r /etc/os-release ] || fail '/etc/os-release is absent'
. /etc/os-release
[ "${ID:-}" = debian ] || fail "container is not Debian: ${ID:-unknown}"
[ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail "container is not the audited Debian bookworm fixture: ${VERSION_CODENAME:-unknown}"
[ ! -e /run/systemd/system ] || fail 'systemd is active; native runit was not selected'
[ "$(dpkg-query -W -f='${Version}' runit)" = "$RUNIT_VERSION" ] \
    || fail 'installed runit version differs from the audited Debian package'
for command in /usr/bin/runsvdir /usr/bin/runsv /usr/bin/sv \
    /usr/bin/setpriv /usr/bin/timeout /usr/sbin/useradd; do
    [ -x "$command" ] || fail "required command is absent: $command"
done
for path in "$SOURCE_BINARY" "$RUNIT_SOURCE" "$LOGINCTL_SOURCE" "$READY" \
    "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "required source fixture is not regular: $path"
done
[ -x "$SOURCE_BINARY" ] && [ -x "$RUNIT_SOURCE" ] && [ -x "$LOGINCTL_SOURCE" ] \
    && [ -x "$READY" ] && [ -x "$PROCESS_GUARD" ] && [ -x "$LAUNCHER_SOURCE" ] \
    && [ -x "$PROBE" ] || fail 'one or more lifecycle fixtures are not executable'
[ "$(stat -c '%u:%g:%a' -- "$SOURCE_BINARY")" = 0:0:755 ] \
    || fail 'the actual RustDesk binary is not root-owned mode 0755'

source_root_identity=$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")
source_hash=$(sha256sum "$SOURCE_BINARY" "$RUNIT_SOURCE" "$LOGINCTL_SOURCE" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE")
[ ! -e "$BINARY" ] && [ ! -L "$BINARY" ] \
    || fail 'container unexpectedly has an installed RustDesk executable'

install -d -o root -g root -m 0711 "$FIXTURE"
install -d -o root -g root -m 0755 "$SERVICES" "$SERVICE_DIR"
install -o root -g root -m 0711 "$SOURCE_BINARY" "$BINARY"
install -o root -g root -m 0755 "$RUNIT_SOURCE" "$SERVICE_DIR/run"
install -o root -g root -m 0755 "$LOGINCTL_SOURCE" /usr/bin/loginctl
printf 'root\n' >/tmp/rd-service-loginctl-state
chmod 0600 /tmp/rd-service-loginctl-state
install -o root -g root -m 0644 /dev/null "$SERVICE_DIR/down"
cmp -s "$SOURCE_BINARY" "$BINARY" || fail 'installed RustDesk bytes differ from source'
cmp -s "$RUNIT_SOURCE" "$SERVICE_DIR/run" || fail 'installed runit service differs from source'
[ "$(stat -c '%u:%g:%a' -- "$BINARY")" = 0:0:711 ] \
    || fail 'installed RustDesk identity or mode differs'
[ "$(stat -c '%u:%g:%a' -- "$SERVICE_DIR/run")" = 0:0:755 ] \
    || fail 'installed runit service identity or mode differs'
[ "$(stat -Lc '%d:%i' -- "$SOURCE_BINARY")" != "$(stat -Lc '%d:%i' -- "$BINARY")" ] \
    || fail 'installed RustDesk did not acquire a distinct executable identity'

env -i HOME=/root USER=root LOGNAME=root PATH=/usr/bin:/bin RUST_LOG=info \
    /usr/bin/runsvdir "$SERVICES" >"$FIXTURE/runsvdir.log" 2>&1 &
RUNSVDIR_PID=$!
RUNSVDIR_START=$($READY --identity "$RUNSVDIR_PID")
capture_runsv
initial_runsv_pid=$RUNSV_PID
initial_runsv_start=$RUNSV_START
/usr/bin/sv status "$SERVICE_DIR" >"$FIXTURE/initial-status.log"
grep -Eq '^down: ' "$FIXTURE/initial-status.log" \
    || fail 'service/down did not keep the private runit service initially down'

start_portable

run_runit start "$FIXTURE/start.log"
capture_service
capture_service_child
first_pid=$SERVICE_PID
first_start=$SERVICE_START
first_child=$SERVICE_CHILD
first_child_start=$SERVICE_CHILD_START
first_generation=$SERVICE_GENERATION
first_record_hash=$(sha256sum -- "$RECORD" | awk '{print $1}')

run_runit restart "$FIXTURE/restart.log"
SERVICE_PID=
SERVICE_START=
capture_service "$first_pid" "$first_start"
wait_identity_gone "$first_pid" "$first_start" 'pre-restart RustDesk supervisor'
wait_identity_gone "$first_child" "$first_child_start" 'pre-restart service child'
capture_service_child "$first_record_hash"
[ "$SERVICE_CHILD:$SERVICE_CHILD_START" != "$first_child:$first_child_start" ] \
    || fail 'runit restart retained the prior child identity'
[ "$SERVICE_GENERATION" != "$first_generation" ] \
    || fail 'runit restart retained the prior child generation'
[ "$RUNSV_PID:$RUNSV_START" = "$initial_runsv_pid:$initial_runsv_start" ] \
    || fail 'runit restart replaced the owning runsv process'
assert_portable_alive

restart_pid=$SERVICE_PID
restart_start=$SERVICE_START
restart_child=$SERVICE_CHILD
restart_child_start=$SERVICE_CHILD_START
run_runit stop "$FIXTURE/stop.log"
wait_identity_gone "$restart_pid" "$restart_start" 'stopped runit RustDesk supervisor'
wait_identity_gone "$restart_child" "$restart_child_start" 'stopped runit service child'
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ] \
    || fail 'graceful runit stop left a service-child record'
/usr/bin/sv status "$SERVICE_DIR" >"$FIXTURE/stopped-status.log"
grep -Eq '^down: ' "$FIXTURE/stopped-status.log" \
    || fail 'runit did not expose its stopped manager state'
assert_runsv_tree
assert_portable_alive

run_runit start "$FIXTURE/restart-after-stop.log"
SERVICE_PID=
SERVICE_START=
capture_service
capture_service_child
assert_portable_alive

crashed_pid=$SERVICE_PID
crashed_start=$SERVICE_START
crashed_child=$SERVICE_CHILD
crashed_child_start=$SERVICE_CHILD_START
crashed_generation=$SERVICE_GENERATION
crashed_record_hash=$(sha256sum -- "$RECORD" | awk '{print $1}')
crashed_child_exit_ms=$(crash_supervisor_and_wait_child \
    "$crashed_pid" "$crashed_start" "$crashed_child" "$crashed_child_start")
wait_identity_gone "$crashed_pid" "$crashed_start" 'crashed runit RustDesk supervisor'
wait_identity_gone "$crashed_child" "$crashed_child_start" 'parent-death-bound service child'
assert_runsv_tree
assert_portable_alive

SERVICE_PID=
SERVICE_START=
capture_service "$crashed_pid" "$crashed_start"
capture_service_child "$crashed_record_hash"
[ "$SERVICE_PID:$SERVICE_START" != "$crashed_pid:$crashed_start" ] \
    || fail 'runsv automatic crash recovery retained the crashed supervisor identity'
[ "$SERVICE_CHILD:$SERVICE_CHILD_START" != "$crashed_child:$crashed_child_start" ] \
    || fail 'runsv automatic crash recovery retained the crashed child identity'
[ "$SERVICE_GENERATION" != "$crashed_generation" ] \
    || fail 'runsv automatic crash recovery retained the crashed generation'
[ "$RUNSV_PID:$RUNSV_START" = "$initial_runsv_pid:$initial_runsv_start" ] \
    || fail 'automatic service crash recovery replaced the owning runsv process'
assert_portable_alive

recovered_pid=$SERVICE_PID
recovered_start=$SERVICE_START
recovered_child=$SERVICE_CHILD
recovered_child_start=$SERVICE_CHILD_START
pidfd_signal_exact "$RUNSVDIR_PID" "$RUNSVDIR_START" HUP
set +e
wait "$RUNSVDIR_PID"
runsvdir_exit=$?
set -e
[ "$runsvdir_exit" -eq 111 ] \
    || fail "runsvdir HUP exit status differs from its native contract: $runsvdir_exit"
wait_identity_gone "$RUNSV_PID" "$RUNSV_START" 'HUP-drained runsv'
wait_identity_gone "$recovered_pid" "$recovered_start" 'HUP-drained RustDesk supervisor'
wait_identity_gone "$recovered_child" "$recovered_child_start" 'HUP-drained RustDesk service child'
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ] \
    || fail 'native runsvdir/runsv shutdown left a service-child record'
RUNSVDIR_PID=
RUNSVDIR_START=
RUNSV_PID=
RUNSV_START=
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
[ "$source_hash" = "$(sha256sum "$SOURCE_BINARY" "$RUNIT_SOURCE" "$LOGINCTL_SOURCE" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE" "$PROBE")" ] \
    || fail 'read-only source fixtures changed'

printf 'RUNIT_NATIVE_LIFECYCLE=pass os=debian-%s runit=%s portable_uid=%s normal_restart=pass crash_recovery=automatic manager_shutdown=hup-111 child_exit_ms=%s\n' \
    "$VERSION_ID" "$RUNIT_VERSION" "$PORTABLE_UID" "$crashed_child_exit_ms"

trap - EXIT HUP INT TERM
rm -rf -- "$FIXTURE"

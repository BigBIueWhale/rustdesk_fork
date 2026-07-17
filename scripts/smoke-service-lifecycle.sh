#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly READY=/work/scripts/smoke-ready.sh
readonly BINARY=/work/target/debug/rustdesk
readonly PROBE=/work/target/debug/examples/smoke_readiness
readonly LAUNCHER=/work/target/smoke-server-launcher
readonly RECORD=/run/rustdesk/service-child.record
readonly FIXTURE=/tmp/rd-service-lifecycle
readonly LOGINCTL_STATE=/tmp/rd-service-loginctl-state

if [ "$(stat -c '%u:%g:%a' -- "$BINARY")" != 0:0:755 ]; then
  echo "service lifecycle binary must model a root-owned mode-0755 installed executable" >&2
  exit 1
fi

SVC=
SVC_START=
CHILD=
CHILD_START=
GENERATION=
PORTABLE=
PORTABLE_START=

pidfd_signal_only() {
  local pid=$1 expected_start=$2 signal_name=$3
  python3 - "$pid" "$expected_start" "$signal_name" <<'PY'
import os
import signal
import sys
import time

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
signal_name = sys.argv[3]
signals = {"STOP": signal.SIGSTOP, "KILL": signal.SIGKILL}
if pid <= 0 or expected_start <= 0 or signal_name not in signals:
    raise SystemExit(2)

try:
    pidfd = os.pidfd_open(pid, 0)
except OSError as error:
    print(f"service lifecycle: pidfd_open failed: {error}", file=sys.stderr)
    raise SystemExit(1)

with os.fdopen(pidfd) as pidfd_file:
    try:
        raw = open(f"/proc/{pid}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError) as error:
        print(f"service lifecycle: process identity read failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
        print("service lifecycle: retained process identity changed before signal", file=sys.stderr)
        raise SystemExit(1)
    try:
        signal.pidfd_send_signal(pidfd_file.fileno(), signals[signal_name], None, 0)
    except OSError as error:
        print(f"service lifecycle: pidfd signal failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    if signal_name == "STOP":
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                raw = open(f"/proc/{pid}/stat", "rb").read()
                fields = raw.rsplit(b") ", 1)[1].split()
            except (OSError, IndexError):
                break
            if len(fields) >= 20 and int(fields[19]) == expected_start and fields[0] in {b"T", b"t"}:
                break
            time.sleep(0.01)
        else:
            print("service lifecycle: exact child did not enter a stopped state", file=sys.stderr)
            raise SystemExit(1)
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
    if pid <= 0 or expected_start <= 0:
        raise SystemExit(f"service lifecycle: invalid {label} identity")
    try:
        pidfd = os.pidfd_open(pid, 0)
        raw = open(f"/proc/{pid}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError) as error:
        if 'pidfd' in locals():
            os.close(pidfd)
        raise SystemExit(f"service lifecycle: {label} identity read failed: {error}")
    if len(fields) < 20 or fields[0] in {b"Z", b"X", b"x"} or int(fields[19]) != expected_start:
        os.close(pidfd)
        raise SystemExit(f"service lifecycle: retained {label} identity changed before crash")
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
        raise SystemExit("service lifecycle: exact service child did not exit after supervisor crash")
    try:
        raw = open(f"/proc/{child}/stat", "rb").read()
        fields = raw.rsplit(b") ", 1)[1].split()
    except (OSError, IndexError):
        fields = []
    if len(fields) >= 20 and int(fields[19]) == child_start and fields[0] not in {b"Z", b"X", b"x"}:
        raise SystemExit("service lifecycle: exact service child remained running after pidfd exit event")
    print((time.monotonic_ns() - started_ns) // 1_000_000)
finally:
    os.close(child_pidfd)
    os.close(supervisor_pidfd)
PY
}

force_kill_exact() {
  local pid=$1 expected_start=$2
  if "$READY" --is-running "$pid" "$expected_start" 2>/dev/null; then
    pidfd_signal_only "$pid" "$expected_start" KILL || return 1
  fi
}

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT HUP INT TERM
  if [ -n "$SVC" ] && [ -n "$SVC_START" ] && "$READY" --is-running "$SVC" "$SVC_START" 2>/dev/null; then
    "$READY" --stop "$SVC" "$SVC_START" >/dev/null 2>&1 \
      || force_kill_exact "$SVC" "$SVC_START" || cleanup_status=1
  fi
  [ -z "$SVC" ] || wait "$SVC" 2>/dev/null || true
  if [ -n "$CHILD" ] && [ -n "$CHILD_START" ]; then
    force_kill_exact "$CHILD" "$CHILD_START" || cleanup_status=1
  fi
  if [ -n "$PORTABLE" ] && [ -n "$PORTABLE_START" ] \
    && "$READY" --is-running "$PORTABLE" "$PORTABLE_START" 2>/dev/null; then
    "$READY" --stop "$PORTABLE" "$PORTABLE_START" >/dev/null 2>&1 \
      || force_kill_exact "$PORTABLE" "$PORTABLE_START" || cleanup_status=1
  fi
  [ -z "$PORTABLE" ] || wait "$PORTABLE" 2>/dev/null || true
  [ "$cleanup_status" -eq 0 ] || status=125
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_portable_alive() {
  "$READY" --is-running "$PORTABLE" "$PORTABLE_START"
  setpriv --reuid=4000 --regid="$portable_gid" --clear-groups --no-new-privs \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    python3 - "$PORTABLE" "$PORTABLE_START" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("portable server identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [b"rd-smoke-server", b"--server", b""]:
    raise SystemExit("portable server role is not exact")
status = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
if values.get("Uid", "").split() != ["4000"] * 4:
    raise SystemExit("portable server uid changed")
if values.get("NoNewPrivs") != "1" or int(values.get("CapEff", "1"), 16) != 0:
    raise SystemExit("portable server retained privilege")
environ = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
if any(entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_") for entry in environ):
    raise SystemExit("portable server acquired a service-owned marker")
PY
}

wait_for_service_child() {
  local log=$1 expected_uid=${2:-0} expected_gid=${3:-} expected_user=${4:-}
  local expected_home=${5:-} expected_groups=${6:-} stale_record_hash=${7:-}
  local current_record_hash service_log_size
  for _ in $(seq 1 1200); do
    if [ -f "$RECORD" ]; then
      if [ -z "$stale_record_hash" ]; then
        break
      fi
      if current_record_hash=$(sha256sum -- "$RECORD" 2>/dev/null | awk '{print $1}'); then
        [ "$current_record_hash" = "$stale_record_hash" ] || break
      fi
    fi
    "$READY" --is-running "$SVC" "$SVC_START"
    sleep 0.05
  done
  [ -f "$RECORD" ]
  if [ -n "$stale_record_hash" ]; then
    [ "$(sha256sum -- "$RECORD" | awk '{print $1}')" != "$stale_record_hash" ]
  fi
  read -r CHILD CHILD_START GENERATION < <(python3 - "$SVC" "$RECORD" \
    "$expected_uid" "$expected_gid" "$expected_user" "$expected_home" "$expected_groups" <<'PY'
import os
import re
import stat
import sys
import uuid

supervisor = int(sys.argv[1])
record_path = sys.argv[2]
expected_uid = sys.argv[3]
expected_gid = sys.argv[4]
expected_user = sys.argv[5]
expected_home = sys.argv[6]
expected_groups = sys.argv[7]
metadata = os.lstat(record_path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("service child record is not a single-linked regular file")
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 1024:
    raise SystemExit("service child record owner, mode, or size is invalid")
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
    raise SystemExit("service child record is not strict and canonical")
pid, start, boot_id, exe_dev, exe_ino, uid, generation = [value.decode("ascii") for value in matched.groups()]
if any(value != "0" and value.startswith("0") for value in (pid, start, exe_dev, exe_ino, uid)):
    raise SystemExit("service child record has noncanonical decimal")
if str(uuid.UUID(boot_id)) != boot_id or str(uuid.UUID(generation)) != generation:
    raise SystemExit("service child record has noncanonical UUID")
if open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii").read().strip() != boot_id:
    raise SystemExit("service child record boot identity differs")
pid_number = int(pid)
raw_stat = open(f"/proc/{pid_number}/stat", "rb").read()
fields = raw_stat.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != int(start):
    raise SystemExit("service child process identity differs")
status_lines = open(f"/proc/{pid_number}/status", "r", encoding="ascii").read().splitlines()
status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status_lines if ":" in line}
if status.get("PPid") != str(supervisor) or status.get("Uid", "").split() != [uid] * 4:
    raise SystemExit("service child parent or uid differs")
if uid != expected_uid or status.get("NoNewPrivs") != "1":
    raise SystemExit("service child expected uid or no-new-privileges state differs")
executable = os.stat(f"/proc/{pid_number}/exe")
if executable.st_dev != int(exe_dev) or executable.st_ino != int(exe_ino):
    raise SystemExit("service child executable object differs")
argv = open(f"/proc/{pid_number}/cmdline", "rb").read().split(b"\0")
if argv[1:] != [b"--server", b"--service-owned-server", b""]:
    raise SystemExit("service child role differs")
if expected_uid == "0" and argv[0] != b"/proc/self/exe":
    raise SystemExit("root service child executable argument differs")
if expected_uid != "0" and re.fullmatch(rb"/proc/self/fd/[0-9]+", argv[0]) is None:
    raise SystemExit("non-root service child is not descriptor-executed")
environ = [entry for entry in open(f"/proc/{pid_number}/environ", "rb").read().split(b"\0") if entry]
expected = {
    f"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT={supervisor}".encode("ascii"),
    f"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION={generation}".encode("ascii"),
}
if not expected.issubset(set(environ)):
    raise SystemExit("service child launch authority differs")
if expected_uid != "0":
    if not all((expected_gid, expected_user, expected_home, expected_groups)):
        raise SystemExit("non-root service child expectation is incomplete")
    if status.get("Gid", "").split() != [expected_gid] * 4:
        raise SystemExit("non-root service child real/effective/saved/filesystem gid differs")
    actual_groups = sorted(int(value) for value in status.get("Groups", "").split())
    wanted_groups = sorted(int(value) for value in expected_groups.split(","))
    if actual_groups != wanted_groups:
        raise SystemExit("non-root service child supplementary groups differ")
    for capability_set in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if int(status.get(capability_set, "1"), 16) != 0:
            raise SystemExit(f"non-root service child retained {capability_set}")
    parsed_environment = {}
    for entry in environ:
        if b"=" not in entry:
            raise SystemExit("non-root service child environment is malformed")
        key, value = entry.split(b"=", 1)
        if key in parsed_environment:
            raise SystemExit("non-root service child environment has a duplicate key")
        parsed_environment[key] = value
    expected_environment = {
        b"PATH": b"/usr/bin:/bin",
        b"HOME": expected_home.encode("ascii"),
        b"USER": expected_user.encode("ascii"),
        b"LOGNAME": expected_user.encode("ascii"),
        b"XDG_RUNTIME_DIR": f"/run/user/{expected_uid}".encode("ascii"),
        b"DISPLAY": b":0",
        b"XAUTHORITY": f"{expected_home}/.Xauthority".encode("ascii"),
        b"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT": str(supervisor).encode("ascii"),
        b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION": generation.encode("ascii"),
        b"RUSTDESK_SERVICE_OWNED_SERVER_EXECUTABLE_FD": argv[0].rsplit(b"/", 1)[1],
    }
    if set(parsed_environment) != set(expected_environment) | {b"TERM"}:
        raise SystemExit("non-root service child environment was not rebuilt from the bounded allowlist")
    if any(parsed_environment[key] != value for key, value in expected_environment.items()):
        raise SystemExit("non-root service child environment binding differs")
    if parsed_environment[b"TERM"] not in {b"xterm", b"xterm-256color"}:
        raise SystemExit("non-root service child TERM is outside the bounded fallback set")
    descriptor_path = f"/proc/{pid_number}/fd/{parsed_environment[b'RUSTDESK_SERVICE_OWNED_SERVER_EXECUTABLE_FD'].decode('ascii')}"
    try:
        descriptor = os.stat(descriptor_path)
    except FileNotFoundError:
        descriptor = None
    if descriptor is not None and descriptor.st_dev == executable.st_dev and descriptor.st_ino == executable.st_ino:
        raise SystemExit("non-root service child leaked its executable descriptor")
print(pid, start, generation)
PY
)
  for _ in $(seq 1 600); do
    grep -Fq -- 'the direct listener is PARKED' "$log" && break
    "$READY" --is-running "$CHILD" "$CHILD_START"
    sleep 0.05
  done
  grep -Fq -- 'the direct listener is PARKED' "$log"
  while :; do
    service_log_size=$(stat -c %s "$log")
    sleep 0.1
    [ "$(stat -c %s "$log")" = "$service_log_size" ] && break
  done
  if [ "$expected_uid" = 0 ]; then
    "$READY" --wait-parked "$CHILD" "$CHILD_START" "$log" "$PROBE" "$expected_uid"
  else
    chown "$expected_user:$expected_gid" "$log"
    setpriv --reuid="$expected_uid" --regid="$expected_gid" --groups="$expected_groups" \
      --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
      env -i HOME="$expected_home" USER="$expected_user" LOGNAME="$expected_user" \
      PATH=/usr/bin:/bin "$FIXTURE/bin/smoke-ready.sh" --wait-parked "$CHILD" \
      "$CHILD_START" "$log" "$FIXTURE/bin/smoke_readiness" "$expected_uid"
  fi
  assert_portable_alive
}

start_service() {
  local log=$1 expected_uid=${2:-0} expected_gid=${3:-} expected_user=${4:-}
  local expected_home=${5:-} expected_groups=${6:-}
  [ ! -e "$RECORD" ] && [ ! -L "$RECORD" ]
  : > "$log"
  chmod 0600 "$log"
  RUST_LOG=info RD_SERVICE_SMOKE_POISON=must-not-reach-child HOME=/tmp \
    "$BINARY" --service >"$log" 2>&1 &
  SVC=$!
  SVC_START=$("$READY" --identity "$SVC")
  wait_for_service_child "$log" "$expected_uid" "$expected_gid" "$expected_user" \
    "$expected_home" "$expected_groups"
}

start_service_recovering() {
  local log=$1 stale_record_identity=$2 stale_record_hash=$3
  [ -f "$RECORD" ] && [ ! -L "$RECORD" ]
  [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")" = "$stale_record_identity" ]
  [ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$stale_record_hash" ]
  : > "$log"
  chmod 0600 "$log"
  RUST_LOG=info RD_SERVICE_SMOKE_POISON=must-not-reach-child HOME=/tmp \
    "$BINARY" --service >"$log" 2>&1 &
  SVC=$!
  SVC_START=$("$READY" --identity "$SVC")
  wait_for_service_child "$log" 0 "" "" "" "" "$stale_record_hash"
}

stop_service_gracefully() {
  local log=$1 old_child=$CHILD old_child_start=$CHILD_START
  "$READY" --stop "$SVC" "$SVC_START"
  wait "$SVC"
  SVC=
  SVC_START=
  [ ! -e "/proc/$old_child" ]
  [ ! -e "$RECORD" ] && [ ! -L "$RECORD" ]
  grep -Fq -- 'R-T9: graceful shutdown complete — exiting 0' "$log"
  grep -Fq -- '--server child exited with exit status: 0' "$log"
  grep -Fq -- 'librustdesk::platform::linux] Exit' "$log"
  if grep -Fq -- 'forcing stop' "$log"; then
    echo 'service lifecycle: graceful stop unexpectedly forced its child' >&2
    return 1
  fi
  CHILD=
  CHILD_START=
  assert_portable_alive
}

install -o root -g root -m 0755 /work/scripts/smoke-service-loginctl.sh /usr/bin/loginctl
printf '%s\n' root > "$LOGINCTL_STATE"
chmod 0600 "$LOGINCTL_STATE"
id -u rduser >/dev/null 2>&1 || useradd -m -u 4000 rduser
[ "$(id -u rduser)" = 4000 ]
portable_gid=$(id -g rduser)
install -d -o root -g root -m 0755 "$FIXTURE" "$FIXTURE/bin"
install -d -o rduser -g "$portable_gid" -m 0700 "$FIXTURE/home"
install -o root -g root -m 0555 "$BINARY" "$FIXTURE/bin/rustdesk"
install -o root -g root -m 0555 "$LAUNCHER" "$FIXTURE/bin/smoke-server-launcher"
install -o root -g root -m 0555 "$READY" "$FIXTURE/bin/smoke-ready.sh"
install -o root -g root -m 0555 "$PROBE" "$FIXTURE/bin/smoke_readiness"
: > "$FIXTURE/portable.log"
chmod 0600 "$FIXTURE/portable.log"
chown rduser:"$portable_gid" "$FIXTURE/portable.log"
setpriv --reuid=4000 --regid="$portable_gid" --clear-groups --no-new-privs \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
  env -i HOME="$FIXTURE/home" USER=rduser LOGNAME=rduser PATH=/usr/bin:/bin RUST_LOG=info \
  "$FIXTURE/bin/smoke-server-launcher" "$FIXTURE/bin/rustdesk" \
  >"$FIXTURE/portable.log" 2>&1 &
PORTABLE=$!
PORTABLE_START=$("$READY" --identity "$PORTABLE")
for _ in $(seq 1 600); do
  grep -Fq -- 'the direct listener is PARKED' "$FIXTURE/portable.log" && break
  "$READY" --is-running "$PORTABLE" "$PORTABLE_START"
  sleep 0.05
done
grep -Fq -- 'the direct listener is PARKED' "$FIXTURE/portable.log"
while :; do
  portable_log_size=$(stat -c %s "$FIXTURE/portable.log")
  sleep 0.1
  [ "$(stat -c %s "$FIXTURE/portable.log")" = "$portable_log_size" ] && break
done
setpriv --reuid=4000 --regid="$portable_gid" --clear-groups --no-new-privs \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
  env -i HOME="$FIXTURE/home" USER=rduser LOGNAME=rduser PATH=/usr/bin:/bin \
  "$FIXTURE/bin/smoke-ready.sh" --wait-parked "$PORTABLE" "$PORTABLE_START" \
  "$FIXTURE/portable.log" "$FIXTURE/bin/smoke_readiness" 4000
assert_portable_alive

start_service "$FIXTURE/service-1.log"
generation_one=$GENERATION
identity_one="$CHILD:$CHILD_START"
stop_service_gracefully "$FIXTURE/service-1.log"
printf 'SERVICE_LIFECYCLE_GRACEFUL=pass generation=%s\n' "$generation_one"

start_service "$FIXTURE/service-2.log"
[ "$GENERATION" != "$generation_one" ]
[ "$CHILD:$CHILD_START" != "$identity_one" ]
generation_two=$GENERATION
stop_service_gracefully "$FIXTURE/service-2.log"
printf 'SERVICE_LIFECYCLE_RESTART=pass generation=%s\n' "$generation_two"

start_service "$FIXTURE/service-3.log"
[ "$GENERATION" != "$generation_one" ] && [ "$GENERATION" != "$generation_two" ]
forced_child=$CHILD
forced_child_start=$CHILD_START
pidfd_signal_only "$CHILD" "$CHILD_START" STOP
assert_portable_alive
started_ms=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
"$READY" --stop "$SVC" "$SVC_START"
finished_ms=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
wait "$SVC"
SVC=
SVC_START=
elapsed_ms=$((finished_ms - started_ms))
[ "$elapsed_ms" -ge 7500 ] && [ "$elapsed_ms" -le 20000 ]
[ ! -e "/proc/$forced_child" ]
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ]
grep -Fq -- '--server child did not exit after SIGTERM; forcing stop' "$FIXTURE/service-3.log"
grep -Fq -- '--server child exited with signal: 9 (SIGKILL)' "$FIXTURE/service-3.log"
grep -Fq -- 'librustdesk::platform::linux] Exit' "$FIXTURE/service-3.log"
CHILD=
CHILD_START=
assert_portable_alive
printf 'SERVICE_LIFECYCLE_FORCED=pass elapsed_ms=%s\n' "$elapsed_ms"

start_service "$FIXTURE/service-4-crashed.log"
crashed_generation=$GENERATION
crashed_child=$CHILD
crashed_child_start=$CHILD_START
crashed_record_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")
crashed_record_sha256=$(sha256sum -- "$RECORD" | awk '{print $1}')
assert_portable_alive
crashed_child_exit_ms=$(crash_supervisor_and_wait_child \
  "$SVC" "$SVC_START" "$crashed_child" "$crashed_child_start")
if wait "$SVC"; then
  echo 'service lifecycle: crashed supervisor unexpectedly exited successfully' >&2
  exit 1
else
  crashed_supervisor_status=$?
fi
[ "$crashed_supervisor_status" -eq 137 ]
SVC=
SVC_START=
if "$READY" --is-running "$crashed_child" "$crashed_child_start" 2>/dev/null; then
  echo 'service lifecycle: parent-death-bound child survived supervisor crash' >&2
  exit 1
fi
[ -f "$RECORD" ] && [ ! -L "$RECORD" ]
[ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")" = "$crashed_record_identity" ]
[ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$crashed_record_sha256" ]
assert_portable_alive

start_service_recovering "$FIXTURE/service-5-recovered.log" \
  "$crashed_record_identity" "$crashed_record_sha256"
[ "$GENERATION" != "$crashed_generation" ]
[ "$CHILD:$CHILD_START" != "$crashed_child:$crashed_child_start" ]
if ! grep -Eq -- "Discarding (exited Linux service child record for pid $crashed_child|stale Linux service child record for absent pid $crashed_child) without signaling" \
  "$FIXTURE/service-5-recovered.log"; then
  echo 'service lifecycle: fresh supervisor did not report exact stale-record recovery' >&2
  exit 1
fi
recovered_generation=$GENERATION
assert_portable_alive
stop_service_gracefully "$FIXTURE/service-5-recovered.log"
printf 'SERVICE_LIFECYCLE_CRASH_RESTART=pass prior_generation=%s recovered_generation=%s child_exit_ms=%s\n' \
  "$crashed_generation" "$recovered_generation" "$crashed_child_exit_ms"

groupadd -g 4001 rdseat
groupadd -g 4101 rdseat-extra
useradd -m -u 4001 -g rdseat -G rdseat-extra rdseat
[ "$(id -u rdseat)" = 4001 ]
seat_gid=$(id -g rdseat)
[ "$seat_gid" = 4001 ]
seat_groups=$(id -G rdseat | tr ' ' ',')
[ "$seat_groups" = 4001,4101 ]
install -d -o rdseat -g "$seat_gid" -m 0700 /run/user/4001
printf '%s\n' user > "$LOGINCTL_STATE"
start_service "$FIXTURE/service-6-nonroot.log" 4001 "$seat_gid" rdseat /home/rdseat "$seat_groups"
nonroot_generation=$GENERATION
stop_service_gracefully "$FIXTURE/service-6-nonroot.log"
printf 'SERVICE_LIFECYCLE_PRIVILEGE_DROP=pass uid=4001 gid=%s groups=%s generation=%s\n' \
  "$seat_gid" "$seat_groups" "$nonroot_generation"

"$READY" --stop "$PORTABLE" "$PORTABLE_START"
wait "$PORTABLE"
grep -Fq -- 'R-T9: graceful shutdown complete — exiting 0' "$FIXTURE/portable.log"
PORTABLE=
PORTABLE_START=
printf 'PORTABLE_NONINTERFERENCE=pass uid=4000\n'

trap - EXIT HUP INT TERM

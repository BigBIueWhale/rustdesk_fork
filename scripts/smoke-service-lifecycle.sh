#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly READY=/work/scripts/smoke-ready.sh
readonly SOURCE_BINARY=/work/target/debug/rustdesk
readonly BINARY=/usr/bin/rustdesk
readonly PROBE=/work/target/debug/examples/smoke_readiness
readonly LAUNCHER=/work/target/smoke-server-launcher
readonly RECORD=/run/rustdesk/service-child.record
readonly FIXTURE=/tmp/rd-service-lifecycle
readonly LOGINCTL_STATE=/tmp/rd-service-loginctl-state

if [ "$(stat -c '%u:%g:%a' -- "$SOURCE_BINARY")" != 0:0:755 ]; then
  echo "service lifecycle source binary must be root-owned mode 0755" >&2
  exit 1
fi
if [ "$(stat -c '%u:%g:%a' -- "$BINARY")" != 0:0:755 ]; then
  echo "service lifecycle binary must model a root-owned mode-0755 installed executable" >&2
  exit 1
fi
SOURCE_BINARY_IDENTITY=$(stat -Lc '%d:%i' -- "$SOURCE_BINARY")
INSTALLED_BINARY_IDENTITY=$(stat -Lc '%d:%i' -- "$BINARY")
[ "$INSTALLED_BINARY_IDENTITY" != "$SOURCE_BINARY_IDENTITY" ] || {
  echo "service lifecycle installed binary did not acquire a distinct file identity" >&2
  exit 1
}
BINARY_SHA256=$(sha256sum -- "$SOURCE_BINARY" | awk '{print $1}')
[ "$(sha256sum -- "$BINARY" | awk '{print $1}')" = "$BINARY_SHA256" ] || {
  echo "service lifecycle installed binary bytes differ from the built source" >&2
  exit 1
}
MOUNT_NAMESPACE=$(stat -Lc %i /proc/self/ns/mnt)
PID_NAMESPACE=$(stat -Lc %i /proc/self/ns/pid)

SVC=
SVC_START=
CHILD=
CHILD_START=
GENERATION=
PORTABLE=
PORTABLE_START=
DECOY=
DECOY_START=
DECOY_EXECUTABLE=
DECOY_GENERATION=
PRE_PIDFD=
PRE_PIDFD_START=
PRE_PIDFD_GENERATION=
ROOT_ENVIRONMENT_PROVEN=0

readonly -a HOSTILE_SERVICE_ENV=(
  env
  RUST_LOG=info
  RD_SERVICE_SMOKE_POISON=must-not-reach-child
  HOME=/tmp/rustdesk-attacker-home
  XDG_CONFIG_HOME=/tmp/rustdesk-attacker-xdg
  DISPLAY=attacker.invalid:99
  XAUTHORITY=/tmp/rustdesk-attacker.Xauthority
  WAYLAND_DISPLAY=rustdesk-attacker-wayland
  DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/rustdesk-attacker-dbus
  TERM=screen-256color
  TMUX=/tmp/rustdesk-attacker-tmux
  STY=rustdesk-attacker-screen
  PULSE_LATENCY_MSEC=31337
  PIPEWIRE_LATENCY=31337/31337
)

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
  if [ -n "$DECOY" ] && [ -n "$DECOY_START" ] \
    && "$READY" --is-running "$DECOY" "$DECOY_START" 2>/dev/null; then
    force_kill_exact "$DECOY" "$DECOY_START" || cleanup_status=1
  fi
  [ -z "$DECOY" ] || wait "$DECOY" 2>/dev/null || true
  if [ -n "$PRE_PIDFD" ] && [ -n "$PRE_PIDFD_START" ] \
    && "$READY" --is-running "$PRE_PIDFD" "$PRE_PIDFD_START" 2>/dev/null; then
    force_kill_exact "$PRE_PIDFD" "$PRE_PIDFD_START" || cleanup_status=1
  fi
  [ -z "$PRE_PIDFD" ] || wait "$PRE_PIDFD" 2>/dev/null || true
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

assert_decoy_alive() {
  "$READY" --is-running "$DECOY" "$DECOY_START"
  setpriv --reuid=4000 --regid="$portable_gid" --clear-groups --no-new-privs \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    python3 - "$DECOY" "$DECOY_START" "$DECOY_EXECUTABLE" "$DECOY_GENERATION" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
expected_executable = os.stat(sys.argv[3])
expected_generation = sys.argv[4].encode("ascii")
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("hostile-record decoy identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"yes", b"--server", b"--service-owned-server", b""
]:
    raise SystemExit("hostile-record decoy role changed")
executable = os.stat(f"/proc/{pid}/exe")
if (executable.st_dev, executable.st_ino) != (
    expected_executable.st_dev, expected_executable.st_ino
):
    raise SystemExit("hostile-record decoy executable identity changed")
status = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
if values.get("Uid", "").split() != ["4000"] * 4:
    raise SystemExit("hostile-record decoy uid changed")
if values.get("NoNewPrivs") != "1":
    raise SystemExit("hostile-record decoy lost no-new-privileges")
for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if int(values.get(capability_set, "1"), 16) != 0:
        raise SystemExit(f"hostile-record decoy retained {capability_set}")
generation_entries = [
    entry
    for entry in open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
    if entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=")
]
if generation_entries != [b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=" + expected_generation]:
    raise SystemExit("hostile-record decoy generation changed")
PY
}

assert_pre_pidfd_child_alive() {
  "$READY" --is-running "$PRE_PIDFD" "$PRE_PIDFD_START"
  python3 - "$PRE_PIDFD" "$PRE_PIDFD_START" "$BINARY" "$PRE_PIDFD_GENERATION" "$$" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
expected_executable = os.stat(sys.argv[3])
expected_generation = sys.argv[4].encode("ascii")
expected_parent = sys.argv[5].encode("ascii")
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("pre-pidfd service child identity changed")
if open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") != [
    b"rd-smoke-server", b"--server", b"--service-owned-server", b""
]:
    raise SystemExit("pre-pidfd service child role changed")
executable = os.stat(f"/proc/{pid}/exe")
if (executable.st_dev, executable.st_ino) != (
    expected_executable.st_dev, expected_executable.st_ino
):
    raise SystemExit("pre-pidfd service child executable identity changed")
status = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
if values.get("Uid", "").split() != ["0"] * 4:
    raise SystemExit("pre-pidfd service child uid changed")
environ = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
expected_entries = {
    b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=" + expected_generation,
    b"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT=" + expected_parent,
}
if not expected_entries.issubset(set(environ)):
    raise SystemExit("pre-pidfd service child launch authority changed")
PY
}

service_record_process_identity() {
  local pid=$1 expected_start=$2
  python3 - "$pid" "$expected_start" <<'PY'
import os
import sys

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
    raise SystemExit("hostile-record target identity changed")
status = open(f"/proc/{pid}/status", "r", encoding="ascii").read().splitlines()
values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
uids = values.get("Uid", "").split()
if len(uids) != 4 or len(set(uids)) != 1:
    raise SystemExit("hostile-record target uid is not stable")
executable = os.stat(f"/proc/{pid}/exe")
print(executable.st_dev, executable.st_ino, uids[0])
PY
}

write_hostile_service_record() {
  local shape=$1 pid=$2 start_time=$3 executable_device=$4 executable_inode=$5
  local uid=$6 generation=$7 mode=$8
  python3 - "$shape" "$pid" "$start_time" "$executable_device" "$executable_inode" \
    "$uid" "$generation" "$mode" <<'PY'
import os
import stat
import sys
import uuid

shape = sys.argv[1]
pid, start_time, executable_device, executable_inode, uid = map(int, sys.argv[2:7])
generation = sys.argv[7]
mode = int(sys.argv[8], 8)
if shape not in {"canonical", "malformed"}:
    raise SystemExit("unknown hostile-record shape")
if min(pid, start_time, executable_inode) <= 0 or min(executable_device, uid) < 0:
    raise SystemExit("invalid hostile-record numeric field")
if str(uuid.UUID(generation)) != generation:
    raise SystemExit("hostile-record generation is not canonical")

directory = os.open(
    "/run/rustdesk",
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
try:
    metadata = os.fstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("hostile-record runtime directory is untrusted")
    if shape == "malformed":
        payload = b"version=1\n"
    else:
        boot_id = open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii").read().strip()
        if str(uuid.UUID(boot_id)) != boot_id:
            raise SystemExit("kernel boot identity is not canonical")
        payload = (
            "version=1\n"
            f"pid={pid}\n"
            f"start_time={start_time}\n"
            f"boot_id={boot_id}\n"
            f"exe_dev={executable_device}\n"
            f"exe_ino={executable_inode}\n"
            f"uid={uid}\n"
            f"generation={generation}\n"
            "role=--server+--service-owned-server\n"
        ).encode("ascii")
    descriptor = os.open(
        "service-child.record",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise SystemExit("short hostile-record write")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

remove_exact_hostile_service_record() {
  local expected_identity=$1 expected_sha256=$2
  python3 - "$expected_identity" "$expected_sha256" <<'PY'
import hashlib
import os
import stat
import sys

expected_identity = sys.argv[1]
expected_sha256 = sys.argv[2]

def identity(metadata):
    return ":".join(
        str(value)
        for value in (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            format(stat.S_IMODE(metadata.st_mode), "o"),
            metadata.st_nlink,
            metadata.st_size,
            int(metadata.st_mtime),
            int(metadata.st_ctime),
        )
    )

directory = os.open(
    "/run/rustdesk",
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
try:
    descriptor = os.open(
        "service-child.record",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1:
            raise SystemExit("refusing to remove an untrusted hostile-record fixture")
        if identity(metadata) != expected_identity:
            raise SystemExit("refusing to remove a changed hostile-record fixture")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 4096)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected_sha256:
            raise SystemExit("refusing to remove hostile-record bytes with a changed hash")
        path_metadata = os.stat(
            "service-child.record", dir_fd=directory, follow_symlinks=False
        )
        if identity(path_metadata) != expected_identity:
            raise SystemExit("hostile-record path changed before removal")
        os.unlink("service-child.record", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
PY
}

run_rejected_record_case() {
  local label=$1 expected_error=$2
  local before_identity before_sha256 after_identity service_status log
  log="$FIXTURE/hostile-$label.log"
  [ -f "$RECORD" ] && [ ! -L "$RECORD" ]
  before_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$RECORD")
  before_sha256=$(sha256sum -- "$RECORD" | awk '{print $1}')
  if "${HOSTILE_SERVICE_ENV[@]}" "$BINARY" --service >"$log" 2>&1; then
    service_status=0
  else
    service_status=$?
  fi
  if [ "$service_status" -ne 1 ]; then
    echo "service lifecycle: hostile record '$label' returned status $service_status, expected 1" >&2
    return 1
  fi
  after_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$RECORD")
  [ "$after_identity" = "$before_identity" ]
  [ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$before_sha256" ]
  [ ! -e "$RECORD.tmp" ] && [ ! -L "$RECORD.tmp" ]
  grep -Fq -- 'Linux service lifecycle authority failed closed:' "$log"
  grep -Fq -- "$expected_error" "$log"
  assert_decoy_alive
  assert_portable_alive
  remove_exact_hostile_service_record "$before_identity" "$before_sha256"
  [ ! -e "$RECORD" ] && [ ! -L "$RECORD" ]
  printf 'SERVICE_LIFECYCLE_HOSTILE_RECORD=pass case=%s record_sha256=%s\n' \
    "$label" "$before_sha256"
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
    "$expected_uid" "$expected_gid" "$expected_user" "$expected_home" "$expected_groups" \
    "$BINARY" <<'PY'
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
expected_executable = os.stat(sys.argv[8])
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
if (executable.st_dev, executable.st_ino) != (
    expected_executable.st_dev, expected_executable.st_ino
):
    raise SystemExit("service child did not execute the installed binary object")
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
parsed_environment = {}
for entry in environ:
    if b"=" not in entry:
        raise SystemExit("service child environment is malformed")
    key, value = entry.split(b"=", 1)
    if key in parsed_environment:
        raise SystemExit("service child environment has a duplicate key")
    parsed_environment[key] = value
if expected_uid == "0":
    import pwd

    root_home = pwd.getpwuid(0).pw_dir.encode()
    required_environment = {
        b"PATH": b"/usr/bin:/bin",
        b"HOME": root_home,
        b"DISPLAY": b":0",
        b"XAUTHORITY": root_home.rstrip(b"/") + b"/.Xauthority",
        b"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT": str(supervisor).encode("ascii"),
        b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION": generation.encode("ascii"),
    }
    if set(parsed_environment) != set(required_environment) | {b"TERM"}:
        raise SystemExit("root service child environment escaped its bounded allowlist")
    if any(parsed_environment[key] != value for key, value in required_environment.items()):
        raise SystemExit("root service child environment binding differs")
    if parsed_environment.get(b"TERM") not in {b"xterm", b"xterm-256color"}:
        raise SystemExit("root service child TERM is outside the bounded fallback set")
    hostile_values = {
        b"attacker.invalid:99",
        b"/tmp/rustdesk-attacker.Xauthority",
        b"rustdesk-attacker-wayland",
        b"unix:path=/tmp/rustdesk-attacker-dbus",
        b"screen-256color",
        b"/tmp/rustdesk-attacker-home",
        b"/tmp/rustdesk-attacker-xdg",
        b"31337",
        b"31337/31337",
    }
    if hostile_values.intersection(parsed_environment.values()):
        raise SystemExit("root service child adopted a hostile ambient environment value")
else:
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
    ROOT_ENVIRONMENT_PROVEN=1
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
  "${HOSTILE_SERVICE_ENV[@]}" "$BINARY" --service >"$log" 2>&1 &
  SVC=$!
  SVC_START=$("$READY" --identity "$SVC")
  wait_for_service_child "$log" "$expected_uid" "$expected_gid" "$expected_user" \
    "$expected_home" "$expected_groups"
}

start_service_recovering() {
  local log=$1 stale_record_identity=$2 stale_record_hash=$3 force_pre_pidfd=${4:-}
  [ -f "$RECORD" ] && [ ! -L "$RECORD" ]
  [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")" = "$stale_record_identity" ]
  [ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$stale_record_hash" ]
  : > "$log"
  chmod 0600 "$log"
  if [ "$force_pre_pidfd" = force-pre-pidfd ]; then
    "${HOSTILE_SERVICE_ENV[@]}" RD_SERVICE_SMOKE_FORCE_PRE_PIDFD=1 \
      "$BINARY" --service >"$log" 2>&1 &
  else
    "${HOSTILE_SERVICE_ENV[@]}" "$BINARY" --service >"$log" 2>&1 &
  fi
  SVC=$!
  SVC_START=$("$READY" --identity "$SVC")
  wait_for_service_child "$log" 0 "" "" "" "" "$stale_record_hash"
}

start_pre_pidfd_recorded_child() {
  local log=$1 device inode uid
  PRE_PIDFD_GENERATION=$(tr -d '\n' </proc/sys/kernel/random/uuid)
  : > "$log"
  chmod 0600 "$log"
  RUST_LOG=info HOME=/tmp \
    RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT="$$" \
    RUSTDESK_SERVICE_OWNED_SERVER_GENERATION="$PRE_PIDFD_GENERATION" \
    bash --noprofile --norc -c 'exec -a rd-smoke-server "$1" --server --service-owned-server' \
    bash "$BINARY" >"$log" 2>&1 &
  PRE_PIDFD=$!
  PRE_PIDFD_START=$("$READY" --identity "$PRE_PIDFD")
  "$READY" --wait-parked "$PRE_PIDFD" "$PRE_PIDFD_START" "$log" "$PROBE" 0
  assert_pre_pidfd_child_alive
  read -r device inode uid < <(service_record_process_identity "$PRE_PIDFD" "$PRE_PIDFD_START")
  [ "$uid" = 0 ]
  write_hostile_service_record canonical "$PRE_PIDFD" "$PRE_PIDFD_START" \
    "$device" "$inode" 0 "$PRE_PIDFD_GENERATION" 0600
  assert_portable_alive
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

for busybox_candidate in /usr/bin/busybox /bin/busybox; do
  if [ -x "$busybox_candidate" ]; then
    DECOY_EXECUTABLE=$busybox_candidate
    break
  fi
done
if [ -z "$DECOY_EXECUTABLE" ]; then
  echo 'service lifecycle: BusyBox is required for the hostile-record executable decoy' >&2
  exit 1
fi
DECOY_GENERATION=$(tr -d '\n' </proc/sys/kernel/random/uuid)
: > "$FIXTURE/hostile-decoy.log"
chmod 0600 "$FIXTURE/hostile-decoy.log"
chown rduser:"$portable_gid" "$FIXTURE/hostile-decoy.log"
setpriv --reuid=4000 --regid="$portable_gid" --clear-groups --no-new-privs \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
  env -i PATH=/usr/bin:/bin \
  RUSTDESK_SERVICE_OWNED_SERVER_GENERATION="$DECOY_GENERATION" \
  bash --noprofile --norc -c 'exec -a yes "$1" --server --service-owned-server' \
  bash "$DECOY_EXECUTABLE" > /dev/null 2>"$FIXTURE/hostile-decoy.log" &
DECOY=$!
DECOY_START=$(
  for _ in $(seq 1 500); do
    if decoy_start=$("$READY" --identity "$DECOY" 2>/dev/null) \
      && [ "$(tr '\0' '\n' <"/proc/$DECOY/cmdline" 2>/dev/null | paste -sd ' ' -)" \
        = 'yes --server --service-owned-server' ]; then
      printf '%s\n' "$decoy_start"
      break
    fi
    sleep 0.01
  done
)
[ -n "$DECOY_START" ]
pidfd_signal_only "$DECOY" "$DECOY_START" STOP
assert_decoy_alive
read -r decoy_device decoy_inode decoy_uid \
  < <(service_record_process_identity "$DECOY" "$DECOY_START")
[ "$decoy_uid" = 4000 ]
read -r portable_device portable_inode portable_uid \
  < <(service_record_process_identity "$PORTABLE" "$PORTABLE_START")
[ "$portable_uid" = 4000 ]
binary_device=$(stat -Lc %d -- "$BINARY")
binary_inode=$(stat -Lc %i -- "$BINARY")
if [ "$binary_device:$binary_inode" = "$decoy_device:$decoy_inode" ]; then
  echo 'service lifecycle: RustDesk and hostile-record decoy executable identities unexpectedly match' >&2
  exit 1
fi
alternate_generation=$(tr -d '\n' </proc/sys/kernel/random/uuid)
[ "$alternate_generation" != "$DECOY_GENERATION" ]
install -d -o root -g root -m 0700 /run/rustdesk

write_hostile_service_record malformed "$DECOY" "$DECOY_START" \
  "$decoy_device" "$decoy_inode" 4000 "$DECOY_GENERATION" 0600
run_rejected_record_case malformed "Service child record is missing 'pid'"

write_hostile_service_record canonical "$DECOY" "$DECOY_START" \
  "$decoy_device" "$decoy_inode" 4000 "$DECOY_GENERATION" 0644
run_rejected_record_case metadata \
  'Refusing untrusted service child record ownership, type, mode, or link count'

write_hostile_service_record canonical "$DECOY" "$((DECOY_START + 1))" \
  "$decoy_device" "$decoy_inode" 4000 "$DECOY_GENERATION" 0600
run_rejected_record_case reused-start 'start time changed from'

write_hostile_service_record canonical "$DECOY" "$DECOY_START" \
  "$binary_device" "$binary_inode" 4000 "$DECOY_GENERATION" 0600
run_rejected_record_case executable 'executable identity changed from'

write_hostile_service_record canonical "$DECOY" "$DECOY_START" \
  "$decoy_device" "$decoy_inode" 4001 "$DECOY_GENERATION" 0600
run_rejected_record_case uid 'uid changed from 4001 to 4000'

write_hostile_service_record canonical "$DECOY" "$DECOY_START" \
  "$decoy_device" "$decoy_inode" 4000 "$alternate_generation" 0600
run_rejected_record_case generation 'service generation is absent or duplicated'

write_hostile_service_record canonical "$PORTABLE" "$PORTABLE_START" \
  "$portable_device" "$portable_inode" 4000 "$alternate_generation" 0600
run_rejected_record_case portable-role 'exact service-owned role marker is absent'

force_kill_exact "$DECOY" "$DECOY_START"
wait "$DECOY" 2>/dev/null || true
DECOY=
DECOY_START=
printf 'SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata,reused-start,executable,uid,generation,portable-role\n'

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

start_pre_pidfd_recorded_child "$FIXTURE/service-5b-pre-pidfd-child.log"
pre_pidfd_child=$PRE_PIDFD
pre_pidfd_child_start=$PRE_PIDFD_START
pre_pidfd_generation=$PRE_PIDFD_GENERATION
pre_pidfd_record_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RECORD")
pre_pidfd_record_sha256=$(sha256sum -- "$RECORD" | awk '{print $1}')
start_service_recovering "$FIXTURE/service-5b-pre-pidfd-recovered.log" \
  "$pre_pidfd_record_identity" "$pre_pidfd_record_sha256" force-pre-pidfd
if "$READY" --is-running "$pre_pidfd_child" "$pre_pidfd_child_start" 2>/dev/null; then
  echo 'service lifecycle: pre-pidfd fallback left its exact prior child alive' >&2
  exit 1
fi
wait "$PRE_PIDFD"
PRE_PIDFD=
PRE_PIDFD_START=
[ "$GENERATION" != "$pre_pidfd_generation" ]
[ "$CHILD:$CHILD_START" != "$pre_pidfd_child:$pre_pidfd_child_start" ]
grep -Fq -- "Smoke forced pidfd_open unavailable for service child pid $pre_pidfd_child" \
  "$FIXTURE/service-5b-pre-pidfd-recovered.log"
grep -Fq -- "Kernel lacks pidfd_open; recovery revalidates pid $pre_pidfd_child immediately before each kill(2)" \
  "$FIXTURE/service-5b-pre-pidfd-recovered.log"
grep -Fq -- 'R-T9: graceful shutdown complete — exiting 0' \
  "$FIXTURE/service-5b-pre-pidfd-child.log"
pre_pidfd_recovered_generation=$GENERATION
assert_portable_alive
stop_service_gracefully "$FIXTURE/service-5b-pre-pidfd-recovered.log"
printf 'SERVICE_LIFECYCLE_PRE_PIDFD_RECOVERY=pass prior_generation=%s recovered_generation=%s\n' \
  "$pre_pidfd_generation" "$pre_pidfd_recovered_generation"

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
[ "$ROOT_ENVIRONMENT_PROVEN" = 1 ]
printf 'SERVICE_LIFECYCLE_ROOT_ENVIRONMENT=pass authority=desktop-snapshot ambient=excluded\n'

"$READY" --stop "$PORTABLE" "$PORTABLE_START"
wait "$PORTABLE"
grep -Fq -- 'R-T9: graceful shutdown complete — exiting 0' "$FIXTURE/portable.log"
PORTABLE=
PORTABLE_START=
printf 'PORTABLE_NONINTERFERENCE=pass uid=4000\n'
printf 'SERVICE_LIFECYCLE_CONTAINER_IDENTITY=pass path=/usr/bin/rustdesk exe=%s source=%s sha256=%s mnt=%s pidns=%s\n' \
  "$INSTALLED_BINARY_IDENTITY" "$SOURCE_BINARY_IDENTITY" "$BINARY_SHA256" \
  "$MOUNT_NAMESPACE" "$PID_NAMESPACE"

trap - EXIT HUP INT TERM

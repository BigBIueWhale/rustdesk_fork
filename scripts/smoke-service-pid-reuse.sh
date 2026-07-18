#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly READY=/work/scripts/smoke-ready.sh
readonly PROCESS_GUARD=/work/scripts/smoke-process-guard.py
readonly BINARY=/work/target/debug/rustdesk
readonly PROBE=/work/target/debug/examples/smoke_readiness
readonly LAUNCHER=/work/target/smoke-server-launcher
readonly RECORD=/run/rustdesk/service-child.record
readonly NS_LAST_PID=/proc/sys/kernel/ns_last_pid
readonly FIXTURE=/tmp/rd-service-pid-reuse

ORIGINAL_PID=
ORIGINAL_START=
ORIGINAL_GENERATION=
REUSED_PID=
REUSED_START=
REUSED_GENERATION=
PROC_SYS_RW=0

remount_proc_sys_ro() {
  if [ "$PROC_SYS_RW" = 1 ]; then
    mount -o remount,ro /proc/sys >/dev/null 2>&1 || true
    PROC_SYS_RW=0
  fi
}

pidfd_signal_only() {
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
    raise SystemExit(2)

pidfd = os.pidfd_open(pid, 0)
try:
    raw = open(f"/proc/{pid}/stat", "rb").read()
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != expected_start:
        raise SystemExit("retained process identity changed before signal")
    signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)
finally:
    os.close(pidfd)
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
  remount_proc_sys_ro
  if [ -n "$ORIGINAL_PID" ] && [ -n "$ORIGINAL_START" ] \
    && "$READY" --is-running "$ORIGINAL_PID" "$ORIGINAL_START" 2>/dev/null; then
    "$READY" --stop "$ORIGINAL_PID" "$ORIGINAL_START" >/dev/null 2>&1 \
      || force_kill_exact "$ORIGINAL_PID" "$ORIGINAL_START" || cleanup_status=1
  fi
  [ -z "$ORIGINAL_PID" ] || wait "$ORIGINAL_PID" 2>/dev/null || true
  if [ -n "$REUSED_PID" ] && [ -n "$REUSED_START" ] \
    && "$READY" --is-running "$REUSED_PID" "$REUSED_START" 2>/dev/null; then
    "$READY" --stop "$REUSED_PID" "$REUSED_START" >/dev/null 2>&1 \
      || force_kill_exact "$REUSED_PID" "$REUSED_START" || cleanup_status=1
  fi
  [ -z "$REUSED_PID" ] || wait "$REUSED_PID" 2>/dev/null || true
  [ "$cleanup_status" -eq 0 ] || status=125
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

force_next_pid() {
  local target=$1 previous observed
  [[ "$target" =~ ^[1-9][0-9]*$ ]] || {
    echo "service PID reuse: invalid target pid" >&2
    return 1
  }
  previous=$((target - 1))
  [ "$previous" -gt 1 ] || {
    echo "service PID reuse: target pid is too small" >&2
    return 1
  }
  mount -o remount,rw /proc/sys
  PROC_SYS_RW=1
  printf '%s\n' "$previous" > "$NS_LAST_PID"
  IFS= read -r observed < "$NS_LAST_PID"
  [ "$observed" = "$previous" ] || {
    echo "service PID reuse: ns_last_pid did not retain the forced predecessor" >&2
    return 1
  }
}

launch_service_owned_child() {
  local generation=$1 log=$2 pid_var=$3 start_var=$4
  local pid start
  env -i HOME=/tmp PATH=/usr/bin:/bin RUST_LOG=info \
    RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT="$$" \
    RUSTDESK_SERVICE_OWNED_SERVER_GENERATION="$generation" \
    setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    "$LAUNCHER" "$BINARY" --service-owned-server >"$log" 2>&1 &
  pid=$!
  start=$("$READY" --identity "$pid")
  "$PROCESS_GUARD" wait-service-server "$pid" "$start" "$BINARY" "$$" "$generation"
  "$READY" --wait-parked "$pid" "$start" "$log" "$PROBE" 0
  printf -v "$pid_var" '%s' "$pid"
  printf -v "$start_var" '%s' "$start"
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
    raise SystemExit("service PID reuse target identity changed")
process = os.stat(f"/proc/{pid}")
executable = os.stat(f"/proc/{pid}/exe")
print(executable.st_dev, executable.st_ino, process.st_uid)
PY
}

write_service_record() {
  local pid=$1 start_time=$2 executable_device=$3 executable_inode=$4 uid=$5 generation=$6
  python3 - "$pid" "$start_time" "$executable_device" "$executable_inode" "$uid" "$generation" <<'PY'
import os
import stat
import sys
import uuid

pid, start_time, executable_device, executable_inode, uid = map(int, sys.argv[1:6])
generation = sys.argv[6]
if min(pid, start_time, executable_inode) <= 0 or min(executable_device, uid) < 0:
    raise SystemExit("invalid service child record identity")
if str(uuid.UUID(generation)) != generation:
    raise SystemExit("service generation is not canonical")
boot_id = open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii").read().strip()
if str(uuid.UUID(boot_id)) != boot_id:
    raise SystemExit("kernel boot identity is not canonical")

os.makedirs("/run/rustdesk", mode=0o700, exist_ok=True)
os.chmod("/run/rustdesk", 0o700)
directory = os.open("/run/rustdesk", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    metadata = os.fstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("service runtime directory is untrusted")
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
                raise SystemExit("short write while creating service child record")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

remove_exact_service_record() {
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

directory = os.open("/run/rustdesk", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    descriptor = os.open(
        "service-child.record",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1:
            raise SystemExit("refusing to remove an untrusted service record")
        if identity(metadata) != expected_identity:
            raise SystemExit("refusing to remove a changed service record")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 4096)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected_sha256:
            raise SystemExit("refusing to remove service record bytes with a changed hash")
        path_metadata = os.stat("service-child.record", dir_fd=directory, follow_symlinks=False)
        if identity(path_metadata) != expected_identity:
            raise SystemExit("service record path changed before removal")
        os.unlink("service-child.record", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
PY
}

[ "$(stat -c '%u:%g:%a' -- "$BINARY")" = 0:0:755 ] || {
  echo "service PID reuse: source binary must be root-owned mode 0755" >&2
  exit 1
}
[ -x "$LAUNCHER" ] && [ -x "$PROBE" ] && [ -x "$READY" ] && [ -x "$PROCESS_GUARD" ]
install -d -o root -g root -m 0700 "$FIXTURE"

pid_max=$(cat /proc/sys/kernel/pid_max)
[[ "$pid_max" =~ ^[1-9][0-9]*$ ]] || {
  echo "service PID reuse: pid_max is not canonical" >&2
  exit 1
}
if [ "$pid_max" -gt 50000 ]; then
  target_pid=50000
else
  target_pid=$((pid_max - 1000))
fi
[ "$target_pid" -gt 1000 ] || {
  echo "service PID reuse: pid_max is too small for a deterministic high PID fixture" >&2
  exit 1
}

ORIGINAL_GENERATION=$(tr -d '\n' </proc/sys/kernel/random/uuid)
original_log="$FIXTURE/original.log"
: >"$original_log"
chmod 0600 "$original_log"
force_next_pid "$target_pid"
launch_service_owned_child "$ORIGINAL_GENERATION" "$original_log" ORIGINAL_PID ORIGINAL_START
remount_proc_sys_ro
[ "$ORIGINAL_PID" = "$target_pid" ] || {
  echo "service PID reuse: original child did not receive the forced PID" >&2
  exit 1
}
read -r original_device original_inode original_uid \
  < <(service_record_process_identity "$ORIGINAL_PID" "$ORIGINAL_START")
[ "$original_uid" = 0 ]
write_service_record "$ORIGINAL_PID" "$ORIGINAL_START" \
  "$original_device" "$original_inode" 0 "$ORIGINAL_GENERATION"

"$READY" --stop "$ORIGINAL_PID" "$ORIGINAL_START"
wait "$ORIGINAL_PID"
ORIGINAL_PID=
sleep 1

REUSED_GENERATION=$(tr -d '\n' </proc/sys/kernel/random/uuid)
[ "$REUSED_GENERATION" != "$ORIGINAL_GENERATION" ]
reused_log="$FIXTURE/reused.log"
: >"$reused_log"
chmod 0600 "$reused_log"
force_next_pid "$target_pid"
launch_service_owned_child "$REUSED_GENERATION" "$reused_log" REUSED_PID REUSED_START
remount_proc_sys_ro
[ "$REUSED_PID" = "$target_pid" ] || {
  echo "service PID reuse: recycled child did not receive the same forced PID" >&2
  exit 1
}
[ "$REUSED_START" != "$ORIGINAL_START" ] || {
  echo "service PID reuse: recycled PID kept the same start-time identity" >&2
  exit 1
}
read -r reused_device reused_inode reused_uid \
  < <(service_record_process_identity "$REUSED_PID" "$REUSED_START")
[ "$reused_uid" = 0 ]
[ "$reused_device:$reused_inode" = "$original_device:$original_inode" ] || {
  echo "service PID reuse: recycled child did not use the same executable object" >&2
  exit 1
}

before_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$RECORD")
before_sha256=$(sha256sum -- "$RECORD" | awk '{print $1}')
recovery_log="$FIXTURE/recovery.log"
: >"$recovery_log"
chmod 0600 "$recovery_log"
if env -i HOME=/tmp PATH=/usr/bin:/bin RUST_LOG=info RD_SERVICE_SMOKE_POISON=must-not-reach-child \
  setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
  "$BINARY" --service >"$recovery_log" 2>&1; then
  recovery_status=0
else
  recovery_status=$?
fi
[ "$recovery_status" -eq 1 ] || {
  echo "service PID reuse: recovery returned $recovery_status, expected 1" >&2
  exit 1
}
after_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$RECORD")
[ "$after_identity" = "$before_identity" ]
[ "$(sha256sum -- "$RECORD" | awk '{print $1}')" = "$before_sha256" ]
grep -Fq -- 'Linux service lifecycle authority failed closed:' "$recovery_log"
grep -Fq -- "start time changed from $ORIGINAL_START to $REUSED_START" "$recovery_log"
"$PROCESS_GUARD" wait-service-server "$REUSED_PID" "$REUSED_START" "$BINARY" "$$" "$REUSED_GENERATION"
"$READY" --wait-parked "$REUSED_PID" "$REUSED_START" "$reused_log" "$PROBE" 0

reused_start_result=$REUSED_START
remove_exact_service_record "$before_identity" "$before_sha256"
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ]
"$READY" --stop "$REUSED_PID" "$REUSED_START"
wait "$REUSED_PID"
REUSED_PID=
REUSED_START=

printf 'SERVICE_LIFECYCLE_PID_REUSE=pass old_pid=%s reused_pid=%s old_start=%s reused_start=%s old_generation=%s reused_generation=%s record_sha256=%s\n' \
  "$target_pid" "$target_pid" "$ORIGINAL_START" "$reused_start_result" \
  "$ORIGINAL_GENERATION" "$REUSED_GENERATION" "$before_sha256"

trap - EXIT HUP INT TERM

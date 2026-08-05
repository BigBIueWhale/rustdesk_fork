#!/usr/bin/env bash
set -euo pipefail

readonly READY_WAIT_SECONDS=60
readonly SERVER_LISTEN_HEX=0100007F:527E
readonly SERVER_SURFACE_MARKER='socket surface verified — exactly one TCP v4:21118, zero UDP'
readonly SERVER_PARKED_MARKER='the direct listener is PARKED'
readonly SERVER_SHUTDOWN_MARKER='R-T9: graceful shutdown complete — exiting 0'
TCP_TABLES=(/proc/net/tcp)
[ ! -r /proc/net/tcp6 ] || TCP_TABLES+=(/proc/net/tcp6)
UDP_TABLES=(/proc/net/udp)
[ ! -r /proc/net/udp6 ] || UDP_TABLES+=(/proc/net/udp6)
readonly -a TCP_TABLES UDP_TABLES

PINNED_PROBE=
PINNED_PROBE_FD=
SELF_TEST_TMP=
SELF_TEST_TMP_ID=
SELF_TEST_UID=
SELF_TEST_SERVER_PID=
SELF_TEST_SERVER_START=
SELF_TEST_PARKED_PID=
SELF_TEST_PARKED_START=
SELF_TEST_DECOY_PID=
SELF_TEST_DECOY_START=
SELF_TEST_IPC_MARKER=
SELF_TEST_IPC_PARENT_ID=
SELF_TEST_IPC_MAIN_ID=
SELF_TEST_IPC_PASSWORD_ID=
SELF_TEST_IPC_MARKER_ID=
declare -A SELF_TEST_TMP_FILE_IDS=()

fail() {
  printf 'smoke readiness: %s\n' "$*" >&2
  exit 1
}

monotonic_millis() {
  local uptime ignored whole fraction
  read -r uptime ignored < /proc/uptime || return 1
  [[ "$uptime" =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
  whole=${BASH_REMATCH[1]}
  fraction=${BASH_REMATCH[2]}000
  printf '%s\n' "$((10#$whole * 1000 + 10#${fraction:0:3}))"
}

validate_pid() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "invalid pid: $1"
}

validate_start() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "invalid pid start identity: $1"
}

validate_uid() {
  [[ "$1" =~ ^[0-9]+$ ]] || fail "invalid uid: $1"
}

validate_duration() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "invalid duration: $1"
}

validate_listen_hex() {
  [[ "$1" =~ ^[0-9A-F]{8}:[0-9A-F]{4}$ ]] || fail "invalid IPv4 listener key: $1"
}

file_identity() {
  stat -c '%d:%i:%u:%g:%a:%s' -- "$1"
}

followed_file_identity() {
  stat -Lc '%d:%i:%u:%g:%a:%s' -- "$1"
}

mutable_file_object_identity() {
  stat -c '%d:%i:%f:%u:%g:%a:%h' -- "$1"
}

followed_mutable_file_object_identity() {
  stat -Lc '%d:%i:%f:%u:%g:%a:%h' -- "$1"
}

path_identity() {
  stat -c '%d:%i:%f:%u:%g:%a' -- "$1"
}

validate_log() {
  local log=$1 mode
  [ -f "$log" ] && [ ! -L "$log" ] || fail "log is not a regular non-symlink file: $log"
  [ "$(stat -c %u -- "$log")" = "$(id -u)" ] || fail "log is not owned by the readiness-check uid: $log"
  mode=$(stat -c %a -- "$log")
  (( (8#$mode & 0022) == 0 )) || fail "log is group- or world-writable: $log"
}

pin_probe() {
  local probe=$1 mode path_id fd_id
  [ "${probe#/}" != "$probe" ] || fail "typed IPC probe path is not absolute: $probe"
  [ -f "$probe" ] && [ ! -L "$probe" ] && [ -x "$probe" ] \
    || fail "typed IPC probe is not an executable regular non-symlink file: $probe"
  mode=$(stat -c %a -- "$probe")
  (( (8#$mode & 0022) == 0 )) || fail "typed IPC probe is group- or world-writable: $probe"
  path_id=$(file_identity "$probe") || fail "typed IPC probe identity is unavailable: $probe"
  exec {PINNED_PROBE_FD}<"$probe" || fail "typed IPC probe cannot be pinned: $probe"
  PINNED_PROBE="/proc/self/fd/$PINNED_PROBE_FD"
  fd_id=$(followed_file_identity "$PINNED_PROBE") || fail "pinned typed IPC probe identity is unavailable"
  [ "$path_id" = "$fd_id" ] || fail "typed IPC probe changed while being pinned: $probe"
}

read_pid_identity() {
  local pid=$1 stat rest state start
  local -a fields
  [ -r "/proc/$pid/stat" ] || return 1
  IFS= read -r stat < "/proc/$pid/stat" || return 1
  rest=${stat##*) }
  read -r -a fields <<<"$rest"
  [ "${#fields[@]}" -ge 20 ] || return 1
  state=${fields[0]}
  start=${fields[19]}
  [[ "$state" =~ ^[A-Z]$ && "$start" =~ ^[0-9]+$ ]] || return 1
  printf '%s %s\n' "$state" "$start"
}

capture_pid_start() {
  local pid=$1 identity state start
  validate_pid "$pid"
  identity=$(read_pid_identity "$pid") || fail "process is absent before identity capture: $pid"
  read -r state start <<<"$identity"
  [ "$state" != Z ] && [ "$state" != X ] || fail "process is not running during identity capture: $pid"
  validate_start "$start"
  printf '%s\n' "$start"
}

pid_is_same_and_running() {
  local pid=$1 expected_start=$2 identity state start
  identity=$(read_pid_identity "$pid") || return 1
  read -r state start <<<"$identity"
  [ "$start" = "$expected_start" ] || return 2
  [ "$state" != Z ] && [ "$state" != X ]
}

pid_has_uid() {
  local pid=$1 expected_uid=$2 line
  line=$(awk '/^Uid:/{print $2 ":" $3 ":" $4 ":" $5}' "/proc/$pid/status" 2>/dev/null) || return 1
  [ "$line" = "$expected_uid:$expected_uid:$expected_uid:$expected_uid" ]
}

tcp_listen_count() {
  awk 'FNR > 1 && $4 == "0A" { n++ } END { print n + 0 }' "${TCP_TABLES[@]}"
}

udp_socket_count() {
  awk 'FNR > 1 { n++ } END { print n + 0 }' "${UDP_TABLES[@]}"
}

listener_inode() {
  local listen_hex=$1
  awk -v local_addr="$listen_hex" '
    FNR > 1 && $4 == "0A" && $2 == local_addr { count++; inode=$10 }
    END { if (count == 1) print inode; else exit 1 }
  ' "${TCP_TABLES[@]}"
}

unix_listener_inode() {
  local path=$1
  awk -v path="$path" '
    $1 != "Num" && NF >= 8 && $8 == path && $4 == "00010000" && $5 == "0001" && $6 == "01" {
      count++
      inode=$7
    }
    END { if (count == 1) print inode; else exit 1 }
  ' /proc/net/unix
}

pid_owns_socket_inode() {
  local pid=$1 inode=$2 fd target
  for fd in "/proc/$pid/fd/"*; do
    [ -e "$fd" ] || continue
    target=$(readlink -- "$fd") || continue
    [ "$target" = "socket:[$inode]" ] && return 0
  done
  return 1
}

pid_owns_listener() {
  local pid=$1 listen_hex=$2 inode
  inode=$(listener_inode "$listen_hex") || return 1
  pid_owns_socket_inode "$pid" "$inode"
}

pid_owns_unix_listener() {
  local pid=$1 path=$2 inode
  inode=$(unix_listener_inode "$path") || return 1
  pid_owns_socket_inode "$pid" "$inode"
}

ipc_surface_ready() {
  local pid=$1 uid=$2 parent="/tmp/RustDesk-$2" socket
  pid_has_uid "$pid" "$uid" || return 1
  [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
  [ "$(stat -c %u:%a -- "$parent")" = "$uid:700" ] || return 1
  for socket in "$parent/ipc" "$parent/ipc_password"; do
    [ -S "$socket" ] && [ ! -L "$socket" ] || return 1
    [ "$(stat -c %u:%a -- "$socket")" = "$uid:600" ] || return 1
    pid_owns_unix_listener "$pid" "$socket" || return 1
  done
}

remaining_millis() {
  local deadline=$1 now
  now=$(monotonic_millis) || return 1
  [ "$now" -lt "$deadline" ] || return 1
  printf '%s\n' "$((deadline - now))"
}

millis_duration() {
  local millis=$1
  printf '%d.%03ds\n' "$((millis / 1000))" "$((millis % 1000))"
}

typed_ipc_ready() {
  local probe=$1 expected=$2 pid=$3 expected_start=$4 deadline=$5 remaining duration output
  remaining=$(remaining_millis "$deadline") || return 1
  duration=$(millis_duration "$remaining")
  if output=$(timeout --signal=TERM --kill-after=1s "$duration" "$probe" "$expected" "$pid" "$expected_start" "$remaining" 2>&1); then
    [ "$output" = "SMOKE_TYPED_IPC_READY state=$expected" ]
  else
    return 1
  fi
}

server_ready() {
  local pid=$1 expected_start=$2 log=$3 deadline=$4 probe=$5 expected=$6 uid=$7
  [ "$(tcp_listen_count)" = 1 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  pid_owns_listener "$pid" "$SERVER_LISTEN_HEX" || return 1
  grep -Fq -- "$SERVER_SURFACE_MARKER" "$log" || return 1
  ipc_surface_ready "$pid" "$uid" || return 1
  typed_ipc_ready "$probe" "$expected" "$pid" "$expected_start" "$deadline" || return 1
  [ "$(tcp_listen_count)" = 1 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  pid_owns_listener "$pid" "$SERVER_LISTEN_HEX" || return 1
  ipc_surface_ready "$pid" "$uid"
}

server_parked() {
  local pid=$1 expected_start=$2 log=$3 deadline=$4 probe=$5 uid=$6
  [ "$(tcp_listen_count)" = 0 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  grep -Fq -- "$SERVER_PARKED_MARKER" "$log" || return 1
  ipc_surface_ready "$pid" "$uid" || return 1
  typed_ipc_ready "$probe" parked "$pid" "$expected_start" "$deadline" || return 1
  [ "$(tcp_listen_count)" = 0 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  ipc_surface_ready "$pid" "$uid"
}

# The release Flutter runner routes Rust logs to its private log tree instead of
# redirected stderr. Keep the complete socket/PID/typed-state proof while making
# no text-log claim for that runner.
server_typed_ready() {
  local pid=$1 expected_start=$2 _log=$3 deadline=$4 probe=$5 expected=$6 uid=$7
  [ "$(tcp_listen_count)" = 1 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  pid_owns_listener "$pid" "$SERVER_LISTEN_HEX" || return 1
  ipc_surface_ready "$pid" "$uid" || return 1
  typed_ipc_ready "$probe" "$expected" "$pid" "$expected_start" "$deadline" || return 1
  [ "$(tcp_listen_count)" = 1 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  pid_owns_listener "$pid" "$SERVER_LISTEN_HEX" || return 1
  ipc_surface_ready "$pid" "$uid"
}

server_typed_parked() {
  local pid=$1 expected_start=$2 _log=$3 deadline=$4 probe=$5 uid=$6
  [ "$(tcp_listen_count)" = 0 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  ipc_surface_ready "$pid" "$uid" || return 1
  typed_ipc_ready "$probe" parked "$pid" "$expected_start" "$deadline" || return 1
  [ "$(tcp_listen_count)" = 0 ] || return 1
  [ "$(udp_socket_count)" = 0 ] || return 1
  ipc_surface_ready "$pid" "$uid"
}

log_contains() {
  local _pid=$1 _expected_start=$2 log=$3 _deadline=$4 literal=$5
  grep -Fq -- "$literal" "$log"
}

key_failure_observed() {
  local _pid=$1 _expected_start=$2 log=$3 _deadline=$4
  grep -Eq 'security summary .* key_confirmation_failures=[1-9][0-9]*' "$log"
}

capacity_shed_observed() {
  local _pid=$1 _expected_start=$2 log=$3 _deadline=$4
  grep -Eq 'security summary .* shed=[1-9][0-9]*' "$log"
}

tcp_listener_ready() {
  local pid=$1 _expected_start=$2 _log=$3 _deadline=$4 listen_hex=$5
  pid_owns_listener "$pid" "$listen_hex"
}

path_exists() {
  local _pid=$1 _expected_start=$2 _log=$3 _deadline=$4 path=$5
  [ -f "$path" ] && [ ! -L "$path" ]
}

readiness_diagnostic() {
  local pid=$1 label=$2 log=$3 identity
  identity=$(read_pid_identity "$pid" 2>/dev/null || true)
  printf 'smoke readiness: %s; pid=%s identity=[%s] tcp=[%s] udp_count=%s\n' \
    "$label" "$pid" "$identity" \
    "$(awk 'FNR > 1 && $4 == "0A" { printf "%s ", $2 }' "${TCP_TABLES[@]}")" \
    "$(udp_socket_count)" >&2
  tail -n 40 -- "$log" >&2 || true
}

probe_diagnostic() {
  local probe=$1 expected=$2 pid=$3 expected_start=$4
  printf 'smoke readiness: typed IPC probe result for %s:\n' "$expected" >&2
  timeout --signal=TERM --kill-after=1s 1s "$probe" "$expected" "$pid" "$expected_start" 1000 >&2 || true
}

wait_for_condition() (
  local seconds=$1 pid=$2 expected_start=$3 log=$4 label=$5 predicate=$6
  shift 6
  local log_path_id log_fd log_fd_id pinned_log now deadline status
  validate_duration "$seconds"
  validate_pid "$pid"
  validate_start "$expected_start"
  validate_log "$log"
  log_path_id=$(mutable_file_object_identity "$log") || fail "$label: log identity is unavailable"
  exec {log_fd}<"$log" || fail "$label: log cannot be pinned"
  pinned_log="/proc/self/fd/$log_fd"
  log_fd_id=$(followed_mutable_file_object_identity "$pinned_log") || fail "$label: pinned log identity is unavailable"
  [ "$log_path_id" = "$log_fd_id" ] || fail "$label: log changed while being pinned"
  pid_is_same_and_running "$pid" "$expected_start" || fail "$label: retained process identity is not running before readiness proof"
  now=$(monotonic_millis) || fail "$label: monotonic clock is unavailable"
  deadline=$((now + seconds * 1000))
  while :; do
    if pid_is_same_and_running "$pid" "$expected_start"; then
      if "$predicate" "$pid" "$expected_start" "$pinned_log" "$deadline" "$@"; then
        now=$(monotonic_millis) || fail "$label: monotonic clock became unavailable"
        if [ "$now" -le "$deadline" ] && pid_is_same_and_running "$pid" "$expected_start"; then
          return 0
        fi
        status=$?
        readiness_diagnostic "$pid" "$label: process, log, or deadline changed after readiness observation" "$pinned_log"
        [ "$status" -ne 2 ] || fail "$label: pid identity changed after readiness observation"
        return 1
      fi
    else
      status=$?
      readiness_diagnostic "$pid" "$label: process exited or changed identity before readiness" "$pinned_log"
      [ "$status" -ne 2 ] || fail "$label: pid identity changed"
      return 1
    fi
    now=$(monotonic_millis) || fail "$label: monotonic clock became unavailable"
    if [ "$now" -ge "$deadline" ]; then
      readiness_diagnostic "$pid" "$label: readiness deadline expired" "$pinned_log"
      return 1
    fi
    sleep 0.05
  done
)

wait_for_duration() (
  local seconds=$1 pid=$2 expected_start=$3 log=$4 label=$5
  local log_path_id log_fd log_fd_id pinned_log now deadline status
  validate_duration "$seconds"
  validate_pid "$pid"
  validate_start "$expected_start"
  validate_log "$log"
  log_path_id=$(mutable_file_object_identity "$log") || fail "$label: log identity is unavailable"
  exec {log_fd}<"$log" || fail "$label: log cannot be pinned"
  pinned_log="/proc/self/fd/$log_fd"
  log_fd_id=$(followed_mutable_file_object_identity "$pinned_log") || fail "$label: pinned log identity is unavailable"
  [ "$log_path_id" = "$log_fd_id" ] || fail "$label: log changed while being pinned"
  pid_is_same_and_running "$pid" "$expected_start" || fail "$label: retained process identity is not running before monitored interval"
  now=$(monotonic_millis) || fail "$label: monotonic clock is unavailable"
  deadline=$((now + seconds * 1000))
  while :; do
    if ! pid_is_same_and_running "$pid" "$expected_start"; then
      status=$?
      readiness_diagnostic "$pid" "$label: process exited or changed identity during monitored interval" "$pinned_log"
      [ "$status" -ne 2 ] || fail "$label: pid identity changed during monitored interval"
      return 1
    fi
    now=$(monotonic_millis) || fail "$label: monotonic clock became unavailable"
    [ "$now" -lt "$deadline" ] || return 0
    sleep 0.05
  done
)

pidfd_signal_and_wait() {
  local pid=$1 expected_start=$2 signal_name=$3 timeout_ms=$4
  python3 - "$pid" "$expected_start" "$signal_name" "$timeout_ms" <<'PY'
import os
import select
import signal
import sys
import time

pid = int(sys.argv[1])
expected_start = int(sys.argv[2])
signal_name = sys.argv[3]
timeout_ms = int(sys.argv[4])
signals = {"TERM": signal.SIGTERM, "INT": signal.SIGINT, "KILL": signal.SIGKILL}
if signal_name not in signals or timeout_ms <= 0:
    raise SystemExit(2)

try:
    pidfd = os.pidfd_open(pid, 0)
except (OSError, ProcessLookupError) as error:
    print(f"pidfd_open failed: {error}", file=sys.stderr)
    raise SystemExit(1)

with os.fdopen(pidfd):
    try:
        stat = open(f"/proc/{pid}/stat", "r", encoding="ascii").read()
    except OSError as error:
        print(f"process identity read failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    fields = stat.rsplit(") ", 1)[1].split()
    if len(fields) < 20 or fields[0] in {"Z", "X"} or int(fields[19]) != expected_start:
        print("retained process identity is absent or changed before signal", file=sys.stderr)
        raise SystemExit(1)
    try:
        signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)
    except OSError as error:
        print(f"pidfd signal delivery failed: {error}", file=sys.stderr)
        raise SystemExit(1)

    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            print("pidfd exit deadline expired", file=sys.stderr)
            raise SystemExit(1)
        if poller.poll(remaining_ms):
            break
PY
}

signal_and_wait() (
  local seconds=$1 signal_name=$2 pid=$3 expected_start=$4 log=$5 required_literal=$6 label=$7
  local log_path_id log_fd log_fd_id pinned_log
  validate_duration "$seconds"
  validate_pid "$pid"
  validate_start "$expected_start"
  case "$signal_name" in TERM|INT|KILL) ;; *) fail "$label: unsupported signal: $signal_name" ;; esac
  pinned_log=-
  if [ "$log" != - ]; then
    validate_log "$log"
    log_path_id=$(mutable_file_object_identity "$log") || fail "$label: log identity is unavailable"
    exec {log_fd}<"$log" || fail "$label: log cannot be pinned"
    pinned_log="/proc/self/fd/$log_fd"
    log_fd_id=$(followed_mutable_file_object_identity "$pinned_log") || fail "$label: pinned log identity is unavailable"
    [ "$log_path_id" = "$log_fd_id" ] || fail "$label: log changed while being pinned"
  fi
  pid_is_same_and_running "$pid" "$expected_start" || fail "$label: retained process identity is not running before signal"
  if ! pidfd_signal_and_wait "$pid" "$expected_start" "$signal_name" "$((seconds * 1000))"; then
    [ "$pinned_log" = - ] || readiness_diagnostic "$pid" "$label: exit deadline expired" "$pinned_log"
    fail "$label: exact process did not exit after pidfd signal"
  fi
  if [ "$required_literal" != - ]; then
    grep -Fq -- "$required_literal" "$pinned_log" || fail "$label: required terminal log record is absent"
  fi
)

remember_tmp_file() {
  local path=$1
  SELF_TEST_TMP_FILE_IDS["$path"]=$(path_identity "$path") || fail "cannot record self-test path identity: $path"
}

remove_tmp_file() {
  local path=$1 expected=${SELF_TEST_TMP_FILE_IDS[$1]:-}
  [ -n "$expected" ] || fail "self-test path identity was not retained: $path"
  [ "$(path_identity "$path" 2>/dev/null || true)" = "$expected" ] || fail "preserving changed self-test entry: $path"
  rm -- "$path"
  unset 'SELF_TEST_TMP_FILE_IDS[$path]'
}

record_self_test_ipc() {
  local parent="/tmp/RustDesk-$SELF_TEST_UID"
  ipc_surface_ready "$SELF_TEST_SERVER_PID" "$SELF_TEST_UID" || \
    ipc_surface_ready "$SELF_TEST_PARKED_PID" "$SELF_TEST_UID" || fail "self-test IPC surface is not owned by its holder"
  [ -f "$SELF_TEST_IPC_MARKER" ] && [ ! -L "$SELF_TEST_IPC_MARKER" ] || fail "self-test IPC marker is invalid"
  SELF_TEST_IPC_PARENT_ID=$(path_identity "$parent")
  SELF_TEST_IPC_MAIN_ID=$(path_identity "$parent/ipc")
  SELF_TEST_IPC_PASSWORD_ID=$(path_identity "$parent/ipc_password")
  SELF_TEST_IPC_MARKER_ID=$(path_identity "$SELF_TEST_IPC_MARKER")
}

remove_self_test_ipc() {
  local parent socket
  [ -n "$SELF_TEST_IPC_PARENT_ID" ] || return 0
  parent="/tmp/RustDesk-$SELF_TEST_UID"
  [ "$(path_identity "$parent" 2>/dev/null || true)" = "$SELF_TEST_IPC_PARENT_ID" ] || fail "preserving changed self-test IPC root: $parent"
  [ "$(path_identity "$parent/ipc" 2>/dev/null || true)" = "$SELF_TEST_IPC_MAIN_ID" ] || fail "preserving changed self-test IPC entry: $parent/ipc"
  [ "$(path_identity "$parent/ipc_password" 2>/dev/null || true)" = "$SELF_TEST_IPC_PASSWORD_ID" ] || fail "preserving changed self-test IPC entry: $parent/ipc_password"
  [ "$(path_identity "$SELF_TEST_IPC_MARKER" 2>/dev/null || true)" = "$SELF_TEST_IPC_MARKER_ID" ] || fail "preserving changed self-test IPC marker: $SELF_TEST_IPC_MARKER"
  for socket in "$parent/ipc" "$parent/ipc_password"; do
    [ -S "$socket" ] && [ ! -L "$socket" ] || fail "preserving changed self-test IPC entry: $socket"
    [ "$(stat -c %u:%a -- "$socket")" = "$SELF_TEST_UID:600" ] || fail "preserving changed self-test IPC entry: $socket"
  done
  rm -- "$parent/ipc" "$parent/ipc_password"
  rmdir -- "$parent"
  rm -- "$SELF_TEST_IPC_MARKER"
  SELF_TEST_IPC_PARENT_ID=
  SELF_TEST_IPC_MAIN_ID=
  SELF_TEST_IPC_PASSWORD_ID=
  SELF_TEST_IPC_MARKER_ID=
}

remove_self_test_tmp() {
  local path
  [ -n "$SELF_TEST_TMP" ] || return 0
  [ "$(path_identity "$SELF_TEST_TMP" 2>/dev/null || true)" = "$SELF_TEST_TMP_ID" ] || fail "preserving changed self-test directory: $SELF_TEST_TMP"
  for path in "${!SELF_TEST_TMP_FILE_IDS[@]}"; do
    [ "$(path_identity "$path" 2>/dev/null || true)" = "${SELF_TEST_TMP_FILE_IDS[$path]}" ] || fail "preserving changed self-test entry: $path"
  done
  for path in "${!SELF_TEST_TMP_FILE_IDS[@]}"; do
    rm -- "$path"
    unset 'SELF_TEST_TMP_FILE_IDS[$path]'
  done
  rmdir -- "$SELF_TEST_TMP" || fail "preserving non-empty self-test directory: $SELF_TEST_TMP"
}

stop_self_test_child() {
  local pid=$1 start=$2
  [ -n "$pid" ] && [ -n "$start" ] || return 0
  if pid_is_same_and_running "$pid" "$start"; then
    pidfd_signal_and_wait "$pid" "$start" KILL 5000 || return 1
  fi
  wait "$pid" 2>/dev/null || true
}

prove_growing_log_can_be_pinned() {
  local log=$1 path_id log_fd pinned_log log_fd_id
  path_id=$(mutable_file_object_identity "$log") || fail "self-test growing log identity is unavailable"
  exec {log_fd}<"$log" || fail "self-test growing log cannot be pinned"
  pinned_log="/proc/self/fd/$log_fd"
  printf 'self-test concurrent log growth\n' >> "$log"
  log_fd_id=$(followed_mutable_file_object_identity "$pinned_log") \
    || fail "self-test pinned growing log identity is unavailable"
  [ "$path_id" = "$log_fd_id" ] || fail "self-test rejected append-only growth of the pinned log object"
  exec {log_fd}<&-
}

self_test() {
  local log parked_log probe typed_ready probe_hang rc
  SELF_TEST_TMP=$(mktemp -d /tmp/rd-smoke-ready.XXXXXX)
  SELF_TEST_TMP_ID=$(path_identity "$SELF_TEST_TMP")
  SELF_TEST_UID=$(id -u)
  log=$SELF_TEST_TMP/server.log
  parked_log=$SELF_TEST_TMP/parked.log
  probe=$SELF_TEST_TMP/smoke-readiness-probe
  typed_ready=$SELF_TEST_TMP/typed-ready
  probe_hang=$SELF_TEST_TMP/probe-hang
  SELF_TEST_IPC_MARKER=$SELF_TEST_TMP/ipc-owned
  : > "$log"
  remember_tmp_file "$log"
  prove_growing_log_can_be_pinned "$log"
  : > "$parked_log"
  remember_tmp_file "$parked_log"
  cat > "$probe" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[ "\$#" -eq 4 ]
case "\$1" in parked|server|user-server) ;; *) exit 1 ;; esac
[[ "\$2" =~ ^[1-9][0-9]*\$ ]]
[[ "\$3" =~ ^[1-9][0-9]*\$ ]]
[[ "\$4" =~ ^[1-9][0-9]*\$ ]]
[ ! -f "$probe_hang" ] || sleep 5
[ -f "$typed_ready" ]
printf 'SMOKE_TYPED_IPC_READY state=%s\\n' "\$1"
EOF
  chmod 0755 "$probe"
  remember_tmp_file "$probe"
  pin_probe "$probe"
  cleanup_self_test() {
    stop_self_test_child "$SELF_TEST_DECOY_PID" "$SELF_TEST_DECOY_START" || true
    stop_self_test_child "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" || true
    stop_self_test_child "$SELF_TEST_PARKED_PID" "$SELF_TEST_PARKED_START" || true
    remove_self_test_ipc || true
    remove_self_test_tmp || true
  }
  trap cleanup_self_test EXIT
  [ ! -e "/tmp/RustDesk-$SELF_TEST_UID" ] || fail "self-test IPC root already exists"
  python3 - "$log" "$SELF_TEST_UID" "$SELF_TEST_IPC_MARKER" <<'PY' &
import os
import socket
import sys
import time

log, uid, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3]
time.sleep(0.4)
parent = f"/tmp/RustDesk-{uid}"
os.mkdir(parent, 0o700)
os.chmod(parent, 0o700)
sockets = []
for name in ("ipc", "ipc_password"):
    path = os.path.join(parent, name)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    os.chmod(path, 0o600)
    sock.listen(1)
    sockets.append(sock)
fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    stream.write("owned\n")
    stream.flush()
    os.fsync(stream.fileno())
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 21118))
listener.listen(1)
with open(log, "a", encoding="utf-8") as stream:
    stream.write("socket surface verified — exactly one TCP v4:21118, zero UDP\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(30)
PY
  SELF_TEST_SERVER_PID=$!
  SELF_TEST_SERVER_START=$(capture_pid_start "$SELF_TEST_SERVER_PID")
  wait_for_condition 5 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test IPC creation' path_exists "$SELF_TEST_IPC_MARKER"
  record_self_test_ipc
  set +e
  wait_for_condition 1 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test stale-socket rejection' server_ready "$PINNED_PROBE" user-server "$SELF_TEST_UID" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "self-test accepted socket files without a successful typed IPC transaction"
  : > "$typed_ready"
  remember_tmp_file "$typed_ready"
  : > "$probe_hang"
  remember_tmp_file "$probe_hang"
  set +e
  wait_for_condition 1 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test hard probe deadline' server_ready "$PINNED_PROBE" user-server "$SELF_TEST_UID" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "self-test accepted a typed IPC transaction past its hard deadline"
  remove_tmp_file "$probe_hang"
  wait_for_condition 5 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test server readiness' server_ready "$PINNED_PROBE" user-server "$SELF_TEST_UID"
  printf 'security summary source=127.0.0.1 key_confirmation_failures=1 shed=1\n' >> "$log"
  wait_for_condition 5 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test key-failure event' key_failure_observed
  wait_for_condition 5 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test capacity-shed event' capacity_shed_observed
  wait_for_duration 1 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" "$log" 'self-test monitored interval'
  signal_and_wait 5 TERM "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START" - - 'self-test server stop'
  wait "$SELF_TEST_SERVER_PID" 2>/dev/null || true
  SELF_TEST_SERVER_PID=
  SELF_TEST_SERVER_START=
  remove_self_test_ipc
  remove_tmp_file "$typed_ready"

  python3 - "$parked_log" "$SELF_TEST_UID" "$SELF_TEST_IPC_MARKER" <<'PY' &
import os
import socket
import sys
import time

log, uid, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3]
time.sleep(0.4)
parent = f"/tmp/RustDesk-{uid}"
os.mkdir(parent, 0o700)
os.chmod(parent, 0o700)
sockets = []
for name in ("ipc", "ipc_password"):
    path = os.path.join(parent, name)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    os.chmod(path, 0o600)
    sock.listen(1)
    sockets.append(sock)
fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    stream.write("owned\n")
    stream.flush()
    os.fsync(stream.fileno())
with open(log, "a", encoding="utf-8") as stream:
    stream.write("the direct listener is PARKED\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(30)
PY
  SELF_TEST_PARKED_PID=$!
  SELF_TEST_PARKED_START=$(capture_pid_start "$SELF_TEST_PARKED_PID")
  wait_for_condition 5 "$SELF_TEST_PARKED_PID" "$SELF_TEST_PARKED_START" "$parked_log" 'self-test parked IPC creation' path_exists "$SELF_TEST_IPC_MARKER"
  record_self_test_ipc
  : > "$typed_ready"
  remember_tmp_file "$typed_ready"
  python3 -c 'import time; time.sleep(30)' &
  SELF_TEST_DECOY_PID=$!
  SELF_TEST_DECOY_START=$(capture_pid_start "$SELF_TEST_DECOY_PID")
  set +e
  wait_for_condition 1 "$SELF_TEST_DECOY_PID" "$SELF_TEST_DECOY_START" "$parked_log" 'self-test foreign-IPC rejection' server_parked "$PINNED_PROBE" "$SELF_TEST_UID" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "self-test accepted IPC listeners owned by another process"
  signal_and_wait 5 TERM "$SELF_TEST_DECOY_PID" "$SELF_TEST_DECOY_START" - - 'self-test decoy stop'
  wait "$SELF_TEST_DECOY_PID" 2>/dev/null || true
  SELF_TEST_DECOY_PID=
  SELF_TEST_DECOY_START=
  wait_for_condition 5 "$SELF_TEST_PARKED_PID" "$SELF_TEST_PARKED_START" "$parked_log" 'self-test parked readiness' server_parked "$PINNED_PROBE" "$SELF_TEST_UID"
  signal_and_wait 5 TERM "$SELF_TEST_PARKED_PID" "$SELF_TEST_PARKED_START" - - 'self-test parked stop'
  wait "$SELF_TEST_PARKED_PID" 2>/dev/null || true
  set +e
  wait_for_condition 1 "$SELF_TEST_PARKED_PID" "$SELF_TEST_PARKED_START" "$parked_log" 'self-test dead-process rejection' server_parked "$PINNED_PROBE" "$SELF_TEST_UID" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "self-test accepted readiness from a dead process"
  SELF_TEST_PARKED_PID=
  SELF_TEST_PARKED_START=
  remove_self_test_ipc
  remove_tmp_file "$typed_ready"
  trap - EXIT
  remove_self_test_tmp
  SELF_TEST_TMP=
  printf 'smoke readiness self-test: PASS\n'
}

case "${1:-}" in
  --identity)
    [ "$#" -eq 2 ] || fail 'usage: --identity PID'
    capture_pid_start "$2"
    ;;
  --is-running)
    [ "$#" -eq 3 ] || fail 'usage: --is-running PID START_IDENTITY'
    validate_pid "$2"
    validate_start "$3"
    pid_is_same_and_running "$2" "$3"
    ;;
  --wait-parked)
    [ "$#" -eq 6 ] || fail 'usage: --wait-parked PID START_IDENTITY LOG TYPED_IPC_PROBE UID'
    validate_uid "$6"
    pin_probe "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'parked server' server_parked "$PINNED_PROBE" "$6" \
      || { probe_diagnostic "$PINNED_PROBE" parked "$2" "$3"; exit 1; }
    ;;
  --wait-typed-parked)
    [ "$#" -eq 6 ] || fail 'usage: --wait-typed-parked PID START_IDENTITY LOG TYPED_IPC_PROBE UID'
    validate_uid "$6"
    pin_probe "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'typed parked server' server_typed_parked "$PINNED_PROBE" "$6" \
      || { probe_diagnostic "$PINNED_PROBE" parked "$2" "$3"; exit 1; }
    ;;
  --wait-server)
    [ "$#" -eq 6 ] || fail 'usage: --wait-server PID START_IDENTITY LOG TYPED_IPC_PROBE UID'
    validate_uid "$6"
    pin_probe "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'listening server' server_ready "$PINNED_PROBE" server "$6" \
      || { probe_diagnostic "$PINNED_PROBE" server "$2" "$3"; exit 1; }
    ;;
  --wait-user-server)
    [ "$#" -eq 6 ] || fail 'usage: --wait-user-server PID START_IDENTITY LOG TYPED_IPC_PROBE UID'
    validate_uid "$6"
    pin_probe "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'listening user-owned server and IPC' server_ready "$PINNED_PROBE" user-server "$6" \
      || { probe_diagnostic "$PINNED_PROBE" user-server "$2" "$3"; exit 1; }
    ;;
  --wait-typed-user-server)
    [ "$#" -eq 6 ] || fail 'usage: --wait-typed-user-server PID START_IDENTITY LOG TYPED_IPC_PROBE UID'
    validate_uid "$6"
    pin_probe "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'typed listening user-owned server and IPC' server_typed_ready "$PINNED_PROBE" user-server "$6" \
      || { probe_diagnostic "$PINNED_PROBE" user-server "$2" "$3"; exit 1; }
    ;;
  --wait-key-failure)
    [ "$#" -eq 4 ] || fail 'usage: --wait-key-failure PID START_IDENTITY LOG'
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'key-confirmation failure observation' key_failure_observed
    ;;
  --wait-capacity-shed)
    [ "$#" -eq 4 ] || fail 'usage: --wait-capacity-shed PID START_IDENTITY LOG'
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" 'capacity-shed observation' capacity_shed_observed
    ;;
  --wait-log)
    [ "$#" -eq 6 ] || fail 'usage: --wait-log PID START_IDENTITY LOG LITERAL LABEL'
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" "$6" log_contains "$5"
    ;;
  --wait-tcp-listener)
    [ "$#" -eq 6 ] || fail 'usage: --wait-tcp-listener PID START_IDENTITY LOG IPV4_HEX LABEL'
    validate_listen_hex "$5"
    wait_for_condition "$READY_WAIT_SECONDS" "$2" "$3" "$4" "$6" tcp_listener_ready "$5"
    ;;
  --hold-running)
    [ "$#" -eq 6 ] || fail 'usage: --hold-running PID START_IDENTITY LOG SECONDS LABEL'
    wait_for_duration "$5" "$2" "$3" "$4" "$6"
    ;;
  --terminate-server)
    [ "$#" -eq 4 ] || fail 'usage: --terminate-server PID START_IDENTITY LOG'
    signal_and_wait "$READY_WAIT_SECONDS" TERM "$2" "$3" "$4" "$SERVER_SHUTDOWN_MARKER" 'server shutdown'
    ;;
  --stop)
    [ "$#" -eq 3 ] || fail 'usage: --stop PID START_IDENTITY'
    signal_and_wait "$READY_WAIT_SECONDS" TERM "$2" "$3" - - 'process stop'
    ;;
  --interrupt)
    [ "$#" -eq 3 ] || fail 'usage: --interrupt PID START_IDENTITY'
    signal_and_wait "$READY_WAIT_SECONDS" INT "$2" "$3" - - 'process interrupt'
    ;;
  --self-test)
    [ "$#" -eq 1 ] || fail 'usage: --self-test'
    self_test
    ;;
  *)
    fail 'expected one readiness operation'
    ;;
esac

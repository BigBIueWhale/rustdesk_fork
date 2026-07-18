#!/usr/bin/env bash
#
# smoke-server.sh — R-B4 / R-A4 / R-T9 / R-T15(d) RUNTIME smoke-test for the controlled-side server.
#
# verify.sh proves the code COMPILES + the KATs pass; it cannot prove the binary BUILDS-and-LINKS,
# nor the runtime startup/listen/shutdown behaviour. This builds the full server binary in the
# pinned-toolchain container and exercises it headless over the docker LOOPBACK — what the spec's
# R-B4 ("assume nothing builds until watched") and R-A8 (runtime exercise) call for.
#
# It binds 127.0.0.1 — never 0.0.0.0 — in an isolated `--rm` container with no published ports.
# The production binary has no runtime bind-address switch; this harness uses an LD_PRELOAD bind
# shim that rewrites only the public test bind (0.0.0.0:21118 -> 127.0.0.1:21118).
#
# Validated at RUNTIME (not merely compile):
#   - R-B4 build  : the full `rustdesk` binary builds + links + runs headless (sciter is `dyn`);
#   - R-A4/R-S9 (fail-closed startup) : with NO permanent password the box PARKS — it stays alive
#     but binds NO listener (nothing on the pinned port) and refuses every connection (finding D:
#     the startup process::exit was removed; on the shared-process Android app it crashed the app);
#   - R-B4 / R-D3/R-D5/R-D6 socket surface : with a password seeded the box binds EXACTLY ONE v4 TCP
#     listener on the pinned port (21118) and ZERO UDP — the §17 direct-IP/no-UDP thesis, empirical;
#   - R-A4 (runtime socket self-check) : `assert_socket_surface` confirms the same from inside;
#   - R-T9 : SIGTERM -> "graceful shutdown initiated" -> "complete — exiting 0";
#   - R-S11c-27h : the real --service active-seat path descriptor-execs as UID/GID 4001 with
#     exact supplementary groups, zero live capability sets, NNP, bounded environment, typed IPC,
#     graceful reap, and no interference with a separate UID-4000 portable server;
#   - R-S11c-27i : the real --service supervisor rejects malformed and live-but-ambiguous durable
#     child records without changing the record or either separately identity-bound UID-4000 process;
#   - R-S11c-27j : the manual lifecycle stage cannot affect a concurrently running networkless
#     sibling Docker container with its own PID namespace and neutral launched RustDesk server;
#   - R-S11c-27k : the real --service recovery path exercises the pre-pidfd revalidated kill(2)
#     fallback under a smoke-only forced pidfd-unavailable runtime;
#   - R-S11c-27n : separate PID/mount namespaces install the same bytes at /usr/bin/rustdesk as
#     different executable objects; the exact-role sibling survives every main-namespace action;
#   - R-D8 / R-D2 (real password provisioning) : the production `--password-stdin` CLI run against a
#     non-installed user-owned live --server (2b root-owned, 2c non-root same-uid) provisions over
#     uid-scoped main IPC and CLEANLY set-and-exits (no hang); the new credential keys and the old one
#     is rejected. An installed-layout binary separately proves service-owned routing cannot fall back
#     to that user-owned daemon when the privileged service endpoint is absent;
#   - R-A9 (wire-capture) : a distinctive plaintext canary sent in a POST-KEY LoginRequest NEVER
#     appears in a tcpdump of the loopback — the keyed session bytes carry no recoverable plaintext.
#
# Most stages seed the permanent password via the TEST-ONLY `examples/seed_password` (a direct Config
# write) for speed; stages (2b-2d) exercise the production `--password-stdin` CLI end-to-end.
#
# Usage:  scripts/smoke-server.sh           (the fast default path)
#         SMOKE_DECAY=1 scripts/smoke-server.sh   (also runs stage 10 — the R-A8 limiter-DECAY proof,
#                                                  which waits out the real 60s window, ~75 s slower)
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
IMG=rd-devcheck
BUILD_RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -w /work "$IMG")
RUN=(docker run --rm
  -v "$PWD:/work:ro"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -w /work "$IMG")
LIFECYCLE_RUN=(docker run --rm --network none --cap-add SYS_PTRACE
  -v "$PWD:/work:ro"
  -w /work "$IMG")
PID_REUSE_RUN=(docker run --rm --network none --read-only --pids-limit 128
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add CHECKPOINT_RESTORE --cap-add SETPCAP
  --security-opt no-new-privileges --security-opt apparmor=unconfined
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777
  --tmpfs /run:rw,nosuid,nodev,noexec,mode=755
  -v "$PWD:/work:ro"
  -w /work "$IMG")
PORT_HEX='527E' # 21118
LOOPBACK_LISTEN='0100007F:527E' # 127.0.0.1:21118
HOST_GUARD=$PWD/scripts/smoke-process-guard.py
HOST_GUARD_ROOT=
HOST_GUARD_ROOT_ID=
HOST_GUARD_PID=
HOST_GUARD_START=
SIBLING_ROOT=
SIBLING_ROOT_ID=
SIBLING_NAME=
SIBLING_CID=

host_guard_diagnostic() {
  [ -n "$HOST_GUARD_ROOT" ] || return 0
  [ ! -f "$HOST_GUARD_ROOT/monitor.log" ] || sed -n '1,120p' "$HOST_GUARD_ROOT/monitor.log" >&2
  [ ! -f "$HOST_GUARD_ROOT/violation.json" ] || sed -n '1,40p' "$HOST_GUARD_ROOT/violation.json" >&2
}

host_guard_is_running() {
  [ -n "$HOST_GUARD_PID" ] && [ -n "$HOST_GUARD_START" ] \
    && bash scripts/smoke-ready.sh --is-running "$HOST_GUARD_PID" "$HOST_GUARD_START"
}

reap_failed_host_guard() {
  local status=0
  [ -n "$HOST_GUARD_PID" ] || return 1
  if wait "$HOST_GUARD_PID"; then
    status=0
  else
    status=$?
  fi
  HOST_GUARD_PID=
  HOST_GUARD_START=
  host_guard_diagnostic
  [ "$status" -eq 0 ] || return "$status"
  return 1
}

host_guard_checkpoint() {
  if host_guard_is_running; then
    return 0
  fi
  echo "  FAIL smoke host coexistence: historical-selector monitor exited" >&2
  reap_failed_host_guard || true
  return 1
}

stop_host_guard() {
  local status=0
  [ -n "$HOST_GUARD_PID" ] || return 0
  if host_guard_is_running; then
    "$HOST_GUARD" request-stop "$HOST_GUARD_ROOT/stop" || status=$?
  fi
  if wait "$HOST_GUARD_PID"; then
    :
  else
    status=$?
  fi
  HOST_GUARD_PID=
  HOST_GUARD_START=
  if [ "$status" -ne 0 ]; then
    host_guard_diagnostic
    return "$status"
  fi
  sed -n '1,120p' "$HOST_GUARD_ROOT/monitor.log"
}

sibling_container_running() {
  [ -n "$SIBLING_CID" ] || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$SIBLING_CID" 2>/dev/null || true)" = true ]
}

cleanup_sibling_root() {
  local cleanup_status=0 path
  [ -n "$SIBLING_ROOT" ] || return 0
  if [ "$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT" 2>/dev/null || true)" != "$SIBLING_ROOT_ID" ]; then
    echo "sibling docker: preserving changed private workspace" >&2
    return 125
  fi
  for path in ready stop; do
    [ ! -e "$SIBLING_ROOT/$path" ] && [ ! -L "$SIBLING_ROOT/$path" ] \
      || rm -- "$SIBLING_ROOT/$path" || cleanup_status=125
  done
  rmdir -- "$SIBLING_ROOT" || cleanup_status=125
  if [ "$cleanup_status" -eq 0 ]; then
    SIBLING_ROOT=
    SIBLING_ROOT_ID=
  fi
  return "$cleanup_status"
}

start_sibling_docker() {
  local docker_out i ready_logs suffix
  SIBLING_ROOT=$(mktemp -d /tmp/rustdesk-smoke-sibling.XXXXXXXXXX) || return 1
  SIBLING_ROOT_ID=$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT") || return 1
  if [ "${SIBLING_ROOT_ID##*:}" != 700 ]; then
    echo "sibling docker workspace is not mode 0700" >&2
    return 1
  fi
  suffix=${SIBLING_ROOT##*.}
  SIBLING_NAME="rd-smoke-sibling-$suffix"
  docker_out=$(docker run -d --name "$SIBLING_NAME" --network none \
    -v "$PWD:/work:ro" \
    -v "$SIBLING_ROOT:/sibling:rw" \
    -w /work "$IMG" \
    bash --noprofile --norc /work/scripts/smoke-server-stage.sh sibling-docker-server 2>&1)
  if [ "$?" -ne 0 ]; then
    printf '%s\n' "$docker_out" >&2
    cleanup_sibling_root || true
    return 1
  fi
  SIBLING_CID=$docker_out
  for ((i = 0; i < 400; i += 1)); do
    if [ -f "$SIBLING_ROOT/ready" ] && [ ! -L "$SIBLING_ROOT/ready" ] \
      && grep -Fxq ready "$SIBLING_ROOT/ready"; then
      ready_logs=$(docker logs "$SIBLING_CID" 2>&1) || return 1
      grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$ready_logs" || return 1
      grep -Eq '^SIBLING_CONTAINER_IDENTITY_READY pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+ generation=[0-9a-f-]{36}$' <<<"$ready_logs" || return 1
      host_guard_checkpoint
      return "$?"
    fi
    if ! sibling_container_running; then
      echo "sibling docker container exited before ready" >&2
      docker logs "$SIBLING_CID" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "sibling docker container did not become ready" >&2
  docker logs "$SIBLING_CID" >&2 || true
  return 1
}

stop_sibling_docker() {
  local cid logs wait_out wait_status
  [ -n "$SIBLING_CID" ] || return 0
  cid=$SIBLING_CID
  if ! sibling_container_running; then
    echo "sibling docker container exited before lifecycle completed" >&2
    docker logs "$cid" >&2 || true
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  if [ -z "$SIBLING_ROOT" ] || [ "$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT" 2>/dev/null || true)" != "$SIBLING_ROOT_ID" ]; then
    echo "sibling docker control workspace identity changed" >&2
    return 1
  fi
  printf 'stop\n' >"$SIBLING_ROOT/stop" || return 1
  wait_out=$(timeout --signal=TERM --kill-after=5s 30s docker wait "$cid" 2>&1)
  if [ "$?" -ne 0 ]; then
    printf '%s\n' "$wait_out" >&2
    docker logs "$cid" >&2 || true
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  wait_status=$(printf '%s\n' "$wait_out" | tail -n 1 | tr -d '\r')
  logs=$(docker logs "$cid" 2>&1) || {
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  printf '%s\n' "$logs"
  if [ "$wait_status" != 0 ]; then
    echo "sibling docker container exited $wait_status" >&2
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$logs" || {
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$logs" || {
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  grep -Eq '^SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ generation=[0-9a-f-]{36}$' <<<"$logs" || {
    docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  docker rm "$cid" >/dev/null || return 1
  SIBLING_CID=
  cleanup_sibling_root || return "$?"
  host_guard_checkpoint || return 1
  printf 'SIBLING_DOCKER_NONINTERFERENCE=pass cid=%s\n' "${cid:0:12}"
}

cleanup_smoke_host_guard() {
  local status=$? cleanup_status=0 path
  trap - EXIT HUP INT TERM
  if [ -n "$SIBLING_CID" ]; then
    stop_sibling_docker >/dev/null 2>&1 || cleanup_status=$?
  elif [ -n "$SIBLING_ROOT" ]; then
    cleanup_sibling_root || cleanup_status=$?
  fi
  if [ -n "$HOST_GUARD_PID" ]; then
    stop_host_guard || cleanup_status=$?
  fi
  if [ -n "$HOST_GUARD_ROOT" ]; then
    if [ "$(stat -c '%d:%i:%u:%g:%a' "$HOST_GUARD_ROOT" 2>/dev/null || true)" != "$HOST_GUARD_ROOT_ID" ]; then
      echo "smoke host guard: preserving changed private workspace" >&2
      cleanup_status=125
    else
      for path in baseline.json ready stop violation.json monitor.log sibling-docker.log; do
        [ ! -e "$HOST_GUARD_ROOT/$path" ] && [ ! -L "$HOST_GUARD_ROOT/$path" ] \
          || rm -- "$HOST_GUARD_ROOT/$path" || cleanup_status=125
      done
      rmdir -- "$HOST_GUARD_ROOT" || cleanup_status=125
    fi
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    status=125
  fi
  exit "$status"
}
trap cleanup_smoke_host_guard EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

rc=0
STAGE_STATUS=0
run_stage() {
  local output_name=$1 captured
  shift
  if ! host_guard_checkpoint; then
    STAGE_STATUS=1
    printf -v "$output_name" '%s' 'historical-selector monitor unavailable before stage'
    return 0
  fi
  if captured=$("$@" 2>&1); then
    STAGE_STATUS=0
  else
    STAGE_STATUS=$?
  fi
  if ! host_guard_checkpoint; then
    STAGE_STATUS=1
    captured="$captured
historical-selector monitor failed during stage"
  fi
  printf -v "$output_name" '%s' "$captured"
}

record_stage_status() {
  local label=$1
  if [ "$STAGE_STATUS" -ne 0 ]; then
    echo "  FAIL $label: isolated stage command exited $STAGE_STATUS"
    rc=1
  fi
}

"$HOST_GUARD" self-test
HOST_GUARD_ROOT=$(mktemp -d /tmp/rustdesk-smoke-host.XXXXXXXXXX)
HOST_GUARD_ROOT_ID=$(stat -c '%d:%i:%u:%g:%a' "$HOST_GUARD_ROOT")
[ "${HOST_GUARD_ROOT_ID##*:}" = 700 ] || { echo "smoke host guard workspace is not mode 0700" >&2; exit 1; }
"$HOST_GUARD" record "$HOST_GUARD_ROOT/baseline.json"
"$HOST_GUARD" monitor "$HOST_GUARD_ROOT/baseline.json" "$HOST_GUARD_ROOT/ready" \
  "$HOST_GUARD_ROOT/stop" "$HOST_GUARD_ROOT/violation.json" >"$HOST_GUARD_ROOT/monitor.log" 2>&1 &
HOST_GUARD_PID=$!
HOST_GUARD_START=$(bash scripts/smoke-ready.sh --identity "$HOST_GUARD_PID")
"$HOST_GUARD" wait-ready "$HOST_GUARD_PID" "$HOST_GUARD_START" "$HOST_GUARD_ROOT/ready"

echo "== (0a) prove the bounded process/socket/IPC readiness checker =="
run_stage ready_out "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-ready.sh --self-test
printf '%s\n' "$ready_out"
record_stage_status smoke-readiness-self-test
[ "$STAGE_STATUS" -eq 0 ] || exit 1

echo "== (0) build the server binary + the test seeder + the CPace probe client (R-B4 build smoke) =="
run_stage build_out "${BUILD_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh build
printf '%s\n' "$build_out"
record_stage_status R-B4-build
[ "$STAGE_STATUS" -eq 0 ] || exit 1

echo "== (0c) Linux manual supervisor lifecycle: exact hostile-record rejection, cross-container identity, pre-pidfd fallback, stop/crash recovery, privilege drop, and portable noninterference (R-S11c-27f/R-S11c-27g/R-S11c-27h/R-S11c-27i/R-S11c-27j/R-S11c-27k/R-S11c-27n) =="
lifecycle_out=
sibling_out=
sibling_out_file=$HOST_GUARD_ROOT/sibling-docker.log
lifecycle_stage_status=1
sibling_stage_status=1
if start_sibling_docker; then
  run_stage lifecycle_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh service-lifecycle-manual
  lifecycle_stage_status=$STAGE_STATUS
  if stop_sibling_docker >"$sibling_out_file" 2>&1; then
    sibling_stage_status=0
  else
    sibling_stage_status=$?
  fi
  sibling_out=$(cat "$sibling_out_file")
else
  lifecycle_out='sibling Docker server failed to start'
  stop_sibling_docker >/dev/null 2>&1 || true
  cleanup_sibling_root >/dev/null 2>&1 || true
fi
printf '%s\n' "$lifecycle_out"
printf '%s\n' "$sibling_out"
STAGE_STATUS=$lifecycle_stage_status
record_stage_status R-S11c-27f
record_stage_status R-S11c-27g
record_stage_status R-S11c-27h
record_stage_status R-S11c-27i
record_stage_status R-S11c-27k
grep -q '^SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata,reused-start,executable,uid,generation,portable-role$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27i: actual --service did not preserve every hostile or ambiguous child record while signaling nothing"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_GRACEFUL=pass generation=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: actual --service SIGTERM did not gracefully reap its exact child"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_RESTART=pass generation=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: fresh manual supervisor generation was not observed"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_FORCED=pass elapsed_ms=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: stopped child did not take the bounded TERM-to-KILL/reap path"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_CRASH_RESTART=pass prior_generation=[0-9a-f-]{36} recovered_generation=[0-9a-f-]{36} child_exit_ms=[0-9]+$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27g: actual supervisor crash did not stop its exact child and recover to a fresh generation"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_PRE_PIDFD_RECOVERY=pass prior_generation=[0-9a-f-]{36} recovered_generation=[0-9a-f-]{36}$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27k: forced pre-pidfd recovery did not terminate the exact prior child and recover to a fresh generation"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_PRIVILEGE_DROP=pass uid=4001 gid=4001 groups=4001,4101 generation=[0-9a-f-]{36}$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27h: actual active-seat child did not complete the exact non-root descriptor-exec path"; rc=1; }
grep -q '^PORTABLE_NONINTERFERENCE=pass uid=4000$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f/R-S11c-27g/R-S11c-27h/R-S11c-27i: unrelated non-root portable server did not survive every service transition"; rc=1; }
if [ "$lifecycle_stage_status" -eq 0 ] && [ "$sibling_stage_status" -eq 0 ] \
  && grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  && grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  && grep -Eq '^SIBLING_DOCKER_NONINTERFERENCE=pass cid=[0-9a-f]{12}$' <<<"$sibling_out"; then
  STAGE_STATUS=0
else
  STAGE_STATUS=1
fi
record_stage_status R-S11c-27j
grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: sibling Docker server did not publish an exact ready identity before lifecycle authority ran"; rc=1; }
grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: unrelated sibling Docker server did not survive the service lifecycle stage"; rc=1; }
grep -Eq '^SIBLING_DOCKER_NONINTERFERENCE=pass cid=[0-9a-f]{12}$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: sibling Docker container was not drained as an unrelated survivor after lifecycle completion"; rc=1; }

main_container_identity=$(grep -E '^SERVICE_LIFECYCLE_CONTAINER_IDENTITY=pass path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+$' <<<"$lifecycle_out" || true)
sibling_container_identity=$(grep -E '^SIBLING_CONTAINER_IDENTITY_READY pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+ generation=[0-9a-f-]{36}$' <<<"$sibling_out" || true)
sibling_container_survived=$(grep -E '^SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ generation=[0-9a-f-]{36}$' <<<"$sibling_out" || true)
container_identity_parse_ok=1
if [[ "$main_container_identity" =~ exe=([0-9]+:[0-9]+)[[:space:]]source=([0-9]+:[0-9]+)[[:space:]]sha256=([0-9a-f]{64})[[:space:]]mnt=([0-9]+)[[:space:]]pidns=([0-9]+)$ ]]; then
  main_executable=${BASH_REMATCH[1]}
  main_source=${BASH_REMATCH[2]}
  main_sha256=${BASH_REMATCH[3]}
  main_mount_namespace=${BASH_REMATCH[4]}
  main_pid_namespace=${BASH_REMATCH[5]}
else
  container_identity_parse_ok=0
fi
if [[ "$sibling_container_identity" =~ exe=([0-9]+:[0-9]+)[[:space:]]source=([0-9]+:[0-9]+)[[:space:]]sha256=([0-9a-f]{64})[[:space:]]mnt=([0-9]+)[[:space:]]pidns=([0-9]+)[[:space:]]generation=([0-9a-f-]{36})$ ]]; then
  sibling_executable=${BASH_REMATCH[1]}
  sibling_source=${BASH_REMATCH[2]}
  sibling_sha256=${BASH_REMATCH[3]}
  sibling_mount_namespace=${BASH_REMATCH[4]}
  sibling_pid_namespace=${BASH_REMATCH[5]}
  sibling_generation=${BASH_REMATCH[6]}
else
  container_identity_parse_ok=0
fi
if [ "$container_identity_parse_ok" -eq 1 ]; then
  if [ "$main_source" = "$sibling_source" ] \
    && [ "$main_sha256" = "$sibling_sha256" ] \
    && [ "$main_executable" != "$main_source" ] \
    && [ "$sibling_executable" != "$sibling_source" ] \
    && [ "$main_executable" != "$sibling_executable" ] \
    && [ "$main_mount_namespace" != "$sibling_mount_namespace" ] \
    && [ "$main_pid_namespace" != "$sibling_pid_namespace" ] \
    && [[ "$sibling_container_survived" == *" exe=$sibling_executable generation=$sibling_generation" ]]; then
    STAGE_STATUS=0
  else
    STAGE_STATUS=1
  fi
else
  STAGE_STATUS=1
fi
record_stage_status R-S11c-27n
if [ "$STAGE_STATUS" -eq 0 ]; then
  printf 'CROSS_CONTAINER_EXECUTABLE_IDENTITY=pass path=/usr/bin/rustdesk main=%s sibling=%s source=%s mnt=%s/%s pidns=%s/%s\n' \
    "$main_executable" "$sibling_executable" "$main_source" \
    "$main_mount_namespace" "$sibling_mount_namespace" "$main_pid_namespace" "$sibling_pid_namespace"
else
  echo "  FAIL R-S11c-27n: identical installed path/bytes/role did not remain bound to distinct executable and PID/mount namespace identities"
  rc=1
fi

echo "== (0d) Linux service-child recovery rejects actual forced numeric PID reuse (R-S11c-27o) =="
run_stage pid_reuse_out "${PID_REUSE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh service-pid-reuse
printf '%s\n' "$pid_reuse_out"
record_stage_status R-S11c-27o
pid_reuse_line=$(grep -E '^SERVICE_LIFECYCLE_PID_REUSE=pass old_pid=[0-9]+ reused_pid=[0-9]+ old_start=[0-9]+ reused_start=[0-9]+ old_generation=[0-9a-f-]{36} reused_generation=[0-9a-f-]{36} record_sha256=[0-9a-f]{64}$' <<<"$pid_reuse_out" || true)
if [[ "$pid_reuse_line" =~ old_pid=([0-9]+)[[:space:]]reused_pid=([0-9]+)[[:space:]]old_start=([0-9]+)[[:space:]]reused_start=([0-9]+) ]] \
  && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
  && [ "${BASH_REMATCH[3]}" != "${BASH_REMATCH[4]}" ]; then
  echo "  ok  R-S11c-27o actual kernel PID reuse kept numeric PID constant while start-time identity changed and recovery failed closed"
else
  echo "  FAIL R-S11c-27o: actual kernel PID reuse was not proven with same numeric PID, changed start time, preserved record, and live recycled child"
  rc=1
fi

echo "== (0e) Debian bookworm without systemd: installed SysV package start/restart/upgrade/remove and portable noninterference (R-S11c-27l) =="
run_stage sysv_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh debian-sysv-installed-lifecycle
printf '%s\n' "$sysv_out"
record_stage_status R-S11c-27l
grep -Eq '^DEBIAN_SYSV_INSTALLED_LIFECYCLE=pass os=debian-12 portable_uid=4000 stale_wrong_exec=survived$' <<<"$sysv_out" \
  || { echo "  FAIL R-S11c-27l: installed Debian SysV lifecycle or unrelated portable survival was not proven"; rc=1; }

echo "== (0b) R-D3a MemoryDenyWriteExecute (W^X) validation: the deployed software VP9 encoder runs clean under the EXACT PR_SET_MDWE primitive systemd applies (so MemoryDenyWriteExecute=yes in the unit is safe) =="
# The controlled --server only ENCODES (§13/Appendix C #2b); the probe sets PR_SET_MDWE|REFUSE_EXEC_GAIN
# BEFORE vpx_codec_enc_init then drives 5 encodes. A runtime W+X mmap/mprotect (a JIT) would SIGSEGV
# under MDWE; libvpx does function-pointer SIMD dispatch, never JIT, so it completes clean (exit 0).
run_stage mdwe_out "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh mdwe
record_stage_status R-D3a
grep -qE 'MDWE_CODEC_OK' <<<"$mdwe_out" && grep -q 'EXIT=0' <<<"$mdwe_out" \
  && echo "  ok  R-D3a: VP9 encoder W^X-clean under MemoryDenyWriteExecute (init + 5/5 encodes, no W+X mapping)" \
  || { echo "  FAIL R-D3a: the codec path is NOT W^X-safe under MDWE — do NOT ship MemoryDenyWriteExecute=yes:"; tail -3 <<<"$mdwe_out"; rc=1; }

echo "== (1) fail-closed startup: --server with NO password MUST PARK — stay alive but bind NOTHING (R-A4/R-S9, finding D) =="
# Finding D: the empty-permanent-password startup process::exit was removed (on Android it crashed
# the shared-process app). An empty password now fails closed by PARKING — direct_server binds NO
# listener and every connection is refused per-connection (server.rs, R-S9). Prove the box stays
# ALIVE (does not exit/crash) yet binds NOTHING on the pinned port. Background it (it no longer
# exits) and probe /proc, mirroring stage (2)'s pattern.
run_stage out1 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh parked
echo "$out1"
record_stage_status R-A4/R-S9
grep -q 'ALIVE=yes' <<<"$out1" \
  || { echo "  FAIL R-A4/R-S9: --server exited on an empty permanent password (finding D: it MUST park, not exit/crash)"; rc=1; }
grep -q 'TCP_LISTEN=\[\]' <<<"$out1" \
  || { echo "  FAIL R-S9: a listener is bound with NO permanent password (must bind NOTHING while parked)"; rc=1; }
grep -q 'the direct listener is PARKED' <<<"$out1" \
  || { echo "  FAIL R-S9: missing the fail-closed park diagnostic on the empty-password path"; rc=1; }
grep -q 'Direct server listening' <<<"$out1" \
  && { echo "  FAIL R-S9: the server bound a listener with no permanent password"; rc=1; }
[ "$rc" = 0 ] && echo "  ok  R-A4/R-S9 fail-closed startup (no password -> PARK: alive, nothing bound, runtime)"

echo "== (2) seed a password, LISTEN on 127.0.0.1, assert the socket surface (R-B4) + R-T9 drain =="
run_stage out2 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh listen
echo "$out2"
record_stage_status R-B4/R-T9
grep -q "TCP_LISTEN=\[$LOOPBACK_LISTEN \]" <<<"$out2" \
  || { echo "  FAIL R-B4: not EXACTLY one v4 TCP listener on 127.0.0.1:21118 (got the TCP_LISTEN line above)"; rc=1; }
grep -q 'UDP_COUNT=0' <<<"$out2" \
  || { echo "  FAIL R-B4: a UDP socket exists — must be ZERO"; rc=1; }
grep -q 'socket surface verified — exactly one TCP v4:21118, zero UDP' <<<"$out2" \
  || { echo "  FAIL R-A4: the runtime socket-surface self-check did not pass"; rc=1; }
grep -q 'R-T9: graceful shutdown complete — exiting 0' <<<"$out2" \
  || { echo "  FAIL R-T9: no graceful SIGTERM shutdown"; rc=1; }

echo "== (2b) R-D8/R-D2: the REAL portable 'rustdesk --password-stdin' CLI provisions over user-owned uid-scoped IPC and cleanly set-and-exits =="
# The other stages seed via the test-only examples/seed_password (a direct Config write) for speed,
# which bypasses the production path. This stage runs the real noninteractive `--password-stdin` CLI
# as root against a root-owned non-installed --server (the non-root same-uid path is stage 2c), so it
# exercises the typed user-owned password IPC end-to-end:
# the value-bound BeginUserOwnedPermanentPassword/status transaction, typed terminal result, storage sync, and the
# current-thread-runtime CLEAN TEARDOWN — the "set-and-exit" stock RustDesk lacked.
# We provision by CHANGING an initial seeded password (--server refuses to listen with none, R-A4) —
# the identical user-owned IPC path; service-launched servers are marked separately and reject this path.
run_stage out2b "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-root
echo "$out2b"
record_stage_status R-D8/R-D2
grep -q 'PW_EXIT=0' <<<"$out2b" \
  || { echo "  FAIL R-D2: the real --password-stdin CLI did not cleanly exit 0 within the timeout (hang/error — the stock never-returns regression)"; rc=1; }
grep -q 'Done!' <<<"$out2b" \
  || { echo "  FAIL R-D2: --password-stdin did not confirm success (no 'Done!') — the daemon did not ACK the IPC set"; rc=1; }
grep -q 'KEYED_NEW: keying ok=true' <<<"$out2b" \
  || { echo "  FAIL R-D8: the IPC-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
grep -q 'KEYED_OLD: keying ok=false' <<<"$out2b" \
  || { echo "  FAIL R-D8: the old password still keys — the --password-stdin change did not take effect over the daemon IPC"; rc=1; }

echo "== (2c) R-D8: portable 'rustdesk --password-stdin' provisions over SAME-UID user-owned IPC as a NON-ROOT owner =="
# An unprivileged owner (uid 4000) runs both non-installed --server and --password-stdin as itself.
# The request reaches its own per-uid raw IPC directly; the endpoint's per-uid mode and SO_PEERCRED
# identity are the authorization. This also exercises RLIMIT_NOFILE enforcement under non-root.
run_stage out2c "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-nonroot
echo "$out2c"
record_stage_status R-D8-nonroot
grep -q 'UID=4000' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) did not run as the intended non-root uid (4000)"; rc=1; }
grep -q 'SERVER_UID=4000' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) server was not owned by the intended non-root uid (4000)"; rc=1; }
grep -q 'PORTABLE_EXE=/tmp/rd-smoke-nonroot/bin/rustdesk' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) did not execute the isolated portable fixture image"; rc=1; }
grep -q 'SERVICE_ROLE_MARKER=absent' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) entered or could not disprove the service-owned role"; rc=1; }
grep -q 'PW_EXIT=0' <<<"$out2c" \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not cleanly exit 0"; rc=1; }
grep -q 'Done!' <<<"$out2c" \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not confirm 'Done!' — the daemon did not ACK the non-root IPC set"; rc=1; }
grep -q 'KEYED_NEW: keying ok=true' <<<"$out2c" \
  || { echo "  FAIL R-D8: the same-uid-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
grep -q 'KEYED_OLD: keying ok=false' <<<"$out2c" \
  || { echo "  FAIL R-D8: the old password still keys after the same-uid change"; rc=1; }
grep -q 'SERVER_EXIT=0' <<<"$out2c" \
  || { echo "  FAIL R-D8: the non-root server did not terminate and reap cleanly"; rc=1; }
grep -q 'SOURCE_BIND_UNCHANGED=yes' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) changed or could not re-prove the source bind"; rc=1; }

echo "== (2d) R-S11b: installed layout selects service ownership and never falls back to user-owned password storage =="
run_stage out2d "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-installed
echo "$out2d"
record_stage_status R-S11b
grep -q 'PW_EXIT=1' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout password request did not fail without the privileged service endpoint"; rc=1; }
grep -q 'KEYED_NEW: keying ok=false' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout request fell back to user-owned password mutation"; rc=1; }
grep -q 'KEYED_OLD: keying ok=true' <<<"$out2d" \
  || { echo "  FAIL R-S11b: failed installed-layout request changed or disabled the existing credential"; rc=1; }

echo "== (3) two-process: a CPace probe client keys the REAL server (R-A1/R-S1) + a wrong password is refused (R-P3/R-P14c) + the R-T12 observability fires =="
run_stage out3 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh keying
echo "$out3"
record_stage_status R-A1/R-S1
grep -q 'keying ok=true (expected=ok)' <<<"$out3" \
  || { echo "  FAIL R-A1/R-S1: the real server did not key a CORRECT-password client"; rc=1; }
grep -q 'keying ok=false (expected=fail)' <<<"$out3" \
  || { echo "  FAIL R-P3/R-P14c: a WRONG-password client was not refused at key-confirmation"; rc=1; }
[ "$(grep -c 'probe_client: PASS' <<<"$out3")" -ge 2 ] \
  || { echo "  FAIL: a probe did not match its expected keying outcome"; rc=1; }
grep -qE 'security summary .* key_confirmation_failures=[1-9]' <<<"$out3" \
  || { echo "  FAIL R-T12/R-P14c: the key-confirmation-failure was not counted in the flood-safe summary"; rc=1; }

echo "== (4) R-T1: a connection flood past the 256-permit budget MUST be capacity-shed =="
run_stage out4 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh flood
echo "$out4"
record_stage_status R-T1
grep -qE 'security summary .* shed=[1-9]' <<<"$out4" \
  || { echo "  FAIL R-T1: the connection-flood capacity shed did not fire (budget 256; flooded 300)"; rc=1; }

echo "== (6) FULL SESSION (R-S6/R-S2/R-S18 + R-D8/R-X8): a keyed credential-free LoginRequest is ADMITTED and the FULL-ACCESS policy denies NOTHING =="
run_stage out6 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh full-session
echo "$out6"
record_stage_status R-S6/R-S18
# R-S6/R-S18: the keyed edge IS the authorization — the credential-free LoginRequest (no second
# credential; the password proof is collapsed into the PAKE) is ADMITTED because CPace already
# authenticated (there is no source-IP ACL). Proven POSITIVELY under the full-access policy: RustDesk
# NOTIFIES the viewer only of DENIED permissions, so an authorized FULL-ACCESS session emits ZERO
# `enabled: false` PermissionInfo. The pinned headless image has no display server: after authorization
# it returns the display backend's exact `connection refused` error instead of PeerInfo.
s6_ok=1
if grep -qE 'blocked by the peer|Some\(Error\("Offline"|Some\(Error\("Wrong Password' <<<"$out6"; then
  echo "  FAIL R-S6/R-S18: the keyed credential-free LoginRequest was REJECTED (must be ADMITTED — CPace authenticated it)"; rc=1; s6_ok=0
fi
if grep -q 'enabled: false' <<<"$out6"; then
  echo "  FAIL R-D8/R-X8: a capability was DENIED (PermissionInfo enabled:false) — the full-access policy must deny nothing"; rc=1; s6_ok=0
fi
if ! grep -qE 'Some\(PeerInfo|Some\(Error\("connection refused"' <<<"$out6"; then
  echo "  FAIL R-S6/R-S18: no authorized remote-session outcome was observed"; rc=1; s6_ok=0
fi
[ "$s6_ok" = 1 ] && echo "  ok  R-S6/R-S18 credential-free LoginRequest reached the authorized remote session + R-D8/R-X8 full access denied no capability"

echo "== (6b) PORT-FORWARD/RDP TUNNEL (R-F1/R-D6/R-S5/R-A9): a real tunnel RELAYS bytes END-TO-END inside the sealed session =="
# R-F1 makes port-forward (incl. RDP) a MUST; R-D6 pins enable-tunnel ON and requires the forward to
# ride the sealed encrypted channel; R-A9 requires the bytes indistinguishable from random. The
# cpace_it wire-ciphertext test + stage (9) prove the SEAL (the wire bytes are ciphertext); this stage
# proves the RELAY is FUNCTIONAL end-to-end — a seal-only test cannot. A port-forward viewer keys,
# sends a PortForward login naming a LOCAL target, and sends a canary THROUGH the tunnel; the box dials
# the target, switches to try_port_forward_loop (the sealed relay), and shuttles the canary both ways.
run_stage out6b "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh port-forward
echo "$out6b"
record_stage_status R-F1/R-D6
# R-F1/R-D6/R-S5/R-A9: the canary made a full round trip THROUGH the box (viewer -> sealed -> box ->
# local target -> echo -> box -> sealed -> viewer), proving the relay is restored AND functional AND
# inside the secretbox (the box never set_raw'd — tcp.rs R-A3 would have panicked otherwise).
if grep -q 'PF-RELAY-ECHO-OK' <<<"$out6b"; then
  echo "  ok  R-F1/R-D6/R-S5/R-A9 port-forward/RDP tunnel RELAYS end-to-end inside the sealed session (canary round-tripped through the box's dial + sealed relay)"
else
  echo "  FAIL R-F1/R-D6/R-S5: the port-forward tunnel did NOT relay the canary end-to-end (the sealed relay is broken)"; rc=1
fi

echo "== (6c) FILE TRANSFER on a headless unix --server (R-F1/R-F2): a keyed FileTransfer login yields a NON-EMPTY PeerInfo.username (the --server process owner) and is NEVER refused with 'No active console user' =="
# The harness runs --server as a NON-login user in a container with NO logind/console session — the
# EXACT repro: get_active_username() resolves empty AND is_prelogin() is true (empty seat0 ->
# `getent passwd ` lists every user, so a nologin shell always matches). Before the fix the server
# reported an EMPTY PeerInfo.username (get_active_username() empty, and the is_prelogin re-clear also
# blanked any fallback) and the viewer refused file transfer with "No active console user logged on".
# The server now (i) falls back to the --server process owner when get_active_username() is empty and
# (ii) confines the prelogin re-clear to Windows, so a keyed FileTransfer login MUST return a PeerInfo
# whose username is NON-EMPTY. (The ReadDir listing is served by the CM process, which needs a display
# this container lacks, so its dir FileResponse is a best-effort observation — the load-bearing
# regression signal is the non-empty PeerInfo.username + the absence of the console-user refusal.)
run_stage out6c "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh file-transfer
echo "$out6c"
record_stage_status R-F1/R-F2
if grep -q 'No active console user' <<<"$out6c"; then
  echo "  FAIL R-F1/R-F2: file transfer was refused with 'No active console user' on a headless unix --server"; rc=1
fi
if grep -q 'FT-PEERINFO username_nonempty=true' <<<"$out6c"; then
  if grep -q 'FT-DIR-RESPONSE' <<<"$out6c"; then
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username + directory FileResponse returned (CM round-trip live)"
  else
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username, not refused (dir FileResponse needs the CM's display, absent in this container — PeerInfo is the load-bearing signal)"
  fi
else
  echo "  FAIL R-F1/R-F2: the FileTransfer login did not return a PeerInfo with a NON-EMPTY username (the headless process-owner fallback regressed, the prelogin re-clear re-broadened to unix, or the login was refused)"; rc=1
fi

echo "== (7) R-A8 / R-T7: an INJECTED (forged) frame on the keyed stream is rejected by the AEAD =="
run_stage out7 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh inject
echo "$out7"
record_stage_status R-A8/R-T7
# The server tears the connection down with "decryption error" — secretbox::open fails the Poly1305
# tag (R-T7: every keyed frame authenticated), so the forged frame NEVER reaches the parser (R-A8).
grep -q 'Connection closed: decryption error' <<<"$out7" \
  || { echo "  FAIL R-A8/R-T7: an injected forged frame was NOT rejected by the AEAD"; rc=1; }

echo "== (8) R-A8.2 / R-S10: the per-source online-guess limiter is OWNER-SAFE (flood one source; a DIFFERENT source still keys) =="
run_stage out8 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh limiter
echo "$out8"
record_stage_status R-A8.2/R-S10
# The CARDINAL R-S10 rule: a limiter must NEVER lock the owner out of their own machine. The per-IP
# online-guess limiter (guess_limiter_allows, MAX 10/60s) blocks the FLOODING source but not a
# different one — so a connection-flood / guess-flood from an attacker cannot deny the owner.
grep -q 'OWNER_DIFF_SRC: keying ok=true' <<<"$out8" \
  || { echo "  FAIL R-A8.2: a DIFFERENT source was blocked by the limiter — owner lock-out, the CARDINAL violation"; rc=1; }
grep -q 'FLOODER_SAME_SRC: keying ok=false' <<<"$out8" \
  || { echo "  FAIL R-A8.2: the flooding source was NOT rate-limited (the per-source guess limiter is not working)"; rc=1; }

echo "== (9) R-A9: wire-capture — a post-key LoginRequest canary is ENCRYPTED (never plaintext on the wire) =="
run_stage out9 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh capture
echo "$out9"
record_stage_status R-A9
# R-A9: the session bytes are indistinguishable from random — a known plaintext canary sent on the
# KEYED stream NEVER appears on the captured wire (AEAD-sealed). The non-empty pcap + the in-binary
# sanity rule out a false pass (we captured real traffic, and the search pattern really matches).
grep -q 'CANARY_IN_BINARY: 1' <<<"$out9" \
  || { echo "  FAIL R-A9: the canary sanity check failed (the grep pattern does not match the probe binary)"; rc=1; }
grep -qE 'PCAP_SIZE: [0-9]{3,}' <<<"$out9" \
  || { echo "  FAIL R-A9: the wire capture was empty/trivial — no real traffic was captured"; rc=1; }
grep -q 'CANARY_ON_WIRE: NO' <<<"$out9" \
  || { echo "  FAIL R-A9: the LoginRequest canary appeared as PLAINTEXT on the wire — the session is NOT encrypted"; rc=1; }

# Opt-in (SMOKE_DECAY=1): the R-A8 limiter-DECAY proof waits out the real 60s GUESS_WINDOW, so it is
# kept off the default fast path. It adds ~75 s but exercises the genuine production window (no
# test-only time-injection into the security-critical limiter).
DECAY_NOTE=""
if [ "${SMOKE_DECAY:-0}" = 1 ]; then
echo "== (10) R-A8 DECAY: a tripped per-source block DECAYS after the window (no PERMANENT lockout) =="
run_stage out10 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh decay
echo "$out10"
record_stage_status R-A8-decay
# The block must be live first (precondition), then self-heal once the window lapses. A limiter that
# never decays is a PERMANENT lockout — the cardinal "never lock the owner out" violation (R-S10).
grep -q 'BLOCKED_NOW: keying ok=false' <<<"$out10" \
  || { echo "  FAIL R-A8: the source was not blocked after the flood (decay-test precondition)"; rc=1; }
grep -q 'DECAYED_AFTER_WINDOW: keying ok=true' <<<"$out10" \
  || { echo "  FAIL R-A8: the block did NOT decay after the 60s window — a PERMANENT lockout (cardinal owner-safety violation)"; rc=1; }
DECAY_NOTE=" + R-A8 limiter-decay (tripped block self-heals after the 60s window)"
fi

if ! stop_host_guard; then
  echo "  FAIL smoke host coexistence: historical-selector monitor did not complete cleanly"
  rc=1
fi

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: host historical-selector baseline preserved with zero new matches + exact RustDesk executable under neutral smoke argv + mounted container stages + R-S11c-27o actual PID reuse recovery + R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-D8/R-D2 non-installed user-owned --password-stdin IPC provisioning (clean set-and-exit; root-owned + non-root same-uid) + R-S11b installed-layout service ownership with no user-storage fallback + R-A1/R-S1 keying (two-process) + R-P3/R-P14c wrong-password refusal + R-T12 observability + R-T1 connection-flood capacity-shed + R-S6 keyed-edge authorization (full session) + R-F1/R-D6/R-S5 port-forward/RDP tunnel relays end-to-end inside the seal + R-F1/R-F2 file transfer (keyed FileTransfer login -> non-empty process-owner PeerInfo.username on a headless unix box, never the 'No active console user' refusal) + R-A8/R-T7 forged-frame rejection + R-A8.2/R-S10 owner-safe limiter + R-A9 wire-capture (no plaintext on the wire)${DECAY_NOTE} — ALL validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

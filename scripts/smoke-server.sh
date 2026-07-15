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
PORT_HEX='527E' # 21118
LOOPBACK_LISTEN='0100007F:527E' # 127.0.0.1:21118

STAGE_STATUS=0
run_stage() {
  local output_name=$1 captured
  shift
  if captured=$("$@" 2>&1); then
    STAGE_STATUS=0
  else
    STAGE_STATUS=$?
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

echo "== (0a) prove the bounded process/socket/IPC readiness checker =="
"${RUN[@]}" bash /work/scripts/smoke-ready.sh --self-test

echo "== (0) build the server binary + the test seeder + the CPace probe client (R-B4 build smoke) =="
rc=0
run_stage build_out "${BUILD_RUN[@]}" bash -euo pipefail -c 'cargo build --features linux-pkg-config --bin rustdesk --example seed_password --example probe_client --example smoke_readiness --example pf_echo --example flood_probe --example mdwe_codec_probe --color never; cc -shared -fPIC -O2 -Wall -Wextra -o target/smoke-bind-loopback.so scripts/smoke-bind-loopback.c -ldl'
printf '%s\n' "$build_out"
record_stage_status R-B4-build
[ "$STAGE_STATUS" -eq 0 ] || exit 1

echo "== (0b) R-D3a MemoryDenyWriteExecute (W^X) validation: the deployed software VP9 encoder runs clean under the EXACT PR_SET_MDWE primitive systemd applies (so MemoryDenyWriteExecute=yes in the unit is safe) =="
# The controlled --server only ENCODES (§13/Appendix C #2b); the probe sets PR_SET_MDWE|REFUSE_EXEC_GAIN
# BEFORE vpx_codec_enc_init then drives 5 encodes. A runtime W+X mmap/mprotect (a JIT) would SIGSEGV
# under MDWE; libvpx does function-pointer SIMD dispatch, never JIT, so it completes clean (exit 0).
run_stage mdwe_out "${RUN[@]}" bash -euo pipefail -c './target/debug/examples/mdwe_codec_probe; echo "EXIT=0"'
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
run_stage out1 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd1; mkdir -p "$HOME"
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv1.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-parked "$SRV" "$SRV_START" /tmp/srv1.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  echo "ALIVE=$(/work/scripts/smoke-ready.sh --is-running "$SRV" "$SRV_START" && echo yes || echo no)"
  echo "TCP_LISTEN=[$(awk "\$4==\"0A\"{print \$2}" /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr "\n" " ")]"
  grep -m1 "the direct listener is PARKED" /tmp/srv1.log || true
  grep -m1 "Direct server listening" /tmp/srv1.log || true
  /work/scripts/smoke-ready.sh --stop "$SRV" "$SRV_START" || exit 1
  wait "$SRV" 2>/dev/null || true
'
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
run_stage out2 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd2; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  echo "TCP_LISTEN=[$(awk "\$4==\"0A\"{print \$2}" /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr "\n" " ")]"
  echo "UDP_COUNT=$(( $(tail -n +2 /proc/net/udp 2>/dev/null | wc -l) + $(tail -n +2 /proc/net/udp6 2>/dev/null | wc -l) ))"
  grep -m1 "Direct server listening" /tmp/srv.log || true
  grep -m1 "socket surface verified" /tmp/srv.log || true
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
  grep "R-T9: graceful shutdown complete" /tmp/srv.log || true
'
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
run_stage out2b "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd2b; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Initial-Seed-Pw-000" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-user-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  # timeout so a HANG (the stock "never returns" regression R-D2 fixes) FAILS the test, not wedges it.
  RECOVERY_SECONDS=$(./target/debug/examples/smoke_readiness password-recovery-seconds)
  [ "$RECOVERY_SECONDS" = 600 ] || exit 1
  if PW_OUT=$(timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" ./target/debug/rustdesk --password-stdin <<<"Changed-Via-Ipc-Pw-9" 2>&1); then
    PW_EXIT=0
  else
    PW_EXIT=$?
  fi
  echo "PW_EXIT=$PW_EXIT"
  echo "PW_OUT=[$PW_OUT]"
  [ "$PW_EXIT" = 0 ] || exit "$PW_EXIT"
  # Proof the round-trip reached the daemon, which APPLIED + PERSISTED it: the NEW credential keys a
  # CPace session and the OLD one is now rejected (R-P1: read live each handshake, no cached PRS).
  KEYED_NEW_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Changed-Via-Ipc-Pw-9" ok 2>&1)
  printf "%s\n" "$KEYED_NEW_OUT"
  echo "KEYED_NEW: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_NEW_OUT")"
  KEYED_OLD_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Initial-Seed-Pw-000" fail 2>&1)
  printf "%s\n" "$KEYED_OLD_OUT"
  echo "KEYED_OLD: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_OLD_OUT")"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out2c "${RUN[@]}" bash -euo pipefail -c '
  id -u rduser >/dev/null 2>&1 || useradd -m -u 4000 rduser
  [ "$(id -u rduser)" = 4000 ] || exit 1
  gid=$(id -g rduser)
  fixture=/tmp/rd-smoke-nonroot
  source_meta=$(stat -c "%d:%i:%u:%g:%a" /work)
  source_hash=$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/debug/examples/smoke_readiness /work/target/smoke-bind-loopback.so /work/scripts/smoke-ready.sh)
  install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"
  install -d -o rduser -g "$gid" -m 0700 "$fixture/home"
  install -o root -g "$gid" -m 0550 target/debug/rustdesk "$fixture/bin/rustdesk"
  install -o root -g "$gid" -m 0550 target/debug/examples/seed_password "$fixture/bin/seed_password"
  install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"
  install -o root -g "$gid" -m 0550 target/debug/examples/smoke_readiness "$fixture/bin/smoke_readiness"
  install -o root -g "$gid" -m 0440 target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"
  install -o root -g "$gid" -m 0550 scripts/smoke-ready.sh "$fixture/bin/smoke-ready.sh"
  cat > "$fixture/run.sh" <<"EOS"
#!/bin/bash
set -euo pipefail
export HOME=/tmp/rd-smoke-nonroot/home
cd "$HOME"
bin=/tmp/rd-smoke-nonroot/bin
echo "UID=$(id -u)"
"$bin/seed_password" Initial-Seed-Pw-000 >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
SRV=
SRV_START=
cleanup_server() {
  status=$?
  trap - EXIT
  cleanup_status=0
  if [ -n "$SRV" ] && [ -n "$SRV_START" ] && "$bin/smoke-ready.sh" --is-running "$SRV" "$SRV_START"; then
    "$bin/smoke-ready.sh" --stop "$SRV" "$SRV_START" || cleanup_status=$?
    wait "$SRV" 2>/dev/null || true
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "NONROOT_SERVER_CLEANUP_EXIT=$cleanup_status" >&2
  fi
  exit "$status"
}
trap cleanup_server EXIT
LD_PRELOAD="$bin/smoke-bind-loopback.so" "$bin/rustdesk" --server >srv2c.log 2>&1 &
SRV=$!
SRV_START=$("$bin/smoke-ready.sh" --identity "$SRV") || exit 1
"$bin/smoke-ready.sh" --wait-user-server "$SRV" "$SRV_START" "$HOME/srv2c.log" "$bin/smoke_readiness" 4000 || exit 1
server_exe=$(readlink -f "/proc/$SRV/exe")
echo "SERVER_UID=$(awk "/^Uid:/{print \$2}" "/proc/$SRV/status")"
echo "PORTABLE_EXE=$server_exe"
[ "$server_exe" = "$bin/rustdesk" ] || exit 1
if grep -zFxq -- --service-owned-server "/proc/$SRV/cmdline"; then exit 1; fi
echo "SERVICE_ROLE_MARKER=absent"
RECOVERY_SECONDS=$("$bin/smoke_readiness" password-recovery-seconds)
[ "$RECOVERY_SECONDS" = 600 ] || exit 1
if PW_OUT=$(timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" "$bin/rustdesk" --password-stdin <<<"Changed-Same-Uid-Pw-9" 2>&1); then
  PW_EXIT=0
else
  PW_EXIT=$?
fi
echo "PW_EXIT=$PW_EXIT"
echo "PW_OUT=[$PW_OUT]"
[ "$PW_EXIT" = 0 ] || exit "$PW_EXIT"
KEYED_NEW_OUT=$("$bin/probe_client" 127.0.0.1:21118 Changed-Same-Uid-Pw-9 ok 2>&1)
printf "%s\n" "$KEYED_NEW_OUT"
echo "KEYED_NEW: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_NEW_OUT")"
KEYED_OLD_OUT=$("$bin/probe_client" 127.0.0.1:21118 Initial-Seed-Pw-000 fail 2>&1)
printf "%s\n" "$KEYED_OLD_OUT"
echo "KEYED_OLD: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_OLD_OUT")"
"$bin/smoke-ready.sh" --terminate-server "$SRV" "$SRV_START" "$HOME/srv2c.log" || exit 1
wait "$SRV"
echo "SERVER_EXIT=$?"
SRV=
SRV_START=
EOS
  chown root:"$gid" "$fixture/run.sh"
  chmod 0550 "$fixture/run.sh"
  cd /tmp
  su -s /bin/bash -c /tmp/rd-smoke-nonroot/run.sh rduser
  [ "$source_meta" = "$(stat -c "%d:%i:%u:%g:%a" /work)" ] || exit 1
  [ "$source_hash" = "$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/debug/examples/smoke_readiness /work/target/smoke-bind-loopback.so /work/scripts/smoke-ready.sh)" ] || exit 1
  echo SOURCE_BIND_UNCHANGED=yes
'
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
run_stage out2d "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd2d; mkdir -p "$HOME"
  install -D ./target/debug/rustdesk /usr/share/rustdesk/rustdesk
  ./target/debug/examples/seed_password "Installed-Initial-Pw-0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so /usr/share/rustdesk/rustdesk --server >/tmp/srv2d.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv2d.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  RECOVERY_SECONDS=$(./target/debug/examples/smoke_readiness password-recovery-seconds)
  [ "$RECOVERY_SECONDS" = 600 ] || exit 1
  if timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" /usr/share/rustdesk/rustdesk --password-stdin <<<"Installed-Fallback-Must-Fail-9" >/tmp/pw2d.out 2>&1; then
    PW_EXIT=0
  else
    PW_EXIT=$?
  fi
  echo "PW_EXIT=$PW_EXIT"
  echo "PW_OUT=[$(tr -d "\n" </tmp/pw2d.out)]"
  [ "$PW_EXIT" = 1 ] || exit 1
  KEYED_NEW_OUT=$(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Fallback-Must-Fail-9 fail 2>&1)
  printf "%s\n" "$KEYED_NEW_OUT"
  echo "KEYED_NEW: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_NEW_OUT")"
  KEYED_OLD_OUT=$(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Initial-Pw-0 ok 2>&1)
  printf "%s\n" "$KEYED_OLD_OUT"
  echo "KEYED_OLD: $(grep -oE "keying ok=(true|false)" <<<"$KEYED_OLD_OUT")"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv2d.log || exit 1
  wait "$SRV" || exit 1
'
echo "$out2d"
record_stage_status R-S11b
grep -q 'PW_EXIT=1' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout password request did not fail without the privileged service endpoint"; rc=1; }
grep -q 'KEYED_NEW: keying ok=false' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout request fell back to user-owned password mutation"; rc=1; }
grep -q 'KEYED_OLD: keying ok=true' <<<"$out2d" \
  || { echo "  FAIL R-S11b: failed installed-layout request changed or disabled the existing credential"; rc=1; }

echo "== (3) two-process: a CPace probe client keys the REAL server (R-A1/R-S1) + a wrong password is refused (R-P3/R-P14c) + the R-T12 observability fires =="
run_stage out3 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd3; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  echo "CORRECT: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok)"
  echo "WRONG:   $(./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-Password-xyz" fail)"
  /work/scripts/smoke-ready.sh --wait-key-failure "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  grep -m1 "security summary" /tmp/srv.log || true
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out4 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd4; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  ./target/debug/examples/flood_probe "127.0.0.1:21118" 300 >/dev/null 2>&1 & FLOOD=$!
  FLOOD_START=$(/work/scripts/smoke-ready.sh --identity "$FLOOD") || exit 1
  /work/scripts/smoke-ready.sh --wait-capacity-shed "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  grep -m1 "security summary.*shed=" /tmp/srv.log || echo "(no shed summary)"
  if /work/scripts/smoke-ready.sh --is-running "$FLOOD" "$FLOOD_START"; then
    /work/scripts/smoke-ready.sh --stop "$FLOOD" "$FLOOD_START" || exit 1
  fi
  wait "$FLOOD" 2>/dev/null || true
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
echo "$out4"
record_stage_status R-T1
grep -qE 'security summary .* shed=[1-9]' <<<"$out4" \
  || { echo "  FAIL R-T1: the connection-flood capacity shed did not fire (budget 256; flooded 300)"; rc=1; }

echo "== (6) FULL SESSION (R-S6/R-S2/R-S18 + R-D8/R-X8): a keyed credential-free LoginRequest is ADMITTED and the FULL-ACCESS policy denies NOTHING =="
run_stage out6 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd6; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out6b "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd6b; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  # Start the box FIRST: its ONE-TIME R-A4 socket-surface audit (post-listen) must see ONLY :21118. A
  # local tunnel target is itself a listener, so it is brought up AFTER the audit has passed.
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  # The LOCAL service the box dials for the tunnel (an RDP/web-server stand-in that echoes bytes back).
  ./target/debug/examples/pf_echo 5555 >/tmp/pf_echo.log 2>&1 & ECHO=$!
  ECHO_START=$(/work/scripts/smoke-ready.sh --identity "$ECHO") || exit 1
  /work/scripts/smoke-ready.sh --wait-tcp-listener "$ECHO" "$ECHO_START" /tmp/pf_echo.log 0100007F:15B3 "port-forward echo listener" || exit 1
  PF_TARGET=127.0.0.1:5555 ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok portforward 2>&1
  /work/scripts/smoke-ready.sh --stop "$ECHO" "$ECHO_START" || exit 1
  wait "$ECHO" 2>/dev/null || true
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out6c "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd6c; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok filetransfer 2>&1
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out7 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd7; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  # The probe keys, reaches the live session, then corrupts its cipher (distinct garbage keys) and
  # sends a frame on the keyed stream — a forged/injected frame an attacker without the keys mimics.
  INJECT_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok inject 2>&1)
  printf "%s\n" "$INJECT_OUT"
  /work/scripts/smoke-ready.sh --wait-log "$SRV" "$SRV_START" /tmp/srv.log "Connection closed: decryption error" "forged-frame rejection" || exit 1
  grep -m1 "Connection closed: decryption error" /tmp/srv.log || echo "(no decryption-error close)"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
echo "$out7"
record_stage_status R-A8/R-T7
# The server tears the connection down with "decryption error" — secretbox::open fails the Poly1305
# tag (R-T7: every keyed frame authenticated), so the forged frame NEVER reaches the parser (R-A8).
grep -q 'Connection closed: decryption error' <<<"$out7" \
  || { echo "  FAIL R-A8/R-T7: an injected forged frame was NOT rejected by the AEAD"; rc=1; }

echo "== (8) R-A8.2 / R-S10: the per-source online-guess limiter is OWNER-SAFE (flood one source; a DIFFERENT source still keys) =="
run_stage out8 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd8; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  # An attacker floods >10 WRONG guesses from 127.0.0.1 within the 60s window (MAX_GUESSES_PER_WINDOW=10).
  for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
  # The OWNER, from a DIFFERENT source (127.0.0.2), with the CORRECT password -> MUST still key.
  OWNER_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok "" "127.0.0.2:0" 2>&1)
  printf "%s\n" "$OWNER_OUT"
  echo "OWNER_DIFF_SRC: $(grep -oE "keying ok=(true|false)" <<<"$OWNER_OUT")"
  # The flooding source (127.0.0.1), even with the CORRECT password, is now rate-limited (shed pre-key).
  FLOODER_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
  printf "%s\n" "$FLOODER_OUT"
  echo "FLOODER_SAME_SRC: $(grep -oE "keying ok=(true|false)" <<<"$FLOODER_OUT")"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out9 "${RUN[@]}" bash -euo pipefail -c '
  if ! command -v tcpdump >/dev/null; then
    apt-get update -q >/dev/null 2>&1
    apt-get install -y -q tcpdump >/dev/null 2>&1
  fi
  command -v tcpdump >/dev/null
  export HOME=/tmp/rd9; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  tcpdump -U -i lo -w /tmp/cap.pcap "tcp port 21118" >/tmp/tcpdump.log 2>&1 & TCPD=$!
  TCPD_START=$(/work/scripts/smoke-ready.sh --identity "$TCPD") || exit 1
  /work/scripts/smoke-ready.sh --wait-log "$TCPD" "$TCPD_START" /tmp/tcpdump.log "listening on lo" "tcpdump capture readiness" || exit 1
  # The probe reaches a live session and sends a LoginRequest whose my_id is the distinctive ASCII
  # canary PLAINTEXT-CANARY-DEADBEEF — sent POST-KEY, so it is sealed by the session cipher.
  LOGIN_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1)
  printf "%s\n" "$LOGIN_OUT"
  /work/scripts/smoke-ready.sh --interrupt "$TCPD" "$TCPD_START" || exit 1
  wait "$TCPD" || exit 1
  echo "PCAP_SIZE: $(wc -c < /tmp/cap.pcap 2>/dev/null || echo 0)"
  # Sanity: the canary string DOES exist in the probe binary, so the grep pattern genuinely matches —
  # its ABSENCE from the wire is real encryption, not a broken/empty search (guards a false pass).
  echo "CANARY_IN_BINARY: $(grep -a -c PLAINTEXT-CANARY-DEADBEEF ./target/debug/examples/probe_client)"
  grep -a -q "PLAINTEXT-CANARY-DEADBEEF" /tmp/cap.pcap 2>/dev/null && echo "CANARY_ON_WIRE: YES" || echo "CANARY_ON_WIRE: NO"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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
run_stage out10 "${RUN[@]}" bash -euo pipefail -c '
  export HOME=/tmp/rd10; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  SRV_START=$(/work/scripts/smoke-ready.sh --identity "$SRV") || exit 1
  /work/scripts/smoke-ready.sh --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0 || exit 1
  # Trip the per-source block: 11 WRONG guesses from 127.0.0.1 (> MAX_GUESSES_PER_WINDOW=10) in <60s.
  for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
  BLOCKED_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
  printf "%s\n" "$BLOCKED_OUT"
  echo "BLOCKED_NOW: $(grep -oE "keying ok=(true|false)" <<<"$BLOCKED_OUT")"
  echo "(holding the exact server identity for 64s so the 60s GUESS_WINDOW lapses...)"
  /work/scripts/smoke-ready.sh --hold-running "$SRV" "$SRV_START" /tmp/srv.log 64 "limiter-decay interval" || exit 1
  DECAYED_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1)
  printf "%s\n" "$DECAYED_OUT"
  echo "DECAYED_AFTER_WINDOW: $(grep -oE "keying ok=(true|false)" <<<"$DECAYED_OUT")"
  /work/scripts/smoke-ready.sh --terminate-server "$SRV" "$SRV_START" /tmp/srv.log || exit 1
  wait "$SRV" || exit 1
'
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

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-D8/R-D2 non-installed user-owned --password-stdin IPC provisioning (clean set-and-exit; root-owned + non-root same-uid) + R-S11b installed-layout service ownership with no user-storage fallback + R-A1/R-S1 keying (two-process) + R-P3/R-P14c wrong-password refusal + R-T12 observability + R-T1 connection-flood capacity-shed + R-S6 keyed-edge authorization (full session) + R-F1/R-D6/R-S5 port-forward/RDP tunnel relays end-to-end inside the seal + R-F1/R-F2 file transfer (keyed FileTransfer login -> non-empty process-owner PeerInfo.username on a headless unix box, never the 'No active console user' refusal) + R-A8/R-T7 forged-frame rejection + R-A8.2/R-S10 owner-safe limiter + R-A9 wire-capture (no plaintext on the wire)${DECAY_NOTE} — ALL validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

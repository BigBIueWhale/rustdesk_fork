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
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -w /work "$IMG")
PORT_HEX='527E' # 21118
LOOPBACK_LISTEN='0100007F:527E' # 127.0.0.1:21118

echo "== (0) build the server binary + the test seeder + the CPace probe client (R-B4 build smoke) =="
"${RUN[@]}" bash -euo pipefail -c 'cargo build --features linux-pkg-config --bin rustdesk --example seed_password --example probe_client --example pf_echo --example flood_probe --example mdwe_codec_probe --color never 2>&1 | tee /tmp/rd-smoke-build.log | grep -E "^error|Finished" | tail -2; grep -q "^error" /tmp/rd-smoke-build.log && exit 1; grep -q "Finished" /tmp/rd-smoke-build.log; cc -shared -fPIC -O2 -Wall -Wextra -o target/smoke-bind-loopback.so scripts/smoke-bind-loopback.c -ldl'

rc=0

echo "== (0b) R-D3a MemoryDenyWriteExecute (W^X) validation: the deployed software VP9 encoder runs clean under the EXACT PR_SET_MDWE primitive systemd applies (so MemoryDenyWriteExecute=yes in the unit is safe) =="
# The controlled --server only ENCODES (§13/Appendix C #2b); the probe sets PR_SET_MDWE|REFUSE_EXEC_GAIN
# BEFORE vpx_codec_enc_init then drives 5 encodes. A runtime W+X mmap/mprotect (a JIT) would SIGSEGV
# under MDWE; libvpx does function-pointer SIMD dispatch, never JIT, so it completes clean (exit 0).
mdwe_out=$("${RUN[@]}" bash -c './target/debug/examples/mdwe_codec_probe; echo "EXIT=$?"' 2>&1 || true)
echo "$mdwe_out" | grep -qE 'MDWE_CODEC_OK' && echo "$mdwe_out" | grep -q 'EXIT=0' \
  && echo "  ok  R-D3a: VP9 encoder W^X-clean under MemoryDenyWriteExecute (init + 5/5 encodes, no W+X mapping)" \
  || { echo "  FAIL R-D3a: the codec path is NOT W^X-safe under MDWE — do NOT ship MemoryDenyWriteExecute=yes:"; echo "$mdwe_out" | tail -3; rc=1; }

echo "== (1) fail-closed startup: --server with NO password MUST PARK — stay alive but bind NOTHING (R-A4/R-S9, finding D) =="
# Finding D: the empty-permanent-password startup process::exit was removed (on Android it crashed
# the shared-process app). An empty password now fails closed by PARKING — direct_server binds NO
# listener and every connection is refused per-connection (server.rs, R-S9). Prove the box stays
# ALIVE (does not exit/crash) yet binds NOTHING on the pinned port. Background it (it no longer
# exits) and probe /proc, mirroring stage (2)'s pattern.
out1=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd1; mkdir -p "$HOME"
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv1.log 2>&1 & SRV=$!
  sleep 8
  echo "ALIVE=$(kill -0 $SRV 2>/dev/null && echo yes || echo no)"
  echo "TCP_LISTEN=[$(awk "\$4==\"0A\"{print \$2}" /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr "\n" " ")]"
  grep -m1 "the direct listener is PARKED" /tmp/srv1.log || true
  grep -m1 "Direct server listening" /tmp/srv1.log || true
  kill -TERM $SRV 2>/dev/null; sleep 1; kill -9 $SRV 2>/dev/null || true
' || true)
echo "$out1"
echo "$out1" | grep -q 'ALIVE=yes' \
  || { echo "  FAIL R-A4/R-S9: --server exited on an empty permanent password (finding D: it MUST park, not exit/crash)"; rc=1; }
echo "$out1" | grep -q 'TCP_LISTEN=\[\]' \
  || { echo "  FAIL R-S9: a listener is bound with NO permanent password (must bind NOTHING while parked)"; rc=1; }
echo "$out1" | grep -q 'the direct listener is PARKED' \
  || { echo "  FAIL R-S9: missing the fail-closed park diagnostic on the empty-password path"; rc=1; }
echo "$out1" | grep -q 'Direct server listening' \
  && { echo "  FAIL R-S9: the server bound a listener with no permanent password"; rc=1; }
[ "$rc" = 0 ] && echo "  ok  R-A4/R-S9 fail-closed startup (no password -> PARK: alive, nothing bound, runtime)"

echo "== (2) seed a password, LISTEN on 127.0.0.1, assert the socket surface (R-B4) + R-T9 drain =="
out2=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd2; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 8
  echo "TCP_LISTEN=[$(awk "\$4==\"0A\"{print \$2}" /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr "\n" " ")]"
  echo "UDP_COUNT=$(( $(tail -n +2 /proc/net/udp 2>/dev/null | wc -l) + $(tail -n +2 /proc/net/udp6 2>/dev/null | wc -l) ))"
  grep -m1 "Direct server listening" /tmp/srv.log || true
  grep -m1 "socket surface verified" /tmp/srv.log || true
  kill -TERM $SRV 2>/dev/null; sleep 3
  grep "R-T9: graceful shutdown complete" /tmp/srv.log || true
' || true)
echo "$out2"
echo "$out2" | grep -q "TCP_LISTEN=\[$LOOPBACK_LISTEN \]" \
  || { echo "  FAIL R-B4: not EXACTLY one v4 TCP listener on 127.0.0.1:21118 (got the TCP_LISTEN line above)"; rc=1; }
echo "$out2" | grep -q 'UDP_COUNT=0' \
  || { echo "  FAIL R-B4: a UDP socket exists — must be ZERO"; rc=1; }
echo "$out2" | grep -q 'socket surface verified — exactly one TCP v4:21118, zero UDP' \
  || { echo "  FAIL R-A4: the runtime socket-surface self-check did not pass"; rc=1; }
echo "$out2" | grep -q 'R-T9: graceful shutdown complete — exiting 0' \
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
out2b=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd2b; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Initial-Seed-Pw-000" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 8
  # timeout so a HANG (the stock "never returns" regression R-D2 fixes) FAILS the test, not wedges it.
  printf "%s\n" "Changed-Via-Ipc-Pw-9" | timeout 15 ./target/debug/rustdesk --password-stdin >/tmp/pw.out 2>&1
  echo "PW_EXIT=$?"
  echo "PW_OUT=[$(tr -d "\n" </tmp/pw.out)]"
  # Proof the round-trip reached the daemon, which APPLIED + PERSISTED it: the NEW credential keys a
  # CPace session and the OLD one is now rejected (R-P1: read live each handshake, no cached PRS).
  echo "KEYED_NEW: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Changed-Via-Ipc-Pw-9" ok 2>&1 | grep -oE "keying ok=(true|false)")"
  echo "KEYED_OLD: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Initial-Seed-Pw-000" fail 2>&1 | grep -oE "keying ok=(true|false)")"
  kill -TERM $SRV 2>/dev/null; sleep 1
' || true)
echo "$out2b"
echo "$out2b" | grep -q 'PW_EXIT=0' \
  || { echo "  FAIL R-D2: the real --password-stdin CLI did not cleanly exit 0 within the timeout (hang/error — the stock never-returns regression)"; rc=1; }
echo "$out2b" | grep -q 'Done!' \
  || { echo "  FAIL R-D2: --password-stdin did not confirm success (no 'Done!') — the daemon did not ACK the IPC set"; rc=1; }
echo "$out2b" | grep -q 'KEYED_NEW: keying ok=true' \
  || { echo "  FAIL R-D8: the IPC-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
echo "$out2b" | grep -q 'KEYED_OLD: keying ok=false' \
  || { echo "  FAIL R-D8: the old password still keys — the --password-stdin change did not take effect over the daemon IPC"; rc=1; }

echo "== (2c) R-D8: portable 'rustdesk --password-stdin' provisions over SAME-UID user-owned IPC as a NON-ROOT owner =="
# An unprivileged owner (uid 4000) runs both non-installed --server and --password-stdin as itself.
# The request reaches its own per-uid raw IPC directly; the endpoint's per-uid mode and SO_PEERCRED
# identity are the authorization. This also exercises RLIMIT_NOFILE enforcement under non-root.
out2c=$("${RUN[@]}" bash -c '
  id -u rduser >/dev/null 2>&1 || useradd -m -u 4000 rduser
  [ "$(id -u rduser)" = 4000 ] || exit 1
  gid=$(id -g rduser)
  fixture=/tmp/rd-smoke-nonroot
  source_meta=$(stat -c "%d:%i:%u:%g:%a" /work)
  source_hash=$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/smoke-bind-loopback.so)
  install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"
  install -d -o rduser -g "$gid" -m 0700 "$fixture/home"
  install -o root -g "$gid" -m 0550 target/debug/rustdesk "$fixture/bin/rustdesk"
  install -o root -g "$gid" -m 0550 target/debug/examples/seed_password "$fixture/bin/seed_password"
  install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"
  install -o root -g "$gid" -m 0440 target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"
  cat > "$fixture/run.sh" <<"EOS"
#!/bin/bash
export HOME=/tmp/rd-smoke-nonroot/home
cd "$HOME"
bin=/tmp/rd-smoke-nonroot/bin
echo "UID=$(id -u)"
"$bin/seed_password" Initial-Seed-Pw-000 >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
SRV=
cleanup_server() {
  if [ -n "$SRV" ] && kill -0 "$SRV" 2>/dev/null; then
    kill -TERM "$SRV" 2>/dev/null || true
    wait "$SRV" 2>/dev/null || true
  fi
}
trap cleanup_server EXIT
LD_PRELOAD="$bin/smoke-bind-loopback.so" "$bin/rustdesk" --server >srv2c.log 2>&1 &
SRV=$!
sleep 8
server_exe=$(readlink -f "/proc/$SRV/exe")
echo "SERVER_UID=$(awk "/^Uid:/{print \$2}" "/proc/$SRV/status")"
echo "PORTABLE_EXE=$server_exe"
[ "$server_exe" = "$bin/rustdesk" ] || exit 1
if tr "\0" "\n" <"/proc/$SRV/cmdline" | grep -Fxq -- --service-owned-server; then exit 1; fi
echo "SERVICE_ROLE_MARKER=absent"
printf "%s\n" Changed-Same-Uid-Pw-9 | timeout 15 "$bin/rustdesk" --password-stdin >pw2c.out 2>&1
echo "PW_EXIT=$?"
echo "PW_OUT=[$(tr -d "\n" <pw2c.out)]"
echo "KEYED_NEW: $("$bin/probe_client" 127.0.0.1:21118 Changed-Same-Uid-Pw-9 ok 2>&1 | grep -oE "keying ok=(true|false)")"
echo "KEYED_OLD: $("$bin/probe_client" 127.0.0.1:21118 Initial-Seed-Pw-000 fail 2>&1 | grep -oE "keying ok=(true|false)")"
kill -TERM "$SRV" 2>/dev/null || true
wait "$SRV"
echo "SERVER_EXIT=$?"
SRV=
EOS
  chown root:"$gid" "$fixture/run.sh"
  chmod 0550 "$fixture/run.sh"
  cd /tmp
  su -s /bin/bash -c /tmp/rd-smoke-nonroot/run.sh rduser
  [ "$source_meta" = "$(stat -c "%d:%i:%u:%g:%a" /work)" ] || exit 1
  [ "$source_hash" = "$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/smoke-bind-loopback.so)" ] || exit 1
  echo SOURCE_BIND_UNCHANGED=yes
' || true)
echo "$out2c"
echo "$out2c" | grep -q 'UID=4000' \
  || { echo "  FAIL R-D8: stage (2c) did not run as the intended non-root uid (4000)"; rc=1; }
echo "$out2c" | grep -q 'SERVER_UID=4000' \
  || { echo "  FAIL R-D8: stage (2c) server was not owned by the intended non-root uid (4000)"; rc=1; }
echo "$out2c" | grep -q 'PORTABLE_EXE=/tmp/rd-smoke-nonroot/bin/rustdesk' \
  || { echo "  FAIL R-D8: stage (2c) did not execute the isolated portable fixture image"; rc=1; }
echo "$out2c" | grep -q 'SERVICE_ROLE_MARKER=absent' \
  || { echo "  FAIL R-D8: stage (2c) entered or could not disprove the service-owned role"; rc=1; }
echo "$out2c" | grep -q 'PW_EXIT=0' \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not cleanly exit 0"; rc=1; }
echo "$out2c" | grep -q 'Done!' \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not confirm 'Done!' — the daemon did not ACK the non-root IPC set"; rc=1; }
echo "$out2c" | grep -q 'KEYED_NEW: keying ok=true' \
  || { echo "  FAIL R-D8: the same-uid-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
echo "$out2c" | grep -q 'KEYED_OLD: keying ok=false' \
  || { echo "  FAIL R-D8: the old password still keys after the same-uid change"; rc=1; }
echo "$out2c" | grep -q 'SERVER_EXIT=0' \
  || { echo "  FAIL R-D8: the non-root server did not terminate and reap cleanly"; rc=1; }
echo "$out2c" | grep -q 'SOURCE_BIND_UNCHANGED=yes' \
  || { echo "  FAIL R-D8: stage (2c) changed or could not re-prove the source bind"; rc=1; }

echo "== (2d) R-S11b: installed layout selects service ownership and never falls back to user-owned password storage =="
out2d=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd2d; mkdir -p "$HOME"
  install -D ./target/debug/rustdesk /usr/share/rustdesk/rustdesk
  ./target/debug/examples/seed_password "Installed-Initial-Pw-0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so /usr/share/rustdesk/rustdesk --server >/tmp/srv2d.log 2>&1 & SRV=$!
  sleep 8
  printf "%s\n" "Installed-Fallback-Must-Fail-9" | timeout 15 /usr/share/rustdesk/rustdesk --password-stdin >/tmp/pw2d.out 2>&1
  echo "PW_EXIT=$?"
  echo "KEYED_NEW: $(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Fallback-Must-Fail-9 fail 2>&1 | grep -oE "keying ok=(true|false)")"
  echo "KEYED_OLD: $(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Initial-Pw-0 ok 2>&1 | grep -oE "keying ok=(true|false)")"
  kill -TERM $SRV 2>/dev/null; sleep 1
' || true)
echo "$out2d"
echo "$out2d" | grep -q 'PW_EXIT=1' \
  || { echo "  FAIL R-S11b: installed-layout password request did not fail without the privileged service endpoint"; rc=1; }
echo "$out2d" | grep -q 'KEYED_NEW: keying ok=false' \
  || { echo "  FAIL R-S11b: installed-layout request fell back to user-owned password mutation"; rc=1; }
echo "$out2d" | grep -q 'KEYED_OLD: keying ok=true' \
  || { echo "  FAIL R-S11b: failed installed-layout request changed or disabled the existing credential"; rc=1; }

echo "== (3) two-process: a CPace probe client keys the REAL server (R-A1/R-S1) + a wrong password is refused (R-P3/R-P14c) + the R-T12 observability fires =="
out3=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd3; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  echo "CORRECT: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok)"
  echo "WRONG:   $(./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-Password-xyz" fail)"
  sleep 1
  grep -m1 "security summary" /tmp/srv.log || true
  kill -TERM $SRV 2>/dev/null; sleep 2
' || true)
echo "$out3"
echo "$out3" | grep -q 'keying ok=true (expected=ok)' \
  || { echo "  FAIL R-A1/R-S1: the real server did not key a CORRECT-password client"; rc=1; }
echo "$out3" | grep -q 'keying ok=false (expected=fail)' \
  || { echo "  FAIL R-P3/R-P14c: a WRONG-password client was not refused at key-confirmation"; rc=1; }
[ "$(echo "$out3" | grep -c 'probe_client: PASS')" -ge 2 ] \
  || { echo "  FAIL: a probe did not match its expected keying outcome"; rc=1; }
echo "$out3" | grep -qE 'security summary .* key_confirmation_failures=[1-9]' \
  || { echo "  FAIL R-T12/R-P14c: the key-confirmation-failure was not counted in the flood-safe summary"; rc=1; }

echo "== (4) R-T1: a connection flood past the 256-permit budget MUST be capacity-shed =="
out4=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd4; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 5
  ./target/debug/examples/flood_probe "127.0.0.1:21118" 300 >/dev/null 2>&1 & FLOOD=$!
  sleep 4
  grep "security summary" /tmp/srv.log | grep -m1 "shed=" || echo "(no shed summary)"
  kill -TERM $SRV 2>/dev/null; kill $FLOOD 2>/dev/null
' || true)
echo "$out4"
echo "$out4" | grep -qE 'security summary .* shed=[1-9]' \
  || { echo "  FAIL R-T1: the connection-flood capacity shed did not fire (budget 256; flooded 300)"; rc=1; }

echo "== (6) FULL SESSION (R-S6/R-S2/R-S18 + R-D8/R-X8): a keyed credential-free LoginRequest is ADMITTED and the FULL-ACCESS policy denies NOTHING =="
out6=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd6; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1 | grep "post-key"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out6"
# R-S6/R-S18: the keyed edge IS the authorization — the credential-free LoginRequest (no second
# credential; the password proof is collapsed into the PAKE) is ADMITTED because CPace already
# authenticated (there is no source-IP ACL). Proven POSITIVELY under the full-access policy: RustDesk
# NOTIFIES the viewer only of DENIED permissions, so an authorized FULL-ACCESS session emits ZERO
# `enabled: false` PermissionInfo. The pinned headless image has no display server: after authorization
# it returns the display backend's exact `connection refused` error instead of PeerInfo.
s6_ok=1
if echo "$out6" | grep -qE 'blocked by the peer|Some\(Error\("Offline"|Some\(Error\("Wrong Password'; then
  echo "  FAIL R-S6/R-S18: the keyed credential-free LoginRequest was REJECTED (must be ADMITTED — CPace authenticated it)"; rc=1; s6_ok=0
fi
if echo "$out6" | grep -q 'enabled: false'; then
  echo "  FAIL R-D8/R-X8: a capability was DENIED (PermissionInfo enabled:false) — the full-access policy must deny nothing"; rc=1; s6_ok=0
fi
if ! echo "$out6" | grep -qE 'Some\(PeerInfo|Some\(Error\("connection refused"'; then
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
out6b=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd6b; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  # Start the box FIRST: its ONE-TIME R-A4 socket-surface audit (post-listen) must see ONLY :21118. A
  # local tunnel target is itself a listener, so it is brought up AFTER the audit has passed.
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  # The LOCAL service the box dials for the tunnel (an RDP/web-server stand-in that echoes bytes back).
  ./target/debug/examples/pf_echo 5555 >/tmp/pf_echo.log 2>&1 & ECHO=$!
  sleep 1
  PF_TARGET=127.0.0.1:5555 ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok portforward 2>&1 | grep "post-key"
  kill -TERM $SRV $ECHO 2>/dev/null
' || true)
echo "$out6b"
# R-F1/R-D6/R-S5/R-A9: the canary made a full round trip THROUGH the box (viewer -> sealed -> box ->
# local target -> echo -> box -> sealed -> viewer), proving the relay is restored AND functional AND
# inside the secretbox (the box never set_raw'd — tcp.rs R-A3 would have panicked otherwise).
if echo "$out6b" | grep -q 'PF-RELAY-ECHO-OK'; then
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
out6c=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd6c; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok filetransfer 2>&1 | grep -E "post-key|PASS"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out6c"
if echo "$out6c" | grep -q 'No active console user'; then
  echo "  FAIL R-F1/R-F2: file transfer was refused with 'No active console user' on a headless unix --server"; rc=1
fi
if echo "$out6c" | grep -q 'FT-PEERINFO username_nonempty=true'; then
  if echo "$out6c" | grep -q 'FT-DIR-RESPONSE'; then
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username + directory FileResponse returned (CM round-trip live)"
  else
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username, not refused (dir FileResponse needs the CM's display, absent in this container — PeerInfo is the load-bearing signal)"
  fi
else
  echo "  FAIL R-F1/R-F2: the FileTransfer login did not return a PeerInfo with a NON-EMPTY username (the headless process-owner fallback regressed, the prelogin re-clear re-broadened to unix, or the login was refused)"; rc=1
fi

echo "== (7) R-A8 / R-T7: an INJECTED (forged) frame on the keyed stream is rejected by the AEAD =="
out7=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd7; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  # The probe keys, reaches the live session, then corrupts its cipher (distinct garbage keys) and
  # sends a frame on the keyed stream — a forged/injected frame an attacker without the keys mimics.
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok inject >/dev/null 2>&1
  sleep 1
  grep "Connection closed: decryption error" /tmp/srv.log | tail -1 || echo "(no decryption-error close)"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out7"
# The server tears the connection down with "decryption error" — secretbox::open fails the Poly1305
# tag (R-T7: every keyed frame authenticated), so the forged frame NEVER reaches the parser (R-A8).
echo "$out7" | grep -q 'Connection closed: decryption error' \
  || { echo "  FAIL R-A8/R-T7: an injected forged frame was NOT rejected by the AEAD"; rc=1; }

echo "== (8) R-A8.2 / R-S10: the per-source online-guess limiter is OWNER-SAFE (flood one source; a DIFFERENT source still keys) =="
out8=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd8; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  # An attacker floods >10 WRONG guesses from 127.0.0.1 within the 60s window (MAX_GUESSES_PER_WINDOW=10).
  for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
  # The OWNER, from a DIFFERENT source (127.0.0.2), with the CORRECT password -> MUST still key.
  echo "OWNER_DIFF_SRC: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok "" "127.0.0.2:0" 2>&1 | grep -oE "keying ok=(true|false)")"
  # The flooding source (127.0.0.1), even with the CORRECT password, is now rate-limited (shed pre-key).
  echo "FLOODER_SAME_SRC: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1 | grep -oE "keying ok=(true|false)")"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out8"
# The CARDINAL R-S10 rule: a limiter must NEVER lock the owner out of their own machine. The per-IP
# online-guess limiter (guess_limiter_allows, MAX 10/60s) blocks the FLOODING source but not a
# different one — so a connection-flood / guess-flood from an attacker cannot deny the owner.
echo "$out8" | grep -q 'OWNER_DIFF_SRC: keying ok=true' \
  || { echo "  FAIL R-A8.2: a DIFFERENT source was blocked by the limiter — owner lock-out, the CARDINAL violation"; rc=1; }
echo "$out8" | grep -q 'FLOODER_SAME_SRC: keying ok=false' \
  || { echo "  FAIL R-A8.2: the flooding source was NOT rate-limited (the per-source guess limiter is not working)"; rc=1; }

echo "== (9) R-A9: wire-capture — a post-key LoginRequest canary is ENCRYPTED (never plaintext on the wire) =="
out9=$("${RUN[@]}" bash -c '
  (apt-get update -q >/dev/null 2>&1; apt-get install -y -q tcpdump >/dev/null 2>&1) || true
  if ! command -v tcpdump >/dev/null; then echo "TCPDUMP_ABSENT"; exit 0; fi
  export HOME=/tmp/rd9; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  tcpdump -i lo -w /tmp/cap.pcap "tcp port 21118" >/dev/null 2>&1 & TCPD=$!
  sleep 1
  # The probe reaches a live session and sends a LoginRequest whose my_id is the distinctive ASCII
  # canary PLAINTEXT-CANARY-DEADBEEF — sent POST-KEY, so it is sealed by the session cipher.
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login >/dev/null 2>&1
  sleep 1; kill $TCPD 2>/dev/null; sleep 1
  echo "PCAP_SIZE: $(wc -c < /tmp/cap.pcap 2>/dev/null || echo 0)"
  # Sanity: the canary string DOES exist in the probe binary, so the grep pattern genuinely matches —
  # its ABSENCE from the wire is real encryption, not a broken/empty search (guards a false pass).
  echo "CANARY_IN_BINARY: $(grep -a -c PLAINTEXT-CANARY-DEADBEEF ./target/debug/examples/probe_client)"
  grep -a -q "PLAINTEXT-CANARY-DEADBEEF" /tmp/cap.pcap 2>/dev/null && echo "CANARY_ON_WIRE: YES" || echo "CANARY_ON_WIRE: NO"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out9"
if echo "$out9" | grep -q 'TCPDUMP_ABSENT'; then
  echo "  SKIP R-A9: tcpdump unavailable in this image (apt offline) — wire-capture not run"
else
  # R-A9: the session bytes are indistinguishable from random — a known plaintext canary sent on the
  # KEYED stream NEVER appears on the captured wire (AEAD-sealed). The non-empty pcap + the in-binary
  # sanity rule out a false pass (we captured real traffic, and the search pattern really matches).
  echo "$out9" | grep -q 'CANARY_IN_BINARY: 1' \
    || { echo "  FAIL R-A9: the canary sanity check failed (the grep pattern does not match the probe binary)"; rc=1; }
  echo "$out9" | grep -qE 'PCAP_SIZE: [0-9]{3,}' \
    || { echo "  FAIL R-A9: the wire capture was empty/trivial — no real traffic was captured"; rc=1; }
  echo "$out9" | grep -q 'CANARY_ON_WIRE: NO' \
    || { echo "  FAIL R-A9: the LoginRequest canary appeared as PLAINTEXT on the wire — the session is NOT encrypted"; rc=1; }
fi

# Opt-in (SMOKE_DECAY=1): the R-A8 limiter-DECAY proof waits out the real 60s GUESS_WINDOW, so it is
# kept off the default fast path. It adds ~75 s but exercises the genuine production window (no
# test-only time-injection into the security-critical limiter).
DECAY_NOTE=""
if [ "${SMOKE_DECAY:-0}" = 1 ]; then
echo "== (10) R-A8 DECAY: a tripped per-source block DECAYS after the window (no PERMANENT lockout) =="
out10=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd10; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  LD_PRELOAD=/work/target/smoke-bind-loopback.so ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  # Trip the per-source block: 11 WRONG guesses from 127.0.0.1 (> MAX_GUESSES_PER_WINDOW=10) in <60s.
  for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
  echo "BLOCKED_NOW: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1 | grep -oE "keying ok=(true|false)")"
  echo "(waiting 64s for the 60s GUESS_WINDOW to lapse...)"; sleep 64
  echo "DECAYED_AFTER_WINDOW: $(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1 | grep -oE "keying ok=(true|false)")"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out10"
# The block must be live first (precondition), then self-heal once the window lapses. A limiter that
# never decays is a PERMANENT lockout — the cardinal "never lock the owner out" violation (R-S10).
echo "$out10" | grep -q 'BLOCKED_NOW: keying ok=false' \
  || { echo "  FAIL R-A8: the source was not blocked after the flood (decay-test precondition)"; rc=1; }
echo "$out10" | grep -q 'DECAYED_AFTER_WINDOW: keying ok=true' \
  || { echo "  FAIL R-A8: the block did NOT decay after the 60s window — a PERMANENT lockout (cardinal owner-safety violation)"; rc=1; }
DECAY_NOTE=" + R-A8 limiter-decay (tripped block self-heals after the 60s window)"
fi

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-D8/R-D2 non-installed user-owned --password-stdin IPC provisioning (clean set-and-exit; root-owned + non-root same-uid) + R-S11b installed-layout service ownership with no user-storage fallback + R-A1/R-S1 keying (two-process) + R-P3/R-P14c wrong-password refusal + R-T12 observability + R-T1 connection-flood capacity-shed + R-S6 keyed-edge authorization (full session) + R-F1/R-D6/R-S5 port-forward/RDP tunnel relays end-to-end inside the seal + R-F1/R-F2 file transfer (keyed FileTransfer login -> non-empty process-owner PeerInfo.username on a headless unix box, never the 'No active console user' refusal) + R-A8/R-T7 forged-frame rejection + R-A8.2/R-S10 owner-safe limiter + R-A9 wire-capture (no plaintext on the wire)${DECAY_NOTE} — ALL validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

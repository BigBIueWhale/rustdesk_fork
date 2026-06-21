#!/usr/bin/env bash
#
# smoke-server.sh — R-B4 / R-A4 / R-T9 / R-T15(d) RUNTIME smoke-test for the controlled-side server.
#
# verify.sh proves the code COMPILES + the KATs pass; it cannot prove the binary BUILDS-and-LINKS,
# nor the runtime startup/listen/shutdown behaviour. This builds the full server binary in the
# pinned-toolchain container and exercises it headless over the docker LOOPBACK — what the spec's
# R-B4 ("assume nothing builds until watched") and R-A8 (runtime exercise) call for.
#
# It binds 127.0.0.1 (RUSTDESK_BIND_LOOPBACK=1) — never 0.0.0.0 — in an isolated `--rm` container
# with no published ports, so nothing is ever exposed off the container.
#
# Validated at RUNTIME (not merely compile):
#   - R-B4 build  : the full `rustdesk` binary builds + links + runs headless (sciter is `dyn`);
#   - R-A4 (fail-closed startup) : with NO permanent password the box refuses to listen + exits;
#   - R-T15(d)/R-S9 : the empty-whitelist default-deny WARNING is surfaced (never a silent lockout);
#   - R-B4 / R-D3/R-D5/R-D6 socket surface : with a password seeded the box binds EXACTLY ONE v4 TCP
#     listener on the pinned port (21118) and ZERO UDP — the §17 direct-IP/no-UDP thesis, empirical;
#   - R-A4 (runtime socket self-check) : `assert_socket_surface` confirms the same from inside;
#   - R-T9 : SIGTERM -> "graceful shutdown initiated" -> "complete — exiting 0".
#
# The permanent password is seeded by the TEST-ONLY `examples/seed_password` (the production
# `--password` CLI is install-privilege-gated and refuses in a container).
#
# Usage:  scripts/smoke-server.sh
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
"${RUN[@]}" bash -c 'cargo build --features linux-pkg-config --bin rustdesk --example seed_password --example probe_client --example flood_probe --color never 2>&1 | grep -E "^error|Finished" | tail -2'

rc=0

echo "== (1) fail-closed startup: --server with NO password MUST refuse (R-A4 / R-T15(d)) =="
out1=$("${RUN[@]}" bash -c 'export HOME=/tmp/rd1; mkdir -p "$HOME"; timeout 12 ./target/debug/rustdesk --server 2>&1' || true)
echo "$out1" | grep -q 'no permanent password is set — refusing to listen' \
  || { echo "  FAIL R-A4: server did not refuse on a missing permanent password"; rc=1; }
echo "$out1" | grep -q 'startup invariants violated — the box refuses to run insecure' \
  || { echo "  FAIL R-A4: no fail-closed refusal"; rc=1; }
echo "$out1" | grep -q 'R-S9: the source whitelist is EMPTY' \
  || { echo "  FAIL R-T15(d): the empty-whitelist default-deny warning was not surfaced"; rc=1; }
[ "$rc" = 0 ] && echo "  ok  R-A4 fail-closed startup + R-T15(d) whitelist warning (runtime)"

echo "== (2) seed a password, LISTEN on 127.0.0.1, assert the socket surface (R-B4) + R-T9 drain =="
out2=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd2 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
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

echo "== (3) two-process: a CPace probe client keys the REAL server (R-A1/R-S1) + a wrong password is refused (R-P3/R-P14c) + the R-T12 observability fires =="
out3=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd3 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
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
  export HOME=/tmp/rd4 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 5
  ./target/debug/examples/flood_probe "127.0.0.1:21118" 300 >/dev/null 2>&1 & FLOOD=$!
  sleep 4
  grep "security summary" /tmp/srv.log | grep -m1 "shed=" || echo "(no shed summary)"
  kill -TERM $SRV 2>/dev/null; kill $FLOOD 2>/dev/null
' || true)
echo "$out4"
echo "$out4" | grep -qE 'security summary .* shed=[1-9]' \
  || { echo "  FAIL R-T1: the connection-flood capacity shed did not fire (budget 256; flooded 300)"; rc=1; }

echo "== (5) R-T15(d) ENFORCED: a fully KEYED connection is DENIED by the empty default-deny whitelist =="
out5=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd5 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok read 2>&1 | grep "post-key"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out5"
# The probe keys, engages the session cipher, reads the post-key flow, and finds the server's
# whitelist refusal — proving default-deny (R-S9) is ENFORCED on a real keyed session, not merely
# warned about at startup (CPace authenticated the peer, yet the empty whitelist still blocks it).
echo "$out5" | grep -q 'Your ip is blocked by the peer' \
  || { echo "  FAIL R-T15(d): a fully-keyed connection was NOT denied by the empty default-deny whitelist"; rc=1; }

echo "== (6) FULL SESSION (R-S6/R-S2): a keyed client + an empty-password LoginRequest is AUTHORIZED (whitelist=0.0.0.0/0) =="
out6=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd6 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" "0.0.0.0/0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
  sleep 6
  ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1 | grep "post-key"
  kill -TERM $SRV 2>/dev/null
' || true)
echo "$out6"
# An authorized session emits PermissionInfo (session-setup) — proving the keyed edge IS the
# authorization (R-S6: the password proof is collapsed into the PAKE; the empty-password
# LoginRequest still authorizes because CPace already authenticated, and the whitelist admits).
echo "$out6" | grep -q 'PermissionInfo\|PeerInfo' \
  || { echo "  FAIL R-S6: a keyed empty-password LoginRequest did NOT authorize / start a session"; rc=1; }
# R-S17: the probe (a faithful viewer) verified the responder's HostIdentity host-proof as the
# FIRST post-key frame — the SSH-known_hosts-style defence against a substituted/MITM host.
echo "$out6" | grep -q 'R-S17 host-proof VERIFIED' \
  || { echo "  FAIL R-S17: the responder's HostIdentity host-proof did not verify"; rc=1; }

echo "== (7) R-A8 / R-T7: an INJECTED (forged) frame on the keyed stream is rejected by the AEAD =="
out7=$("${RUN[@]}" bash -c '
  export HOME=/tmp/rd7 RUSTDESK_BIND_LOOPBACK=1; mkdir -p "$HOME"
  ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" "0.0.0.0/0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
  ./target/debug/rustdesk --server >/tmp/srv.log 2>&1 & SRV=$!
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

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-T15(d) startup-warning AND session-enforcement + R-A1/R-S1 keying (two-process) + R-P3/R-P14c wrong-password refusal + R-T12 observability + R-T1 connection-flood capacity-shed + R-S17 host-proof verify + R-S6 keyed-edge authorization (full session) + R-A8/R-T7 forged-frame rejection — ALL validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

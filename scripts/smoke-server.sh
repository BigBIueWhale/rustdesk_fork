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

echo "== (0) build the server binary + the test seeder (R-B4 build smoke) =="
"${RUN[@]}" bash -c 'cargo build --features linux-pkg-config --bin rustdesk --example seed_password --color never 2>&1 | tail -2'

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

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-T15(d) — ALL validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

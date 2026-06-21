#!/usr/bin/env bash
#
# smoke-server.sh — R-B4 / R-A4 RUNTIME smoke-test for the controlled-side server.
#
# verify.sh proves the code COMPILES + the unit/integration KATs pass; it cannot prove the
# binary actually BUILDS-and-LINKS, nor that the fail-closed STARTUP fires at runtime. This does:
# it builds the full server binary in the pinned-toolchain container and runs it headless,
# asserting the runtime behaviour the compile-time asserts of R-A4 can only promise.
#
# Validated at RUNTIME (not merely compile):
#   - R-B4   : the full `rustdesk` binary builds + links + runs headless (sciter is the `dyn`
#              branch, dlopened at runtime, so it does not block the link);
#   - R-A4   : `assert_startup_invariants` REFUSES to listen with no permanent password set —
#              the box "refuses to run insecure" and exits fail-closed (NOT a silent partial start);
#   - R-T15(d)/R-S9 : the empty-whitelist DEFAULT-DENY warning is surfaced loudly at startup, so a
#              deny-all is never a SILENT lockout.
#
# The container is `docker run --rm` with NO published ports (no `-p`) and its own network
# namespace, so nothing here is ever exposed off the container (honouring "never 0.0.0.0 on the
# host"). The fork ALSO never reaches the listener in this test — it refuses before binding.
#
# NEXT STAGE (not yet automated): the full R-B4 socket-surface check — `ss -lntup` on the RUNNING
# `--service` showing exactly one v4 TCP listener on the direct port + zero UDP + no unsolicited
# outbound (R-D3/R-D5/R-D6) — plus the R-T9 SIGTERM graceful-drain — both require a permanent
# password to be SET so the box gets past R-A4 to actually listen. The `--password` CLI gates that
# behind an install-privilege check, so that stage needs a config-seed affordance first.
#
# Usage:  scripts/smoke-server.sh
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=rd-devcheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -w /work "$IMG")

echo "== (1) build the server binary in docker (R-B4 build smoke) =="
"${RUN[@]}" cargo build --features linux-pkg-config --bin rustdesk --color never 2>&1 | tail -2

echo "== (2) run --server headless: assert the FAIL-CLOSED startup (R-A4) =="
out=$("${RUN[@]}" bash -c \
  'export HOME=/tmp/rdtest; mkdir -p "$HOME"; timeout 12 /work/target/debug/rustdesk --server 2>&1' \
  || true)
echo "$out" | grep -iE 'R-A4|R-S9|refus|invariant' || true

rc=0
echo "$out" | grep -q 'no permanent password is set — refusing to listen' \
  || { echo "  FAIL R-A4: server did not refuse on a missing permanent password"; rc=1; }
echo "$out" | grep -q 'startup invariants violated — the box refuses to run insecure' \
  || { echo "  FAIL R-A4: no fail-closed refusal at startup"; rc=1; }
echo "$out" | grep -q 'R-S9: the source whitelist is EMPTY' \
  || { echo "  FAIL R-T15(d): the empty-whitelist default-deny warning was not surfaced"; rc=1; }

if [ "$rc" = 0 ]; then
  echo "SMOKE OK: binary builds + runs headless (R-B4); R-A4 fail-closed startup + R-T15(d) whitelist warning validated at RUNTIME."
else
  echo "SMOKE FAILED"; exit 1
fi

#!/usr/bin/env bash
# scripts/verify-release.sh — run EVERY source-verification gate in one shot.
#
# Motivation (HARDENING_STATUS "Open residuals" / the 2026-07-01 apple-conform finding): several gates
# live OUTSIDE verify.sh — apple-conform-check.sh, audit.sh, dart-audit.sh, smoke-server.sh,
# dart-verify.sh, native-codec-watch.sh. Because nothing ran them together, the apple-conform #2b
# leftover (0c54912) sat FAILING, unnoticed, straight through the "complete/proven" milestones. This
# orchestrator closes that blind spot: one command, every gate, a single pass/fail summary, so a
# silently-failing gate fails the release instead of hiding.
#
# It does NOT run the R-B2 artifact builds (build-{debian,android,windows}*.sh) — those are the
# separate reproducible-build step. This is the SOURCE-verification gate (slow: ~45-60 min total,
# each sub-gate is a fresh docker image/run; it binds only 127.0.0.1).
set -uo pipefail
cd "$(dirname "$0")/.."

# gate-script | one-line description
GATES=(
  "verify.sh|compile + KATs + handshake + policy funnel + R-A6 done-set"
  "smoke-server.sh|runtime: one-TCP/zero-UDP, fail-closed, keying, provisioning, full session"
  "dart-verify.sh|flutter analyze lib/ (zero errors)"
  "native-codec-watch.sh|native-codec advisory ledger + requirements.html hash pin"
  "apple-conform-check.sh|R-R2 macOS/iOS source conformance + cross-checks"
  "audit.sh|cargo-audit + cargo-deny (Rust advisory floor)"
  "dart-audit.sh|osv-scanner (Dart advisory floor)"
)

declare -a results
fail=0
for entry in "${GATES[@]}"; do
  s="${entry%%|*}"; d="${entry#*|}"
  printf '\n================ RELEASE GATE: scripts/%s ================\n%s\n' "$s" "$d"
  if bash "scripts/$s"; then
    results+=("  PASS  $s")
  else
    results+=("  FAIL  $s  ($d)")
    fail=1
  fi
done

printf '\n===== verify-release summary (HEAD %s) =====\n' "$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
printf '%s\n' "${results[@]}"
if [ "$fail" = 0 ]; then
  echo "VERIFY-RELEASE: ALL GATES GREEN"
else
  echo "VERIFY-RELEASE: ONE OR MORE GATES FAILED"
  exit 1
fi

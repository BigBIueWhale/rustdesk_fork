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

# shellcheck source=scripts/verify-scan.sh
source scripts/verify-scan.sh
verify_scan_preflight || exit 1
case "${1:-}" in
  "") ;;
  --preflight) [ "$#" -eq 1 ] || { echo "verify-release: --preflight takes no arguments" >&2; exit 2; }; exit 0 ;;
  *) echo "usage: scripts/verify-release.sh [--preflight]" >&2; exit 2 ;;
esac

# gate-script | one-line description
GATES=(
  "verify.sh|compile + KATs + handshake + policy funnel + R-A6 done-set"
  "verify-windows-harness.py --self-test|Windows harness contracts + bounded behavioral mutation suites"
  "online-input-provenance.py --self-test|immutable online-input snapshot mutation suite"
  "test-android-gradle-cache.sh|non-root immutable Gradle projection + pinned offline semantics"
  "android-rust-check.sh|pinned offline aarch64 Android Rust check"
  "smoke-server.sh|runtime: host coexistence + one-TCP/zero-UDP, fail-closed, keying, provisioning, full session"
  "smoke-debian-systemd-lifecycle.sh|installed Debian systemd stop/restart/crash recovery + portable noninterference"
  "dart-verify.sh|flutter analyze lib/ (zero errors)"
  "native-codec-watch.sh|native-codec advisory ledger + requirements.html hash pin"
  "apple-conform-check.sh|R-R2 macOS/iOS source conformance + cross-checks"
  "audit.sh|cargo-audit + cargo-deny (Rust advisory floor)"
  "dart-audit.sh|osv-scanner (Dart advisory floor)"
  "test-build-faillo.sh|build-harness fail-loud guards + pinned offline reset recovery (§12.3)"
)

declare -a results
fail=0
for entry in "${GATES[@]}"; do
  s="${entry%%|*}"; d="${entry#*|}"
  printf '\n================ RELEASE GATE: scripts/%s ================\n%s\n' "$s" "$d"
  if [[ "$s" == *.py* ]]; then
    read -r -a gate_args <<< "$s"
    python3 "scripts/${gate_args[0]}" "${gate_args[@]:1}"
    gate_status=$?
  else
    bash "scripts/$s"
    gate_status=$?
  fi
  if [ "$gate_status" -eq 0 ]; then
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
  echo "NOTE: these are SOURCE gates (compile + flutter analyze + KATs + greps + advisories) — they do"
  echo "      NOT build the shipped artifacts. A project-specific Gradle / CMake / msbuild / Android"
  echo "      resource-theme break can pass here yet fail the platform build. Android Rust is target-checked."
  echo "      For buildability + reproducible A==B artifacts + a SHA256SUMS manifest: scripts/build-release.sh"
else
  echo "VERIFY-RELEASE: ONE OR MORE GATES FAILED"
  exit 1
fi

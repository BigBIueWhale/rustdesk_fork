#!/usr/bin/env bash
# scripts/test-build-faillo.sh — assert the BUILD HARNESS itself fails loud (§12.3 / R-B2).
#
# The release build must make silent failure structurally impossible: on a fresh machine, in any
# order, on any stale state, an operator either gets byte-identical A==B artifacts or a LOUD,
# actionable error. This gate PROVES that property doesn't regress — it feeds each guard a
# misconfiguration and asserts the guard DIES with a FATAL message (never proceeds silently).
# Needs docker + git; binds no socket. Run standalone or via verify-release.sh.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
RV="$(. scripts/pins.env; echo "$RUST_VERSION")"
P=0; F=0

# run_die DESC SNIPPET : SNIPPET (lib sourced) MUST exit non-zero AND print a FATAL/FAIL message.
run_die() {
  local desc="$1" snip="$2" out rc
  out="$(bash -c "source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; $snip" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qiE 'FATAL|FAIL'; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc  (rc=$rc; no loud message)"; F=$((F+1)); fi
}
# run_ok DESC SNIPPET : MUST exit 0.
run_ok() {
  local desc="$1" snip="$2" rc
  bash -c "source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; $snip" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then echo "  PASS  $desc"; P=$((P+1)); else echo "  FAIL  $desc (rc=$rc)"; F=$((F+1)); fi
}
# run_script_die DESC CMD... : running CMD MUST exit non-zero AND print FATAL.
run_script_die() {
  local desc="$1"; shift
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qiE 'FATAL|FAIL'; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc)"; F=$((F+1)); fi
}

echo "== build-harness fail-loud proofs (guard level) =="
run_die "SOURCE_DATE_EPOCH unset"          'unset SOURCE_DATE_EPOCH; assert_source_date_epoch'
run_die "SOURCE_DATE_EPOCH non-integer"    'export SOURCE_DATE_EPOCH=notanum; assert_source_date_epoch'
run_ok  "SOURCE_DATE_EPOCH from the pin"   'export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"; assert_source_date_epoch'
run_die "verify_sha256 R-B12 sentinel"     'verify_sha256 /etc/hostname "$SHA_PENDING"'
run_die "verify_sha256 missing file"       'verify_sha256 /online/DOES-NOT-EXIST.tar.xz 00000000000000000000000000000000000000000000000000000000deadbeef'
run_die "verify_online_shas wrong SHA"     "verify_online_shas rust-${RV}.tar.xz 0000000000000000000000000000000000000000000000000000000000000000"
run_die "verify_online_shas odd arg count" 'verify_online_shas loneName'
run_die "require_cmd missing tool"         'require_cmd this_tool_does_not_exist_xyz'
run_die "clean-worktree guard dies dirty"  'touch scripts/.faillo_ct_probe; trap "rm -f scripts/.faillo_ct_probe" EXIT; assert_clean_worktree'
run_ok  "clean-worktree yields ALLOW_DIRTY" 'export ALLOW_DIRTY_TREE=1; assert_clean_worktree'

echo "== build-harness fail-loud proofs (script level) =="
run_script_die "build-release.sh rejects a bad arg"    bash scripts/build-release.sh --nonsense
run_script_die "build-release.sh --doctor rejects a dirty tree" \
  bash -c 'touch scripts/.faillo_dirt_probe; o="$(bash scripts/build-release.sh --doctor 2>&1)"; r=$?; rm -f scripts/.faillo_dirt_probe; printf "%s" "$o"; exit $r'
run_script_die "gen-android-keystore refuses to overwrite" bash scripts/gen-android-keystore.sh scripts/lib.sh /tmp/faillo-nonexistent-pass

echo
echo "RESULT: $P passed, $F failed"
if [ "$F" -eq 0 ]; then echo "BUILD-FAILLO: GREEN — every misconfiguration died loud"; exit 0
else echo "BUILD-FAILLO: RED — $F silent path(s)!"; exit 1; fi

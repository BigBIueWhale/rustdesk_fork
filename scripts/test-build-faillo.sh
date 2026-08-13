#!/usr/bin/env bash
# scripts/test-build-faillo.sh — assert the BUILD HARNESS itself fails loud (§12.3 / R-B2).
#
# The release build must make silent failure structurally impossible: on a fresh machine, in any
# order, on any stale state, an operator either gets byte-identical A==B artifacts or a LOUD,
# actionable error. This gate exercises the enumerated guards against regression — it feeds each a
# misconfiguration and asserts the guard DIES with a FATAL message (never proceeds silently).
# Needs docker + git; uses only the local Docker Unix socket and binds no network listener.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
RV="$(. scripts/pins.env; echo "$RUST_VERSION")"
TEST_HOME="$(getent passwd "$(id -u)" | awk -F: 'NF == 7 { print $6 }')"
[ -n "$TEST_HOME" ] && [ -d "$TEST_HOME" ] || { echo "BUILD-FAILLO: FATAL - cannot resolve test home"; exit 1; }
CLEAN_SCRIPT_ENV=(env -i HOME="$TEST_HOME" PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC)
EXPECTED_SOURCE_COMMIT="$(/usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
  -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
  || { echo "BUILD-FAILLO: FATAL - cannot resolve exact source commit"; exit 1; }
[[ "$EXPECTED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "BUILD-FAILLO: FATAL - source commit is not lowercase 40-hex"; exit 1; }
DIRTY_PROBE_PARENT="$REPO_ROOT/scripts"
P=0; F=0

# run_die DESC EXPECTED SNIPPET : SNIPPET (lib sourced) MUST exit non-zero with EXPECTED.
run_die() {
  local desc="$1" expected="$2" snip="$3" out rc
  out="$(bash -c "source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; $snip" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$expected"; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc  (rc=$rc; no loud message)"; F=$((F+1)); fi
}
# run_ok DESC SNIPPET : MUST exit 0.
run_ok() {
  local desc="$1" snip="$2" rc
  bash -c "source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; $snip" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then echo "  PASS  $desc"; P=$((P+1)); else echo "  FAIL  $desc (rc=$rc)"; F=$((F+1)); fi
}
# run_script_die DESC EXPECTED CMD... : CMD MUST exit non-zero with EXPECTED.
script_die_output_is_expected() {
  local rc="$1" out="$2" expected="$3"
  [ "$rc" -ne 0 ] && [ "$rc" -ne 125 ] && printf '%s' "$out" | grep -qF "$expected" \
    && ! printf '%s' "$out" | grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'
}
run_script_die() {
  local desc="$1" expected="$2"; shift 2
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if script_die_output_is_expected "$rc" "$out" "$expected"; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc)"; F=$((F+1)); fi
}
run_script_ok() {
  local desc="$1"; shift
  local rc; "$@" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc)"; F=$((F+1)); fi
}
run_script_ok_marker() {
  local desc="$1" marker="$2"; shift 2
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -qF "$marker"; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc; success marker absent)"; F=$((F+1)); fi
}
run_script_die_reached() {
  local desc="$1" expected="$2" reached="$3"; shift 3
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if script_die_output_is_expected "$rc" "$out" "$expected" \
    && printf '%s\n' "$out" | grep -qF "$reached"; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc; target state or diagnostic absent)"; F=$((F+1)); fi
}
reached_failure_is_expected() {
  local rc="$1" out="$2" reached="$3" expected="$4" marker="$5"
  [ "$rc" -ne 0 ] || return 1
  printf '%s\n' "$out" | grep -qF "$reached" \
    && printf '%s\n' "$out" | grep -qF "$expected" \
    && ! printf '%s\n' "$out" | grep -qF "$marker"
}
run_script_die_reached_without_marker() {
  local desc="$1" reached="$2" expected="$3" marker="$4"; shift 4
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if reached_failure_is_expected "$rc" "$out" "$reached" "$expected" "$marker"; then
    echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (rc=$rc; invalid marker or loud failure contract)"; F=$((F+1)); fi
}
exercise_reached_failure_classifier() {
  local reached="fixture reached" expected="fixture expected" marker="fixture invalid success"
  local valid="$reached
$expected"
  reached_failure_is_expected 1 "$valid" "$reached" "$expected" "$marker" \
    && ! reached_failure_is_expected 0 "$valid" "$reached" "$expected" "$marker" \
    && ! reached_failure_is_expected 1 "$expected" "$reached" "$expected" "$marker" \
    && ! reached_failure_is_expected 1 "$reached" "$reached" "$expected" "$marker" \
    && ! reached_failure_is_expected 1 "$valid
$marker" "$reached" "$expected" "$marker"
}

run_wrong_online_sha_probe() (
  local fixture="" fixture_id="" status
  cleanup_wrong_sha_fixture() {
    status=$?
    local cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$fixture" ]; then
      /usr/bin/python3 -I -S "$REPO_ROOT/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$fixture" --expected-identity "$fixture_id" \
        || cleanup_failed=1
      [ ! -e "$fixture" ] && [ ! -L "$fixture" ] || cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || status=125
    exit "$status"
  }
  umask 077
  trap cleanup_wrong_sha_fixture EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  fixture="$(mktemp -d /tmp/rustdesk-faillo-sha.XXXXXXXXXX)" || exit 1
  fixture_id="$(stat -c '%d:%i' -- "$fixture")" || exit 1
  printf 'independent wrong-sha fixture\n' > "$fixture/rust-${RV}.tar.xz" || exit 1
  ONLINE_DIR="$fixture" bash -c \
    'source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; verify_online_shas "$1" "$2"' \
    _ "rust-${RV}.tar.xz" 0000000000000000000000000000000000000000000000000000000000000000
)

run_with_dirty_probe() (
  local label="$1" probe="" probe_id="" probe_parent="$DIRTY_PROBE_PARENT"
  shift
  cleanup_dirty_probe() {
    local status=$? cleanup_failed=0 observed
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$probe" ]; then
      observed="$(stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$probe" 2>/dev/null)" || cleanup_failed=1
      [ "$observed" = "$probe_id" ] || cleanup_failed=1
      if [ "$cleanup_failed" -eq 0 ]; then
        rm -f -- "$probe" || cleanup_failed=1
        [ ! -e "$probe" ] && [ ! -L "$probe" ] || cleanup_failed=1
      fi
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
      printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\n' "$probe" >&2
      status=125
    fi
    exit "$status"
  }
  trap cleanup_dirty_probe EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  probe="$(umask 077 && mktemp "$probe_parent/.faillo-${label}.XXXXXXXXXX")" || exit 1
  probe_id="$(stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$probe")" || exit 1
  [ "$probe_id" = "$(stat -c '%d:%i' -- "$probe"):$(id -u):$(id -g):600:1:regular empty file" ] \
    || exit 1
  printf 'BUILD-FAILLO: DIRTY-PROBE-READY: %s\n' "$probe" >&2
  "$@"
)

run_production_dirty_probe() (
  local fixture_root="" fixture_id="" fixture_repo="" observed status
  cleanup_production_fixture() {
    status=$?
    local cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$fixture_root" ]; then
      observed="$(stat -c '%d:%i:%u:%g:%a:%F' -- "$fixture_root" 2>/dev/null)" \
        || cleanup_failed=1
      [ "$observed" = "$fixture_id:$(id -u):$(id -g):700:directory" ] \
        || cleanup_failed=1
      if [ "$cleanup_failed" -eq 0 ]; then
        /usr/bin/python3 -I -S "$REPO_ROOT/scripts/verify-private-tree-closure.py" \
          --mount-root "$fixture_root" \
          && /usr/bin/python3 -I -S "$REPO_ROOT/scripts/verify-private-tree-closure.py" \
          --inode-root "$fixture_root" \
          && /usr/bin/python3 -I -S "$REPO_ROOT/scripts/verify-private-tree-closure.py" \
          --remove-private-root "$fixture_root" --expected-identity "$fixture_id" \
          && [ ! -e "$fixture_root" ] && [ ! -L "$fixture_root" ] \
          || cleanup_failed=1
      fi
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
      printf 'BUILD-FAILLO: PRODUCTION-FIXTURE-CLEANUP-FAILURE: %s\n' "$fixture_root" >&2
      status=125
    fi
    exit "$status"
  }
  umask 077
  trap cleanup_production_fixture EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  fixture_root="$(mktemp -d /tmp/rustdesk-faillo-doctor.XXXXXXXXXX)" || exit 1
  fixture_id="$(stat -c '%d:%i' -- "$fixture_root")" || exit 1
  fixture_repo="$fixture_root/repository"
  /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null clone \
    --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo" \
    || exit 1
  chmod 0700 "$fixture_repo" || exit 1
  /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null -C "$fixture_repo" \
    checkout --quiet -B master "$EXPECTED_SOURCE_COMMIT" || exit 1
  [ "$(stat -c '%u:%g:%a' -- "$fixture_repo")" = "$(id -u):$(id -g):700" ] \
    || exit 1
  [ "$(/usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null -C "$fixture_repo" \
    symbolic-ref --quiet --short HEAD)" = master ] || exit 1
  [ "$(/usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null -C "$fixture_repo" \
    rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_SOURCE_COMMIT" ] || exit 1
  [ -z "$(/usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null -C "$fixture_repo" \
    status --porcelain=v1 --untracked-files=all)" ] || exit 1
  DIRTY_PROBE_PARENT="$fixture_repo" run_with_dirty_probe doctor \
    "${CLEAN_SCRIPT_ENV[@]}" "$fixture_repo/scripts/build-release.sh" --doctor
)

exercise_dirty_probe_cleanup_failure() (
  local fixture="" fixture_id="" out rc
  cleanup_fixture() {
    local status=$? cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$fixture" ]; then
      [ -n "$fixture_id" ] \
        && [ "$(stat -c '%d:%i' -- "$fixture" 2>/dev/null)" = "$fixture_id" ] \
        && /usr/bin/python3 scripts/verify-private-tree-closure.py --mount-root "$fixture" \
        && chmod 0700 "$fixture" \
        && rm -rf -- "$fixture" \
        && [ ! -e "$fixture" ] && [ ! -L "$fixture" ] \
        || cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || status=1
    exit "$status"
  }
  trap cleanup_fixture EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  fixture="$(umask 077 && mktemp -d "$REPO_ROOT/scripts/.faillo-cleanup-fixture.XXXXXXXXXX")" \
    || exit 1
  fixture_id="$(stat -c '%d:%i' -- "$fixture")" || exit 1
  out="$(DIRTY_PROBE_PARENT="$fixture" run_with_dirty_probe cleanup-failure \
    bash -c 'chmod 0500 "$1"; echo "BUILD-FAILLO: FATAL - expected command failure" >&2; exit 1' \
    _ "$fixture" 2>&1)"; rc=$?
  [ "$rc" -eq 125 ] \
    && printf '%s\n' "$out" | grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:' \
    && ! script_die_output_is_expected "$rc" "$out" "BUILD-FAILLO: FATAL - expected command failure"
)

echo "== build-harness fail-loud proofs (guard level) =="
run_die "SOURCE_DATE_EPOCH unset"          "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('')" 'unset SOURCE_DATE_EPOCH; assert_source_date_epoch'
run_die "SOURCE_DATE_EPOCH non-integer"    "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('notanum')" 'export SOURCE_DATE_EPOCH=notanum; assert_source_date_epoch'
run_die "SOURCE_DATE_EPOCH negative"       "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('-1')" 'export SOURCE_DATE_EPOCH=-1; assert_source_date_epoch'
run_die "SOURCE_DATE_EPOCH leading sign"   "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('+1')" 'export SOURCE_DATE_EPOCH=+1; assert_source_date_epoch'
run_die "SOURCE_DATE_EPOCH non-canonical"  "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('01700000000')" 'export SOURCE_DATE_EPOCH=01700000000; assert_source_date_epoch'
run_ok  "SOURCE_DATE_EPOCH from the pin"   'export SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN"; assert_source_date_epoch'
run_die "verify_sha256 R-B12 sentinel"     "is pinned to the R-B12 sentinel" 'verify_sha256 /etc/hostname "$SHA_PENDING"'
run_die "verify_sha256 missing file"       "verify_sha256: file not found: /online/DOES-NOT-EXIST.tar.xz" 'verify_sha256 /online/DOES-NOT-EXIST.tar.xz 00000000000000000000000000000000000000000000000000000000deadbeef'
run_script_die "verify_online_shas wrong SHA" "SHA-256 mismatch for " run_wrong_online_sha_probe
run_die "verify_online_shas odd arg count" "verify_online_shas: odd argument count" 'verify_online_shas loneName'
run_die "require_cmd missing tool"         "required tool(s) not found: this_tool_does_not_exist_xyz" 'require_cmd this_tool_does_not_exist_xyz'
run_script_die_reached "clean-worktree guard dies dirty" \
  "release build requires a CLEAN worktree traceable to HEAD" "BUILD-FAILLO: DIRTY-PROBE-READY:" \
  run_with_dirty_probe clean-tree bash -c \
  'source scripts/lib.sh >/dev/null 2>&1; load_pins >/dev/null 2>&1; assert_clean_worktree'
if exercise_dirty_probe_cleanup_failure; then
  echo "  PASS  dirty-probe cleanup failure cannot satisfy a fail-loud case"; P=$((P+1))
else
  echo "  FAIL  dirty-probe cleanup failure was accepted or not reconciled"; F=$((F+1))
fi
if exercise_reached_failure_classifier; then
  echo "  PASS  reached-state classifier rejects every incomplete lifecycle result"; P=$((P+1))
else
  echo "  FAIL  reached-state classifier accepted an incomplete lifecycle result"; F=$((F+1))
fi
run_ok  "clean-worktree yields ALLOW_DIRTY" 'export ALLOW_DIRTY_TREE=1; assert_clean_worktree'

echo "== build-harness fail-loud proofs (script level) =="
run_script_ok "release source-gate preflight accepts the fixed scanner" \
  "${CLEAN_SCRIPT_ENV[@]}" bash scripts/verify-release.sh --preflight
run_script_die "verifier scanner rejects an operational error" "verify-scan: scanner failed with status 2" \
  bash -c 'source scripts/verify-scan.sh; verify_scan_capture /dev/null -E "[" /dev/null'
run_script_die "build-release.sh rejects a bad arg" "unknown argument '--nonsense'" \
  "${CLEAN_SCRIPT_ENV[@]}" bash scripts/build-release.sh --nonsense
run_script_ok_marker "verify.sh emits success only after workspace removal" \
  "verify workspace self-test: OK" scripts/verify.sh --self-test-workspace
run_script_die_reached_without_marker "verify.sh rejects a missing recorded workspace" \
  "verify workspace missing self-test: REACHED" \
  "verify: private workspace identity is unavailable or changed" \
  "verify workspace missing self-test: INVALID SUCCESS" \
  scripts/verify.sh --self-test-workspace-missing
run_script_die_reached_without_marker "build-release.sh rejects a missing recorded workspace" \
  "build-release cleanup-missing self-test: REACHED" \
  "build-release: cleanup failed; recorded private workspace state is absent" \
  "build-release cleanup-missing self-test: INVALID SUCCESS" \
  "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh --self-test-cleanup-missing
run_script_ok_marker "pinned offline reset removes current-owner inaccessible generated state" \
  "build-release owner-only reset self-test: OK" \
  "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh --self-test-reset
run_script_ok_marker "exact source-state self-test accepts a clean checkout" \
  "build-release source-state self-test: OK" \
  "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh \
  "--self-test-source-state=$EXPECTED_SOURCE_COMMIT"
run_script_die "exact source-state self-test rejects a different expected commit" \
  "source-state self-test: HEAD changed" \
  "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh \
  --self-test-source-state=0000000000000000000000000000000000000000
run_script_die_reached_without_marker "exact source-state self-test rejects a dirty checkout" \
  "BUILD-FAILLO: DIRTY-PROBE-READY:" \
  "source-state self-test: source tree is not clean, including untracked files" \
  "build-release source-state self-test: OK" \
  run_with_dirty_probe source-state "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh \
  "--self-test-source-state=$EXPECTED_SOURCE_COMMIT"
run_script_die_reached "production release source gate rejects a dirty checkout" \
  "release preflight: source tree is not clean, including untracked files" \
  "BUILD-FAILLO: DIRTY-PROBE-READY:" \
  run_production_dirty_probe
run_script_die "gen-android-keystore refuses to overwrite" "refusing to overwrite existing keystore: scripts/lib.sh" \
  bash scripts/gen-android-keystore.sh scripts/lib.sh /tmp/faillo-nonexistent-pass
run_script_die "publish-github-release rejects a bad flag" "unknown argument '--nonsense'" \
  "${CLEAN_SCRIPT_ENV[@]}" bash scripts/publish-github-release.sh --nonsense

echo
echo "RESULT: $P passed, $F failed"
if [ "$F" -eq 0 ]; then echo "BUILD-FAILLO: GREEN — enumerated guards died loud and pinned offline reset recovery passed"; exit 0
else echo "BUILD-FAILLO: RED — $F proof case(s) failed"; exit 1; fi

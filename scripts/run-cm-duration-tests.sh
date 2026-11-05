#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'CM duration test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/cm-duration
readonly PREFIX=ui_cm_interface::tests::cm_connection_duration_
readonly CASES=(
    "${PREFIX}follows_registry_lifetime"
    "${PREFIX}survives_process_and_admission_delay"
)
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" CM_DURATION
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 10s \
    "$test_executable" "$PREFIX" --list >"$WORK/inventory"
printf '%s: test\n' "${CASES[@]}" >"$WORK/expected"
printf '\n2 tests, 0 benchmarks\n' >>"$WORK/expected"
cmp -- "$WORK/inventory" "$WORK/expected"
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" "$PREFIX" --color never --test-threads=1 --show-output
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'CM_DURATION_ARTIFACT=pass sha256=%s executable=%s tests=2 groups=1 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

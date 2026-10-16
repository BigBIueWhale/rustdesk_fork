#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'CM read-tick test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/cm-read-tick
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" CM_READ_TICK
execution_started=$SECONDS
readonly TEST_PREFIX=ui_cm_interface::tests
for test_name in \
    cm_read_tick_retires_only_the_selected_failed_job_before_next_work \
    cm_read_tick_response_refusal_retains_selected_ownership_until_drain; do
    timeout --signal=TERM --kill-after=5s 20s \
        "$test_executable" "$TEST_PREFIX::$test_name" --exact --color never --test-threads=1 --show-output
    [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
done
printf 'CM_READ_TICK_ARTIFACT=pass sha256=%s executable=%s tests=2 groups=2 unchanged=before-between-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

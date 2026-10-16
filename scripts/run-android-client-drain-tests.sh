#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Android client-drain test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/android-client-drain
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" ANDROID_CLIENT_DRAIN
execution_started=$SECONDS
readonly TEST_PREFIX=flutter::mobile_session_lifecycle_tests
for test_name in \
    android_lifecycle_retirement_is_nonblocking_and_replacement_waits_for_exact_drain \
    android_lifecycle_transition_does_not_wait_for_mobile_replacement_drain; do
    timeout --signal=TERM --kill-after=5s 10s \
        "$test_executable" "$TEST_PREFIX::$test_name" --exact --color never --test-threads=1
    [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
done
printf 'ANDROID_CLIENT_DRAIN_ARTIFACT=pass sha256=%s executable=%s tests=2 groups=2 unchanged=before-between-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

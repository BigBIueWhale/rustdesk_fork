#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Remote restart-test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/remote-restart
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" REMOTE_RESTART
execution_started=$SECONDS
execution_status=0
timeout --signal=TERM --kill-after=5s 25s \
    "$test_executable" flutter::restart_tests:: --color never --test-threads=1 \
    || execution_status=$?
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'REMOTE_RESTART_ARTIFACT=complete sha256=%s executable=%s tests=9 exit_code=%s unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$execution_status" "$((SECONDS - execution_started))"
exit "$execution_status"

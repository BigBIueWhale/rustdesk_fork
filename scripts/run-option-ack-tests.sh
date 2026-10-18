#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Option acknowledgement test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/option-ack
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" OPTION_ACK
execution_started=$SECONDS
execution_status=0
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" ipc::test::ordinary_option_ack_waits_for_persistence \
    --exact --color never --test-threads=1 --show-output || execution_status=$?
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'OPTION_ACK_ARTIFACT_AFTER=observed sha256=%s tests=1 exit_code=%s unchanged=before-after\n' \
    "$artifact_sha" "$execution_status"
[ "$execution_status" -eq 0 ] || exit "$execution_status"
printf 'OPTION_ACK_ARTIFACT=pass sha256=%s executable=%s tests=1 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'File-receive caller-test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/file-receive-caller
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" FILE_RECEIVE_PARENT
execution_started=$SECONDS
for group in client::io_loop::tests::r_s11fi_ ui_cm_interface::tests::r_s11fi_ \
    flutter_ffi::file_job_id_tests::; do
    timeout --signal=TERM --kill-after=5s 30s \
        "$test_executable" "$group" --color never --test-threads=1
    [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
done
printf 'FILE_RECEIVE_PARENT_ARTIFACT=pass sha256=%s executable=%s tests=9 groups=3 unchanged=before-between-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

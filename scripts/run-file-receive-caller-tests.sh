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
[ "$(sha256sum scripts/fixtures/cm-owner-before-cancel.rs | cut -d ' ' -f 1)" = \
  20420e74f04c3f443d6930651b6bf37a592a730c16d87caa01c5ec5a4dc3d71d ] \
    || { echo 'CM owner counterexample differs from the retained source function' >&2; exit 1; }
build_linux_parent_test "$WORK" FILE_RECEIVE_PARENT
execution_started=$SECONDS
for group in client::io_loop::tests::r_s11fi_ ui_cm_interface::tests::r_s11fi_ \
    flutter_ffi::file_job_id_tests:: server::connection::cm_startup_lifecycle_tests::; do
    timeout --signal=TERM --kill-after=5s 30s \
        "$test_executable" "$group" --color never --test-threads=1
    [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
done
printf 'CM_OWNER_BEFORE=pass source=c16ec444530f001145395c3d4974d2d5d57df960 function_sha256=a1973487bd83eed992b357615b7024bf4e96fe243250e668e15dd1c0f355be53 fixture_sha256=20420e74f04c3f443d6930651b6bf37a592a730c16d87caa01c5ec5a4dc3d71d\n'
printf 'FILE_RECEIVE_PARENT_ARTIFACT=pass sha256=%s executable=%s tests=21 groups=4 unchanged=before-between-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Local file-listing test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/local-file-listing
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" LOCAL_FILE_LISTING
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" flutter_ffi::local_file_listing_tests:: --color never --test-threads=1 --show-output
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'LOCAL_FILE_LISTING_ARTIFACT=pass sha256=%s executable=%s tests=3 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

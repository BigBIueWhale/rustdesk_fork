#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Viewer video test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/viewer-video
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" VIEWER_VIDEO
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" client::video_handler_tests:: \
    --color never --test-threads=1
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIEWER_VIDEO_ARTIFACT=pass sha256=%s executable=%s tests=4 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

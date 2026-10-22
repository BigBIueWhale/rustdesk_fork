#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'VPX test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/video-vpx
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
python3 -I -S - <<'PY'
import errno
import socket
with socket.socket() as canary:
    try:
        canary.connect(("192.0.2.1", 9))
    except OSError as error:
        if error.errno != errno.ENETUNREACH:
            raise
    else:
        raise SystemExit("VPX offline canary connected")
print("R-B10 canary: build confirmed network-isolated (offline compile stage).")
PY
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" VIDEO_VPX
execution_started=$SECONDS
execution_status=0
for test_module in common::vpxcodec::tests:: common::convert::tests::; do
    module_status=0
    timeout --signal=TERM --kill-after=5s 30s \
        "$test_executable" "$test_module" \
        --color never --test-threads=1 --show-output --skip native_x11_capture_ \
        || module_status=$?
    if [ "$execution_status" -eq 0 ]; then execution_status=$module_status; fi
done
native_status=0
python3 -B -I -S /source/scripts/run-screenshot-x11-tests.py "$test_executable" || native_status=$?
if [ "$execution_status" -eq 0 ]; then execution_status=$native_status; fi
allocation_status=0
python3 -B -I -S /source/scripts/run-decoded-image-allocation-tests.py "$test_executable" || allocation_status=$?
if [ "$execution_status" -eq 0 ]; then execution_status=$allocation_status; fi
metadata_status=0
python3 -B -I -S /source/scripts/run-capture-metadata-tests.py "$test_executable" || metadata_status=$?
if [ "$execution_status" -eq 0 ]; then execution_status=$metadata_status; fi
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIDEO_VPX_ARTIFACT_AFTER=observed sha256=%s tests=23 exit_code=%s unchanged=before-after\n' \
    "$artifact_sha" "$execution_status"
[ "$execution_status" -eq 0 ] || exit "$execution_status"
printf 'VIDEO_VPX_ARTIFACT=pass sha256=%s executable=%s tests=23 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

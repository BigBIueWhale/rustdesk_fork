#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Video QoS controller test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/video-qos-controller
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
        raise SystemExit("Video QoS controller offline canary connected")
print("R-B10 canary: build confirmed network-isolated (offline compile stage).")
PY
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" VIDEO_QOS_CONTROLLER
execution_started=$SECONDS
execution_status=0
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" server:: \
    --color never --test-threads=1 --show-output || execution_status=$?
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIDEO_QOS_CONTROLLER_ARTIFACT_AFTER=observed sha256=%s tests=24 exit_code=%s unchanged=before-after\n' \
    "$artifact_sha" "$execution_status"
[ "$execution_status" -eq 0 ] || exit "$execution_status"
printf 'VIDEO_QOS_CONTROLLER_ARTIFACT=pass sha256=%s executable=%s tests=24 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Viewer credential-test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/viewer-credentials
[ "$(stat -c '%u:%g:%a:%h:%s' /etc/machine-id)" = 1000:1000:400:1:33 ] \
    && [ "$(cat /etc/machine-id)" = 727573746465736b2d76696577657231 ] \
    || { echo 'Viewer credential fixture machine identity differs' >&2; exit 1; }
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" VIEWER_CREDENTIAL
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 25s \
    "$test_executable" client::tests::r_s11hj_viewer_ --color never --test-threads=1
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
timeout --signal=TERM --kill-after=5s 25s \
    "$test_executable" client::tests::r_p14 --color never --test-threads=1
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
timeout --signal=TERM --kill-after=5s 25s \
    "$test_executable" flutter::viewer_credential_bridge_tests::explicit_password_survives_all_session_factories_and_exact_retirement \
    --exact --color never --test-threads=1
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
[ "$(cat /etc/machine-id)" = 727573746465736b2d76696577657231 ]
printf 'VIEWER_CREDENTIAL_ARTIFACT=pass sha256=%s executable=%s tests=10 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"

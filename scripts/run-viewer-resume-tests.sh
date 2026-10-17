#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Viewer resume-test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/viewer-resume
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
source /source/scripts/linux-parent-test-build.sh
build_linux_parent_test "$WORK" VIEWER_RESUME
execution_started=$SECONDS
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" client::io_loop::file_resume_tests:: --color never --test-threads=1
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" port_forward::tests:: --color never --test-threads=1
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" ui_session_interface::port_forward_mapping_tests:: --color never --test-threads=1
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" cli_command::tests:: --color never --test-threads=1
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" common::tests::retired_server_key_option_remains_pinned_empty \
    --exact --color never --test-threads=1
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIEWER_RESUME_ARTIFACT=pass sha256=%s executable=%s tests=22 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"
printf 'VIEWER_RESUME_CLI_CHECK=started target=rustdesk features=linux-pkg-config,cli budget_seconds=120\n'
if ! timeout --signal=TERM --kill-after=5s 120s \
    cargo check --offline --locked --bin rustdesk --features linux-pkg-config,cli \
    --color never >"$WORK/cli-check.log" 2>&1; then
    tail -c 16000 "$WORK/cli-check.log" >&2
    exit 1
fi
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIEWER_RESUME_CLI_CHECK=pass target=rustdesk features=linux-pkg-config,cli runtime=unexecuted\n'

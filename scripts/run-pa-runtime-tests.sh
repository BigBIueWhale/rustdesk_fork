#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -ge 1 ] && [ "$#" -le 2 ] && [ "$1" = /inputs/pa-runtime.tar.gz ] \
    && { [ "$#" -eq 1 ] || [[ "$2" = --product-pair || "$2" = --playback ]]; } \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'PulseAudio runtime test entry authority differs' >&2; exit 1; }

source /source/scripts/pa-runtime-fixture.sh
readonly WORK=$PA_FIXTURE_WORK
readonly PACTL=$PA_FIXTURE_PACTL
if [ "${2:-}" = --product-pair ]; then
    [ "${HOME:-}" = /tmp/home ] \
        || { echo 'PulseAudio product-pair HOME authority differs' >&2; exit 1; }
    mkdir -m 0700 -- "$HOME"
fi
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    pa_fixture_stop || { [ "$status" -ne 0 ] || status=1; }
    if [ "$status" -ne 0 ] && [ -f "$WORK/pulseaudio.log" ]; then
        tail -n 80 "$WORK/pulseaudio.log" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pa_fixture_prepare "$1"
export "${PA_FIXTURE_ENV[@]}"
if [ "${2:-}" != --product-pair ]; then
    export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
    source /source/scripts/linux-parent-test-build.sh
    build_linux_parent_test "$WORK" PA_RUNTIME
fi
if [ "${2:-}" = --playback ]; then
    pa_fixture_start silent
else
    pa_fixture_start sine
fi
if [ "${2:-}" = --product-pair ]; then
    RUSTDESK_PA_PRODUCT_PAIR=1 \
        /bin/bash --noprofile --norc /source/scripts/smoke-server-stage.sh video-pipeline
else
    export RUSTDESK_PA_NATIVE_TEST=1 RUSTDESK_PA_NATIVE_PACTL="$PACTL" \
        RUSTDESK_PA_NATIVE_SINE_MODULE="${PA_FIXTURE_SINE_MODULE:-}"
    execution_started=$SECONDS
    execution_deadline=$((SECONDS + 120))
    run_tests() {
        [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ] || return 1
        local remaining=$((execution_deadline - SECONDS))
        [ "$remaining" -gt 0 ] || { echo 'PulseAudio scenario budget exhausted' >&2; exit 1; }
        local status=0
        timeout --signal=TERM --kill-after=5s "${remaining}s" \
            "$test_executable" "$@" --color never --test-threads=1 || status=$?
        [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ] || return 1
        return "$status"
    }
    if [ "${2:-}" = --playback ]; then
        before_status=0
        run_tests client::audio_playback_before::audio_playback_tests:: --ignored --show-output \
            >"$WORK/playback-before.out" 2>&1 || before_status=$?
        cat "$WORK/playback-before.out"
        [ "$before_status" -eq 101 ] \
            && grep -Fq 'test result: FAILED. 0 passed; 2 failed; 0 ignored;' "$WORK/playback-before.out" \
            && grep -Fq 'failed playback must release its native connection' "$WORK/playback-before.out" \
            && grep -Fq 'failed playback must release its decoder' "$WORK/playback-before.out" \
            || { echo 'native old playback did not reproduce both resource failures' >&2; exit 1; }
        printf 'PA_PLAYBACK_BASELINE=pass old_exit=101 failed_tests=2 block_sha256=402f1f1ec861a8e9fac810e30072f70a6fbeffa0d2d0a3f62c2c4b366d7d4db5\n'
        run_tests client::audio_playback_tests:: --ignored --show-output
        printf 'PA_PLAYBACK_ARTIFACT=pass sha256=%s executable=%s baseline_failed=2 corrected_passed=2 unchanged=before-between-after execution_seconds=%s\n' \
            "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"
    else
    run_tests r_s11iu_pa_capture_
    run_tests ipc::test::linux_pulse_audio_channel_uses_closed_bounded_protocol
    run_tests server::service::pa_dispatch_tests::
    run_tests ipc::pulse_audio::tests:: \
        --skip real_
    run_tests ipc::pulse_audio::tests::real_ --ignored --show-output
    printf 'PA_RUNTIME_ARTIFACT=pass sha256=%s executable=%s groups=5 unchanged=before-between-after execution_seconds=%s\n' \
        "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"
    fi
fi

pa_fixture_stop
if [ "${2:-}" = --product-pair ]; then
    printf 'PA_RUNTIME_PRODUCT_PAIR=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 network=none uid=1000 cleanup=joined\n'
elif [ "${2:-}" = --playback ]; then
    printf 'PA_PLAYBACK_NATIVE=pass daemon=16.1 playback=null-sink network=none uid=1000 cleanup=joined\n'
else
    printf 'PA_RUNTIME_NATIVE=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 revocation=after-unload same_uid_stolen_token=refused network=none uid=1000 cleanup=joined\n'
fi

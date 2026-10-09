#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -ge 1 ] && [ "$#" -le 2 ] && [ "$1" = /inputs/pa-runtime.tar.gz ] \
    && { [ "$#" -eq 1 ] || [ "$2" = --product-pair ]; } \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'PulseAudio runtime test entry authority differs' >&2; exit 1; }

readonly WORK=/tmp/pa-runtime
readonly PACKAGE_ROOT=$WORK/packages
readonly IMAGE_ROOT=$WORK/root
readonly RUNTIME=$WORK/runtime
readonly MODULES=$IMAGE_ROOT/usr/lib/pulse-16.1+dfsg1/modules
readonly DAEMON=$IMAGE_ROOT/usr/bin/pulseaudio
readonly PACTL=$IMAGE_ROOT/usr/bin/pactl
readonly PACAT=$IMAGE_ROOT/usr/bin/pacat
if [ "$#" -eq 2 ]; then
    [ "${HOME:-}" = /tmp/home ] \
        || { echo 'PulseAudio product-pair HOME authority differs' >&2; exit 1; }
    mkdir -m 0700 -- "$HOME"
fi
mkdir -m 0700 -- "$WORK" "$PACKAGE_ROOT" "$IMAGE_ROOT" "$RUNTIME"
python3 -I -S /source/scripts/verify-pa-runtime-candidate.py \
    --archive "$1" --output "$PACKAGE_ROOT" \
    --sha256 "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" \
    --size "$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" \
    --manifest-sha256 "$PA_RUNTIME_CANDIDATE_MANIFEST_SHA256" \
    --base "$DEV_CHECK_IMAGE_ID" \
    --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
    --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
    --version "$PA_RUNTIME_PULSEAUDIO_VERSION" \
    --pa-sha256 "$PA_RUNTIME_PULSEAUDIO_SHA256" \
    --pa-size "$PA_RUNTIME_PULSEAUDIO_SIZE"

packages=("$PACKAGE_ROOT"/*.deb)
[ "${#packages[@]}" -eq 40 ] || exit 1
for package in "${packages[@]}"; do
    dpkg-deb --extract "$package" "$IMAGE_ROOT"
done
[ -x "$DAEMON" ] && [ -x "$PACTL" ] && [ -x "$PACAT" ] \
    && [ -f "$MODULES/module-native-protocol-unix.so" ] \
    && [ -f "$MODULES/module-null-sink.so" ] \
    && [ -f "$MODULES/module-sine.so" ] \
    || { echo 'PulseAudio runtime executable or modules are absent' >&2; exit 1; }

export LD_LIBRARY_PATH="$IMAGE_ROOT/usr/lib/x86_64-linux-gnu/pulseaudio:$IMAGE_ROOT/usr/lib/x86_64-linux-gnu:$IMAGE_ROOT/lib/x86_64-linux-gnu:$MODULES"
export PULSE_DLPATH="$MODULES"
export XDG_RUNTIME_DIR="$RUNTIME"
export PULSE_RUNTIME_PATH="$RUNTIME/pulse"
export PULSE_SERVER="unix:$PULSE_RUNTIME_PATH/native"
export PULSE_CLIENTCONFIG="$WORK/client.conf"
printf 'autospawn = no\n' >"$PULSE_CLIENTCONFIG"
daemon_pid=
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$daemon_pid" ]; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ] && [ -f "$WORK/pulseaudio.log" ]; then
        tail -n 80 "$WORK/pulseaudio.log" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$#" -eq 1 ]; then
    printf 'PA_RUNTIME_BUILD=started target=linux-libtest budget_seconds=600\n'
    build_started=$SECONDS
    timeout --signal=TERM --kill-after=5s 600s \
        cargo test --offline --locked --lib --features linux-pkg-config --no-run \
        --message-format=json-render-diagnostics --color never >"$WORK/build.json"
    test_executable="$(python3 -I -S - "$WORK/build.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], 'rb') as stream:
    output = stream.read(4 * 1024 * 1024 + 1)
if len(output) > 4 * 1024 * 1024:
    sys.exit('PulseAudio Cargo metadata exceeds 4 MiB')
artifacts = []
finished = []
for line in output.splitlines():
    if not line.startswith(b'{'):
        continue
    message = json.loads(line)
    if message.get('reason') == 'build-finished':
        finished.append(message.get('success'))
    if (message.get('reason') == 'compiler-artifact'
            and message.get('manifest_path') == '/source/Cargo.toml'
            and message.get('target', {}).get('name') == 'librustdesk'
            and message.get('target', {}).get('src_path') == '/source/src/lib.rs'
            and message.get('profile', {}).get('test') is True):
        artifacts.append(message.get('executable'))
if finished != [True] or len(artifacts) != 1 or not isinstance(artifacts[0], str):
    sys.exit('PulseAudio build lacks one exact completed library test artifact')
if not re.fullmatch(r'/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}', artifacts[0]):
    sys.exit('PulseAudio test artifact is outside its private target directory')
print(artifacts[0])
PY
)"
    [ -f "$test_executable" ] && [ ! -L "$test_executable" ] \
        && [ -x "$test_executable" ] \
        && [ "$(stat -c '%u:%g:%h' -- "$test_executable")" = 1000:1000:1 ] \
        || { echo 'PulseAudio test artifact metadata differs' >&2; exit 1; }
    artifact_sha="$(sha256sum "$test_executable" | cut -d ' ' -f 1)"
    [[ "$artifact_sha" =~ ^[0-9a-f]{64}$ ]]
    printf 'PA_RUNTIME_BUILD=pass seconds=%s artifact_sha256=%s\n' \
        "$((SECONDS - build_started))" "$artifact_sha"
fi

"$DAEMON" -n --daemonize=no --exit-idle-time=-1 --log-target=stderr \
    --dl-search-path="$MODULES" \
    --load='module-native-protocol-unix' \
    --load='module-null-sink sink_name=rd_pa_test rate=48000 channels=2' \
    >"$WORK/pulseaudio.log" 2>&1 &
daemon_pid=$!
ready=0
for _ in $(seq 1 50); do
    if [ -S "$PULSE_RUNTIME_PATH/native" ] \
       && "$PACTL" info >"$WORK/pactl-info" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$daemon_pid" 2>/dev/null || break
    sleep 0.1
done
[ "$ready" -eq 1 ] \
    || { echo 'private PulseAudio daemon did not become ready' >&2; exit 1; }
"$PACTL" list short sources >"$WORK/sources"
grep -Fq 'rd_pa_test.monitor' "$WORK/sources" \
    || { echo 'private PulseAudio monitor source is absent' >&2; exit 1; }
sine_module="$("$PACTL" load-module module-sine sink=rd_pa_test frequency=440)"
[[ "$sine_module" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'private PulseAudio sine source was not admitted' >&2; exit 1; }
"$PACTL" suspend-sink rd_pa_test 0
for _ in $(seq 1 20); do
    "$PACTL" list short sink-inputs >"$WORK/sink-inputs"
    [ -s "$WORK/sink-inputs" ] && break
    sleep 0.1
done
[ -s "$WORK/sink-inputs" ] \
    || { echo 'private PulseAudio sine sink input is absent' >&2; exit 1; }
monitor_status=0
timeout 5 "$PACAT" --record --device=rd_pa_test.monitor --raw \
    --format=float32le --rate=48000 --channels=2 \
    >"$WORK/monitor-sample" 2>"$WORK/pacat.log" || monitor_status=$?
[ "$monitor_status" -eq 0 ] || [ "$monitor_status" -eq 124 ] \
    || { tail -n 40 "$WORK/pacat.log" >&2; echo 'private monitor probe failed' >&2; exit 1; }
sample_size="$(stat -c '%s' -- "$WORK/monitor-sample")"
[ "$sample_size" -ge 3840 ] \
    || {
        printf 'private monitor probe produced no complete frame: bytes=%s status=%s\n' "$sample_size" "$monitor_status" >&2
        "$PACTL" list short sinks >&2 || true
        "$PACTL" list short sources >&2 || true
        "$PACTL" list short sink-inputs >&2 || true
        tail -n 40 "$WORK/pacat.log" >&2
        exit 1
    }
cmp_status=0
cmp -s -n "$sample_size" "$WORK/monitor-sample" /dev/zero || cmp_status=$?
[ "$cmp_status" -eq 1 ] \
    || { echo 'private monitor probe produced no nonzero frame' >&2; exit 1; }
printf 'PA_RUNTIME_MONITOR=pass source=rd_pa_test.monitor signal=sine440 probe=pacat-native\n'
if [ "$#" -eq 2 ]; then
    RUSTDESK_PA_PRODUCT_PAIR=1 \
        /bin/bash --noprofile --norc /source/scripts/smoke-server-stage.sh video-pipeline
else
    export RUSTDESK_PA_NATIVE_TEST=1 RUSTDESK_PA_NATIVE_PACTL="$PACTL" \
        RUSTDESK_PA_NATIVE_SINE_MODULE="$sine_module"
    execution_started=$SECONDS
    execution_deadline=$((SECONDS + 120))
    run_tests() {
        [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
        local remaining=$((execution_deadline - SECONDS))
        [ "$remaining" -gt 0 ] || { echo 'PulseAudio scenario budget exhausted' >&2; exit 1; }
        timeout --signal=TERM --kill-after=5s "${remaining}s" \
            "$test_executable" "$@" --color never --test-threads=1
        [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
    }
    run_tests r_s11iu_pa_capture_
    run_tests ipc::test::linux_pulse_audio_channel_uses_closed_bounded_protocol
    run_tests server::service::pa_dispatch_tests::
    run_tests ipc::pulse_audio::tests:: \
        --skip real_monitor_capture_revokes_after_audio_stops \
        --skip real_kernel_pa_admission_refuses_same_uid_child_with_token
    run_tests ipc::pulse_audio::tests::real_ --ignored --show-output
    printf 'PA_RUNTIME_ARTIFACT=pass sha256=%s executable=%s groups=5 unchanged=before-between-after execution_seconds=%s\n' \
        "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"
fi

kill -TERM "$daemon_pid"
wait "$daemon_pid"
daemon_pid=
[ ! -S "$PULSE_RUNTIME_PATH/native" ] \
    || { echo 'private PulseAudio socket survived daemon shutdown' >&2; exit 1; }
if [ "$#" -eq 2 ]; then
    printf 'PA_RUNTIME_PRODUCT_PAIR=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 network=none uid=1000 cleanup=joined\n'
else
    printf 'PA_RUNTIME_NATIVE=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 revocation=after-unload same_uid_stolen_token=refused network=none uid=1000 cleanup=joined\n'
fi

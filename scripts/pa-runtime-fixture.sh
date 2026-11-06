# Shared private PulseAudio fixture. Callers own the EXIT trap and join the daemon.
readonly PA_FIXTURE_WORK=/tmp/pa-runtime
readonly PA_FIXTURE_ROOT=$PA_FIXTURE_WORK/root
readonly PA_FIXTURE_MODULES=$PA_FIXTURE_ROOT/usr/lib/pulse-16.1+dfsg1/modules
readonly PA_FIXTURE_PACTL=$PA_FIXTURE_ROOT/usr/bin/pactl
readonly PA_FIXTURE_SOCKET=$PA_FIXTURE_WORK/runtime/pulse/native
readonly -a PA_FIXTURE_ENV=(
    "LD_LIBRARY_PATH=$PA_FIXTURE_ROOT/usr/lib/x86_64-linux-gnu/pulseaudio:$PA_FIXTURE_ROOT/usr/lib/x86_64-linux-gnu:$PA_FIXTURE_ROOT/lib/x86_64-linux-gnu:$PA_FIXTURE_MODULES"
    "PULSE_DLPATH=$PA_FIXTURE_MODULES"
    "XDG_RUNTIME_DIR=$PA_FIXTURE_WORK/runtime"
    "PULSE_RUNTIME_PATH=$PA_FIXTURE_WORK/runtime/pulse"
    "PULSE_SERVER=unix:$PA_FIXTURE_SOCKET"
    "PULSE_CLIENTCONFIG=$PA_FIXTURE_WORK/client.conf"
)
PA_FIXTURE_PID=
PA_FIXTURE_START=
PA_FIXTURE_SINE_MODULE=

pa_fixture_prepare() {
    [ "$#" -eq 1 ] && [ "$1" = /inputs/pa-runtime.tar.gz ] \
        && [ "$(id -u):$(id -g)" = 1000:1000 ] || return 1
    mkdir -m 0700 -- "$PA_FIXTURE_WORK" "$PA_FIXTURE_WORK/packages" \
        "$PA_FIXTURE_ROOT" "$PA_FIXTURE_WORK/runtime" || return 1
    python3 -I -S /source/scripts/verify-pa-runtime-candidate.py \
        --archive "$1" --output "$PA_FIXTURE_WORK/packages" \
        --sha256 "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" \
        --size "$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" \
        --manifest-sha256 "$PA_RUNTIME_CANDIDATE_MANIFEST_SHA256" \
        --base "$DEV_CHECK_IMAGE_ID" \
        --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
        --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
        --version "$PA_RUNTIME_PULSEAUDIO_VERSION" \
        --pa-sha256 "$PA_RUNTIME_PULSEAUDIO_SHA256" \
        --pa-size "$PA_RUNTIME_PULSEAUDIO_SIZE" || return 1
    local package
    local -a packages=("$PA_FIXTURE_WORK/packages"/*.deb)
    [ "${#packages[@]}" -eq 40 ] || return 1
    for package in "${packages[@]}"; do
        dpkg-deb --extract "$package" "$PA_FIXTURE_ROOT" || return 1
    done
    [ -x "$PA_FIXTURE_ROOT/usr/bin/pulseaudio" ] && [ -x "$PA_FIXTURE_PACTL" ] \
        && [ -x "$PA_FIXTURE_ROOT/usr/bin/pacat" ] \
        && [ -f "$PA_FIXTURE_MODULES/module-native-protocol-unix.so" ] \
        && [ -f "$PA_FIXTURE_MODULES/module-null-sink.so" ] \
        && [ -f "$PA_FIXTURE_MODULES/module-sine.so" ] || return 1
    printf 'autospawn = no\ncookie-file = %s/cookie\n' "$PA_FIXTURE_WORK" \
        >"$PA_FIXTURE_WORK/client.conf"
}

pa_fixture_pactl() {
    timeout --signal=TERM --kill-after=2s 5s \
        env "${PA_FIXTURE_ENV[@]}" "$PA_FIXTURE_PACTL" "$@"
}

pa_fixture_start() {
    [ "$#" -eq 1 ] && [[ "$1" = sine || "$1" = silent ]] \
        && [ -z "$PA_FIXTURE_PID" ] || return 1
    env "${PA_FIXTURE_ENV[@]}" "$PA_FIXTURE_ROOT/usr/bin/pulseaudio" \
        -n --daemonize=no --exit-idle-time=-1 --log-target=stderr \
        --dl-search-path="$PA_FIXTURE_MODULES" \
        --load="module-native-protocol-unix auth-cookie=$PA_FIXTURE_WORK/cookie" \
        --load='module-null-sink sink_name=rd_pa_test rate=48000 channels=2' \
        >"$PA_FIXTURE_WORK/pulseaudio.log" 2>&1 &
    PA_FIXTURE_PID=$!
    PA_FIXTURE_START="$(/bin/bash /source/scripts/smoke-ready.sh --identity "$PA_FIXTURE_PID")" \
        || return 1
    local ready=0 attempt
    for attempt in $(seq 1 50); do
        if [ -S "$PA_FIXTURE_SOCKET" ] \
           && pa_fixture_pactl info >"$PA_FIXTURE_WORK/pactl-info" 2>/dev/null; then
            ready=1
            break
        fi
        kill -0 "$PA_FIXTURE_PID" 2>/dev/null || break
        sleep 0.1
    done
    [ "$ready" -eq 1 ] || { echo 'private PulseAudio daemon did not become ready' >&2; return 1; }
    pa_fixture_pactl list short sources >"$PA_FIXTURE_WORK/sources" || return 1
    grep -Fq 'rd_pa_test.monitor' "$PA_FIXTURE_WORK/sources" || return 1
    [ "$1" = sine ] || return 0
    PA_FIXTURE_SINE_MODULE="$(pa_fixture_pactl load-module module-sine sink=rd_pa_test frequency=440)" \
        || return 1
    [[ "$PA_FIXTURE_SINE_MODULE" =~ ^[1-9][0-9]*$ ]] || return 1
    pa_fixture_pactl suspend-sink rd_pa_test 0 || return 1
    local monitor_status=0 sample_size cmp_status=0
    timeout --signal=TERM --kill-after=2s 5s env "${PA_FIXTURE_ENV[@]}" \
        "$PA_FIXTURE_ROOT/usr/bin/pacat" --record --device=rd_pa_test.monitor --raw \
        --format=float32le --rate=48000 --channels=2 \
        >"$PA_FIXTURE_WORK/monitor-sample" 2>"$PA_FIXTURE_WORK/pacat.log" || monitor_status=$?
    [ "$monitor_status" -eq 0 ] || [ "$monitor_status" -eq 124 ] \
        || { tail -n 40 "$PA_FIXTURE_WORK/pacat.log" >&2; return 1; }
    sample_size="$(stat -c '%s' -- "$PA_FIXTURE_WORK/monitor-sample")" || return 1
    [ "$sample_size" -ge 3840 ] \
        || { echo 'private monitor probe produced no complete frame' >&2; return 1; }
    cmp -s -n "$sample_size" "$PA_FIXTURE_WORK/monitor-sample" /dev/zero || cmp_status=$?
    [ "$cmp_status" -eq 1 ] \
        || { echo 'private monitor probe produced no nonzero frame' >&2; return 1; }
    printf 'PA_RUNTIME_MONITOR=pass source=rd_pa_test.monitor signal=sine440 probe=pacat-native\n'
}

pa_fixture_stop() {
    local status=0
    if [ -n "$PA_FIXTURE_PID" ]; then
        /bin/bash /source/scripts/smoke-ready.sh --stop "$PA_FIXTURE_PID" "$PA_FIXTURE_START" \
            || status=1
        wait "$PA_FIXTURE_PID" || status=1
        PA_FIXTURE_PID=
        PA_FIXTURE_START=
        [ ! -S "$PA_FIXTURE_SOCKET" ] || status=1
    fi
    return "$status"
}

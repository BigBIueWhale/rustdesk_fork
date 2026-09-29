#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'Android emulator boot smoke: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || [ "$#" -eq 5 ] || [ "$#" -eq 6 ] \
    || [ "$#" -eq 7 ] \
    || fail 'usage: smoke-android-emulator-boot.sh EMULATOR_ZIP SYSTEM_IMAGE_ZIP ADB WORK_ROOT [RUNTIME_TEST_APK [launch|recents|lifecycle|peer-lifecycle [RECENTS_GESTURE_JAR]]]'
readonly EMULATOR_ZIP=$1
readonly SYSTEM_IMAGE_ZIP=$2
readonly INPUT_ADB=$3
readonly WORK_ROOT=$4
readonly RUNTIME_TEST_APK=${5:-}
readonly APP_SCENARIO=${6:-launch}
readonly RECENTS_GESTURE_JAR=${7:-}
if [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = peer-lifecycle ]; then
    readonly WORKLOAD=app-peer-lifecycle
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = lifecycle ]; then
    readonly WORKLOAD=app-lifecycle
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = recents ]; then
    readonly WORKLOAD=app-recents
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=app
elif [ -z "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=boot
else
    fail 'the Android app scenario differs from launch, recents, lifecycle, or peer-lifecycle'
fi
EMULATOR_GRPC_ARGS=()
if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    EMULATOR_GRPC_ARGS=(-grpc 8554)
fi
readonly -a EMULATOR_GRPC_ARGS
readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly RUN_UID="$(id -u)"
readonly RUN_GID="$(id -g)"
[ "$RUN_UID:$RUN_GID" = 1000:1000 ] \
    || fail 'the emulator workload requires numeric uid/gid 1000:1000'
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-recents ] \
   || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ "$WORK_ROOT" = /tmp/android-emulator-app ] \
        || fail 'the emulator app work root differs from the fixed private tmpfs path'
else
    [ "$WORK_ROOT" = /tmp/android-emulator-boot ] \
        || fail 'the emulator boot work root differs from the fixed private tmpfs path'
fi
[ ! -e "$WORK_ROOT" ] && [ ! -L "$WORK_ROOT" ] \
    || fail 'the emulator work root is already occupied'

verify_regular_input() {
    local path=$1 mode=$2 size=$3 digest=$4 label=$5
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
             "1000:1000:$mode:1:$size" ] \
        || fail "$label metadata differs"
    [ "$(sha256sum "$path" | awk '{ print $1 }')" = "$digest" ] \
        || fail "$label digest differs"
}

verify_regular_input \
    "$EMULATOR_ZIP" 400 "$SIZE_ANDROID_EMULATOR_LINUX_X64" \
    "$SHA256_ANDROID_EMULATOR_LINUX_X64" 'Android emulator archive'
verify_regular_input \
    "$SYSTEM_IMAGE_ZIP" 400 "$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" \
    "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" 'Android system-image archive'
verify_regular_input \
    "$INPUT_ADB" 555 "$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" \
    "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" 'Android adb executable'
APK_SHA256=
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-recents ] \
   || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ -f "$RUNTIME_TEST_APK" ] && [ ! -L "$RUNTIME_TEST_APK" ] \
        || fail 'runtime-test APK is absent or ambiguous'
    apk_size="$(stat -c '%s' -- "$RUNTIME_TEST_APK")"
    case "$apk_size" in
        ''|*[!0-9]*) fail 'runtime-test APK size is malformed' ;;
    esac
    [ "$apk_size" -ge 1048576 ] && [ "$apk_size" -le 2147483648 ] \
        || fail 'runtime-test APK size is outside the admitted range'
    [ "$(stat -c '%u:%g:%a:%h' -- "$RUNTIME_TEST_APK")" = 1000:1000:400:1 ] \
        || fail 'runtime-test APK metadata differs'
    APK_SHA256="$(sha256sum "$RUNTIME_TEST_APK" | awk '{ print $1 }')"
    [[ "$APK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'runtime-test APK digest is malformed'
    readonly APK_SHA256 apk_size
fi
RECENTS_GESTURE_SHA256=
if [ "$WORKLOAD" = app-recents ] || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ -f "$RECENTS_GESTURE_JAR" ] && [ ! -L "$RECENTS_GESTURE_JAR" ] \
        || fail 'the Recents gesture driver is absent or ambiguous'
    gesture_size="$(stat -c '%s' -- "$RECENTS_GESTURE_JAR")"
    case "$gesture_size" in
        ''|*[!0-9]*) fail 'the Recents gesture driver size is malformed' ;;
    esac
    [ "$gesture_size" -ge 512 ] && [ "$gesture_size" -le 1048576 ] \
        || fail 'the Recents gesture driver size is outside the admitted range'
    [ "$(stat -c '%u:%g:%a:%h' -- "$RECENTS_GESTURE_JAR")" = \
      1000:1000:400:1 ] \
        || fail 'the Recents gesture driver metadata differs'
    RECENTS_GESTURE_SHA256="$(sha256sum "$RECENTS_GESTURE_JAR" | awk '{ print $1 }')"
    [[ "$RECENTS_GESTURE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'the Recents gesture driver digest is malformed'
    readonly RECENTS_GESTURE_SHA256 gesture_size
elif [ -n "$RECENTS_GESTURE_JAR" ]; then
    fail 'the launch-only Android scenario received a Recents gesture driver'
fi

mkdir -m 0700 -- "$WORK_ROOT"
readonly SDK_ROOT=$WORK_ROOT/sdk
readonly HOME_ROOT=$WORK_ROOT/home
readonly AVD_HOME=$HOME_ROOT/.android/avd
readonly SYSTEM_ROOT=$SDK_ROOT/system-images/android-34/default/x86_64
readonly EMULATOR=$SDK_ROOT/emulator/emulator
readonly ADB=$SDK_ROOT/platform-tools/adb
readonly EMULATOR_LOG=$WORK_ROOT/emulator.log
readonly ADB_LOG=$WORK_ROOT/adb.log
readonly FRAMEBUFFER=$WORK_ROOT/framebuffer.png
readonly ANDROID_CONNECTION_DIAGNOSTIC=$WORK_ROOT/android-connection.diagnostic
readonly ANDROID_CONTROLLED_CPACE_LOG=$WORK_ROOT/android-controlled-cpace.log
readonly FRAME_OBSERVER_ROOT=/observer
readonly FRAME_OBSERVER_FRAME=$FRAME_OBSERVER_ROOT/latest.frame
readonly FRAME_OBSERVER_READY=$FRAME_OBSERVER_ROOT/ready
readonly FRAME_OBSERVER_FAILURE=$FRAME_OBSERVER_ROOT/failure
readonly FRAME_OBSERVER_STOP=$FRAME_OBSERVER_ROOT/stop
readonly FRAME_OBSERVER_STOPPED=$FRAME_OBSERVER_ROOT/stopped
readonly FRAME_DECODER=$SCRIPT_DIR/android-emulator-frame.py
mkdir -m 0700 -p -- "$SDK_ROOT" "$HOME_ROOT" "$AVD_HOME" "$SYSTEM_ROOT" \
    "$SDK_ROOT/platform-tools"

# The archives are exact-hash inputs, but extraction still rejects every archive
# shape that could escape or alias the destination.  File modes are derived here,
# never trusted from ZIP metadata.
python3 -I -S - "$EMULATOR_ZIP" "$SDK_ROOT/emulator" emulator/ \
    "$SYSTEM_IMAGE_ZIP" "$SYSTEM_ROOT" x86_64/ <<'PY'
import os
import stat
import sys
import zipfile


def extract(archive: str, destination: str, required_root: str) -> None:
    seen = set()
    root = os.path.realpath(destination)
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            name = member.filename
            if not name.startswith(required_root):
                raise SystemExit(f"noncanonical ZIP root: {name!r}")
            relative = name[len(required_root):]
            if not relative:
                continue
            parts = relative.rstrip("/").split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"unsafe ZIP path: {name!r}")
            normalized = "/".join(parts)
            if normalized in seen:
                raise SystemExit(f"duplicate ZIP path: {name!r}")
            seen.add(normalized)
            unix_mode = (member.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(unix_mode)
            is_directory = member.is_dir()
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise SystemExit(f"special ZIP member: {name!r}")
            if is_directory and kind == stat.S_IFREG:
                raise SystemExit(f"directory/file mode disagreement: {name!r}")
            if not is_directory and kind == stat.S_IFDIR:
                raise SystemExit(f"file/directory mode disagreement: {name!r}")
            target = os.path.join(root, *parts)
            parent = target if is_directory else os.path.dirname(target)
            os.makedirs(parent, mode=0o700, exist_ok=True)
            if os.path.commonpath((root, os.path.realpath(parent))) != root:
                raise SystemExit(f"ZIP path escaped destination: {name!r}")
            if is_directory:
                os.chmod(target, 0o700)
                continue
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o500 if unix_mode & 0o111 else 0o400,
            )
            try:
                with zf.open(member, "r") as source, os.fdopen(descriptor, "wb") as sink:
                    descriptor = -1
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        sink.write(chunk)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)


extract(sys.argv[1], sys.argv[2], sys.argv[3])
extract(sys.argv[4], sys.argv[5], sys.argv[6])
PY

install -m 0555 -- "$INPUT_ADB" "$ADB"
[ -x "$EMULATOR" ] && [ ! -L "$EMULATOR" ] \
    || fail 'the extracted emulator launcher is absent or ambiguous'
[ -f "$SYSTEM_ROOT/kernel-ranchu" ] && [ ! -L "$SYSTEM_ROOT/kernel-ranchu" ] \
    && [ -f "$SYSTEM_ROOT/system.img" ] && [ ! -L "$SYSTEM_ROOT/system.img" ] \
    && [ -f "$SYSTEM_ROOT/vendor.img" ] && [ ! -L "$SYSTEM_ROOT/vendor.img" ] \
    || fail 'the extracted Android system image is incomplete'

cat >"$AVD_HOME/rustdesk.ini" <<EOF
avd.ini.encoding=UTF-8
path=$AVD_HOME/rustdesk.avd
path.rel=avd/rustdesk.avd
target=android-34
EOF
mkdir -m 0700 -- "$AVD_HOME/rustdesk.avd"
cat >"$AVD_HOME/rustdesk.avd/config.ini" <<EOF
AvdId=rustdesk
PlayStore.enabled=false
abi.type=x86_64
avd.ini.displayname=RustDesk isolated Android 34
disk.dataPartition.size=2G
fastboot.forceColdBoot=yes
fastboot.forceFastBoot=no
hw.accelerometer=no
hw.arc=false
hw.audioInput=no
hw.audioOutput=no
hw.battery=yes
hw.camera.back=none
hw.camera.front=none
hw.cpu.arch=x86_64
hw.cpu.ncore=2
hw.dPad=no
hw.gps=no
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader
hw.initialOrientation=portrait
hw.keyboard=yes
hw.lcd.density=240
hw.lcd.height=800
hw.lcd.width=480
hw.mainKeys=no
hw.ramSize=2048
hw.sensors.proximity=no
hw.trackBall=no
image.sysdir.1=$SYSTEM_ROOT/
runtime.network.latency=none
runtime.network.speed=full
showDeviceFrame=no
skin.dynamic=yes
skin.name=480x800
tag.display=Default
tag.id=default
target=android-34
vm.heapSize=256
EOF

export HOME=$HOME_ROOT
export ANDROID_HOME=$SDK_ROOT
export ANDROID_SDK_ROOT=$SDK_ROOT
export ANDROID_AVD_HOME=$AVD_HOME
export ADB_SERVER_SOCKET=tcp:localhost:5037
export QT_QPA_PLATFORM=offscreen
export LC_ALL=C
readonly SERIAL=emulator-5554
EMULATOR_PID=
ADB_PID=
ADB_STARTED=0
XVFB_PID=
XVFB_START=
SOURCE_PID=
SOURCE_START=
SERVER_PID=
SERVER_START=
PEER_DISTINCT_FRAMES=0
PEER_FRESHNESS_MAX_MS=0
PEER_INITIAL_RECOVERY_MS=0
PEER_BACKGROUND_RECOVERY_MS=0
PEER_BACKGROUND_CYCLES=0
PEER_TASK_RECOVERY_MAX_MS=0
PEER_LAST_CONNECTION_WAIT_MS=0
PEER_CORRECT_CREDENTIAL_CONNECTION_MS=0
PEER_CACHED_CONNECTION_MAX_MS=0
PEER_CAPTURE_MAX_MS=0
PEER_INITIAL_CREDENTIAL_PROMPT_MS=0
PEER_INITIAL_CREDENTIAL_SEMANTIC_MODE=unavailable
PEER_CREDENTIAL_PROMPT_MS=0
PEER_CREDENTIAL_SEMANTIC_MODE=unavailable
PEER_PRESENTATION_STAGE_READY=0
declare -a PEER_PRESENTATION_PHASES=()
declare -a PEER_SERVER_PRESENTATION_STAGES=()
declare -a PEER_NATIVE_PRESENTATION_STAGES=()
declare -a PEER_DART_PRESENTATION_STAGES=()
ANDROID_CONTROL_FORWARD_READY=0
ANDROID_CONTROL_FORWARD_LISTING=
FRAME_OBSERVER_STOP_REQUESTED=0
FRAME_OBSERVER_JOINED=0
readonly PEER_RECOVERY_LIMIT_MS=8000
readonly PEER_FRESHNESS_LIMIT_MS=2000
# A timing observer that consumes a material part of the freshness budget
# cannot classify the product.  Emulator-stream transport and publication get
# one quarter of that budget.
readonly PEER_CAPTURE_LIMIT_MS=500
readonly PEER_CONNECTION_WAIT_LIMIT_MS=30000
# The nested, acceleration-off x86_64 emulator can spend multiple minutes in the
# deliberately memory-hard Argon2id derivation under host contention.  These two
# values are integration-finality ceilings, not native credential-latency claims;
# presentation recovery and freshness retain their independent tight bounds above.
readonly PEER_PASSWORD_CONNECTION_WAIT_LIMIT_MS=240000
readonly PEER_CREDENTIAL_PROMPT_LIMIT_MS=240000
readonly PERMANENT_PASSWORD_SUBMIT_LIMIT_MS=240000
# Keep one authenticated session across intervals below, within, and beyond the
# reported roughly ten-second focus-loss delay window.
readonly -a PEER_BACKGROUND_SECONDS=(2 6 12)
readonly RECENTS_DISMISS_GESTURE_EVENTS=12
readonly RECENTS_DISMISS_GESTURE_STEPS=10
readonly RECENTS_DISMISS_GESTURE_STEP_MS=16
readonly RECENTS_DISMISS_OUTCOME_POLLS=20
readonly RECENTS_FOCUSED_CYCLES=10
readonly RECENTS_GESTURE_DEVICE_PATH=/data/local/tmp/rustdesk-recents-dismiss.jar
readonly RECENTS_RUNTIME_UIAUTOMATOR_PATH=/system/framework/uiautomator.jar
RECENTS_GESTURE_STAGED=0
RECENTS_RUNTIME_UIAUTOMATOR_SHA256=
RECENTS_LAST_TASK_ID=
# The retained failing artifact repeated the rejected credential after 129.4 s. This integration
# observation intentionally spans that old behavior; focused development checks remain separate.
readonly PEER_NO_AUTO_RETRY_OBSERVATION_MS=140000
readonly PEER_PASSWORD_PRE_SUBMIT_QUIET_MS=15000
readonly PERMANENT_PASSWORD_SUBMIT_ACK_LIMIT_MS=30000
readonly PERMANENT_PASSWORD_SUBMIT_TAP_RETRY_MS=5000
readonly PERMANENT_PASSWORD_SUBMIT_TAP_ATTEMPTS=3
readonly ANDROID_CONTROL_FORWARD_LOCAL_SPEC=tcp:22119
readonly ANDROID_CONTROL_FORWARD_DEVICE_SPEC=tcp:21118
readonly ANDROID_CONTROL_FORWARD_PORT_HEX=5667

monotonic_millis() {
    local uptime ignored whole fraction
    read -r uptime ignored < /proc/uptime || return 1
    [[ "$uptime" =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
    whole=${BASH_REMATCH[1]}
    fraction=${BASH_REMATCH[2]}000
    printf '%s\n' "$((10#$whole * 1000 + 10#${fraction:0:3}))"
}

process_start_time() {
    local pid=$1
    [ -r "/proc/$pid/stat" ] || return 1
    awk '{ print $22 }' "/proc/$pid/stat"
}

EMULATOR_START=
ADB_START=
is_exact_emulator_process() {
    [ -n "$EMULATOR_PID" ] && [ -n "$EMULATOR_START" ] \
        && [ -r "/proc/$EMULATOR_PID/stat" ] \
        && [ "$(process_start_time "$EMULATOR_PID" 2>/dev/null)" = \
             "$EMULATOR_START" ]
}

is_exact_adb_process() {
    [ -n "$ADB_PID" ] && [ -n "$ADB_START" ] \
        && [ -r "/proc/$ADB_PID/stat" ] \
        && [ "$(process_start_time "$ADB_PID" 2>/dev/null)" = "$ADB_START" ]
}

frame_observer_listener_is_exact() {
    local -a interfaces=(/sys/class/net/*)
    [ "${#interfaces[@]}" -eq 1 ] \
        && [ "${interfaces[0]}" = /sys/class/net/lo ] \
        && [ "$(awk 'FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == ":216A" {
            count++
        }
        END { print count + 0 }' /proc/net/tcp /proc/net/tcp6)" -eq 1 ] \
        && awk 'FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == ":216A" {
                if (FILENAME != "/proc/net/tcp6" ||
                    $2 != "00000000000000000000000000000000:216A") bad=1
            }
            END { exit bad ? 1 : 0 }' /proc/net/tcp /proc/net/tcp6
}

frame_observer_failure_detail() {
    [ -f "$FRAME_OBSERVER_FAILURE" ] \
        && [ ! -L "$FRAME_OBSERVER_FAILURE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FRAME_OBSERVER_FAILURE")" = \
             1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$FRAME_OBSERVER_FAILURE")" -le 1024 ] \
        || return 1
    tr '\r\n' '  ' <"$FRAME_OBSERVER_FAILURE" | cut -c 1-1024
}

stop_frame_observer() {
    local detail= stopped= temporary=
    [ "$WORKLOAD" = app-peer-lifecycle ] || return 0
    [ "$FRAME_OBSERVER_JOINED" -eq 0 ] || return 0
    [ -d "$FRAME_OBSERVER_ROOT" ] && [ ! -L "$FRAME_OBSERVER_ROOT" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$FRAME_OBSERVER_ROOT")" = \
             1000:1000:700 ] \
        || return 1
    if [ "$FRAME_OBSERVER_STOP_REQUESTED" -eq 0 ]; then
        temporary=$FRAME_OBSERVER_ROOT/.stop.$$
        [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 1
        printf 'stop\n' >"$temporary" || return 1
        chmod 0600 "$temporary" || return 1
        mv -T -- "$temporary" "$FRAME_OBSERVER_STOP" || return 1
        FRAME_OBSERVER_STOP_REQUESTED=1
    fi
    for _ in $(seq 1 200); do
        if [ -e "$FRAME_OBSERVER_FAILURE" ] || [ -L "$FRAME_OBSERVER_FAILURE" ]; then
            detail="$(frame_observer_failure_detail 2>/dev/null || true)"
            printf 'Android frame observer failure: %s\n' "${detail:-malformed}" >&2
            return 1
        fi
        if [ -f "$FRAME_OBSERVER_STOPPED" ] \
           && [ ! -L "$FRAME_OBSERVER_STOPPED" ]; then
            break
        fi
        sleep 0.05
    done
    [ -f "$FRAME_OBSERVER_STOPPED" ] \
        && [ ! -L "$FRAME_OBSERVER_STOPPED" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FRAME_OBSERVER_STOPPED")" = \
             1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$FRAME_OBSERVER_STOPPED")" -le 256 ] \
        || return 1
    stopped="$(<"$FRAME_OBSERVER_STOPPED")"
    [[ "$stopped" =~ ^stopped\ frames_received=([1-9][0-9]*)\ frames_published=([1-9][0-9]*)\ last_seq=([0-9]+)$ ]] \
        || return 1
    [ "${BASH_REMATCH[1]}" -ge "${BASH_REMATCH[2]}" ] || return 1
    FRAME_OBSERVER_JOINED=1
}

print_android_connection_diagnostic() {
    local authority=${1:-cleanup} device_state=
    local logcat_diag= log_dir=/storage/emulated/0/RustDesk/Logs
    local listing= latest= filename= native_diag=
    case "$authority" in
        active)
            if ! is_exact_emulator_process; then
                printf 'Android connection diagnostic: exact emulator process is unavailable\n' >&2
                return 0
            fi
            for _ in $(seq 1 4); do
                device_state="$(
                    timeout --signal=TERM --kill-after=2s 10s \
                        "$ADB" -s "$SERIAL" get-state 2>/dev/null \
                        | tr -d '\r' \
                        || true
                )"
                [ "$device_state" = device ] && break
                sleep 0.25
            done
            if [ "$device_state" != device ]; then
                case "$device_state" in
                    '') device_state=unavailable ;;
                    offline|unknown) ;;
                    *) device_state=unexpected ;;
                esac
                printf 'Android connection diagnostic: exact serial state is %s\n' \
                    "$device_state" >&2
                return 0
            fi
            ;;
        cleanup)
            [ "$ADB_STARTED" -eq 1 ] && is_exact_adb_process || return 0
            ;;
        *) return 1 ;;
    esac

    logcat_diag="$(
        timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" logcat -d -v brief 2>/dev/null \
            | grep -Ei \
                'No remembered password|CPace handshake failed|R-S9|connect-password-prompt|session_set_connect_password|viewer owner|outgoing viewer|connection round|Connection closed|keying|RUSTDESK_PRESENTATION_STAGE' \
            | tail -n 160 \
            | tail -c 98304 \
            || true
    )"
    if [ -n "$logcat_diag" ]; then
        printf 'Android connection diagnostic (logcat):\n%s\n' "$logcat_diag" >&2
    else
        printf 'Android connection diagnostic (logcat): no matching records\n' >&2
    fi

    listing="$(
        timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" shell ls -1t "$log_dir" 2>/dev/null \
            | tr -d '\r' \
            || true
    )"
    if [ "${#listing}" -gt 32768 ]; then
        printf 'Android connection diagnostic: native-log inventory exceeded 32 KiB\n' >&2
        return 0
    fi
    while IFS= read -r filename; do
        [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || continue
        latest=$filename
        break
    done <<<"$listing"
    if [ -z "$latest" ]; then
        printf 'Android connection diagnostic: no release log file\n' >&2
        return 0
    fi
    native_diag="$(
        timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" exec-out tail -c 98304 \
            "$log_dir/$latest" 2>/dev/null \
            | tr -d '\r' \
            | tail -n 200 \
            || true
    )"
    if [ -n "$native_diag" ]; then
        printf 'Android connection diagnostic (%s):\n%s\n' \
            "$latest" "$native_diag" >&2
    else
        printf 'Android connection diagnostic (%s): no matching records\n' \
            "$latest" >&2
    fi
}

capture_android_connection_diagnostic() {
    local authority=$1
    rm -f -- "$ANDROID_CONNECTION_DIAGNOSTIC"
    {
        printf 'ANDROID_CONNECTION_DIAGNOSTIC_BEGIN\n'
        print_android_connection_diagnostic "$authority" || true
        printf 'ANDROID_CONNECTION_DIAGNOSTIC_END\n'
    } >"$ANDROID_CONNECTION_DIAGNOSTIC" 2>&1
    [ -f "$ANDROID_CONNECTION_DIAGNOSTIC" ] \
        && [ ! -L "$ANDROID_CONNECTION_DIAGNOSTIC" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- \
            "$ANDROID_CONNECTION_DIAGNOSTIC")" = 1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$ANDROID_CONNECTION_DIAGNOSTIC")" -le 262144 ]
}

reprint_android_connection_diagnostic() {
    [ -f "$ANDROID_CONNECTION_DIAGNOSTIC" ] \
        && [ ! -L "$ANDROID_CONNECTION_DIAGNOSTIC" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- \
            "$ANDROID_CONNECTION_DIAGNOSTIC")" = 1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$ANDROID_CONNECTION_DIAGNOSTIC")" -le 262144 ] \
        || return 1
    cat -- "$ANDROID_CONNECTION_DIAGNOSTIC" >&2
}

print_connect_password_prompt_diagnostic() {
    local password_prompt= swipe_attempted=0
    [ "$ADB_STARTED" -eq 1 ] && is_exact_adb_process || return 0
    [ "${UI_XML+x}" = x ] || return 0
    capture_ui_hierarchy complete || return 0
    password_prompt="$(ui_center text 'Password required' 2>/dev/null || true)"
    [[ "$password_prompt" =~ ^[0-9]+\ [0-9]+$ ]] || return 0

    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null \
        || return 0
    sleep 0.5
    capture_ui_hierarchy complete || return 0
    if ! grep -Eq \
        'No remembered password|CPace handshake failed|R-S9' "$UI_XML"; then
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell input swipe 240 600 240 120 500 \
            >/dev/null || return 0
        swipe_attempted=1
        sleep 0.5
        capture_ui_hierarchy complete || return 0
    fi
    printf 'Android connect-password prompt diagnostic (swiped=%s):\n' \
        "$swipe_attempted" >&2
    print_initial_ui_semantics
}

is_exact_peer_process() {
    local pid=$1 start=$2
    [ -n "$pid" ] && [ -n "$start" ] && [ -r "/proc/$pid/stat" ] \
        && [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ]
}

peer_server_established_count() {
    awk 'FNR > 1 && $4 == "01" && $2 == "0100007F:527E" { count++ }
         END { print count + 0 }' /proc/net/tcp
}

wait_peer_server_connections() {
    local expected=$1 comparison=$2
    local limit_ms=${3:-$PEER_CONNECTION_WAIT_LIMIT_MS}
    local count started_ms now_ms elapsed_ms next_progress_ms=30000
    case "$expected" in
        ''|*[!0-9]*) return 2 ;;
    esac
    case "$limit_ms" in
        ''|*[!0-9]*) return 2 ;;
    esac
    [ "$limit_ms" -ge 1 ] || return 2
    case "$comparison" in
        at-least|exact) ;;
        *) return 2 ;;
    esac
    started_ms="$(monotonic_millis)" || return 2
    while :; do
        count="$(peer_server_established_count)"
        case "$comparison" in
            at-least) [ "$count" -ge "$expected" ] && break ;;
            exact) [ "$count" -eq "$expected" ] && break ;;
        esac
        now_ms="$(monotonic_millis)" || return 2
        elapsed_ms=$((now_ms - started_ms))
        if [ "$elapsed_ms" -ge "$limit_ms" ]; then
            PEER_LAST_CONNECTION_WAIT_MS=$elapsed_ms
            return 1
        fi
        if [ "$limit_ms" -gt 30000 ] \
           && [ "$elapsed_ms" -ge "$next_progress_ms" ]; then
            printf 'ANDROID_PEER_CONNECTION_WAIT=progress elapsed_ms=%s limit_ms=%s established=%s failures=%s\n' \
                "$elapsed_ms" "$limit_ms" "$count" \
                "$(peer_server_key_failure_count)"
            next_progress_ms=$((next_progress_ms + 30000))
        fi
        sleep 0.25
    done
    now_ms="$(monotonic_millis)" || return 2
    PEER_LAST_CONNECTION_WAIT_MS=$((now_ms - started_ms))
}

peer_server_key_failure_count() {
    if [ -z "${PEER_SERVER_LOG:-}" ] || [ ! -f "$PEER_SERVER_LOG" ]; then
        printf 'unavailable\n'
        return
    fi
    grep -Fc 'ended before session completion: CPace handshake failed: fail-closed' \
        "$PEER_SERVER_LOG" || true
}

peer_server_pre_session_failure_count() {
    if [ -z "${PEER_SERVER_LOG:-}" ] || [ ! -f "$PEER_SERVER_LOG" ]; then
        printf 'unavailable\n'
        return
    fi
    grep -Fc ' ended before session completion:' "$PEER_SERVER_LOG" || true
}

peer_server_keyed_session_count() {
    if [ -z "${PEER_SERVER_LOG:-}" ] || [ ! -f "$PEER_SERVER_LOG" ]; then
        printf 'unavailable\n'
        return
    fi
    grep -Fc ' Connection opened from ' "$PEER_SERVER_LOG" || true
}

android_native_presentation_stages() {
    local log_dir=/storage/emulated/0/RustDesk/Logs
    local listing= filename= latest=
    listing="$(timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" shell ls -1t "$log_dir" 2>/dev/null \
        | tr -d '\r' || true)"
    [ "${#listing}" -le 32768 ] || return 1
    while IFS= read -r filename; do
        [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || continue
        latest=$filename
        break
    done <<<"$listing"
    [ -n "$latest" ] || return 1
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" exec-out tail -c 1048576 \
        "$log_dir/$latest" 2>/dev/null \
        | tr -d '\r' \
        | grep -Eo \
            'RUSTDESK_PRESENTATION_STAGE stage=viewer-independent-decoded display=[0-9]+ wire_generation=[1-9][0-9]* mailbox_generation=[1-9][0-9]* wall_ms=[1-9][0-9]* receive_to_admit_us=[0-9]+ admit_to_dequeue_us=[0-9]+ decode_us=[0-9]+' \
        || true
}

android_dart_presentation_stages() {
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" logcat -d -v brief 2>/dev/null \
        | tr -d '\r' \
        | grep -Eo \
            'RUSTDESK_PRESENTATION_STAGE stage=dart-image-notified session=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} display=[0-9]+ publication=[1-9][0-9]* wall_ms=[1-9][0-9]* event_queue_us=[0-9]+ take_us=[0-9]+ checkpoint_us=[0-9]+ decode_commit_us=[0-9]+ ui_finalize_us=[0-9]+ total_us=[0-9]+' \
        || true
}

print_peer_presentation_stage_diagnostic() {
    local phase=$1
    printf 'ANDROID_PEER_PRESENTATION_STAGE_DIAGNOSTIC_BEGIN phase=%s\n' "$phase"
    grep -Eo \
        'RUSTDESK_PRESENTATION_STAGE stage=server-independent-enqueued connection=[1-9][0-9]* display=[0-9]+ wire_generation=[1-9][0-9]* wall_ms=[1-9][0-9]* queue_us=[0-9]+' \
        "$PEER_SERVER_LOG" 2>/dev/null \
        | tail -n 8 \
        | sed 's/^/ANDROID_PEER_PRESENTATION_STAGE_SERVER /' \
        || true
    android_native_presentation_stages \
        | tail -n 8 \
        | sed 's/^/ANDROID_PEER_PRESENTATION_STAGE_NATIVE /' \
        || true
    android_dart_presentation_stages \
        | tail -n 8 \
        | sed 's/^/ANDROID_PEER_PRESENTATION_STAGE_DART /' \
        || true
    printf 'ANDROID_PEER_PRESENTATION_STAGE_DIAGNOSTIC_END phase=%s\n' "$phase"
}

presentation_stage_line_recorded() {
    local candidate=$1 recorded
    shift
    for recorded in "$@"; do
        [ "$recorded" != "$candidate" ] || return 0
    done
    return 1
}

record_peer_presentation_stage() {
    local phase=$1 line attempt
    local server_pattern
    local -a server_current native_current dart_current
    local -a new_server=() new_native=() new_dart=()

    server_pattern='RUSTDESK_PRESENTATION_STAGE stage=server-independent-enqueued connection=[1-9][0-9]* display=[0-9]+ wire_generation=[1-9][0-9]* wall_ms=[1-9][0-9]* queue_us=[0-9]+'
    for attempt in $(seq 1 30); do
        server_current=()
        native_current=()
        dart_current=()
        new_server=()
        new_native=()
        new_dart=()
        mapfile -t server_current < <(grep -Eo "$server_pattern" \
            "$PEER_SERVER_LOG" 2>/dev/null || true)
        mapfile -t native_current < <(android_native_presentation_stages)
        mapfile -t dart_current < <(android_dart_presentation_stages)
        for line in "${server_current[@]}"; do
            presentation_stage_line_recorded \
                "$line" "${PEER_SERVER_PRESENTATION_STAGES[@]}" \
                || new_server+=("$line")
        done
        for line in "${native_current[@]}"; do
            presentation_stage_line_recorded \
                "$line" "${PEER_NATIVE_PRESENTATION_STAGES[@]}" \
                || new_native+=("$line")
        done
        for line in "${dart_current[@]}"; do
            presentation_stage_line_recorded \
                "$line" "${PEER_DART_PRESENTATION_STAGES[@]}" \
                || new_dart+=("$line")
        done
        [ "${#new_server[@]}" -le 1 ] \
            && [ "${#new_native[@]}" -le 1 ] \
            && [ "${#new_dart[@]}" -le 1 ] \
            || break
        if [ "${#new_server[@]}" -eq 1 ] \
           && [ "${#new_native[@]}" -eq 1 ] \
           && [ "${#new_dart[@]}" -eq 1 ]; then
            PEER_PRESENTATION_PHASES+=("$phase")
            PEER_SERVER_PRESENTATION_STAGES+=("${new_server[0]}")
            PEER_NATIVE_PRESENTATION_STAGES+=("${new_native[0]}")
            PEER_DART_PRESENTATION_STAGES+=("${new_dart[0]}")
            return 0
        fi
        sleep 0.1
    done
    printf 'ANDROID_PEER_PRESENTATION_STAGE_SNAPSHOT=fail phase=%s server=%s native=%s dart=%s expected=1\n' \
        "$phase" "${#new_server[@]}" "${#new_native[@]}" \
        "${#new_dart[@]}"
    return 1
}

emit_peer_presentation_stage_receipts() {
    local server_line native_line dart_line phase
    local server_connection server_display server_generation server_wall_ms
    local server_queue_us native_display native_generation mailbox_generation
    local native_wall_ms receive_to_admit_us admit_to_dequeue_us decode_us
    local dart_session dart_display publication dart_wall_ms event_queue_us
    local take_us checkpoint_us decode_commit_us ui_finalize_us total_us
    local calculated_total connections= sessions= previous_generation=0
    local index
    local -a phases=(initial task-relaunch-1 task-relaunch-2)
    local -a server_stages native_stages dart_stages

    server_stages=("${PEER_SERVER_PRESENTATION_STAGES[@]}")
    native_stages=("${PEER_NATIVE_PRESENTATION_STAGES[@]}")
    dart_stages=("${PEER_DART_PRESENTATION_STAGES[@]}")
    [ "${#server_stages[@]}" -eq "${#phases[@]}" ] \
        && [ "${#native_stages[@]}" -eq "${#phases[@]}" ] \
        && [ "${#dart_stages[@]}" -eq "${#phases[@]}" ] \
        && [ "${#PEER_PRESENTATION_PHASES[@]}" -eq "${#phases[@]}" ] \
        || {
            printf 'ANDROID_PEER_PRESENTATION_STAGE=fail server=%s native=%s dart=%s expected=%s\n' \
                "${#server_stages[@]}" "${#native_stages[@]}" \
                "${#dart_stages[@]}" "${#phases[@]}"
            return 1
        }

    for index in "${!phases[@]}"; do
        phase=${phases[$index]}
        [ "${PEER_PRESENTATION_PHASES[$index]}" = "$phase" ] || return 1
        server_line=${server_stages[$index]}
        native_line=${native_stages[$index]}
        dart_line=${dart_stages[$index]}
        [[ "$server_line" =~ ^RUSTDESK_PRESENTATION_STAGE\ stage=server-independent-enqueued\ connection=([1-9][0-9]*)\ display=([0-9]+)\ wire_generation=([1-9][0-9]*)\ wall_ms=([1-9][0-9]*)\ queue_us=([0-9]+)$ ]] \
            || return 1
        server_connection=${BASH_REMATCH[1]}
        server_display=${BASH_REMATCH[2]}
        server_generation=${BASH_REMATCH[3]}
        server_wall_ms=${BASH_REMATCH[4]}
        server_queue_us=${BASH_REMATCH[5]}
        [[ "$native_line" =~ ^RUSTDESK_PRESENTATION_STAGE\ stage=viewer-independent-decoded\ display=([0-9]+)\ wire_generation=([1-9][0-9]*)\ mailbox_generation=([1-9][0-9]*)\ wall_ms=([1-9][0-9]*)\ receive_to_admit_us=([0-9]+)\ admit_to_dequeue_us=([0-9]+)\ decode_us=([0-9]+)$ ]] \
            || return 1
        native_display=${BASH_REMATCH[1]}
        native_generation=${BASH_REMATCH[2]}
        mailbox_generation=${BASH_REMATCH[3]}
        native_wall_ms=${BASH_REMATCH[4]}
        receive_to_admit_us=${BASH_REMATCH[5]}
        admit_to_dequeue_us=${BASH_REMATCH[6]}
        decode_us=${BASH_REMATCH[7]}
        [[ "$dart_line" =~ ^RUSTDESK_PRESENTATION_STAGE\ stage=dart-image-notified\ session=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\ display=([0-9]+)\ publication=([1-9][0-9]*)\ wall_ms=([1-9][0-9]*)\ event_queue_us=([0-9]+)\ take_us=([0-9]+)\ checkpoint_us=([0-9]+)\ decode_commit_us=([0-9]+)\ ui_finalize_us=([0-9]+)\ total_us=([0-9]+)$ ]] \
            || return 1
        dart_session=${BASH_REMATCH[1]}
        dart_display=${BASH_REMATCH[2]}
        publication=${BASH_REMATCH[3]}
        dart_wall_ms=${BASH_REMATCH[4]}
        event_queue_us=${BASH_REMATCH[5]}
        take_us=${BASH_REMATCH[6]}
        checkpoint_us=${BASH_REMATCH[7]}
        decode_commit_us=${BASH_REMATCH[8]}
        ui_finalize_us=${BASH_REMATCH[9]}
        total_us=${BASH_REMATCH[10]}
        calculated_total=$((event_queue_us + take_us + checkpoint_us \
            + decode_commit_us + ui_finalize_us))
        [ "$server_display" -eq "$native_display" ] \
            && [ "$native_display" -eq "$dart_display" ] \
            && [ "$server_generation" -eq "$native_generation" ] \
            && [ "$server_generation" -gt "$previous_generation" ] \
            && [ "$calculated_total" -eq "$total_us" ] \
            || return 1
        case " $connections " in
            *" $server_connection "*) return 1 ;;
        esac
        case " $sessions " in
            *" $dart_session "*) return 1 ;;
        esac
        connections="${connections:+$connections }$server_connection"
        sessions="${sessions:+$sessions }$dart_session"
        previous_generation=$server_generation
        printf 'ANDROID_PEER_PRESENTATION_STAGE=pass phase=%s ordinal=%s server_connection=%s display=%s wire_generation=%s server_wall_ms=%s server_queue_us=%s viewer_mailbox_generation=%s viewer_wall_ms=%s receive_to_admit_us=%s admit_to_dequeue_us=%s decode_us=%s dart_session=%s publication=%s dart_wall_ms=%s event_queue_us=%s take_us=%s checkpoint_us=%s decode_commit_us=%s ui_finalize_us=%s dart_total_us=%s\n' \
            "$phase" "$((index + 1))" "$server_connection" \
            "$server_display" "$server_generation" "$server_wall_ms" \
            "$server_queue_us" "$mailbox_generation" "$native_wall_ms" \
            "$receive_to_admit_us" "$admit_to_dequeue_us" "$decode_us" \
            "$dart_session" "$publication" "$dart_wall_ms" \
            "$event_queue_us" "$take_us" "$checkpoint_us" \
            "$decode_commit_us" "$ui_finalize_us" "$total_us"
    done
}

record_peer_password_pre_submit_state() {
    local kind=$1 stage=$2 expected_pre_session_failures=$3
    local expected_key_failures=$4 expected_keyed_sessions=$5
    local wall_ms pre_session_failures key_failures keyed_sessions established
    wall_ms="$(date +%s%3N)" || return 2
    [[ "$wall_ms" =~ ^[1-9][0-9]{12}$ ]] || return 2
    pre_session_failures="$(peer_server_pre_session_failure_count)"
    key_failures="$(peer_server_key_failure_count)"
    keyed_sessions="$(peer_server_keyed_session_count)"
    established="$(peer_server_established_count)"
    if [ "$pre_session_failures" -ne "$expected_pre_session_failures" ] \
       || [ "$key_failures" -ne "$expected_key_failures" ] \
       || [ "$keyed_sessions" -ne "$expected_keyed_sessions" ] \
       || [ "$established" -ne 0 ]; then
        printf 'ANDROID_PEER_PASSWORD_PRE_SUBMIT_STATE=fail kind=%s stage=%s observed_wall_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s\n' \
            "$kind" "$stage" "$wall_ms" "$pre_session_failures" \
            "$expected_pre_session_failures" "$key_failures" \
            "$expected_key_failures" "$keyed_sessions" \
            "$expected_keyed_sessions" "$established"
        return 1
    fi
    printf 'ANDROID_PEER_PASSWORD_PRE_SUBMIT_STATE=pass kind=%s stage=%s observed_wall_ms=%s pre_session_failures=%s key_failures=%s keyed_sessions=%s established=0\n' \
        "$kind" "$stage" "$wall_ms" "$pre_session_failures" \
        "$key_failures" "$keyed_sessions"
}

observe_peer_password_pre_submit_quiet() {
    local kind=$1 stage=$2 expected_pre_session_failures=$3
    local expected_key_failures=$4 expected_keyed_sessions=$5
    local started_ms now_ms elapsed_ms wall_ms
    local pre_session_failures key_failures keyed_sessions established
    started_ms="$(monotonic_millis)" || return 2
    while :; do
        pre_session_failures="$(peer_server_pre_session_failure_count)"
        key_failures="$(peer_server_key_failure_count)"
        keyed_sessions="$(peer_server_keyed_session_count)"
        established="$(peer_server_established_count)"
        now_ms="$(monotonic_millis)" || return 2
        elapsed_ms=$((now_ms - started_ms))
        if [ "$pre_session_failures" -ne "$expected_pre_session_failures" ] \
           || [ "$key_failures" -ne "$expected_key_failures" ] \
           || [ "$keyed_sessions" -ne "$expected_keyed_sessions" ] \
           || [ "$established" -ne 0 ]; then
            wall_ms="$(date +%s%3N)" || return 2
            printf 'ANDROID_PEER_PASSWORD_PRE_SUBMIT_QUIET=fail kind=%s stage=%s observed_wall_ms=%s elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s\n' \
                "$kind" "$stage" "$wall_ms" "$elapsed_ms" \
                "$PEER_PASSWORD_PRE_SUBMIT_QUIET_MS" \
                "$pre_session_failures" "$expected_pre_session_failures" \
                "$key_failures" "$expected_key_failures" \
                "$keyed_sessions" "$expected_keyed_sessions" "$established"
            return 1
        fi
        if [ "$elapsed_ms" -ge "$PEER_PASSWORD_PRE_SUBMIT_QUIET_MS" ]; then
            break
        fi
        sleep 0.25
    done
    record_peer_password_pre_submit_state "$kind" "$stage-quiet" \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    printf 'ANDROID_PEER_PASSWORD_PRE_SUBMIT_QUIET=pass kind=%s stage=%s elapsed_ms=%s limit_ms=%s observed_network_attempts=0\n' \
        "$kind" "$stage" "$elapsed_ms" \
        "$PEER_PASSWORD_PRE_SUBMIT_QUIET_MS"
}

stop_peer_infrastructure() {
    local status=0
    if [ -n "$SERVER_PID" ]; then
        if is_exact_peer_process "$SERVER_PID" "$SERVER_START"; then
            "$PEER_READY" --terminate-server \
                "$SERVER_PID" "$SERVER_START" "$PEER_SERVER_LOG" || status=1
        fi
        wait "$SERVER_PID" 2>/dev/null || status=1
        SERVER_PID=
        SERVER_START=
    fi
    if [ -n "$SOURCE_PID" ]; then
        if is_exact_peer_process "$SOURCE_PID" "$SOURCE_START"; then
            "$PEER_READY" --stop "$SOURCE_PID" "$SOURCE_START" || status=1
        fi
        wait "$SOURCE_PID" 2>/dev/null || status=1
        SOURCE_PID=
        SOURCE_START=
    fi
    if [ -n "$XVFB_PID" ]; then
        if is_exact_peer_process "$XVFB_PID" "$XVFB_START"; then
            "$PEER_READY" --stop "$XVFB_PID" "$XVFB_START" || status=1
        fi
        wait "$XVFB_PID" 2>/dev/null || true
        XVFB_PID=
        XVFB_START=
    fi
    return "$status"
}

android_control_forward_listing_is_exact() {
    local listing=$1 identity local_spec device_spec extra
    [ "${#listing}" -le 256 ] && [[ "$listing" != *$'\n'* ]] || return 1
    read -r identity local_spec device_spec extra <<<"$listing"
    [ "$identity" = "$SERIAL" ] \
        && [ "$local_spec" = "$ANDROID_CONTROL_FORWARD_LOCAL_SPEC" ] \
        && [ "$device_spec" = "$ANDROID_CONTROL_FORWARD_DEVICE_SPEC" ] \
        && [ -z "$extra" ]
}

android_control_forward_is_loopback_only() {
    local ipv4_total ipv4_loopback ipv6_total
    read -r ipv4_total ipv4_loopback < <(
        awk -v port="$ANDROID_CONTROL_FORWARD_PORT_HEX" '
            FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == ":" port {
                total++
                if ($2 == "0100007F:" port) loopback++
            }
            END { print total + 0, loopback + 0 }
        ' /proc/net/tcp
    ) || return 1
    ipv6_total="$(awk -v port="$ANDROID_CONTROL_FORWARD_PORT_HEX" '
        FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == ":" port {
            total++
        }
        END { print total + 0 }
    ' /proc/net/tcp6)" || return 1
    [ "$ipv4_total:$ipv4_loopback:$ipv6_total" = 1:1:0 ]
}

android_control_forward_is_absent() {
    ! awk -v port="$ANDROID_CONTROL_FORWARD_PORT_HEX" \
        'FNR > 1 && $4 == "0A" \
            && substr($2, length($2) - 4) == ":" port { found=1 }
         END { exit found ? 0 : 1 }' /proc/net/tcp \
        && ! awk -v port="$ANDROID_CONTROL_FORWARD_PORT_HEX" \
            'FNR > 1 && $4 == "0A" \
                && substr($2, length($2) - 4) == ":" port { found=1 }
             END { exit found ? 0 : 1 }' /proc/net/tcp6
}

remove_android_control_forward() {
    local listing output
    [ "$ANDROID_CONTROL_FORWARD_READY" -eq 1 ] || return 0
    [ "$ADB_STARTED" -eq 1 ] && is_exact_adb_process || return 1
    listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --list | tr -d '\r')" \
        || return 1
    android_control_forward_listing_is_exact "$listing" || return 1
    if [ -n "$ANDROID_CONTROL_FORWARD_LISTING" ] \
       && [ "$listing" != "$ANDROID_CONTROL_FORWARD_LISTING" ]; then
        return 1
    fi
    output="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --remove \
        "$ANDROID_CONTROL_FORWARD_LOCAL_SPEC" | tr -d '\r')" \
        || return 1
    ANDROID_CONTROL_FORWARD_READY=0
    ANDROID_CONTROL_FORWARD_LISTING=
    [ -z "$output" ] || return 1
    listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --list | tr -d '\r')" \
        || return 1
    [ -z "$listing" ] && android_control_forward_is_absent
}

stop_emulator() {
    local status=0
    if [ "$ADB_STARTED" -eq 1 ]; then
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" emu kill >/dev/null 2>&1 || true
    fi
    if is_exact_emulator_process; then
        for _ in $(seq 1 100); do
            is_exact_emulator_process || break
            sleep 0.1
        done
    fi
    if is_exact_emulator_process; then
        kill -TERM "$EMULATOR_PID" 2>/dev/null || status=1
        for _ in $(seq 1 100); do
            is_exact_emulator_process || break
            sleep 0.1
        done
    fi
    if is_exact_emulator_process; then
        kill -KILL "$EMULATOR_PID" 2>/dev/null || status=1
    fi
    if [ -n "$EMULATOR_PID" ]; then
        wait "$EMULATOR_PID" 2>/dev/null || true
        EMULATOR_PID=
        EMULATOR_START=
    fi
    if [ "$ADB_STARTED" -eq 1 ]; then
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" kill-server >/dev/null 2>&1 || status=1
        ADB_STARTED=0
    fi
    if is_exact_adb_process; then
        for _ in $(seq 1 100); do
            is_exact_adb_process || break
            sleep 0.1
        done
    fi
    if is_exact_adb_process; then
        kill -TERM "$ADB_PID" 2>/dev/null || status=1
        for _ in $(seq 1 50); do
            is_exact_adb_process || break
            sleep 0.1
        done
    fi
    if is_exact_adb_process; then
        kill -KILL "$ADB_PID" 2>/dev/null || status=1
    fi
    if [ -n "$ADB_PID" ]; then
        wait "$ADB_PID" 2>/dev/null || true
        ADB_PID=
        ADB_START=
    fi
    return "$status"
}

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        print_connect_password_prompt_diagnostic || true
        if [ ! -e "$ANDROID_CONNECTION_DIAGNOSTIC" ]; then
            capture_android_connection_diagnostic cleanup || true
        fi
    fi
    remove_android_control_forward || cleanup_status=1
    stop_frame_observer || cleanup_status=1
    stop_emulator || cleanup_status=1
    stop_peer_infrastructure || cleanup_status=1
    if [ "$status" -ne 0 ]; then
        tail -n 160 "$EMULATOR_LOG" >&2 2>/dev/null || true
        tail -n 80 "$ADB_LOG" >&2 2>/dev/null || true
        [ -z "${PEER_SERVER_LOG:-}" ] \
            || tail -n 120 "$PEER_SERVER_LOG" >&2 2>/dev/null || true
        [ -z "${PEER_SEED_LOG:-}" ] \
            || tail -n 40 "$PEER_SEED_LOG" >&2 2>/dev/null || true
        [ -z "${PEER_SOURCE_LOG:-}" ] \
            || tail -n 80 "$PEER_SOURCE_LOG" >&2 2>/dev/null || true
        [ -z "${PEER_XVFB_LOG:-}" ] \
            || tail -n 80 "$PEER_XVFB_LOG" >&2 2>/dev/null || true
        reprint_android_connection_diagnostic || true
    fi
    [ "$cleanup_status" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    readonly PEER_TARGET=/smoke-target
    readonly PEER_XVFB_ROOT=/xvfb-root
    readonly PEER_XVFB_MANIFEST=$SCRIPT_DIR/smoke-xvfb-files.tsv
    readonly PEER_READY=$SCRIPT_DIR/smoke-ready.sh
    readonly PEER_PASSWORD=RuntimePeer1x
    readonly PEER_WRONG_PASSWORD=RuntimeWrong1x
    readonly PEER_MISSING_CREDENTIAL_REASON="No remembered password for this peer — cannot run the CPace handshake (R-S9, fail-closed). Enter the box's password and reconnect."
    readonly PEER_CONFIRMATION_UNAVAILABLE_REASON="The peer did not provide CPace key confirmation after this viewer sent its confirmation. The peer may have rejected a stale or wrong password, or the connection may have ended. Re-enter the box's password if it changed; otherwise retry the connection. No session was authorized."
    readonly PEER_SEED_LOG=$WORK_ROOT/peer-seed.log
    readonly PEER_SOURCE_LOG=$WORK_ROOT/peer-source.log
    readonly PEER_SERVER_LOG=$WORK_ROOT/peer-server.log
    readonly PEER_XVFB_LOG=$WORK_ROOT/peer-xvfb.log
    [ -f "$FRAME_DECODER" ] && [ ! -L "$FRAME_DECODER" ] \
        || fail 'the Android emulator frame decoder is absent or ambiguous'
    [ -d "$FRAME_OBSERVER_ROOT" ] && [ ! -L "$FRAME_OBSERVER_ROOT" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$FRAME_OBSERVER_ROOT")" = \
             1000:1000:700 ] \
        || fail 'the Android emulator frame-observer exchange root differs'
    [ -z "$(find "$FRAME_OBSERVER_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ] \
        || fail 'the Android emulator frame-observer exchange root is not empty'
    [ "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = lo ] \
        || fail 'the real-peer runtime container has a non-loopback interface'
    [ -f "$PEER_TARGET/android-peer-manifest.sha256" ] \
        && [ ! -L "$PEER_TARGET/android-peer-manifest.sha256" ] \
        || fail 'the Android peer runtime manifest is absent or ambiguous'
    (cd "$PEER_TARGET" \
        && sha256sum --check --strict android-peer-manifest.sha256 >/dev/null) \
        || fail 'the Android peer runtime bundle differs from its manifest'
    [ -f "$PEER_XVFB_MANIFEST" ] && [ ! -L "$PEER_XVFB_MANIFEST" ] \
        || fail 'the Android peer Xvfb file manifest is absent or ambiguous'
    xvfb_file_count=0
    while IFS=$'\t' read -r relative size mode digest extra \
          || [ -n "${relative:-}" ]; do
        [ -n "${relative:-}" ] || continue
        [[ "$relative" == \#* ]] && continue
        [ -z "${extra:-}" ] \
            && [[ "$relative" =~ ^[A-Za-z0-9._+/-]+$ ]] \
            && [[ "$relative" != /* ]] \
            && [[ "$relative" != ../* ]] \
            && [[ "$relative" != */../* ]] \
            && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
            && [[ "$mode" =~ ^(644|755)$ ]] \
            && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
            || fail 'the Android peer Xvfb file manifest is malformed'
        xvfb_file="$PEER_XVFB_ROOT/$relative"
        [ -f "$xvfb_file" ] && [ ! -L "$xvfb_file" ] \
            && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$xvfb_file")" = \
                 "$RUN_UID:$RUN_GID:$mode:1:$size" ] \
            && [ "$(sha256sum "$xvfb_file" | awk '{ print $1 }')" = "$digest" ] \
            || fail "the Android peer Xvfb closure differs: $relative"
        xvfb_file_count=$((xvfb_file_count + 1))
    done < "$PEER_XVFB_MANIFEST"
    [ "$xvfb_file_count" -eq 5 ] \
        || fail 'the Android peer Xvfb file cardinality differs'
    for executable in \
        "$PEER_TARGET/debug/rustdesk" \
        "$PEER_TARGET/debug/examples/seed_password" \
        "$PEER_TARGET/debug/examples/probe_client" \
        "$PEER_TARGET/debug/examples/smoke_readiness" \
        "$PEER_TARGET/flutter-peer-source-x11" \
        "$PEER_TARGET/smoke-bind-loopback.so" \
        "$PEER_TARGET/smoke-server-launcher" \
        "$PEER_XVFB_ROOT/usr/bin/Xvfb" /usr/bin/xkbcomp "$PEER_READY"; do
        [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
            || fail "the Android peer runtime executable is absent or ambiguous: $executable"
    done
    export DISPLAY=:99
    LD_LIBRARY_PATH="$PEER_XVFB_ROOT/usr/lib/x86_64-linux-gnu" \
        "$PEER_XVFB_ROOT/usr/bin/Xvfb" :99 -screen 0 640x480x24 \
        -nolisten tcp -ac -noreset >"$PEER_XVFB_LOG" 2>&1 &
    XVFB_PID=$!
    XVFB_START="$(process_start_time "$XVFB_PID")" \
        || fail 'cannot bind the Android peer Xvfb generation'
    for _ in $(seq 1 100); do
        [ -S /tmp/.X11-unix/X99 ] && break
        is_exact_peer_process "$XVFB_PID" "$XVFB_START" \
            || fail 'Android peer Xvfb exited before readiness'
        sleep 0.1
    done
    [ -S /tmp/.X11-unix/X99 ] && [ ! -L /tmp/.X11-unix/X99 ] \
        || fail 'Android peer Xvfb Unix socket did not become ready'
    RUSTDESK_PRESENTATION_TRACE=1 "$PEER_TARGET/flutter-peer-source-x11" \
        >"$PEER_SOURCE_LOG" 2>&1 &
    SOURCE_PID=$!
    SOURCE_START="$(process_start_time "$SOURCE_PID")" \
        || fail 'cannot bind the Android peer source generation'
    "$PEER_READY" --wait-log "$SOURCE_PID" "$SOURCE_START" "$PEER_SOURCE_LOG" \
        'FLUTTER_PEER_SOURCE_READY display=:99 dimensions=640x480 interval_ms=250 states=256' \
        'Android peer changing-source readiness'
    install -d -m 0700 -- /tmp/android-peer-server-home
    HOME=/tmp/android-peer-server-home \
        "$PEER_TARGET/debug/examples/seed_password" "$PEER_PASSWORD" \
        >"$PEER_SEED_LOG" 2>&1 \
        || { tail -n 40 "$PEER_SEED_LOG" >&2; fail 'cannot provision the Android peer test password'; }
    [ "$(grep -Fc 'seed_password: set_permanent_password ok=true, prs_empty=false, prs_is_plaintext=false' \
        "$PEER_SEED_LOG" || true)" -eq 1 ] \
        && [ "$(stat -c '%s' -- "$PEER_SEED_LOG")" -le 4096 ] \
        || { tail -n 40 "$PEER_SEED_LOG" >&2; fail 'the Android peer password seed receipt differs'; }
    HOME=/tmp/android-peer-server-home DISPLAY=:99 RUST_LOG=debug \
        LD_PRELOAD="$PEER_TARGET/smoke-bind-loopback.so" \
        "$PEER_TARGET/smoke-server-launcher" "$PEER_TARGET/debug/rustdesk" \
        >"$PEER_SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    SERVER_START="$(process_start_time "$SERVER_PID")" \
        || fail 'cannot bind the controlled Android peer server generation'
    "$PEER_READY" --wait-server "$SERVER_PID" "$SERVER_START" \
        "$PEER_SERVER_LOG" "$PEER_TARGET/debug/examples/smoke_readiness" "$RUN_UID"
    [ "$(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' \
        /proc/net/tcp)" -eq 1 ] \
        && awk 'FNR > 1 && $4 == "0A" && $2 == "0100007F:527E" { count++ }
            END { exit count == 1 ? 0 : 1 }' /proc/net/tcp \
        || fail 'the controlled Android peer is not one exact 127.0.0.1:21118 listener'
    [ "$(awk 'FNR > 1 { count++ } END { print count + 0 }' \
        /proc/net/udp)" -eq 0 ] \
        || fail 'the controlled Android peer opened a UDP socket'
    peer_cpace_output="$(
        printf '%s\n' "$PEER_PASSWORD" \
            | timeout --signal=TERM --kill-after=2s 60s \
                "$PEER_TARGET/debug/examples/probe_client" \
                127.0.0.1:21118 --password-stdin ok 2>&1
    )" \
        || { printf '%s\n' "$peer_cpace_output" >&2; fail 'the production Android peer responder rejected its seeded password'; }
    expected_peer_cpace_output=$'probe_client: keying ok=true (expected=ok)\nprobe_client: PASS'
    [ "$peer_cpace_output" = "$expected_peer_cpace_output" ] \
        || { printf '%s\n' "$peer_cpace_output" >&2; fail 'the production Android peer CPace receipt differs'; }
    wait_peer_server_connections 0 exact \
        || fail 'the Android peer credential probe did not close exactly'
    printf 'ANDROID_PEER_RESPONDER_CPACE=pass initiator=linux-probe responder=production-peer credential=seeded correct=keyed listener=127.0.0.1:21118 connection_cleanup=closed password_transport=stdin\n'
    printf 'ANDROID_PEER_INFRASTRUCTURE=ready server=production auth=cpace listener=127.0.0.1:21118 source=changing-x11 x11=unix-only container_network=none\n'
fi

"$ADB" server nodaemon >"$ADB_LOG" 2>&1 &
ADB_PID=$!
ADB_START="$(process_start_time "$ADB_PID")" \
    || fail 'cannot bind the adb-server process generation'
[[ "$ADB_START" =~ ^[1-9][0-9]*$ ]] \
    || fail 'the adb-server process start time is malformed'
ADB_STARTED=1
adb_ready=0
for _ in $(seq 1 100); do
    if is_exact_adb_process \
       && timeout --signal=TERM --kill-after=2s 5s "$ADB" devices >/dev/null 2>&1; then
        adb_ready=1
        break
    fi
    is_exact_adb_process || break
    sleep 0.1
done
[ "$adb_ready" -eq 1 ] || fail 'the private loopback adb server did not become ready'
"$EMULATOR" @rustdesk \
    -port 5554 \
    -no-window \
    -no-audio \
    -no-boot-anim \
    -no-snapshot \
    -no-snapstorage \
    -no-metrics \
    -wipe-data \
    -accel off \
    -gpu swiftshader \
    "${EMULATOR_GRPC_ARGS[@]}" \
    >"$EMULATOR_LOG" 2>&1 &
EMULATOR_PID=$!
EMULATOR_START="$(process_start_time "$EMULATOR_PID")" \
    || fail 'cannot bind the emulator process generation'
[[ "$EMULATOR_START" =~ ^[1-9][0-9]*$ ]] \
    || fail 'the emulator process start time is malformed'

if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    grpc_ready=0
    for _ in $(seq 1 300); do
        is_exact_emulator_process \
            || fail 'the Android emulator exited before its display observer became ready'
        if frame_observer_listener_is_exact; then
            grpc_ready=1
            break
        fi
        sleep 0.1
    done
    [ "$grpc_ready" -eq 1 ] \
        || fail 'the emulator display observer is not one exact isolated [::]:8554 listener'
    printf 'ANDROID_EMULATOR_FRAME_ENDPOINT=pass connect=127.0.0.1:8554 bind=[::]:8554 namespace=loopback-only transport=grpc-stream network=container-none\n'
fi

boot_ready=0
for _ in $(seq 1 3600); do
    is_exact_emulator_process \
        || fail 'the Android emulator exited before framework readiness'
    sys_boot="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null \
        | tr -d '\r' || true)"
    dev_boot="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell getprop dev.bootcomplete 2>/dev/null \
        | tr -d '\r' || true)"
    bootanim="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell getprop init.svc.bootanim 2>/dev/null \
        | tr -d '\r' || true)"
    if [ "$sys_boot:$dev_boot:$bootanim" = 1:1:stopped ]; then
        boot_ready=1
        break
    fi
    sleep 1
done
[ "$boot_ready" -eq 1 ] || fail 'Android framework readiness exceeded 3600 seconds'

adb_shell_value() {
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell "$@" | tr -d '\r'
}

exercise_android_controlled_cpace() {
    local forward_output forward_listing expected_probe_output
    [ "$ANDROID_CONTROL_FORWARD_READY" -eq 0 ] \
        && [ -z "$ANDROID_CONTROL_FORWARD_LISTING" ] \
        || fail 'the Android controlled-side forward is already owned'
    forward_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --list | tr -d '\r')" \
        || fail 'cannot inspect the initial Android forward table'
    [ -z "$forward_listing" ] \
        || fail 'the clean Android emulator has a pre-existing forward mapping'
    android_control_forward_is_absent \
        || fail 'the private Android controlled-side probe port is already listening'
    forward_output="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --no-rebind \
        "$ANDROID_CONTROL_FORWARD_LOCAL_SPEC" \
        "$ANDROID_CONTROL_FORWARD_DEVICE_SPEC" | tr -d '\r')" \
        || fail 'cannot create the private Android controlled-side forward'
    ANDROID_CONTROL_FORWARD_READY=1
    case "$forward_output" in
        ''|22119) ;;
        *) fail 'creating the Android controlled-side forward returned unexpected output' ;;
    esac
    forward_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" forward --list | tr -d '\r')" \
        || fail 'cannot verify the private Android controlled-side forward'
    android_control_forward_listing_is_exact "$forward_listing" \
        || fail "the private Android controlled-side forward differs: $forward_listing"
    ANDROID_CONTROL_FORWARD_LISTING=$forward_listing
    android_control_forward_is_loopback_only \
        || fail 'the Android controlled-side forward is not one exact container-loopback listener'

    {
        printf '%s\n' "$TEST_PASSWORD" \
            | timeout --signal=TERM --kill-after=2s 60s \
                "$PEER_TARGET/debug/examples/probe_client" \
                127.0.0.1:22119 --password-stdin ok
        printf '%s\n' 'RuntimeWrong1x' \
            | timeout --signal=TERM --kill-after=2s 60s \
                "$PEER_TARGET/debug/examples/probe_client" \
                127.0.0.1:22119 --password-stdin fail
    } >"$ANDROID_CONTROLLED_CPACE_LOG" 2>&1 \
        || { tail -n 20 "$ANDROID_CONTROLLED_CPACE_LOG" >&2; fail 'the Android controlled-side CPace probe failed'; }
    [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_CONTROLLED_CPACE_LOG")" = \
      "$RUN_UID:$RUN_GID:600:1" ] \
        && [ "$(stat -c '%s' -- "$ANDROID_CONTROLLED_CPACE_LOG")" -le 4096 ] \
        || fail 'the Android controlled-side CPace receipt metadata differs'
    ! grep -Fq -- "$TEST_PASSWORD" "$ANDROID_CONTROLLED_CPACE_LOG" \
        && ! grep -Fq -- 'RuntimeWrong1x' "$ANDROID_CONTROLLED_CPACE_LOG" \
        || fail 'the Android controlled-side CPace receipt exposed a password'
    expected_probe_output=$'probe_client: keying ok=true (expected=ok)\nprobe_client: PASS\nprobe_client: keying ok=false (expected=fail)\nprobe_client: PASS'
    [ "$(<"$ANDROID_CONTROLLED_CPACE_LOG")" = "$expected_probe_output" ] \
        || { tail -n 20 "$ANDROID_CONTROLLED_CPACE_LOG" >&2; fail 'the Android controlled-side CPace receipt differs'; }
    remove_android_control_forward \
        || fail 'the private Android controlled-side forward did not close exactly'
    printf 'ANDROID_CONTROLLED_CPACE=pass initiator=linux-probe responder=android-mainservice correct=keyed wrong=refused transport=adb-forward-loopback forward_listener=127.0.0.1:22119 forward_cleanup=removed password_transport=stdin\n'
}

readonly APP_PACKAGE=com.carriez.flutter_hbb
readonly APP_ACTIVITY=$APP_PACKAGE/.MainActivity
readonly PEER_VIEW_ADDRESS=127.0.0.1:22118
readonly PEER_REVERSE_DEVICE_SPEC=tcp:22118
readonly PEER_REVERSE_CONTAINER_SPEC=tcp:21118
readonly SERVICE_START_WARNING_TEXT='Turning on "Screen Capture" will automatically start the service, allowing other devices to request a connection to your device.'
readonly UI_XML=$WORK_ROOT/window.xml
readonly FRAMEWORK_ANR_MARKER=$WORK_ROOT/framework-anr.waited
readonly IMMERSIVE_CLING_MARKER=$WORK_ROOT/immersive-cling.dismissed
readonly MAX_FRAMEWORK_ANR_WAITS=12
FRAMEWORK_INTERRUPTION_HANDLED=0

capture_ui_hierarchy() {
    local detail=${1:-compressed}
    local -a dump_args=(shell uiautomator dump)
    case "$detail" in
        compressed) dump_args+=(--compressed) ;;
        complete) ;;
        *) return 1 ;;
    esac
    dump_args+=(/data/local/tmp/rustdesk-window.xml)
    rm -f -- "$UI_XML"
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" "${dump_args[@]}" >/dev/null \
        || return 1
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" exec-out cat \
        /data/local/tmp/rustdesk-window.xml >"$UI_XML" \
        || return 1
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell rm -f \
        /data/local/tmp/rustdesk-window.xml >/dev/null \
        || return 1
    [ -f "$UI_XML" ] && [ ! -L "$UI_XML" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$UI_XML")" = 1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$UI_XML")" -gt 0 ] \
        && [ "$(stat -c '%s' -- "$UI_XML")" -le 1048576 ]
}

ui_center() {
    local kind=$1
    shift
    python3 -I -S - "$UI_XML" "$kind" "$@" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

path, kind, *wanted = sys.argv[1:]
if kind not in ("address-field", "focused-password-field") and not wanted:
    raise SystemExit(2)
nodes = ET.parse(path).getroot().iter("node")
centers = set()
for node in nodes:
    attributes = node.attrib
    if kind == "text":
        semantic_tokens = {
            token.strip()
            for key in ("text", "content-desc")
            for token in attributes.get(key, "").splitlines()
            if token.strip()
        }
        matched = any(value in semantic_tokens for value in wanted)
    elif kind == "resource":
        matched = attributes.get("resource-id") in wanted
    elif kind == "address-field":
        matched = (
            attributes.get("class") == "android.widget.EditText"
            and attributes.get("focusable") == "true"
            and attributes.get("enabled") == "true"
            and attributes.get("password") == "false"
            and (not wanted or attributes.get("text") in wanted)
        )
    elif kind == "focused-password-field":
        matched = (
            attributes.get("class") == "android.widget.EditText"
            and attributes.get("focusable") == "true"
            and attributes.get("focused") == "true"
            and attributes.get("enabled") == "true"
            and attributes.get("password") == "true"
        )
    else:
        raise SystemExit(2)
    if not matched:
        continue
    bounds = re.fullmatch(r"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]",
                          attributes.get("bounds", ""))
    if not bounds:
        continue
    left, top, right, bottom = map(int, bounds.groups())
    if right <= left or bottom <= top:
        continue
    centers.add(((left + right) // 2, (top + bottom) // 2))
if len(centers) != 1:
    raise SystemExit(1)
for x, y in sorted(centers, key=lambda point: (point[1], point[0])):
    print(f"{x} {y}")
PY
}

ui_button_enabled_state() {
    local label=$1
    python3 -I -S - "$UI_XML" "$label" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, label = sys.argv[1:]
states = set()
for node in ET.parse(path).getroot().iter("node"):
    attributes = node.attrib
    semantic_tokens = {
        token.strip()
        for key in ("text", "content-desc")
        for token in attributes.get(key, "").splitlines()
        if token.strip()
    }
    if (
        label in semantic_tokens
        and attributes.get("class") == "android.widget.Button"
        and attributes.get("enabled") in ("true", "false")
    ):
        states.add(attributes["enabled"])
if len(states) != 1:
    raise SystemExit(1)
print(states.pop())
PY
}

ui_checkbox_checked() {
    local expected=$1
    python3 -I -S - "$UI_XML" "$expected" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, expected = sys.argv[1:]
states = set()
for node in ET.parse(path).getroot().iter("node"):
    attributes = node.attrib
    semantic_tokens = {
        token.strip()
        for key in ("text", "content-desc")
        for token in attributes.get(key, "").splitlines()
        if token.strip()
    }
    if (
        expected in semantic_tokens
        and attributes.get("class") == "android.widget.CheckBox"
        and attributes.get("enabled") == "true"
        and attributes.get("checked") in ("true", "false")
    ):
        states.add(attributes["checked"])
if len(states) != 1:
    raise SystemExit(1)
print(states.pop())
PY
}

ui_password_field_semantics() {
    local mode=$1
    shift
    python3 -I -S - "$UI_XML" "$mode" "$@" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET


def parse_bounds(value):
    match = re.fullmatch(
        r"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]",
        value,
    )
    if not match:
        return None
    left, top, right, bottom = map(int, match.groups())
    if right <= left or bottom <= top:
        return None
    return left, top, right, bottom


path, mode, *arguments = sys.argv[1:]
if mode not in ("focused-remaining", "center-with-remaining"):
    raise SystemExit(2)
fields = []
counters = []
for node in ET.parse(path).getroot().iter("node"):
    attributes = node.attrib
    bounds = parse_bounds(attributes.get("bounds", ""))
    if bounds is None:
        continue
    if (
        attributes.get("class") == "android.widget.EditText"
        and attributes.get("focusable") == "true"
        and attributes.get("enabled") == "true"
        and attributes.get("password") == "true"
    ):
        fields.append((bounds, attributes.get("focused") == "true"))
    semantic_tokens = {
        token.strip()
        for key in ("text", "content-desc")
        for token in attributes.get(key, "").splitlines()
        if token.strip()
    }
    for remaining in {
        int(match.group(1))
        for token in semantic_tokens
        if (match := re.fullmatch(r"([0-9]+) characters remaining", token))
    }:
        counters.append((bounds, remaining))


def field_remaining(field):
    field_left, field_top, field_right, field_bottom = field
    values = {
        remaining
        for (counter_left, counter_top, counter_right, counter_bottom), remaining
        in counters
        if counter_left >= field_left
        and counter_top >= field_top
        and counter_right <= field_right
        and counter_bottom <= field_bottom
    }
    return values.pop() if len(values) == 1 else None


if mode == "focused-remaining":
    if arguments:
        raise SystemExit(2)
    focused = {field for field, is_focused in fields if is_focused}
    if len(focused) != 1:
        raise SystemExit(1)
    remaining = field_remaining(focused.pop())
    if remaining is None:
        raise SystemExit(1)
    print(remaining)
else:
    if len(arguments) != 1:
        raise SystemExit(2)
    expected_remaining = int(arguments[0])
    matching = {
        field for field, _ in fields
        if field_remaining(field) == expected_remaining
    }
    if len(matching) != 1:
        raise SystemExit(1)
    left, top, right, bottom = matching.pop()
    print((left + right) // 2, (top + bottom) // 2)
PY
}

ui_focused_password_remaining() {
    ui_password_field_semantics focused-remaining
}

ui_password_field_center_with_remaining() {
    ui_password_field_semantics center-with-remaining "$1"
}

fill_focused_password() {
    local password=$1 expected_remaining=$2
    local observed_remaining=
    for _ in $(seq 1 3); do
        wait_ui_center focused-password-field >/dev/null \
            || return 1
        "$ADB" -s "$SERIAL" shell input keycombination \
            KEYCODE_CTRL_LEFT KEYCODE_A >/dev/null \
            || fail 'cannot select the disposable password field'
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_DEL >/dev/null \
            || fail 'cannot clear the disposable password field'
        "$ADB" -s "$SERIAL" shell input text "$password" >/dev/null \
            || fail 'cannot enter the disposable password'
        for _ in $(seq 1 12); do
            if capture_unobscured_ui_hierarchy complete; then
                ! grep -Fq "$password" "$UI_XML" \
                    || fail 'the Android accessibility hierarchy exposed the password'
                observed_remaining="$(ui_focused_password_remaining 2>/dev/null || true)"
                if [ "$observed_remaining" = "$expected_remaining" ]; then
                    return 0
                fi
            fi
            sleep 0.5
        done
    done
    return 1
}

enter_exact_password() {
    local field_x=$1 field_y=$2 password=$3 expected_remaining=$4
    "$ADB" -s "$SERIAL" shell input tap "$field_x" "$field_y" \
        >/dev/null \
        || fail 'cannot focus the disposable password field'
    sleep 0.5
    fill_focused_password "$password" "$expected_remaining"
}

ui_resource_bounds() {
    local resource=$1
    python3 -I -S - "$UI_XML" "$resource" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

path, resource = sys.argv[1:]
bounds = set()
for node in ET.parse(path).getroot().iter("node"):
    attributes = node.attrib
    if attributes.get("resource-id") != resource:
        continue
    match = re.fullmatch(
        r"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]",
        attributes.get("bounds", ""),
    )
    if not match:
        continue
    left, top, right, bottom = map(int, match.groups())
    if right > left and bottom > top:
        bounds.add((left, top, right, bottom))
if len(bounds) != 1:
    raise SystemExit(1)
print(*bounds.pop())
PY
}

wait_ui_resource_bounds() {
    local resource=$1 bounds=
    for _ in $(seq 1 12); do
        if capture_unobscured_ui_hierarchy complete; then
            bounds="$(ui_resource_bounds "$resource" 2>/dev/null || true)"
            if [[ "$bounds" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
                printf '%s\n' "$bounds"
                return 0
            fi
        fi
        sleep 0.5
    done
    return 1
}

print_initial_ui_semantics() {
    python3 -I -S - "$UI_XML" <<'PY' >&2
import sys
import xml.etree.ElementTree as ET

shown = 0
for node in ET.parse(sys.argv[1]).getroot().iter("node"):
    attributes = node.attrib
    values = []
    for key in ("text", "content-desc", "resource-id"):
        if attributes.get("password") == "true" and key in ("text", "content-desc"):
            continue
        value = attributes.get(key, "").strip()
        if value:
            values.append(f"{key}={value[:240]!r}")
    if not values and attributes.get("class") != "android.widget.EditText":
        continue
    print("Android initial UI:", " ".join(values),
          f"class={attributes.get('class', '')!r}",
          f"bounds={attributes.get('bounds', '')!r}",
          f"focusable={attributes.get('focusable', '')!r}",
          f"focused={attributes.get('focused', '')!r}",
          f"enabled={attributes.get('enabled', '')!r}",
          f"password={attributes.get('password', '')!r}")
    shown += 1
    if shown == 80:
        break
PY
}

print_mobile_storage_key_log() {
    local storage_log
    storage_log="$(timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" logcat -d -v brief \
        'MainApplication:D' 'MobileAtRestStorageKey:D' '*:S' \
        2>/dev/null || true)"
    [ "${#storage_log}" -le 65536 ] \
        || fail 'the bounded Android storage-key diagnostic exceeds 64 KiB'
    if [ -n "$storage_log" ]; then
        printf 'Android storage-key diagnostic:\n%s\n' "$storage_log" >&2
    else
        printf 'Android storage-key diagnostic: no matching log records\n' >&2
    fi
}

print_native_password_log() {
    local log_dir=/storage/emulated/0/RustDesk/Logs
    local listing= latest= filename= native_log= password_log=
    listing="$(adb_shell_value ls -1t "$log_dir" 2>/dev/null || true)"
    [ "${#listing}" -le 32768 ] \
        || fail 'the bounded Android native-log inventory exceeds 32 KiB'
    while IFS= read -r filename; do
        [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || continue
        latest=$filename
        break
    done <<<"$listing"
    if [ -z "$latest" ]; then
        printf 'Android native password diagnostic: no release log file\n' >&2
        return
    fi
    native_log="$(timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" exec-out tail -c 65536 "$log_dir/$latest" \
        2>/dev/null | tr -d '\r' || true)"
    [ "${#native_log}" -le 65536 ] \
        || fail 'the bounded Android native password diagnostic exceeds 64 KiB'
    password_log="$(printf '%s\n' "$native_log" \
        | grep -Ei 'permanent password|at-rest storage key|config durability' \
        || true)"
    if [ -n "$password_log" ]; then
        printf 'Android native password diagnostic (%s):\n%s\n' \
            "$latest" "$password_log" >&2
    else
        printf 'Android native password diagnostic (%s): no matching records\n' \
            "$latest" >&2
    fi
}

print_password_submit_thread_diagnostic() {
    local threads= cpu= backtrace=
    printf 'ANDROID_PASSWORD_SUBMIT_DIAGNOSTIC_BEGIN\n' >&2
    printf 'Android password-submit diagnostic: app_pid=%s\n' \
        "${APP_PID:-unavailable}" >&2
    if [[ "${APP_PID:-}" =~ ^[1-9][0-9]*$ ]]; then
        threads="$(timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" shell ps -T -p "$APP_PID" \
            -o PID,TID,NAME,STAT 2>/dev/null \
            | tr -d '\r' | head -n 128 | tail -c 32768 || true)"
        if [ -n "$threads" ]; then
            printf 'Android password-submit threads:\n%s\n' "$threads" >&2
        else
            printf 'Android password-submit threads: unavailable\n' >&2
        fi
        cpu="$(timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" shell dumpsys cpuinfo 2>/dev/null \
            | tr -d '\r' | grep -F "$APP_PACKAGE" \
            | head -n 16 | tail -c 16384 || true)"
        if [ -n "$cpu" ]; then
            printf 'Android password-submit CPU:\n%s\n' "$cpu" >&2
        else
            printf 'Android password-submit CPU: unavailable\n' >&2
        fi
        backtrace="$(timeout --signal=TERM --kill-after=2s 30s \
            "$ADB" -s "$SERIAL" shell debuggerd -b "$APP_PID" \
            2>&1 | tr -d '\r' | tail -c 131072 || true)"
        if [ -n "$backtrace" ]; then
            printf 'Android password-submit native backtrace:\n%s\n' \
                "$backtrace" >&2
        else
            printf 'Android password-submit native backtrace: unavailable\n' >&2
        fi
    fi
    printf 'ANDROID_PASSWORD_SUBMIT_DIAGNOSTIC_END\n' >&2
}

handle_framework_interruption() {
    local cling_title= cling_ok= cling_x= cling_y=
    local anr_title= anr_wait= anr_x= anr_y= anr_wait_count=0
    FRAMEWORK_INTERRUPTION_HANDLED=0

    cling_title="$(ui_center text 'Viewing full screen' 2>/dev/null || true)"
    if [[ "$cling_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
        cling_ok="$(ui_center resource android:id/ok 2>/dev/null || true)"
        [[ "$cling_ok" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
        read -r cling_x cling_y <<<"$cling_ok"
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell input tap "$cling_x" "$cling_y" \
            >/dev/null || return 1
        printf 'dismissed\n' >>"$IMMERSIVE_CLING_MARKER"
        [ "$(wc -l <"$IMMERSIVE_CLING_MARKER")" -le 1 ] || return 1
        FRAMEWORK_INTERRUPTION_HANDLED=1
        sleep 1
        return 0
    fi

    anr_title="$(ui_center text "System UI isn't responding" \
        "Process system isn't responding" 2>/dev/null || true)"
    if ! [[ "$anr_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
        return 0
    fi
    if [ -e "$FRAMEWORK_ANR_MARKER" ] \
       || [ -L "$FRAMEWORK_ANR_MARKER" ]; then
        [ -f "$FRAMEWORK_ANR_MARKER" ] && [ ! -L "$FRAMEWORK_ANR_MARKER" ] \
            || return 1
        [ "$(stat -c '%u:%g:%a:%h' -- "$FRAMEWORK_ANR_MARKER")" = \
          "$RUN_UID:$RUN_GID:600:1" ] || return 1
        anr_wait_count="$(wc -l <"$FRAMEWORK_ANR_MARKER")"
    fi
    [ "$anr_wait_count" -lt "$MAX_FRAMEWORK_ANR_WAITS" ] || return 1
    anr_wait="$(ui_center resource android:id/aerr_wait 2>/dev/null || true)"
    [[ "$anr_wait" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
    printf 'waited\n' >>"$FRAMEWORK_ANR_MARKER"
    read -r anr_x anr_y <<<"$anr_wait"
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input tap "$anr_x" "$anr_y" \
        >/dev/null || return 1
    FRAMEWORK_INTERRUPTION_HANDLED=1
    sleep 2
}

capture_unobscured_ui_hierarchy() {
    local detail=${1:-compressed}
    while :; do
        capture_ui_hierarchy "$detail" || return 1
        handle_framework_interruption || return 1
        if [ "$FRAMEWORK_INTERRUPTION_HANDLED" -eq 0 ]; then
            return 0
        fi
    done
}

framework_anr_receipt() {
    local anr_wait_count=
    if [ ! -e "$FRAMEWORK_ANR_MARKER" ]; then
        [ ! -L "$FRAMEWORK_ANR_MARKER" ] || return 1
        printf 'absent\n'
        return 0
    fi
    [ -f "$FRAMEWORK_ANR_MARKER" ] && [ ! -L "$FRAMEWORK_ANR_MARKER" ] \
        || return 1
    [ "$(stat -c '%u:%g:%a:%h' -- "$FRAMEWORK_ANR_MARKER")" = \
      "$RUN_UID:$RUN_GID:600:1" ] || return 1
    anr_wait_count="$(wc -l <"$FRAMEWORK_ANR_MARKER")"
    [[ "$anr_wait_count" =~ ^[1-9][0-9]*$ ]] \
        && [ "$anr_wait_count" -le "$MAX_FRAMEWORK_ANR_WAITS" ] || return 1
    printf 'waited-%s\n' "$anr_wait_count"
}

wait_ui_center() {
    local kind=$1
    shift
    local center= ui_attempt=0
    while [ "$ui_attempt" -lt 12 ]; do
        if capture_unobscured_ui_hierarchy; then
            center="$(ui_center "$kind" "$@" 2>/dev/null || true)"
            if [[ "$center" =~ ^[0-9]+\ [0-9]+$ ]]; then
                printf '%s\n' "$center"
                return 0
            fi
        fi
        ui_attempt=$((ui_attempt + 1))
        sleep 0.5
    done
    return 1
}

ui_semantic_token_count() {
    local token=$1
    python3 -I -S - "$UI_XML" "$token" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, token = sys.argv[1:]
count = 0
for node in ET.parse(path).getroot().iter("node"):
    attributes = node.attrib
    semantic_tokens = {
        value.strip()
        for key in ("text", "content-desc")
        for value in attributes.get(key, "").splitlines()
        if value.strip()
    }
    if token in semantic_tokens:
        count += 1
print(count)
PY
}

assert_peer_presentation_ui_finality() {
    local phase=$1 token count
    capture_unobscured_ui_hierarchy complete || return 1
    for token in \
        'Connecting...' \
        'Password required' \
        'Connected, waiting for image...'; do
        count="$(ui_semantic_token_count "$token")" || return 1
        [ "$count" -eq 0 ] || {
            printf 'ANDROID_PEER_PRESENTATION_UI=fail phase=%s token=%s count=%s\n' \
                "$phase" "$token" "$count"
            return 1
        }
    done
    printf 'ANDROID_PEER_PRESENTATION_UI=pass phase=%s connecting=retired credential=retired waiting=retired\n' \
        "$phase"
}

tap_ui() {
    local kind=$1
    shift
    local center x y
    center="$(wait_ui_center "$kind" "$@")" || return 1
    read -r x y <<<"$center"
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null
}

grant_media_projection_after_password_submit() {
    local started_ms now_ms elapsed_ms consent password_error x y
    local password_title waiting ok_state home_action password_ok
    local submit_x submit_y last_submit_ms=0
    local acknowledged=0 ack_ms=0 submit_attempt=0
    started_ms="$(monotonic_millis)" || return 2
    while :; do
        if capture_ui_hierarchy complete; then
            handle_framework_interruption || return 1
            if [ "$FRAMEWORK_INTERRUPTION_HANDLED" -eq 1 ]; then
                continue
            fi
            consent="$(ui_center resource android:id/button1 2>/dev/null || true)"
            if [[ "$consent" =~ ^[0-9]+\ [0-9]+$ ]]; then
                read -r x y <<<"$consent"
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input tap "$x" "$y" \
                    >/dev/null || return 1
                now_ms="$(monotonic_millis)" || return 2
                elapsed_ms=$((now_ms - started_ms))
                if [ "$acknowledged" -eq 0 ]; then
                    acknowledged=1
                    ack_ms=$elapsed_ms
                fi
                printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=pass result=media-projection-consent-ready ack_ms=%s wait_ms=%s limit_ms=%s\n' \
                    "$ack_ms" \
                    "$elapsed_ms" \
                    "$PERMANENT_PASSWORD_SUBMIT_LIMIT_MS"
                return 0
            fi
            password_error="$(ui_center text \
                'Prompt: Failed' \
                'Prompt: The confirmation is not identical.' \
                2>/dev/null || true)"
            if [[ "$password_error" =~ ^[0-9]+\ [0-9]+$ ]]; then
                now_ms="$(monotonic_millis)" || return 2
                printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=fail result=validation-error wait_ms=%s limit_ms=%s\n' \
                    "$((now_ms - started_ms))" \
                    "$PERMANENT_PASSWORD_SUBMIT_LIMIT_MS"
                return 1
            fi
            password_title="$(ui_center text 'Set password' 2>/dev/null || true)"
            if [[ "$password_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                waiting="$(ui_center text 'Waiting' 2>/dev/null || true)"
                ok_state="$(ui_button_enabled_state 'OK' 2>/dev/null || true)"
                if [ "$acknowledged" -eq 0 ] \
                   && [[ "$waiting" =~ ^[0-9]+\ [0-9]+$ ]] \
                   && [ "$ok_state" = false ]; then
                    now_ms="$(monotonic_millis)" || return 2
                    ack_ms=$((now_ms - started_ms))
                    acknowledged=1
                    printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=progress result=mutation-owned ack_ms=%s ack_limit_ms=%s\n' \
                        "$ack_ms" "$PERMANENT_PASSWORD_SUBMIT_ACK_LIMIT_MS"
                elif [ "$acknowledged" -eq 0 ] && [ "$ok_state" = true ]; then
                    now_ms="$(monotonic_millis)" || return 2
                    if [ "$submit_attempt" -lt \
                         "$PERMANENT_PASSWORD_SUBMIT_TAP_ATTEMPTS" ] \
                       && { [ "$submit_attempt" -eq 0 ] \
                            || [ "$((now_ms - last_submit_ms))" -ge \
                                 "$PERMANENT_PASSWORD_SUBMIT_TAP_RETRY_MS" ]; }; then
                        password_ok="$(ui_center text 'OK' 2>/dev/null || true)"
                        [[ "$password_ok" =~ ^[0-9]+\ [0-9]+$ ]] \
                            || return 1
                        read -r submit_x submit_y <<<"$password_ok"
                        timeout --signal=TERM --kill-after=2s 10s \
                            "$ADB" -s "$SERIAL" shell input tap \
                            "$submit_x" "$submit_y" >/dev/null \
                            || return 1
                        submit_attempt=$((submit_attempt + 1))
                        last_submit_ms="$now_ms"
                        printf 'ANDROID_PERMANENT_PASSWORD_ACTION=injected attempt=%s max_attempts=%s elapsed_ms=%s target=current-enabled-semantic-ok\n' \
                            "$submit_attempt" \
                            "$PERMANENT_PASSWORD_SUBMIT_TAP_ATTEMPTS" \
                            "$((now_ms - started_ms))"
                    fi
                fi
            elif [ "$acknowledged" -eq 0 ]; then
                home_action="$(ui_center text \
                    'Start screen sharing' 2>/dev/null || true)"
                if [[ "$home_action" =~ ^[0-9]+\ [0-9]+$ ]]; then
                    now_ms="$(monotonic_millis)" || return 2
                    ack_ms=$((now_ms - started_ms))
                    acknowledged=1
                    printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=progress result=dialog-retired-after-durable-write ack_ms=%s ack_limit_ms=%s\n' \
                        "$ack_ms" "$PERMANENT_PASSWORD_SUBMIT_ACK_LIMIT_MS"
                fi
            fi
        fi
        now_ms="$(monotonic_millis)" || return 2
        elapsed_ms=$((now_ms - started_ms))
        if [ "$acknowledged" -eq 0 ] \
           && [ "$elapsed_ms" -ge \
                "$PERMANENT_PASSWORD_SUBMIT_ACK_LIMIT_MS" ]; then
            printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=fail result=action-not-acknowledged attempts=%s wait_ms=%s ack_limit_ms=%s\n' \
                "$submit_attempt" "$elapsed_ms" \
                "$PERMANENT_PASSWORD_SUBMIT_ACK_LIMIT_MS"
            return 1
        fi
        if [ "$elapsed_ms" -ge \
             "$PERMANENT_PASSWORD_SUBMIT_LIMIT_MS" ]; then
            printf 'ANDROID_PERMANENT_PASSWORD_SUBMIT=fail result=consent-not-requested acknowledged=%s ack_ms=%s wait_ms=%s limit_ms=%s\n' \
                "$acknowledged" "$ack_ms" "$elapsed_ms" \
                "$PERMANENT_PASSWORD_SUBMIT_LIMIT_MS"
            return 1
        fi
        sleep 0.5
    done
}

wait_resumed_activity() {
    local state
    for _ in $(seq 1 120); do
        state="$(adb_shell_value dumpsys activity activities 2>/dev/null || true)"
        if grep -Eq 'mResumedActivity:.*com\.carriez\.flutter_hbb/\.MainActivity|topResumedActivity=.*com\.carriez\.flutter_hbb/\.MainActivity' \
            <<<"$state"; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

stage_recents_gesture_driver() {
    local push_output= device_checksum= device_digest= device_path= extra=
    local runtime_checksum= runtime_digest= runtime_path=
    [ "$RECENTS_GESTURE_STAGED" -eq 0 ] || return 1
    push_output="$(timeout --signal=TERM --kill-after=2s 30s \
        "$ADB" -s "$SERIAL" push --sync \
        "$RECENTS_GESTURE_JAR" "$RECENTS_GESTURE_DEVICE_PATH" \
        2>&1 | tr -d '\r')" \
        || { printf '%s\n' "$push_output" >&2; return 1; }
    [ "${#push_output}" -le 4096 ] || return 1
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell chmod 0400 \
        "$RECENTS_GESTURE_DEVICE_PATH" >/dev/null \
        || return 1
    device_checksum="$(adb_shell_value sha256sum \
        "$RECENTS_GESTURE_DEVICE_PATH")" || return 1
    read -r device_digest device_path extra <<<"$device_checksum"
    [ "$device_digest" = "$RECENTS_GESTURE_SHA256" ] \
        && [ "$device_path" = "$RECENTS_GESTURE_DEVICE_PATH" ] \
        && [ -z "$extra" ] \
        || return 1
    runtime_checksum="$(adb_shell_value sha256sum \
        "$RECENTS_RUNTIME_UIAUTOMATOR_PATH")" || return 1
    read -r runtime_digest runtime_path extra <<<"$runtime_checksum"
    [[ "$runtime_digest" =~ ^[0-9a-f]{64}$ ]] \
        && [ "$runtime_path" = "$RECENTS_RUNTIME_UIAUTOMATOR_PATH" ] \
        && [ -z "$extra" ] \
        || return 1
    RECENTS_RUNTIME_UIAUTOMATOR_SHA256=$runtime_digest
    RECENTS_GESTURE_STAGED=1
    printf 'ANDROID_RECENTS_GESTURE_DRIVER=pass sha256=%s framework=android14-ui-automation-direct open=ui-automation-app-switch-key-display-0 events=%s steps=%s step_ms=%s wait_for_animations=false runtime_uiautomator_sha256=%s device_path=%s\n' \
        "$RECENTS_GESTURE_SHA256" "$RECENTS_DISMISS_GESTURE_EVENTS" \
        "$RECENTS_DISMISS_GESTURE_STEPS" "$RECENTS_DISMISS_GESTURE_STEP_MS" \
        "$RECENTS_RUNTIME_UIAUTOMATOR_SHA256" "$RECENTS_GESTURE_DEVICE_PATH"
}

retire_recents_gesture_driver() {
    [ "$RECENTS_GESTURE_STAGED" -eq 1 ] || return 1
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell rm -f \
        "$RECENTS_GESTURE_DEVICE_PATH" >/dev/null \
        || return 1
    if timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell test -e \
        "$RECENTS_GESTURE_DEVICE_PATH" >/dev/null 2>&1; then
        return 1
    fi
    RECENTS_GESTURE_STAGED=0
}

app_task_state() {
    local state
    state="$(adb_shell_value dumpsys activity recents)" || return 1
    python3 -I -S - "$state" <<'PY'
import re
import sys

task_ids = set()
for line in sys.argv[1].splitlines():
    stripped = line.lstrip()
    # RecentTasks also dumps mHiddenTasks=[Task{...}] for non-empty tasks that
    # have already been removed from Recents. Only the active raw-list entries
    # identify cards that a user can still see and dismiss.
    if (not stripped.startswith("* Recent #")
            or ": Task{" not in stripped
            or "com.carriez.flutter_hbb" not in stripped):
        continue
    match = re.search(r"Task\{[^}]* #[1-9][0-9]*\b", stripped)
    if match:
        task_ids.add(match.group().rsplit("#", 1)[1])
if not task_ids:
    print("absent")
elif len(task_ids) == 1:
    print(task_ids.pop())
else:
    raise SystemExit(1)
PY
}

current_app_task_id() {
    local state
    state="$(app_task_state)" || return 1
    [[ "$state" =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s\n' "$state"
}

open_app_recents() {
    local expected_task_id=$1 lifecycle_cycle=$2
    local open_output= open_receipt= elapsed_ms=
    capture_unobscured_ui_hierarchy complete || return 1
    if ! open_output="$(timeout --signal=TERM --kill-after=2s 30s \
        "$ADB" -s "$SERIAL" shell env \
        "CLASSPATH=$RECENTS_RUNTIME_UIAUTOMATOR_PATH:$RECENTS_GESTURE_DEVICE_PATH" \
        /system/bin/app_process /system/bin \
        com.rustdesk.harness.AndroidRecentsDismiss \
        open-recents-with-app-switch-key \
        2>&1 | tr -d '\r')"; then
        printf 'ANDROID_RECENTS_OPEN_OUTPUT_BEGIN cycle=%s task_id=%s\n%s\nANDROID_RECENTS_OPEN_OUTPUT_END cycle=%s task_id=%s\n' \
            "$lifecycle_cycle" "$expected_task_id" "$open_output" \
            "$lifecycle_cycle" "$expected_task_id" >&2
        return 1
    fi
    open_receipt="$(grep -E \
        '^ANDROID_RECENTS_DIRECT_OPEN=pass action=ui-automation-app-switch-key key=KEYCODE_APP_SWITCH keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false elapsed_ms=[0-9]+$' \
        <<<"$open_output" || true)"
    [ "${#open_output}" -le 16384 ] \
        && [ "$(grep -c '^ANDROID_RECENTS_DIRECT_OPEN=' \
             <<<"$open_output")" -eq 1 ] \
        && [ -n "$open_receipt" ] \
        || {
            printf 'ANDROID_RECENTS_OPEN_OUTPUT_BEGIN cycle=%s task_id=%s\n%s\nANDROID_RECENTS_OPEN_OUTPUT_END cycle=%s task_id=%s\n' \
                "$lifecycle_cycle" "$expected_task_id" "$open_output" \
                "$lifecycle_cycle" "$expected_task_id" >&2
            return 1
        }
    [[ "$open_receipt" =~ elapsed_ms=([0-9]+)$ ]] \
        || return 1
    elapsed_ms=${BASH_REMATCH[1]}
    [ "$elapsed_ms" -le 5000 ] || return 1
    printf 'ANDROID_RECENTS_OPEN_ACTION=injected cycle=%s task_id=%s mechanism=android14-ui-automation-app-switch-key keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false driver_elapsed_ms=%s driver_sha256=%s\n' \
        "$lifecycle_cycle" "$expected_task_id" \
        "$elapsed_ms" \
        "$RECENTS_GESTURE_SHA256"
}

swipe_app_task_from_recents() {
    local expected_task_id=$1 lifecycle_cycle=$2
    local current_task_id= task_bounds=
    local left= top= right= bottom= center_x= center_y=
    local gesture_output= injection_receipt= injection_elapsed_ms=
    [ "$RECENTS_GESTURE_STAGED" -eq 1 ] || return 1
    current_task_id="$(current_app_task_id 2>/dev/null || true)"
    [ "$current_task_id" = "$expected_task_id" ] || return 1
    open_app_recents "$expected_task_id" "$lifecycle_cycle" || return 1
    task_bounds="$(wait_ui_resource_bounds \
        com.android.launcher3:id/snapshot 2>/dev/null || true)"
    if ! [[ "$task_bounds" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
        capture_ui_hierarchy complete && print_initial_ui_semantics
        return 1
    fi
    read -r left top right bottom <<<"$task_bounds"
    [ "$right" -gt "$left" ] && [ "$bottom" -gt "$top" ] \
        || return 1
    center_x=$(((left + right) / 2))
    center_y=$(((top + bottom) / 2))
    if ! gesture_output="$(timeout --signal=TERM --kill-after=2s 30s \
        "$ADB" -s "$SERIAL" shell env \
        "CLASSPATH=$RECENTS_RUNTIME_UIAUTOMATOR_PATH:$RECENTS_GESTURE_DEVICE_PATH" \
        /system/bin/app_process /system/bin \
        com.rustdesk.harness.AndroidRecentsDismiss \
        "$center_x" "$center_y" "$center_x" 0 \
        2>&1 | tr -d '\r')"; then
        printf 'ANDROID_RECENTS_GESTURE_OUTPUT_BEGIN cycle=%s task_id=%s\n%s\nANDROID_RECENTS_GESTURE_OUTPUT_END cycle=%s task_id=%s\n' \
            "$lifecycle_cycle" "$expected_task_id" "$gesture_output" \
            "$lifecycle_cycle" "$expected_task_id" >&2
        return 1
    fi
    injection_receipt="$(grep -E \
        '^ANDROID_RECENTS_DIRECT_INJECTION=pass events=12 steps=10 step_ms=16 wait_for_animations=false elapsed_ms=[0-9]+$' \
        <<<"$gesture_output" || true)"
    [ "${#gesture_output}" -le 16384 ] \
        && [ "$(grep -c '^ANDROID_RECENTS_DIRECT_INJECTION=' \
             <<<"$gesture_output")" -eq 1 ] \
        && [ -n "$injection_receipt" ] \
        || {
            printf 'ANDROID_RECENTS_GESTURE_OUTPUT_BEGIN cycle=%s task_id=%s\n%s\nANDROID_RECENTS_GESTURE_OUTPUT_END cycle=%s task_id=%s\n' \
                "$lifecycle_cycle" "$expected_task_id" "$gesture_output" \
                "$lifecycle_cycle" "$expected_task_id" >&2
            return 1
        }
    [[ "$injection_receipt" =~ elapsed_ms=([0-9]+)$ ]] || return 1
    injection_elapsed_ms=${BASH_REMATCH[1]}
    [ "$injection_elapsed_ms" -ge \
      "$((RECENTS_DISMISS_GESTURE_STEPS * RECENTS_DISMISS_GESTURE_STEP_MS))" ] \
        && [ "$injection_elapsed_ms" -le 5000 ] \
        || return 1
    printf 'ANDROID_RECENTS_DISMISS_ACTION=injected cycle=%s task_id=%s bounds=%s,%s,%s,%s start=%s,%s end=%s,%s framework=android14-ui-automation-direct events=%s steps=%s step_ms=%s wait_for_animations=false driver_elapsed_ms=%s driver_sha256=%s\n' \
        "$lifecycle_cycle" "$expected_task_id" \
        "$left" "$top" "$right" "$bottom" "$center_x" "$center_y" "$center_x" 0 \
        "$RECENTS_DISMISS_GESTURE_EVENTS" "$RECENTS_DISMISS_GESTURE_STEPS" \
        "$RECENTS_DISMISS_GESTURE_STEP_MS" "$injection_elapsed_ms" \
        "$RECENTS_GESTURE_SHA256"
}

print_app_task_diagnostic() {
    local lifecycle_cycle=$1 expected_task_id=$2 state=
    state="$(adb_shell_value dumpsys activity recents)" || return 1
    [ "${#state}" -le 1048576 ] || return 1
    python3 -I -S - "$lifecycle_cycle" "$expected_task_id" "$state" <<'PY'
import sys

cycle, expected_task_id, state = sys.argv[1:]
records = []
for line in state.splitlines():
    stripped = line.lstrip()
    if "com.carriez.flutter_hbb" not in stripped:
        continue
    if stripped.startswith("* Recent #") and ": Task{" in stripped:
        records.append(("active", stripped))
    elif stripped.startswith("mHiddenTasks="):
        records.append(("hidden", stripped))

if len(records) > 8 or any(len(line) > 4096 for _, line in records):
    raise SystemExit(1)

print(
    "ANDROID_RECENTS_TASK_DIAGNOSTIC_BEGIN "
    f"cycle={cycle} task_id={expected_task_id} records={len(records)}"
)
if records:
    for kind, line in records:
        print(f"ANDROID_RECENTS_TASK_RECORD kind={kind} value={line}")
else:
    print("ANDROID_RECENTS_TASK_RECORD kind=none")
print(
    "ANDROID_RECENTS_TASK_DIAGNOSTIC_END "
    f"cycle={cycle} task_id={expected_task_id}"
)
PY
}

dismiss_current_app_task() {
    local lifecycle_cycle=$1 task_id= observed_task_state=
    local outcome_started_ms= outcome_now_ms= outcome_elapsed_ms=
    task_id="$(current_app_task_id 2>/dev/null || true)"
    [[ "$task_id" =~ ^[1-9][0-9]*$ ]] || return 1
    swipe_app_task_from_recents "$task_id" "$lifecycle_cycle" || return 1
    outcome_started_ms="$(monotonic_millis)" || return 1
    for _ in $(seq 1 "$RECENTS_DISMISS_OUTCOME_POLLS"); do
        observed_task_state="$(app_task_state 2>/dev/null || true)"
        if [ "$observed_task_state" = absent ]; then
            RECENTS_LAST_TASK_ID=$task_id
            printf 'ANDROID_RECENTS_DISMISS_OUTCOME=pass cycle=%s task_id=%s actions=1\n' \
                "$lifecycle_cycle" "$task_id"
            return 0
        fi
        if [ "$observed_task_state" != "$task_id" ]; then
            outcome_now_ms="$(monotonic_millis)" || return 1
            outcome_elapsed_ms=$((outcome_now_ms - outcome_started_ms))
            printf 'ANDROID_RECENTS_DISMISS_OUTCOME=fail cycle=%s task_id=%s observed=%s polls=%s elapsed_ms=%s\n' \
                "$lifecycle_cycle" "$task_id" \
                "${observed_task_state:-invalid}" \
                "$RECENTS_DISMISS_OUTCOME_POLLS" "$outcome_elapsed_ms" >&2
            print_app_task_diagnostic "$lifecycle_cycle" "$task_id" >&2 \
                || printf 'ANDROID_RECENTS_TASK_DIAGNOSTIC=unavailable cycle=%s task_id=%s\n' \
                    "$lifecycle_cycle" "$task_id" >&2
            return 1
        fi
        sleep 0.25
    done
    outcome_now_ms="$(monotonic_millis)" || return 1
    outcome_elapsed_ms=$((outcome_now_ms - outcome_started_ms))
    printf 'ANDROID_RECENTS_DISMISS_OUTCOME=fail cycle=%s task_id=%s observed=%s polls=%s elapsed_ms=%s\n' \
        "$lifecycle_cycle" "$task_id" "$observed_task_state" \
        "$RECENTS_DISMISS_OUTCOME_POLLS" "$outcome_elapsed_ms" >&2
    print_app_task_diagnostic "$lifecycle_cycle" "$task_id" >&2 \
        || printf 'ANDROID_RECENTS_TASK_DIAGNOSTIC=unavailable cycle=%s task_id=%s\n' \
            "$lifecycle_cycle" "$task_id" >&2
    return 1
}

assert_main_service() {
    local state
    state="$(adb_shell_value dumpsys activity services "$APP_PACKAGE")" \
        || return 1
    grep -qF "$APP_PACKAGE/.MainService" <<<"$state" \
        && grep -qF 'isForeground=true' <<<"$state" \
        && grep -qF 'startRequested=true' <<<"$state"
}

assert_no_main_service() {
    local state
    state="$(adb_shell_value dumpsys activity services "$APP_PACKAGE")" \
        || return 1
    ! grep -qF "$APP_PACKAGE/.MainService" <<<"$state"
}

assert_main_service_log_cardinality() {
    local lifecycle_log=$1
    local context=$2
    local expected_start_count=$3
    local expected_health_count=$4
    local create_count start_count projection_start_count launch_count health_count
    create_count="$(grep -cF 'MainService onCreate' <<<"$lifecycle_log" || true)"
    start_count="$(grep -cF 'this service:' <<<"$lifecycle_log" || true)"
    projection_start_count="$(grep -cF 'service starting:' <<<"$lifecycle_log" || true)"
    launch_count="$(grep -cF 'Launch MainService' <<<"$lifecycle_log" || true)"
    health_count="$(grep -cF 'controlled service health check:' <<<"$lifecycle_log" || true)"
    if [ "$create_count" -eq 1 ] \
       && [ "$start_count" -eq "$expected_start_count" ] \
       && [ "$projection_start_count" -eq 1 ] \
       && [ "$launch_count" -eq 1 ] \
       && [ "$health_count" -eq "$expected_health_count" ]; then
        return 0
    fi
    printf 'ANDROID_MAIN_SERVICE_LOG_CARDINALITY=fail context=%s create=%s start=%s expected_start=%s projection_start=%s projection_launch=%s health=%s expected_health=%s\n' \
        "$context" "$create_count" "$start_count" "$expected_start_count" \
        "$projection_start_count" "$launch_count" "$health_count" \
        "$expected_health_count"
    printf '%s\n' "$lifecycle_log" \
        | grep -E 'MainService onCreate|this service:|service starting:|Launch MainService|controlled service health check:' \
        | tail -n 32 \
        | sed 's/^/ANDROID_MAIN_SERVICE_LOG_LINE /' \
        || true
    return 1
}

peer_source_state() {
    awk '/^RUSTDESK_PRESENTATION_TRACE stage=source-publish / {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^state=[0-9]+$/) {
                    split($i, value, "="); state = value[2]
                }
            }
         }
         END { if (state != "") print state; else exit 1 }' "$PEER_SOURCE_LOG"
}

decode_peer_framebuffer() {
    local framebuffer=$1 source_state=$2 mode=${3:-decode}
    local -a arguments=(decode "$framebuffer" "$source_state")
    [ "$mode" = diagnose ] && arguments+=(diagnose)
    python3 -I -S "$FRAME_DECODER" "${arguments[@]}"
}

wait_frame_observer_ready() {
    local detail= ready=
    for _ in $(seq 1 600); do
        if [ -e "$FRAME_OBSERVER_FAILURE" ] || [ -L "$FRAME_OBSERVER_FAILURE" ]; then
            detail="$(frame_observer_failure_detail 2>/dev/null || true)"
            printf 'ANDROID_PEER_OBSERVER=unavailable reason=observer-failed detail=%s\n' \
                "${detail:-malformed}"
            return 1
        fi
        if [ -f "$FRAME_OBSERVER_READY" ] \
           && [ ! -L "$FRAME_OBSERVER_READY" ] \
           && [ -f "$FRAME_OBSERVER_FRAME" ] \
           && [ ! -L "$FRAME_OBSERVER_FRAME" ]; then
            break
        fi
        sleep 0.05
    done
    [ -f "$FRAME_OBSERVER_READY" ] \
        && [ ! -L "$FRAME_OBSERVER_READY" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FRAME_OBSERVER_READY")" = \
             1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$FRAME_OBSERVER_READY")" -le 128 ] \
        || return 1
    ready="$(<"$FRAME_OBSERVER_READY")"
    [[ "$ready" =~ ^ready\ seq=([0-9]+)$ ]] || return 1
    [ -f "$FRAME_OBSERVER_FRAME" ] \
        && [ ! -L "$FRAME_OBSERVER_FRAME" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FRAME_OBSERVER_FRAME")" = \
             1000:1000:600:1 ] \
        && [ "$(stat -c '%s' -- "$FRAME_OBSERVER_FRAME")" -le 262144 ]
}

PEER_LAST_RECOVERY_MS=0
capture_peer_freshness() {
    local phase=$1 attempt=0 started_ms now_ms source_state decoded
    local total_elapsed_ms capture_elapsed_ms
    local state age score matched layout format_name orientation width height
    local sequence timestamp_us last_sequence= observer_failure= source_seen=0
    local baseline_pending=1
    local max_age=0 last_source_state= diagnostic_png= framebuffer_size=
    local -A seen=()

    wait_frame_observer_ready \
        || fail "the Android emulator display observer did not become ready for $phase"
    started_ms="$(monotonic_millis)" \
        || fail "cannot read the monotonic clock for $phase"
    while [ "$attempt" -lt 160 ]; do
        now_ms="$(monotonic_millis)" \
            || fail "cannot reread the monotonic clock for $phase"
        [ "$((now_ms - started_ms))" -le "$PEER_RECOVERY_LIMIT_MS" ] \
            || break
        if [ -e "$FRAME_OBSERVER_FAILURE" ] || [ -L "$FRAME_OBSERVER_FAILURE" ]; then
            observer_failure="Android emulator display observer failed for $phase"
            break
        fi
        source_state="$(peer_source_state 2>/dev/null || true)"
        decoded=
        if [[ "$source_state" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
            last_source_state=$source_state
            source_seen=1
            if ! decoded="$(decode_peer_framebuffer \
                "$FRAME_OBSERVER_FRAME" "$source_state" 2>/dev/null)"; then
                printf 'ANDROID_PEER_OBSERVER=unavailable phase=%s reason=invalid-grpc-frame-record\n' \
                    "$phase"
                observer_failure="Android emulator display observer returned an invalid frame for $phase"
                break
            fi
        fi
        if [[ "$decoded" =~ ^([0-9]+)\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)\ (left-right|top-bottom)\ (rgb888)\ (bottom-up)\ (120|200)\ (120|200)\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)$ ]]; then
            state=${BASH_REMATCH[1]}
            age=${BASH_REMATCH[2]}
            score=${BASH_REMATCH[3]}
            matched=${BASH_REMATCH[4]}
            layout=${BASH_REMATCH[5]}
            format_name=${BASH_REMATCH[6]}
            orientation=${BASH_REMATCH[7]}
            width=${BASH_REMATCH[8]}
            height=${BASH_REMATCH[9]}
            sequence=${BASH_REMATCH[10]}
            timestamp_us=${BASH_REMATCH[11]}
            capture_elapsed_ms=${BASH_REMATCH[12]}
            if ! { [ "$width:$height" = 120:200 ] \
                   || [ "$width:$height" = 200:120 ]; }; then
                observer_failure="Android emulator display observer dimensions differ for $phase"
                break
            fi
            if [ "$baseline_pending" -eq 1 ]; then
                last_sequence=$sequence
                baseline_pending=0
                printf 'ANDROID_PEER_FRAME_BASELINE phase=%s observer_age_ms=%s source_state=%s display_state=%s dimensions=%sx%s seq=%s timestamp_us=%s\n' \
                    "$phase" "$capture_elapsed_ms" "$source_state" "$state" \
                    "$width" "$height" "$sequence" "$timestamp_us"
                sleep 0.05
                continue
            fi
            if [ -n "$last_sequence" ]; then
                if [ "$sequence" -lt "$last_sequence" ]; then
                    observer_failure="Android emulator display observer sequence regressed for $phase"
                    break
                fi
                if [ "$sequence" -eq "$last_sequence" ]; then
                    sleep 0.05
                    continue
                fi
            fi
            last_sequence=$sequence
            attempt=$((attempt + 1))
            total_elapsed_ms=$((now_ms - started_ms))
            [ "$capture_elapsed_ms" -le "$PEER_CAPTURE_MAX_MS" ] \
                || PEER_CAPTURE_MAX_MS=$capture_elapsed_ms
            if [ "$capture_elapsed_ms" -gt "$PEER_CAPTURE_LIMIT_MS" ]; then
                printf 'ANDROID_PEER_OBSERVER=unavailable phase=%s attempt=%s observer_age_ms=%s limit_ms=%s seq=%s reason=grpc-frame-too-old\n' \
                    "$phase" "$attempt" "$capture_elapsed_ms" \
                    "$PEER_CAPTURE_LIMIT_MS" "$sequence"
                observer_failure="Android emulator display observer exceeded its $PEER_CAPTURE_LIMIT_MS ms limit for $phase"
                break
            fi
            printf 'ANDROID_PEER_FRAME_SAMPLE phase=%s attempt=%s elapsed_ms=%s observer_age_ms=%s source_state=%s display_state=%s age=%s score=%s matched=%s layout=%s format=%s orientation=%s dimensions=%sx%s seq=%s timestamp_us=%s\n' \
                "$phase" "$attempt" "$total_elapsed_ms" "$capture_elapsed_ms" \
                "$source_state" "$state" "$age" "$score" "$matched" "$layout" \
                "$format_name" "$orientation" "$width" "$height" "$sequence" \
                "$timestamp_us"
            seen[$state]=1
            [ "$age" -le "$max_age" ] || max_age=$age
            if [ "${#seen[@]}" -ge 2 ]; then
                now_ms="$(monotonic_millis)" \
                    || fail "cannot finish the monotonic measurement for $phase"
                PEER_LAST_RECOVERY_MS=$((now_ms - started_ms))
                [ "$PEER_LAST_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                    || break
                if ! assert_peer_presentation_ui_finality "$phase"; then
                    observer_failure="Android remote-view dialogs did not retire after presentation for $phase"
                    break
                fi
                PEER_DISTINCT_FRAMES=$((PEER_DISTINCT_FRAMES + ${#seen[@]}))
                [ "$((max_age * 250))" -le "$PEER_FRESHNESS_MAX_MS" ] \
                    || PEER_FRESHNESS_MAX_MS=$((max_age * 250))
                printf 'ANDROID_PEER_FRESHNESS=pass phase=%s recovery_ms=%s max_age_ms=%s distinct=%s score=%s matched=%s layout=%s observer=emulator-grpc-rgb888 last_seq=%s\n' \
                    "$phase" "$PEER_LAST_RECOVERY_MS" "$((max_age * 250))" \
                    "${#seen[@]}" "$score" "$matched" "$layout" "$sequence"
                return 0
            fi
        elif [[ "$decoded" =~ ^unavailable\ rgb888\ bottom-up\ (120|200)\ (120|200)\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)$ ]] \
             || [ -z "$decoded" ]; then
            if [ -n "$decoded" ]; then
                width=${BASH_REMATCH[1]}
                height=${BASH_REMATCH[2]}
                sequence=${BASH_REMATCH[3]}
                timestamp_us=${BASH_REMATCH[4]}
                capture_elapsed_ms=${BASH_REMATCH[5]}
                if [ -n "$last_sequence" ] && [ "$sequence" -lt "$last_sequence" ]; then
                    observer_failure="Android emulator display observer sequence regressed for $phase"
                    break
                fi
                if [ "$baseline_pending" -eq 1 ]; then
                    last_sequence=$sequence
                    baseline_pending=0
                    printf 'ANDROID_PEER_FRAME_BASELINE phase=%s observer_age_ms=%s source_state=%s display_state=unavailable dimensions=%sx%s seq=%s timestamp_us=%s\n' \
                        "$phase" "$capture_elapsed_ms" "$source_state" \
                        "$width" "$height" "$sequence" "$timestamp_us"
                    sleep 0.05
                    continue
                fi
                if [ -n "$last_sequence" ] && [ "$sequence" -eq "$last_sequence" ]; then
                    sleep 0.05
                    continue
                fi
                last_sequence=$sequence
                attempt=$((attempt + 1))
                [ "$capture_elapsed_ms" -le "$PEER_CAPTURE_MAX_MS" ] \
                    || PEER_CAPTURE_MAX_MS=$capture_elapsed_ms
                if [ "$capture_elapsed_ms" -gt "$PEER_CAPTURE_LIMIT_MS" ]; then
                    observer_failure="Android emulator display observer exceeded its $PEER_CAPTURE_LIMIT_MS ms limit for $phase"
                    break
                fi
                total_elapsed_ms=$((now_ms - started_ms))
                printf 'ANDROID_PEER_FRAME_SAMPLE phase=%s attempt=%s elapsed_ms=%s observer_age_ms=%s source_state=%s display_state=unavailable dimensions=%sx%s seq=%s timestamp_us=%s\n' \
                    "$phase" "$attempt" "$total_elapsed_ms" "$capture_elapsed_ms" \
                    "$source_state" "$width" "$height" "$sequence" "$timestamp_us"
            fi
        else
            printf 'ANDROID_PEER_OBSERVER=unavailable phase=%s reason=malformed-decoder-result\n' \
                "$phase"
            observer_failure="Android emulator display observer returned a malformed result for $phase"
            break
        fi
        sleep 0.05
    done
    if [ "$source_seen" -eq 0 ] && [ -z "$observer_failure" ]; then
        printf 'ANDROID_PEER_OBSERVER=unavailable phase=%s reason=missing-source-state\n' \
            "$phase"
        observer_failure="Android peer source-state observer produced no valid state for $phase"
    fi
    if [ -n "$last_source_state" ] \
       && [ -f "$FRAME_OBSERVER_FRAME" ] \
       && [ ! -L "$FRAME_OBSERVER_FRAME" ]; then
        decode_peer_framebuffer \
            "$FRAME_OBSERVER_FRAME" "$last_source_state" diagnose || true
    fi
    capture_ui_hierarchy complete && print_initial_ui_semantics
    capture_android_connection_diagnostic active || true
    reprint_android_connection_diagnostic || true
    print_peer_presentation_stage_diagnostic "$phase" || true
    diagnostic_png="$WORK_ROOT/peer-$phase-diagnostic.png"
    if timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" exec-out screencap -p >"$diagnostic_png"; then
        framebuffer_size="$(stat -c '%s' -- "$diagnostic_png")"
        if [ "$framebuffer_size" -le 262144 ]; then
            printf 'ANDROID_PEER_FRAMEBUFFER_PNG_BEGIN phase=%s bytes=%s verdict_input=false\n' \
                "$phase" "$framebuffer_size"
            base64 -w 76 -- "$diagnostic_png"
            printf 'ANDROID_PEER_FRAMEBUFFER_PNG_END phase=%s\n' "$phase"
        else
            printf 'ANDROID_PEER_FRAMEBUFFER_PNG_OMITTED phase=%s bytes=%s limit=262144 verdict_input=false\n' \
                "$phase" "$framebuffer_size"
        fi
    else
        printf 'ANDROID_PEER_FRAMEBUFFER_PNG_OMITTED phase=%s reason=capture-failed verdict_input=false\n' \
            "$phase"
    fi
    rm -f -- "$diagnostic_png"
    [ -z "$observer_failure" ] || fail "$observer_failure"
    fail "Android peer display did not become fresh and changing for $phase"
}

ui_has_credential_reason_semantics() {
    local expected=$1
    local mode=${2:-quiet}
    if [ ! -f "$UI_XML" ] || [ -L "$UI_XML" ]; then
        [ "$mode" != diagnose ] \
            || printf 'ANDROID_PEER_CREDENTIAL_SEMANTICS=unavailable reason=hierarchy-absent\n'
        return 1
    fi
    python3 -I -S - "$UI_XML" "$expected" "$mode" <<'PY'
import hashlib
import sys
import xml.etree.ElementTree as ET

path, expected, mode = sys.argv[1:]
if mode not in ("quiet", "diagnose", "describe"):
    raise SystemExit(2)
prefix = expected[:240]
exact_matches = 0
prefix_matches = 0
related = set()
for node in ET.parse(path).getroot().iter("node"):
    values = {
        node.attrib.get(key, "")
        for key in ("text", "content-desc")
    }
    if expected in values:
        exact_matches += 1
    elif len(expected) > len(prefix) and prefix in values:
        prefix_matches += 1
    related.update(
        value for value in values
        if value and (expected.startswith(value) or value.startswith(expected[:64]))
    )
matches = exact_matches + prefix_matches
if matches != 1:
    if mode == "diagnose":
        details = ",".join(
            f"{len(value)}:{hashlib.sha256(value.encode()).hexdigest()}"
            for value in sorted(related, key=lambda value: (len(value), value))
        ) or "none"
        print(
            "ANDROID_PEER_CREDENTIAL_SEMANTICS=unavailable "
            f"exact_matches={exact_matches} prefix_240_matches={prefix_matches} "
            f"related_length_sha256={details}"
        )
    raise SystemExit(1)
observer = "exact" if exact_matches else "android-accessibility-prefix-240"
if mode == "diagnose":
    print(
        "ANDROID_PEER_CREDENTIAL_SEMANTICS=pass "
        f"observer={observer} "
        f"observed_chars={len(expected) if exact_matches else len(prefix)} "
        f"expected_chars={len(expected)}"
    )
elif mode == "describe":
    print(observer)
PY
}

print_peer_connection_state_diagnostic() {
    local phase=$1 prompt=unavailable reason=unavailable remember=unavailable
    local app_pid= thread_listing=
    if capture_ui_hierarchy complete; then
        if ui_center text 'Password required' >/dev/null 2>&1; then
            prompt=present
            if ui_has_credential_reason_semantics \
                "$PEER_CONFIRMATION_UNAVAILABLE_REASON"; then
                reason=peer-confirmation-unavailable
            else
                reason=other-or-absent
            fi
            remember="$(ui_checkbox_checked 'Remember password' 2>/dev/null || true)"
            [ -n "$remember" ] || remember=unavailable
        else
            prompt=absent
            reason=absent
            remember=absent
        fi
    fi
    printf 'ANDROID_PEER_CONNECTION_STATE=diagnostic phase=%s established=%s pre_session_failures=%s key_failures=%s keyed_sessions=%s prompt=%s reason=%s remember=%s\n' \
        "$phase" "$(peer_server_established_count)" \
        "$(peer_server_pre_session_failure_count)" \
        "$(peer_server_key_failure_count)" \
        "$(peer_server_keyed_session_count)" \
        "$prompt" "$reason" "$remember"
    app_pid="$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)"
    if [[ "$app_pid" =~ ^[1-9][0-9]*$ ]]; then
        thread_listing="$(adb_shell_value ps -T -p "$app_pid" -o TID,STAT,NAME \
            2>/dev/null || true)"
        if [ -n "$thread_listing" ]; then
            printf '%s\n' "$thread_listing" \
                | sed -n '1,64p' \
                | sed 's/^/ANDROID_PEER_PROCESS_THREAD /'
        else
            printf 'ANDROID_PEER_PROCESS_THREAD unavailable pid=%s\n' "$app_pid"
        fi
    else
        printf 'ANDROID_PEER_PROCESS_THREAD unavailable pid=absent\n'
    fi
}

wait_peer_initial_credential_prompt() {
    local pre_session_failures_before=$1 key_failures_before=$2
    local keyed_sessions_before=$3
    local started_ms now_ms pre_session_failures key_failures keyed_sessions
    local established_count title semantic_mode reveal_attempted=0 count
    for count in \
        "$pre_session_failures_before" "$key_failures_before" \
        "$keyed_sessions_before"; do
        case "$count" in
            ''|*[!0-9]*) return 2 ;;
        esac
    done
    started_ms="$(monotonic_millis)" || return 2
    while :; do
        pre_session_failures="$(peer_server_pre_session_failure_count)"
        key_failures="$(peer_server_key_failure_count)"
        keyed_sessions="$(peer_server_keyed_session_count)"
        established_count="$(peer_server_established_count)"
        if [ "$pre_session_failures" -ne "$pre_session_failures_before" ] \
           || [ "$key_failures" -ne "$key_failures_before" ] \
           || [ "$keyed_sessions" -ne "$keyed_sessions_before" ] \
           || [ "$established_count" -ne 0 ]; then
            now_ms="$(monotonic_millis)" || return 2
            capture_ui_hierarchy complete || true
            ui_has_credential_reason_semantics \
                "$PEER_MISSING_CREDENTIAL_REASON" diagnose || true
            printf 'ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=fail reason=unexpected-network-attempt-before-credential elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s\n' \
                "$((now_ms - started_ms))" "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$pre_session_failures" "$pre_session_failures_before" \
                "$key_failures" "$key_failures_before" \
                "$keyed_sessions" "$keyed_sessions_before" \
                "$established_count"
            return 1
        fi
        if capture_unobscured_ui_hierarchy complete; then
            title="$(ui_center text 'Password required' 2>/dev/null || true)"
            if [[ "$title" =~ ^[0-9]+\ [0-9]+$ ]] \
               && ui_has_credential_reason_semantics \
                    "$PEER_MISSING_CREDENTIAL_REASON"; then
                break
            fi
            if [[ "$title" =~ ^[0-9]+\ [0-9]+$ ]] \
               && [ "$reveal_attempted" -eq 0 ]; then
                reveal_attempted=1
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input keyevent \
                    KEYCODE_BACK >/dev/null \
                    || return 1
                sleep 0.5
            fi
        fi
        now_ms="$(monotonic_millis)" || return 2
        if [ "$((now_ms - started_ms))" -ge \
             "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" ]; then
            ui_has_credential_reason_semantics \
                "$PEER_MISSING_CREDENTIAL_REASON" diagnose || true
            printf 'ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=fail reason=prompt-timeout elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s\n' \
                "$((now_ms - started_ms))" "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$pre_session_failures" "$pre_session_failures_before" \
                "$key_failures" "$key_failures_before" \
                "$keyed_sessions" "$keyed_sessions_before" \
                "$established_count"
            return 1
        fi
        sleep 0.25
    done
    now_ms="$(monotonic_millis)" || return 2
    PEER_INITIAL_CREDENTIAL_PROMPT_MS=$((now_ms - started_ms))
    pre_session_failures="$(peer_server_pre_session_failure_count)"
    key_failures="$(peer_server_key_failure_count)"
    keyed_sessions="$(peer_server_keyed_session_count)"
    established_count="$(peer_server_established_count)"
    if [ "$pre_session_failures" -ne "$pre_session_failures_before" ] \
       || [ "$key_failures" -ne "$key_failures_before" ] \
       || [ "$keyed_sessions" -ne "$keyed_sessions_before" ] \
       || [ "$established_count" -ne 0 ]; then
        printf 'ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=fail reason=unexpected-network-attempt-before-credential elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s\n' \
            "$PEER_INITIAL_CREDENTIAL_PROMPT_MS" \
            "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
            "$pre_session_failures" "$pre_session_failures_before" \
            "$key_failures" "$key_failures_before" \
            "$keyed_sessions" "$keyed_sessions_before" \
            "$established_count"
        return 1
    fi
    semantic_mode="$(
        ui_has_credential_reason_semantics \
            "$PEER_MISSING_CREDENTIAL_REASON" describe
    )" || return 1
    PEER_INITIAL_CREDENTIAL_SEMANTIC_MODE=$semantic_mode
    printf 'ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=pass reason=missing-credential observer=%s observed_network_attempts=0 pre_session_failure_delta=0 key_failure_delta=0 keyed_session_delta=0 established=0 prompt_ms=%s prompt_limit_ms=%s\n' \
        "$PEER_INITIAL_CREDENTIAL_SEMANTIC_MODE" \
        "$PEER_INITIAL_CREDENTIAL_PROMPT_MS" \
        "$PEER_CREDENTIAL_PROMPT_LIMIT_MS"
}

inject_peer_password_submit() {
    local password=$1 kind=$2 remember=$3
    local expected_pre_session_failures=$4 expected_key_failures=$5
    local expected_keyed_sessions=$6
    local center= x= y=
    local remember_state= remember_ready=0
    local pre_session_failures key_failures keyed_sessions established_count
    local action_wall_ms count
    case "$kind:$remember" in
        wrong:0|correct:1) ;;
        *) return 2 ;;
    esac
    for count in \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions"; do
        case "$count" in
            ''|*[!0-9]*) return 2 ;;
        esac
    done
    wait_ui_center text 'Password required' >/dev/null || return 1
    capture_unobscured_ui_hierarchy complete || return 1
    remember_state="$(ui_checkbox_checked 'Remember password' 2>/dev/null || true)"
    if [ "$remember_state" != false ]; then
        printf 'ANDROID_PEER_PASSWORD_INPUT=fail kind=%s stage=initial-remember-state observed=%s expected=false\n' \
            "$kind" "${remember_state:-unavailable}"
        return 1
    fi
    record_peer_password_pre_submit_state "$kind" dialog-observed \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    capture_unobscured_ui_hierarchy || return 1
    center="$(ui_center focused-password-field 2>/dev/null || true)"
    [[ "$center" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
    read -r x y <<<"$center"
    "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null || return 1
    "$ADB" -s "$SERIAL" shell input keycombination \
        KEYCODE_CTRL_LEFT KEYCODE_A >/dev/null || return 1
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_DEL >/dev/null || return 1
    record_peer_password_pre_submit_state "$kind" field-cleared \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    "$ADB" -s "$SERIAL" shell input text "$password" >/dev/null || return 1
    record_peer_password_pre_submit_state "$kind" text-injected \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    observe_peer_password_pre_submit_quiet "$kind" text-injected \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    printf 'ANDROID_PEER_PASSWORD_INPUT=pass kind=%s obscured=true chars=%s remember=%s\n' \
        "$kind" "${#password}" "$remember"
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null || return 1
    capture_unobscured_ui_hierarchy complete || return 1
    ui_center focused-password-field >/dev/null || return 1
    ! grep -Fq "$password" "$UI_XML" || return 1
    record_peer_password_pre_submit_state "$kind" keyboard-dismissed \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    if [ "$remember" -eq 1 ]; then
        tap_ui text 'Remember password' || return 1
        for _ in $(seq 1 12); do
            if capture_unobscured_ui_hierarchy complete \
               && [ "$(ui_checkbox_checked 'Remember password' \
                    2>/dev/null || true)" = true ]; then
                remember_ready=1
                break
            fi
            sleep 0.25
        done
        if [ "$remember_ready" -ne 1 ]; then
            printf 'ANDROID_PEER_PASSWORD_INPUT=fail kind=%s stage=remember-enable observed=%s expected=true\n' \
                "$kind" \
                "$(ui_checkbox_checked 'Remember password' 2>/dev/null || \
                    printf unavailable)"
            return 1
        fi
        record_peer_password_pre_submit_state "$kind" remember-enabled \
            "$expected_pre_session_failures" "$expected_key_failures" \
            "$expected_keyed_sessions" || return 1
    else
        remember_state="$(ui_checkbox_checked 'Remember password' \
            2>/dev/null || true)"
        if [ "$remember_state" != false ]; then
            printf 'ANDROID_PEER_PASSWORD_INPUT=fail kind=%s stage=remember-preservation observed=%s expected=false\n' \
                "$kind" "${remember_state:-unavailable}"
            return 1
        fi
    fi
    capture_unobscured_ui_hierarchy complete || return 1
    center="$(ui_center text 'OK' 2>/dev/null || true)"
    [[ "$center" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
    read -r x y <<<"$center"
    record_peer_password_pre_submit_state "$kind" ok-ready \
        "$expected_pre_session_failures" "$expected_key_failures" \
        "$expected_keyed_sessions" || return 1
    pre_session_failures="$(peer_server_pre_session_failure_count)"
    key_failures="$(peer_server_key_failure_count)"
    keyed_sessions="$(peer_server_keyed_session_count)"
    established_count="$(peer_server_established_count)"
    if [ "$pre_session_failures" -ne "$expected_pre_session_failures" ] \
       || [ "$key_failures" -ne "$expected_key_failures" ] \
       || [ "$keyed_sessions" -ne "$expected_keyed_sessions" ] \
       || [ "$established_count" -ne 0 ]; then
        printf 'ANDROID_PEER_PASSWORD_SUBMIT=fail kind=%s stage=pre-submit-network-state pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s reason=unexpected-network-attempt\n' \
            "$kind" "$pre_session_failures" \
            "$expected_pre_session_failures" "$key_failures" \
            "$expected_key_failures" "$keyed_sessions" \
            "$expected_keyed_sessions" "$established_count"
        print_peer_connection_state_diagnostic "pre-submit-$kind"
        return 1
    fi
    action_wall_ms="$(date +%s%3N)" || return 2
    [[ "$action_wall_ms" =~ ^[1-9][0-9]{12}$ ]] || return 2
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null \
        || return 1
    printf 'ANDROID_PEER_PASSWORD_ACTION=injected kind=%s issued_wall_ms=%s pre_session_failures_before=%s key_failures_before=%s keyed_sessions_before=%s established_before=0\n' \
        "$kind" "$action_wall_ms" "$pre_session_failures" \
        "$key_failures" "$keyed_sessions"
}

wait_peer_credential_recovery_prompt() {
    local pre_session_failures_before=$1 key_failures_before=$2
    local keyed_sessions_before=$3
    local expected_pre_session_failures expected_key_failures
    local started_ms now_ms pre_session_failures key_failures keyed_sessions
    local established_count title
    local reveal_attempted=0 count
    for count in \
        "$pre_session_failures_before" "$key_failures_before" \
        "$keyed_sessions_before"; do
        case "$count" in
            ''|*[!0-9]*) return 2 ;;
        esac
    done
    expected_pre_session_failures=$((pre_session_failures_before + 1))
    expected_key_failures=$((key_failures_before + 1))
    started_ms="$(monotonic_millis)" || return 2
    while :; do
        pre_session_failures="$(peer_server_pre_session_failure_count)"
        key_failures="$(peer_server_key_failure_count)"
        keyed_sessions="$(peer_server_keyed_session_count)"
        established_count="$(peer_server_established_count)"
        if [ "$pre_session_failures" -gt "$expected_pre_session_failures" ] \
           || [ "$key_failures" -gt "$expected_key_failures" ] \
           || [ "$keyed_sessions" -ne "$keyed_sessions_before" ] \
           || [ "$established_count" -ne 0 ]; then
            capture_ui_hierarchy complete || true
            ui_has_credential_reason_semantics \
                "$PEER_CONFIRMATION_UNAVAILABLE_REASON" diagnose || true
            now_ms="$(monotonic_millis)" || return 2
            printf 'ANDROID_PEER_CREDENTIAL_RECOVERY=fail elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s reason=additional-network-attempt-after-single-submit\n' \
                "$((now_ms - started_ms))" \
                "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$pre_session_failures" "$expected_pre_session_failures" \
                "$key_failures" "$expected_key_failures" \
                "$keyed_sessions" "$keyed_sessions_before" \
                "$established_count"
            return 1
        fi
        if [ "$pre_session_failures" -eq "$expected_pre_session_failures" ] \
           && [ "$key_failures" -ne "$expected_key_failures" ]; then
            now_ms="$(monotonic_millis)" || return 2
            printf 'ANDROID_PEER_CREDENTIAL_RECOVERY=fail elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s reason=unexpected-terminal-result\n' \
                "$((now_ms - started_ms))" \
                "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$pre_session_failures" "$expected_pre_session_failures" \
                "$key_failures" "$expected_key_failures" \
                "$keyed_sessions" "$keyed_sessions_before" \
                "$established_count"
            return 1
        fi
        if capture_unobscured_ui_hierarchy complete; then
            title="$(ui_center text 'Password required' 2>/dev/null || true)"
            if [[ "$title" =~ ^[0-9]+\ [0-9]+$ ]] \
               && ui_has_credential_reason_semantics "$PEER_CONFIRMATION_UNAVAILABLE_REASON" \
               && [ "$pre_session_failures" -eq \
                    "$expected_pre_session_failures" ] \
               && [ "$key_failures" -eq "$expected_key_failures" ] \
               && [ "$established_count" -eq 0 ]; then
                break
            fi
            if [[ "$title" =~ ^[0-9]+\ [0-9]+$ ]] \
               && [ "$pre_session_failures" -eq \
                    "$expected_pre_session_failures" ] \
               && [ "$key_failures" -eq "$expected_key_failures" ] \
               && [ "$established_count" -eq 0 ] \
               && [ "$reveal_attempted" -eq 0 ]; then
                reveal_attempted=1
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input keyevent \
                    KEYCODE_BACK >/dev/null \
                    || return 1
                sleep 0.5
                capture_unobscured_ui_hierarchy complete || return 1
                title="$(ui_center text 'Password required' 2>/dev/null || true)"
                [[ "$title" =~ ^[0-9]+\ [0-9]+$ ]] \
                    || return 1
                ui_has_credential_reason_semantics \
                    "$PEER_CONFIRMATION_UNAVAILABLE_REASON" \
                    || return 1
                printf 'ANDROID_PEER_CREDENTIAL_REVEAL=pass action=back prompt=retained semantics=exact-or-accessibility-prefix\n'
                break
            fi
        fi
        now_ms="$(monotonic_millis)" || return 2
        if [ "$((now_ms - started_ms))" -ge "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" ]; then
            ui_has_credential_reason_semantics \
                "$PEER_CONFIRMATION_UNAVAILABLE_REASON" diagnose || true
            printf 'ANDROID_PEER_CREDENTIAL_RECOVERY=fail elapsed_ms=%s limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s reason=prompt-timeout\n' \
                "$((now_ms - started_ms))" "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "${pre_session_failures:-unavailable}" \
                "$expected_pre_session_failures" \
                "${key_failures:-unavailable}" "$expected_key_failures" \
                "${keyed_sessions:-unavailable}" "$keyed_sessions_before" \
                "$(peer_server_established_count)"
            return 1
        fi
        sleep 0.5
    done
    now_ms="$(monotonic_millis)" || return 2
    PEER_CREDENTIAL_PROMPT_MS=$((now_ms - started_ms))
    [ "$PEER_CREDENTIAL_PROMPT_MS" -le "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" ] \
        || return 1
    for _ in $(seq 1 $((PEER_NO_AUTO_RETRY_OBSERVATION_MS / 250))); do
        established_count="$(peer_server_established_count)"
        pre_session_failures="$(peer_server_pre_session_failure_count)"
        key_failures="$(peer_server_key_failure_count)"
        keyed_sessions="$(peer_server_keyed_session_count)"
        if [ "$established_count" -ne 0 ] \
           || [ "$pre_session_failures" -ne \
                "$expected_pre_session_failures" ] \
           || [ "$key_failures" -ne "$expected_key_failures" ] \
           || [ "$keyed_sessions" -ne "$keyed_sessions_before" ]; then
            now_ms="$(monotonic_millis)" || return 2
            capture_ui_hierarchy complete || true
            ui_has_credential_reason_semantics \
                "$PEER_CONFIRMATION_UNAVAILABLE_REASON" diagnose || true
            printf 'ANDROID_PEER_CREDENTIAL_RECOVERY=fail elapsed_ms=%s observation_limit_ms=%s pre_session_failures=%s expected_pre_session_failures=%s key_failures=%s expected_key_failures=%s keyed_sessions=%s expected_keyed_sessions=%s established=%s reason=automatic-retry-observed\n' \
                "$((now_ms - started_ms))" \
                "$PEER_NO_AUTO_RETRY_OBSERVATION_MS" \
                "$pre_session_failures" "$expected_pre_session_failures" \
                "$key_failures" "$expected_key_failures" \
                "$keyed_sessions" "$keyed_sessions_before" \
                "$established_count"
            return 1
        fi
        sleep 0.25
    done
    capture_unobscured_ui_hierarchy complete \
        && [[ "$(ui_center text 'Password required' 2>/dev/null || true)" \
             =~ ^[0-9]+\ [0-9]+$ ]] \
        && ui_has_credential_reason_semantics \
            "$PEER_CONFIRMATION_UNAVAILABLE_REASON" diagnose \
        || return 1
    PEER_CREDENTIAL_SEMANTIC_MODE="$(
        ui_has_credential_reason_semantics \
            "$PEER_CONFIRMATION_UNAVAILABLE_REASON" describe
    )" || return 1
    printf 'ANDROID_PEER_CREDENTIAL_RECOVERY=pass wrong_attempts=1 pre_session_failure_delta=1 key_failure_delta=1 keyed_session_delta=0 error=peer-confirmation-unavailable prompt=%s manual_retry=required auto_retry=absent prompt_ms=%s prompt_limit_ms=%s observation_ms=%s\n' \
        "$PEER_CREDENTIAL_SEMANTIC_MODE" \
        "$PEER_CREDENTIAL_PROMPT_MS" "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
        "$PEER_NO_AUTO_RETRY_OBSERVATION_MS"
}

open_peer_connection() {
    local generation=$1 expect_password=$2 center x y
    local credential=remembered pre_session_failures_before=
    local key_failures_before= keyed_sessions_before=
    local connection_wait_limit_ms=$PEER_CONNECTION_WAIT_LIMIT_MS
    if ! wait_ui_center address-field >/dev/null 2>&1; then
        tap_ui text 'Connection' \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
    fi
    center="$(wait_ui_center address-field)" || return 1
    read -r x y <<<"$center"
    "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null || return 1
    sleep 0.5
    "$ADB" -s "$SERIAL" shell input keycombination \
        KEYCODE_CTRL_LEFT KEYCODE_A >/dev/null || return 1
    "$ADB" -s "$SERIAL" shell input text "$PEER_VIEW_ADDRESS" >/dev/null || return 1
    wait_ui_center address-field "$PEER_VIEW_ADDRESS" >/dev/null \
        || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
    if [ "$expect_password" -eq 1 ]; then
        pre_session_failures_before="$(peer_server_pre_session_failure_count)"
        key_failures_before="$(peer_server_key_failure_count)"
        keyed_sessions_before="$(peer_server_keyed_session_count)"
    fi
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_ENTER >/dev/null || return 1
    if [ "$expect_password" -eq 1 ]; then
        wait_peer_initial_credential_prompt \
            "$pre_session_failures_before" "$key_failures_before" \
            "$keyed_sessions_before" \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
        inject_peer_password_submit "$PEER_WRONG_PASSWORD" wrong 0 \
            "$pre_session_failures_before" "$key_failures_before" \
            "$keyed_sessions_before" \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
        wait_peer_credential_recovery_prompt \
            "$pre_session_failures_before" "$key_failures_before" \
            "$keyed_sessions_before" \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
        pre_session_failures_before="$(peer_server_pre_session_failure_count)"
        key_failures_before="$(peer_server_key_failure_count)"
        keyed_sessions_before="$(peer_server_keyed_session_count)"
        inject_peer_password_submit "$PEER_PASSWORD" correct 1 \
            "$pre_session_failures_before" "$key_failures_before" \
            "$keyed_sessions_before" \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
        credential=entered-after-manual-recovery
        connection_wait_limit_ms=$PEER_PASSWORD_CONNECTION_WAIT_LIMIT_MS
    else
        sleep 1
        if capture_unobscured_ui_hierarchy \
           && ui_center text 'Password required' >/dev/null 2>&1; then
            print_initial_ui_semantics
            return 1
        fi
    fi
    if ! wait_peer_server_connections \
        1 exact "$connection_wait_limit_ms"; then
        printf 'ANDROID_PEER_CONNECTION_READY=fail generation=%s credential=%s wait_ms=%s limit_ms=%s expected_connections=1\n' \
            "$generation" "$credential" "$PEER_LAST_CONNECTION_WAIT_MS" \
            "$connection_wait_limit_ms" >&2
        print_peer_connection_state_diagnostic "connection-$generation"
        return 1
    fi
    printf 'ANDROID_PEER_CONNECTION_READY=pass generation=%s credential=%s wait_ms=%s limit_ms=%s connections=1\n' \
        "$generation" "$credential" "$PEER_LAST_CONNECTION_WAIT_MS" \
        "$connection_wait_limit_ms"
    if [ "$expect_password" -eq 1 ]; then
        PEER_CORRECT_CREDENTIAL_CONNECTION_MS=$PEER_LAST_CONNECTION_WAIT_MS
    elif [ "$PEER_LAST_CONNECTION_WAIT_MS" -gt "$PEER_CACHED_CONNECTION_MAX_MS" ]; then
        PEER_CACHED_CONNECTION_MAX_MS=$PEER_LAST_CONNECTION_WAIT_MS
    fi
    capture_peer_freshness "$generation"
    record_peer_presentation_stage "$generation" \
        || {
            print_peer_presentation_stage_diagnostic "$generation" || true
            return 1
        }
    wait_peer_server_connections 1 exact
}

exercise_peer_background_resume() {
    local pid_before=$1 cycle=$2 background_seconds=$3 phase=
    [[ "$cycle" =~ ^[1-9][0-9]*$ ]] \
        && [[ "$background_seconds" =~ ^[1-9][0-9]*$ ]] \
        || fail 'the Android background/resume phase identity is malformed'
    phase="background-resume-$cycle-${background_seconds}s"
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_HOME >/dev/null \
        || fail 'cannot background the Android peer Activity'
    sleep "$background_seconds"
    [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = "$pid_before" ] \
        || fail "$phase replaced the MainService process"
    wait_peer_server_connections 1 exact \
        || fail "$phase retired the live Android peer connection"
    timeout --signal=TERM --kill-after=2s 60s \
        "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" >/dev/null \
        || fail "cannot resume the Android peer Activity for $phase"
    wait_resumed_activity || fail "the Android peer Activity did not resume for $phase"
    [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = "$pid_before" ] \
        || fail "$phase replaced the MainService process on resume"
    capture_peer_freshness "$phase"
    wait_peer_server_connections 1 exact \
        || fail "$phase duplicated or retired the Android peer connection"
    [ "$PEER_LAST_RECOVERY_MS" -le "$PEER_BACKGROUND_RECOVERY_MS" ] \
        || PEER_BACKGROUND_RECOVERY_MS=$PEER_LAST_RECOVERY_MS
    PEER_BACKGROUND_CYCLES=$((PEER_BACKGROUND_CYCLES + 1))
}

readonly API="$(adb_shell_value getprop ro.build.version.sdk)"
readonly ABI="$(adb_shell_value getprop ro.product.cpu.abi)"
readonly SELINUX="$(adb_shell_value getenforce)"
[ "$API" = 34 ] || fail "booted Android API differs: $API"
[ "$ABI" = x86_64 ] || fail "booted Android ABI differs: $ABI"
[ "$SELINUX" = Enforcing ] || fail "booted Android SELinux mode differs: $SELINUX"

renderer_line="$(
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" shell dumpsys SurfaceFlinger 2>/dev/null \
        | tr -d '\r' \
        | awk '
            /^[[:space:]]*GLES:/ && renderer == "" {
                sub(/^[[:space:]]*/, "")
                renderer = $0
            }
            END {
                if (renderer == "") exit 1
                print renderer
            }
        '
)" || fail 'cannot observe the Android SurfaceFlinger GLES renderer'
[ "${#renderer_line}" -le 4096 ] \
    || fail 'the Android SurfaceFlinger GLES renderer description exceeds 4 KiB'
case "$renderer_line" in
    *SwiftShader*) ;;
    *) fail "the Android renderer is not SwiftShader: $renderer_line" ;;
esac
renderer_angle=absent
case "$renderer_line" in
    *ANGLE*) renderer_angle=present ;;
esac
renderer_sha256="$(printf '%s' "$renderer_line" | sha256sum | awk '{ print $1 }')"
[[ "$renderer_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'the Android renderer description digest is malformed'
readonly renderer_line renderer_angle renderer_sha256
printf 'ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader angle=%s gles_sha256=%s\n' \
    "$renderer_angle" "$renderer_sha256"

PEER_REVERSE_READY=0
PEER_REVERSE_LISTING=
if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    peer_reverse_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --list | tr -d '\r')" \
        || fail 'cannot inspect the initial Android reverse table'
    [ -z "$peer_reverse_listing" ] \
        || fail 'the clean Android emulator has a pre-existing reverse mapping'
    peer_reverse_output="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --no-rebind \
        "$PEER_REVERSE_DEVICE_SPEC" "$PEER_REVERSE_CONTAINER_SPEC" \
        | tr -d '\r')" \
        || fail 'cannot create the private Android peer reverse mapping'
    [ "${#peer_reverse_output}" -le 32 ] \
        || fail 'the Android peer reverse command output exceeds its bound'
    case "$peer_reverse_output" in
        ''|22118) ;;
        *) fail "the Android peer reverse command output differs: $peer_reverse_output" ;;
    esac
    peer_reverse_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --list | tr -d '\r')" \
        || fail 'cannot verify the private Android peer reverse mapping'
    [ "${#peer_reverse_listing}" -le 256 ] \
        && [[ "$peer_reverse_listing" != *$'\n'* ]] \
        || fail 'the private Android peer reverse listing exceeds its bound'
    read -r peer_reverse_identity peer_reverse_device peer_reverse_container \
        peer_reverse_extra <<<"$peer_reverse_listing"
    [ -n "$peer_reverse_identity" ] && [ "${#peer_reverse_identity}" -le 128 ] \
        && [[ "$peer_reverse_identity" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] \
        && [ "$peer_reverse_device" = "$PEER_REVERSE_DEVICE_SPEC" ] \
        && [ "$peer_reverse_container" = "$PEER_REVERSE_CONTAINER_SPEC" ] \
        && [ -z "$peer_reverse_extra" ] \
        || fail "the private Android peer reverse mapping differs: $peer_reverse_listing"
    PEER_REVERSE_LISTING=$peer_reverse_listing
    PEER_REVERSE_READY=1
fi

APP_PID=
LIFECYCLE_RECEIPT_READY=0
PEER_RECEIPT_READY=0
RECENTS_RECEIPT_READY=0
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-recents ] \
   || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    install_output="$(timeout --signal=TERM --kill-after=2s 180s \
        "$ADB" -s "$SERIAL" install --no-streaming --no-incremental \
        "$RUNTIME_TEST_APK")" \
        || fail 'runtime-test APK installation failed'
    case "$install_output" in
        Success|$'Performing Push Install\nSuccess') ;;
        *) fail "runtime-test APK install receipt differs: $install_output" ;;
    esac
    resolved_activity="$(adb_shell_value cmd package resolve-activity --components \
        com.carriez.flutter_hbb)"
    [ "$resolved_activity" = com.carriez.flutter_hbb/.MainActivity ] \
        || fail "runtime-test launcher activity differs: $resolved_activity"
    if [ "$WORKLOAD" = app-lifecycle ] || [ "$WORKLOAD" = app-peer-lifecycle ]; then
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell pm grant "$APP_PACKAGE" \
            android.permission.POST_NOTIFICATIONS >/dev/null \
            || fail 'cannot grant the disposable notification prerequisite'
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell appops set "$APP_PACKAGE" \
            MANAGE_EXTERNAL_STORAGE allow >/dev/null \
            || fail 'cannot grant the disposable storage prerequisite'
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell dumpsys deviceidle whitelist \
            "+$APP_PACKAGE" >/dev/null \
            || fail 'cannot grant the disposable battery prerequisite'
        package_state="$(adb_shell_value dumpsys package "$APP_PACKAGE")"
        grep -Eq 'android\.permission\.POST_NOTIFICATIONS: granted=true' \
            <<<"$package_state" \
            || fail 'the notification prerequisite is not granted'
        appops_state="$(adb_shell_value appops get "$APP_PACKAGE" \
            MANAGE_EXTERNAL_STORAGE)"
        grep -Eq 'MANAGE_EXTERNAL_STORAGE: allow' <<<"$appops_state" \
            || fail 'the storage prerequisite is not granted'
        idle_state="$(adb_shell_value dumpsys deviceidle whitelist)"
        grep -Eq "(^|,)$APP_PACKAGE(,|$)" <<<"$idle_state" \
            || fail 'the battery prerequisite is not granted'
    fi
    "$ADB" -s "$SERIAL" logcat -c \
        || fail 'cannot clear the runtime-test log before launch'
    launch_output="$(timeout --signal=TERM --kill-after=2s 60s \
        "$ADB" -s "$SERIAL" shell am start -W \
        -n com.carriez.flutter_hbb/.MainActivity | tr -d '\r')" \
        || fail 'runtime-test activity launch failed'
    [ "${#launch_output}" -le 16384 ] \
        || fail 'runtime-test activity launch receipt exceeds its bound'
    LAUNCH_WAIT_STATUS="$(python3 -I -S - "$launch_output" <<'PY'
import re
import sys

lines = sys.argv[1].splitlines()
prefix = "Starting: Intent { cmp=com.carriez.flutter_hbb/.MainActivity }"
activity = "Activity: com.carriez.flutter_hbb/.MainActivity"
if len(lines) < 6 or lines[0] != prefix or lines[3] != activity:
    raise SystemExit("malformed Android activity-launch receipt")
if lines[-1] != "Complete" or not re.fullmatch(r"WaitTime: [0-9]+", lines[-2]):
    raise SystemExit("incomplete Android activity-launch receipt")
if lines[1] == "Status: timeout":
    if lines != [prefix, "Status: timeout", "LaunchState: UNKNOWN (-1)",
                 activity, lines[-2], "Complete"]:
        raise SystemExit("malformed Android activity timeout receipt")
    print("timeout")
elif lines[1] == "Status: ok":
    if not re.fullmatch(r"LaunchState: (COLD|WARM|HOT)", lines[2]):
        raise SystemExit("malformed Android successful launch state")
    timings = lines[4:-2]
    if not timings or any(not re.fullmatch(r"(ThisTime|TotalTime): [0-9]+", line)
                          for line in timings):
        raise SystemExit("malformed Android successful launch timings")
    if len({line.split(":", 1)[0] for line in timings}) != len(timings):
        raise SystemExit("duplicated Android successful launch timing")
    print("ok")
else:
    raise SystemExit("Android activity launch status is neither ok nor timeout")
PY
    )" || fail "runtime-test activity launch receipt differs: $launch_output"
    readonly LAUNCH_WAIT_STATUS
    for _ in $(seq 1 120); do
        APP_PID="$(adb_shell_value pidof com.carriez.flutter_hbb 2>/dev/null || true)"
        if [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]]; then
            break
        fi
        APP_PID=
        sleep 0.25
    done
    [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] \
        || fail 'runtime-test application process did not become live'
    sleep 5
    [ "$(adb_shell_value pidof com.carriez.flutter_hbb 2>/dev/null || true)" = \
      "$APP_PID" ] \
        || fail 'runtime-test application process did not survive initial rendering'
    wait_resumed_activity \
        || fail 'runtime-test MainActivity is not the resumed activity'

    if [ "$WORKLOAD" = app-recents ]; then
        assert_no_main_service \
            || fail 'the focused Recents scenario began with MainService running'
        stage_recents_gesture_driver \
            || fail 'cannot stage the platform UiAutomator Recents driver'
        focused_task_ids=
        for lifecycle_cycle in $(seq 1 "$RECENTS_FOCUSED_CYCLES"); do
            dismiss_current_app_task "$lifecycle_cycle" \
                || {
                    capture_ui_hierarchy && print_initial_ui_semantics
                    fail "focused Recents cycle $lifecycle_cycle did not remove its bound task"
                }
            case " $focused_task_ids " in
                *" $RECENTS_LAST_TASK_ID "*)
                    fail "focused Recents cycle $lifecycle_cycle reused a removed task ID"
                    ;;
            esac
            focused_task_ids="${focused_task_ids:+$focused_task_ids }$RECENTS_LAST_TASK_ID"
            assert_no_main_service \
                || fail "focused Recents cycle $lifecycle_cycle started MainService"
            timeout --signal=TERM --kill-after=2s 60s \
                "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" \
                >/dev/null \
                || fail "focused Recents relaunch $lifecycle_cycle failed"
            wait_resumed_activity \
                || fail "focused Recents relaunch $lifecycle_cycle did not resume MainActivity"
            for _ in $(seq 1 120); do
                APP_PID="$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)"
                [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] && break
                APP_PID=
                sleep 0.25
            done
            [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] \
                || fail "focused Recents relaunch $lifecycle_cycle has no application process"
            assert_no_main_service \
                || fail "focused Recents relaunch $lifecycle_cycle started MainService"
        done
        retire_recents_gesture_driver \
            || fail 'the focused Recents gesture driver did not retire exactly'
        RECENTS_RECEIPT_READY=1
    fi

    if [ "$WORKLOAD" = app-lifecycle ] || [ "$WORKLOAD" = app-peer-lifecycle ]; then
        share_command=
        for _ in $(seq 1 3); do
            tap_ui text 'Share screen' || continue
            share_command="$(wait_ui_center text 'Start screen sharing' 2>/dev/null || true)"
            [[ "$share_command" =~ ^[0-9]+\ [0-9]+$ ]] && break
        done
        [[ "$share_command" =~ ^[0-9]+\ [0-9]+$ ]] \
            || { print_initial_ui_semantics; fail 'cannot observe the production screen-sharing command'; }
        read -r share_x share_y <<<"$share_command"
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell input tap "$share_x" "$share_y" \
            >/dev/null \
            || fail 'cannot invoke the production screen-sharing command'
        service_warning_observed=0
        password_dialog_ready=0
        service_transition_attempt=0
        while [ "$service_transition_attempt" -lt 12 ]; do
            if ! capture_ui_hierarchy complete; then
                service_transition_attempt=$((service_transition_attempt + 1))
                sleep 0.5
                continue
            fi
            handle_framework_interruption \
                || fail 'cannot handle the Android framework UI interruption'
            if [ "$FRAMEWORK_INTERRUPTION_HANDLED" -eq 1 ]; then
                continue
            fi
            service_transition_attempt=$((service_transition_attempt + 1))
            password_title="$(ui_center text 'Set password' 2>/dev/null || true)"
            if [[ "$password_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                password_dialog_ready=1
                break
            fi
            warning_title="$(ui_center text 'Warning' 2>/dev/null || true)"
            if [[ "$warning_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                service_warning_observed=1
                warning_content="$(ui_center text \
                    "$SERVICE_START_WARNING_TEXT" 2>/dev/null || true)"
                warning_ok="$(ui_center text 'OK' 2>/dev/null || true)"
                [[ "$warning_content" =~ ^[0-9]+\ [0-9]+$ ]] \
                    && [[ "$warning_ok" =~ ^[0-9]+\ [0-9]+$ ]] \
                    || { print_initial_ui_semantics; fail 'the production service-start warning differs'; }
                read -r warning_x warning_y <<<"$warning_ok"
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input tap "$warning_x" "$warning_y" \
                    >/dev/null \
                    || fail 'cannot accept the production service-start warning'
                sleep 1
                continue
            fi
            share_command="$(ui_center text 'Start screen sharing' 2>/dev/null || true)"
            if [[ "$share_command" =~ ^[0-9]+\ [0-9]+$ ]]; then
                read -r share_x share_y <<<"$share_command"
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input tap "$share_x" "$share_y" \
                    >/dev/null \
                    || fail 'cannot retry the production screen-sharing command'
                sleep 1
            else
                sleep 0.5
            fi
        done
        [ "$service_warning_observed:$password_dialog_ready" = 1:1 ] \
            || { print_initial_ui_semantics; fail 'the production service-start transition did not reach the password dialog'; }
        wait_ui_center text 'Set password' >/dev/null \
            || { print_initial_ui_semantics; fail 'the production permanent-password dialog did not open'; }
        password_field="$(wait_ui_center focused-password-field 2>/dev/null || true)"
        [[ "$password_field" =~ ^[0-9]+\ [0-9]+$ ]] \
            || { print_initial_ui_semantics; fail 'the permanent-password dialog has no exact focused password field'; }
        readonly TEST_PASSWORD=Runtime1x
        readonly TEST_PASSWORD_REMAINING=$((128 - ${#TEST_PASSWORD}))
        read -r field_x field_y <<<"$password_field"
        enter_exact_password \
            "$field_x" "$field_y" "$TEST_PASSWORD" "$TEST_PASSWORD_REMAINING" \
            || {
                print_initial_ui_semantics
                fail 'the password field did not observe the exact disposable input'
            }
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null \
            || fail 'cannot dismiss the disposable soft keyboard'
        confirmation_field=
        confirmation_focused=0
        for attempt in $(seq 1 5); do
            if capture_unobscured_ui_hierarchy; then
                ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
                    || fail 'the Android accessibility hierarchy exposed the password'
                confirmation_field="$(ui_password_field_center_with_remaining \
                    128 2>/dev/null || true)"
                if [[ "$confirmation_field" =~ ^[0-9]+\ [0-9]+$ ]]; then
                    read -r field_x field_y <<<"$confirmation_field"
                    "$ADB" -s "$SERIAL" shell input tap \
                        "$field_x" "$field_y" >/dev/null \
                        || fail 'cannot focus the password-confirmation field'
                    sleep 0.5
                    if wait_ui_center focused-password-field >/dev/null \
                       && capture_unobscured_ui_hierarchy complete; then
                        ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
                            || fail 'the Android accessibility hierarchy exposed the password'
                        focused_remaining="$(ui_focused_password_remaining \
                            2>/dev/null || true)"
                        if [ "$focused_remaining" = 128 ]; then
                            confirmation_focused=1
                            break
                        fi
                        "$ADB" -s "$SERIAL" shell input keyevent \
                            KEYCODE_BACK >/dev/null \
                            || fail 'cannot dismiss the misplaced password keyboard'
                        sleep 0.5
                    fi
                fi
            fi
            [ "$attempt" -lt 5 ] || break
            timeout --signal=TERM --kill-after=2s 10s \
                "$ADB" -s "$SERIAL" shell input swipe 240 270 240 120 300 \
                >/dev/null || fail 'cannot scroll the permanent-password dialog'
            sleep 0.5
        done
        if [ "$confirmation_focused" -ne 1 ]; then
            ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
                || fail 'the Android accessibility hierarchy exposed the password'
            print_initial_ui_semantics
            fail 'the exact untouched password-confirmation field did not receive focus'
        fi
        fill_focused_password "$TEST_PASSWORD" "$TEST_PASSWORD_REMAINING" \
            || {
                print_initial_ui_semantics
                fail 'the password-confirmation field did not observe the exact disposable input'
            }
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null \
            || fail 'cannot dismiss the disposable soft keyboard'
        capture_unobscured_ui_hierarchy \
            || fail 'cannot inspect the completed permanent-password dialog'
        ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
            || fail 'the Android accessibility hierarchy exposed the password'
        grant_media_projection_after_password_submit \
            || {
                print_password_submit_thread_diagnostic
                print_mobile_storage_key_log
                print_native_password_log
                capture_ui_hierarchy \
                    || fail 'cannot inspect the missing MediaProjection consent'
                ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
                    || fail 'the Android accessibility hierarchy exposed the password'
                print_initial_ui_semantics
                fail 'cannot grant the production MediaProjection consent'
            }
        wait_ui_center text 'Screen capture ready' >/dev/null \
            || fail 'the production UI did not observe MediaProjection readiness'
        assert_main_service \
            || fail 'MainService is not one started foreground-service generation'
        [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
          "$APP_PID" ] \
            || fail 'the application process changed while starting MainService'

        lifecycle_log="$(adb_shell_value logcat -d -v brief)"
        assert_main_service_log_cardinality "$lifecycle_log" initial 1 0 \
            || fail 'MainService was not created and started exactly once'
        ! grep -Eq 'FATAL EXCEPTION|Failed to resume Android client session ownership|MainService destruction retained incomplete generation authority' \
            <<<"$lifecycle_log" \
            || fail 'the initial lifecycle log contains a fatal ownership failure'

        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            exercise_android_controlled_cpace
            assert_main_service \
                || fail 'the Android controlled-side CPace probe changed MainService state'
            [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
              "$APP_PID" ] \
                || fail 'the Android controlled-side CPace probe changed the application process'
            tap_ui text 'Connection' \
                || fail 'cannot return to the production Connection page'
            open_peer_connection initial 1 \
                || {
                    capture_android_connection_diagnostic active || true
                    reprint_android_connection_diagnostic || true
                    capture_ui_hierarchy complete && print_initial_ui_semantics
                    fail 'the initial authenticated Android peer connection failed'
                }
            PEER_INITIAL_RECOVERY_MS=$PEER_LAST_RECOVERY_MS
            background_cycle=0
            for background_seconds in "${PEER_BACKGROUND_SECONDS[@]}"; do
                background_cycle=$((background_cycle + 1))
                exercise_peer_background_resume \
                    "$APP_PID" "$background_cycle" "$background_seconds"
            done
        fi

        stage_recents_gesture_driver \
            || fail 'cannot stage the platform UiAutomator Recents driver'
        for lifecycle_cycle in 1 2; do
            dismiss_current_app_task "$lifecycle_cycle" \
                || {
                    capture_ui_hierarchy && print_initial_ui_semantics
                    fail "lifecycle task $lifecycle_cycle was not removed by its bound Recents action"
                }
            [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
              "$APP_PID" ] \
                || fail "task removal $lifecycle_cycle killed or replaced the service process"
            assert_main_service \
                || fail "task removal $lifecycle_cycle did not preserve MainService"
            if [ "$WORKLOAD" = app-peer-lifecycle ]; then
                wait_peer_server_connections 0 exact \
                    || fail "task removal $lifecycle_cycle retained the obsolete Android peer connection"
            fi
            timeout --signal=TERM --kill-after=2s 60s \
                "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" \
                >/dev/null \
                || fail "relaunch $lifecycle_cycle failed"
            wait_resumed_activity \
                || fail "relaunch $lifecycle_cycle did not resume MainActivity"
            [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
              "$APP_PID" ] \
                || fail "relaunch $lifecycle_cycle did not reuse the service process"
            tap_ui text 'Share screen' \
                || fail "relaunch $lifecycle_cycle cannot select Share screen"
            wait_ui_center text 'Screen capture ready' >/dev/null \
                || fail "relaunch $lifecycle_cycle lost MediaProjection readiness"
            assert_main_service \
                || fail "relaunch $lifecycle_cycle changed MainService state"
            lifecycle_log="$(adb_shell_value logcat -d -v brief)"
            assert_main_service_log_cardinality \
                "$lifecycle_log" "relaunch-$lifecycle_cycle" \
                "$((lifecycle_cycle + 1))" "$lifecycle_cycle" \
                || fail "relaunch $lifecycle_cycle changed MainService lifecycle cardinality"
            ! grep -Eq 'FATAL EXCEPTION|Failed to resume Android client session ownership|MainService destruction retained incomplete generation authority' \
                <<<"$lifecycle_log" \
                || fail "relaunch $lifecycle_cycle logged a fatal ownership failure"
            if [ "$WORKLOAD" = app-peer-lifecycle ]; then
                tap_ui text 'Connection' \
                    || fail "relaunch $lifecycle_cycle cannot select Connection"
                open_peer_connection "task-relaunch-$lifecycle_cycle" 0 \
                    || { capture_ui_hierarchy complete && print_initial_ui_semantics; fail "relaunch $lifecycle_cycle did not establish a fresh cached-credential peer session"; }
                [ "$PEER_LAST_RECOVERY_MS" -le "$PEER_TASK_RECOVERY_MAX_MS" ] \
                    || PEER_TASK_RECOVERY_MAX_MS=$PEER_LAST_RECOVERY_MS
            fi
        done
        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            emit_peer_presentation_stage_receipts \
                || {
                    print_peer_presentation_stage_diagnostic complete || true
                    fail 'the bounded Android presentation-stage receipts differ'
                }
            PEER_PRESENTATION_STAGE_READY=1
        fi
        retire_recents_gesture_driver \
            || fail 'the lifecycle Recents gesture driver did not retire exactly'

        readonly PRE_FORCE_PID=$APP_PID
        timeout --signal=TERM --kill-after=2s 10s \
            "$ADB" -s "$SERIAL" shell am force-stop "$APP_PACKAGE" >/dev/null \
            || fail 'the Android Force Stop baseline failed'
        force_stopped=0
        for _ in $(seq 1 120); do
            if [ -z "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" ] \
               && assert_no_main_service; then
                force_stopped=1
                break
            fi
            sleep 0.25
        done
        [ "$force_stopped" -eq 1 ] \
            || fail 'Force Stop did not remove both the process and MainService'
        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            wait_peer_server_connections 0 exact \
                || fail 'Force Stop retained the Android peer connection'
        fi
        package_state="$(adb_shell_value dumpsys package "$APP_PACKAGE")"
        grep -Eq 'stopped=true' <<<"$package_state" \
            || fail 'Android did not record the package Force Stop state'
        timeout --signal=TERM --kill-after=2s 60s \
            "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" >/dev/null \
            || fail 'the post-Force-Stop launch failed'
        wait_resumed_activity \
            || fail 'the post-Force-Stop MainActivity did not resume'
        for _ in $(seq 1 120); do
            APP_PID="$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)"
            [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] && break
            APP_PID=
            sleep 0.25
        done
        [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] && [ "$APP_PID" != "$PRE_FORCE_PID" ] \
            || fail 'the post-Force-Stop launch did not create a distinct process'
        assert_no_main_service \
            || fail 'the post-Force-Stop launch silently resurrected MainService'
        tap_ui text 'Share screen' \
            || fail 'the post-Force-Stop UI cannot select Share screen'
        wait_ui_center text 'Screen sharing is off' >/dev/null \
            || fail 'the post-Force-Stop UI does not report the stopped service'
        package_state="$(adb_shell_value dumpsys package "$APP_PACKAGE")"
        grep -Eq 'stopped=false' <<<"$package_state" \
            || fail 'the relaunched package remained Force Stopped'
        sleep 5
        [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
          "$APP_PID" ] \
            || fail 'the post-Force-Stop process did not survive rendering'
        assert_no_main_service \
            || fail 'MainService started without a post-Force-Stop user command'
        lifecycle_log="$(adb_shell_value logcat -d -v brief)"
        assert_main_service_log_cardinality \
            "$lifecycle_log" post-force-stop 3 2 \
            || fail 'the post-Force-Stop launch changed MainService start cardinality'
        ! grep -Eq 'FATAL EXCEPTION' <<<"$lifecycle_log" \
            || fail 'the completed lifecycle logged a fatal exception'
        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            retired_session_events="$(printf '%s\n' "$lifecycle_log" \
                | grep -Ec 'Retired [1-9][0-9]* outgoing client peer session\(s\)' || true)"
            [ "$retired_session_events" -eq 2 ] \
                || fail 'the two removed tasks did not report exact outgoing-session retirement'
            [ "$PEER_INITIAL_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_BACKGROUND_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_BACKGROUND_CYCLES" -eq "${#PEER_BACKGROUND_SECONDS[@]}" ] \
                && [ "$PEER_TASK_RECOVERY_MAX_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_FRESHNESS_MAX_MS" -le "$PEER_FRESHNESS_LIMIT_MS" ] \
                && [ "$PEER_DISTINCT_FRAMES" -ge 12 ] \
                || fail 'the Android peer display exceeded its recovery or freshness bounds'
            PEER_RECEIPT_READY=1
        fi
        LIFECYCLE_RECEIPT_READY=1
    fi
fi

timeout --signal=TERM --kill-after=2s 20s \
    "$ADB" -s "$SERIAL" exec-out screencap -p >"$FRAMEBUFFER" \
    || fail 'cannot capture the booted Android framebuffer'
framebuffer_dimensions="$(python3 -I -S - "$FRAMEBUFFER" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as stream:
    header = stream.read(24)
    remainder = stream.read(8 * 1024 * 1024 + 1)
if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
    raise SystemExit("framebuffer is not a PNG")
if header[12:16] != b"IHDR":
    raise SystemExit("framebuffer PNG has no leading IHDR")
width, height = struct.unpack(">II", header[16:24])
if width < 320 or height < 320 or width > 4096 or height > 4096:
    raise SystemExit("framebuffer dimensions are outside the admitted range")
if not remainder or len(remainder) > 8 * 1024 * 1024:
    raise SystemExit("framebuffer PNG size is outside the admitted range")
print(f"{width}x{height}")
PY
)" || fail 'the booted Android framebuffer is structurally invalid'
case "$framebuffer_dimensions" in
    480x800|800x480) ;;
    *) fail "booted Android framebuffer dimensions differ: $framebuffer_dimensions" ;;
esac

if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ "$PEER_REVERSE_READY" -eq 1 ] \
        || fail 'the private Android peer reverse mapping was not established'
    peer_reverse_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --list | tr -d '\r')" \
        || fail 'cannot recheck the private Android peer reverse mapping'
    [ "$peer_reverse_listing" = "$PEER_REVERSE_LISTING" ] \
        || fail 'the private Android peer reverse mapping changed during execution'
    peer_reverse_output="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --remove "$PEER_REVERSE_DEVICE_SPEC" \
        | tr -d '\r')" \
        || fail 'cannot remove the private Android peer reverse mapping'
    [ -z "$peer_reverse_output" ] \
        || fail 'removing the Android peer reverse mapping returned unexpected output'
    peer_reverse_listing="$(timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" reverse --list | tr -d '\r')" \
        || fail 'cannot verify Android peer reverse-mapping closure'
    [ -z "$peer_reverse_listing" ] \
        || fail 'the Android peer reverse mapping survived explicit removal'
    PEER_REVERSE_READY=0
    PEER_REVERSE_LISTING=
    stop_frame_observer \
        || fail 'the Android emulator display observer did not join cleanly'
    frame_observer_listener_is_exact \
        || fail 'the emulator display endpoint changed before emulator shutdown'
fi

stop_emulator || fail 'Android emulator or adb did not stop within the bounded teardown'
[ "$WORKLOAD" != app-peer-lifecycle ] \
    || ! frame_observer_listener_is_exact \
    || fail 'the emulator display endpoint survived emulator shutdown'
[ -z "$(find /proc -maxdepth 2 -path '*/comm' -readable -exec \
    awk '$0 == "qemu-system-x86" { print FILENAME }' {} + 2>/dev/null)" ] \
    || fail 'an Android emulator process survived bounded teardown'
if [ "$WORKLOAD" = app-peer-lifecycle ]; then
    stop_peer_infrastructure \
        || fail 'the controlled Android peer infrastructure did not join'
    grep -Eq '^FLUTTER_PEER_SOURCE_COMPLETE frames=[0-9]+$' "$PEER_SOURCE_LOG" \
        || { tail -n 80 "$PEER_SOURCE_LOG" >&2; fail 'the changing X11 source did not close exactly'; }
    [ "$(stat -c '%s' -- "$PEER_SOURCE_LOG")" -le 2097152 ] \
        && [ "$(stat -c '%s' -- "$PEER_SERVER_LOG")" -le 2097152 ] \
        && [ "$(stat -c '%s' -- "$PEER_SEED_LOG")" -le 4096 ] \
        && [ ! -s "$PEER_XVFB_LOG" ] \
        || fail 'the controlled Android peer logs differ from their finite bounds'
    [ "$(awk 'FNR > 1 && $2 == "0100007F:527E" { count++ }
        END { print count + 0 }' /proc/net/tcp)" -eq 0 ] \
        || fail 'the controlled Android peer listener survived teardown'
fi
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-recents ] \
   || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ "$(sha256sum "$RUNTIME_TEST_APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
        || fail 'runtime-test APK changed during emulator execution'
    printf 'ANDROID_EMULATOR_APP=pass emulator=%s api=%s abi=%s package=com.carriez.flutter_hbb activity=MainActivity launch_wait=%s state=resumed process=stable-five-seconds apk_sha256=%s signing=test-only acceleration=software gpu=swiftshader framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$LAUNCH_WAIT_STATUS" "$APK_SHA256" \
        "$framebuffer_dimensions" "$SELINUX"
    if [ "$WORKLOAD" = app-recents ]; then
        [ "$RECENTS_RECEIPT_READY" -eq 1 ] \
            || fail 'the focused Recents receipt is not ready'
        [ "$RECENTS_GESTURE_STAGED" -eq 0 ] \
            || fail 'the focused Recents gesture driver remained staged'
        framework_anr="$(framework_anr_receipt)" \
            || fail 'the focused Recents framework ANR receipt is invalid'
        printf 'ANDROID_EMULATOR_RECENTS=pass task_removals=%s actions=%s open_actions=%s task_ids=distinct open=ui-automation-app-switch-key-display-0 driver=android14-ui-automation-direct events=%s steps=%s step_ms=%s wait_for_animations=false runtime_uiautomator_sha256=%s driver_sha256=%s framework_anr=%s service=never-started relaunch=resumed apk_sha256=%s vm_network=none container_network=none cleanup=joined\n' \
            "$RECENTS_FOCUSED_CYCLES" "$RECENTS_FOCUSED_CYCLES" \
            "$RECENTS_FOCUSED_CYCLES" \
            "$RECENTS_DISMISS_GESTURE_EVENTS" "$RECENTS_DISMISS_GESTURE_STEPS" \
            "$RECENTS_DISMISS_GESTURE_STEP_MS" \
            "$RECENTS_RUNTIME_UIAUTOMATOR_SHA256" "$RECENTS_GESTURE_SHA256" \
            "$framework_anr" \
            "$APK_SHA256"
    fi
    if [ "$WORKLOAD" = app-lifecycle ] || [ "$WORKLOAD" = app-peer-lifecycle ]; then
        [ "$LIFECYCLE_RECEIPT_READY" -eq 1 ] \
            || fail 'the Android lifecycle receipt is not ready'
        framework_anr="$(framework_anr_receipt)" \
            || fail 'the Android lifecycle framework ANR receipt is invalid'
        immersive_cling=absent
        if [ -f "$IMMERSIVE_CLING_MARKER" ] && [ ! -L "$IMMERSIVE_CLING_MARKER" ]; then
            [ "$(stat -c '%u:%g:%a:%h' -- "$IMMERSIVE_CLING_MARKER")" = \
              "$RUN_UID:$RUN_GID:600:1" ] \
                || fail 'the immersive-cling marker metadata differs'
            [ "$(wc -l <"$IMMERSIVE_CLING_MARKER")" -eq 1 ] \
                || fail 'the immersive-mode tutorial was not dismissed exactly once'
            immersive_cling=dismissed-1
        fi
        printf 'ANDROID_EMULATOR_LIFECYCLE=pass task_removals=2 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=%s immersive_cling=%s apk_sha256=%s vm_network=none container_network=none cleanup=joined\n' \
            "$framework_anr" "$immersive_cling" "$APK_SHA256"
        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            [ "$PEER_RECEIPT_READY" -eq 1 ] \
                || fail 'the Android real-peer lifecycle receipt is not ready'
            [ "$PEER_PRESENTATION_STAGE_READY" -eq 1 ] \
                || fail 'the Android presentation-stage receipt is not ready'
            [ "$PEER_REVERSE_READY" -eq 0 ] \
                || fail 'the Android peer reverse mapping remained live at receipt time'
            printf 'ANDROID_EMULATOR_PEER_LIFECYCLE=pass auth=cpace server=production address=127.0.0.1:22118 transport=adb-reverse-loopback service=foreground-preserved process=same-across-task-removal task_removals=2 old_sessions=closed replacements=2 initial_credential=missing-credential initial_credential_prompt_observer=%s initial_credential_prompt_ms=%s initial_credential_prompt_limit_ms=%s initial_network_attempts=0 wrong_credential=peer-confirmation-unavailable-prompt wrong_attempts=1 auto_retry=absent credential_prompt_observer=%s credential_prompt_ms=%s credential_prompt_limit_ms=%s auto_retry_observation_ms=%s correct_credential_connection_ms=%s credential_connection_limit_ms=%s cached_connection_max_ms=%s cached_connection_limit_ms=%s initial_recovery_ms=%s background_cycles=%s background_seconds=2,6,12 background_recovery_max_ms=%s task_recovery_max_ms=%s recovery_limit_ms=%s freshness_max_ms=%s freshness_limit_ms=%s capture_max_ms=%s capture_limit_ms=%s distinct_frames=%s force_stop=baseline apk_sha256=%s vm_network=none container_network=none server_listener=127.0.0.1:21118 reverse_cleanup=removed x11=unix-only cleanup=joined\n' \
                "$PEER_INITIAL_CREDENTIAL_SEMANTIC_MODE" \
                "$PEER_INITIAL_CREDENTIAL_PROMPT_MS" \
                "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$PEER_CREDENTIAL_SEMANTIC_MODE" \
                "$PEER_CREDENTIAL_PROMPT_MS" "$PEER_CREDENTIAL_PROMPT_LIMIT_MS" \
                "$PEER_NO_AUTO_RETRY_OBSERVATION_MS" \
                "$PEER_CORRECT_CREDENTIAL_CONNECTION_MS" \
                "$PEER_PASSWORD_CONNECTION_WAIT_LIMIT_MS" \
                "$PEER_CACHED_CONNECTION_MAX_MS" "$PEER_CONNECTION_WAIT_LIMIT_MS" \
                "$PEER_INITIAL_RECOVERY_MS" "$PEER_BACKGROUND_CYCLES" \
                "$PEER_BACKGROUND_RECOVERY_MS" "$PEER_TASK_RECOVERY_MAX_MS" \
                "$PEER_RECOVERY_LIMIT_MS" \
                "$PEER_FRESHNESS_MAX_MS" "$PEER_FRESHNESS_LIMIT_MS" \
                "$PEER_CAPTURE_MAX_MS" "$PEER_CAPTURE_LIMIT_MS" \
                "$PEER_DISTINCT_FRAMES" "$APK_SHA256"
        fi
    fi
else
    printf 'ANDROID_EMULATOR_BOOT=pass emulator=%s api=%s abi=%s acceleration=software gpu=swiftshader framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$framebuffer_dimensions" "$SELINUX"
fi

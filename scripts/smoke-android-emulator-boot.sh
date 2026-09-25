#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'Android emulator boot smoke: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || [ "$#" -eq 5 ] || [ "$#" -eq 6 ] \
    || fail 'usage: smoke-android-emulator-boot.sh EMULATOR_ZIP SYSTEM_IMAGE_ZIP ADB WORK_ROOT [RUNTIME_TEST_APK [lifecycle|peer-lifecycle]]'
readonly EMULATOR_ZIP=$1
readonly SYSTEM_IMAGE_ZIP=$2
readonly INPUT_ADB=$3
readonly WORK_ROOT=$4
readonly RUNTIME_TEST_APK=${5:-}
readonly APP_SCENARIO=${6:-launch}
if [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = peer-lifecycle ]; then
    readonly WORKLOAD=app-peer-lifecycle
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = lifecycle ]; then
    readonly WORKLOAD=app-lifecycle
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=app
elif [ -z "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=boot
else
    fail 'the Android app scenario differs from launch, lifecycle, or peer-lifecycle'
fi
readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly RUN_UID="$(id -u)"
readonly RUN_GID="$(id -g)"
[ "$RUN_UID:$RUN_GID" = 1000:1000 ] \
    || fail 'the emulator workload requires numeric uid/gid 1000:1000'
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ] \
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
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ] \
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
PEER_TASK_RECOVERY_MAX_MS=0
readonly PEER_RECOVERY_LIMIT_MS=8000
readonly PEER_FRESHNESS_LIMIT_MS=2000

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
                'No remembered password|CPace handshake failed|R-S9|connect-password-prompt|session_set_connect_password|viewer owner|outgoing viewer|connection round|Connection closed|keying' \
            | tail -n 160 \
            || true
    )"
    if [ "${#logcat_diag}" -gt 131072 ]; then
        printf 'Android connection diagnostic: filtered logcat exceeded 128 KiB\n' >&2
    elif [ -n "$logcat_diag" ]; then
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
            "$ADB" -s "$SERIAL" exec-out tail -c 131072 \
            "$log_dir/$latest" 2>/dev/null \
            | tr -d '\r' \
            | tail -n 200 \
            || true
    )"
    if [ "${#native_diag}" -gt 131072 ]; then
        printf 'Android connection diagnostic: native-log tail exceeded 128 KiB\n' >&2
    elif [ -n "$native_diag" ]; then
        printf 'Android connection diagnostic (%s):\n%s\n' \
            "$latest" "$native_diag" >&2
    else
        printf 'Android connection diagnostic (%s): no matching records\n' \
            "$latest" >&2
    fi
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
    local expected=$1 comparison=$2 count
    for _ in $(seq 1 120); do
        count="$(peer_server_established_count)"
        case "$comparison" in
            at-least) [ "$count" -ge "$expected" ] && return 0 ;;
            exact) [ "$count" -eq "$expected" ] && return 0 ;;
            *) return 2 ;;
        esac
        sleep 0.25
    done
    return 1
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
        print_android_connection_diagnostic || true
    fi
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
    readonly PEER_SEED_LOG=$WORK_ROOT/peer-seed.log
    readonly PEER_SOURCE_LOG=$WORK_ROOT/peer-source.log
    readonly PEER_SERVER_LOG=$WORK_ROOT/peer-server.log
    readonly PEER_XVFB_LOG=$WORK_ROOT/peer-xvfb.log
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
    >"$EMULATOR_LOG" 2>&1 &
EMULATOR_PID=$!
EMULATOR_START="$(process_start_time "$EMULATOR_PID")" \
    || fail 'cannot bind the emulator process generation'
[[ "$EMULATOR_START" =~ ^[1-9][0-9]*$ ]] \
    || fail 'the emulator process start time is malformed'

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
if kind not in ("address-field", "focused-password-field", "password-fields") and not wanted:
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
    elif kind == "password-fields":
        matched = (
            attributes.get("class") == "android.widget.EditText"
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
if kind == "password-fields" and len(centers) not in (1, 2):
    raise SystemExit(1)
if kind != "password-fields" and len(centers) != 1:
    raise SystemExit(1)
for x, y in sorted(centers, key=lambda point: (point[1], point[0])):
    print(f"{x} {y}")
PY
}

ui_focused_password_bounds() {
    python3 -I -S - "$UI_XML" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

bounds = set()
for node in ET.parse(sys.argv[1]).getroot().iter("node"):
    attributes = node.attrib
    if not (
        attributes.get("class") == "android.widget.EditText"
        and attributes.get("focusable") == "true"
        and attributes.get("focused") == "true"
        and attributes.get("enabled") == "true"
        and attributes.get("password") == "true"
    ):
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
        if capture_ui_hierarchy complete; then
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

wait_ui_center() {
    local kind=$1
    shift
    local center= cling_title= cling_ok= cling_x= cling_y=
    local anr_title= anr_wait= anr_x= anr_y=
    local ui_attempt=0
    while [ "$ui_attempt" -lt 12 ]; do
        if capture_ui_hierarchy; then
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
                sleep 1
                continue
            fi
            anr_title="$(ui_center text "System UI isn't responding" \
                "Process system isn't responding" 2>/dev/null || true)"
            if [[ "$anr_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                anr_wait="$(ui_center resource android:id/aerr_wait 2>/dev/null || true)"
                [[ "$anr_wait" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
                printf 'waited\n' >>"$FRAMEWORK_ANR_MARKER"
                [ "$(wc -l <"$FRAMEWORK_ANR_MARKER")" -le \
                  "$MAX_FRAMEWORK_ANR_WAITS" ] || return 1
                read -r anr_x anr_y <<<"$anr_wait"
                timeout --signal=TERM --kill-after=2s 10s \
                    "$ADB" -s "$SERIAL" shell input tap "$anr_x" "$anr_y" \
                    >/dev/null || return 1
                sleep 2
                continue
            fi
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

tap_ui() {
    local kind=$1
    shift
    local center x y
    center="$(wait_ui_center "$kind" "$@")" || return 1
    read -r x y <<<"$center"
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null
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

current_app_task_id() {
    local state
    state="$(adb_shell_value dumpsys activity recents)" || return 1
    python3 -I -S - "$state" <<'PY'
import re
import sys

task_ids = set()
for line in sys.argv[1].splitlines():
    if "com.carriez.flutter_hbb" not in line or "Task{" not in line:
        continue
    match = re.search(r"Task\{[^}]* #[1-9][0-9]*\b", line)
    if match:
        task_ids.add(match.group().rsplit("#", 1)[1])
if len(task_ids) != 1:
    raise SystemExit(1)
print(task_ids.pop())
PY
}

swipe_app_task_from_recents() {
    local expected_task_id=$1 current_task_id= task_bounds=
    local left= top= right= bottom= center_x= start_y=
    current_task_id="$(current_app_task_id 2>/dev/null || true)"
    [ "$current_task_id" = "$expected_task_id" ] || return 1
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_APP_SWITCH \
        >/dev/null || return 1
    task_bounds="$(wait_ui_resource_bounds \
        com.android.launcher3:id/snapshot 2>/dev/null || true)"
    if ! [[ "$task_bounds" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
        capture_ui_hierarchy complete && print_initial_ui_semantics
        return 1
    fi
    read -r left top right bottom <<<"$task_bounds"
    [ "$right" -gt "$left" ] && [ "$bottom" -gt "$top" ] \
        && [ "$bottom" -gt 1 ] || return 1
    center_x=$(((left + right) / 2))
    start_y=$((bottom - 1))
    timeout --signal=TERM --kill-after=2s 10s \
        "$ADB" -s "$SERIAL" shell input swipe \
        "$center_x" "$start_y" "$center_x" 0 600 \
        >/dev/null
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

decode_peer_screenshot() {
    local screenshot=$1 source_state=$2
    python3 -I -S - "$screenshot" "$source_state" <<'PY'
import collections
import struct
import sys
import zlib

path = sys.argv[1]
source_state = int(sys.argv[2])
palette = (
    (232, 36, 36), (36, 224, 48), (36, 64, 232), (232, 220, 36),
    (224, 36, 220), (36, 220, 220), (240, 120, 24), (128, 40, 232),
    (24, 132, 232), (232, 40, 128), (132, 232, 24), (24, 232, 132),
    (196, 92, 44), (44, 196, 92), (92, 44, 196), (196, 196, 196),
)

data = open(path, "rb").read()
if len(data) > 8 * 1024 * 1024 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
    raise SystemExit(1)
offset = 8
idat = bytearray()
width = height = depth = color_type = interlace = None
while offset + 12 <= len(data):
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    kind = data[offset + 4:offset + 8]
    payload = data[offset + 8:offset + 8 + length]
    if offset + 12 + length > len(data):
        raise SystemExit(1)
    if kind == b"IHDR":
        width, height, depth, color_type, compression, filtering, interlace = \
            struct.unpack(">IIBBBBB", payload)
        if compression != 0 or filtering != 0:
            raise SystemExit(1)
    elif kind == b"IDAT":
        idat.extend(payload)
    elif kind == b"IEND":
        break
    offset += 12 + length
if depth != 8 or color_type not in (2, 6) or interlace != 0:
    raise SystemExit(1)
channels = 3 if color_type == 2 else 4
raw = zlib.decompress(bytes(idat))
stride = width * channels
if len(raw) != height * (stride + 1):
    raise SystemExit(1)
rows = []
previous = bytearray(stride)
cursor = 0
for _ in range(height):
    filter_type = raw[cursor]
    scanline = bytearray(raw[cursor + 1:cursor + 1 + stride])
    cursor += stride + 1
    for index in range(stride):
        left = scanline[index - channels] if index >= channels else 0
        above = previous[index]
        upper_left = previous[index - channels] if index >= channels else 0
        if filter_type == 1:
            scanline[index] = (scanline[index] + left) & 0xff
        elif filter_type == 2:
            scanline[index] = (scanline[index] + above) & 0xff
        elif filter_type == 3:
            scanline[index] = (scanline[index] + ((left + above) >> 1)) & 0xff
        elif filter_type == 4:
            estimate = left + above - upper_left
            pa = abs(estimate - left)
            pb = abs(estimate - above)
            pc = abs(estimate - upper_left)
            predictor = left if pa <= pb and pa <= pc else above if pb <= pc else upper_left
            scanline[index] = (scanline[index] + predictor) & 0xff
        elif filter_type != 0:
            raise SystemExit(1)
    rows.append(scanline)
    previous = scanline

regions = {
    "left-right": (collections.Counter(), collections.Counter()),
    "top-bottom": (collections.Counter(), collections.Counter()),
}
sample_count = 0
for y in range(0, height, 2):
    row = rows[y]
    for x in range(0, width, 2):
        base = x * channels
        rgb = row[base], row[base + 1], row[base + 2]
        distances = [sum((rgb[i] - color[i]) ** 2 for i in range(3)) for color in palette]
        nearest = min(range(len(palette)), key=distances.__getitem__)
        if distances[nearest] > 55 * 55:
            continue
        regions["left-right"][0 if x < width // 2 else 1][nearest] += 1
        regions["top-bottom"][0 if y < height // 2 else 1][nearest] += 1
        sample_count += 1

candidates = []
for layout, (first, second) in regions.items():
    if not first or not second:
        continue
    low, low_count = first.most_common(1)[0]
    high, high_count = second.most_common(1)[0]
    state = high * 16 + low
    age = (source_state - state) % 256
    score = min(low_count, high_count)
    candidates.append((age <= 8, score, -age, state, age, layout,
                       low_count + high_count))
valid = [candidate for candidate in candidates if candidate[0]]
if not valid:
    raise SystemExit(1)
chosen = max(valid)
_, score, _, state, age, layout, matched = chosen
minimum = max(300, (width * height) // 40)
if score < minimum or matched < minimum * 2:
    raise SystemExit(1)
print(f"{state} {age} {score} {matched} {layout}")
PY
}

PEER_LAST_RECOVERY_MS=0
capture_peer_freshness() {
    local phase=$1 started_ms now_ms source_state screenshot decoded
    local state age score matched layout max_age=0
    local -A seen=()
    started_ms="$(monotonic_millis)" \
        || fail "cannot read the monotonic clock for $phase"
    for attempt in $(seq 1 30); do
        now_ms="$(monotonic_millis)" \
            || fail "cannot reread the monotonic clock for $phase"
        [ "$((now_ms - started_ms))" -le "$PEER_RECOVERY_LIMIT_MS" ] \
            || break
        screenshot="$WORK_ROOT/peer-$phase-$attempt.png"
        timeout --signal=TERM --kill-after=2s 20s \
            "$ADB" -s "$SERIAL" exec-out screencap -p >"$screenshot" \
            || fail "cannot capture Android peer framebuffer for $phase"
        source_state="$(peer_source_state 2>/dev/null || true)"
        decoded=
        if [[ "$source_state" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
            decoded="$(decode_peer_screenshot "$screenshot" "$source_state" 2>/dev/null || true)"
        fi
        rm -f -- "$screenshot"
        if [[ "$decoded" =~ ^([0-9]+)\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)\ (left-right|top-bottom)$ ]]; then
            state=${BASH_REMATCH[1]}
            age=${BASH_REMATCH[2]}
            score=${BASH_REMATCH[3]}
            matched=${BASH_REMATCH[4]}
            layout=${BASH_REMATCH[5]}
            seen[$state]=1
            [ "$age" -le "$max_age" ] || max_age=$age
            if [ "${#seen[@]}" -ge 2 ]; then
                now_ms="$(monotonic_millis)" \
                    || fail "cannot finish the monotonic measurement for $phase"
                PEER_LAST_RECOVERY_MS=$((now_ms - started_ms))
                [ "$PEER_LAST_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                    || break
                PEER_DISTINCT_FRAMES=$((PEER_DISTINCT_FRAMES + ${#seen[@]}))
                [ "$((max_age * 250))" -le "$PEER_FRESHNESS_MAX_MS" ] \
                    || PEER_FRESHNESS_MAX_MS=$((max_age * 250))
                printf 'ANDROID_PEER_FRESHNESS=pass phase=%s recovery_ms=%s max_age_ms=%s distinct=%s score=%s matched=%s layout=%s\n' \
                    "$phase" "$PEER_LAST_RECOVERY_MS" "$((max_age * 250))" \
                    "${#seen[@]}" "$score" "$matched" "$layout"
                return 0
            fi
        fi
        sleep 0.5
    done
    capture_ui_hierarchy complete && print_initial_ui_semantics
    print_android_connection_diagnostic active
    fail "Android peer display did not become fresh and changing for $phase"
}

open_peer_connection() {
    local generation=$1 expect_password=$2 center x y bounds=
    local left= top= right= bottom= visibility_x= visibility_y=
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
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_ENTER >/dev/null || return 1
    if [ "$expect_password" -eq 1 ]; then
        wait_ui_center text 'Password required' >/dev/null \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; return 1; }
        capture_ui_hierarchy || return 1
        center="$(ui_center focused-password-field 2>/dev/null || true)"
        [[ "$center" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
        read -r x y <<<"$center"
        bounds="$(ui_focused_password_bounds 2>/dev/null || true)"
        [[ "$bounds" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || return 1
        read -r left top right bottom <<<"$bounds"
        "$ADB" -s "$SERIAL" shell input tap "$x" "$y" >/dev/null || return 1
        "$ADB" -s "$SERIAL" shell input text "$PEER_PASSWORD" >/dev/null || return 1
        visibility_x=$((right - 24))
        visibility_y=$(((top + bottom) / 2))
        "$ADB" -s "$SERIAL" shell input tap \
            "$visibility_x" "$visibility_y" >/dev/null || return 1
        wait_ui_center address-field "$PEER_PASSWORD" >/dev/null || return 1
        printf 'ANDROID_PEER_PASSWORD_INPUT=pass visible_roundtrip=true chars=%s\n' \
            "${#PEER_PASSWORD}"
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null || return 1
        capture_ui_hierarchy || return 1
        grep -Fq "$PEER_PASSWORD" "$UI_XML" || return 1
        tap_ui text 'Remember password' || return 1
        tap_ui text 'OK' || return 1
    else
        sleep 1
        if capture_ui_hierarchy \
           && ui_center text 'Password required' >/dev/null 2>&1; then
            print_initial_ui_semantics
            return 1
        fi
    fi
    wait_peer_server_connections 1 exact || return 1
    capture_peer_freshness "$generation"
    wait_peer_server_connections 1 exact
}

exercise_peer_background_resume() {
    local pid_before=$1
    "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_HOME >/dev/null \
        || fail 'cannot background the Android peer Activity'
    sleep 4
    [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = "$pid_before" ] \
        || fail 'backgrounding replaced the MainService process'
    wait_peer_server_connections 1 exact \
        || fail 'backgrounding retired the live Android peer connection'
    timeout --signal=TERM --kill-after=2s 60s \
        "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" >/dev/null \
        || fail 'cannot resume the backgrounded Android peer Activity'
    wait_resumed_activity || fail 'backgrounded Android peer Activity did not resume'
    [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = "$pid_before" ] \
        || fail 'resuming replaced the MainService process'
    capture_peer_freshness background-resume
    wait_peer_server_connections 1 exact \
        || fail 'background resume duplicated or retired the Android peer connection'
    PEER_BACKGROUND_RECOVERY_MS=$PEER_LAST_RECOVERY_MS
}

readonly API="$(adb_shell_value getprop ro.build.version.sdk)"
readonly ABI="$(adb_shell_value getprop ro.product.cpu.abi)"
readonly SELINUX="$(adb_shell_value getenforce)"
[ "$API" = 34 ] || fail "booted Android API differs: $API"
[ "$ABI" = x86_64 ] || fail "booted Android ABI differs: $ABI"
[ "$SELINUX" = Enforcing ] || fail "booted Android SELinux mode differs: $SELINUX"

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
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ] \
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

    if [ "$WORKLOAD" = app-lifecycle ] || [ "$WORKLOAD" = app-peer-lifecycle ]; then
        share_command=
        for _ in $(seq 1 3); do
            tap_ui text 'Share screen' \
                || { print_initial_ui_semantics; fail 'cannot select the production Share screen page'; }
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
        service_warning_accepted=0
        for service_start_attempt in $(seq 1 3); do
            warning_title="$(wait_ui_center text 'Warning' 2>/dev/null || true)"
            if [[ "$warning_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                capture_ui_hierarchy complete \
                    || fail 'cannot inspect the production service-start warning'
                warning_content="$(ui_center text \
                    "$SERVICE_START_WARNING_TEXT" 2>/dev/null || true)"
                [[ "$warning_content" =~ ^[0-9]+\ [0-9]+$ ]] \
                    || { print_initial_ui_semantics; fail 'the production service-start warning text differs'; }
                tap_ui text 'OK' \
                    || { print_initial_ui_semantics; fail 'cannot accept the production service-start warning'; }
                service_warning_accepted=1
                break
            fi
            [ "$service_start_attempt" -lt 3 ] || break
            share_command="$(wait_ui_center text 'Start screen sharing' 2>/dev/null || true)"
            [[ "$share_command" =~ ^[0-9]+\ [0-9]+$ ]] || break
            read -r share_x share_y <<<"$share_command"
            timeout --signal=TERM --kill-after=2s 10s \
                "$ADB" -s "$SERIAL" shell input tap "$share_x" "$share_y" \
                >/dev/null \
                || fail 'cannot retry the production screen-sharing command'
        done
        [ "$service_warning_accepted" -eq 1 ] \
            || { capture_ui_hierarchy complete && print_initial_ui_semantics; fail 'cannot observe the production service-start warning'; }
        wait_ui_center text 'Set password' >/dev/null \
            || { print_initial_ui_semantics; fail 'the production permanent-password dialog did not open'; }
        capture_ui_hierarchy \
            || fail 'cannot inspect the permanent-password dialog'
        password_field="$(ui_center focused-password-field 2>/dev/null || true)"
        [[ "$password_field" =~ ^[0-9]+\ [0-9]+$ ]] \
            || { print_initial_ui_semantics; fail 'the permanent-password dialog has no exact focused password field'; }
        readonly TEST_PASSWORD=Runtime1x
        read -r field_x field_y <<<"$password_field"
        "$ADB" -s "$SERIAL" shell input tap "$field_x" "$field_y" >/dev/null \
            || fail 'cannot focus the password field'
        "$ADB" -s "$SERIAL" shell input text "$TEST_PASSWORD" >/dev/null \
            || fail 'cannot enter the disposable password'
        wait_ui_center text '119 characters remaining' >/dev/null \
            || fail 'the password field did not observe the exact disposable input'
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null \
            || fail 'cannot dismiss the disposable soft keyboard'
        confirmation_counter=
        for attempt in $(seq 1 5); do
            if capture_ui_hierarchy; then
                confirmation_counter="$(ui_center text \
                    '128 characters remaining' 2>/dev/null || true)"
                if [[ "$confirmation_counter" =~ ^[0-9]+\ [0-9]+$ ]]; then
                    break
                fi
            fi
            [ "$attempt" -lt 5 ] || break
            timeout --signal=TERM --kill-after=2s 10s \
                "$ADB" -s "$SERIAL" shell input swipe 240 270 240 120 300 \
                >/dev/null || fail 'cannot scroll the permanent-password dialog'
            sleep 0.5
        done
        if ! [[ "$confirmation_counter" =~ ^[0-9]+\ [0-9]+$ ]]; then
            ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
                || fail 'the Android accessibility hierarchy exposed the password'
            print_initial_ui_semantics
            fail 'the exact untouched password-confirmation field did not enter view'
        fi
        capture_ui_hierarchy \
            || fail 'cannot inspect the visible password-confirmation field'
        mapfile -t password_fields < <(ui_center password-fields 2>/dev/null || true)
        [ "${#password_fields[@]}" -ge 1 ] \
            && [ "${#password_fields[@]}" -le 2 ] \
            || fail 'the scrolled password dialog exposes ambiguous exact fields'
        confirmation_index=$((${#password_fields[@]} - 1))
        read -r field_x field_y <<<"${password_fields[$confirmation_index]}"
        "$ADB" -s "$SERIAL" shell input tap "$field_x" "$field_y" >/dev/null \
            || fail 'cannot focus the visible password-confirmation field'
        "$ADB" -s "$SERIAL" shell input text "$TEST_PASSWORD" >/dev/null \
            || fail 'cannot enter the disposable password confirmation'
        "$ADB" -s "$SERIAL" shell input keyevent KEYCODE_BACK >/dev/null \
            || fail 'cannot dismiss the disposable soft keyboard'
        capture_ui_hierarchy \
            || fail 'cannot inspect the completed permanent-password dialog'
        ! grep -Fq "$TEST_PASSWORD" "$UI_XML" \
            || fail 'the Android accessibility hierarchy exposed the password'
        password_ok="$(ui_center text 'OK' 2>/dev/null || true)"
        [[ "$password_ok" =~ ^[0-9]+\ [0-9]+$ ]] \
            || fail 'the completed permanent-password dialog has no exact OK action'
        read -r ok_x ok_y <<<"$password_ok"
        "$ADB" -s "$SERIAL" shell input tap "$ok_x" "$ok_y" >/dev/null \
            || fail 'cannot submit the disposable permanent password'
        tap_ui resource android:id/button1 \
            || {
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
        [ "$(printf '%s\n' "$lifecycle_log" \
            | grep -cF 'MainService onCreate' || true)" -eq 1 ] \
            || fail 'MainService was not created exactly once'
        [ "$(printf '%s\n' "$lifecycle_log" \
            | grep -cF 'this service:' || true)" -eq 1 ] \
            || fail 'MainService was not started exactly once'
        ! grep -Eq 'FATAL EXCEPTION|Failed to resume Android client session ownership|MainService destruction retained incomplete generation authority' \
            <<<"$lifecycle_log" \
            || fail 'the initial lifecycle log contains a fatal ownership failure'

        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            tap_ui text 'Connection' \
                || fail 'cannot return to the production Connection page'
            open_peer_connection initial 1 \
                || { capture_ui_hierarchy complete && print_initial_ui_semantics; fail 'the initial authenticated Android peer connection failed'; }
            PEER_INITIAL_RECOVERY_MS=$PEER_LAST_RECOVERY_MS
            exercise_peer_background_resume "$APP_PID"
        fi

        for lifecycle_cycle in 1 2; do
            task_id="$(current_app_task_id 2>/dev/null || true)"
            [[ "$task_id" =~ ^[1-9][0-9]*$ ]] \
                || fail "cannot bind lifecycle task $lifecycle_cycle"
            swipe_app_task_from_recents "$task_id" \
                || fail "cannot swipe lifecycle task $lifecycle_cycle from Recents"
            task_removed=0
            for _ in $(seq 1 120); do
                if ! current_app_task_id >/dev/null 2>&1; then
                    task_removed=1
                    break
                fi
                sleep 0.25
            done
            [ "$task_removed" -eq 1 ] \
                || {
                    capture_ui_hierarchy && print_initial_ui_semantics
                    fail "lifecycle task $lifecycle_cycle survived the Recents swipe"
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
            [ "$(printf '%s\n' "$lifecycle_log" \
                | grep -cF 'MainService onCreate' || true)" -eq 1 ] \
                || fail "relaunch $lifecycle_cycle duplicated MainService"
            [ "$(printf '%s\n' "$lifecycle_log" \
                | grep -cF 'this service:' || true)" -eq 1 ] \
                || fail "relaunch $lifecycle_cycle restarted MainService"
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
        ! grep -Eq 'FATAL EXCEPTION' <<<"$lifecycle_log" \
            || fail 'the completed lifecycle logged a fatal exception'
        if [ "$WORKLOAD" = app-peer-lifecycle ]; then
            retired_session_events="$(printf '%s\n' "$lifecycle_log" \
                | grep -Ec 'Retired [1-9][0-9]* outgoing client peer session\(s\)' || true)"
            [ "$retired_session_events" -eq 2 ] \
                || fail 'the two removed tasks did not report exact outgoing-session retirement'
            [ "$PEER_INITIAL_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_BACKGROUND_RECOVERY_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_TASK_RECOVERY_MAX_MS" -le "$PEER_RECOVERY_LIMIT_MS" ] \
                && [ "$PEER_FRESHNESS_MAX_MS" -le "$PEER_FRESHNESS_LIMIT_MS" ] \
                && [ "$PEER_DISTINCT_FRAMES" -ge 8 ] \
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
fi

stop_emulator || fail 'Android emulator or adb did not stop within the bounded teardown'
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
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ] \
   || [ "$WORKLOAD" = app-peer-lifecycle ]; then
    [ "$(sha256sum "$RUNTIME_TEST_APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
        || fail 'runtime-test APK changed during emulator execution'
    printf 'ANDROID_EMULATOR_APP=pass emulator=%s api=%s abi=%s package=com.carriez.flutter_hbb activity=MainActivity launch_wait=%s state=resumed process=stable-five-seconds apk_sha256=%s signing=test-only acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$LAUNCH_WAIT_STATUS" "$APK_SHA256" \
        "$framebuffer_dimensions" "$SELINUX"
    if [ "$WORKLOAD" = app-lifecycle ] || [ "$WORKLOAD" = app-peer-lifecycle ]; then
        [ "$LIFECYCLE_RECEIPT_READY" -eq 1 ] \
            || fail 'the Android lifecycle receipt is not ready'
        framework_anr=absent
        if [ -f "$FRAMEWORK_ANR_MARKER" ] && [ ! -L "$FRAMEWORK_ANR_MARKER" ]; then
            [ "$(stat -c '%u:%g:%a:%h' -- "$FRAMEWORK_ANR_MARKER")" = \
              1000:1000:600:1 ] \
                || fail 'the Android framework ANR marker metadata differs'
            framework_anr_count="$(wc -l <"$FRAMEWORK_ANR_MARKER")"
            [[ "$framework_anr_count" =~ ^([1-9]|1[0-2])$ ]] \
                || fail 'the Android framework ANR wait count is malformed'
            framework_anr=waited-$framework_anr_count
        fi
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
            [ "$PEER_REVERSE_READY" -eq 0 ] \
                || fail 'the Android peer reverse mapping remained live at receipt time'
            printf 'ANDROID_EMULATOR_PEER_LIFECYCLE=pass auth=cpace server=production address=127.0.0.1:22118 transport=adb-reverse-loopback service=foreground-preserved process=same-across-task-removal task_removals=2 old_sessions=closed replacements=2 initial_recovery_ms=%s background_recovery_ms=%s task_recovery_max_ms=%s recovery_limit_ms=%s freshness_max_ms=%s freshness_limit_ms=%s distinct_frames=%s force_stop=baseline apk_sha256=%s vm_network=none container_network=none server_listener=127.0.0.1:21118 reverse_cleanup=removed x11=unix-only cleanup=joined\n' \
                "$PEER_INITIAL_RECOVERY_MS" "$PEER_BACKGROUND_RECOVERY_MS" "$PEER_TASK_RECOVERY_MAX_MS" \
                "$PEER_RECOVERY_LIMIT_MS" \
                "$PEER_FRESHNESS_MAX_MS" "$PEER_FRESHNESS_LIMIT_MS" \
                "$PEER_DISTINCT_FRAMES" "$APK_SHA256"
        fi
    fi
else
    printf 'ANDROID_EMULATOR_BOOT=pass emulator=%s api=%s abi=%s acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$framebuffer_dimensions" "$SELINUX"
fi

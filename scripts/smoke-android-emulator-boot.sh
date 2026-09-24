#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'Android emulator boot smoke: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || [ "$#" -eq 5 ] || [ "$#" -eq 6 ] \
    || fail 'usage: smoke-android-emulator-boot.sh EMULATOR_ZIP SYSTEM_IMAGE_ZIP ADB WORK_ROOT [RUNTIME_TEST_APK [lifecycle]]'
readonly EMULATOR_ZIP=$1
readonly SYSTEM_IMAGE_ZIP=$2
readonly INPUT_ADB=$3
readonly WORK_ROOT=$4
readonly RUNTIME_TEST_APK=${5:-}
readonly APP_SCENARIO=${6:-launch}
if [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = lifecycle ]; then
    readonly WORKLOAD=app-lifecycle
elif [ -n "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=app
elif [ -z "$RUNTIME_TEST_APK" ] && [ "$APP_SCENARIO" = launch ]; then
    readonly WORKLOAD=boot
else
    fail 'the Android app scenario differs from launch or lifecycle'
fi
readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly RUN_UID="$(id -u)"
readonly RUN_GID="$(id -g)"
[ "$RUN_UID:$RUN_GID" = 1000:1000 ] \
    || fail 'the emulator workload requires numeric uid/gid 1000:1000'
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ]; then
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
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ]; then
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
    stop_emulator || cleanup_status=1
    if [ "$status" -ne 0 ]; then
        tail -n 160 "$EMULATOR_LOG" >&2 2>/dev/null || true
        tail -n 80 "$ADB_LOG" >&2 2>/dev/null || true
    fi
    [ "$cleanup_status" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
readonly UI_XML=$WORK_ROOT/window.xml
readonly FRAMEWORK_ANR_MARKER=$WORK_ROOT/framework-anr.waited

capture_ui_hierarchy() {
    rm -f -- "$UI_XML"
    timeout --signal=TERM --kill-after=2s 20s \
        "$ADB" -s "$SERIAL" shell uiautomator dump --compressed \
        /data/local/tmp/rustdesk-window.xml >/dev/null \
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
if kind != "field" and not wanted:
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
    elif kind == "field":
        matched = attributes.get("class") == "android.widget.EditText"
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
if kind != "field" and len(centers) != 1:
    raise SystemExit(1)
if kind == "field" and len(centers) != 2:
    raise SystemExit(1)
for x, y in sorted(centers, key=lambda point: (point[1], point[0])):
    print(f"{x} {y}")
PY
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

wait_ui_center() {
    local kind=$1
    shift
    local center= anr_title= anr_wait= anr_x= anr_y=
    for _ in $(seq 1 12); do
        if capture_ui_hierarchy; then
            anr_title="$(ui_center text "System UI isn't responding" \
                "Process system isn't responding" 2>/dev/null || true)"
            if [[ "$anr_title" =~ ^[0-9]+\ [0-9]+$ ]]; then
                anr_wait="$(ui_center resource android:id/aerr_wait 2>/dev/null || true)"
                [[ "$anr_wait" =~ ^[0-9]+\ [0-9]+$ ]] || return 1
                printf 'waited\n' >>"$FRAMEWORK_ANR_MARKER"
                [ "$(wc -l <"$FRAMEWORK_ANR_MARKER")" -le 3 ] || return 1
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

readonly API="$(adb_shell_value getprop ro.build.version.sdk)"
readonly ABI="$(adb_shell_value getprop ro.product.cpu.abi)"
readonly SELINUX="$(adb_shell_value getenforce)"
[ "$API" = 34 ] || fail "booted Android API differs: $API"
[ "$ABI" = x86_64 ] || fail "booted Android ABI differs: $ABI"
[ "$SELINUX" = Enforcing ] || fail "booted Android SELinux mode differs: $SELINUX"

APP_PID=
LIFECYCLE_RECEIPT_READY=0
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ]; then
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
    if [ "$WORKLOAD" = app-lifecycle ]; then
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

    if [ "$WORKLOAD" = app-lifecycle ]; then
        tap_ui text 'Share screen' \
            || { print_initial_ui_semantics; fail 'cannot select the production Share screen page'; }
        tap_ui text 'Start screen sharing' \
            || { print_initial_ui_semantics; fail 'cannot invoke the production screen-sharing command'; }
        tap_ui text 'OK' \
            || { print_initial_ui_semantics; fail 'cannot accept the production service-start warning'; }
        wait_ui_center text 'Set password' >/dev/null \
            || { print_initial_ui_semantics; fail 'the production permanent-password dialog did not open'; }
        capture_ui_hierarchy \
            || fail 'cannot inspect the permanent-password dialog'
        mapfile -t password_fields < <(ui_center field 2>/dev/null || true)
        [ "${#password_fields[@]}" -eq 2 ] \
            || { print_initial_ui_semantics; fail 'the permanent-password dialog does not expose two exact fields'; }
        readonly TEST_PASSWORD=Runtime1x
        read -r field_x field_y <<<"${password_fields[0]}"
        "$ADB" -s "$SERIAL" shell input tap "$field_x" "$field_y" >/dev/null \
            || fail 'cannot focus the password field'
        "$ADB" -s "$SERIAL" shell input text "$TEST_PASSWORD" >/dev/null \
            || fail 'cannot enter the disposable password'
        read -r field_x field_y <<<"${password_fields[1]}"
        "$ADB" -s "$SERIAL" shell input tap "$field_x" "$field_y" >/dev/null \
            || fail 'cannot focus the password-confirmation field'
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
            || fail 'cannot grant the production MediaProjection consent'
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

        for lifecycle_cycle in 1 2; do
            task_id="$(current_app_task_id 2>/dev/null || true)"
            [[ "$task_id" =~ ^[1-9][0-9]*$ ]] \
                || fail "cannot bind lifecycle task $lifecycle_cycle"
            timeout --signal=TERM --kill-after=2s 10s \
                "$ADB" -s "$SERIAL" shell am task remove "$task_id" >/dev/null \
                || fail "cannot remove lifecycle task $lifecycle_cycle"
            task_removed=0
            for _ in $(seq 1 120); do
                if ! current_app_task_id >/dev/null 2>&1; then
                    task_removed=1
                    break
                fi
                sleep 0.25
            done
            [ "$task_removed" -eq 1 ] \
                || fail "lifecycle task $lifecycle_cycle survived exact removal"
            [ "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" = \
              "$APP_PID" ] \
                || fail "task removal $lifecycle_cycle killed or replaced the service process"
            assert_main_service \
                || fail "task removal $lifecycle_cycle did not preserve MainService"
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

stop_emulator || fail 'Android emulator or adb did not stop within the bounded teardown'
[ -z "$(find /proc -maxdepth 2 -path '*/comm' -readable -exec \
    awk '$0 == "qemu-system-x86" { print FILENAME }' {} + 2>/dev/null)" ] \
    || fail 'an Android emulator process survived bounded teardown'
if [ "$WORKLOAD" = app ] || [ "$WORKLOAD" = app-lifecycle ]; then
    [ "$(sha256sum "$RUNTIME_TEST_APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
        || fail 'runtime-test APK changed during emulator execution'
    printf 'ANDROID_EMULATOR_APP=pass emulator=%s api=%s abi=%s package=com.carriez.flutter_hbb activity=MainActivity launch_wait=%s state=resumed process=stable-five-seconds apk_sha256=%s signing=test-only acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$LAUNCH_WAIT_STATUS" "$APK_SHA256" \
        "$framebuffer_dimensions" "$SELINUX"
    if [ "$WORKLOAD" = app-lifecycle ]; then
        [ "$LIFECYCLE_RECEIPT_READY" -eq 1 ] \
            || fail 'the Android lifecycle receipt is not ready'
        framework_anr=absent
        if [ -f "$FRAMEWORK_ANR_MARKER" ] && [ ! -L "$FRAMEWORK_ANR_MARKER" ]; then
            [ "$(stat -c '%u:%g:%a:%h' -- "$FRAMEWORK_ANR_MARKER")" = \
              1000:1000:600:1 ] \
                || fail 'the Android framework ANR marker metadata differs'
            framework_anr_count="$(wc -l <"$FRAMEWORK_ANR_MARKER")"
            [[ "$framework_anr_count" =~ ^[1-3]$ ]] \
                || fail 'the Android framework ANR wait count is malformed'
            framework_anr=waited-$framework_anr_count
        fi
        printf 'ANDROID_EMULATOR_LIFECYCLE=pass task_removals=2 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=%s apk_sha256=%s vm_network=none container_network=none cleanup=joined\n' \
            "$framework_anr" "$APK_SHA256"
    fi
else
    printf 'ANDROID_EMULATOR_BOOT=pass emulator=%s api=%s abi=%s acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$framebuffer_dimensions" "$SELINUX"
fi

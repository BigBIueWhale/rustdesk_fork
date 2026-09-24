#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'Android emulator boot smoke: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || [ "$#" -eq 5 ] \
    || fail 'usage: smoke-android-emulator-boot.sh EMULATOR_ZIP SYSTEM_IMAGE_ZIP ADB WORK_ROOT [RUNTIME_TEST_APK]'
readonly EMULATOR_ZIP=$1
readonly SYSTEM_IMAGE_ZIP=$2
readonly INPUT_ADB=$3
readonly WORK_ROOT=$4
readonly RUNTIME_TEST_APK=${5:-}
if [ -n "$RUNTIME_TEST_APK" ]; then
    readonly WORKLOAD=app
else
    readonly WORKLOAD=boot
fi
readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly RUN_UID="$(id -u)"
readonly RUN_GID="$(id -g)"
[ "$RUN_UID:$RUN_GID" = 1000:1000 ] \
    || fail 'the emulator workload requires numeric uid/gid 1000:1000'
if [ "$WORKLOAD" = app ]; then
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
if [ "$WORKLOAD" = app ]; then
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

readonly API="$(adb_shell_value getprop ro.build.version.sdk)"
readonly ABI="$(adb_shell_value getprop ro.product.cpu.abi)"
readonly SELINUX="$(adb_shell_value getenforce)"
[ "$API" = 34 ] || fail "booted Android API differs: $API"
[ "$ABI" = x86_64 ] || fail "booted Android ABI differs: $ABI"
[ "$SELINUX" = Enforcing ] || fail "booted Android SELinux mode differs: $SELINUX"

APP_PID=
if [ "$WORKLOAD" = app ]; then
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
    "$ADB" -s "$SERIAL" logcat -c \
        || fail 'cannot clear the runtime-test log before launch'
    launch_output="$(timeout --signal=TERM --kill-after=2s 60s \
        "$ADB" -s "$SERIAL" shell am start -W \
        -n com.carriez.flutter_hbb/.MainActivity | tr -d '\r')" \
        || fail 'runtime-test activity launch failed'
    [ "${#launch_output}" -le 16384 ] \
        || fail 'runtime-test activity launch receipt exceeds its bound'
    printf '%s\n' "$launch_output" | grep -qFx 'Status: ok' \
        || fail "runtime-test activity did not report a successful launch: $launch_output"
    printf '%s\n' "$launch_output" \
        | grep -qFx 'Activity: com.carriez.flutter_hbb/.MainActivity' \
        || fail "runtime-test launch resolved to a different activity: $launch_output"
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
    activity_state="$(adb_shell_value dumpsys activity activities)"
    printf '%s\n' "$activity_state" \
        | grep -Eq 'mResumedActivity:.*com\.carriez\.flutter_hbb/\.MainActivity|topResumedActivity=.*com\.carriez\.flutter_hbb/\.MainActivity' \
        || fail 'runtime-test MainActivity is not the resumed activity'
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
if [ "$WORKLOAD" = app ]; then
    [ "$(sha256sum "$RUNTIME_TEST_APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
        || fail 'runtime-test APK changed during emulator execution'
    printf 'ANDROID_EMULATOR_APP=pass emulator=%s api=%s abi=%s package=com.carriez.flutter_hbb activity=MainActivity state=resumed process=stable-five-seconds apk_sha256=%s signing=test-only acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$APK_SHA256" \
        "$framebuffer_dimensions" "$SELINUX"
else
    printf 'ANDROID_EMULATOR_BOOT=pass emulator=%s api=%s abi=%s acceleration=software framebuffer=%s selinux=%s vm_network=none container_network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_VERSION" "$API" "$ABI" "$framebuffer_dimensions" "$SELINUX"
fi

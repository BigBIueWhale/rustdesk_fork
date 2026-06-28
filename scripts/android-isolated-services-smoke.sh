#!/usr/bin/env bash
#
# Device/emulator smoke for the Android hostile-peer native parser boundary.
# It installs a caller-supplied app APK and its matching androidTest APK, then
# runs the test APK's Instrumentation runner. The runner binds the app's four
# non-exported isolatedProcess services and requires each native self-test to
# pass from inside the isolated service process.
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  echo "FAIL: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  APP_APK=/path/to/app.apk TEST_APK=/path/to/app-androidTest.apk \
    scripts/android-isolated-services-smoke.sh

Optional:
  ADB=/path/to/adb
  ANDROID_SERIAL=device-serial
  INSTALL_APKS=0      # skip adb install, run instrumentation against already-installed APKs

The app APK and androidTest APK must be built from the same source and signed
compatibly for instrumentation. This script does not build them.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

ADB=${ADB:-"$PWD/online/android-sdk/platform-tools/adb"}
[ -x "$ADB" ] || die "adb not found or not executable at $ADB; set ADB=..."

adb_cmd=("$ADB")
if [ -n "${ANDROID_SERIAL:-}" ]; then
  adb_cmd+=("-s" "$ANDROID_SERIAL")
fi

app_package=com.carriez.flutter_hbb
test_package=com.carriez.flutter_hbb.test
runner=com.carriez.flutter_hbb.NativeIsolatedServicesSmokeInstrumentation
component="$test_package/$runner"

"${adb_cmd[@]}" wait-for-device >/dev/null

api_level=$("${adb_cmd[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
case "$api_level" in
  ''|*[!0-9]*) die "could not read numeric Android API level from device: '$api_level'" ;;
esac
[ "$api_level" -ge 27 ] || die "Android API $api_level lacks SharedMemory; run this smoke on API 27+"

if [ "${INSTALL_APKS:-1}" != "0" ]; then
  [ -n "${APP_APK:-}" ] || { usage; die "APP_APK is required unless INSTALL_APKS=0"; }
  [ -n "${TEST_APK:-}" ] || { usage; die "TEST_APK is required unless INSTALL_APKS=0"; }
  [ -f "$APP_APK" ] || die "APP_APK does not exist: $APP_APK"
  [ -f "$TEST_APK" ] || die "TEST_APK does not exist: $TEST_APK"
  "${adb_cmd[@]}" install -r "$APP_APK"
  "${adb_cmd[@]}" install -r "$TEST_APK"
fi

output=$("${adb_cmd[@]}" shell am instrument -w -r "$component" 2>&1) || {
  printf '%s\n' "$output"
  die "am instrument failed for $component"
}
printf '%s\n' "$output"

printf '%s\n' "$output" | grep -q 'INSTRUMENTATION_CODE: -1' ||
  die "isolated-service smoke failed for $app_package; expected INSTRUMENTATION_CODE: -1"

echo "ok: Android isolated native services smoke passed for $app_package"

#!/usr/bin/env bash
# scripts/apple-conform-check.sh - R-R2 Apple (macOS/iOS) source-conformance gate.
#
# Apple is not an artifact target on this Linux build host, but the macOS/iOS
# source must still inherit the fork's security posture. This gate proves the
# source layer with:
#   1. retain-and-check over the Apple source, plist, entitlement, pod, and Xcode
#      project surfaces;
#   2. R-A6 Apple-cfg forbidden-token and sole-backend assertions;
#   3. structured metadata allow-lists for Info.plist, entitlements, Podfile.lock,
#      and PBXShellScriptBuildPhase shell scripts;
#   4. Rust parse checks plus cargo cross-checks for the documented default matrix:
#        aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios
#      using the real Apple features: macOS = flutter,unix-file-copy-paste;
#      iOS = flutter.
#
# Override the matrix only for focused diagnosis:
#   APPLE_TARGETS="x86_64-apple-darwin aarch64-apple-ios" scripts/apple-conform-check.sh
# Legacy APPLE_TARGET=<target> is accepted as a single-target override, but the
# default remains the full R-R2 target matrix.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

BASE_IMG=rd-devcheck
IMG=rd-apple-check
SDK_DIR="${MACOS_SDK_DIR:-$REPO/online/macos-sdk}"
DEFAULT_APPLE_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios)

die(){ echo "FATAL: $*" >&2; exit 1; }
note(){ echo "  $*"; }
rc=0

if [ -n "${APPLE_TARGETS:-}" ]; then
  targets_raw="${APPLE_TARGETS//,/ }"
  read -r -a SELECTED_APPLE_TARGETS <<< "$targets_raw"
elif [ -n "${APPLE_TARGET:-}" ]; then
  SELECTED_APPLE_TARGETS=("$APPLE_TARGET")
else
  SELECTED_APPLE_TARGETS=("${DEFAULT_APPLE_TARGETS[@]}")
fi

valid_apple_target(){
  case "$1" in
    aarch64-apple-darwin|x86_64-apple-darwin|aarch64-apple-ios) return 0 ;;
    *) return 1 ;;
  esac
}
target_features(){
  case "$1" in
    *-apple-ios) echo "flutter" ;;
    *-apple-darwin) echo "flutter,unix-file-copy-paste" ;;
    *) die "unsupported Apple target: $1" ;;
  esac
}
target_triplet(){
  case "$1" in
    aarch64-apple-ios) echo "arm64-ios" ;;
    aarch64-apple-darwin) echo "arm64-osx" ;;
    x86_64-apple-darwin) echo "x64-osx" ;;
    *) die "unsupported Apple target: $1" ;;
  esac
}
target_env_lower(){ echo "$1" | tr '-' '_'; }
target_env_upper(){ echo "$1" | tr '[:lower:]-' '[:upper:]_'; }
version_hash(){
  if [ -e "$REPO/src/version.rs" ]; then
    sha256sum "$REPO/src/version.rs" | awk '{print $1}'
  else
    echo "__MISSING__"
  fi
}

for t in "${SELECTED_APPLE_TARGETS[@]}"; do
  valid_apple_target "$t" || die "unsupported APPLE_TARGETS entry '$t'"
done

# ---- preflight ----
command -v docker >/dev/null 2>&1 || die "docker not found - this gate runs entirely in containers"
[ -f "$REPO/scripts/apple-cc-shim.sh" ] || die "scripts/apple-cc-shim.sh missing"
[ -f "$REPO/scripts/Dockerfile.devcheck" ] || die "scripts/Dockerfile.devcheck missing"
[ -f "$REPO/scripts/Dockerfile.apple-check" ] || die "scripts/Dockerfile.apple-check missing"

echo "== building the apple-check image (devcheck base + Rust 1.81 + Apple std targets) =="
docker build -q -t "$BASE_IMG" -f scripts/Dockerfile.devcheck scripts >/dev/null \
  || die "could not build $BASE_IMG from scripts/Dockerfile.devcheck"
docker build -q -t "$IMG" -f scripts/Dockerfile.apple-check scripts >/dev/null \
  || die "could not build $IMG from scripts/Dockerfile.apple-check"

# ---- Apple source set (R-R2 retain-and-check) ----
APPLE_RS=(
  src/platform/macos.rs
  src/privacy_mode/macos.rs
  src/whiteboard/macos.rs
  libs/hbb_common/src/platform/macos.rs
  libs/enigo/src/macos/macos_impl.rs
)
APPLE_OTHER=(
  src/platform/macos.mm
  flutter/ios/Runner/Info.plist
  flutter/ios/Runner/Runner.entitlements
  flutter/ios/Podfile.lock
  flutter/ios/Runner.xcodeproj/project.pbxproj
  flutter/macos/Runner/Info.plist
  flutter/macos/Runner/Release.entitlements
  flutter/macos/Runner/DebugProfile.entitlements
  flutter/macos/Podfile.lock
  flutter/macos/Runner.xcodeproj/project.pbxproj
)
GREP_SRC=("${APPLE_RS[@]/#/$REPO/}" "$REPO/src/platform/macos.mm")

echo "== (1) retain-and-check: hardened Apple sources and metadata must be present (R-R2/R-A6) =="
for f in "${APPLE_RS[@]}" "${APPLE_OTHER[@]}"; do
  [ -e "$REPO/$f" ] || {
    echo "  MISSING $f - R-R2 is retain-and-check; deleting Apple source drops hardening a future Apple build must inherit"
    rc=1
  }
done
[ "$rc" = 0 ] && note "ok  all ${#APPLE_RS[@]} Rust + ${#APPLE_OTHER[@]} metadata/source files present"

echo "== (2) R-A6 Apple-cfg forbidden-token greps =="
apple_absent(){
  local hits
  hits=$(grep -rnE "$1" "${GREP_SRC[@]}" 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL $2 - Apple-cfg token present:"
    echo "$hits" | sed 's/^/      /'
    rc=1
  else
    note "ok  $2 - absent on the Apple source"
  fi
}

apple_absent 'fn update_me\b|update_from_dmg|extract_update_dmg|fn update_to\b' \
  'R-X1 macOS DMG self-updater'
apple_absent 'fn elevate\b|bool Elevate\b|AuthorizationExecuteWithPrivileges' \
  'R-X9/X11 in-process root-exec (osascript elevate / Authorization Elevate)'
apple_absent 'libpam|pam_authenticate|\bpam::' \
  'R-X14 PAM (absent-by-construction on Apple)'

echo "== (2b) R-X12/R-X13 macOS sole-backend assertions =="
if grep -qE 'pub mod quartz' "$REPO/libs/scrap/src/lib.rs"; then
  note "ok  R-X12 macOS capture = quartz/CGDisplayStream present (sole backend)"
else
  echo "  FAIL R-X12: macOS quartz capture backend is missing from libs/scrap/src/lib.rs"
  rc=1
fi
if grep -qE 'CGEventPost' "$REPO/libs/enigo/src/macos/macos_impl.rs"; then
  note "ok  R-X13 macOS input = CGEvent present (sole injector)"
else
  echo "  FAIL R-X13: macOS CGEvent injector is missing from libs/enigo/src/macos/macos_impl.rs"
  rc=1
fi

# (2c) Appendix C #2b is an ACCEPTED, documented residual: the fork SHOULD (not MUST) sandbox the decode
# path. Commit 0c54912 deliberately reverted the ENTIRE native-worker decode-sandbox subsystem (the
# per-codec worker processes + the macOS Seatbelt sandbox file + the Android isolatedProcess services
# + ~1800 lines of verify.sh worker gates) as "a documented residual, not a MUST". That revert updated
# verify.sh but missed THIS macOS Seatbelt assertion, leaving apple-conform-check failing on a
# deliberately-absent file. Removed to match: the macOS worker sandbox is intentionally gone (the
# universal #2b residual), so the Apple source carries no worker hardening to retain. (Re-closing #2b
# later restores the subsystem on ALL platforms, not Apple alone — this is not a presence-of-absence pin.)
echo "== (2c) Appendix C #2b native-worker decode sandbox: accepted residual (reverted 0c54912) — no macOS worker hardening to assert =="

echo "== (2d) Apple metadata allow-lists: plist/entitlements/pods/Xcode shell phases =="
docker run --rm -i -v "$REPO:/work:ro" -w /work "$IMG" python3 - <<'PY' || rc=1
from pathlib import Path
import ast
import plistlib
import re
import sys
import xml.etree.ElementTree as ET

FAIL = []

def fail(msg):
    FAIL.append(msg)

def duplicate_plist_keys(path):
    root = ET.fromstring(Path(path).read_bytes())

    def walk(elem, where):
        children = list(elem)
        if elem.tag == "dict":
            seen = set()
            i = 0
            while i < len(children):
                child = children[i]
                if child.tag == "key":
                    key = child.text or ""
                    if key in seen:
                        fail(f"{path}: duplicate plist key {key!r} at {where}")
                    seen.add(key)
                    if i + 1 < len(children):
                        walk(children[i + 1], f"{where}.{key}")
                    i += 2
                else:
                    walk(child, where)
                    i += 1
        else:
            for child in children:
                walk(child, where)

    walk(root, path)

def load_plist(path):
    duplicate_plist_keys(path)
    with open(path, "rb") as fh:
        return plistlib.load(fh)

def assert_keys(path, expected):
    got = load_plist(path)
    actual = set(got.keys())
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        fail(f"{path}: plist key allow-list mismatch; missing={missing} extra={extra}")
    for forbidden in ("com.apple.developer.associated-domains", "associated-domains",
                      "NSUserActivityTypes", "aps-environment",
                      "com.apple.developer.networking.wifi-info"):
        if forbidden in actual:
            fail(f"{path}: forbidden Apple capability/deep-link key present: {forbidden}")
    return got

IOS_INFO_KEYS = {
    "CADisableMinimumFrameDurationOnPhone",
    "CFBundleDevelopmentRegion",
    "CFBundleDisplayName",
    "CFBundleExecutable",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleSignature",
    "CFBundleURLTypes",
    "CFBundleVersion",
    "ITSAppUsesNonExemptEncryption",
    "LSRequiresIPhoneOS",
    "NSCameraUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "UIApplicationSupportsIndirectInputEvents",
    "UIFileSharingEnabled",
    "UILaunchStoryboardName",
    "UIMainStoryboardFile",
    "UISupportedInterfaceOrientations",
    "UISupportedInterfaceOrientations~ipad",
    "UISupportsDocumentBrowser",
    "UIViewControllerBasedStatusBarAppearance",
    "io.flutter.embedded_views_preview",
}
MACOS_INFO_KEYS = {
    "CFBundleDevelopmentRegion",
    "CFBundleExecutable",
    "CFBundleIconFile",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleURLTypes",
    "CFBundleVersion",
    "LSMinimumSystemVersion",
    "LSUIElement",
    "NSHumanReadableCopyright",
    "NSMainNibFile",
    "NSMicrophoneUsageDescription",
    "NSPrincipalClass",
}

ios_info = assert_keys("flutter/ios/Runner/Info.plist", IOS_INFO_KEYS)
macos_info = assert_keys("flutter/macos/Runner/Info.plist", MACOS_INFO_KEYS)

def assert_rustdesk_scheme(path, obj):
    url_types = obj.get("CFBundleURLTypes")
    if not isinstance(url_types, list):
        fail(f"{path}: CFBundleURLTypes is not a list")
        return
    schemes = []
    for item in url_types:
        if isinstance(item, dict):
            schemes.extend(item.get("CFBundleURLSchemes", []))
    if schemes != ["rustdesk"]:
        fail(f"{path}: expected the sole URL scheme ['rustdesk'], got {schemes!r}")

assert_rustdesk_scheme("flutter/ios/Runner/Info.plist", ios_info)
assert_rustdesk_scheme("flutter/macos/Runner/Info.plist", macos_info)

if load_plist("flutter/ios/Runner/Runner.entitlements") != {}:
    fail("flutter/ios/Runner/Runner.entitlements: iOS entitlements must remain an empty dict")

EXPECTED_RELEASE_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.client": True,
}
EXPECTED_DEBUG_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.network.server": True,
}
if load_plist("flutter/macos/Runner/Release.entitlements") != EXPECTED_RELEASE_ENTITLEMENTS:
    fail("flutter/macos/Runner/Release.entitlements: entitlement allow-list/value mismatch")
if load_plist("flutter/macos/Runner/DebugProfile.entitlements") != EXPECTED_DEBUG_ENTITLEMENTS:
    fail("flutter/macos/Runner/DebugProfile.entitlements: entitlement allow-list/value mismatch")

# APPLE_POD_ALLOWLISTS: exact top-level pod + checksum allow-lists for R-SV8/R-A6.
EXPECTED_IOS_PODS = [
    "device_info_plus (0.0.1)",
    "DKImagePickerController/Core (4.3.4)",
    "DKImagePickerController/ImageDataManager (4.3.4)",
    "DKImagePickerController/PhotoGallery (4.3.4)",
    "DKImagePickerController/Resource (4.3.4)",
    "DKPhotoGallery (0.0.17)",
    "DKPhotoGallery/Core (0.0.17)",
    "DKPhotoGallery/Model (0.0.17)",
    "DKPhotoGallery/Preview (0.0.17)",
    "DKPhotoGallery/Resource (0.0.17)",
    "file_picker (0.0.1)",
    "Flutter (1.0.0)",
    "flutter_keyboard_visibility (0.0.1)",
    "image_picker_ios (0.0.1)",
    "MTBBarcodeScanner (5.0.11)",
    "package_info_plus (0.4.5)",
    "path_provider_foundation (0.0.1)",
    "qr_code_scanner (0.2.0)",
    "SDWebImage (5.18.11)",
    "SDWebImage/Core (5.18.11)",
    "sqflite (0.0.3)",
    "SwiftyGif (5.4.4)",
    "uni_links (0.0.1)",
    "url_launcher_ios (0.0.1)",
    "video_player_avfoundation (0.0.1)",
    "wakelock_plus (0.0.1)",
]
EXPECTED_IOS_CHECKSUMS = {
    "device_info_plus": "c6fb39579d0f423935b0c9ce7ee2f44b71b9fce6",
    "DKImagePickerController": "b512c28220a2b8ac7419f21c491fc8534b7601ac",
    "DKPhotoGallery": "fdfad5125a9fdda9cc57df834d49df790dbb4179",
    "file_picker": "ce3938a0df3cc1ef404671531facef740d03f920",
    "Flutter": "e0871f40cf51350855a761d2e70bf5af5b9b5de7",
    "flutter_keyboard_visibility": "0339d06371254c3eb25eeb90ba8d17dca8f9c069",
    "image_picker_ios": "99dfe1854b4fa34d0364e74a78448a0151025425",
    "MTBBarcodeScanner": "f453b33c4b7dfe545d8c6484ed744d55671788cb",
    "package_info_plus": "115f4ad11e0698c8c1c5d8a689390df880f47e85",
    "path_provider_foundation": "3784922295ac71e43754bd15e0653ccfd36a147c",
    "qr_code_scanner": "bb67d64904c3b9658ada8c402e8b4d406d5d796e",
    "SDWebImage": "a3ba0b8faac7228c3c8eadd1a55c9c9fe5e16457",
    "sqflite": "673a0e54cc04b7d6dba8d24fb8095b31c3a99eec",
    "SwiftyGif": "93a1cc87bf3a51916001cf8f3d63835fb64c819f",
    "uni_links": "d97da20c7701486ba192624d99bffaaffcfc298a",
    "url_launcher_ios": "5334b05cef931de560670eeae103fd3e431ac3fe",
    "video_player_avfoundation": "02011213dab73ae3687df27ce441fbbcc82b5579",
    "wakelock_plus": "8b09852c8876491e4b6d179e17dfe2a0b5f60d47",
}
EXPECTED_MACOS_PODS = [
    "desktop_drop (0.0.1)",
    "desktop_multi_window (0.0.1)",
    "device_info_plus (0.0.1)",
    "file_selector_macos (0.0.1)",
    "flutter_custom_cursor (0.0.1)",
    "FlutterMacOS (1.0.0)",
    "FMDB (2.7.12)",
    "FMDB/Core (2.7.12)",
    "FMDB/standard (2.7.12)",
    "package_info_plus (0.0.1)",
    "path_provider_foundation (0.0.1)",
    "screen_retriever (0.0.1)",
    "sqflite (0.0.2)",
    "texture_rgba_renderer (0.0.1)",
    "uni_links_desktop (0.0.1)",
    "url_launcher_macos (0.0.1)",
    "video_player_avfoundation (0.0.1)",
    "wakelock_plus (0.0.1)",
    "window_manager (0.2.0)",
    "window_size (0.0.2)",
]
EXPECTED_MACOS_CHECKSUMS = {
    "desktop_drop": "e0b672a7d84c0a6cbc378595e82cdb15f2970a43",
    "desktop_multi_window": "93667594ccc4b88d91a97972fd3b1b89667fa80a",
    "device_info_plus": "b0fafc687fb901e2af612763340f1b0d4352f8e5",
    "file_selector_macos": "6280b52b459ae6c590af5d78fc35c7267a3c4b31",
    "flutter_custom_cursor": "37e588711a2746f5cf48adb58b582cacff11c0c6",
    "FlutterMacOS": "8f6f14fa908a6fb3fba0cd85dbd81ec4b251fb24",
    "FMDB": "728731dd336af3936ce00f91d9d8495f5718a0e6",
    "package_info_plus": "122abb51244f66eead59ce7c9c200d6b53111779",
    "path_provider_foundation": "080d55be775b7414fd5a5ef3ac137b97b097e564",
    "screen_retriever": "4f97c103641aab8ce183fa5af3b87029df167936",
    "sqflite": "c73556b2499b92f0b6e6946abe4a4084510cdf90",
    "texture_rgba_renderer": "6661f577ea5d4990e964c7e3840e544ac798e6da",
    "uni_links_desktop": "34322c2646e4c9abc69b62e1865f9782d2850ba2",
    "url_launcher_macos": "0fba8ddabfc33ce0a9afe7c5fef5aab3d8d2d673",
    "video_player_avfoundation": "2cef49524dd1f16c5300b9cd6efd9611ce03639b",
    "wakelock_plus": "21ddc249ac4b8d018838dbdabd65c5976c308497",
    "window_manager": "1d01fa7ac65a6e6f83b965471b1a7fdd3f06166c",
    "window_size": "4bd15034e6e3d0720fd77928a7c42e5492cfece9",
}
FORBIDDEN_POD_TOKENS = ("Firebase", "Crashlytics", "Fabric", "Sentry", "AppCenter", "Sparkle")

def parse_podfile(path):
    pods = []
    checksums = {}
    section = None
    for line in Path(path).read_text().splitlines():
        if line and not line.startswith(" "):
            section = line.rstrip(":")
            continue
        if section == "PODS" and line.startswith("  - "):
            pods.append(line[4:].strip().rstrip(":"))
        elif section == "SPEC CHECKSUMS" and line.startswith("  "):
            name, value = line.strip().split(": ", 1)
            checksums[name] = value
    return pods, checksums

def assert_podfile(path, expected_pods, expected_checksums):
    pods, checksums = parse_podfile(path)
    if pods != expected_pods:
        fail(f"{path}: pod allow-list mismatch\n  expected={expected_pods!r}\n  actual={pods!r}")
    if checksums != expected_checksums:
        fail(f"{path}: SPEC CHECKSUMS allow-list mismatch")
    joined = "\n".join(pods + sorted(checksums))
    for token in FORBIDDEN_POD_TOKENS:
        if token in joined:
            fail(f"{path}: forbidden telemetry/updater pod token present: {token}")

assert_podfile("flutter/ios/Podfile.lock", EXPECTED_IOS_PODS, EXPECTED_IOS_CHECKSUMS)
assert_podfile("flutter/macos/Podfile.lock", EXPECTED_MACOS_PODS, EXPECTED_MACOS_CHECKSUMS)

# PBXShellScriptBuildPhase allow-list: exact decoded shellScript values.
COCOAPODS_MANIFEST_SCRIPT = """diff "${PODS_PODFILE_DIR_PATH}/Podfile.lock" "${PODS_ROOT}/Manifest.lock" > /dev/null
if [ $? != 0 ] ; then
    # print error to STDERR
    echo "error: The sandbox is not in sync with the Podfile.lock. Run 'pod install' or update your CocoaPods installation." >&2
    exit 1
fi
# This output is used by Xcode 'outputs' to avoid re-running this script phase.
echo "SUCCESS" > "${SCRIPT_OUTPUT_FILE_0}"
"""
EXPECTED_IOS_SCRIPTS = [
    '/bin/sh "$FLUTTER_ROOT/packages/flutter_tools/bin/xcode_backend.sh" embed_and_thin',
    '"${PODS_ROOT}/Target Support Files/Pods-Runner/Pods-Runner-frameworks.sh"\n',
    COCOAPODS_MANIFEST_SCRIPT,
    '/bin/sh "$FLUTTER_ROOT/packages/flutter_tools/bin/xcode_backend.sh" build',
]
EXPECTED_MACOS_SCRIPTS = [
    'echo "$PRODUCT_NAME.app" > "$PROJECT_DIR"/Flutter/ephemeral/.app_filename && "$FLUTTER_ROOT"/packages/flutter_tools/bin/macos_assemble.sh embed\n',
    '"$FLUTTER_ROOT"/packages/flutter_tools/bin/macos_assemble.sh && touch Flutter/ephemeral/tripwire',
    '"${PODS_ROOT}/Target Support Files/Pods-Runner/Pods-Runner-frameworks.sh"\n',
    COCOAPODS_MANIFEST_SCRIPT,
]
FORBIDDEN_SHELL_TOKENS = ("curl", "codesign", "security", "PlistBuddy", "osascript")

def decode_shell_scripts(path):
    text = Path(path).read_text()
    scripts = []
    for match in re.finditer(r'shellScript = ("(?:\\.|[^"\\])*");', text):
        scripts.append(ast.literal_eval(match.group(1)))
    return scripts

def assert_shell_scripts(path, expected):
    scripts = decode_shell_scripts(path)
    if scripts != expected:
        fail(f"{path}: PBXShellScriptBuildPhase allow-list mismatch\n  expected={expected!r}\n  actual={scripts!r}")
    for script in scripts:
        for token in FORBIDDEN_SHELL_TOKENS:
            if re.search(rf'(^|[^A-Za-z0-9_./-]){re.escape(token)}([^A-Za-z0-9_./-]|$)', script):
                fail(f"{path}: forbidden shell token {token!r} in script {script!r}")

assert_shell_scripts("flutter/ios/Runner.xcodeproj/project.pbxproj", EXPECTED_IOS_SCRIPTS)
assert_shell_scripts("flutter/macos/Runner.xcodeproj/project.pbxproj", EXPECTED_MACOS_SCRIPTS)

if FAIL:
    for item in FAIL:
        print(f"  FAIL {item}")
    sys.exit(1)
print("  ok  metadata allow-lists: plist keys, entitlements, pods, checksums, and Xcode shell phases")
PY

echo "== (3) rustfmt parse-check of Rust Apple sources (SDK-free syntax gate) =="
docker run --rm -i -v "$REPO:/work:ro" -w /work "$IMG" bash -s -- "${APPLE_RS[@]}" <<'SH' || rc=1
set -euo pipefail
rc=0
for f in "$@"; do
  if ! rustfmt --emit stdout --edition 2021 "$f" >/dev/null 2>/tmp/rfe; then
    echo "  PARSE-FAIL $f"
    sed 's/^/      /' /tmp/rfe
    rc=1
  fi
done
[ "$rc" = 0 ] && echo "  ok  all Apple .rs sources parse"
exit "$rc"
SH

echo "== (4) cross-compile coherence matrix (Rust 1.81, actual Apple features) =="
echo "  targets: ${SELECTED_APPLE_TARGETS[*]}"
before_version_hash=$(version_hash)
COMMON_CHECK=( docker run --rm
  -v "$REPO:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-apple-target:/build
  -e CARGO_TARGET_DIR=/build
  -e RUSTUP_TOOLCHAIN=1.81.0
  -e SOURCE_DATE_EPOCH=1700000000
  -e PKG_CONFIG_ALLOW_CROSS=1
  -w /work )

for target in "${SELECTED_APPLE_TARGETS[@]}"; do
  features=$(target_features "$target")
  triplet=$(target_triplet "$target")
  lower_env=$(target_env_lower "$target")
  upper_env=$(target_env_upper "$target")
  log="/tmp/apple-xcheck-$target.log"
  echo "  -- $target features=$features"

  if [ -d "$SDK_DIR" ]; then
    note "online/macos-sdk present ($SDK_DIR) -> real Apple SDK cross-check"
    set +e
    "${COMMON_CHECK[@]}" \
      -v "$SDK_DIR:/apple-sdk:ro" \
      -e SDKROOT=/apple-sdk \
      -e BINDGEN_EXTRA_CLANG_ARGS="-isysroot /apple-sdk" \
      -e "CFLAGS_$lower_env=-isysroot /apple-sdk" \
      "$IMG" bash -s -- "$target" "$features" "$triplet" <<'SH' > "$log" 2>&1
set -euo pipefail
target="$1"; features="$2"; triplet="$3"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv aom; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo +1.81.0 check --target "$target" --features "$features"
SH
    xrc=$?
    set -e
    if [ "$xrc" = 0 ]; then
      note "ok  $target real-SDK cross-check compiled clean"
    else
      echo "  FAIL $target real-SDK cross-check failed:"
      tail -40 "$log" | sed 's/^/      /'
      rc=1
    fi
  else
    note "no online/macos-sdk -> SDK-free best-effort check with scripts/apple-cc-shim.sh"
    set +e
    "${COMMON_CHECK[@]}" \
      -v "$REPO/scripts/apple-cc-shim.sh:/applecc:ro" \
      -e SDKROOT=/tmp \
      -e BINDGEN_EXTRA_CLANG_ARGS="-isysroot /tmp" \
      -e "CC_$lower_env=/applecc" \
      -e "CXX_$lower_env=/applecc" \
      -e "CFLAGS_$lower_env=-isysroot /tmp" \
      -e "CXXFLAGS_$lower_env=-isysroot /tmp" \
      -e "CARGO_TARGET_${upper_env}_LINKER=/applecc" \
      "$IMG" bash -s -- "$target" "$features" "$triplet" <<'SH' > "$log" 2>&1
set -euo pipefail
target="$1"; features="$2"; triplet="$3"
stub=/tmp/apple-vcpkg
rm -rf "$stub"
mkdir -p "$stub/installed/$triplet/include" "$stub/installed/$triplet/lib"
for d in opus vpx libyuv aom; do
  [ -d "/usr/include/$d" ] && ln -s "/usr/include/$d" "$stub/installed/$triplet/include/$d"
done
export VCPKG_ROOT="$stub"
cargo +1.81.0 check --target "$target" --features "$features"
SH
    xrc=$?
    set -e
    if [ "$xrc" = 0 ]; then
      note "ok  $target compiled clean even without Apple SDK headers"
    elif grep -qE 'error\[E[0-9]{4}\]' "$log"; then
      echo "  FAIL $target has a Rust compiler error (real Apple-cfg coherence break):"
      grep -nE 'error\[E[0-9]{4}\]' "$log" | head -25 | sed 's/^/      /'
      rc=1
    elif grep -qE 'Checking rustdesk|Compiling rustdesk|Checking hbb_common|Compiling hbb_common|Checking scrap|Compiling scrap' "$log" \
      && grep -qE "coreaudio-sys|AudioUnit|fatal error: .+ file not found|framework=|inttypes\.h|vpx/vp8\.h" "$log"; then
      note "ok  $target reached the expected Apple SDK/header boundary with no Rust error"
    else
      echo "  FAIL $target failed before the accepted SDK/header boundary:"
      tail -40 "$log" | sed 's/^/      /'
      rc=1
    fi
  fi
done

after_version_hash=$(version_hash)
if [ "$before_version_hash" != "$after_version_hash" ]; then
  echo "  FAIL non-mutating Apple gate: src/version.rs changed during cargo check"
  echo "       before=$before_version_hash after=$after_version_hash"
  rc=1
else
  note "ok  non-mutating source proof: src/version.rs hash unchanged (SOURCE_DATE_EPOCH=1700000000)"
fi

echo
if [ "$rc" = 0 ]; then
  echo "== apple-conform-check PASS =="
else
  echo "== apple-conform-check FAIL =="
fi
exit "$rc"

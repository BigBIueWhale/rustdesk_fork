#!/usr/bin/env bash
# scripts/android-apk-build.sh — the shared android build flow (R-B7).
#
# Run INSIDE the pinned android-builder container by TWO callers, so the offline build
# and the online gradle-warming stay byte-for-byte the same flow:
#   - build-android.sh  build_apk        APK_MODE=offline   (the --network=none .apk build)
#   - online-fetch.sh   stage_gradle     APK_MODE=warm      (the ONE networked gradle warm)
#   - android-rust-check.sh              APK_MODE=rust-check (the offline Android Rust gate)
#   - android-emulator-app-check.sh      APK_MODE=emulator-test (x86_64 runtime-test APK)
# It builds the Rust JNI lib (cargo-ndk) + the Flutter APK from the staged ./online cache:
# host rust + the aarch64-linux-android cross-std, the NDK, the arm64-android vcpkg natives,
# cargo-ndk, the offline cargo vendor, the offline flutter shim, the SDK, and the gradle cache.
#
# APK_MODE selects the requested Android build operation:
#   offline: project the read-only warm /online/gradle-home into a private writable cache
#            whose tracked init authority enables Gradle's actual offline start parameter.
#   warm:    the caller supplies one private GRADLE_USER_HOME output. The complete /online
#            input closure, including the exact Android SDK, stays read-only.
#   rust-check: generate the real Flutter bridge and type-check the aarch64 Android Rust library;
#               Gradle is not entered.
#   emulator-test: build the same application for x86_64 from the separately pinned candidate
#                  std/native closure. The resulting debug-signed APK is runtime-test-only.
set -euo pipefail
case "${APK_MODE:-}" in
    offline|warm|rust-check|emulator-test) ;;
    *) echo "[FATAL] APK_MODE must be exactly offline, warm, rust-check, or emulator-test" >&2; exit 1 ;;
esac
[ -z "${RUSTDESK_GRADLE_OFFLINE+x}" ] \
    || { echo "[FATAL] RUSTDESK_GRADLE_OFFLINE is build-internal" >&2; exit 1; }
if [ "$APK_MODE" = warm ]; then
    [ "${RUSTDESK_GRADLE_WARM_HOME:-}" = /outputs/gradle-home ] \
        || { echo "[FATAL] warm Gradle output must be the exact private /outputs/gradle-home mount" >&2; exit 1; }
    [ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ] \
        || { echo "[FATAL] warm builds may not redirect the read-only Android SDK" >&2; exit 1; }
    ANDROID_BUILD_SDK=/online/android-sdk
else
    [ -z "${RUSTDESK_GRADLE_WARM_HOME+x}" ] \
        || { echo "[FATAL] RUSTDESK_GRADLE_WARM_HOME is warm-build-internal" >&2; exit 1; }
    [ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ] \
        || { echo "[FATAL] RUSTDESK_ANDROID_SDK_HOME is warm-build-internal" >&2; exit 1; }
    ANDROID_BUILD_SDK=/online/android-sdk
fi
readonly ANDROID_BUILD_SDK

ANDROID_RUST_TARGET=aarch64-linux-android
ANDROID_JNI_ABI=arm64-v8a
ANDROID_CLANG_TARGET=aarch64-linux-android21
ANDROID_NDK_LIB_TRIPLE=aarch64-linux-android
FLUTTER_TARGET_PLATFORM=android-arm64
ANDROID_STD_ARCHIVE=/online/rust-std-1.75-aarch64-linux-android.tar.xz
ANDROID_STD_INSTALLER_NAME=rust-std-1.75.0-aarch64-linux-android
ANDROID_VCPKG_ROOT=/online/vcpkg
if [ "$APK_MODE" = emulator-test ]; then
    [ -d /android-candidate ] && [ ! -L /android-candidate ] \
        || { echo "[FATAL] x86_64 Android candidate root is absent or ambiguous" >&2; exit 1; }
    [ -f /android-candidate/rust-std-1.75-x86_64-linux-android.tar.xz ] \
        && [ ! -L /android-candidate/rust-std-1.75-x86_64-linux-android.tar.xz ] \
        || { echo "[FATAL] x86_64 Android Rust std candidate is absent or ambiguous" >&2; exit 1; }
    [ -d /android-candidate/vcpkg/installed/x64-android ] \
        && [ ! -L /android-candidate/vcpkg/installed/x64-android ] \
        || { echo "[FATAL] x86_64 Android native candidate is absent or ambiguous" >&2; exit 1; }
    [ "$(stat -c '%u:%g:%a:%h:%s' -- \
        /android-candidate/rust-std-1.75-x86_64-linux-android.tar.xz)" = \
      "$(id -u):$(id -g):400:1:${RUSTDESK_ANDROID_X86_STD_SIZE:?}" ] \
        || { echo "[FATAL] x86_64 Android Rust std candidate metadata differs" >&2; exit 1; }
    [ "$(sha256sum /android-candidate/rust-std-1.75-x86_64-linux-android.tar.xz \
        | awk '{ print $1 }')" = "${RUSTDESK_ANDROID_X86_STD_SHA256:?}" ] \
        || { echo "[FATAL] x86_64 Android Rust std candidate digest differs" >&2; exit 1; }
    python3 -I -S /src/scripts/online-input-provenance.py verify-subtree \
        --tree /android-candidate/vcpkg/installed/x64-android \
        --expected "${RUSTDESK_ANDROID_X86_VCPKG_SHA256:?}"
    [ "${FLUTTER_STORAGE_BASE_URL:-}" = file:///flutter-storage ] \
        || { echo "[FATAL] x86_64 runtime build must use the exact local Flutter storage root" >&2; exit 1; }
    flutter_maven=/flutter-storage/download.flutter.io/io/flutter
    flutter_version="${RUSTDESK_FLUTTER_ANDROID_MAVEN_VERSION:?}"
    for specification in \
        "flutter_embedding_release:jar:${RUSTDESK_FLUTTER_ANDROID_EMBEDDING_JAR_SIZE:?}:${RUSTDESK_FLUTTER_ANDROID_EMBEDDING_JAR_SHA256:?}" \
        "flutter_embedding_release:pom:${RUSTDESK_FLUTTER_ANDROID_EMBEDDING_POM_SIZE:?}:${RUSTDESK_FLUTTER_ANDROID_EMBEDDING_POM_SHA256:?}" \
        "x86_64_release:jar:${RUSTDESK_FLUTTER_ANDROID_X86_64_JAR_SIZE:?}:${RUSTDESK_FLUTTER_ANDROID_X86_64_JAR_SHA256:?}" \
        "x86_64_release:pom:${RUSTDESK_FLUTTER_ANDROID_X86_64_POM_SIZE:?}:${RUSTDESK_FLUTTER_ANDROID_X86_64_POM_SHA256:?}"
    do
        IFS=: read -r artifact extension expected_size expected_sha256 \
            <<<"$specification"
        input="$flutter_maven/$artifact/$flutter_version/$artifact-$flutter_version.$extension"
        [ -f "$input" ] && [ ! -L "$input" ] \
            && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$input")" = \
                 "$(id -u):$(id -g):400:1:$expected_size" ] \
            || { echo "[FATAL] local Flutter Maven input metadata differs: $artifact.$extension" >&2; exit 1; }
        [ "$(sha256sum "$input" | awk '{ print $1 }')" = "$expected_sha256" ] \
            || { echo "[FATAL] local Flutter Maven input digest differs: $artifact.$extension" >&2; exit 1; }
    done
    ANDROID_RUST_TARGET=x86_64-linux-android
    ANDROID_JNI_ABI=x86_64
    ANDROID_CLANG_TARGET=x86_64-linux-android21
    ANDROID_NDK_LIB_TRIPLE=x86_64-linux-android
    FLUTTER_TARGET_PLATFORM=android-x64
    ANDROID_STD_ARCHIVE=/android-candidate/rust-std-1.75-x86_64-linux-android.tar.xz
    ANDROID_STD_INSTALLER_NAME=rust-std-1.75.0-x86_64-linux-android
    ANDROID_VCPKG_ROOT=/android-candidate/vcpkg
fi
if [ "$APK_MODE" != emulator-test ]; then
    [ -z "${FLUTTER_STORAGE_BASE_URL+x}" ] \
        || { echo "[FATAL] non-emulator builds may not redirect Flutter storage" >&2; exit 1; }
fi
readonly ANDROID_RUST_TARGET ANDROID_JNI_ABI ANDROID_CLANG_TARGET \
    ANDROID_NDK_LIB_TRIPLE FLUTTER_TARGET_PLATFORM ANDROID_STD_ARCHIVE \
    ANDROID_STD_INSTALLER_NAME ANDROID_VCPKG_ROOT

# Android SDK preferences are distinct from shell HOME: AGP runs in a JVM whose
# user.home comes from the image account. In the pinned 30.3.1 tool stack, current
# location code treats ANDROID_PREFS_ROOT as the parent of .android, while the older
# analytics library uses that root directly. One private root therefore owns both
# paths without the conflicting dual-variable injection rejected by current tools.
unset ANDROID_USER_HOME ANDROID_SDK_HOME
export ANDROID_PREFS_ROOT=/tmp/android-preferences-root
if [ -e "$ANDROID_PREFS_ROOT" ] || [ -L "$ANDROID_PREFS_ROOT" ]; then
    echo "[FATAL] Android preferences root was not freshly absent" >&2
    exit 1
fi
install -d -m 0700 "$ANDROID_PREFS_ROOT"
install -d -m 0700 "$ANDROID_PREFS_ROOT/.android"
[ "$(stat -c '%u:%a' "$ANDROID_PREFS_ROOT")" = "$(id -u):700" ] \
    || { echo "[FATAL] Android preferences root is not private to the build identity" >&2; exit 1; }
[ "$(stat -c '%u:%a' "$ANDROID_PREFS_ROOT/.android")" = "$(id -u):700" ] \
    || { echo "[FATAL] current Android preferences directory is not private to the build identity" >&2; exit 1; }

prepare_offline_gradle_cache() {
    [ "$APK_MODE" = offline ] || [ "$APK_MODE" = emulator-test ] || return 0
    python3 -I -S /src/scripts/android-gradle-cache.py materialize \
        --source /online/gradle-home \
        --init-script /src/scripts/android-gradle-offline.init.gradle
    export GRADLE_USER_HOME=/tmp/gradle-home
    export RUSTDESK_GRADLE_OFFLINE=1
}

if [ "$APK_MODE" = warm ]; then
    [ -d "$RUSTDESK_GRADLE_WARM_HOME" ] && [ ! -L "$RUSTDESK_GRADLE_WARM_HOME" ] \
        || { echo "[FATAL] private warm Gradle output is not a real directory" >&2; exit 1; }
    [ -d "$ANDROID_BUILD_SDK" ] && [ ! -L "$ANDROID_BUILD_SDK" ] \
        || { echo "[FATAL] private warm Android SDK output is not a real directory" >&2; exit 1; }
    export GRADLE_USER_HOME="$RUSTDESK_GRADLE_WARM_HOME"
fi

TC=/tmp/tc; mkdir -p "$TC"
# Install Rust and its Android cross-std before expanding Flutter and LLVM. The installer
# payloads have no consumer after installation and must not overlap those larger toolchains.
tar -C "$TC" -xf /online/rust-1.75.tar.xz
tar -C "$TC" -xf "$ANDROID_STD_ARCHIVE"
RUST_INSTALLER_ROOT="$TC/rust-1.75.0-x86_64-unknown-linux-gnu"
ANDROID_STD_INSTALLER_ROOT="$TC/$ANDROID_STD_INSTALLER_NAME"
"$RUST_INSTALLER_ROOT/install.sh" --prefix="$TC/r" --disable-ldconfig \
    --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
"$ANDROID_STD_INSTALLER_ROOT/install.sh" --prefix="$TC/r" --disable-ldconfig >/dev/null
rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"
if [ -e "$RUST_INSTALLER_ROOT" ] || [ -L "$RUST_INSTALLER_ROOT" ] \
    || [ -e "$ANDROID_STD_INSTALLER_ROOT" ] || [ -L "$ANDROID_STD_INSTALLER_ROOT" ]; then
    echo "[FATAL] consumed Rust installer payload survived scratch retirement" >&2
    exit 1
fi

tar -C "$TC" -xf /online/flutter-3.24.5.tar.xz
tar -C "$TC" -xf /online/llvm-15.0.6.tar.xz
LLVM_ROOT="$TC/clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04"
[ -d "$TC/flutter" ] && [ -d "$LLVM_ROOT" ] \
    || { echo "[FATAL] pinned Flutter or LLVM extraction is incomplete" >&2; exit 1; }
if [ "$APK_MODE" = emulator-test ]; then
    [ -f "$TC/flutter/bin/internal/engine.version" ] \
        && [ ! -L "$TC/flutter/bin/internal/engine.version" ] \
        && [ "$(tr -d '\n' <"$TC/flutter/bin/internal/engine.version")" = \
             "${RUSTDESK_FLUTTER_ANDROID_ENGINE_REVISION:?}" ] \
        || { echo "[FATAL] Flutter SDK engine revision differs from the local Maven closure" >&2; exit 1; }
fi
export LIBCLANG_PATH="$LLVM_ROOT/lib"
export ANDROID_NDK_HOME=/online/android-ndk
# bindgen (scrap) must parse the NDK android sysroot, not the host glibc headers.
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot --target=$ANDROID_CLANG_TARGET"
export VCPKG_ROOT="$ANDROID_VCPKG_ROOT"
export ANDROID_SDK_ROOT="$ANDROID_BUILD_SDK" ANDROID_HOME="$ANDROID_BUILD_SDK"
# Build-time CARGO_HOME (do NOT clobber the tracked /src/.cargo/config.toml).
export CARGO_HOME=/tmp/cargo-home; mkdir -p "$CARGO_HOME"
# Offline flutter shim: routes `flutter pub {run,get}` -> dart --offline and injects --no-pub
# on `flutter build` (the flutter wrapper drives pub ONLINE -> advisories _TypeError).
export REAL_FLUTTER="$TC/flutter/bin/flutter"
SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
export PATH="$SHIM:$TC/r/bin:/online/cargo-ndk-tool/bin:$TC/flutter/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
# Vendored, offline cargo (gradle also shells out to `cargo metadata`).
printf '[net]\noffline = true\n' > "$CARGO_HOME/config.toml"
sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
    /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
export HOME=/tmp/buildhome; mkdir -p "$HOME"
git config --global --add safe.directory "*"
export PUB_CACHE=/online/pub-cache CI=true

# R-B9 idempotency ("re-running is safe"): DELETE stale generated Android outputs FIRST.
# flutter/build holds Gradle resource-merge intermediates that `flutter build apk` does not clean.
# jniLibs holds the Rust/NDK projection; the immutable online snapshot makes libc++_shared.so mode
# 0400, so a second pass cannot overwrite that prior projection in place. Both paths are git-ignored
# harness output regenerated by every APK pass.
if [ "$APK_MODE" != rust-check ]; then
    rm -rf ./flutter/build ./flutter/android/app/src/main/jniLibs
fi

# Offline pub: the project + the flutter SDK tool package (flutter build re-resolves both
# in-process ONLINE otherwise -> pub advisories _TypeError on the read-only cache).
pub_lock_before="$(sha256sum flutter/pubspec.lock | awk '{print $1}')"
( cd flutter && dart pub get --offline --enforce-lockfile )
( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline --enforce-lockfile )
/src/scripts/finalize-flutter-tools-offline.sh \
    "$TC/flutter" \
    "${RUSTDESK_FLUTTER_VERSION:?}" \
    "${RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256:?}"
# Plugin injection: bare `dart pub get` above does NOT write .flutter-plugins-dependencies (the gradle plugin
# list) -- only the REAL `flutter pub get` does (the flutter-tool's plugin resolution). Without it the gradle
# build reuses whatever .flutter-plugins-dependencies is on disk, which can be STALE/wrong -- e.g. one a
# windows/FRB docker step left listing the desktop-only `desktop_drop` under "android", so gradle asserts its
# (nonexistent) android dir and fails. Run the REAL flutter (NOT the --no-pub shim) so android's plugin list is
# regenerated correctly + offline. Mirrors the windows build's generated_plugins.cmake fix (3a577a6).
( cd flutter && "$REAL_FLUTTER" pub get --offline --enforce-lockfile )
pub_lock_after="$(sha256sum flutter/pubspec.lock | awk '{print $1}')"
[ "$pub_lock_before" = "$pub_lock_after" ] || {
    echo "[FATAL] flutter/pubspec.lock changed during offline pub resolution" >&2
    git --no-pager diff -- flutter/pubspec.lock || true
    exit 1
}
# FRB bridge (--llvm-compiler-opts so ffigen resolves <stdbool.h> -> correct bool bindings).
# ffigen can emit a [SEVERE] diagnostic yet let the outer generator return success. Preserve its
# complete output for the build log, but reject that contradictory success before Cargo or Gradle.
FRB_CODEGEN_LOG="$(mktemp /tmp/rustdesk-frb-codegen.XXXXXXXXXX)"
readonly FRB_CODEGEN_LOG
trap 'rm -f -- "$FRB_CODEGEN_LOG"' EXIT
flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart \
    --llvm-path "$LLVM_ROOT" \
    --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)" \
    2>&1 | tee "$FRB_CODEGEN_LOG"
if grep -qF '[SEVERE]' "$FRB_CODEGEN_LOG"; then
    echo "[FATAL] Flutter-Rust-Bridge generation emitted a severe diagnostic" >&2
    exit 1
fi
rm -f -- "$FRB_CODEGEN_LOG"
trap - EXIT
if [ "$APK_MODE" = rust-check ]; then
    cargo ndk --platform 21 --target aarch64-linux-android \
        check --locked --release --features flutter --lib
    exit 0
fi
# The Rust JNI lib (cargo-ndk -> liblibrustdesk.so), copied into jniLibs as librustdesk.so
# with the NDK libc++_shared.so, then the Flutter APK (gradle offline via the warm cache).
if [ "$APK_MODE" = emulator-test ]; then
    cargo ndk --platform 21 --target "$ANDROID_RUST_TARGET" \
        build --locked --release --features flutter
else
    bash ./flutter/ndk_arm64.sh
fi
mkdir -p "./flutter/android/app/src/main/jniLibs/$ANDROID_JNI_ABI"
cp "./target/$ANDROID_RUST_TARGET/release/liblibrustdesk.so" \
    "./flutter/android/app/src/main/jniLibs/$ANDROID_JNI_ABI/librustdesk.so"
cp "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/$ANDROID_NDK_LIB_TRIPLE/libc++_shared.so" \
    "./flutter/android/app/src/main/jniLibs/$ANDROID_JNI_ABI/"
# LLVM is required by bridge generation and the Rust JNI build, but not by the final Flutter/
# Gradle packaging phase. Gradle still needs the installed Cargo for its tracked metadata query.
rm -rf -- "$LLVM_ROOT"
if [ -e "$LLVM_ROOT" ] || [ -L "$LLVM_ROOT" ]; then
    echo "[FATAL] consumed LLVM payload survived scratch retirement" >&2
    exit 1
fi
unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS
prepare_offline_gradle_cache
flutter_test_args=()
if [ "$APK_MODE" = emulator-test ]; then
    # The isolated synthetic-frame test needs one bounded engine readback. Normal
    # Android artifacts must never log remote-display pixels or pay this cost.
    flutter_test_args=(--dart-define=RUSTDESK_ANDROID_RGBA_ENGINE_EVIDENCE=true)
fi
cd flutter && flutter build apk --release --target-platform "$FLUTTER_TARGET_PLATFORM" --split-per-abi "${flutter_test_args[@]}"

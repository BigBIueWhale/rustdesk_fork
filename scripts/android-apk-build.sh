#!/usr/bin/env bash
# scripts/android-apk-build.sh — the shared android build flow (R-B7).
#
# Run INSIDE the pinned android-builder container by TWO callers, so the offline build
# and the online gradle-warming stay byte-for-byte the same flow:
#   - build-android.sh  build_apk        APK_MODE=offline   (the --network=none .apk build)
#   - online-fetch.sh   stage_gradle     APK_MODE=warm      (the ONE networked gradle warm)
#   - android-rust-check.sh              APK_MODE=rust-check (the offline Android Rust gate)
# It builds the Rust JNI lib (cargo-ndk) + the Flutter APK from the staged ./online cache:
# host rust + the aarch64-linux-android cross-std, the NDK, the arm64-android vcpkg natives,
# cargo-ndk, the offline cargo vendor, the offline flutter shim, the SDK, and the gradle cache.
#
# APK_MODE selects the requested Android build operation:
#   offline: project the read-only warm /online/gradle-home into a private writable cache
#            whose tracked init authority enables Gradle's actual offline start parameter.
#   warm:    GRADLE_USER_HOME=/online/gradle-home directly (the networked run populates it,
#            and gradle auto-installs the extra SDK packages it needs into /online/android-sdk).
#   rust-check: generate the real Flutter bridge and type-check the aarch64 Android Rust library;
#               Gradle is not entered.
set -euo pipefail
case "${APK_MODE:-}" in
    offline|warm|rust-check) ;;
    *) echo "[FATAL] APK_MODE must be exactly offline, warm, or rust-check" >&2; exit 1 ;;
esac
[ -z "${RUSTDESK_GRADLE_OFFLINE+x}" ] \
    || { echo "[FATAL] RUSTDESK_GRADLE_OFFLINE is build-internal" >&2; exit 1; }

# Android SDK preferences are distinct from shell HOME: AGP runs in a JVM whose
# user.home comes from the image account. Keep that per-pass state on the existing
# bounded tmpfs instead of falling through to the read-only container root.
export ANDROID_USER_HOME=/tmp/android-user-home
if [ -e "$ANDROID_USER_HOME" ] || [ -L "$ANDROID_USER_HOME" ]; then
    echo "[FATAL] Android user home was not freshly absent" >&2
    exit 1
fi
install -d -m 0700 "$ANDROID_USER_HOME"
[ "$(stat -c '%u:%a' "$ANDROID_USER_HOME")" = "$(id -u):700" ] \
    || { echo "[FATAL] Android user home is not private to the build identity" >&2; exit 1; }

prepare_offline_gradle_cache() {
    [ "$APK_MODE" = offline ] || return 0
    python3 -I -S /src/scripts/android-gradle-cache.py materialize \
        --source /online/gradle-home \
        --init-script /src/scripts/android-gradle-offline.init.gradle
    export GRADLE_USER_HOME=/tmp/gradle-home
    export RUSTDESK_GRADLE_OFFLINE=1
}

if [ "$APK_MODE" = warm ]; then
    if [ -e /online/gradle-home ] || [ -L /online/gradle-home ]; then
        [ -d /online/gradle-home ] && [ ! -L /online/gradle-home ] \
            || { echo "[FATAL] warm Gradle cache is not a real directory" >&2; exit 1; }
    else
        mkdir /online/gradle-home
    fi
    export GRADLE_USER_HOME=/online/gradle-home
fi

TC=/tmp/tc; mkdir -p "$TC"
# Install Rust and its Android cross-std before expanding Flutter and LLVM. The installer
# payloads have no consumer after installation and must not overlap those larger toolchains.
tar -C "$TC" -xf /online/rust-1.75.tar.xz
tar -C "$TC" -xf /online/rust-std-1.75-aarch64-linux-android.tar.xz
RUST_INSTALLER_ROOT="$TC/rust-1.75.0-x86_64-unknown-linux-gnu"
ANDROID_STD_INSTALLER_ROOT="$TC/rust-std-1.75.0-aarch64-linux-android"
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
export LIBCLANG_PATH="$LLVM_ROOT/lib"
export ANDROID_NDK_HOME=/online/android-ndk
# bindgen (scrap) must parse the NDK android sysroot, not the host glibc headers.
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot --target=aarch64-linux-android21"
export VCPKG_ROOT=/online/vcpkg
export ANDROID_SDK_ROOT=/online/android-sdk ANDROID_HOME=/online/android-sdk
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
( cd flutter && dart pub get --offline )
( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
# Plugin injection: bare `dart pub get` above does NOT write .flutter-plugins-dependencies (the gradle plugin
# list) -- only the REAL `flutter pub get` does (the flutter-tool's plugin resolution). Without it the gradle
# build reuses whatever .flutter-plugins-dependencies is on disk, which can be STALE/wrong -- e.g. one a
# windows/FRB docker step left listing the desktop-only `desktop_drop` under "android", so gradle asserts its
# (nonexistent) android dir and fails. Run the REAL flutter (NOT the --no-pub shim) so android's plugin list is
# regenerated correctly + offline. Mirrors the windows build's generated_plugins.cmake fix (3a577a6).
( cd flutter && "$REAL_FLUTTER" pub get --offline )
pub_lock_after="$(sha256sum flutter/pubspec.lock | awk '{print $1}')"
[ "$pub_lock_before" = "$pub_lock_after" ] || {
    echo "[FATAL] flutter/pubspec.lock changed during offline pub resolution" >&2
    git --no-pager diff -- flutter/pubspec.lock || true
    exit 1
}
# FRB bridge (--llvm-compiler-opts so ffigen resolves <stdbool.h> -> correct bool bindings).
flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart \
    --llvm-path "$LLVM_ROOT" \
    --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
if [ "$APK_MODE" = rust-check ]; then
    cargo ndk --platform 21 --target aarch64-linux-android \
        check --locked --release --features flutter --lib
    exit 0
fi
# The Rust JNI lib (cargo-ndk -> liblibrustdesk.so), copied into jniLibs as librustdesk.so
# with the NDK libc++_shared.so, then the Flutter APK (gradle offline via the warm cache).
bash ./flutter/ndk_arm64.sh
mkdir -p ./flutter/android/app/src/main/jniLibs/arm64-v8a
cp ./target/aarch64-linux-android/release/liblibrustdesk.so \
    ./flutter/android/app/src/main/jniLibs/arm64-v8a/librustdesk.so
cp "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so \
    ./flutter/android/app/src/main/jniLibs/arm64-v8a/
# LLVM is required by bridge generation and the Rust JNI build, but not by the final Flutter/
# Gradle packaging phase. Gradle still needs the installed Cargo for its tracked metadata query.
rm -rf -- "$LLVM_ROOT"
if [ -e "$LLVM_ROOT" ] || [ -L "$LLVM_ROOT" ]; then
    echo "[FATAL] consumed LLVM payload survived scratch retirement" >&2
    exit 1
fi
unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS
prepare_offline_gradle_cache
cd flutter && flutter build apk --release --target-platform android-arm64 --split-per-abi

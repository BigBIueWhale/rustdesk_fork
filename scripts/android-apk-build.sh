#!/usr/bin/env bash
# scripts/android-apk-build.sh — the shared android build flow (R-B7).
#
# Run INSIDE the pinned android-builder container by TWO callers, so the offline build
# and the online gradle-warming stay byte-for-byte the same flow:
#   - build-android.sh  build_apk        APK_MODE=offline   (the --network=none .apk build)
#   - online-fetch.sh   stage_gradle     APK_MODE=warm      (the ONE networked gradle warm)
# It builds the Rust JNI lib (cargo-ndk) + the Flutter APK from the staged ./online cache:
# host rust + the aarch64-linux-android cross-std, the NDK, the arm64-android vcpkg natives,
# cargo-ndk, the offline cargo vendor, the offline flutter shim, the SDK, and the gradle cache.
#
# APK_MODE selects ONLY the gradle-cache handling (everything else is identical):
#   offline: copy the read-only warm /online/gradle-home -> a writable /tmp dir, force
#            org.gradle.offline (gradle builds from the warm cache with no network).
#   warm:    GRADLE_USER_HOME=/online/gradle-home directly (the networked run populates it,
#            and gradle auto-installs the extra SDK packages it needs into /online/android-sdk).
set -euo pipefail
: "${APK_MODE:?APK_MODE must be offline|warm}"

TC=/tmp/tc; mkdir -p "$TC"
# Host rust (rust-1.* ONLY — a bare rust-* glob would also grab the android cross-std),
# flutter, LLVM; then the aarch64-linux-android cross-std as an extra rust component.
for t in /online/rust-1.*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
    [ -e "$t" ] && tar -C "$TC" -xf "$t"
done
tar -C "$TC" -xf /online/rust-std-1.75-aarch64-linux-android.tar.xz
"$TC"/rust-1.*/install.sh --prefix="$TC/r" --disable-ldconfig \
    --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
"$TC"/rust-std-1.75.0-aarch64-linux-android/install.sh --prefix="$TC/r" --disable-ldconfig >/dev/null
LLVM_ROOT="$(echo "$TC"/clang+llvm-*)"; export LIBCLANG_PATH="$LLVM_ROOT/lib"
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

# gradle cache: the only offline-vs-warm difference.
if [ "$APK_MODE" = offline ]; then
    cp -a /online/gradle-home /tmp/gradle-home
    echo "org.gradle.offline=true" >> /tmp/gradle-home/gradle.properties
    export GRADLE_USER_HOME=/tmp/gradle-home
else
    export GRADLE_USER_HOME=/online/gradle-home; mkdir -p "$GRADLE_USER_HOME"
fi

# Offline pub: the project + the flutter SDK tool package (flutter build re-resolves both
# in-process ONLINE otherwise -> pub advisories _TypeError on the read-only cache).
( cd flutter && dart pub get --offline )
( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
# FRB bridge (--llvm-compiler-opts so ffigen resolves <stdbool.h> -> correct bool bindings).
flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart \
    --llvm-path "$LLVM_ROOT" \
    --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
# The Rust JNI lib (cargo-ndk -> liblibrustdesk.so), copied into jniLibs as librustdesk.so
# with the NDK libc++_shared.so, then the Flutter APK (gradle offline via the warm cache).
bash ./flutter/ndk_arm64.sh
mkdir -p ./flutter/android/app/src/main/jniLibs/arm64-v8a
cp ./target/aarch64-linux-android/release/liblibrustdesk.so \
    ./flutter/android/app/src/main/jniLibs/arm64-v8a/librustdesk.so
cp "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so \
    ./flutter/android/app/src/main/jniLibs/arm64-v8a/
cd flutter && flutter build apk --release --target-platform android-arm64 --split-per-abi

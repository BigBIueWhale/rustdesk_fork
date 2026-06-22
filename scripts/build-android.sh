#!/usr/bin/env bash
# scripts/build-android.sh — Android aarch64 .apk build (R-B7/B8/B9, R-B2, §12.1).
#
# Reproduces upstream 1.4.7's official Android build (R-B7: cargo-ndk for the
# aarch64-linux-android lib + `flutter build apk`, verbatim from flutter-build.yml
# / flutter/ndk_arm64.sh) in a digest-pinned ubuntu:24.04 container — the same
# environment upstream cross-compiles Android in — with exactly two deltas: signed
# with a self-generated LOCAL key (no Play Store, R-B2), off GitHub-hosted runners.
# Build is offline (--network=none) against the SHA-verified ./online cache (R-B10).
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
# The pinned .apk build image: the digest-pinned ubuntu:24.04 baseline + the android
# build-deps (xz/openjdk/cmake/ninja/nasm/...), baked by online-fetch.sh
# (build_android_builder_image) via Dockerfile.android-builder. The compile runs inside
# it with --network=none; the rust/flutter/NDK toolchains come from ./online.
IMAGE="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"

# R-B2: the ONE stable RSA-4096 keystore (SHA256withRSA, validity >= 10000 days,
# fixed alias) generated once and reused for every release — Android ties app
# identity to the signing key, so a stable key gives clean in-place upgrades. It is
# a SECRET: kept out of the repo and the build image, fed in only at sign time,
# mounted read-only, password via FILE (never env/argv — both leak via /proc).
KEYSTORE="${ANDROID_KEYSTORE:-}"          # path to the .jks, supplied by the operator
KEYSTORE_PASS_FILE="${ANDROID_KEYSTORE_PASS_FILE:-}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-rustdesk-fork}"

preflight() {
    require_cmd docker git
    assert_repo_state
    require_online_complete
    case "$SHA256_BASEIMAGE_UBUNTU_2404" in *"${SHA_PENDING}"*) die "the ubuntu:24.04 base digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "build image '$IMAGE' not found — run scripts/online-fetch.sh first (it docker-builds it from the pinned ubuntu:24.04 + the android build-deps, Dockerfile.android-builder)"
    [ -n "$KEYSTORE" ] && [ -f "$KEYSTORE" ] || die "set ANDROID_KEYSTORE to the stable RSA-4096 keystore (R-B2); Android refuses to install an unsigned APK"
    [ -n "$KEYSTORE_PASS_FILE" ] && [ -f "$KEYSTORE_PASS_FILE" ] || die "set ANDROID_KEYSTORE_PASS_FILE (password via file, never env/argv — R-B2)"
    log "preflight OK — building aarch64 .apk in $IMAGE, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

build_apk() {
    log "building unsigned aarch64 .apk (features flutter — software codec, §3.2 arm64-android)"
    docker run --rm \
        --name "${HARNESS_PREFIX:-rustdesk-fork-harness}-apk" \
        --network=none \
        -e SOURCE_DATE_EPOCH \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online:ro" \
        -w /src \
        "$IMAGE" \
        bash -euo pipefail -c '
            TC=/tmp/tc; mkdir -p "$TC"
            # Host rust (rust-1.* ONLY — a bare rust-* glob would also grab the android cross-std),
            # flutter, LLVM from ./online; the aarch64-linux-android cross-std is a SEPARATE tarball
            # installed as an extra rust component below (the host tarball ships only x86_64).
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
            # Offline flutter shim: routes `flutter pub {run,get}` -> dart --offline and injects
            # --no-pub on `flutter build` (the flutter wrapper drives pub ONLINE → advisories _TypeError).
            export REAL_FLUTTER="$TC/flutter/bin/flutter"
            SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
            cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
            export PATH="$SHIM:$TC/r/bin:/online/cargo-ndk-tool/bin:$TC/flutter/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
            # Vendored, offline cargo (gradle also shells out to `cargo metadata`).
            printf "[net]\noffline = true\n" > "$CARGO_HOME/config.toml"
            sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
            export HOME=/tmp/buildhome; mkdir -p "$HOME"
            git config --global --add safe.directory "*"
            export PUB_CACHE=/online/pub-cache CI=true
            # gradle: the warm GRADLE_USER_HOME (online-fetch stage_gradle) is read-only in ./online;
            # copy to a writable dir (gradle writes locks/daemon) + force offline (fail fast, no net).
            cp -a /online/gradle-home /tmp/gradle-home
            echo "org.gradle.offline=true" >> /tmp/gradle-home/gradle.properties
            export GRADLE_USER_HOME=/tmp/gradle-home
            # Offline pub: the project + the flutter SDK tool package (flutter build re-resolves both
            # in-process ONLINE otherwise → pub advisories _TypeError on the read-only cache).
            ( cd flutter && dart pub get --offline )
            ( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
            # FRB bridge (--llvm-compiler-opts so ffigen resolves <stdbool.h> → correct bool bindings).
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
            cd flutter && flutter build apk --release \
                --target-platform android-arm64 --split-per-abi
        '
    mkdir -p "$OUT_DIR"
    local apk; apk="$(ls -1 "$REPO_ROOT"/flutter/build/app/outputs/flutter-apk/*arm64*release*.apk 2>/dev/null | head -1)" \
        || die "no arm64 release APK produced"
    cp "$apk" "$OUT_DIR/rustdesk-arm64-unsigned.apk"
}

sign_apk() {
    # apksigner v2 (mandatory since Android 11). Password from the mounted file,
    # never on argv: apksigner reads it via the file: provider.
    log "signing the APK with the stable local key (alias $KEY_ALIAS, R-B2)"
    docker run --rm \
        --network=none \
        -v "$OUT_DIR:/out" \
        -v "$KEYSTORE:/ks/keystore.jks:ro" \
        -v "$KEYSTORE_PASS_FILE:/ks/pass:ro" \
        -v "$ONLINE_DIR:/online:ro" \
        "$IMAGE" \
        bash -euo pipefail -c '
            export PATH="/online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/:$PATH"
            apksigner sign --ks /ks/keystore.jks --ks-key-alias '"$KEY_ALIAS"' \
                --ks-pass file:/ks/pass --v2-signing-enabled true \
                --out /out/rustdesk-arm64.apk /out/rustdesk-arm64-unsigned.apk
            apksigner verify --verbose /out/rustdesk-arm64.apk
        '
    rm -f "$OUT_DIR/rustdesk-arm64-unsigned.apk"
    sha256sum "$OUT_DIR/rustdesk-arm64.apk" | tee "$OUT_DIR/rustdesk-arm64.apk.sha256"
}

main() {
    preflight
    build_apk
    sign_apk
    log "build-android.sh complete: $OUT_DIR/rustdesk-arm64.apk"
    log "NOTE: integrity to the device is the pinned SHA-256 over the trusted channel"
    log "      (R-B2); the signature is Android's install gate, not the trust anchor."
}

main "$@"

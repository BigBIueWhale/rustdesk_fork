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
IMAGE="ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"
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
    case "$IMAGE" in *"${SHA_PENDING}"*) die "the .apk base image digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    [ -n "$KEYSTORE" ] && [ -f "$KEYSTORE" ] || die "set ANDROID_KEYSTORE to the stable RSA-4096 keystore (R-B2); Android refuses to install an unsigned APK"
    [ -n "$KEYSTORE_PASS_FILE" ] && [ -f "$KEYSTORE_PASS_FILE" ] || die "set ANDROID_KEYSTORE_PASS_FILE (password via file, never env/argv — R-B2)"
    log "preflight OK — building aarch64 .apk in $IMAGE, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

build_apk() {
    log "building unsigned aarch64 .apk (features flutter,hwcodec — §3.2 arm64-android)"
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
            for t in /online/rust-*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
                [ -e "$t" ] && tar -C "$TC" -xf "$t"
            done
            # NDK r28c + Android cmdline-tools (build-tools 34.0.0, platform-34) from
            # ./online; cargo-ndk 3.1.2 is in the vendored cargo set.
            export ANDROID_NDK_HOME=/online/android-ndk
            export PATH="$TC/flutter/bin:$TC/rust/bin:$HOME/.cargo/bin:$PATH"
            mkdir -p .cargo
            cat > .cargo/config.toml <<CFG
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "/online/cargo-vendor"
[net]
offline = true
CFG
            [ -f /online/cargo-vendor-config.toml ] && \
                sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                    /online/cargo-vendor-config.toml >> .cargo/config.toml
            flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart
            # The Rust JNI lib (R-D7a controlled-side direct-only hardening applies
            # WITHIN this build), then the Flutter APK — verbatim from upstream.
            ./flutter/ndk_arm64.sh
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

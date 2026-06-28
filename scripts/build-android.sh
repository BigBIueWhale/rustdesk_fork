#!/usr/bin/env bash
# scripts/build-android.sh — Android aarch64 .apk + androidTest build (R-B7/B8/B9, R-B2, §12.1).
#
# Reproduces upstream 1.4.7's official Android build (R-B7: cargo-ndk for the
# aarch64-linux-android lib + `flutter build apk`, plus the fork's matching
# isolated-service androidTest smoke APK, from the same offline source/toolchain,
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
    log "preflight OK — building aarch64 app/test APKs in $IMAGE, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

build_apk() {
    log "building unsigned aarch64 app APK + androidTest smoke APK (features flutter — software codec, §3.2 arm64-android)"
    docker run --rm \
        --name "${HARNESS_PREFIX:-rustdesk-fork-harness}-apk" \
        --network=none \
        -e SOURCE_DATE_EPOCH \
        -e RUSTDESK_CANARY_OFFLINE=1 \
        -e APK_MODE=offline \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online:ro" \
        -w /src \
        "$IMAGE" \
        bash /src/scripts/android-apk-build.sh
    mkdir -p "$OUT_DIR"
    local apk; apk="$(ls -1 "$REPO_ROOT"/flutter/build/app/outputs/flutter-apk/*arm64*release*.apk 2>/dev/null | head -1)" \
        || die "no arm64 release APK produced"
    local test_apk
    test_apk="$(find "$REPO_ROOT"/flutter/build/app/outputs "$REPO_ROOT"/flutter/android/app/build/outputs \
        -type f -path '*androidTest*' -name '*.apk' 2>/dev/null | sort | head -1 || true)"
    [ -n "$test_apk" ] && [ -f "$test_apk" ] || die "no release androidTest APK produced for isolated-service smoke"
    cp "$apk" "$OUT_DIR/rustdesk-arm64-unsigned.apk"
    cp "$test_apk" "$OUT_DIR/rustdesk-arm64-androidTest-unsigned.apk"
}

sign_apk() {
    # apksigner v2 (mandatory since Android 11). Password from the mounted file,
    # never on argv: apksigner reads it via the file: provider.
    log "signing the APK with the stable local key (alias $KEY_ALIAS, R-B2)"
    docker run --rm \
        --network=none \
        -e ANDROID_BUILD_TOOLS="$ANDROID_BUILD_TOOLS" \
        -e KEY_ALIAS="$KEY_ALIAS" \
        -v "$OUT_DIR:/out" \
        -v "$KEYSTORE:/ks/keystore.jks:ro" \
        -v "$KEYSTORE_PASS_FILE:/ks/pass:ro" \
        -v "$ONLINE_DIR:/online:ro" \
        "$IMAGE" \
        bash -euo pipefail -c '
            export PATH="/online/android-sdk/build-tools/${ANDROID_BUILD_TOOLS}/:$PATH"
            for artifact in rustdesk-arm64 rustdesk-arm64-androidTest; do
                apksigner sign --ks /ks/keystore.jks --ks-key-alias "$KEY_ALIAS" \
                    --ks-pass file:/ks/pass --v2-signing-enabled true \
                    --out "/out/${artifact}.apk" "/out/${artifact}-unsigned.apk"
                apksigner verify --verbose "/out/${artifact}.apk"
            done
        '
    rm -f "$OUT_DIR/rustdesk-arm64-unsigned.apk" "$OUT_DIR/rustdesk-arm64-androidTest-unsigned.apk"
    sha256sum "$OUT_DIR/rustdesk-arm64.apk" | tee "$OUT_DIR/rustdesk-arm64.apk.sha256"
    sha256sum "$OUT_DIR/rustdesk-arm64-androidTest.apk" | tee "$OUT_DIR/rustdesk-arm64-androidTest.apk.sha256"
}

main() {
    preflight
    build_apk
    sign_apk
    log "build-android.sh complete: $OUT_DIR/rustdesk-arm64.apk + $OUT_DIR/rustdesk-arm64-androidTest.apk"
    log "NOTE: integrity to the device is the pinned SHA-256 over the trusted channel"
    log "      (R-B2); the signature is Android's install gate, not the trust anchor."
}

main "$@"

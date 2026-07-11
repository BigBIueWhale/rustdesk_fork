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
# R-B2: fixed pinned reproducible epoch (pins.env SOURCE_DATE_EPOCH_PIN), not a commit date.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_PIN}"

# R-B2: the ONE stable RSA-4096 keystore (SHA256withRSA, validity >= 10000 days,
# fixed alias) generated once and reused for every release — Android ties app
# identity to the signing key, so a stable key gives clean in-place upgrades. It is
# a SECRET: kept out of the repo and the build image, fed in only at sign time,
# mounted read-only, password via FILE (never env/argv — both leak via /proc).
KEYSTORE="${ANDROID_KEYSTORE:-$DEFAULT_ANDROID_KEYSTORE}"                   # defaults to .harness-state/android-keystore/ (lib.sh); no env var needed
KEYSTORE_PASS_FILE="${ANDROID_KEYSTORE_PASS_FILE:-$DEFAULT_ANDROID_KEYSTORE_PASS_FILE}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-rustdesk-fork}"

preflight() {
    require_cmd docker git
    assert_repo_state
    assert_clean_worktree
    assert_source_date_epoch
    require_online_complete
    # §12.3 / R-B10 (trust nobody): re-verify the exact ./online tarballs this offline build extracts
    # against their pins BEFORE building — a corrupt/partial cache, or a stray version-renamed tarball
    # a glob would grab, dies HERE, not silently compiled.
    verify_online_shas \
        "rust-${RUST_VERSION}.tar.xz"                           "${SHA256_RUST_1_75}" \
        "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz" "${SHA256_RUST_STD_ANDROID_1_75}" \
        "flutter-${FLUTTER_VERSION}.tar.xz"                     "${SHA256_FLUTTER_3_24_5}" \
        "llvm-${LLVM_VERSION}.tar.xz"                           "${SHA256_LLVM_15_0_6}" \
        "android-ndk-${ANDROID_NDK_VERSION}.zip"               "${SHA256_ANDROID_NDK_R28C}" \
        "android-cmdline-tools.zip"                            "${SHA256_ANDROID_CMDLINE_TOOLS}"
    case "$SHA256_BASEIMAGE_UBUNTU_2404" in *"${SHA_PENDING}"*) die "the ubuntu:24.04 base digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "build image '$IMAGE' not found — run scripts/online-fetch.sh first (it docker-builds it from the pinned ubuntu:24.04 + the android build-deps, Dockerfile.android-builder)"
    [ -n "$KEYSTORE" ] && [ -f "$KEYSTORE" ] || die "set ANDROID_KEYSTORE to the stable RSA-4096 keystore (R-B2) — generate it once with scripts/gen-android-keystore.sh; Android refuses to install an unsigned APK"
    [ -n "$KEYSTORE_PASS_FILE" ] && [ -f "$KEYSTORE_PASS_FILE" ] || die "set ANDROID_KEYSTORE_PASS_FILE (password via file, never env/argv — R-B2)"
    assert_keystore_properties
    log "preflight OK — building aarch64 .apk in $IMAGE, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

# assert_keystore_properties: R-B2 mandates a SPECIFIC key (RSA 4096-bit, SHA256withRSA, fixed alias).
# A wrong key silently signs the release, and Android WELDS app identity to the signing key — a wrong
# key at first release is PERMANENT (rotation = a data-wiping reinstall). So assert the key's
# PROPERTIES, not just its existence. keytool runs in the build IMAGE (the host may have no JDK); the
# store password is fed on keytool's stdin (never argv/env — both leak via /proc, per the R-B2 note).
assert_keystore_properties() {
    local info
    info="$(docker run --rm --network=none \
        -v "$KEYSTORE:/ks/keystore.jks:ro" -v "$KEYSTORE_PASS_FILE:/ks/pass:ro" "$IMAGE" \
        bash -c 'keytool -list -v -keystore /ks/keystore.jks -alias "'"$KEY_ALIAS"'" 2>/dev/null < /ks/pass')" \
        || die "android keystore: alias '$KEY_ALIAS' not found, or wrong password (R-B2) — regenerate with scripts/gen-android-keystore.sh"
    printf '%s' "$info" | grep -qE 'Signature algorithm name:[[:space:]]*SHA256withRSA' \
        || die "android keystore signature algorithm is not SHA256withRSA (R-B2) — regenerate: scripts/gen-android-keystore.sh"
    printf '%s' "$info" | grep -qiE '4096-bit RSA key' \
        || die "android keystore is not a 4096-bit RSA key (R-B2) — regenerate: scripts/gen-android-keystore.sh"
    log "android keystore OK: alias '$KEY_ALIAS', 4096-bit RSA, SHA256withRSA"
}

build_apk() {
    log "building unsigned aarch64 .apk (features flutter — software codec, §3.2 arm64-android)"
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
    # The docker run built into the bind-mounted flutter/build (android-apk-build.sh wiped it up front,
    # so no prior-run APK survives to be mispicked). Assert the produced APK explicitly: the old
    # `apk="$(ls…)" || die` was DEAD CODE (the assignment's exit status is `head`'s = always 0), so a
    # missing APK fell through to a confusing `cp ''` under set -e instead of this loud message.
    local apk; apk="$(ls -1 "$REPO_ROOT"/flutter/build/app/outputs/flutter-apk/*arm64*release*.apk 2>/dev/null | head -1)"
    [ -n "$apk" ] && [ -f "$apk" ] || die "no arm64 release APK produced by the in-container build — see the build output above (android-apk-build.sh / gradle failure)"
    cp "$apk" "$OUT_DIR/rustdesk-arm64-unsigned.apk"
}

sign_apk() {
    # apksigner v2 (mandatory since Android 11). Password from the mounted file,
    # never on argv: apksigner reads it via the file: provider.
    log "signing the APK with the stable local key (alias $KEY_ALIAS, R-B2)"
    docker run --rm \
        --network=none \
        -v "$REPO_ROOT:/src:ro" \
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
            python3 /src/scripts/verify-android-apk-manifest.py \
                --apk /out/rustdesk-arm64.apk \
                --aapt2 /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/aapt2
        '
    rm -f "$OUT_DIR/rustdesk-arm64-unsigned.apk"
    sha256sum "$OUT_DIR/rustdesk-arm64.apk" | tee "$OUT_DIR/rustdesk-arm64.apk.sha256"
}

main() {
    preflight
    build_apk
    sign_apk
    # R-B2 double-build determinism (DEFAULT — the correct build proves its OWN reproducibility).
    # A second build of identical source MUST produce a byte-identical SIGNED APK, or the recorded
    # SHA is unfalsifiable. build-debian.sh makes this assertion for the .deb; mirror it here so the
    # DEFAULT `build-android.sh` invocation self-proves A==B and DIES on any drift — assume nothing,
    # trust nothing. Each pass self-cleans flutter/build (android-apk-build.sh, R-B9), so this is
    # safe on any tree state / any run order. (Set DOUBLE_BUILD=0 only for a deliberate single pass.)
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        local first saved_out second
        first="$(awk '{print $1}' "$OUT_DIR/rustdesk-arm64.apk.sha256")"
        saved_out="$OUT_DIR"
        OUT_DIR="$saved_out/_rebuild"; rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"
        build_apk
        sign_apk
        second="$(awk '{print $1}' "$OUT_DIR/rustdesk-arm64.apk.sha256")"
        rm -rf "$OUT_DIR"; OUT_DIR="$saved_out"
        [ "$first" = "$second" ] || die "R-B2 double-build APK SHA mismatch ($first vs $second) — the APK is NOT reproducible; fix SOURCE_DATE_EPOCH / apksigner determinism before release"
        log "R-B2 double-build determinism OK (A==B): $first"
    fi
    log "build-android.sh complete: $OUT_DIR/rustdesk-arm64.apk"
    log "NOTE: integrity to the device is the pinned SHA-256 over the trusted channel"
    log "      (R-B2); the signature is Android's install gate, not the trust anchor."
}

main "$@"

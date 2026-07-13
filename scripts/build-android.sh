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

if [ -n "${ONLINE_DIR+x}" ]; then
    printf 'build-android: ONLINE_DIR is not an operator override; release snapshots use RUSTDESK_RELEASE_ONLINE_SNAPSHOT\n' >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
# The pinned .apk build image: the digest-pinned ubuntu:24.04 baseline + the android
# build-deps (xz/openjdk/cmake/ninja/nasm/...), baked by online-fetch.sh
# (build_android_builder_image) via Dockerfile.android-builder. The compile runs inside
# it with --network=none; the rust/flutter/NDK toolchains come from ./online.
IMAGE_ID="${ANDROID_BUILDER_IMAGE_ID:-}"
# R-B2: fixed pinned reproducible epoch (pins.env SOURCE_DATE_EPOCH_PIN), not a commit date.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_PIN}"

# R-B2: the ONE stable RSA-4096 keystore (SHA256withRSA, validity >= 10000 days,
# fixed alias) generated once and reused for every release — Android ties app
# identity to the signing key, so a stable key gives clean in-place upgrades. It is
# a SECRET: kept out of the repo and the build image, fed in only at sign time,
# mounted read-only, password via FILE (never env/argv — both leak via /proc).
KEYSTORE="${ANDROID_KEYSTORE:-$DEFAULT_ANDROID_KEYSTORE}"                   # defaults to .harness-state/android-keystore/ (lib.sh); no env var needed
KEYSTORE_PASS_FILE="${ANDROID_KEYSTORE_PASS_FILE:-$DEFAULT_ANDROID_KEYSTORE_PASS_FILE}"
KEY_ALIAS="rustdesk-fork"
BUILD_UID="$(id -u)"
BUILD_GID="$(id -g)"
VERIFY_APK=""
RELEASE_CHILD=0
ONLINE_SNAPSHOT_PARENT=""
OWNED_WORKSPACE=""

case "${ANDROID_KEY_ALIAS:-rustdesk-fork}" in
    rustdesk-fork) ;;
    *) die "ANDROID_KEY_ALIAS is fixed to rustdesk-fork" ;;
esac
case "${DOCKER_HOST:-unix:///var/run/docker.sock}" in
    unix:///var/run/docker.sock) export DOCKER_HOST=unix:///var/run/docker.sock ;;
    *) die "Docker must use the local unix:///var/run/docker.sock daemon" ;;
esac
for variable in DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS; do
    [ -z "${!variable+x}" ] || die "$variable must not influence an Android build"
done
if [ "$#" -gt 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = --verify-apk ] \
        || die "usage: build-android.sh [--verify-apk APK]"
    VERIFY_APK="$2"
fi

cleanup_owned_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$OWNED_WORKSPACE" ] && [ -d "$OWNED_WORKSPACE" ]; then
        if ! chmod -R u+rwX "$OWNED_WORKSPACE" 2>/dev/null \
            || ! rm -rf -- "$OWNED_WORKSPACE"; then
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup_owned_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_private_directory() {
    local path="$1" label="$2" resolved metadata
    case "$path" in
        /*) ;;
        *) die "$label must be an absolute path" ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be a canonical non-symlinked path"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is absent"
    [ "$metadata" = "$BUILD_UID:700" ] || die "$label must be a current-UID mode-0700 directory"
}

assert_private_docker_config() {
    local config_dir="${DOCKER_CONFIG:-}" metadata
    [ -n "$config_dir" ] || die "release child is missing its private Docker configuration"
    assert_private_directory "$config_dir" "release Docker configuration"
    [ -f "$config_dir/config.json" ] && [ ! -L "$config_dir/config.json" ] \
        || die "release Docker config.json must be a non-symlink regular file"
    metadata="$(stat -c '%u:%a:%h' -- "$config_dir/config.json" 2>/dev/null)" \
        || die "release Docker config.json is absent"
    [ "$metadata" = "$BUILD_UID:600:1" ] \
        || die "release Docker config.json must be a current-UID mode-0600 non-hardlinked file"
    cmp -s "$config_dir/config.json" <(printf '{}\n') \
        || die "Docker config.json must equal the empty canonical configuration"
}

assert_private_online_snapshot() {
    local parent="$1" online bad
    assert_private_directory "$parent" "online snapshot parent"
    online="$parent/online"
    [ -d "$online" ] && [ ! -L "$online" ] || die "online snapshot tree must be a real directory"
    [ "$(stat -c '%u:%a' -- "$online" 2>/dev/null)" = "$BUILD_UID:500" ] \
        || die "online snapshot tree must be a current-UID mode-0500 directory"
    bad="$(find "$online" \( ! -uid "$BUILD_UID" -o \
        \( \( -type f -o -type d \) -perm /0222 \) \) -print -quit)" \
        || die "cannot inspect online snapshot ownership and modes"
    [ -z "$bad" ] || die "online snapshot contains a writable or differently owned path: $bad"
    verify_private_online_snapshot "$parent"
}

prepare_execution_contract() {
    local current
    if [ -n "${RELEASE_SRC_COMMIT:-}" ]; then
        RELEASE_CHILD=1
        [[ "$RELEASE_SRC_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            || die "RELEASE_SRC_COMMIT must be one full lowercase commit ID"
        current="$(git -c core.hooksPath=/dev/null -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
            || die "cannot resolve release-child source commit"
        [ "$current" = "$RELEASE_SRC_COMMIT" ] || die "release-child source commit does not equal HEAD"
        [ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
        [ -n "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "release child requires RELEASE_DOCKER_IMAGE_ID"
        assert_private_docker_config
        ONLINE_SNAPSHOT_PARENT="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
    else
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "RUSTDESK_RELEASE_ONLINE_SNAPSHOT is release-internal"
        [ -z "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "RELEASE_DOCKER_IMAGE_ID is release-internal"
        [ -z "${DOCKER_CONFIG+x}" ] || die "DOCKER_CONFIG must not influence a direct Android build"
        OWNED_WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX)" \
            || die "cannot create private Android build workspace"
        chmod 0700 "$OWNED_WORKSPACE"
        install -d -m 0700 "$OWNED_WORKSPACE/docker-config"
        printf '{}\n' > "$OWNED_WORKSPACE/docker-config/config.json"
        chmod 0600 "$OWNED_WORKSPACE/docker-config/config.json"
        export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"
        assert_private_docker_config
    fi
}

resolve_image() {
    require_pinned_builder_image android-builder "$IMAGE_ID"
    if [ "$RELEASE_CHILD" -eq 1 ] && [ "$RELEASE_DOCKER_IMAGE_ID" != "$IMAGE_ID" ]; then
        die "release Android image ID does not equal ANDROID_BUILDER_IMAGE_ID"
    fi
}

activate_online_snapshot() {
    if [ "$RELEASE_CHILD" -eq 0 ]; then
        require_online_complete
        ONLINE_SNAPSHOT_PARENT="$OWNED_WORKSPACE/online-input"
        create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    fi
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
}

verify_active_online_snapshot() {
    assert_private_docker_config
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

assert_private_signing_files() {
    python3 - "$KEYSTORE" "$KEYSTORE_PASS_FILE" "$BUILD_UID" <<'PY'
import os
import stat
import sys
from pathlib import Path

paths = [Path(sys.argv[1]), Path(sys.argv[2])]
uid = int(sys.argv[3])
if paths[0].parent != paths[1].parent:
    raise SystemExit("android signing files must share one protected directory")
for path in paths:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
        raise SystemExit(f"android signing file must be a current-UID regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(f"android signing file must have mode 0600: {path}")
for directory in (paths[0].parent, paths[0].parent.parent):
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
        raise SystemExit(f"android signing parent must be a current-UID directory: {directory}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit(f"android signing parent must have mode 0700: {directory}")
PY
}

certificate_fingerprint_from_keytool() {
    awk '
        /^[[:space:]]*SHA256:/ {
            value = $0
            sub(/^[[:space:]]*SHA256:[[:space:]]*/, "", value)
            gsub(/:/, "", value)
            print toupper(value)
            count++
        }
        END { if (count != 1) exit 1 }
    '
}

preflight() {
    require_cmd cmp docker git python3 find install readlink stat
    assert_repo_state
    assert_clean_worktree
    assert_source_date_epoch
    prepare_execution_contract
    resolve_image
    activate_online_snapshot
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
    [ -n "$KEYSTORE" ] && [ -f "$KEYSTORE" ] || die "set ANDROID_KEYSTORE to the stable RSA-4096 keystore (R-B2) — generate it once with scripts/gen-android-keystore.sh; Android refuses to install an unsigned APK"
    [ -n "$KEYSTORE_PASS_FILE" ] && [ -f "$KEYSTORE_PASS_FILE" ] || die "set ANDROID_KEYSTORE_PASS_FILE (password via file, never env/argv — R-B2)"
    assert_private_signing_files
    assert_keystore_properties
    log "preflight OK — building aarch64 .apk in $IMAGE_ID, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

# assert_keystore_properties: R-B2 mandates a SPECIFIC key (RSA 4096-bit, SHA256withRSA, fixed alias).
# A wrong key silently signs the release, and Android WELDS app identity to the signing key — a wrong
# key at first release is PERMANENT (rotation = a data-wiping reinstall). So assert the key's
# PROPERTIES, not just its existence. keytool runs in the build IMAGE (the host may have no JDK); the
# store password is fed on keytool's stdin (never argv/env — both leak via /proc, per the R-B2 note).
assert_keystore_properties() {
    local info fingerprint
    assert_private_docker_config
    info="$(docker run --rm --network=none \
        --user "$BUILD_UID:$BUILD_GID" \
        -v "$KEYSTORE:/ks/keystore.jks:ro" -v "$KEYSTORE_PASS_FILE:/ks/pass:ro" "$IMAGE_ID" \
        bash -c 'keytool -J-Duser.language=en -J-Duser.country=US -list -v -keystore /ks/keystore.jks -alias "'"$KEY_ALIAS"'" 2>/dev/null < /ks/pass')" \
        || die "android keystore: alias '$KEY_ALIAS' not found, or wrong password (R-B2) — regenerate with scripts/gen-android-keystore.sh"
    printf '%s' "$info" | grep -qE 'Signature algorithm name:[[:space:]]*SHA256withRSA' \
        || die "android keystore signature algorithm is not SHA256withRSA (R-B2) — regenerate: scripts/gen-android-keystore.sh"
    printf '%s' "$info" | grep -qiE '4096-bit RSA key' \
        || die "android keystore is not a 4096-bit RSA key (R-B2) — regenerate: scripts/gen-android-keystore.sh"
    fingerprint="$(printf '%s\n' "$info" | certificate_fingerprint_from_keytool)" \
        || die "android keystore did not expose exactly one canonical SHA-256 certificate fingerprint"
    [ "$fingerprint" = "$ANDROID_SIGNING_CERT_SHA256" ] \
        || die "android keystore certificate does not match ANDROID_SIGNING_CERT_SHA256"
    log "android keystore OK: pinned certificate $fingerprint"
}

verify_apk_certificate() {
    local apk="$1" resolved
    resolved="$(readlink -f -- "$apk" 2>/dev/null)" \
        || die "cannot resolve APK path: $apk"
    [ -f "$resolved" ] && [ ! -L "$apk" ] && [ -s "$resolved" ] \
        || die "APK must be a regular non-empty non-symlink file"
    verify_active_online_snapshot
    if ! docker run --rm --network=none \
        --user "$BUILD_UID:$BUILD_GID" \
        -e ANDROID_MIN_SDK="$ANDROID_MIN_SDK" \
        -e ANDROID_SIGNING_CERT_SHA256="$ANDROID_SIGNING_CERT_SHA256" \
        -v "$resolved:/verify/app.apk:ro" \
        -v "$ONLINE_DIR:/online:ro" \
        "$IMAGE_ID" bash -euo pipefail -c '
            export PATH="/online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/:$PATH"
            output="$(apksigner verify -Werr --min-sdk-version "$ANDROID_MIN_SDK" --print-certs /verify/app.apk)"
            observed="$(printf "%s\n" "$output" | awk -F: '\''
                /^Signer #1 certificate SHA-256 digest:/ {
                    value = $2
                    gsub(/[[:space:]:]/, "", value)
                    print toupper(value)
                    count++
                }
                END { if (count != 1) exit 1 }
            '\'')"
            [ "$observed" = "$ANDROID_SIGNING_CERT_SHA256" ]
        '; then
        verify_active_online_snapshot
        die "APK signing certificate does not match ANDROID_SIGNING_CERT_SHA256"
    fi
    verify_active_online_snapshot
}

build_apk() {
    log "building unsigned aarch64 .apk (features flutter — software codec, §3.2 arm64-android)"
    verify_active_online_snapshot
    if ! docker run --rm \
        --name rustdesk-fork-harness-apk \
        --network=none \
        --user "$BUILD_UID:$BUILD_GID" \
        -e SOURCE_DATE_EPOCH \
        -e RUSTDESK_CANARY_OFFLINE=1 \
        -e APK_MODE=offline \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online:ro" \
        -w /src \
        "$IMAGE_ID" \
        bash /src/scripts/android-apk-build.sh; then
        verify_active_online_snapshot
        die "Android build container failed"
    fi
    verify_active_online_snapshot
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
    # Android 7+ only: v2/v3 protect the whole APK, including runtime META-INF resources.
    # Password from the mounted file, never on argv: apksigner reads it via the file: provider.
    log "signing the APK with the stable local key (alias $KEY_ALIAS, R-B2)"
    verify_active_online_snapshot
    if ! docker run --rm \
        --network=none \
        --user "$BUILD_UID:$BUILD_GID" \
        -v "$REPO_ROOT:/src:ro" \
        -v "$OUT_DIR:/out" \
        -v "$KEYSTORE:/ks/keystore.jks:ro" \
        -v "$KEYSTORE_PASS_FILE:/ks/pass:ro" \
        -v "$ONLINE_DIR:/online:ro" \
        -e ANDROID_MIN_SDK="$ANDROID_MIN_SDK" \
        -e ANDROID_SIGNING_CERT_SHA256="$ANDROID_SIGNING_CERT_SHA256" \
        "$IMAGE_ID" \
        bash -euo pipefail -c '
            export PATH="/online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/:$PATH"
            apksigner sign --ks /ks/keystore.jks --ks-key-alias '"$KEY_ALIAS"' \
                --ks-pass file:/ks/pass \
                --min-sdk-version "$ANDROID_MIN_SDK" \
                --v1-signing-enabled false \
                --v2-signing-enabled true \
                --v3-signing-enabled true \
                --out /out/rustdesk-arm64.apk /out/rustdesk-arm64-unsigned.apk
            verify_output="$(apksigner verify -Werr --min-sdk-version "$ANDROID_MIN_SDK" --verbose /out/rustdesk-arm64.apk)"
            printf "%s\n" "$verify_output"
            printf "%s\n" "$verify_output" | grep -qF "Verified using v1 scheme (JAR signing): false"
            printf "%s\n" "$verify_output" | grep -qF "Verified using v2 scheme (APK Signature Scheme v2): true"
            printf "%s\n" "$verify_output" | grep -qF "Verified using v3 scheme (APK Signature Scheme v3): true"
            ! printf "%s\n" "$verify_output" | grep -qF "not protected by signature"
            cert_output="$(apksigner verify -Werr --min-sdk-version "$ANDROID_MIN_SDK" --print-certs /out/rustdesk-arm64.apk)"
            cert_sha256="$(printf "%s\n" "$cert_output" | awk -F: '\''
                /^Signer #1 certificate SHA-256 digest:/ {
                    value = $2
                    gsub(/[[:space:]:]/, "", value)
                    print toupper(value)
                    count++
                }
                END { if (count != 1) exit 1 }
            '\'')"
            [ "$cert_sha256" = "$ANDROID_SIGNING_CERT_SHA256" ]
            python3 /src/scripts/verify-android-apk-manifest.py \
                --apk /out/rustdesk-arm64.apk \
                --aapt2 /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/aapt2
        '; then
        verify_active_online_snapshot
        die "Android signing container failed"
    fi
    verify_active_online_snapshot
    rm -f "$OUT_DIR/rustdesk-arm64-unsigned.apk"
    sha256sum "$OUT_DIR/rustdesk-arm64.apk" | tee "$OUT_DIR/rustdesk-arm64.apk.sha256"
}

main() {
    if [ -n "$VERIFY_APK" ]; then
        require_cmd cmp docker git python3 find install readlink stat
        prepare_execution_contract
        resolve_image
        activate_online_snapshot
        verify_apk_certificate "$VERIFY_APK"
        log "APK certificate OK: $ANDROID_SIGNING_CERT_SHA256"
        return 0
    fi
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
    verify_apk_certificate "$OUT_DIR/rustdesk-arm64.apk"
    log "build-android.sh complete: $OUT_DIR/rustdesk-arm64.apk"
    log "NOTE: integrity to the device is the pinned SHA-256 over the trusted channel"
    log "      (R-B2); the signature is Android's install gate, not the trust anchor."
}

main

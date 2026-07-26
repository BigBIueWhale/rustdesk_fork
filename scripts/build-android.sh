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
umask 077

export PATH=/usr/bin:/bin
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] \
    || { echo "Android artifact building refuses host or container-root execution" >&2; exit 1; }
[ "$BUILD_GID" -ne 0 ] \
    || { echo "Android artifact building refuses a root primary group" >&2; exit 1; }

if [ -n "${ONLINE_DIR+x}" ]; then
    printf 'build-android: ONLINE_DIR is not an operator override; release snapshots use RUSTDESK_RELEASE_ONLINE_SNAPSHOT\n' >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
OUT_PARENT=""
OUT_DESTINATION=""
OUT_PARENT_ID=""
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
readonly PYTHON_BIN=/usr/bin/python3
VERIFY_APK=""
RELEASE_CHILD=0
ONLINE_SNAPSHOT_PARENT=""
OWNED_WORKSPACE=""
OWNED_WORKSPACE_ID=""
SOURCE_COMMIT=""
SOURCE_ARCHIVE=""
SOURCE_AUTHORITY_ROOT=""
BUILD_SOURCE_ROOT=""
BUILD_UNSIGNED_APK=""
PASS_A_SOURCE_ROOT=""
PASS_B_SOURCE_ROOT=""
PASS_A_APK=""
PASS_A_APK_ID=""
PASS_A_SHA256=""
PASS_B_SHA256=""
PENDING_RESULT=""
PENDING_RESULT_ID=""

case "${ANDROID_KEY_ALIAS:-rustdesk-fork}" in
    rustdesk-fork) ;;
    *) die "ANDROID_KEY_ALIAS is fixed to rustdesk-fork" ;;
esac
if [ "$#" -gt 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = --verify-apk ] \
        || die "usage: build-android.sh [--verify-apk APK]"
    VERIFY_APK="$2"
fi

cleanup_owned_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
        && ! remove_local_docker_authority; then
        warn "preserving changed private Android builder Docker authority: $OWNED_WORKSPACE"
        status=1
    elif [ -n "$OWNED_WORKSPACE" ]; then
        if ! remove_owned_workspace_exact; then
            warn "preserving changed private Android build workspace: $OWNED_WORKSPACE"
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup_owned_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

remove_owned_workspace_exact() {
    [ -n "$OWNED_WORKSPACE" ] && [ -n "$OWNED_WORKSPACE_ID" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$OWNED_WORKSPACE" \
            --expected-identity "$OWNED_WORKSPACE_ID" \
        || return 1
    { [ ! -e "$OWNED_WORKSPACE" ] && [ ! -L "$OWNED_WORKSPACE" ]; } || return 1
    OWNED_WORKSPACE=""
    OWNED_WORKSPACE_ID=""
}

record_output_parent_identity() {
    local metadata owner group mode device inode extra
    [ -d "$OUT_PARENT" ] && [ ! -L "$OUT_PARENT" ] \
        || die "Android output parent must be a real directory"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$OUT_PARENT" 2>/dev/null)" \
        || die "Android output-parent identity is unavailable"
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$BUILD_UID" ] \
        && [ "$group" = "$BUILD_GID" ] \
        && [ $((8#$mode & 8#700)) -eq $((8#700)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        || die "Android output parent does not grant only current-principal write authority"
    [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "Android output-parent identity is malformed"
    OUT_PARENT_ID="$device:$inode"
}

prepare_output_contract() {
    local planned_parent planned_destination
    case "$OUT_DIR" in
        /*) ;;
        *) die "Android output directory must be absolute" ;;
    esac
    planned_parent="$(/usr/bin/dirname -- "$OUT_DIR")" \
        || die "cannot derive Android output parent"
    planned_destination="$(/usr/bin/basename -- "$OUT_DIR")" \
        || die "cannot derive Android output destination"
    [ "$planned_parent" != / ] \
        || die "Android output parent must not be the filesystem root"
    [ -d "$planned_parent" ] && [ ! -L "$planned_parent" ] \
        || die "Android output parent must already be a real directory"
    OUT_PARENT="$(/usr/bin/readlink -f -- "$planned_parent" 2>/dev/null)" \
        || die "Android output parent cannot be resolved"
    [ "$OUT_PARENT" = "$planned_parent" ] \
        || die "Android output parent must be absolute, canonical, and non-symlinked"
    OUT_DESTINATION="$planned_destination"
    [ "$OUT_DIR" = "$OUT_PARENT/$OUT_DESTINATION" ] \
        || die "Android output directory must be one canonical parent edge"
    [[ "$OUT_DESTINATION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || die "Android output destination name is malformed"
    record_output_parent_identity
    { [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; } \
        || die "Android output directory must be absent for no-clobber publication"
}

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
    current="$(git -c core.hooksPath=/dev/null -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cannot resolve the exact Android source commit"
    [[ "$current" =~ ^[0-9a-f]{40}$ ]] \
        || die "Android source commit must be one full lowercase commit ID"
    OWNED_WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX)" \
        || die "cannot create private Android build workspace"
    chmod 0700 "$OWNED_WORKSPACE" \
        || die "cannot protect private Android build workspace"
    [ "$(/usr/bin/readlink -f -- "$OWNED_WORKSPACE" 2>/dev/null)" = "$OWNED_WORKSPACE" ] \
        || die "private Android build workspace is not canonical"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$OWNED_WORKSPACE" 2>/dev/null)" = "$BUILD_UID:$BUILD_GID:700" ] \
        || die "private Android build workspace is not current-principal mode 0700"
    OWNED_WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i' -- "$OWNED_WORKSPACE" 2>/dev/null)" \
        || die "private Android build-workspace identity is unavailable"
    [[ "$OWNED_WORKSPACE_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || die "private Android build-workspace identity is malformed"
    initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "android-builder"
    if [ -n "${RELEASE_SRC_COMMIT:-}" ]; then
        RELEASE_CHILD=1
        [[ "$RELEASE_SRC_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            || die "RELEASE_SRC_COMMIT must be one full lowercase commit ID"
        [ "$current" = "$RELEASE_SRC_COMMIT" ] || die "release-child source commit does not equal HEAD"
        [ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
        [ -n "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "release child requires RELEASE_DOCKER_IMAGE_ID"
        ONLINE_SNAPSHOT_PARENT="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
    else
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "RUSTDESK_RELEASE_ONLINE_SNAPSHOT is release-internal"
        [ -z "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "RELEASE_DOCKER_IMAGE_ID is release-internal"
    fi
    SOURCE_COMMIT="$current"
}

prepare_source_snapshot() {
    local invalid_tree_entry
    SOURCE_ARCHIVE="$OWNED_WORKSPACE/source.tar"
    SOURCE_AUTHORITY_ROOT="$OWNED_WORKSPACE/source-authority"
    invalid_tree_entry="$(
        git -c core.hooksPath=/dev/null -C "$REPO_ROOT" ls-tree -rz --full-tree "$SOURCE_COMMIT" \
            | "$PYTHON_BIN" -c '
import sys

for entry in sys.stdin.buffer.read().split(b"\0"):
    if not entry:
        continue
    metadata, path = entry.split(b"\t", 1)
    mode = metadata.split(b" ", 1)[0]
    if mode not in (b"100644", b"100755"):
        print("{} {}".format(mode.decode("ascii", "replace"), path.decode("utf-8", "replace")))
        break
'
    )" || die "cannot inspect the exact Android source tree"
    [ -z "$invalid_tree_entry" ] \
        || die "Android source commit contains a symlink or special entry: $invalid_tree_entry"
    install -d -m 0700 "$SOURCE_AUTHORITY_ROOT"
    git -c core.hooksPath=/dev/null -C "$REPO_ROOT" archive --format=tar "$SOURCE_COMMIT" \
        >"$SOURCE_ARCHIVE" \
        || die "cannot archive the exact Android source commit"
    [ -s "$SOURCE_ARCHIVE" ] && [ ! -L "$SOURCE_ARCHIVE" ] \
        || die "Android source archive is missing or invalid"
    chmod 0400 "$SOURCE_ARCHIVE"
    tar --extract --file="$SOURCE_ARCHIVE" --directory="$SOURCE_AUTHORITY_ROOT" \
        || die "cannot extract the Android source authority snapshot"
    invalid_tree_entry="$(find "$SOURCE_AUTHORITY_ROOT" \
        \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit \
    )" || die "cannot inspect the Android source authority snapshot"
    [ -z "$invalid_tree_entry" ] \
        || die "Android source authority contains a symlink or special file: $invalid_tree_entry"
    # The admitted Git tree distinguishes only regular versus executable files. Do not let the
    # archive producer's or extractor's umask decide whether source is writable:
    # directories/executables are 0555 and ordinary files are 0444.
    chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"
}

prepare_build_source() {
    local label="$1" invalid_tree_entry
    case "$label" in
        pass-a|pass-b) ;;
        *) die "unknown Android build-source pass: $label" ;;
    esac
    BUILD_SOURCE_ROOT="$OWNED_WORKSPACE/source-$label"
    [ ! -e "$BUILD_SOURCE_ROOT" ] && [ ! -L "$BUILD_SOURCE_ROOT" ] \
        || die "Android writable source path was not freshly absent"
    install -d -m 0700 "$BUILD_SOURCE_ROOT"
    tar --extract --file="$SOURCE_ARCHIVE" --directory="$BUILD_SOURCE_ROOT" \
        || die "cannot extract a fresh Android writable build snapshot"
    # The build copy has one canonical Git-derived mode policy too:
    # directories/executables are 0755 and ordinary files are 0644.
    chmod -R u=rwX,go=rX "$BUILD_SOURCE_ROOT"
    invalid_tree_entry="$(find "$BUILD_SOURCE_ROOT" \
        \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit \
    )" || die "cannot inspect the Android writable build snapshot"
    [ -z "$invalid_tree_entry" ] \
        || die "Android writable source contains a symlink or special file: $invalid_tree_entry"
    "$PYTHON_BIN" "$SOURCE_AUTHORITY_ROOT/scripts/verify-android-build-source.py" \
        --reference "$SOURCE_AUTHORITY_ROOT" --candidate "$BUILD_SOURCE_ROOT" \
        || die "Android writable source does not match the exact commit snapshot"
    case "$label" in
        pass-a) PASS_A_SOURCE_ROOT="$BUILD_SOURCE_ROOT" ;;
        pass-b) PASS_B_SOURCE_ROOT="$BUILD_SOURCE_ROOT" ;;
    esac
}

verify_build_source_unchanged() {
    local candidate="$1" label="$2"
    "$PYTHON_BIN" "$SOURCE_AUTHORITY_ROOT/scripts/verify-android-build-source.py" \
        --reference "$SOURCE_AUTHORITY_ROOT" --candidate "$candidate" --allow-extras \
        || die "$label Android build changed an exact-commit source input"
}

verify_all_build_sources_unchanged() {
    [ -n "$PASS_A_SOURCE_ROOT" ] \
        || die "Android pass-A source authority is unavailable"
    verify_build_source_unchanged "$PASS_A_SOURCE_ROOT" pass-a
    if [ -n "$PASS_B_SOURCE_ROOT" ]; then
        verify_build_source_unchanged "$PASS_B_SOURCE_ROOT" pass-b
    fi
}

android_docker_run() {
    local_docker run --rm --pull=never --network=none --read-only \
        --user "$BUILD_UID:$BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        "$@"
}

prepare_pass_output() {
    local output="$1"
    [ ! -e "$output" ] && [ ! -L "$output" ] \
        || die "Android private pass output already exists: $output"
    install -d -m 0700 "$output"
    assert_private_directory "$output" "Android private pass output"
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
    assert_local_docker_authority \
        || die "Android builder local Docker authority changed"
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

assert_private_signing_files() {
    "$PYTHON_BIN" - "$KEYSTORE" "$KEYSTORE_PASS_FILE" "$BUILD_UID" <<'PY'
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
    require_cmd basename cmp dirname git find grep install readlink sha256sum stat tar
    [ -x "$PYTHON_BIN" ] || die "trusted Python interpreter is unavailable at $PYTHON_BIN"
    [ "${ALLOW_DIRTY_TREE:-0}" = 0 ] \
        || die "the Android artifact builder accepts only an exact clean commit; use a developer check for working-tree experiments"
    assert_repo_state
    assert_clean_worktree
    assert_source_date_epoch
    prepare_output_contract
    prepare_execution_contract
    prepare_source_snapshot
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
    assert_local_docker_authority \
        || die "Android builder local Docker authority changed before keytool preflight"
    info="$(android_docker_run \
        --pids-limit=32 --memory=512m --memory-swap=512m --cpus=1 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
        --env HOME=/tmp/home \
        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks,readonly" \
        --mount "type=bind,source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly" \
        "$IMAGE_ID" /bin/bash --noprofile --norc -c \
        'mkdir -p "$HOME"; keytool -J-Duser.language=en -J-Duser.country=US -list -v -keystore /ks/keystore.jks -alias "'"$KEY_ALIAS"'" 2>/dev/null < /ks/pass')" \
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

verify_apk_artifact() {
    local apk="$1" resolved
    resolved="$(readlink -f -- "$apk" 2>/dev/null)" \
        || die "cannot resolve APK path: $apk"
    [ -f "$resolved" ] && [ ! -L "$apk" ] && [ -s "$resolved" ] \
        || die "APK must be a regular non-empty non-symlink file"
    verify_active_online_snapshot
    if ! android_docker_run \
        --pids-limit=128 --memory=4g --memory-swap=4g --cpus=2 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=2g \
        --env HOME=/tmp/home \
        --env ANDROID_MIN_SDK="$ANDROID_MIN_SDK" \
        --env ANDROID_SIGNING_CERT_SHA256="$ANDROID_SIGNING_CERT_SHA256" \
        --mount "type=bind,source=$resolved,target=/verify/app.apk,readonly" \
        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py,readonly" \
        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-mobile-key-artifact.py,target=/checks/verify-android-mobile-key-artifact.py,readonly" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly" \
        "$IMAGE_ID" /bin/bash --noprofile --norc -euo pipefail -c '
            mkdir -p "$HOME"
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
            python3 /checks/verify-android-apk-manifest.py \
                --apk /verify/app.apk \
                --aapt2 /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/aapt2
            python3 /checks/verify-android-mobile-key-artifact.py \
                --apk /verify/app.apk \
                --dexdump /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/dexdump \
                --readelf /usr/bin/readelf
        '; then
        verify_active_online_snapshot
        die "APK certificate or signed-artifact authority verification failed"
    fi
    verify_active_online_snapshot
}

build_apk() {
    local pass_output="$1" pass="$2"
    log "building unsigned aarch64 .apk (features flutter — software codec, §3.2 arm64-android)"
    verify_active_online_snapshot
    prepare_build_source "$pass"
    verify_build_source_unchanged "$BUILD_SOURCE_ROOT" "$pass"
    if ! android_docker_run \
        --pids-limit=512 --memory=12g --memory-swap=12g --cpus=4 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g \
        --env SOURCE_DATE_EPOCH \
        --env RUSTDESK_CANARY_OFFLINE=1 \
        --env APK_MODE=offline \
        --mount "type=bind,source=$BUILD_SOURCE_ROOT,target=/src" \
        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly" \
        --workdir /src \
        "$IMAGE_ID" \
        /bin/bash /authority/android-apk-build.sh; then
        verify_active_online_snapshot
        die "Android build container failed"
    fi
    verify_active_online_snapshot
    verify_build_source_unchanged "$BUILD_SOURCE_ROOT" "$pass"
    # The docker run built into the bind-mounted flutter/build (android-apk-build.sh wiped it up front,
    # so no prior-run APK survives to be mispicked). Assert the produced APK explicitly: the old
    # `apk="$(ls…)" || die` was DEAD CODE (the assignment's exit status is `head`'s = always 0), so a
    # missing APK fell through to a confusing `cp ''` under set -e instead of this loud message.
    local -a apks=()
    mapfile -t apks < <(find "$BUILD_SOURCE_ROOT/flutter/build/app/outputs/flutter-apk" \
        -maxdepth 1 -type f -name '*arm64*release*.apk' -print 2>/dev/null | LC_ALL=C sort)
    [ "${#apks[@]}" -eq 1 ] \
        || die "expected exactly one arm64 release APK from the in-container build, found ${#apks[@]}"
    BUILD_UNSIGNED_APK="${apks[0]}"
}

sign_apk() {
    local pass_output="$1" unsigned_apk="$2"
    [ -f "$unsigned_apk" ] && [ ! -L "$unsigned_apk" ] && [ -s "$unsigned_apk" ] \
        || die "private unsigned Android APK is unavailable"
    # Android 7+ only: v2/v3 protect the whole APK, including runtime META-INF resources.
    # Password from the mounted file, never on argv: apksigner reads it via the file: provider.
    log "signing the APK with the stable local key (alias $KEY_ALIAS, R-B2)"
    verify_active_online_snapshot
    if ! android_docker_run \
        --pids-limit=128 --memory=4g --memory-swap=4g --cpus=2 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=2g \
        --env HOME=/tmp/home \
        --env ANDROID_MIN_SDK="$ANDROID_MIN_SDK" \
        --env ANDROID_SIGNING_CERT_SHA256="$ANDROID_SIGNING_CERT_SHA256" \
        --mount "type=bind,source=$pass_output,target=/out" \
        --mount "type=bind,source=$unsigned_apk,target=/in/rustdesk-arm64-unsigned.apk,readonly" \
        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks,readonly" \
        --mount "type=bind,source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly" \
        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py,readonly" \
        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-mobile-key-artifact.py,target=/checks/verify-android-mobile-key-artifact.py,readonly" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly" \
        "$IMAGE_ID" \
        /bin/bash --noprofile --norc -euo pipefail -c '
            mkdir -p "$HOME"
            export PATH="/online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/:$PATH"
            apksigner sign --ks /ks/keystore.jks --ks-key-alias '"$KEY_ALIAS"' \
                --ks-pass file:/ks/pass \
                --min-sdk-version "$ANDROID_MIN_SDK" \
                --v1-signing-enabled false \
                --v2-signing-enabled true \
                --v3-signing-enabled true \
                --out /out/rustdesk-arm64.apk /in/rustdesk-arm64-unsigned.apk
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
            python3 /checks/verify-android-apk-manifest.py \
                --apk /out/rustdesk-arm64.apk \
                --aapt2 /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/aapt2
            python3 /checks/verify-android-mobile-key-artifact.py \
                --apk /out/rustdesk-arm64.apk \
                --dexdump /online/android-sdk/build-tools/'"${ANDROID_BUILD_TOOLS}"'/dexdump \
                --readelf /usr/bin/readelf
        '; then
        verify_active_online_snapshot
        die "Android signing container failed"
    fi
    verify_active_online_snapshot
    (
        cd "$pass_output"
        sha256sum rustdesk-arm64.apk >rustdesk-arm64.apk.sha256
    )
    chmod 0400 \
        "$pass_output/rustdesk-arm64.apk" \
        "$pass_output/rustdesk-arm64.apk.sha256" \
        || die "cannot seal the private Android result"
}

assert_exact_private_result_inventory() {
    local pass_output="$1" pass="$2"
    local apk="$pass_output/rustdesk-arm64.apk"
    local checksum="$pass_output/rustdesk-arm64.apk.sha256"
    local nullglob_was_set=0 dotglob_was_set=0
    local -a entries=()

    shopt -q nullglob && nullglob_was_set=1
    shopt -q dotglob && dotglob_was_set=1
    shopt -s nullglob dotglob
    entries=("$pass_output"/*)
    [ "$nullglob_was_set" -eq 1 ] || shopt -u nullglob
    [ "$dotglob_was_set" -eq 1 ] || shopt -u dotglob
    [ "${#entries[@]}" -eq 2 ] \
        && [ -e "$apk" ] && [ ! -L "$apk" ] \
        && [ -e "$checksum" ] && [ ! -L "$checksum" ] \
        || die "$pass Android result is not the exact APK/checksum pair"
}

validate_private_result() {
    local pass_output="$1" pass="$2"
    local apk="$pass_output/rustdesk-arm64.apk"
    local checksum="$pass_output/rustdesk-arm64.apk.sha256"
    local metadata checksum_metadata
    local owner group mode links size device inode mtime ctime extra
    local checksum_owner checksum_group checksum_mode checksum_links checksum_size
    local checksum_device checksum_inode checksum_mtime checksum_ctime checksum_extra
    local checksum_line before_sha256 after_sha256 after_metadata after_checksum_metadata
    local after_checksum_line

    case "$pass" in
        pass-a|pass-b) ;;
        *) die "unknown private Android result pass: $pass" ;;
    esac
    assert_private_directory "$pass_output" "$pass Android result"
    assert_exact_private_result_inventory "$pass_output" "$pass"

    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i:%Y:%Z' -- "$apk" 2>/dev/null)" \
        || die "cannot inspect $pass Android APK"
    IFS=: read -r owner group mode links size device inode mtime ctime extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$BUILD_UID" ] \
        && [ "$group" = "$BUILD_GID" ] \
        && [ "$mode" = 400 ] \
        && [ "$links" = 1 ] \
        && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
        && [ "$size" -le 4294967296 ] \
        && [[ "$device" =~ ^[0-9]+$ ]] \
        && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "$pass Android APK metadata is unsafe"

    checksum_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i:%Y:%Z' -- "$checksum" 2>/dev/null)" \
        || die "cannot inspect $pass Android checksum"
    IFS=: read -r checksum_owner checksum_group checksum_mode checksum_links checksum_size \
        checksum_device checksum_inode checksum_mtime checksum_ctime checksum_extra \
        <<<"$checksum_metadata"
    [ -z "$checksum_extra" ] \
        && [ "$checksum_owner" = "$BUILD_UID" ] \
        && [ "$checksum_group" = "$BUILD_GID" ] \
        && [ "$checksum_mode" = 400 ] \
        && [ "$checksum_links" = 1 ] \
        && [ "$checksum_size" = 85 ] \
        && [[ "$checksum_device" =~ ^[0-9]+$ ]] \
        && [[ "$checksum_inode" =~ ^[1-9][0-9]*$ ]] \
        || die "$pass Android checksum metadata is unsafe"

    checksum_line="$(<"$checksum")" \
        || die "cannot read $pass Android checksum"
    [[ "$checksum_line" =~ ^([0-9a-f]{64})\ \ rustdesk-arm64\.apk$ ]] \
        || die "$pass Android checksum is not canonical"
    before_sha256="$(/usr/bin/sha256sum -- "$apk")" \
        || die "cannot hash $pass Android APK"
    before_sha256="${before_sha256%% *}"
    [ "$before_sha256" = "${BASH_REMATCH[1]}" ] \
        || die "$pass Android APK does not match its checksum"

    verify_apk_artifact "$apk"

    assert_exact_private_result_inventory "$pass_output" "$pass"
    after_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i:%Y:%Z' -- "$apk" 2>/dev/null)" \
        || die "cannot re-inspect $pass Android APK"
    after_checksum_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i:%Y:%Z' -- "$checksum" 2>/dev/null)" \
        || die "cannot re-inspect $pass Android checksum"
    after_checksum_line="$(<"$checksum")" \
        || die "cannot reread $pass Android checksum"
    after_sha256="$(/usr/bin/sha256sum -- "$apk")" \
        || die "cannot rehash $pass Android APK"
    after_sha256="${after_sha256%% *}"
    [ "$after_metadata" = "$metadata" ] \
        && [ "$after_checksum_metadata" = "$checksum_metadata" ] \
        && [ "$after_checksum_line" = "$checksum_line" ] \
        && [ "$after_sha256" = "$before_sha256" ] \
        || die "$pass Android result changed while it was verified"

    case "$pass" in
        pass-a)
            PASS_A_APK="$apk"
            PASS_A_APK_ID="$device:$inode"
            PASS_A_SHA256="$before_sha256"
            ;;
        pass-b)
            PASS_B_SHA256="$before_sha256"
            ;;
    esac
}

prepare_pending_result() {
    local authority extra
    [ -n "$PASS_A_APK" ] && [ -n "$PASS_A_APK_ID" ] && [ -n "$PASS_A_SHA256" ] \
        || die "validated Android pass-A authority is incomplete"
    [ -n "$OUT_PARENT" ] && [ -n "$OUT_PARENT_ID" ] && [ -n "$OUT_DESTINATION" ] \
        || die "Android output-parent authority is incomplete"
    authority="$(/usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py" \
            --prepare \
            --artifact-kind android-arm64 \
            --source "$PASS_A_APK" \
            --source-identity "$PASS_A_APK_ID" \
            --source-sha256 "$PASS_A_SHA256" \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --destination "$OUT_DESTINATION")" \
        || die "Android output candidate preparation failed"
    read -r PENDING_RESULT PENDING_RESULT_ID extra <<<"$authority"
    [[ "$PENDING_RESULT" =~ ^\.android-output-pending-[0-9a-f]{64}$ ]] \
        && [[ "$PENDING_RESULT_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        && [ -z "$extra" ] \
        || die "pending Android output authority is malformed"
}

publish_result() {
    PENDING_RESULT=""
    PENDING_RESULT_ID=""
    verify_active_online_snapshot
    verify_all_build_sources_unchanged
    assert_local_docker_authority \
        || die "Android builder Docker authority changed before retirement"
    remove_local_docker_authority \
        || die "Android builder Docker authority could not retire before publication"
    prepare_pending_result
    remove_owned_workspace_exact \
        || die "private Android build workspace could not retire before final publication"
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py" \
            --commit \
            --artifact-kind android-arm64 \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --pending "$PENDING_RESULT" \
            --pending-identity "$PENDING_RESULT_ID" \
            --destination "$OUT_DESTINATION"
}

main() {
    if [ -n "$VERIFY_APK" ]; then
        require_cmd cmp git find grep install readlink sha256sum stat tar
        [ -x "$PYTHON_BIN" ] || die "trusted Python interpreter is unavailable at $PYTHON_BIN"
        prepare_execution_contract
        prepare_source_snapshot
        resolve_image
        activate_online_snapshot
        verify_apk_artifact "$VERIFY_APK"
        log "APK certificate and authority contents OK: $ANDROID_SIGNING_CERT_SHA256"
        return 0
    fi
    preflight
    local pass_a="$OWNED_WORKSPACE/pass-a"
    prepare_pass_output "$pass_a"
    build_apk "$pass_a" pass-a
    sign_apk "$pass_a" "$BUILD_UNSIGNED_APK"
    validate_private_result "$pass_a" pass-a
    # R-B2 double-build determinism (DEFAULT — the correct build proves its OWN reproducibility).
    # A second build of identical source MUST produce a byte-identical SIGNED APK, or the recorded
    # SHA is unfalsifiable. build-debian.sh makes this assertion for the .deb; mirror it here so the
    # DEFAULT `build-android.sh` invocation self-proves A==B and DIES on any drift — assume nothing,
    # trust nothing. Each pass gets a freshly extracted exact-commit writable tree; the inner R-B9 cleanup
    # remains defense in depth. (Set DOUBLE_BUILD=0 only for an explicit single-pass diagnostic or when the
    # enclosing release transaction supplies the two independent exact-commit snapshots.)
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        local pass_b="$OWNED_WORKSPACE/pass-b"
        prepare_pass_output "$pass_b"
        build_apk "$pass_b" pass-b
        sign_apk "$pass_b" "$BUILD_UNSIGNED_APK"
        validate_private_result "$pass_b" pass-b
        [ "$PASS_A_SHA256" = "$PASS_B_SHA256" ] || die "R-B2 double-build APK SHA mismatch ($PASS_A_SHA256 vs $PASS_B_SHA256) — the APK is NOT reproducible; fix SOURCE_DATE_EPOCH / apksigner determinism before release"
        log "R-B2 double-build determinism OK (A==B): $PASS_A_SHA256"
    fi
    publish_result
}

main

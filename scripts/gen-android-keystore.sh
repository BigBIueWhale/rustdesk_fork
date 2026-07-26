#!/usr/bin/env bash
# scripts/gen-android-keystore.sh — generate THE stable R-B2 Android signing key, once (§12.1).
#
# Android welds app identity to the first signing key. This tool therefore refuses root execution,
# mutable image names, alias overrides, existing output, public destination directories, and broad
# host mounts. Random-password generation, key generation, and independent key inspection all run
# in the already-present immutable Android builder with no network or ambient container authority.
#
# Usage: scripts/gen-android-keystore.sh [OUT_JKS PASS_FILE]
# With no arguments, the protected default paths from scripts/lib.sh are used. OUT_JKS and
# PASS_FILE must be distinct canonical absolute paths in the same current-UID mode-0700 directory;
# that directory and its parent are created mode 0700 when absent. The alias is always
# "rustdesk-fork". The keystore is never overwritten.
set -euo pipefail
umask 077

export PATH=/usr/bin:/bin
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] \
    || { echo "Android signing identity generation refuses host or container-root execution" >&2; exit 1; }
[ "$BUILD_GID" -ne 0 ] \
    || { echo "Android signing identity generation refuses a root primary group" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly INNER_SOURCE="$SCRIPT_DIR/android-keystore-generate.sh"
readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"
readonly KEY_ALIAS=rustdesk-fork

case "$#" in
    0)
        OUT_JKS="$DEFAULT_ANDROID_KEYSTORE"
        PASS_FILE="$DEFAULT_ANDROID_KEYSTORE_PASS_FILE"
        ;;
    2)
        OUT_JKS="$1"
        PASS_FILE="$2"
        ;;
    *)
        die "usage: gen-android-keystore.sh [OUT_JKS PASS_FILE] (the alias is fixed to rustdesk-fork)"
        ;;
esac

[ -f "$INNER_SOURCE" ] && [ ! -L "$INNER_SOURCE" ] \
    || die "Android keystore inner program must be a non-symlink regular file"
case "${ANDROID_KEY_ALIAS:-$KEY_ALIAS}" in
    "$KEY_ALIAS") ;;
    *) die "ANDROID_KEY_ALIAS is fixed to $KEY_ALIAS" ;;
esac

for value in "$OUT_JKS" "$PASS_FILE"; do
    case "$value" in
        /*) ;;
        *) die "Android signing paths must be absolute: $value" ;;
    esac
    case "$value" in
        *$'\n'*|*$'\r'*) die "Android signing paths must not contain line breaks" ;;
        *,*) die "Android signing paths must not contain a Docker mount delimiter: $value" ;;
    esac
    [ "$(readlink -m -- "$value")" = "$value" ] \
        || die "Android signing paths must be canonical and contain no symlink component: $value"
done
[ "$OUT_JKS" != "$PASS_FILE" ] || die "the keystore and password paths must be distinct"
[ ! -e "$OUT_JKS" ] && [ ! -L "$OUT_JKS" ] \
    || die "refusing to overwrite existing keystore: $OUT_JKS — regenerating breaks in-place upgrades"

readonly SIGNING_DIR="$(dirname -- "$OUT_JKS")"
readonly PASS_DIR="$(dirname -- "$PASS_FILE")"
[ "$SIGNING_DIR" = "$PASS_DIR" ] \
    || die "the keystore and password must share one protected directory"
readonly SIGNING_PARENT="$(dirname -- "$SIGNING_DIR")"
readonly SIGNING_ANCESTOR="$(dirname -- "$SIGNING_PARENT")"
[ -d "$SIGNING_ANCESTOR" ] && [ ! -L "$SIGNING_ANCESTOR" ] \
    || die "the signing directory's existing ancestor must be a real directory: $SIGNING_ANCESTOR"
[ "$(readlink -f -- "$SIGNING_ANCESTOR")" = "$SIGNING_ANCESTOR" ] \
    || die "the signing directory's existing ancestor must be canonical: $SIGNING_ANCESTOR"

assert_private_directory() {
    local path="$1" label="$2" metadata resolved
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory: $path"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved: $path"
    [ "$resolved" = "$path" ] || die "$label must be canonical and non-symlinked: $path"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is unavailable: $path"
    [ "$metadata" = "$BUILD_UID:700" ] \
        || die "$label must be a current-UID mode-0700 directory: $path"
}

create_private_directory() {
    local path="$1" label="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        mkdir -m 0700 -- "$path" || die "cannot create $label: $path"
    fi
    assert_private_directory "$path" "$label"
}

assert_secret_file() {
    local path="$1" label="$2" metadata
    [ -f "$path" ] && [ ! -L "$path" ] || die "$label must be a non-symlink regular file: $path"
    [ "$(readlink -f -- "$path")" = "$path" ] \
        || die "$label must be canonical and non-symlinked: $path"
    metadata="$(stat -c '%u:%a:%h:%s' -- "$path" 2>/dev/null)" \
        || die "$label is unavailable: $path"
    case "$metadata" in
        "$BUILD_UID:600:1:"[1-9]*) ;;
        *) die "$label must be a non-empty current-UID mode-0600 single-link file: $path" ;;
    esac
}

create_private_directory "$SIGNING_PARENT" "Android signing parent"
create_private_directory "$SIGNING_DIR" "Android signing directory"
if [ -e "$PASS_FILE" ] || [ -L "$PASS_FILE" ]; then
    assert_secret_file "$PASS_FILE" "Android signing password"
fi

STAGE_ROOT="$(mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX")" \
    || die "cannot create a private Android keystore staging directory"
readonly STAGE_ROOT
chmod 0700 "$STAGE_ROOT"

cleanup_stage() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
        && ! remove_local_docker_authority; then
        warn "preserving changed private Android keystore Docker authority: $STAGE_ROOT"
        status=1
    elif [ -d "$STAGE_ROOT" ]; then
        if ! chmod -R u+rwX "$STAGE_ROOT" 2>/dev/null \
            || ! rm -rf -- "$STAGE_ROOT"; then
            status=1
        fi
    fi
    exit "$status"
}
trap cleanup_stage EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0700 \
    "$STAGE_ROOT/authority" \
    "$STAGE_ROOT/output" \
    "$STAGE_ROOT/secret"
install -m 0400 -- "$INNER_SOURCE" "$STAGE_ROOT/authority/android-keystore-generate.sh"
cmp -s -- "$INNER_SOURCE" "$STAGE_ROOT/authority/android-keystore-generate.sh" \
    || die "private Android keystore inner-program snapshot differs from its source"
initialize_local_docker_authority "$STAGE_ROOT/docker-config" "android-keystore"

require_pinned_builder_image android-builder "$IMAGE_ID"

android_keystore_docker_run() {
    local_docker run --rm --pull=never --network=none --read-only \
        --user "$BUILD_UID:$BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        "$@"
}

generated_password=0
if [ ! -e "$PASS_FILE" ] && [ ! -L "$PASS_FILE" ]; then
    if ! android_keystore_docker_run \
        --pids-limit=32 --memory=256m --memory-swap=256m --cpus=1 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m \
        --mount "type=bind,source=$STAGE_ROOT/output,target=/out" \
        --mount "type=bind,source=$STAGE_ROOT/authority/android-keystore-generate.sh,target=/authority/android-keystore-generate.sh,readonly" \
        "$IMAGE_ID" /bin/bash --noprofile --norc \
        /authority/android-keystore-generate.sh password; then
        die "confined Android keystore password generation failed"
    fi
    [ ! -e "$STAGE_ROOT/secret/pass" ] && [ ! -L "$STAGE_ROOT/secret/pass" ] \
        || die "private password destination was not freshly absent"
    mv -- "$STAGE_ROOT/output/pass" "$STAGE_ROOT/secret/pass" \
        || die "cannot isolate the generated password from writable key output"
    PASS_INPUT="$STAGE_ROOT/secret/pass"
    generated_password=1
else
    assert_secret_file "$PASS_FILE" "Android signing password"
    PASS_INPUT="$PASS_FILE"
fi
readonly PASS_INPUT
assert_secret_file "$PASS_INPUT" "Android signing password input"
readonly PASS_STATE_BEFORE="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$PASS_INPUT")"
readonly PASS_SHA_BEFORE="$(sha256sum -- "$PASS_INPUT" | awk '{print $1}')"

log "generating the R-B2 Android key in a private stage (RSA 4096, SHA256withRSA, 10000 days, alias '$KEY_ALIAS')"
if ! android_keystore_docker_run \
    --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m \
    --env HOME=/tmp/home \
    --mount "type=bind,source=$STAGE_ROOT/output,target=/out" \
    --mount "type=bind,source=$PASS_INPUT,target=/authority/pass,readonly" \
    --mount "type=bind,source=$STAGE_ROOT/authority/android-keystore-generate.sh,target=/authority/android-keystore-generate.sh,readonly" \
    "$IMAGE_ID" /bin/bash --noprofile --norc \
    /authority/android-keystore-generate.sh keystore; then
    die "confined Android keystore generation failed"
fi

readonly STAGED_KEYSTORE="$STAGE_ROOT/output/keystore.jks"
assert_secret_file "$STAGED_KEYSTORE" "generated Android keystore"
readonly KEYSTORE_STATE_BEFORE="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$STAGED_KEYSTORE")"
readonly KEYSTORE_SHA_BEFORE="$(sha256sum -- "$STAGED_KEYSTORE" | awk '{print $1}')"
verification="$(
    android_keystore_docker_run \
        --pids-limit=32 --memory=512m --memory-swap=512m --cpus=1 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m \
        --env HOME=/tmp/home \
        --mount "type=bind,source=$STAGED_KEYSTORE,target=/authority/keystore.jks,readonly" \
        --mount "type=bind,source=$PASS_INPUT,target=/authority/pass,readonly" \
        --mount "type=bind,source=$STAGE_ROOT/authority/android-keystore-generate.sh,target=/authority/android-keystore-generate.sh,readonly" \
        "$IMAGE_ID" /bin/bash --noprofile --norc \
        /authority/android-keystore-generate.sh verify
)" || die "independent confined Android keystore verification failed"
[[ "$verification" =~ ^ANDROID_KEYSTORE_CERT_SHA256=[0-9A-F]{64}$ ]] \
    || die "Android keystore verifier returned a noncanonical certificate fingerprint"

assert_secret_file "$PASS_INPUT" "Android signing password input after generation"
[ "$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$PASS_INPUT")" = "$PASS_STATE_BEFORE" ] \
    || die "Android signing password identity or metadata changed during key generation"
[ "$(sha256sum -- "$PASS_INPUT" | awk '{print $1}')" = "$PASS_SHA_BEFORE" ] \
    || die "Android signing password bytes changed during key generation"
assert_secret_file "$STAGED_KEYSTORE" "generated Android keystore after verification"
[ "$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$STAGED_KEYSTORE")" = "$KEYSTORE_STATE_BEFORE" ] \
    || die "generated Android keystore identity or metadata changed during verification"
[ "$(sha256sum -- "$STAGED_KEYSTORE" | awk '{print $1}')" = "$KEYSTORE_SHA_BEFORE" ] \
    || die "generated Android keystore bytes changed during verification"

# Publish the password first, when this run generated it: a keystore must never become visible
# without its matching password. Hard links are same-filesystem, atomic, and no-clobber. The private
# staging links are removed only after filesystem synchronization, leaving each final secret at one link.
if [ "$generated_password" -eq 1 ]; then
    [ ! -e "$PASS_FILE" ] && [ ! -L "$PASS_FILE" ] \
        || die "password destination appeared during generation: $PASS_FILE"
    ln -- "$PASS_INPUT" "$PASS_FILE" \
        || die "cannot publish the generated password without clobbering: $PASS_FILE"
    sync -f -- "$PASS_FILE" || die "cannot synchronize the published Android password"
fi
[ ! -e "$OUT_JKS" ] && [ ! -L "$OUT_JKS" ] \
    || die "keystore destination appeared during generation: $OUT_JKS"
if ! ln -- "$STAGED_KEYSTORE" "$OUT_JKS"; then
    if [ "$generated_password" -eq 1 ]; then
        warn "the matching generated password was published at $PASS_FILE, but the keystore was not; retain that password and retry"
    fi
    die "cannot publish the generated keystore without clobbering: $OUT_JKS"
fi
sync -f -- "$OUT_JKS" "$PASS_FILE" \
    || die "cannot synchronize the published Android signing identity"
rm -f -- "$STAGED_KEYSTORE"
if [ "$generated_password" -eq 1 ]; then
    rm -f -- "$PASS_INPUT"
fi

assert_secret_file "$PASS_FILE" "published Android signing password"
assert_secret_file "$OUT_JKS" "published Android keystore"
[ "$(sha256sum -- "$PASS_FILE" | awk '{print $1}')" = "$PASS_SHA_BEFORE" ] \
    || die "published Android signing password differs from the verified private input"
[ "$(sha256sum -- "$OUT_JKS" | awk '{print $1}')" = "$KEYSTORE_SHA_BEFORE" ] \
    || die "published Android keystore differs from the verified private artifact"

log "OK — Android keystore generated, independently verified, synchronized, and published without clobber: $OUT_JKS"
log "$verification"
if [ "$generated_password" -eq 1 ]; then
    warn "created the matching random password at $PASS_FILE — back it up; losing it loses the Android identity"
fi
if [ "$OUT_JKS" = "$DEFAULT_ANDROID_KEYSTORE" ] && [ "$PASS_FILE" = "$DEFAULT_ANDROID_KEYSTORE_PASS_FILE" ]; then
    log "The identity is at the default protected location used by build-android.sh."
else
    log "For release builds, set ANDROID_KEYSTORE='$OUT_JKS' and ANDROID_KEYSTORE_PASS_FILE='$PASS_FILE'."
fi
log "KEEP BOTH FILES SAFE AND BACKED UP — this is the permanent Android app identity (R-B2)."

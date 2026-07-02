#!/usr/bin/env bash
# scripts/gen-android-keystore.sh — generate THE stable R-B2 Android signing key, once (R-B2, §12.1).
#
# Android WELDS app identity to the signing key: the key you first release with is PERMANENT (rotating
# it forces every user into a data-wiping reinstall). So the key is generated ONCE, kept as a secret
# OUTSIDE the repo/build image, and reused for every release. build-android.sh asserts these exact
# properties before signing (RSA 4096-bit, SHA256withRSA, validity >= 10000 days, fixed alias), so a
# wrong key fails loud rather than silently signing the release.
#
# Usage:   scripts/gen-android-keystore.sh <out.jks> <pass-file> [alias]
#   <out.jks>    where to write the keystore (MUST NOT already exist — never silently overwrite)
#   <pass-file>  the store/key password, read from this file (never argv/env). Auto-created with a
#                strong random password if absent (chmod 600) — BACK IT UP; losing it loses the key.
#   [alias]      key alias (default: rustdesk-fork — must match ANDROID_KEY_ALIAS at sign time)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

OUT_JKS="${1:?usage: gen-android-keystore.sh <out.jks> <pass-file> [alias]}"
PASS_FILE="${2:?usage: gen-android-keystore.sh <out.jks> <pass-file> [alias]}"
ALIAS="${3:-rustdesk-fork}"
IMAGE="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"   # ships the JDK/keytool

require_cmd docker
# Never silently overwrite: Android identity is welded to the key, so clobbering it would break every
# installed user's upgrade path. Refuse loudly.
[ ! -e "$OUT_JKS" ] || die "refusing to overwrite existing keystore: $OUT_JKS — Android welds app identity to the signing key; regenerating breaks in-place upgrades. Move the old key aside first if you REALLY intend to mint a new identity."
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "build image '$IMAGE' not found — run scripts/online-fetch.sh first (it builds the android image with the JDK/keytool)"

# Password: read from the file (never argv/env). Auto-create a strong one if the operator did not.
if [ ! -f "$PASS_FILE" ]; then
    require_cmd openssl
    ( umask 077; openssl rand -base64 33 > "$PASS_FILE" )
    warn "created a random keystore password at $PASS_FILE (chmod 600) — BACK IT UP; losing it loses the key forever"
fi
[ -s "$PASS_FILE" ] || die "password file is empty: $PASS_FILE"

OUT_DIR_ABS="$(cd "$(dirname "$OUT_JKS")" && pwd)"
JKS_NAME="$(basename "$OUT_JKS")"
log "generating the R-B2 Android key: $OUT_JKS (RSA 4096, SHA256withRSA, 10000-day validity, alias '$ALIAS')"

# keytool runs in the ephemeral, --network=none image; the password is read from the mounted file
# inside the container (not passed on THIS script's argv). -dname is non-interactive so keytool never
# prompts. (The store/key password does reach keytool's argv INSIDE the throwaway container — that
# process list dies with the container and never touches the network; the repeated, sensitive
# build/SIGN path uses the file-mount and never argv.)
docker run --rm --network=none \
    -v "$OUT_DIR_ABS:/out" -v "$PASS_FILE:/pass:ro" "$IMAGE" \
    bash -euo pipefail -c '
        pw="$(cat /pass)"
        keytool -genkeypair -keystore "/out/'"$JKS_NAME"'" -alias "'"$ALIAS"'" \
            -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000 \
            -storepass "$pw" -keypass "$pw" \
            -dname "CN=RustDesk Fork (local validation key), OU=fork, O=rustdesk-fork, L=local, ST=local, C=US"
        # Trust nothing — verify the key we just wrote actually has the R-B2 properties.
        info="$(keytool -list -v -keystore "/out/'"$JKS_NAME"'" -alias "'"$ALIAS"'" -storepass "$pw")"
        printf "%s" "$info" | grep -qE "Signature algorithm name:[[:space:]]*SHA256withRSA" || { echo "[FATAL] generated key is not SHA256withRSA" >&2; exit 1; }
        printf "%s" "$info" | grep -qiE "4096-bit RSA key" || { echo "[FATAL] generated key is not 4096-bit RSA" >&2; exit 1; }
        printf "%s\n" "$info" | grep -E "SHA256:" | head -1
    '

log "OK — keystore written + verified: $OUT_JKS (alias '$ALIAS')"
log "Now build the signed APK with:"
log "  export ANDROID_KEYSTORE='$OUT_JKS' ANDROID_KEYSTORE_PASS_FILE='$PASS_FILE'${3:+ ANDROID_KEY_ALIAS='$ALIAS'}"
log "  scripts/build-android.sh    # (or scripts/build-release.sh for all platforms)"
log "KEEP $OUT_JKS AND $PASS_FILE SAFE + BACKED UP — they are the permanent app identity (R-B2)."

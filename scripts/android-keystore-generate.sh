#!/usr/bin/env bash
# Narrow container-side worker for gen-android-keystore.sh. It receives no secret through argv/env.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'android-keystore-generate: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "requires exactly one fixed operation"
case "$1" in
    password)
        [ -d /out ] && [ ! -L /out ] || fail "/out must be a real output directory"
        [ ! -e /out/pass ] && [ ! -L /out/pass ] || fail "password output was not absent"
        dd if=/dev/urandom of=/tmp/android-keystore-password.raw bs=33 count=1 status=none
        base64 -w 0 /tmp/android-keystore-password.raw > /out/pass
        printf '\n' >> /out/pass
        rm -f /tmp/android-keystore-password.raw
        chmod 0600 /out/pass
        [ "$(stat -c '%u:%a:%h:%s' /out/pass)" = "$(id -u):600:1:45" ] \
            || fail "generated password metadata or length is invalid"
        ;;
    keystore)
        [ -d /out ] && [ ! -L /out ] || fail "/out must be a real output directory"
        [ ! -e /out/keystore.jks ] && [ ! -L /out/keystore.jks ] \
            || fail "keystore output was not absent"
        [ -f /authority/pass ] && [ ! -L /authority/pass ] && [ -s /authority/pass ] \
            || fail "password input must be a non-empty regular file"
        mkdir -p "$HOME"
        keytool -J-Duser.language=en -J-Duser.country=US -genkeypair -noprompt \
            -keystore /out/keystore.jks -alias rustdesk-fork \
            -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000 \
            -storepass:file /authority/pass -keypass:file /authority/pass \
            -dname "CN=RustDesk Fork Android Identity, OU=fork, O=rustdesk-fork, L=local, ST=local, C=US"
        chmod 0600 /out/keystore.jks
        [ -f /out/keystore.jks ] && [ ! -L /out/keystore.jks ] && [ -s /out/keystore.jks ] \
            || fail "keytool did not create a non-empty regular keystore"
        ;;
    verify)
        [ -f /authority/keystore.jks ] && [ ! -L /authority/keystore.jks ] \
            && [ -s /authority/keystore.jks ] \
            || fail "keystore input must be a non-empty regular file"
        [ -f /authority/pass ] && [ ! -L /authority/pass ] && [ -s /authority/pass ] \
            || fail "password input must be a non-empty regular file"
        mkdir -p "$HOME"
        info="$(
            keytool -J-Duser.language=en -J-Duser.country=US -list -v \
                -keystore /authority/keystore.jks -alias rustdesk-fork \
                -storepass:file /authority/pass 2>/dev/null
        )" || fail "keytool could not inspect the fixed alias"
        printf '%s\n' "$info" \
            | grep -qE 'Signature algorithm name:[[:space:]]*SHA256withRSA' \
            || fail "keystore certificate is not SHA256withRSA"
        printf '%s\n' "$info" | grep -qiE '4096-bit RSA key' \
            || fail "keystore key is not 4096-bit RSA"
        fingerprint="$(
            printf '%s\n' "$info" | awk '
                /^[[:space:]]*SHA256:/ {
                    value = $0
                    sub(/^[[:space:]]*SHA256:[[:space:]]*/, "", value)
                    gsub(/:/, "", value)
                    print toupper(value)
                    count++
                }
                END { if (count != 1) exit 1 }
            '
        )" || fail "keystore did not expose exactly one SHA-256 certificate fingerprint"
        case "$fingerprint" in
            *[!0-9A-F]*|'') fail "certificate fingerprint is not uppercase hexadecimal" ;;
        esac
        [ "${#fingerprint}" -eq 64 ] || fail "certificate fingerprint is not 32 bytes"
        printf 'ANDROID_KEYSTORE_CERT_SHA256=%s\n' "$fingerprint"
        ;;
    *)
        fail "unknown operation"
        ;;
esac

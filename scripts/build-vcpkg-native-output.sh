#!/usr/bin/env bash
# One producer for the exact vcpkg consumer projections used by acquisition and
# reproducibility verification. The caller supplies only sealed inputs and one
# empty private output root.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

fail() {
    printf 'vcpkg native producer: %s\n' "$*" >&2
    exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ "$#" -eq 1 ] || fail 'expected exactly one native-output kind'
[[ "${RUSTDESK_VCPKG_BASELINE:-}" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'vcpkg baseline is absent or malformed'
[[ "${VCPKG_NATIVE_OUTPUT_KEY:-}" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'vcpkg native output key is absent or malformed'
[[ "${LIBVPX_NATIVE_KEY:-}" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'libvpx native key is absent or malformed'
[ "${RUSTDESK_VCPKG_DISTFILES_DIR:-}" = /online/vcpkg-distfiles ] \
    || fail 'vcpkg distfile authority differs'
for directory in /online /overlay /outputs/native; do
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "required directory is absent or ambiguous: $directory"
done
[ -z "$(find /outputs/native -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail 'private native output is not empty'
readonly VCPKG_ARCHIVE="/online/vcpkg-${RUSTDESK_VCPKG_BASELINE}.tar.gz"
[ -f "$VCPKG_ARCHIVE" ] && [ ! -L "$VCPKG_ARCHIVE" ] \
    || fail 'vcpkg source archive is absent or ambiguous'

readonly VCPKG_ROOT=/tmp/vcpkg
export HOME=/tmp/home
mkdir -p "$HOME" "$VCPKG_ROOT"
tar -C "$VCPKG_ROOT" --strip-components=1 -xzf "$VCPKG_ARCHIVE"
export VCPKG_DISABLE_METRICS=1
export VCPKG_BINARY_SOURCES=clear

case "$1" in
    x64-linux)
        export CC=/usr/bin/gcc-8 CXX=/usr/bin/g++-8
        readonly LIBRARIES=(libjpeg.a libopus.a libturbojpeg.a libvpx.a libyuv.a)
        readonly PORTS=(libvpx libyuv opus)
        ;;
    arm64-android)
        export ANDROID_NDK_HOME=/online/android-ndk
        [ -d "$ANDROID_NDK_HOME/toolchains" ] && [ ! -L "$ANDROID_NDK_HOME" ] \
            || fail 'Android NDK authority is absent or ambiguous'
        readonly LIBRARIES=(libjpeg.a liboboe.a libopus.a libturbojpeg.a libvpx.a libyuv.a)
        readonly PORTS=(libvpx libyuv opus oboe)
        ;;
    *) fail 'native-output kind is outside the closed supported set' ;;
esac
readonly TRIPLET=$1

"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics >/dev/null
"$VCPKG_ROOT/vcpkg" install --triplet "$TRIPLET" --overlay-ports=/overlay \
    "${PORTS[@]}"
install -d -m 0700 /outputs/native/include /outputs/native/lib
cp -a "$VCPKG_ROOT/installed/$TRIPLET/include/." /outputs/native/include/
for archive in "${LIBRARIES[@]}"; do
    cp -a "$VCPKG_ROOT/installed/$TRIPLET/lib/$archive" /outputs/native/lib/
done
printf '%s\n' "$VCPKG_NATIVE_OUTPUT_KEY" \
    > /outputs/native/.rustdesk-vcpkg-native-output-key-v1
printf '%s\n' "$LIBVPX_NATIVE_KEY" \
    > /outputs/native/.rustdesk-libvpx-native-key

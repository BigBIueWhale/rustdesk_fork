#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C

[ "$#" -eq 1 ] && [ "$1" = /outputs ] \
    && [ "$(dpkg --print-architecture)" = amd64 ] \
    && [ "$(id -u):$(id -g)" = "${XRANDR_UID:?}:${XRANDR_GID:?}" ] \
    && [ "$XRANDR_UID" -ne 0 ] && [ "$XRANDR_GID" -ne 0 ] \
    || { echo 'xrandr acquisition entry differs' >&2; exit 1; }
[[ "${XRANDR_DEBIAN_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${XRANDR_SECURITY_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${XRANDR_BASE:?}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "${XRANDR_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${XRANDR_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${XRANDR_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'xrandr acquisition pins are malformed' >&2; exit 1; }
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ ! -L /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$XRANDR_UID:$XRANDR_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'xrandr keyring or output authority differs' >&2; exit 1; }

readonly APT_ROOT=/tmp/xrandr-apt
readonly SOURCES=$APT_ROOT/snapshot.sources
install -d -m 0700 "$APT_ROOT" "$APT_ROOT/lists" "$APT_ROOT/lists/partial" "$APT_ROOT/log"
printf '%s\n' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian/${XRANDR_DEBIAN_SNAPSHOT}/" \
    'Suites: bookworm bookworm-updates' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' '' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian-security/${XRANDR_SECURITY_SNAPSHOT}/" \
    'Suites: bookworm-security' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' >"$SOURCES"
readonly -a APT_OPTIONS=(
    -o "Dir::Etc::sourcelist=$SOURCES" -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$APT_ROOT/lists" -o "Dir::Log=$APT_ROOT/log"
    -o APT::Sandbox::User= -o Debug::NoLocking=1
    -o Acquire::Retries=0 -o Acquire::https::Timeout=30
    -o APT::Get::AllowUnauthenticated=false
    -o Acquire::AllowInsecureRepositories=false
)
env -i PATH=/usr/bin:/bin LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" -o APT::Update::Error-Mode=any update -qq
# Only the xrandr executable will be used, against the exact recorded compiler image.
# This package is not a standalone runtime closure for its other X utilities.
cd /outputs
env -i PATH=/usr/bin:/bin LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" download "x11-xserver-utils=$XRANDR_VERSION"
readonly PACKAGE="x11-xserver-utils_${XRANDR_VERSION}_amd64.deb"
[ -f "$PACKAGE" ] && [ ! -L "$PACKAGE" ] \
    && [ "$(stat -c '%u:%g:%h:%s' "$PACKAGE")" = "$XRANDR_UID:$XRANDR_GID:1:$XRANDR_SIZE" ] \
    && [ "$(sha256sum "$PACKAGE" | cut -d ' ' -f 1)" = "$XRANDR_SHA256" ] \
    && [ "$(dpkg-deb --field "$PACKAGE" Package)" = x11-xserver-utils ] \
    && [ "$(dpkg-deb --field "$PACKAGE" Version)" = "$XRANDR_VERSION" ] \
    && [ "$(dpkg-deb --field "$PACKAGE" Architecture)" = amd64 ] \
    && [ "$(find /outputs -mindepth 1 -maxdepth 1 -printf x)" = x ] \
    || { echo 'signed xrandr package differs from publisher pins' >&2; exit 1; }
printf 'base=%s\ndebian_snapshot=%s\nsecurity_snapshot=%s\npackage=x11-xserver-utils\nversion=%s\narchitecture=amd64\nscope=xrandr-only-on-recorded-base\nkeyring_sha256=%s\n' \
    "$XRANDR_BASE" "$XRANDR_DEBIAN_SNAPSHOT" "$XRANDR_SECURITY_SNAPSHOT" \
    "$XRANDR_VERSION" "$(sha256sum /usr/share/keyrings/debian-archive-keyring.gpg | cut -d ' ' -f 1)" >contract
chmod 0400 "$PACKAGE" contract
printf 'XRANDR_RUNTIME_CANDIDATE=downloaded package=x11-xserver-utils version=%s bytes=%s sha256=%s base=%s execution=absent\n' \
    "$XRANDR_VERSION" "$XRANDR_SIZE" "$XRANDR_SHA256" "$XRANDR_BASE"

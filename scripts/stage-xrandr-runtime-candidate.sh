#!/usr/bin/env bash
# Acquire xrandr, Xephyr and missing dependencies for the recorded test image.
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
    && [[ "${XRANDR_DPKG_MANIFEST_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${XRANDR_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${XRANDR_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${XRANDR_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    && [[ "${XEPHYR_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${XEPHYR_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${XEPHYR_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'xrandr acquisition pins are malformed' >&2; exit 1; }
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ ! -L /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ "$(sha256sum /usr/local/share/rustdesk-devcheck-provenance/dpkg-manifest.tsv | cut -d' ' -f1)" = "$XRANDR_DPKG_MANIFEST_SHA256" ] \
    && [ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$XRANDR_UID:$XRANDR_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'xrandr keyring or output authority differs' >&2; exit 1; }

readonly APT_ROOT=/tmp/xrandr-apt
readonly SOURCES=$APT_ROOT/snapshot.sources
install -d -m 0700 "$APT_ROOT" "$APT_ROOT/lists" "$APT_ROOT/lists/partial" "$APT_ROOT/log" \
    /outputs/packages /outputs/packages/partial
cp /var/lib/dpkg/status "$APT_ROOT/status"
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
    -o "Dir::State::lists=$APT_ROOT/lists" -o "Dir::State::status=$APT_ROOT/status"
    -o Dir::Cache::archives=/outputs/packages
    -o "Dir::State::extended_states=$APT_ROOT/extended_states" -o "Dir::Log=$APT_ROOT/log"
    -o APT::Sandbox::User= -o Debug::NoLocking=1
    -o Acquire::Retries=0 -o Acquire::https::Timeout=30
    -o APT::Get::AllowUnauthenticated=false
    -o Acquire::AllowInsecureRepositories=false
)
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" -o APT::Update::Error-Mode=any update -qq
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" --yes --download-only --no-install-recommends \
    install "x11-xserver-utils=$XRANDR_VERSION" "xserver-xephyr=$XEPHYR_VERSION"

shopt -s nullglob
packages=(/outputs/packages/*.deb)
[ "${#packages[@]}" -ge 2 ] && [ "${#packages[@]}" -le 64 ] \
    || { echo 'xrandr runtime dependency cardinality differs' >&2; exit 1; }
total=0
entry_count=0
for package in "${packages[@]}"; do
    [ -f "$package" ] && [ ! -L "$package" ] \
        && [ "$(stat -c '%u:%g:%h' "$package")" = "$XRANDR_UID:$XRANDR_GID:1" ] \
        || { echo 'xrandr runtime package authority differs' >&2; exit 1; }
    size="$(stat -c '%s' "$package")"
    [ "$size" -gt 0 ] && [ "$size" -le 16777216 ] \
        || { echo 'xrandr runtime package exceeds its bound' >&2; exit 1; }
    total=$((total + size))
    [ "$total" -le 67108864 ] \
        || { echo 'xrandr runtime dependencies exceed 64 MiB' >&2; exit 1; }
    name="$(dpkg-deb --field "$package" Package)"
    version="$(dpkg-deb --field "$package" Version)"
    architecture="$(dpkg-deb --field "$package" Architecture)"
    digest="$(sha256sum "$package" | cut -d' ' -f1)"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] \
        && [[ "$version" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
        && [[ "$architecture" = amd64 || "$architecture" = all ]] \
        || { echo 'xrandr runtime package metadata differs' >&2; exit 1; }
    case "$name" in
        x11-xserver-utils)
            [ "$version:$architecture:$size:$digest" = "$XRANDR_VERSION:amd64:$XRANDR_SIZE:$XRANDR_SHA256" ] \
                || { echo 'signed xrandr package differs from publisher pins' >&2; exit 1; }
            entry_count=$((entry_count + 1)) ;;
        xserver-xephyr)
            [ "$version:$architecture:$size:$digest" = "$XEPHYR_VERSION:amd64:$XEPHYR_SIZE:$XEPHYR_SHA256" ] \
                || { echo 'signed Xephyr package differs from publisher pins' >&2; exit 1; }
            entry_count=$((entry_count + 1)) ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" \
        "${package##*/}" "$size" "$digest" >> /outputs/manifest.tsv
    chmod 0400 "$package"
done
[ "$entry_count" -eq 2 ] || { echo 'xrandr runtime entry packages are missing' >&2; exit 1; }
sort -o /outputs/manifest.tsv /outputs/manifest.tsv
printf 'base=%s\ndpkg_manifest_sha256=%s\ndebian_snapshot=%s\nsecurity_snapshot=%s\nxrandr=%s\nxephyr=%s\nscope=rotation-runtime-missing-dependencies-on-recorded-base\nkeyring_sha256=%s\n' \
    "$XRANDR_BASE" "$XRANDR_DPKG_MANIFEST_SHA256" "$XRANDR_DEBIAN_SNAPSHOT" "$XRANDR_SECURITY_SNAPSHOT" \
    "$XRANDR_VERSION" "$XEPHYR_VERSION" "$(sha256sum /usr/share/keyrings/debian-archive-keyring.gpg | cut -d' ' -f1)" \
    > /outputs/contract
chmod 0400 /outputs/manifest.tsv /outputs/contract
printf 'XRANDR_RUNTIME_CANDIDATE=downloaded packages=%s base=%s execution=absent\n' \
    "${#packages[@]}" "$XRANDR_BASE"

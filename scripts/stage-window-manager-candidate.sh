#!/usr/bin/env bash
# Acquire Openbox and its missing dependencies for the exact devcheck test image.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C

[ "$#" -eq 1 ] && [ "$1" = /outputs ] \
    && [ "$(dpkg --print-architecture)" = amd64 ] \
    && [ "$(id -u):$(id -g)" = "${WM_UID:?}:${WM_GID:?}" ] \
    && [ "$WM_UID" -ne 0 ] && [ "$WM_GID" -ne 0 ] \
    || { echo 'window-manager acquisition entry differs' >&2; exit 1; }
[[ "${WM_DEBIAN_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${WM_SECURITY_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${WM_BASE:?}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "${WM_DPKG_MANIFEST_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${WM_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${WM_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${WM_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'window-manager acquisition pins are malformed' >&2; exit 1; }
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ ! -L /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ "$(sha256sum /usr/local/share/rustdesk-devcheck-provenance/dpkg-manifest.tsv | cut -d' ' -f1)" = "$WM_DPKG_MANIFEST_SHA256" ] \
    && [ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$WM_UID:$WM_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'window-manager base, keyring or output authority differs' >&2; exit 1; }

readonly APT_ROOT=/tmp/window-manager-apt
readonly SOURCES=$APT_ROOT/snapshot.sources
install -d -m 0700 "$APT_ROOT" "$APT_ROOT/lists" "$APT_ROOT/lists/partial" \
    "$APT_ROOT/log" /outputs/packages /outputs/packages/partial
# The offline replay uses this exact image, not an unrelated native guest.
cp /var/lib/dpkg/status "$APT_ROOT/status"
printf '%s\n' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian/${WM_DEBIAN_SNAPSHOT}/" \
    'Suites: bookworm bookworm-updates' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' '' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian-security/${WM_SECURITY_SNAPSHOT}/" \
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
    -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false
)
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" -o APT::Update::Error-Mode=any update -qq
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" --yes --download-only --no-install-recommends \
    install "openbox=$WM_VERSION"

shopt -s nullglob
packages=(/outputs/packages/*.deb)
[ "${#packages[@]}" -gt 0 ] && [ "${#packages[@]}" -le 64 ] \
    || { echo 'window-manager dependency cardinality differs' >&2; exit 1; }
readonly OPENBOX="/outputs/packages/openbox_${WM_VERSION}_amd64.deb"
[ -f "$OPENBOX" ] && [ ! -L "$OPENBOX" ] \
    && [ "$(stat -c '%s' "$OPENBOX")" = "$WM_SIZE" ] \
    && [ "$(sha256sum "$OPENBOX" | cut -d' ' -f1)" = "$WM_SHA256" ] \
    || { echo 'signed Openbox package differs from publisher pins' >&2; exit 1; }
total=0
for package in "${packages[@]}"; do
    [ -f "$package" ] && [ ! -L "$package" ] \
        && [ "$(stat -c '%u:%g:%h' "$package")" = "$WM_UID:$WM_GID:1" ] \
        || { echo 'window-manager package authority differs' >&2; exit 1; }
    size="$(stat -c '%s' "$package")"
    [ "$size" -gt 0 ] && [ "$size" -le 16777216 ] \
        || { echo 'window-manager package exceeds its bound' >&2; exit 1; }
    total=$((total + size))
    [ "$total" -le 67108864 ] \
        || { echo 'window-manager dependencies exceed 64 MiB' >&2; exit 1; }
    name="$(dpkg-deb --field "$package" Package)"
    version="$(dpkg-deb --field "$package" Version)"
    architecture="$(dpkg-deb --field "$package" Architecture)"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] \
        && [[ "$version" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
        && [[ "$architecture" = amd64 || "$architecture" = all ]] \
        || { echo 'window-manager package metadata differs' >&2; exit 1; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" \
        "${package##*/}" "$size" "$(sha256sum "$package" | cut -d' ' -f1)"
    chmod 0400 "$package"
done | sort > /outputs/manifest.tsv
printf 'base=%s\ndpkg_manifest_sha256=%s\ndebian_snapshot=%s\nsecurity_snapshot=%s\nopenbox=%s\nscope=missing-dependencies-on-recorded-base\nkeyring_sha256=%s\n' \
    "$WM_BASE" "$WM_DPKG_MANIFEST_SHA256" "$WM_DEBIAN_SNAPSHOT" "$WM_SECURITY_SNAPSHOT" \
    "$WM_VERSION" "$(sha256sum /usr/share/keyrings/debian-archive-keyring.gpg | cut -d' ' -f1)" \
    > /outputs/contract
chmod 0400 /outputs/manifest.tsv /outputs/contract
printf 'WINDOW_MANAGER_CANDIDATE=downloaded packages=%s base=%s execution=absent\n' \
    "${#packages[@]}" "$WM_BASE"

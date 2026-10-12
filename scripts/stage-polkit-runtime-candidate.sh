#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

[ "$#" -eq 1 ] && [ "$1" = /outputs ] || exit 2
[ "$(dpkg --print-architecture)" = amd64 ] \
    || { echo 'polkit acquisition requires the pinned amd64 runtime' >&2; exit 1; }
[ "$(id -u)" = "${POLKIT_RUNTIME_UID:?}" ] \
    && [ "$(id -g)" = "${POLKIT_RUNTIME_GID:?}" ] \
    && [ "$POLKIT_RUNTIME_UID" -ne 0 ] && [ "$POLKIT_RUNTIME_GID" -ne 0 ] \
    || { echo 'polkit acquisition principal differs' >&2; exit 1; }
[[ "${POLKIT_DEBIAN_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${POLKIT_SECURITY_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${POLKIT_DEV_CHECK_IMAGE_ID:?}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "${POLKIT_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${POLKIT_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${POLKIT_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'polkit acquisition pins are malformed' >&2; exit 1; }
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ ! -L /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$POLKIT_RUNTIME_UID:$POLKIT_RUNTIME_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'polkit acquisition keyring or output authority differs' >&2; exit 1; }

readonly APT_ROOT=/tmp/polkit-runtime-apt
readonly SOURCES=$APT_ROOT/snapshot.sources
install -d -m 0700 "$APT_ROOT" "$APT_ROOT/lists" "$APT_ROOT/lists/partial" \
    "$APT_ROOT/log" /outputs/packages /outputs/packages/partial
# Resolve the complete runtime closure, independently of packages already in
# the compiler image. The disposable native guest has a different package set.
: >"$APT_ROOT/status"
printf '%s\n' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian/${POLKIT_DEBIAN_SNAPSHOT}/" \
    'Suites: bookworm bookworm-updates' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' '' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian-security/${POLKIT_SECURITY_SNAPSHOT}/" \
    'Suites: bookworm-security' 'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' >"$SOURCES"
readonly -a APT_OPTIONS=(
    -o "Dir::Etc::sourcelist=$SOURCES" -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$APT_ROOT/lists"
    -o "Dir::State::status=$APT_ROOT/status"
    -o Dir::Cache::archives=/outputs/packages
    -o "Dir::State::extended_states=$APT_ROOT/extended_states"
    -o "Dir::Log=$APT_ROOT/log"
    -o APT::Sandbox::User= -o Debug::NoLocking=1
    -o Acquire::Retries=0 -o Acquire::https::Timeout=30
    -o APT::Get::AllowUnauthenticated=false
    -o Acquire::AllowInsecureRepositories=false
)
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" -o APT::Update::Error-Mode=any update -qq
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" --yes --download-only --no-install-recommends \
    install "polkitd=$POLKIT_VERSION"

shopt -s nullglob
packages=(/outputs/packages/*.deb)
[ "${#packages[@]}" -gt 0 ] && [ "${#packages[@]}" -le 96 ] \
    || { echo 'polkit package closure cardinality is invalid' >&2; exit 1; }
polkit_file="/outputs/packages/polkitd_${POLKIT_VERSION}_amd64.deb"
[ -f "$polkit_file" ] && [ ! -L "$polkit_file" ] \
    && [ "$(stat -c '%s' "$polkit_file")" = "$POLKIT_SIZE" ] \
    && [ "$(sha256sum "$polkit_file" | cut -d' ' -f1)" = "$POLKIT_SHA256" ] \
    || { echo 'signed polkitd package differs from the publisher pin' >&2; exit 1; }
total=0
for package in "${packages[@]}"; do
    [ -f "$package" ] && [ ! -L "$package" ] \
        && [ "$(stat -c '%u:%g:%h' "$package")" = "$POLKIT_RUNTIME_UID:$POLKIT_RUNTIME_GID:1" ] \
        || { echo 'polkit package output authority differs' >&2; exit 1; }
    size="$(stat -c '%s' "$package")"
    [ "$size" -gt 0 ] && [ "$size" -le 33554432 ] \
        || { echo 'polkit package size is outside its bound' >&2; exit 1; }
    total=$((total + size))
    [ "$total" -le 134217728 ] \
        || { echo 'polkit package closure exceeds 128 MiB' >&2; exit 1; }
    name="$(dpkg-deb --field "$package" Package)"
    version="$(dpkg-deb --field "$package" Version)"
    architecture="$(dpkg-deb --field "$package" Architecture)"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] \
        && [[ "$version" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
        && [[ "$architecture" = amd64 || "$architecture" = all ]] \
        || { echo 'polkit package metadata is malformed' >&2; exit 1; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" \
        "${package##*/}" "$size" "$(sha256sum "$package" | cut -d' ' -f1)"
    chmod 0400 "$package"
done | sort > /outputs/manifest.tsv
printf 'base=%s\ndebian_snapshot=%s\nsecurity_snapshot=%s\npolkitd=%s\nclosure=empty-dpkg-status\n' \
    "$POLKIT_DEV_CHECK_IMAGE_ID" "$POLKIT_DEBIAN_SNAPSHOT" \
    "$POLKIT_SECURITY_SNAPSHOT" "$POLKIT_VERSION" > /outputs/contract
printf 'keyring_sha256=%s\n' \
    "$(sha256sum /usr/share/keyrings/debian-archive-keyring.gpg | cut -d' ' -f1)" \
    >> /outputs/contract
chmod 0400 /outputs/manifest.tsv /outputs/contract
printf 'POLKIT_RUNTIME_CANDIDATE=downloaded packages=%s base=%s\n' \
    "${#packages[@]}" "$POLKIT_DEV_CHECK_IMAGE_ID"

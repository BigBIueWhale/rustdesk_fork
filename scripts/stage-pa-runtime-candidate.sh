#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

[ "$#" -eq 1 ] && [ "$1" = /outputs ] || exit 2
[ "$(id -u)" = "${PA_RUNTIME_UID:?}" ] \
    && [ "$(id -g)" = "${PA_RUNTIME_GID:?}" ] \
    && [ "$PA_RUNTIME_UID" -ne 0 ] && [ "$PA_RUNTIME_GID" -ne 0 ] \
    || { echo 'PulseAudio acquisition principal differs' >&2; exit 1; }
[[ "${PA_DEBIAN_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${PA_SECURITY_SNAPSHOT:?}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    && [[ "${PA_VERSION:?}" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
    && [[ "${PA_DEV_CHECK_IMAGE_ID:?}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "${PA_SHA256:?}" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "${PA_SIZE:?}" =~ ^[1-9][0-9]*$ ]] \
    || { echo 'PulseAudio acquisition pins are malformed' >&2; exit 1; }
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ ! -L /usr/share/keyrings/debian-archive-keyring.gpg ] \
    && [ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$PA_RUNTIME_UID:$PA_RUNTIME_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'PulseAudio acquisition keyring or output authority differs' >&2; exit 1; }

readonly APT_ROOT=/tmp/pa-runtime-apt
readonly SOURCES=$APT_ROOT/snapshot.sources
install -d -m 0700 \
    "$APT_ROOT" "$APT_ROOT/lists" "$APT_ROOT/lists/partial" \
    "$APT_ROOT/log" \
    /outputs/packages /outputs/packages/partial
printf '%s\n' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian/${PA_DEBIAN_SNAPSHOT}/" \
    'Suites: bookworm bookworm-updates' \
    'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' \
    '' \
    'Types: deb' \
    "URIs: https://snapshot.debian.org/archive/debian-security/${PA_SECURITY_SNAPSHOT}/" \
    'Suites: bookworm-security' \
    'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    'Check-Valid-Until: no' \
    >"$SOURCES"
readonly -a APT_OPTIONS=(
    -o "Dir::Etc::sourcelist=$SOURCES"
    -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$APT_ROOT/lists"
    -o Dir::Cache::archives=/outputs/packages
    -o "Dir::State::extended_states=$APT_ROOT/extended_states"
    -o "Dir::Log=$APT_ROOT/log"
    -o APT::Sandbox::User=
    -o Debug::NoLocking=1
)
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" -o APT::Update::Error-Mode=any update -qq
simulation="$(env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" --simulate --no-install-recommends \
    install "pulseaudio=$PA_VERSION")"
[[ "$simulation" == *'Inst pulseaudio '* ]] \
    || { echo 'PulseAudio is not selected for the pinned devcheck image' >&2; exit 1; }
env -i PATH=/usr/bin:/bin HOME="$APT_ROOT" LC_ALL=C \
    apt-get "${APT_OPTIONS[@]}" --yes --download-only --no-install-recommends \
    install "pulseaudio=$PA_VERSION"

shopt -s nullglob
packages=(/outputs/packages/*.deb)
[ "${#packages[@]}" -gt 0 ] && [ "${#packages[@]}" -le 64 ] \
    || { echo 'PulseAudio package closure cardinality is invalid' >&2; exit 1; }
pulseaudio_file="/outputs/packages/pulseaudio_${PA_VERSION}_amd64.deb"
[ -f "$pulseaudio_file" ] && [ ! -L "$pulseaudio_file" ] \
    && [ "$(stat -c '%s' "$pulseaudio_file")" = "$PA_SIZE" ] \
    && [ "$(sha256sum "$pulseaudio_file" | cut -d' ' -f1)" = "$PA_SHA256" ] \
    || { echo 'signed PulseAudio package differs from the pinned discovery' >&2; exit 1; }
for package in "${packages[@]}"; do
    [ -f "$package" ] && [ ! -L "$package" ] \
        && [ "$(stat -c '%u:%g:%h' "$package")" = "$PA_RUNTIME_UID:$PA_RUNTIME_GID:1" ] \
        || { echo 'PulseAudio package output authority differs' >&2; exit 1; }
    name="$(dpkg-deb --field "$package" Package)"
    version="$(dpkg-deb --field "$package" Version)"
    architecture="$(dpkg-deb --field "$package" Architecture)"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] \
        && [[ "$version" =~ ^[0-9A-Za-z.+:~\-]+$ ]] \
        && [[ "$architecture" = amd64 || "$architecture" = all ]] \
        || { echo 'PulseAudio package metadata is malformed' >&2; exit 1; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$version" "$architecture" "${package##*/}" \
        "$(stat -c '%s' "$package")" \
        "$(sha256sum "$package" | cut -d' ' -f1)"
    chmod 0400 "$package"
done | LC_ALL=C sort > /outputs/manifest.tsv
printf 'base=%s\ndebian_snapshot=%s\nsecurity_snapshot=%s\npulseaudio=%s\n' \
    "$PA_DEV_CHECK_IMAGE_ID" "$PA_DEBIAN_SNAPSHOT" \
    "$PA_SECURITY_SNAPSHOT" "$PA_VERSION" > /outputs/contract
chmod 0400 /outputs/manifest.tsv /outputs/contract
printf 'PA_RUNTIME_CANDIDATE=downloaded packages=%s base=%s\n' \
    "${#packages[@]}" "$PA_DEV_CHECK_IMAGE_ID"

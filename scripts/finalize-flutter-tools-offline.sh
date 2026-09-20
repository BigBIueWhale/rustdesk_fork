#!/usr/bin/env bash
# Publish the Flutter-tools freshness state after an exact offline Dart Pub resolve.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

fail() {
    printf 'finalize-flutter-tools-offline: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 3 ] \
    || fail 'usage: finalize-flutter-tools-offline.sh FLUTTER_ROOT VERSION LOCK_SHA256'
readonly FLUTTER_ROOT=$1
readonly EXPECTED_VERSION=$2
readonly EXPECTED_LOCK_SHA256=$3

case "$FLUTTER_ROOT" in
    /*) ;;
    *) fail 'Flutter root must be absolute' ;;
esac
[[ "$EXPECTED_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] \
    || fail 'expected Flutter version is malformed'
[[ "$EXPECTED_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'expected Flutter-tools lock digest is malformed'

[ -d "$FLUTTER_ROOT" ] && [ ! -L "$FLUTTER_ROOT" ] \
    || fail 'Flutter root is not one real directory'
[ "$(/usr/bin/readlink -f -- "$FLUTTER_ROOT")" = "$FLUTTER_ROOT" ] \
    || fail 'Flutter root is not canonical'

readonly VERSION_FILE=$FLUTTER_ROOT/version
readonly TOOLS_ROOT=$FLUTTER_ROOT/packages/flutter_tools
readonly DART_TOOL_ROOT=$TOOLS_ROOT/.dart_tool
readonly PUBSPEC=$TOOLS_ROOT/pubspec.yaml
readonly LOCK=$TOOLS_ROOT/pubspec.lock
readonly PACKAGE_CONFIG=$DART_TOOL_ROOT/package_config.json
readonly MARKER=$DART_TOOL_ROOT/version
readonly CURRENT_UID=$(/usr/bin/id -u)
readonly CURRENT_GID=$(/usr/bin/id -g)

for directory in "$FLUTTER_ROOT/packages" "$TOOLS_ROOT" "$DART_TOOL_ROOT"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "required Flutter-tools directory is absent or ambiguous: $directory"
done
for input in "$VERSION_FILE" "$PUBSPEC" "$LOCK" "$PACKAGE_CONFIG"; do
    [ -f "$input" ] && [ ! -L "$input" ] \
        && [ "$(/usr/bin/stat -c '%h' -- "$input")" = 1 ] \
        || fail "required Flutter-tools input is absent or ambiguous: $input"
done
[ "$(/usr/bin/stat -c '%u:%g' -- "$DART_TOOL_ROOT" "$PACKAGE_CONFIG")" = \
  "$CURRENT_UID:$CURRENT_GID
$CURRENT_UID:$CURRENT_GID" ] \
    || fail 'offline Pub output is not owned by the invoking principal'
[ "$(/usr/bin/stat -c '%s' -- "$VERSION_FILE")" = "${#EXPECTED_VERSION}" ] \
    && [ "$(/usr/bin/cat -- "$VERSION_FILE")" = "$EXPECTED_VERSION" ] \
    || fail 'Flutter version file differs from the expected version'
[ "$(/usr/bin/sha256sum "$LOCK" | /usr/bin/awk '{ print $1 }')" = \
  "$EXPECTED_LOCK_SHA256" ] \
    || fail 'Flutter-tools lockfile differs from its expected digest'
[ "$PUBSPEC" -ot "$LOCK" ] \
    || fail 'Flutter-tools lockfile is not newer than its pubspec'
[ "$PUBSPEC" -ot "$PACKAGE_CONFIG" ] \
    || fail 'offline Pub package configuration is not newer than its pubspec'

if [ -e "$MARKER" ] || [ -L "$MARKER" ]; then
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$MARKER")" = \
             "$CURRENT_UID:$CURRENT_GID:644:1:${#EXPECTED_VERSION}" ] \
        && /usr/bin/cmp -s -- "$VERSION_FILE" "$MARKER" \
        || fail 'existing Flutter-tools freshness marker is not exact'
else
    /usr/bin/install -m 0644 -- "$VERSION_FILE" "$MARKER" \
        || fail 'cannot publish the Flutter-tools freshness marker'
fi
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$MARKER")" = \
  "$CURRENT_UID:$CURRENT_GID:644:1:${#EXPECTED_VERSION}" ] \
    && /usr/bin/cmp -s -- "$VERSION_FILE" "$MARKER" \
    || fail 'published Flutter-tools freshness marker is not exact'

printf 'FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=%s lock=%s implicit_pub=prevented\n' \
    "$EXPECTED_VERSION" "$EXPECTED_LOCK_SHA256"

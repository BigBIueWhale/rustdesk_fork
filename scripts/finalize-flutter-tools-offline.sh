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
canonical_flutter_root="$(
    cd -P -- "$FLUTTER_ROOT" 2>/dev/null && builtin pwd -P
)" || fail 'Flutter root cannot be resolved'
[ "$canonical_flutter_root" = "$FLUTTER_ROOT" ] \
    || fail 'Flutter root is not canonical'
readonly canonical_flutter_root

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
    && [ "$(<"$VERSION_FILE")" = "$EXPECTED_VERSION" ] \
    || fail 'Flutter version file differs from the expected version'
[ "$(/usr/bin/sha256sum "$LOCK" | /usr/bin/awk '{ print $1 }')" = \
  "$EXPECTED_LOCK_SHA256" ] \
    || fail 'Flutter-tools lockfile differs from its expected digest'
[ "$PUBSPEC" -ot "$LOCK" ] \
    || fail 'Flutter-tools lockfile is not newer than its pubspec'
[ "$PUBSPEC" -ot "$PACKAGE_CONFIG" ] \
    || fail 'offline Pub package configuration is not newer than its pubspec'

if ! package_count="$(
    /usr/bin/python3 -I -S - "$PACKAGE_CONFIG" <<'PY'
import json
import os
import pathlib
import sys
import urllib.parse


def invalid():
    raise ValueError


try:
    config_path = os.path.abspath(sys.argv[1])
    if os.path.getsize(config_path) > 1024 * 1024:
        invalid()
    with open(config_path, "rb") as stream:
        config = json.load(stream)
    if not isinstance(config, dict) or config.get("configVersion") != 2:
        invalid()
    packages = config.get("packages")
    if not isinstance(packages, list) or not 0 < len(packages) <= 4096:
        invalid()
    base_uri = pathlib.Path(config_path).as_uri()
    names = set()
    for package in packages:
        if not isinstance(package, dict):
            invalid()
        name = package.get("name")
        root_uri = package.get("rootUri")
        if not isinstance(name, str) or not name or name in names:
            invalid()
        if not isinstance(root_uri, str) or not root_uri:
            invalid()
        names.add(name)
        resolved = urllib.parse.urlsplit(urllib.parse.urljoin(base_uri, root_uri))
        if (resolved.scheme != "file" or resolved.netloc
                or resolved.query or resolved.fragment):
            invalid()
        root_path = urllib.parse.unquote(resolved.path)
        if not os.path.isabs(root_path):
            invalid()
        if not os.path.isfile(os.path.join(root_path, "pubspec.yaml")):
            invalid()
    print(len(packages))
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    sys.exit(1)
PY
)"; then
    fail "offline Pub package roots do not satisfy Flutter's freshness predicate"
fi
[[ "$package_count" =~ ^[1-9][0-9]*$ ]] \
    || fail 'offline Pub package count is malformed'

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

#!/usr/bin/env bash
# Establish one private D-Bus/AT-SPI session before entering the requested peer stage.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

fail() {
  echo "private AT-SPI session: $*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ "$#" -eq 1 ] || fail 'expected one stage: atspi-check or viewer'
case "$1" in
  atspi-check)
    [ "${DISPLAY:-}" = :97 ] \
      && [ "${HOME:-}" = /tmp/atspi-home ] \
      && [ "${XDG_RUNTIME_DIR:-}" = /tmp/atspi-runtime ] \
      || fail 'AT-SPI preflight session paths differ'
    ;;
  viewer)
    [ "${DISPLAY:-}" = :99 ] \
      && [ "${HOME:-}" = /tmp/viewer-home ] \
      && [ "${XDG_RUNTIME_DIR:-}" = /tmp/viewer-runtime ] \
      || fail 'viewer session paths differ'
    ;;
  *) fail 'expected atspi-check or viewer stage' ;;
esac
[ "${XDG_DATA_DIRS:-}" = /atspi-root/usr/share:/usr/local/share:/usr/share ] \
  || fail 'AT-SPI session data roots differ'
for directory in "$HOME" "$XDG_RUNTIME_DIR"; do
  [ ! -e "$directory" ] && [ ! -L "$directory" ] \
    || fail "private session directory was not freshly absent: $directory"
  mkdir -m 0700 -- "$directory"
  [ -d "$directory" ] && [ ! -L "$directory" ] \
    && [ "$(stat -c '%u:%g:%a' -- "$directory")" = \
      "$(id -u):$(id -g):700" ] \
    || fail "private session directory metadata differs: $directory"
done
command -v dbus-run-session >/dev/null || fail 'dbus-run-session is absent'
exec dbus-run-session -- \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh "$1"

#!/usr/bin/env bash
# The ONE place that reads + validates the fork RELEASE version. The single source of truth is the
# repo-root FORK_VERSION file; the base (before "-hardened.") MUST equal Cargo.toml's `version` — a
# drift guard so the fork string and the app/wire/package version can never silently diverge.
#
#   FORK_VERSION scheme:  <Cargo version>-hardened.<N>    e.g.  1.4.7-hardened.1    (see docs/VERSIONING.md)
#
# Safe to `source` (defines `fork_version` only, no top-level `set -e` to leak into the caller) or to
# run directly (prints the validated version). Dies loud on a missing/malformed/drifted value.

fork_version() {
  local root fv cargo
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
  fv="$(tr -d '[:space:]' < "$root/FORK_VERSION" 2>/dev/null)" || true
  cargo="$(grep -m1 '^version' "$root/Cargo.toml" 2>/dev/null | sed 's/.*=[[:space:]]*"\(.*\)".*/\1/')"
  if [ -z "$fv" ]; then
    echo "fork-version: FORK_VERSION file is missing or empty ($root/FORK_VERSION)" >&2
    return 1
  fi
  if [ -z "$cargo" ]; then
    echo "fork-version: could not read 'version' from $root/Cargo.toml" >&2
    return 1
  fi
  case "$fv" in
    "${cargo}-hardened."[0-9]*)
      # reject a non-integer counter (e.g. 1.4.7-hardened.1x): the part after '-hardened.' must be digits
      case "${fv##*-hardened.}" in
        *[!0-9]*)
          echo "fork-version: '$fv' — the release counter after '-hardened.' must be a bare integer" >&2
          return 1 ;;
      esac
      ;;
    *)
      echo "fork-version: '$fv' must be '<Cargo version ${cargo}>-hardened.<N>' (see docs/VERSIONING.md)" >&2
      return 1 ;;
  esac
  printf '%s' "$fv"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  fork_version || exit 1
  echo
fi

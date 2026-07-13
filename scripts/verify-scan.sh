#!/usr/bin/env bash

readonly VERIFY_SCAN_GREP=/usr/bin/grep

verify_scan_preflight() {
  /usr/bin/python3 - "$VERIFY_SCAN_GREP" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
try:
    metadata = os.lstat(path)
except OSError as error:
    raise SystemExit(f"verify-scan: cannot inspect {path}: {error}") from error
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_mode & 0o022
    or not metadata.st_mode & 0o111
):
    raise SystemExit(f"verify-scan: {path} must be a root-owned, non-writable executable regular file")
PY
  local version
  version="$($VERIFY_SCAN_GREP --version 2>/dev/null)" || {
    echo "verify-scan: cannot identify $VERIFY_SCAN_GREP" >&2
    return 1
  }
  case "${version%%$'\n'*}" in
    'grep (GNU grep) '*) ;;
    *) echo "verify-scan: $VERIFY_SCAN_GREP is not GNU grep" >&2; return 1 ;;
  esac
}

verify_scan_capture() {
  local output="$1" status
  shift
  if "$VERIFY_SCAN_GREP" "$@" >"$output"; then
    return 0
  else
    status=$?
  fi
  if [ "$status" -eq 1 ]; then
    return 1
  fi
  printf 'verify-scan: scanner failed with status %s:' "$status" >&2
  printf ' %q' "$VERIFY_SCAN_GREP" "$@" >&2
  printf '\n' >&2
  exit 1
}

verify_scan_self_test() {
  local directory="$1" match output
  match="$directory/match"
  output="$directory/output"
  printf 'needle\n' >"$match"
  verify_scan_capture "$output" -nF needle "$match" || return 1
  [ "$(cat "$output")" = "1:needle" ] || return 1
  if verify_scan_capture "$output" -nF absent "$match"; then
    return 1
  elif [ "$?" -ne 1 ]; then
    return 1
  fi
  if (verify_scan_capture "$output" -E '[' "$match") >/dev/null 2>&1; then
    return 1
  fi
  if (verify_scan_capture "$output" -nF needle "$directory/missing") >/dev/null 2>&1; then
    return 1
  fi
}

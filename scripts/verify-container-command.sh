#!/usr/bin/env bash
# Exact command boundary for verify.sh's ordinary non-root build/test containers.
set -euo pipefail

[ "$PWD" = /work ] || {
  echo "verify-container-command: expected /work" >&2
  exit 1
}
[ "${CARGO_HOME:-}" = /tmp/cargo-home ] || {
  echo "verify-container-command: private Cargo home is not selected" >&2
  exit 1
}
[ "${CARGO_TARGET_DIR:-}" = /build ] || {
  echo "verify-container-command: private Cargo target is not selected" >&2
  exit 1
}
[ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ] || {
  echo "verify-container-command: ordinary verification refuses root" >&2
  exit 1
}
[ "$#" -gt 0 ] || {
  echo "verify-container-command: missing command" >&2
  exit 1
}
install -d -m 0700 -- "$HOME" "$CARGO_HOME"

case "$1" in
  cargo)
    shift
    if [ "${1:-}" = clean ]; then
      [ "$#" -eq 3 ] && [ "$2" = -p ] && [ "$3" = rustdesk ] || {
        echo "verify-container-command: unexpected Cargo clean command" >&2
        exit 1
      }
      # Cargo 1.75 panics when clean receives the command-line --config path.
      # It still resolves workspace sources, so give this non-code-executing,
      # exact private-target operation the same complete map through CARGO_HOME.
      install -m 0400 -- /tmp/cargo-config.toml "$CARGO_HOME/config.toml"
      exec cargo clean -p rustdesk
    fi
    exec cargo --config /tmp/cargo-config.toml --offline --locked "$@"
    ;;
  bash)
    [ "$#" -eq 2 ] && [ "$2" = scripts/version-metadata-check.sh ] || {
      echo "verify-container-command: unexpected shell command" >&2
      exit 1
    }
    exec /bin/bash --noprofile --norc /work/scripts/version-metadata-check.sh
    ;;
  *)
    echo "verify-container-command: unexpected command: $1" >&2
    exit 1
    ;;
esac

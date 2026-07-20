#!/usr/bin/env bash
#
# dart-audit.sh — the DART half of the R-R3 dependency-advisory gate.
#
# The mirror of scripts/audit.sh (which audits the Rust crate graph). This runs
# Google's OSV-Scanner, pinned in scripts/Dockerfile.dart-audit (osv-scanner at
# pins.env OSV_SCANNER_VERSION + a pinned snapshot of the OSV "Pub" advisory db),
# against the resolved Dart/Pub graph in flutter/pubspec.lock. The scan is
# --offline: it never queries the live OSV API, so the verdict is reproducible
# against the recorded snapshot (R-B10/R-B12), the way the cargo-audit twin runs
# against the pinned ADVISORY_DB_COMMIT.
#
# scripts/dart-audit-ignores.txt is the SINGLE source of truth for consciously-
# accepted advisories (each with a reason — R-R3's "ignore + reason"). This script
# reads only that file, then EXITS NON-ZERO on ANY advisory not listed there
# (fail-closed) — the accept-list and the tool can never drift apart.
#
# Like audit.sh this is NOT the inner-loop verify.sh gate: it needs the OSV db +
# a (pinned) binary fetch to build the image, so it is a separate, slower gate —
# run it in CI and before a release.
#
# Usage:  scripts/dart-audit.sh
set -euo pipefail

cd "$(dirname "$0")/.."
. scripts/pins.env

readonly IMG=rd-dart-audit
readonly LOCKFILE=flutter/pubspec.lock
readonly IGNORES_FILE=scripts/dart-audit-ignores.txt
readonly DOCKER_BIN=/usr/bin/docker
readonly PYTHON_BIN=/usr/bin/python3

die() {
  echo "dart-audit.sh: $*" >&2
  exit 2
}

[ "$(id -u)" -ne 0 ] || die "refuses host or container-root execution"
[ "$(id -g)" -ne 0 ] || die "refuses a root primary group"
[ -x "$DOCKER_BIN" ] || die "trusted Docker client is unavailable at $DOCKER_BIN"
[ -x "$PYTHON_BIN" ] || die "trusted Python interpreter is unavailable at $PYTHON_BIN"

[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ] \
  || die "$LOCKFILE is not a regular non-symlink file"
[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ] \
  || die "$IGNORES_FILE is not a regular non-symlink accept-list source"

# Every pin must be present — refuse to build a non-reproducible image.
: "${OSV_SCANNER_VERSION:?dart-audit.sh: OSV_SCANNER_VERSION unset in pins.env}"
: "${OSV_SCANNER_SHA256:?dart-audit.sh: OSV_SCANNER_SHA256 unset in pins.env}"
: "${OSV_DB_PUB_SHA256:?dart-audit.sh: OSV_DB_PUB_SHA256 unset in pins.env}"
: "${SHA256_BASEIMAGE_UBUNTU_1804:?dart-audit.sh: SHA256_BASEIMAGE_UBUNTU_1804 unset in pins.env}"

AUDIT_TMP=""
AUDIT_TMP_ID=""
AUDIT_SUCCESS_MESSAGE=""
cleanup_audit_tmp() {
  local status=$? cleanup_failed=0
  trap - EXIT HUP INT TERM
  if [ -n "$AUDIT_TMP" ]; then
    if [ -z "$AUDIT_TMP_ID" ] || [ ! -d "$AUDIT_TMP" ] || [ -L "$AUDIT_TMP" ] \
      || [ "$(/usr/bin/stat -c '%d:%i' -- "$AUDIT_TMP" 2>/dev/null)" != "$AUDIT_TMP_ID" ]; then
      echo "dart-audit.sh: private workspace identity is unavailable or changed: $AUDIT_TMP" >&2
      cleanup_failed=1
    elif ! "$PYTHON_BIN" scripts/verify-private-tree-closure.py \
      --remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"; then
      echo "dart-audit.sh: failed to remove private workspace: $AUDIT_TMP" >&2
      cleanup_failed=1
    elif [ -e "$AUDIT_TMP" ] || [ -L "$AUDIT_TMP" ]; then
      echo "dart-audit.sh: private workspace remains after removal: $AUDIT_TMP" >&2
      cleanup_failed=1
    fi
  fi
  [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
  if [ "$cleanup_failed" -eq 0 ] && [ "$status" -eq 0 ] && [ -n "$AUDIT_SUCCESS_MESSAGE" ]; then
    echo "$AUDIT_SUCCESS_MESSAGE"
  fi
  exit "$status"
}
trap cleanup_audit_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"
AUDIT_TMP_ID="$(/usr/bin/stat -c '%d:%i' -- "$AUDIT_TMP")"
readonly AUDIT_TMP AUDIT_TMP_ID
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$AUDIT_TMP")" = "$(id -u):$(id -g):700" ] \
  || die "private workspace is not current-user/current-group mode 0700"

# Validate the reason-bearing policy before the networked image-construction step.
ACCEPT_COUNT="$($PYTHON_BIN scripts/dart-audit-result.py validate-policy --policy "$IGNORES_FILE")" \
  || die "accept-list validation failed"
[[ "$ACCEPT_COUNT" =~ ^[0-9]+$ ]] || die "accept-list validator returned a malformed count"
echo "== R-R3 Dart advisory audit: ${ACCEPT_COUNT} documented accept(s) from ${IGNORES_FILE} =="

echo "== building the Dart advisory gate image (osv-scanner ${OSV_SCANNER_VERSION} + pinned OSV Pub db) =="
IMAGE_ID="$($DOCKER_BIN build -q \
  --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
  --build-arg "OSV_SCANNER_VERSION=${OSV_SCANNER_VERSION}" \
  --build-arg "OSV_SCANNER_SHA256=${OSV_SCANNER_SHA256}" \
  --build-arg "OSV_DB_PUB_SHA256=${OSV_DB_PUB_SHA256}" \
  -t "$IMG" -f scripts/Dockerfile.dart-audit scripts)" \
  || die "could not build the pinned Dart advisory image"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "docker build returned a malformed image identity"
TAG_IMAGE_ID="$($DOCKER_BIN image inspect --format '{{.Id}}' "$IMG")" \
  || die "cannot inspect the just-built Dart advisory image"
[ "$TAG_IMAGE_ID" = "$IMAGE_ID" ] \
  || die "Dart advisory image tag changed after construction"
readonly IMAGE_ID TAG_IMAGE_ID

RESULT_FILE="$AUDIT_TMP/osv-result.json"
ERROR_FILE="$AUDIT_TMP/osv-stderr.log"
LOCKFILE_PATH="$(/usr/bin/readlink -f -- "$LOCKFILE")" \
  || die "cannot canonicalize $LOCKFILE"
readonly RESULT_FILE ERROR_FILE LOCKFILE_PATH

# The scanner sees only the exact lockfile. The image ID, offline database, exit
# status, and JSON are one decision: status 0 means packages/no findings, status
# 1 means findings, and every other OSV status is an infrastructure failure.
set +e
$DOCKER_BIN run --rm --pull=never --network=none --read-only \
  --user "$(id -u):$(id -g)" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=512m --memory-swap=512m --cpus=2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
  --env HOME=/tmp/audit-home \
  --mount "type=bind,source=$LOCKFILE_PATH,target=/work/$LOCKFILE,readonly" \
  --workdir /work "$IMAGE_ID" \
  osv-scanner --offline --format=json --lockfile="$LOCKFILE" \
  >"$RESULT_FILE" 2>"$ERROR_FILE"
SCANNER_STATUS=$?
set -e
readonly SCANNER_STATUS

case "$SCANNER_STATUS" in
  0|1) ;;
  *)
    echo "dart-audit.sh: OSV scanner infrastructure failure (status $SCANNER_STATUS)" >&2
    if [ -s "$ERROR_FILE" ]; then
      /usr/bin/tail -c 65536 -- "$ERROR_FILE" | /usr/bin/sed 's/^/  /' >&2
    fi
    exit 2
    ;;
esac

RESULT_BYTES="$(/usr/bin/stat -c '%s' -- "$RESULT_FILE")" \
  || die "cannot inspect the OSV result"
[ "$RESULT_BYTES" -gt 0 ] || die "OSV scanner produced an empty result"
[ "$RESULT_BYTES" -le 67108864 ] || die "OSV scanner result exceeds 64 MiB"

$PYTHON_BIN scripts/dart-audit-result.py evaluate \
  --policy "$IGNORES_FILE" \
  --result "$RESULT_FILE" \
  --scanner-status "$SCANNER_STATUS" \
  --lockfile "$LOCKFILE"

AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green — exact OSV status and structured results contain no unignored advisories against the pinned Pub snapshot (R-R3/R-S11be)"

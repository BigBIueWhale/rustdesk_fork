#!/usr/bin/env bash
#
# dart-audit.sh — the Dart/Pub half of the R-R3 dependency-advisory gate.
#
# Acquisition and verdict execution are deliberately separate. This script
# never builds, pulls, or resolves an image tag. It requires one immutable local
# image content ID, verifies the exact OSV-Scanner and Pub database bytes inside
# it, rejects a database capture older than 30 days, and scans one stable private
# copy of flutter/pubspec.lock with no network or ambient container authority.
#
# scripts/dart-audit-ignores.txt is the sole reason-bearing Pub advisory accept
# policy. Status, structured JSON, and the scanner's bounded stderr telemetry are
# one decision; infrastructure failures cannot be reinterpreted as clean output.
#
# Usage: scripts/dart-audit.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"

readonly LOCKFILE=flutter/pubspec.lock
readonly IGNORES_FILE=scripts/dart-audit-ignores.txt
readonly PYTHON_BIN=/usr/bin/python3
readonly AUDIT_UID="$(/usr/bin/id -u)"
readonly AUDIT_GID="$(/usr/bin/id -g)"
readonly MAX_SCANNER_OUTPUT_BLOCKS=65536 # Bash ulimit -f units: 64 MiB on Linux.

dart_audit_die() {
  echo "dart-audit.sh: $*" >&2
  exit 2
}

# Bound stdout and stderr at the Docker client, before either private output
# file can consume unbounded host storage. Preserve any stricter caller limit.
run_bounded_docker() (
  current_limit="$(ulimit -Sf)" \
    || dart_audit_die "could not read the scanner output-file limit"
  if [ "$current_limit" = unlimited ]; then
    ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS" \
      || dart_audit_die "could not apply the scanner output-file limit"
  elif [[ "$current_limit" =~ ^[0-9]+$ ]]; then
    if (( current_limit > MAX_SCANNER_OUTPUT_BLOCKS )); then
      ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS" \
        || dart_audit_die "could not lower the scanner output-file limit"
    fi
  else
    dart_audit_die "scanner output-file limit is malformed"
  fi
  local_docker "$@"
)

[ "$AUDIT_UID" -ne 0 ] || dart_audit_die "refuses host or container-root execution"
[ "$AUDIT_GID" -ne 0 ] || dart_audit_die "refuses a root primary group"
[ -x "$PYTHON_BIN" ] || dart_audit_die "trusted Python interpreter is unavailable at $PYTHON_BIN"

[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ] \
  || dart_audit_die "$LOCKFILE is not a regular non-symlink file"
[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ] \
  || dart_audit_die "$IGNORES_FILE is not a regular non-symlink accept-list source"

: "${OSV_SCANNER_VERSION:?dart-audit.sh: OSV_SCANNER_VERSION unset in pins.env}"
: "${OSV_SCALIBR_VERSION:?dart-audit.sh: OSV_SCALIBR_VERSION unset in pins.env}"
: "${OSV_SCANNER_COMMIT:?dart-audit.sh: OSV_SCANNER_COMMIT unset in pins.env}"
: "${OSV_SCANNER_BUILT_AT:?dart-audit.sh: OSV_SCANNER_BUILT_AT unset in pins.env}"
: "${OSV_SCANNER_SHA256:?dart-audit.sh: OSV_SCANNER_SHA256 unset in pins.env}"
: "${OSV_DB_PUB_SHA256:?dart-audit.sh: OSV_DB_PUB_SHA256 unset in pins.env}"
: "${OSV_DB_PUB_SIZE:?dart-audit.sh: OSV_DB_PUB_SIZE unset in pins.env}"
: "${OSV_DB_PUB_CAPTURE_EPOCH:?dart-audit.sh: OSV_DB_PUB_CAPTURE_EPOCH unset in pins.env}"
: "${OSV_DB_PUB_MAX_AGE_DAYS:?dart-audit.sh: OSV_DB_PUB_MAX_AGE_DAYS unset in pins.env}"
: "${DART_AUDIT_IMAGE_ID:?dart-audit.sh: DART_AUDIT_IMAGE_ID unset in pins.env}"
[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || dart_audit_die "DART_AUDIT_IMAGE_ID is malformed"

AUDIT_TMP=""
AUDIT_TMP_ID=""
AUDIT_SUCCESS_MESSAGE=""
cleanup_audit_tmp() {
  local status=$? cleanup_failed=0
  trap - EXIT HUP INT TERM
  if [ -n "$AUDIT_TMP" ]; then
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
      && ! remove_local_docker_authority; then
      echo "dart-audit.sh: preserving changed private Docker authority: $AUDIT_TMP" >&2
      cleanup_failed=1
    elif [ -z "$AUDIT_TMP_ID" ] || [ ! -d "$AUDIT_TMP" ] || [ -L "$AUDIT_TMP" ] \
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
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$AUDIT_TMP")" = "$AUDIT_UID:$AUDIT_GID:700" ] \
  || dart_audit_die "private workspace is not current-user/current-group mode 0700"
initialize_local_docker_authority "$AUDIT_TMP/docker-config" "dart-audit"

# Validate and privately stage exact stable inputs before touching Docker. The
# freshness policy has no caller override; acquisition must deliberately replace
# the immutable image and pins when its captured Pub database ages out.
ACCEPT_COUNT="$($PYTHON_BIN scripts/dart-audit-result.py prepare \
  --policy "$IGNORES_FILE" --lockfile "$LOCKFILE" --output "$AUDIT_TMP")" \
  || dart_audit_die "could not validate and stage Dart advisory inputs"
[[ "$ACCEPT_COUNT" =~ ^[0-9]+$ ]] \
  || dart_audit_die "accept-list validator returned a malformed count"
echo "== R-R3 Dart advisory audit: ${ACCEPT_COUNT} documented accept(s) from ${IGNORES_FILE} =="

if ! "$PYTHON_BIN" scripts/dart-audit-result.py check-freshness \
  --capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH" \
  --max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"; then
  dart_audit_die "the pinned OSV Pub snapshot is not release-current; acquire and review a fresh immutable audit image before release"
fi

SOURCE_LOCK_SHA="$(/usr/bin/sha256sum -- "$LOCKFILE" | /usr/bin/awk '{print $1}')"
SOURCE_POLICY_SHA="$(/usr/bin/sha256sum -- "$IGNORES_FILE" | /usr/bin/awk '{print $1}')"
[ "$SOURCE_LOCK_SHA" = "$(/usr/bin/tr -d '\n' <"$AUDIT_TMP/lockfile.sha256")" ] \
  || dart_audit_die "$LOCKFILE changed during private staging"
[ "$SOURCE_POLICY_SHA" = "$(/usr/bin/tr -d '\n' <"$AUDIT_TMP/policy.sha256")" ] \
  || dart_audit_die "$IGNORES_FILE changed during private staging"
readonly SOURCE_LOCK_SHA SOURCE_POLICY_SHA

IMAGE_ID="$(local_docker image inspect --format '{{.Id}}' "$DART_AUDIT_IMAGE_ID")" \
  || dart_audit_die "the pinned Dart advisory image is not present locally (no pull/build fallback)"
[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_ID" ] \
  || dart_audit_die "Docker did not resolve the exact pinned Dart advisory content ID"
readonly IMAGE_ID

IMAGE_PREFLIGHT_OUT="$AUDIT_TMP/image-preflight.out"
IMAGE_PREFLIGHT_ERR="$AUDIT_TMP/image-preflight.err"
set +e
run_bounded_docker run --rm --pull=never --network=none --read-only \
  --user "$AUDIT_UID:$AUDIT_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=32 --memory=256m --memory-swap=256m --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m \
  --env HOME=/tmp --env LC_ALL=C \
  "$IMAGE_ID" /bin/bash --noprofile --norc -c '
    set -euo pipefail
    expected_version="osv-scanner version: $1
osv-scalibr version: $2
commit: $3
built at: $4"
    [ "$(osv-scanner --version)" = "$expected_version" ]
    printf "%s  %s\n" "$5" /usr/local/bin/osv-scanner \
      | sha256sum --check --strict --status -
    printf "%s  %s\n" "$6" /opt/osv-db/osv-scanner/Pub/all.zip \
      | sha256sum --check --strict --status -
    [ "$(stat -c "%F:%a:%u:%g:%h" /usr/local/bin/osv-scanner)" = \
      "regular file:755:0:0:1" ]
    [ "$(stat -c "%F:%s:%Y:%a:%u:%g:%h" /opt/osv-db/osv-scanner/Pub/all.zip)" = \
      "regular file:$7:$8:644:0:0:1" ]
  ' _ "$OSV_SCANNER_VERSION" "$OSV_SCALIBR_VERSION" \
    "$OSV_SCANNER_COMMIT" "$OSV_SCANNER_BUILT_AT" \
    "$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256" \
    "$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH" \
  >"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"
IMAGE_PREFLIGHT_STATUS=$?
set -e
[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ] || {
  echo "dart-audit.sh: immutable audit-image preflight failed (status $IMAGE_PREFLIGHT_STATUS)" >&2
  /usr/bin/tail -c 65536 -- "$IMAGE_PREFLIGHT_ERR" | /usr/bin/sed 's/^/  /' >&2
  exit 2
}
[ ! -s "$IMAGE_PREFLIGHT_OUT" ] \
  || dart_audit_die "immutable audit-image preflight emitted unexpected stdout"
[ ! -s "$IMAGE_PREFLIGHT_ERR" ] \
  || dart_audit_die "immutable audit-image preflight emitted unexpected stderr"

RESULT_FILE="$AUDIT_TMP/osv-result.json"
ERROR_FILE="$AUDIT_TMP/osv-stderr.log"
STAGED_LOCKFILE_PATH="$AUDIT_TMP/pubspec.lock"
readonly RESULT_FILE ERROR_FILE STAGED_LOCKFILE_PATH

# The scanner sees one stable private lockfile. Status 0 means packages/no
# findings, status 1 means findings, and every other status is infrastructure
# failure. The evaluator then binds status, JSON, and exact stderr telemetry.
set +e
run_bounded_docker run --rm --pull=never --network=none --read-only \
  --user "$AUDIT_UID:$AUDIT_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=512m --memory-swap=512m --cpus=2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
  --env HOME=/tmp/audit-home --env LC_ALL=C \
  --env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db \
  --mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly" \
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
  || dart_audit_die "cannot inspect the OSV result"
ERROR_BYTES="$(/usr/bin/stat -c '%s' -- "$ERROR_FILE")" \
  || dart_audit_die "cannot inspect OSV scanner stderr"
[ "$RESULT_BYTES" -gt 0 ] || dart_audit_die "OSV scanner produced an empty result"
[ "$RESULT_BYTES" -le 67108864 ] || dart_audit_die "OSV scanner result exceeds 64 MiB"
[ "$ERROR_BYTES" -gt 0 ] || dart_audit_die "OSV scanner omitted required telemetry"
[ "$ERROR_BYTES" -le 1048576 ] || dart_audit_die "OSV scanner stderr exceeds 1 MiB"

$PYTHON_BIN scripts/dart-audit-result.py evaluate \
  --policy "$AUDIT_TMP/policy.txt" \
  --result "$RESULT_FILE" --stderr "$ERROR_FILE" \
  --scanner-status "$SCANNER_STATUS" --lockfile "$LOCKFILE"

# Bind green to a still-current DB and unchanged source/private inputs, not only
# to a completed container process.
"$PYTHON_BIN" scripts/dart-audit-result.py check-freshness \
  --capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH" \
  --max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS" >/dev/null \
  || dart_audit_die "the OSV Pub snapshot crossed its release-freshness boundary during the audit"
[ "$(/usr/bin/sha256sum -- "$LOCKFILE" | /usr/bin/awk '{print $1}')" = "$SOURCE_LOCK_SHA" ] \
  || dart_audit_die "$LOCKFILE changed during the audit"
[ "$(/usr/bin/sha256sum -- "$IGNORES_FILE" | /usr/bin/awk '{print $1}')" = "$SOURCE_POLICY_SHA" ] \
  || dart_audit_die "$IGNORES_FILE changed during the audit"
[ "$(/usr/bin/sha256sum -- "$AUDIT_TMP/pubspec.lock" | /usr/bin/awk '{print $1}')" = "$SOURCE_LOCK_SHA" ] \
  || dart_audit_die "the staged lockfile changed during the audit"
[ "$(/usr/bin/sha256sum -- "$AUDIT_TMP/policy.txt" | /usr/bin/awk '{print $1}')" = "$SOURCE_POLICY_SHA" ] \
  || dart_audit_die "the staged accept policy changed during the audit"

AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green — exact OSV status, telemetry, and structured results contain no unignored advisories against the pinned current Pub snapshot (R-R3/R-S11be)"

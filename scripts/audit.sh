#!/usr/bin/env bash
#
# audit.sh — the R-R3 / R-A7 Rust dependency-advisory release gate.
#
# The scan is intentionally split from acquisition. This script never builds,
# pulls, or resolves an image tag. It requires one immutable local image content
# ID, verifies the exact scanner bytes and RustSec checkout inside that image,
# rejects a RustSec snapshot older than 90 days, and runs both scanners offline
# under a non-root, networkless, read-only, resource-bounded Docker authority.
#
# deny.toml remains the sole reason-bearing RustSec accept policy. Mutable
# crates.io yank state is not part of the pinned RustSec/vendor closure and is
# therefore excluded from this reproducible release advisory verdict.
#
# Usage: scripts/audit.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"

readonly LOCKFILE=Cargo.lock
readonly POLICY=deny.toml
readonly VENDOR_DIR=online/cargo-vendor
readonly VENDOR_CONFIG=online/cargo-vendor-config.toml
readonly DOCKER_BIN=/usr/bin/docker
readonly PYTHON_BIN=/usr/bin/python3
readonly MAX_SCANNER_OUTPUT_BLOCKS=65536 # Bash ulimit -f units: 64 MiB on Linux.

audit_die() {
  echo "audit.sh: $*" >&2
  exit 2
}

# Bound stdout and stderr at the Docker client as well as bounding parser input.
# The limit is inherited by the client process, which owns the regular output
# file descriptors opened by the invoking shell.
run_bounded_docker() (
  current_limit="$(ulimit -Sf)" \
    || audit_die "could not read the scanner output-file limit"
  if [ "$current_limit" = unlimited ]; then
    ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS" \
      || audit_die "could not apply the scanner output-file limit"
  elif [[ "$current_limit" =~ ^[0-9]+$ ]]; then
    if (( current_limit > MAX_SCANNER_OUTPUT_BLOCKS )); then
      ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS" \
        || audit_die "could not lower the scanner output-file limit"
    fi
  else
    audit_die "scanner output-file limit is malformed"
  fi
  exec "$DOCKER_BIN" "$@"
)

[ "$(id -u)" -ne 0 ] || audit_die "refuses host or container-root execution"
[ "$(id -g)" -ne 0 ] || audit_die "refuses a root primary group"
[ -x "$DOCKER_BIN" ] || audit_die "trusted Docker client is unavailable at $DOCKER_BIN"
[ -x "$PYTHON_BIN" ] || audit_die "trusted Python interpreter is unavailable at $PYTHON_BIN"

[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ] \
  || audit_die "$LOCKFILE is not a regular non-symlink file"
[ -f "$POLICY" ] && [ ! -L "$POLICY" ] \
  || audit_die "$POLICY is not a regular non-symlink policy"
[ -d "$VENDOR_DIR" ] && [ ! -L "$VENDOR_DIR" ] \
  || audit_die "$VENDOR_DIR is not a real directory"
[ -f "$VENDOR_CONFIG" ] && [ ! -L "$VENDOR_CONFIG" ] \
  || audit_die "$VENDOR_CONFIG is not a regular non-symlink file"

: "${CARGO_AUDIT_VERSION:?audit.sh: CARGO_AUDIT_VERSION unset in pins.env}"
: "${CARGO_DENY_VERSION:?audit.sh: CARGO_DENY_VERSION unset in pins.env}"
: "${ADVISORY_DB_COMMIT:?audit.sh: ADVISORY_DB_COMMIT unset in pins.env}"
: "${ADVISORY_DB_COMMIT_EPOCH:?audit.sh: ADVISORY_DB_COMMIT_EPOCH unset in pins.env}"
: "${ADVISORY_DB_MAX_AGE_DAYS:?audit.sh: ADVISORY_DB_MAX_AGE_DAYS unset in pins.env}"
: "${RUST_AUDIT_IMAGE_ID:?audit.sh: RUST_AUDIT_IMAGE_ID unset in pins.env}"
: "${SHA256_RUST_AUDIT_CARGO_AUDIT:?audit.sh: cargo-audit binary hash unset in pins.env}"
: "${SHA256_RUST_AUDIT_CARGO_DENY:?audit.sh: cargo-deny binary hash unset in pins.env}"
: "${SHA256_CARGO_VENDOR_CLOSURE_V1:?audit.sh: cargo vendor closure pin unset in pins.env}"
: "${SHA256_CARGO_VENDOR_CONFIG:?audit.sh: cargo vendor config pin unset in pins.env}"
[[ "$RUST_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || audit_die "RUST_AUDIT_IMAGE_ID is malformed"

AUDIT_TMP=""
AUDIT_TMP_ID=""
AUDIT_SUCCESS_MESSAGE=""
cleanup_audit_tmp() {
  local status=$? cleanup_failed=0
  trap - EXIT HUP INT TERM
  if [ -n "$AUDIT_TMP" ]; then
    if [ -z "$AUDIT_TMP_ID" ] || [ ! -d "$AUDIT_TMP" ] || [ -L "$AUDIT_TMP" ] \
      || [ "$(/usr/bin/stat -c '%d:%i' -- "$AUDIT_TMP" 2>/dev/null)" != "$AUDIT_TMP_ID" ]; then
      echo "audit.sh: private workspace identity is unavailable or changed: $AUDIT_TMP" >&2
      cleanup_failed=1
    elif ! "$PYTHON_BIN" scripts/verify-private-tree-closure.py \
      --remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"; then
      echo "audit.sh: failed to remove private workspace: $AUDIT_TMP" >&2
      cleanup_failed=1
    elif [ -e "$AUDIT_TMP" ] || [ -L "$AUDIT_TMP" ]; then
      echo "audit.sh: private workspace remains after removal: $AUDIT_TMP" >&2
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
AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-rust-audit.XXXXXXXXXX)"
AUDIT_TMP_ID="$(/usr/bin/stat -c '%d:%i' -- "$AUDIT_TMP")"
readonly AUDIT_TMP AUDIT_TMP_ID
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$AUDIT_TMP")" = "$(id -u):$(id -g):700" ] \
  || audit_die "private workspace is not current-user/current-group mode 0700"

# Validate policy and stage stable private copies before touching the Docker
# daemon. The freshness check intentionally has no caller override: this pinned
# November 2025 DB is release-blocking until an audited refresh is acquired.
ACCEPT_COUNT="$($PYTHON_BIN scripts/rust-audit-policy.py prepare \
  --policy "$POLICY" --lockfile "$LOCKFILE" \
  --vendor-config "$VENDOR_CONFIG" --output "$AUDIT_TMP")" \
  || audit_die "could not validate and stage Rust advisory inputs"
[[ "$ACCEPT_COUNT" =~ ^[0-9]+$ ]] || audit_die "policy validator returned a malformed count"
echo "== R-R3 Rust advisory audit: ${ACCEPT_COUNT} documented accept(s) from $POLICY =="

if ! "$PYTHON_BIN" scripts/rust-audit-policy.py check-freshness \
  --commit-epoch "$ADVISORY_DB_COMMIT_EPOCH" \
  --max-age-days "$ADVISORY_DB_MAX_AGE_DAYS"; then
  audit_die "the pinned RustSec snapshot is not release-current; acquire and review a fresh immutable audit image before release"
fi

SOURCE_LOCK_SHA="$(/usr/bin/sha256sum -- "$LOCKFILE" | /usr/bin/awk '{print $1}')"
SOURCE_POLICY_SHA="$(/usr/bin/sha256sum -- "$POLICY" | /usr/bin/awk '{print $1}')"
SOURCE_VENDOR_CONFIG_SHA="$(/usr/bin/sha256sum -- "$VENDOR_CONFIG" | /usr/bin/awk '{print $1}')"
[ "$SOURCE_VENDOR_CONFIG_SHA" = "$SHA256_CARGO_VENDOR_CONFIG" ] \
  || audit_die "$VENDOR_CONFIG does not match its pin"
[ "$SOURCE_LOCK_SHA" = "$(/usr/bin/tr -d '\n' <"$AUDIT_TMP/lockfile.sha256")" ] \
  || audit_die "$LOCKFILE changed during private staging"
[ "$SOURCE_POLICY_SHA" = "$(/usr/bin/tr -d '\n' <"$AUDIT_TMP/policy.sha256")" ] \
  || audit_die "$POLICY changed during private staging"
[ "$SOURCE_VENDOR_CONFIG_SHA" = "$(/usr/bin/tr -d '\n' <"$AUDIT_TMP/vendor-config.sha256")" ] \
  || audit_die "$VENDOR_CONFIG changed during private staging"
readonly SOURCE_LOCK_SHA SOURCE_POLICY_SHA SOURCE_VENDOR_CONFIG_SHA

"$PYTHON_BIN" scripts/online-input-provenance.py verify-subtree \
  --tree "$VENDOR_DIR" --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
  || audit_die "the Cargo vendor closure does not match its canonical pin"

IMAGE_ID="$($DOCKER_BIN image inspect --format '{{.Id}}' "$RUST_AUDIT_IMAGE_ID")" \
  || audit_die "the pinned Rust advisory image is not present locally (no pull/build fallback)"
[ "$IMAGE_ID" = "$RUST_AUDIT_IMAGE_ID" ] \
  || audit_die "Docker did not resolve the exact pinned Rust advisory content ID"
readonly IMAGE_ID

IMAGE_PREFLIGHT_OUT="$AUDIT_TMP/image-preflight.out"
IMAGE_PREFLIGHT_ERR="$AUDIT_TMP/image-preflight.err"
set +e
run_bounded_docker run --rm --pull=never --network=none --read-only \
  --user "$(id -u):$(id -g)" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=32 --memory=256m --memory-swap=256m --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m \
  --env HOME=/tmp --env RUSTUP_TOOLCHAIN=1.75.0-x86_64-unknown-linux-gnu \
  "$IMAGE_ID" /bin/bash --noprofile --norc -c '
    set -euo pipefail
    [ "$(cargo-audit --version)" = "cargo-audit $1" ]
    [ "$(cargo-deny --version)" = "cargo-deny $2" ]
    printf "%s  %s\n" "$3" /usr/local/cargo/bin/cargo-audit \
      | sha256sum --check --strict -
    printf "%s  %s\n" "$4" /usr/local/cargo/bin/cargo-deny \
      | sha256sum --check --strict -
    [ "$(git -c safe.directory=/opt/advisory-db -C /opt/advisory-db rev-parse HEAD)" = "$5" ]
    [ "$(git -c safe.directory=/opt/advisory-db -C /opt/advisory-db show -s --format=%ct HEAD)" = "$6" ]
    [ -z "$(git -c safe.directory=/opt/advisory-db -C /opt/advisory-db status --porcelain --untracked-files=all)" ]
  ' _ "$CARGO_AUDIT_VERSION" "$CARGO_DENY_VERSION" \
    "$SHA256_RUST_AUDIT_CARGO_AUDIT" "$SHA256_RUST_AUDIT_CARGO_DENY" \
    "$ADVISORY_DB_COMMIT" "$ADVISORY_DB_COMMIT_EPOCH" \
  >"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"
IMAGE_PREFLIGHT_STATUS=$?
set -e
[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ] || {
  echo "audit.sh: immutable audit-image preflight failed (status $IMAGE_PREFLIGHT_STATUS)" >&2
  /usr/bin/tail -c 65536 -- "$IMAGE_PREFLIGHT_ERR" | /usr/bin/sed 's/^/  /' >&2
  exit 2
}

mapfile -t IGNORE_IDS <"$AUDIT_TMP/accepted-ids.txt"
IGNORE_FLAGS=()
for advisory_id in "${IGNORE_IDS[@]}"; do
  [ -n "$advisory_id" ] || audit_die "staged accept list contains an empty id"
  IGNORE_FLAGS+=(--ignore "$advisory_id")
done
[ "${#IGNORE_IDS[@]}" -eq "$ACCEPT_COUNT" ] \
  || audit_die "staged accept-list cardinality changed"

AUDIT_RESULT="$AUDIT_TMP/cargo-audit.json"
AUDIT_ERROR="$AUDIT_TMP/cargo-audit.stderr"
echo "== cargo-audit: exact lockfile against the pinned, fresh RustSec snapshot =="
set +e
run_bounded_docker run --rm --pull=never --network=none --read-only \
  --user "$(id -u):$(id -g)" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=512m --memory-swap=512m --cpus=2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m \
  --env HOME=/audit --env RUSTUP_TOOLCHAIN=1.75.0-x86_64-unknown-linux-gnu \
  --mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly" \
  --workdir /audit "$IMAGE_ID" \
  cargo-audit audit --file /audit/Cargo.lock --db /opt/advisory-db --no-fetch --deny warnings --json \
  "${IGNORE_FLAGS[@]}" >"$AUDIT_RESULT" 2>"$AUDIT_ERROR"
CARGO_AUDIT_STATUS=$?
set -e
if [ "$CARGO_AUDIT_STATUS" -ne 0 ]; then
  echo "audit.sh: cargo-audit found an unaccepted advisory or failed (status $CARGO_AUDIT_STATUS)" >&2
  [ ! -s "$AUDIT_ERROR" ] || /usr/bin/tail -c 65536 -- "$AUDIT_ERROR" | /usr/bin/sed 's/^/  /' >&2
  [ ! -s "$AUDIT_RESULT" ] || /usr/bin/tail -c 65536 -- "$AUDIT_RESULT" | /usr/bin/sed 's/^/  /' >&2
  exit 1
fi
"$PYTHON_BIN" scripts/rust-audit-policy.py validate-audit-result \
  --result "$AUDIT_RESULT" --status "$CARGO_AUDIT_STATUS" \
  --policy "$POLICY" --expected-db-commit "$ADVISORY_DB_COMMIT"

DENY_OUTPUT="$AUDIT_TMP/cargo-deny.stdout"
DENY_ERROR="$AUDIT_TMP/cargo-deny.stderr"
echo "== cargo-deny: offline metadata advisory scan against the same snapshot =="
set +e
run_bounded_docker run --rm --pull=never --network=none --read-only \
  --user "$(id -u):$(id -g)" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=256 --memory=2g --memory-swap=2g --cpus=2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m \
  --tmpfs /work/.cargo:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/.git:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/.harness-state:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/online:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/target:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/flutter/.dart_tool:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --tmpfs /work/flutter/build:rw,noexec,nosuid,nodev,mode=0700,size=1m \
  --env HOME=/tmp/home --env CARGO_HOME=/tmp/cargo-home \
  --env RUSTUP_TOOLCHAIN=1.75.0-x86_64-unknown-linux-gnu \
  --mount "type=bind,source=$REPO_ROOT,target=/work,readonly" \
  --mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly" \
  --mount "type=bind,source=$REPO_ROOT/$VENDOR_DIR,target=/vendor,readonly" \
  --workdir /work "$IMAGE_ID" /bin/bash --noprofile --norc -c '
    set -euo pipefail
    db_root=/tmp/advisory-dbs
    db="$db_root/$CARGO_DENY_DB_DIR"
    mkdir -p "$db_root" /tmp/cargo-home /tmp/home
    cp -a -- /opt/advisory-db "$db"
    [ "$(git -c safe.directory="$db" -C "$db" rev-parse HEAD)" = "$1" ]
    [ "$(git -c safe.directory="$db" -C "$db" show -s --format=%ct HEAD)" = "$2" ]
    [ -z "$(git -c safe.directory="$db" -C "$db" status --porcelain --untracked-files=all)" ]
    cp -- /audit/cargo.config.toml /tmp/cargo-home/config.toml
    cargo-deny --format json --locked --offline \
      --manifest-path /work/Cargo.toml \
      check -c /audit/deny.runtime.toml advisories --disable-fetch
    [ "$(git -c safe.directory="$db" -C "$db" rev-parse HEAD)" = "$1" ]
    [ -z "$(git -c safe.directory="$db" -C "$db" status --porcelain --untracked-files=all)" ]
  ' _ "$ADVISORY_DB_COMMIT" "$ADVISORY_DB_COMMIT_EPOCH" \
  >"$DENY_OUTPUT" 2>"$DENY_ERROR"
CARGO_DENY_STATUS=$?
set -e
if [ "$CARGO_DENY_STATUS" -ne 0 ]; then
  echo "audit.sh: cargo-deny found an unaccepted advisory or failed (status $CARGO_DENY_STATUS)" >&2
  [ ! -s "$DENY_ERROR" ] || /usr/bin/tail -c 65536 -- "$DENY_ERROR" | /usr/bin/sed 's/^/  /' >&2
  [ ! -s "$DENY_OUTPUT" ] || /usr/bin/tail -c 65536 -- "$DENY_OUTPUT" | /usr/bin/sed 's/^/  /' >&2
  exit 1
fi

"$PYTHON_BIN" scripts/rust-audit-policy.py validate-deny-result \
  --stdout "$DENY_OUTPUT" --stderr "$DENY_ERROR" --status "$CARGO_DENY_STATUS"

# Bind the final green message to stable real inputs and the full vendor subtree,
# not merely to the container statuses.
[ "$(/usr/bin/sha256sum -- "$LOCKFILE" | /usr/bin/awk '{print $1}')" = "$SOURCE_LOCK_SHA" ] \
  || audit_die "$LOCKFILE changed during the audit"
[ "$(/usr/bin/sha256sum -- "$POLICY" | /usr/bin/awk '{print $1}')" = "$SOURCE_POLICY_SHA" ] \
  || audit_die "$POLICY changed during the audit"
[ "$(/usr/bin/sha256sum -- "$VENDOR_CONFIG" | /usr/bin/awk '{print $1}')" = "$SOURCE_VENDOR_CONFIG_SHA" ] \
  || audit_die "$VENDOR_CONFIG changed during the audit"
"$PYTHON_BIN" scripts/online-input-provenance.py verify-subtree \
  --tree "$VENDOR_DIR" --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
  || audit_die "the Cargo vendor closure changed during the audit"

AUDIT_SUCCESS_MESSAGE="VERIFY-AUDIT: green — immutable-image cargo-audit and cargo-deny completed offline against one current pinned RustSec snapshot with exact reasoned accepts (R-R3/R-S11bf)"

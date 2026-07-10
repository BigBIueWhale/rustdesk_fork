#!/usr/bin/env bash
#
# audit.sh — the R-R3 / R-A7 dependency-advisory gate.
#
# The spec (R-R3) requires the advisory gate to be WIRED, "so the green result
# is enforced, not one-time." This runs cargo-audit and cargo-deny from the
# pinned scripts/Dockerfile.audit image against the same RustSec advisory-db
# snapshot. deny.toml is the SINGLE source of truth for consciously-accepted
# advisories, each carrying a reason (R-R3's "ignore + reason"). Exits non-zero
# on ANY unignored advisory (fail-closed).
#
# This is NOT the day-to-day verify.sh gate (that one is fast + offline). The
# audit needs the advisory-db + advisory tools, so it is a separate, slower gate
# — run it in CI and before a release, not on every inner-loop edit.
#
# Usage:  scripts/audit.sh
set -euo pipefail

cd "$(dirname "$0")/.."
. scripts/pins.env

: "${RUST_VERSION:?audit.sh: RUST_VERSION unset in pins.env}"
: "${CARGO_AUDIT_VERSION:?audit.sh: CARGO_AUDIT_VERSION unset in pins.env}"
: "${CARGO_DENY_VERSION:?audit.sh: CARGO_DENY_VERSION unset in pins.env}"
: "${ADVISORY_DB_COMMIT:?audit.sh: ADVISORY_DB_COMMIT unset in pins.env}"
: "${SHA256_BASEIMAGE_RUST_1_75_SLIM:?audit.sh: SHA256_BASEIMAGE_RUST_1_75_SLIM unset in pins.env}"

IMG=rd-audit

echo "== building the Rust advisory gate image (cargo-audit ${CARGO_AUDIT_VERSION}, cargo-deny ${CARGO_DENY_VERSION}, pinned advisory-db) =="
docker build -q \
  --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_RUST_1_75_SLIM}" \
  --build-arg "RUST_VERSION=${RUST_VERSION}" \
  --build-arg "CARGO_AUDIT_VERSION=${CARGO_AUDIT_VERSION}" \
  --build-arg "CARGO_DENY_VERSION=${CARGO_DENY_VERSION}" \
  --build-arg "ADVISORY_DB_SHA=${ADVISORY_DB_COMMIT}" \
  -t "$IMG" -f scripts/Dockerfile.audit scripts >/dev/null

# deny.toml is the single source of truth. Parse TOML, not comments: advisory ids
# mentioned in prose as "fixed" must never become cargo-audit ignore flags.
accepts_tmp=$(mktemp)
trap 'rm -f "$accepts_tmp"' EXIT
python3 - <<'PY' >"$accepts_tmp"
import re
import sys
import tomllib

with open("deny.toml", "rb") as f:
    data = tomllib.load(f)

entries = data.get("advisories", {}).get("ignore", [])
if not isinstance(entries, list):
    print("audit.sh: deny.toml [advisories].ignore must be a list", file=sys.stderr)
    sys.exit(2)

ids = []
seen = set()
for index, entry in enumerate(entries, 1):
    if not isinstance(entry, dict):
        print(f"audit.sh: deny.toml ignore entry {index} must be {{ id, reason }}", file=sys.stderr)
        sys.exit(2)
    adv_id = entry.get("id")
    reason = entry.get("reason")
    if not isinstance(adv_id, str) or not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", adv_id):
        print(f"audit.sh: deny.toml ignore entry {index} has an invalid RUSTSEC id", file=sys.stderr)
        sys.exit(2)
    if not isinstance(reason, str) or not reason.strip():
        print(f"audit.sh: deny.toml ignore entry {adv_id} has no reason", file=sys.stderr)
        sys.exit(2)
    if adv_id in seen:
        print(f"audit.sh: duplicate deny.toml ignore id {adv_id}", file=sys.stderr)
        sys.exit(2)
    seen.add(adv_id)
    ids.append(adv_id)

sys.stdout.write("\n".join(sorted(ids)))
PY
mapfile -t IGNORES <"$accepts_tmp"
IGNORE_FLAGS=()
for id in "${IGNORES[@]}"; do IGNORE_FLAGS+=(--ignore "$id"); done
echo "== R-R3 advisory audit: ${#IGNORES[@]} documented accepts from deny.toml =="

# The repo mount is read-only. cargo-audit is a lockfile scan and runs without
# fetching advisory data; cargo-deny needs cargo metadata, so it may populate the
# external Docker cargo caches for locked git dependencies, but it still reads the
# baked advisory snapshot with fetching disabled.
echo "== cargo-audit: lockfile scan against the pinned RustSec snapshot =="
docker run --rm \
  -v "$PWD:/work:ro" \
  -v rd-cargo-cache:/usr/local/cargo/registry \
  -w /work "$IMG" \
  bash -c 'cargo-audit audit --db "$ADVISORY_DB" --no-fetch "$@"' _ "${IGNORE_FLAGS[@]}"

echo "== cargo-deny: metadata advisory scan against the pinned RustSec snapshot =="
docker run --rm \
  -v "$PWD:/work:ro" \
  -v rd-cargo-cache:/usr/local/cargo/registry \
  -v rd-cargo-git-cache:/usr/local/cargo/git \
  -w /work "$IMG" \
  bash -c '
    set -euo pipefail
    tmp=$(mktemp)
    trap "rm -f \"$tmp\"" EXIT
    awk -v db_path="$CARGO_DENY_DB_PATH" '"'"'
      BEGIN { inserted = 0 }
      /^\[advisories\]$/ {
        print
        print "db-path = \"" db_path "\""
        inserted = 1
        next
      }
      { print }
      END { if (!inserted) exit 2 }
    '"'"' deny.toml >"$tmp"
    cargo-deny --locked check -c "$tmp" advisories --disable-fetch
  '

echo "VERIFY-AUDIT: green — cargo-audit and cargo-deny found no unignored advisories against the pinned snapshot (R-R3/R-A7)"

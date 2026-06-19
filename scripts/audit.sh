#!/usr/bin/env bash
#
# audit.sh — the R-R3 / R-A7 dependency-advisory gate.
#
# The spec (R-R3) requires the advisory gate to be WIRED, "so the green result
# is enforced, not one-time." This runs cargo-audit 0.21.1 from the pinned
# scripts/Dockerfile.audit image (cargo-audit + a pinned advisory-db snapshot)
# against the repo's --locked Cargo.lock, applying the deny.toml accept-list —
# the SINGLE source of truth for consciously-accepted advisories, each carrying
# a reason (R-R3's "ignore + reason"). Exits non-zero on ANY unignored advisory
# (fail-closed).
#
# This is NOT the day-to-day verify.sh gate (that one is fast + offline). The
# audit needs the advisory-db + a cargo-audit compile, so it is a separate,
# slower gate — run it in CI and before a release, not on every inner-loop edit.
#
# Usage:  scripts/audit.sh
set -euo pipefail

cd "$(dirname "$0")/.."
IMG=rd-audit

echo "== building the advisory gate image (cargo-audit 0.21.1 + pinned advisory-db) =="
docker build -q -t "$IMG" -f scripts/Dockerfile.audit scripts >/dev/null

# deny.toml is the single source of truth: every RUSTSEC id there is a reasoned
# accept (R-R3). Derive the cargo-audit --ignore flags from it so the two tools
# (cargo-deny via deny.toml, cargo-audit via these flags) never drift apart.
mapfile -t IGNORES < <(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' deny.toml | sort -u)
if [ "${#IGNORES[@]}" -eq 0 ]; then
  echo "audit.sh: no accepts found in deny.toml — refusing to run blind" >&2
  exit 2
fi
IGNORE_FLAGS=()
for id in "${IGNORES[@]}"; do IGNORE_FLAGS+=(--ignore "$id"); done
echo "== R-R3 advisory audit: ${#IGNORES[@]} documented accepts from deny.toml =="

# Read-only mounts: the audit must never mutate the repo. The repo at /work and
# the cached crates.io index (rd-cargo-cache, populated by the build gates) so
# cargo-audit's yanked-crate check can run offline — without an index it cannot
# resolve any crate and floods non-fatal "no such crate" noise that could mask a
# real finding. --no-fetch + --db pin the advisory snapshot baked into the image
# (no network). cargo-audit exits non-zero on any unignored advisory, and
# `set -e` propagates that — fail-closed.
docker run --rm \
  -v "$PWD:/work:ro" \
  -v rd-cargo-cache:/usr/local/cargo/registry:ro \
  -w /work "$IMG" \
  bash -c 'cargo audit --db "$ADVISORY_DB" --no-fetch "$@"' _ "${IGNORE_FLAGS[@]}"

echo "VERIFY-AUDIT: green — no unignored advisories against the pinned snapshot (R-R3/R-A7)"

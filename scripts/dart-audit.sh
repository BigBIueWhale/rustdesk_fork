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

IMG=rd-dart-audit
LOCKFILE=flutter/pubspec.lock
IGNORES_FILE=scripts/dart-audit-ignores.txt

if [ ! -f "$LOCKFILE" ]; then
  echo "dart-audit.sh: $LOCKFILE not found — nothing to audit" >&2
  exit 2
fi

# Every pin must be present — refuse to build a non-reproducible image.
: "${OSV_SCANNER_VERSION:?dart-audit.sh: OSV_SCANNER_VERSION unset in pins.env}"
: "${OSV_SCANNER_SHA256:?dart-audit.sh: OSV_SCANNER_SHA256 unset in pins.env}"
: "${OSV_DB_PUB_SHA256:?dart-audit.sh: OSV_DB_PUB_SHA256 unset in pins.env}"
: "${SHA256_BASEIMAGE_UBUNTU_1804:?dart-audit.sh: SHA256_BASEIMAGE_UBUNTU_1804 unset in pins.env}"

echo "== building the Dart advisory gate image (osv-scanner ${OSV_SCANNER_VERSION} + pinned OSV Pub db) =="
docker build -q \
  --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
  --build-arg "OSV_SCANNER_VERSION=${OSV_SCANNER_VERSION}" \
  --build-arg "OSV_SCANNER_SHA256=${OSV_SCANNER_SHA256}" \
  --build-arg "OSV_DB_PUB_SHA256=${OSV_DB_PUB_SHA256}" \
  -t "$IMG" -f scripts/Dockerfile.dart-audit scripts >/dev/null

# dart-audit-ignores.txt is the single accept-list: strip comments/blanks, keep
# the first whitespace-delimited token (the advisory id) of each remaining line.
mapfile -t IGNORES < <(sed -E 's/#.*//' "$IGNORES_FILE" | awk '{print $1}' | grep -E '\S' | sort -u)
echo "== R-R3 Dart advisory audit: ${#IGNORES[@]} documented accept(s) from ${IGNORES_FILE} =="

# Run the scan offline against a READ-ONLY mount of the repo (the audit must never
# mutate it) and capture the machine-readable JSON. osv-scanner exits non-zero
# when it finds vulnerabilities; with --format=json that exit is advisory, so we
# decide pass/fail from the parsed ids below (more precise than the binary's exit,
# and it lets the accept-list subtract). `|| true` keeps `set -e` from aborting on
# the expected non-zero, but the JSON is the authority. --offline forbids any
# network and errors if the baked db is missing — fail-closed.
JSON="$(docker run --rm \
  -v "$PWD:/work:ro" \
  -w /work "$IMG" \
  osv-scanner --offline --format=json --lockfile="$LOCKFILE" 2>/dev/null || true)"

if [ -z "$JSON" ]; then
  echo "dart-audit.sh: osv-scanner produced no output — refusing to pass blind" >&2
  exit 2
fi

# Compare the found advisory ids against the accept-list. Any id (or any of its
# aliases, e.g. the CVE behind a GHSA) present in the accept-list is suppressed;
# anything left over fails the gate. The JSON and the accept-list are passed via
# the environment (stdin belongs to the heredoc), and this `python3` is the sole
# command on the line, so `set -e` propagates its non-zero exit — fail-closed.
OSV_JSON="$JSON" \
IGNORES="$(printf '%s\n' "${IGNORES[@]:-}")" \
python3 - "$LOCKFILE" <<'PY'
import json, os, sys

lockfile = sys.argv[1]
ignores = {x.strip() for x in os.environ.get("IGNORES", "").splitlines() if x.strip()}
data = json.loads(os.environ["OSV_JSON"])

unignored = []   # (id, package, version, fixed)
accepted  = []   # (id, package)
for result in data.get("results", []):
    for pkg in result.get("packages", []):
        p = pkg.get("package", {})
        name, ver = p.get("name", "?"), p.get("version", "?")
        for vuln in pkg.get("vulnerabilities", []):
            vid = vuln.get("id", "?")
            ids = {vid, *vuln.get("aliases", [])}
            fixed = ""
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed = ev["fixed"]
            if ids & ignores:
                accepted.append((vid, name))
            else:
                unignored.append((vid, name, ver, fixed))

if accepted:
    print(f"-- {len(accepted)} accepted advisory(ies) (from the accept-list):")
    for vid, name in accepted:
        print(f"     ACCEPTED  {vid}  ({name})")

if unignored:
    print(f"\nDART-AUDIT: FAIL — {len(unignored)} unignored advisory(ies) against {lockfile}:")
    for vid, name, ver, fixed in unignored:
        fx = f"  (fixed in {fixed})" if fixed else ""
        print(f"     {vid}  {name} {ver}{fx}")
    print("\nResolve by an in-range pubspec.lock bump, or add the id to "
          "scripts/dart-audit-ignores.txt WITH A REASON (R-R3).")
    sys.exit(1)

print("\nVERIFY-DART-AUDIT: green — no unignored advisories against the pinned "
      "OSV Pub snapshot (R-R3).")
PY

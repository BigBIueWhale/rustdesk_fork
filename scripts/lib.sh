#!/usr/bin/env bash
# scripts/lib.sh — shared, fail-loud helpers for the build harness (R-B9/B10).
#
# Sourced by every build script. Embodies the "one mode, the good one" discipline:
# validate the environment to EXACT pinned versions, fail loud with a precise
# message, no fallbacks, no "install latest if missing", pin every version from the
# single manifest (pins.env), and verify every fetched artifact against its pinned
# SHA-256 (fail-closed). This file RUNS NOTHING on its own — it only defines
# functions; the build scripts call them.
#
# Usage:
#   set -euo pipefail
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/lib.sh"
#   load_pins
#   require_cmd cargo rustc
#   assert_version "rustc 1.75" "$(rustc --version)"

# Strict mode for any script that sources us (callers should also set it).
set -euo pipefail

# Resolve the repo root from this file's location (scripts/ is at repo top).
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/.." && pwd)"
ONLINE_DIR="${ONLINE_DIR:-$REPO_ROOT/online}"
PINS_FILE="$LIB_DIR/pins.env"

# ── Logging / failure ─────────────────────────────────────────────────────────
log()  { printf '\033[0;36m[harness]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[0;33m[harness:warn]\033[0m %s\n' "$*" >&2; }
# die: print a precise message and abort the whole pipeline (no fallback path).
die()  { printf '\033[0;31m[harness:FATAL]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Pin manifest ──────────────────────────────────────────────────────────────
# Load the single source of truth. Every version downstream comes from here; no
# script may resolve "latest" or a moving channel (R-B5a, R-R1).
load_pins() {
    [ -f "$PINS_FILE" ] || die "pins manifest not found: $PINS_FILE"
    # shellcheck disable=SC1090
    source "$PINS_FILE"
    [ -n "${RUST_VERSION:-}" ] || die "pins.env is missing RUST_VERSION — refusing to guess"
}

# ── Environment validation (exact versions, then abort) ───────────────────────
# require_cmd: each named tool MUST be on PATH, else abort. Presence only — pair
# with assert_version for the version check.
require_cmd() {
    local missing=()
    local c
    for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
    [ ${#missing[@]} -eq 0 ] || die "required tool(s) not found: ${missing[*]}"
}

# assert_version EXPECT ACTUAL: ACTUAL must CONTAIN the EXACT pinned EXPECT string,
# else abort. Validates the pinned version, not mere presence (R-B9). Example:
#   assert_version "$RUST_VERSION" "$(rustc --version)"   # "1.75" in "rustc 1.75.0 ..."
assert_version() {
    local expect="$1" actual="$2"
    case "$actual" in
        *"$expect"*) log "version OK: matched '$expect'" ;;
        *) die "version mismatch: expected to find '$expect', got '$actual' — pin from pins.env, do not upgrade in place" ;;
    esac
}

# ── SHA-256 verification of ./online artifacts (R-B10/R-B12), fail-closed ──────
# verify_sha256 FILE EXPECTED_SHA: abort unless FILE hashes to EXPECTED_SHA. The
# R-B12 sentinel (__PENDING_R_B12__) is a HARD error — never fetch-and-trust, never
# skip the check (R-B10). Never falls back to "download it anyway".
verify_sha256() {
    local file="$1" expected="${2:-}"
    [ -n "$expected" ] || die "verify_sha256: no expected hash given for $file"
    [ "$expected" != "${SHA_PENDING:-__PENDING_R_B12__}" ] || \
        die "verify_sha256: $file is pinned to the R-B12 sentinel — establish its audited dual-source provenance in pins.env before any fetch"
    [ -f "$file" ] || die "verify_sha256: file not found: $file"
    local got
    got="$(sha256sum "$file" | awk '{print $1}')"
    [ "$got" = "$expected" ] || die "SHA-256 mismatch for $file: expected $expected, got $got"
    log "sha256 OK: $(basename "$file")"
}

# ── Offline-build guards (R-B10) ──────────────────────────────────────────────
# require_online_complete: the build runs with the network namespace removed and
# MUST refuse to start if ./online is missing/incomplete (never silently fetch).
require_online_complete() {
    [ -d "$ONLINE_DIR" ] || die "./online cache is absent — run scripts/online-fetch.sh first (the ONLY networked step, R-B10)"
}

# assert_offline: assert no network is reachable from the compile container, so a
# build that "works" could not have silently fetched (paired with the R-B10
# canary build.rs in CI). Best-effort; the authoritative isolation is
# --network=none on the container itself.
assert_offline() {
    if command -v curl >/dev/null 2>&1; then
        ! curl -sSf --max-time 2 https://example.com >/dev/null 2>&1 \
            || die "network is reachable inside the build step — it MUST run with --network=none (R-B10)"
    fi
    log "offline guard OK"
}

# assert_no_build_host_network_residual: the Windows VM harness must not run on
# a host where the old system-libvirt default NAT network is still present. That
# network creates virbr0, host DNS/DHCP listeners, and usually enables IPv4
# forwarding. The cleanup path is manifest-gated in cleanup.sh; this check is the
# artifact/provision preflight that refuses to build from a dirty host.
assert_no_build_host_network_residual() {
    require_cmd ip ss
    local dirty=()
    local listeners

    if ip link show virbr0 >/dev/null 2>&1; then
        dirty+=("virbr0 exists")
    fi

    listeners="$(ss -ltnup 2>/dev/null | grep -E '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' || true)"
    if [ -n "$listeners" ]; then
        dirty+=("libvirt default-network DNS/DHCP listener active")
    fi

    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
        dirty+=("net.ipv4.ip_forward=1")
    fi

    if [ "${#dirty[@]}" -ne 0 ]; then
        [ -z "$listeners" ] || printf '%s\n' "$listeners" >&2
        die "dirty build-host network state (${dirty[*]}); run scripts/cleanup.sh --build-host-network with privileges if harness-created, or reconcile manually before Windows VM artifact work (R-B11a/§12.2)"
    fi

    log "build-host network preflight OK (no virbr0, no libvirt default-network listener, ip_forward=0)"
}

# ── Submodule / lockfile state (R-B9: assert before compiling) ────────────────
# assert_repo_state: hbb_common is absorbed in-tree (not a submodule) and the
# committed lockfile must be the one we build from (--locked).
assert_repo_state() {
    [ -f "$REPO_ROOT/libs/hbb_common/src/lib.rs" ] || die "libs/hbb_common is not populated in-tree (R-R1)"
    [ ! -f "$REPO_ROOT/.gitmodules" ] || die ".gitmodules present — hbb_common must be absorbed in-tree, not a submodule (R-R1)"
    [ -f "$REPO_ROOT/Cargo.lock" ] || die "Cargo.lock missing — the build is lockfile-pinned (R-R1, --locked)"
    [ -f "$REPO_ROOT/rust-toolchain.toml" ] || die "rust-toolchain.toml missing — the toolchain pin upstream omits (R-R1)"
}

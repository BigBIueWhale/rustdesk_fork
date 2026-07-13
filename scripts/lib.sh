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

# The stable R-B2 Android signing key lives here by DEFAULT (a gitignored secret under .harness-state,
# generated ONCE by gen-android-keystore.sh, reused for every release). build-android.sh + build-release.sh
# read these paths by default, so a bare `bash scripts/build-release.sh` needs NO env vars. Override with
# ANDROID_KEYSTORE / ANDROID_KEYSTORE_PASS_FILE only to point at a key kept somewhere else.
DEFAULT_ANDROID_KEYSTORE="$REPO_ROOT/.harness-state/android-keystore/rustdesk-fork.jks"
DEFAULT_ANDROID_KEYSTORE_PASS_FILE="$REPO_ROOT/.harness-state/android-keystore/pass"

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

verify_sha512() {
    local file="$1" expected="${2:-}"
    [ -n "$expected" ] || die "verify_sha512: no expected hash given for $file"
    [ "$expected" != "${SHA_PENDING:-__PENDING_R_B12__}" ] || \
        die "verify_sha512: $file is pinned to the R-B12 sentinel"
    [ -f "$file" ] || die "verify_sha512: file not found: $file"
    local got
    got="$(sha512sum "$file" | awk '{print $1}')"
    [ "$got" = "$expected" ] || die "SHA-512 mismatch for $file: expected $expected, got $got"
    log "sha512 OK: $(basename "$file")"
}

# ── Offline-build guards (R-B10) ──────────────────────────────────────────────
# require_online_complete: the build runs with the network namespace removed and
# MUST refuse to start if ./online is missing/incomplete (never silently fetch).
require_online_complete() {
    [ -d "$ONLINE_DIR" ] || die "./online cache is absent — run scripts/online-fetch.sh first (the ONLY networked step, R-B10)"
    require_cmd python3
    local expected="${SHA256_ONLINE_CLOSURE_V1:-}"
    [ -n "$expected" ] || die "pins.env is missing SHA256_ONLINE_CLOSURE_V1"
    [ "$expected" != "${SHA_PENDING:-__PENDING_R_B12__}" ] || die "SHA256_ONLINE_CLOSURE_V1 is not established"
    verify_online_glob_cardinality
    python3 "$LIB_DIR/online-input-provenance.py" verify --tree "$ONLINE_DIR" --expected "$expected" \
        || die "./online does not equal its canonical pinned closure"
    log "./online canonical closure verified: $expected"
}

create_private_online_snapshot() {
    [ "$#" -eq 1 ] || die "create_private_online_snapshot requires one absent destination path"
    local expected="${SHA256_ONLINE_CLOSURE_V1:-}"
    [ -n "$expected" ] || die "pins.env is missing SHA256_ONLINE_CLOSURE_V1"
    require_cmd python3
    python3 "$LIB_DIR/online-input-provenance.py" snapshot-create \
        --source "$ONLINE_DIR" --destination "$1" --expected "$expected" \
        || die "private ./online snapshot creation failed"
}

verify_private_online_snapshot() {
    [ "$#" -eq 1 ] || die "verify_private_online_snapshot requires one snapshot path"
    local expected="${SHA256_ONLINE_CLOSURE_V1:-}"
    [ -n "$expected" ] || die "pins.env is missing SHA256_ONLINE_CLOSURE_V1"
    require_cmd python3
    [ "$(stat -c '%a' "$1" 2>/dev/null)" = "700" ] || die "private snapshot parent is not mode 0700: $1"
    python3 "$LIB_DIR/online-input-provenance.py" snapshot-verify --tree "$1/online" --expected "$expected" \
        || die "private ./online snapshot changed during build use"
}

assert_single_online_match() {
    [ "$#" -eq 2 ] || die "assert_single_online_match requires PATTERN EXPECTED_BASENAME"
    local pattern="$1" expected="$2" matches=()
    mapfile -d '' matches < <(find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 -type f -name "$pattern" -print0)
    [ "${#matches[@]}" -eq 1 ] || die "./online/$pattern must resolve to exactly one top-level regular file"
    [ "${matches[0]}" = "$ONLINE_DIR/$expected" ] || die "./online/$pattern resolved to ${matches[0]}, expected $ONLINE_DIR/$expected"
}

verify_online_glob_cardinality() {
    assert_single_online_match 'rust-1.*.tar.xz' "rust-${RUST_VERSION}.tar.xz"
    assert_single_online_match 'flutter-*.tar.xz' "flutter-${FLUTTER_VERSION}.tar.xz"
    assert_single_online_match 'llvm-*.tar.xz' "llvm-${LLVM_VERSION}.tar.xz"
    assert_single_online_match 'flutter-windows-*.zip' "flutter-windows-${FLUTTER_VERSION}.zip"
}

verify_online_pinned_archives() {
    verify_online_glob_cardinality
    verify_online_shas \
        "rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
        "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz" "$SHA256_RUST_STD_ANDROID_1_75" \
        "flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
        "flutter-windows-${FLUTTER_VERSION}.zip" "$SHA256_FLUTTER_WIN_3_24_5" \
        "flutter-windows-engine.tar.gz" "$SHA256_FLUTTER_WIN_ENGINE" \
        "flutter-pub-cache.tar.gz" "$SHA256_FLUTTER_PUB_CACHE" \
        "llvm-${LLVM_VERSION}.tar.xz" "$SHA256_LLVM_15_0_6" \
        "llvm-windows-${LLVM_VERSION}.exe" "$SHA256_LLVM_WIN_15_0_6" \
        "python-windows-${PYTHON_VERSION}.exe" "$SHA256_PYTHON_WIN_3_11_9" \
        "olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" "$SHA256_OLEFILE_0_47" \
        "wix-nuget.tar.gz" "$SHA256_WIX_NUGET" \
        "android-ndk-${ANDROID_NDK_VERSION}.zip" "$SHA256_ANDROID_NDK_R28C" \
        "android-cmdline-tools.zip" "$SHA256_ANDROID_CMDLINE_TOOLS" \
        "vcpkg-${VCPKG_BASELINE}.tar.gz" "$SHA256_VCPKG_120DEAC3" \
        "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "$SHA256_FRB_1_80_1" \
        "win11.iso" "$SHA256_WIN11_ISO" \
        "vs-buildtools.layout.tar" "$SHA256_VS_BUILDTOOLS" \
        "win/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi" "$SHA256_RUST_MSVC_1_75" \
        "win/Git-2.45.2-64-bit.exe" "$SHA256_GIT_WIN_2_45_2" \
        "win/rustup-init.exe" "$SHA256_RUSTUP_INIT_WIN"
    verify_sha512 "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"
}

require_pinned_builder_image() {
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "require_pinned_builder_image requires ROLE [IMAGE_REF]"
    local role="$1" image_ref="${2:-}" prefix base image_id dockerfile_sha dpkg_sha
    case "$role" in
        deb-builder) prefix=DEB_BUILDER; base="ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" ;;
        android-builder) prefix=ANDROID_BUILDER; base="ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" ;;
        win-helper) prefix=WIN_HELPER; base="ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" ;;
        *) die "unknown builder image role: $role" ;;
    esac
    local image_var="${prefix}_IMAGE_ID" dockerfile_var="SHA256_${prefix}_DOCKERFILE" dpkg_var="SHA256_${prefix}_DPKG_MANIFEST"
    image_id="${!image_var:-}"
    dockerfile_sha="${!dockerfile_var:-}"
    dpkg_sha="${!dpkg_var:-}"
    [ -n "$image_id" ] && [ -n "$dockerfile_sha" ] && [ -n "$dpkg_sha" ] \
        || die "pins.env is missing $image_var, $dockerfile_var, or $dpkg_var"
    require_cmd python3 docker
    local args=(
        verify-local --role "$role" --expected-id "$image_id" --base "$base"
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
    )
    [ -z "$image_ref" ] || args+=(--image-ref "$image_ref")
    python3 "$LIB_DIR/offline-image-provenance.py" "${args[@]}" \
        || die "pinned $role image provenance verification failed"
}

# verify_online_shas NAME1 SHA1 NAME2 SHA2 ...: re-verify each ./online artifact against its pinned
# SHA-256 BEFORE an offline build extracts it (R-B10/§12.3 — "each script distrusts the outputs of
# its sibling scripts and re-verifies them"). require_online_complete only proves the directory
# EXISTS; this proves the bytes are the PINNED bytes, so a corrupt/truncated cache, or a
# version-renamed tarball a glob would grab (e.g. a stray rust-1.90.tar.xz), is caught HERE and dies
# loud — never silently compiled. Cheap (a few hashes) vs a full build; each build preflight calls it
# for exactly the artifacts it consumes.
verify_online_shas() {
    [ $(( $# % 2 )) -eq 0 ] || die "verify_online_shas: odd argument count — every ./online NAME needs its SHA"
    while [ "$#" -ge 2 ]; do
        verify_sha256 "$ONLINE_DIR/$1" "$2"
        shift 2
    done
    log "./online artifact SHAs re-verified against pins.env"
}

# assert_source_date_epoch: the reproducible-build timestamp MUST be a valid integer that actually
# propagated. gen_version() (libs/hbb_common/src/lib.rs) and every mtime-stamping step depend on it;
# if unset or non-numeric it silently bakes a wall-clock date and only a double-build catches it
# (R-B2). Assert it is a plain integer and LOG the value so it is visible — a broken git-derived
# fallback cannot pass unnoticed.
assert_source_date_epoch() {
    case "${SOURCE_DATE_EPOCH:-}" in
        ''|*[!0-9]*) die "SOURCE_DATE_EPOCH is unset or not an integer ('${SOURCE_DATE_EPOCH:-}') — refusing to build with a non-deterministic timestamp (R-B2). It derives from the release commit's author date; check RUSTDESK_COMMIT (pins.env) resolves in this repo." ;;
    esac
    log "SOURCE_DATE_EPOCH = $SOURCE_DATE_EPOCH (deterministic build timestamp, R-B2)"
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
    local listeners harness_libvirt_net=0

    if ip link show virbr0 >/dev/null 2>&1; then
        dirty+=("virbr0 exists")
        harness_libvirt_net=1
    fi

    listeners="$(ss -ltnup 2>/dev/null | grep -E '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' || true)"
    if [ -n "$listeners" ]; then
        dirty+=("libvirt default-network DNS/DHCP listener active")
        harness_libvirt_net=1
    fi

    # R-B11/R-B11a forbid only an ip_forward change ATTRIBUTABLE TO THE HARNESS. The harness's sole
    # forwarding lever is libvirt's default NAT network (libvirt sets ip_forward=1 when it starts that
    # network) — detected above as virbr0 / its dnsmasq listeners. A standalone ip_forward=1 with no
    # virbr0/dnsmasq is NOT harness-attributable: it belongs to the container engine the build itself
    # runs on (Docker enables IP forwarding for its bridge, and online-fetch.sh needs it), which R-B11
    # explicitly provisions and the build-*.sh scripts use. Flagging it would make the Windows build
    # impossible on its own Docker build host. So net.ipv4.ip_forward=1 counts as dirty only alongside
    # the libvirt default network that makes it harness-attributable.
    if [ "$harness_libvirt_net" = "1" ] \
       && [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
        dirty+=("net.ipv4.ip_forward=1 (harness-attributable: libvirt default network present)")
    fi

    if [ "${#dirty[@]}" -ne 0 ]; then
        [ -z "$listeners" ] || printf '%s\n' "$listeners" >&2
        die "dirty build-host network state (${dirty[*]}); run scripts/cleanup.sh --build-host-network with privileges if harness-created, or reconcile manually before Windows VM artifact work (R-B11a/§12.2)"
    fi

    log "build-host network preflight OK (no virbr0, no libvirt default-network DNS/DHCP listener, no harness-attributable ip_forward)"
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

# assert_clean_worktree: a RELEASE build MUST compile committed HEAD, not a dirty / stale /
# concurrently-edited worktree — else the artifact matches no commit and its recorded SHA (R-B2) is
# meaningless. The deb/apk builds mount the LIVE tree (-v $REPO_ROOT:/src), so assert it is clean and
# fail LOUD on any uncommitted tracked change or untracked non-ignored file (gitignored build output —
# dist/, target/, flutter/build, the regenerated FRB bridges — is NOT flagged; git status --porcelain
# excludes it). Set ALLOW_DIRTY_TREE=1 for a deliberate LOCAL (non-release) build of the working tree.
# (The Windows build already has this immunity structurally via WINDOWS_BUILD_SOURCE=head — a clean
# `git archive HEAD` snapshot; giving deb/apk the same snapshot is the stronger follow-up, immune even
# to a mid-build edit. This assert + the double-build A==B are the current backstop for that race.)
assert_clean_worktree() {
    if [ "${ALLOW_DIRTY_TREE:-0}" = "1" ]; then
        log "ALLOW_DIRTY_TREE=1 — building the WORKING TREE, not committed HEAD (NOT a reproducible release build)"
        return 0
    fi
    local dirt
    dirt="$(cd "$REPO_ROOT" && git status --porcelain 2>/dev/null)" \
        || die "assert_clean_worktree: '$REPO_ROOT' is not a git repo (cannot verify the build traces to a commit)"
    [ -z "$dirt" ] || die "release build requires a CLEAN worktree traceable to HEAD ($(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null)); uncommitted changes present:
$dirt
Commit or stash them, or set ALLOW_DIRTY_TREE=1 for a deliberate local (non-release) build."
}

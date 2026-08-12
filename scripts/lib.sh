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

# A caller opts into this authority by calling initialize_local_docker_authority
# with a new docker-config path below its own current-user-private workspace.
# Keep the state process-local: nested verifier scripts create independent
# authorities and never inherit a caller's Docker routing/configuration.
LOCAL_DOCKER_AUTHORITY_INITIALIZED=0
LOCAL_DOCKER_AUTHORITY_LABEL=
LOCAL_DOCKER_AUTHORITY_PARENT=
LOCAL_DOCKER_AUTHORITY_PARENT_ID=
LOCAL_DOCKER_AUTHORITY_CONFIG=
LOCAL_DOCKER_AUTHORITY_CONFIG_ID=
LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=
LOCAL_DOCKER_AUTHORITY_CLIENT_ID=
LOCAL_DOCKER_AUTHORITY_SOCKET_ID=

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
    [ "$(/usr/bin/stat -c '%a' "$1" 2>/dev/null)" = "700" ] || die "private snapshot parent is not mode 0700: $1"
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
        "wix-nuget-packages/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_FIREWALL" \
        "wix-nuget-packages/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_HEAT" \
        "wix-nuget-packages/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_NETFX" \
        "wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_SDK" \
        "wix-nuget-packages/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_UI" \
        "wix-nuget-packages/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg" "$SHA256_WIX_NUGET_UTIL" \
        "android-ndk-${ANDROID_NDK_VERSION}.zip" "$SHA256_ANDROID_NDK_R28C" \
        "android-cmdline-tools.zip" "$SHA256_ANDROID_CMDLINE_TOOLS" \
        "vcpkg-${VCPKG_BASELINE}.tar.gz" "$SHA256_VCPKG_120DEAC3" \
        "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "$SHA256_FRB_1_80_1" \
        "win11.iso" "$SHA256_WIN11_ISO" \
        "vs-buildtools.layout.tar" "$SHA256_VS_BUILDTOOLS" \
        "win/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi" "$SHA256_RUST_MSVC_1_75" \
        "win/Git-2.45.2-64-bit.exe" "$SHA256_GIT_WIN_2_45_2" \
        "win/rustup-init.exe" "$SHA256_RUSTUP_INIT_WIN" \
        "dart-audit-inputs/Pub-all.zip" "$OSV_DB_PUB_SHA256" \
        "dart-audit-inputs/osv-scanner" "$OSV_SCANNER_SHA256"
    verify_sha512 "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"
}

initialize_local_docker_authority() {
    [ "$#" -eq 2 ] || die "initialize_local_docker_authority requires CONFIG_PATH LABEL"
    [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \
        || die "local Docker authority is already initialized"
    [ "$(/usr/bin/id -u)" -ne 0 ] || die "$2 refuses host or container-root Docker authority"
    [ "$(/usr/bin/id -g)" -ne 0 ] || die "$2 refuses a root primary group for Docker authority"

    local config="$1" label="$2" parent variable
    case "$config" in
        /*/docker-config) ;;
        *) die "$label Docker configuration must be an absolute docker-config path" ;;
    esac
    parent="${config%/docker-config}"
    [ -n "$parent" ] && [ -d "$parent" ] && [ ! -L "$parent" ] \
        || die "$label Docker authority parent is not a real directory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$parent" 2>/dev/null)" = \
        "$(/usr/bin/id -u):$(/usr/bin/id -g):700" ] \
        || die "$label Docker authority parent is not current-user/current-group mode 0700"
    { [ ! -e "$config" ] && [ ! -L "$config" ]; } \
        || die "$label Docker configuration path already exists"

    [ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ] \
        || die "$label trusted Docker client is unavailable at /usr/bin/docker"
    case "$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)" in
        0:0:755:1) ;;
        *) die "$label trusted Docker client must be a root-owned mode-0755 single-link file" ;;
    esac
    [ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] \
        || die "$label fixed local Docker Unix socket is unavailable"
    case "$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)" in
        0:1) ;;
        *) die "$label fixed local Docker Unix socket must be root-owned and single-link" ;;
    esac

    for variable in \
        DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \
        DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST \
        DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS; do
        [ -z "${!variable+x}" ] \
            || die "$label rejects inherited Docker client input $variable"
    done

    /usr/bin/install -d -m 0700 -- "$config"
    (umask 077 && set -o noclobber && printf '{}\n' >"$config/config.json") \
        || die "$label Docker config.json creation failed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$config/config.json" 2>/dev/null)" = \
        "$(/usr/bin/id -u):$(/usr/bin/id -g):600:1" ] \
        || die "$label Docker config.json is not current-user/current-group mode 0600 single-link"

    LOCAL_DOCKER_AUTHORITY_LABEL="$label"
    LOCAL_DOCKER_AUTHORITY_PARENT="$parent"
    LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$parent")"
    LOCAL_DOCKER_AUTHORITY_CONFIG="$config"
    LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- "$config")"
    LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- "$config/config.json")"
    LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /usr/bin/docker)"
    LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /var/run/docker.sock)"
    LOCAL_DOCKER_AUTHORITY_INITIALIZED=1
    assert_local_docker_authority
}

assert_local_docker_authority() {
    [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
        || { echo "local Docker authority is not initialized" >&2; return 1; }
    local label="$LOCAL_DOCKER_AUTHORITY_LABEL"
    [ -d "$LOCAL_DOCKER_AUTHORITY_PARENT" ] && [ ! -L "$LOCAL_DOCKER_AUTHORITY_PARENT" ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$LOCAL_DOCKER_AUTHORITY_PARENT" 2>/dev/null)" = \
            "$LOCAL_DOCKER_AUTHORITY_PARENT_ID" ] \
        || { echo "$label Docker authority parent identity changed" >&2; return 1; }
    [ -d "$LOCAL_DOCKER_AUTHORITY_CONFIG" ] && [ ! -L "$LOCAL_DOCKER_AUTHORITY_CONFIG" ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- "$LOCAL_DOCKER_AUTHORITY_CONFIG" 2>/dev/null)" = \
            "$LOCAL_DOCKER_AUTHORITY_CONFIG_ID" ] \
        || { echo "$label Docker configuration identity changed" >&2; return 1; }
    [ -f "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" ] \
        && [ ! -L "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" 2>/dev/null)" = \
            "$LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID" ] \
        || { echo "$label Docker config.json identity changed" >&2; return 1; }
    /usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf '{}\n') \
        || { echo "$label Docker config.json bytes changed" >&2; return 1; }
    [ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)" = \
            "$LOCAL_DOCKER_AUTHORITY_CLIENT_ID" ] \
        || { echo "$label trusted Docker client identity changed" >&2; return 1; }
    [ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /var/run/docker.sock 2>/dev/null)" = \
            "$LOCAL_DOCKER_AUTHORITY_SOCKET_ID" ] \
        || { echo "$label fixed local Docker Unix socket identity changed" >&2; return 1; }
}

local_docker() {
    local status=0
    assert_local_docker_authority || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        HOME="$LOCAL_DOCKER_AUTHORITY_PARENT" \
        DOCKER_HOST=unix:///var/run/docker.sock \
        DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG" \
        /usr/bin/docker \
            --host unix:///var/run/docker.sock \
            --config "$LOCAL_DOCKER_AUTHORITY_CONFIG" \
            "$@" || status=$?
    assert_local_docker_authority || return 1
    return "$status"
}

local_docker_image_provenance() {
    local status=0
    assert_local_docker_authority || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        HOME="$LOCAL_DOCKER_AUTHORITY_PARENT" \
        DOCKER_HOST=unix:///var/run/docker.sock \
        DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG" \
        /usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py" "$@" \
        || status=$?
    assert_local_docker_authority || return 1
    return "$status"
}

remove_local_docker_authority() {
    assert_local_docker_authority || {
        echo "$LOCAL_DOCKER_AUTHORITY_LABEL preserving changed private Docker authority" >&2
        return 125
    }
    /usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125
    /usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG" || return 125
    [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$LOCAL_DOCKER_AUTHORITY_PARENT" 2>/dev/null)" = \
        "$LOCAL_DOCKER_AUTHORITY_PARENT_ID" ] \
        || { echo "$LOCAL_DOCKER_AUTHORITY_LABEL Docker authority parent changed during removal" >&2; return 125; }
    LOCAL_DOCKER_AUTHORITY_INITIALIZED=0
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
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then
        [ -x /usr/bin/python3 ] || die "trusted Python interpreter is unavailable at /usr/bin/python3"
        assert_local_docker_authority || die "local Docker authority is unavailable"
    else
        require_cmd python3 docker
    fi
    local args=()
    if [ "$role" = android-builder ] \
        || [ "$role" = deb-builder ] \
        || [ "$role" = win-helper ]; then
        local required=(
            "${prefix}_CONFIG_ID"
            "${prefix}_MANIFEST_ID"
            "${prefix}_BOOTSTRAP_IMAGE_ID"
            "${prefix}_BOOTSTRAP_MANIFEST_ID"
            "SHA256_${prefix}_CERTIFICATION_DOCKERFILE"
            SOURCE_DATE_EPOCH_PIN
        )
        local name
        for name in "${required[@]}"; do
            [ -n "${!name:-}" ] || die "pins.env is missing $name"
        done
        local config_var="${prefix}_CONFIG_ID"
        local manifest_var="${prefix}_MANIFEST_ID"
        local bootstrap_image_var="${prefix}_BOOTSTRAP_IMAGE_ID"
        local bootstrap_manifest_var="${prefix}_BOOTSTRAP_MANIFEST_ID"
        local certification_dockerfile_var="SHA256_${prefix}_CERTIFICATION_DOCKERFILE"
        args=(
            verify-local --role "$role" --expected-id "$image_id" --base "$base"
            --dockerfile-sha "${!certification_dockerfile_var}"
            --recipe-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
            --bootstrap-image-id "${!bootstrap_image_var}"
            --bootstrap-manifest-id "${!bootstrap_manifest_var}"
            --source-date-epoch "$SOURCE_DATE_EPOCH_PIN"
            --config-id "${!config_var}"
            --manifest-id "${!manifest_var}"
        )
    else
        args=(
            verify-local --role "$role" --expected-id "$image_id" --base "$base"
            --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
        )
    fi
    [ -z "$image_ref" ] || args+=(--image-ref "$image_ref")
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then
        local_docker_image_provenance "${args[@]}" \
            || die "pinned $role image provenance verification failed"
    else
        python3 "$LIB_DIR/offline-image-provenance.py" "${args[@]}" \
            || die "pinned $role image provenance verification failed"
    fi
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
# propagated. build.rs version generation and every mtime-stamping step depend on it; if unset or
# non-numeric, release builds refuse to proceed before any wall-clock value can enter an artifact
# (R-B2). Assert its canonical non-negative decimal form and log the value so a malformed caller
# override cannot pass unnoticed.
assert_source_date_epoch() {
    case "${SOURCE_DATE_EPOCH:-}" in
        ''|*[!0-9]*|0[0-9]*) die "SOURCE_DATE_EPOCH is unset or not a canonical non-negative integer ('${SOURCE_DATE_EPOCH:-}') — refusing to build with a non-deterministic timestamp (R-B2). Release entry points supply the explicit SOURCE_DATE_EPOCH_PIN from scripts/pins.env." ;;
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
    local listeners tcp_dns udp_dns udp_dhcp harness_libvirt_net=0

    if ip link show virbr0 >/dev/null 2>&1; then
        dirty+=("virbr0 exists")
        harness_libvirt_net=1
    fi

    # Query only the two libvirt DNS/DHCP ports and never request process ownership. An unfiltered
    # `ss -p` dump would incidentally inspect unrelated host services (including RustDesk), which is
    # outside this harness's authority even when a later grep discards those rows.
    tcp_dns="$(ss -H -ltn 'sport = :53' 2>/dev/null)" \
        || die "cannot inspect the exact host TCP/53 preflight surface"
    udp_dns="$(ss -H -lun 'sport = :53' 2>/dev/null)" \
        || die "cannot inspect the exact host UDP/53 preflight surface"
    udp_dhcp="$(ss -H -lun 'sport = :67' 2>/dev/null)" \
        || die "cannot inspect the exact host UDP/67 preflight surface"
    listeners="$(printf '%s\n%s\n%s\n' "$tcp_dns" "$udp_dns" "$udp_dhcp" \
        | grep -E '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' || true)"
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
# meaningless. The Debian build still mounts the live tree, while the Android artifact builder archives
# exact HEAD into a private source authority plus a fresh writable copy for each pass. Assert cleanliness
# before either path and fail LOUD on any uncommitted tracked change or untracked non-ignored file (ignored output —
# dist/, target/, flutter/build, the regenerated FRB bridges — is NOT flagged; git status --porcelain
# excludes it). Set ALLOW_DIRTY_TREE=1 only for a deliberate LOCAL Debian build of the working tree;
# Android artifact builds reject that override. Windows likewise has snapshot immunity through
# WINDOWS_BUILD_SOURCE=head. The Debian live-tree mount remains the narrower source-race follow-up.
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

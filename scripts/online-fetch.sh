#!/usr/bin/env bash
# scripts/online-fetch.sh — the ONE networked step (R-B10).
#
# The repository is build-oriented and offline-by-construction. This is the only
# script permitted to touch the network; it materializes every resource the repo
# does not embed into ./online/ (git-ignored, NOT vendored — pinning != vendoring,
# R-R1), each verified against its pinned SHA-256 in scripts/pins.env. Any mismatch
# aborts fail-closed. The build scripts then run with the network namespace removed
# (--network=none) and refuse to run if ./online is incomplete or any SHA fails.
#
# This reconciles R-R1's "pinning != vendoring" with the offline build: the bulky
# pinned world is CACHED, not committed — re-creatable from pins.env and
# re-verifiable, never trusted from the network at build time.
#
# Run order (R-B10): host-provision.sh -> online-fetch.sh (once, or on a pins.env
# change) -> build-* (offline) -> cleanup.sh
#
# R-B12 requires each first pin be established by an audited, dual-sourced
# bootstrap (publisher hash/signature cross-checked) and recorded in pins.env
# BEFORE this script is allowed to fetch it. fetch_verify enforces that by
# rejecting the SHA_PENDING sentinel before touching the network.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

mkdir -p "$ONLINE_DIR"

# fetch_verify URL DEST_BASENAME EXPECTED_SHA: idempotent download + verify.
# Skips re-download if the cached file already verifies; aborts on any SHA failure
# or the R-B12 sentinel (verify_sha256 enforces both). Never "download anyway".
fetch_verify() {
    local url="$1" name="$2" sha="$3"
    local dest="$ONLINE_DIR/$name"
    if [ -f "$dest" ] && [ "$sha" != "${SHA_PENDING}" ] && \
       [ "$(sha256sum "$dest" | awk '{print $1}')" = "$sha" ]; then
        log "cached + verified, skipping: $name"
        return 0
    fi
    # Refuse before reaching for the network if provenance isn't established.
    [ "$sha" != "${SHA_PENDING}" ] || \
        die "refusing to fetch $name — its pins.env SHA-256 is the R-B12 sentinel; record audited provenance first"
    log "fetching: $url -> $name"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$dest.part" "$url"; then
        rm -f "$dest.part"
        die "failed to fetch $name"
    fi
    mv "$dest.part" "$dest"
    verify_sha256 "$dest" "$sha"
}

fetch_verify_sha512() {
    local url="$1" name="$2" sha="$3"
    local dest="$ONLINE_DIR/$name"
    if [ -f "$dest" ] && [ "$(sha512sum "$dest" | awk '{print $1}')" = "$sha" ]; then
        log "cached + SHA512-verified, skipping: $name"
        return 0
    fi
    log "fetching: $url -> $name"
    mkdir -p "$(dirname "$dest")"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$dest.part" "$url"; then
        rm -f "$dest.part"
        die "failed to fetch $name"
    fi
    [ "$(sha512sum "$dest.part" | awk '{print $1}')" = "$sha" ] || {
        rm -f "$dest.part"
        die "SHA512 mismatch for $name"
    }
    mv "$dest.part" "$dest"
}

# The installed-systemd behavior gate needs a real PID-1/cgroup environment but
# must never borrow the host manager or host cgroup tree. Keep its immutable,
# publisher-hashed Debian base in the private harness state used for VM images.
# This explicit mode remains the sole network acquisition path; the smoke itself
# runs QEMU with `-nic none` and a throwaway CoW overlay.
fetch_debian_systemd_smoke_image() {
    local harness_state="$REPO_ROOT/.harness-state"
    local state_dir="$harness_state/debian-systemd-smoke"
    local name="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
    local dest="$state_dir/$name"
    local url="https://cloud.debian.org/images/cloud/bookworm/${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}/$name"
    local current_uid
    current_uid=$(id -u)
    if [ -e "$harness_state" ] || [ -L "$harness_state" ]; then
        [ -d "$harness_state" ] && [ ! -L "$harness_state" ] \
            || die "harness state root is not one real directory"
    else
        mkdir -m 0700 -- "$harness_state"
    fi
    [ "$(stat -c '%u:%a' "$harness_state")" = "$current_uid:700" ] \
        || die "harness state root is not current-user-owned mode 0700"
    if [ -e "$state_dir" ] || [ -L "$state_dir" ]; then
        [ -d "$state_dir" ] && [ ! -L "$state_dir" ] \
            || die "systemd smoke state directory is not one real directory"
    else
        mkdir -m 0700 -- "$state_dir"
    fi
    [ "$(stat -c '%u:%a' "$state_dir")" = "$current_uid:700" ] \
        || die "systemd smoke state directory is not current-user-owned mode 0700"
    if [ -f "$dest" ] && [ ! -L "$dest" ] \
       && [ "$(sha512sum "$dest" | awk '{print $1}')" = "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE" ]; then
        [ "$(stat -c '%u:%h' "$dest")" = "$current_uid:1" ] \
            || die "cached systemd smoke image has unsafe ownership or links"
        chmod 0444 "$dest"
        [ "$(stat -c '%u:%a:%h' "$dest")" = "$current_uid:444:1" ] \
            || die "cached systemd smoke image has unsafe ownership, mode, or links"
        log "cached + SHA512-verified, skipping: $name"
        return 0
    fi
    [ ! -e "$dest.part" ] && [ ! -L "$dest.part" ] \
        || die "stale systemd smoke image download temporary exists: $dest.part"
    log "fetching pinned Debian systemd smoke image: $url"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$dest.part" "$url"; then
        rm -f "$dest.part"
        die "failed to fetch pinned Debian systemd smoke image"
    fi
    [ "$(sha512sum "$dest.part" | awk '{print $1}')" = "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE" ] || {
        rm -f "$dest.part"
        die "SHA512 mismatch for pinned Debian systemd smoke image"
    }
    chmod 0444 "$dest.part"
    mv "$dest.part" "$dest"
    [ "$(stat -c '%u:%a:%h' "$dest")" = "$current_uid:444:1" ] \
        || die "fetched systemd smoke image has unsafe ownership, mode, or links"
    log "Debian systemd smoke image cached + SHA512-verified: $dest"
}

libvpx_native_key() {
    (
        printf 'VCPKG_BASELINE=%s\n' "$VCPKG_BASELINE"
        printf 'LIBVPX_SOURCE_REF=%s\n' "$LIBVPX_SOURCE_REF"
        printf 'SHA512_LIBVPX_SOURCE=%s\n' "$SHA512_LIBVPX_SOURCE"
        printf 'LIBVPX_FIX_COMMIT=%s\n' "$LIBVPX_FIX_COMMIT"
        printf 'SHA512_LIBVPX_PATCH=%s\n' "$SHA512_LIBVPX_PATCH"
        cd "$REPO_ROOT"
        find res/vcpkg/libvpx -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            sha256sum "$file"
        done
    ) | sha256sum | awk '{print $1}'
}

require_libvpx_distfiles() {
    local dir="$ONLINE_DIR/vcpkg-distfiles"
    local key
    key="$(libvpx_native_key)"
    [ -f "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" ] || die "libvpx source capture missing — stage_vcpkg_distfiles must run first"
    [ "$(sha512sum "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" | awk '{print $1}')" = "$SHA512_LIBVPX_SOURCE" ] || die "libvpx source capture SHA512 mismatch"
    [ -f "$dir/libvpx-${LIBVPX_FIX_COMMIT}.patch" ] || die "libvpx security patch capture missing — stage_vcpkg_distfiles must run first"
    [ "$(sha512sum "$dir/libvpx-${LIBVPX_FIX_COMMIT}.patch" | awk '{print $1}')" = "$SHA512_LIBVPX_PATCH" ] || die "libvpx security patch capture SHA512 mismatch"
    [ "$(cat "$dir/libvpx-native-key.txt" 2>/dev/null)" = "$key" ] || die "libvpx native key is stale — stage_vcpkg_distfiles must refresh it"
}

# ── Rust crate world: vendor the committed lockfile (incl. 38 git-sourced records) ──
# `cargo vendor --locked` reproduces the exact lockfile-pinned crate set offline.
# It is itself a network step and belongs here, not in the offline build.
vendor_cargo() {
    require_cmd cargo
    log "cargo vendor (--locked) -> ./online/cargo-vendor (+ its [source] config)"
    # Capture the printed [source] config (crates-io + all 38 git-sourced records) so
    # the offline build can replay it; build-debian.sh rewrites its directory path.
    ( cd "$REPO_ROOT" && cargo vendor --locked --versioned-dirs "$ONLINE_DIR/cargo-vendor" \
        > "$ONLINE_DIR/cargo-vendor-config.toml" )
    log "cargo vendor done — config at ./online/cargo-vendor-config.toml"
}

# ── Toolchains / SDKs (each SHA-pinned in pins.env, R-B5a/§3.2) ────────────────
fetch_toolchains() {
    # Rust 1.75 toolchain (rustup-init or the offline toolchain tarball).
    fetch_verify "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz" \
        "rust-${RUST_VERSION}.tar.xz" "${SHA256_RUST_1_75}"
    # Rust std for aarch64-linux-android — the cargo-ndk JNI cross-compile target (the host
    # tarball above ships only x86_64). Dated path = the immutable 1.75.0 release (2023-12-28).
    fetch_verify "https://static.rust-lang.org/dist/2023-12-28/rust-std-${RUST_VERSION}.0-aarch64-linux-android.tar.xz" \
        "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz" "${SHA256_RUST_STD_ANDROID_1_75}"
    # Flutter SDK 3.24.5.
    fetch_verify "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
        "flutter-${FLUTTER_VERSION}.tar.xz" "${SHA256_FLUTTER_3_24_5}"
    # Android NDK r28c.
    fetch_verify "https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip" \
        "android-ndk-${ANDROID_NDK_VERSION}.zip" "${SHA256_ANDROID_NDK_R28C}"
    # Android cmdline-tools (then build-tools 34.0.0 / platform-34 via sdkmanager, offline).
    # Versioned build (R-B2 reproducibility): NOT the moving "...-latest.zip" — the exact build
    # number is pinned in pins.env so a Google "latest" bump can never silently change the artifact.
    fetch_verify "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_BUILD}_latest.zip" \
        "android-cmdline-tools.zip" "${SHA256_ANDROID_CMDLINE_TOOLS}"
    # LLVM/Clang 15.0.6 (libclang for bindgen determinism, R-B12).
    fetch_verify "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz" \
        "llvm-${LLVM_VERSION}.tar.xz" "${SHA256_LLVM_15_0_6}"
    # flutter_rust_bridge_codegen 1.80.1 (R-B7 — the uncommitted bridge generator).
    fetch_verify "https://github.com/fzyzcjy/flutter_rust_bridge/archive/refs/tags/v${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" \
        "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "${SHA256_FRB_1_80_1}"
}

# ── Windows toolchains (the §12.2 KVM-VM build; stably-addressable downloads) ──────
# Windows can't be cross-built from Linux (MSVC + WiX are Windows-only), so these stage
# into ./online for the guest setup to install OFFLINE (provision-windows-vm.sh mounts
# ./online as C:\online). The flutter/llvm in fetch_toolchains are the LINUX .tar.xz; the
# guest needs the WINDOWS distributions. (The Win11 ISO + the VS Build Tools layout are
# evergreen — not stably SHA-addressable upstream — so they are CAPTURED and pinned
# separately by SHA per R-B12(c), not fetched here.)
fetch_windows_toolchains() {
    # Windows Flutter SDK 3.24.5 — the .zip distribution (the linux .tar.xz won't run on Windows).
    fetch_verify "https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${FLUTTER_VERSION}-stable.zip" \
        "flutter-windows-${FLUTTER_VERSION}.zip" "${SHA256_FLUTTER_WIN_3_24_5}"
    # Windows LLVM/clang 15.0.6 installer (libclang for FRB/bindgen determinism, R-B12). The guest
    # installs it silently (/S); VS Build Tools' bundled clang is a different, non-pinned version.
    fetch_verify "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-win64.exe" \
        "llvm-windows-${LLVM_VERSION}.exe" "${SHA256_LLVM_WIN_15_0_6}"
    # Python for the §12.2 build host: build.py orchestrates the windows build + libs/portable/generate.py
    # (imports brotli) packs the portable installer. The golden installs it + `pip install brotli` networked.
    fetch_verify "https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-amd64.exe" \
        "python-windows-${PYTHON_VERSION}.exe" "${SHA256_PYTHON_WIN_3_11_9}"
    fetch_verify "https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" \
        "olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" "${SHA256_OLEFILE_0_47}"
    # The golden's Rust compiler MSI + Git installer — publicly re-fetchable and DUAL-SOURCE-pinned
    # (pins.env), so fetch + verify them here like the other windows toolchains instead of relying on
    # an operator hand-stage. rustup-init has NO stable versioned URL (its 'latest' drifts), so it
    # stays OPERATOR-CAPTURED in online/win/ and is SHA-verified at provision time (R-B12(c)); fail
    # loud here with the exact stage-it command if it is missing so nothing silently proceeds.
    mkdir -p "$ONLINE_DIR/win"
    fetch_verify "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi" \
        "win/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi" "${SHA256_RUST_MSVC_1_75}"
    fetch_verify "https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe" \
        "win/Git-2.45.2-64-bit.exe" "${SHA256_GIT_WIN_2_45_2}"
    if [ -f "$ONLINE_DIR/win/rustup-init.exe" ]; then
        verify_sha256 "$ONLINE_DIR/win/rustup-init.exe" "${SHA256_RUSTUP_INIT_WIN}"
    else
        die "online/win/rustup-init.exe missing — it is operator-captured (rustup-init has no stable versioned URL; R-B12(c)). Stage it, then it is SHA-verified against SHA256_RUSTUP_INIT_WIN:
    curl -fsSL --proto '=https' --tlsv1.2 -o online/win/rustup-init.exe https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe
  (if upstream rustup has moved on, its SHA will mismatch the pin — re-pin SHA256_RUSTUP_INIT_WIN deliberately in scripts/pins.env after review.)"
    fi
}

# ── vcpkg registry snapshot ───────────────────────────────────────────────────
fetch_vcpkg() {
    # vcpkg @ the pinned baseline commit (then `vcpkg install` builds the native
    # set offline from the overlay ports in res/vcpkg).
    fetch_verify "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz" \
        "vcpkg-${VCPKG_BASELINE}.tar.gz" "${SHA256_VCPKG_120DEAC3}"
}

require_image_pin() {
    local name="$1" value="${!1:-}"
    [ -n "$value" ] || die "pins.env is missing $name"
    [ "$value" != "$SHA_PENDING" ] || die "$name is not established"
}

verify_or_load_builder_image() {
    local role="$1" image_id="$2" base="$3" dockerfile_sha="$4" dpkg_sha="$5" archive_sha="$6" compatibility_tag="$7"
    local archive="$ONLINE_DIR/build-images/${role}.docker.tar.gz"
    require_cmd python3 docker
    python3 "$LIB_DIR/offline-image-provenance.py" verify-load \
        --archive "$archive" --archive-sha "$archive_sha" \
        --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
    docker tag "$image_id" "$compatibility_tag"
    python3 "$LIB_DIR/offline-image-provenance.py" verify-local \
        --image-ref "$compatibility_tag" --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
}

load_builder_images() {
    local names=(
        DEB_BUILDER_IMAGE_ID SHA256_DEB_BUILDER_DOCKERFILE SHA256_DEB_BUILDER_DPKG_MANIFEST SHA256_DEB_BUILDER_IMAGE_ARCHIVE
        ANDROID_BUILDER_IMAGE_ID SHA256_ANDROID_BUILDER_DOCKERFILE SHA256_ANDROID_BUILDER_DPKG_MANIFEST SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE
        WIN_HELPER_IMAGE_ID SHA256_WIN_HELPER_DOCKERFILE SHA256_WIN_HELPER_DPKG_MANIFEST SHA256_WIN_HELPER_IMAGE_ARCHIVE
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    verify_or_load_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID" \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" "$SHA256_DEB_BUILDER_DOCKERFILE" \
        "$SHA256_DEB_BUILDER_DPKG_MANIFEST" "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    verify_or_load_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        "${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    verify_or_load_builder_image win-helper "$WIN_HELPER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_WIN_HELPER_DOCKERFILE" \
        "$SHA256_WIN_HELPER_DPKG_MANIFEST" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \
        "${HARNESS_PREFIX:-rustdesk-fork-harness}-win-helper"
}

# Explicit maintenance candidate builds. Captured images remain the release authority.
build_deb_builder_image() {
    require_cmd docker
    require_image_pin SHA256_DEB_BUILDER_DOCKERFILE
    require_image_pin SHA256_DEB_BUILDER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder-candidate"
    docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_DEB_BUILDER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_DEB_BUILDER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.deb-builder" "$LIB_DIR"
    local image_id
    image_id="$(docker image inspect --format '{{.Id}}' "$tag")"
    python3 "$LIB_DIR/offline-image-provenance.py" verify-local --image-ref "$tag" \
        --role deb-builder --expected-id "$image_id" --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --dockerfile-sha "$SHA256_DEB_BUILDER_DOCKERFILE" --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST"
    printf 'DEB_BUILDER_IMAGE_ID="%s"\n' "$image_id"
}

# ── The pinned .apk build image (R-B7/B8): ubuntu:24.04 + the android build-deps ────
# build-android.sh runs --network=none; the NDK r28c prebuilt clang needs a modern glibc, so
# this is FROM ubuntu:24.04 (not the bionic deb-builder). Dockerfile.android-builder bakes the
# vcpkg/cargo-ndk/gradle system deps; the rust/flutter/NDK toolchains stay in ./online.
build_android_builder_image() {
    require_cmd docker
    require_image_pin SHA256_ANDROID_BUILDER_DOCKERFILE
    require_image_pin SHA256_ANDROID_BUILDER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder-candidate"
    docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_ANDROID_BUILDER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_ANDROID_BUILDER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.android-builder" "$LIB_DIR"
    local image_id
    image_id="$(docker image inspect --format '{{.Id}}' "$tag")"
    python3 "$LIB_DIR/offline-image-provenance.py" verify-local --image-ref "$tag" \
        --role android-builder --expected-id "$image_id" --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"
    printf 'ANDROID_BUILDER_IMAGE_ID="%s"\n' "$image_id"
}

# ── The pinned Windows VM helper image: genisoimage + libguestfs + MSI tooling ──
# The Windows artifact path uses host-side helper containers for UDF media creation,
# libguestfs inspection/extraction, and MSI canonicalization. Those helpers are build
# inputs, so their apt installs belong HERE (the one networked phase), not inside
# build-windows-vm.sh/provision-windows-vm.sh/verify-windows-golden.sh.
build_windows_helper_image() {
    require_cmd docker
    require_image_pin SHA256_WIN_HELPER_DOCKERFILE
    require_image_pin SHA256_WIN_HELPER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-helper-candidate"
    docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_WIN_HELPER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_WIN_HELPER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.win-helper" "$LIB_DIR"
    local image_id
    image_id="$(docker image inspect --format '{{.Id}}' "$tag")"
    python3 "$LIB_DIR/offline-image-provenance.py" verify-local --image-ref "$tag" \
        --role win-helper --expected-id "$image_id" --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE" --dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"
    printf 'WIN_HELPER_IMAGE_ID="%s"\n' "$image_id"
}

maintenance_build_image_candidates() {
    require_cmd docker python3
    docker pull "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}"
    docker pull "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"
    build_deb_builder_image
    build_android_builder_image
    build_windows_helper_image
}

capture_builder_image() {
    local role="$1" image_id="$2" base="$3" dockerfile_sha="$4" dpkg_sha="$5" output="$6"
    python3 "$LIB_DIR/offline-image-provenance.py" maintenance-capture \
        --output "$output" \
        --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
}

maintenance_capture_builder_images() {
    local names=(
        DEB_BUILDER_IMAGE_ID SHA256_DEB_BUILDER_DOCKERFILE SHA256_DEB_BUILDER_DPKG_MANIFEST
        ANDROID_BUILDER_IMAGE_ID SHA256_ANDROID_BUILDER_DOCKERFILE SHA256_ANDROID_BUILDER_DPKG_MANIFEST
        WIN_HELPER_IMAGE_ID SHA256_WIN_HELPER_DOCKERFILE SHA256_WIN_HELPER_DPKG_MANIFEST
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    local dir="$ONLINE_DIR/build-images"
    local deb="$dir/deb-builder.docker.tar.gz" android="$dir/android-builder.docker.tar.gz" win="$dir/win-helper.docker.tar.gz"
    local deb_tmp="$dir/.deb-builder.docker.tar.gz.part" android_tmp="$dir/.android-builder.docker.tar.gz.part" win_tmp="$dir/.win-helper.docker.tar.gz.part"
    [ ! -e "$deb" ] && [ ! -e "$android" ] && [ ! -e "$win" ] || die "one or more final builder archives already exist"
    [ ! -e "$deb_tmp" ] && [ ! -e "$android_tmp" ] && [ ! -e "$win_tmp" ] || die "stale builder archive capture temporary exists"
    require_pinned_builder_image deb-builder
    require_pinned_builder_image android-builder
    require_pinned_builder_image win-helper
    mkdir -p "$dir"
    local deb_result android_result win_result
    trap 'rm -f "$deb_tmp" "$android_tmp" "$win_tmp"' EXIT HUP INT TERM
    deb_result="$(capture_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID" \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" "$SHA256_DEB_BUILDER_DOCKERFILE" "$SHA256_DEB_BUILDER_DPKG_MANIFEST" "$deb_tmp")"
    android_result="$(capture_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_ANDROID_BUILDER_DOCKERFILE" "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" "$android_tmp")"
    win_result="$(capture_builder_image win-helper "$WIN_HELPER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_WIN_HELPER_DOCKERFILE" "$SHA256_WIN_HELPER_DPKG_MANIFEST" "$win_tmp")"
    local deb_sha android_sha win_sha
    deb_sha="$(printf '%s\n' "$deb_result" | sed -n 's/^sha256=//p')"
    android_sha="$(printf '%s\n' "$android_result" | sed -n 's/^sha256=//p')"
    win_sha="$(printf '%s\n' "$win_result" | sed -n 's/^sha256=//p')"
    case "$deb_sha$android_sha$win_sha" in *[!0-9a-f]*|'') die "builder capture returned malformed archive hashes" ;; esac
    [ "${#deb_sha}" -eq 64 ] && [ "${#android_sha}" -eq 64 ] && [ "${#win_sha}" -eq 64 ] \
        || die "builder capture returned malformed archive hash lengths"
    mv "$deb_tmp" "$deb"
    mv "$android_tmp" "$android"
    mv "$win_tmp" "$win"
    trap - EXIT HUP INT TERM
    printf 'SHA256_DEB_BUILDER_IMAGE_ARCHIVE="%s"\n' "$deb_sha"
    printf 'SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE="%s"\n' "$android_sha"
    printf 'SHA256_WIN_HELPER_IMAGE_ARCHIVE="%s"\n' "$win_sha"
}

# ── The FRB codegen tool (R-B7): built FOR ubuntu:18.04, staged to ./online/frb-tool ──
# build_one needs flutter_rust_bridge_codegen to (re)generate the bridge; it cannot
# `cargo install` it offline (its deps are not in the main vendor set), so build it HERE
# (networked) in the deb-builder image with the pinned rust — exactly as upstream's
# bridge.yml does: `cargo install ... --version <pin> --features uuid --locked`.
build_frb_codegen() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified deb-builder image missing — load_builder_images must run first"
    if [ -x "$ONLINE_DIR/frb-tool/bin/flutter_rust_bridge_codegen" ]; then
        log "frb codegen tool already staged, skipping"; return 0
    fi
    log "building flutter_rust_bridge_codegen ${FLUTTER_RUST_BRIDGE_VERSION} for ubuntu:18.04 -> ./online/frb-tool"
    docker run --rm -v "$ONLINE_DIR:/online" "$builder" bash -euo pipefail -c '
        TC=/tmp/tc; mkdir -p "$TC"; tar -C "$TC" -xf /online/rust-1.*.tar.xz
        "$TC"/rust-1.*/install.sh --prefix=/tmp/rust --disable-ldconfig \
            --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
        export PATH=/tmp/rust/bin:$PATH
        cargo install flutter_rust_bridge_codegen --version '"${FLUTTER_RUST_BRIDGE_VERSION}"' \
            --features uuid --locked --root /online/frb-tool
    '
}

# ── The flutter pub cache (R-B7): hosted + git deps, staged to ./online/pub-cache ──
# build_one resolves the flutter project --offline from this cache. The committed
# pubspec.lock is the pin; this networked staging step fails if pub would rewrite it.
stage_pub_cache() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified deb-builder image missing — load_builder_images must run first"
    if [ -d "$ONLINE_DIR/pub-cache/hosted" ] || [ -d "$ONLINE_DIR/pub-cache/git" ]; then
        log "pub cache already staged, skipping"; return 0
    fi
    log "staging the flutter pub cache (hosted + git deps) -> ./online/pub-cache"
    docker run --rm -v "$ONLINE_DIR:/online" -v "$REPO_ROOT/flutter:/flutterproj:ro" "$builder" bash -euo pipefail -c '
        TC=/tmp/tc; mkdir -p "$TC"; tar -C "$TC" -xf /online/flutter-*.tar.xz
        export PATH="$TC/flutter/bin:$PATH"
        export HOME=/tmp/home; mkdir -p "$HOME"; git config --global --add safe.directory "*"
        export PUB_CACHE=/online/pub-cache; mkdir -p "$PUB_CACHE"
        # /flutterproj is RO; pub get writes .dart_tool, so copy to a writable dir. The committed
        # pubspec.lock pins the versions; the cache fills PUB_CACHE (hosted + the git-dep clones).
        cp -a /flutterproj /tmp/proj
        cd /tmp/proj
        lock_before="$(sha256sum pubspec.lock | awk "{print \$1}")"
        flutter pub get
        lock_after="$(sha256sum pubspec.lock | awk "{print \$1}")"
        [ "$lock_before" = "$lock_after" ] || {
            echo "flutter/pubspec.lock drifted during pub cache staging; regenerate/commit the lock under the pinned Flutter SDK" >&2
            diff -u /flutterproj/pubspec.lock pubspec.lock || true
            exit 1
        }
    '
}

# ── vcpkg overlay distfiles (R-B12(a)) ─────────────────────────────────────────
# libvpx uses a SHA512-pinned v1.15.2 archive plus the exact upstream d5f35ac8
# security patch. The overlay consumes only these captures through file:// URLs.
# libyuv fetches from googlesource, whose gitiles
# `+archive` tarballs are EMPIRICALLY non-reproducible (two fetches differ — even decompressed),
# so the URL can't be SHA-pinned and R-R1 forbids vendoring. Capture a deterministic
# `git archive --format=tar | gzip -n` of the pinned commit into ./online + verify its SHA512
# against pins.env; the libyuv overlay portfile then consumes /online/libyuv-<commit>.tar.gz
# (file://, SHA512-verified) on the Linux build hosts — both stage_vcpkg_natives + _arm64 mount the
# SAME file. (The Windows golden VM has no ./online capture, so the portfile falls back to
# vcpkg_from_git.) MUST run before stage_vcpkg_natives[_arm64]. The archive is byte-deterministic
# given the image's git (this SHA512 was computed in this deb-builder, git 2.17.1 — re-pin if it
# changes; same class as the SHA256_VCPKG_120DEAC3 GitHub-archive caveat in pins.env).
stage_libvpx_distfiles() {
    local vpx_dir="$ONLINE_DIR/vcpkg-distfiles"
    mkdir -p "$vpx_dir"
    fetch_verify_sha512 \
        "https://github.com/webmproject/libvpx/archive/refs/tags/${LIBVPX_SOURCE_REF}.tar.gz" \
        "vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" "$SHA512_LIBVPX_SOURCE"

    local committed_patch="$REPO_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch"
    [ "$(sha512sum "$committed_patch" | awk '{print $1}')" = "$SHA512_LIBVPX_PATCH" ] || die "committed libvpx security patch does not match SHA512_LIBVPX_PATCH"
    if [ ! -f "$vpx_dir/libvpx-${LIBVPX_FIX_COMMIT}.patch" ] || \
       [ "$(sha512sum "$vpx_dir/libvpx-${LIBVPX_FIX_COMMIT}.patch" | awk '{print $1}')" != "$SHA512_LIBVPX_PATCH" ]; then
        cp "$committed_patch" "$vpx_dir/libvpx-${LIBVPX_FIX_COMMIT}.patch.part"
        mv "$vpx_dir/libvpx-${LIBVPX_FIX_COMMIT}.patch.part" "$vpx_dir/libvpx-${LIBVPX_FIX_COMMIT}.patch"
    fi

    local tool_hash tool_name tool_extra tool_url
    [ "$(sha256sum "$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512" | awk '{print $1}')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST" ] || die "libvpx Windows acquisition manifest does not match its pin"
    while read -r tool_hash tool_name tool_extra; do
        [ -z "$tool_extra" ] || die "malformed libvpx Windows tool manifest entry: $tool_hash $tool_name $tool_extra"
        case "$tool_hash" in *[!0-9a-f]*|'') die "malformed SHA512 in libvpx Windows tool manifest: $tool_hash" ;; esac
        [ "${#tool_hash}" -eq 128 ] || die "malformed SHA512 length in libvpx Windows tool manifest: $tool_hash"
        case "$tool_name" in
            msys2-*.pkg.tar.zst)
                tool_url="https://mirror.msys2.org/msys/x86_64/${tool_name#msys2-}"
                ;;
            mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst)
                tool_url="https://mirror.msys2.org/mingw/mingw64/$tool_name"
                ;;
            nasm-2.16.03-win64.zip)
                tool_url="https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/$tool_name"
                ;;
            cmake-3.30.1-windows-i386.zip)
                tool_url="https://github.com/Kitware/CMake/releases/download/v3.30.1/$tool_name"
                ;;
            ninja-win-1.12.1.zip)
                tool_url="https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip"
                ;;
            7z2409.7z.exe)
                tool_url="https://github.com/ip7z/7zip/releases/download/24.09/7z2409.exe"
                ;;
            7zr.exe)
                tool_url="https://github.com/ip7z/7zip/releases/download/24.09/7zr.exe"
                ;;
            PowerShell-7.2.24-win-x64.zip)
                tool_url="https://github.com/PowerShell/PowerShell/releases/download/v7.2.24/PowerShell-7.2.24-win-x64.zip"
                ;;
            *) die "unexpected libvpx Windows tool archive: $tool_name" ;;
        esac
        fetch_verify_sha512 "$tool_url" "vcpkg-distfiles/windows-tools/$tool_name" "$tool_hash"
    done <"$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512"

    printf '%s\n' "$(libvpx_native_key)" >"$vpx_dir/libvpx-native-key.txt.part"
    mv "$vpx_dir/libvpx-native-key.txt.part" "$vpx_dir/libvpx-native-key.txt"
    require_libvpx_distfiles
    log "libvpx source, security patch, and Windows acquisition closure captured + SHA512-verified"
}

stage_vcpkg_distfiles() {
    stage_libvpx_distfiles
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified deb-builder image missing — load_builder_images must run first"
    local yuv_tgz="$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz"
    if [ -f "$yuv_tgz" ]; then
        [ "$(sha512sum "$yuv_tgz" | awk '{print $1}')" = "$SHA512_LIBYUV" ] || die "cached libyuv distfile SHA512 mismatch"
        log "vcpkg distfile (libyuv) already captured + verified"
        return 0
    fi
    case "$SHA512_LIBYUV" in
        *"${SHA_PENDING}"*) die "libyuv distfile SHA512 is the R-B12 sentinel — record it in pins.env first" ;;
    esac
    log "capturing the libyuv vcpkg distfile (reproducible git archive | gzip -n) -> ./online"
    docker run --rm \
        -v "$ONLINE_DIR:/online" \
        -e LIBYUV_COMMIT="$LIBYUV_COMMIT" \
        -e SHA512_LIBYUV="$SHA512_LIBYUV" \
        "$builder" bash -euo pipefail -c '
            gen() { # url commit out want-sha512
                rm -rf /tmp/src; mkdir -p /tmp/src; cd /tmp/src; git init -q; git remote add origin "$1"
                git fetch -q --depth 1 origin "$2" 2>/dev/null || { cd /tmp; rm -rf /tmp/src; git clone -q "$1" /tmp/src >/dev/null 2>&1; cd /tmp/src; }
                git -c core.autocrlf=false archive --format=tar "$2" | gzip -n > "$3"
                local got; got=$(sha512sum "$3" | cut -d" " -f1)
                [ "$got" = "$4" ] || { echo "R-B12(a) SHA512 MISMATCH $3: got $got want $4" >&2; exit 1; }
            }
            gen https://chromium.googlesource.com/libyuv/libyuv "$LIBYUV_COMMIT" "/online/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"
            echo "libyuv distfile captured + SHA512-verified"
        '
    log "vcpkg distfile captured (libyuv, SHA512-verified)"
}

# ── The vcpkg-built native codecs (R-R1 pinned overlay ports): vpx/yuv/opus ──
# scrap + magnum-opus (libs/scrap/build.rs; the magnum-opus git dep) link these STATICALLY
# from VCPKG_ROOT/installed/x64-linux when the linux-pkg-config feature is OFF — the shipped
# .deb feature set (build-debian.sh: --flutter --unix-file-copy-paste). `vcpkg install`
# downloads each port's source and compiles it, so it belongs in this ONE networked step; the
# built x64-linux tree is then staged read-only for the offline build. Built from the repo's
# patched, pinned res/vcpkg overlay ports atop the baseline registry snapshot (the vcpkg
# source archive is pinned at VCPKG_BASELINE). vcpkg's bootstrap needs `zip` (in the image).
stage_vcpkg_natives() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified deb-builder image missing — load_builder_images must run first"
    require_libvpx_distfiles
    local native_key
    native_key="$(libvpx_native_key)"
    if [ -d "$ONLINE_DIR/vcpkg/installed/x64-linux/lib" ] && \
       [ "$(cat "$ONLINE_DIR/vcpkg/installed/x64-linux/.rustdesk-libvpx-native-key" 2>/dev/null)" = "$native_key" ]; then
        log "vcpkg native codecs already staged for libvpx key $native_key, skipping"; return 0
    fi
    [ -f "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" ] || die "vcpkg source archive missing — fetch_vcpkg must run first"
    log "staging the vcpkg native codecs (libvpx/libyuv/opus, x64-linux static) -> ./online/vcpkg/installed"
    docker run --rm \
        -v "$ONLINE_DIR:/online" \
        -v "$REPO_ROOT/res/vcpkg:/overlay:ro" \
        -e RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        -e LIBVPX_NATIVE_KEY="$native_key" \
        "$builder" bash -euo pipefail -c '
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            export VCPKG_BINARY_SOURCES=clear
            # Build the native codecs with the pinned gcc-8 toolchain used by the
            # offline deb-builder image, keeping C/C++ object generation stable. The
            # outputs are C-ABI static libs → link fine into the gcc/rust cargo build.
            export CC=/usr/bin/gcc-8 CXX=/usr/bin/g++-8
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet x64-linux --overlay-ports=/overlay \
                libvpx libyuv opus
            # Stage only the x64-linux install tree (lib/*.a + include/) that
            # scrap/magnum-opus link_vcpkg read via VCPKG_ROOT/installed/x64-linux.
            mkdir -p /online/vcpkg/installed
            staged="/online/vcpkg/installed/.x64-linux-${LIBVPX_NATIVE_KEY}.tmp"
            rm -rf /online/vcpkg/installed/.x64-linux-*.tmp
            cp -a "$VR"/installed/x64-linux "$staged"
            printf "%s\n" "$LIBVPX_NATIVE_KEY" >"$staged/.rustdesk-libvpx-native-key"
            rm -rf /online/vcpkg/installed/x64-linux
            mv "$staged" /online/vcpkg/installed/x64-linux
        '
    log "vcpkg natives staged ($(ls "$ONLINE_DIR"/vcpkg/installed/x64-linux/lib/*.a 2>/dev/null | wc -l) static libs)"
}

# ── The Android NDK r28c, extracted for the cargo-ndk JNI cross-compile ─────────
# fetch_toolchains fetched the NDK zip; build-android.sh expects it at ANDROID_NDK_HOME=
# /online/android-ndk. Unzip it ONCE here (~2GB extracted) so the offline build reuses it.
# (The SDK build-tools/platform are staged separately via sdkmanager; the rust JNI lib also
# needs the aarch64-linux-android std + cargo-ndk + the arm64-android vcpkg set.)
stage_android_ndk() {
    require_cmd unzip
    if [ -d "$ONLINE_DIR/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
        log "android NDK already extracted, skipping"; return 0
    fi
    [ -f "$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip" ] || die "android NDK zip missing — fetch_toolchains must run first"
    log "extracting the Android NDK ${ANDROID_NDK_VERSION} -> ./online/android-ndk"
    rm -rf "$ONLINE_DIR/.ndk-tmp" "$ONLINE_DIR/android-ndk"; mkdir -p "$ONLINE_DIR/.ndk-tmp"
    unzip -q "$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip" -d "$ONLINE_DIR/.ndk-tmp"
    local extracted=()
    mapfile -d '' extracted < <(find "$ONLINE_DIR/.ndk-tmp" -mindepth 1 -maxdepth 1 -type d -name 'android-ndk-*' -print0)
    [ "${#extracted[@]}" -eq 1 ] || die "pinned Android NDK archive did not extract exactly one android-ndk-* directory"
    mv "${extracted[0]}" "$ONLINE_DIR/android-ndk"
    rm -rf "$ONLINE_DIR/.ndk-tmp"
}

# ── The vcpkg-built arm64-android native codecs (R-R1 pinned overlay) ─────────────
# The android JNI lib (scrap + magnum-opus, cross-compiled by cargo-ndk for
# aarch64-linux-android) links the codecs STATICALLY from VCPKG_ROOT/installed/arm64-android.
# vcpkg's arm64-android triplet cross-compiles them with the NDK clang (ANDROID_NDK_HOME) — no
# host gcc-8 needed (ARM NEON, not x86 AVX2). CLASSIC mode (--overlay-ports + explicit ports),
# not manifest mode: manifest mode needs the vcpkg tree to be a git checkout (to resolve the
# builtin-baseline), but ./online stages the pinned TARBALL (no .git) — classic mode over the
# tarball baseline ports + the overlay is equivalent + git-free.
stage_vcpkg_natives_arm64() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified android-builder image missing — load_builder_images must run first"
    require_libvpx_distfiles
    local native_key
    native_key="$(libvpx_native_key)"
    if [ -d "$ONLINE_DIR/vcpkg/installed/arm64-android/lib" ] && \
       [ "$(cat "$ONLINE_DIR/vcpkg/installed/arm64-android/.rustdesk-libvpx-native-key" 2>/dev/null)" = "$native_key" ]; then
        log "vcpkg arm64-android codecs already staged for libvpx key $native_key, skipping"; return 0
    fi
    [ -d "$ONLINE_DIR/android-ndk/toolchains" ] || die "android NDK not extracted — stage_android_ndk must run first"
    [ -f "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" ] || die "vcpkg source archive missing — fetch_vcpkg must run first"
    log "staging the vcpkg arm64-android natives (libvpx/libyuv/opus + oboe audio) -> ./online/vcpkg/installed/arm64-android"
    docker run --rm \
        -v "$ONLINE_DIR:/online" \
        -v "$REPO_ROOT/res/vcpkg:/overlay:ro" \
        -e RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        -e LIBVPX_NATIVE_KEY="$native_key" \
        "$builder" bash -euo pipefail -c '
            export ANDROID_NDK_HOME=/online/android-ndk
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            export VCPKG_BINARY_SOURCES=clear
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet arm64-android --overlay-ports=/overlay \
                libvpx libyuv opus oboe
            mkdir -p /online/vcpkg/installed
            staged="/online/vcpkg/installed/.arm64-android-${LIBVPX_NATIVE_KEY}.tmp"
            rm -rf /online/vcpkg/installed/.arm64-android-*.tmp
            cp -a "$VR"/installed/arm64-android "$staged"
            printf "%s\n" "$LIBVPX_NATIVE_KEY" >"$staged/.rustdesk-libvpx-native-key"
            rm -rf /online/vcpkg/installed/arm64-android
            mv "$staged" /online/vcpkg/installed/arm64-android
        '
    log "vcpkg arm64-android codecs staged ($(ls "$ONLINE_DIR"/vcpkg/installed/arm64-android/lib/*.a 2>/dev/null | wc -l) static libs)"
}

# ── cargo-ndk (R-B7): the JNI cross-compile orchestrator, staged ───────────────────
# ndk_arm64.sh runs `cargo ndk ... build` to cross-compile librustdesk.so for android;
# cargo-ndk is NOT in the main cargo-vendor set, so `cargo install` it HERE (networked) in
# the android-builder image with the pinned rust — exactly as upstream's android job does
# (`cargo install cargo-ndk --version <pin> --locked`). A HOST tool → ./online/cargo-ndk-tool.
stage_cargo_ndk() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified android-builder image missing — load_builder_images must run first"
    if [ -x "$ONLINE_DIR/cargo-ndk-tool/bin/cargo-ndk" ]; then
        log "cargo-ndk already staged, skipping"; return 0
    fi
    log "installing cargo-ndk ${CARGO_NDK_VERSION} for the android-builder image -> ./online/cargo-ndk-tool"
    docker run --rm -v "$ONLINE_DIR:/online" "$builder" bash -euo pipefail -c '
        TC=/tmp/tc; mkdir -p "$TC"; tar -C "$TC" -xf /online/rust-1.*.tar.xz
        "$TC"/rust-1.*/install.sh --prefix=/tmp/rust --disable-ldconfig \
            --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu >/dev/null
        export PATH=/tmp/rust/bin:$PATH
        cargo install cargo-ndk --version '"${CARGO_NDK_VERSION}"' --locked --root /online/cargo-ndk-tool
    '
}

# ── The Android SDK (build-tools + platform), via sdkmanager ────────────────────────
# `flutter build apk` + apksigner need the SDK; online-fetch fetched the cmdline-tools zip,
# but the build-tools/platform packages are sdkmanager-installed HERE (networked). The exact
# versions are pinned (ANDROID_BUILD_TOOLS / ANDROID_COMPILE_SDK) and sdkmanager verifies each
# package's checksum against the SDK repository XML, so the install is reproducible. Staged to
# ./online/android-sdk (build-tools = aapt2/apksigner/zipalign; platform-N = the android.jar).
stage_android_sdk() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified android-builder image missing — load_builder_images must run first"
    if [ -d "$ONLINE_DIR/android-sdk/build-tools/${ANDROID_BUILD_TOOLS}" ]; then
        log "android SDK already staged, skipping"; return 0
    fi
    [ -f "$ONLINE_DIR/android-cmdline-tools.zip" ] || die "android cmdline-tools zip missing — fetch_toolchains must run first"
    log "staging the Android SDK (build-tools ${ANDROID_BUILD_TOOLS} + platform-${ANDROID_COMPILE_SDK}) -> ./online/android-sdk"
    docker run --rm -v "$ONLINE_DIR:/online" "$builder" bash -euo pipefail -c '
        mkdir -p /tmp/sdk/cmdline-tools
        unzip -q /online/android-cmdline-tools.zip -d /tmp/sdk/cmdline-tools
        mv /tmp/sdk/cmdline-tools/cmdline-tools /tmp/sdk/cmdline-tools/latest
        export ANDROID_SDK_ROOT=/tmp/sdk ANDROID_HOME=/tmp/sdk
        SDKMGR=/tmp/sdk/cmdline-tools/latest/bin/sdkmanager
        yes | "$SDKMGR" --licenses >/dev/null 2>&1 || true
        "$SDKMGR" "platform-tools" "build-tools;'"${ANDROID_BUILD_TOOLS}"'" \
            "platforms;android-'"${ANDROID_COMPILE_SDK}"'" >/dev/null
        rm -rf /online/android-sdk
        cp -a /tmp/sdk /online/android-sdk
    '
}

# ── The warm gradle cache (R-B7): GRADLE_USER_HOME, populated by ONE online apk build ──
# `flutter build apk` drives gradle, which downloads the gradle distribution + the AGP/kotlin/
# plugin deps from google()/mavenCentral()/gradlePluginPortal(); the offline build_apk
# (--network=none) cannot. Populate the cache HERE (the ONE networked step) by running the SAME
# shared android build flow online (APK_MODE=warm, scripts/android-apk-build.sh) — it writes
# /online/gradle-home AND auto-installs the extra SDK packages gradle pulls (build-tools 30.0.3,
# platform-33/32 beyond stage_android_sdk's 34.0.0/platform-34). build_apk then projects this cache
# into private writable execution state whose tracked init authority enables Gradle offline mode.
stage_gradle() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "verified android-builder image missing — load_builder_images must run first"
    if [ -d "$ONLINE_DIR/gradle-home/caches/modules-2" ]; then
        log "gradle cache already warm, skipping"; return 0
    fi
    [ -d "$ONLINE_DIR/android-sdk/build-tools" ] || die "android SDK not staged — stage_android_sdk must run first"
    [ -d "$ONLINE_DIR/vcpkg/installed/arm64-android" ] || die "arm64-android vcpkg not staged — stage_vcpkg_natives_arm64 must run first"
    [ -x "$ONLINE_DIR/cargo-ndk-tool/bin/cargo-ndk" ] || die "cargo-ndk not staged — stage_cargo_ndk must run first"
    log "warming the gradle cache via one online apk build (APK_MODE=warm) -> ./online/gradle-home"
    docker run --rm \
        -e APK_MODE=warm \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online" \
        -w /src \
        "$builder" bash /src/scripts/android-apk-build.sh
    log "gradle cache warmed ($(du -sh "$ONLINE_DIR/gradle-home" 2>/dev/null | cut -f1))"
}

# ── The windows flutter ENGINE (precache --windows): ~780MB of windows-x64{,-profile,-release} ──
# The §12.2 golden-provision's IN-VM `flutter precache --windows` 780MB CDN fetch STALLS mid-transfer
# over the guest's slirp NAT, so the engine is staged HERE on a real network (~22s) and shipped into the
# golden (TOOLCHAINS CD) instead. The LINUX flutter's `precache --windows` pulls the WINDOWS-x64 engine
# (platform data, host-agnostic); precache writes ONLY artifacts/engine/windows-x64* (no external
# stamps), so the captured set is the complete cached state — with it pre-placed the in-VM precache
# validates in ~4s and downloads nothing (docker-verified). Deterministic tar + gzip -n => stable SHA.
stage_windows_engine() {
    require_cmd docker
    local out="$ONLINE_DIR/flutter-windows-engine.tar.gz"
    [ -f "$out" ] && { log "windows flutter engine already staged, skipping"; return 0; }
    log "staging the windows flutter engine (linux flutter precache --windows) -> ./online/flutter-windows-engine.tar.gz"
    docker run --rm -v "$ONLINE_DIR:/online" ubuntu:24.04 bash -euo pipefail -c '
        apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git curl ca-certificates unzip xz-utils >/dev/null 2>&1
        tar -C /tmp -xf /online/flutter-*.tar.xz
        export PATH=/tmp/flutter/bin:$PATH CI=true
        export HOME=/tmp/home; mkdir -p "$HOME"; git config --global --add safe.directory "*"
        cd /tmp/flutter
        find bin/cache -type f | sort > /tmp/before.txt
        touch /tmp/marker
        flutter precache --windows >/dev/null 2>&1
        # Stage the NEW files (the engine binaries — they keep PRESERVED-OLD mtimes from the zip, so
        # find -newer misses them) PLUS the files precache MODIFIED with a fresh mtime (find -newer) --
        # crucially bin/cache/windows-sdk.stamp, the freshness marker the WINDOWS flutter checks. Without
        # it the windows flutter RE-DOWNLOADS the engine even though the artifacts are present (the linux
        # flutter accepts without it, which is why a linux-only verify is misleading; the windows flutter
        # does not -- this wedged the in-VM precache over slirp). Exclude the transient bin/cache/lockfile.
        { comm -13 /tmp/before.txt <(find bin/cache -type f | sort); find bin/cache -type f -newer /tmp/marker; } \
            | sort -u | grep -v "bin/cache/lockfile$" > /tmp/stage.txt
        grep -q "artifacts/engine/windows-x64" /tmp/stage.txt || { echo "precache produced no windows-x64 engine"; exit 1; }
        grep -q "windows-sdk.stamp" /tmp/stage.txt || { echo "windows-sdk.stamp not captured -- windows flutter would re-download"; exit 1; }
        # deterministic: sorted names + fixed mtime/owner + gzip -n -> stable R-B12 SHA
        tar --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner -cf - -T /tmp/stage.txt | gzip -n -9 > /online/flutter-windows-engine.tar.gz
    '
    [ -f "$out" ] || die "windows flutter engine staging failed"
    log "windows flutter engine staged: $out ($(du -h "$out" | cut -f1))"
}

# ── The windows flutter_tools pub cache (§12.2): hosted deps incl. flutter_tools' DEV deps ──
# The §12.2 golden-provision's IN-VM `dart pub get --offline` on flutter_tools FAILS over the bundled
# cache alone: the flutter SDK zip bundles flutter_tools' RUNTIME deps but NOT its DEV deps (test 1.25.7,
# test_core, test_api, fake_async, …), so `--offline` cannot solve the full set ("Because flutter_tools
# depends on test 1.25.7 which doesn't match any versions, version solving failed"). The non-offline
# resolve makes ~98 pub.dev metadata round-trips that STALL over the guest's slirp NAT. So the COMPLETE
# flutter_tools hosted closure is staged HERE on a real network and shipped into the golden (TOOLCHAINS
# CD), then pre-placed at the builder's %LOCALAPPDATA%\Pub\Cache so the in-VM resolve is a 0-download.
# Derived from stage_pub_cache's ./online/pub-cache (the rustdesk `flutter pub get` resolved a superset
# of flutter_tools' pinned pubspec.lock — docker-verified the 95 hosted pkgs are all present at their
# pinned versions). We package ONLY hosted/ + hosted-hashes/ (flutter_tools needs no git deps); the
# internal layout begins at hosted/ so it extracts under a Pub\Cache root. Deterministic tar + gzip -n.
stage_flutter_pub_cache() {
    local out="$ONLINE_DIR/flutter-pub-cache.tar.gz"
    [ -f "$out" ] && { log "windows flutter pub cache already staged, skipping"; return 0; }
    # stage_pub_cache must have populated ./online/pub-cache first (the hosted closure lives there).
    [ -d "$ONLINE_DIR/pub-cache/hosted/pub.dev" ] || die "pub-cache/hosted not staged — stage_pub_cache must run first"
    [ -d "$ONLINE_DIR/pub-cache/hosted-hashes/pub.dev" ] || die "pub-cache/hosted-hashes not staged — stage_pub_cache must run first"
    log "staging the windows flutter_tools pub cache (hosted + hosted-hashes) -> ./online/flutter-pub-cache.tar.gz"
    require_cmd docker
    # Run in a container as root: ./online/pub-cache is root-owned (written by the docker flutter steps).
    # Deterministic: sorted names + fixed mtime/owner/numeric-owner + gzip -n -> stable R-B12 SHA.
    docker run --rm -v "$ONLINE_DIR:/online" ubuntu:24.04 bash -euo pipefail -c '
        cd /online/pub-cache
        tar --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner -cf - hosted hosted-hashes \
            | gzip -n -9 > /online/flutter-pub-cache.tar.gz
    '
    [ -f "$out" ] || die "windows flutter pub cache staging failed"
    # Sanity: flutter_tools' load-bearing DEV dep (test 1.25.7) MUST be in the archive, else the in-VM
    # offline resolve would still "version solving failed" — the exact failure this step exists to fix.
    zcat "$out" | tar -t 2>/dev/null | grep -q 'hosted/pub.dev/test-1.25.7/pubspec.yaml' \
        || die "flutter-pub-cache.tar.gz lacks test-1.25.7 — flutter_tools dev deps missing; the offline resolve would fail"
    log "windows flutter pub cache staged: $out ($(du -h "$out" | cut -f1))"
    # NB the tarball deliberately includes hosted/pub.dev/.cache/ (pub's metadata + advisory cache). The in-VM
    # win-guest-setup STAMPS that .cache fresh after extraction: the deterministic --mtime above pins it to 2023
    # so dart would treat the advisory cache as expired and re-fetch it from pub.dev (fatal on the fresh-Win11
    # guest whose TLS handshake to pub.dev fails). Stamping it NOW keeps the flutter_tools resolve 0-network.
}

# ── The WiX v4.0.5 NuGet closure (§12.2 milestone-2, the .msi) ──────────────────────────────
# The .msi (R-B7/B8) builds via `python res/msi/preprocess.py` then `msbuild res/msi/msi.sln`, which restores the
# wixproj's 5 .wixext PackageReferences + the WixToolset.Sdk. Stage that whole NuGet closure OFFLINE so the in-VM
# msbuild needs 0 network. Captured by a host `dotnet restore` of the real wixproj. 6 packages.
# DETERMINISTIC (proven: two fresh re-downloads -> identical SHA): sorted tar + fixed mtime/owner + gzip -n. Shipped
# on the TOOLCHAINS CD + pre-placed at the golden's NUGET_PACKAGES by win-guest-setup (milestone 2 re-provision).
stage_windows_wix_nuget() {
    require_cmd docker
    local out="$ONLINE_DIR/wix-nuget.tar.gz"
    if [ -f "$out" ]; then
        verify_sha256 "$out" "${SHA256_WIX_NUGET}"
        log "WiX NuGet already staged and digest-verified, skipping"
        return 0
    fi
    log "staging the WiX v4.0.5 NuGet closure (host dotnet restore) -> ./online/wix-nuget.tar.gz"
    docker run --rm -e HU="$(id -u)" -e HG="$(id -g)" \
        -v "$(dirname "$ONLINE_DIR")/res/msi:/msi:ro" -v "$ONLINE_DIR:/online" \
        mcr.microsoft.com/dotnet/sdk:8.0 bash -euo pipefail -c '
        export NUGET_PACKAGES=/cache; mkdir -p /cache
        cp -r /msi /tmp/m; cd /tmp/m
        dotnet restore Package/Package.wixproj >/dev/null 2>&1
        [ -d /cache/wixtoolset.sdk ] && [ -d /cache/wixtoolset.firewall.wixext ] \
            && [ -d /cache/wixtoolset.heat ] && [ -d /cache/wixtoolset.netfx.wixext ] \
            && [ -d /cache/wixtoolset.ui.wixext ] && [ -d /cache/wixtoolset.util.wixext ] \
            || { echo "WiX NuGet capture incomplete"; exit 1; }
        tar --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner -C /cache -cf - . | gzip -n > /online/wix-nuget.tar.gz
        chown "$HU:$HG" /online/wix-nuget.tar.gz
    '
    [ -f "$out" ] || die "WiX NuGet staging failed"
    verify_sha256 "$out" "${SHA256_WIX_NUGET}"
    log "WiX NuGet staged: $out ($(du -h "$out" | cut -f1))"
}

main() {
    case "${1:-}" in
        --libvpx-distfiles)
            [ "$#" -eq 1 ] || die "--libvpx-distfiles takes no arguments"
            stage_libvpx_distfiles
            return 0
            ;;
        --maintenance-build-image-candidates)
            [ "$#" -eq 1 ] || die "--maintenance-build-image-candidates takes no arguments"
            maintenance_build_image_candidates
            return 0
            ;;
        --maintenance-capture-builder-images)
            [ "$#" -eq 1 ] || die "--maintenance-capture-builder-images takes no arguments"
            maintenance_capture_builder_images
            return 0
            ;;
        --maintenance-print-online-closure)
            [ "$#" -eq 1 ] || die "--maintenance-print-online-closure takes no arguments"
            python3 "$LIB_DIR/online-input-provenance.py" maintenance-print-root --tree "$ONLINE_DIR"
            return 0
            ;;
        --maintenance-write-online-closure)
            [ "$#" -eq 1 ] || die "--maintenance-write-online-closure takes no arguments"
            python3 "$LIB_DIR/online-input-provenance.py" maintenance-write-record --tree "$ONLINE_DIR"
            return 0
            ;;
        --verify-offline-inputs)
            [ "$#" -eq 1 ] || die "--verify-offline-inputs takes no arguments"
            verify_online_pinned_archives
            load_builder_images
            require_online_complete
            return 0
            ;;
        --debian-systemd-smoke-image)
            [ "$#" -eq 1 ] || die "--debian-systemd-smoke-image takes no arguments"
            fetch_debian_systemd_smoke_image
            return 0
            ;;
        '') ;;
        *) die "usage: scripts/online-fetch.sh [--libvpx-distfiles|--maintenance-build-image-candidates|--maintenance-capture-builder-images|--maintenance-print-online-closure|--maintenance-write-online-closure|--verify-offline-inputs|--debian-systemd-smoke-image]" ;;
    esac
    log "online-fetch: materializing the SHA-256-verified ./online cache (R-B10)"
    load_builder_images
    vendor_cargo
    fetch_toolchains
    verify_online_glob_cardinality
    fetch_vcpkg
    build_frb_codegen
    stage_pub_cache
    stage_vcpkg_distfiles
    stage_vcpkg_natives
    stage_android_ndk
    stage_vcpkg_natives_arm64
    stage_cargo_ndk
    stage_android_sdk
    stage_gradle
    fetch_windows_toolchains
    stage_windows_engine
    stage_flutter_pub_cache
    stage_windows_wix_nuget
    verify_online_pinned_archives
    require_online_complete
    log "online-fetch complete — ./online equals its pinned closure. Builds run --network=none."
}

main "$@"

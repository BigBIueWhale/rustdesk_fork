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
# NOTE: every SHA-256 in pins.env is currently the R-B12 fail-closed sentinel, so
# fetch_verify aborts before trusting any download. That is intentional: R-B12
# requires each first pin be established by an audited, dual-sourced bootstrap
# (publisher hash/signature cross-checked) and recorded in pins.env FIRST. This
# script is the structure that then enforces it. It is NOT run as part of "fork
# creation".
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
    curl -fsSL --proto '=https' --tlsv1.2 -o "$dest.part" "$url"
    mv "$dest.part" "$dest"
    verify_sha256 "$dest" "$sha"
}

# ── Rust crate world: vendor the committed lockfile (incl. the 44 git deps) ────
# `cargo vendor --locked` reproduces the exact lockfile-pinned crate set offline.
# It is itself a network step and belongs here, not in the offline build.
vendor_cargo() {
    require_cmd cargo
    log "cargo vendor (--locked) -> ./online/cargo-vendor (+ its [source] config)"
    # Capture the printed [source] config (crates-io + each of the 44 git deps) so
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
    # Flutter SDK 3.24.5.
    fetch_verify "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
        "flutter-${FLUTTER_VERSION}.tar.xz" "${SHA256_FLUTTER_3_24_5}"
    # Android NDK r28c.
    fetch_verify "https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip" \
        "android-ndk-${ANDROID_NDK_VERSION}.zip" "${SHA256_ANDROID_NDK_R28C}"
    # Android cmdline-tools (then build-tools 34.0.0 / platform-34 via sdkmanager, offline).
    fetch_verify "https://dl.google.com/android/repository/commandlinetools-linux-latest.zip" \
        "android-cmdline-tools.zip" "${SHA256_ANDROID_CMDLINE_TOOLS}"
    # LLVM/Clang 15.0.6 (libclang for bindgen determinism, R-B12).
    fetch_verify "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz" \
        "llvm-${LLVM_VERSION}.tar.xz" "${SHA256_LLVM_15_0_6}"
    # flutter_rust_bridge_codegen 1.80.1 (R-B7 — the uncommitted bridge generator).
    fetch_verify "https://github.com/fzyzcjy/flutter_rust_bridge/archive/refs/tags/v${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" \
        "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "${SHA256_FRB_1_80_1}"
}

# ── vcpkg registry snapshot + the digest-pinned build base images ─────────────
fetch_vcpkg_and_images() {
    # vcpkg @ the pinned baseline commit (then `vcpkg install` builds the native
    # set offline from the overlay ports in res/vcpkg).
    fetch_verify "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz" \
        "vcpkg-${VCPKG_BASELINE}.tar.gz" "${SHA256_VCPKG_120DEAC3}"
    # Digest-pinned base images for the §12.1 Docker builds (upstream's ubuntu18.04
    # for the .deb, ubuntu-24.04 for the .apk). Pulled by digest, exported to a tar.
    require_cmd docker
    for tag in "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"; do
        case "$tag" in *"${SHA_PENDING}"*) die "base-image digest is the R-B12 sentinel — record it in pins.env first" ;; esac
        log "docker pull (by digest): $tag"
        docker pull "$tag"
    done
}

main() {
    log "online-fetch: materializing the SHA-256-verified ./online cache (R-B10)"
    vendor_cargo
    fetch_toolchains
    fetch_vcpkg_and_images
    # Windows ISO / VS Build Tools are partly evergreen (R-B12(c)): pin the CAPTURED
    # offline layout by SHA-256, documenting publisher-verified vs evergreen.
    log "online-fetch complete — ./online is now offline-buildable. Builds run --network=none."
}

main "$@"

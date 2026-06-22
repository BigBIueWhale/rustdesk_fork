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

# ── The pinned .deb build image (R-B7/B8): ubuntu:18.04 + the system build-deps ────
# build-debian.sh runs the compile with --network=none, so the dev libs upstream's CI
# apt-installs into ubuntu:18.04 (flutter-build.yml) are baked into a local image HERE,
# during this one networked step. The toolchains stay in ./online (not in the image).
build_deb_builder_image() {
    require_cmd docker
    case "$SHA256_BASEIMAGE_UBUNTU_1804" in *"${SHA_PENDING}"*) die "base-image digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    log "docker build: $tag (FROM the pinned ubuntu:18.04 + system build-deps, Dockerfile.deb-builder)"
    docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
        -t "$tag" -f "$LIB_DIR/Dockerfile.deb-builder" "$LIB_DIR"
}

# ── The pinned .apk build image (R-B7/B8): ubuntu:24.04 + the android build-deps ────
# build-android.sh runs --network=none; the NDK r28c prebuilt clang needs a modern glibc, so
# this is FROM ubuntu:24.04 (not the bionic deb-builder). Dockerfile.android-builder bakes the
# vcpkg/cargo-ndk/gradle system deps; the rust/flutter/NDK toolchains stay in ./online.
build_android_builder_image() {
    require_cmd docker
    case "$SHA256_BASEIMAGE_UBUNTU_2404" in *"${SHA_PENDING}"*) die "base-image digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    log "docker build: $tag (FROM the pinned ubuntu:24.04 + android build-deps, Dockerfile.android-builder)"
    docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_2404}" \
        -t "$tag" -f "$LIB_DIR/Dockerfile.android-builder" "$LIB_DIR"
}

# ── The FRB codegen tool (R-B7): built FOR ubuntu:18.04, staged to ./online/frb-tool ──
# build_one needs flutter_rust_bridge_codegen to (re)generate the bridge; it cannot
# `cargo install` it offline (its deps are not in the main vendor set), so build it HERE
# (networked) in the deb-builder image with the pinned rust — exactly as upstream's
# bridge.yml does: `cargo install ... --version <pin> --features uuid --locked`.
build_frb_codegen() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "deb-builder image missing — build_deb_builder_image must run first"
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
# build_one resolves the flutter project --offline from this cache (the committed pubspec.lock
# pins it, so it is reproducible). Populated HERE (networked) by a real flutter pub get.
stage_pub_cache() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "deb-builder image missing — build_deb_builder_image must run first"
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
        cd /tmp/proj && flutter pub get
    '
}

# ── The vcpkg-built native codecs (R-R1 pinned overlay ports): aom/vpx/yuv/opus ──
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
    docker image inspect "$builder" >/dev/null 2>&1 || die "deb-builder image missing — build_deb_builder_image must run first"
    if [ -d "$ONLINE_DIR/vcpkg/installed/x64-linux/lib" ]; then
        log "vcpkg native codecs already staged, skipping"; return 0
    fi
    [ -f "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" ] || die "vcpkg source archive missing — fetch_vcpkg_and_images must run first"
    log "staging the vcpkg native codecs (aom/libvpx/libyuv/opus, x64-linux static) -> ./online/vcpkg/installed"
    docker run --rm \
        -v "$ONLINE_DIR:/online" \
        -v "$REPO_ROOT/res/vcpkg:/overlay:ro" \
        "$builder" bash -euo pipefail -c '
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            # bionic'\''s default gcc-7.5 miscompiles aom AVX2 intrinsics
            # (disflow_avx2.c: "incompatible types ... __m256i using int"); build the
            # codecs with gcc-8 (upstream uses gcc-8 for the vcpkg natives too). The
            # outputs are C-ABI static libs → link fine into the gcc/rust cargo build.
            export CC=/usr/bin/gcc-8 CXX=/usr/bin/g++-8
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet x64-linux --overlay-ports=/overlay \
                aom libvpx libyuv opus
            # Stage only the x64-linux install tree (lib/*.a + include/) that
            # scrap/magnum-opus link_vcpkg read via VCPKG_ROOT/installed/x64-linux.
            mkdir -p /online/vcpkg/installed
            rm -rf /online/vcpkg/installed/x64-linux
            cp -a "$VR"/installed/x64-linux /online/vcpkg/installed/x64-linux
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
    mv "$ONLINE_DIR"/.ndk-tmp/android-ndk-* "$ONLINE_DIR/android-ndk"
    rm -rf "$ONLINE_DIR/.ndk-tmp"
}

# ── The vcpkg-built arm64-android native codecs (R-R1 pinned overlay) ─────────────
# The android JNI lib (scrap + magnum-opus, cross-compiled by cargo-ndk for
# aarch64-linux-android) links the codecs STATICALLY from VCPKG_ROOT/installed/arm64-android.
# vcpkg's arm64-android triplet cross-compiles them with the NDK clang (ANDROID_NDK_HOME) — no
# host gcc-8 needed (ARM NEON, not x86 AVX2). CLASSIC mode (--overlay-ports + explicit ports),
# NOT the manifest mode of flutter/build_android_deps.sh: manifest mode needs the vcpkg tree to
# be a git checkout (to resolve the builtin-baseline), but ./online stages the pinned TARBALL
# (no .git) — classic mode over the tarball baseline ports + the overlay is equivalent + git-free.
stage_vcpkg_natives_arm64() {
    require_cmd docker
    local builder="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder"
    docker image inspect "$builder" >/dev/null 2>&1 || die "android-builder image missing — build_android_builder_image must run first"
    if [ -d "$ONLINE_DIR/vcpkg/installed/arm64-android/lib" ]; then
        log "vcpkg arm64-android codecs already staged, skipping"; return 0
    fi
    [ -d "$ONLINE_DIR/android-ndk/toolchains" ] || die "android NDK not extracted — stage_android_ndk must run first"
    [ -f "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" ] || die "vcpkg source archive missing — fetch_vcpkg_and_images must run first"
    log "staging the vcpkg arm64-android codecs (aom/libvpx/libyuv/opus) -> ./online/vcpkg/installed/arm64-android"
    docker run --rm \
        -v "$ONLINE_DIR:/online" \
        -v "$REPO_ROOT/res/vcpkg:/overlay:ro" \
        "$builder" bash -euo pipefail -c '
            export ANDROID_NDK_HOME=/online/android-ndk
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet arm64-android --overlay-ports=/overlay \
                aom libvpx libyuv opus
            mkdir -p /online/vcpkg/installed
            rm -rf /online/vcpkg/installed/arm64-android
            cp -a "$VR"/installed/arm64-android /online/vcpkg/installed/arm64-android
        '
    log "vcpkg arm64-android codecs staged ($(ls "$ONLINE_DIR"/vcpkg/installed/arm64-android/lib/*.a 2>/dev/null | wc -l) static libs)"
}

main() {
    log "online-fetch: materializing the SHA-256-verified ./online cache (R-B10)"
    vendor_cargo
    fetch_toolchains
    fetch_vcpkg_and_images
    build_deb_builder_image
    build_android_builder_image
    build_frb_codegen
    stage_pub_cache
    stage_vcpkg_natives
    stage_android_ndk
    stage_vcpkg_natives_arm64
    # Windows ISO / VS Build Tools are partly evergreen (R-B12(c)): pin the CAPTURED
    # offline layout by SHA-256, documenting publisher-verified vs evergreen.
    log "online-fetch complete — ./online is now offline-buildable. Builds run --network=none."
}

main "$@"

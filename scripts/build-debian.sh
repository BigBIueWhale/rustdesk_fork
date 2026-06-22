#!/usr/bin/env bash
# scripts/build-debian.sh — Debian x86_64 .deb build (R-B7/B8/B9, §12.1, §17).
#
# Reproduces upstream 1.4.7's OFFICIAL .deb build (R-B7: inherited, not reinvented)
# inside a digest-pinned ubuntu:18.04 container — upstream's own glibc baseline
# (run-on-arch-action) — with EXACTLY two deltas and no others: no code-signing,
# and it runs off GitHub-hosted runners (R-B2). The build is offline
# (--network=none) against the SHA-verified ./online cache (R-B10).
#
# One mode, the good one (R-B9): validate the EXACT pinned env, then abort; fail
# loud; no fallbacks; pin every version from pins.env; verify the artifact.
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
# The §3.2 x64-linux feature set minus hwcodec — CPU-only, software vpx/aom (R-R2b).
FEATURES="--flutter --unix-file-copy-paste"
# Determinism (R-B2): pin BUILD_DATE so two builds of identical source are
# byte-identical. Use the release commit's author date; gen_version MUST honor
# SOURCE_DATE_EPOCH (the hbb_common patch is tracked in HARDENING_STATUS as R-B2).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"
# The pinned .deb build image: the digest-pinned ubuntu:18.04 baseline + the system
# build-deps, baked by online-fetch.sh (the ONE networked step) via Dockerfile.deb-builder.
# The compile then runs inside it with --network=none.
IMAGE="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"

preflight() {
    require_cmd docker git
    assert_repo_state
    require_online_complete
    case "$SHA256_BASEIMAGE_UBUNTU_1804" in *"${SHA_PENDING}"*) die "the ubuntu:18.04 base digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "build image '$IMAGE' not found — run scripts/online-fetch.sh first (it docker-builds it from the pinned ubuntu:18.04 + the system build-deps, Dockerfile.deb-builder)"
    log "preflight OK — building $FEATURES in $IMAGE, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

# build_one PROFILE FEATURES: run upstream's build.py in the pinned container,
# network removed, ./online mounted read-only. Emits target/release + the .deb.
build_one() {
    local profile="$1" features="$2" tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-$1"
    log "building profile '$profile' (features: $features)"
    docker run --rm \
        --name "$tag" \
        --network=none \
        -e SOURCE_DATE_EPOCH \
        -v "$REPO_ROOT:/src" \
        -v "$ONLINE_DIR:/online:ro" \
        -w /src \
        "$IMAGE" \
        bash -euo pipefail -c '
            # The container is the pinned, immutable template (R-B8): everything
            # comes from /online (R-B5a), nothing is fetched (--network=none).
            TC=/tmp/tc; mkdir -p "$TC"
            # Extract the pinned toolchains from the ./online tarballs that
            # online-fetch.sh materialized (Rust 1.75, Flutter 3.24.5, NDK, LLVM 15,
            # vcpkg snapshot) and put their bins on PATH. vcpkg then builds the
            # native set offline from res/vcpkg overlay ports.
            for t in /online/rust-*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
                [ -e "$t" ] && tar -C "$TC" -xf "$t"
            done
            # Rust: the standalone tarball extracts to rust-1.75.0-.../ with an install.sh
            # (there is no top-level bin/) — install it to a prefix. LLVM: the tarball is
            # clang+llvm-15.0.6-.../ — point bindgen at its libclang.
            "$TC"/rust-*/install.sh --prefix="$TC/rustinstall" --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
            export LIBCLANG_PATH="$(echo "$TC"/clang+llvm-*/lib)"
            # Use a build-time CARGO_HOME so the vendored/offline config does NOT
            # overwrite the repo'\''s TRACKED .cargo/config.toml (which carries the
            # windows/macos rustflags); cargo merges CARGO_HOME/config.toml with it.
            export CARGO_HOME=/tmp/cargo-home
            mkdir -p "$CARGO_HOME"
            # The pre-built FRB codegen tool is staged at /online/frb-tool/bin by
            # online-fetch'\''s build_frb_codegen (built FOR ubuntu:18.04 there).
            export PATH="$TC/flutter/bin:$TC/rustinstall/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
            # Wire cargo to the vendored, lockfile-pinned crate set (R-B10) so the
            # --locked build resolves from ./online/cargo-vendor, never the network.
            # The vendor_cargo step captured the AUTHORITATIVE [source.*] map (the cargo
            # vendor output: [source.crates-io] replace-with="vendored-sources", every
            # git-dep source, and [source.vendored-sources]). Use it verbatim (rewrite its
            # directory to /online/cargo-vendor) + ONLY add [net] offline. Do NOT also
            # hand-write a [source.crates-io] -- that duplicates the table and cargo (incl.
            # cargo-metadata, which FRB codegen runs) rejects it (duplicate key crates-io).
            cat > "$CARGO_HOME/config.toml" <<CFG
[net]
offline = true
CFG
            [ -f /online/cargo-vendor-config.toml ] || { echo "[FATAL] /online/cargo-vendor-config.toml missing -- run online-fetch.sh"; exit 1; }
            sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
            # FRB codegen first (R-B7: the uncommitted generated_bridge.dart /
            # bridge_generated.rs every build job needs), then upstream build.py
            # with the §3.2 x64-linux features.
            flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart
            python3 ./build.py '"$features"'
        '
    mkdir -p "$OUT_DIR"
    local deb
    deb="$(ls -1 "$REPO_ROOT"/rustdesk-*.deb 2>/dev/null | head -1)" || die "no .deb produced"
    cp "$deb" "$OUT_DIR/rustdesk-${profile}.deb"
    sha256sum "$OUT_DIR/rustdesk-${profile}.deb" | tee "$OUT_DIR/rustdesk-${profile}.deb.sha256"
}

main() {
    preflight
    # The one .deb — viewer and --server in a single binary, role by argv (R-R2b/R-B1).
    build_one x86_64 "$FEATURES"

    # Double-build determinism (R-B2): a second build of identical source MUST
    # produce a byte-identical SHA-256, or the recorded-SHA bar is unfalsifiable.
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        local first; first="$(awk '{print $1}' "$OUT_DIR/rustdesk-x86_64.deb.sha256")"
        OUT_DIR="$OUT_DIR/_rebuild" build_one x86_64 "$FEATURES"
        local second; second="$(awk '{print $1}' "$OUT_DIR/_rebuild/rustdesk-x86_64.deb.sha256")"
        [ "$first" = "$second" ] || die "double-build SHA mismatch ($first vs $second) — fix BUILD_DATE/SOURCE_DATE_EPOCH determinism (R-B2)"
        log "double-build determinism OK: $first"
    fi

    log "build-debian.sh complete: $OUT_DIR/rustdesk-x86_64.deb"
}

main "$@"

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
    # HONESTY GATE (the af8746f class): build.py renames the freshly built package to
    # $REPO_ROOT/rustdesk-<version>.deb, and the post-build step copies whatever
    # rustdesk-*.deb it finds there. A PRIOR run leaves one behind (root-owned), so if a
    # build fails WITHOUT producing a new one, that STALE .deb would be picked up and shipped
    # as a false success. Remove any pre-existing rustdesk-*.deb up front (these are
    # git-ignored artifacts) so the gate below can ONLY find a package THIS run produced.
    rm -f "$REPO_ROOT"/rustdesk-*.deb
    docker run --rm \
        --name "$tag" \
        --network=none \
        -e SOURCE_DATE_EPOCH \
        -e RUSTDESK_CANARY_OFFLINE=1 \
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
            # rust-1.* (NOT rust-*) so the glob does not also grab the android cross-std
            # online/rust-std-1.75-aarch64-linux-android.tar.xz (added for the .apk build).
            for t in /online/rust-1.*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
                [ -e "$t" ] && tar -C "$TC" -xf "$t"
            done
            # Rust: the standalone tarball extracts to rust-1.75.0-.../ with an install.sh
            # (there is no top-level bin/) — install it to a prefix. LLVM: the tarball is
            # clang+llvm-15.0.6-.../ — point bindgen at its libclang.
            "$TC"/rust-1.*/install.sh --prefix="$TC/rustinstall" --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
            LLVM_ROOT="$(echo "$TC"/clang+llvm-*)"
            export LIBCLANG_PATH="$LLVM_ROOT/lib"
            # The native codecs (aom/vpx/yuv/opus) come from the vcpkg overlay tree that
            # online-fetch'\''s stage_vcpkg_natives built (R-R1 pinned, x64-linux static).
            # scrap + magnum-opus link them from VCPKG_ROOT/installed/x64-linux (the shipped
            # feature set has linux-pkg-config OFF, so build.rs find_package needs VCPKG_ROOT).
            export VCPKG_ROOT=/online/vcpkg
            [ -d "$VCPKG_ROOT/installed/x64-linux/lib" ] || { echo "[FATAL] /online/vcpkg/installed/x64-linux missing -- run online-fetch.sh (stage_vcpkg_natives)"; exit 1; }
            # Use a build-time CARGO_HOME so the vendored/offline config does NOT
            # overwrite the repo'\''s TRACKED .cargo/config.toml (which carries the
            # windows/macos rustflags); cargo merges CARGO_HOME/config.toml with it.
            export CARGO_HOME=/tmp/cargo-home
            mkdir -p "$CARGO_HOME"
            # The pre-built FRB codegen tool is staged at /online/frb-tool/bin by
            # online-fetch'\''s build_frb_codegen (built FOR ubuntu:18.04 there).
            export PATH="$TC/flutter/bin:$TC/rustinstall/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
            # Shadow `flutter` with the offline shim (scripts/flutter-offline-shim.sh): the
            # flutter wrapper drives `pub` ONLINE (it refreshes pub security advisories, which
            # _TypeError against the read-only offline cache → rc=1), so route `flutter pub
            # {run,get}` (FRB ffigen + any implicit get) to `dart --offline`; `flutter build
            # linux` passes through to the real flutter ($REAL_FLUTTER) unchanged.
            export REAL_FLUTTER="$TC/flutter/bin/flutter"
            SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
            cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
            export PATH="$SHIM:$PATH"
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
            # Flutter pub OFFLINE from the staged cache (online-fetch stage_pub_cache).
            # Fix git "dubious ownership" on the root-owned flutter SDK + the git-dep clones,
            # set PUB_CACHE, and pre-resolve the project --offline (the committed pubspec.lock
            # pins it) so the .dart_tool exists -- then FRB build_runner + flutter build use it
            # without auto-running a networked pub get.
            export HOME=/tmp/buildhome; mkdir -p "$HOME"
            git config --global --add safe.directory "*"
            export PUB_CACHE=/online/pub-cache
            [ -d "$PUB_CACHE" ] || { echo "[FATAL] /online/pub-cache missing -- run online-fetch.sh (stage_pub_cache)"; exit 1; }
            pub_lock_before="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            # Resolve the project: dart pub get --offline reads straight from PUB_CACHE and
            # skips advisories (validated against the staged cache). It is the ONLINE flutter
            # wrapper pub get that refreshes pub security advisories and _TypeErrors against the
            # read-only offline cache → rc=1; `--offline` (here and the flutter injection below)
            # avoids that advisories fetch entirely.
            export CI=true   # non-interactive flutter (suppress the fresh-HOME first-run prompt)
            ( cd flutter && dart pub get --offline )
            # Pre-resolve the flutter SDK'\''s OWN tool package (packages/flutter_tools) OFFLINE before
            # ANY `flutter` invocation: the cold tarball ships it UNRESOLVED, and the first `flutter ...`
            # would otherwise re-resolve it IN-PROCESS + ONLINE (pub.dev + the advisories _TypeError).
            # Its deps are staged in PUB_CACHE by stage_pub_cache. Must precede the injection + build below.
            ( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
            # Plugin injection (R-B7), mirroring build-windows.ps1:107-110. `dart pub get`
            # resolves the project (writes .dart_tool) but does NOT run flutter'\''s plugin
            # injection, which is what (re)generates flutter/linux/flutter/generated_plugins.cmake
            # + flutter/linux/flutter/ephemeral/.plugin_symlinks/* + flutter/.flutter-plugins{,-dependencies}.
            # The git-ignored ephemeral symlinks are stale across runs -- a prior build wrote them
            # pointing at /root/.pub-cache (its PUB_CACHE), so under THIS build'\''s PUB_CACHE=/online/pub-cache
            # they DANGLE and `flutter build linux` CMake-aborts: "add_subdirectory given source
            # flutter/ephemeral/.plugin_symlinks/<plugin>/linux which is not an existing directory"
            # (generated_plugins.cmake:23). Run the FLUTTER-level pub get to re-inject them against the
            # current PUB_CACHE. Use $REAL_FLUTTER (NOT the shim, which routes `pub get`->`dart pub get`
            # and so SKIPS injection) with --offline: only the ONLINE wrapper pub get refreshes the
            # advisories that _TypeError on the read-only cache; `flutter pub get --offline` resolves
            # straight from PUB_CACHE WITHOUT advisories (proven: "Got dependencies!", rc=0), so the
            # injection runs clean offline. The regenerated symlinks resolve under /online/pub-cache and
            # each <plugin>/linux exists. (.flutter-plugins-dependencies carries a wall-clock date_created,
            # but it is git-ignored build-input metadata referenced by nothing in build/linux/.../bundle/,
            # so it never reaches the .deb payload -- R-B2 unaffected, enforced by the DOUBLE_BUILD A==B gate.)
            # R-B9 idempotency: DELETE the stale ephemeral symlinks FIRST. `flutter pub get` does NOT
            # overwrite an existing (dangling) symlink, so if a prior build (even from another session)
            # left flutter/linux/flutter/ephemeral/.plugin_symlinks/* pointing at its own PUB_CACHE, the
            # re-injection below is SKIPPED and `flutter build linux` CMake-aborts on every plugin
            # ("<plugin>/linux is not an existing directory"). Removing them forces a clean re-inject
            # against the current PUB_CACHE. Git-ignored build-input metadata (never in the .deb
            # payload), regenerated identically by both double-build passes, so A==B is unaffected.
            # This makes the build safe to re-run on a non-pristine tree (R-B9 "re-running is safe").
            rm -rf flutter/linux/flutter/ephemeral/.plugin_symlinks \
                   flutter/.flutter-plugins-dependencies flutter/.flutter-plugins
            ( cd flutter && "$REAL_FLUTTER" pub get --offline )
            pub_lock_after="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            [ "$pub_lock_before" = "$pub_lock_after" ] || {
                echo "[FATAL] flutter/pubspec.lock changed during offline pub resolution" >&2
                git --no-pager diff -- flutter/pubspec.lock || true
                exit 1
            }
            # FRB codegen first (R-B7: the uncommitted generated_bridge.dart /
            # bridge_generated.rs every build job needs), then upstream build.py
            # with the §3.2 x64-linux features.
            # --llvm-compiler-opts: give ffigen'\''s libclang the clang BUILTIN-header dir so it
            # can resolve <stdbool.h>. Without it ffigen emits "[SEVERE] stdbool.h not found" and
            # DEGRADES every bool-returning binding (e.g. mainPeerHasPassword) to a raw
            # NativeFunction<Int...> → the flutter `kernel_snapshot` Dart compile then fails.
            flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart \
                --llvm-path "$LLVM_ROOT" \
                --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
            python3 ./build.py '"$features"'
        '
    mkdir -p "$OUT_DIR"
    # build.py fails loud (system2 → sys.exit(-1)) on any step, so a non-zero docker run already
    # aborts under set -e. This is the second line of defence: with the stale .deb purged above,
    # a missing rustdesk-*.deb now unambiguously means build.py did NOT emit one (e.g. flutter
    # build linux failed) -- fail loud rather than ship nothing/something stale.
    local deb
    deb="$(ls -1 "$REPO_ROOT"/rustdesk-*.deb 2>/dev/null | head -1 || true)"
    [ -n "$deb" ] && [ -f "$deb" ] || die "no rustdesk-*.deb produced — build.py did not emit a package (flutter build linux likely failed); see the build output above"
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

#!/usr/bin/env bash
# scripts/frb-codegen.sh — (re)generate the git-ignored flutter_rust_bridge bridges OFFLINE on the
# host (R-B7), so a build that cannot run FRB itself can consume them pre-built. FRB PARSES
# src/flutter_ffi.rs (it does not compile it), so the three outputs are platform-AGNOSTIC — bridges
# generated here on linux are byte-for-byte what the §12.2 Windows guest needs, which lets that guest
# skip the fragile in-VM FRB wiring (no FRB tool, no offline flutter-pub-run, no libclang plumbing).
#
# Produces (the .gitignore'd set): src/bridge_generated.rs, src/bridge_generated.io.rs,
# flutter/lib/generated_bridge.dart. Mirrors build-debian.sh's in-container FRB prefix (the canonical
# offline-flutter env: pinned ./online toolchains, CARGO_HOME, PUB_CACHE, the flutter-offline shim,
# dart pub get --offline) — that script is the source of truth; keep them in sync. Runs --network=none
# in the pinned deb-builder image. NOT part of "fork creation" — a build-harness helper.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
IMAGE="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"

require_cmd docker git
require_online_complete
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "build image '$IMAGE' not found — run scripts/online-fetch.sh first (Dockerfile.deb-builder)"

log "generating the FRB bridges offline in $IMAGE (--network=none) — mirrors build-debian.sh"
docker run --rm --network=none \
    -v "$REPO_ROOT:/src" -v "$ONLINE_DIR:/online:ro" -w /src "$IMAGE" \
    bash -euo pipefail -c '
        # --- the pinned offline toolchains from ./online (identical to build-debian.sh) -----------
        TC=/tmp/tc; mkdir -p "$TC"
        for t in /online/rust-1.*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
            [ -e "$t" ] && tar -C "$TC" -xf "$t"
        done
        "$TC"/rust-1.*/install.sh --prefix="$TC/rustinstall" --disable-ldconfig \
            --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
        LLVM_ROOT="$(echo "$TC"/clang+llvm-*)"
        export LIBCLANG_PATH="$LLVM_ROOT/lib"
        export CARGO_HOME=/tmp/cargo-home; mkdir -p "$CARGO_HOME"
        export PATH="$TC/flutter/bin:$TC/rustinstall/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
        # --- the flutter-offline shim (route flutter pub {run,get} -> dart --offline) -------------
        export REAL_FLUTTER="$TC/flutter/bin/flutter"
        SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
        cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
        export PATH="$SHIM:$PATH"
        # --- cargo offline (the authoritative vendored source map) --------------------------------
        cat > "$CARGO_HOME/config.toml" <<CFG
[net]
offline = true
CFG
        sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
        # --- pub offline: pre-resolve the project + the SDK flutter_tools from PUB_CACHE ----------
        export HOME=/tmp/buildhome; mkdir -p "$HOME"
        git config --global --add safe.directory "*"
        export PUB_CACHE=/online/pub-cache CI=true
        ( cd flutter && dart pub get --offline )
        ( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline )
        # --- the codegen: --llvm-compiler-opts gives ffigen libclang the builtin-header dir so
        #     <stdbool.h> resolves (else bool bindings DEGRADE and the dart compile later fails) ----
        flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
            --dart-output ./flutter/lib/generated_bridge.dart \
            --llvm-path "$LLVM_ROOT" \
            --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
    '
# generated_bridge.freezed.dart is the freezed `part` FRB's internal build_runner produces for
# generated_bridge.dart's @freezed types (EventToUI ...); the windows --no-pub build ships it (build-windows-vm.sh).
for f in src/bridge_generated.rs src/bridge_generated.io.rs flutter/lib/generated_bridge.dart flutter/lib/generated_bridge.freezed.dart; do
    [ -f "$REPO_ROOT/$f" ] || die "FRB did not produce $f (the offline flutter-pub/ffigen step failed — see output above)"
done
log "FRB bridges generated: bridge_generated.rs(.io.rs) + generated_bridge.dart(.freezed.dart)"

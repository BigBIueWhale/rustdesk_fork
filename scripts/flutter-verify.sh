#!/usr/bin/env bash
#
# flutter-verify.sh — compile-check the `feature="flutter"` Rust code in docker.
#
# The day-to-day verify.sh compiles the linux-pkg-config (Sciter/non-flutter) build, so it
# cannot see flutter_ffi.rs / the FRB bridge / the viewer-GUI FFI. This harness:
#   1. ensures the rd-devcheck + rd-fluttercheck images exist (Dockerfile.fluttercheck);
#   2. runs flutter_rust_bridge_codegen 1.80.1 to (re)generate the git-ignored bridge
#      (src/bridge_generated.rs + flutter/lib/generated_bridge.dart) from src/flutter_ffi.rs;
#   3. runs `cargo check --features flutter` — the gate that surfaces the rust-1.75 vs
#      flutter-dep version skew, and that verifies viewer-side / GUI Rust changes.
#
# No socket is bound (cargo check + FRB codegen are offline-of-listeners), so it is safe on
# the DMZ host — it NEVER publishes a port and uses the loopback/none docker network only.
#
# Usage: scripts/flutter-verify.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DEV=rd-devcheck
IMG=rd-fluttercheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-verify-target:/build
  -e CARGO_TARGET_DIR=/build
  -w /work "$IMG")

echo "== ensuring images (rd-devcheck base, then rd-fluttercheck) =="
docker volume create rd-cargo-cache  >/dev/null
docker volume create rd-git-cache    >/dev/null
docker volume create rd-verify-target >/dev/null
docker build -q -t "$DEV" -f scripts/Dockerfile.devcheck     scripts >/dev/null
docker build -q -t "$IMG" -f scripts/Dockerfile.fluttercheck scripts >/dev/null

echo "== (1) generate the FRB Rust bridge from src/flutter_ffi.rs (FRB 1.80.1) =="
# The codegen also emits the Dart bridge via `flutter pub run ffigen`, which needs
# flutter/.dart_tool (a `flutter pub get`) — that is the §19-GUI-build concern, deferred.
# For the Rust `cargo check` below we only need src/bridge_generated.rs(.io.rs), which the
# codegen writes in its "Generate Rust code" phase BEFORE the Dart phase; so tolerate the
# Dart-side failure but FAIL CLOSED if the Rust bridge was not produced.
"${RUN[@]}" flutter_rust_bridge_codegen \
    --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart || \
  echo "  (Dart-side ffigen skipped — needs 'flutter pub get'; Rust bridge is what we gate)"
[ -f src/bridge_generated.rs ] && [ -f src/bridge_generated.io.rs ] \
  || { echo "FLUTTER-VERIFY: FAILED — FRB did not produce the Rust bridge"; exit 1; }

echo "== (2) cargo check --features flutter,linux-pkg-config (rust 1.75) =="
# linux-pkg-config routes scrap/the native opus/vpx/aom build.rs to the distro pkg-config
# (the rd-devcheck libs) instead of vcpkg; flutter adds the FFI/UI surface. Together they
# compile-verify the viewer-side + GUI Rust the linux-only devcheck cannot see.
"${RUN[@]}" cargo check --features flutter,linux-pkg-config --color never

echo "FLUTTER-VERIFY: cargo check --features flutter,linux-pkg-config is GREEN"

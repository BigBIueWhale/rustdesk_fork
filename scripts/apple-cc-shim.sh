#!/usr/bin/env bash
# scripts/apple-cc-shim.sh — a fake C/ObjC compiler for the SDK-FREE apple cross-check.
#
# Used ONLY by scripts/apple-conform-check.sh layer-2b (no online/macos-sdk). The apple
# `cargo check --target *-apple-*` runs each -sys crate's build script, which shells out
# to `cc`/`clang` to compile apple C/ObjC (e.g. objc_exception's exception.m) with apple
# flags (`-arch arm64 -mmacosx-version-min=...`). The host cc cannot target apple without
# the SDK. But `cargo check` never LINKS, so a stub object file is enough to get the build
# script to "succeed" and let the RUST type-check proceed. This shim, set as
# CC_aarch64_apple_darwin / CXX_*, emits a host stub object for apple compiles and passes
# everything else (version probes, etc.) through to the real cc.
#
# It does NOT fake bindgen HEADER resolution — crates that bindgen against real apple SDK
# headers (coreaudio-sys → AudioUnit/AudioUnit.h) still fail; that is the apple-SDK boundary
# apple-conform-check.sh detects and reports (full coherence past it needs online/macos-sdk).
set -euo pipefail

out=""; prev=""; compile=0
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  [ "$a" = "-c" ] && compile=1
  prev="$a"
done

if [ "$compile" = 1 ] && [ -n "$out" ]; then
  # a -c …-o out.<o> compile: emit a host stub object (cargo check won't link it)
  printf '' | cc -c -x c - -o "$out" 2>/dev/null || : > "$out"
  exit 0
fi

# not an object compile (version/feature probe, link step, …): use the real cc
exec cc "$@"

#!/usr/bin/env bash
# scripts/flutter-offline-shim.sh — offline shim for the flutter CLI (R-B10).
#
# The offline builds (build-debian.sh / build-android.sh) run --network=none against
# the SHA-verified ./online cache. The flutter SDK tarball already carries everything
# they need (flutter_tools.snapshot, the bundled dart-sdk, the linux/android engine
# artifacts) — EXCEPT that the `flutter` wrapper drives `pub` in ONLINE mode: a
# `flutter pub get`/`flutter pub run` makes pub fetch/refresh package security
# advisories, which type-errors against the read-only offline pub cache
#   (pub hosted.dart:778  HostedSource._getAdvisories.readAdvisoriesFromCache → _TypeError)
# and aborts the whole command (rc=1). `dart ... --offline` performs the identical
# resolution but skips the advisories step, so it works offline.
#
# flutter_rust_bridge_codegen hardcodes `flutter pub run ffigen` (a flutter project →
# the Flutter toolchain; no CLI flag overrides it in 1.80.1), and `flutter build`
# may run an implicit `flutter pub get`. So shadow `flutter` on PATH with this shim,
# which routes ONLY those two pub subcommands to `dart --offline` and passes
# everything else — crucially `flutter build linux`/`apk` — through to the real
# flutter ($REAL_FLUTTER) unchanged.
set -euo pipefail
if [ "${1:-}" = pub ] && [ "${2:-}" = run ]; then exec dart run "${@:3}"; fi
if [ "${1:-}" = pub ] && [ "${2:-}" = get ]; then exec dart pub get --offline "${@:3}"; fi
exec "${REAL_FLUTTER:?REAL_FLUTTER must point at the real flutter binary}" "$@"

#!/usr/bin/env bash
#
# dart-verify.sh — analyze the Flutter/Dart UI (lib/) in docker.
#
# flutter-verify.sh cargo-checks the feature="flutter" RUST; this gates the DART side, so
# the §19 GUI sweep (removing dead widgets/strings) and the R-S17 known-hosts dialogs are
# verifiable. It runs `flutter pub get` + the full FRB codegen (the Dart bridge too) +
# `flutter analyze lib/`, requiring ZERO ERRORS — the ~238 info/warnings are the upstream
# baseline (style lints), and test/ has pre-existing errors out of scope here. No socket is
# bound by pub-get/codegen/analyze, so this is safe on the DMZ host (never publishes a port).
#
# R-B12 FINDING (documented, not silently swallowed): under the PINNED flutter 3.24.5,
# `flutter pub get` RESOLVES A DIFFERENT pubspec.lock than the committed one — it downgrades
# ~10 packages to the 3.24.5 SDK constraints and adds the flutter_test/leak_tracker dev-deps.
# So the committed flutter/pubspec.lock is NOT consistent with the pinned flutter, i.e. the
# Dart side does NOT build from the committed lock as-is (the R-R1 "build from the committed
# lockfile" invariant is broken on the Dart side). Reconciling it (regenerate the lock under
# flutter 3.24.5, or align the flutter pin to the lock) is an open R-B12/R-R3 item. Until
# then this harness RESTORES the committed pubspec.lock after analyzing, so it never mutates
# the pin behind your back.
set -euo pipefail
cd "$(dirname "$0")/.."

IMG=rd-fluttercheck
RUN=(docker run --rm
  -v "$PWD:/work:rw"
  -v rd-pub-cache:/root/.pub-cache
  -v rd-cargo-cache:/usr/local/cargo/registry
  -v rd-git-cache:/usr/local/cargo/git
  -v rd-verify-target:/build
  -e CARGO_TARGET_DIR=/build
  -w /work "$IMG")

echo "== ensuring images + caches =="
docker volume create rd-pub-cache     >/dev/null
docker volume create rd-cargo-cache   >/dev/null
docker volume create rd-git-cache     >/dev/null
docker volume create rd-verify-target >/dev/null
docker build -q -t rd-devcheck -f scripts/Dockerfile.devcheck     scripts >/dev/null
docker build -q -t "$IMG"      -f scripts/Dockerfile.fluttercheck scripts >/dev/null

echo "== flutter pub get + full FRB codegen + flutter analyze lib/ (zero-errors gate) =="
"${RUN[@]}" bash -c '
  set -e
  cd /work/flutter
  cp pubspec.lock /tmp/pubspec.lock.pin
  trap "cp /tmp/pubspec.lock.pin /work/flutter/pubspec.lock" EXIT  # preserve the committed pin
  flutter pub get >/dev/null
  cd /work
  flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
      --dart-output ./flutter/lib/generated_bridge.dart >/dev/null 2>&1
  cd /work/flutter
  out="$(flutter analyze lib/ 2>&1 || true)"
  errs="$(printf "%s\n" "$out" | grep -c "error •" || true)"
  echo "  lib/ analyze errors: $errs"
  if [ "$errs" != "0" ]; then
    printf "%s\n" "$out" | grep "error •"
    echo "DART-VERIFY: FAILED — $errs error(s) in lib/"
    exit 1
  fi
'
echo "DART-VERIFY: flutter analyze lib/ is GREEN (zero errors; ~238 baseline info/warnings ignored)"

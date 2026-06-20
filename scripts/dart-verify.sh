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
echo "== §19 / R-A6 Dart-layer grep (dead GUI tokens absent) =="
# Extends the R-A6/R-SV10 grep set into the Dart + asset layers (§19's CI hook). Each
# token names a UI surface whose backend §8/§18 removed; a non-comment hit fails the gate.
# Host-side (plain file content — no flutter needed). Grows as the §19 sweep proceeds.
dg_clean() { # token, label
  local tok="$1" label="$2" hits
  # exclude the FRB-GENERATED bridge (git-ignored, regenerated — not authored Dart)
  hits=$(grep -RInE "$tok" flutter/lib flutter/assets 2>/dev/null | grep -v '//' | grep -v 'generated_bridge' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL §19: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    exit 1
  fi
  echo "  ok  $label absent"
}
# R-G3: the insecure/relay security-badge assets + states are deleted — the channel is
# ALWAYS secure+direct (§10 PAKE + R-SV4/R-D4), so a badge that could render "insecure"
# or "relayed" is both dead and a dangerous security MISLABEL. (secure.svg is the one kept.)
dg_clean 'insecure\.svg|secure_relay\.svg|insecure_relay\.svg' 'R-G3 insecure/relay security-badge assets'
# R-G4 / R-SV3 / §18: the startup version-check FFI trigger is gone — the app makes no
# api.rustdesk.com/version call at launch (the updater + version-check are excised).
dg_clean 'bind\.mainGetSoftwareUpdateUrl' 'R-G4/R-SV3 startup version-check FFI trigger'

echo "DART-VERIFY: flutter analyze lib/ is GREEN (zero errors) + §19 Dart-layer greps clean"

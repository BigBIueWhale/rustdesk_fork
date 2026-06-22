#!/usr/bin/env bash
# scripts/apple-conform-check.sh — R-R2 apple (macOS/iOS) SOURCE-conformance gate.
#
# Apple is NOT a build target: macOS's licence permits virtualization only on Apple
# hardware, and a real build needs the Apple-only toolchain (ld64/codesign/CocoaPods/the
# Flutter macos|ipa embedders). But R-R2 makes apple a SOURCE-conformance obligation —
# "every philosophy and hardening here MUST hold on the macOS/iOS code paths, so any future
# Apple build on a real Mac is the hardened fork, never the un-hardened upstream" — enforced
# with "a cargo check --target {x86_64,aarch64}-apple-darwin + aarch64-apple-ios pass running
# the R-A6 greps on the Apple cfg (no artifact produced)." This script IS that gate, and it
# is the ONE supported way to run it (no hand-run docker commands).
#
# It runs in layers so the inner loop works on a plain Linux box AND the full coherence gate
# is available wherever the Apple SDK is:
#   (1) retain-and-check: macos.rs/.mm + the iOS plist MUST be PRESENT (R-R2 audits, never
#       deletes the hardened apple source);
#   (2) R-A6 apple-cfg forbidden-token greps (completed apple excisions absent; pending = TODO);
#   (3) rustfmt parse-check of the Rust apple sources (SDK-free syntax gate);
#   (4) cross-compile coherence — cargo check --target *-apple-* on Rust 1.81:
#         (4a) online/macos-sdk present (operator-supplied, the §12.2-Win11-ISO analog):
#              a real apple-sysroot cross-check — the full type-check, a HARD gate; or
#         (4b) no SDK: a best-effort cross-check via scripts/apple-cc-shim.sh that compiles
#              the apple dependency graph + the Rust-only crates, then stops at the first
#              Apple-SDK-gated framework crate (coreaudio-sys bindgens AudioUnit.h). Reaching
#              that boundary with NO rust error below it confirms the dep-graph + rust crates
#              are apple-coherent; the macos.rs/.mm type-check PAST it needs (4a) — never
#              silently skipped. A rust error is FATAL.
#
# Exit non-zero if any hard gate fails. Usage: scripts/apple-conform-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

BASE_IMG=rd-devcheck
IMG=rd-apple-check
SDK_DIR="${MACOS_SDK_DIR:-$REPO/online/macos-sdk}"
APPLE_TARGET="${APPLE_TARGET:-aarch64-apple-darwin}"   # x86_64-apple-darwin / aarch64-apple-ios also valid

die(){ echo "FATAL: $*" >&2; exit 1; }
note(){ echo "  $*"; }
rc=0

# ---- preflight (defensive: fail loudly if the world isn't as expected) ----
command -v docker >/dev/null 2>&1 || die "docker not found — this gate runs entirely in a container"
[ -f "$REPO/scripts/apple-cc-shim.sh" ] || die "scripts/apple-cc-shim.sh missing (the SDK-free compile shim)"
[ -f "$REPO/scripts/Dockerfile.devcheck" ] || die "scripts/Dockerfile.devcheck missing"
[ -f "$REPO/scripts/Dockerfile.apple-check" ] || die "scripts/Dockerfile.apple-check missing"

echo "== building the apple-check image (devcheck base + Rust 1.81 + apple std) =="
docker build -q -t "$BASE_IMG" -f scripts/Dockerfile.devcheck scripts >/dev/null \
  || die "could not build $BASE_IMG from scripts/Dockerfile.devcheck"
docker build -q -t "$IMG" -f scripts/Dockerfile.apple-check scripts >/dev/null \
  || die "could not build $IMG from scripts/Dockerfile.apple-check"

# ---- the apple source set (R-R2 retain-and-check) ----
APPLE_RS=(
  src/platform/macos.rs
  src/privacy_mode/macos.rs
  src/whiteboard/macos.rs
  libs/hbb_common/src/platform/macos.rs
  libs/enigo/src/macos/macos_impl.rs
)
APPLE_OTHER=(
  src/platform/macos.mm
  flutter/macos/Runner/Release.entitlements
  flutter/ios/Runner/Info.plist
)
# grep targets = the Rust apple sources + the ObjC twin (Elevate lives in macos.mm)
GREP_SRC=("${APPLE_RS[@]/#/$REPO/}" "$REPO/src/platform/macos.mm")

echo "== (1) retain-and-check: the hardened apple sources MUST be PRESENT (R-R2) =="
for f in "${APPLE_RS[@]}" "${APPLE_OTHER[@]}"; do
  [ -e "$REPO/$f" ] || { echo "  MISSING $f — R-R2 is retain-and-check; deleting the apple source discards hardened code a future Mac build must inherit"; rc=1; }
done
[ "$rc" = 0 ] && note "ok  all ${#APPLE_RS[@]} Rust + ${#APPLE_OTHER[@]} other apple sources present"

echo "== (2) R-A6 apple-cfg forbidden-token greps =="
apple_absent(){ # <regex> <label>  — a COMPLETED apple excision: MUST be absent (fatal if present)
  local hits; hits=$(grep -rnE "$1" "${GREP_SRC[@]}" 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' || true)
  if [ -n "$hits" ]; then echo "  FAIL $2 — apple-cfg token present:"; echo "$hits" | sed 's/^/      /'; rc=1
  else note "ok  $2 — absent on the apple source"; fi
}
apple_todo(){ # <regex> <label>  — a PENDING apple excision: report, don't fail (verify.sh pattern)
  local hits; hits=$(grep -rnE "$1" "${GREP_SRC[@]}" 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*//' || true)
  if [ -n "$hits" ]; then echo "  TODO $2 — still present (apple-conform pending):"; echo "$hits" | sed 's/^/      /'
  else note "ok  $2 — absent on the apple source"; fi
}
# completed:
apple_absent 'fn update_me\b|update_from_dmg|extract_update_dmg|fn update_to\b' 'R-X1 macOS DMG self-updater'
apple_absent 'fn elevate\b|bool Elevate\b|AuthorizationExecuteWithPrivileges' 'R-X9/X11 in-process root-exec (osascript elevate / Authorization Elevate)'
# pending (flip to apple_absent as each lands): R-X6 macOS _url-IPC sender-auth (start_ipc_url_server)
# is a POSITIVE assertion handled separately; nothing left to grep-as-absent here.

echo "== (3) rustfmt parse-check of the Rust apple sources (SDK-free syntax gate) =="
docker run --rm -v "$REPO:/work:ro" -w /work "$IMG" bash -c '
  rc=0
  for f in '"${APPLE_RS[*]}"'; do
    if ! rustfmt --emit stdout --edition 2021 "$f" >/dev/null 2>/tmp/rfe; then
      echo "  PARSE-FAIL $f"; sed "s/^/      /" /tmp/rfe; rc=1
    fi
  done
  [ $rc = 0 ] && echo "  ok  all apple .rs parse"
  exit $rc
' || rc=1

echo "== (4) cross-compile coherence: cargo check --target $APPLE_TARGET (Rust 1.81) =="
COMMON_CHECK=( docker run --rm
  -v "$REPO:/work:rw"
  -v rd-cargo-cache:/usr/local/cargo/registry -v rd-git-cache:/usr/local/cargo/git
  -v rd-apple-target:/build -e CARGO_TARGET_DIR=/build
  -e PKG_CONFIG_ALLOW_CROSS=1 -w /work )

if [ -d "$SDK_DIR" ]; then
  echo "  online/macos-sdk present ($SDK_DIR) → real apple-sysroot cross-check (HARD gate)"
  set +e
  "${COMMON_CHECK[@]}" -v "$SDK_DIR:/macos-sdk:ro" \
    -e SDKROOT=/macos-sdk \
    -e BINDGEN_EXTRA_CLANG_ARGS="-isysroot /macos-sdk" \
    -e "CFLAGS_${APPLE_TARGET//-/_}=-isysroot /macos-sdk" \
    "$IMG" cargo +1.81.0 check --target "$APPLE_TARGET" --features linux-pkg-config \
    > /tmp/apple-xcheck.log 2>&1
  xrc=$?; set -e
  if [ $xrc = 0 ]; then note "ok  apple cross-check (real SDK) compiled clean — full coherence verified"
  else echo "  FAIL apple cross-check (real SDK):"; tail -25 /tmp/apple-xcheck.log | sed 's/^/      /'; rc=1; fi
else
  note "no online/macos-sdk → SDK-FREE best-effort cross-check (scripts/apple-cc-shim.sh)."
  note "  it compiles the apple dep-graph + Rust-only crates, then stops at the apple-SDK"
  note "  framework boundary; the macos.rs/.mm type-check past it needs a Mac's SDK (provide"
  note "  it at online/macos-sdk — the §12.2-Win11-ISO analog — to turn this into a HARD gate)."
  set +e
  "${COMMON_CHECK[@]}" -v "$REPO/scripts/apple-cc-shim.sh:/applecc:ro" \
    -e "CC_${APPLE_TARGET//-/_}=/applecc" -e "CXX_${APPLE_TARGET//-/_}=/applecc" \
    "$IMG" cargo +1.81.0 check --target "$APPLE_TARGET" --features linux-pkg-config \
    > /tmp/apple-xcheck.log 2>&1
  xrc=$?; set -e
  if [ $xrc = 0 ]; then
    note "ok  apple cross-check compiled CLEAN even without the SDK (the dep-graph needs no apple framework headers)"
  elif grep -qE 'error\[E[0-9]' /tmp/apple-xcheck.log; then
    echo "  FAIL apple cross-check has a RUST error — a real apple-cfg coherence break:"
    grep -nE 'error\[E[0-9]|^error: ' /tmp/apple-xcheck.log | head -25 | sed 's/^/      /'; rc=1
  elif grep -qE "coreaudio-sys|AudioUnit|file not found|framework=" /tmp/apple-xcheck.log; then
    note "ok  reached the apple-SDK framework boundary (coreaudio-sys/AudioUnit.h) with NO rust"
    note "    error below it → the apple dependency graph + Rust-only crates are coherent."
    note "    (the macos.rs/.mm type-check past this boundary is the part that needs online/macos-sdk)"
  else
    echo "  FAIL apple cross-check failed for an unrecognized reason:"; tail -25 /tmp/apple-xcheck.log | sed 's/^/      /'; rc=1
  fi
fi

echo
if [ "$rc" = 0 ]; then echo "== apple-conform-check PASS =="; else echo "== apple-conform-check FAIL =="; fi
exit $rc

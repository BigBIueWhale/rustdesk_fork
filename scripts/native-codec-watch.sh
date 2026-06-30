#!/usr/bin/env bash
#
# Offline source gate for the native C/C++ codec advisory watch.
#
# Cargo/RustSec and Dart/OSV do not see vcpkg-built libraries. This script does
# not fetch advisory data or assert "no current CVEs"; it asserts that the exact
# native package set and source pins in this tree have a maintained manual watch
# ledger, and that a manifest or pin change fails until the ledger is updated.
set -euo pipefail

cd "$(dirname "$0")/.."

LEDGER=docs/NATIVE-CODEC-WATCH.md
EXPECTED_REQUIREMENTS_SHA=db8f32dd05c03682cf383424bc0a65118403362b3a01570b394d8163b17bb630
expected_packages=(aom cpu-features libjpeg-turbo libvpx libyuv oboe opus)
rc=0

fail() {
  echo "native-codec-watch: FAIL: $*" >&2
  rc=1
}

require_file() {
  if [ ! -f "$1" ]; then
    fail "missing required file $1"
  fi
}

require_literal() {
  local needle=$1
  local file=$2
  if ! grep -qF "$needle" "$file"; then
    fail "$file missing required literal: $needle"
  fi
}

json_string_value() {
  local key=$1
  local file=$2
  sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\\1/p" "$file" | head -n 1
}

first_sha512() {
  sed -nE 's/.*SHA512[[:space:]]+([0-9a-f]{128}).*/\1/p' "$1" | head -n 1
}

require_file "$LEDGER"
require_file vcpkg.json
require_file scripts/pins.env
require_file res/vcpkg/aom/vcpkg.json
require_file res/vcpkg/aom/portfile.cmake
require_file res/vcpkg/libvpx/vcpkg.json
require_file res/vcpkg/libvpx/portfile.cmake
require_file res/vcpkg/libyuv/vcpkg.json
require_file res/vcpkg/libyuv/portfile.cmake
require_file res/vcpkg/opus/vcpkg.json
require_file res/vcpkg/opus/portfile.cmake

# shellcheck source=/dev/null
. scripts/pins.env

: "${VCPKG_BASELINE:?native-codec-watch: VCPKG_BASELINE unset in scripts/pins.env}"
: "${AOM_COMMIT:?native-codec-watch: AOM_COMMIT unset in scripts/pins.env}"
: "${LIBYUV_COMMIT:?native-codec-watch: LIBYUV_COMMIT unset in scripts/pins.env}"
: "${SHA512_AOM_3_12_1:?native-codec-watch: SHA512_AOM_3_12_1 unset in scripts/pins.env}"
: "${SHA512_LIBYUV:?native-codec-watch: SHA512_LIBYUV unset in scripts/pins.env}"

actual_baseline=$(json_string_value baseline vcpkg.json)
if [ "$actual_baseline" != "$VCPKG_BASELINE" ]; then
  fail "vcpkg.json baseline '$actual_baseline' does not match scripts/pins.env VCPKG_BASELINE '$VCPKG_BASELINE'"
fi

tmp_expected=$(mktemp)
tmp_actual=$(mktemp)
trap 'rm -f "$tmp_expected" "$tmp_actual"' EXIT

printf '%s\n' "${expected_packages[@]}" | sort -u >"$tmp_expected"
grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' vcpkg.json \
  | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
  | sort -u >"$tmp_actual"

missing=$(comm -23 "$tmp_expected" "$tmp_actual" || true)
extra=$(comm -13 "$tmp_expected" "$tmp_actual" || true)
if [ -n "$missing" ]; then
  fail "vcpkg.json is missing expected native packages: $(echo "$missing" | tr '\n' ' ')"
fi
if [ -n "$extra" ]; then
  fail "vcpkg.json contains native packages not covered by $LEDGER: $(echo "$extra" | tr '\n' ' ')"
fi

if grep -qE '"(ffmpeg|mfx-dispatch|ffnvcodec|amd-amf)"' vcpkg.json; then
  fail "hardware-codec native dependency reappeared in vcpkg.json"
fi

require_literal "Native-Codec-Watch-Version: 1" "$LEDGER"
require_literal "Requirements hash: $EXPECTED_REQUIREMENTS_SHA" "$LEDGER"
require_literal "Cargo/RustSec and Dart/OSV gates do not cover these vcpkg C/C++" "$LEDGER"
require_literal "This gate is not the decoder sandbox." "$LEDGER"
require_literal "VCPKG_BASELINE: $VCPKG_BASELINE" "$LEDGER"
require_literal "Forbidden native decoder expansion remains: no \`ffmpeg\`, no \`mfx-dispatch\`, no" "$LEDGER"

for pkg in "${expected_packages[@]}"; do
  require_literal "Package: $pkg" "$LEDGER"
done

if grep -qE '\b(PENDING|TODO|TBD)\b' "$LEDGER"; then
  fail "$LEDGER contains a pending/TODO/TBD marker"
fi

aom_version=$(json_string_value version-semver res/vcpkg/aom/vcpkg.json)
libvpx_version=$(json_string_value version res/vcpkg/libvpx/vcpkg.json)
libyuv_version=$(json_string_value version res/vcpkg/libyuv/vcpkg.json)
opus_version=$(json_string_value version res/vcpkg/opus/vcpkg.json)
libvpx_sha=$(first_sha512 res/vcpkg/libvpx/portfile.cmake)
opus_sha=$(first_sha512 res/vcpkg/opus/portfile.cmake)

require_literal "aom version: $aom_version" "$LEDGER"
require_literal "AOM_COMMIT: $AOM_COMMIT" "$LEDGER"
require_literal "aom SHA512: $SHA512_AOM_3_12_1" "$LEDGER"
require_literal "libvpx version: $libvpx_version" "$LEDGER"
require_literal "libvpx SHA512: $libvpx_sha" "$LEDGER"
require_literal "libyuv version: $libyuv_version" "$LEDGER"
require_literal "LIBYUV_COMMIT: $LIBYUV_COMMIT" "$LEDGER"
require_literal "libyuv SHA512: $SHA512_LIBYUV" "$LEDGER"
require_literal "opus version: $opus_version" "$LEDGER"
require_literal "opus SHA512: $opus_sha" "$LEDGER"

grep -qF "REF $AOM_COMMIT" res/vcpkg/aom/portfile.cmake \
  || fail "AOM_COMMIT is not present in res/vcpkg/aom/portfile.cmake"
grep -qF "SHA512 $SHA512_AOM_3_12_1" res/vcpkg/aom/portfile.cmake \
  || fail "SHA512_AOM_3_12_1 is not present in res/vcpkg/aom/portfile.cmake"
grep -qF "REF $LIBYUV_COMMIT" res/vcpkg/libyuv/portfile.cmake \
  || fail "LIBYUV_COMMIT is not present in res/vcpkg/libyuv/portfile.cmake"
grep -qF "SHA512 $SHA512_LIBYUV" res/vcpkg/libyuv/portfile.cmake \
  || fail "SHA512_LIBYUV is not present in res/vcpkg/libyuv/portfile.cmake"

if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

echo "native-codec-watch: ok (vcpkg native set and manual advisory ledger are in sync; decoder sandbox still separate)"

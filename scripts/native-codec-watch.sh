#!/usr/bin/env bash
#
# Offline source gate for the native C/C++ codec advisory watch.
#
# Cargo/RustSec and Dart/OSV do not see vcpkg-built libraries. This script does
# not fetch advisory data or assert "no current CVEs"; it asserts that the exact
# native package set and source pins in this tree have a maintained manual watch
# ledger, and that a manifest or pin change fails until the ledger is updated.
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "${NATIVE_CODEC_WATCH_ROOT:-$(dirname "$0")/..}"

LEDGER=docs/NATIVE-CODEC-WATCH.md
expected_packages=(cpu-features libjpeg-turbo libvpx libyuv oboe opus)
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

require_unique_line() {
  local expected=$1
  local file=$2
  local count
  count=$(awk -v expected="$expected" '$0 == expected { count++ } END { print count + 0 }' "$file")
  if [ "$count" -ne 1 ]; then
    fail "$file must contain exactly one line: $expected"
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

json_number_value() {
  local key=$1
  local file=$2
  sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*([0-9]+).*/\\1/p" "$file" | head -n 1
}

validate_libvpx_port_structure() {
  if ! python3 - res/vcpkg/libvpx/portfile.cmake res/vcpkg/libvpx/vcpkg.json <<'PY'
import json
import re
import sys

portfile, metadata = sys.argv[1:]
with open(metadata, encoding="utf-8") as handle:
    package = json.load(handle)
if type(package.get("port-version")) is not int or package["port-version"] != 1:
    raise SystemExit("libvpx port-version must be the integer 1")
with open(portfile, encoding="utf-8") as handle:
    lines = handle.read().splitlines()
starts = [
    index
    for index, line in enumerate(lines)
    if re.fullmatch(r"\s*vcpkg_extract_source_archive\s*\(\s*SOURCE_PATH\s*", line)
]
if len(starts) != 1:
    raise SystemExit("expected exactly one vcpkg_extract_source_archive(SOURCE_PATH block")
start = starts[0]
end = None
depth = 0
for index in range(start, len(lines)):
    line = re.sub(r"#.*$", "", lines[index])
    depth += line.count("(") - line.count(")")
    if depth == 0:
        end = index
        break
    if depth < 0:
        raise SystemExit("unbalanced extraction block")
if end is None:
    raise SystemExit("unterminated extraction block")
normalized = [line.strip() for line in lines[start : end + 1] if line.strip()]
dollar = chr(36)
expected = [
    "vcpkg_extract_source_archive(SOURCE_PATH",
    'ARCHIVE "' + dollar + '{_libvpx_archive}"',
    "PATCHES",
    '"' + dollar + '{_libvpx_security_patch}"',
    "0003-add-uwp-v142-and-v143-support.patch",
    "0004-remove-library-suffixes.patch",
    ")",
]
if normalized != expected:
    raise SystemExit(
        "libvpx extraction block must apply the exact security patch variable first: "
        + repr(normalized)
    )
PY
  then
    fail "libvpx port extraction/port-version structure is invalid"
  fi
}

run_self_test() {
  local tmp base case_dir
  tmp=$(mktemp -d)
  base="$tmp/base"
  mkdir -p "$base"
  (
    cd "${NATIVE_CODEC_WATCH_ROOT:-$(dirname "$SCRIPT_PATH")/..}"
    cp --parents \
      requirements.html vcpkg.json HARDENING_STATUS.md \
      docs/NATIVE-CODEC-WATCH.md \
      scripts/native-codec-watch.sh scripts/pins.env scripts/online-fetch.sh \
      scripts/build-windows-vm.sh scripts/build-windows.ps1 \
      res/vcpkg/libvpx/* res/vcpkg/libyuv/vcpkg.json res/vcpkg/libyuv/portfile.cmake \
      res/vcpkg/opus/vcpkg.json res/vcpkg/opus/portfile.cmake \
      "$base"
  )
  NATIVE_CODEC_WATCH_ROOT="$base" bash "$base/scripts/native-codec-watch.sh" >/dev/null

  expect_rejected() {
    local name=$1 mutation=$2
    case_dir="$tmp/$name"
    cp -a "$base" "$case_dir"
    (cd "$case_dir" && eval "$mutation")
    if NATIVE_CODEC_WATCH_ROOT="$case_dir" bash "$case_dir/scripts/native-codec-watch.sh" >/dev/null 2>&1; then
      echo "native-codec-watch self-test: mutation was accepted: $name" >&2
      rm -rf "$tmp"
      exit 1
    fi
  }

  expect_rejected open-advisory "printf '\\nStatus: OPEN ADVISORY\\n' >> docs/NATIVE-CODEC-WATCH.md"
  expect_rejected codec-ledger-requirements-hash "sed -i 's/^Requirements hash:.*/Requirements hash: 0000000000000000000000000000000000000000000000000000000000000000/' docs/NATIVE-CODEC-WATCH.md"
  expect_rejected hardening-ledger-requirements-hash "sed -i 's/^[0-9a-f]\\{64\\}  requirements[.]html$/0000000000000000000000000000000000000000000000000000000000000000  requirements.html/' HARDENING_STATUS.md"
  expect_rejected patch-byte "printf '\\n' >> res/vcpkg/libvpx/0005-cve-2026-1861.patch"
  expect_rejected windows-tool-manifest "sed -i '1s/dda8/dda9/' res/vcpkg/libvpx/windows-tools.sha512"
  expect_rejected powershell-acquisition "sed -i 's#PowerShell/releases/download/v7.2.24#PowerShell/releases/download/latest#' scripts/online-fetch.sh"
  expect_rejected mingw-pkgconf-acquisition "sed -i 's#mirror.msys2.org/mingw/mingw64#mirror.msys2.org/mingw/ucrt64#' scripts/online-fetch.sh"
  expect_rejected guest-distfile-passthrough "sed -i '/VCPKG_KEEP_ENV_VARS/d' scripts/build-windows.ps1"
  expect_rejected guest-origin-fallback "sed -i '/X_VCPKG_ASSET_SOURCES/d' scripts/build-windows.ps1"
  expect_rejected guest-cache-name "sed -i \"s/-ceq '7zr.exe'/-ceq '7za.exe'/\" scripts/build-windows.ps1"
  expect_rejected guest-mingw-cache-name "sed -i 's/\$cacheName = \"msys2-\$toolName\"/\$cacheName = \$toolName/' scripts/build-windows.ps1"
  expect_rejected network-fallback "printf '\\nvcpkg_from_github()\\n' >> res/vcpkg/libvpx/portfile.cmake"
  expect_rejected patch-block-remove "sed -i '29d' res/vcpkg/libvpx/portfile.cmake"
  expect_rejected patch-block-substitute "sed -i '29s/_libvpx_security_patch/_libvpx_archive/' res/vcpkg/libvpx/portfile.cmake"
  expect_rejected patch-block-reorder "sed -i '29s/.*/        0003-add-uwp-v142-and-v143-support.patch/;30s/.*/        \"\${_libvpx_security_patch}\"/' res/vcpkg/libvpx/portfile.cmake"
  expect_rejected port-version "sed -i 's/\"port-version\": 1/\"port-version\": 2/' res/vcpkg/libvpx/vcpkg.json"
  expect_rejected linux-cache-key "sed -i 's/\\.rustdesk-vcpkg-native-output-key-v1/.rustdesk-vcpkg-native-output-key-broken/g' scripts/online-fetch.sh"
  expect_rejected windows-rebuild "sed -i '/vcpkg.exe.*remove --recurse/d' scripts/build-windows.ps1"
  rm -rf "$tmp"
  echo "native-codec-watch: self-test ok (advisory, integrity, offline acquisition, cache naming, and Windows-rebuild mutations rejected)"
}

if [ "${1:-}" = "--self-test" ]; then
  run_self_test
  exit 0
fi

require_file "$LEDGER"
require_file requirements.html
require_file vcpkg.json
require_file scripts/pins.env
require_file res/vcpkg/libvpx/vcpkg.json
require_file res/vcpkg/libvpx/portfile.cmake
require_file res/vcpkg/libvpx/0005-cve-2026-1861.patch
require_file res/vcpkg/libvpx/windows-tools.sha512
require_file res/vcpkg/libyuv/vcpkg.json
require_file res/vcpkg/libyuv/portfile.cmake
require_file res/vcpkg/opus/vcpkg.json
require_file res/vcpkg/opus/portfile.cmake
command -v python3 >/dev/null 2>&1 || {
  fail "python3 is required for the structural libvpx port gate"
}

# shellcheck source=/dev/null
. scripts/pins.env

: "${VCPKG_BASELINE:?native-codec-watch: VCPKG_BASELINE unset in scripts/pins.env}"
: "${LIBVPX_SOURCE_REF:?native-codec-watch: LIBVPX_SOURCE_REF unset in scripts/pins.env}"
: "${SHA512_LIBVPX_SOURCE:?native-codec-watch: SHA512_LIBVPX_SOURCE unset in scripts/pins.env}"
: "${LIBVPX_FIX_COMMIT:?native-codec-watch: LIBVPX_FIX_COMMIT unset in scripts/pins.env}"
: "${SHA512_LIBVPX_PATCH:?native-codec-watch: SHA512_LIBVPX_PATCH unset in scripts/pins.env}"
: "${SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST:?native-codec-watch: SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST unset in scripts/pins.env}"
: "${LIBYUV_COMMIT:?native-codec-watch: LIBYUV_COMMIT unset in scripts/pins.env}"
: "${SHA512_LIBYUV:?native-codec-watch: SHA512_LIBYUV unset in scripts/pins.env}"

actual_baseline=$(json_string_value baseline vcpkg.json)
if [ "$actual_baseline" != "$VCPKG_BASELINE" ]; then
  fail "vcpkg.json baseline '$actual_baseline' does not match scripts/pins.env VCPKG_BASELINE '$VCPKG_BASELINE'"
fi

requirements_sha=$(sha256sum requirements.html | awk '{print $1}')

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
require_unique_line "Requirements hash: $requirements_sha" "$LEDGER"
require_unique_line "$requirements_sha  requirements.html" HARDENING_STATUS.md
require_literal "Cargo/RustSec and Dart/OSV gates do not cover these vcpkg C/C++" "$LEDGER"
require_literal "This gate is not the decoder sandbox." "$LEDGER"
require_literal "VCPKG_BASELINE: $VCPKG_BASELINE" "$LEDGER"
require_literal "Forbidden native decoder expansion remains: no \`ffmpeg\`, no \`mfx-dispatch\`, no" "$LEDGER"
require_literal "Retired library: aom" "$LEDGER"
require_literal "AV1/libaom dependency removal" "$LEDGER"

for pkg in "${expected_packages[@]}"; do
  require_literal "Package: $pkg" "$LEDGER"
done

if grep -qE '\b(PENDING|TODO|TBD|OPEN ADVISORY)\b' "$LEDGER"; then
  fail "$LEDGER contains a pending/TODO/TBD/OPEN ADVISORY marker"
fi

if [ -e res/vcpkg/aom ]; then
  fail "retired aom overlay path res/vcpkg/aom reappeared"
fi

aom_scaffold_files=(
  Dockerfile
  README.md
  build.py
  vcpkg.json
  libs/scrap/build.rs
  scripts/Dockerfile.devcheck
  scripts/Dockerfile.win-helper
  scripts/build-debian.sh
  scripts/build-android.sh
  scripts/build-windows.ps1
  scripts/win-guest-setup.ps1
  scripts/online-fetch.sh
  .github/workflows/flutter-build.yml.disabled
)
existing_aom_scaffold_files=()
for file in "${aom_scaffold_files[@]}"; do
  if [ -f "$file" ]; then
    existing_aom_scaffold_files+=("$file")
  fi
done
if ((${#existing_aom_scaffold_files[@]})); then
  aom_scaffold_hits=$(grep -HInE '(^|[^[:alnum:]_])(aom|libaom|AOM_)([^[:alnum:]_]|$)' "${existing_aom_scaffold_files[@]}" 2>/dev/null || true)
  if [ -n "$aom_scaffold_hits" ]; then
    echo "$aom_scaffold_hits" | sed 's/^/      /'
    fail "retired aom appears in tracked native build scaffolds"
  fi
fi

libvpx_version=$(json_string_value version res/vcpkg/libvpx/vcpkg.json)
libvpx_port_version=$(json_number_value port-version res/vcpkg/libvpx/vcpkg.json)
libyuv_version=$(json_string_value version res/vcpkg/libyuv/vcpkg.json)
opus_version=$(json_string_value version res/vcpkg/opus/vcpkg.json)
libvpx_sha=$(first_sha512 res/vcpkg/libvpx/portfile.cmake)
libvpx_patch_sha=$(sha512sum res/vcpkg/libvpx/0005-cve-2026-1861.patch | awk '{print $1}')
opus_sha=$(first_sha512 res/vcpkg/opus/portfile.cmake)
validate_libvpx_port_structure

require_literal "libvpx version: $libvpx_version" "$LEDGER"
require_literal "libvpx port-version: $libvpx_port_version" "$LEDGER"
[ "$libvpx_port_version" = 1 ] || fail "libvpx port-version must remain 1"
require_literal "libvpx SHA512: $libvpx_sha" "$LEDGER"
require_literal "LIBVPX_SOURCE_REF: $LIBVPX_SOURCE_REF" "$LEDGER"
require_literal "LIBVPX_FIX_COMMIT: $LIBVPX_FIX_COMMIT" "$LEDGER"
require_literal "libvpx patch SHA512: $SHA512_LIBVPX_PATCH" "$LEDGER"
require_literal "CVE-2026-2447" "$LEDGER"
require_literal "VP9 encoder" "$LEDGER"
require_literal "CVE-2026-1861" HARDENING_STATUS.md
require_literal "CVE-2026-2447" HARDENING_STATUS.md
require_literal "libyuv version: $libyuv_version" "$LEDGER"
require_literal "LIBYUV_COMMIT: $LIBYUV_COMMIT" "$LEDGER"
require_literal "libyuv SHA512: $SHA512_LIBYUV" "$LEDGER"
require_literal "opus version: $opus_version" "$LEDGER"
require_literal "opus SHA512: $opus_sha" "$LEDGER"

grep -qF "REF $LIBYUV_COMMIT" res/vcpkg/libyuv/portfile.cmake \
  || fail "LIBYUV_COMMIT is not present in res/vcpkg/libyuv/portfile.cmake"
grep -qF "SHA512 $SHA512_LIBYUV" res/vcpkg/libyuv/portfile.cmake \
  || fail "SHA512_LIBYUV is not present in res/vcpkg/libyuv/portfile.cmake"

[ "$libvpx_patch_sha" = "$SHA512_LIBVPX_PATCH" ] \
  || fail "libvpx security patch bytes do not match SHA512_LIBVPX_PATCH"
[ "$(sha256sum res/vcpkg/libvpx/windows-tools.sha512 | awk '{print $1}')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST" ] \
  || fail "libvpx Windows acquisition manifest does not match its pin"
[ "$(wc -l < res/vcpkg/libvpx/windows-tools.sha512)" -eq 32 ] \
  || fail "libvpx Windows acquisition manifest must contain 25 MSYS2 runtime archives, MinGW pkgconf, and six pinned build tools"
if [ "$(awk '{print $2}' res/vcpkg/libvpx/windows-tools.sha512 | sort -u | wc -l)" -ne 32 ]; then
  fail "libvpx Windows acquisition manifest contains duplicate archive names"
fi
if grep -qEv '^[0-9a-f]{128}  (msys2-[A-Za-z0-9._~+-]+[.]pkg[.]tar[.]zst|mingw-w64-x86_64-pkgconf-1~2[.]4[.]3-1-any[.]pkg[.]tar[.]zst|nasm-2[.]16[.]03-win64[.]zip|cmake-3[.]30[.]1-windows-i386[.]zip|ninja-win-1[.]12[.]1[.]zip|7z2409[.]7z[.]exe|7zr[.]exe|PowerShell-7[.]2[.]24-win-x64[.]zip)$' res/vcpkg/libvpx/windows-tools.sha512; then
  fail "libvpx Windows acquisition manifest contains malformed or unexpected entries"
fi
require_literal '22869ceb70ea0e6597fe06abe205b5d5dd66b41fe54dda73d338c488ba6ef13a39158f25b357616bf578752bb112869ef26ad897eb29352e85cf1ecc61a7c07a  nasm-2.16.03-win64.zip' res/vcpkg/libvpx/windows-tools.sha512
require_literal '0b74bd4222064cfb6e42838987704eb21d57ad5f7bbd87714ab570f1d107fa19bd2f14316475338518292bc377bf38b581a07c73267a775cd385bbd1800879b4  cmake-3.30.1-windows-i386.zip' res/vcpkg/libvpx/windows-tools.sha512
require_literal 'd6715c6458d798bcb809f410c0364dabd937b5b7a3ddb4cd5aba42f9fca45139b2a8a3e7fd9fbd88fd75d298ed99123220b33c7bdc8966a9d5f2a1c9c230955f  ninja-win-1.12.1.zip' res/vcpkg/libvpx/windows-tools.sha512
require_literal '44d8504a693ad4d6b79631b653fc19b572de6bbe38713b53c45d9c9d5d3710aa8df93ee867a2a24419ebe883b8255fd18f30f8cf374b2242145fd6acb2189659  7zr.exe' res/vcpkg/libvpx/windows-tools.sha512
require_literal 'a08b72958f5a552240d3f68c581d8c8cb580468a71f5e55ca54a1dd0c0fcd81da9df11036653e2300fc4a5778a77c0147832ca06f7837f03417e9795e577a76f  PowerShell-7.2.24-win-x64.zip' res/vcpkg/libvpx/windows-tools.sha512
require_literal 'bd7986cdf104a6e21abc27f270716cf7f93152fdb92733b23dfa0e44465b3e739e9c90a4934419198f856887f1cfe20ba1ef52478b84ea9e795f44e699475e11  mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst' res/vcpkg/libvpx/windows-tools.sha512
require_literal "From $LIBVPX_FIX_COMMIT " res/vcpkg/libvpx/0005-cve-2026-1861.patch
require_literal "set(_libvpx_source_ref \"$LIBVPX_SOURCE_REF\")" res/vcpkg/libvpx/portfile.cmake
require_literal "set(_libvpx_fix_commit \"$LIBVPX_FIX_COMMIT\")" res/vcpkg/libvpx/portfile.cmake
require_literal "SHA512 $SHA512_LIBVPX_SOURCE" res/vcpkg/libvpx/portfile.cmake
require_literal "SHA512 $SHA512_LIBVPX_PATCH" res/vcpkg/libvpx/portfile.cmake
require_literal 'RUSTDESK_VCPKG_DISTFILES_DIR is required' res/vcpkg/libvpx/portfile.cmake
require_literal 'file://' res/vcpkg/libvpx/portfile.cmake
if grep -qE 'vcpkg_from_(github|git|gitlab)|https?://' res/vcpkg/libvpx/portfile.cmake; then
  fail "libvpx port contains a network source fallback"
fi

require_literal 'libvpx_native_key()' scripts/online-fetch.sh
require_literal 'vcpkg_native_output_key()' scripts/online-fetch.sh
require_literal 'vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz' scripts/online-fetch.sh
require_literal 'vcpkg-distfiles/windows-tools/$tool_name' scripts/online-fetch.sh
require_literal 'PowerShell-7.2.24-win-x64.zip)' scripts/online-fetch.sh
require_literal 'https://github.com/PowerShell/PowerShell/releases/download/v7.2.24/PowerShell-7.2.24-win-x64.zip' scripts/online-fetch.sh
require_literal 'https://mirror.msys2.org/mingw/mingw64/$tool_name' scripts/online-fetch.sh
require_literal '.rustdesk-libvpx-native-key' scripts/online-fetch.sh
require_literal '.rustdesk-vcpkg-native-output-key-v1' scripts/online-fetch.sh
require_literal 'vcpkg_native_output_tool check-complete' scripts/online-fetch.sh
require_literal 'source=$staging/output,target=/outputs/native' scripts/online-fetch.sh
require_literal 'source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled' scripts/online-fetch.sh
require_literal 'RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles' scripts/online-fetch.sh
require_literal 'VCPKG_BINARY_SOURCES=clear' scripts/online-fetch.sh

require_literal 'libvpx_native_key_for_tree()' scripts/build-windows-vm.sh
require_literal '/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz=' scripts/build-windows-vm.sh
require_literal '/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch=' scripts/build-windows-vm.sh
require_literal '/vcpkg-distfiles/windows-tools=/online/vcpkg-distfiles/windows-tools' scripts/build-windows-vm.sh
require_literal "\$LIBVPX_FIX_COMMIT = '$LIBVPX_FIX_COMMIT'" scripts/build-windows.ps1
require_literal "\$LIBVPX_PATCH_SHA512 = '$SHA512_LIBVPX_PATCH'" scripts/build-windows.ps1
require_literal "\$env:VCPKG_KEEP_ENV_VARS = 'RUSTDESK_VCPKG_DISTFILES_DIR'" scripts/build-windows.ps1
require_literal "\$env:VCPKG_BINARY_SOURCES = 'clear'" scripts/build-windows.ps1
require_literal "\$env:X_VCPKG_ASSET_SOURCES = 'clear;x-block-origin'" scripts/build-windows.ps1
require_literal "\$env:VCPKG_DOWNLOADS = 'C:\vcpkg-build-downloads'" scripts/build-windows.ps1
require_literal 'Copy-Item -LiteralPath $vpxSource -Destination (Join-Path $env:VCPKG_DOWNLOADS (Split-Path -Leaf $vpxSource))' scripts/build-windows.ps1
require_literal 'Copy-Item -LiteralPath $vpxPatch -Destination (Join-Path $env:VCPKG_DOWNLOADS (Split-Path -Leaf $vpxPatch))' scripts/build-windows.ps1
require_literal 'libvpx Windows tool manifest must contain exactly 32 entries' scripts/build-windows.ps1
require_literal "if (\$toolName -ceq 'mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst')" scripts/build-windows.ps1
require_literal '$cacheName = "msys2-$toolName"' scripts/build-windows.ps1
require_literal "if (\$toolName -ceq '7zr.exe')" scripts/build-windows.ps1
require_literal '$cacheName = "$($toolHash.Substring(0, 8))-$toolName"' scripts/build-windows.ps1
require_literal 'Copy-Item -LiteralPath $toolSource -Destination (Join-Path $env:VCPKG_DOWNLOADS $cacheName)' scripts/build-windows.ps1
require_literal "vcpkg.exe' remove --recurse 'libvpx:x64-windows-static' --classic" scripts/build-windows.ps1
require_literal 'libvpx --classic' scripts/build-windows.ps1
require_literal 'vcpkg_abi_info.txt' scripts/build-windows.ps1
require_literal 'stale compiled libvpx bytes remain after mandatory removal' scripts/build-windows.ps1
if grep -qF '$installedVpxKey' scripts/build-windows.ps1; then
  fail "a libvpx sidecar still authorizes reuse of compiled Windows bytes"
fi

if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

echo "native-codec-watch: ok (vcpkg native set and manual advisory ledger are in sync; decoder sandbox still separate)"

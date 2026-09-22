#!/usr/bin/env bash
# Build the minimal private AT-SPI runtime closure from exact offline Debian packages.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly PACKAGE_MANIFEST=/work/scripts/smoke-atspi-packages.tsv
readonly FILE_MANIFEST=/work/scripts/smoke-atspi-files.tsv
readonly INPUT_ROOT=/atspi-inputs
readonly DEB_ROOT=/atspi-debs
readonly TOOL_ROOT=/atspi-root
readonly STAGING=/tmp/atspi-package-root
readonly SCHEMA_A=/tmp/atspi-schema-a
readonly SCHEMA_B=/tmp/atspi-schema-b
readonly EXPECTED_PACKAGES=2
readonly EXPECTED_FILES=5

fail() {
  echo "AT-SPI offline preparation: $*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ -d "$INPUT_ROOT" ] && [ ! -L "$INPUT_ROOT" ] \
  || fail 'offline input root is unavailable or ambiguous'
input_mount_options="$(findmnt -n -o OPTIONS --target "$INPUT_ROOT")" \
  || fail 'offline input mount cannot be resolved'
case ",$input_mount_options," in
  *,ro,*) ;;
  *) fail 'offline input mount is writable' ;;
esac
for directory in "$DEB_ROOT" "$TOOL_ROOT"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] \
    || fail "invalid output directory: $directory"
  [ "$(stat -c %u:%g:%a -- "$directory")" = "$(id -u):$(id -g):700" ] \
    || fail "output directory has the wrong owner: $directory"
  [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail "output directory is not empty: $directory"
done
for manifest in "$PACKAGE_MANIFEST" "$FILE_MANIFEST"; do
  [ -f "$manifest" ] && [ ! -L "$manifest" ] \
    || fail "manifest is unavailable: $manifest"
done
for command in dpkg-deb glib-compile-schemas; do
  command -v "$command" >/dev/null || fail "required exact-image command is absent: $command"
done
mkdir -m 0700 "$STAGING" "$SCHEMA_A" "$SCHEMA_B"

declare -A expected_version=(
  [at-spi2-core]=2.46.0-5
  [gsettings-desktop-schemas]=43.0-1
)
declare -A expected_architecture=(
  [at-spi2-core]=amd64
  [gsettings-desktop-schemas]=all
)
declare -A seen_packages=()
package_count=0
while IFS=$'\t' read -r name size digest url extra || [ -n "${name:-}" ]; do
  [ -n "${name:-}" ] || continue
  [[ "$name" == \#* ]] && continue
  [ -z "${extra:-}" ] || fail "package manifest row has extra fields: $name"
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail "invalid package name: $name"
  [ -n "${expected_version[$name]:-}" ] \
    && [ -n "${expected_architecture[$name]:-}" ] \
    || fail "unexpected package identity: $name"
  [ -z "${seen_packages[$name]+x}" ] || fail "duplicate package name: $name"
  [[ "$size" =~ ^[1-9][0-9]*$ ]] || fail "invalid package size: $name"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid package digest: $name"
  case "$url" in
    https://deb.debian.org/debian/pool/*.deb) ;;
    *) fail "package URL is not an exact Debian HTTPS pool path: $name" ;;
  esac
  seen_packages[$name]=1
  package_count=$((package_count + 1))
  input="$INPUT_ROOT/$name.deb"
  [ -f "$input" ] && [ ! -L "$input" ] \
    || fail "offline package is unavailable or ambiguous: $name"
  input_metadata="$(stat -c %u:%g:%a:%h:%s -- "$input")"
  case "$input_metadata" in
    "$(id -u):$(id -g):400:1:$size"|*:*:444:1:"$size") ;;
    *) fail "offline package authority metadata differs: $name" ;;
  esac
  [ "$(sha256sum "$input" | awk '{print $1}')" = "$digest" ] \
    || fail "offline package digest differs from its manifest: $name"
  output="$DEB_ROOT/$name.deb"
  cp --reflink=never -- "$input" "$output"
  chmod 0600 "$output"
  [ "$(stat -c %u:%g:%a:%h:%s -- "$output")" = \
    "$(id -u):$(id -g):600:1:$size" ] \
    || fail "private package-copy metadata differs: $name"
  [ "$(sha256sum "$output" | awk '{print $1}')" = "$digest" ] \
    || fail "private package-copy digest differs: $name"
  [ "$(dpkg-deb --field "$output" Package)" = "$name" ] \
    || fail "package field differs from its manifest: $name"
  [ "$(dpkg-deb --field "$output" Version)" = "${expected_version[$name]}" ] \
    || fail "package version differs: $name"
  [ "$(dpkg-deb --field "$output" Architecture)" = \
    "${expected_architecture[$name]}" ] \
    || fail "package architecture differs: $name"
  dpkg-deb --extract "$output" "$STAGING"
  printf 'ATSPI_PACKAGE_OK name=%s version=%s architecture=%s size=%s sha256=%s\n' \
    "$name" "${expected_version[$name]}" "${expected_architecture[$name]}" \
    "$size" "$digest"
done < "$PACKAGE_MANIFEST"
[ "$package_count" -eq "$EXPECTED_PACKAGES" ] \
  || fail "package cardinality is $package_count, expected $EXPECTED_PACKAGES"

[ -z "$(find "$STAGING" -xdev -type f -perm /6000 -print -quit)" ] \
  || fail 'extracted package closure contains a setuid or setgid file'
[ -z "$(find "$STAGING" -xdev ! \( -type d -o -type f -o -type l \) -print -quit)" ] \
  || fail 'extracted package closure contains a special file'
while IFS= read -r link; do
  target="$(readlink -- "$link")" || fail "cannot inspect extracted symlink: $link"
  case "$target" in
    /*|../*|*/../*|*/..) fail "extracted symlink escapes the package root: $link" ;;
  esac
done < <(find "$STAGING" -xdev -type l -print)

declare -A seen_files=()
file_count=0
while IFS=$'\t' read -r relative size package_mode runtime_mode digest extra \
  || [ -n "${relative:-}" ]; do
  [ -n "${relative:-}" ] || continue
  [[ "$relative" == \#* ]] && continue
  [ -z "${extra:-}" ] || fail "file manifest row has extra fields: $relative"
  [[ "$relative" =~ ^[A-Za-z0-9._+/-]+$ ]] \
    && [[ "$relative" != /* ]] \
    && [[ "$relative" != ../* ]] \
    && [[ "$relative" != */../* ]] \
    || fail "invalid extracted file path: $relative"
  [ -z "${seen_files[$relative]+x}" ] || fail "duplicate required file: $relative"
  [[ "$size" =~ ^[1-9][0-9]*$ ]] || fail "invalid extracted file size: $relative"
  [[ "$package_mode" =~ ^(644|755)$ ]] \
    && [[ "$runtime_mode" =~ ^(400|500)$ ]] \
    || fail "invalid extracted/runtime file mode: $relative"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid extracted file digest: $relative"
  source_file="$STAGING/$relative"
  [ -f "$source_file" ] && [ ! -L "$source_file" ] \
    && [ "$(stat -c %u:%g:%a:%h:%s -- "$source_file")" = \
      "$(id -u):$(id -g):$package_mode:1:$size" ] \
    && [ "$(sha256sum "$source_file" | awk '{print $1}')" = "$digest" ] \
    || fail "required package file differs from its manifest: $relative"
  destination="$TOOL_ROOT/$relative"
  mkdir -p -- "${destination%/*}"
  install -m "0$runtime_mode" -- "$source_file" "$destination"
  [ "$(stat -c %u:%g:%a:%h:%s -- "$destination")" = \
    "$(id -u):$(id -g):$runtime_mode:1:$size" ] \
    && [ "$(sha256sum "$destination" | awk '{print $1}')" = "$digest" ] \
    || fail "sealed runtime file differs after projection: $relative"
  seen_files[$relative]=1
  file_count=$((file_count + 1))
done < "$FILE_MANIFEST"
[ "$file_count" -eq "$EXPECTED_FILES" ] \
  || fail "required-file cardinality is $file_count, expected $EXPECTED_FILES"

readonly SCHEMA_SOURCE="$STAGING/usr/share/glib-2.0/schemas"
[ -d "$SCHEMA_SOURCE" ] && [ ! -L "$SCHEMA_SOURCE" ] \
  || fail 'GSettings schema source is absent or ambiguous'
glib-compile-schemas --strict --targetdir="$SCHEMA_A" "$SCHEMA_SOURCE"
glib-compile-schemas --strict --targetdir="$SCHEMA_B" "$SCHEMA_SOURCE"
for compiled in "$SCHEMA_A/gschemas.compiled" "$SCHEMA_B/gschemas.compiled"; do
  [ -f "$compiled" ] && [ ! -L "$compiled" ] \
    && [ "$(stat -c %u:%g:%a:%h -- "$compiled")" = "$(id -u):$(id -g):600:1" ] \
    && [ "$(stat -c %s -- "$compiled")" -gt 0 ] \
    || fail 'compiled GSettings schema output is absent or ambiguous'
done
cmp -s "$SCHEMA_A/gschemas.compiled" "$SCHEMA_B/gschemas.compiled" \
  || fail 'repeated exact-image GSettings compilation is not byte-identical'
readonly SCHEMA_DESTINATION="$TOOL_ROOT/usr/share/glib-2.0/schemas/gschemas.compiled"
mkdir -p -- "${SCHEMA_DESTINATION%/*}"
install -m 0400 -- "$SCHEMA_A/gschemas.compiled" "$SCHEMA_DESTINATION"
readonly SCHEMA_SIZE="$(stat -c %s -- "$SCHEMA_DESTINATION")"
readonly SCHEMA_SHA256="$(sha256sum "$SCHEMA_DESTINATION" | awk '{print $1}')"
compiler_version="$(glib-compile-schemas --version)"
[[ "$compiler_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail 'GSettings compiler version is malformed'
readonly compiler_version
{
  printf 'contract=rustdesk-flutter-peer-atspi-v1\n'
  printf 'package_manifest_sha256=%s\n' "$(sha256sum "$PACKAGE_MANIFEST" | awk '{print $1}')"
  printf 'file_manifest_sha256=%s\n' "$(sha256sum "$FILE_MANIFEST" | awk '{print $1}')"
  printf 'glib_compile_schemas_version=%s\n' "$compiler_version"
  printf 'schemas_size=%s\n' "$SCHEMA_SIZE"
  printf 'schemas_sha256=%s\n' "$SCHEMA_SHA256"
} > "$TOOL_ROOT/closure.identity.tmp"
chmod 0400 "$TOOL_ROOT/closure.identity.tmp"
mv "$TOOL_ROOT/closure.identity.tmp" "$TOOL_ROOT/closure.identity"
find "$TOOL_ROOT" -xdev -type d -exec chmod 0500 {} +
[ "$(find "$TOOL_ROOT" -xdev -type f | wc -l)" -eq 7 ] \
  && [ "$(find "$TOOL_ROOT" -xdev -type d | wc -l)" -eq 11 ] \
  && [ -z "$(find "$TOOL_ROOT" -xdev -type l -print -quit)" ] \
  || fail 'minimal sealed AT-SPI runtime inventory differs'

tcp_listeners="$(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp)"
[ ! -r /proc/net/tcp6 ] \
  || tcp_listeners=$((tcp_listeners + $(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp6)))
udp_sockets="$(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp)"
[ ! -r /proc/net/udp6 ] \
  || udp_sockets=$((udp_sockets + $(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp6)))
[ "$tcp_listeners" -eq 0 ] || fail 'offline preparation container opened a TCP listener'
[ "$udp_sockets" -eq 0 ] || fail 'offline preparation container retained a UDP socket'
printf 'ATSPI_OFFLINE_INPUT_SURFACE=tcp-listen:%s udp:%s\n' "$tcp_listeners" "$udp_sockets"
printf 'ATSPI_TOOL_CLOSURE_OK packages=%s files=%s schemas_size=%s schemas_sha256=%s compiler=%s\n' \
  "$package_count" "$file_count" "$SCHEMA_SIZE" "$SCHEMA_SHA256" "$compiler_version"

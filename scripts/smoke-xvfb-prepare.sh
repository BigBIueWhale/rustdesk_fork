#!/usr/bin/env bash
# Verify and extract the exact offline Xvfb test-infrastructure closure as an ordinary uid.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly MANIFEST=/work/scripts/smoke-xvfb-packages.tsv
readonly FILE_MANIFEST=/work/scripts/smoke-xvfb-files.tsv
readonly INPUT_ROOT=/xvfb-inputs
readonly DEB_ROOT=/xvfb-debs
readonly TOOL_ROOT=/xvfb-root
readonly EXPECTED_PACKAGES=5

fail() {
  echo "Xvfb offline preparation: $*" >&2
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
  [ -d "$directory" ] && [ ! -L "$directory" ] || fail "invalid output directory: $directory"
  [ "$(stat -c %u:%g:%a -- "$directory")" = "$(id -u):$(id -g):700" ] \
    || fail "output directory has the wrong owner: $directory"
  [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || fail "output directory is not empty: $directory"
done
for manifest in "$MANIFEST" "$FILE_MANIFEST"; do
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || fail "manifest is unavailable: $manifest"
done

declare -A seen=()
package_count=0
while IFS=$'\t' read -r name size digest url extra || [ -n "${name:-}" ]; do
  [ -n "${name:-}" ] || continue
  [[ "$name" == \#* ]] && continue
  [ -z "${extra:-}" ] || fail "manifest row has extra fields: $name"
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail "invalid package name: $name"
  [ -z "${seen[$name]+x}" ] || fail "duplicate package name: $name"
  [[ "$size" =~ ^[1-9][0-9]*$ ]] || fail "invalid package size: $name"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid package digest: $name"
  case "$url" in
    https://deb.debian.org/debian/pool/*.deb|https://security.debian.org/debian-security/pool/*.deb) ;;
    *) fail "package URL is not an exact allowed Debian HTTPS pool path: $name" ;;
  esac
  seen[$name]=1
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
  /usr/bin/cp --reflink=never -- "$input" "$output"
  chmod 0600 "$output"
  [ -f "$output" ] && [ ! -L "$output" ] || fail "private package copy is not a regular file: $name"
  [ "$(stat -c %u:%g:%a:%h:%s -- "$output")" = "$(id -u):$(id -g):600:1:$size" ] \
    || fail "private package-copy metadata or size differs from its manifest: $name"
  [ "$(sha256sum "$output" | awk '{print $1}')" = "$digest" ] \
    || fail "private package-copy digest differs from its manifest: $name"
  [ "$(dpkg-deb --field "$output" Package)" = "$name" ] \
    || fail "package identity differs from its manifest: $name"
  [ "$(dpkg-deb --field "$output" Architecture)" = amd64 ] \
    || fail "package architecture is not amd64: $name"
  dpkg-deb --extract "$output" "$TOOL_ROOT"
  printf 'XVFB_PACKAGE_OK name=%s size=%s sha256=%s\n' "$name" "$size" "$digest"
done < "$MANIFEST"

[ "$package_count" -eq "$EXPECTED_PACKAGES" ] \
  || fail "package cardinality is $package_count, expected $EXPECTED_PACKAGES"
file_count=0
while IFS=$'\t' read -r relative size mode digest extra || [ -n "${relative:-}" ]; do
  [ -n "${relative:-}" ] || continue
  [[ "$relative" == \#* ]] && continue
  [ -z "${extra:-}" ] || fail "file manifest row has extra fields: $relative"
  [[ "$relative" =~ ^[A-Za-z0-9._+/-]+$ ]] \
    && [[ "$relative" != /* ]] \
    && [[ "$relative" != ../* ]] \
    && [[ "$relative" != */../* ]] \
    || fail "invalid extracted file path: $relative"
  [[ "$size" =~ ^[1-9][0-9]*$ ]] || fail "invalid extracted file size: $relative"
  [[ "$mode" =~ ^(644|755)$ ]] || fail "invalid extracted file mode: $relative"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid extracted file digest: $relative"
  file="$TOOL_ROOT/$relative"
  [ -f "$file" ] && [ ! -L "$file" ] || fail "required extracted file is missing: $relative"
  [ "$(stat -c %u:%g:%a:%h:%s -- "$file")" = "$(id -u):$(id -g):$mode:1:$size" ] \
    || fail "extracted file metadata differs from its manifest: $relative"
  [ "$(sha256sum "$file" | awk '{print $1}')" = "$digest" ] \
    || fail "extracted file digest differs from its manifest: $relative"
  file_count=$((file_count + 1))
done < "$FILE_MANIFEST"
[ "$file_count" -eq 5 ] || fail "file manifest cardinality is $file_count, expected 5"
[ -z "$(find "$TOOL_ROOT" -xdev -type f -perm /6000 -print -quit)" ] \
  || fail 'extracted tool closure contains a setuid or setgid file'
while IFS= read -r link; do
  target=$(readlink -- "$link") || fail "cannot inspect extracted symlink: $link"
  case "$target" in
    /*|../*|*/../*|*/..) fail "extracted symlink escapes the tool root: $link" ;;
  esac
done < <(find "$TOOL_ROOT" -xdev -type l -print)
chmod 0700 "$DEB_ROOT" "$TOOL_ROOT"

tcp_listeners=$(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp)
[ ! -r /proc/net/tcp6 ] \
  || tcp_listeners=$((tcp_listeners + $(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp6)))
udp_sockets=$(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp)
[ ! -r /proc/net/udp6 ] \
  || udp_sockets=$((udp_sockets + $(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp6)))
[ "$tcp_listeners" -eq 0 ] || fail 'offline preparation container opened a TCP listener'
[ "$udp_sockets" -eq 0 ] || fail 'offline preparation container retained a UDP socket'
printf 'XVFB_OFFLINE_INPUT_SURFACE=tcp-listen:%s udp:%s\n' "$tcp_listeners" "$udp_sockets"
printf 'XVFB_TOOL_CLOSURE_OK packages=%s xvfb_sha256=%s xkbcomp_sha256=%s\n' \
  "$package_count" \
  "$(sha256sum "$TOOL_ROOT/usr/bin/Xvfb" | awk '{print $1}')" \
  "$(sha256sum "$TOOL_ROOT/usr/bin/xkbcomp" | awk '{print $1}')"

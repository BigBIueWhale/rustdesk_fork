#!/usr/bin/env bash
# Inner build/server/viewer stages for the exact full RustDesk peer-presentation probe.
set -euo pipefail
umask 077

fail() {
  echo "flutter peer presentation stage: $*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ -z "${LD_PRELOAD:-}" ] || fail 'refuses an ambient preload'
[ "$#" -eq 1 ] \
  || fail 'expected one stage: input-check, atspi-check, pub-cache, pub-cache-check, build, server, or viewer'

verify_regular() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "missing regular input: $1"
}

verify_archive() {
  local path=$1 size=$2 digest=$3 label=$4
  verify_regular "$path"
  [ "$(stat -c %s "$path")" = "$size" ] || fail "$label size differs from its pin"
  [ "$(sha256sum "$path" | awk '{print $1}')" = "$digest" ] \
    || fail "$label digest differs from its pin"
}

verify_canonical_pub_cache() {
  local root=$1 expected=$2
  [ -d "$root" ] && [ ! -L "$root" ] \
    || fail 'canonical evidence Pub cache is missing or linked'
  verify_regular /source/scripts/online-pub-cache-output.py
  /usr/bin/python3 -I -S - /source/scripts/online-pub-cache-output.py \
    "$root" "$expected" "$(id -u)" "$(id -g)" <<'PY'
import importlib.util
import pathlib
import sys

helper_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
expected = sys.argv[3]
uid = int(sys.argv[4])
gid = int(sys.argv[5])
spec = importlib.util.spec_from_file_location("rustdesk_pub_cache_output", helper_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load Pub-cache verifier")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
summary = module.inspect_tree(root, owners={(uid, gid)}, published=True)
module.validate_shape(root, strict_output=True)
if summary.digest != expected:
    raise SystemExit(
        f"canonical evidence Pub-cache digest differs: {summary.digest} != {expected}"
    )
print(f"FLUTTER_PEER_CANONICAL_PUB_CACHE_OK sha256={summary.digest}")
PY
}

verify_machine_identity() {
  [ -f /etc/machine-id ] && [ ! -L /etc/machine-id ] \
    && [ "$(stat -c '%u:%g:%a:%h:%s' /etc/machine-id)" = \
      "$(id -u):$(id -g):400:1:33" ] \
    && grep -Eq '^[0-9a-f]{32}$' /etc/machine-id \
    || fail 'private endpoint machine identity differs'
}

verify_xvfb_closure() {
  local count=0 relative size mode digest extra file
  verify_regular /source/scripts/smoke-xvfb-files.tsv
  while IFS=$'\t' read -r relative size mode digest extra || [ -n "${relative:-}" ]; do
    [ -n "${relative:-}" ] || continue
    [[ "$relative" == \#* ]] && continue
    [ -z "${extra:-}" ] || fail 'Xvfb file manifest has extra fields'
    file="/xvfb-root/$relative"
    [ -f "$file" ] && [ ! -L "$file" ] \
      && [ "$(stat -c '%u:%g:%a:%h:%s' "$file")" = \
        "$(id -u):$(id -g):$mode:1:$size" ] \
      && [ "$(sha256sum "$file" | awk '{print $1}')" = "$digest" ] \
      || fail "Xvfb closure file differs from its manifest: $relative"
    count=$((count + 1))
  done < /source/scripts/smoke-xvfb-files.tsv
  [ "$count" -eq 5 ] || fail 'Xvfb closure file cardinality is not five'
}

verify_atspi_package_inputs() {
  local count=0 name size digest url extra package
  verify_regular /source/scripts/smoke-atspi-packages.tsv
  [ -d /online/atspi-debs ] && [ ! -L /online/atspi-debs ] \
    || fail 'offline AT-SPI package root is absent or ambiguous'
  while IFS=$'\t' read -r name size digest url extra || [ -n "${name:-}" ]; do
    [ -n "${name:-}" ] || continue
    [[ "$name" == \#* ]] && continue
    [ -z "${extra:-}" ] || fail "AT-SPI package manifest has extra fields: $name"
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] \
      && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
      && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
      || fail "AT-SPI package manifest row is malformed: $name"
    case "$url" in
      https://deb.debian.org/debian/pool/*.deb) ;;
      *) fail "AT-SPI package URL is not an exact Debian pool URL: $name" ;;
    esac
    package="/online/atspi-debs/$name.deb"
    [ -f "$package" ] && [ ! -L "$package" ] \
      && [ "$(stat -c '%u:%g:%a:%h:%s' "$package")" = \
        "$(id -u):$(id -g):400:1:$size" ] \
      && [ "$(sha256sum "$package" | awk '{print $1}')" = "$digest" ] \
      || fail "offline AT-SPI package differs from its manifest: $name"
    count=$((count + 1))
  done < /source/scripts/smoke-atspi-packages.tsv
  [ "$count" -eq 2 ] || fail 'AT-SPI package cardinality is not two'
}

verify_atspi_closure() {
  local count=0 relative size package_mode runtime_mode digest extra file
  local package_manifest_sha file_manifest_sha compiler_version schema_size schema_sha
  [ -d /atspi-root ] && [ ! -L /atspi-root ] \
    && [ "$(stat -c '%u:%g:%a' /atspi-root)" = "$(id -u):$(id -g):500" ] \
    || fail 'sealed AT-SPI runtime root is absent or ambiguous'
  verify_regular /source/scripts/smoke-atspi-packages.tsv
  verify_regular /source/scripts/smoke-atspi-files.tsv
  verify_regular /atspi-root/closure.identity
  [ "$(stat -c '%u:%g:%a:%h' /atspi-root/closure.identity)" = \
    "$(id -u):$(id -g):400:1" ] \
    && [ "$(wc -l < /atspi-root/closure.identity)" -eq 6 ] \
    || fail 'AT-SPI closure identity metadata differs'
  grep -qx 'contract=rustdesk-flutter-peer-atspi-v1' /atspi-root/closure.identity \
    || fail 'AT-SPI closure contract differs'
  package_manifest_sha="$(awk -F= '$1 == "package_manifest_sha256" {print $2}' \
    /atspi-root/closure.identity)"
  file_manifest_sha="$(awk -F= '$1 == "file_manifest_sha256" {print $2}' \
    /atspi-root/closure.identity)"
  compiler_version="$(awk -F= '$1 == "glib_compile_schemas_version" {print $2}' \
    /atspi-root/closure.identity)"
  schema_size="$(awk -F= '$1 == "schemas_size" {print $2}' /atspi-root/closure.identity)"
  schema_sha="$(awk -F= '$1 == "schemas_sha256" {print $2}' /atspi-root/closure.identity)"
  [ "$package_manifest_sha" = \
    "$(sha256sum /source/scripts/smoke-atspi-packages.tsv | awk '{print $1}')" ] \
    && [ "$file_manifest_sha" = \
      "$(sha256sum /source/scripts/smoke-atspi-files.tsv | awk '{print $1}')" ] \
    && [[ "$compiler_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && [[ "$schema_size" =~ ^[1-9][0-9]*$ ]] \
    && [[ "$schema_sha" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'AT-SPI closure identity values differ'
  while IFS=$'\t' read -r relative size package_mode runtime_mode digest extra \
    || [ -n "${relative:-}" ]; do
    [ -n "${relative:-}" ] || continue
    [[ "$relative" == \#* ]] && continue
    [ -z "${extra:-}" ] \
      && [[ "$relative" =~ ^[A-Za-z0-9._+/-]+$ ]] \
      && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
      && [[ "$package_mode" =~ ^(644|755)$ ]] \
      && [[ "$runtime_mode" =~ ^(400|500)$ ]] \
      && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
      || fail "AT-SPI runtime manifest row is malformed: $relative"
    file="/atspi-root/$relative"
    [ -f "$file" ] && [ ! -L "$file" ] \
      && [ "$(stat -c '%u:%g:%a:%h:%s' "$file")" = \
        "$(id -u):$(id -g):$runtime_mode:1:$size" ] \
      && [ "$(sha256sum "$file" | awk '{print $1}')" = "$digest" ] \
      || fail "AT-SPI runtime file differs from its manifest: $relative"
    count=$((count + 1))
  done < /source/scripts/smoke-atspi-files.tsv
  [ "$count" -eq 5 ] || fail 'AT-SPI runtime file cardinality is not five'
  file=/atspi-root/usr/share/glib-2.0/schemas/gschemas.compiled
  [ -f "$file" ] && [ ! -L "$file" ] \
    && [ "$(stat -c '%u:%g:%a:%h:%s' "$file")" = \
      "$(id -u):$(id -g):400:1:$schema_size" ] \
    && [ "$(sha256sum "$file" | awk '{print $1}')" = "$schema_sha" ] \
    || fail 'compiled AT-SPI GSettings schema differs from its identity'
  [ "$(find /atspi-root -xdev -type f | wc -l)" -eq 7 ] \
    && [ "$(find /atspi-root -xdev -type d | wc -l)" -eq 11 ] \
    && [ -z "$(find /atspi-root -xdev -type l -print -quit)" ] \
    && [ -z "$(find /atspi-root -xdev -type f -perm /6000 -print -quit)" ] \
    || fail 'sealed minimal AT-SPI runtime inventory differs'
}

exact_executable_process_count() {
  local expected=$1 count=0 path target
  for path in /proc/[0-9]*/exe; do
    target="$(readlink "$path" 2>/dev/null)" || continue
    [ "$target" != "$expected" ] || count=$((count + 1))
  done
  printf '%s\n' "$count"
}

verify_runtime_bundle() {
  verify_regular /out/manifest.sha256
  [ -z "$(find /out -xdev -type l -print -quit)" ] \
    || fail 'runtime bundle contains a symlink'
  (cd /out && sha256sum --check --strict manifest.sha256 >/dev/null)
  verify_regular /out/smoke-bind-loopback.so
  for executable in \
    /out/bundle/rustdesk \
    /out/smoke-readiness \
    /out/flutter-peer-source-x11 \
    /out/flutter-peer-presentation-x11 \
    /source/scripts/smoke-ready.sh \
    /xvfb-root/usr/bin/Xvfb; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
      || fail "runtime executable is missing or invalid: $executable"
  done
  verify_xvfb_closure
}

assert_loopback_only_interface() {
  local interfaces
  interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" \
    || fail 'cannot inspect runtime network interfaces'
  [ "$interfaces" = lo ] || fail "runtime has a non-loopback interface: $interfaces"
}

tcp_listener_count() {
  local -a tables=(/proc/net/tcp)
  [ -z "$TCP6_TABLE" ] || tables+=("$TCP6_TABLE")
  awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' \
    "${tables[@]}"
}

udp_socket_count() {
  local -a tables=(/proc/net/udp)
  [ -z "$UDP6_TABLE" ] || tables+=("$UDP6_TABLE")
  awk 'FNR > 1 { count++ } END { print count + 0 }' \
    "${tables[@]}"
}

listener_is_exact() {
  [ "$(tcp_listener_count)" -eq 1 ] \
    && awk 'FNR > 1 && $4 == "0A" && $2 == "0100007F:527E" { count++ }
      END { exit count == 1 ? 0 : 1 }' /proc/net/tcp
}

process_maps_exact_file() {
  local pid=$1 expected=$2
  [ -r "/proc/$pid/maps" ] \
    && awk -v expected="$expected" '$6 == expected { found = 1 }
      END { exit found == 1 ? 0 : 1 }' "/proc/$pid/maps"
}

wait_process_maps_exact_file() {
  local pid=$1 start=$2 expected=$3
  for _ in $(seq 1 300); do
    process_maps_exact_file "$pid" "$expected" && return 0
    "$READY" --is-running "$pid" "$start" || return 1
    sleep 0.02
  done
  return 1
}

start_xvfb() {
  local display=$1 geometry=$2 log=$3
  "$XVFB" "$display" -screen 0 "$geometry" -nolisten tcp -ac -noreset >"$log" 2>&1 &
  XVFB_PID=$!
  XVFB_START=
  if ! XVFB_START=$("$READY" --identity "$XVFB_PID"); then
    wait "$XVFB_PID" 2>/dev/null || true
    cat "$log" >&2
    fail "Xvfb $display exited before identity capture"
  fi
  local socket="/tmp/.X11-unix/X${display#:}"
  for _ in $(seq 1 300); do
    [ -S "$socket" ] && break
    "$READY" --is-running "$XVFB_PID" "$XVFB_START" \
      || { cat "$log" >&2; fail "Xvfb $display exited before readiness"; }
    sleep 0.02
  done
  [ -S "$socket" ] && [ ! -L "$socket" ] \
    || fail "Xvfb $display Unix socket did not become ready"
  "$READY" --hold-running "$XVFB_PID" "$XVFB_START" "$log" 1 \
    "Flutter peer presentation Xvfb $display stability"
}

emit_runtime_logs() {
  local label=$1 root=$2 path metadata uid gid mode size links files=0 bytes=0
  [[ "$label" =~ ^[A-Z]+$ ]] || fail 'runtime-log diagnostic label is malformed'
  if [ ! -e "$root" ]; then
    printf 'FLUTTER_PEER_%s_FILE_LOGS_ABSENT\n' "$label" >&2
    return
  fi
  [ -d "$root" ] && [ ! -L "$root" ] \
    || fail 'runtime-log diagnostic root is not one real directory'
  while IFS= read -r -d '' path; do
    [ -f "$path" ] && [ ! -L "$path" ] \
      || fail 'runtime-log diagnostic selected a non-regular file'
    metadata="$(stat -c '%u %g %a %s %h' "$path")"
    read -r uid gid mode size links <<<"$metadata"
    [ "$uid:$gid" = "$(id -u):$(id -g)" ] \
      && [[ "$mode" =~ ^[0-7]{3,4}$ ]] \
      && [ $((8#$mode & 0022)) -eq 0 ] \
      && [[ "$size" =~ ^[0-9]+$ ]] \
      && [ "$links" = 1 ] \
      || fail 'runtime-log diagnostic file metadata differs'
    files=$((files + 1))
    bytes=$((bytes + size))
    [ "$files" -le 16 ] && [ "$size" -le 8388608 ] && [ "$bytes" -le 33554432 ] \
      || fail 'runtime-log diagnostic exceeds its exact bounds'
    printf 'FLUTTER_PEER_%s_FILE_LOG_BEGIN path=%s bytes=%s\n' \
      "$label" "${path#"$root"/}" "$size" >&2
    cat -- "$path" >&2
    printf 'FLUTTER_PEER_%s_FILE_LOG_END\n' "$label" >&2
  done < <(find "$root" -xdev -mindepth 1 -maxdepth 5 -type f -print0 | sort -z)
  [ "$files" -gt 0 ] \
    || printf 'FLUTTER_PEER_%s_FILE_LOGS_EMPTY\n' "$label" >&2
}

TCP6_TABLE=
[ ! -r /proc/net/tcp6 ] || TCP6_TABLE=/proc/net/tcp6
UDP6_TABLE=
[ ! -r /proc/net/udp6 ] || UDP6_TABLE=/proc/net/udp6

case "$1" in
  input-check)
    for variable in \
      RUSTDESK_RUST_VERSION RUSTDESK_RUST_SHA256 RUSTDESK_RUST_SIZE \
      RUSTDESK_FLUTTER_ARCHIVE RUSTDESK_FLUTTER_VERSION \
      RUSTDESK_FLUTTER_SHA256 RUSTDESK_FLUTTER_SIZE \
      RUSTDESK_LLVM_VERSION RUSTDESK_LLVM_SHA256 RUSTDESK_LLVM_SIZE \
      RUSTDESK_FRB_VERSION RUSTDESK_FRB_SHA256 RUSTDESK_FRB_SIZE \
      RUSTDESK_CARGO_VENDOR_SHA256 RUSTDESK_CARGO_VENDOR_CONFIG_SHA256 \
      RUSTDESK_CARGO_VENDOR_CONFIG_SIZE RUSTDESK_VCPKG_X64_LINUX_SHA256; do
      [ -n "${!variable:-}" ] || fail "missing input identity: $variable"
    done
    verify_archive "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz" \
      "$RUSTDESK_RUST_SIZE" "$RUSTDESK_RUST_SHA256" Rust
    [ "$RUSTDESK_FLUTTER_ARCHIVE" = /flutter-sdk.tar.xz ] \
      || fail 'Flutter archive projection path differs'
    verify_archive "$RUSTDESK_FLUTTER_ARCHIVE" \
      "$RUSTDESK_FLUTTER_SIZE" "$RUSTDESK_FLUTTER_SHA256" Flutter
    verify_archive "/online/llvm-${RUSTDESK_LLVM_VERSION}.tar.xz" \
      "$RUSTDESK_LLVM_SIZE" "$RUSTDESK_LLVM_SHA256" LLVM
    for input in \
      /online/cargo-vendor-config.toml \
      /online/frb-tool/bin/flutter_rust_bridge_codegen \
      /source/scripts/online-cargo-tool-output.py \
      /source/scripts/online-input-provenance.py; do
      verify_regular "$input"
    done
    for directory in /online/cargo-vendor /online/frb-tool /online/vcpkg/installed/x64-linux; do
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "missing persistent build-input directory: $directory"
    done
    [ "$(stat -c %s /online/cargo-vendor-config.toml)" = \
      "$RUSTDESK_CARGO_VENDOR_CONFIG_SIZE" ] \
      || fail 'Cargo vendor configuration size differs from its pin'
    [ "$(sha256sum /online/cargo-vendor-config.toml | awk '{print $1}')" = \
      "$RUSTDESK_CARGO_VENDOR_CONFIG_SHA256" ] \
      || fail 'Cargo vendor configuration digest differs from its pin'
    /usr/bin/python3 -I -S /source/scripts/online-input-provenance.py verify-subtree \
      --tree /online/cargo-vendor --expected "$RUSTDESK_CARGO_VENDOR_SHA256"
    /usr/bin/python3 -I -S /source/scripts/online-cargo-tool-output.py check-complete \
      --online /online --uid "$(id -u)" --gid "$(id -g)" \
      --kind frb --tool-version "$RUSTDESK_FRB_VERSION" \
      --rust-version "$RUSTDESK_RUST_VERSION"
    [ "$(stat -c %s /online/frb-tool/bin/flutter_rust_bridge_codegen)" = \
      "$RUSTDESK_FRB_SIZE" ] \
      || fail 'FRB codegen size differs from its evidence pin'
    [ "$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk '{print $1}')" = \
      "$RUSTDESK_FRB_SHA256" ] \
      || fail 'FRB codegen digest differs from its evidence pin'
    /usr/bin/python3 -I -S /source/scripts/online-input-provenance.py verify-subtree \
      --tree /online/vcpkg/installed/x64-linux \
      --expected "$RUSTDESK_VCPKG_X64_LINUX_SHA256"
    verify_atspi_package_inputs
    printf 'FLUTTER_PEER_INPUTS_OK rust=%s flutter=%s llvm=%s frb=%s cargo_vendor=%s vcpkg_x64_linux=%s atspi_packages=2\n' \
      "$RUSTDESK_RUST_SHA256" "$RUSTDESK_FLUTTER_SHA256" "$RUSTDESK_LLVM_SHA256" \
      "$RUSTDESK_FRB_SHA256" "$RUSTDESK_CARGO_VENDOR_SHA256" \
      "$RUSTDESK_VCPKG_X64_LINUX_SHA256"
    ;;

  atspi-check)
    verify_atspi_closure
    verify_xvfb_closure
    assert_loopback_only_interface
    [ "${DISPLAY:-}" = :97 ] \
      && [ "${HOME:-}" = /tmp/atspi-home ] \
      && [ "${XDG_RUNTIME_DIR:-}" = /tmp/atspi-runtime ] \
      && [ "${XDG_DATA_DIRS:-}" = \
        /atspi-root/usr/share:/usr/local/share:/usr/share ] \
      && [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] \
      || fail 'private AT-SPI preflight environment differs'
    for command in gdbus python3; do
      command -v "$command" >/dev/null \
        || fail "AT-SPI preflight command is absent: $command"
    done
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    export LD_LIBRARY_PATH=/xvfb-root/usr/lib/x86_64-linux-gnu
    [ -d "$HOME" ] && [ ! -L "$HOME" ] \
      && [ "$(stat -c '%u:%g:%a' "$HOME")" = "$(id -u):$(id -g):700" ] \
      && [ -d "$XDG_RUNTIME_DIR" ] && [ ! -L "$XDG_RUNTIME_DIR" ] \
      && [ "$(stat -c '%u:%g:%a' "$XDG_RUNTIME_DIR")" = \
        "$(id -u):$(id -g):700" ] \
      || fail 'private AT-SPI preflight session directories differ'
    mkdir -m 1777 /tmp/.X11-unix
    XVFB_PID= XVFB_START=
    cleanup_atspi_check() {
      local status=$? cleanup_status=0
      trap - EXIT HUP INT TERM
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_atspi_check EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_xvfb :97 640x480x24 /tmp/atspi-xvfb.log
    bus_reply="$(gdbus call --session --dest org.a11y.Bus \
      --object-path /org/a11y/bus --method org.a11y.Bus.GetAddress)"
    bus_address="$(/usr/bin/python3 -I -S - "$bus_reply" <<'PY'
import ast
import re
import sys

try:
    value = ast.literal_eval(sys.argv[1])
except (SyntaxError, ValueError) as exc:
    raise SystemExit(f"AT-SPI address reply is malformed: {exc}")
if not isinstance(value, tuple) or len(value) != 1 or not isinstance(value[0], str):
    raise SystemExit("AT-SPI address reply has the wrong type")
if re.fullmatch(
    r"unix:path=/tmp/atspi-runtime/at-spi/bus_97,guid=([0-9a-f]{32})", value[0]
) is None:
    raise SystemExit(f"AT-SPI address differs: {value[0]!r}")
print(value[0])
PY
)"
    gdbus call --address "$bus_address" --dest org.a11y.atspi.Registry \
      --object-path /org/a11y/atspi/registry \
      --method org.freedesktop.DBus.Peer.Ping >/dev/null
    [ "$(exact_executable_process_count /usr/libexec/at-spi-bus-launcher)" -eq 1 ] \
      && [ "$(exact_executable_process_count /usr/libexec/at-spi2-registryd)" -eq 1 ] \
      || fail 'private AT-SPI launcher or registry process identity differs'
    [ "$(tcp_listener_count)" -eq 0 ] && [ "$(udp_socket_count)" -eq 0 ] \
      || fail 'private AT-SPI preflight opened an INET listener or UDP socket'
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID= XVFB_START=
    printf 'FLUTTER_PEER_ATSPI_RUNTIME_OK session_bus=private accessibility_bus=unix launcher=exact registry=exact x11=joined inet=0 udp=0\n'
    trap - EXIT HUP INT TERM
    ;;

  pub-cache)
    : "${RUSTDESK_EVIDENCE_PUB_CACHE_SHA256:?}"
    [ -d /evidence-online ] && [ ! -L /evidence-online ] \
      && [ "$(stat -c '%u:%g:%a' /evidence-online)" = "$(id -u):$(id -g):700" ] \
      || fail 'evidence-cache output is not a private current-user directory'
    [ -z "$(find /evidence-online -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'evidence-cache output is not empty'
    verify_canonical_pub_cache \
      /evidence-pub-cache "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256"
    printf 'sha256=%s source=canonical-pinned-online semantics=readonly-closure-writable-runtime-root\n' \
      "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256" > /evidence-online/pub-cache.identity
    chmod 0444 /evidence-online/pub-cache.identity
    chmod 0555 /evidence-online
    printf 'FLUTTER_PEER_PUB_CACHE_PREPARED sha256=%s source_unchanged=true projection=readonly-closure-writable-runtime-root\n' \
      "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256"
    ;;

  pub-cache-check)
    : "${RUSTDESK_EVIDENCE_PUB_CACHE_SHA256:?}"
    verify_canonical_pub_cache \
      /evidence-pub-cache "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256"
    verify_regular /evidence-online/pub-cache.identity
    [ "$(< /evidence-online/pub-cache.identity)" = \
      "sha256=$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256 source=canonical-pinned-online semantics=readonly-closure-writable-runtime-root" ] \
      || fail 'evidence Pub-cache identity receipt differs'
    printf 'FLUTTER_PEER_PUB_CACHE_CHECK_OK sha256=%s sealed=true source_unchanged=true\n' \
      "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256"
    ;;

  build)
    for variable in \
      RUSTDESK_RUST_VERSION RUSTDESK_RUST_SHA256 RUSTDESK_RUST_SIZE \
      RUSTDESK_FLUTTER_ARCHIVE RUSTDESK_FLUTTER_VERSION \
      RUSTDESK_FLUTTER_SHA256 RUSTDESK_FLUTTER_SIZE \
      RUSTDESK_LLVM_VERSION RUSTDESK_LLVM_SHA256 RUSTDESK_LLVM_SIZE \
      RUSTDESK_FRB_SHA256 RUSTDESK_FRB_SIZE \
      RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256 RUSTDESK_FLUTTER_TOOLS_MODE \
      RUSTDESK_EVIDENCE_PUB_CACHE_SHA256 RUSTDESK_PROJECT_LOCK_MODE; do
      [ -n "${!variable:-}" ] || fail "missing build identity: $variable"
    done
    [ "$RUSTDESK_FLUTTER_TOOLS_MODE" = offline-resolved ] \
      || fail 'Flutter tools mode differs'
    verify_archive "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz" \
      "$RUSTDESK_RUST_SIZE" "$RUSTDESK_RUST_SHA256" Rust
    [ "$RUSTDESK_FLUTTER_ARCHIVE" = /flutter-sdk.tar.xz ] \
      || fail 'Flutter archive projection path differs'
    verify_archive "$RUSTDESK_FLUTTER_ARCHIVE" \
      "$RUSTDESK_FLUTTER_SIZE" "$RUSTDESK_FLUTTER_SHA256" Flutter
    verify_archive "/online/llvm-${RUSTDESK_LLVM_VERSION}.tar.xz" \
      "$RUSTDESK_LLVM_SIZE" "$RUSTDESK_LLVM_SHA256" LLVM
    for input in \
      /online/cargo-vendor-config.toml \
      /online/frb-tool/bin/flutter_rust_bridge_codegen \
      /source/Cargo.lock \
      /source/flutter/pubspec.lock \
      /source/scripts/flutter-offline-shim.sh \
      /source/scripts/flutter-peer-source-x11.c \
      /source/scripts/flutter-peer-presentation-x11.c; do
      verify_regular "$input"
    done
    for directory in /online/cargo-vendor /online/vcpkg; do
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "missing build-input directory: $directory"
    done
    verify_regular /evidence-online/pub-cache.identity
    [ "$(< /evidence-online/pub-cache.identity)" = \
      "sha256=$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256 source=canonical-pinned-online semantics=readonly-closure-writable-runtime-root" ] \
      || fail 'build evidence Pub-cache identity differs'
    [ -d /out ] && [ ! -L /out ] \
      && [ "$(stat -c '%u:%g:%a' /out)" = "$(id -u):$(id -g):700" ] \
      || fail 'build output is not a private current-user directory'
    [ -z "$(find /out -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'build output directory is not empty'
    [ -d /build-work ] && [ ! -L /build-work ] \
      && [ "$(stat -c '%u:%g:%a' /build-work)" = "$(id -u):$(id -g):700" ] \
      || fail 'build work is not a private current-user directory'
    [ "$(find /build-work -mindepth 1 -maxdepth 1 -printf '%f\n')" = pub-cache ] \
      || fail 'build work initial inventory differs'
    [ -d /build-work/pub-cache ] && [ ! -L /build-work/pub-cache ] \
      && [ "$(stat -c '%u:%g:%a' /build-work/pub-cache)" = \
        "$(id -u):$(id -g):700" ] \
      && [ "$(find /build-work/pub-cache -mindepth 1 -maxdepth 1 -printf '%f\n' \
          | sort)" = $'git\nhosted\nhosted-hashes' ] \
      || fail 'disposable Pub-cache runtime topology differs'
    for directory in /build-work/pub-cache/hosted \
      /build-work/pub-cache/hosted-hashes /build-work/pub-cache/git; do
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "read-only Pub-cache closure mount is missing: $directory"
    done

    readonly TOOLCHAIN=/build-work/toolchain
    readonly BUILD_SOURCE=/build-work/source
    readonly FRB_CODEGEN=$TOOLCHAIN/flutter_rust_bridge_codegen
    readonly HOME=/build-work/home
    readonly CARGO_HOME=/build-work/cargo-home
    mkdir -m 0700 "$TOOLCHAIN" "$BUILD_SOURCE" "$HOME" "$CARGO_HOME"
    cp -a /source/. "$BUILD_SOURCE/"
    chmod -R u+rwX "$BUILD_SOURCE"
    tar -C "$TOOLCHAIN" -xf "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz"
    tar -C "$TOOLCHAIN" -xf "$RUSTDESK_FLUTTER_ARCHIVE"
    tar -C "$TOOLCHAIN" -xf "/online/llvm-${RUSTDESK_LLVM_VERSION}.tar.xz"
    [ "$(stat -c %s /online/frb-tool/bin/flutter_rust_bridge_codegen)" = \
      "$RUSTDESK_FRB_SIZE" ] \
      || fail 'FRB codegen size differs before executable projection'
    [ "$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk '{print $1}')" = \
      "$RUSTDESK_FRB_SHA256" ] \
      || fail 'FRB codegen digest differs before executable projection'
    install -m 0500 /online/frb-tool/bin/flutter_rust_bridge_codegen "$FRB_CODEGEN"
    [ "$(stat -c '%u:%g:%a:%h:%s' "$FRB_CODEGEN")" = \
      "$(id -u):$(id -g):500:1:$RUSTDESK_FRB_SIZE" ] \
      || fail 'private FRB executable projection metadata differs'
    [ "$(sha256sum "$FRB_CODEGEN" | awk '{print $1}')" = "$RUSTDESK_FRB_SHA256" ] \
      || fail 'private FRB executable projection digest differs'
    "$TOOLCHAIN"/rust-1.*/install.sh --prefix="$TOOLCHAIN/rustinstall" \
      --disable-ldconfig \
      --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview \
      >/dev/null
    readonly FLUTTER_ROOT=$TOOLCHAIN/flutter
    LLVM_ROOT="$(echo "$TOOLCHAIN"/clang+llvm-*)"
    [ -x "$FLUTTER_ROOT/bin/flutter" ] || fail 'Flutter SDK extracted at an unexpected path'
    [ "$(sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}')" = \
      "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ] \
      || fail 'Flutter tools lockfile differs from its pin'
    export HOME CARGO_HOME CI=true PUB_CACHE=/build-work/pub-cache
    export FLUTTER_SUPPRESS_ANALYTICS=true
    export REAL_FLUTTER="$FLUTTER_ROOT/bin/flutter"
    export VCPKG_ROOT=/online/vcpkg
    export LIBCLANG_PATH="$LLVM_ROOT/lib"
    export CARGO_PROFILE_RELEASE_RPATH=false
    export PATH="$FLUTTER_ROOT/bin:$FLUTTER_ROOT/bin/cache/dart-sdk/bin:$TOOLCHAIN/rustinstall/bin:$PATH"
    git config --global --add safe.directory '*'
    cat > "$CARGO_HOME/config.toml" <<'CFG'
[net]
offline = true
CFG
    sed 's#directory = .*#directory = "/online/cargo-vendor"#' \
      /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
    readonly SHIM=/tmp/flutter-shim
    mkdir "$SHIM"
    cp "$BUILD_SOURCE/scripts/flutter-offline-shim.sh" "$SHIM/flutter"
    chmod 0700 "$SHIM/flutter"
    export PATH="$SHIM:$PATH"
    if [ "$RUSTDESK_PROJECT_LOCK_MODE" = candidate-pinned ]; then
      for variable in \
        RUSTDESK_FLUTTER_CANDIDATE_FRAMEWORK_REVISION \
        RUSTDESK_FLUTTER_CANDIDATE_ENGINE_REVISION \
        RUSTDESK_FLUTTER_CANDIDATE_DART_VERSION \
        RUSTDESK_FLUTTER_CANDIDATE_VERSION_JSON_SHA256; do
        [ -n "${!variable:-}" ] || fail "missing candidate identity: $variable"
      done
      for input in \
        "$FLUTTER_ROOT/bin/cache/flutter.version.json" \
        "$FLUTTER_ROOT/bin/cache/dart-sdk/version" \
        "$FLUTTER_ROOT/bin/cache/flutter_tools.snapshot" \
        "$FLUTTER_ROOT/bin/internal/engine.version"; do
        verify_regular "$input"
      done
      [ "$(sha256sum "$FLUTTER_ROOT/bin/cache/flutter.version.json" | awk '{print $1}')" = \
        "$RUSTDESK_FLUTTER_CANDIDATE_VERSION_JSON_SHA256" ] \
        || fail 'candidate Flutter version manifest digest differs'
      [ "$(<"$FLUTTER_ROOT/bin/internal/engine.version")" = \
        "$RUSTDESK_FLUTTER_CANDIDATE_ENGINE_REVISION" ] \
        || fail 'candidate Flutter engine revision differs'
      [ "$(<"$FLUTTER_ROOT/bin/cache/dart-sdk/version")" = \
        "$RUSTDESK_FLUTTER_CANDIDATE_DART_VERSION" ] \
        || fail 'candidate Dart SDK version differs'
      /usr/bin/python3 -I -S - \
        "$FLUTTER_ROOT/bin/cache/flutter.version.json" \
        "$RUSTDESK_FLUTTER_VERSION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_FRAMEWORK_REVISION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_ENGINE_REVISION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_DART_VERSION" <<'PY'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
if manifest.stat().st_size > 4096:
    raise SystemExit("candidate Flutter version manifest exceeds its bound")
data = json.loads(manifest.read_text(encoding="utf-8"))
expected = {
    "frameworkVersion": sys.argv[2],
    "flutterVersion": sys.argv[2],
    "channel": "stable",
    "repositoryUrl": "https://github.com/flutter/flutter.git",
    "frameworkRevision": sys.argv[3],
    "engineRevision": sys.argv[4],
    "dartSdkVersion": sys.argv[5],
}
for key, value in expected.items():
    if data.get(key) != value:
        raise SystemExit(f"candidate Flutter version field differs: {key}")
PY
      candidate_snapshot_sha="$(
        sha256sum "$FLUTTER_ROOT/bin/cache/flutter_tools.snapshot" | awk '{print $1}'
      )"
      candidate_version_sha="$(
        sha256sum "$FLUTTER_ROOT/bin/cache/flutter.version.json" | awk '{print $1}'
      )"
    fi
    flutter_tools_lock_before="$(
      sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}'
    )"
    printf 'FLUTTER_PEER_BUILD_PHASE=flutter-tools-offline-start version=%s network=none timeout_seconds=300\n' \
      "$RUSTDESK_FLUTTER_VERSION"
    (
      cd "$FLUTTER_ROOT/packages/flutter_tools"
      /usr/bin/timeout --signal=TERM --kill-after=10s 300s \
        dart pub get --offline --enforce-lockfile
    )
    [ "$(sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}')" = \
      "$flutter_tools_lock_before" ] \
      || fail 'Flutter tools lockfile changed during offline resolution'
    "$BUILD_SOURCE/scripts/finalize-flutter-tools-offline.sh" \
      "$FLUTTER_ROOT" \
      "$RUSTDESK_FLUTTER_VERSION" \
      "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256"
    printf 'FLUTTER_PEER_BUILD_PHASE=flutter-tools-offline-complete version=%s implicit_pub=prevented\n' \
      "$RUSTDESK_FLUTTER_VERSION"
    if [ "$RUSTDESK_PROJECT_LOCK_MODE" = candidate-pinned ]; then
      "$REAL_FLUTTER" --suppress-analytics --version > /tmp/flutter-candidate-version.out
      grep -Fq "Flutter $RUSTDESK_FLUTTER_VERSION" /tmp/flutter-candidate-version.out \
        || fail 'candidate Flutter executable reports a different version'
      [ "$(sha256sum "$FLUTTER_ROOT/bin/cache/flutter_tools.snapshot" | awk '{print $1}')" = \
        "$candidate_snapshot_sha" ] \
        && [ "$(sha256sum "$FLUTTER_ROOT/bin/cache/flutter.version.json" | awk '{print $1}')" = \
             "$candidate_version_sha" ] \
        && [ "$(sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}')" = \
             "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ] \
        || fail 'candidate Flutter invocation rebuilt or changed its pinned SDK state'
      printf 'FLUTTER_PEER_CANDIDATE_SDK_OK version=%s framework=%s engine=%s dart=%s snapshot_sha256=%s tools=offline-resolved network=none\n' \
        "$RUSTDESK_FLUTTER_VERSION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_FRAMEWORK_REVISION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_ENGINE_REVISION" \
        "$RUSTDESK_FLUTTER_CANDIDATE_DART_VERSION" \
        "$candidate_snapshot_sha"
    fi
    case "$RUSTDESK_PROJECT_LOCK_MODE" in
      source-current)
        [ "$RUSTDESK_FLUTTER_TOOLS_MODE" = offline-resolved ] \
          && [ -z "${RUSTDESK_PROJECT_LOCK_SHA256:-}" ] \
          || fail 'source-current project lock is paired with the wrong Flutter mode or pin'
        ;;
      candidate-pinned)
        [ "$RUSTDESK_FLUTTER_TOOLS_MODE" = offline-resolved ] \
          && [[ "${RUSTDESK_PROJECT_LOCK_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
          || fail 'candidate project lock identity is missing or paired with the wrong Flutter mode'
        verify_regular "$BUILD_SOURCE/scripts/flutter-presentation-candidate-pubspec.lock"
        [ "$(sha256sum "$BUILD_SOURCE/scripts/flutter-presentation-candidate-pubspec.lock" \
              | awk '{print $1}')" = "$RUSTDESK_PROJECT_LOCK_SHA256" ] \
          || fail 'committed candidate project lock differs from its pin'
        install -m 0600 \
          "$BUILD_SOURCE/scripts/flutter-presentation-candidate-pubspec.lock" \
          "$BUILD_SOURCE/flutter/pubspec.lock"
        ;;
      *) fail 'project Pub lock mode differs' ;;
    esac
    pub_lock_before="$(sha256sum "$BUILD_SOURCE/flutter/pubspec.lock" | awk '{print $1}')"
    if [ -n "${RUSTDESK_PROJECT_LOCK_SHA256:-}" ]; then
      [ "$pub_lock_before" = "$RUSTDESK_PROJECT_LOCK_SHA256" ] \
        || fail 'selected project lock differs before offline resolution'
    fi
    (
      cd "$BUILD_SOURCE/flutter"
      rm -rf linux/flutter/ephemeral/.plugin_symlinks \
        .flutter-plugins-dependencies .flutter-plugins
      printf 'FLUTTER_PEER_BUILD_PHASE=project-dart-pub-start network=none timeout_seconds=300\n'
      /usr/bin/timeout --signal=TERM --kill-after=10s 300s \
        dart pub get --offline --enforce-lockfile >/dev/null
      printf 'FLUTTER_PEER_BUILD_PHASE=project-dart-pub-complete network=none\n'
    )
    [ "$(sha256sum "$BUILD_SOURCE/flutter/pubspec.lock" | awk '{print $1}')" = \
      "$pub_lock_before" ] || fail 'project pubspec.lock changed during Dart offline resolution'
    (
      cd "$BUILD_SOURCE/flutter"
      printf 'FLUTTER_PEER_BUILD_PHASE=plugin-injection-start network=none timeout_seconds=300\n'
      /usr/bin/timeout --signal=TERM --kill-after=10s 300s \
        "$REAL_FLUTTER" --suppress-analytics --no-version-check \
          pub get --offline --enforce-lockfile >/dev/null
      printf 'FLUTTER_PEER_BUILD_PHASE=plugin-injection-complete network=none\n'
    )
    [ "$(sha256sum "$BUILD_SOURCE/flutter/pubspec.lock" | awk '{print $1}')" = \
      "$pub_lock_before" ] || fail 'project pubspec.lock changed during Flutter plugin injection'
    for generated_plugin_input in \
      "$BUILD_SOURCE/flutter/linux/flutter/generated_plugins.cmake" \
      "$BUILD_SOURCE/flutter/linux/flutter/generated_plugin_registrant.cc" \
      "$BUILD_SOURCE/flutter/linux/flutter/generated_plugin_registrant.h"; do
      verify_regular "$generated_plugin_input"
    done
    readonly NATIVE_PLUGIN_NAMES=/tmp/flutter-peer-native-plugin-names
    /usr/bin/python3 -I -S - \
      "$BUILD_SOURCE/flutter/linux/flutter/generated_plugins.cmake" \
      > "$NATIVE_PLUGIN_NAMES" <<'PY'
import pathlib
import re
import sys

cmake = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(
    r"list\(APPEND FLUTTER_(?:FFI_)?PLUGIN_LIST\s*\n(.*?)\n\)",
    cmake,
    flags=re.DOTALL,
)
if len(blocks) != 2:
    raise SystemExit("generated native/FFI Flutter plugin lists are absent or ambiguous")
names = []
for block in blocks:
    for line in block.splitlines():
        name = line.strip()
        if not name:
            continue
        if re.fullmatch(r"[A-Za-z0-9_]+", name) is None:
            raise SystemExit(f"generated Flutter plugin name is invalid: {name!r}")
        names.append(name)
if not names:
    raise SystemExit("generated native/FFI Flutter plugin lists are empty")
if len(names) != len(set(names)):
    raise SystemExit("generated native/FFI Flutter plugin lists contain a duplicate")
print(*names, sep="\n")
PY
    verify_regular "$NATIVE_PLUGIN_NAMES"
    plugin_symlink_count=0
    while IFS= read -r plugin_name; do
      plugin_symlink="$BUILD_SOURCE/flutter/linux/flutter/ephemeral/.plugin_symlinks/$plugin_name"
      [ -L "$plugin_symlink" ] \
        || fail "generated native Linux plugin symlink is missing: $plugin_name"
      plugin_target="$(readlink -f -- "$plugin_symlink")" \
        || fail "generated native Linux plugin symlink is dangling: $plugin_name"
      [[ "$plugin_target" == "$PUB_CACHE"/* ]] \
        && [ -d "$plugin_target/linux" ] \
        || fail "generated native Linux plugin escaped the pinned cache or lacks Linux sources: $plugin_name"
      plugin_symlink_count=$((plugin_symlink_count + 1))
    done < "$NATIVE_PLUGIN_NAMES"
    printf 'FLUTTER_PEER_PLUGIN_INPUTS_OK generated=3 native_symlinks=%s lock_unchanged=true network=none\n' \
      "$plugin_symlink_count"
    readonly BUILD_ENTRY_DIRECTORY=$PWD
    {
      cd "$BUILD_SOURCE"
      codegen_log=/tmp/flutter-peer-codegen.log
      set +e
      "$FRB_CODEGEN" --rust-input ./src/flutter_ffi.rs \
        --dart-output ./flutter/lib/generated_bridge.dart \
        --llvm-path "$LLVM_ROOT" \
        --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)" \
        >"$codegen_log" 2>&1
      codegen_status=$?
      set -e
      cat "$codegen_log"
      [ "$codegen_status" -eq 0 ] || fail "Flutter bridge generation exited $codegen_status"
      ! grep -Fq '[SEVERE]' "$codegen_log" \
        || fail 'Flutter bridge generation emitted a severe diagnostic'
      cargo build --locked --offline --features flutter,unix-file-copy-paste \
        --lib --release
      readonly CORE_LIB=$BUILD_SOURCE/target/release/liblibrustdesk.so
      verify_regular "$CORE_LIB"
      readelf --wide --dyn-syms "$CORE_LIB" \
        | grep -Eq '[[:space:]]rustdesk_core_main$' \
        || fail 'Cargo library build does not export rustdesk_core_main'
      CORE_LIB_SHA256="$(sha256sum "$CORE_LIB" | awk '{print $1}')"
      readonly CORE_LIB_SHA256
      cargo build --locked --offline --features flutter,unix-file-copy-paste \
        --example smoke_readiness --release
      [ "$(sha256sum "$CORE_LIB" | awk '{print $1}')" = "$CORE_LIB_SHA256" ] \
        || fail 'example build replaced the verified Rust core library'
      readelf --wide --dyn-syms "$CORE_LIB" \
        | grep -Eq '[[:space:]]rustdesk_core_main$' \
        || fail 'verified Rust core export disappeared after the example build'
      sed -i 's/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g' \
        flutter/lib/generated_bridge.dart
      (
        cd flutter
        rm -rf build/linux
        printf 'FLUTTER_PEER_BUILD_PHASE=flutter-build-start version=%s network=none pub=disabled timeout_seconds=1200\n' \
          "$RUSTDESK_FLUTTER_VERSION"
        /usr/bin/timeout --signal=TERM --kill-after=30s 1200s \
          "$REAL_FLUTTER" --suppress-analytics --no-version-check --verbose \
          build linux --release --no-pub
        printf 'FLUTTER_PEER_BUILD_PHASE=flutter-build-complete version=%s\n' \
          "$RUSTDESK_FLUTTER_VERSION"
      )
    }
    cd "$BUILD_ENTRY_DIRECTORY"
    readonly BUNDLE=$BUILD_SOURCE/flutter/build/linux/x64/release/bundle
    [ -x "$BUNDLE/rustdesk" ] || fail 'exact RustDesk Flutter runner is missing'
    verify_regular "$BUNDLE/lib/librustdesk.so"
    verify_regular "$BUNDLE/lib/libtexture_rgba_renderer_plugin.so"
    [ "$(sha256sum "$BUNDLE/lib/librustdesk.so" | awk '{print $1}')" = \
      "$CORE_LIB_SHA256" ] \
      || fail 'Flutter bundle did not copy the exact verified Rust core library'
    readelf --wide --dyn-syms "$BUNDLE/lib/librustdesk.so" \
      | grep -Eq '[[:space:]]rustdesk_core_main$' \
      || fail 'Rust core library does not export rustdesk_core_main'
    for symbol in FlutterRgbaRendererPluginTryOnRgba FlutterRgbaRendererPluginTryNotifyPending; do
      readelf --wide --dyn-syms "$BUNDLE/lib/libtexture_rgba_renderer_plugin.so" \
        | grep -Eq "[[:space:]]$symbol$" \
        || fail "texture plugin does not export $symbol"
    done
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      "$BUILD_SOURCE/scripts/flutter-peer-source-x11.c" \
      $(pkg-config --cflags --libs x11) -o /out/flutter-peer-source-x11
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      "$BUILD_SOURCE/scripts/flutter-peer-presentation-x11.c" \
      $(pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0) \
      -o /out/flutter-peer-presentation-x11
    cc -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror \
      "$BUILD_SOURCE/scripts/smoke-bind-loopback.c" \
      -Wl,-z,relro,-z,now,-z,noexecstack -ldl -o /out/smoke-bind-loopback.so
    verify_regular "$BUILD_SOURCE/target/release/examples/smoke_readiness"
    cp "$BUILD_SOURCE/target/release/examples/smoke_readiness" /out/smoke-readiness
    mkdir /out/bundle
    cp -a "$BUNDLE/." /out/bundle/
    [ -z "$(find /out -xdev -type l -print -quit)" ] \
      || fail 'build output contains a symlink'
    [ -z "$(find /out -xdev -type f -perm /6000 -print -quit)" ] \
      || fail 'build output contains a setuid or setgid file'
    printf 'rust=%s flutter=%s flutter_tools=%s llvm=%s pub_cache_sha256=%s features=flutter,unix-file-copy-paste app=rustdesk\n' \
      "$RUSTDESK_RUST_VERSION" "$RUSTDESK_FLUTTER_VERSION" \
      "$RUSTDESK_FLUTTER_TOOLS_MODE" "$RUSTDESK_LLVM_VERSION" \
      "$RUSTDESK_EVIDENCE_PUB_CACHE_SHA256" \
      > /out/build.identity
    find /out -xdev -type f -exec chmod 0444 {} +
    chmod 0555 /out/smoke-readiness /out/flutter-peer-source-x11 \
      /out/flutter-peer-presentation-x11 \
      /out/bundle/rustdesk /out/bundle/lib/*.so*
    (
      cd /out
      find bundle -type f -print0 | sort -z | xargs -0 sha256sum
      sha256sum build.identity smoke-bind-loopback.so smoke-readiness flutter-peer-source-x11 \
        flutter-peer-presentation-x11
    ) > /out/manifest.sha256
    chmod 0444 /out/manifest.sha256
    find /out -xdev -type d -exec chmod 0555 {} +
    printf 'FLUTTER_PEER_BUILD_OK rust=%s flutter=%s tools=%s files=%s exact_runner=true exact_core=true\n' \
      "$RUSTDESK_RUST_VERSION" "$RUSTDESK_FLUTTER_VERSION" \
      "$RUSTDESK_FLUTTER_TOOLS_MODE" \
      "$(wc -l < /out/manifest.sha256)"
    ;;

  server)
    verify_runtime_bundle
    verify_machine_identity
    assert_loopback_only_interface
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly APP=/out/bundle/rustdesk
    readonly BIND_SHIM=/out/smoke-bind-loopback.so
    readonly PROBE=/out/smoke-readiness
    readonly SOURCE_FIXTURE=/out/flutter-peer-source-x11
    readonly COORD=/coord
    [ -d "$COORD" ] && [ ! -L "$COORD" ] \
      && [ "$(stat -c '%u:%g:%a' "$COORD")" = "$(id -u):$(id -g):700" ] \
      || fail 'coordination root is not a private current-user directory'
    [ -z "$(find "$COORD" -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'coordination root was not initially empty'
    export DISPLAY=:98 HOME=/tmp/server-home XDG_RUNTIME_DIR=/tmp/server-runtime
    export GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1
    export LD_LIBRARY_PATH="/out/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu"
    mkdir -m 0700 "$HOME" "$XDG_RUNTIME_DIR"
    mkdir -m 1777 /tmp/.X11-unix
    XVFB_PID= XVFB_START= SOURCE_PID= SOURCE_START= SERVER_PID= SERVER_START= SERVER_LOG=
    cleanup_server() {
      local status=$? cleanup_status=0
      trap - EXIT HUP INT TERM
      if [ -n "$SERVER_PID" ] && [ -n "$SERVER_START" ] \
        && "$READY" --is-running "$SERVER_PID" "$SERVER_START"; then
        "$READY" --stop "$SERVER_PID" "$SERVER_START" || cleanup_status=$?
        wait "$SERVER_PID" 2>/dev/null || true
      fi
      if [ -n "$SOURCE_PID" ] && [ -n "$SOURCE_START" ] \
        && "$READY" --is-running "$SOURCE_PID" "$SOURCE_START"; then
        "$READY" --stop "$SOURCE_PID" "$SOURCE_START" || cleanup_status=$?
        wait "$SOURCE_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_server EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_server_generation() {
      local generation=$1
      [ -z "$SERVER_PID" ] && [ -z "$SERVER_START" ] \
        || fail 'cannot overlap controlled-server generations'
      SERVER_LOG="/tmp/server.$generation.log"
      (cd /out/bundle && LD_PRELOAD="$BIND_SHIM" RUST_LOG=info exec "$APP" --server) \
        >"$SERVER_LOG" 2>&1 &
      SERVER_PID=$!
      SERVER_START=$("$READY" --identity "$SERVER_PID")
      wait_process_maps_exact_file "$SERVER_PID" "$SERVER_START" "$BIND_SHIM" \
        || fail "controlled server generation $generation did not map the manifested loopback bind shim"
    }
    stop_server_generation() {
      local generation=$1
      [ -n "$SERVER_PID" ] && [ -n "$SERVER_START" ] \
        || fail 'controlled-server generation authority is absent'
      "$READY" --stop "$SERVER_PID" "$SERVER_START"
      wait "$SERVER_PID" \
        || fail "controlled server generation $generation exited unsuccessfully"
      SERVER_PID=
      SERVER_START=
      [ "$(tcp_listener_count)" -eq 0 ] && [ "$(udp_socket_count)" -eq 0 ] \
        || fail "controlled server generation $generation retained a socket after teardown"
    }
    start_xvfb :98 640x480x24 /tmp/server-xvfb.log
    "$SOURCE_FIXTURE" >/tmp/source.log 2>&1 &
    SOURCE_PID=$!
    SOURCE_START=$("$READY" --identity "$SOURCE_PID")
    "$READY" --wait-log "$SOURCE_PID" "$SOURCE_START" /tmp/source.log \
      FLUTTER_PEER_SOURCE_READY 'peer source readiness'
    start_server_generation 1
    "$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START" "$SERVER_LOG" \
      "$PROBE" "$(id -u)"
    set +e
    password_output="$(printf '%s\n' 'rustdesk-peer-9f2a7c4e' \
      | (cd /out/bundle && "$APP" --password-stdin) 2>&1)"
    password_status=$?
    set -e
    printf '%s\n' "$password_output"
    if [ "$password_status" -ne 0 ]; then
      cat "$SERVER_LOG" >&2
      emit_runtime_logs SERVER "$HOME/.local/share/logs"
      fail "shipped password-stdin command exited $password_status"
    fi
    grep -qx 'Done!' <<<"$password_output" \
      || fail 'password-stdin completion marker differs'
    "$READY" --wait-typed-user-server "$SERVER_PID" "$SERVER_START" "$SERVER_LOG" \
      "$PROBE" "$(id -u)"
    listener_is_exact || fail 'server listener is not exactly 127.0.0.1:21118'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'server network namespace has a UDP socket'
    printf 'server_pid=%s server_start=%s listener=127.0.0.1:21118\n' \
      "$SERVER_PID" "$SERVER_START" > "$COORD/server.ready.tmp"
    mv "$COORD/server.ready.tmp" "$COORD/server.ready"
    echo 'FLUTTER_PEER_SERVER_READY network=none interfaces=lo listener=127.0.0.1:21118 udp=0 parked_then_passworded=true'
    stop_seen=0
    next_generation=2
    for _ in $(seq 1 3000); do
      if [ -f "$COORD/stop" ] && [ ! -L "$COORD/stop" ]; then
        stop_seen=1
        break
      fi
      restart_request="$COORD/server.restart.$next_generation.request"
      if [ -f "$restart_request" ] && [ ! -L "$restart_request" ]; then
        expected_request="generation=$next_generation"
        expected_size=$((${#expected_request} + 1))
        [ "$(stat -c '%u:%g:%a:%h:%s' "$restart_request")" = \
          "$(id -u):$(id -g):600:1:$expected_size" ] \
          && [ "$(<"$restart_request")" = "$expected_request" ] \
          || fail "server restart request $next_generation differs"
        rm -- "$restart_request"
        previous_generation=$((next_generation - 1))
        stop_server_generation "$previous_generation"
        start_server_generation "$next_generation"
        "$READY" --wait-typed-user-server "$SERVER_PID" "$SERVER_START" "$SERVER_LOG" \
          "$PROBE" "$(id -u)"
        listener_is_exact \
          || fail "replacement server generation $next_generation listener differs"
        [ "$(udp_socket_count)" -eq 0 ] \
          || fail "replacement server generation $next_generation opened a UDP socket"
        restart_ready="$COORD/server.restart.$next_generation.ready"
        [ ! -e "$restart_ready" ] && [ ! -L "$restart_ready" ] \
          || fail "server restart receipt $next_generation was not freshly absent"
        printf 'generation=%s\n' "$next_generation" > "$restart_ready.tmp"
        mv "$restart_ready.tmp" "$restart_ready"
        echo "FLUTTER_PEER_SERVER_RESTART_OK generation=$next_generation listener=127.0.0.1:21118 udp=0"
        next_generation=$((next_generation + 1))
        continue
      fi
      "$READY" --is-running "$SERVER_PID" "$SERVER_START" \
        || { cat "$SERVER_LOG" >&2; fail 'server exited before viewer completion'; }
      "$READY" --is-running "$SOURCE_PID" "$SOURCE_START" \
        || { cat /tmp/source.log >&2; fail 'source fixture exited before viewer completion'; }
      sleep 0.1
    done
    [ "$stop_seen" -eq 1 ] || fail 'viewer completion marker timed out'
    completed_restarts=$((next_generation - 2))
    stop_server_generation "$((next_generation - 1))"
    if [ "$(<"$COORD/stop")" != viewer-complete ]; then
      echo 'FLUTTER_PEER_SERVER_DIAGNOSTIC_BEGIN' >&2
      cat "$SERVER_LOG" >&2
      emit_runtime_logs SERVER "$HOME/.local/share/logs"
      echo 'FLUTTER_PEER_SERVER_DIAGNOSTIC_END' >&2
    else
      [ "$completed_restarts" -eq 3 ] \
        || fail "successful viewer completed only $completed_restarts server restarts"
    fi
    "$READY" --stop "$SOURCE_PID" "$SOURCE_START"
    wait "$SOURCE_PID"
    SOURCE_PID= SOURCE_START=
    grep -q '^FLUTTER_PEER_SOURCE_COMPLETE ' /tmp/source.log \
      || { cat /tmp/source.log >&2; fail 'source fixture did not close exactly'; }
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID= XVFB_START=
    [ "$(tcp_listener_count)" -eq 0 ] && [ "$(udp_socket_count)" -eq 0 ] \
      || fail 'server retained an INET listener or UDP socket after teardown'
    printf 'server=joined source=joined xvfb=joined listener=closed replacements=%s\n' \
      "$completed_restarts" \
      > "$COORD/server.result.tmp"
    mv "$COORD/server.result.tmp" "$COORD/server.result"
    printf 'FLUTTER_PEER_SERVER_RUNTIME_OK server=joined source=joined xvfb=joined listener=closed replacements=%s\n' \
      "$completed_restarts"
    trap - EXIT HUP INT TERM
    ;;

  viewer)
    verify_runtime_bundle
    verify_machine_identity
    verify_atspi_closure
    assert_loopback_only_interface
    readonly EXPECTED_PASSWD_ROOT_ENTRY="root:x:0:0:root:/root:/usr/sbin/nologin"
    readonly EXPECTED_PASSWD_ENTRY="rustdesk-evidence:x:$(id -u):$(id -g):RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"
    command -v getent >/dev/null \
      || fail 'viewer runtime lacks passwd-database inspection'
    [ -f /etc/passwd ] && [ ! -L /etc/passwd ] \
      && [ "$(stat -c '%u:%g:%a:%h' /etc/passwd)" = "$(id -u):$(id -g):400:1" ] \
      && [ "$(wc -l < /etc/passwd)" -eq 2 ] \
      && [ "$(sed -n '1p' /etc/passwd)" = "$EXPECTED_PASSWD_ROOT_ENTRY" ] \
      && [ "$(sed -n '2p' /etc/passwd)" = "$EXPECTED_PASSWD_ENTRY" ] \
      && [ "$(getent passwd 0)" = "$EXPECTED_PASSWD_ROOT_ENTRY" ] \
      && [ "$(getent passwd "$(id -u)")" = "$EXPECTED_PASSWD_ENTRY" ] \
      || fail 'viewer passwd identity witness differs'
    [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] \
      || fail 'viewer lacks its private D-Bus accessibility session'
    [ "${DISPLAY:-}" = :99 ] \
      && [ "${HOME:-}" = /tmp/viewer-home ] \
      && [ "${XDG_RUNTIME_DIR:-}" = /tmp/viewer-runtime ] \
      && [ "${XDG_DATA_DIRS:-}" = \
        /atspi-root/usr/share:/usr/local/share:/usr/share ] \
      || fail 'viewer accessibility activation environment differs'
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly APP=/out/bundle/rustdesk
    readonly CONTROLLER=/out/flutter-peer-presentation-x11
    readonly COORD=/coord
    [ -f "$COORD/server.ready" ] && [ ! -L "$COORD/server.ready" ] \
      || fail 'server readiness authority is absent'
    [ ! -e "$COORD/stop" ] && [ ! -L "$COORD/stop" ] \
      || fail 'viewer stop marker was not freshly absent'
    export GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1
    export LD_LIBRARY_PATH="/out/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu"
    [ -d "$HOME" ] && [ ! -L "$HOME" ] \
      && [ "$(stat -c '%u:%g:%a' "$HOME")" = "$(id -u):$(id -g):700" ] \
      && [ -d "$XDG_RUNTIME_DIR" ] && [ ! -L "$XDG_RUNTIME_DIR" ] \
      && [ "$(stat -c '%u:%g:%a' "$XDG_RUNTIME_DIR")" = \
        "$(id -u):$(id -g):700" ] \
      || fail 'viewer private session directories differ'
    mkdir -m 1777 /tmp/.X11-unix
    XVFB_PID= XVFB_START= VIEWER_PID= VIEWER_START=
    cleanup_viewer() {
      local status=$? cleanup_status=0
      trap - EXIT HUP INT TERM
      if [ -n "$VIEWER_PID" ] && [ -n "$VIEWER_START" ] \
        && "$READY" --is-running "$VIEWER_PID" "$VIEWER_START"; then
        "$READY" --stop "$VIEWER_PID" "$VIEWER_START" || cleanup_status=$?
        wait "$VIEWER_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_viewer EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_xvfb :99 1280x800x24 /tmp/viewer-xvfb.log
    listener_is_exact || fail 'shared namespace lost the exact loopback server listener'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'shared namespace has a UDP socket before connect'
    (cd /out/bundle && RUST_LOG=info exec "$APP" --connect 127.0.0.1) \
      >/tmp/viewer.log 2>&1 &
    VIEWER_PID=$!
    VIEWER_START=$("$READY" --identity "$VIEWER_PID")
    set +e
    controller_output="$(timeout --signal=TERM --kill-after=3s 180s \
      "$CONTROLLER" :98 :99 "$VIEWER_PID" 2>&1)"
    controller_status=$?
    set -e
    printf '%s\n' "$controller_output"
    if [ "$controller_status" -ne 0 ]; then
      cat /tmp/viewer.log >&2 || true
      cat /tmp/viewer-xvfb.log >&2 || true
      emit_runtime_logs VIEWER "$HOME/.local/share/logs"
      exit "$controller_status"
    fi
    grep -q '^FLUTTER_PEER_PASSWORD_INPUT_OK characters=22 observed_without_value=true$' \
      <<<"$controller_output" || fail 'complete count-only password input verdict is missing'
    grep -q '^FLUTTER_PEER_PASSWORD_PROMPT_OK accessible=true characters=22 count_only=true retired=true typed_via_xtest=true argv_password=false$' \
      <<<"$controller_output" || fail 'real password prompt verdict is missing'
    [ "$(grep -Ec '^FLUTTER_PEER_BACKGROUND_FRESHNESS_OK cycle=[123] ' \
        <<<"$controller_output")" -eq 3 ] \
      || fail 'three-cycle background freshness evidence is missing'
    [ "$(grep -Ec '^FLUTTER_PEER_FOCUS_RECOVERY_OK cycle=[123] .* real_pointer=true stable_connection=true$' \
        <<<"$controller_output")" -eq 3 ] \
      || fail 'three-cycle stable-connection focus recovery evidence is missing'
    [ "$(grep -Ec '^FLUTTER_PEER_RECONNECT_OK sequence=[123] generation=[234] .* same_window=true cached_credential=true$' \
        <<<"$controller_output")" -eq 3 ] \
      || fail 'three exact viewer reconnect results are missing'
    grep -q '^FLUTTER_PEER_RESOURCE_BOUNDS_OK reconnects=3 focus_cycles=3 threads_growth_max=8 fds_growth_max=16 rss_growth_kib_max=131072$' \
      <<<"$controller_output" || fail 'viewer resource-bound verdict is missing'
    grep -q '^FLUTTER_PEER_PRESENTATION_OK actual_peer=true password_prompt=true capture=true transport=true decode=true flutter_texture=true x11_pixels=true focus_recovery=true background_freshness=true reconnects=3 resources=bounded$' \
      <<<"$controller_output" || fail 'full peer-presentation verdict is missing'
    for _ in $(seq 1 750); do
      "$READY" --is-running "$VIEWER_PID" "$VIEWER_START" || break
      sleep 0.02
    done
    if "$READY" --is-running "$VIEWER_PID" "$VIEWER_START"; then
      fail 'viewer did not retire after its real remote window closed'
    fi
    set +e
    wait "$VIEWER_PID"
    viewer_status=$?
    set -e
    VIEWER_PID= VIEWER_START=
    [ "$viewer_status" -eq 0 ] \
      || { cat /tmp/viewer.log >&2; fail "viewer exited $viewer_status"; }
    if grep -qF 'FlBinaryMessenger without an engine' /tmp/viewer.log; then
      cat /tmp/viewer.log >&2
      fail 'viewer used a Flutter messenger after engine retirement'
    fi
    listener_is_exact || fail 'viewer lifecycle changed the exact server listener'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'viewer lifecycle opened a UDP socket'
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID= XVFB_START=
    printf 'viewer=joined xvfb=joined stable_focus_connection=true reconnects=3 resources=bounded\n' \
      > "$COORD/viewer.result.tmp"
    mv "$COORD/viewer.result.tmp" "$COORD/viewer.result"
    printf 'viewer-complete\n' > "$COORD/stop.tmp"
    mv "$COORD/stop.tmp" "$COORD/stop"
    echo 'FLUTTER_PEER_VIEWER_RUNTIME_OK viewer=joined xvfb=joined stable_focus_connection=true reconnects=3 resources=bounded'
    trap - EXIT HUP INT TERM
    ;;

  *)
    fail 'expected input-check, atspi-check, pub-cache, pub-cache-check, build, server, or viewer stage'
    ;;
esac

#!/usr/bin/env bash
# Exact-commit full RustDesk capture-to-Flutter peer-presentation evidence, admitted only inside
# the authenticated no-NIC verifier VM and confined to its guest-owned Docker daemon.
set -euo pipefail
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
die(){ echo "FATAL: $*" >&2; exit 1; }
[ "$HOST_UID" -ne 0 ] \
  || { echo 'flutter peer presentation smoke refuses host or container-root execution' >&2; exit 1; }
[ "$HOST_GID" -ne 0 ] \
  || { echo 'flutter peer presentation smoke refuses a root primary group' >&2; exit 1; }
for name in DOCKER_HOST DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH \
    DOCKER_TLS_VERIFY DOCKER_TLS; do
  [ -z "${!name:-}" ] || die "caller $name authority is forbidden"
done
readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$VERIFIER_VM_ENTRY_PREFLIGHT" ] && [ ! -L "$VERIFIER_VM_ENTRY_PREFLIGHT" ] \
  && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1 ] \
  || { echo 'flutter peer presentation verifier-VM entry preflight is absent or ambiguous' >&2; exit 1; }
/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"

# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"
umask 077

readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker
readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock
readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config
VERIFIER_VM_MARKER_DOCKER="$(/usr/bin/awk '{ print $2 }' \
  "$VERIFIER_VM_AUTHORITY_ROOT/authority")"
[ "$VERIFIER_VM_MARKER_DOCKER" = "docker=$VERIFIER_VM_DOCKER_VERSION" ] \
  || die 'Flutter peer-presentation guest Docker authority differs from its repository pin'
readonly VERIFIER_VM_MARKER_DOCKER

peer_vm_docker() {
  local status=0
  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
    DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET" \
    DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG" \
    "$VERIFIER_VM_DOCKER_CLIENT" \
      --host "unix://$VERIFIER_VM_DOCKER_SOCKET" \
      --config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?
  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1
  return "$status"
}

PEER_VM_AUTHORITY_SELF_TEST=0
SOURCE_AUTHORITY=git
SUPPLIED_SOURCE_ARCHIVE=
SUPPLIED_SOURCE_COMMIT=
SUPPLIED_SOURCE_TREE=
SUPPLIED_SOURCE_ARCHIVE_SHA256=
case "$#:${1:-}" in
  0:) ;;
  1:--self-test-vm-authority)
    PEER_VM_AUTHORITY_SELF_TEST=1
    ;;
  8:--source-archive)
    [ "$3" = --commit ] && [ "$5" = --tree ] && [ "$7" = --archive-sha256 ] \
      || die 'source-archive authority argument order differs'
    SOURCE_AUTHORITY=archive
    SUPPLIED_SOURCE_ARCHIVE=$2
    SUPPLIED_SOURCE_COMMIT=$4
    SUPPLIED_SOURCE_TREE=$6
    SUPPLIED_SOURCE_ARCHIVE_SHA256=$8
    ;;
  *) die 'accepts no arguments except --self-test-vm-authority or the exact source-archive authority' ;;
esac
readonly SOURCE_AUTHORITY SUPPLIED_SOURCE_ARCHIVE SUPPLIED_SOURCE_COMMIT \
  SUPPLIED_SOURCE_TREE SUPPLIED_SOURCE_ARCHIVE_SHA256
if [ "$PEER_VM_AUTHORITY_SELF_TEST" -eq 1 ]; then
  authority_version="$(peer_vm_docker version \
    --format '{{.Client.Version}}|{{.Server.Version}}')" \
    || die 'Flutter peer-presentation verifier-VM Docker authority self-test failed'
  [ "$authority_version" = \
    "$VERIFIER_VM_DOCKER_VERSION|$VERIFIER_VM_DOCKER_VERSION" ] \
    || die "Flutter peer-presentation verifier-VM Docker version differs: $authority_version"
  printf 'FLUTTER_PEER_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed workload=unexecuted\n' \
    "$HOST_UID" "$HOST_GID" "$VERIFIER_VM_DOCKER_VERSION"
  exit 0
fi

readonly EVIDENCE_PUB_CACHE="$ONLINE_DIR/pub-cache"
readonly EVIDENCE_PUB_CACHE_SHA256="$SHA256_PUB_CACHE_CLOSURE_V1"
readonly XVFB_INPUTS="$ONLINE_DIR/xvfb-debs"
readonly ATSPI_INPUTS="$ONLINE_DIR/atspi-debs"
WORKSPACE=
WORKSPACE_ID=
BUILD_WORK=
SERVER_CID=
declare -a CID_FILES=()

cleanup_container() {
  local cid_file=$1 cid
  [ -f "$cid_file" ] && [ ! -L "$cid_file" ] || return 0
  cid=$(<"$cid_file")
  [[ "$cid" =~ ^[0-9a-f]{64}$ ]] || return 125
  if peer_vm_docker container inspect "$cid" >/dev/null 2>&1; then
    peer_vm_docker rm --force "$cid" >/dev/null || return 125
  fi
  rm -- "$cid_file"
}

cleanup() {
  local status=$? cleanup_status=0 cid_file
  trap - EXIT HUP INT TERM
  for cid_file in "${CID_FILES[@]}"; do
    cleanup_container "$cid_file" || cleanup_status=$?
  done
  if [ -n "$WORKSPACE" ]; then
    if [ -z "$WORKSPACE_ID" ] || [ ! -d "$WORKSPACE" ] || [ -L "$WORKSPACE" ] \
      || [ "$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE" 2>/dev/null)" != "$WORKSPACE_ID" ]; then
      echo "flutter peer presentation smoke: preserving changed workspace: $WORKSPACE" >&2
      cleanup_status=125
    else
      chmod -R u+rwX "$WORKSPACE" 2>/dev/null || cleanup_status=1
      rm -rf -- "$WORKSPACE" || cleanup_status=1
    fi
  fi
  [ "$cleanup_status" -eq 0 ] || status=125
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_cmd git tar sha256sum stat find chmod readlink
SOURCE_COMMIT=
SOURCE_TREE=
if [ "$SOURCE_AUTHORITY" = git ]; then
  assert_clean_worktree
  SOURCE_COMMIT="$(git rev-parse HEAD)"
  SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
else
  case "$SUPPLIED_SOURCE_ARCHIVE" in /*) ;; *) die 'source archive path is not absolute' ;; esac
  [ "$SUPPLIED_SOURCE_ARCHIVE" = "$(readlink -f -- "$SUPPLIED_SOURCE_ARCHIVE" 2>/dev/null)" ] \
    || die 'source archive path is not canonical'
  [[ "$SUPPLIED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    && [[ "$SUPPLIED_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
    && [[ "$SUPPLIED_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die 'supplied source identity is malformed'
  [ -f "$SUPPLIED_SOURCE_ARCHIVE" ] && [ ! -L "$SUPPLIED_SOURCE_ARCHIVE" ] \
    && [ "$(stat -c '%u:%g:%a:%h' -- "$SUPPLIED_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
    || die 'supplied source archive metadata differs'
  [ "$(sha256sum "$SUPPLIED_SOURCE_ARCHIVE" | awk '{print $1}')" = \
    "$SUPPLIED_SOURCE_ARCHIVE_SHA256" ] \
    || die 'supplied source archive digest differs'
  SOURCE_COMMIT=$SUPPLIED_SOURCE_COMMIT
  SOURCE_TREE=$SUPPLIED_SOURCE_TREE
fi
readonly SOURCE_COMMIT SOURCE_TREE
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
  || die 'source commit or tree identity is malformed'

for pin in \
  DEB_BUILDER_IMAGE_ID DEB_BUILDER_CONFIG_ID DEV_CHECK_IMAGE_ID \
  DEV_CHECK_IMAGE_CONFIG_ID \
  RUST_VERSION SHA256_RUST_1_75 SIZE_RUST_1_75 \
  FLUTTER_VERSION SHA256_FLUTTER_3_24_5 SIZE_FLUTTER_3_24_5 \
  LLVM_VERSION SHA256_LLVM_15_0_6 SIZE_LLVM_15_0_6 \
  FLUTTER_RUST_BRIDGE_VERSION SHA256_FLUTTER_TOOLS_LOCK \
  SHA256_CARGO_VENDOR_CLOSURE_V1 SHA256_CARGO_VENDOR_CONFIG \
  SIZE_CARGO_VENDOR_CONFIG SHA256_PUB_CACHE_CLOSURE_V1 \
  SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1 \
  SHA256_FLUTTER_PEER_FRB_CODEGEN SIZE_FLUTTER_PEER_FRB_CODEGEN; do
  [ -n "${!pin:-}" ] || die "pins.env is missing $pin"
done
[ -d "$EVIDENCE_PUB_CACHE" ] && [ ! -L "$EVIDENCE_PUB_CACHE" ] \
  && [ "$(stat -c '%u:%g:%a' "$EVIDENCE_PUB_CACHE")" = \
    "$HOST_UID:$HOST_GID:500" ] \
  || die 'canonical current-lock evidence Pub cache is unavailable or has changed metadata'
[ -d "$XVFB_INPUTS" ] && [ ! -L "$XVFB_INPUTS" ] \
  || die 'authenticated offline Xvfb package closure is missing or ambiguous'
[ -d "$ATSPI_INPUTS" ] && [ ! -L "$ATSPI_INPUTS" ] \
  || die 'authenticated offline AT-SPI package closure is missing or ambiguous'
readonly EVIDENCE_PUB_CACHE_ID="$(stat -c '%d:%i:%u:%g:%a' "$EVIDENCE_PUB_CACHE")"

WORKSPACE="$(mktemp -d /tmp/rustdesk-flutter-peer-presentation.XXXXXXXXXX)"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
  && [ "$(stat -c '%u:%g:%a' "$WORKSPACE")" = "$HOST_UID:$HOST_GID:700" ] \
  || die 'private workspace creation failed'
WORKSPACE_ID="$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE")"
require_exact_local_image() {
  local label=$1 expected=$2 actual
  actual="$(peer_vm_docker image inspect --format '{{.Id}}' "$expected")" \
    || die "$label image is not locally available by its exact content ID"
  [ "$actual" = "$expected" ] \
    || die "$label image content ID differs: expected $expected, got $actual"
}

require_exact_local_image deb-builder "$DEB_BUILDER_CONFIG_ID"
require_exact_local_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"

SOURCE_ARCHIVE=
readonly SOURCE_SNAPSHOT="$WORKSPACE/source"
readonly BUILD_OUTPUT="$WORKSPACE/output"
readonly XVFB_DEBS="$WORKSPACE/xvfb-debs"
readonly XVFB_ROOT="$WORKSPACE/xvfb-root"
readonly ATSPI_DEBS="$WORKSPACE/atspi-debs"
readonly ATSPI_ROOT="$WORKSPACE/atspi-root"
readonly COORD="$WORKSPACE/coord"
readonly EVIDENCE_ONLINE="$WORKSPACE/evidence-online"
readonly BUILD_INPUT_ROOT="$WORKSPACE/build-input-root"
readonly VIEWER_PASSWD="$WORKSPACE/viewer.passwd"
readonly VIEWER_PASSWD_ENTRY="rustdesk-evidence:x:$HOST_UID:$HOST_GID:RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"
readonly SERVER_MACHINE_ID="$WORKSPACE/server.machine-id"
readonly SERVER_MACHINE_ID_VALUE=727573746465736b2d73657276657231
readonly VIEWER_MACHINE_ID="$WORKSPACE/viewer.machine-id"
readonly VIEWER_MACHINE_ID_VALUE=727573746465736b2d76696577657231
[[ "$SERVER_MACHINE_ID_VALUE" =~ ^[0-9a-f]{32}$ ]] \
  && [[ "$VIEWER_MACHINE_ID_VALUE" =~ ^[0-9a-f]{32}$ ]] \
  && [ "$SERVER_MACHINE_ID_VALUE" != "$VIEWER_MACHINE_ID_VALUE" ] \
  || die 'private endpoint machine identities are invalid or shared'
BUILD_WORK="$WORKSPACE/build-work"
mkdir "$SOURCE_SNAPSHOT" "$BUILD_OUTPUT" "$XVFB_DEBS" "$XVFB_ROOT" \
  "$ATSPI_DEBS" "$ATSPI_ROOT" \
  "$COORD" "$EVIDENCE_ONLINE" "$BUILD_INPUT_ROOT" "$BUILD_WORK"
mkdir -p "$BUILD_INPUT_ROOT/cargo-vendor" "$BUILD_INPUT_ROOT/frb-tool/bin" \
  "$BUILD_INPUT_ROOT/vcpkg/installed/x64-linux"
touch "$BUILD_INPUT_ROOT/rust-${RUST_VERSION}.tar.xz" \
  "$BUILD_INPUT_ROOT/flutter-${FLUTTER_VERSION}.tar.xz" \
  "$BUILD_INPUT_ROOT/llvm-${LLVM_VERSION}.tar.xz" \
  "$BUILD_INPUT_ROOT/cargo-vendor-config.toml" \
  "$BUILD_INPUT_ROOT/frb-tool/bin/flutter_rust_bridge_codegen"
chmod -R a-w "$BUILD_INPUT_ROOT"
printf '%s\n' "$VIEWER_PASSWD_ENTRY" > "$VIEWER_PASSWD.tmp"
chmod 0400 "$VIEWER_PASSWD.tmp"
mv "$VIEWER_PASSWD.tmp" "$VIEWER_PASSWD"
[ -f "$VIEWER_PASSWD" ] && [ ! -L "$VIEWER_PASSWD" ] \
  && [ "$(stat -c '%u:%g:%a:%h' "$VIEWER_PASSWD")" = "$HOST_UID:$HOST_GID:400:1" ] \
  && [ "$(<"$VIEWER_PASSWD")" = "$VIEWER_PASSWD_ENTRY" ] \
  || die 'private viewer passwd witness creation failed'
readonly VIEWER_PASSWD_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$VIEWER_PASSWD")"
printf '%s\n' "$SERVER_MACHINE_ID_VALUE" > "$SERVER_MACHINE_ID.tmp"
printf '%s\n' "$VIEWER_MACHINE_ID_VALUE" > "$VIEWER_MACHINE_ID.tmp"
chmod 0400 "$SERVER_MACHINE_ID.tmp" "$VIEWER_MACHINE_ID.tmp"
mv "$SERVER_MACHINE_ID.tmp" "$SERVER_MACHINE_ID"
mv "$VIEWER_MACHINE_ID.tmp" "$VIEWER_MACHINE_ID"
for endpoint in SERVER VIEWER; do
  identity_path="${endpoint}_MACHINE_ID"
  identity_value="${endpoint}_MACHINE_ID_VALUE"
  [ -f "${!identity_path}" ] && [ ! -L "${!identity_path}" ] \
    && [ "$(stat -c '%u:%g:%a:%h:%s' "${!identity_path}")" = \
      "$HOST_UID:$HOST_GID:400:1:33" ] \
    && [ "$(<"${!identity_path}")" = "${!identity_value}" ] \
    || die "$endpoint private machine identity creation failed"
done
readonly SERVER_MACHINE_ID_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$SERVER_MACHINE_ID")"
readonly VIEWER_MACHINE_ID_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$VIEWER_MACHINE_ID")"
if [ "$SOURCE_AUTHORITY" = git ]; then
  SOURCE_ARCHIVE="$WORKSPACE/source.tar"
  git archive --format=tar --output="$SOURCE_ARCHIVE" "$SOURCE_COMMIT"
else
  SOURCE_ARCHIVE=$SUPPLIED_SOURCE_ARCHIVE
fi
readonly SOURCE_ARCHIVE
readonly SOURCE_ARCHIVE_SHA256="$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')"
[ "$SOURCE_AUTHORITY" = git ] \
  || [ "$SOURCE_ARCHIVE_SHA256" = "$SUPPLIED_SOURCE_ARCHIVE_SHA256" ] \
  || die 'source archive changed between admission and extraction'
tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_SNAPSHOT"
chmod -R a-w "$SOURCE_SNAPSHOT"
[ -z "$(find "$SOURCE_SNAPSHOT" -perm /0222 -print -quit)" ] \
  || die 'exact source snapshot remained writable'

run_owned_container() {
  local cid_file=$1 run_status=0 cleanup_status=0
  shift
  CID_FILES+=("$cid_file")
  peer_vm_docker run --cidfile "$cid_file" "$@" || run_status=$?
  cleanup_container "$cid_file" || cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] || return 125
  return "$run_status"
}

inspect_container_contract() {
  local cid=$1 expected_network=$2 label=$3
  local expected_passwd_source= expected_machine_id_source= expected_atspi_mounts=0 mounts_path
  local record_kind source destination writable extra
  local network ipc pid uts privileged read_only user ports devices caps security
  local source_mounts=0 output_mounts=0 xvfb_root_mounts=0 xkbcomp_mounts=0 coord_mounts=0
  local passwd_mounts=0 machine_id_mounts=0
  local atspi_root_mounts=0 atspi_launcher_mounts=0 atspi_registry_mounts=0
  local atspi_defaults_mounts=0 atspi_services_mounts=0
  local receipt_ends=0
  case "$label" in
    server) expected_machine_id_source=$SERVER_MACHINE_ID ;;
    viewer)
      expected_passwd_source=$VIEWER_PASSWD
      expected_machine_id_source=$VIEWER_MACHINE_ID
      expected_atspi_mounts=1
      ;;
    *) die "unknown inspected runtime label: $label" ;;
  esac
  network="$(peer_vm_docker container inspect --format '{{.HostConfig.NetworkMode}}' "$cid")"
  ipc="$(peer_vm_docker container inspect --format '{{.HostConfig.IpcMode}}' "$cid")"
  pid="$(peer_vm_docker container inspect --format '{{.HostConfig.PidMode}}' "$cid")"
  uts="$(peer_vm_docker container inspect --format '{{.HostConfig.UTSMode}}' "$cid")"
  privileged="$(peer_vm_docker container inspect --format '{{.HostConfig.Privileged}}' "$cid")"
  read_only="$(peer_vm_docker container inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
  user="$(peer_vm_docker container inspect --format '{{.Config.User}}' "$cid")"
  ports="$(peer_vm_docker container inspect --format '{{json .HostConfig.PortBindings}}' "$cid")"
  devices="$(peer_vm_docker container inspect --format '{{json .HostConfig.Devices}}' "$cid")"
  caps="$(peer_vm_docker container inspect --format '{{json .HostConfig.CapDrop}}' "$cid")"
  security="$(peer_vm_docker container inspect --format '{{json .HostConfig.SecurityOpt}}' "$cid")"
  [ "$network" = "$expected_network" ] || die "$label network mode differs: $network"
  { [ -z "$ipc" ] || [ "$ipc" = private ]; } || die "$label IPC namespace is not private"
  [ -z "$pid" ] && [ -z "$uts" ] || die "$label shares a PID or UTS namespace"
  [ "$privileged" = false ] && [ "$read_only" = true ] \
    || die "$label privilege/read-only-root contract differs"
  [ "$user" = "$HOST_UID:$HOST_GID" ] || die "$label numeric user differs: $user"
  { [ "$ports" = null ] || [ "$ports" = '{}' ]; } || die "$label publishes a port"
  { [ "$devices" = null ] || [ "$devices" = '[]' ]; } || die "$label receives a host device"
  [ "$caps" = '["ALL"]' ] || die "$label does not drop all capabilities"
  case "$security" in
    '["no-new-privileges"]'|'["no-new-privileges:true"]') ;;
    *) die "$label lacks the exact no-new-privileges contract" ;;
  esac
  mounts_path="$WORKSPACE/$label.mounts.tsv"
  peer_vm_docker container inspect \
    --format '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}{{printf "end"}}' \
    "$cid" > "$mounts_path"
  while IFS=$'\t' read -r record_kind source destination writable extra \
    || [ -n "${record_kind:-}${source:-}${destination:-}${writable:-}${extra:-}" ]; do
    if [ "$record_kind" = end ]; then
      [ -z "$source" ] && [ -z "$destination" ] && [ -z "$writable" ] \
        && [ -z "$extra" ] && [ "$receipt_ends" -eq 0 ] \
        || die "$label inspection produced a malformed mount terminator"
      receipt_ends=1
      continue
    fi
    [ "$record_kind" = bind ] && [ "$receipt_ends" -eq 0 ] \
      && [ -n "$source" ] && [ -n "$destination" ] && [ -n "$writable" ] && [ -z "$extra" ] \
      || die "$label inspection produced a malformed mount receipt"
    [[ "$source" != */docker.sock ]] && [[ "$source" != /dev/* ]] \
      || die "$label receives an unsafe mount: $source"
    case "$destination" in
      /source)
        [ "$source" = "$SOURCE_SNAPSHOT" ] && [ "$writable" = false ] \
          || die "$label source mount contract differs"
        source_mounts=$((source_mounts + 1))
        ;;
      /out)
        [ "$source" = "$BUILD_OUTPUT" ] && [ "$writable" = false ] \
          || die "$label output mount contract differs"
        output_mounts=$((output_mounts + 1))
        ;;
      /xvfb-root)
        [ "$source" = "$XVFB_ROOT" ] && [ "$writable" = false ] \
          || die "$label Xvfb root mount contract differs"
        xvfb_root_mounts=$((xvfb_root_mounts + 1))
        ;;
      /usr/bin/xkbcomp)
        [ "$source" = "$XVFB_ROOT/usr/bin/xkbcomp" ] && [ "$writable" = false ] \
          || die "$label xkbcomp mount contract differs"
        xkbcomp_mounts=$((xkbcomp_mounts + 1))
        ;;
      /coord)
        [ "$source" = "$COORD" ] && [ "$writable" = true ] \
          || die "$label coordination mount contract differs"
        coord_mounts=$((coord_mounts + 1))
        ;;
      /atspi-root)
        [ "$source" = "$ATSPI_ROOT" ] && [ "$writable" = false ] \
          || die "$label AT-SPI root mount contract differs"
        atspi_root_mounts=$((atspi_root_mounts + 1))
        ;;
      /usr/libexec/at-spi-bus-launcher)
        [ "$source" = "$ATSPI_ROOT/usr/libexec/at-spi-bus-launcher" ] \
          && [ "$writable" = false ] \
          || die "$label AT-SPI launcher mount contract differs"
        atspi_launcher_mounts=$((atspi_launcher_mounts + 1))
        ;;
      /usr/libexec/at-spi2-registryd)
        [ "$source" = "$ATSPI_ROOT/usr/libexec/at-spi2-registryd" ] \
          && [ "$writable" = false ] \
          || die "$label AT-SPI registry mount contract differs"
        atspi_registry_mounts=$((atspi_registry_mounts + 1))
        ;;
      /usr/share/defaults/at-spi2)
        [ "$source" = "$ATSPI_ROOT/usr/share/defaults/at-spi2" ] \
          && [ "$writable" = false ] \
          || die "$label AT-SPI defaults mount contract differs"
        atspi_defaults_mounts=$((atspi_defaults_mounts + 1))
        ;;
      /usr/share/dbus-1/accessibility-services)
        [ "$source" = "$ATSPI_ROOT/usr/share/dbus-1/accessibility-services" ] \
          && [ "$writable" = false ] \
          || die "$label AT-SPI services mount contract differs"
        atspi_services_mounts=$((atspi_services_mounts + 1))
        ;;
      /etc/passwd)
        [ -n "$expected_passwd_source" ] && [ "$source" = "$expected_passwd_source" ] \
          && [ "$writable" = false ] \
          || die "$label passwd witness source or read-only contract differs"
        passwd_mounts=$((passwd_mounts + 1))
        ;;
      /etc/machine-id)
        [ "$source" = "$expected_machine_id_source" ] && [ "$writable" = false ] \
          || die "$label machine-id witness source or read-only contract differs"
        machine_id_mounts=$((machine_id_mounts + 1))
        ;;
      *) die "$label receives an unexpected mount destination: $destination" ;;
    esac
  done < "$mounts_path"
  [ "$receipt_ends" -eq 1 ] && [ "$source_mounts" -eq 1 ] \
    && [ "$output_mounts" -eq 1 ] && [ "$xvfb_root_mounts" -eq 1 ] \
    && [ "$xkbcomp_mounts" -eq 1 ] && [ "$coord_mounts" -eq 1 ] \
    && [ "$machine_id_mounts" -eq 1 ] \
    || die "$label runtime mount cardinality differs"
  if [ -n "$expected_passwd_source" ]; then
    [ "$passwd_mounts" -eq 1 ] || die 'viewer passwd witness mount cardinality differs'
  else
    [ "$passwd_mounts" -eq 0 ] || die 'non-viewer container received a passwd witness mount'
  fi
  [ "$atspi_root_mounts" -eq "$expected_atspi_mounts" ] \
    && [ "$atspi_launcher_mounts" -eq "$expected_atspi_mounts" ] \
    && [ "$atspi_registry_mounts" -eq "$expected_atspi_mounts" ] \
    && [ "$atspi_defaults_mounts" -eq "$expected_atspi_mounts" ] \
    && [ "$atspi_services_mounts" -eq "$expected_atspi_mounts" ] \
    || die "$label AT-SPI mount cardinality differs"
}

run_input_check() {
  local cid_file=$1
  run_owned_container "$cid_file" \
    --pull=never --network=none --read-only \
    --user "$HOST_UID:$HOST_GID" \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=64 --memory=2g --memory-swap=2g --cpus=2 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m \
    --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
    --env "RUSTDESK_RUST_VERSION=$RUST_VERSION" \
    --env "RUSTDESK_RUST_SHA256=$SHA256_RUST_1_75" \
    --env "RUSTDESK_RUST_SIZE=$SIZE_RUST_1_75" \
    --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
    --env "RUSTDESK_FLUTTER_SHA256=$SHA256_FLUTTER_3_24_5" \
    --env "RUSTDESK_FLUTTER_SIZE=$SIZE_FLUTTER_3_24_5" \
    --env "RUSTDESK_LLVM_VERSION=$LLVM_VERSION" \
    --env "RUSTDESK_LLVM_SHA256=$SHA256_LLVM_15_0_6" \
    --env "RUSTDESK_LLVM_SIZE=$SIZE_LLVM_15_0_6" \
    --env "RUSTDESK_FRB_VERSION=$FLUTTER_RUST_BRIDGE_VERSION" \
    --env "RUSTDESK_FRB_SHA256=$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
    --env "RUSTDESK_FRB_SIZE=$SIZE_FLUTTER_PEER_FRB_CODEGEN" \
    --env "RUSTDESK_CARGO_VENDOR_SHA256=$SHA256_CARGO_VENDOR_CLOSURE_V1" \
    --env "RUSTDESK_CARGO_VENDOR_CONFIG_SHA256=$SHA256_CARGO_VENDOR_CONFIG" \
    --env "RUSTDESK_CARGO_VENDOR_CONFIG_SIZE=$SIZE_CARGO_VENDOR_CONFIG" \
    --env "RUSTDESK_VCPKG_X64_LINUX_SHA256=$SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1" \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh input-check
}

echo '== independently verify every persistent input consumed by the build =='
run_input_check "$WORKSPACE/input-pre.cid"

echo '== verify and extract the exact offline Xvfb closure in one networkless non-root container =='
run_owned_container "$WORKSPACE/xvfb.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/work,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_INPUTS,target=/xvfb-inputs,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_DEBS,target=/xvfb-debs,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /work/scripts/smoke-xvfb-prepare.sh

echo '== verify and extract the exact offline AT-SPI closure in one networkless non-root container =='
run_owned_container "$WORKSPACE/atspi-prepare.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/work,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_INPUTS,target=/atspi-inputs,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_DEBS,target=/atspi-debs,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT,target=/atspi-root,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /work/scripts/smoke-atspi-prepare.sh
readonly ATSPI_ROOT_ID="$(stat -c '%d:%i:%u:%g:%a' "$ATSPI_ROOT"):$(
  sha256sum "$ATSPI_ROOT/closure.identity" | awk '{print $1}'
)"

echo '== prove private D-Bus and AT-SPI activation before the expensive build =='
atspi_check_status=0
run_owned_container "$WORKSPACE/atspi-check.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=96 --memory=1g --memory-swap=1g --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT,target=/atspi-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/libexec/at-spi-bus-launcher,target=/usr/libexec/at-spi-bus-launcher,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/libexec/at-spi2-registryd,target=/usr/libexec/at-spi2-registryd,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/share/defaults/at-spi2,target=/usr/share/defaults/at-spi2,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/share/dbus-1/accessibility-services,target=/usr/share/dbus-1/accessibility-services,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$VIEWER_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled" \
  --env DISPLAY=:97 \
  --env HOME=/tmp/atspi-home \
  --env XDG_RUNTIME_DIR=/tmp/atspi-runtime \
  --env XDG_DATA_DIRS=/atspi-root/usr/share:/usr/local/share:/usr/share \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-private-atspi-session.sh atspi-check \
  > "$WORKSPACE/atspi-check.log" 2>&1 || atspi_check_status=$?
cat "$WORKSPACE/atspi-check.log"
[ "$atspi_check_status" -eq 0 ] \
  || die "private AT-SPI activation preflight exited $atspi_check_status"
grep -q '^FLUTTER_PEER_ATSPI_RUNTIME_OK session_bus=private accessibility_bus=unix launcher=exact registry=exact x11=joined inet=0 udp=0$' \
  "$WORKSPACE/atspi-check.log" || die 'private AT-SPI activation verdict is missing'

echo '== copy and reverify the canonical exact-current Pub cache without mutating it =='
run_owned_container "$WORKSPACE/pub-cache.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=128 --memory=2g --memory-swap=2g --cpus=2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$EVIDENCE_ONLINE,target=/evidence-online,bind-recursive=disabled" \
  --env "RUSTDESK_EVIDENCE_PUB_CACHE_SHA256=$EVIDENCE_PUB_CACHE_SHA256" \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh pub-cache
[ "$(stat -c '%d:%i:%u:%g:%a' "$EVIDENCE_PUB_CACHE")" = "$EVIDENCE_PUB_CACHE_ID" ] \
  || die 'canonical evidence Pub-cache identity changed while copied'

echo '== build one exact full RustDesk Linux Flutter bundle without packaging =='
run_owned_container "$WORKSPACE/build.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=1024 --memory=16g --memory-swap=16g --cpus=4 \
  --ulimit nofile=8192:8192 --ulimit fsize=4294967296:4294967296 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz,target=/online/rust-${RUST_VERSION}.tar.xz,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz,target=/online/flutter-${FLUTTER_VERSION}.tar.xz,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/llvm-${LLVM_VERSION}.tar.xz,target=/online/llvm-${LLVM_VERSION}.tar.xz,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/cargo-vendor,target=/online/cargo-vendor,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/cargo-vendor-config.toml,target=/online/cargo-vendor-config.toml,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/frb-tool/bin/flutter_rust_bridge_codegen,target=/online/frb-tool/bin/flutter_rust_bridge_codegen,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ONLINE_DIR/vcpkg/installed/x64-linux,target=/online/vcpkg/installed/x64-linux,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$EVIDENCE_ONLINE,target=/evidence-online,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_WORK,target=/build-work,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_OUTPUT,target=/out,bind-recursive=disabled" \
  --env "RUSTDESK_RUST_VERSION=$RUST_VERSION" \
  --env "RUSTDESK_RUST_SHA256=$SHA256_RUST_1_75" \
  --env "RUSTDESK_RUST_SIZE=$SIZE_RUST_1_75" \
  --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
  --env "RUSTDESK_FLUTTER_SHA256=$SHA256_FLUTTER_3_24_5" \
  --env "RUSTDESK_FLUTTER_SIZE=$SIZE_FLUTTER_3_24_5" \
  --env "RUSTDESK_LLVM_VERSION=$LLVM_VERSION" \
  --env "RUSTDESK_LLVM_SHA256=$SHA256_LLVM_15_0_6" \
  --env "RUSTDESK_LLVM_SIZE=$SIZE_LLVM_15_0_6" \
  --env "RUSTDESK_FRB_SHA256=$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
  --env "RUSTDESK_FRB_SIZE=$SIZE_FLUTTER_PEER_FRB_CODEGEN" \
  --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
  --env "RUSTDESK_EVIDENCE_PUB_CACHE_SHA256=$EVIDENCE_PUB_CACHE_SHA256" \
  "$DEB_BUILDER_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh build

echo '== reverify the exact evidence Pub-cache copy after the offline build =='
run_owned_container "$WORKSPACE/pub-cache-post.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$EVIDENCE_ONLINE,target=/evidence-online,readonly,bind-recursive=disabled" \
  --env "RUSTDESK_EVIDENCE_PUB_CACHE_SHA256=$EVIDENCE_PUB_CACHE_SHA256" \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh pub-cache-check
[ "$(stat -c '%d:%i:%u:%g:%a' "$EVIDENCE_PUB_CACHE")" = "$EVIDENCE_PUB_CACHE_ID" ] \
  || die 'canonical evidence Pub-cache identity changed during the build'

chmod -R u+rwX "$BUILD_WORK"
rm -rf -- "$BUILD_WORK"
BUILD_WORK=

echo '== start the exact controlled peer in an external-interface-free namespace =='
readonly SERVER_CID_FILE="$WORKSPACE/server.cid"
CID_FILES+=("$SERVER_CID_FILE")
peer_vm_docker run --detach --cidfile "$SERVER_CID_FILE" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=384 --memory=4g --memory-swap=4g --cpus=2 \
  --ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_OUTPUT,target=/out,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$COORD,target=/coord,bind-recursive=disabled" \
  --mount "type=bind,source=$SERVER_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh server \
  >/dev/null
SERVER_CID=$(<"$SERVER_CID_FILE")
[[ "$SERVER_CID" =~ ^[0-9a-f]{64}$ ]] || die 'server container identity is malformed'
inspect_container_contract "$SERVER_CID" none server
server_ready=0
for _ in $(seq 1 900); do
  if [ -f "$COORD/server.ready" ] && [ ! -L "$COORD/server.ready" ]; then
    server_ready=1
    break
  fi
  [ "$(peer_vm_docker inspect --format '{{.State.Running}}' "$SERVER_CID")" = true ] || break
  sleep 0.1
done
if [ "$server_ready" -ne 1 ]; then
  peer_vm_docker logs "$SERVER_CID" > "$WORKSPACE/server.log" 2>&1 || true
  cat "$WORKSPACE/server.log" >&2
  die 'controlled peer did not become ready'
fi

echo '== authenticate through the real prompt and observe current pixels across focus loss =='
readonly VIEWER_CID_FILE="$WORKSPACE/viewer.cid"
CID_FILES+=("$VIEWER_CID_FILE")
set +e
peer_vm_docker run --cidfile "$VIEWER_CID_FILE" \
  --pull=never --network="container:$SERVER_CID" --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=384 --memory=4g --memory-swap=4g --cpus=2 \
  --ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_OUTPUT,target=/out,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$COORD,target=/coord,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT,target=/atspi-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/libexec/at-spi-bus-launcher,target=/usr/libexec/at-spi-bus-launcher,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/libexec/at-spi2-registryd,target=/usr/libexec/at-spi2-registryd,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/share/defaults/at-spi2,target=/usr/share/defaults/at-spi2,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$ATSPI_ROOT/usr/share/dbus-1/accessibility-services,target=/usr/share/dbus-1/accessibility-services,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$VIEWER_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled" \
  --env DISPLAY=:99 \
  --env HOME=/tmp/viewer-home \
  --env XDG_RUNTIME_DIR=/tmp/viewer-runtime \
  --env XDG_DATA_DIRS=/atspi-root/usr/share:/usr/local/share:/usr/share \
  "$DEV_CHECK_IMAGE_CONFIG_ID" \
  bash --noprofile --norc /source/scripts/smoke-private-atspi-session.sh viewer \
  > "$WORKSPACE/viewer.log" 2>&1
viewer_status=$?
set -e
VIEWER_CID=$(<"$VIEWER_CID_FILE")
[[ "$VIEWER_CID" =~ ^[0-9a-f]{64}$ ]] || die 'viewer container identity is malformed'
inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer
[ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$VIEWER_PASSWD")" = "$VIEWER_PASSWD_ID" ] \
  && [ "$(<"$VIEWER_PASSWD")" = "$VIEWER_PASSWD_ENTRY" ] \
  || die 'private viewer passwd witness changed during runtime'
[ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$SERVER_MACHINE_ID")" = "$SERVER_MACHINE_ID_ID" ] \
  && [ "$(<"$SERVER_MACHINE_ID")" = "$SERVER_MACHINE_ID_VALUE" ] \
  && [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$VIEWER_MACHINE_ID")" = "$VIEWER_MACHINE_ID_ID" ] \
  && [ "$(<"$VIEWER_MACHINE_ID")" = "$VIEWER_MACHINE_ID_VALUE" ] \
  || die 'private endpoint machine identity changed during runtime'
[ "$(stat -c '%d:%i:%u:%g:%a' "$ATSPI_ROOT"):$(
    sha256sum "$ATSPI_ROOT/closure.identity" | awk '{print $1}'
  )" = "$ATSPI_ROOT_ID" ] \
  || die 'sealed AT-SPI runtime identity changed during runtime'
cat "$WORKSPACE/viewer.log"
if [ ! -f "$COORD/stop" ] && [ ! -L "$COORD/stop" ]; then
  printf 'outer-retirement-after-viewer-status=%s\n' "$viewer_status" > "$COORD/stop.tmp"
  mv "$COORD/stop.tmp" "$COORD/stop"
fi

server_stopped=0
for _ in $(seq 1 900); do
  if [ "$(peer_vm_docker inspect --format '{{.State.Running}}' "$SERVER_CID")" = false ]; then
    server_stopped=1
    break
  fi
  sleep 0.1
done
peer_vm_docker logs "$SERVER_CID" > "$WORKSPACE/server.log" 2>&1 || true
cat "$WORKSPACE/server.log"
[ "$server_stopped" -eq 1 ] || die 'controlled peer container did not retire'
server_status="$(peer_vm_docker inspect --format '{{.State.ExitCode}}' "$SERVER_CID")"
[[ "$server_status" =~ ^[0-9]+$ ]] || die 'server exit status is malformed'

[ "$viewer_status" -eq 0 ] || exit "$viewer_status"
[ "$server_status" -eq 0 ] || die "controlled peer stage exited $server_status"
grep -q '^FLUTTER_PEER_VIEWER_RUNTIME_OK viewer=joined xvfb=joined stable_connection=true$' \
  "$WORKSPACE/viewer.log" || die 'viewer terminal verdict is missing'
grep -q '^FLUTTER_PEER_SERVER_RUNTIME_OK server=joined source=joined xvfb=joined listener=closed$' \
  "$WORKSPACE/server.log" || die 'server terminal verdict is missing'
[ "$(<"$COORD/viewer.result")" = 'viewer=joined xvfb=joined stable_connection=true' ] \
  || die 'viewer result receipt differs'
[ "$(<"$COORD/server.result")" = 'server=joined source=joined xvfb=joined listener=closed' ] \
  || die 'server result receipt differs'

echo '== independently reverify every persistent build input after runtime =='
run_input_check "$WORKSPACE/input-post.cid"
if [ "$SOURCE_AUTHORITY" = git ]; then
  [ "$(git rev-parse HEAD)" = "$SOURCE_COMMIT" ] \
    && [ "$(git rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
    || die 'repository identity changed during the probe'
  assert_clean_worktree
  git archive --format=tar --output="$WORKSPACE/source-after.tar" "$SOURCE_COMMIT"
  [ "$(sha256sum "$WORKSPACE/source-after.tar" | awk '{print $1}')" = \
    "$SOURCE_ARCHIVE_SHA256" ] || die 'exact source archive changed during the probe'
else
  [ "$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')" = \
    "$SOURCE_ARCHIVE_SHA256" ] || die 'supplied source archive changed during the probe'
fi
printf 'FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=%s tree=%s archive_sha256=%s scope=linux-x11-full-peer-only network=owned-none-namespace\n' \
  "$SOURCE_COMMIT" "$SOURCE_TREE" "$SOURCE_ARCHIVE_SHA256"

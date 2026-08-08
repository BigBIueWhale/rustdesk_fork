#!/usr/bin/env bash
# Exact-commit full RustDesk capture-to-Flutter peer-presentation evidence, confined to Docker.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"
umask 077

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
readonly EVIDENCE_PUB_CACHE="$ONLINE_DIR/pub-cache"
readonly EVIDENCE_PUB_CACHE_SHA256="$SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1"
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
  if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
    && local_docker container inspect "$cid" >/dev/null 2>&1; then
    local_docker rm --force "$cid" >/dev/null || return 125
  fi
  rm -- "$cid_file"
}

cleanup() {
  local status=$? cleanup_status=0 cid_file
  trap - EXIT HUP INT TERM
  for cid_file in "${CID_FILES[@]}"; do
    cleanup_container "$cid_file" || cleanup_status=$?
  done
  if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then
    remove_local_docker_authority || cleanup_status=$?
  fi
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

require_cmd git tar sha256sum stat find chmod docker
[ "$HOST_UID" -ne 0 ] || die 'flutter peer presentation smoke refuses host root'
[ "$HOST_GID" -ne 0 ] || die 'flutter peer presentation smoke refuses a root primary group'
assert_clean_worktree
readonly SOURCE_COMMIT="$(git rev-parse HEAD)"
readonly SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
  || die 'source commit or tree identity is malformed'

for pin in \
  DEB_BUILDER_IMAGE_ID DEV_CHECK_IMAGE_ID \
  RUST_VERSION SHA256_RUST_1_75 SIZE_RUST_1_75 \
  FLUTTER_VERSION SHA256_FLUTTER_3_24_5 SIZE_FLUTTER_3_24_5 \
  LLVM_VERSION SHA256_LLVM_15_0_6 SIZE_LLVM_15_0_6 \
  FLUTTER_RUST_BRIDGE_VERSION SHA256_FLUTTER_TOOLS_LOCK \
  SHA256_CARGO_VENDOR_CLOSURE_V1 SHA256_CARGO_VENDOR_CONFIG \
  SIZE_CARGO_VENDOR_CONFIG SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1 \
  SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1 \
  SHA256_FLUTTER_PEER_FRB_CODEGEN SIZE_FLUTTER_PEER_FRB_CODEGEN; do
  [ -n "${!pin:-}" ] || die "pins.env is missing $pin"
done
[ -d "$EVIDENCE_PUB_CACHE" ] && [ ! -L "$EVIDENCE_PUB_CACHE" ] \
  && [ "$(stat -c '%u:%g:%a' "$EVIDENCE_PUB_CACHE")" = \
    "$HOST_UID:$HOST_GID:500" ] \
  || die 'canonical current-lock evidence Pub cache is unavailable or has changed metadata'
readonly EVIDENCE_PUB_CACHE_ID="$(stat -c '%d:%i:%u:%g:%a' "$EVIDENCE_PUB_CACHE")"

WORKSPACE="$(mktemp -d /tmp/rustdesk-flutter-peer-presentation.XXXXXXXXXX)"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
  && [ "$(stat -c '%u:%g:%a' "$WORKSPACE")" = "$HOST_UID:$HOST_GID:700" ] \
  || die 'private workspace creation failed'
WORKSPACE_ID="$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE")"
initialize_local_docker_authority "$WORKSPACE/docker-config" \
  'flutter-peer-presentation-smoke'

require_exact_local_image() {
  local label=$1 expected=$2 actual
  actual="$(local_docker image inspect --format '{{.Id}}' "$expected")" \
    || die "$label image is not locally available by its exact content ID"
  [ "$actual" = "$expected" ] \
    || die "$label image content ID differs: expected $expected, got $actual"
}

require_exact_local_image deb-builder "$DEB_BUILDER_IMAGE_ID"
require_exact_local_image devcheck "$DEV_CHECK_IMAGE_ID"

readonly SOURCE_ARCHIVE="$WORKSPACE/source.tar"
readonly SOURCE_SNAPSHOT="$WORKSPACE/source"
readonly BUILD_OUTPUT="$WORKSPACE/output"
readonly XVFB_DEBS="$WORKSPACE/xvfb-debs"
readonly XVFB_ROOT="$WORKSPACE/xvfb-root"
readonly COORD="$WORKSPACE/coord"
readonly EVIDENCE_ONLINE="$WORKSPACE/evidence-online"
readonly BUILD_INPUT_ROOT="$WORKSPACE/build-input-root"
readonly VIEWER_PASSWD="$WORKSPACE/viewer.passwd"
readonly VIEWER_PASSWD_ENTRY="rustdesk-evidence:x:$HOST_UID:$HOST_GID:RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"
BUILD_WORK="$WORKSPACE/build-work"
mkdir "$SOURCE_SNAPSHOT" "$BUILD_OUTPUT" "$XVFB_DEBS" "$XVFB_ROOT" \
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
git archive --format=tar --output="$SOURCE_ARCHIVE" "$SOURCE_COMMIT"
readonly SOURCE_ARCHIVE_SHA256="$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')"
tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_SNAPSHOT"
chmod -R a-w "$SOURCE_SNAPSHOT"

run_owned_container() {
  local cid_file=$1 run_status=0 cleanup_status=0
  shift
  CID_FILES+=("$cid_file")
  local_docker run --cidfile "$cid_file" "$@" || run_status=$?
  cleanup_container "$cid_file" || cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] || return 125
  return "$run_status"
}

inspect_container_contract() {
  local cid=$1 expected_network=$2 label=$3
  local expected_passwd_source= mounts_path source destination writable extra
  local network ipc pid uts privileged read_only user ports devices caps security
  local passwd_mounts=0
  case "$label" in
    server) ;;
    viewer) expected_passwd_source=$VIEWER_PASSWD ;;
    *) die "unknown inspected runtime label: $label" ;;
  esac
  network="$(local_docker container inspect --format '{{.HostConfig.NetworkMode}}' "$cid")"
  ipc="$(local_docker container inspect --format '{{.HostConfig.IpcMode}}' "$cid")"
  pid="$(local_docker container inspect --format '{{.HostConfig.PidMode}}' "$cid")"
  uts="$(local_docker container inspect --format '{{.HostConfig.UTSMode}}' "$cid")"
  privileged="$(local_docker container inspect --format '{{.HostConfig.Privileged}}' "$cid")"
  read_only="$(local_docker container inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
  user="$(local_docker container inspect --format '{{.Config.User}}' "$cid")"
  ports="$(local_docker container inspect --format '{{json .HostConfig.PortBindings}}' "$cid")"
  devices="$(local_docker container inspect --format '{{json .HostConfig.Devices}}' "$cid")"
  caps="$(local_docker container inspect --format '{{json .HostConfig.CapDrop}}' "$cid")"
  security="$(local_docker container inspect --format '{{json .HostConfig.SecurityOpt}}' "$cid")"
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
  local_docker container inspect \
    --format '{{range .Mounts}}{{printf "%s\t%s\t%t\n" .Source .Destination .RW}}{{end}}' \
    "$cid" > "$mounts_path"
  while IFS=$'\t' read -r source destination writable extra \
    || [ -n "${source:-}${destination:-}${writable:-}${extra:-}" ]; do
    [ -n "$source" ] && [ -n "$destination" ] && [ -n "$writable" ] && [ -z "$extra" ] \
      || die "$label inspection produced a malformed mount receipt"
    [[ "$source" != */docker.sock ]] && [[ "$source" != /dev/* ]] \
      || die "$label receives an unsafe mount: $source"
    if [ "$destination" = /etc/passwd ]; then
      passwd_mounts=$((passwd_mounts + 1))
      [ -n "$expected_passwd_source" ] && [ "$source" = "$expected_passwd_source" ] \
        && [ "$writable" = false ] \
        || die "$label passwd witness source or read-only contract differs"
    fi
  done < "$mounts_path"
  if [ -n "$expected_passwd_source" ]; then
    [ "$passwd_mounts" -eq 1 ] || die 'viewer passwd witness mount cardinality differs'
  else
    [ "$passwd_mounts" -eq 0 ] || die 'non-viewer container received a passwd witness mount'
  fi
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
    "$DEV_CHECK_IMAGE_ID" \
    bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh input-check
}

echo '== independently verify every persistent input consumed by the build =='
run_input_check "$WORKSPACE/input-pre.cid"

echo '== acquire the exact five-package Xvfb closure in one non-root producer =='
run_owned_container "$WORKSPACE/xvfb.cid" \
  --pull=never --network=bridge --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/work,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_DEBS,target=/xvfb-debs,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_ID" \
  bash --noprofile --norc /work/scripts/smoke-xvfb-prepare.sh

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
  "$DEV_CHECK_IMAGE_ID" \
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
  --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
  --env "RUSTDESK_EVIDENCE_PUB_CACHE_SHA256=$EVIDENCE_PUB_CACHE_SHA256" \
  "$DEB_BUILDER_IMAGE_ID" \
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
  "$DEV_CHECK_IMAGE_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh pub-cache-check
[ "$(stat -c '%d:%i:%u:%g:%a' "$EVIDENCE_PUB_CACHE")" = "$EVIDENCE_PUB_CACHE_ID" ] \
  || die 'canonical evidence Pub-cache identity changed during the build'

chmod -R u+rwX "$BUILD_WORK"
rm -rf -- "$BUILD_WORK"
BUILD_WORK=

echo '== start the exact controlled peer in an external-interface-free namespace =='
readonly SERVER_CID_FILE="$WORKSPACE/server.cid"
CID_FILES+=("$SERVER_CID_FILE")
local_docker run --detach --cidfile "$SERVER_CID_FILE" \
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
  "$DEV_CHECK_IMAGE_ID" \
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
  [ "$(local_docker inspect --format '{{.State.Running}}' "$SERVER_CID")" = true ] || break
  sleep 0.1
done
if [ "$server_ready" -ne 1 ]; then
  local_docker logs "$SERVER_CID" > "$WORKSPACE/server.log" 2>&1 || true
  cat "$WORKSPACE/server.log" >&2
  die 'controlled peer did not become ready'
fi

echo '== authenticate through the real prompt and observe current pixels across focus loss =='
readonly VIEWER_CID_FILE="$WORKSPACE/viewer.cid"
CID_FILES+=("$VIEWER_CID_FILE")
set +e
local_docker run --cidfile "$VIEWER_CID_FILE" \
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
  --mount "type=bind,source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_ID" \
  dbus-run-session -- \
  bash --noprofile --norc /source/scripts/smoke-flutter-peer-presentation-stage.sh viewer \
  > "$WORKSPACE/viewer.log" 2>&1
viewer_status=$?
set -e
VIEWER_CID=$(<"$VIEWER_CID_FILE")
[[ "$VIEWER_CID" =~ ^[0-9a-f]{64}$ ]] || die 'viewer container identity is malformed'
inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer
[ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$VIEWER_PASSWD")" = "$VIEWER_PASSWD_ID" ] \
  && [ "$(<"$VIEWER_PASSWD")" = "$VIEWER_PASSWD_ENTRY" ] \
  || die 'private viewer passwd witness changed during runtime'
cat "$WORKSPACE/viewer.log"
if [ ! -f "$COORD/stop" ] && [ ! -L "$COORD/stop" ]; then
  printf 'outer-retirement-after-viewer-status=%s\n' "$viewer_status" > "$COORD/stop.tmp"
  mv "$COORD/stop.tmp" "$COORD/stop"
fi

server_stopped=0
for _ in $(seq 1 900); do
  if [ "$(local_docker inspect --format '{{.State.Running}}' "$SERVER_CID")" = false ]; then
    server_stopped=1
    break
  fi
  sleep 0.1
done
local_docker logs "$SERVER_CID" > "$WORKSPACE/server.log" 2>&1 || true
cat "$WORKSPACE/server.log"
[ "$server_stopped" -eq 1 ] || die 'controlled peer container did not retire'
server_status="$(local_docker inspect --format '{{.State.ExitCode}}' "$SERVER_CID")"
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
[ "$(git rev-parse HEAD)" = "$SOURCE_COMMIT" ] \
  && [ "$(git rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
  || die 'repository identity changed during the probe'
assert_clean_worktree
git archive --format=tar --output="$WORKSPACE/source-after.tar" "$SOURCE_COMMIT"
[ "$(sha256sum "$WORKSPACE/source-after.tar" | awk '{print $1}')" = \
  "$SOURCE_ARCHIVE_SHA256" ] || die 'exact source archive changed during the probe'
printf 'FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=%s tree=%s archive_sha256=%s scope=linux-x11-full-peer-only network=owned-none-namespace\n' \
  "$SOURCE_COMMIT" "$SOURCE_TREE" "$SOURCE_ARCHIVE_SHA256"

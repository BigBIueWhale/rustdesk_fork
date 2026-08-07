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
readonly EVIDENCE_PUB_CACHE_SHA256=854718cb6c9f02d6364ae038e1d3bb9d0ef90e13048a119008bc7c47e9507d19
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

require_cmd git tar sha256sum stat find chmod docker python3
[ "$HOST_UID" -ne 0 ] || die 'flutter peer presentation smoke refuses host root'
[ "$HOST_GID" -ne 0 ] || die 'flutter peer presentation smoke refuses a root primary group'
assert_clean_worktree
readonly SOURCE_COMMIT="$(git rev-parse HEAD)"
readonly SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
  || die 'source commit or tree identity is malformed'

for pin in \
  DEB_BUILDER_IMAGE_ID DEV_CHECK_IMAGE_ID DEV_CHECK_BASE_IMAGE_ID \
  DEV_CHECK_IMAGE_CONFIG_ID DEV_CHECK_IMAGE_MANIFEST_ID \
  DEV_CHECK_SOURCE_COMMIT DEV_CHECK_SOURCE_REPOSITORY \
  SHA256_DEV_CHECK_DOCKERFILE SHA256_DEV_CHECK_DPKG_MANIFEST \
  SHA256_DEV_CHECK_CARGO SHA256_DEV_CHECK_RUSTC \
  RUST_VERSION SHA256_RUST_1_75 SIZE_RUST_1_75 \
  FLUTTER_VERSION SHA256_FLUTTER_3_24_5 SIZE_FLUTTER_3_24_5 \
  LLVM_VERSION SHA256_LLVM_15_0_6 SIZE_LLVM_15_0_6 \
  SHA256_FLUTTER_TOOLS_LOCK; do
  [ -n "${!pin:-}" ] || die "pins.env is missing $pin"
done
require_online_complete
verify_online_shas \
  "rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
  "flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
  "llvm-${LLVM_VERSION}.tar.xz" "$SHA256_LLVM_15_0_6"
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
require_pinned_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID"
local_docker_image_provenance verify-local \
  --role devcheck \
  --expected-id "$DEV_CHECK_IMAGE_ID" \
  --image-ref "$DEV_CHECK_IMAGE_ID" \
  --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
  --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
  --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
  --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
  --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
  --source-commit "$DEV_CHECK_SOURCE_COMMIT" \
  --source-repository "$DEV_CHECK_SOURCE_REPOSITORY" \
  --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
  --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID" \
  || die 'immutable devcheck image provenance verification failed'

readonly SOURCE_ARCHIVE="$WORKSPACE/source.tar"
readonly SOURCE_SNAPSHOT="$WORKSPACE/source"
readonly BUILD_OUTPUT="$WORKSPACE/output"
readonly XVFB_DEBS="$WORKSPACE/xvfb-debs"
readonly XVFB_ROOT="$WORKSPACE/xvfb-root"
readonly COORD="$WORKSPACE/coord"
readonly EVIDENCE_ONLINE="$WORKSPACE/evidence-online"
readonly VIEWER_PASSWD="$WORKSPACE/viewer.passwd"
readonly VIEWER_PASSWD_ENTRY="rustdesk-evidence:x:$HOST_UID:$HOST_GID:RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"
BUILD_WORK="$WORKSPACE/build-work"
mkdir "$SOURCE_SNAPSHOT" "$BUILD_OUTPUT" "$XVFB_DEBS" "$XVFB_ROOT" \
  "$COORD" "$EVIDENCE_ONLINE" "$BUILD_WORK"
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
  local json_path expected_passwd_source=
  json_path="$WORKSPACE/$label.inspect.json"
  case "$label" in
    server) ;;
    viewer) expected_passwd_source=$VIEWER_PASSWD ;;
    *) die "unknown inspected runtime label: $label" ;;
  esac
  local_docker container inspect "$cid" > "$json_path"
  /usr/bin/python3 -I -S - "$json_path" "$expected_network" "$HOST_UID:$HOST_GID" \
    "$expected_passwd_source" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_network = sys.argv[2]
expected_user = sys.argv[3]
expected_passwd_source = sys.argv[4]
objects = json.loads(path.read_text(encoding="utf-8"))
if len(objects) != 1:
    raise SystemExit("container inspection cardinality differs")
obj = objects[0]
host = obj["HostConfig"]
config = obj["Config"]
if host.get("NetworkMode") != expected_network:
    raise SystemExit(f"network mode differs: {host.get('NetworkMode')!r}")
if host.get("IpcMode") not in ("private", ""):
    raise SystemExit(f"IPC namespace is not private: {host.get('IpcMode')!r}")
if host.get("PidMode") not in ("", None) or host.get("UTSMode") not in ("", None):
    raise SystemExit("container shares a PID or UTS namespace")
if host.get("Privileged") is not False or host.get("ReadonlyRootfs") is not True:
    raise SystemExit("container privilege/read-only-root contract differs")
if config.get("User") != expected_user:
    raise SystemExit(f"numeric user differs: {config.get('User')!r}")
if host.get("PortBindings") not in (None, {}):
    raise SystemExit("container publishes a port")
if host.get("Devices") not in (None, []):
    raise SystemExit("container receives a host device")
if sorted(host.get("CapDrop") or []) != ["ALL"]:
    raise SystemExit("container does not drop all capabilities")
security = host.get("SecurityOpt") or []
if not any(value in ("no-new-privileges", "no-new-privileges:true") for value in security):
    raise SystemExit("container lacks no-new-privileges")
for mount in obj.get("Mounts", []):
    source = mount.get("Source", "")
    if source.endswith("docker.sock") or source.startswith("/dev/"):
        raise SystemExit(f"unsafe mount: {source}")
passwd_mounts = [
    mount for mount in obj.get("Mounts", []) if mount.get("Destination") == "/etc/passwd"
]
if expected_passwd_source:
    if len(passwd_mounts) != 1:
        raise SystemExit("viewer passwd witness mount cardinality differs")
    passwd_mount = passwd_mounts[0]
    if passwd_mount.get("Source") != expected_passwd_source or passwd_mount.get("RW") is not False:
        raise SystemExit("viewer passwd witness source or read-only contract differs")
elif passwd_mounts:
    raise SystemExit("non-viewer container received a passwd witness mount")
PY
}

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
  --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
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

verify_online_shas \
  "rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
  "flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
  "llvm-${LLVM_VERSION}.tar.xz" "$SHA256_LLVM_15_0_6"
[ "$(git rev-parse HEAD)" = "$SOURCE_COMMIT" ] \
  && [ "$(git rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
  || die 'repository identity changed during the probe'
assert_clean_worktree
git archive --format=tar --output="$WORKSPACE/source-after.tar" "$SOURCE_COMMIT"
[ "$(sha256sum "$WORKSPACE/source-after.tar" | awk '{print $1}')" = \
  "$SOURCE_ARCHIVE_SHA256" ] || die 'exact source archive changed during the probe'
printf 'FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=%s tree=%s archive_sha256=%s scope=linux-x11-full-peer-only network=owned-none-namespace\n' \
  "$SOURCE_COMMIT" "$SOURCE_TREE" "$SOURCE_ARCHIVE_SHA256"

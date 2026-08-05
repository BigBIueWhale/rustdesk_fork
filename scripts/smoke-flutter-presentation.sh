#!/usr/bin/env bash
# Exact-commit Linux Flutter texture/X11 presentation evidence, confined to Docker.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"
umask 077

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
WORKSPACE=
WORKSPACE_ID=
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
      echo "flutter presentation smoke: preserving changed workspace: $WORKSPACE" >&2
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
[ "$HOST_UID" -ne 0 ] || die 'flutter presentation smoke refuses host root'
[ "$HOST_GID" -ne 0 ] || die 'flutter presentation smoke refuses a root primary group'
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
  FLUTTER_VERSION SHA256_FLUTTER_3_24_5 SIZE_FLUTTER_3_24_5 \
  SHA256_FLUTTER_TOOLS_LOCK SHA256_FLUTTER_PUB_CACHE SIZE_FLUTTER_PUB_CACHE; do
  [ -n "${!pin:-}" ] || die "pins.env is missing $pin"
done

readonly FLUTTER_ARCHIVE="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
readonly PUB_CACHE_ARCHIVE="$ONLINE_DIR/flutter-pub-cache.tar.gz"
[ -f "$FLUTTER_ARCHIVE" ] && [ ! -L "$FLUTTER_ARCHIVE" ] \
  || die 'pinned Flutter archive is missing or not regular'
[ -f "$PUB_CACHE_ARCHIVE" ] && [ ! -L "$PUB_CACHE_ARCHIVE" ] \
  || die 'pinned Flutter pub-cache archive is missing or not regular'
[ "$(stat -c %s "$FLUTTER_ARCHIVE")" = "$SIZE_FLUTTER_3_24_5" ] \
  || die 'pinned Flutter archive size differs'
[ "$(sha256sum "$FLUTTER_ARCHIVE" | awk '{print $1}')" = \
  "$SHA256_FLUTTER_3_24_5" ] || die 'pinned Flutter archive digest differs'
[ "$(stat -c %s "$PUB_CACHE_ARCHIVE")" = "$SIZE_FLUTTER_PUB_CACHE" ] \
  || die 'pinned Flutter pub-cache archive size differs'
[ "$(sha256sum "$PUB_CACHE_ARCHIVE" | awk '{print $1}')" = \
  "$SHA256_FLUTTER_PUB_CACHE" ] || die 'pinned Flutter pub-cache digest differs'

WORKSPACE="$(mktemp -d /tmp/rustdesk-flutter-presentation.XXXXXXXXXX)"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
  && [ "$(stat -c '%u:%g:%a' "$WORKSPACE")" = "$HOST_UID:$HOST_GID:700" ] \
  || die 'private workspace creation failed'
WORKSPACE_ID="$(stat -c '%d:%i:%u:%g:%a' "$WORKSPACE")"
initialize_local_docker_authority "$WORKSPACE/docker-config" \
  'flutter-presentation-smoke'
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
readonly RUNTIME_STATE="$WORKSPACE/runtime-state"
mkdir "$SOURCE_SNAPSHOT" "$BUILD_OUTPUT" "$XVFB_DEBS" "$XVFB_ROOT" \
  "$RUNTIME_STATE"
git archive --format=tar --output="$SOURCE_ARCHIVE" "$SOURCE_COMMIT"
readonly SOURCE_ARCHIVE_SHA256="$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')"
tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_SNAPSHOT"
chmod -R a-w "$SOURCE_SNAPSHOT"

run_owned_container() {
  local cid_file=$1 run_status=0 cleanup_status=0
  shift
  CID_FILES+=("$cid_file")
  local_docker run --rm --cidfile "$cid_file" "$@" || run_status=$?
  cleanup_container "$cid_file" || cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] || return 125
  return "$run_status"
}

echo '== acquire the exact five-package Xvfb closure in a non-root producer =='
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

echo '== build the exact-commit Flutter app and actual RustDesk Linux texture plugin =='
run_owned_container "$WORKSPACE/build.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=512 --memory=12g --memory-swap=12g --cpus=4 \
  --ulimit nofile=8192:8192 --ulimit fsize=4294967296:4294967296 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$FLUTTER_ARCHIVE,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$PUB_CACHE_ARCHIVE,target=/inputs/pub-cache.tar.gz,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_OUTPUT,target=/out,bind-recursive=disabled" \
  --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
  --env "RUSTDESK_FLUTTER_SHA256=$SHA256_FLUTTER_3_24_5" \
  --env "RUSTDESK_FLUTTER_SIZE=$SIZE_FLUTTER_3_24_5" \
  --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
  --env "RUSTDESK_PUB_CACHE_SHA256=$SHA256_FLUTTER_PUB_CACHE" \
  --env "RUSTDESK_PUB_CACHE_SIZE=$SIZE_FLUTTER_PUB_CACHE" \
  "$DEB_BUILDER_IMAGE_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-presentation-stage.sh build

echo '== observe actual Flutter Texture pixels across external X11 unmap/remap =='
set +e
run_owned_container "$WORKSPACE/runtime.cid" \
  --pull=never --network=none --read-only \
  --user "$HOST_UID:$HOST_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \
  --ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g \
  --mount "type=bind,source=$SOURCE_SNAPSHOT,target=/source,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$BUILD_OUTPUT,target=/out,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled" \
  --mount "type=bind,source=$RUNTIME_STATE,target=/state,bind-recursive=disabled" \
  "$DEV_CHECK_IMAGE_ID" \
  bash --noprofile --norc /source/scripts/smoke-flutter-presentation-stage.sh runtime \
  >"$WORKSPACE/runtime.log" 2>&1
runtime_status=$?
set -e
runtime_output="$(<"$WORKSPACE/runtime.log")"
printf '%s\n' "$runtime_output"
[ "$runtime_status" -eq 0 ] || exit "$runtime_status"
grep -Eq '^FLUTTER_PRESENTATION_PIXELS_OK .* direct_abi=true actual_texture=true x11_pixels=true$' \
  <<<"$runtime_output" || die 'runtime pixel verdict is missing'
grep -q '^FLUTTER_PRESENTATION_NETWORK_SURFACE=network-none tcp-listen:0 udp:0 x11:unix-only$' \
  <<<"$runtime_output" || die 'runtime confinement verdict is missing'
grep -q '^FLUTTER_PRESENTATION_RUNTIME_OK app=joined texture=closed xvfb=joined$' \
  <<<"$runtime_output" || die 'runtime teardown verdict is missing'

[ "$(git rev-parse HEAD)" = "$SOURCE_COMMIT" ] \
  && [ "$(git rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
  || die 'repository identity changed during the probe'
assert_clean_worktree
git archive --format=tar --output="$WORKSPACE/source-after.tar" "$SOURCE_COMMIT"
[ "$(sha256sum "$WORKSPACE/source-after.tar" | awk '{print $1}')" = \
  "$SOURCE_ARCHIVE_SHA256" ] || die 'exact source archive changed during the probe'
[ "$(stat -c %s "$FLUTTER_ARCHIVE")" = "$SIZE_FLUTTER_3_24_5" ] \
  && [ "$(sha256sum "$FLUTTER_ARCHIVE" | awk '{print $1}')" = \
    "$SHA256_FLUTTER_3_24_5" ] || die 'Flutter archive changed during the probe'
[ "$(stat -c %s "$PUB_CACHE_ARCHIVE")" = "$SIZE_FLUTTER_PUB_CACHE" ] \
  && [ "$(sha256sum "$PUB_CACHE_ARCHIVE" | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PUB_CACHE" ] || die 'Flutter pub-cache archive changed during the probe'
printf 'FLUTTER_PRESENTATION_SMOKE_OK commit=%s tree=%s archive_sha256=%s scope=linux-flutter-x11-only\n' \
  "$SOURCE_COMMIT" "$SOURCE_TREE" "$SOURCE_ARCHIVE_SHA256"

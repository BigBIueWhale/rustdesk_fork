#!/usr/bin/env bash
#
# smoke-server.sh — R-B4 / R-A4 / R-T9 / R-T15(d) RUNTIME smoke-test for the controlled-side server.
#
# verify.sh proves the code COMPILES + the KATs pass; it cannot prove the binary BUILDS-and-LINKS,
# nor the runtime startup/listen/shutdown behaviour. This builds the full server binary in the
# pinned-toolchain container and exercises it headless over the guest-container loopback — what the spec's
# R-B4 ("assume nothing builds until watched") and R-A8 (runtime exercise) call for.
#
# The invoking nonroot host user can reach this harness only through the authenticated, zero-NIC
# verifier VM. Inside that disposable guest, every product/tool container remains network-none.
# The tested server binds 127.0.0.1 — never 0.0.0.0 — with no published ports.
# The production binary has no runtime bind-address switch; this harness uses an LD_PRELOAD bind
# shim that rewrites only the public test bind (0.0.0.0:21118 -> 127.0.0.1:21118).
#
# The portable smoke exercises parked/listening startup, graceful drain, software VP9 MDWE,
# CPace admission/refusal, bounded capacity, sealed relay, FileTransfer and limiter behavior.
# Privileged service/init-system, installed-layout password, PID-reuse and packet-capture
# acceptance executes directly in disposable VMs under R-S11dh.
#
# Usage:  scripts/smoke-server.sh [--portable-rootless]
#         scripts/smoke-server.sh --video-pipeline
#         scripts/smoke-server.sh --self-test-vm-authority
#         SMOKE_DECAY=1 scripts/smoke-server.sh [--portable-rootless]
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly SMOKE_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] || {
  echo "smoke: refuses host or container-root execution" >&2
  exit 1
}
[ "$BUILD_GID" -ne 0 ] || {
  echo "smoke: refuses a root primary group" >&2
  exit 1
}
readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$VERIFIER_VM_ENTRY_PREFLIGHT" ] && [ ! -L "$VERIFIER_VM_ENTRY_PREFLIGHT" ] \
  && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1 ] || {
  echo "smoke: verifier-VM entry preflight is absent or ambiguous" >&2
  exit 1
}
/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"

readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly DOCKER_BIN=/usr/bin/docker
readonly SMOKE_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock
readonly SMOKE_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config

read_smoke_pin() {
  local name=$1 line value= count=0
  case "$name" in
    DEV_CHECK_IMAGE_CONFIG_ID|RUST_VERSION|SHA256_CARGO_VENDOR_CLOSURE_V1|SHA256_CARGO_VENDOR_CONFIG|VERIFIER_VM_DOCKER_VERSION) ;;
    *) echo "smoke: unsupported pin name $name" >&2; return 1 ;;
  esac
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" == "$name="* ]]; then
      count=$((count + 1))
      if [[ "$line" =~ ^${name}=\"([A-Za-z0-9._:-]+)\"([[:space:]]*#.*)?$ ]]; then
        value=${BASH_REMATCH[1]}
      else
        echo "smoke: $name is not one canonical quoted pins.env assignment" >&2
        return 1
      fi
    fi
  done < "$SCRIPT_DIR/pins.env"
  [ "$count" -eq 1 ] && [ -n "$value" ] || {
    echo "smoke: $name must occur exactly once in scripts/pins.env" >&2
    return 1
  }
  printf '%s\n' "$value"
}

SMOKE_VM_DOCKER_VERSION=$(read_smoke_pin VERIFIER_VM_DOCKER_VERSION)
[[ "$SMOKE_VM_DOCKER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "smoke: verifier-VM Docker version pin is malformed" >&2; exit 1; }
SMOKE_VM_MARKER_DOCKER="$(/usr/bin/awk '{ print $2 }' \
  "$VERIFIER_VM_AUTHORITY_ROOT/authority")"
[ "$SMOKE_VM_MARKER_DOCKER" = "docker=$SMOKE_VM_DOCKER_VERSION" ] || {
  echo "smoke: guest Docker authority differs from its repository pin" >&2
  exit 1
}
readonly SMOKE_VM_DOCKER_VERSION SMOKE_VM_MARKER_DOCKER
readonly SMOKE_DOCKER_COMMAND=(
  /usr/bin/env -i
  PATH=/usr/bin:/bin
  LC_ALL=C
  HOME=/nonexistent
  DOCKER_HOST="unix://$SMOKE_DOCKER_SOCKET"
  DOCKER_CONFIG="$SMOKE_DOCKER_CONFIG"
  "$DOCKER_BIN"
  --host "unix://$SMOKE_DOCKER_SOCKET"
  --config "$SMOKE_DOCKER_CONFIG"
)

smoke_vm_authority() {
  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null
}

smoke_vm_docker() {
  local status=0
  smoke_vm_authority || return 1
  "${SMOKE_DOCKER_COMMAND[@]}" "$@" || status=$?
  smoke_vm_authority || return 1
  return "$status"
}

cd "$SMOKE_REPO_ROOT"
case "$#" in
  0)
    SMOKE_MODE=portable-rootless
    ;;
  1)
    case "$1" in
      --portable-rootless) SMOKE_MODE=portable-rootless ;;
      --video-pipeline) SMOKE_MODE=video-pipeline-rootless ;;
      --self-test-vm-authority) SMOKE_MODE=vm-authority-self-test ;;
      *)
        echo "usage: scripts/smoke-server.sh [--portable-rootless|--video-pipeline|--self-test-vm-authority]" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "usage: scripts/smoke-server.sh [--portable-rootless|--video-pipeline|--self-test-vm-authority]" >&2
    exit 2
    ;;
esac
readonly SMOKE_MODE

if [ "$SMOKE_MODE" = vm-authority-self-test ]; then
  authority_version="$(smoke_vm_docker version \
    --format '{{.Client.Version}}|{{.Server.Version}}')" || {
    echo "smoke: verifier-VM Docker authority self-test failed" >&2
    exit 1
  }
  [ "$authority_version" = "$SMOKE_VM_DOCKER_VERSION|$SMOKE_VM_DOCKER_VERSION" ] || {
    echo "smoke: verifier-VM Docker authority version differs: $authority_version" >&2
    exit 1
  }
  printf 'SMOKE_SERVER_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed\n' \
    "$BUILD_UID" "$BUILD_GID" "$SMOKE_VM_DOCKER_VERSION"
  exit 0
fi

EXPECTED_RUNTIME_IMAGE_ID=$(read_smoke_pin DEV_CHECK_IMAGE_CONFIG_ID)
SMOKE_RUST_VERSION=$(read_smoke_pin RUST_VERSION)
SMOKE_VENDOR_CLOSURE_SHA256=$(read_smoke_pin SHA256_CARGO_VENDOR_CLOSURE_V1)
SMOKE_VENDOR_CONFIG_SHA256=$(read_smoke_pin SHA256_CARGO_VENDOR_CONFIG)
[[ "$EXPECTED_RUNTIME_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "smoke: DEV_CHECK_IMAGE_CONFIG_ID is not a canonical runtime image ID" >&2; exit 1; }
[[ "$SMOKE_RUST_VERSION" =~ ^[0-9]+\.[0-9]+$ ]] \
  || { echo "smoke: RUST_VERSION is not a canonical major.minor version" >&2; exit 1; }
[[ "$SMOKE_VENDOR_CLOSURE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "smoke: Cargo vendor closure pin is not canonical SHA-256" >&2; exit 1; }
[[ "$SMOKE_VENDOR_CONFIG_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "smoke: Cargo vendor config pin is not canonical SHA-256" >&2; exit 1; }
readonly EXPECTED_RUNTIME_IMAGE_ID SMOKE_RUST_VERSION SMOKE_VENDOR_CLOSURE_SHA256 SMOKE_VENDOR_CONFIG_SHA256
readonly SMOKE_RUSTUP_TOOLCHAIN="${SMOKE_RUST_VERSION}.0-x86_64-unknown-linux-gnu"

smoke_source_tree_digest() {
  /usr/bin/python3 -I -S - "$SMOKE_SOURCE" "$BUILD_UID" "$BUILD_GID" <<'PY'
import hashlib
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
expected_uid = int(sys.argv[2])
expected_gid = int(sys.argv[3])
digest = hashlib.sha256()


def fail(message):
    raise SystemExit(f"smoke source: {message}")


def add_field(value):
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


root_metadata = os.lstat(root)
if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) != 0o555:
    fail("snapshot root is not a mode-0555 real directory")
if root_metadata.st_uid != expected_uid or root_metadata.st_gid != expected_gid:
    fail("snapshot root ownership changed")

entry_count = 0
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    directories.sort()
    files.sort()
    for name in [*directories, *files]:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, root)
        metadata = os.lstat(path)
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            fail(f"snapshot entry ownership changed: {os.fsdecode(relative)}")
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            if mode != 0o555:
                fail(f"snapshot directory mode changed: {os.fsdecode(relative)}")
            kind = b"directory"
            content_digest = b""
        elif stat.S_ISREG(metadata.st_mode):
            if mode not in (0o444, 0o555) or metadata.st_nlink != 1:
                fail(f"snapshot file metadata changed: {os.fsdecode(relative)}")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                before = os.fstat(descriptor)
                file_digest = hashlib.sha256()
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    file_digest.update(block)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if identity_before != identity_after:
                fail(f"snapshot file changed while read: {os.fsdecode(relative)}")
            kind = b"file"
            content_digest = file_digest.digest()
        else:
            fail(f"snapshot contains a symlink or special entry: {os.fsdecode(relative)}")
        add_field(relative)
        add_field(kind)
        add_field(f"{mode:o}".encode("ascii"))
        add_field(content_digest)
        entry_count += 1

if entry_count == 0:
    fail("snapshot is empty")
add_field(str(entry_count).encode("ascii"))
print(digest.hexdigest())
PY
}

readonly SMOKE_ONLINE_ROOT="$(realpath -e -- "$SMOKE_REPO_ROOT/online")"
case "$SMOKE_ONLINE_ROOT" in
  *','*|*':'*) echo "smoke: online input path contains a Docker mount delimiter" >&2; exit 1 ;;
esac
[ -d "$SMOKE_ONLINE_ROOT" ] && [ ! -L "$SMOKE_ONLINE_ROOT" ] || {
  echo "smoke: canonical online input root is unavailable" >&2
  exit 1
}
readonly SMOKE_XVFB_INPUT_ROOT=$SMOKE_ONLINE_ROOT/xvfb-debs
if [ "$SMOKE_MODE" = video-pipeline-rootless ]; then
  [ -d "$SMOKE_XVFB_INPUT_ROOT" ] && [ ! -L "$SMOKE_XVFB_INPUT_ROOT" ] || {
    echo "smoke: authenticated offline Xvfb package closure is unavailable" >&2
    exit 1
  }
fi
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || {
  echo "smoke: exact-commit runtime evidence requires a clean tracked and nonignored source tree" >&2
  exit 1
}
SMOKE_SOURCE_COMMIT="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "$SMOKE_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "smoke: source commit is not one full lowercase Git object ID" >&2
  exit 1
}
readonly SMOKE_SOURCE_COMMIT SMOKE_ONLINE_ROOT

SMOKE_ROOT=$(mktemp -d /tmp/rustdesk-smoke.XXXXXXXXXX)
readonly SMOKE_ROOT
readonly SMOKE_BUILD_TARGET="$SMOKE_ROOT/target"
readonly SMOKE_SOURCE_ARCHIVE="$SMOKE_ROOT/source.tar"
readonly SMOKE_SOURCE="$SMOKE_ROOT/source"
readonly SMOKE_XVFB_DEBS="$SMOKE_ROOT/xvfb-debs"
readonly SMOKE_XVFB_ROOT="$SMOKE_ROOT/xvfb-root"
install -d -m 0700 \
  "$SMOKE_BUILD_TARGET" "$SMOKE_SOURCE" \
  "$SMOKE_XVFB_DEBS" "$SMOKE_XVFB_ROOT"
git -c core.hooksPath=/dev/null archive --format=tar "$SMOKE_SOURCE_COMMIT" >"$SMOKE_SOURCE_ARCHIVE"
[ -s "$SMOKE_SOURCE_ARCHIVE" ] && [ ! -L "$SMOKE_SOURCE_ARCHIVE" ] || {
  echo "smoke: exact source archive is missing or invalid" >&2
  exit 1
}
chmod 0400 "$SMOKE_SOURCE_ARCHIVE"
tar --extract --file="$SMOKE_SOURCE_ARCHIVE" --directory="$SMOKE_SOURCE"
chmod -R a=rX "$SMOKE_SOURCE"
readonly SMOKE_SOURCE_ARCHIVE_SHA256="$(sha256sum "$SMOKE_SOURCE_ARCHIVE" | awk '{print $1}')"
readonly SMOKE_SOURCE_TREE_SHA256="$(smoke_source_tree_digest)"
[[ "$SMOKE_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  && [[ "$SMOKE_SOURCE_TREE_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "smoke: exact source snapshot digests are malformed" >&2
  exit 1
}
readonly SMOKE_ROOT_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_ROOT")"
readonly SMOKE_BUILD_TARGET_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_BUILD_TARGET")"
readonly SMOKE_SOURCE_ARCHIVE_ID="$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_SOURCE_ARCHIVE")"
readonly SMOKE_SOURCE_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_SOURCE")"
readonly SMOKE_XVFB_DEBS_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_DEBS")"
readonly SMOKE_XVFB_ROOT_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_ROOT")"
smoke_docker_authority() {
  smoke_vm_authority || return 1
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_ROOT" 2>/dev/null)" = "$SMOKE_ROOT_ID" ] \
    || { echo "smoke: private authority root identity changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_BUILD_TARGET" 2>/dev/null)" = "$SMOKE_BUILD_TARGET_ID" ] \
    || { echo "smoke: private build-target authority changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_SOURCE_ARCHIVE" 2>/dev/null)" = "$SMOKE_SOURCE_ARCHIVE_ID" ] \
    || { echo "smoke: exact source-archive authority changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_SOURCE" 2>/dev/null)" = "$SMOKE_SOURCE_ID" ] \
    || { echo "smoke: exact source-snapshot authority changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_DEBS" 2>/dev/null)" = "$SMOKE_XVFB_DEBS_ID" ] \
    || { echo "smoke: private Xvfb package authority changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_ROOT" 2>/dev/null)" = "$SMOKE_XVFB_ROOT_ID" ] \
    || { echo "smoke: private Xvfb tool authority changed" >&2; return 1; }
}

smoke_docker() {
  local status=0
  smoke_docker_authority || return 1
  "${SMOKE_DOCKER_COMMAND[@]}" "$@" || status=$?
  smoke_docker_authority || return 1
  return "$status"
}

verify_smoke_source_snapshot() {
  local archive_sha tree_sha
  archive_sha="$(sha256sum "$SMOKE_SOURCE_ARCHIVE" | awk '{print $1}')" || return 1
  [ "$archive_sha" = "$SMOKE_SOURCE_ARCHIVE_SHA256" ] \
    || { echo "smoke: exact source archive changed" >&2; return 1; }
  tree_sha="$(smoke_source_tree_digest)" || return 1
  [ "$tree_sha" = "$SMOKE_SOURCE_TREE_SHA256" ] \
    || { echo "smoke: exact source snapshot changed" >&2; return 1; }
}

remove_smoke_authority_root() {
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_ROOT" 2>/dev/null)" = "$SMOKE_ROOT_ID" ] \
    || { echo "smoke: preserving changed private authority root" >&2; return 125; }
  smoke_docker_authority \
    || { echo "smoke: preserving changed Docker/build authority" >&2; return 125; }
  verify_smoke_source_snapshot \
    || { echo "smoke: preserving changed exact source authority" >&2; return 125; }
  chmod -R u+rwX "$SMOKE_XVFB_DEBS" "$SMOKE_XVFB_ROOT" || return 125
  rm -rf -- "$SMOKE_XVFB_DEBS" "$SMOKE_XVFB_ROOT" || return 125
  rm -rf -- "$SMOKE_BUILD_TARGET" || return 125
  chmod -R u+rwX "$SMOKE_SOURCE" || return 125
  rm -rf -- "$SMOKE_SOURCE" || return 125
  rm -- "$SMOKE_SOURCE_ARCHIVE" || return 125
  rmdir -- "$SMOKE_ROOT" || return 125
}

cleanup_smoke_authority_only() {
  local status=$?
  trap - EXIT HUP INT TERM
  remove_smoke_authority_root || status=125
  exit "$status"
}
trap cleanup_smoke_authority_only EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

IMAGE_ID=$(smoke_docker image inspect --format '{{.Id}}' "$EXPECTED_RUNTIME_IMAGE_ID") || {
  echo "smoke: required pinned local runtime image $EXPECTED_RUNTIME_IMAGE_ID is absent" >&2
  exit 1
}
if [ "$IMAGE_ID" != "$EXPECTED_RUNTIME_IMAGE_ID" ]; then
  echo "smoke: Docker did not resolve the exact pinned development runtime config ID" >&2
  exit 1
fi
readonly IMAGE_ID
BUILD_RUN=(smoke_docker run --rm --network none --pull=never --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 1024
  --memory 12g
  --memory-swap 12g
  --cpus 4
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g
  --env HOME=/tmp/smoke-build
  --env CARGO_HOME=/tmp/smoke-cargo-home
  --env CARGO_TARGET_DIR=/smoke-target
  --env CARGO_INCREMENTAL=0
  --env CARGO_NET_OFFLINE=true
  --env CARGO_NET_RETRY=0
  --env "RUSTUP_TOOLCHAIN=$SMOKE_RUSTUP_TOOLCHAIN"
  --env "SMOKE_EXPECTED_RUSTUP_TOOLCHAIN=$SMOKE_RUSTUP_TOOLCHAIN"
  --env "SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256=$SMOKE_VENDOR_CLOSURE_SHA256"
  --env "SMOKE_EXPECTED_VENDOR_CONFIG_SHA256=$SMOKE_VENDOR_CONFIG_SHA256"
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  --mount "type=bind,source=$SMOKE_ONLINE_ROOT,target=/online,readonly"
  -v "$SMOKE_BUILD_TARGET:/smoke-target:rw"
  -w /work "$IMAGE_ID")
RUN=(smoke_docker run --rm --network none --pull=never --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 1024
  --memory 4g
  --memory-swap 4g
  --cpus 2
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g
  --env HOME=/tmp/smoke-runtime
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  -v "$SMOKE_BUILD_TARGET:/smoke-target:ro"
  -w /work "$IMAGE_ID")
XVFB_PREPARE_RUN=(smoke_docker run --rm --network none --pull=never --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 32
  --memory 256m
  --memory-swap 256m
  --cpus 1
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=32m
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  --mount "type=bind,source=$SMOKE_XVFB_INPUT_ROOT,target=/xvfb-inputs,readonly"
  --mount "type=bind,source=$SMOKE_XVFB_DEBS,target=/xvfb-debs"
  --mount "type=bind,source=$SMOKE_XVFB_ROOT,target=/xvfb-root"
  -w /work "$IMAGE_ID")
VIDEO_RUN=(smoke_docker run --rm --network none --pull=never --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit=1024
  --memory=4g
  --memory-swap=4g
  --cpus=2
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g
  --tmpfs /tmp/.X11-unix:rw,nosuid,nodev,noexec,mode=1777,size=1m
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  --mount "type=bind,source=$SMOKE_BUILD_TARGET,target=/smoke-target,readonly"
  --mount "type=bind,source=$SMOKE_XVFB_ROOT,target=/xvfb-root,readonly"
  --mount "type=bind,source=$SMOKE_XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly"
  -w /work "$IMAGE_ID")
PORT_HEX='527E' # 21118
LOOPBACK_LISTEN='0100007F:527E' # 127.0.0.1:21118
printf 'SMOKE_SOURCE_COMMIT=%s archive_sha256=%s tree_sha256=%s\n' \
  "$SMOKE_SOURCE_COMMIT" "$SMOKE_SOURCE_ARCHIVE_SHA256" "$SMOKE_SOURCE_TREE_SHA256"

rc=0
STAGE_STATUS=0
run_stage() {
  local output_name=$1 captured
  shift
  if captured=$("$@" 2>&1); then
    STAGE_STATUS=0
  else
    STAGE_STATUS=$?
  fi
  printf -v "$output_name" '%s' "$captured"
}

record_stage_status() {
  local label=$1
  if [ "$STAGE_STATUS" -ne 0 ]; then
    echo "  FAIL $label: isolated stage command exited $STAGE_STATUS"
    rc=1
  fi
}

echo "== (0a) prove the bounded process/socket/IPC readiness checker =="
run_stage ready_out "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-ready.sh --self-test
printf '%s\n' "$ready_out"
record_stage_status smoke-readiness-self-test
[ "$STAGE_STATUS" -eq 0 ] || exit 1

echo "== (0) build the server binary + the test seeder + the CPace probe client (R-B4 build smoke) =="
run_stage build_out "${BUILD_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh build
printf '%s\n' "$build_out"
record_stage_status R-B4-build
[ "$STAGE_STATUS" -eq 0 ] || exit 1
verify_smoke_source_snapshot || exit 1

if [ "$SMOKE_MODE" = video-pipeline-rootless ]; then
  echo "== (0b) verify and extract the exact offline Xvfb test closure in a networkless container =="
  run_stage xvfb_prepare_out "${XVFB_PREPARE_RUN[@]}" \
    bash --noprofile --norc /work/scripts/smoke-xvfb-prepare.sh
  printf '%s\n' "$xvfb_prepare_out"
  record_stage_status Xvfb-test-infrastructure
  [ "$STAGE_STATUS" -eq 0 ] || exit 1
  [ "$(grep -c '^XVFB_PACKAGE_OK ' <<<"$xvfb_prepare_out")" -eq 7 ] \
    || { echo '  FAIL video pipeline: the exact seven-package offline Xvfb closure was not prepared'; exit 1; }
  grep -q '^XVFB_OFFLINE_INPUT_SURFACE=tcp-listen:0 udp:0$' <<<"$xvfb_prepare_out" \
    || { echo '  FAIL video pipeline: the offline preparation container retained a listener or UDP socket'; exit 1; }
  grep -Eq '^XVFB_TOOL_CLOSURE_OK packages=7 xvfb_sha256=[0-9a-f]{64} xkbcomp_sha256=[0-9a-f]{64}$' <<<"$xvfb_prepare_out" \
    || { echo '  FAIL video pipeline: the extracted Xvfb closure did not match its file manifest'; exit 1; }
  verify_smoke_source_snapshot || exit 1

  echo "== (1) real X11 capture -> VP8/VP9 encode -> keyed loopback -> exact receipt -> software decode =="
  run_stage video_pipeline_out "${VIDEO_RUN[@]}" \
    bash --noprofile --norc /work/scripts/smoke-server-stage.sh video-pipeline
  printf '%s\n' "$video_pipeline_out"
  record_stage_status real-video-pipeline
  [ "$STAGE_STATUS" -eq 0 ] || exit 1
  grep -q '^X11_NETWORK_SURFACE=unix-only tcp=0 udp=0$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: Xvfb did not remain Unix-socket-only'; exit 1; }
  grep -Eq '^VIDEO_PIPELINE_OK codec=VP(8|9) dimensions=640x480 frames=[0-9]+ distinct=[0-9]+ receipts=[0-9]+ first_decode_ms=[0-9]+ pts_span_ms=[0-9]+ max_decode_us=[0-9]+ mean_decode_us=[0-9]+ max_receive_backlog_drift_ms=[0-9]+$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: the real decode transcript is missing or outside its bounds'; exit 1; }
  grep -Eq '^PRODUCTION_VIEWER_PIPELINE_OK dimensions=640x480 frames=[0-9]+ distinct=[0-9]+ stall_ms=[0-9]+ recovery_ms=[0-9]+ connected=true peer_info=true close_successes=[0-9]+ teardown=io-and-media-joined$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: production viewer integration/recovery evidence is missing'; exit 1; }
  grep -q '^TWO_VIEWER_CAPTURE_ISOLATION=healthy-active,slow-receipt-withheld,no-reconnect$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: stalled-peer isolation evidence is missing'; exit 1; }
  grep -q '^VIDEO_PIPELINE_CLEANUP=server,stalled-peer,motion,xvfb-joined$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: exact runtime owners were not joined'; exit 1; }
  verify_smoke_source_snapshot || exit 1
  echo "SMOKE VIDEO PIPELINE OK: exact committed RustDesk server captured a changing 640x480 Xvfb display, software-encoded it, and carried it over keyed 127.0.0.1:21118 sessions with exact generation receipts. One exact keyed Remote remained alive after intentionally withholding its first frame receipt while the concurrent production Session/Client I/O, receipt, mailbox, decoder-worker, and RGBA-publication path recovered from a deliberate 1.5-second publication stall without reconnect and joined its exact I/O/media ownership; the stalled peer was then identity-bound and reaped. The dedicated probe also software-decoded changing frames under finite bounds. Xvfb used only a private Unix socket; the runtime container had no network, capabilities, host namespaces, devices, published ports, Docker socket, Flutter/compositor presentation, native Windows/Android lifecycle, installed-service, sustained performance/soak, or release-artifact coverage."
  exit 0
fi

echo "== (0b) R-D3a MemoryDenyWriteExecute (W^X) validation: the deployed software VP9 encoder runs clean under the EXACT PR_SET_MDWE primitive systemd applies (so MemoryDenyWriteExecute=yes in the unit is safe) =="
# The controlled --server only ENCODES (§13/Appendix C #2b); the probe sets PR_SET_MDWE|REFUSE_EXEC_GAIN
# BEFORE vpx_codec_enc_init then drives 5 encodes. A runtime W+X mmap/mprotect (a JIT) would SIGSEGV
# under MDWE; libvpx does function-pointer SIMD dispatch, never JIT, so it completes clean (exit 0).
run_stage mdwe_out "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh mdwe
record_stage_status R-D3a
grep -qE 'MDWE_CODEC_OK' <<<"$mdwe_out" && grep -q 'EXIT=0' <<<"$mdwe_out" \
  && echo "  ok  R-D3a: VP9 encoder W^X-clean under MemoryDenyWriteExecute (init + 5/5 encodes, no W+X mapping)" \
  || { echo "  FAIL R-D3a: the codec path is NOT W^X-safe under MDWE — do NOT ship MemoryDenyWriteExecute=yes:"; tail -3 <<<"$mdwe_out"; rc=1; }

echo "== (1) fail-closed startup: --server with NO password MUST PARK — stay alive but bind NOTHING (R-A4/R-S9, finding D) =="
# Finding D: the empty-permanent-password startup process::exit was removed (on Android it crashed
# the shared-process app). An empty password now fails closed by PARKING — direct_server binds NO
# listener and every connection is refused per-connection (server.rs, R-S9). Prove the box stays
# ALIVE (does not exit/crash) yet binds NOTHING on the pinned port. Background it (it no longer
# exits) and probe /proc, mirroring stage (2)'s pattern.
run_stage out1 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh parked
echo "$out1"
parked_stage_status=$STAGE_STATUS
record_stage_status R-A4/R-S9
if [ "$parked_stage_status" -eq 0 ]; then
  parked_evidence_ok=1
  grep -q 'ALIVE=yes' <<<"$out1" \
    || { echo "  FAIL R-A4/R-S9: --server exited on an empty permanent password (finding D: it MUST park, not exit/crash)"; parked_evidence_ok=0; rc=1; }
  grep -q 'TCP_LISTEN=\[\]' <<<"$out1" \
    || { echo "  FAIL R-S9: a listener is bound with NO permanent password (must bind NOTHING while parked)"; parked_evidence_ok=0; rc=1; }
  grep -q 'the direct listener is PARKED' <<<"$out1" \
    || { echo "  FAIL R-S9: missing the fail-closed park diagnostic on the empty-password path"; parked_evidence_ok=0; rc=1; }
  if grep -q 'Direct server listening' <<<"$out1"; then
    echo "  FAIL R-S9: the server bound a listener with no permanent password"
    parked_evidence_ok=0
    rc=1
  fi
  [ "$parked_evidence_ok" -eq 0 ] \
    || echo "  ok  R-A4/R-S9 fail-closed startup (no password -> PARK: alive, nothing bound, runtime)"
else
  echo "  NOTE R-A4/R-S9: parked product-state assertions were not evaluated because the isolated stage did not emit a complete result"
fi

echo "== (2) seed a password, LISTEN on 127.0.0.1, assert the socket surface (R-B4) + R-T9 drain =="
run_stage out2 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh listen
echo "$out2"
record_stage_status R-B4/R-T9
grep -q "TCP_LISTEN=\[$LOOPBACK_LISTEN \]" <<<"$out2" \
  || { echo "  FAIL R-B4: not EXACTLY one v4 TCP listener on 127.0.0.1:21118 (got the TCP_LISTEN line above)"; rc=1; }
grep -q 'UDP_COUNT=0' <<<"$out2" \
  || { echo "  FAIL R-B4: a UDP socket exists — must be ZERO"; rc=1; }
grep -q 'socket surface verified — exactly one TCP v4:21118, zero UDP' <<<"$out2" \
  || { echo "  FAIL R-A4: the runtime socket-surface self-check did not pass"; rc=1; }
grep -q 'R-T9: graceful shutdown complete — exiting 0' <<<"$out2" \
  || { echo "  FAIL R-T9: no graceful SIGTERM shutdown"; rc=1; }

echo "== (3) two-process: a CPace probe client keys the REAL server (R-A1/R-S1) + a wrong password is refused (R-P3/R-P14c) + the R-T12 observability fires =="
run_stage out3 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh keying
echo "$out3"
record_stage_status R-A1/R-S1
grep -q 'keying ok=true (expected=ok)' <<<"$out3" \
  || { echo "  FAIL R-A1/R-S1: the real server did not key a CORRECT-password client"; rc=1; }
grep -q 'keying ok=false (expected=fail)' <<<"$out3" \
  || { echo "  FAIL R-P3/R-P14c: a WRONG-password client was not refused at key-confirmation"; rc=1; }
[ "$(grep -c 'probe_client: PASS' <<<"$out3")" -ge 2 ] \
  || { echo "  FAIL: a probe did not match its expected keying outcome"; rc=1; }
grep -qE 'security summary .* key_confirmation_failures=[1-9]' <<<"$out3" \
  || { echo "  FAIL R-T12/R-P14c: the key-confirmation-failure was not counted in the flood-safe summary"; rc=1; }

echo "== (4) R-T1: a connection flood past the 256-permit budget MUST be capacity-shed =="
run_stage out4 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh flood
echo "$out4"
record_stage_status R-T1
grep -qE 'security summary .* shed=[1-9]' <<<"$out4" \
  || { echo "  FAIL R-T1: the connection-flood capacity shed did not fire (budget 256; flooded 300)"; rc=1; }

echo "== (6) FULL SESSION (R-S6/R-S2/R-S18 + R-D8/R-X8): a keyed credential-free LoginRequest is ADMITTED and the FULL-ACCESS policy denies NOTHING =="
run_stage out6 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh full-session
echo "$out6"
record_stage_status R-S6/R-S18
# R-S6/R-S18: the keyed edge IS the authorization — the credential-free LoginRequest (no second
# credential; the password proof is collapsed into the PAKE) is ADMITTED because CPace already
# authenticated (there is no source-IP ACL). The probe advertises the exact current video-receipt
# capability and accepts only a matching PeerInfo or the pinned headless image's exact
# post-authorization `connection refused` display error. Proven POSITIVELY under the full-access policy: RustDesk
# NOTIFIES the viewer only of DENIED permissions, so an authorized FULL-ACCESS session emits ZERO
# `enabled: false` PermissionInfo. The pinned headless image has no display server: after authorization
# it returns the display backend's exact `connection refused` error instead of PeerInfo.
s6_ok=1
if grep -qE 'blocked by the peer|Some\(Error\("Offline"|Some\(Error\("Wrong Password|Incompatible remote video protocol' <<<"$out6"; then
  echo "  FAIL R-S6/R-S18: the keyed credential-free LoginRequest was REJECTED (must be ADMITTED — CPace authenticated it)"; rc=1; s6_ok=0
fi
if grep -q 'enabled: false' <<<"$out6"; then
  echo "  FAIL R-D8/R-X8: a capability was DENIED (PermissionInfo enabled:false) — the full-access policy must deny nothing"; rc=1; s6_ok=0
fi
if ! grep -q 'REMOTE-LOGIN-ADMITTED' <<<"$out6"; then
  echo "  FAIL R-S6/R-S18: no authorized remote-session outcome was observed"; rc=1; s6_ok=0
fi
[ "$s6_ok" = 1 ] && echo "  ok  R-S6/R-S18 credential-free LoginRequest reached the authorized remote session + R-D8/R-X8 full access denied no capability"

echo "== (6b) PORT-FORWARD/RDP TUNNEL (R-F1/R-D6/R-S5/R-A9): a real tunnel RELAYS bytes END-TO-END inside the sealed session =="
# R-F1 makes port-forward (incl. RDP) a MUST; R-D6 pins enable-tunnel ON and requires the forward to
# ride the sealed encrypted channel; R-A9 requires the bytes indistinguishable from random. The
# cpace_it wire-ciphertext test covers the seal; VM packet-capture acceptance remains required. This stage
# proves the RELAY is FUNCTIONAL end-to-end — a seal-only test cannot. A port-forward viewer keys,
# sends a PortForward login naming a LOCAL target, and sends a canary THROUGH the tunnel; the box dials
# the target, switches to try_port_forward_loop (the sealed relay), and shuttles the canary both ways.
run_stage out6b "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh port-forward
echo "$out6b"
record_stage_status R-F1/R-D6
# R-F1/R-D6/R-S5/R-A9: the canary made a full round trip THROUGH the box (viewer -> sealed -> box ->
# local target -> echo -> box -> sealed -> viewer), proving the relay is restored AND functional AND
# inside the secretbox (the box never set_raw'd — tcp.rs R-A3 would have panicked otherwise).
if grep -q 'PF-RELAY-ECHO-OK' <<<"$out6b"; then
  echo "  ok  R-F1/R-D6/R-S5/R-A9 port-forward/RDP tunnel RELAYS end-to-end inside the sealed session (canary round-tripped through the box's dial + sealed relay)"
else
  echo "  FAIL R-F1/R-D6/R-S5: the port-forward tunnel did NOT relay the canary end-to-end (the sealed relay is broken)"; rc=1
fi

echo "== (6c) FILE TRANSFER on a headless unix --server (R-F1/R-F2): a keyed FileTransfer login yields a NON-EMPTY PeerInfo.username (the --server process owner) and is NEVER refused with 'No active console user' =="
# The harness runs --server as a NON-login user in a container with NO logind/console session — the
# EXACT repro: get_active_username() resolves empty AND is_prelogin() is true (empty seat0 ->
# `getent passwd ` lists every user, so a nologin shell always matches). Before the fix the server
# reported an EMPTY PeerInfo.username (get_active_username() empty, and the is_prelogin re-clear also
# blanked any fallback) and the viewer refused file transfer with "No active console user logged on".
# The server now (i) falls back to the --server process owner when get_active_username() is empty and
# (ii) confines the prelogin re-clear to Windows, so a keyed FileTransfer login MUST return a PeerInfo
# whose username is NON-EMPTY. (The ReadDir listing is served by the CM process, which needs a display
# this container lacks, so its dir FileResponse is a best-effort observation — the load-bearing
# regression signal is the non-empty PeerInfo.username + the absence of the console-user refusal.)
run_stage out6c "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh file-transfer
echo "$out6c"
record_stage_status R-F1/R-F2
if grep -q 'No active console user' <<<"$out6c"; then
  echo "  FAIL R-F1/R-F2: file transfer was refused with 'No active console user' on a headless unix --server"; rc=1
fi
if grep -q 'FT-PEERINFO username_nonempty=true' <<<"$out6c"; then
  if grep -q 'FT-DIR-RESPONSE' <<<"$out6c"; then
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username + directory FileResponse returned (CM round-trip live)"
  else
    echo "  ok  R-F1/R-F2 file transfer: keyed login -> non-empty process-owner PeerInfo.username, not refused (dir FileResponse needs the CM's display, absent in this container — PeerInfo is the load-bearing signal)"
  fi
else
  echo "  FAIL R-F1/R-F2: the FileTransfer login did not return a PeerInfo with a NON-EMPTY username (the headless process-owner fallback regressed, the prelogin re-clear re-broadened to unix, or the login was refused)"; rc=1
fi

echo "== (7) R-A8 / R-T7: an INJECTED (forged) frame on the keyed stream is rejected by the AEAD =="
run_stage out7 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh inject
echo "$out7"
record_stage_status R-A8/R-T7
# The server tears the connection down with "decryption error" — secretbox::open fails the Poly1305
# tag (R-T7: every keyed frame authenticated), so the forged frame NEVER reaches the parser (R-A8).
grep -q 'Connection closed: decryption error' <<<"$out7" \
  || { echo "  FAIL R-A8/R-T7: an injected forged frame was NOT rejected by the AEAD"; rc=1; }

echo "== (8) R-A8.2 / R-S10: the per-source online-guess limiter is OWNER-SAFE (flood one source; a DIFFERENT source still keys) =="
run_stage out8 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh limiter
echo "$out8"
record_stage_status R-A8.2/R-S10
# The CARDINAL R-S10 rule: a limiter must NEVER lock the owner out of their own machine. The per-IP
# online-guess limiter (guess_limiter_allows, MAX 10/60s) blocks the FLOODING source but not a
# different one — so a connection-flood / guess-flood from an attacker cannot deny the owner.
grep -q 'OWNER_DIFF_SRC: keying ok=true' <<<"$out8" \
  || { echo "  FAIL R-A8.2: a DIFFERENT source was blocked by the limiter — owner lock-out, the CARDINAL violation"; rc=1; }
grep -q 'FLOODER_SAME_SRC: keying ok=false' <<<"$out8" \
  || { echo "  FAIL R-A8.2: the flooding source was NOT rate-limited (the per-source guess limiter is not working)"; rc=1; }

# Opt-in (SMOKE_DECAY=1): the R-A8 limiter-DECAY proof waits out the real 60s GUESS_WINDOW, so it is
# kept off the default fast path. It adds ~75 s but exercises the genuine production window (no
# test-only time-injection into the security-critical limiter).
DECAY_NOTE=""
if [ "${SMOKE_DECAY:-0}" = 1 ]; then
echo "== (10) R-A8 DECAY: a tripped per-source block DECAYS after the window (no PERMANENT lockout) =="
run_stage out10 "${RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh decay
echo "$out10"
record_stage_status R-A8-decay
# The block must be live first (precondition), then self-heal once the window lapses. A limiter that
# never decays is a PERMANENT lockout — the cardinal "never lock the owner out" violation (R-S10).
grep -q 'BLOCKED_NOW: keying ok=false' <<<"$out10" \
  || { echo "  FAIL R-A8: the source was not blocked after the flood (decay-test precondition)"; rc=1; }
grep -q 'DECAYED_AFTER_WINDOW: keying ok=true' <<<"$out10" \
  || { echo "  FAIL R-A8: the block did NOT decay after the 60s window — a PERMANENT lockout (cardinal owner-safety violation)"; rc=1; }
DECAY_NOTE=" + R-A8 limiter-decay (tripped block self-heals after the 60s window)"
fi

if [ "$rc" = 0 ]; then
  verify_smoke_source_snapshot || exit 1
  echo "SMOKE ROOTLESS OK: exact numeric-nonroot RustDesk executable + R-B4 build + one container-loopback TCP listener on 127.0.0.1:21118 and zero UDP + fail-closed parked startup + graceful drain + VP9 MDWE + correct/wrong CPace keying + capacity shedding + authenticated Remote admission + sealed port-forward relay + FileTransfer admission + forged-frame rejection + owner-safe limiter${DECAY_NOTE}. Root/service/init-system/user-creation/installed-layout/packet-capture, graphical/native/device, performance/soak, and release-artifact evidence were not entered or claimed."
else
  echo "SMOKE FAILED"; exit 1
fi

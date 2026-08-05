#!/usr/bin/env bash
#
# smoke-server.sh — R-B4 / R-A4 / R-T9 / R-T15(d) RUNTIME smoke-test for the controlled-side server.
#
# verify.sh proves the code COMPILES + the KATs pass; it cannot prove the binary BUILDS-and-LINKS,
# nor the runtime startup/listen/shutdown behaviour. This builds the full server binary in the
# pinned-toolchain container and exercises it headless over the docker LOOPBACK — what the spec's
# R-B4 ("assume nothing builds until watched") and R-A8 (runtime exercise) call for.
#
# It binds 127.0.0.1 — never 0.0.0.0 — in a network-none `--rm` container with no published ports.
# The production binary has no runtime bind-address switch; this harness uses an LD_PRELOAD bind
# shim that rewrites only the public test bind (0.0.0.0:21118 -> 127.0.0.1:21118).
#
# Validated at RUNTIME (not merely compile). Portable bullets run in the default rootless mode;
# service/init-system/root-owned/packet-capture bullets require explicit --with-root-containers:
#   - R-B4 build  : the full `rustdesk` binary builds + links + runs headless (sciter is `dyn`);
#   - R-A4/R-S9 (fail-closed startup) : with NO permanent password the box PARKS — it stays alive
#     but binds NO listener (nothing on the pinned port) and refuses every connection (finding D:
#     the startup process::exit was removed; on the shared-process Android app it crashed the app);
#   - R-B4 / R-D3/R-D5/R-D6 socket surface : with a password seeded the box binds EXACTLY ONE v4 TCP
#     listener on the pinned port (21118) and ZERO UDP — the §17 direct-IP/no-UDP thesis, empirical;
#   - R-A4 (runtime socket self-check) : `assert_socket_surface` confirms the same from inside;
#   - R-T9 : SIGTERM -> "graceful shutdown initiated" -> "complete — exiting 0";
#   - R-S11c-27h/R-S11e-26 : the real --service active-seat path descriptor-execs as UID/GID 4001
#     with exact supplementary groups, zero live capability sets, NNP, bounded environment, typed
#     IPC, and graceful reap; the root child rejects a hostile ambient launch environment and uses
#     only its passwd home plus the selected desktop snapshot;
#   - R-S11c-27i : the real --service supervisor rejects malformed and live-but-ambiguous durable
#     child records without changing the record or either separately identity-bound UID-4000 process;
#   - R-S11c-27j : the manual lifecycle stage cannot affect a concurrently running networkless
#     sibling Docker container with its own PID namespace and neutral launched RustDesk server;
#   - R-S11c-27u : the real --service recovery path refuses to signal a live recorded child when
#     a smoke-only hook makes pidfd_open unavailable, preserving both child and record;
#   - R-S11c-27n : separate PID/mount namespaces install the same bytes at /usr/bin/rustdesk as
#     different executable objects; the exact-role sibling survives every main-namespace action;
#   - R-D8 / R-D2 (real password provisioning) : the production `--password-stdin` CLI run against a
#     non-installed user-owned live --server (2b root-owned, 2c non-root same-uid) provisions over
#     uid-scoped main IPC and CLEANLY set-and-exits (no hang); the new credential keys and the old one
#     is rejected. An installed-layout binary separately proves service-owned routing cannot fall back
#     to that user-owned daemon when the privileged service endpoint is absent;
#   - R-A9 (wire-capture) : a distinctive plaintext canary sent in a POST-KEY LoginRequest NEVER
#     appears in a tcpdump of the loopback — the keyed session bytes carry no recoverable plaintext.
#
# Most stages seed the permanent password via the TEST-ONLY `examples/seed_password` (a direct Config
# write) for speed; stages (2b-2d) exercise the production `--password-stdin` CLI end-to-end.
#
# Usage:  scripts/smoke-server.sh [--portable-rootless]
#         scripts/smoke-server.sh --with-root-containers
#         scripts/smoke-server.sh --video-pipeline
#         SMOKE_DECAY=1 scripts/smoke-server.sh [--portable-rootless]
#
# The default is the portable rootless path. The installed-service, root-owned password fixture,
# user-creation fixture, PID-reuse namespace, init-system, and packet-capture stages are unreachable
# unless --with-root-containers is explicit.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
case "$#" in
  0)
    SMOKE_MODE=portable-rootless
    ;;
  1)
    case "$1" in
      --portable-rootless) SMOKE_MODE=portable-rootless ;;
      --with-root-containers) SMOKE_MODE=with-root-containers ;;
      --video-pipeline) SMOKE_MODE=video-pipeline-rootless ;;
      *)
        echo "usage: scripts/smoke-server.sh [--portable-rootless|--with-root-containers|--video-pipeline]" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "usage: scripts/smoke-server.sh [--portable-rootless|--with-root-containers|--video-pipeline]" >&2
    exit 2
    ;;
esac
readonly SMOKE_MODE
readonly DOCKER_BIN=/usr/bin/docker
readonly SMOKE_DOCKER_HOST=unix:///var/run/docker.sock
readonly SMOKE_REPO_ROOT="$PWD"
readonly BUILD_UID="$(id -u)"
readonly BUILD_GID="$(id -g)"
[ "$BUILD_UID" -ne 0 ] || {
  echo "smoke: refuses host or container-root execution" >&2
  exit 1
}
[ "$BUILD_GID" -ne 0 ] || {
  echo "smoke: refuses a root primary group" >&2
  exit 1
}
[ -f "$DOCKER_BIN" ] && [ ! -L "$DOCKER_BIN" ] && [ -x "$DOCKER_BIN" ] || {
  echo "smoke: trusted Docker client is unavailable at $DOCKER_BIN" >&2
  exit 1
}
[ "$(stat -c '%u:%g:%a:%h' -- "$DOCKER_BIN" 2>/dev/null)" = "0:0:755:1" ] || {
  echo "smoke: trusted Docker client must be a root-owned mode-0755 single-link file" >&2
  exit 1
}
[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] || {
  echo "smoke: the fixed local Docker Unix socket is unavailable" >&2
  exit 1
}
readonly SMOKE_DOCKER_SOCKET_ID="$(stat -c '%d:%i:%u:%g:%a:%h' -- /var/run/docker.sock)"
case "$SMOKE_DOCKER_SOCKET_ID" in
  *:*:0:*:*:1) ;;
  *) echo "smoke: the fixed local Docker Unix socket is not root-owned and single-link" >&2; exit 1 ;;
esac
for variable in \
  DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \
  DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST \
  DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS; do
  [ -z "${!variable+x}" ] || {
    echo "smoke: $variable must not influence the Docker client" >&2
    exit 1
  }
done

read_smoke_pin() {
  local name=$1 line value= count=0
  case "$name" in
    DEV_CHECK_IMAGE_ID|RUST_VERSION|SHA256_CARGO_VENDOR_CLOSURE_V1|SHA256_CARGO_VENDOR_CONFIG) ;;
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
  done < scripts/pins.env
  [ "$count" -eq 1 ] && [ -n "$value" ] || {
    echo "smoke: $name must occur exactly once in scripts/pins.env" >&2
    return 1
  }
  printf '%s\n' "$value"
}

EXPECTED_IMAGE_ID=$(read_smoke_pin DEV_CHECK_IMAGE_ID)
SMOKE_RUST_VERSION=$(read_smoke_pin RUST_VERSION)
SMOKE_VENDOR_CLOSURE_SHA256=$(read_smoke_pin SHA256_CARGO_VENDOR_CLOSURE_V1)
SMOKE_VENDOR_CONFIG_SHA256=$(read_smoke_pin SHA256_CARGO_VENDOR_CONFIG)
[[ "$EXPECTED_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "smoke: DEV_CHECK_IMAGE_ID is not a canonical image ID" >&2; exit 1; }
[[ "$SMOKE_RUST_VERSION" =~ ^[0-9]+\.[0-9]+$ ]] \
  || { echo "smoke: RUST_VERSION is not a canonical major.minor version" >&2; exit 1; }
[[ "$SMOKE_VENDOR_CLOSURE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "smoke: Cargo vendor closure pin is not canonical SHA-256" >&2; exit 1; }
[[ "$SMOKE_VENDOR_CONFIG_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "smoke: Cargo vendor config pin is not canonical SHA-256" >&2; exit 1; }
readonly EXPECTED_IMAGE_ID SMOKE_RUST_VERSION SMOKE_VENDOR_CLOSURE_SHA256 SMOKE_VENDOR_CONFIG_SHA256
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
readonly SMOKE_DOCKER_CONFIG="$SMOKE_ROOT/docker-config"
readonly SMOKE_BUILD_TARGET="$SMOKE_ROOT/target"
readonly SMOKE_SOURCE_ARCHIVE="$SMOKE_ROOT/source.tar"
readonly SMOKE_SOURCE="$SMOKE_ROOT/source"
readonly SMOKE_XVFB_DEBS="$SMOKE_ROOT/xvfb-debs"
readonly SMOKE_XVFB_ROOT="$SMOKE_ROOT/xvfb-root"
install -d -m 0700 \
  "$SMOKE_DOCKER_CONFIG" "$SMOKE_BUILD_TARGET" "$SMOKE_SOURCE" \
  "$SMOKE_XVFB_DEBS" "$SMOKE_XVFB_ROOT"
printf '{}\n' >"$SMOKE_DOCKER_CONFIG/config.json"
chmod 0600 "$SMOKE_DOCKER_CONFIG/config.json"
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
readonly SMOKE_DOCKER_CONFIG_ID="$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_DOCKER_CONFIG")"
readonly SMOKE_DOCKER_CONFIG_FILE_ID="$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_DOCKER_CONFIG/config.json")"
readonly SMOKE_BUILD_TARGET_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_BUILD_TARGET")"
readonly SMOKE_SOURCE_ARCHIVE_ID="$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_SOURCE_ARCHIVE")"
readonly SMOKE_SOURCE_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_SOURCE")"
readonly SMOKE_XVFB_DEBS_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_DEBS")"
readonly SMOKE_XVFB_ROOT_ID="$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_XVFB_ROOT")"
readonly SMOKE_DOCKER_COMMAND=(
  /usr/bin/env -i
  PATH=/usr/bin:/bin
  HOME="$SMOKE_ROOT"
  DOCKER_HOST="$SMOKE_DOCKER_HOST"
  DOCKER_CONFIG="$SMOKE_DOCKER_CONFIG"
  "$DOCKER_BIN"
  --host "$SMOKE_DOCKER_HOST"
  --config "$SMOKE_DOCKER_CONFIG"
)

smoke_docker_authority() {
  [ "$(stat -c '%d:%i:%u:%g:%a' -- "$SMOKE_ROOT" 2>/dev/null)" = "$SMOKE_ROOT_ID" ] \
    || { echo "smoke: private authority root identity changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_DOCKER_CONFIG" 2>/dev/null)" = "$SMOKE_DOCKER_CONFIG_ID" ] \
    || { echo "smoke: private Docker configuration identity changed" >&2; return 1; }
  [ "$(stat -c '%d:%i:%u:%g:%a:%h' -- "$SMOKE_DOCKER_CONFIG/config.json" 2>/dev/null)" = "$SMOKE_DOCKER_CONFIG_FILE_ID" ] \
    || { echo "smoke: private Docker config.json identity changed" >&2; return 1; }
  cmp -s -- "$SMOKE_DOCKER_CONFIG/config.json" <(printf '{}\n') \
    || { echo "smoke: private Docker config.json bytes changed" >&2; return 1; }
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
  [ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] \
    && [ "$(stat -c '%d:%i:%u:%g:%a:%h' -- /var/run/docker.sock 2>/dev/null)" = "$SMOKE_DOCKER_SOCKET_ID" ] \
    || { echo "smoke: fixed local Docker Unix socket identity changed" >&2; return 1; }
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
  rm -- "$SMOKE_DOCKER_CONFIG/config.json" || return 125
  rmdir -- "$SMOKE_DOCKER_CONFIG" || return 125
  if [ -e "$SMOKE_ROOT/sibling-docker.log" ] || [ -L "$SMOKE_ROOT/sibling-docker.log" ]; then
    [ "$(stat -c '%u:%g:%a:%h' -- "$SMOKE_ROOT/sibling-docker.log" 2>/dev/null)" = "$BUILD_UID:$BUILD_GID:600:1" ] \
      || { echo "smoke: preserving changed sibling transcript" >&2; return 125; }
    rm -- "$SMOKE_ROOT/sibling-docker.log" || return 125
  fi
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

IMAGE_ID=$(smoke_docker image inspect --format '{{.Id}}' "$EXPECTED_IMAGE_ID") || {
  echo "smoke: required pinned local image $EXPECTED_IMAGE_ID is absent" >&2
  exit 1
}
if [ "$IMAGE_ID" != "$EXPECTED_IMAGE_ID" ]; then
  echo "smoke: Docker did not resolve the exact pinned development image ID" >&2
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
ROOT_RUN=(smoke_docker run --rm --network none --pull=never
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  -v "$SMOKE_BUILD_TARGET:/smoke-target:ro"
  -w /work "$IMAGE_ID")
LIFECYCLE_RUN=(smoke_docker run --rm --network none --cap-add SYS_PTRACE --pull=never
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  -v "$SMOKE_BUILD_TARGET:/smoke-target:ro"
  -w /work "$IMAGE_ID")
PID_REUSE_RUN=(smoke_docker run --rm --network none --read-only --pids-limit 128 --pull=never
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add CHECKPOINT_RESTORE --cap-add SETPCAP
  --security-opt no-new-privileges --security-opt apparmor=unconfined
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777
  --tmpfs /run:rw,nosuid,nodev,noexec,mode=755
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
  -v "$SMOKE_BUILD_TARGET:/smoke-target:ro"
  -w /work "$IMAGE_ID")
XVFB_PREPARE_RUN=(smoke_docker run --rm --network bridge --pull=never --read-only
  --user "$BUILD_UID:$BUILD_GID"
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 32
  --memory 256m
  --memory-swap 256m
  --cpus 1
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=32m
  --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly"
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
SIBLING_ROOT=
SIBLING_ROOT_ID=
SIBLING_NAME=
SIBLING_CID=

sibling_container_running() {
  [ -n "$SIBLING_CID" ] || return 1
  [ "$(smoke_docker inspect -f '{{.State.Running}}' "$SIBLING_CID" 2>/dev/null || true)" = true ]
}

cleanup_sibling_root() {
  local cleanup_status=0 path
  [ -n "$SIBLING_ROOT" ] || return 0
  if [ "$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT" 2>/dev/null || true)" != "$SIBLING_ROOT_ID" ]; then
    echo "sibling docker: preserving changed private workspace" >&2
    return 125
  fi
  for path in ready stop; do
    [ ! -e "$SIBLING_ROOT/$path" ] && [ ! -L "$SIBLING_ROOT/$path" ] \
      || rm -- "$SIBLING_ROOT/$path" || cleanup_status=125
  done
  rmdir -- "$SIBLING_ROOT" || cleanup_status=125
  if [ "$cleanup_status" -eq 0 ]; then
    SIBLING_ROOT=
    SIBLING_ROOT_ID=
  fi
  return "$cleanup_status"
}

start_sibling_docker() {
  local docker_out i ready_logs suffix
  SIBLING_ROOT=$(mktemp -d /tmp/rustdesk-smoke-sibling.XXXXXXXXXX) || return 1
  SIBLING_ROOT_ID=$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT") || return 1
  if [ "${SIBLING_ROOT_ID##*:}" != 700 ]; then
    echo "sibling docker workspace is not mode 0700" >&2
    return 1
  fi
  suffix=${SIBLING_ROOT##*.}
  SIBLING_NAME="rd-smoke-sibling-$suffix"
  if docker_out=$(smoke_docker run -d --name "$SIBLING_NAME" --network none --pull=never \
      --mount "type=bind,source=$SMOKE_SOURCE,target=/work,readonly" \
      -v "$SMOKE_BUILD_TARGET:/smoke-target:ro" \
      -v "$SIBLING_ROOT:/sibling:rw" \
      -w /work "$IMAGE_ID" \
      bash --noprofile --norc /work/scripts/smoke-server-stage.sh sibling-docker-server 2>&1); then
    :
  else
    printf '%s\n' "$docker_out" >&2
    cleanup_sibling_root || true
    return 1
  fi
  SIBLING_CID=$docker_out
  for ((i = 0; i < 400; i += 1)); do
    if [ -f "$SIBLING_ROOT/ready" ] && [ ! -L "$SIBLING_ROOT/ready" ] \
      && grep -Fxq ready "$SIBLING_ROOT/ready"; then
      ready_logs=$(smoke_docker logs "$SIBLING_CID" 2>&1) || return 1
      grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$ready_logs" || return 1
      grep -Eq '^SIBLING_CONTAINER_IDENTITY_READY pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+ generation=[0-9a-f-]{36}$' <<<"$ready_logs" || return 1
      return 0
    fi
    if ! sibling_container_running; then
      echo "sibling docker container exited before ready" >&2
      smoke_docker logs "$SIBLING_CID" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "sibling docker container did not become ready" >&2
  smoke_docker logs "$SIBLING_CID" >&2 || true
  return 1
}

stop_sibling_docker() {
  local cid logs wait_command_status wait_out wait_status
  [ -n "$SIBLING_CID" ] || return 0
  cid=$SIBLING_CID
  if ! sibling_container_running; then
    echo "sibling docker container exited before lifecycle completed" >&2
    smoke_docker logs "$cid" >&2 || true
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  if [ -z "$SIBLING_ROOT" ] || [ "$(stat -c '%d:%i:%u:%g:%a' "$SIBLING_ROOT" 2>/dev/null || true)" != "$SIBLING_ROOT_ID" ]; then
    echo "sibling docker control workspace identity changed" >&2
    return 1
  fi
  printf 'stop\n' >"$SIBLING_ROOT/stop" || return 1
  smoke_docker_authority || return 1
  if wait_out=$(timeout --signal=TERM --kill-after=5s 30s \
      "${SMOKE_DOCKER_COMMAND[@]}" wait "$cid" 2>&1); then
    wait_command_status=0
  else
    wait_command_status=$?
  fi
  smoke_docker_authority || return 1
  if [ "$wait_command_status" -ne 0 ]; then
    printf '%s\n' "$wait_out" >&2
    smoke_docker logs "$cid" >&2 || true
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  wait_status=$(printf '%s\n' "$wait_out" | tail -n 1 | tr -d '\r')
  logs=$(smoke_docker logs "$cid" 2>&1) || {
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  printf '%s\n' "$logs"
  if [ "$wait_status" != 0 ]; then
    echo "sibling docker container exited $wait_status" >&2
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  fi
  grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$logs" || {
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$logs" || {
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  grep -Eq '^SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ generation=[0-9a-f-]{36}$' <<<"$logs" || {
    smoke_docker rm -f "$cid" >/dev/null 2>&1 || true
    SIBLING_CID=
    cleanup_sibling_root || true
    return 1
  }
  smoke_docker rm "$cid" >/dev/null || return 1
  SIBLING_CID=
  cleanup_sibling_root || return "$?"
  printf 'SIBLING_DOCKER_NONINTERFERENCE=pass cid=%s\n' "${cid:0:12}"
}

cleanup_smoke() {
  local status=$? cleanup_status=0
  trap - EXIT HUP INT TERM
  if [ -n "$SIBLING_CID" ]; then
    stop_sibling_docker >/dev/null 2>&1 || cleanup_status=$?
  elif [ -n "$SIBLING_ROOT" ]; then
    cleanup_sibling_root || cleanup_status=$?
  fi
  remove_smoke_authority_root || cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ]; then
    status=125
  fi
  exit "$status"
}
trap cleanup_smoke EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
  echo "== (0b) acquire the exact non-root Xvfb test closure in an isolated producer container =="
  run_stage xvfb_prepare_out "${XVFB_PREPARE_RUN[@]}" \
    bash --noprofile --norc /work/scripts/smoke-xvfb-prepare.sh
  printf '%s\n' "$xvfb_prepare_out"
  record_stage_status Xvfb-test-infrastructure
  [ "$STAGE_STATUS" -eq 0 ] || exit 1
  [ "$(grep -c '^XVFB_PACKAGE_OK ' <<<"$xvfb_prepare_out")" -eq 5 ] \
    || { echo '  FAIL video pipeline: the exact five-package Xvfb closure was not acquired'; exit 1; }
  grep -q '^XVFB_ACQUISITION_NETWORK_SURFACE=tcp-listen:0 udp:0$' <<<"$xvfb_prepare_out" \
    || { echo '  FAIL video pipeline: the acquisition container retained a listener or UDP socket'; exit 1; }
  grep -Eq '^XVFB_TOOL_CLOSURE_OK packages=5 xvfb_sha256=[0-9a-f]{64} xkbcomp_sha256=[0-9a-f]{64}$' <<<"$xvfb_prepare_out" \
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
  grep -q '^VIDEO_PIPELINE_CLEANUP=server,motion,xvfb-joined$' <<<"$video_pipeline_out" \
    || { echo '  FAIL video pipeline: exact runtime owners were not joined'; exit 1; }
  verify_smoke_source_snapshot || exit 1
  echo "SMOKE VIDEO PIPELINE OK: exact committed RustDesk server captured a changing 640x480 Xvfb display, software-encoded it, carried it over the keyed 127.0.0.1:21118 session with exact generation receipts, and software-decoded multiple changing frames under finite bounds. Xvfb used only a private Unix socket; the runtime container had no network, capabilities, host namespaces, devices, published ports, Docker socket, Flutter/compositor presentation, native Windows/Android lifecycle, installed-service, performance/soak, or release-artifact coverage."
  exit 0
fi

if [ "$SMOKE_MODE" = with-root-containers ]; then
echo "== (0c) Linux manual supervisor lifecycle: exact hostile-record rejection, cross-container identity, pidfd-unavailable refusal, stop/crash recovery, privilege drop, and portable noninterference (R-S11c-27f/R-S11c-27g/R-S11c-27h/R-S11c-27i/R-S11c-27j/R-S11c-27n/R-S11c-27u) =="
lifecycle_out=
sibling_out=
sibling_out_file=$SMOKE_ROOT/sibling-docker.log
lifecycle_stage_status=1
sibling_stage_status=1
if start_sibling_docker; then
  run_stage lifecycle_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh service-lifecycle-manual
  lifecycle_stage_status=$STAGE_STATUS
  if stop_sibling_docker >"$sibling_out_file" 2>&1; then
    sibling_stage_status=0
  else
    sibling_stage_status=$?
  fi
  sibling_out=$(cat "$sibling_out_file")
else
  lifecycle_out='sibling Docker server failed to start'
  stop_sibling_docker >/dev/null 2>&1 || true
  cleanup_sibling_root >/dev/null 2>&1 || true
fi
printf '%s\n' "$lifecycle_out"
printf '%s\n' "$sibling_out"
STAGE_STATUS=$lifecycle_stage_status
record_stage_status R-S11c-27f
record_stage_status R-S11c-27g
record_stage_status R-S11c-27h
record_stage_status R-S11c-27i
record_stage_status R-S11c-27u
grep -q '^SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata,reused-start,executable,uid,generation,portable-role$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27i: actual --service did not preserve every hostile or ambiguous child record while signaling nothing"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_GRACEFUL=pass generation=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: actual --service SIGTERM did not gracefully reap its exact child"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_RESTART=pass generation=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: fresh manual supervisor generation was not observed"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_FORCED=pass elapsed_ms=' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f: stopped child did not take the bounded TERM-to-KILL/reap path"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_CRASH_RESTART=pass prior_generation=[0-9a-f-]{36} recovered_generation=[0-9a-f-]{36} child_exit_ms=[0-9]+$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27g: actual supervisor crash did not stop its exact child and recover to a fresh generation"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_PIDFD_UNAVAILABLE_REFUSAL=pass generation=[0-9a-f-]{36} record_sha256=[0-9a-f]{64}$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27u: pidfd-unavailable recovery did not preserve the exact live child and record while refusing startup"; rc=1; }
grep -Eq '^SERVICE_LIFECYCLE_PRIVILEGE_DROP=pass uid=4001 gid=4001 groups=4001,4101 generation=[0-9a-f-]{36}$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27h: actual active-seat child did not complete the exact non-root descriptor-exec path"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_ROOT_ENVIRONMENT=pass authority=desktop-snapshot ambient=excluded$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11e-26: root service child did not reject the hostile ambient launch environment"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_WORKING_DIRECTORY=pass supervisor=/ child=/ ambient=excluded$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11e-27: Linux service supervisor/child retained ambient cwd or consumed cwd-relative custom.txt"; rc=1; }
grep -q '^SERVICE_LIFECYCLE_FILE_DESCRIPTOR_AUTHORITY=pass supervisor=excluded child=excluded ambient=excluded$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11e-28: Linux service supervisor/child retained launcher file-descriptor authority"; rc=1; }
grep -q '^PORTABLE_NONINTERFERENCE=pass uid=4000$' <<<"$lifecycle_out" \
  || { echo "  FAIL R-S11c-27f/R-S11c-27g/R-S11c-27h/R-S11c-27i: unrelated non-root portable server did not survive every service transition"; rc=1; }
if [ "$lifecycle_stage_status" -eq 0 ] && [ "$sibling_stage_status" -eq 0 ] \
  && grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  && grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  && grep -Eq '^SIBLING_DOCKER_NONINTERFERENCE=pass cid=[0-9a-f]{12}$' <<<"$sibling_out"; then
  STAGE_STATUS=0
else
  STAGE_STATUS=1
fi
record_stage_status R-S11c-27j
grep -Eq '^SIBLING_DOCKER_READY pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: sibling Docker server did not publish an exact ready identity before lifecycle authority ran"; rc=1; }
grep -Eq '^SIBLING_DOCKER_SURVIVED=pass pid=[0-9]+ start=[0-9]+$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: unrelated sibling Docker server did not survive the service lifecycle stage"; rc=1; }
grep -Eq '^SIBLING_DOCKER_NONINTERFERENCE=pass cid=[0-9a-f]{12}$' <<<"$sibling_out" \
  || { echo "  FAIL R-S11c-27j: sibling Docker container was not drained as an unrelated survivor after lifecycle completion"; rc=1; }

main_container_identity=$(grep -E '^SERVICE_LIFECYCLE_CONTAINER_IDENTITY=pass path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+$' <<<"$lifecycle_out" || true)
sibling_container_identity=$(grep -E '^SIBLING_CONTAINER_IDENTITY_READY pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ source=[0-9]+:[0-9]+ sha256=[0-9a-f]{64} mnt=[0-9]+ pidns=[0-9]+ generation=[0-9a-f-]{36}$' <<<"$sibling_out" || true)
sibling_container_survived=$(grep -E '^SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=[0-9]+ start=[0-9]+ path=/usr/bin/rustdesk exe=[0-9]+:[0-9]+ generation=[0-9a-f-]{36}$' <<<"$sibling_out" || true)
container_identity_parse_ok=1
if [[ "$main_container_identity" =~ exe=([0-9]+:[0-9]+)[[:space:]]source=([0-9]+:[0-9]+)[[:space:]]sha256=([0-9a-f]{64})[[:space:]]mnt=([0-9]+)[[:space:]]pidns=([0-9]+)$ ]]; then
  main_executable=${BASH_REMATCH[1]}
  main_source=${BASH_REMATCH[2]}
  main_sha256=${BASH_REMATCH[3]}
  main_mount_namespace=${BASH_REMATCH[4]}
  main_pid_namespace=${BASH_REMATCH[5]}
else
  container_identity_parse_ok=0
fi
if [[ "$sibling_container_identity" =~ exe=([0-9]+:[0-9]+)[[:space:]]source=([0-9]+:[0-9]+)[[:space:]]sha256=([0-9a-f]{64})[[:space:]]mnt=([0-9]+)[[:space:]]pidns=([0-9]+)[[:space:]]generation=([0-9a-f-]{36})$ ]]; then
  sibling_executable=${BASH_REMATCH[1]}
  sibling_source=${BASH_REMATCH[2]}
  sibling_sha256=${BASH_REMATCH[3]}
  sibling_mount_namespace=${BASH_REMATCH[4]}
  sibling_pid_namespace=${BASH_REMATCH[5]}
  sibling_generation=${BASH_REMATCH[6]}
else
  container_identity_parse_ok=0
fi
if [ "$container_identity_parse_ok" -eq 1 ]; then
  if [ "$main_source" = "$sibling_source" ] \
    && [ "$main_sha256" = "$sibling_sha256" ] \
    && [ "$main_executable" != "$main_source" ] \
    && [ "$sibling_executable" != "$sibling_source" ] \
    && [ "$main_executable" != "$sibling_executable" ] \
    && [ "$main_mount_namespace" != "$sibling_mount_namespace" ] \
    && [ "$main_pid_namespace" != "$sibling_pid_namespace" ] \
    && [[ "$sibling_container_survived" == *" exe=$sibling_executable generation=$sibling_generation" ]]; then
    STAGE_STATUS=0
  else
    STAGE_STATUS=1
  fi
else
  STAGE_STATUS=1
fi
record_stage_status R-S11c-27n
if [ "$STAGE_STATUS" -eq 0 ]; then
  printf 'CROSS_CONTAINER_EXECUTABLE_IDENTITY=pass path=/usr/bin/rustdesk main=%s sibling=%s source=%s mnt=%s/%s pidns=%s/%s\n' \
    "$main_executable" "$sibling_executable" "$main_source" \
    "$main_mount_namespace" "$sibling_mount_namespace" "$main_pid_namespace" "$sibling_pid_namespace"
else
  echo "  FAIL R-S11c-27n: identical installed path/bytes/role did not remain bound to distinct executable and PID/mount namespace identities"
  rc=1
fi

echo "== (0d) Linux service-child recovery rejects actual forced numeric PID reuse (R-S11c-27o) =="
run_stage pid_reuse_out "${PID_REUSE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh service-pid-reuse
printf '%s\n' "$pid_reuse_out"
record_stage_status R-S11c-27o
pid_reuse_line=$(grep -E '^SERVICE_LIFECYCLE_PID_REUSE=pass old_pid=[0-9]+ reused_pid=[0-9]+ old_start=[0-9]+ reused_start=[0-9]+ old_generation=[0-9a-f-]{36} reused_generation=[0-9a-f-]{36} record_sha256=[0-9a-f]{64}$' <<<"$pid_reuse_out" || true)
if [[ "$pid_reuse_line" =~ old_pid=([0-9]+)[[:space:]]reused_pid=([0-9]+)[[:space:]]old_start=([0-9]+)[[:space:]]reused_start=([0-9]+) ]] \
  && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
  && [ "${BASH_REMATCH[3]}" != "${BASH_REMATCH[4]}" ]; then
  echo "  ok  R-S11c-27o actual kernel PID reuse kept numeric PID constant while start-time identity changed and recovery failed closed"
else
  echo "  FAIL R-S11c-27o: actual kernel PID reuse was not proven with same numeric PID, changed start time, preserved record, and live recycled child"
  rc=1
fi

echo "== (0e) Debian bookworm without systemd: installed SysV package start/restart/upgrade/remove and portable noninterference (R-S11c-27l) =="
run_stage sysv_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh debian-sysv-installed-lifecycle
printf '%s\n' "$sysv_out"
record_stage_status R-S11c-27l
grep -Eq '^DEBIAN_SYSV_INSTALLED_LIFECYCLE=pass os=debian-12 portable_uid=4000 stale_wrong_exec=survived$' <<<"$sysv_out" \
  || { echo "  FAIL R-S11c-27l: installed Debian SysV lifecycle or unrelated portable survival was not proven"; rc=1; }

echo "== (0f) Debian bookworm native OpenRC: exact supervisor/child authority, restart/stop/stale-pidfile/crash recovery, and portable noninterference (R-S11c-27q) =="
run_stage openrc_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh debian-openrc-native-lifecycle
printf '%s\n' "$openrc_out"
record_stage_status R-S11c-27q
grep -Eq '^OPENRC_NATIVE_LIFECYCLE=pass os=debian-12 openrc=0\.45\.2-2\+deb12u1 portable_uid=4000 normal_restart=pass stale_pidfile=overwritten crash_recovery=zap-start child_exit_ms=[0-9]+$' <<<"$openrc_out" \
  || { echo "  FAIL R-S11c-27q: native OpenRC lifecycle or unrelated portable survival was not proven"; rc=1; }

echo "== (0g) Debian bookworm native runit: exact runsvdir/runsv/supervisor/child authority, restart/stop/automatic crash recovery, native shutdown, and portable noninterference (R-S11c-27r) =="
run_stage runit_out "${LIFECYCLE_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh debian-runit-native-lifecycle
printf '%s\n' "$runit_out"
record_stage_status R-S11c-27r
grep -Eq '^RUNIT_NATIVE_LIFECYCLE=pass os=debian-12 runit=2\.1\.2-54 portable_uid=4000 normal_restart=pass crash_recovery=automatic manager_shutdown=hup-111 child_exit_ms=[0-9]+$' <<<"$runit_out" \
  || { echo "  FAIL R-S11c-27r: native runit lifecycle or unrelated portable survival was not proven"; rc=1; }
else
  echo "== (0c-0g) portable-rootless mode: root service, PID-reuse, and init-system lifecycle stages not entered =="
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

if [ "$SMOKE_MODE" = with-root-containers ]; then
echo "== (2b) R-D8/R-D2: the REAL portable 'rustdesk --password-stdin' CLI provisions over user-owned uid-scoped IPC and cleanly set-and-exits =="
# The other stages seed via the test-only examples/seed_password (a direct Config write) for speed,
# which bypasses the production path. This stage runs the real noninteractive `--password-stdin` CLI
# as root against a root-owned non-installed --server (the non-root same-uid path is stage 2c), so it
# exercises the typed user-owned password IPC end-to-end:
# the value-bound BeginUserOwnedPermanentPassword/status transaction, typed terminal result, storage sync, and the
# current-thread-runtime CLEAN TEARDOWN — the "set-and-exit" stock RustDesk lacked.
# We provision by CHANGING an initial seeded password (--server refuses to listen with none, R-A4) —
# the identical user-owned IPC path; service-launched servers are marked separately and reject this path.
run_stage out2b "${ROOT_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-root
echo "$out2b"
record_stage_status R-D8/R-D2
grep -q 'PW_EXIT=0' <<<"$out2b" \
  || { echo "  FAIL R-D2: the real --password-stdin CLI did not cleanly exit 0 within the timeout (hang/error — the stock never-returns regression)"; rc=1; }
grep -q 'Done!' <<<"$out2b" \
  || { echo "  FAIL R-D2: --password-stdin did not confirm success (no 'Done!') — the daemon did not ACK the IPC set"; rc=1; }
grep -q 'KEYED_NEW: keying ok=true' <<<"$out2b" \
  || { echo "  FAIL R-D8: the IPC-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
grep -q 'KEYED_OLD: keying ok=false' <<<"$out2b" \
  || { echo "  FAIL R-D8: the old password still keys — the --password-stdin change did not take effect over the daemon IPC"; rc=1; }

echo "== (2c) R-D8: portable 'rustdesk --password-stdin' provisions over SAME-UID user-owned IPC as a NON-ROOT owner =="
# An unprivileged owner (uid 4000) runs both non-installed --server and --password-stdin as itself.
# The request reaches its own per-uid raw IPC directly; the endpoint's per-uid mode and SO_PEERCRED
# identity are the authorization. This also exercises RLIMIT_NOFILE enforcement under non-root.
run_stage out2c "${ROOT_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-nonroot
echo "$out2c"
record_stage_status R-D8-nonroot
grep -q 'UID=4000' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) did not run as the intended non-root uid (4000)"; rc=1; }
grep -q 'SERVER_UID=4000' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) server was not owned by the intended non-root uid (4000)"; rc=1; }
grep -q 'PORTABLE_EXE=/tmp/rd-smoke-nonroot/bin/rustdesk' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) did not execute the isolated portable fixture image"; rc=1; }
grep -q 'SERVICE_ROLE_MARKER=absent' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) entered or could not disprove the service-owned role"; rc=1; }
grep -q 'PW_EXIT=0' <<<"$out2c" \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not cleanly exit 0"; rc=1; }
grep -q 'Done!' <<<"$out2c" \
  || { echo "  FAIL R-D8: same-uid --password-stdin did not confirm 'Done!' — the daemon did not ACK the non-root IPC set"; rc=1; }
grep -q 'KEYED_NEW: keying ok=true' <<<"$out2c" \
  || { echo "  FAIL R-D8: the same-uid-provisioned password is not usable — a CPace probe could not key with it"; rc=1; }
grep -q 'KEYED_OLD: keying ok=false' <<<"$out2c" \
  || { echo "  FAIL R-D8: the old password still keys after the same-uid change"; rc=1; }
grep -q 'SERVER_EXIT=0' <<<"$out2c" \
  || { echo "  FAIL R-D8: the non-root server did not terminate and reap cleanly"; rc=1; }
grep -q 'SOURCE_BIND_UNCHANGED=yes' <<<"$out2c" \
  || { echo "  FAIL R-D8: stage (2c) changed or could not re-prove the source bind"; rc=1; }

echo "== (2d) R-S11b: installed layout selects service ownership and never falls back to user-owned password storage =="
run_stage out2d "${ROOT_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-installed
echo "$out2d"
record_stage_status R-S11b
grep -q 'PW_EXIT=1' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout password request did not fail without the privileged service endpoint"; rc=1; }
grep -q 'KEYED_NEW: keying ok=false' <<<"$out2d" \
  || { echo "  FAIL R-S11b: installed-layout request fell back to user-owned password mutation"; rc=1; }
grep -q 'KEYED_OLD: keying ok=true' <<<"$out2d" \
  || { echo "  FAIL R-S11b: failed installed-layout request changed or disabled the existing credential"; rc=1; }
else
  echo "== (2b-2d) portable-rootless mode: root-owned/user-creation/installed-layout password fixtures not entered =="
fi

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
# cpace_it wire-ciphertext test + stage (9) prove the SEAL (the wire bytes are ciphertext); this stage
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

if [ "$SMOKE_MODE" = with-root-containers ]; then
echo "== (9) R-A9: wire-capture — a post-key LoginRequest canary is ENCRYPTED (never plaintext on the wire) =="
run_stage out9 "${ROOT_RUN[@]}" bash --noprofile --norc /work/scripts/smoke-server-stage.sh capture
echo "$out9"
record_stage_status R-A9
# R-A9: the session bytes are indistinguishable from random — a known plaintext canary sent on the
# KEYED stream NEVER appears on the captured wire (AEAD-sealed). The non-empty pcap + the in-binary
# sanity rule out a false pass (we captured real traffic, and the search pattern really matches).
grep -q 'CANARY_IN_BINARY: 1' <<<"$out9" \
  || { echo "  FAIL R-A9: the canary sanity check failed (the grep pattern does not match the probe binary)"; rc=1; }
grep -qE 'PCAP_SIZE: [0-9]{3,}' <<<"$out9" \
  || { echo "  FAIL R-A9: the wire capture was empty/trivial — no real traffic was captured"; rc=1; }
grep -q 'CANARY_ON_WIRE: NO' <<<"$out9" \
  || { echo "  FAIL R-A9: the LoginRequest canary appeared as PLAINTEXT on the wire — the session is NOT encrypted"; rc=1; }
else
  echo "== (9) portable-rootless mode: packet-capture stage not entered =="
fi

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
  if [ "$SMOKE_MODE" = with-root-containers ]; then
    echo "SMOKE OK: exact RustDesk executable under neutral smoke argv + mounted container stages + R-S11c-27o actual PID reuse recovery + R-S11c-27q native OpenRC exact lifecycle and portable noninterference + R-S11c-27r native runit exact lifecycle, automatic recovery, native shutdown, and portable noninterference + R-B4 build + socket surface (one v4 TCP on 127.0.0.1:21118, zero UDP) + R-A4 fail-closed/self-check + R-T9 graceful shutdown + R-D8/R-D2 non-installed user-owned --password-stdin IPC provisioning (clean set-and-exit; root-owned + non-root same-uid) + R-S11b installed-layout service ownership with no user-storage fallback + R-A1/R-S1 keying (two-process) + R-P3/R-P14c wrong-password refusal + R-T12 observability + R-T1 connection-flood capacity-shed + R-S6 keyed-edge authorization (full session) + R-F1/R-D6/R-S5 port-forward/RDP tunnel relays end-to-end inside the seal + R-F1/R-F2 file transfer (keyed FileTransfer login -> non-empty process-owner PeerInfo.username on a headless unix box, never the 'No active console user' refusal) + R-A8/R-T7 forged-frame rejection + R-A8.2/R-S10 owner-safe limiter + R-A9 wire-capture (no plaintext on the wire)${DECAY_NOTE} — ALL validated at RUNTIME."
  else
    echo "SMOKE ROOTLESS OK: exact numeric-nonroot RustDesk executable + R-B4 build + one container-loopback TCP listener on 127.0.0.1:21118 and zero UDP + fail-closed parked startup + graceful drain + VP9 MDWE + correct/wrong CPace keying + capacity shedding + authenticated Remote admission + sealed port-forward relay + FileTransfer admission + forged-frame rejection + owner-safe limiter${DECAY_NOTE}. Root/service/init-system/user-creation/installed-layout/packet-capture, graphical/native/device, performance/soak, and release-artifact evidence were not entered or claimed."
  fi
else
  echo "SMOKE FAILED"; exit 1
fi

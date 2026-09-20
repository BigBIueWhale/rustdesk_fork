#!/usr/bin/env bash
set -euo pipefail
umask 077

export PATH=/usr/bin:/bin
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] \
    || { echo "Android Rust release check refuses host or container-root execution" >&2; exit 1; }
[ "$BUILD_GID" -ne 0 ] \
    || { echo "Android Rust release check refuses a root primary group" >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$VERIFIER_VM_ENTRY_PREFLIGHT" ] && [ ! -L "$VERIFIER_VM_ENTRY_PREFLIGHT" ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1 ] \
    || { echo "Android Rust release check requires the verifier-VM entry preflight" >&2; exit 1; }
/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker
readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock
readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config
VERIFIER_VM_MARKER_DOCKER="$(/usr/bin/awk '{ print $2 }' \
    "$VERIFIER_VM_AUTHORITY_ROOT/authority")"
[ "$VERIFIER_VM_MARKER_DOCKER" = "docker=$VERIFIER_VM_DOCKER_VERSION" ] \
    || die "guest Docker authority differs from its repository pin"
readonly VERIFIER_VM_MARKER_DOCKER

verifier_vm_docker() {
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

verifier_vm_image_provenance() {
    local status=0
    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET" \
        DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG" \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py" "$@" \
        || status=$?
    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1
    return "$status"
}

require_verifier_vm_android_builder() {
    verifier_vm_image_provenance verify-local \
        --role android-builder \
        --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
        --image-ref "$ANDROID_BUILDER_CONFIG_ID" \
        --base "ubuntu:24.04@$SHA256_BASEIMAGE_UBUNTU_2404" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
        --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
        --config-id "$ANDROID_BUILDER_CONFIG_ID" \
        --manifest-id "$ANDROID_BUILDER_MANIFEST_ID" \
        || die "pinned Android builder image provenance verification failed"
}

if [ "$#" -eq 1 ] && [ "$1" = --self-test-vm-authority ]; then
    authority_version="$(verifier_vm_docker version \
        --format '{{.Client.Version}}|{{.Server.Version}}')" \
        || die "verifier-VM Docker authority self-test failed"
    [ "$authority_version" = \
      "$VERIFIER_VM_DOCKER_VERSION|$VERIFIER_VM_DOCKER_VERSION" ] \
        || die "verifier-VM Docker authority version differs: $authority_version"
    printf 'ANDROID_RUST_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed source=untouched online=untouched workload=unexecuted\n' \
        "$BUILD_UID" "$BUILD_GID" "$VERIFIER_VM_DOCKER_VERSION"
    exit 0
fi
[ "$#" -eq 0 ] \
    || die "Android Rust release check accepts no arguments except --self-test-vm-authority"

cd "$REPO_ROOT"

WORKSPACE=""
WORKSPACE_ID=""
cleanup_workspace() {
    local status=$? cleanup_failed=0
    trap - EXIT HUP INT TERM
    if [ -n "$WORKSPACE" ]; then
        if [ -z "$WORKSPACE_ID" ] || [ ! -d "$WORKSPACE" ] || [ -L "$WORKSPACE" ] \
            || [ "$(/usr/bin/stat -c '%d:%i' -- "$WORKSPACE" 2>/dev/null)" != "$WORKSPACE_ID" ]; then
            echo "android-rust-check: preserving changed private workspace: $WORKSPACE" >&2
            cleanup_failed=1
        elif ! /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$WORKSPACE" --expected-identity "$WORKSPACE_ID"; then
            echo "android-rust-check: failed to remove private workspace: $WORKSPACE" >&2
            cleanup_failed=1
        elif [ -e "$WORKSPACE" ] || [ -L "$WORKSPACE" ]; then
            echo "android-rust-check: private workspace survived removal: $WORKSPACE" >&2
            cleanup_failed=1
        fi
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

archive_current_source() {
    /usr/bin/git -c core.hooksPath=/dev/null -C "$REPO_ROOT" \
        ls-files -z --cached --others --exclude-standard \
        | /usr/bin/python3 -I -S -c '
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
for relative in sys.stdin.buffer.read().split(b"\0"):
    if not relative:
        continue
    path = os.path.join(root, relative)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(
            "Android Rust release-check source is not a regular file: "
            + os.fsdecode(relative)
        )
    sys.stdout.buffer.write(relative + b"\0")
' "$REPO_ROOT" \
        | /usr/bin/tar --create --file=- --directory="$REPO_ROOT" \
            --null --verbatim-files-from --no-recursion --files-from=- \
            --sort=name --format=gnu --mtime='@0' \
            --owner=0 --group=0 --numeric-owner
}

require_cmd git python3 sha256sum tar
require_online_complete
[[ "$ANDROID_BUILDER_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    && [[ "$ANDROID_BUILDER_CONFIG_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "Android Rust release check has malformed certified/runtime builder identities"

WORKSPACE="$(umask 077 && /usr/bin/mktemp -d /tmp/rustdesk-android-rust-check.XXXXXXXXXX)" \
    || die "cannot create Android Rust release-check workspace"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
    || die "Android Rust release-check workspace is not a real directory"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ] \
    || die "Android Rust release-check workspace is not current-user/current-group mode 0700"
WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORKSPACE")"
require_verifier_vm_android_builder

SOURCE_ARCHIVE="$WORKSPACE/source.tar"
SOURCE_AUTHORITY="$WORKSPACE/source-authority"
BUILD_SOURCE="$WORKSPACE/source-build"
/usr/bin/mkdir -- "$SOURCE_AUTHORITY" "$BUILD_SOURCE"
archive_current_source >"$SOURCE_ARCHIVE"
SOURCE_DIGEST="$(/usr/bin/sha256sum "$SOURCE_ARCHIVE" | /usr/bin/awk '{print $1}')"
/usr/bin/tar --extract --file="$SOURCE_ARCHIVE" --directory="$SOURCE_AUTHORITY"
/usr/bin/tar --extract --file="$SOURCE_ARCHIVE" --directory="$BUILD_SOURCE"
/usr/bin/chmod -R a=rX "$SOURCE_AUTHORITY"
/usr/bin/chmod -R u=rwX,go=rX "$BUILD_SOURCE"
/usr/bin/python3 -I -S "$SOURCE_AUTHORITY/scripts/verify-android-build-source.py" \
    --reference "$SOURCE_AUTHORITY" --candidate "$BUILD_SOURCE"

online="$(/usr/bin/readlink -f -- "$ONLINE_DIR")" \
    || die "cannot resolve the canonical online closure"
[ "$online" = "$ONLINE_DIR" ] || die "online closure must be canonical"

if ! verifier_vm_docker run --rm --pull=never --network=none --read-only \
    --user "$BUILD_UID:$BUILD_GID" \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=512 --memory=12g --memory-swap=12g --cpus=4 \
    --ulimit core=0:0 --ulimit nofile=4096:4096 \
    --ulimit fsize=2147483648:2147483648 \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g \
    --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_PIN" \
    --env RUSTDESK_CANARY_OFFLINE=1 \
    --env APK_MODE=rust-check \
    --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
    --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
    --mount "type=bind,source=$BUILD_SOURCE,target=/src,bind-recursive=disabled" \
    --mount "type=bind,source=$SOURCE_AUTHORITY/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$online,target=/online,readonly,bind-recursive=disabled" \
    --workdir /src \
    "$ANDROID_BUILDER_CONFIG_ID" \
    /bin/bash /authority/android-apk-build.sh; then
    die "Android Rust release-check container failed"
fi
/usr/bin/python3 -I -S "$SOURCE_AUTHORITY/scripts/verify-android-build-source.py" \
    --reference "$SOURCE_AUTHORITY" --candidate "$BUILD_SOURCE" --allow-extras
require_online_complete
SOURCE_DIGEST_AFTER="$(archive_current_source | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ] \
    || die "live source changed while the disposable Android Rust check was running"

echo "ANDROID-RUST-CHECK: aarch64 Android Rust library is GREEN"

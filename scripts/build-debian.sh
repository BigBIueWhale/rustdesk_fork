#!/usr/bin/env bash
# scripts/build-debian.sh — Debian x86_64 .deb build (R-B7/B8/B9, §12.1, §17).
#
# Reproduces upstream 1.4.7's OFFICIAL .deb build (R-B7: inherited, not reinvented)
# inside a digest-pinned ubuntu:18.04 container — upstream's own glibc baseline
# (run-on-arch-action) — with EXACTLY two deltas and no others: no code-signing,
# and it runs off GitHub-hosted runners (R-B2). The build is offline
# (--network=none) against the SHA-verified ./online cache (R-B10).
#
# One mode, the good one (R-B9): validate the EXACT pinned env, then abort; fail
# loud; no fallbacks; pin every version from pins.env; verify the artifact.
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
umask 077

export PATH=/usr/bin:/bin
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] \
    || { echo "Debian artifact building refuses host or container-root execution" >&2; exit 1; }
[ "$BUILD_GID" -ne 0 ] \
    || { echo "Debian artifact building refuses a root primary group" >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$VERIFIER_VM_ENTRY_PREFLIGHT" ] && [ ! -L "$VERIFIER_VM_ENTRY_PREFLIGHT" ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1 ] \
    || { echo "Debian artifact building requires the verifier-VM entry preflight" >&2; exit 1; }
/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"

if [ -n "${ONLINE_DIR+x}" ]; then
    printf 'build-debian: ONLINE_DIR is not an operator override; release snapshots use RUSTDESK_RELEASE_ONLINE_SNAPSHOT\n' >&2
    exit 1
fi

# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

SELF_TEST_VM_AUTHORITY=0
PROBE_IMAGE_ID=""
case "$#:${1:-}" in
    0:) ;;
    2:--self-test-vm-authority)
        SELF_TEST_VM_AUTHORITY=1
        PROBE_IMAGE_ID=$2
        ;;
    *)
        echo "usage: scripts/build-debian.sh [--self-test-vm-authority PROBE_IMAGE_ID]" >&2
        exit 2
        ;;
esac

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

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
OUT_PARENT=""
OUT_DESTINATION=""
OUT_PARENT_ID=""
# The §3.2 x64-linux feature set minus hwcodec: CPU-only VP8/VP9.
FEATURES="--flutter --unix-file-copy-paste"
# Determinism (R-B2): SOURCE_DATE_EPOCH is a FIXED pinned epoch (SOURCE_DATE_EPOCH_PIN in pins.env),
# NOT a commit date — so the .deb depends only on the source tree; build.rs honours it. (An
# operator override, `export SOURCE_DATE_EPOCH=...`, still wins.)
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_PIN}"
# The pinned .deb build image: the digest-pinned ubuntu:18.04 baseline + the system
# build-deps, baked by online-fetch.sh (the ONE networked step) via Dockerfile.deb-builder.
# The compile then runs inside it with --network=none.
IMAGE_ID="${DEB_BUILDER_CONFIG_ID:-}"
RELEASE_CHILD=0
ONLINE_SNAPSHOT_PARENT=""
OWNED_WORKSPACE=""
OWNED_WORKSPACE_ID=""
SOURCE_COMMIT=""
BUILD_SOURCE_ROOT=""
BUILD_SOURCE_ID=""
PASS_A_DEB=""
PASS_A_DEB_ID=""
PASS_A_SHA256=""
PASS_B_SHA256=""
PENDING_RESULT=""
PENDING_RESULT_ID=""

cleanup_owned_workspace() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$OWNED_WORKSPACE" ]; then
        if ! remove_owned_workspace_exact; then
            warn "preserving changed private Debian build workspace: $OWNED_WORKSPACE"
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup_owned_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

remove_owned_workspace_exact() {
    [ -n "$OWNED_WORKSPACE" ] && [ -n "$OWNED_WORKSPACE_ID" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$OWNED_WORKSPACE" \
            --expected-identity "$OWNED_WORKSPACE_ID" \
        || return 1
    { [ ! -e "$OWNED_WORKSPACE" ] && [ ! -L "$OWNED_WORKSPACE" ]; } || return 1
    OWNED_WORKSPACE=""
    OWNED_WORKSPACE_ID=""
}

record_output_parent_identity() {
    local metadata owner group mode device inode extra
    [ -d "$OUT_PARENT" ] && [ ! -L "$OUT_PARENT" ] \
        || die "Debian output parent must be a real directory"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$OUT_PARENT" 2>/dev/null)" \
        || die "Debian output-parent identity is unavailable"
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$BUILD_UID" ] \
        && [ "$group" = "$BUILD_GID" ] \
        && [ $((8#$mode & 8#700)) -eq $((8#700)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        || die "Debian output parent does not grant only current-principal write authority"
    [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "Debian output-parent identity is malformed"
    OUT_PARENT_ID="$device:$inode"
}

prepare_output_contract() {
    local planned_parent planned_destination
    case "$OUT_DIR" in
        /*) ;;
        *) die "Debian output directory must be absolute" ;;
    esac
    planned_parent="$(/usr/bin/dirname -- "$OUT_DIR")" \
        || die "cannot derive Debian output parent"
    planned_destination="$(/usr/bin/basename -- "$OUT_DIR")" \
        || die "cannot derive Debian output destination"
    [ "$planned_parent" != / ] \
        || die "Debian output parent must not be the filesystem root"
    [ -d "$planned_parent" ] && [ ! -L "$planned_parent" ] \
        || die "Debian output parent must already be a real directory"
    OUT_PARENT="$(/usr/bin/readlink -f -- "$planned_parent" 2>/dev/null)" \
        || die "Debian output parent cannot be resolved"
    [ "$OUT_PARENT" = "$planned_parent" ] \
        || die "Debian output parent must be absolute, canonical, and non-symlinked"
    OUT_DESTINATION="$planned_destination"
    [ "$OUT_DIR" = "$OUT_PARENT/$OUT_DESTINATION" ] \
        || die "Debian output directory must be one canonical parent edge"
    [[ "$OUT_DESTINATION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || die "Debian output destination name is malformed"
    record_output_parent_identity
    { [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; } \
        || die "Debian output directory must be absent for no-clobber publication"
}

assert_private_directory() {
    local path="$1" label="$2" resolved metadata
    case "$path" in
        /*) ;;
        *) die "$label must be an absolute path" ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be a canonical non-symlinked path"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is absent"
    [ "$metadata" = "$BUILD_UID:700" ] || die "$label must be a current-UID mode-0700 directory"
}

assert_private_online_snapshot() {
    local parent="$1" online bad
    assert_private_directory "$parent" "online snapshot parent"
    online="$parent/online"
    [ -d "$online" ] && [ ! -L "$online" ] || die "online snapshot tree must be a real directory"
    [ "$(stat -c '%u:%a' -- "$online" 2>/dev/null)" = "$BUILD_UID:500" ] \
        || die "online snapshot tree must be a current-UID mode-0500 directory"
    bad="$(find "$online" \( ! -uid "$BUILD_UID" -o \
        \( \( -type f -o -type d \) -perm /0222 \) \) -print -quit)" \
        || die "cannot inspect online snapshot ownership and modes"
    [ -z "$bad" ] || die "online snapshot contains a writable or differently owned path: $bad"
    verify_private_online_snapshot "$parent"
}

git_closed() {
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
        command git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

assert_private_build_source() {
    local path="$1" label="$2" resolved metadata current common dirt remotes sparse index_flags
    case "$path" in
        /*) ;;
        *) die "$label must be an absolute path" ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be canonical and non-symlinked"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is absent"
    [ "$metadata" = "$BUILD_UID:700" ] \
        || die "$label must be a current-UID mode-0700 directory"
    current="$(git_closed -C "$path" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "$label has no exact Git commit"
    [ "$current" = "$SOURCE_COMMIT" ] || die "$label commit changed"
    common="$(git_closed -C "$path" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
        || die "$label Git directory cannot be resolved"
    [ "$common" = "$path/.git" ] && [ -d "$common" ] && [ ! -L "$common" ] \
        || die "$label does not own a private Git directory"
    [ ! -e "$common/info/grafts" ] && [ ! -L "$common/info/grafts" ] \
        || die "$label contains Git grafts"
    [ ! -e "$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternates" ] \
        || die "$label contains Git object alternates"
    [ ! -e "$common/shallow" ] && [ ! -L "$common/shallow" ] \
        || die "$label is shallow"
    [ "$(git_closed -C "$path" rev-parse --is-shallow-repository 2>/dev/null)" = false ] \
        || die "$label cannot prove complete Git history"
    [ -z "$(git_closed -C "$path" for-each-ref --format='%(refname)' refs/replace 2>/dev/null)" ] \
        || die "$label contains Git replacement refs"
    remotes="$(git_closed -C "$path" remote 2>/dev/null)" || die "$label remotes cannot be inspected"
    [ -z "$remotes" ] || die "$label retains a Git remote"
    sparse="$(git_closed -C "$path" config --local --no-includes --bool core.sparseCheckout 2>/dev/null || true)"
    [ "$sparse" != true ] || die "$label uses a sparse checkout"
    index_flags="$(git_closed -C "$path" ls-files -v 2>/dev/null)" \
        || die "$label index flags cannot be inspected"
    if printf '%s\n' "$index_flags" \
        | awk 'substr($0,1,1) != "H" { found=1 } END { exit found ? 0 : 1 }'; then
        die "$label contains noncanonical index flags"
    fi
    git_closed -C "$path" symbolic-ref --quiet HEAD >/dev/null 2>&1 \
        && die "$label is not detached"
    dirt="$(git_closed -C "$path" status --porcelain=v1 --untracked-files=no 2>/dev/null)" \
        || die "$label tracked state cannot be inspected"
    [ -z "$dirt" ] || die "$label tracked state differs from the exact commit"
    git_closed -C "$path" diff --quiet --no-ext-diff HEAD -- \
        || die "$label worktree differs from the exact commit"
    git_closed -C "$path" diff --cached --quiet --no-ext-diff HEAD -- \
        || die "$label index differs from the exact commit"
}

prepare_direct_build_source() {
    local label="$1" source
    source="$OWNED_WORKSPACE/source-$label"
    [ ! -e "$source" ] && [ ! -L "$source" ] \
        || die "direct Debian build source path was not freshly absent"
    git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source" \
        || die "cannot create private direct Debian source $label"
    git_closed -C "$source" checkout --quiet --detach "$SOURCE_COMMIT" \
        || die "cannot check out private direct Debian source $label"
    git_closed -C "$source" remote remove origin \
        || die "cannot detach private direct Debian source $label"
    chmod 0700 "$source" || die "cannot protect private direct Debian source $label"
    git_closed -C "$source" fsck --full --strict --no-reflogs >/dev/null \
        || die "private direct Debian source $label has invalid Git objects"
    BUILD_SOURCE_ROOT="$source"
    BUILD_SOURCE_ID="$(stat -c '%d:%i' -- "$BUILD_SOURCE_ROOT")" \
        || die "cannot record private direct Debian source identity"
    assert_private_build_source "$BUILD_SOURCE_ROOT" "private direct Debian source $label"
}

activate_build_source() {
    local label="$1"
    if [ "$RELEASE_CHILD" -eq 1 ]; then
        BUILD_SOURCE_ROOT="$REPO_ROOT"
        BUILD_SOURCE_ID="$(stat -c '%d:%i' -- "$BUILD_SOURCE_ROOT")" \
            || die "cannot record release Debian source identity"
        assert_private_build_source "$BUILD_SOURCE_ROOT" "release Debian source"
    else
        prepare_direct_build_source "$label"
    fi
}

verify_build_source_postcondition() {
    local label="$1" observed
    observed="$(stat -c '%d:%i' -- "$BUILD_SOURCE_ROOT" 2>/dev/null)" \
        || die "$label source identity cannot be inspected after compilation"
    [ "$observed" = "$BUILD_SOURCE_ID" ] || die "$label source identity changed during compilation"
    assert_private_build_source "$BUILD_SOURCE_ROOT" "$label source after compilation"
}

prepare_execution_contract() {
    local current
    current="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || die "cannot resolve the exact Debian source commit"
    [[ "$current" =~ ^[0-9a-f]{40}$ ]] \
        || die "Debian source commit must be one full lowercase commit ID"
    SOURCE_COMMIT="$current"
    OWNED_WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX)" \
        || die "cannot create private Debian build workspace"
    chmod 0700 "$OWNED_WORKSPACE" \
        || die "cannot protect private Debian build workspace"
    [ "$(/usr/bin/readlink -f -- "$OWNED_WORKSPACE" 2>/dev/null)" = "$OWNED_WORKSPACE" ] \
        || die "private Debian build workspace is not canonical"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$OWNED_WORKSPACE" 2>/dev/null)" = "$BUILD_UID:$BUILD_GID:700" ] \
        || die "private Debian build workspace is not current-principal mode 0700"
    OWNED_WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i' -- "$OWNED_WORKSPACE" 2>/dev/null)" \
        || die "private Debian build-workspace identity is unavailable"
    [[ "$OWNED_WORKSPACE_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || die "private Debian build-workspace identity is malformed"
    if [ -n "${RELEASE_SRC_COMMIT:-}" ]; then
        RELEASE_CHILD=1
        [[ "$RELEASE_SRC_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            || die "RELEASE_SRC_COMMIT must be one full lowercase commit ID"
        [ "$current" = "$RELEASE_SRC_COMMIT" ] || die "release-child source commit does not equal HEAD"
        [ -n "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
        [ -n "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "release child requires RELEASE_DOCKER_IMAGE_ID"
        ONLINE_SNAPSHOT_PARENT="$RUSTDESK_RELEASE_ONLINE_SNAPSHOT"
    else
        [ -z "${RUSTDESK_RELEASE_ONLINE_SNAPSHOT:-}" ] \
            || die "RUSTDESK_RELEASE_ONLINE_SNAPSHOT is release-internal"
        [ -z "${RELEASE_DOCKER_IMAGE_ID:-}" ] \
            || die "RELEASE_DOCKER_IMAGE_ID is release-internal"
    fi
}

resolve_image() {
    require_pinned_builder_image deb-builder "$IMAGE_ID" verifier_vm_image_provenance
    if [ "$RELEASE_CHILD" -eq 1 ] && [ "$RELEASE_DOCKER_IMAGE_ID" != "$IMAGE_ID" ]; then
        die "release Debian runtime image ID does not equal DEB_BUILDER_CONFIG_ID"
    fi
}

activate_online_snapshot() {
    if [ "$RELEASE_CHILD" -eq 0 ]; then
        require_online_complete
        ONLINE_SNAPSHOT_PARENT="$OWNED_WORKSPACE/online-input"
        create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    fi
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
    ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"
}

verify_active_online_snapshot() {
    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null \
        || die "Debian builder verifier-VM authority changed"
    assert_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
}

preflight() {
    require_cmd basename cmp dirname dpkg-deb find git python3 readlink sha256sum stat
    assert_repo_state
    assert_clean_worktree
    assert_source_date_epoch
    prepare_output_contract
    prepare_execution_contract
    resolve_image
    activate_online_snapshot
    # §12.3 / R-B10 (trust nobody): re-verify the exact ./online tarballs this offline build extracts
    # against their pins BEFORE building — a corrupt cache or a stray version-renamed tarball dies here.
    verify_online_shas \
        "rust-${RUST_VERSION}.tar.xz"       "${SHA256_RUST_1_75}" \
        "flutter-${FLUTTER_VERSION}.tar.xz" "${SHA256_FLUTTER_3_24_5}" \
        "llvm-${LLVM_VERSION}.tar.xz"       "${SHA256_LLVM_15_0_6}"
    case "$SHA256_BASEIMAGE_UBUNTU_1804" in *"${SHA_PENDING}"*) die "the ubuntu:18.04 base digest is the R-B12 sentinel — record it in pins.env first" ;; esac
    case "${DOUBLE_BUILD:-1}" in
        0|1) ;;
        *) die "DOUBLE_BUILD must be exactly 0 or 1" ;;
    esac
    if [ "$RELEASE_CHILD" -eq 1 ] && [ "${DOUBLE_BUILD:-1}" != 0 ]; then
        die "release child requires outer independent snapshots and DOUBLE_BUILD=0"
    fi
    log "preflight OK — building exact commit $SOURCE_COMMIT with $FEATURES in $IMAGE_ID, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

verify_deb_control_scripts() {
    local deb="$1"
    local tmp_package tmp_control tmp_data
    tmp_package="$(umask 077 && mktemp -d "$OWNED_WORKSPACE/debian-package-check.XXXXXXXXXX")" \
        || die "cannot create private Debian package-check workspace"
    tmp_control="$tmp_package/control"
    tmp_data="$tmp_package/data"
    mkdir "$tmp_control" "$tmp_data"
    dpkg-deb -e "$deb" "$tmp_control"
    dpkg-deb -x "$deb" "$tmp_data"
    for script in preinst postinst prerm postrm; do
        [ -f "$tmp_control/$script" ] \
          && [ ! -L "$tmp_control/$script" ] \
          && [ "$(stat -c '%a:%h' "$tmp_control/$script" 2>/dev/null)" = "755:1" ] || {
            die "built .deb control script $script is not a mode-0755 non-hardlinked regular file"
        }
        cmp -s "$BUILD_SOURCE_ROOT/res/DEBIAN/$script" "$tmp_control/$script" || {
            die "built .deb control script $script differs from res/DEBIAN/$script"
        }
    done
    [ -f "$tmp_data/etc/init.d/rustdesk" ] \
      && [ ! -L "$tmp_data/etc/init.d/rustdesk" ] \
      && [ "$(stat -c '%a:%h' "$tmp_data/etc/init.d/rustdesk" 2>/dev/null)" = "755:1" ] || {
        die "built .deb SysV init script is not a mode-0755 non-hardlinked regular file"
    }
    cmp -s "$BUILD_SOURCE_ROOT/res/rustdesk.init" "$tmp_data/etc/init.d/rustdesk" || {
        die "built .deb SysV init script differs from res/rustdesk.init"
    }
    [ -f "$tmp_data/usr/lib/systemd/system/rustdesk.service" ] \
      && [ ! -L "$tmp_data/usr/lib/systemd/system/rustdesk.service" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$tmp_data/usr/lib/systemd/system/rustdesk.service" 2>/dev/null)" = "$BUILD_UID:$BUILD_GID:644:1" ] || {
        die "built .deb systemd unit is not a mode-0644 non-hardlinked regular file"
    }
    cmp -s "$BUILD_SOURCE_ROOT/res/rustdesk.service" "$tmp_data/usr/lib/systemd/system/rustdesk.service" || {
        die "built .deb systemd unit differs from res/rustdesk.service"
    }
    [ ! -e "$tmp_data/usr/share/rustdesk/files/systemd/rustdesk.service" ] \
      && [ ! -L "$tmp_data/usr/share/rustdesk/files/systemd/rustdesk.service" ] || {
        die "built .deb retains the legacy maintainer-script systemd unit template"
    }
    [ -L "$tmp_data/usr/bin/rustdesk" ] \
      && [ "$(readlink "$tmp_data/usr/bin/rustdesk")" = "../share/rustdesk/rustdesk" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$tmp_data/usr/bin/rustdesk" 2>/dev/null)" = "$BUILD_UID:$BUILD_GID:777:1" ] || {
        die "built .deb command is not the exact mode-0777 non-hardlinked relative symlink"
    }
    local template
    for template in openrc/rustdesk runit/run manual/rustdesk-service; do
        [ -f "$tmp_data/usr/share/rustdesk/files/$template" ] \
          && [ ! -L "$tmp_data/usr/share/rustdesk/files/$template" ] \
          && [ "$(stat -c '%a:%h' "$tmp_data/usr/share/rustdesk/files/$template" 2>/dev/null)" = "755:1" ] || {
            die "built .deb service-manager template $template is not a mode-0755 non-hardlinked regular file"
        }
        cmp -s \
            "$BUILD_SOURCE_ROOT/res/service-managers/$template" \
            "$tmp_data/usr/share/rustdesk/files/$template" || {
            die "built .deb service-manager template $template differs from its source"
        }
    done
    local masked
    masked="$(grep -RInE '\|\|[[:space:]]*true|deb-systemd-(invoke|helper).*\|\|' "$tmp_control" || true)"
    if [ -n "$masked" ]; then
        printf '%s\n' "$masked" >&2
        die "built .deb maintainer scripts mask lifecycle failure"
    fi
    python3 "$SCRIPT_DIR/verify-debian-maintainer-scripts.py" \
        --scripts-dir "$tmp_control" \
        --init-script "$tmp_data/etc/init.d/rustdesk" \
        --openrc-script "$tmp_data/usr/share/rustdesk/files/openrc/rustdesk" \
        --runit-run "$tmp_data/usr/share/rustdesk/files/runit/run" \
        --manual-run "$tmp_data/usr/share/rustdesk/files/manual/rustdesk-service" || {
        die "built .deb maintainer scripts fail lifecycle semantics"
    }
}

debian_compiler_run() {
    [ "$#" -ge 2 ] || die "Debian compiler launch requires IMAGE COMMAND [ARG...]"
    local image=$1
    shift
    verifier_vm_docker run --rm --pull=never \
        --network=none \
        --read-only \
        --user "$BUILD_UID:$BUILD_GID" \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --cgroupns=private \
        --ipc=private \
        --pids-limit=1024 \
        --memory=16g \
        --memory-swap=16g \
        --cpus=4 \
        --ulimit core=0:0 \
        --ulimit nofile=65536:65536 \
        --ulimit fsize=4294967296:4294967296 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g \
        --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
        --env RUSTDESK_CANARY_OFFLINE=1 \
        --mount "type=bind,source=$BUILD_SOURCE_ROOT,target=/src,bind-recursive=disabled" \
        --tmpfs /src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --workdir /src \
        "$image" "$@"
}

run_vm_authority_self_test() {
    [[ "$PROBE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "Debian builder verifier-VM probe image ID is malformed"
    local authority_version containers_before containers_after online_before online_after
    local profile_output profile_probe
    authority_version="$(verifier_vm_docker version \
        --format '{{.Client.Version}}|{{.Server.Version}}')" \
        || die "Debian builder verifier-VM Docker authority self-test failed"
    [ "$authority_version" = \
      "$VERIFIER_VM_DOCKER_VERSION|$VERIFIER_VM_DOCKER_VERSION" ] \
        || die "verifier-VM Docker authority version differs: $authority_version"

    OWNED_WORKSPACE="$(umask 077 && /usr/bin/mktemp -d /tmp/rustdesk-debian-profile.XXXXXXXXXX)" \
        || die "cannot create private Debian profile workspace"
    /usr/bin/chmod 0700 "$OWNED_WORKSPACE" \
        || die "cannot protect private Debian profile workspace"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$OWNED_WORKSPACE")" = \
      "$BUILD_UID:$BUILD_GID:700" ] \
        || die "Debian profile workspace is not current-principal mode 0700"
    OWNED_WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i' -- "$OWNED_WORKSPACE")" \
        || die "cannot record private Debian profile workspace identity"
    BUILD_SOURCE_ROOT=$OWNED_WORKSPACE/source
    ONLINE_DIR=$OWNED_WORKSPACE/online
    /usr/bin/mkdir "$BUILD_SOURCE_ROOT" "$BUILD_SOURCE_ROOT/.git" "$ONLINE_DIR"
    /usr/bin/chmod 0700 "$BUILD_SOURCE_ROOT" "$BUILD_SOURCE_ROOT/.git" "$ONLINE_DIR"
    printf 'must be hidden\n' >"$BUILD_SOURCE_ROOT/.git/host-only"
    printf 'immutable input\n' >"$ONLINE_DIR/input"
    /usr/bin/chmod 0400 "$BUILD_SOURCE_ROOT/.git/host-only" "$ONLINE_DIR/input"
    online_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$ONLINE_DIR/input"):$(/usr/bin/sha256sum "$ONLINE_DIR/input")"
    containers_before="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || die "cannot record the initial guest container inventory"

    profile_probe='
        [ "$$" = 1 ]
        [ "$SOURCE_DATE_EPOCH" = "$1" ]
        [ "$RUSTDESK_CANARY_OFFLINE" = 1 ]
        uid= gid= cap= nnp= seccomp=
        while IFS=":" read -r key value; do
            set -- $value
            case "$key" in
                Uid) uid="$1:$2:$3:$4" ;;
                Gid) gid="$1:$2:$3:$4" ;;
                CapEff) cap=$1 ;;
                NoNewPrivs) nnp=$1 ;;
                Seccomp) seccomp=$1 ;;
            esac
        done </proc/self/status
        [ "$uid" = 4000:4000:4000:4000 ]
        [ "$gid" = 4000:4000:4000:4000 ]
        [ "$cap" = 0000000000000000 ]
        [ "$nnp" = 1 ]
        [ "$seccomp" = 2 ]
        IFS= read -r apparmor </proc/self/attr/current
        case "$apparmor" in docker-default\ *) ;; *) exit 90 ;; esac
        IFS= read -r pids_max </sys/fs/cgroup/pids.max
        IFS= read -r memory_max </sys/fs/cgroup/memory.max
        IFS= read -r swap_max </sys/fs/cgroup/memory.swap.max
        IFS=" " read -r cpu_quota cpu_period </sys/fs/cgroup/cpu.max
        [ "$pids_max" = 1024 ]
        [ "$memory_max" = 17179869184 ]
        [ "$swap_max" = 0 ]
        [ "$cpu_quota:$cpu_period" = 400000:100000 ]
        [ "$(ulimit -c)" = 0 ]
        [ "$(ulimit -n)" = 65536 ]
        fsize_limit=
        while IFS=" " read -r first second third soft hard unit remainder; do
            case "$first:$second:$third" in
                Max:file:size) fsize_limit="$soft:$hard:$unit" ;;
            esac
        done </proc/self/limits
        [ "$fsize_limit" = 4294967296:4294967296:bytes ]
        set -- /sys/class/net/*
        [ "$#" = 1 ] && [ "$1" = /sys/class/net/lo ]
        if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
        [ ! -e /src/.git/host-only ]
        if (: >/src/.git/forbidden-write) 2>/dev/null; then exit 92; fi
        [ "$(IFS= read -r line </online/input; printf %s "$line")" = "immutable input" ]
        if (: >/online/forbidden-write) 2>/dev/null; then exit 93; fi
        printf "private build output\n" >/src/profile-output
        tmp_options= git_options=
        while IFS=" " read -r device mountpoint filesystem options remainder; do
            case "$mountpoint" in
                /tmp) tmp_options=$options ;;
                /src/.git) git_options=$options ;;
            esac
        done </proc/mounts
        case ",$tmp_options," in *,rw,*nosuid,*nodev,*) ;; *) exit 94 ;; esac
        case ",$git_options," in *,ro,*nosuid,*nodev,*noexec,*) ;; *) exit 95 ;; esac
        printf "profile=debian-compiler uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default mounts=source-rw,git-hidden-ro,online-ro\n"
    '
    profile_output="$(debian_compiler_run "$PROBE_IMAGE_ID" \
        -euc "$profile_probe" debian-compiler "$SOURCE_DATE_EPOCH")" \
        || die "Debian compiler production profile failed"
    [ "$profile_output" = \
      'profile=debian-compiler uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default mounts=source-rw,git-hidden-ro,online-ro' ] \
        || die "Debian compiler profile receipt differs: $profile_output"
    [ "$(<"$BUILD_SOURCE_ROOT/profile-output")" = 'private build output' ] \
        || die "Debian compiler profile did not write only its private source fixture"
    [ "$(<"$BUILD_SOURCE_ROOT/.git/host-only")" = 'must be hidden' ] \
        || die "Debian compiler profile changed hidden Git authority"
    online_after="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$ONLINE_DIR/input"):$(/usr/bin/sha256sum "$ONLINE_DIR/input")"
    [ "$online_after" = "$online_before" ] \
        || die "Debian compiler profile changed its read-only online input"
    [ ! -e "$ONLINE_DIR/forbidden-write" ] && [ ! -L "$ONLINE_DIR/forbidden-write" ] \
        || die "Debian compiler profile wrote its online input"
    containers_after="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || die "cannot record the final guest container inventory"
    [ "$containers_after" = "$containers_before" ] \
        || die "Debian compiler profile left a guest container behind"
    remove_owned_workspace_exact \
        || die "Debian compiler profile workspace cleanup failed"
    printf 'DEBIAN_BUILDER_VM_AUTHORITY=pass uid=%s gid=%s docker=%s profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined\n' \
        "$BUILD_UID" "$BUILD_GID" "$VERIFIER_VM_DOCKER_VERSION"
}

# build_one PROFILE FEATURES PASS: run upstream's build.py in the pinned container,
# network removed, ./online mounted read-only. Validate the exact private .deb and
# retain only its object identity and digest for later no-clobber publication.
build_one() {
    local profile="$1" features="$2" pass="$3"
    log "building profile '$profile' (features: $features)"
    # HONESTY GATE (the af8746f class): build.py renames the freshly built package to
    # $BUILD_SOURCE_ROOT/rustdesk-<version>.deb, and the post-build step copies whatever
    # rustdesk-*.deb it finds there. A PRIOR run leaves one behind (root-owned), so if a
    # build fails WITHOUT producing a new one, that STALE .deb would be picked up and shipped
    # as a false success. Remove any pre-existing rustdesk-*.deb up front (these are
    # git-ignored artifacts) so the gate below can ONLY find a package THIS run produced.
    rm -f "$BUILD_SOURCE_ROOT"/rustdesk-*.deb
    verify_active_online_snapshot
    if ! debian_compiler_run "$IMAGE_ID" \
        bash -euo pipefail -c '
            # The container is the pinned, immutable template (R-B8): everything
            # comes from /online (R-B5a), nothing is fetched (--network=none).
            TC=/tmp/tc; mkdir -p "$TC"
            # Extract the pinned toolchains from the ./online tarballs that
            # online-fetch.sh materialized (Rust 1.75, Flutter 3.24.5, NDK, LLVM 15,
            # vcpkg snapshot) and put their bins on PATH. vcpkg then builds the
            # native set offline from res/vcpkg overlay ports.
            # rust-1.* (NOT rust-*) so the glob does not also grab the android cross-std
            # online/rust-std-1.75-aarch64-linux-android.tar.xz (added for the .apk build).
            for t in /online/rust-1.*.tar.xz /online/flutter-*.tar.xz /online/llvm-*.tar.xz; do
                [ -e "$t" ] && tar -C "$TC" -xf "$t"
            done
            # Rust: the standalone tarball extracts to rust-1.75.0-.../ with an install.sh
            # (there is no top-level bin/) — install it to a prefix. LLVM: the tarball is
            # clang+llvm-15.0.6-.../ — point bindgen at its libclang.
            "$TC"/rust-1.*/install.sh --prefix="$TC/rustinstall" --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
            LLVM_ROOT="$(echo "$TC"/clang+llvm-*)"
            export LIBCLANG_PATH="$LLVM_ROOT/lib"
            # The native codecs (vpx/yuv/opus) come from the vcpkg overlay tree that
            # online-fetch'\''s stage_vcpkg_natives built (R-R1 pinned, x64-linux static).
            # scrap + magnum-opus link them from VCPKG_ROOT/installed/x64-linux (the shipped
            # feature set has linux-pkg-config OFF, so build.rs find_package needs VCPKG_ROOT).
            export VCPKG_ROOT=/online/vcpkg
            [ -d "$VCPKG_ROOT/installed/x64-linux/lib" ] || { echo "[FATAL] /online/vcpkg/installed/x64-linux missing -- run online-fetch.sh (stage_vcpkg_natives)"; exit 1; }
            export CARGO_PROFILE_RELEASE_RPATH=false
            # Use a build-time CARGO_HOME so the vendored/offline config does NOT
            # overwrite the repo'\''s TRACKED .cargo/config.toml (which carries the
            # windows/macos rustflags); cargo merges CARGO_HOME/config.toml with it.
            export CARGO_HOME=/tmp/cargo-home
            mkdir -p "$CARGO_HOME"
            # The pre-built FRB codegen tool is staged at /online/frb-tool/bin by
            # online-fetch'\''s build_frb_codegen (built FOR ubuntu:18.04 there).
            export PATH="$TC/flutter/bin:$TC/rustinstall/bin:/online/frb-tool/bin:$CARGO_HOME/bin:$PATH"
            # Shadow `flutter` with the offline shim (scripts/flutter-offline-shim.sh): the
            # flutter wrapper drives `pub` ONLINE (it refreshes pub security advisories, which
            # _TypeError against the read-only offline cache → rc=1), so route `flutter pub
            # {run,get}` (FRB ffigen + any implicit get) to `dart --offline`; `flutter build
            # linux` passes through to the real flutter ($REAL_FLUTTER) unchanged.
            export REAL_FLUTTER="$TC/flutter/bin/flutter"
            SHIM=/tmp/flutter-shim; mkdir -p "$SHIM"
            cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"; chmod +x "$SHIM/flutter"
            export PATH="$SHIM:$PATH"
            # Wire cargo to the vendored, lockfile-pinned crate set (R-B10) so the
            # --locked build resolves from ./online/cargo-vendor, never the network.
            # The vendor_cargo step captured the AUTHORITATIVE [source.*] map (the cargo
            # vendor output: [source.crates-io] replace-with="vendored-sources", every
            # git-dep source, and [source.vendored-sources]). Use it verbatim (rewrite its
            # directory to /online/cargo-vendor) + ONLY add [net] offline. Do NOT also
            # hand-write a [source.crates-io] -- that duplicates the table and cargo (incl.
            # cargo-metadata, which FRB codegen runs) rejects it (duplicate key crates-io).
            cat > "$CARGO_HOME/config.toml" <<CFG
[net]
offline = true
CFG
            [ -f /online/cargo-vendor-config.toml ] || { echo "[FATAL] /online/cargo-vendor-config.toml missing -- run online-fetch.sh"; exit 1; }
            sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
            # Flutter pub OFFLINE from the staged cache (online-fetch stage_pub_cache).
            # Fix git "dubious ownership" on the root-owned flutter SDK + the git-dep clones,
            # set PUB_CACHE, and pre-resolve the project --offline (the committed pubspec.lock
            # pins it) so the .dart_tool exists -- then FRB build_runner + flutter build use it
            # without auto-running a networked pub get.
            export HOME=/tmp/buildhome; mkdir -p "$HOME"
            git config --global --add safe.directory "*"
            export PUB_CACHE=/online/pub-cache
            [ -d "$PUB_CACHE" ] || { echo "[FATAL] /online/pub-cache missing -- run online-fetch.sh (stage_pub_cache)"; exit 1; }
            pub_lock_before="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            # Resolve the project: dart pub get --offline reads straight from PUB_CACHE and
            # skips advisories (validated against the staged cache). It is the ONLINE flutter
            # wrapper pub get that refreshes pub security advisories and _TypeErrors against the
            # read-only offline cache → rc=1; `--offline` (here and the flutter injection below)
            # avoids that advisories fetch entirely.
            export CI=true   # non-interactive flutter (suppress the fresh-HOME first-run prompt)
            ( cd flutter && dart pub get --offline --enforce-lockfile )
            # Pre-resolve the flutter SDK'\''s OWN tool package (packages/flutter_tools) OFFLINE before
            # ANY `flutter` invocation: the cold tarball ships it UNRESOLVED, and the first `flutter ...`
            # would otherwise re-resolve it IN-PROCESS + ONLINE (pub.dev + the advisories _TypeError).
            # Its deps are staged in PUB_CACHE by stage_pub_cache. Must precede the injection + build below.
            ( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline --enforce-lockfile )
            # Plugin injection (R-B7), mirroring build-windows.ps1:107-110. `dart pub get`
            # resolves the project (writes .dart_tool) but does NOT run flutter'\''s plugin
            # injection, which is what (re)generates flutter/linux/flutter/generated_plugins.cmake
            # + flutter/linux/flutter/ephemeral/.plugin_symlinks/* + flutter/.flutter-plugins{,-dependencies}.
            # The git-ignored ephemeral symlinks are stale across runs -- a prior build wrote them
            # pointing at /root/.pub-cache (its PUB_CACHE), so under THIS build'\''s PUB_CACHE=/online/pub-cache
            # they DANGLE and `flutter build linux` CMake-aborts: "add_subdirectory given source
            # flutter/ephemeral/.plugin_symlinks/<plugin>/linux which is not an existing directory"
            # (generated_plugins.cmake:23). Run the FLUTTER-level pub get to re-inject them against the
            # current PUB_CACHE. Use $REAL_FLUTTER (NOT the shim, which routes `pub get`->`dart pub get`
            # and so SKIPS injection) with --offline: only the ONLINE wrapper pub get refreshes the
            # advisories that _TypeError on the read-only cache; `flutter pub get --offline` resolves
            # straight from PUB_CACHE WITHOUT advisories (proven: "Got dependencies!", rc=0), so the
            # injection runs clean offline. The regenerated symlinks resolve under /online/pub-cache and
            # each <plugin>/linux exists. (.flutter-plugins-dependencies carries a wall-clock date_created,
            # but it is git-ignored build-input metadata referenced by nothing in build/linux/.../bundle/,
            # so it never reaches the .deb payload -- R-B2 unaffected, enforced by the DOUBLE_BUILD A==B gate.)
            # R-B9 idempotency: DELETE the stale ephemeral symlinks FIRST. `flutter pub get` does NOT
            # overwrite an existing (dangling) symlink, so if a prior build (even from another session)
            # left flutter/linux/flutter/ephemeral/.plugin_symlinks/* pointing at its own PUB_CACHE, the
            # re-injection below is SKIPPED and `flutter build linux` CMake-aborts on every plugin
            # ("<plugin>/linux is not an existing directory"). Removing them forces a clean re-inject
            # against the current PUB_CACHE. Git-ignored build-input metadata (never in the .deb
            # payload), regenerated identically by both double-build passes, so A==B is unaffected.
            # This makes the build safe to re-run on a non-pristine tree (R-B9 "re-running is safe").
            rm -rf flutter/linux/flutter/ephemeral/.plugin_symlinks \
                   flutter/.flutter-plugins-dependencies flutter/.flutter-plugins
            ( cd flutter && "$REAL_FLUTTER" pub get --offline --enforce-lockfile )
            pub_lock_after="$(sha256sum flutter/pubspec.lock | awk "{print \$1}")"
            [ "$pub_lock_before" = "$pub_lock_after" ] || {
                echo "[FATAL] flutter/pubspec.lock changed during offline pub resolution" >&2
                git --no-pager diff -- flutter/pubspec.lock || true
                exit 1
            }
            # FRB codegen first (R-B7: the uncommitted generated_bridge.dart /
            # bridge_generated.rs every build job needs), then upstream build.py
            # with the §3.2 x64-linux features.
            # --llvm-compiler-opts: give ffigen'\''s libclang the clang BUILTIN-header dir so it
            # can resolve <stdbool.h>. Without it ffigen emits "[SEVERE] stdbool.h not found" and
            # DEGRADES every bool-returning binding (e.g. mainPeerHasPassword) to a raw
            # NativeFunction<Int...> → the flutter `kernel_snapshot` Dart compile then fails.
            flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
                --dart-output ./flutter/lib/generated_bridge.dart \
                --llvm-path "$LLVM_ROOT" \
                --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)"
            python3 ./build.py '"$features"'
        '; then
        verify_active_online_snapshot
        verify_build_source_postcondition "failed Debian $profile build"
        die "Debian build container failed for profile $profile"
    fi
    verify_active_online_snapshot
    verify_build_source_postcondition "completed Debian $profile build"
    # build.py fails loud (system2 → sys.exit(-1)) on any step, so a non-zero docker run already
    # aborts under set -e. This is the second line of defence: with the stale .deb purged above,
    # a missing rustdesk-*.deb now unambiguously means build.py did NOT emit one (e.g. flutter
    # build linux failed) -- fail loud rather than ship nothing/something stale.
    local -a packages=("$BUILD_SOURCE_ROOT"/rustdesk-*.deb)
    [ "${#packages[@]}" -eq 1 ] \
        && [ "${packages[0]}" != "$BUILD_SOURCE_ROOT/rustdesk-*.deb" ] \
        || die "Debian build must emit exactly one rustdesk-*.deb package"
    local deb="${packages[0]}" basename metadata owner group mode links size device inode extra
    basename="${deb##*/}"
    [[ "$basename" =~ ^rustdesk-[A-Za-z0-9._+-]+\.deb$ ]] \
        || die "Debian build emitted a package with a malformed basename"
    [ -f "$deb" ] && [ ! -L "$deb" ] \
        || die "Debian build output is not one regular package"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i' -- "$deb" 2>/dev/null)" \
        || die "Debian build-output identity is unavailable"
    IFS=: read -r owner group mode links size device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$BUILD_UID" ] \
        && [ "$group" = "$BUILD_GID" ] \
        && [ "$links" = 1 ] \
        && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
        && [ "$size" -le $((4 * 1024 * 1024 * 1024)) ] \
        && [ $((8#$mode & 8#7133)) -eq 0 ] \
        && [ $((8#$mode & 8#400)) -eq $((8#400)) ] \
        || die "Debian build output metadata is unsafe"
    [[ "$device" =~ ^[0-9]+$ ]] && [[ "$inode" =~ ^[1-9][0-9]*$ ]] \
        || die "Debian build-output identity is malformed"
    local package_identity="$device:$inode"
    local before_sha256 after_sha256 after_metadata
    before_sha256="$(sha256sum -- "$deb")" \
        || die "cannot hash private Debian build output"
    before_sha256="${before_sha256%% *}"
    [[ "$before_sha256" =~ ^[0-9a-f]{64}$ ]] \
        || die "private Debian build-output SHA-256 is malformed"
    /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-debian-package-authority.py" \
        --repo "$BUILD_SOURCE_ROOT" --deb "$deb"
    verify_deb_control_scripts "$deb"
    verify_build_source_postcondition "verified Debian $profile build"
    verify_active_online_snapshot
    after_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s:%d:%i' -- "$deb" 2>/dev/null)" \
        || die "verified Debian build-output identity is unavailable"
    after_sha256="$(sha256sum -- "$deb")" \
        || die "cannot rehash verified Debian build output"
    after_sha256="${after_sha256%% *}"
    [ "$after_metadata" = "$metadata" ] && [ "$after_sha256" = "$before_sha256" ] \
        || die "Debian build output changed while it was verified"
    case "$pass" in
        pass-a)
            PASS_A_DEB="$deb"
            PASS_A_DEB_ID="$package_identity"
            PASS_A_SHA256="$before_sha256"
            ;;
        pass-b)
            PASS_B_SHA256="$before_sha256"
            ;;
        *) die "unknown private Debian build pass: $pass" ;;
    esac
}

prepare_pending_result() {
    local authority extra
    [ -n "$PASS_A_DEB" ] && [ -n "$PASS_A_DEB_ID" ] && [ -n "$PASS_A_SHA256" ] \
        || die "validated Debian pass-A authority is incomplete"
    [ -n "$OUT_PARENT" ] && [ -n "$OUT_PARENT_ID" ] && [ -n "$OUT_DESTINATION" ] \
        || die "Debian output-parent authority is incomplete"
    authority="$(/usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py" \
            --prepare \
            --artifact-kind debian-x86_64 \
            --source "$PASS_A_DEB" \
            --source-identity "$PASS_A_DEB_ID" \
            --source-sha256 "$PASS_A_SHA256" \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --destination "$OUT_DESTINATION")" \
        || die "Debian output candidate preparation failed"
    read -r PENDING_RESULT PENDING_RESULT_ID extra <<<"$authority"
    [[ "$PENDING_RESULT" =~ ^\.debian-output-pending-[0-9a-f]{64}$ ]] \
        && [[ "$PENDING_RESULT_ID" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        && [ -z "$extra" ] \
        || die "pending Debian output authority is malformed"
}

publish_result() {
    PENDING_RESULT=""
    PENDING_RESULT_ID=""
    verify_active_online_snapshot
    verify_build_source_postcondition "final Debian build-source state"
    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null \
        || die "Debian builder verifier-VM authority changed before publication"
    prepare_pending_result
    remove_owned_workspace_exact \
        || die "private Debian build workspace could not retire before final publication"
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py" \
            --commit \
            --artifact-kind debian-x86_64 \
            --output-parent "$OUT_PARENT" \
            --output-parent-identity "$OUT_PARENT_ID" \
            --pending "$PENDING_RESULT" \
            --pending-identity "$PENDING_RESULT_ID" \
            --destination "$OUT_DESTINATION"
}

main() {
    preflight
    # The one .deb — viewer and --server in a single binary, role by argv (R-R2b/R-B1).
    activate_build_source pass-a
    build_one x86_64 "$FEATURES" pass-a

    # Double-build determinism (R-B2): a second independent private build of
    # identical source MUST produce a byte-identical SHA-256. Neither pass is
    # caller-visible until that equality and every package check have succeeded.
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        activate_build_source pass-b
        build_one x86_64 "$FEATURES" pass-b
        [ "$PASS_A_SHA256" = "$PASS_B_SHA256" ] \
            || die "double-build SHA mismatch ($PASS_A_SHA256 vs $PASS_B_SHA256) — fix BUILD_DATE/SOURCE_DATE_EPOCH determinism (R-B2)"
        log "double-build determinism OK: $PASS_A_SHA256"
    fi

    publish_result
}

if [ "$SELF_TEST_VM_AUTHORITY" -eq 1 ]; then
    run_vm_authority_self_test
else
    main
fi

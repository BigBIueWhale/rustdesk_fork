#!/usr/bin/env bash
# Shared least-authority Docker runtime for the pinned Windows build helper.
# This file is sourced after scripts/lib.sh and scripts/pins.env are loaded.

export PATH=/usr/bin:/bin
WINDOWS_HELPER_RUNTIME_ROOT=""
WINDOWS_HELPER_RUNTIME_ROOT_ID=""
WINDOWS_HELPER_RUNTIME_READY=0
WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0
WINDOWS_HELPER_KVM_GID=""
WINDOWS_HELPER_EXTRACTOR_SHA256=""
WINDOWS_HELPER_INSPECTOR_SHA256=""
WINDOWS_HELPER_VALIDATED_MOUNT_TARGET=""
WINDOWS_HELPER_VALIDATED_MOUNT_VALUE=""

windows_helper_assert_private_directory() {
    local path="$1" label="$2" resolved metadata
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(/usr/bin/readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be canonical and non-symlinked"
    metadata="$(/usr/bin/stat -c '%u:%g:%a' -- "$path" 2>/dev/null)" \
        || die "$label is unavailable"
    [ "$metadata" = "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:700" ] \
        || die "$label must be a current-principal mode-0700 directory"
}

windows_helper_assert_authority_file() {
    local path="$1" expected_sha="$2" label="$3" metadata
    [ -f "$path" ] && [ ! -L "$path" ] || die "$label must be a regular non-symlink file"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$path" 2>/dev/null)" \
        || die "$label is unavailable"
    [ "$metadata" = "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:400:1" ] \
        || die "$label must be current-principal mode-0400 and single-link"
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$expected_sha" ] \
        || die "$label SHA-256 changed"
}

windows_helper_assert_runtime() {
    local kernel="$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz" metadata
    [ "$WINDOWS_HELPER_RUNTIME_READY" = 1 ] || die "Windows helper runtime is not resolved"
    assert_local_docker_authority || die "Windows helper local-Docker authority changed"
    windows_helper_assert_private_directory \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority" "Windows helper program authority"
    windows_helper_assert_private_directory \
        "$WINDOWS_HELPER_RUNTIME_ROOT/kernel" "Windows helper kernel authority"
    windows_helper_assert_authority_file \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-helper-extract-kernel.py" \
        "$WINDOWS_HELPER_EXTRACTOR_SHA256" "Windows helper kernel extractor"
    windows_helper_assert_authority_file \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh" \
        "$WINDOWS_HELPER_INSPECTOR_SHA256" "Windows golden inspector"
    [ -f "$kernel" ] && [ ! -L "$kernel" ] \
        || die "Windows helper kernel must be a regular non-symlink file"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$kernel" 2>/dev/null)" \
        || die "Windows helper kernel is unavailable"
    case "$metadata" in
        "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:400:1:"[1-9]*) ;;
        *) die "Windows helper kernel must be non-empty, current-principal mode-0400, and single-link" ;;
    esac
    [ "$(/usr/bin/sha256sum -- "$kernel" | /usr/bin/awk '{print $1}')" = \
        "$SHA256_WIN_HELPER_KERNEL" ] \
        || die "Windows helper kernel SHA-256 changed"
}

windows_helper_authority_open() {
    [ -z "$WINDOWS_HELPER_RUNTIME_ROOT" ] || die "Windows helper authority is already open"
    [ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \
        || die "Windows helper Docker authority state is already open"
    [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \
        || die "Windows helper refuses an existing process-local Docker authority"
    [ "${WINDOWS_HELPER_BUILD_UID:-}" = "$(/usr/bin/id -u)" ] \
        || die "Windows helper captured UID authority is unavailable or changed"
    [ "${WINDOWS_HELPER_BUILD_GID:-}" = "$(/usr/bin/id -g)" ] \
        || die "Windows helper captured GID authority is unavailable or changed"
    [ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
        || die "Windows helper containers refuse host or container-root execution"
    [ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
        || die "Windows helper containers refuse a root primary group"
    WINDOWS_HELPER_RUNTIME_ROOT="$(
        umask 077
        /usr/bin/mktemp -d /tmp/rustdesk-windows-helper.XXXXXXXXXX
    )" || die "cannot create private Windows helper authority"
    /usr/bin/chmod 0700 "$WINDOWS_HELPER_RUNTIME_ROOT"
    windows_helper_assert_private_directory \
        "$WINDOWS_HELPER_RUNTIME_ROOT" "Windows helper runtime root"
    WINDOWS_HELPER_RUNTIME_ROOT_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$WINDOWS_HELPER_RUNTIME_ROOT"
    )" || die "cannot record Windows helper runtime-root identity"
    /usr/bin/install -d -m 0700 \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/kernel"
    initialize_local_docker_authority \
        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \
        "Windows helper runtime"
    WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=1
}

windows_helper_authority_close() {
    if [ -z "$WINDOWS_HELPER_RUNTIME_ROOT" ]; then
        [ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \
            && [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \
            || { echo "Windows helper empty runtime has live Docker authority state" >&2; return 1; }
        return 0
    fi
    if [ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 1 ]; then
        [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
            || { echo "Windows helper preserving runtime after premature Docker authority loss" >&2; return 1; }
        remove_local_docker_authority || return 1
        WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0
    elif [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then
        echo "Windows helper preserving runtime with unowned Docker authority" >&2
        return 1
    fi
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT" \
            --expected-identity "$WINDOWS_HELPER_RUNTIME_ROOT_ID" \
        || return 1
    { [ ! -e "$WINDOWS_HELPER_RUNTIME_ROOT" ] \
        && [ ! -L "$WINDOWS_HELPER_RUNTIME_ROOT" ]; } \
        || return 1
    WINDOWS_HELPER_RUNTIME_ROOT=""
    WINDOWS_HELPER_RUNTIME_ROOT_ID=""
    WINDOWS_HELPER_RUNTIME_READY=0
    WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0
    WINDOWS_HELPER_KVM_GID=""
}

windows_helper_snapshot_program() {
    local source="$1" name="$2" destination sha
    [ -f "$source" ] && [ ! -L "$source" ] \
        || die "Windows helper authority program must be a regular non-symlink file: $source"
    case "$name" in
        *[!A-Za-z0-9._-]*|'') die "Windows helper authority-program basename is malformed" ;;
    esac
    destination="$WINDOWS_HELPER_RUNTIME_ROOT/authority/$name"
    [ ! -e "$destination" ] && [ ! -L "$destination" ] \
        || die "Windows helper authority-program destination is occupied"
    /usr/bin/install -m 0400 -- "$source" "$destination"
    /usr/bin/cmp -s -- "$source" "$destination" \
        || die "Windows helper authority-program snapshot differs from its source"
    sha="$(/usr/bin/sha256sum -- "$destination" | /usr/bin/awk '{print $1}')"
    windows_helper_assert_authority_file "$destination" "$sha" "Windows helper authority program"
    printf '%s\n' "$sha"
}

windows_helper_validate_mount() {
    local value="$1" rest source target suffix metadata mode links
    case "$value" in
        type=bind,source=*,target=*) ;;
        *) die "Windows helper containers accept only explicit bind mounts" ;;
    esac
    rest="${value#type=bind,source=}"
    source="${rest%%,target=*}"
    [ "$rest" != "$source" ] || die "Windows helper bind mount lacks a target"
    rest="${rest#*,target=}"
    target="${rest%%,*}"
    suffix="${rest#"$target"}"
    case "$suffix" in
        ''|,readonly) ;;
        *) die "Windows helper bind mount has unsupported options: $value" ;;
    esac
    case "$source" in
        /*) ;;
        *) die "Windows helper bind source must be absolute" ;;
    esac
    case "$target" in
        /*) ;;
        *) die "Windows helper bind target must be absolute" ;;
    esac
    [ "$(realpath -ms -- "$target" 2>/dev/null)" = "$target" ] \
        || die "Windows helper bind target must be lexically canonical"
    case "$target" in
        /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/var/run|/var/run/*|\
        /tmp|/tmp/*|/var/tmp|/var/tmp/*|/authority/kernel|/authority/kernel/*|\
        /authority|/authority/windows-golden-inspect.sh)
            die "Windows helper bind target overlaps fixed runtime authority: $target"
            ;;
    esac
    [ -e "$source" ] && [ ! -L "$source" ] \
        || die "Windows helper bind source must exist without a terminal symlink: $source"
    [ "$(readlink -f -- "$source")" = "$source" ] \
        || die "Windows helper bind source must be canonical: $source"
    if [ ! -f "$source" ] && [ ! -d "$source" ]; then
        die "Windows helper bind source must be a regular file or directory"
    fi
    if [ -z "$suffix" ]; then
        metadata="$(/usr/bin/stat -c '%u:%a:%h' -- "$source" 2>/dev/null)" \
            || die "cannot inspect writable Windows helper bind source"
        [ "${metadata%%:*}" = "$WINDOWS_HELPER_BUILD_UID" ] \
            || die "writable Windows helper bind source must be current-UID owned"
        metadata="${metadata#*:}"
        mode="${metadata%%:*}"
        links="${metadata#*:}"
        [ $((8#$mode & 8#022)) -eq 0 ] \
            || die "writable Windows helper bind source must not be group/world writable"
        if [ -f "$source" ] && [ "$links" != 1 ]; then
            die "writable Windows helper file must be single-link"
        fi
    fi
    WINDOWS_HELPER_VALIDATED_MOUNT_TARGET="$target"
    WINDOWS_HELPER_VALIDATED_MOUNT_VALUE="$value,bind-recursive=disabled"
}

windows_helper_parse_mounts() {
    WINDOWS_HELPER_MOUNTS=()
    WINDOWS_HELPER_COMMAND=()
    local -a targets=()
    local target existing
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
        [ "$1" = --mount ] || die "Windows helper runtime accepts only --mount before --"
        [ "$#" -ge 2 ] || die "Windows helper --mount is missing its value"
        windows_helper_validate_mount "$2"
        target="$WINDOWS_HELPER_VALIDATED_MOUNT_TARGET"
        for existing in "${targets[@]}"; do
            [ "$existing" != "$target" ] \
                || die "Windows helper bind target is duplicated: $target"
        done
        targets+=("$target")
        WINDOWS_HELPER_MOUNTS+=(--mount "$WINDOWS_HELPER_VALIDATED_MOUNT_VALUE")
        shift 2
    done
    [ "$#" -gt 0 ] && [ "$1" = -- ] || die "Windows helper runtime requires an option terminator"
    shift
    [ "$#" -gt 0 ] || die "Windows helper runtime requires a fixed command"
    WINDOWS_HELPER_COMMAND=("$@")
}

windows_helper_run_profile() {
    local profile="$1"
    shift
    windows_helper_parse_mounts "$@"
    local -a limits runtime
    case "$profile" in
        bootstrap|small)
            limits=(--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1)
            runtime=(--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m)
            ;;
        media)
            limits=(--pids-limit=64 --memory=2g --memory-swap=2g --cpus=2)
            runtime=(--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m)
            ;;
        guestfish|kvm-guestfish)
            limits=(--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2)
            runtime=(
                --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g
                --tmpfs /var/tmp:rw,exec,nosuid,nodev,mode=1777,size=512m
                --env HOME=/tmp
                --env TMPDIR=/tmp
                --env LIBGUESTFS_BACKEND=direct
                --env LIBGUESTFS_CACHEDIR=/tmp
                --env LIBGUESTFS_TMPDIR=/tmp
                --env SUPERMIN_KERNEL=/authority/kernel/vmlinuz
                --env "SUPERMIN_MODULES=/lib/modules/$WIN_HELPER_KERNEL_VERSION"
                --env "SUPERMIN_KERNEL_VERSION=$WIN_HELPER_KERNEL_VERSION"
                --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly,bind-recursive=disabled"
                --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh,target=/authority/windows-golden-inspect.sh,readonly,bind-recursive=disabled"
            )
            ;;
        *) die "unknown Windows helper runtime profile: $profile" ;;
    esac
    if [ "$profile" = kvm-guestfish ]; then
        [ -e /dev/kvm ] && [ ! -L /dev/kvm ] || die "/dev/kvm is unavailable"
        WINDOWS_HELPER_KVM_GID="$(/usr/bin/stat -c %g -- /dev/kvm 2>/dev/null)" \
            || die "cannot inspect /dev/kvm group authority"
        case "$WINDOWS_HELPER_KVM_GID" in
            ''|*[!0-9]*|0) die "/dev/kvm must have one non-root numeric group" ;;
        esac
        runtime+=(
            --group-add "$WINDOWS_HELPER_KVM_GID"
            --device /dev/kvm:/dev/kvm:rw
        )
    fi
    if [ "$profile" = bootstrap ]; then
        assert_local_docker_authority || die "Windows helper local-Docker authority changed"
        windows_helper_assert_authority_file \
            "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-helper-extract-kernel.py" \
            "$WINDOWS_HELPER_EXTRACTOR_SHA256" "Windows helper kernel extractor"
        windows_helper_assert_authority_file \
            "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh" \
            "$WINDOWS_HELPER_INSPECTOR_SHA256" "Windows golden inspector"
    else
        windows_helper_assert_runtime
    fi
    local status
    if local_docker run --rm --pull=never --network=none --read-only \
        --user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --ulimit core=0:0 --ulimit nofile=4096:4096 \
        --ulimit fsize=137438953472:137438953472 \
        "${limits[@]}" "${runtime[@]}" "${WINDOWS_HELPER_MOUNTS[@]}" \
        "$WIN_HELPER_IMAGE_ID" "${WINDOWS_HELPER_COMMAND[@]}"; then
        status=0
    else
        status=$?
    fi
    if [ "$profile" = bootstrap ]; then
        assert_local_docker_authority || die "Windows helper local-Docker authority changed"
    else
        windows_helper_assert_runtime
    fi
    return "$status"
}

windows_helper_bootstrap_run() {
    windows_helper_run_profile bootstrap "$@"
}

windows_helper_small_run() {
    windows_helper_run_profile small "$@"
}

windows_helper_media_run() {
    windows_helper_run_profile media "$@"
}

windows_helper_guestfish_run() {
    windows_helper_run_profile guestfish "$@"
}

windows_helper_kvm_guestfish_run() {
    windows_helper_run_profile kvm-guestfish "$@"
}

windows_helper_verify_archive() {
    [ "$#" -eq 1 ] \
        || die "windows_helper_verify_archive requires one archive path"
    /usr/bin/python3 "$LIB_DIR/offline-image-provenance.py" verify-archive \
        --archive "$1" \
        --archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \
        --archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE" \
        --role win-helper \
        --expected-id "$WIN_HELPER_IMAGE_ID" \
        --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE" \
        --dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST" \
        --bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
        --config-id "$WIN_HELPER_CONFIG_ID" \
        --manifest-id "$WIN_HELPER_MANIFEST_ID"
}

windows_helper_runtime_resolve() {
    local archive="$1" extractor_source inspector_source kernel
    [ "$WINDOWS_HELPER_RUNTIME_READY" = 0 ] || die "Windows helper runtime is already resolved"
    assert_local_docker_authority || die "Windows helper local-Docker authority changed"
    archive="$(readlink -f -- "$archive" 2>/dev/null)" \
        || die "cannot resolve the pinned Windows helper image archive"
    [ -f "$archive" ] && [ ! -L "$archive" ] \
        || die "pinned Windows helper image archive must be a regular non-symlink file"
    windows_helper_verify_archive "$archive" \
        || die "pinned Windows helper image archive provenance verification failed"
    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"
    assert_local_docker_authority || die "Windows helper local-Docker authority changed"

    extractor_source="$LIB_DIR/windows-helper-extract-kernel.py"
    inspector_source="$LIB_DIR/windows-golden-inspect.sh"
    WINDOWS_HELPER_EXTRACTOR_SHA256="$(
        windows_helper_snapshot_program "$extractor_source" windows-helper-extract-kernel.py
    )"
    WINDOWS_HELPER_INSPECTOR_SHA256="$(
        windows_helper_snapshot_program "$inspector_source" windows-golden-inspect.sh
    )"
    kernel="$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz"
    windows_helper_bootstrap_run \
        --mount "type=bind,source=$archive,target=/authority/image.tar.gz,readonly" \
        --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-helper-extract-kernel.py,target=/authority/windows-helper-extract-kernel.py,readonly" \
        --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel,target=/out" \
        -- /usr/bin/python3 /authority/windows-helper-extract-kernel.py \
            --archive /authority/image.tar.gz \
            --output /out/vmlinuz \
            --kernel-version "$WIN_HELPER_KERNEL_VERSION" \
            --kernel-sha256 "$SHA256_WIN_HELPER_KERNEL" \
        || die "confined Windows helper kernel derivation failed"
    windows_helper_verify_archive "$archive" \
        || die "Windows helper image archive changed during kernel derivation"
    /usr/bin/cmp -s -- "$extractor_source" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-helper-extract-kernel.py" \
        || die "Windows helper kernel-extractor source changed during its snapshot"
    /usr/bin/cmp -s -- "$inspector_source" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh" \
        || die "Windows golden-inspector source changed during its snapshot"
    [ -f "$kernel" ] && [ ! -L "$kernel" ] \
        || die "confined Windows helper kernel derivation produced no regular file"
    WINDOWS_HELPER_RUNTIME_READY=1
    windows_helper_assert_runtime
}

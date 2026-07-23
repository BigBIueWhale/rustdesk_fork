#!/usr/bin/env bash
# Shared least-authority Docker runtime for the pinned Windows build helper.
# This file is sourced after scripts/lib.sh and scripts/pins.env are loaded.

export PATH=/usr/bin:/bin
WINDOWS_HELPER_DOCKER_BIN=/usr/bin/docker
WINDOWS_HELPER_DOCKER_HOST=unix:///var/run/docker.sock
WINDOWS_HELPER_RUNTIME_ROOT=""
WINDOWS_HELPER_RUNTIME_READY=0
WINDOWS_HELPER_BUILD_UID="$(id -u)"
WINDOWS_HELPER_BUILD_GID="$(id -g)"
WINDOWS_HELPER_KVM_GID=""
WINDOWS_HELPER_EXTRACTOR_SHA256=""
WINDOWS_HELPER_INSPECTOR_SHA256=""

windows_helper_assert_private_directory() {
    local path="$1" label="$2" resolved metadata
    [ -d "$path" ] && [ ! -L "$path" ] || die "$label must be a real directory"
    resolved="$(readlink -f -- "$path" 2>/dev/null)" || die "$label cannot be resolved"
    [ "$resolved" = "$path" ] || die "$label must be canonical and non-symlinked"
    metadata="$(stat -c '%u:%a' -- "$path" 2>/dev/null)" || die "$label is unavailable"
    [ "$metadata" = "$WINDOWS_HELPER_BUILD_UID:700" ] \
        || die "$label must be a current-UID mode-0700 directory"
}

windows_helper_assert_authority_file() {
    local path="$1" expected_sha="$2" label="$3" metadata
    [ -f "$path" ] && [ ! -L "$path" ] || die "$label must be a regular non-symlink file"
    metadata="$(stat -c '%u:%a:%h' -- "$path" 2>/dev/null)" || die "$label is unavailable"
    [ "$metadata" = "$WINDOWS_HELPER_BUILD_UID:400:1" ] \
        || die "$label must be current-UID mode-0400 and single-link"
    [ "$(sha256sum -- "$path" | awk '{print $1}')" = "$expected_sha" ] \
        || die "$label SHA-256 changed"
}

windows_helper_assert_docker_config() {
    local config metadata
    [ -n "$WINDOWS_HELPER_RUNTIME_ROOT" ] || die "Windows helper authority is not open"
    windows_helper_assert_private_directory \
        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" "Windows helper Docker configuration"
    config="$WINDOWS_HELPER_RUNTIME_ROOT/docker-config/config.json"
    [ -f "$config" ] && [ ! -L "$config" ] \
        || die "Windows helper Docker config.json must be a regular non-symlink file"
    metadata="$(stat -c '%u:%a:%h' -- "$config" 2>/dev/null)" \
        || die "Windows helper Docker config.json is unavailable"
    [ "$metadata" = "$WINDOWS_HELPER_BUILD_UID:600:1" ] \
        || die "Windows helper Docker config.json must be current-UID mode-0600 and single-link"
    cmp -s -- "$config" <(printf '{}\n') \
        || die "Windows helper Docker config.json must remain the canonical empty configuration"
    [ "${DOCKER_CONFIG:-}" = "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" ] \
        || die "Windows helper Docker configuration authority changed"
    [ "${DOCKER_HOST:-}" = "$WINDOWS_HELPER_DOCKER_HOST" ] \
        || die "Windows helper Docker daemon authority changed"
}

windows_helper_assert_runtime() {
    local kernel="$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz" metadata
    [ "$WINDOWS_HELPER_RUNTIME_READY" = 1 ] || die "Windows helper runtime is not resolved"
    windows_helper_assert_docker_config
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
    metadata="$(stat -c '%u:%a:%h:%s' -- "$kernel" 2>/dev/null)" \
        || die "Windows helper kernel is unavailable"
    case "$metadata" in
        "$WINDOWS_HELPER_BUILD_UID:400:1:"[1-9]*) ;;
        *) die "Windows helper kernel must be non-empty, current-UID mode-0400, and single-link" ;;
    esac
    [ "$(sha256sum -- "$kernel" | awk '{print $1}')" = "$SHA256_WIN_HELPER_KERNEL" ] \
        || die "Windows helper kernel SHA-256 changed"
}

windows_helper_authority_open() {
    local docker_metadata
    [ -z "$WINDOWS_HELPER_RUNTIME_ROOT" ] || die "Windows helper authority is already open"
    [ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
        || die "Windows helper containers refuse host or container-root execution"
    [ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
        || die "Windows helper containers refuse a root primary group"
    [ -f "$WINDOWS_HELPER_DOCKER_BIN" ] && [ ! -L "$WINDOWS_HELPER_DOCKER_BIN" ] \
        && [ -x "$WINDOWS_HELPER_DOCKER_BIN" ] \
        || die "trusted Docker client is unavailable at $WINDOWS_HELPER_DOCKER_BIN"
    docker_metadata="$(stat -c '%u:%g:%a:%h' -- "$WINDOWS_HELPER_DOCKER_BIN" 2>/dev/null)" \
        || die "cannot inspect the trusted Docker client"
    [ "$docker_metadata" = "0:0:755:1" ] \
        || die "trusted Docker client must be a root-owned mode-0755 single-link file"
    case "${DOCKER_HOST:-$WINDOWS_HELPER_DOCKER_HOST}" in
        "$WINDOWS_HELPER_DOCKER_HOST") ;;
        *) die "Windows helper containers require the local Docker Unix socket" ;;
    esac
    local variable
    for variable in \
        DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \
        DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST \
        DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS; do
        [ -z "${!variable+x}" ] \
            || die "$variable must not influence Windows helper containers"
    done
    WINDOWS_HELPER_RUNTIME_ROOT="$(
        umask 077
        mktemp -d /tmp/rustdesk-windows-helper.XXXXXXXXXX
    )" || die "cannot create private Windows helper authority"
    chmod 0700 "$WINDOWS_HELPER_RUNTIME_ROOT"
    install -d -m 0700 \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/kernel"
    printf '{}\n' >"$WINDOWS_HELPER_RUNTIME_ROOT/docker-config/config.json"
    chmod 0600 "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config/config.json"
    export DOCKER_HOST="$WINDOWS_HELPER_DOCKER_HOST"
    export DOCKER_CONFIG="$WINDOWS_HELPER_RUNTIME_ROOT/docker-config"
    windows_helper_assert_docker_config
}

windows_helper_authority_close() {
    local status=0
    if [ -n "$WINDOWS_HELPER_RUNTIME_ROOT" ] \
        && [ -d "$WINDOWS_HELPER_RUNTIME_ROOT" ] \
        && [ ! -L "$WINDOWS_HELPER_RUNTIME_ROOT" ]; then
        chmod -R u+rwX "$WINDOWS_HELPER_RUNTIME_ROOT" 2>/dev/null || status=1
        rm -rf -- "$WINDOWS_HELPER_RUNTIME_ROOT" || status=1
    fi
    WINDOWS_HELPER_RUNTIME_ROOT=""
    WINDOWS_HELPER_RUNTIME_READY=0
    WINDOWS_HELPER_KVM_GID=""
    unset DOCKER_CONFIG
    return "$status"
}

windows_helper_docker_command() {
    local status
    windows_helper_assert_docker_config
    if DOCKER_HOST="$WINDOWS_HELPER_DOCKER_HOST" \
        DOCKER_CONFIG="$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \
        "$WINDOWS_HELPER_DOCKER_BIN" \
            --host "$WINDOWS_HELPER_DOCKER_HOST" \
            --config "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" "$@"; then
        status=0
    else
        status=$?
    fi
    windows_helper_assert_docker_config
    return "$status"
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
    install -m 0400 -- "$source" "$destination"
    cmp -s -- "$source" "$destination" \
        || die "Windows helper authority-program snapshot differs from its source"
    sha="$(sha256sum -- "$destination" | awk '{print $1}')"
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
        metadata="$(stat -c '%u:%a:%h' -- "$source" 2>/dev/null)" \
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
        WINDOWS_HELPER_MOUNTS+=(--mount "$2")
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
                --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly"
                --mount "type=bind,source=$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh,target=/authority/windows-golden-inspect.sh,readonly"
            )
            ;;
        *) die "unknown Windows helper runtime profile: $profile" ;;
    esac
    if [ "$profile" = kvm-guestfish ]; then
        [ -e /dev/kvm ] && [ ! -L /dev/kvm ] || die "/dev/kvm is unavailable"
        WINDOWS_HELPER_KVM_GID="$(stat -c %g -- /dev/kvm 2>/dev/null)" \
            || die "cannot inspect /dev/kvm group authority"
        case "$WINDOWS_HELPER_KVM_GID" in
            ''|*[!0-9]*|0) die "/dev/kvm must have one non-root numeric group" ;;
        esac
        runtime+=(
            --group-add "$WINDOWS_HELPER_KVM_GID"
            --device /dev/kvm:/dev/kvm:rwm
        )
    fi
    if [ "$profile" = bootstrap ]; then
        windows_helper_assert_docker_config
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
    if windows_helper_docker_command run --rm --pull=never --network=none --read-only \
        --user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        "${limits[@]}" "${runtime[@]}" "${WINDOWS_HELPER_MOUNTS[@]}" \
        "$WIN_HELPER_IMAGE_ID" "${WINDOWS_HELPER_COMMAND[@]}"; then
        status=0
    else
        status=$?
    fi
    if [ "$profile" = bootstrap ]; then
        windows_helper_assert_docker_config
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

windows_helper_runtime_resolve() {
    local archive="$1" extractor_source inspector_source kernel
    [ "$WINDOWS_HELPER_RUNTIME_READY" = 0 ] || die "Windows helper runtime is already resolved"
    windows_helper_assert_docker_config
    archive="$(readlink -f -- "$archive" 2>/dev/null)" \
        || die "cannot resolve the pinned Windows helper image archive"
    [ -f "$archive" ] && [ ! -L "$archive" ] \
        || die "pinned Windows helper image archive must be a regular non-symlink file"
    verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"
    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"
    windows_helper_assert_docker_config

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
    verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"
    cmp -s -- "$extractor_source" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-helper-extract-kernel.py" \
        || die "Windows helper kernel-extractor source changed during its snapshot"
    cmp -s -- "$inspector_source" \
        "$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh" \
        || die "Windows golden-inspector source changed during its snapshot"
    [ -f "$kernel" ] && [ ! -L "$kernel" ] \
        || die "confined Windows helper kernel derivation produced no regular file"
    WINDOWS_HELPER_RUNTIME_READY=1
    windows_helper_assert_runtime
}

#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly STAGE_UID="$(/usr/bin/id -u)"
readonly STAGE_GID="$(/usr/bin/id -g)"
[ "$STAGE_UID" -ne 0 ] \
    || { echo 'Debian systemd runtime-library staging refuses root execution' >&2; exit 1; }
[ "$STAGE_GID" -ne 0 ] \
    || { echo 'Debian systemd runtime-library staging refuses a root primary group' >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$ENTRY_PREFLIGHT" ] && [ ! -L "$ENTRY_PREFLIGHT" ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$ENTRY_PREFLIGHT")" = 755:1 ] \
    || { echo 'Debian systemd runtime-library staging requires the verifier-VM entry preflight' >&2; exit 1; }
/usr/bin/bash "$ENTRY_PREFLIGHT"

# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly DOCKER_CLIENT=/usr/bin/docker
readonly DOCKER_SOCKET=$AUTHORITY_ROOT/docker.sock
readonly DOCKER_CONFIG=$AUTHORITY_ROOT/docker-config

SELF_TEST=0
PROBE_IMAGE_ID=
BINARY=
OUTPUT=
case "$#:${1:-}" in
    2:--self-test-vm-authority)
        SELF_TEST=1
        PROBE_IMAGE_ID=$2
        ;;
    2:*)
        BINARY=$1
        OUTPUT=$2
        ;;
    *)
        printf 'usage: %s BINARY EMPTY_OUTPUT_DIR | --self-test-vm-authority PROBE_IMAGE_ID\n' "${0##*/}" >&2
        exit 2
        ;;
esac

WORK=
WORK_ID=

fail() {
    printf 'Debian systemd runtime-library staging: %s\n' "$*" >&2
    exit 1
}

remove_work() {
    [ -n "$WORK" ] && [ -n "$WORK_ID" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$WORK" --expected-identity "$WORK_ID" \
        || return 1
    [ ! -e "$WORK" ] && [ ! -L "$WORK" ] || return 1
    WORK=
    WORK_ID=
}

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WORK" ] && ! remove_work; then
        printf 'Debian systemd runtime-library staging: preserving changed private fixture: %s\n' "$WORK" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

verifier_vm_docker() {
    local status=0
    /usr/bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$DOCKER_SOCKET" \
        DOCKER_CONFIG="$DOCKER_CONFIG" \
        "$DOCKER_CLIENT" --host "unix://$DOCKER_SOCKET" \
            --config "$DOCKER_CONFIG" "$@" || status=$?
    /usr/bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    return "$status"
}

require_input_file() {
    local path=$1 label=$2 resolved metadata owner group mode links size
    case "$path" in /*) ;; *) fail "$label path must be absolute" ;; esac
    [ -f "$path" ] && [ ! -L "$path" ] || fail "$label is not one regular file"
    resolved="$(/usr/bin/readlink -f -- "$path" 2>/dev/null)" \
        || fail "$label path cannot be resolved"
    [ "$resolved" = "$path" ] || fail "$label path is not canonical"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" \
        || fail "$label metadata cannot be read"
    IFS=: read -r owner group mode links size <<<"$metadata"
    [ "$owner:$group" = 0:0 ] || fail "$label is not VM-root-owned"
    [ "$links" = 1 ] || fail "$label has multiple links"
    [ $((8#$mode & 8#022)) -eq 0 ] || fail "$label is group/world writable"
    [ $((8#$mode & 8#111)) -ne 0 ] || fail "$label is not executable"
    [ "$size" -gt 0 ] && [ "$size" -le 1073741824 ] \
        || fail "$label size is outside 1..1073741824 bytes"
    case "$path" in *,*) fail "$label path contains a mount delimiter" ;; esac
}

require_empty_output() {
    local path=$1 resolved metadata
    case "$path" in /*) ;; *) fail 'runtime-library output path must be absolute' ;; esac
    [ -d "$path" ] && [ ! -L "$path" ] \
        || fail 'runtime-library output is not one real directory'
    resolved="$(/usr/bin/readlink -f -- "$path" 2>/dev/null)" \
        || fail 'runtime-library output cannot be resolved'
    [ "$resolved" = "$path" ] || fail 'runtime-library output is not canonical'
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$path")" \
        || fail 'runtime-library output metadata cannot be read'
    [ "$metadata" = "$STAGE_UID:$STAGE_GID:700:2" ] \
        || fail 'runtime-library output is not a private empty current-principal directory'
    [ -z "$(/usr/bin/find "$path" -mindepth 1 -print -quit)" ] \
        || fail 'runtime-library output is not empty'
    case "$path" in *,*) fail 'runtime-library output path contains a mount delimiter' ;; esac
}

runtime_library_stage_run() {
    [ "$#" -ge 5 ] || fail 'runtime-library launch requires IMAGE BINARY OUTPUT ENTRYPOINT ARGUMENT'
    local image=$1 binary=$2 output=$3 entrypoint=$4
    shift 4
    verifier_vm_docker run --rm --pull=never \
        --network=none \
        --read-only \
        --user "$STAGE_UID:$STAGE_GID" \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --cgroupns=private \
        --ipc=private \
        --pids-limit=64 \
        --memory=1g \
        --memory-swap=1g \
        --cpus=1 \
        --ulimit core=0:0 \
        --ulimit nofile=4096:4096 \
        --ulimit fsize=268435456:268435456 \
        --tmpfs "/tmp:rw,noexec,nosuid,nodev,mode=700,uid=$STAGE_UID,gid=$STAGE_GID,size=32m" \
        --mount "type=bind,source=$binary,target=/input/rustdesk,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$output,target=/out,bind-recursive=disabled" \
        --workdir /tmp \
        --entrypoint "$entrypoint" \
        "$image" "$@"
}

run_self_test() {
    [[ "$PROBE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail 'probe image ID is malformed'
    local before after input_before profile profile_output
    WORK="$(/usr/bin/mktemp -d /tmp/rustdesk-systemd-libs-profile.XXXXXXXXXX)" \
        || fail 'cannot create private staging fixture'
    /usr/bin/chmod 0700 "$WORK"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$WORK")" = "$STAGE_UID:$STAGE_GID:700" ] \
        || fail 'staging fixture metadata differs'
    WORK_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORK")" \
        || fail 'cannot record staging fixture identity'
    BINARY=$WORK/rustdesk-fixture
    OUTPUT=$WORK/output
    printf 'immutable executable fixture\n' >"$BINARY"
    /usr/bin/chmod 0500 "$BINARY"
    /usr/bin/mkdir "$OUTPUT"
    /usr/bin/chmod 0700 "$OUTPUT"
    input_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BINARY"):$(/usr/bin/sha256sum "$BINARY")"
    before="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || fail 'cannot record initial guest container inventory'
    profile='
        umask 077
        [ "$$" = 1 ]
        IFS= read -r input_line </input/rustdesk
        [ "$input_line" = "immutable executable fixture" ]
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
        [ "$pids_max" = 64 ]
        [ "$memory_max" = 1073741824 ]
        [ "$swap_max" = 0 ]
        [ "$cpu_quota:$cpu_period" = 100000:100000 ]
        [ "$(ulimit -c)" = 0 ]
        [ "$(ulimit -n)" = 4096 ]
        fsize_limit=
        while IFS=" " read -r first second third soft hard unit remainder; do
            case "$first:$second:$third" in
                Max:file:size) fsize_limit="$soft:$hard:$unit" ;;
            esac
        done </proc/self/limits
        [ "$fsize_limit" = 268435456:268435456:bytes ]
        set -- /sys/class/net/*
        [ "$#" = 1 ] && [ "$1" = /sys/class/net/lo ]
        if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
        if (: >/input/rustdesk) 2>/dev/null; then exit 92; fi
        printf "fixture library\n" >/out/libfixture.so
        printf "profile=debian-systemd-runtime-libs uid=4000 network=none root=readonly input=readonly output=private caps=none nnp=on seccomp=filter apparmor=docker-default\n"
    '
    profile_output="$(runtime_library_stage_run "$PROBE_IMAGE_ID" "$BINARY" "$OUTPUT" \
        /bin/dash -euc "$profile")" \
        || fail 'runtime-library production confinement profile failed'
    [ "$profile_output" = \
      'profile=debian-systemd-runtime-libs uid=4000 network=none root=readonly input=readonly output=private caps=none nnp=on seccomp=filter apparmor=docker-default' ] \
        || fail "runtime-library confinement receipt differs: $profile_output"
    [ "$(<"$OUTPUT/libfixture.so")" = 'fixture library' ] \
        || fail 'runtime-library profile did not write its sole output'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OUTPUT/libfixture.so")" = \
      "$STAGE_UID:$STAGE_GID:600:1" ] \
        || fail 'runtime-library profile output metadata differs'
    [ "$input_before" = \
      "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BINARY"):$(/usr/bin/sha256sum "$BINARY")" ] \
        || fail 'runtime-library profile changed its immutable input'
    after="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || fail 'cannot record final guest container inventory'
    [ "$after" = "$before" ] || fail 'runtime-library profile left a guest container'
    remove_work || fail 'runtime-library profile cleanup failed'
    printf 'DEBIAN_SYSTEMD_RUNTIME_LIBS_VM_AUTHORITY=pass uid=%s gid=%s docker=%s profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined\n' \
        "$STAGE_UID" "$STAGE_GID" "$VERIFIER_VM_DOCKER_VERSION"
}

stage_runtime_libraries() {
    local runtime_image_id binary_before binary_after count bytes library size bad
    local library_metadata library_owner library_group library_mode library_links
    require_input_file "$BINARY" 'RustDesk lifecycle executable'
    require_empty_output "$OUTPUT"
    [[ "$DEV_CHECK_IMAGE_CONFIG_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail 'pinned devcheck runtime config ID is malformed'
    runtime_image_id="$(verifier_vm_docker image inspect --format '{{.Id}}' "$DEV_CHECK_IMAGE_CONFIG_ID")" \
        || fail 'exact devcheck runtime image is absent from the guest authority'
    [ "$runtime_image_id" = "$DEV_CHECK_IMAGE_CONFIG_ID" ] \
        || fail 'devcheck runtime image identity differs from its config pin'
    binary_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BINARY"):$(/usr/bin/sha256sum "$BINARY")"
    runtime_library_stage_run "$DEV_CHECK_IMAGE_CONFIG_ID" "$BINARY" "$OUTPUT" \
        /bin/bash --noprofile --norc -euo pipefail -c '
            umask 077
            stage_library() {
                source=$1
                destination=/out/${source##*/}
                [ -f "$source" ] || { printf "missing runtime library: %s\n" "$source" >&2; exit 1; }
                if [ -e "$destination" ]; then
                    cmp -s "$source" "$destination" \
                        || { printf "runtime library basename collision: %s\n" "$destination" >&2; exit 1; }
                else
                    cp -L --no-preserve=ownership -- "$source" "$destination"
                fi
            }
            ldd_output="$(ldd /input/rustdesk)"
            case "$ldd_output" in
                *"not found"*) printf "%s\n" "$ldd_output" >&2; exit 1 ;;
            esac
            while IFS= read -r library; do
                stage_library "$library"
            done < <(
                printf "%s\n" "$ldd_output" \
                    | awk '\''/=> \/[^ ]+/{print $3} /^[[:space:]]*\//{print $1}'\'' \
                    | sort -u
            )
            for pattern in \
                /usr/lib/x86_64-linux-gnu/libxdo.so\* \
                /usr/lib/x86_64-linux-gnu/libva.so\* \
                /usr/lib/x86_64-linux-gnu/libva-drm.so\* \
                /usr/lib/x86_64-linux-gnu/libva-x11.so\* \
                /usr/lib/x86_64-linux-gnu/libvdpau.so\*; do
                for library in $pattern; do
                    [ -f "$library" ] || continue
                    stage_library "$library"
                done
            done
        '
    binary_after="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BINARY"):$(/usr/bin/sha256sum "$BINARY")"
    [ "$binary_after" = "$binary_before" ] \
        || fail 'RustDesk lifecycle executable changed during staging'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OUTPUT")" = \
      "$STAGE_UID:$STAGE_GID:700:2" ] \
        || fail 'runtime-library output directory metadata changed'
    bad="$(/usr/bin/find "$OUTPUT" -mindepth 1 ! -type f -print -quit)" \
        || fail 'cannot inspect runtime-library output'
    [ -z "$bad" ] || fail "runtime-library output contains a non-regular entry: $bad"
    count="$(/usr/bin/find "$OUTPUT" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l)"
    [ "$count" -ge 60 ] && [ "$count" -le 256 ] \
        || fail "runtime-library count is outside 60..256: $count"
    bytes=0
    while IFS= read -r -d '' library; do
        library_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$library")"
        IFS=: read -r library_owner library_group library_mode library_links \
            <<<"$library_metadata"
        [ "$library_owner:$library_group:$library_links" = \
          "$STAGE_UID:$STAGE_GID:1" ] \
            || fail "runtime-library ownership/link count differs: $library"
        [ $((8#$library_mode & 8#022)) -eq 0 ] \
            || fail "runtime library is group/world writable: $library"
        size="$(/usr/bin/stat -c '%s' -- "$library")"
        [ "$size" -gt 0 ] || fail "runtime library is empty: $library"
        bytes=$((bytes + size))
    done < <(/usr/bin/find "$OUTPUT" -mindepth 1 -maxdepth 1 -type f -print0)
    [ "$bytes" -le 1073741824 ] \
        || fail "runtime-library output exceeds 1 GiB: $bytes bytes"
    printf 'DEBIAN_SYSTEMD_RUNTIME_LIBS=pass runtime_image=%s libraries=%s bytes=%s input=readonly output=private\n' \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$count" "$bytes"
}

if [ "$SELF_TEST" -eq 1 ]; then
    run_self_test
else
    stage_runtime_libraries
fi

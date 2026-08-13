#!/usr/bin/env bash
# Exact transient storage-pool and user-session libvirt residue ownership.

WINDOWS_LIBVIRT_CONTROL_ROOT=""
WINDOWS_LIBVIRT_CONTROL_ROOT_ID=""
WINDOWS_LIBVIRT_USER_HOME=""
WINDOWS_LIBVIRT_CACHE_ROOT=""
WINDOWS_LIBVIRT_CACHE_ROOT_ID=""
WINDOWS_LIBVIRT_CONFIG_ROOT=""
WINDOWS_LIBVIRT_CONFIG_ROOT_ID=""
WINDOWS_LIBVIRT_RUNTIME_ROOT=""
WINDOWS_LIBVIRT_RUNTIME_ROOT_ID=""
WINDOWS_LIBVIRT_DAEMON_PID=""
WINDOWS_LIBVIRT_DAEMON_START=""
WINDOWS_LIBVIRT_CLIENT_ENV=()
WINDOWS_LIBVIRT_OBJECTS_RETIRED=0
WINDOWS_LIBVIRT_RUNTIME_RETIRED=0
WINDOWS_LIBVIRT_CONTROL_RETIRED=0
WINDOWS_LIBVIRT_POOL_NAMES=()
WINDOWS_LIBVIRT_POOL_UUIDS=()
WINDOWS_LIBVIRT_POOL_TARGETS=()
WINDOWS_LIBVIRT_POOL_TARGET_IDS=()
WINDOWS_LIBVIRT_DOMAIN_NAMES=()
WINDOWS_LIBVIRT_DOMAIN_UUIDS=()

windows_libvirt_helper() {
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
        /usr/bin/python3 -I -S "$SCRIPT_DIR/windows-libvirt-storage-pool.py" "$@"
}

windows_libvirt_transaction_is_open() {
    [ -n "$WINDOWS_LIBVIRT_CONTROL_ROOT" ] \
        && [ -n "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" ] \
        && [ -n "$WINDOWS_LIBVIRT_USER_HOME" ] \
        && [ -n "$WINDOWS_LIBVIRT_CACHE_ROOT" ] \
        && [ -n "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" ] \
        && [ -n "$WINDOWS_LIBVIRT_CONFIG_ROOT" ] \
        && [ -n "$WINDOWS_LIBVIRT_CONFIG_ROOT_ID" ] \
        && [ -n "$WINDOWS_LIBVIRT_RUNTIME_ROOT" ] \
        && [ -n "$WINDOWS_LIBVIRT_RUNTIME_ROOT_ID" ] \
        && [ "${#WINDOWS_LIBVIRT_CLIENT_ENV[@]}" -gt 0 ]
}

windows_libvirt_process_group_is_live() {
    local wanted="$1" path value state group session
    [[ "$wanted" =~ ^[1-9][0-9]*$ ]] || return 1
    for path in /proc/[0-9]*/stat; do
        [ -r "$path" ] || continue
        value="$(<"$path")" || continue
        value="${value##*) }"
        set -- $value
        [ "$#" -ge 4 ] || continue
        state="$1"
        group="$3"
        session="$4"
        if [ "$group" = "$wanted" ] && [ "$session" = "$wanted" ] \
            && [ "$state" != Z ] && [ "$state" != X ]; then
            return 0
        fi
    done
    return 1
}

windows_libvirt_daemon_matches() {
    local identity state start group session executable metadata owner gid extra
    [ -n "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ -n "$WINDOWS_LIBVIRT_DAEMON_START" ] || return 1
    identity="$(process_identity "$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null)" \
        || return 1
    read -r state start group session <<<"$identity"
    [ "$start" = "$WINDOWS_LIBVIRT_DAEMON_START" ] \
        && [ "$group" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ "$session" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ "$state" != Z ] && [ "$state" != X ] \
        || return 1
    executable="$(/usr/bin/readlink -f -- "/proc/$WINDOWS_LIBVIRT_DAEMON_PID/exe" 2>/dev/null)" \
        || return 1
    [ "$executable" = /usr/sbin/libvirtd ] || return 1
    metadata="$(/usr/bin/stat -c '%u:%g' -- "/proc/$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null)" \
        || return 1
    IFS=: read -r owner gid extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$gid" = "$WINDOWS_HELPER_BUILD_GID" ]
}

windows_libvirt_daemon_is_terminal_or_absent() {
    local identity state start group session metadata owner gid extra
    [ -n "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ -n "$WINDOWS_LIBVIRT_DAEMON_START" ] || return 1
    if identity="$(process_identity "$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null)"; then
        read -r state start group session <<<"$identity"
        [ "$start" = "$WINDOWS_LIBVIRT_DAEMON_START" ] \
            && [ "$group" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && [ "$session" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && { [ "$state" = Z ] || [ "$state" = X ]; } \
            || return 1
        metadata="$(/usr/bin/stat -c '%u:%g' -- "/proc/$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null)" \
            || return 1
        IFS=: read -r owner gid extra <<<"$metadata"
        [ -z "$extra" ] \
            && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
            && [ "$gid" = "$WINDOWS_HELPER_BUILD_GID" ]
        return
    fi
    [ ! -e "/proc/$WINDOWS_LIBVIRT_DAEMON_PID" ]
}

windows_libvirt_require_ambient_session_quiescent() {
    local runtime="$1" home="$2" path process status uid_fields process_uid executable
    for path in \
        "$runtime/libvirt/libvirt-sock" \
        "$runtime/libvirt/libvirt-sock-ro" \
        "$runtime/libvirt/libvirt-admin-sock" \
        "$runtime/libvirt/libvirtd.pid"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
    done
    if [ -e "$runtime/libvirt" ] || [ -L "$runtime/libvirt" ]; then
        [ -d "$runtime/libvirt" ] && [ ! -L "$runtime/libvirt" ] || return 1
        [ -z "$(/usr/bin/find "$runtime/libvirt" -mindepth 1 \
            \( -type s -o -name '*.pid' \) -print -quit)" ] || return 1
    fi
    for process in /proc/[0-9]*; do
        [ -r "$process/status" ] && [ -L "$process/exe" ] || continue
        status="$(<"$process/status")" || continue
        uid_fields="$(printf '%s\n' "$status" \
            | /usr/bin/awk '$1 == "Uid:" { print $2 ":" $3 ":" $4 ":" $5; found++ } END { exit found != 1 }')" \
            || continue
        IFS=: read -r process_uid _ _ _ <<<"$uid_fields"
        [ "$process_uid" = "$WINDOWS_HELPER_BUILD_UID" ] || continue
        executable="$(/usr/bin/readlink -f -- "$process/exe" 2>/dev/null)" || continue
        case "$executable" in
            /usr/sbin/libvirtd|/usr/sbin/virtqemud|/usr/sbin/virtstoraged|\
            /usr/sbin/virtproxyd|/usr/sbin/virtlogd|/usr/sbin/virtlockd|\
            /usr/sbin/virtnetworkd|/usr/sbin/virtnwfilterd|\
            /usr/sbin/virtsecretd|/usr/sbin/virtinterfaced|/usr/sbin/virtnodedevd)
                return 1
                ;;
        esac
    done
    path="$home/.config/libvirt/storage"
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -d "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/readlink -f -- "$path")" = "$path" ] \
            || return 1
        [ -z "$(/usr/bin/find "$path" -mindepth 1 ! -type d -print -quit)" ] \
            || return 1
        [ -z "$(/usr/bin/find "$path" -mindepth 1 -type d \
            ! -path "$path/autostart" -print -quit)" ] || return 1
    fi
}

windows_libvirt_start_private_daemon() {
    local config qemu_config config_metadata qemu_metadata
    local pid_file stdout stderr deadline identity state start group session
    windows_libvirt_transaction_is_open || return 1
    [ -x /usr/sbin/libvirtd ] && declare -F process_identity >/dev/null \
        || return 1
    [ -z "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ -z "$WINDOWS_LIBVIRT_DAEMON_START" ] || return 1
    config="$WINDOWS_LIBVIRT_CONTROL_ROOT/libvirtd.conf"
    qemu_config="$WINDOWS_LIBVIRT_CONFIG_ROOT/libvirt/qemu.conf"
    pid_file="$WINDOWS_LIBVIRT_CONTROL_ROOT/libvirtd.pid"
    stdout="$WINDOWS_LIBVIRT_CONTROL_ROOT/libvirtd.stdout"
    stderr="$WINDOWS_LIBVIRT_CONTROL_ROOT/libvirtd.stderr"
    config_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$config" 2>/dev/null)" \
        || return 1
    qemu_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$qemu_config" 2>/dev/null)" \
        || return 1
    [ "$config_metadata" = \
        "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:600:1" ] \
        && [ "$qemu_metadata" = \
            "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:600:1" ] \
        && [ ! -L "$config" ] && [ ! -L "$qemu_config" ] \
        && [ "$(<"$config")" = $'listen_tls = 0\nlisten_tcp = 0' ] \
        && [ "$(<"$qemu_config")" = \
            $'lock_manager = "nop"\nstdio_handler = "file"' ] \
        || return 1
    /usr/bin/setsid "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}" \
        /usr/sbin/libvirtd --config "$config" --pid-file "$pid_file" \
        >"$stdout" 2>"$stderr" &
    WINDOWS_LIBVIRT_DAEMON_PID=$!
    if ! WINDOWS_LIBVIRT_DAEMON_START="$(
        process_start_time "$WINDOWS_LIBVIRT_DAEMON_PID"
    )"; then
        wait "$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null || :
        [ ! -e "/proc/$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && ! windows_libvirt_process_group_is_live \
                "$WINDOWS_LIBVIRT_DAEMON_PID" \
            || return 1
        WINDOWS_LIBVIRT_DAEMON_PID=""
        return 1
    fi
    deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))
    while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        identity="$(process_identity "$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null)" \
            || return 1
        read -r state start group session <<<"$identity"
        [ "$start" = "$WINDOWS_LIBVIRT_DAEMON_START" ] \
            && [ "$state" != Z ] && [ "$state" != X ] || return 1
        if [ "$group" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && [ "$session" = "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && windows_libvirt_daemon_matches \
            && [ -S "$WINDOWS_LIBVIRT_RUNTIME_ROOT/libvirt/libvirt-sock" ] \
            && [ ! -L "$WINDOWS_LIBVIRT_RUNTIME_ROOT/libvirt/libvirt-sock" ]; then
            return 0
        fi
        /usr/bin/sleep 0.05
    done
    return 1
}

windows_libvirt_stop_private_daemon() {
    local deadline
    [ -n "$WINDOWS_LIBVIRT_DAEMON_PID" ] || return 0
    [ -n "$WINDOWS_LIBVIRT_DAEMON_START" ] || return 1
    if windows_libvirt_daemon_matches; then
        if ! /bin/kill -TERM -- "-$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null; then
            windows_libvirt_daemon_is_terminal_or_absent \
                && ! windows_libvirt_process_group_is_live \
                    "$WINDOWS_LIBVIRT_DAEMON_PID" \
                || return 1
        fi
    elif windows_libvirt_daemon_is_terminal_or_absent; then
        if windows_libvirt_process_group_is_live "$WINDOWS_LIBVIRT_DAEMON_PID"; then
            if ! /bin/kill -TERM -- "-$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null; then
                ! windows_libvirt_process_group_is_live \
                    "$WINDOWS_LIBVIRT_DAEMON_PID" \
                    || return 1
            fi
        fi
    else
        return 1
    fi
    deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
    while windows_libvirt_process_group_is_live "$WINDOWS_LIBVIRT_DAEMON_PID" \
        && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        /usr/bin/sleep 0.05
    done
    if windows_libvirt_process_group_is_live "$WINDOWS_LIBVIRT_DAEMON_PID"; then
        if ! /bin/kill -KILL -- "-$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null; then
            windows_libvirt_daemon_is_terminal_or_absent \
                && ! windows_libvirt_process_group_is_live \
                    "$WINDOWS_LIBVIRT_DAEMON_PID" \
                || return 1
        fi
        deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
        while windows_libvirt_process_group_is_live "$WINDOWS_LIBVIRT_DAEMON_PID" \
            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            /usr/bin/sleep 0.05
        done
    fi
    windows_libvirt_process_group_is_live "$WINDOWS_LIBVIRT_DAEMON_PID" \
        && return 1
    wait "$WINDOWS_LIBVIRT_DAEMON_PID" 2>/dev/null || :
    [ ! -e "/proc/$WINDOWS_LIBVIRT_DAEMON_PID" ] || return 1
    WINDOWS_LIBVIRT_DAEMON_PID=""
    WINDOWS_LIBVIRT_DAEMON_START=""
}

windows_libvirt_run_bounded_control() {
    /usr/bin/setsid --wait \
        /usr/bin/timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \
        "$@" </dev/null
}

windows_libvirt_virsh_bounded() {
    local status
    windows_libvirt_daemon_matches || return 1
    if windows_libvirt_run_bounded_control \
        "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}" \
        /usr/bin/virsh --connect qemu:///session "$@"; then
        status=0
    else
        status=$?
    fi
    windows_libvirt_daemon_matches || return 1
    return "$status"
}

windows_libvirt_transaction_open() {
    local parent="$1" stale passwd_line runtime_parent
    local pw_name pw_pass pw_uid pw_gid pw_gecos pw_home pw_shell pw_extra
    local metadata owner group mode device inode extra candidate candidate_id
    local cache_root config_root runtime_root cache_id config_id runtime_id
    local private_home data_root state_root tmp_root
    ! windows_libvirt_transaction_is_open \
        && [ -z "$WINDOWS_LIBVIRT_CONTROL_ROOT" ] \
        && [ -z "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" ] \
        && [ -z "$WINDOWS_LIBVIRT_USER_HOME" ] \
        && [ -z "$WINDOWS_LIBVIRT_CACHE_ROOT" ] \
        && [ -z "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" ] \
        && [ -z "$WINDOWS_LIBVIRT_CONFIG_ROOT" ] \
        && [ -z "$WINDOWS_LIBVIRT_CONFIG_ROOT_ID" ] \
        && [ -z "$WINDOWS_LIBVIRT_RUNTIME_ROOT" ] \
        && [ -z "$WINDOWS_LIBVIRT_RUNTIME_ROOT_ID" ] \
        && [ -z "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
        && [ -z "$WINDOWS_LIBVIRT_DAEMON_START" ] \
        && [ "${#WINDOWS_LIBVIRT_CLIENT_ENV[@]}" = 0 ] \
        && [ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ] \
        && [ "$WINDOWS_LIBVIRT_RUNTIME_RETIRED" = 0 ] \
        && [ "$WINDOWS_LIBVIRT_CONTROL_RETIRED" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_POOL_NAMES[@]}" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_POOL_TARGETS[@]}" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_POOL_TARGET_IDS[@]}" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_DOMAIN_NAMES[@]}" = 0 ] \
        && [ "${#WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}" = 0 ] \
        || return 1
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(/usr/bin/readlink -f -- "$parent")" = "$parent" ] \
        || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$parent")" || return 1
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ -z "$extra" ] \
        && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$group" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ $((8#$mode & 8#700)) -eq $((8#700)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        && [[ "$device:$inode" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || return 1
    [ -z "${XDG_CACHE_HOME:-}" ] && [ -z "${XDG_CONFIG_HOME:-}" ] \
        || return 1
    passwd_line="$(/usr/bin/getent passwd "$WINDOWS_HELPER_BUILD_UID")" || return 1
    [ "$(printf '%s\n' "$passwd_line" | /usr/bin/wc -l)" = 1 ] || return 1
    IFS=: read -r pw_name pw_pass pw_uid pw_gid pw_gecos pw_home pw_shell pw_extra \
        <<<"$passwd_line"
    [ -z "$pw_extra" ] && [ -n "$pw_name" ] && [ -n "$pw_shell" ] \
        && [ "$pw_uid" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$pw_gid" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ -n "$pw_home" ] && [ "${HOME:-}" = "$pw_home" ] \
        && [ -d "$pw_home" ] && [ ! -L "$pw_home" ] \
        && [ "$(/usr/bin/readlink -f -- "$pw_home")" = "$pw_home" ] \
        || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a' -- "$pw_home")" || return 1
    IFS=: read -r owner group mode extra <<<"$metadata"
    [ -z "$extra" ] && [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$group" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ $((8#$mode & 8#500)) -eq $((8#500)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        || return 1
    runtime_parent="/run/user/$WINDOWS_HELPER_BUILD_UID"
    [ "${XDG_RUNTIME_DIR:-$runtime_parent}" = "$runtime_parent" ] \
        && [ -d "$runtime_parent" ] && [ ! -L "$runtime_parent" ] \
        && [ "$(/usr/bin/readlink -f -- "$runtime_parent")" = "$runtime_parent" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$runtime_parent")" = \
            "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:700" ] \
        || return 1
    windows_libvirt_require_ambient_session_quiescent "$runtime_parent" "$pw_home" \
        || return 1
    stale="$(/usr/bin/find "$parent" -mindepth 1 -maxdepth 1 \
        -name '.windows-libvirt-transaction.*' -print -quit)" || return 1
    [ -z "$stale" ] || return 1
    candidate="$(/usr/bin/mktemp -d \
        "$parent/.windows-libvirt-transaction.XXXXXXXX")" || return 1
    if ! /usr/bin/chmod 0700 -- "$candidate"; then
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    fi
    candidate_id="$(/usr/bin/stat -c '%d:%i' -- "$candidate")" || {
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    }
    if ! [[ "$candidate_id" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]]; then
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    fi
    runtime_root="$(/usr/bin/mktemp -d \
        "$runtime_parent/.rustdesk-libvirt-runtime.XXXXXXXX")" || {
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    }
    if ! /usr/bin/chmod 0700 -- "$runtime_root"; then
        /usr/bin/rmdir -- "$runtime_root" 2>/dev/null || true
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    fi
    runtime_id="$(/usr/bin/stat -c '%d:%i' -- "$runtime_root")" || {
        /usr/bin/rmdir -- "$runtime_root" 2>/dev/null || true
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    }
    [[ "$runtime_id" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] || {
        /usr/bin/rmdir -- "$runtime_root" 2>/dev/null || true
        /usr/bin/rmdir -- "$candidate" 2>/dev/null || true
        return 1
    }
    cache_root="$candidate/cache"
    config_root="$candidate/config"
    private_home="$candidate/home"
    data_root="$candidate/data"
    state_root="$candidate/state"
    tmp_root="$candidate/tmp"
    if ! /usr/bin/mkdir -m 0700 -- \
        "$cache_root" "$config_root" "$private_home" \
        "$data_root" "$state_root" "$tmp_root"; then
        /usr/bin/rmdir -- "$runtime_root" 2>/dev/null || true
        /usr/bin/rmdir -- \
            "$cache_root" "$config_root" "$private_home" \
            "$data_root" "$state_root" "$tmp_root" "$candidate" \
            2>/dev/null || true
        return 1
    fi
    cache_id="$(/usr/bin/stat -c '%d:%i' -- "$cache_root")" || {
        /usr/bin/rmdir -- \
            "$cache_root" "$config_root" "$private_home" \
            "$data_root" "$state_root" "$tmp_root" \
            "$runtime_root" "$candidate" \
            2>/dev/null || true
        return 1
    }
    config_id="$(/usr/bin/stat -c '%d:%i' -- "$config_root")" || {
        /usr/bin/rmdir -- \
            "$cache_root" "$config_root" "$private_home" \
            "$data_root" "$state_root" "$tmp_root" \
            "$runtime_root" "$candidate" \
            2>/dev/null || true
        return 1
    }
    [[ "$cache_id" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        && [[ "$config_id" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] \
        || {
            /usr/bin/rmdir -- \
                "$cache_root" "$config_root" "$private_home" \
                "$data_root" "$state_root" "$tmp_root" \
                "$runtime_root" "$candidate" \
                2>/dev/null || true
            return 1
        }
    WINDOWS_LIBVIRT_CONTROL_ROOT="$candidate"
    WINDOWS_LIBVIRT_CONTROL_ROOT_ID="$candidate_id"
    WINDOWS_LIBVIRT_USER_HOME="$pw_home"
    WINDOWS_LIBVIRT_CACHE_ROOT="$cache_root"
    WINDOWS_LIBVIRT_CACHE_ROOT_ID="$cache_id"
    WINDOWS_LIBVIRT_CONFIG_ROOT="$config_root"
    WINDOWS_LIBVIRT_CONFIG_ROOT_ID="$config_id"
    WINDOWS_LIBVIRT_RUNTIME_ROOT="$runtime_root"
    WINDOWS_LIBVIRT_RUNTIME_ROOT_ID="$runtime_id"
    WINDOWS_LIBVIRT_RUNTIME_RETIRED=0
    WINDOWS_LIBVIRT_CONTROL_RETIRED=0
    WINDOWS_LIBVIRT_OBJECTS_RETIRED=0
    WINDOWS_LIBVIRT_CLIENT_ENV=(
        /usr/bin/env -i
        "HOME=$private_home"
        "USER=$pw_name"
        "LOGNAME=$pw_name"
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        LC_ALL=C
        "XDG_CACHE_HOME=$cache_root"
        "XDG_CONFIG_HOME=$config_root"
        "XDG_DATA_HOME=$data_root"
        "XDG_RUNTIME_DIR=$runtime_root"
        "XDG_STATE_HOME=$state_root"
        "TMPDIR=$tmp_root"
        LIBVIRT_DEFAULT_URI=qemu:///session
    )
    /usr/bin/mkdir -m 0700 -p -- \
        "$cache_root/libvirt/qemu/log" \
        "$cache_root/libvirt/storage/run" \
        "$config_root/libvirt/storage/autostart" \
        || return 1
    if ! (umask 077; set -o noclobber; /usr/bin/printf '%s\n' \
        'listen_tls = 0' \
        'listen_tcp = 0' \
        >"$candidate/libvirtd.conf"); then
        return 1
    fi
    if ! (umask 077; set -o noclobber; /usr/bin/printf '%s\n' \
        'lock_manager = "nop"' \
        'stdio_handler = "file"' \
        >"$config_root/libvirt/qemu.conf"); then
        return 1
    fi
    windows_libvirt_start_private_daemon
}

windows_libvirt_pool_name_is_listed() {
    local wanted="$1" names
    names="$(virsh_bounded pool-list --all --name)" || return 2
    printf '%s\n' "$names" \
        | /usr/bin/awk -v wanted="$wanted" '$0 == wanted { found=1 } END { exit !found }'
}

windows_libvirt_pool_uuid_is_listed() {
    local wanted="$1" uuids
    uuids="$(virsh_bounded pool-list --all --uuid)" || return 2
    printf '%s\n' "$uuids" \
        | /usr/bin/awk -v wanted="$wanted" '$0 == wanted { found=1 } END { exit !found }'
}

windows_libvirt_domain_name_is_listed() {
    local wanted="$1" names
    names="$(virsh_bounded list --all --name)" || return 2
    printf '%s\n' "$names" \
        | /usr/bin/awk -v wanted="$wanted" '$0 == wanted { found=1 } END { exit !found }'
}

windows_libvirt_domain_uuid_is_listed() {
    local wanted="$1" uuids
    uuids="$(virsh_bounded list --all --uuid)" || return 2
    printf '%s\n' "$uuids" \
        | /usr/bin/awk -v wanted="$wanted" '$0 == wanted { found=1 } END { exit !found }'
}

windows_libvirt_pool_target_uuids() {
    local target="$1" uuids pool_uuid status
    uuids="$(virsh_bounded pool-list --all --uuid)" || return 2
    while IFS= read -r pool_uuid; do
        [ -n "$pool_uuid" ] || continue
        if virsh_bounded pool-dumpxml "$pool_uuid" \
            | windows_libvirt_helper pool-target-match --target "$target"; then
            printf '%s\n' "$pool_uuid"
        else
            status=$?
            [ "$status" = 3 ] || return 2
        fi
    done <<<"$uuids"
}

windows_libvirt_require_pool_absent() {
    local name="$1" pool_uuid="$2" status
    if windows_libvirt_pool_name_is_listed "$name"; then
        return 1
    else
        status=$?
        [ "$status" = 1 ] || return 1
    fi
    if windows_libvirt_pool_uuid_is_listed "$pool_uuid"; then
        return 1
    else
        status=$?
        [ "$status" = 1 ] || return 1
    fi
}

windows_libvirt_require_domain_absent() {
    local name="$1" domain_uuid="$2" status
    if windows_libvirt_domain_name_is_listed "$name"; then
        return 1
    else
        status=$?
        [ "$status" = 1 ] || return 1
    fi
    if windows_libvirt_domain_uuid_is_listed "$domain_uuid"; then
        return 1
    else
        status=$?
        [ "$status" = 1 ] || return 1
    fi
}

windows_libvirt_require_target_unmanaged() {
    local target="$1" matches
    matches="$(windows_libvirt_pool_target_uuids "$target")" || return 1
    [ -z "$matches" ]
}

windows_libvirt_require_no_persistent_pool_files() {
    local name="$1" path
    windows_libvirt_transaction_is_open || return 1
    for path in \
        "$WINDOWS_LIBVIRT_CONFIG_ROOT/libvirt/storage/$name.xml" \
        "$WINDOWS_LIBVIRT_CONFIG_ROOT/libvirt/storage/autostart/$name.xml"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
    done
}

windows_libvirt_pool_info_field() {
    local info="$1" field="$2"
    printf '%s\n' "$info" \
        | /usr/bin/awk -F: -v field="$field" \
            '$1 == field { sub(/^[[:space:]]*/, "", $2); print $2; found++ } END { exit found != 1 }'
}

windows_libvirt_prove_exact_transient_pool() {
    local name="$1" pool_uuid="$2" target="$3" target_id="$4"
    local actual_name actual_uuid info target_matches
    [ "$(/usr/bin/stat -c '%d:%i' -- "$target" 2>/dev/null)" = "$target_id" ] \
        || return 1
    actual_name="$(virsh_bounded pool-name "$pool_uuid")" || return 1
    actual_uuid="$(virsh_bounded pool-uuid "$name")" || return 1
    [ "$actual_name" = "$name" ] && [ "$actual_uuid" = "$pool_uuid" ] \
        || return 1
    virsh_bounded pool-dumpxml "$pool_uuid" \
        | windows_libvirt_helper verify-pool-xml \
            --uid "$WINDOWS_HELPER_BUILD_UID" \
            --gid "$WINDOWS_HELPER_BUILD_GID" \
            --name "$name" --uuid "$pool_uuid" --target "$target" \
            --target-identity "$target_id" \
        || return 1
    info="$(virsh_bounded pool-info "$pool_uuid")" || return 1
    [ "$(windows_libvirt_pool_info_field "$info" State)" = running ] \
        && [ "$(windows_libvirt_pool_info_field "$info" Persistent)" = no ] \
        && [ "$(windows_libvirt_pool_info_field "$info" Autostart)" = no ] \
        || return 1
    windows_libvirt_require_no_persistent_pool_files "$name" || return 1
    target_matches="$(windows_libvirt_pool_target_uuids "$target")" || return 1
    [ "$target_matches" = "$pool_uuid" ]
}

windows_libvirt_ensure_transient_pool() {
    local target="$1" canonical metadata owner group mode target_id
    local index pool_uuid compact name xml
    windows_libvirt_transaction_is_open || return 1
    canonical="$(/usr/bin/readlink -f -- "$target" 2>/dev/null)" || return 1
    [ "$canonical" = "$target" ] && [ -d "$target" ] && [ ! -L "$target" ] \
        || return 1
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%d:%i' -- "$target")" || return 1
    IFS=: read -r owner group mode device inode extra <<<"$metadata"
    [ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ] \
        && [ "$group" = "$WINDOWS_HELPER_BUILD_GID" ] \
        && [ -z "$extra" ] \
        && [ $((8#$mode & 8#500)) -eq $((8#500)) ] \
        && [ $((8#$mode & 8#7022)) -eq 0 ] \
        || return 1
    target_id="$device:$inode"
    [[ "$target_id" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]] || return 1
    for index in "${!WINDOWS_LIBVIRT_POOL_TARGETS[@]}"; do
        if [ "${WINDOWS_LIBVIRT_POOL_TARGETS[$index]}" = "$target" ]; then
            [ "${WINDOWS_LIBVIRT_POOL_TARGET_IDS[$index]}" = "$target_id" ] \
                && windows_libvirt_prove_exact_transient_pool \
                    "${WINDOWS_LIBVIRT_POOL_NAMES[$index]}" \
                    "${WINDOWS_LIBVIRT_POOL_UUIDS[$index]}" \
                    "$target" "$target_id"
            return
        fi
    done
    windows_libvirt_require_target_unmanaged "$target" || return 1
    pool_uuid="$(</proc/sys/kernel/random/uuid)" || return 1
    [[ "$pool_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
        || return 1
    compact="${pool_uuid//-/}"
    name="rustdesk-tpool-$compact"
    windows_libvirt_require_pool_absent "$name" "$pool_uuid" || return 1
    windows_libvirt_require_no_persistent_pool_files "$name" || return 1
    windows_libvirt_helper write-pool-request \
        --control-root "$WINDOWS_LIBVIRT_CONTROL_ROOT" \
        --control-identity "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" \
        --uid "$WINDOWS_HELPER_BUILD_UID" --gid "$WINDOWS_HELPER_BUILD_GID" \
        --name "$name" --uuid "$pool_uuid" \
        --target "$target" --target-identity "$target_id" \
        || return 1
    xml="$WINDOWS_LIBVIRT_CONTROL_ROOT/pool-$compact.xml"
    index="${#WINDOWS_LIBVIRT_POOL_NAMES[@]}"
    WINDOWS_LIBVIRT_POOL_NAMES[index]="$name"
    WINDOWS_LIBVIRT_POOL_UUIDS[index]="$pool_uuid"
    WINDOWS_LIBVIRT_POOL_TARGETS[index]="$target"
    WINDOWS_LIBVIRT_POOL_TARGET_IDS[index]="$target_id"
    virsh_bounded pool-create "$xml" >/dev/null || return 1
    windows_libvirt_prove_exact_transient_pool \
        "$name" "$pool_uuid" "$target" "$target_id"
}

windows_libvirt_ensure_transient_pools() {
    local target
    for target in "$@"; do
        windows_libvirt_ensure_transient_pool "$target" || return 1
    done
}

windows_libvirt_prepare_domain() {
    local name="$1" domain_uuid="$2" index
    windows_libvirt_transaction_is_open || return 1
    windows_libvirt_require_domain_absent "$name" "$domain_uuid" || return 1
    for index in "${!WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}"; do
        [ "${WINDOWS_LIBVIRT_DOMAIN_UUIDS[$index]}" != "$domain_uuid" ] \
            && [ "${WINDOWS_LIBVIRT_DOMAIN_NAMES[$index]}" != "$name" ] \
            || return 1
    done
    windows_libvirt_helper record-domain \
        --control-root "$WINDOWS_LIBVIRT_CONTROL_ROOT" \
        --control-identity "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" \
        --uid "$WINDOWS_HELPER_BUILD_UID" --gid "$WINDOWS_HELPER_BUILD_GID" \
        --cache-root "$WINDOWS_LIBVIRT_CACHE_ROOT" \
        --cache-identity "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" \
        --name "$name" --uuid "$domain_uuid" \
        || return 1
    index="${#WINDOWS_LIBVIRT_DOMAIN_NAMES[@]}"
    WINDOWS_LIBVIRT_DOMAIN_NAMES[index]="$name"
    WINDOWS_LIBVIRT_DOMAIN_UUIDS[index]="$domain_uuid"
}

windows_libvirt_require_targets_owned() {
    local target index found
    for target in "$@"; do
        found=0
        for index in "${!WINDOWS_LIBVIRT_POOL_TARGETS[@]}"; do
            [ "${WINDOWS_LIBVIRT_POOL_TARGETS[$index]}" = "$target" ] || continue
            windows_libvirt_prove_exact_transient_pool \
                "${WINDOWS_LIBVIRT_POOL_NAMES[$index]}" \
                "${WINDOWS_LIBVIRT_POOL_UUIDS[$index]}" \
                "$target" "${WINDOWS_LIBVIRT_POOL_TARGET_IDS[$index]}" \
                || return 1
            found=$((found + 1))
        done
        [ "$found" = 1 ] || return 1
    done
}

windows_libvirt_destroy_transient_pool() {
    local index="$1" name pool_uuid target target_id status matches
    name="${WINDOWS_LIBVIRT_POOL_NAMES[$index]}"
    pool_uuid="${WINDOWS_LIBVIRT_POOL_UUIDS[$index]}"
    target="${WINDOWS_LIBVIRT_POOL_TARGETS[$index]}"
    target_id="${WINDOWS_LIBVIRT_POOL_TARGET_IDS[$index]}"
    if windows_libvirt_pool_uuid_is_listed "$pool_uuid"; then
        windows_libvirt_prove_exact_transient_pool \
            "$name" "$pool_uuid" "$target" "$target_id" || return 1
        virsh_bounded pool-destroy "$pool_uuid" >/dev/null || return 1
    else
        status=$?
        [ "$status" = 1 ] || return 1
        if windows_libvirt_pool_name_is_listed "$name"; then
            return 1
        else
            status=$?
            [ "$status" = 1 ] || return 1
        fi
    fi
    windows_libvirt_require_pool_absent "$name" "$pool_uuid" || return 1
    matches="$(windows_libvirt_pool_target_uuids "$target")" || return 1
    [ -z "$matches" ] || return 1
    windows_libvirt_require_no_persistent_pool_files "$name" || return 1
    windows_libvirt_helper remove-poolstate \
        --uid "$WINDOWS_HELPER_BUILD_UID" --gid "$WINDOWS_HELPER_BUILD_GID" \
        --cache-root "$WINDOWS_LIBVIRT_CACHE_ROOT" \
        --cache-identity "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" \
        --name "$name" --uuid "$pool_uuid" --target "$target" \
        --target-identity "$target_id" \
        || return 1
}

windows_libvirt_cleanup_domain() {
    local index="$1" name domain_uuid
    name="${WINDOWS_LIBVIRT_DOMAIN_NAMES[$index]}"
    domain_uuid="${WINDOWS_LIBVIRT_DOMAIN_UUIDS[$index]}"
    windows_libvirt_require_domain_absent "$name" "$domain_uuid" || return 1
    windows_libvirt_helper cleanup-domain \
        --control-root "$WINDOWS_LIBVIRT_CONTROL_ROOT" \
        --control-identity "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" \
        --uid "$WINDOWS_HELPER_BUILD_UID" --gid "$WINDOWS_HELPER_BUILD_GID" \
        --cache-root "$WINDOWS_LIBVIRT_CACHE_ROOT" \
        --cache-identity "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" \
        --name "$name" --uuid "$domain_uuid"
}

windows_libvirt_transaction_close() {
    local index cleanup_failed=0 domain_unresolved=0
    if ! windows_libvirt_transaction_is_open; then
        [ -z "$WINDOWS_LIBVIRT_CONTROL_ROOT" ] \
            && [ -z "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" ] \
            && [ -z "$WINDOWS_LIBVIRT_USER_HOME" ] \
            && [ -z "$WINDOWS_LIBVIRT_CACHE_ROOT" ] \
            && [ -z "$WINDOWS_LIBVIRT_CACHE_ROOT_ID" ] \
            && [ -z "$WINDOWS_LIBVIRT_CONFIG_ROOT" ] \
            && [ -z "$WINDOWS_LIBVIRT_CONFIG_ROOT_ID" ] \
            && [ -z "$WINDOWS_LIBVIRT_RUNTIME_ROOT" ] \
            && [ -z "$WINDOWS_LIBVIRT_RUNTIME_ROOT_ID" ] \
            && [ -z "$WINDOWS_LIBVIRT_DAEMON_PID" ] \
            && [ -z "$WINDOWS_LIBVIRT_DAEMON_START" ] \
            && [ "${#WINDOWS_LIBVIRT_CLIENT_ENV[@]}" = 0 ] \
            && [ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ] \
            && [ "$WINDOWS_LIBVIRT_RUNTIME_RETIRED" = 0 ] \
            && [ "$WINDOWS_LIBVIRT_CONTROL_RETIRED" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_NAMES[@]}" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_TARGETS[@]}" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_TARGET_IDS[@]}" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_DOMAIN_NAMES[@]}" = 0 ] \
            && [ "${#WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}" = 0 ]
        return
    fi
    if [ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ]; then
        [ "${#WINDOWS_LIBVIRT_POOL_NAMES[@]}" = "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_NAMES[@]}" = "${#WINDOWS_LIBVIRT_POOL_TARGETS[@]}" ] \
            && [ "${#WINDOWS_LIBVIRT_POOL_NAMES[@]}" = "${#WINDOWS_LIBVIRT_POOL_TARGET_IDS[@]}" ] \
            && [ "${#WINDOWS_LIBVIRT_DOMAIN_NAMES[@]}" = "${#WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}" ] \
            || return 1
        for index in "${!WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}"; do
            windows_libvirt_require_domain_absent \
                "${WINDOWS_LIBVIRT_DOMAIN_NAMES[$index]}" \
                "${WINDOWS_LIBVIRT_DOMAIN_UUIDS[$index]}" \
                || domain_unresolved=1
        done
        [ "$domain_unresolved" = 0 ] || return 1
        for ((index=${#WINDOWS_LIBVIRT_POOL_NAMES[@]} - 1; index >= 0; index--)); do
            windows_libvirt_destroy_transient_pool "$index" || cleanup_failed=1
        done
        for index in "${!WINDOWS_LIBVIRT_DOMAIN_UUIDS[@]}"; do
            windows_libvirt_cleanup_domain "$index" || cleanup_failed=1
        done
        [ "$cleanup_failed" = 0 ] || return 1
        WINDOWS_LIBVIRT_OBJECTS_RETIRED=1
    fi
    windows_libvirt_stop_private_daemon || return 1
    windows_libvirt_require_ambient_session_quiescent \
        "/run/user/$WINDOWS_HELPER_BUILD_UID" "$WINDOWS_LIBVIRT_USER_HOME" \
        || return 1
    if [ "$WINDOWS_LIBVIRT_RUNTIME_RETIRED" = 0 ]; then
        /usr/bin/env -i PATH=/usr/bin:/bin \
            /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
                --remove-private-root "$WINDOWS_LIBVIRT_RUNTIME_ROOT" \
                --expected-identity "$WINDOWS_LIBVIRT_RUNTIME_ROOT_ID" \
            || return 1
        [ ! -e "$WINDOWS_LIBVIRT_RUNTIME_ROOT" ] \
            && [ ! -L "$WINDOWS_LIBVIRT_RUNTIME_ROOT" ] || return 1
        WINDOWS_LIBVIRT_RUNTIME_RETIRED=1
    fi
    if [ "$WINDOWS_LIBVIRT_CONTROL_RETIRED" = 0 ]; then
        /usr/bin/env -i PATH=/usr/bin:/bin \
            /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
                --remove-private-root "$WINDOWS_LIBVIRT_CONTROL_ROOT" \
                --expected-identity "$WINDOWS_LIBVIRT_CONTROL_ROOT_ID" \
            || return 1
        [ ! -e "$WINDOWS_LIBVIRT_CONTROL_ROOT" ] \
            && [ ! -L "$WINDOWS_LIBVIRT_CONTROL_ROOT" ] || return 1
        WINDOWS_LIBVIRT_CONTROL_RETIRED=1
    fi
    WINDOWS_LIBVIRT_CONTROL_ROOT=""
    WINDOWS_LIBVIRT_CONTROL_ROOT_ID=""
    WINDOWS_LIBVIRT_USER_HOME=""
    WINDOWS_LIBVIRT_CACHE_ROOT=""
    WINDOWS_LIBVIRT_CACHE_ROOT_ID=""
    WINDOWS_LIBVIRT_CONFIG_ROOT=""
    WINDOWS_LIBVIRT_CONFIG_ROOT_ID=""
    WINDOWS_LIBVIRT_RUNTIME_ROOT=""
    WINDOWS_LIBVIRT_RUNTIME_ROOT_ID=""
    WINDOWS_LIBVIRT_DAEMON_PID=""
    WINDOWS_LIBVIRT_DAEMON_START=""
    WINDOWS_LIBVIRT_CLIENT_ENV=()
    WINDOWS_LIBVIRT_OBJECTS_RETIRED=0
    WINDOWS_LIBVIRT_RUNTIME_RETIRED=0
    WINDOWS_LIBVIRT_CONTROL_RETIRED=0
    WINDOWS_LIBVIRT_POOL_NAMES=()
    WINDOWS_LIBVIRT_POOL_UUIDS=()
    WINDOWS_LIBVIRT_POOL_TARGETS=()
    WINDOWS_LIBVIRT_POOL_TARGET_IDS=()
    WINDOWS_LIBVIRT_DOMAIN_NAMES=()
    WINDOWS_LIBVIRT_DOMAIN_UUIDS=()
}

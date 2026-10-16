# Shared ordinary-user orchestration; the durable run marker is already reserved.
VM_TRANSIENT=
VM_TRANSIENT_ID=
VM_TRANSIENT_ROOT_FD=
VM_STORAGE_MONITOR_PID=
readonly VM_STORAGE_SOURCE="$SCRIPT_DIR/vm-transient-storage.py"
if [ "${MODE:-}" = ledger-token-count ]; then
    readonly VM_STORAGE_PROFILE=ledger-token-count
elif [ "${MODE:-}" = authority-smoke ]; then
    readonly VM_STORAGE_PROFILE=authority-smoke
elif [ "${MODE:-}:${REQUEST:-}" = transaction:--maintenance-stage-xrandr-runtime-candidate ]; then
    readonly VM_STORAGE_PROFILE=xrandr-acquisition
elif [ "${MODE:-}" = cpace-recovery-tests ]; then
    readonly VM_STORAGE_PROFILE=cpace-recovery-tests
elif [ "${MODE:-}" = hbb-common-fs ] && [ "${HBB_LOGIND_NATIVE:-}" = 0 ] \
    && [ "${HBB_FUSE_READ_TESTS:-}" = 0 ]; then
    readonly VM_STORAGE_PROFILE=hbb-common-fs
elif [[ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:credential-dialog \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:terminal-output \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:peer-data \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-navigation \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:modifier-release \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:directory-ordering \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:direct-address \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:window-dispatch ]]; then
    readonly VM_STORAGE_PROFILE=flutter-credential-dialog
elif [ "${MODE:-}:${PEER_BUILD_PROFILE:-}" = android-peer-build:bounded ]; then
    readonly VM_STORAGE_PROFILE=linux-service-build
elif [ "${MODE:-}:${LINUX_RECEIVER_PROFILE:-}" = linux-service-receiver-tests:authorization-timeout ]; then
    readonly VM_STORAGE_PROFILE=linux-service-receiver
elif [ "${MODE:-}:${X11_FOCUS_ONLY:-0}" = x11-display-tests:1 ]; then
    readonly VM_STORAGE_PROFILE=x11-focus
elif [ "${MODE:-}:${LINUX_PA_PLAYBACK:-0}" = linux-pa-authority-tests:1 ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:resolution-parent ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:viewer-credentials ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:android-client-drain ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:file-receive-caller ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:input-revocation ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:clipboard ]; then
    readonly VM_STORAGE_PROFILE=linux-parent-libtest
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:linux-resolution-lifetime ]; then
    readonly VM_STORAGE_PROFILE=linux-resolution-lifetime
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:fusermount-process ]; then
    readonly VM_STORAGE_PROFILE=fusermount-process
else
    readonly VM_STORAGE_PROFILE=standard
fi

vm_storage_preflight() {
    /usr/bin/python3 -I -S "$VM_STORAGE_SOURCE" preflight --memory-mib "$VM_MEMORY" \
        --storage-profile "$VM_STORAGE_PROFILE" \
        || fail 'VM RAM admission failed; no disk-backed scratch fallback is permitted'
}

reserve_vm_storage() {
    local reserved
    reserved=$(/usr/bin/python3 -I -S "$VM_STORAGE_SOURCE" reserve --memory-mib "$VM_MEMORY" \
        --storage-profile "$VM_STORAGE_PROFILE") \
        || fail 'cannot reserve bounded VM RAM scratch'
    VM_TRANSIENT=${reserved%%$'\n'*}
    VM_TRANSIENT_ID=${reserved#*$'\n'}
    [[ "$VM_TRANSIENT" =~ ^/dev/shm/rustdesk-fork-vm-$HOST_UID/run\.[A-Za-z0-9_]+$ ]] \
        && [[ "$VM_TRANSIENT_ID" =~ ^[0-9]+:[0-9]+$ ]] \
        || fail 'RAM scratch reservation receipt differs'
    exec {VM_TRANSIENT_ROOT_FD}<"/dev/shm/rustdesk-fork-vm-$HOST_UID" \
        || fail 'cannot retain the RAM scratch parent'
    /usr/bin/flock --exclusive --nonblock "$VM_TRANSIENT_ROOT_FD" \
        || fail 'RAM scratch parent is held by another harness'
    printf '%s\n%s\n' "$VM_TRANSIENT" "$VM_TRANSIENT_ID" >"$RUN/storage.workspace"
    export TMPDIR="$VM_TRANSIENT"
    /usr/bin/python3 -I -S "$VM_STORAGE_SOURCE" watch --memory-mib "$VM_MEMORY" \
        --storage-profile "$VM_STORAGE_PROFILE" \
        --workspace "$VM_TRANSIENT" --identity "$VM_TRANSIENT_ID" --parent "$$" \
        --run "$RUN" --ready "$RUN/storage.ready" --stop "$RUN/storage.stop" \
        --receipt "$RUN_ROOT/$MODE-${RUN##*/}.storage.json" &
    VM_STORAGE_MONITOR_PID=$!
    for _ in $(/usr/bin/seq 1 100); do
        [ -f "$RUN/storage.ready" ] && return 0
        kill -0 "$VM_STORAGE_MONITOR_PID" 2>/dev/null \
            || fail 'VM RAM monitor exited before readiness'
        /usr/bin/sleep 0.05
    done
    fail 'VM RAM monitor did not become ready'
}

vm_storage_check() {
    /usr/bin/python3 -I -S "$VM_STORAGE_SOURCE" check --memory-mib "$VM_MEMORY" \
        --storage-profile "$VM_STORAGE_PROFILE" \
        --workspace "$VM_TRANSIENT" --identity "$VM_TRANSIENT_ID" \
        || fail 'VM RAM storage admission changed before launch'
}

vm_source_command() (
    ulimit -f 262144 || exit 1
    export TMPDIR="$VM_TRANSIENT"
    "$@"
)

vm_iso_command() (
    ulimit -f 5242880 || exit 1
    export TMPDIR="$VM_TRANSIENT"
    "$@"
)

vm_seed_command() (
    ulimit -f 8192 || exit 1
    export TMPDIR="$VM_TRANSIENT"
    "$@"
)

retire_vm_storage() {
    local joined=$1 monitor_failed=0
    if [ -n "$VM_STORAGE_MONITOR_PID" ]; then
        [ -d "$RUN" ] && [ ! -L "$RUN" ] \
            && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$RUN")" = \
                 "$RUN_ID:$HOST_UID:$HOST_GID:700" ] || return 1
        (set -o noclobber; printf 'stop\n' >"$RUN/storage.stop") || return 1
        wait "$VM_STORAGE_MONITOR_PID" || monitor_failed=1
        VM_STORAGE_MONITOR_PID=
    fi
    if [ "$joined" -eq 0 ] && [ -n "$VM_TRANSIENT" ]; then
        /usr/bin/python3 -I -S "$CLEANUP_HELPER" --remove-private-root "$VM_TRANSIENT" \
            --expected-identity "$VM_TRANSIENT_ID" || return 1
        VM_TRANSIENT=
        VM_TRANSIENT_ID=
    fi
    if [ -n "$VM_TRANSIENT_ROOT_FD" ]; then
        exec {VM_TRANSIENT_ROOT_FD}<&- || return 1
        VM_TRANSIENT_ROOT_FD=
    fi
    [ "$monitor_failed" -eq 0 ] && [ "$joined" -eq 0 ]
}

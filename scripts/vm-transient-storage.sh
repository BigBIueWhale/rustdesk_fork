# Shared ordinary-user orchestration; the durable run marker is already reserved.
VM_TRANSIENT=
VM_TRANSIENT_ID=
VM_TRANSIENT_ROOT_FD=
VM_STORAGE_MONITOR_PID=
readonly VM_STORAGE_SOURCE="$SCRIPT_DIR/vm-transient-storage.py"
if [ "${MODE:-}" = ledger-token-count ]; then
    readonly VM_STORAGE_PROFILE=ledger-token-count
elif [ "${MODE:-}" = fixed-archive-tests ] || [ "${MODE:-}" = windows-service-result-tests ]; then
    readonly VM_STORAGE_PROFILE=fixed-archive-tests
elif [ "${MODE:-}" = debian-package-tests ]; then
    readonly VM_STORAGE_PROFILE=debian-package-tests
elif [ "${MODE:-}" = media-kernel-tests ]; then
    readonly VM_STORAGE_PROFILE=media-kernel-tests
elif [ "${MODE:-}" = authority-smoke ] || [ "${MODE:-}" = dependency-inventory ] \
    || [ "${MODE:-}" = debian-maintainer-tests ] || [ "${MODE:-}" = android-runtime-log-tests ] \
    || [ "${MODE:-}" = network-impairment-probe ]; then
    readonly VM_STORAGE_PROFILE=authority-smoke
elif [ "${MODE:-}:${REQUEST:-}" = transaction:--maintenance-stage-xrandr-runtime-candidate ]; then
    readonly VM_STORAGE_PROFILE=xrandr-acquisition
elif [ "${MODE:-}" = cpace-recovery-tests ]; then
    readonly VM_STORAGE_PROFILE=cpace-recovery-tests
elif [ "${MODE:-}" = linux-service-uid-tests ] || [ "${MODE:-}" = linux-ipc-parent-tests ]; then
    readonly VM_STORAGE_PROFILE=linux-service-uid-tests
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:installer-package ]; then
    readonly VM_STORAGE_PROFILE=installer-package
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = hbb-common-fs:protobuf-parser ]; then
    readonly VM_STORAGE_PROFILE=protobuf-parser
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = hbb-common-fs:tcp-key-transition ]; then
    readonly VM_STORAGE_PROFILE=tcp-key-transition
elif [ "${MODE:-}:${HBB_LOGIND_NATIVE:-}" = hbb-common-fs:1 ]; then
    readonly VM_STORAGE_PROFILE=linux-logind
elif [ "${MODE:-}" = hbb-common-fs ] && [ "${HBB_LOGIND_NATIVE:-}" = 0 ] \
    && [ "${HBB_FUSE_READ_TESTS:-}" = 0 ]; then
    readonly VM_STORAGE_PROFILE=hbb-common-fs
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:locales ]; then
    readonly VM_STORAGE_PROFILE=flutter-locales
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:password-fields ]; then
    readonly VM_STORAGE_PROFILE=flutter-password-fields
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-progress ]; then
    readonly VM_STORAGE_PROFILE=flutter-file-progress
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:peer-search ]; then
    readonly VM_STORAGE_PROFILE=flutter-peer-search
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:audio-input ]; then
    readonly VM_STORAGE_PROFILE=flutter-audio-input
elif [[ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:draggable-divider \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:menu-button \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:help-button ]]; then
    readonly VM_STORAGE_PROFILE=flutter-divider
elif [[ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-columns \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:trackpad-speed ]]; then
    readonly VM_STORAGE_PROFILE=flutter-file-columns
elif [ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:keyboard-layout ]; then
    readonly VM_STORAGE_PROFILE=flutter-keyboard-layout
elif [[ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:credential-dialog \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:screenshot-save ]]; then
    readonly VM_STORAGE_PROFILE=flutter-dialog-tests
elif [[ "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:connect-password \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:terminal-output \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:settings-navigation \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:desktop-theme \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:peer-data \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:custom-scale \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:combo-box \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:image-quality \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:virtual-mouse-buttons \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:virtual-joystick \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:floating-position \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:clipboard-keystrokes \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-search \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:reconnect \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-navigation \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:modifier-release \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:auto-disconnect \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:directory-ordering \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:direct-address \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:file-metadata \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:frame-queue \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:share-rdp \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:hold-drag \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:path-labels \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:setting-checkbox \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:list-search \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:credential-badge \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:tab-selection \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:status-refresh \
    || "${MODE:-}:${FLUTTER_TEST_PROFILE:-}" = flutter-model-tests:window-dispatch ]]; then
    readonly VM_STORAGE_PROFILE=flutter-credential-dialog
elif [ "${MODE:-}:${PEER_BUILD_PROFILE:-}" = android-peer-build:bounded ]; then
    readonly VM_STORAGE_PROFILE=linux-service-build
elif [ "${MODE:-}:${LINUX_RECEIVER_PROFILE:-}" = linux-service-receiver-tests:authorization-timeout ]; then
    readonly VM_STORAGE_PROFILE=linux-service-receiver
elif [ "${MODE:-}:${FLUTTER_APP_BUILD_ONLY:-0}" = flutter-peer-presentation:1 ]; then
    readonly VM_STORAGE_PROFILE=linux-flutter-build
elif [ "${MODE:-}:${FLUTTER_APP_REPLAY:-0}" = flutter-peer-presentation:1 ]; then
    case "${FLUTTER_VIEWER_SUSPEND:-0}" in
        0) readonly VM_STORAGE_PROFILE=linux-flutter-replay ;;
        1) readonly VM_STORAGE_PROFILE=linux-flutter-suspend ;;
        *) fail 'VM workload has no admitted RAM storage profile' ;;
    esac
elif [ "${MODE:-}:${ANDROID_STORAGE_TESTS:-0}" = android-emulator-boot:1 ]; then
    readonly VM_STORAGE_PROFILE=android-storage-key
elif [ "${MODE:-}" = android-frame-tests ] \
    || [ "${MODE:-}:${X11_FOCUS_ONLY:-0}" = x11-display-tests:1 ]; then
    readonly VM_STORAGE_PROFILE=x11-focus
elif [ "${MODE:-}:${X11_KEY_INPUT_ONLY:-0}" = x11-display-tests:1 ]; then
    readonly VM_STORAGE_PROFILE=x11-key-input
elif [ "${MODE:-}" = linux-pa-authority-tests ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:video-qos ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:video-qos-controller ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:video-vpx ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:option-ack ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:viewer-video ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:recording-output ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:clipboard-filetime ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:resolution-parent ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:viewer-credentials ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:viewer-resume ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:local-file-listing ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:android-client-drain ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:cm-read-tick ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:file-receive-caller ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:input-revocation ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:clipboard ]; then
    readonly VM_STORAGE_PROFILE=linux-parent-libtest
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:pake-allocation ]; then
    readonly VM_STORAGE_PROFILE=pake-allocation
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:pake-timing ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:pake-backend-default ] \
    || [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:pake-backend-serial ]; then
    readonly VM_STORAGE_PROFILE=pake-timing
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:main-config-key ]; then
    readonly VM_STORAGE_PROFILE=main-config-key
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:language-selection ]; then
    readonly VM_STORAGE_PROFILE=language-selection
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:windows-pointer ]; then
    readonly VM_STORAGE_PROFILE=windows-pointer
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:linux-resource-limits ]; then
    readonly VM_STORAGE_PROFILE=linux-resource-limits
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:linux-resolution-lifetime ]; then
    readonly VM_STORAGE_PROFILE=linux-resolution-lifetime
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:fusermount-process ]; then
    readonly VM_STORAGE_PROFILE=fusermount-process
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:audio-buffer ]; then
    readonly VM_STORAGE_PROFILE=audio-buffer
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:audio-mailbox ]; then
    readonly VM_STORAGE_PROFILE=audio-mailbox
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:control-egress ]; then
    readonly VM_STORAGE_PROFILE=control-egress
elif [[ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:file-block \
    || "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:android-key-modifiers ]]; then
    readonly VM_STORAGE_PROFILE=file-block
elif [ "${MODE:-}:${RUST_TEST_PROFILE:-}" = android-rust-lifecycle-tests:clipboard-response ]; then
    readonly VM_STORAGE_PROFILE=clipboard-response
else
    case "${MODE:-}" in
        android-emulator-app|android-emulator-boot|android-emulator-runtime|\
        android-execution-probe|android-owner-tests|android-peer-build|\
        android-rust-lifecycle-tests|android-rust-target-check|\
        apple-conform|cm-file-replay|dart-audit|debian-elf-role-tests|\
        debian-polkit-tests|debian-systemd-lifecycle|\
        flutter-model-tests|flutter-peer-presentation|\
        hbb-common-fs|host-network-tests|linux-flutter-artifact-tests|\
        linux-flutter-engine-build|linux-flutter-engine-prepare|\
        linux-service-receiver-tests|\
        linux-systemd-notification-tests|rust-audit|transaction|x11-display-tests)
            readonly VM_STORAGE_PROFILE=standard
            ;;
        *) fail 'VM workload has no admitted RAM storage profile' ;;
    esac
fi

# The caller holds the shared run lock through publication and retirement.
# Keep room for two comparison pairs; retire classified obsolete artifacts before
# admitting a fifth generation. Never silently archive or discard a replay input.
vm_artifact_cache_admit() {
    /usr/bin/python3 -B -I -S - "$1" "$2" <<'PY'
import os
import stat
import sys

path, expected = sys.argv[1:]
if os.geteuid() == 0 or os.path.realpath(path) != path:
    raise SystemExit('artifact cache requires an ordinary user and canonical path')
fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    metadata = os.fstat(fd)
    if (f'{metadata.st_dev}:{metadata.st_ino}' != expected
            or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
            != (os.geteuid(), os.getegid(), 0o700)):
        raise SystemExit('artifact cache identity or ownership differs')
    with os.scandir(fd) as entries:
        for count, _ in enumerate(entries, 1):
            if count >= 4:
                raise SystemExit('artifact cache is full (4 generations); retire obsolete '
                                 'artifacts before building another generation')
    current = os.stat(path, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise SystemExit('artifact cache changed during admission')
finally:
    os.close(fd)
PY
}

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

#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

die() {
    printf 'Android emulator runtime check: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || [ "$#" -eq 8 ] \
    || die 'usage: android-emulator-runtime-check.sh APK APK_SHA256 ARTIFACT_SOURCE_COMMIT recents | APK APK_SHA256 ARTIFACT_SOURCE_COMMIT {peer-lifecycle|controlled-cm} PEER_ROOT PEER_COMMIT PEER_TREE MANIFEST_SHA256'
readonly APK=$1
readonly APK_SHA256=$2
readonly ARTIFACT_SOURCE_COMMIT=$3
readonly RUNTIME_SCENARIO=$4
readonly PEER_ROOT=${5:-}
readonly PEER_COMMIT=${6:-}
readonly PEER_TREE=${7:-}
readonly PEER_MANIFEST_SHA256=${8:-}
case "$RUNTIME_SCENARIO" in
    recents) [ "$#" -eq 4 ] || die 'Recents-only replay accepts no peer authority' ;;
    peer-lifecycle|controlled-cm)
        [ "$#" -eq 8 ] && [[ "$PEER_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$PEER_TREE" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$PEER_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
            || die 'peer replay requires exact source and manifest authority'
        ;;
    *) die 'the Android runtime scenario differs from recents, peer-lifecycle, or controlled-cm' ;;
esac
readonly RUN_UID="$(id -u)"
readonly RUN_GID="$(id -g)"
[ "$RUN_UID:$RUN_GID" = 1000:1000 ] \
    || die 'the Android emulator runtime check requires numeric uid/gid 1000:1000'
[[ "$APK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die 'APK digest is malformed'
[[ "$ARTIFACT_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || die 'artifact source commit is malformed'
[ "$APK" = "$(readlink -f -- "$APK")" ] \
    || die 'APK path is not absolute and canonical'
[ -f "$APK" ] && [ ! -L "$APK" ] \
    && [ "$(stat -c '%u:%g:%a:%h' -- "$APK")" = 1000:1000:400:1 ] \
    || die 'guest-staged APK metadata differs'
[ "$(sha256sum "$APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
    || die 'APK digest differs'

readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
/bin/bash "$ENTRY_PREFLIGHT"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"

readonly VM_ROOT=/run/rustdesk-verifier-vm
readonly RUNTIME_FAILURE_ROOT=/mnt/rustdesk-android-runtime-failure
readonly DOCKER_SOCKET=$VM_ROOT/docker.sock
readonly DOCKER_CONFIG_ROOT=$VM_ROOT/docker-config
readonly DOCKER_CLIENT=/usr/bin/docker
readonly CANDIDATE_ROOT=$REPO_ROOT/online/candidates/android-emulator
readonly EMULATOR_ZIP=$CANDIDATE_ROOT/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
readonly SYSTEM_IMAGE_ZIP=$CANDIDATE_ROOT/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
readonly ADB=$ONLINE_DIR/android-sdk/platform-tools/adb
readonly ANDROID_PLATFORM_JAR=$ONLINE_DIR/android-sdk/platforms/android-${ANDROID_COMPILE_SDK}/android.jar
readonly ANDROID_D8=$ONLINE_DIR/android-sdk/build-tools/${ANDROID_BUILD_TOOLS}/d8
readonly RECENTS_DRIVER_SOURCE=$SCRIPT_DIR/AndroidRecentsDismiss.java
readonly OBSERVER_DEPENDENCY_MANIFEST=$SCRIPT_DIR/android-emulator-frame-observer-dependencies.tsv
OBSERVER_DEPENDENCY_MANIFEST_SHA256=
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    [ -f "$OBSERVER_DEPENDENCY_MANIFEST" ] && [ ! -L "$OBSERVER_DEPENDENCY_MANIFEST" ] \
        || die 'the observer dependency manifest is absent or ambiguous'
    OBSERVER_DEPENDENCY_MANIFEST_SHA256="$(sha256sum "$OBSERVER_DEPENDENCY_MANIFEST" \
        | awk '{ print $1 }')" \
        || die 'cannot digest the observer dependency manifest'
    [[ "$OBSERVER_DEPENDENCY_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || die 'the observer dependency manifest digest is malformed'
fi
readonly OBSERVER_DEPENDENCY_MANIFEST_SHA256

verify_android_sdk_root() {
    python3 -I -S "$SCRIPT_DIR/online-android-sdk-output.py" check-complete \
        --online "$ONLINE_DIR" \
        --cmdline-archive "$ONLINE_DIR/android-cmdline-tools.zip" \
        --uid "$RUN_UID" --gid "$RUN_GID" \
        --builder "$ANDROID_BUILDER_CONFIG_ID" \
        --package-pin "cmdline-tools=$SHA256_ANDROID_CMDLINE_TOOLS" \
        --package-pin "platform-tools=$SHA256_ANDROID_PLATFORM_TOOLS_37_0_1" \
        --package-pin "build-tools-30.0.3=$SHA256_ANDROID_BUILD_TOOLS_30_0_3" \
        --package-pin "build-tools-34.0.0=$SHA256_ANDROID_BUILD_TOOLS_34_0_0" \
        --package-pin "platform-31=$SHA256_ANDROID_PLATFORM_31" \
        --package-pin "platform-32=$SHA256_ANDROID_PLATFORM_32" \
        --package-pin "platform-33=$SHA256_ANDROID_PLATFORM_33" \
        --package-pin "platform-34=$SHA256_ANDROID_PLATFORM_34"
}

verify_gradle_root() {
    python3 -I -S "$SCRIPT_DIR/online-gradle-output.py" check-complete \
        --online "$ONLINE_DIR" --uid "$RUN_UID" --gid "$RUN_GID" \
        --gradle-version "$ANDROID_GRADLE_WRAPPER" \
        --gradle-sha256 "$SHA256_ANDROID_GRADLE_WRAPPER_ALL" \
        --build-tools "$ANDROID_BUILD_TOOLS" \
        --compile-sdk "$ANDROID_COMPILE_SDK"
}

vm_docker() {
    local status=0
    /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$DOCKER_SOCKET" \
        DOCKER_CONFIG="$DOCKER_CONFIG_ROOT" \
        "$DOCKER_CLIENT" --host "unix://$DOCKER_SOCKET" \
            --config "$DOCKER_CONFIG_ROOT" "$@" || status=$?
    /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    return "$status"
}

capture_runtime_log() {
    local status=0
    /usr/bin/python3 -B -u -I -S -c '
import os
import stat
import sys

limit = 1048576
events = {
    b"ANDROID_EMULATOR_KVM_API", b"ANDROID_EMULATOR_KVM_EXECUTION",
    b"ANDROID_EMULATOR_FRAME_ENDPOINT", b"ANDROID_EMULATOR_RENDERER",
    b"ANDROID_PEER_INFRASTRUCTURE", b"ANDROID_CONTROLLED_CPACE",
    b"ANDROID_CONTROLLED_CM_FILE", b"ANDROID_CONTROLLED_CM_STOP",
    b"ANDROID_CONTROLLED_CM_RESTART",
    b"ANDROID_RECENTS_GESTURE_DRIVER", b"ANDROID_RECENTS_DISMISS_ACTION",
    b"ANDROID_RECENTS_DISMISS_OUTCOME", b"ANDROID_PEER_CONNECTION_WAIT",
    b"ANDROID_PEER_CONNECTION_READY", b"ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT",
    b"ANDROID_PEER_CREDENTIAL_RECOVERY", b"ANDROID_PEER_PRESENTATION_STAGE",
    b"ANDROID_PEER_FRESHNESS", b"ANDROID_PEER_RESOURCE_SAMPLE",
    b"ANDROID_PEER_WARM_HOLD", b"ANDROID_PEER_TASK_PARK_SAMPLE",
}

def forward(line):
    if len(line) > 4096 or any(value < 32 or value > 126 for value in line):
        return
    token, _, detail = line.partition(b" ")
    name, _, result = token.partition(b"=")
    if name in events:
        stage = name[len(b"ANDROID_"):].lower().replace(b"_", b"-")
        summary = b"stage=" + stage
        if result:
            summary += b" result=" + result
        if detail:
            summary += b" " + detail
        sys.stdout.buffer.write(b"ANDROID_RUNTIME_STAGE " + summary + b"\n")
        sys.stdout.buffer.flush()

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
with os.fdopen(descriptor, "wb", buffering=0) as output:
    metadata = os.fstat(output.fileno())
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_uid, metadata.st_gid) != (os.getuid(), os.getgid())):
        raise RuntimeError("runtime log authority differs")
    total = 0
    pending = b""
    while True:
        chunk = sys.stdin.buffer.read1(4096)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError("Android app runtime output exceeds its bound")
        if output.write(chunk) != len(chunk):
            raise RuntimeError("runtime log write is incomplete")
        lines = (pending + chunk).split(b"\n")
        pending = lines.pop()
        for line in lines:
            forward(line)
    if pending:
        forward(pending)
' "$1" || status=$?
    if [ "$status" -ne 0 ]; then
        # End the producer even if it becomes silent after the failed log write.
        vm_docker stop --time 10 "$RUNTIME_CONTAINER" >/dev/null || true
    fi
    return "$status"
}

stream_runtime_log() {
    local status=0
    vm_docker logs --follow "$RUNTIME_CONTAINER" 2>&1 \
        | capture_runtime_log "$RUNTIME_LOG" || status=$?
    if [ "$status" -ne 0 ]; then
        vm_docker stop --time 10 "$RUNTIME_CONTAINER" >/dev/null || true
    fi
    return "$status"
}

join_runtime_log() {
    local status=0
    [ -n "$RUNTIME_LOG_READER" ] || return 0
    wait "$RUNTIME_LOG_READER" || status=$?
    RUNTIME_LOG_READER=
    return "$status"
}

start_runtime_log() {
    local cancel_status=0
    trap 'cancel_status=129' HUP
    trap 'cancel_status=130' INT
    trap 'cancel_status=143' TERM
    stream_runtime_log &
    RUNTIME_LOG_READER=$!
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    [ "$cancel_status" -eq 0 ] || exit "$cancel_status"
}

preserve_runtime_failure_log() {
    /usr/bin/python3 -B -I -S - "$1" "$2" <<'PY'
import contextlib
import hashlib
import os
import stat
import sys

limit = 1048576
owner = (os.getuid(), os.getgid())
if 0 in owner or owner != (os.geteuid(), os.getegid()):
    raise RuntimeError("failure-log export requires an ordinary principal")
source_path, root_path = sys.argv[1:]
for path in (source_path, root_path):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RuntimeError("failure-log path is not absolute and canonical")

def fingerprint(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)

with contextlib.ExitStack() as lifetime:
    root = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lifetime.callback(os.close, root)
    root_metadata = os.fstat(root)
    if ((root_metadata.st_uid, root_metadata.st_gid) != owner
            or stat.S_IMODE(root_metadata.st_mode) != 0o700):
        raise RuntimeError("failure-log output is not one fresh private directory")
    with os.scandir(root) as entries:
        if next(entries, None) is not None:
            raise RuntimeError("failure-log output is already occupied")
    source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    source = lifetime.enter_context(os.fdopen(source_fd, "rb"))
    before = os.fstat(source.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or (before.st_uid, before.st_gid) != owner
            or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= limit):
        raise RuntimeError("failure-log source authority or byte bound differs")
    content = source.read(limit + 1)
    if (len(content) != before.st_size
            or fingerprint(os.fstat(source.fileno())) != fingerprint(before)
            or fingerprint(os.stat(source_path, follow_symlinks=False)) != fingerprint(before)):
        raise RuntimeError("failure-log source changed while reading")
    name = "android-runtime-failure.log"
    output_fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o400, dir_fd=root)
    output = lifetime.enter_context(os.fdopen(output_fd, "w+b"))
    if output.write(content) != len(content):
        raise RuntimeError("failure-log write is incomplete")
    output.flush()
    os.fsync(output.fileno())
    output.seek(0)
    if output.read(limit + 1) != content:
        raise RuntimeError("failure-log readback differs")
    after = os.fstat(output.fileno())
    if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
            or (after.st_uid, after.st_gid) != owner
            or stat.S_IMODE(after.st_mode) != 0o400 or after.st_size != len(content)
            or fingerprint(os.stat(name, dir_fd=root, follow_symlinks=False)) != fingerprint(after)):
        raise RuntimeError("failure-log output authority differs")
    edge = os.stat(root_path, follow_symlinks=False)
    if ((edge.st_dev, edge.st_ino, edge.st_uid, edge.st_gid, stat.S_IMODE(edge.st_mode))
            != (root_metadata.st_dev, root_metadata.st_ino, *owner, 0o700)):
        raise RuntimeError("failure-log output directory changed")
    os.fsync(root)
    digest = hashlib.sha256(content).hexdigest()
print(f"ANDROID_RUNTIME_FAILURE_LOG=retained bytes={len(content)} sha256={digest} verdict_input=false")
PY
}

runtime_monotonic_millis() {
    local uptime ignored whole fraction
    read -r uptime ignored < /proc/uptime || return 1
    [[ "$uptime" =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
    whole=${BASH_REMATCH[1]}
    fraction=${BASH_REMATCH[2]}000
    printf '%s\n' "$((10#$whole * 1000 + 10#${fraction:0:3}))"
}

runtime_deadline_command() {
    local deadline=$1 now remaining duration status=0
    shift
    now=$(runtime_monotonic_millis) || return 125
    remaining=$((deadline - now))
    [ "$remaining" -gt 0 ] || return 124
    printf -v duration '%d.%03d' "$((remaining / 1000))" "$((remaining % 1000))"
    # TERM starts cancellation; timeout remains the synchronous command owner during drain.
    LC_ALL=C /usr/bin/timeout --signal=TERM "$duration" "$@" || status=$?
    [ "$status" -eq 0 ] || return "$status"
    now=$(runtime_monotonic_millis) || return 125
    [ "$now" -lt "$deadline" ] || return 124
}

runtime_container_state() {
    local deadline=$1 container=$2 state status=0
    runtime_deadline_command "$deadline" /bin/bash "$ENTRY_PREFLIGHT" >/dev/null \
        || return "$?"
    state=$(runtime_deadline_command "$deadline" \
        /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$DOCKER_SOCKET" DOCKER_CONFIG="$DOCKER_CONFIG_ROOT" \
        "$DOCKER_CLIENT" --host "unix://$DOCKER_SOCKET" \
        --config "$DOCKER_CONFIG_ROOT" inspect --format '{{.State.Status}}' "$container") \
        || status=$?
    runtime_deadline_command "$deadline" /bin/bash "$ENTRY_PREFLIGHT" >/dev/null \
        || return "$?"
    [ "$status" -eq 0 ] || return "$status"
    printf '%s\n' "$state"
}

wait_runtime_container_terminal() {
    local container=$1 limit_ms=$2 now deadline state
    now=$(runtime_monotonic_millis) || return 125
    deadline=$((now + limit_ms))
    while :; do
        state=$(runtime_container_state "$deadline" "$container") || return "$?"
        now=$(runtime_monotonic_millis) || return 125
        [ "$now" -lt "$deadline" ] || return 124
        case "$state" in
            exited|dead) printf '%s\n' "$state"; return 0 ;;
            created|running|restarting|removing|paused) ;;
            *) printf 'Malformed Android container state: %s\n' "$state" >&2; return 65 ;;
        esac
        runtime_deadline_command "$deadline" /usr/bin/sleep 0.1 || return "$?"
    done
}

/usr/bin/python3 -B -I -S "$SCRIPT_DIR/test-android-runtime-waits.py"

vm_provenance() {
    local status=0
    /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$DOCKER_SOCKET" \
        DOCKER_CONFIG="$DOCKER_CONFIG_ROOT" \
        python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py" "$@" \
        || status=$?
    /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    return "$status"
}

verify_image() {
    local role=$1 image=$2
    case "$role" in
        android-builder)
            vm_provenance verify-local \
                --role android-builder \
                --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
                --image-ref "$image" \
                --base "ubuntu:24.04@$SHA256_BASEIMAGE_UBUNTU_2404" \
                --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$ANDROID_BUILDER_CONFIG_ID" \
                --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
            ;;
        devcheck)
            vm_provenance verify-local \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --image-ref "$image" \
                --base "rust:1.75-slim@$DEV_CHECK_BASE_IMAGE_ID" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
            ;;
        *) die "unsupported image role: $role" ;;
    esac
}

WORKSPACE=
WORKSPACE_ID=
VERIFY_CONTAINER=
XVFB_CONTAINER=
RUNTIME_CONTAINER=
OBSERVER_CONTAINER=
RUNTIME_LOG_READER=
cleanup() {
    local status=$? cleanup_status=0 container
    trap - EXIT
    trap '' HUP INT TERM
    for container in "$OBSERVER_CONTAINER" "$RUNTIME_CONTAINER" "$XVFB_CONTAINER" \
        "$VERIFY_CONTAINER"; do
        [ -n "$container" ] || continue
        vm_docker rm -f "$container" >/dev/null 2>&1 || cleanup_status=1
    done
    join_runtime_log || cleanup_status=1
    if [ "$status" -ne 0 ] && [ -n "${RUNTIME_LOG:-}" ] && [ -e "$RUNTIME_LOG" ]; then
        preserve_runtime_failure_log "$RUNTIME_LOG" "$RUNTIME_FAILURE_ROOT" \
            || { printf 'Android runtime failure-log retention failed\n' >&2; cleanup_status=1; }
    fi
    if [ -n "$WORKSPACE" ]; then
        if [ -z "$WORKSPACE_ID" ] || [ ! -d "$WORKSPACE" ] || [ -L "$WORKSPACE" ] \
           || [ "$(stat -c '%d:%i' -- "$WORKSPACE" 2>/dev/null)" != "$WORKSPACE_ID" ]; then
            printf 'Android emulator runtime check: preserving changed private workspace: %s\n' \
                "$WORKSPACE" >&2
            cleanup_status=1
        elif ! python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$WORKSPACE" --expected-identity "$WORKSPACE_ID"; then
            cleanup_status=1
        fi
    fi
    [ "$cleanup_status" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

verify_android_sdk_root
verify_gradle_root
verify_sha256 "$EMULATOR_ZIP" "$SHA256_ANDROID_EMULATOR_LINUX_X64"
verify_sha256 "$SYSTEM_IMAGE_ZIP" "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64"
verify_sha256 "$ADB" "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1"
for sdk_input in "$ANDROID_PLATFORM_JAR" "$ANDROID_D8"; do
    [ -f "$sdk_input" ] && [ ! -L "$sdk_input" ] \
        || die "the Recents-driver SDK input is absent or ambiguous: $sdk_input"
done
[ -f "$RECENTS_DRIVER_SOURCE" ] && [ ! -L "$RECENTS_DRIVER_SOURCE" ] \
    && [ "$(stat -c '%u:%g:%a:%h' -- "$RECENTS_DRIVER_SOURCE")" = \
         1000:1000:400:1 ] \
    || die 'the Recents-driver Java source metadata differs'
readonly RECENTS_DRIVER_SOURCE_SHA256="$(sha256sum "$RECENTS_DRIVER_SOURCE" | awk '{ print $1 }')"
readonly ANDROID_PLATFORM_JAR_SHA256="$(sha256sum "$ANDROID_PLATFORM_JAR" | awk '{ print $1 }')"
readonly ANDROID_D8_SHA256="$(sha256sum "$ANDROID_D8" | awk '{ print $1 }')"
for component_digest in "$RECENTS_DRIVER_SOURCE_SHA256" \
    "$ANDROID_PLATFORM_JAR_SHA256" "$ANDROID_D8_SHA256"; do
    [[ "$component_digest" =~ ^[0-9a-f]{64}$ ]] \
        || die 'a Recents-driver source/tool digest is malformed'
done
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    [ -d "$ONLINE_DIR/xvfb-debs" ] && [ ! -L "$ONLINE_DIR/xvfb-debs" ] \
        || die 'sealed Xvfb package input is absent or ambiguous'
fi
verify_image android-builder "$ANDROID_BUILDER_CONFIG_ID"
verify_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"

readonly APK_ID="$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$APK")"
WORKSPACE="$(mktemp -d /var/tmp/rustdesk-android-emulator-runtime.XXXXXXXXXX)" \
    || die 'cannot create the private runtime-check workspace'
WORKSPACE_ID="$(stat -c '%d:%i' -- "$WORKSPACE")"
[ "$(stat -c '%u:%g:%a' -- "$WORKSPACE")" = 1000:1000:700 ] \
    || die 'private runtime-check workspace metadata differs'
readonly VERIFY_LOG=$WORKSPACE/verify.log
readonly XVFB_LOG=$WORKSPACE/xvfb.log
readonly RUNTIME_LOG=$WORKSPACE/runtime.log
readonly OBSERVER_LOG=$WORKSPACE/observer.log
readonly RECENTS_DRIVER_ROOT=$WORKSPACE/recents-driver
readonly RECENTS_DRIVER_JAR=$RECENTS_DRIVER_ROOT/recents-dismiss.jar
readonly OBSERVER_ROOT=$WORKSPACE/observer
readonly FRAME_SOURCE_ROOT=$WORKSPACE/frame-source
readonly FRAME_SOURCE=$FRAME_SOURCE_ROOT/frame-source
readonly FRAME_SOURCE_C=$SCRIPT_DIR/flutter-peer-source-x11.c
readonly SERVER_TARGET=$WORKSPACE/materialized-peer
readonly XVFB_DEBS=$WORKSPACE/xvfb-debs
readonly XVFB_ROOT=$WORKSPACE/xvfb-root
readonly SERVER_MACHINE_ID=$WORKSPACE/server.machine-id
readonly SERVER_MACHINE_ID_VALUE=727573746465736b2d73657276657231
install -d -m 0700 -- "$RECENTS_DRIVER_ROOT"
SERVER_MACHINE_ID_ID=
PEER_EXECUTION_INVENTORY=
FRAME_SOURCE_SHA256=
FRAME_SOURCE_BYTES=
FRAME_SOURCE_C_ID=
FRAME_SOURCE_C_SHA256=
FRAME_SOURCE_ID=
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    install -d -m 0700 -- "$OBSERVER_ROOT" "$XVFB_DEBS" \
        "$XVFB_ROOT" "$FRAME_SOURCE_ROOT"
    [ -f "$FRAME_SOURCE_C" ] && [ ! -L "$FRAME_SOURCE_C" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FRAME_SOURCE_C")" = 1000:1000:400:1 ] \
        || die 'independent X11 fixture source authority differs'
    FRAME_SOURCE_C_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$FRAME_SOURCE_C")"
    FRAME_SOURCE_C_SHA256="$(sha256sum "$FRAME_SOURCE_C" | awk '{ print $1 }')"
    [[ "$SERVER_MACHINE_ID_VALUE" =~ ^[0-9a-f]{32}$ ]] \
        || die 'private Android peer machine identity is malformed'
    printf '%s\n' "$SERVER_MACHINE_ID_VALUE" > "$SERVER_MACHINE_ID.tmp"
    chmod 0400 "$SERVER_MACHINE_ID.tmp"
    mv -- "$SERVER_MACHINE_ID.tmp" "$SERVER_MACHINE_ID"
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$SERVER_MACHINE_ID")" = \
      "1000:1000:400:1:33" ] \
        && [ "$(<"$SERVER_MACHINE_ID")" = "$SERVER_MACHINE_ID_VALUE" ] \
        || die 'private Android peer machine identity metadata differs'
    SERVER_MACHINE_ID_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$SERVER_MACHINE_ID")"
fi
readonly SERVER_MACHINE_ID_ID

VERIFY_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-runtime-verify \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=128 --memory=4g --memory-swap=4g --cpus=2 \
    --ulimit nofile=1024:1024 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g \
    --env HOME=/tmp/recents-driver-home \
    --mount "type=bind,source=$APK,target=/verify/app.apk,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$RECENTS_DRIVER_ROOT,target=/driver,bind-recursive=disabled" \
    "$ANDROID_BUILDER_CONFIG_ID" \
    /bin/bash --noprofile --norc -euo pipefail -c '
        umask 077
        python3 -I -S /source/scripts/verify-android-emulator-apk.py \
            --apk /verify/app.apk \
            --apksigner /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/apksigner \
            --aapt2 /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/aapt2 \
            --stable-cert-sha256 '"$ANDROID_SIGNING_CERT_SHA256"'
        python3 -I -S /source/scripts/verify-android-apk-manifest.py \
            --apk /verify/app.apk \
            --aapt2 /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/aapt2
        for pass in a b; do
            mkdir -m 0700 "/driver/classes-$pass"
            javac -encoding UTF-8 -source 8 -target 8 \
                -classpath /online/android-sdk/platforms/android-'"$ANDROID_COMPILE_SDK"'/android.jar \
                -d "/driver/classes-$pass" \
                /source/scripts/AndroidRecentsDismiss.java
            /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/d8 \
                --release --min-api 16 \
                --lib /online/android-sdk/platforms/android-'"$ANDROID_COMPILE_SDK"'/android.jar \
                --output "/driver/recents-dismiss-$pass.jar" \
                "/driver/classes-$pass/com/rustdesk/harness/AndroidRecentsDismiss.class"
        done
        cmp -- /driver/recents-dismiss-a.jar /driver/recents-dismiss-b.jar
        install -m 0400 -- /driver/recents-dismiss-b.jar /driver/recents-dismiss.jar
        [ "$(unzip -Z1 /driver/recents-dismiss.jar)" = classes.dex ]
        unzip -t /driver/recents-dismiss.jar >/dev/null
        rm -rf -- /driver/classes-a /driver/classes-b \
            /driver/recents-dismiss-a.jar /driver/recents-dismiss-b.jar
        printf "ANDROID_RECENTS_GESTURE_BUILD=pass sha256=%s source_sha256=%s android_jar_sha256=%s d8_sha256=%s copies=2 equality=byte-identical network=none output=private-bind\\n" \
            "$(sha256sum /driver/recents-dismiss.jar | cut -d " " -f 1)" \
            '"$RECENTS_DRIVER_SOURCE_SHA256"' '"$ANDROID_PLATFORM_JAR_SHA256"' \
            '"$ANDROID_D8_SHA256"'
    ')"
[[ "$VERIFY_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'APK verifier container ID is malformed'
verify_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$VERIFY_CONTAINER")"
[ "$verify_authority" = \
  'none|true|1000:1000|4294967296|4294967296|2000000000|128|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
    || die "APK verifier container authority differs: $verify_authority"
verify_namespace="$(vm_docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' \
    "$VERIFY_CONTAINER")"
[ "$verify_namespace" = 'false||private||private' ] \
    || die "APK verifier container namespace authority differs: $verify_namespace"
verify_status=0
vm_docker start --attach "$VERIFY_CONTAINER" >"$VERIFY_LOG" 2>&1 || verify_status=$?
[ "$verify_status" -eq 0 ] \
    || { tail -n 200 "$VERIFY_LOG" >&2; die "x86_64 APK verification exited with status $verify_status"; }
[ "$(stat -c '%s' -- "$VERIFY_LOG")" -le 262144 ] \
    || die 'APK verifier output exceeds its bound'
mapfile -t apk_receipts < <(grep -E \
    '^ANDROID_EMULATOR_APK=pass sha256=[0-9a-f]{64} package=com\.carriez\.flutter_hbb abi=x86_64 native_libraries=[1-9][0-9]* signer=[0-9A-F]{64} signing=test-only$' \
    "$VERIFY_LOG" || true)
[ "${#apk_receipts[@]}" -eq 1 ] \
    || { tail -n 200 "$VERIFY_LOG" >&2; die 'runtime-test APK receipt is absent or duplicated'; }
case "${apk_receipts[0]}" in
    *"sha256=$APK_SHA256"*) ;;
    *) die 'runtime-test APK verifier reported a different digest' ;;
esac
mapfile -t recents_driver_build_receipts < <(grep -E \
    "^ANDROID_RECENTS_GESTURE_BUILD=pass sha256=[0-9a-f]{64} source_sha256=$RECENTS_DRIVER_SOURCE_SHA256 android_jar_sha256=$ANDROID_PLATFORM_JAR_SHA256 d8_sha256=$ANDROID_D8_SHA256 copies=2 equality=byte-identical network=none output=private-bind$" \
    "$VERIFY_LOG" || true)
[ "${#recents_driver_build_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_RECENTS_GESTURE_BUILD=' "$VERIFY_LOG")" -eq 1 ] \
    || { tail -n 200 "$VERIFY_LOG" >&2; die 'Recents gesture-driver build receipt is absent or malformed'; }
[[ "${recents_driver_build_receipts[0]}" =~ sha256=([0-9a-f]{64})\ source_sha256= ]] \
    || die 'Recents gesture-driver digest receipt is malformed'
RECENTS_DRIVER_SHA256=${BASH_REMATCH[1]}
[ -f "$RECENTS_DRIVER_JAR" ] && [ ! -L "$RECENTS_DRIVER_JAR" ] \
    && [ "$(stat -c '%u:%g:%a:%h' -- "$RECENTS_DRIVER_JAR")" = \
         1000:1000:400:1 ] \
    && [ "$(stat -c '%s' -- "$RECENTS_DRIVER_JAR")" -ge 512 ] \
    && [ "$(stat -c '%s' -- "$RECENTS_DRIVER_JAR")" -le 1048576 ] \
    && [ "$(sha256sum "$RECENTS_DRIVER_JAR" | awk '{ print $1 }')" = \
         "$RECENTS_DRIVER_SHA256" ] \
    || die 'Recents gesture-driver artifact differs from its build receipt'
readonly RECENTS_DRIVER_SHA256
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$VERIFY_CONTAINER")" = exited:0 ] \
    || die 'APK verifier container did not exit cleanly'
vm_docker rm "$VERIFY_CONTAINER" >/dev/null
VERIFY_CONTAINER=

if [ "$RUNTIME_SCENARIO" = peer-lifecycle ] \
   || [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
materialized="$(python3 -I -S "$SCRIPT_DIR/android-peer-artifact.py" materialize \
    --root "$PEER_ROOT" --root-identity "$(stat -c '%d:%i' -- "$PEER_ROOT")" \
    --parent "$WORKSPACE" --parent-identity "$WORKSPACE_ID" \
    --manifest-sha256 "$PEER_MANIFEST_SHA256" \
    --source-commit "$PEER_COMMIT" --source-tree "$PEER_TREE" \
    --builder-config "$DEV_CHECK_IMAGE_CONFIG_ID" \
    --vendor-closure "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
    --vendor-config "$SHA256_CARGO_VENDOR_CONFIG" \
    --rust-toolchain "${RUST_VERSION}.0-x86_64-unknown-linux-gnu")" \
    || die 'source-bound Android peer admission failed'
[ "$materialized" = "$SERVER_TARGET" ] \
    || die 'Android peer materialization destination differs'
printf 'ANDROID_PEER_ARTIFACT_ADMITTED=pass commit=%s tree=%s manifest_sha256=%s builder=%s files=7 build=absent execution=readonly-guest-copy\n' \
    "$PEER_COMMIT" "$PEER_TREE" "$PEER_MANIFEST_SHA256" "$DEV_CHECK_IMAGE_CONFIG_ID"
PEER_EXECUTION_INVENTORY="$(find "$SERVER_TARGET" -xdev -mindepth 0 -printf '%p\0' \
    | LC_ALL=C sort -z | xargs -0 stat -c '%d:%i:%u:%g:%a:%h:%s')"
fi

if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
XVFB_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-xvfb-prepare \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=64 --memory=512m --memory-swap=512m --cpus=1 \
    --ulimit nofile=1024:1024 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m \
    --mount "type=bind,source=$REPO_ROOT,target=/work,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR/xvfb-debs,target=/xvfb-inputs,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$XVFB_DEBS,target=/xvfb-debs,bind-recursive=disabled" \
    --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,bind-recursive=disabled" \
    --mount "type=bind,source=$FRAME_SOURCE_ROOT,target=/frame-source,bind-recursive=disabled" \
    --workdir /work \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    /bin/bash --noprofile --norc -euo pipefail -c '
        /bin/bash /work/scripts/smoke-xvfb-prepare.sh
        /usr/bin/python3 -B -I -S /work/scripts/build-x11-frame-source.py \
            /work/scripts/flutter-peer-source-x11.c /frame-source "$1"
    ' frame-source "$FRAME_SOURCE_C_SHA256")"
[[ "$XVFB_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Android peer Xvfb preparation container ID is malformed'
xvfb_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$XVFB_CONTAINER")"
[ "$xvfb_authority" = \
  'none|true|1000:1000|536870912|536870912|1000000000|64|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
    || die "Android peer Xvfb preparation authority differs: $xvfb_authority"
xvfb_status=0
vm_docker start --attach "$XVFB_CONTAINER" >"$XVFB_LOG" 2>&1 || xvfb_status=$?
[ "$xvfb_status" -eq 0 ] \
    || { tail -n 160 "$XVFB_LOG" >&2; die "Android peer Xvfb preparation exited with status $xvfb_status"; }
[ "$(grep -c '^XVFB_PACKAGE_OK ' "$XVFB_LOG" || true)" -eq 5 ] \
    && grep -Eq '^XVFB_TOOL_CLOSURE_OK packages=5 xvfb_sha256=[0-9a-f]{64} xkbcomp_sha256=[0-9a-f]{64}$' \
        "$XVFB_LOG" \
    || { tail -n 160 "$XVFB_LOG" >&2; die 'Android peer Xvfb preparation receipt differs'; }
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$XVFB_CONTAINER")" = exited:0 ] \
    || die 'Android peer Xvfb preparation container did not exit cleanly'
vm_docker rm "$XVFB_CONTAINER" >/dev/null
XVFB_CONTAINER=
mapfile -t frame_source_build_receipts < <(grep -E \
    "^X11_FRAME_SOURCE_BUILD=pass source_sha256=$FRAME_SOURCE_C_SHA256 sha256=[0-9a-f]{64} bytes=[1-9][0-9]* copies=2 equality=byte-identical network=none output=private$" \
    "$XVFB_LOG" || true)
[ "${#frame_source_build_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^X11_FRAME_SOURCE_BUILD=' "$XVFB_LOG")" -eq 1 ] \
    || die 'independent X11 fixture build receipt differs'
frame_build_identity_pattern=' sha256=([0-9a-f]{64}) bytes=([1-9][0-9]*) '
[[ "${frame_source_build_receipts[0]}" =~ $frame_build_identity_pattern ]] \
    || die 'independent X11 fixture identity is malformed'
FRAME_SOURCE_SHA256=${BASH_REMATCH[1]}
FRAME_SOURCE_BYTES=${BASH_REMATCH[2]}
[ "$(stat -c '%u:%g:%a:%h:%s' -- "$FRAME_SOURCE")" = \
  "1000:1000:500:1:$FRAME_SOURCE_BYTES" ] \
    && [ "$FRAME_SOURCE_BYTES" -le 1048576 ] \
    && [ "$(sha256sum "$FRAME_SOURCE" | awk '{ print $1 }')" = "$FRAME_SOURCE_SHA256" ] \
    && [ "$(find "$FRAME_SOURCE_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\n')" = frame-source ] \
    || die 'independent X11 fixture artifact differs'
FRAME_SOURCE_ID="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$FRAME_SOURCE")"
printf '%s\n' "${frame_source_build_receipts[0]}"
fi
readonly FRAME_SOURCE_SHA256 FRAME_SOURCE_BYTES FRAME_SOURCE_C_ID FRAME_SOURCE_C_SHA256 FRAME_SOURCE_ID

runtime_mounts=(
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$EMULATOR_ZIP,target=/inputs/emulator.zip,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$SYSTEM_IMAGE_ZIP,target=/inputs/system-image.zip,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$ADB,target=/inputs/adb,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$APK,target=/inputs/app.apk,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$RECENTS_DRIVER_JAR,target=/inputs/recents-dismiss.jar,readonly,bind-recursive=disabled"
)
runtime_environment=()
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ] \
   || [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
    runtime_mounts+=(
        --mount "type=bind,source=$SERVER_TARGET,target=/smoke-target,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$PEER_ROOT/peer-manifest.json,target=/inputs/peer-manifest.json,readonly,bind-recursive=disabled"
    )
    runtime_environment=(
        --env "ANDROID_PEER_MANIFEST_SHA256=$PEER_MANIFEST_SHA256"
        --env "ANDROID_PEER_SOURCE_COMMIT=$PEER_COMMIT"
        --env "ANDROID_PEER_SOURCE_TREE=$PEER_TREE"
    )
fi
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    runtime_mounts+=(
        --mount "type=bind,source=$FRAME_SOURCE,target=/inputs/frame-source,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$SERVER_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$OBSERVER_ROOT,target=/observer,bind-recursive=disabled"
    )
    runtime_environment+=(
        --env "ANDROID_FRAME_SOURCE_SHA256=$FRAME_SOURCE_SHA256"
        --env "ANDROID_FRAME_SOURCE_BYTES=$FRAME_SOURCE_BYTES"
    )
fi
readonly -a runtime_mounts runtime_environment

RUNTIME_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-runtime \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --device /dev/kvm:/dev/kvm:rw \
    --pids-limit=1024 --memory=12g --memory-swap=12g --cpus=4 \
    --shm-size=1g --ulimit nofile=8192:8192 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    "${runtime_mounts[@]}" \
    "${runtime_environment[@]}" \
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=10g,mode=700,uid=1000,gid=1000 \
    --tmpfs /tmp/.X11-unix:rw,noexec,nosuid,nodev,size=1m,mode=1777 \
    --workdir /source \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    /bin/bash --noprofile --norc \
        /source/scripts/smoke-android-emulator-boot.sh \
        /inputs/emulator.zip /inputs/system-image.zip /inputs/adb \
        /tmp/android-emulator-app /inputs/app.apk "$RUNTIME_SCENARIO" \
        /inputs/recents-dismiss.jar)"
[[ "$RUNTIME_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Android runtime container ID is malformed'
runtime_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$RUNTIME_CONTAINER")"
[ "${runtime_authority%|*}" = \
  'none|true|1000:1000|12884901888|12884901888|4000000000|1024|1073741824|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}' ] \
    || die "Android runtime container authority differs: $runtime_authority"
python3 -I -S - "${runtime_authority##*|}" <<'PY' \
    || die 'Android runtime container device authority differs'
import json
import sys

expected = [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm", "CgroupPermissions": "rw"}]
if json.loads(sys.argv[1]) != expected:
    raise SystemExit("Android runtime requires exactly the guest KVM read/write mapping")
PY
runtime_namespace="$(vm_docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' \
    "$RUNTIME_CONTAINER")"
[ "$runtime_namespace" = 'false||private||private' ] \
    || die "Android runtime container namespace authority differs: $runtime_namespace"
runtime_driver_mounts="$(vm_docker inspect --format \
    '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
    "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/inputs/recents-dismiss.jar" { print }')"
[ "$runtime_driver_mounts" = \
  "bind	$RECENTS_DRIVER_JAR	/inputs/recents-dismiss.jar	false" ] \
    || die 'Android Recents gesture-driver mount authority differs'
if [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
    runtime_peer_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/smoke-target" { print }')"
    [ "$runtime_peer_mounts" = \
      "bind	$SERVER_TARGET	/smoke-target	false" ] \
        || die 'Android controlled-CM peer execution mount is not the admitted read-only copy'
fi
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    runtime_machine_id_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/etc/machine-id" { print }')"
    [ "$runtime_machine_id_mounts" = \
      "bind	$SERVER_MACHINE_ID	/etc/machine-id	false" ] \
        || die 'Android peer private machine-ID mount authority differs'
    runtime_peer_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/smoke-target" { print }')"
    [ "$runtime_peer_mounts" = \
      "bind	$SERVER_TARGET	/smoke-target	false" ] \
        || die 'Android peer execution mount is not the admitted read-only copy'
    runtime_frame_source_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/inputs/frame-source" { print }')"
    [ "$runtime_frame_source_mounts" = \
      "bind	$FRAME_SOURCE	/inputs/frame-source	false" ] \
        || die 'independent X11 fixture execution mount is not read-only'
    runtime_observer_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/observer" { print }')"
    [ "$runtime_observer_mounts" = \
      "bind	$OBSERVER_ROOT	/observer	true" ] \
        || die 'Android runtime frame-observer exchange mount authority differs'
fi

vm_docker start "$RUNTIME_CONTAINER" >/dev/null \
    || die 'cannot start the Android runtime container'
start_runtime_log

if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
OBSERVER_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-frame-observer \
    --pull=never --network="container:$RUNTIME_CONTAINER" --read-only \
    --user 1000:1000 \
    --pids-limit=512 --memory=3g --memory-swap=3g --cpus=2 \
    --ulimit nofile=2048:2048 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=700,uid=1000,gid=1000,size=2g \
    --env HOME=/tmp/frame-observer-home \
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$EMULATOR_ZIP,target=/inputs/emulator.zip,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR/gradle-home,target=/gradle,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$OBSERVER_ROOT,target=/observer,bind-recursive=disabled" \
    --workdir /source \
    "$ANDROID_BUILDER_CONFIG_ID" \
    /bin/bash --noprofile --norc \
        /source/scripts/android-emulator-frame-observer.sh \
        /inputs/emulator.zip /gradle /observer)"
[[ "$OBSERVER_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Android emulator frame-observer container ID is malformed'
observer_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$OBSERVER_CONTAINER")"
[ "$observer_authority" = \
  "container:$RUNTIME_CONTAINER|true|1000:1000|3221225472|3221225472|2000000000|512|[\"ALL\"]|[\"no-new-privileges\",\"apparmor=docker-default\"]|{}|[]" ] \
    || die "Android emulator frame-observer authority differs: $observer_authority"
observer_namespace="$(vm_docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' \
    "$OBSERVER_CONTAINER")"
[ "$observer_namespace" = 'false||private||private' ] \
    || die "Android emulator frame-observer namespace authority differs: $observer_namespace"
observer_configured_mount_output="$(vm_docker inspect --format \
    '{{range .HostConfig.Mounts}}{{printf "%s|%s|%s|%t|%t\n" .Type .Source .Target .ReadOnly .BindOptions.NonRecursive}}{{end}}' \
    "$OBSERVER_CONTAINER")"
mapfile -t observer_configured_mounts <<<"$observer_configured_mount_output"
[ "${#observer_configured_mounts[@]}" -eq 4 ] \
    || die "Android emulator frame-observer configured mount count differs: $observer_configured_mount_output"
observer_source_mounts=0
observer_emulator_mounts=0
observer_gradle_mounts=0
observer_output_mounts=0
for observer_mount in "${observer_configured_mounts[@]}"; do
    IFS='|' read -r observer_type observer_source observer_target \
        observer_read_only observer_non_recursive observer_extra <<<"$observer_mount"
    [ "$observer_type" = bind ] && [ -z "$observer_extra" ] \
        && [ "$observer_non_recursive" = true ] \
        || die "Android emulator frame-observer configured mount shape differs: $observer_mount"
    case "$observer_target" in
        /source)
            [ "$observer_source:$observer_read_only" = "$REPO_ROOT:true" ] \
                || die "Android emulator frame-observer source mount differs: $observer_mount"
            observer_source_mounts=$((observer_source_mounts + 1))
            ;;
        /inputs/emulator.zip)
            [ "$observer_source:$observer_read_only" = "$EMULATOR_ZIP:true" ] \
                || die "Android emulator frame-observer emulator mount differs: $observer_mount"
            observer_emulator_mounts=$((observer_emulator_mounts + 1))
            ;;
        /gradle)
            [ "$observer_source:$observer_read_only" = \
              "$ONLINE_DIR/gradle-home:true" ] \
                || die "Android emulator frame-observer Gradle mount differs: $observer_mount"
            observer_gradle_mounts=$((observer_gradle_mounts + 1))
            ;;
        /observer)
            [ "$observer_source:$observer_read_only" = \
              "$OBSERVER_ROOT:false" ] \
                || die "Android emulator frame-observer output mount differs: $observer_mount"
            observer_output_mounts=$((observer_output_mounts + 1))
            ;;
        *) die "Android emulator frame-observer configured an unexpected mount: $observer_mount" ;;
    esac
done
[ "$observer_source_mounts:$observer_emulator_mounts:$observer_gradle_mounts:$observer_output_mounts" = \
  1:1:1:1 ] \
    || die 'Android emulator frame-observer configured mount targets are not unique'
observer_tmpfs="$(vm_docker inspect --format '{{json .HostConfig.Tmpfs}}' \
    "$OBSERVER_CONTAINER")"
[ "$observer_tmpfs" = \
  '{"/tmp":"rw,exec,nosuid,nodev,mode=700,uid=1000,gid=1000,size=2g"}' ] \
    || die "Android emulator frame-observer tmpfs authority differs: $observer_tmpfs"
observer_resolved_mount_output="$(vm_docker inspect --format \
    '{{range .Mounts}}{{printf "%s|%s|%s|%t|%s\n" .Type .Source .Destination .RW .Propagation}}{{end}}' \
    "$OBSERVER_CONTAINER")"
mapfile -t observer_resolved_mounts <<<"$observer_resolved_mount_output"
[ "${#observer_resolved_mounts[@]}" -ge 4 ] \
    && [ "${#observer_resolved_mounts[@]}" -le 5 ] \
    || die "Android emulator frame-observer resolved mount count differs: $observer_resolved_mount_output"
observer_resolved_source=0
observer_resolved_emulator=0
observer_resolved_gradle=0
observer_resolved_output=0
observer_resolved_tmpfs=0
for observer_mount in "${observer_resolved_mounts[@]}"; do
    IFS='|' read -r observer_type observer_source observer_target \
        observer_writable observer_propagation observer_extra <<<"$observer_mount"
    [ -z "$observer_extra" ] \
        || die "Android emulator frame-observer resolved mount shape differs: $observer_mount"
    case "$observer_type:$observer_target" in
        bind:/source)
            [ "$observer_source:$observer_writable:$observer_propagation" = \
              "$REPO_ROOT:false:rprivate" ] \
                || die "Android emulator frame-observer resolved source mount differs: $observer_mount"
            observer_resolved_source=$((observer_resolved_source + 1))
            ;;
        bind:/inputs/emulator.zip)
            [ "$observer_source:$observer_writable:$observer_propagation" = \
              "$EMULATOR_ZIP:false:rprivate" ] \
                || die "Android emulator frame-observer resolved emulator mount differs: $observer_mount"
            observer_resolved_emulator=$((observer_resolved_emulator + 1))
            ;;
        bind:/gradle)
            [ "$observer_source:$observer_writable:$observer_propagation" = \
              "$ONLINE_DIR/gradle-home:false:rprivate" ] \
                || die "Android emulator frame-observer resolved Gradle mount differs: $observer_mount"
            observer_resolved_gradle=$((observer_resolved_gradle + 1))
            ;;
        bind:/observer)
            [ "$observer_source:$observer_writable:$observer_propagation" = \
              "$OBSERVER_ROOT:true:rprivate" ] \
                || die "Android emulator frame-observer resolved output mount differs: $observer_mount"
            observer_resolved_output=$((observer_resolved_output + 1))
            ;;
        tmpfs:/tmp)
            [ -z "$observer_source" ] && [ "$observer_writable" = true ] \
                && [ -z "$observer_propagation" ] \
                || die "Android emulator frame-observer resolved tmpfs differs: $observer_mount"
            observer_resolved_tmpfs=$((observer_resolved_tmpfs + 1))
            ;;
        *) die "Android emulator frame-observer resolved an unexpected mount: $observer_mount" ;;
    esac
done
[ "$observer_resolved_source:$observer_resolved_emulator:$observer_resolved_gradle:$observer_resolved_output" = \
  1:1:1:1 ] && [ "$observer_resolved_tmpfs" -le 1 ] \
    || die 'Android emulator frame-observer resolved mount targets are not unique'
vm_docker start "$OBSERVER_CONTAINER" >/dev/null \
    || die 'cannot start the Android emulator frame-observer container'

observer_ready=0
observer_startup_failed=0
startup_wait_status=0
startup_now=$(runtime_monotonic_millis) || die 'cannot read the runtime elapsed clock'
startup_deadline=$((startup_now + 900000))
while :; do
    startup_now=$(runtime_monotonic_millis) || die 'cannot read the runtime elapsed clock'
    [ "$startup_now" -lt "$startup_deadline" ] || { startup_wait_status=124; break; }
    if [ -f "$OBSERVER_ROOT/ready" ] && [ ! -L "$OBSERVER_ROOT/ready" ]; then
        ready_metadata=$(runtime_deadline_command "$startup_deadline" \
            /usr/bin/stat -c '%u:%g:%a:%h' -- "$OBSERVER_ROOT/ready") \
            || { startup_wait_status=$?; break; }
        [ "$ready_metadata" = 1000:1000:600:1 ] \
            || die 'Android emulator frame-observer ready metadata differs'
        startup_now=$(runtime_monotonic_millis) || die 'cannot read the runtime elapsed clock'
        [ "$startup_now" -lt "$startup_deadline" ] \
            || { startup_wait_status=124; break; }
        observer_ready=1
        break
    fi
    observer_state=$(runtime_container_state "$startup_deadline" "$OBSERVER_CONTAINER") \
        || { startup_wait_status=$?; break; }
    case "$observer_state" in
        exited|dead)
            observer_startup_failed=1
            break
            ;;
        created|running|restarting|removing|paused) ;;
        *) die "Android emulator frame-observer startup state is malformed: $observer_state" ;;
    esac
    runtime_state=$(runtime_container_state "$startup_deadline" "$RUNTIME_CONTAINER") \
        || { startup_wait_status=$?; break; }
    case "$runtime_state" in
        exited|dead) break ;;
        created|running|restarting|removing|paused) ;;
        *) die "Android runtime startup state is malformed: $runtime_state" ;;
    esac
    runtime_deadline_command "$startup_deadline" /usr/bin/sleep 0.1 \
        || { startup_wait_status=$?; break; }
done
if [ "$startup_wait_status" -ne 0 ]; then
    vm_docker logs --tail 240 "$OBSERVER_CONTAINER" >"$OBSERVER_LOG" 2>&1 || true
    tail -n 240 "$OBSERVER_LOG" >&2
    [ ! -f "$RUNTIME_LOG" ] || tail -n 240 "$RUNTIME_LOG" >&2
fi
[ "$startup_wait_status" -ne 124 ] \
    || die 'Android emulator frame observer produced no external frame within 15 minutes'
[ "$startup_wait_status" -eq 0 ] \
    || die "Android emulator startup observation failed with status $startup_wait_status"
if [ "$observer_startup_failed" -eq 1 ]; then
    runtime_startup_terminal=0
    runtime_terminal_status=0
    runtime_state=$(wait_runtime_container_terminal "$RUNTIME_CONTAINER" 120000) \
        || runtime_terminal_status=$?
    case "$runtime_terminal_status" in
        0) runtime_startup_terminal=1 ;;
        124) runtime_state=deadline-expired ;;
        *) runtime_state="observation-failed:$runtime_terminal_status" ;;
    esac
    vm_docker logs --tail 320 "$OBSERVER_CONTAINER" >"$OBSERVER_LOG" 2>&1 || true
    runtime_final_state="$(vm_docker inspect --format \
        '{{.State.Status}}:{{.State.ExitCode}}' "$RUNTIME_CONTAINER" 2>/dev/null \
        || printf unavailable)"
    observer_final_state="$(vm_docker inspect --format \
        '{{.State.Status}}:{{.State.ExitCode}}' "$OBSERVER_CONTAINER" 2>/dev/null \
        || printf unavailable)"
    printf 'Android emulator startup failure states: runtime=%s observer=%s runtime_terminal=%s\n' \
        "$runtime_final_state" "$observer_final_state" "$runtime_startup_terminal" >&2
    printf '%s\n' '--- Android runtime log (last 320 lines) ---' >&2
    [ ! -f "$RUNTIME_LOG" ] || tail -n 320 "$RUNTIME_LOG" >&2
    printf '%s\n' '--- Android frame-observer log (last 320 lines) ---' >&2
    tail -n 320 "$OBSERVER_LOG" >&2
    die "Android emulator frame observer exited before its first external frame (runtime startup state: $runtime_state)"
fi
if ! runtime_status="$(vm_docker wait "$RUNTIME_CONTAINER")"; then
    die 'cannot wait for the Android runtime container'
fi
[[ "$runtime_status" =~ ^[0-9]+$ ]] \
    || die "Android runtime container returned a malformed status: $runtime_status"
join_runtime_log || die 'Android runtime log reader failed'

observer_join_status=0
observer_state=$(wait_runtime_container_terminal "$OBSERVER_CONTAINER" 120000) \
    || observer_join_status=$?
vm_docker logs "$OBSERVER_CONTAINER" >"$OBSERVER_LOG" 2>&1 \
    || die 'cannot collect the Android emulator frame-observer log'
[ "$observer_join_status" -ne 124 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame observer did not join within 120 seconds'; }
[ "$observer_join_status" -eq 0 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die "Android emulator observer shutdown observation failed with status $observer_join_status"; }
observer_status="$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$OBSERVER_CONTAINER")"
else
    if ! runtime_status="$(vm_docker wait "$RUNTIME_CONTAINER")"; then
        die 'cannot wait for the focused Android runtime container'
    fi
    [[ "$runtime_status" =~ ^[0-9]+$ ]] \
        || die "focused Android runtime container returned a malformed status: $runtime_status"
    join_runtime_log || die 'focused Android runtime log reader failed'
    observer_status=not-applicable
fi
if [ "$runtime_status" -ne 0 ]; then
    awk '
        /^ANDROID_FRAMEWORK_DIAGNOSTIC_BEGIN$/ { in_diag = 1 }
        in_diag { print }
        /^ANDROID_FRAMEWORK_DIAGNOSTIC_END$/ { in_diag = 0 }
    ' "$RUNTIME_LOG" >&2
    tail -n 240 "$RUNTIME_LOG" >&2
    [ "$RUNTIME_SCENARIO" != peer-lifecycle ] \
        || tail -n 240 "$OBSERVER_LOG" >&2
    grep '^ANDROID_MAIN_SERVICE_LOG_' "$RUNTIME_LOG" \
        | tail -n 40 >&2 || true
    grep -E '^ANDROID_PEER_(INITIAL_CREDENTIAL_PROMPT|PASSWORD_INPUT|PASSWORD_PRE_SUBMIT_(STATE|QUIET)|PASSWORD_ACTION|PASSWORD_SUBMIT|CREDENTIAL_RECOVERY|CONNECTION_WAIT|CONNECTION_READY|CONNECTION_STATE)=' \
        "$RUNTIME_LOG" | tail -n 80 >&2 || true
    grep '^ANDROID_PEER_PROCESS_THREAD ' "$RUNTIME_LOG" \
        | tail -n 64 >&2 || true
    awk '
        /^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_BEGIN / { in_png = 1 }
        in_png { print }
        /^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_END( |$)/ { in_png = 0 }
    ' "$RUNTIME_LOG" >&2
    grep -E '^ANDROID_PEER_(FRAME_BASELINE |FRAME_SAMPLE |PRESENTATION_UI=)' \
        "$RUNTIME_LOG" | tail -n 140 >&2 || true
    grep -E '^(ANDROID_PEER_PRESENTATION_STAGE(_DIAGNOSTIC_(BEGIN|END)|_(SERVER|NATIVE|DART)|=)|ANDROID_PEER_PRESENTATION_PROGRESS |.*RUSTDESK_PRESENTATION_PROGRESS )' \
        "$RUNTIME_LOG" | tail -n 80 >&2 || true
    grep '^ANDROID_PEER_FRAMEBUFFER_DIAGNOSTIC ' "$RUNTIME_LOG" \
        | tail -n 20 >&2 || true
    awk '
        /^ANDROID_PASSWORD_SUBMIT_DIAGNOSTIC_BEGIN$/ {
            block = ""
            in_diag = 1
        }
        in_diag { block = block $0 ORS }
        /^ANDROID_PASSWORD_SUBMIT_DIAGNOSTIC_END$/ && in_diag {
            last = block
            in_diag = 0
        }
        END { printf "%s", last }
    ' "$RUNTIME_LOG" >&2
    grep '^ANDROID_PERMANENT_PASSWORD_SUBMIT=' "$RUNTIME_LOG" \
        | tail -n 20 >&2 || true
    grep '^ANDROID_PERMANENT_PASSWORD_ACTION=' "$RUNTIME_LOG" \
        | tail -n 20 >&2 || true
    grep '^ANDROID_RECENTS_DISMISS_ACTION=' "$RUNTIME_LOG" \
        | tail -n 12 >&2 || true
    grep '^ANDROID_RECENTS_DISMISS_OUTCOME=' "$RUNTIME_LOG" \
        | tail -n 12 >&2 || true
    grep '^Android initial UI:' "$RUNTIME_LOG" | tail -n 80 >&2 || true
    runtime_failure="$(grep -m 1 '^Android emulator boot smoke:' \
        "$RUNTIME_LOG" || true)"
    [ -z "$runtime_failure" ] || printf '%s\n' "$runtime_failure" >&2
    die "Android app runtime exited with status $runtime_status"
fi
[ "$RUNTIME_SCENARIO" != peer-lifecycle ] || [ "$observer_status" = exited:0 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die "Android emulator frame observer did not exit cleanly: $observer_status"; }
[ "$(stat -c '%s' -- "$RUNTIME_LOG")" -le 1048576 ] \
    || die 'Android app runtime output exceeds its bound'
[ "$RUNTIME_SCENARIO" != peer-lifecycle ] \
    || [ "$(stat -c '%s' -- "$OBSERVER_LOG")" -le 1048576 ] \
    || die 'Android emulator frame-observer output exceeds its bound'
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
mapfile -t endpoint_receipts < <(grep -Fx \
    'ANDROID_EMULATOR_FRAME_ENDPOINT=pass connect=127.0.0.1:8554 bind=[::]:8554 namespace=loopback-only transport=grpc-stream network=container-none' \
    "$RUNTIME_LOG" || true)
[ "${#endpoint_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android emulator frame-endpoint receipt is absent or duplicated'; }
mapfile -t frame_parser_receipts < <(grep -Fx \
    'ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=pass format=counter32 source=monotonic-publication alias=refused' \
    "$OBSERVER_LOG" || true)
[ "${#frame_parser_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame-parser self-test receipt is absent or duplicated'; }
mapfile -t frame_observer_self_test_receipts < <(grep -Fx \
    'ANDROID_EMULATOR_FRAME_OBSERVER_SELF_TEST=pass scenarios=7' \
    "$OBSERVER_LOG" || true)
[ "${#frame_observer_self_test_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame-observer self-test receipt is absent or duplicated'; }
mapfile -t frame_observer_build_receipts < <(grep -E \
    "^ANDROID_EMULATOR_FRAME_OBSERVER_BUILD=pass protoc=3\\.20\\.1 protobuf=3\\.22\\.3 grpc=1\\.57\\.0 jars=31 generated_sources=[1-9][0-9]* dependency_manifest_sha256=$OBSERVER_DEPENDENCY_MANIFEST_SHA256 network=container-loopback output=private-bind$" \
    "$OBSERVER_LOG" || true)
[ "${#frame_observer_build_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame-observer build receipt is absent or duplicated'; }
mapfile -t frame_observer_receipts < <(grep -E \
    '^ANDROID_EMULATOR_FRAME_OBSERVER=pass endpoint=127\.0\.0\.1:8554 transport=grpc-stream format=rgb888 orientation=bottom-up frames_received=[1-9][0-9]* frames_published=[1-9][0-9]* last_seq=[0-9]+ cleanup=joined$' \
    "$OBSERVER_LOG" || true)
[ "${#frame_observer_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame-observer runtime receipt is absent or duplicated'; }
observer_inventory="$(find "$OBSERVER_ROOT" -mindepth 1 -maxdepth 1 \
    -printf '%f\n' | LC_ALL=C sort)"
[ "$observer_inventory" = $'latest.frame\nready\nstop\nstopped' ] \
    || die "Android emulator frame-observer output inventory differs: $observer_inventory"
for observer_output in latest.frame ready stop stopped; do
    [ -f "$OBSERVER_ROOT/$observer_output" ] \
        && [ ! -L "$OBSERVER_ROOT/$observer_output" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- \
            "$OBSERVER_ROOT/$observer_output")" = 1000:1000:600:1 ] \
        || die "Android emulator frame-observer output metadata differs: $observer_output"
done
[ "$(stat -c '%s' -- "$OBSERVER_ROOT/latest.frame")" -ge 1024 ] \
    && [ "$(stat -c '%s' -- "$OBSERVER_ROOT/latest.frame")" -le 262144 ] \
    && [ "$(stat -c '%s' -- "$OBSERVER_ROOT/ready")" -le 128 ] \
    && [ "$(stat -c '%s' -- "$OBSERVER_ROOT/stop")" -eq 5 ] \
    && [ "$(stat -c '%s' -- "$OBSERVER_ROOT/stopped")" -le 256 ] \
    || die 'Android emulator frame-observer output size differs'
[ "$(<"$OBSERVER_ROOT/stop")" = stop ] \
    || die 'Android emulator frame-observer stop marker differs'
[[ "${frame_observer_receipts[0]}" =~ \
    frames_received=([1-9][0-9]*)\ frames_published=([1-9][0-9]*)\ last_seq=([0-9]+)\ cleanup=joined$ ]] \
    || die 'Android emulator frame-observer runtime counts are malformed'
observer_frames_received=${BASH_REMATCH[1]}
observer_frames_published=${BASH_REMATCH[2]}
observer_last_sequence=${BASH_REMATCH[3]}
[ "$observer_frames_received" -ge "$observer_frames_published" ] \
    || die 'Android emulator frame-observer published more frames than it received'
[ "$(<"$OBSERVER_ROOT/stopped")" = \
  "stopped frames_received=$observer_frames_received frames_published=$observer_frames_published last_seq=$observer_last_sequence" ] \
    || die 'Android emulator frame-observer finality receipt differs from its output marker'
fi
mapfile -t renderer_receipts < <(grep -E \
    '^ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader angle=(present|absent) gles_sha256=[0-9a-f]{64}$' \
    "$RUNTIME_LOG" || true)
[ "${#renderer_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android renderer receipt is absent or duplicated'; }
[ "$(grep -c '^ANDROID_EMULATOR_RENDERER=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android renderer receipt is malformed or duplicated'; }
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
readonly peer_presentation_phase_pattern='(initial|background-resume-1-2s|background-resume-2-6s|background-resume-3-120s|warm-hold-[1-6]|warm-reconnect-[1-6]|task-relaunch-[1-6])'
readonly peer_presentation_phase_inventory=$'background-resume-1-2s\nbackground-resume-2-6s\nbackground-resume-3-120s\ninitial\ntask-relaunch-1\ntask-relaunch-2\ntask-relaunch-3\ntask-relaunch-4\ntask-relaunch-5\ntask-relaunch-6\nwarm-hold-1\nwarm-hold-2\nwarm-hold-3\nwarm-hold-4\nwarm-hold-5\nwarm-hold-6\nwarm-reconnect-1\nwarm-reconnect-2\nwarm-reconnect-3\nwarm-reconnect-4\nwarm-reconnect-5\nwarm-reconnect-6'
mapfile -t peer_frame_baselines < <(grep -E \
    "^ANDROID_PEER_FRAME_BASELINE phase=$peer_presentation_phase_pattern observer_age_ms=[0-9]+ source_state=[0-9]+ display_state=([0-9]+|unavailable) dimensions=(120x200|200x120) seq=[0-9]+ timestamp_us=[1-9][0-9]*$" \
    "$RUNTIME_LOG" || true)
[ "${#peer_frame_baselines[@]}" -eq 22 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer frame baselines are absent or duplicated'; }
peer_frame_baseline_phases="$(printf '%s\n' "${peer_frame_baselines[@]}" \
    | sed -nE 's/^ANDROID_PEER_FRAME_BASELINE phase=([^ ]+) .*/\1/p' \
    | LC_ALL=C sort)"
[ "$peer_frame_baseline_phases" = "$peer_presentation_phase_inventory" ] \
    || die "Android peer frame baseline phases differ: $peer_frame_baseline_phases"
mapfile -t peer_presentation_ui_receipts < <(grep -E \
    "^ANDROID_PEER_PRESENTATION_UI=pass phase=$peer_presentation_phase_pattern connecting=retired credential=retired waiting=retired$" \
    "$RUNTIME_LOG" || true)
[ "${#peer_presentation_ui_receipts[@]}" -eq 22 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer presentation UI receipts are absent or duplicated'; }
peer_presentation_ui_phases="$(printf '%s\n' "${peer_presentation_ui_receipts[@]}" \
    | sed -nE 's/^ANDROID_PEER_PRESENTATION_UI=pass phase=([^ ]+) .*/\1/p' \
    | LC_ALL=C sort)"
[ "$peer_presentation_ui_phases" = "$peer_presentation_phase_inventory" ] \
    || die "Android peer presentation UI phases differ: $peer_presentation_ui_phases"
mapfile -t peer_warm_hold_receipts < <(grep -E \
    '^ANDROID_PEER_WARM_HOLD=pass samples=6 interval_seconds=20 elapsed_ms=[1-9][0-9]* task=stable process=stable service=foreground-preserved keyed_sessions=unchanged peer_connections=1 pixels=fresh-changing$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_warm_hold_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_PEER_WARM_HOLD=' "$RUNTIME_LOG")" -eq 1 ] \
    || die 'Android peer warm-hold receipt is absent, malformed, or duplicated'
[[ "${peer_warm_hold_receipts[0]}" =~ elapsed_ms=([1-9][0-9]*)\ task=stable ]] \
    || die 'Android peer warm-hold duration is malformed'
[ "${BASH_REMATCH[1]}" -ge 120000 ] \
    && [ "${BASH_REMATCH[1]}" -le 240000 ] \
    || die 'Android peer warm-hold duration is outside its bounded schedule'
mapfile -t peer_task_park_receipts < <(grep -E \
    '^ANDROID_PEER_TASK_PARK=pass samples=6 interval_seconds=20 elapsed_ms=[1-9][0-9]* task=absent process=stable service=foreground-preserved keyed_sessions=unchanged peer_connections=0$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_task_park_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_PEER_TASK_PARK=' "$RUNTIME_LOG")" -eq 1 ] \
    || die 'Android peer removed-task hold receipt is absent, malformed, or duplicated'
[[ "${peer_task_park_receipts[0]}" =~ elapsed_ms=([1-9][0-9]*)\ task=absent ]] \
    || die 'Android peer removed-task hold duration is malformed'
[ "${BASH_REMATCH[1]}" -ge 120000 ] \
    && [ "${BASH_REMATCH[1]}" -le 180000 ] \
    || die 'Android peer removed-task hold duration is outside its bounded schedule'
mapfile -t peer_presentation_stage_receipts < <(grep -E \
    '^ANDROID_PEER_PRESENTATION_STAGE=pass phase=(initial|warm-reconnect-[1-6]|task-relaunch-[1-6]) ordinal=([1-9]|1[0-3]) server_connection=[1-9][0-9]* display=[0-9]+ server_wire_generation=[1-9][0-9]* viewer_wire_generation=[1-9][0-9]* server_wall_ms=[1-9][0-9]* server_queue_us=[0-9]+ viewer_mailbox_generation=[1-9][0-9]* viewer_wall_ms=[1-9][0-9]* receive_to_admit_us=[0-9]+ admit_to_dequeue_us=[0-9]+ decode_us=[0-9]+ dart_session=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} publication=[1-9][0-9]* dart_wall_ms=[1-9][0-9]* event_queue_us=[0-9]+ take_us=[0-9]+ checkpoint_us=[0-9]+ decode_commit_us=[0-9]+ ui_finalize_us=[0-9]+ dart_total_us=[0-9]+ image_conversions_active=[1-3] image_conversions_waiting=([0-9]|[1-5][0-9]|6[0-4]) image_conversions_peak=[1-3] client_owner=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_presentation_stage_receipts[@]}" -eq 13 ] \
    && [ "$(grep -c '^ANDROID_PEER_PRESENTATION_STAGE=' "$RUNTIME_LOG")" -eq 13 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer presentation-stage receipts are absent, malformed, or duplicated'; }
for phase_ordinal in 'initial 1' 'warm-reconnect-1 2' 'warm-reconnect-2 3' \
    'warm-reconnect-3 4' 'warm-reconnect-4 5' 'warm-reconnect-5 6' \
    'warm-reconnect-6 7' 'task-relaunch-1 8' 'task-relaunch-2 9' \
    'task-relaunch-3 10' 'task-relaunch-4 11' 'task-relaunch-5 12' \
    'task-relaunch-6 13'; do
    read -r phase ordinal <<<"$phase_ordinal"
    [ "$(printf '%s\n' "${peer_presentation_stage_receipts[@]}" \
        | grep -Ec "^ANDROID_PEER_PRESENTATION_STAGE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
        || die "Android peer presentation-stage binding differs for $phase"
done
mapfile -t peer_resource_samples < <(grep -E \
    '^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=(baseline|warm-reconnect-[1-6]|task-relaunch-[1-6]) ordinal=([0-9]|1[0-2]) rss_kib=[1-9][0-9]* threads=[1-9][0-9]* rss_growth_kib=[0-9]+ thread_growth=[0-9]+ handles=unobserved handle_reason=release-apk-nonroot-procfs-denied observer_survival=process-service-peer$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_resource_samples[@]}" -eq 13 ] \
    && [ "$(grep -c '^ANDROID_PEER_RESOURCE_SAMPLE=' "$RUNTIME_LOG")" -eq 13 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer resource samples are absent, malformed, or duplicated'; }
for phase_ordinal in 'baseline 0' 'warm-reconnect-1 1' 'warm-reconnect-2 2' \
    'warm-reconnect-3 3' 'warm-reconnect-4 4' 'warm-reconnect-5 5' \
    'warm-reconnect-6 6' 'task-relaunch-1 7' 'task-relaunch-2 8' \
    'task-relaunch-3 9' 'task-relaunch-4 10' 'task-relaunch-5 11' \
    'task-relaunch-6 12'; do
    read -r phase ordinal <<<"$phase_ordinal"
    [ "$(printf '%s\n' "${peer_resource_samples[@]}" \
        | grep -Ec "^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
        || die "Android peer resource-sample binding differs for $phase"
done
[ "$(printf '%s\n' "${peer_resource_samples[@]}" \
    | grep -Ec '^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=baseline ordinal=0 .* rss_growth_kib=0 thread_growth=0 handles=unobserved handle_reason=release-apk-nonroot-procfs-denied observer_survival=process-service-peer$')" -eq 1 ] \
    || die 'Android peer resource baseline has nonzero growth'
mapfile -t peer_resource_bounds < <(grep -E \
    '^ANDROID_PEER_RESOURCE_BOUND=partial samples=13 replacement_samples=12 rss_baseline_kib=[1-9][0-9]* rss_max_kib=[1-9][0-9]* rss_final_kib=[1-9][0-9]* rss_growth_max_kib=[0-9]+ rss_growth_limit_kib=131072 threads_baseline=[1-9][0-9]* threads_max=[1-9][0-9]* threads_final=[1-9][0-9]* thread_growth_max=[0-9]+ thread_growth_limit=8 handles=unobserved handle_bound=open handle_reason=release-apk-nonroot-procfs-denied observer_survival=process-service-peer$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_resource_bounds[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_PEER_RESOURCE_BOUND=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer aggregate resource bound is absent, malformed, or duplicated'; }
fi
mapfile -t runtime_receipts < <(grep -E \
    '^ANDROID_EMULATOR_APP=pass emulator=37\.1\.11 api=34 abi=x86_64 package=com\.carriez\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=[0-9a-f]{64} signing=test-only acceleration=kvm-nested gpu=swiftshader framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#runtime_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android app runtime receipt is absent or duplicated'; }
case "${runtime_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android app runtime reported a different APK digest' ;;
esac
mapfile -t recents_driver_stage_receipts < <(grep -E \
    "^ANDROID_RECENTS_GESTURE_DRIVER=pass sha256=$RECENTS_DRIVER_SHA256 framework=android14-ui-automation-direct open=ui-automation-app-switch-key-display-0 events=12 steps=10 step_ms=16 wait_for_animations=false runtime_uiautomator_sha256=[0-9a-f]{64} device_path=/data/local/tmp/rustdesk-recents-dismiss\.jar$" \
    "$RUNTIME_LOG" || true)
[ "${#recents_driver_stage_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_RECENTS_GESTURE_DRIVER=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android Recents gesture-driver stage receipt is absent, malformed, or duplicated'; }
[[ "${recents_driver_stage_receipts[0]}" =~ \
    runtime_uiautomator_sha256=([0-9a-f]{64})\ device_path= ]] \
    || die 'Android Recents gesture-driver runtime UiAutomator digest is malformed'
RECENTS_RUNTIME_UIAUTOMATOR_SHA256=${BASH_REMATCH[1]}
case "$RUNTIME_SCENARIO" in
    recents)
        readonly expected_recents_cycles=10
        readonly recents_cycle_pattern='([1-9]|10)'
        ;;
    peer-lifecycle)
        readonly expected_recents_cycles=6
        readonly recents_cycle_pattern='[1-6]'
        ;;
    controlled-cm)
        readonly expected_recents_cycles=1
        readonly recents_cycle_pattern=1
        ;;
esac
mapfile -t recents_open_action_receipts < <(grep -E \
    "^ANDROID_RECENTS_OPEN_ACTION=injected cycle=$recents_cycle_pattern task_id=[1-9][0-9]* mechanism=android14-ui-automation-app-switch-key keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$RECENTS_DRIVER_SHA256$" \
    "$RUNTIME_LOG" || true)
[ "${#recents_open_action_receipts[@]}" -eq "$expected_recents_cycles" ] \
    && [ "$(grep -c '^ANDROID_RECENTS_OPEN_ACTION=' "$RUNTIME_LOG")" -eq \
         "$expected_recents_cycles" ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android Recents-open action receipts are absent, malformed, or duplicated'; }
for recents_open_action_receipt in "${recents_open_action_receipts[@]}"; do
    [[ "$recents_open_action_receipt" =~ \
        driver_elapsed_ms=([0-9]+)\ driver_sha256= ]] \
        || die 'Android Recents-open driver elapsed time is malformed'
    recents_open_elapsed_ms=${BASH_REMATCH[1]}
    [ "$recents_open_elapsed_ms" -le 5000 ] \
        || die 'Android Recents-open driver elapsed time is outside its bound'
done
mapfile -t recents_dismiss_action_receipts < <(grep -E \
    "^ANDROID_RECENTS_DISMISS_ACTION=injected cycle=$recents_cycle_pattern task_id=[1-9][0-9]* bounds=[0-9]+,[0-9]+,[0-9]+,[0-9]+ start=[0-9]+,[0-9]+ end=[0-9]+,0 framework=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$RECENTS_DRIVER_SHA256$" \
    "$RUNTIME_LOG" || true)
[ "${#recents_dismiss_action_receipts[@]}" -eq "$expected_recents_cycles" ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android Recents-dismiss action receipts are absent, malformed, or duplicated'; }
[ "$(grep -c '^ANDROID_RECENTS_DISMISS_ACTION=' "$RUNTIME_LOG")" -eq \
  "${#recents_dismiss_action_receipts[@]}" ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android Recents-dismiss action receipt cardinality differs'; }
recents_action_geometry_pattern='bounds=([0-9]+),([0-9]+),([0-9]+),([0-9]+) start=([0-9]+),([0-9]+) end=([0-9]+),0 '
for recents_action_receipt in "${recents_dismiss_action_receipts[@]}"; do
    [[ "$recents_action_receipt" =~ $recents_action_geometry_pattern ]] \
        || die 'Android Recents-dismiss action geometry is malformed'
    recents_left=${BASH_REMATCH[1]}
    recents_top=${BASH_REMATCH[2]}
    recents_right=${BASH_REMATCH[3]}
    recents_bottom=${BASH_REMATCH[4]}
    recents_start_x=${BASH_REMATCH[5]}
    recents_start_y=${BASH_REMATCH[6]}
    recents_end_x=${BASH_REMATCH[7]}
    [ "$recents_right" -gt "$recents_left" ] \
        && [ "$recents_bottom" -gt "$recents_top" ] \
        && [ "$recents_start_x" -eq "$(((recents_left + recents_right) / 2))" ] \
        && [ "$recents_start_y" -eq "$(((recents_top + recents_bottom) / 2))" ] \
        && [ "$recents_end_x" -eq "$recents_start_x" ] \
        || die 'Android Recents-dismiss action did not use the exact visible-task center'
    [[ "$recents_action_receipt" =~ \
        driver_elapsed_ms=([0-9]+)\ driver_sha256= ]] \
        || die 'Android Recents-dismiss driver elapsed time is malformed'
    recents_driver_elapsed_ms=${BASH_REMATCH[1]}
    [ "$recents_driver_elapsed_ms" -ge 160 ] \
        && [ "$recents_driver_elapsed_ms" -le 5000 ] \
        || die 'Android Recents-dismiss driver elapsed time is outside its bound'
done
mapfile -t recents_dismiss_outcome_receipts < <(grep -E \
    "^ANDROID_RECENTS_DISMISS_OUTCOME=pass cycle=$recents_cycle_pattern task_id=[1-9][0-9]* actions=1$" \
    "$RUNTIME_LOG" || true)
[ "${#recents_dismiss_outcome_receipts[@]}" -eq "$expected_recents_cycles" ] \
    && [ "$(grep -c '^ANDROID_RECENTS_DISMISS_OUTCOME=' "$RUNTIME_LOG")" -eq \
         "$expected_recents_cycles" ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android Recents-dismiss outcome receipts are absent, malformed, or duplicated'; }
recents_task_ids=
for lifecycle_cycle in $(seq 1 "$expected_recents_cycles"); do
    mapfile -t cycle_outcomes < <(grep -E \
        "^ANDROID_RECENTS_DISMISS_OUTCOME=pass cycle=$lifecycle_cycle task_id=[1-9][0-9]* actions=1$" \
        "$RUNTIME_LOG" || true)
    [ "${#cycle_outcomes[@]}" -eq 1 ] \
        || die "Android Recents-dismiss cycle $lifecycle_cycle outcome cardinality differs"
    [[ "${cycle_outcomes[0]}" =~ task_id=([1-9][0-9]*)\ actions=1$ ]] \
        || die "Android Recents-dismiss cycle $lifecycle_cycle outcome differs"
    cycle_task_id=${BASH_REMATCH[1]}
    [ "$(grep -Ec \
        "^ANDROID_RECENTS_OPEN_ACTION=injected cycle=$lifecycle_cycle task_id=$cycle_task_id mechanism=android14-ui-automation-app-switch-key keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$RECENTS_DRIVER_SHA256$" \
        "$RUNTIME_LOG")" -eq 1 ] \
        || die "Android Recents-dismiss cycle $lifecycle_cycle open/outcome binding differs"
    [ "$(grep -Ec \
        "^ANDROID_RECENTS_DISMISS_ACTION=injected cycle=$lifecycle_cycle task_id=$cycle_task_id .* framework=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$RECENTS_DRIVER_SHA256$" \
        "$RUNTIME_LOG")" -eq 1 ] \
        || die "Android Recents-dismiss cycle $lifecycle_cycle action/outcome binding differs"
    case " $recents_task_ids " in
        *" $cycle_task_id "*)
            die "Android Recents-dismiss cycle $lifecycle_cycle reused task $cycle_task_id"
            ;;
    esac
    recents_task_ids="${recents_task_ids:+$recents_task_ids }$cycle_task_id"
done
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ] \
   || [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
mapfile -t controlled_cm_receipts < <(grep -Fx \
    'ANDROID_CONTROLLED_CM_FILE=pass initiator=linux-probe responder=android-mainservice auth=cpace login=filetransfer cm=admitted directory=reply transport=adb-forward-loopback forward_cleanup=removed password_transport=stdin' \
    "$RUNTIME_LOG" || true)
[ "${#controlled_cm_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_CONTROLLED_CM_FILE=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android controlled-side CM transaction receipt is absent or malformed'; }
fi
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
mapfile -t lifecycle_receipts < <(grep -E \
    '^ANDROID_EMULATOR_LIFECYCLE=pass task_removals=6 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=absent immersive_cling=(absent|dismissed-1) apk_sha256=[0-9a-f]{64} vm_network=none container_network=none cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#lifecycle_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android lifecycle runtime receipt is absent or duplicated'; }
case "${lifecycle_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android lifecycle runtime reported a different APK digest' ;;
esac
mapfile -t initial_credential_receipts < <(grep -E \
    '^ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=pass reason=missing-credential observer=(exact|android-accessibility-prefix-240) observed_network_attempts=0 pre_session_failure_delta=0 key_failure_delta=0 keyed_session_delta=0 established=0 prompt_ms=[0-9]+ prompt_limit_ms=240000$' \
    "$RUNTIME_LOG" || true)
[ "${#initial_credential_receipts[@]}" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android initial credential prompt receipt is absent or duplicated'; }
[ "$(grep -c '^ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android initial credential prompt receipt is malformed or duplicated'; }
mapfile -t peer_receipts < <(grep -E \
    '^ANDROID_EMULATOR_PEER_LIFECYCLE=pass auth=cpace server=production address=127\.0\.0\.1:22118 transport=adb-reverse-loopback service=foreground-preserved process=same-across-task-removal task_removals=6 old_sessions=closed replacements=6 warm_reconnects=6 warm_owner=preserved warm_recovery_max_ms=[0-9]+ initial_credential=missing-credential initial_credential_prompt_observer=(exact|android-accessibility-prefix-240) initial_credential_prompt_ms=[0-9]+ initial_credential_prompt_limit_ms=240000 initial_network_attempts=0 wrong_credential=peer-confirmation-unavailable-prompt wrong_attempts=1 auto_retry=absent credential_prompt_observer=(exact|android-accessibility-prefix-240) credential_prompt_ms=[0-9]+ credential_prompt_limit_ms=240000 auto_retry_observation_ms=140000 correct_credential_connection_ms=[0-9]+ credential_connection_limit_ms=240000 cached_connection_max_ms=[0-9]+ cached_connection_limit_ms=30000 initial_recovery_ms=[0-9]+ background_cycles=3 background_seconds=2,6,120 background_recovery_max_ms=[0-9]+ task_recovery_max_ms=[0-9]+ recovery_limit_ms=8000 freshness_max_ms=[0-9]+ freshness_limit_ms=2000 capture_max_ms=[0-9]+ capture_limit_ms=500 distinct_frames=(1[2-9]|[2-9][0-9]|[1-9][0-9]{2,}) resource_samples=13 resource_bound=partial-rss-threads handle_bound=open force_stop=baseline apk_sha256=[0-9a-f]{64} vm_network=none container_network=none server_listener=127\.0\.0\.1:21118 reverse_cleanup=removed x11=unix-only cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_receipts[@]}" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android real-peer lifecycle receipt is absent or duplicated'; }
case "${peer_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android real-peer lifecycle reported a different APK digest' ;;
esac
elif [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
mapfile -t controlled_restart_receipts < <(grep -Fx \
    'ANDROID_CONTROLLED_CM_RESTART=pass auth=cpace login=filetransfer cm=admitted directory=reply service=foreground process=same forward_cleanup=removed force_stop=absent' \
    "$RUNTIME_LOG" || true)
[ "${#controlled_restart_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_CONTROLLED_CM_RESTART=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android controlled-CM restart receipt is absent or duplicated'; }
mapfile -t controlled_stop_receipts < <(grep -Fx \
    'ANDROID_CONTROLLED_CM_STOP=pass command=production-ui-stop service=absent process=same live_keyed_cm=closed fresh_keyed_cm=refused forward_cleanup=removed force_stop=absent restart=keyed-cm-file-reply' \
    "$RUNTIME_LOG" || true)
[ "${#controlled_stop_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_CONTROLLED_CM_STOP=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android controlled-CM Stop receipt is absent or duplicated'; }
mapfile -t controlled_lifecycle_receipts < <(grep -Fx \
    "ANDROID_EMULATOR_CONTROLLED_CM=pass task_removals=1 service=foreground-across-task-relaunch-then-stopped process=same positive=filetransfer-dir-reply stopped=live-keyed-cm-closed-and-fresh-refused restart=filetransfer-dir-reply framework_anr=absent apk_sha256=$APK_SHA256 vm_network=none container_network=none cleanup=joined" \
    "$RUNTIME_LOG" || true)
[ "${#controlled_lifecycle_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_EMULATOR_CONTROLLED_CM=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android controlled-CM lifecycle receipt is absent or duplicated'; }
else
mapfile -t focused_recents_receipts < <(grep -E \
    "^ANDROID_EMULATOR_RECENTS=pass task_removals=10 actions=10 open_actions=10 task_ids=distinct open=ui-automation-app-switch-key-display-0 driver=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false runtime_uiautomator_sha256=$RECENTS_RUNTIME_UIAUTOMATOR_SHA256 driver_sha256=$RECENTS_DRIVER_SHA256 framework_anr=absent service=never-started relaunch=resumed apk_sha256=$APK_SHA256 vm_network=none container_network=none cleanup=joined$" \
    "$RUNTIME_LOG" || true)
[ "${#focused_recents_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_EMULATOR_RECENTS=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'focused Android Recents receipt is absent, malformed, or duplicated'; }
fi
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$RUNTIME_CONTAINER")" = exited:0 ] \
    || die 'Android runtime container did not exit cleanly'
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    vm_docker rm "$OBSERVER_CONTAINER" >/dev/null
    OBSERVER_CONTAINER=
fi
vm_docker rm "$RUNTIME_CONTAINER" >/dev/null
RUNTIME_CONTAINER=
[ -z "$(vm_docker ps -aq)" ] \
    || die 'Android emulator runtime check left a container'

if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$FRAME_SOURCE")" = "$FRAME_SOURCE_ID" ] \
        && [ "$(sha256sum "$FRAME_SOURCE" | awk '{ print $1 }')" = "$FRAME_SOURCE_SHA256" ] \
        && [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$FRAME_SOURCE_C")" = "$FRAME_SOURCE_C_ID" ] \
        && [ "$(sha256sum "$FRAME_SOURCE_C" | awk '{ print $1 }')" = "$FRAME_SOURCE_C_SHA256" ] \
        || die 'independent X11 fixture source or executable changed during replay'
    [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$SERVER_MACHINE_ID")" = \
      "$SERVER_MACHINE_ID_ID" ] \
        && [ "$(<"$SERVER_MACHINE_ID")" = "$SERVER_MACHINE_ID_VALUE" ] \
        || die 'private Android peer machine identity changed during execution'
fi
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ] \
   || [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
    [ "$PEER_EXECUTION_INVENTORY" = "$(find "$SERVER_TARGET" -xdev -mindepth 0 -printf '%p\0' \
        | LC_ALL=C sort -z | xargs -0 stat -c '%d:%i:%u:%g:%a:%h:%s')" ] \
        || die 'admitted Android peer execution layout changed during the read-only run'
fi
[ "$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$APK")" = "$APK_ID" ] \
    && [ "$(sha256sum "$APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
    || die 'runtime-test APK identity or bytes changed during execution'
verify_android_sdk_root
verify_gradle_root
verify_sha256 "$EMULATOR_ZIP" "$SHA256_ANDROID_EMULATOR_LINUX_X64"
verify_sha256 "$SYSTEM_IMAGE_ZIP" "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64"
verify_sha256 "$ADB" "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1"
[ "$(stat -c '%u:%g:%a:%h' -- "$RECENTS_DRIVER_SOURCE")" = 1000:1000:400:1 ] \
    && [ "$(sha256sum "$RECENTS_DRIVER_SOURCE" | awk '{ print $1 }')" = \
         "$RECENTS_DRIVER_SOURCE_SHA256" ] \
    || die 'Recents gesture-driver source changed during execution'
[ "$(sha256sum "$ANDROID_PLATFORM_JAR" | awk '{ print $1 }')" = \
  "$ANDROID_PLATFORM_JAR_SHA256" ] \
    && [ "$(sha256sum "$ANDROID_D8" | awk '{ print $1 }')" = \
         "$ANDROID_D8_SHA256" ] \
    || die 'a Recents gesture-driver SDK input changed during execution'
[ "$(stat -c '%u:%g:%a:%h' -- "$RECENTS_DRIVER_JAR")" = 1000:1000:400:1 ] \
    && [ "$(sha256sum "$RECENTS_DRIVER_JAR" | awk '{ print $1 }')" = \
         "$RECENTS_DRIVER_SHA256" ] \
    || die 'Recents gesture-driver artifact changed during execution'
verify_image android-builder "$ANDROID_BUILDER_CONFIG_ID"
verify_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"
printf '%s\n' "${apk_receipts[0]}" "${recents_driver_build_receipts[0]}" \
    "${recents_driver_stage_receipts[0]}" \
    "${renderer_receipts[0]}" "${runtime_receipts[0]}" \
    "${recents_open_action_receipts[@]}" \
    "${recents_dismiss_action_receipts[@]}" \
    "${recents_dismiss_outcome_receipts[@]}"
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    printf '%s\n' "${endpoint_receipts[0]}" "${frame_parser_receipts[0]}" \
        "${frame_observer_self_test_receipts[0]}" \
        "${frame_observer_build_receipts[0]}" \
        "${frame_observer_receipts[0]}" \
        "${peer_frame_baselines[@]}" "${peer_presentation_ui_receipts[@]}" \
        "${peer_warm_hold_receipts[0]}" "${peer_task_park_receipts[0]}" \
        "${peer_presentation_stage_receipts[@]}" \
        "${peer_resource_samples[@]}" "${peer_resource_bounds[0]}" \
        "${lifecycle_receipts[0]}" "${initial_credential_receipts[0]}" \
        "${peer_receipts[0]}"
    runtime_peer=production-loopback-cpace-changing-display
elif [ "$RUNTIME_SCENARIO" = controlled-cm ]; then
    printf '%s\n' "${controlled_cm_receipts[0]}" \
        "${controlled_stop_receipts[0]}" "${controlled_restart_receipts[0]}" \
        "${controlled_lifecycle_receipts[0]}"
    runtime_peer=production-loopback-cpace-controlled-cm
else
    printf '%s\n' "${focused_recents_receipts[0]}"
    runtime_peer=absent
fi
printf 'ANDROID_EMULATOR_RUNTIME_CHECK=pass scenario=%s artifact_commit=%s apk_sha256=%s signing=test-only package=com.carriez.flutter_hbb abi=x86_64 source=commit-bound-retained-artifact builder=%s runtime=%s peer=%s vm_network=none container_network=none inputs=readonly cleanup=joined\n' \
    "$RUNTIME_SCENARIO" \
    "$ARTIFACT_SOURCE_COMMIT" "$APK_SHA256" \
    "$ANDROID_BUILDER_CONFIG_ID" "$DEV_CHECK_IMAGE_CONFIG_ID" "$runtime_peer"

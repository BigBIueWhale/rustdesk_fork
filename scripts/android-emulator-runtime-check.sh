#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

die() {
    printf 'Android emulator runtime check: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 3 ] \
    || die 'usage: android-emulator-runtime-check.sh APK APK_SHA256 ARTIFACT_SOURCE_COMMIT'
readonly APK=$1
readonly APK_SHA256=$2
readonly ARTIFACT_SOURCE_COMMIT=$3
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
readonly DOCKER_SOCKET=$VM_ROOT/docker.sock
readonly DOCKER_CONFIG_ROOT=$VM_ROOT/docker-config
readonly DOCKER_CLIENT=/usr/bin/docker
readonly CANDIDATE_ROOT=$REPO_ROOT/online/candidates/android-emulator
readonly EMULATOR_ZIP=$CANDIDATE_ROOT/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
readonly SYSTEM_IMAGE_ZIP=$CANDIDATE_ROOT/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
readonly ADB=$ONLINE_DIR/android-sdk/platform-tools/adb

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
RUNTIME_CONTAINER=
cleanup() {
    local status=$? cleanup_status=0 container
    trap - EXIT HUP INT TERM
    for container in "$RUNTIME_CONTAINER" "$VERIFY_CONTAINER"; do
        [ -n "$container" ] || continue
        vm_docker rm -f "$container" >/dev/null 2>&1 || cleanup_status=1
    done
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
verify_sha256 "$EMULATOR_ZIP" "$SHA256_ANDROID_EMULATOR_LINUX_X64"
verify_sha256 "$SYSTEM_IMAGE_ZIP" "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64"
verify_sha256 "$ADB" "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1"
verify_image android-builder "$ANDROID_BUILDER_CONFIG_ID"
verify_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"

readonly APK_ID="$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$APK")"
WORKSPACE="$(mktemp -d /var/tmp/rustdesk-android-emulator-runtime.XXXXXXXXXX)" \
    || die 'cannot create the private runtime-check workspace'
WORKSPACE_ID="$(stat -c '%d:%i' -- "$WORKSPACE")"
[ "$(stat -c '%u:%g:%a' -- "$WORKSPACE")" = 1000:1000:700 ] \
    || die 'private runtime-check workspace metadata differs'
readonly VERIFY_LOG=$WORKSPACE/verify.log
readonly RUNTIME_LOG=$WORKSPACE/runtime.log

VERIFY_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-runtime-verify \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=128 --memory=4g --memory-swap=4g --cpus=2 \
    --ulimit nofile=1024:1024 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g \
    --mount "type=bind,source=$APK,target=/verify/app.apk,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
    "$ANDROID_BUILDER_CONFIG_ID" \
    /bin/bash --noprofile --norc -euo pipefail -c '
        python3 -I -S /source/scripts/verify-android-emulator-apk.py \
            --apk /verify/app.apk \
            --apksigner /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/apksigner \
            --aapt2 /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/aapt2 \
            --stable-cert-sha256 '"$ANDROID_SIGNING_CERT_SHA256"'
        python3 -I -S /source/scripts/verify-android-apk-manifest.py \
            --apk /verify/app.apk \
            --aapt2 /online/android-sdk/build-tools/'"$ANDROID_BUILD_TOOLS"'/aapt2
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
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$VERIFY_CONTAINER")" = exited:0 ] \
    || die 'APK verifier container did not exit cleanly'
vm_docker rm "$VERIFY_CONTAINER" >/dev/null
VERIFY_CONTAINER=

RUNTIME_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-runtime \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=768 --memory=12g --memory-swap=12g --cpus=4 \
    --shm-size=1g --ulimit nofile=8192:8192 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$EMULATOR_ZIP,target=/inputs/emulator.zip,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SYSTEM_IMAGE_ZIP,target=/inputs/system-image.zip,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ADB,target=/inputs/adb,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$APK,target=/inputs/app.apk,readonly,bind-recursive=disabled" \
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=10g,mode=700,uid=1000,gid=1000 \
    --workdir /source \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    /bin/bash --noprofile --norc \
        /source/scripts/smoke-android-emulator-boot.sh \
        /inputs/emulator.zip /inputs/system-image.zip /inputs/adb \
        /tmp/android-emulator-app /inputs/app.apk lifecycle)"
[[ "$RUNTIME_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Android runtime container ID is malformed'
runtime_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$RUNTIME_CONTAINER")"
[ "$runtime_authority" = \
  'none|true|1000:1000|12884901888|12884901888|4000000000|768|1073741824|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
    || die "Android runtime container authority differs: $runtime_authority"
runtime_namespace="$(vm_docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' \
    "$RUNTIME_CONTAINER")"
[ "$runtime_namespace" = 'false||private||private' ] \
    || die "Android runtime container namespace authority differs: $runtime_namespace"
runtime_status=0
vm_docker start --attach "$RUNTIME_CONTAINER" >"$RUNTIME_LOG" 2>&1 || runtime_status=$?
[ "$runtime_status" -eq 0 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die "Android app runtime exited with status $runtime_status"; }
[ "$(stat -c '%s' -- "$RUNTIME_LOG")" -le 1048576 ] \
    || die 'Android app runtime output exceeds its bound'
mapfile -t runtime_receipts < <(grep -E \
    '^ANDROID_EMULATOR_APP=pass emulator=37\.1\.11 api=34 abi=x86_64 package=com\.carriez\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=[0-9a-f]{64} signing=test-only acceleration=software framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#runtime_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android app runtime receipt is absent or duplicated'; }
case "${runtime_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android app runtime reported a different APK digest' ;;
esac
mapfile -t lifecycle_receipts < <(grep -E \
    '^ANDROID_EMULATOR_LIFECYCLE=pass task_removals=2 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped system_ui_anr=(absent|waited-[1-3]) apk_sha256=[0-9a-f]{64} vm_network=none container_network=none cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#lifecycle_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android lifecycle runtime receipt is absent or duplicated'; }
case "${lifecycle_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android lifecycle runtime reported a different APK digest' ;;
esac
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$RUNTIME_CONTAINER")" = exited:0 ] \
    || die 'Android runtime container did not exit cleanly'
vm_docker rm "$RUNTIME_CONTAINER" >/dev/null
RUNTIME_CONTAINER=
[ -z "$(vm_docker ps -aq)" ] \
    || die 'Android emulator runtime check left a container'

[ "$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$APK")" = "$APK_ID" ] \
    && [ "$(sha256sum "$APK" | awk '{ print $1 }')" = "$APK_SHA256" ] \
    || die 'runtime-test APK identity or bytes changed during execution'
verify_android_sdk_root
verify_sha256 "$EMULATOR_ZIP" "$SHA256_ANDROID_EMULATOR_LINUX_X64"
verify_sha256 "$SYSTEM_IMAGE_ZIP" "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64"
verify_sha256 "$ADB" "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1"
verify_image android-builder "$ANDROID_BUILDER_CONFIG_ID"
verify_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"
printf '%s\n' "${apk_receipts[0]}" "${runtime_receipts[0]}" \
    "${lifecycle_receipts[0]}"
printf 'ANDROID_EMULATOR_RUNTIME_CHECK=pass artifact_commit=%s apk_sha256=%s signing=test-only package=com.carriez.flutter_hbb abi=x86_64 source=commit-bound-retained-artifact builder=%s runtime=%s vm_network=none container_network=none inputs=readonly cleanup=joined\n' \
    "$ARTIFACT_SOURCE_COMMIT" "$APK_SHA256" \
    "$ANDROID_BUILDER_CONFIG_ID" "$DEV_CHECK_IMAGE_CONFIG_ID"

#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

die() {
    printf 'Android emulator runtime check: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 3 ] || [ "$#" -eq 4 ] \
    || die 'usage: android-emulator-runtime-check.sh APK APK_SHA256 ARTIFACT_SOURCE_COMMIT [recents|peer-lifecycle]'
readonly APK=$1
readonly APK_SHA256=$2
readonly ARTIFACT_SOURCE_COMMIT=$3
readonly RUNTIME_SCENARIO=${4:-peer-lifecycle}
case "$RUNTIME_SCENARIO" in
    recents|peer-lifecycle) ;;
    *) die 'the Android runtime scenario differs from recents or peer-lifecycle' ;;
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
BUILD_CONTAINER=
XVFB_CONTAINER=
RUNTIME_CONTAINER=
OBSERVER_CONTAINER=
cleanup() {
    local status=$? cleanup_status=0 container
    trap - EXIT HUP INT TERM
    for container in "$OBSERVER_CONTAINER" "$RUNTIME_CONTAINER" "$XVFB_CONTAINER" \
        "$BUILD_CONTAINER" "$VERIFY_CONTAINER"; do
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
    [ -d "$ONLINE_DIR/cargo-vendor" ] && [ ! -L "$ONLINE_DIR/cargo-vendor" ] \
        || die 'sealed Cargo vendor input is absent or ambiguous'
    [ -d "$ONLINE_DIR/xvfb-debs" ] && [ ! -L "$ONLINE_DIR/xvfb-debs" ] \
        || die 'sealed Xvfb package input is absent or ambiguous'
    verify_sha256 "$ONLINE_DIR/cargo-vendor-config.toml" "$SHA256_CARGO_VENDOR_CONFIG"
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
readonly BUILD_LOG=$WORKSPACE/build.log
readonly XVFB_LOG=$WORKSPACE/xvfb.log
readonly RUNTIME_LOG=$WORKSPACE/runtime.log
readonly OBSERVER_LOG=$WORKSPACE/observer.log
readonly RECENTS_DRIVER_ROOT=$WORKSPACE/recents-driver
readonly RECENTS_DRIVER_JAR=$RECENTS_DRIVER_ROOT/recents-dismiss.jar
readonly OBSERVER_ROOT=$WORKSPACE/observer
readonly SERVER_TARGET=$WORKSPACE/server-target
readonly XVFB_DEBS=$WORKSPACE/xvfb-debs
readonly XVFB_ROOT=$WORKSPACE/xvfb-root
readonly SERVER_MACHINE_ID=$WORKSPACE/server.machine-id
readonly SERVER_MACHINE_ID_VALUE=727573746465736b2d73657276657231
install -d -m 0700 -- "$RECENTS_DRIVER_ROOT"
SERVER_MACHINE_ID_ID=
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    install -d -m 0700 -- "$OBSERVER_ROOT" "$SERVER_TARGET" "$XVFB_DEBS" \
        "$XVFB_ROOT"
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

if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
BUILD_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-peer-build \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=1024 --memory=12g --memory-swap=12g --cpus=4 \
    --ulimit nofile=8192:8192 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g \
    --env HOME=/tmp/android-peer-build \
    --env CARGO_HOME=/tmp/smoke-cargo-home \
    --env CARGO_TARGET_DIR=/smoke-target \
    --env CARGO_INCREMENTAL=0 \
    --env CARGO_NET_OFFLINE=true \
    --env CARGO_NET_RETRY=0 \
    --env "RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
    --env "SMOKE_EXPECTED_RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
    --env "SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256=$SHA256_CARGO_VENDOR_CLOSURE_V1" \
    --env "SMOKE_EXPECTED_VENDOR_CONFIG_SHA256=$SHA256_CARGO_VENDOR_CONFIG" \
    --mount "type=bind,source=$REPO_ROOT,target=/work,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SERVER_TARGET,target=/smoke-target,bind-recursive=disabled" \
    --workdir /work \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    /bin/bash --noprofile --norc \
        /work/scripts/smoke-server-stage.sh android-peer-build)"
[[ "$BUILD_CONTAINER" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Android peer build container ID is malformed'
build_authority="$(vm_docker inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' \
    "$BUILD_CONTAINER")"
[ "$build_authority" = \
  'none|true|1000:1000|12884901888|12884901888|4000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
    || die "Android peer build authority differs: $build_authority"
build_status=0
vm_docker start --attach "$BUILD_CONTAINER" >"$BUILD_LOG" 2>&1 || build_status=$?
[ "$build_status" -eq 0 ] \
    || { tail -n 240 "$BUILD_LOG" >&2; die "Android peer build exited with status $build_status"; }
[ "$(stat -c '%s' -- "$BUILD_LOG")" -le 4194304 ] \
    || die 'Android peer build output exceeds its bound'
[ "$(grep -c '^ANDROID_PEER_BUILD=pass server=production auth=cpace source=x11-changing files=7 network=none$' \
    "$BUILD_LOG" || true)" -eq 1 ] \
    || { tail -n 240 "$BUILD_LOG" >&2; die 'Android peer build receipt is absent or duplicated'; }
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$BUILD_CONTAINER")" = exited:0 ] \
    || die 'Android peer build container did not exit cleanly'
vm_docker rm "$BUILD_CONTAINER" >/dev/null
BUILD_CONTAINER=

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
    --workdir /work \
    "$DEV_CHECK_IMAGE_CONFIG_ID" \
    /bin/bash --noprofile --norc /work/scripts/smoke-xvfb-prepare.sh)"
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
fi

runtime_mounts=(
    --mount "type=bind,source=$REPO_ROOT,target=/source,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$EMULATOR_ZIP,target=/inputs/emulator.zip,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$SYSTEM_IMAGE_ZIP,target=/inputs/system-image.zip,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$ADB,target=/inputs/adb,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$APK,target=/inputs/app.apk,readonly,bind-recursive=disabled"
    --mount "type=bind,source=$RECENTS_DRIVER_JAR,target=/inputs/recents-dismiss.jar,readonly,bind-recursive=disabled"
)
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    runtime_mounts+=(
        --mount "type=bind,source=$SERVER_TARGET,target=/smoke-target,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$XVFB_ROOT,target=/xvfb-root,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$XVFB_ROOT/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$SERVER_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$OBSERVER_ROOT,target=/observer,bind-recursive=disabled"
    )
fi
readonly -a runtime_mounts

RUNTIME_CONTAINER="$(vm_docker create \
    --name rustdesk-android-emulator-runtime \
    --pull=never --network=none --read-only \
    --user 1000:1000 \
    --pids-limit=1024 --memory=12g --memory-swap=12g --cpus=4 \
    --shm-size=1g --ulimit nofile=8192:8192 --ulimit core=0:0 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --security-opt=apparmor=docker-default \
    "${runtime_mounts[@]}" \
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
[ "$runtime_authority" = \
  'none|true|1000:1000|12884901888|12884901888|4000000000|1024|1073741824|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
    || die "Android runtime container authority differs: $runtime_authority"
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
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    runtime_machine_id_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/etc/machine-id" { print }')"
    [ "$runtime_machine_id_mounts" = \
      "bind	$SERVER_MACHINE_ID	/etc/machine-id	false" ] \
        || die 'Android peer private machine-ID mount authority differs'
    runtime_observer_mounts="$(vm_docker inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$RUNTIME_CONTAINER" | awk -F '\t' '$3 == "/observer" { print }')"
    [ "$runtime_observer_mounts" = \
      "bind	$OBSERVER_ROOT	/observer	true" ] \
        || die 'Android runtime frame-observer exchange mount authority differs'
fi

vm_docker start "$RUNTIME_CONTAINER" >/dev/null \
    || die 'cannot start the Android runtime container'

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
for _ in $(seq 1 9000); do
    if [ -f "$OBSERVER_ROOT/ready" ] && [ ! -L "$OBSERVER_ROOT/ready" ]; then
        [ "$(stat -c '%u:%g:%a:%h' -- "$OBSERVER_ROOT/ready")" = \
          1000:1000:600:1 ] \
            || die 'Android emulator frame-observer ready metadata differs'
        observer_ready=1
        break
    fi
    observer_state="$(vm_docker inspect --format '{{.State.Status}}' \
        "$OBSERVER_CONTAINER")" \
        || die 'cannot inspect the Android emulator frame-observer startup state'
    case "$observer_state" in
        exited|dead)
            observer_startup_failed=1
            break
            ;;
        created|running|restarting|removing|paused) ;;
        *) die "Android emulator frame-observer startup state is malformed: $observer_state" ;;
    esac
    runtime_state="$(vm_docker inspect --format '{{.State.Status}}' \
        "$RUNTIME_CONTAINER")" \
        || die 'cannot inspect the Android runtime startup state'
    case "$runtime_state" in
        exited|dead) break ;;
        created|running|restarting|removing|paused) ;;
        *) die "Android runtime startup state is malformed: $runtime_state" ;;
    esac
    sleep 0.1
done
if [ "$observer_startup_failed" -eq 1 ]; then
    runtime_startup_terminal=0
    runtime_state=unknown
    for _ in $(seq 1 1200); do
        if ! runtime_state="$(vm_docker inspect --format '{{.State.Status}}' \
            "$RUNTIME_CONTAINER")"; then
            runtime_state=inspect-failed
            break
        fi
        case "$runtime_state" in
            exited|dead)
                runtime_startup_terminal=1
                break
                ;;
            created|running|restarting|removing|paused) ;;
            *)
                runtime_state="malformed:$runtime_state"
                break
                ;;
        esac
        sleep 0.1
    done
    vm_docker logs --tail 320 "$RUNTIME_CONTAINER" >"$RUNTIME_LOG" 2>&1 || true
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
    tail -n 320 "$RUNTIME_LOG" >&2
    printf '%s\n' '--- Android frame-observer log (last 320 lines) ---' >&2
    tail -n 320 "$OBSERVER_LOG" >&2
    die "Android emulator frame observer exited before its first external frame (runtime startup state: $runtime_state)"
fi
if [ "$observer_ready" -eq 0 ] \
   && [ "$(vm_docker inspect --format '{{.State.Status}}' \
        "$RUNTIME_CONTAINER")" = running ]; then
    vm_docker logs "$OBSERVER_CONTAINER" >"$OBSERVER_LOG" 2>&1 || true
    tail -n 240 "$OBSERVER_LOG" >&2
    die 'Android emulator frame observer produced no external frame within 15 minutes'
fi

if ! runtime_status="$(vm_docker wait "$RUNTIME_CONTAINER")"; then
    die 'cannot wait for the Android runtime container'
fi
[[ "$runtime_status" =~ ^[0-9]+$ ]] \
    || die "Android runtime container returned a malformed status: $runtime_status"
vm_docker logs "$RUNTIME_CONTAINER" >"$RUNTIME_LOG" 2>&1 \
    || die 'cannot collect the Android runtime log'

observer_joined=0
for _ in $(seq 1 1200); do
    observer_state="$(vm_docker inspect --format '{{.State.Status}}' \
        "$OBSERVER_CONTAINER")" \
        || die 'cannot inspect the Android emulator frame-observer state'
    case "$observer_state" in
        exited|dead)
            observer_joined=1
            break
            ;;
        created|running|restarting|removing|paused) ;;
        *) die "Android emulator frame-observer state is malformed: $observer_state" ;;
    esac
    sleep 0.1
done
vm_docker logs "$OBSERVER_CONTAINER" >"$OBSERVER_LOG" 2>&1 \
    || die 'cannot collect the Android emulator frame-observer log'
[ "$observer_joined" -eq 1 ] \
    || { tail -n 240 "$OBSERVER_LOG" >&2; die 'Android emulator frame observer did not join within 120 seconds'; }
observer_status="$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' \
    "$OBSERVER_CONTAINER")"
else
    if ! runtime_status="$(vm_docker wait "$RUNTIME_CONTAINER")"; then
        die 'cannot wait for the focused Android runtime container'
    fi
    [[ "$runtime_status" =~ ^[0-9]+$ ]] \
        || die "focused Android runtime container returned a malformed status: $runtime_status"
    vm_docker logs "$RUNTIME_CONTAINER" >"$RUNTIME_LOG" 2>&1 \
        || die 'cannot collect the focused Android runtime log'
    observer_status=not-applicable
fi
if [ "$runtime_status" -ne 0 ]; then
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
        /^ANDROID_PEER_FRAMEBUFFER_PNG_BEGIN / { in_png = 1 }
        in_png { print }
        /^ANDROID_PEER_FRAMEBUFFER_PNG_END / { in_png = 0 }
    ' "$RUNTIME_LOG" >&2
    grep -E '^ANDROID_PEER_(FRAME_BASELINE |FRAME_SAMPLE |PRESENTATION_UI=)' \
        "$RUNTIME_LOG" | tail -n 140 >&2 || true
    grep -E '^ANDROID_PEER_PRESENTATION_STAGE(_DIAGNOSTIC_(BEGIN|END)|_(SERVER|NATIVE|DART)|=)' \
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
mapfile -t tombstone_fd_parser_receipts < <(grep -Fx \
    'ANDROID_TOMBSTONE_FD_PARSER_SELF_TEST=pass scenarios=10 max_input_bytes=33554432' \
    "$RUNTIME_LOG" || true)
[ "${#tombstone_fd_parser_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android tombstone descriptor-parser self-test receipt is absent or duplicated'; }
mapfile -t tombstone_fd_authority_receipts < <(grep -E \
    '^ANDROID_TOMBSTONE_FD_AUTHORITY=pass observer=debuggerd-live-tombstone target=installed-test-apk process=stable service=not-started peer_connections=0 fds=[1-9][0-9]*$' \
    "$RUNTIME_LOG" || true)
[ "${#tombstone_fd_authority_receipts[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_TOMBSTONE_FD_AUTHORITY=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android live-tombstone descriptor authority receipt is absent, malformed, or duplicated'; }
mapfile -t endpoint_receipts < <(grep -Fx \
    'ANDROID_EMULATOR_FRAME_ENDPOINT=pass connect=127.0.0.1:8554 bind=[::]:8554 namespace=loopback-only transport=grpc-stream network=container-none' \
    "$RUNTIME_LOG" || true)
[ "${#endpoint_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$RUNTIME_LOG" >&2; die 'Android emulator frame-endpoint receipt is absent or duplicated'; }
mapfile -t frame_parser_receipts < <(grep -Fx \
    'ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=pass scenarios=11' \
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
readonly peer_presentation_phase_pattern='(initial|background-resume-1-2s|background-resume-2-6s|background-resume-3-12s|task-relaunch-[1-6])'
readonly peer_presentation_phase_inventory=$'background-resume-1-2s\nbackground-resume-2-6s\nbackground-resume-3-12s\ninitial\ntask-relaunch-1\ntask-relaunch-2\ntask-relaunch-3\ntask-relaunch-4\ntask-relaunch-5\ntask-relaunch-6'
mapfile -t peer_frame_baselines < <(grep -E \
    "^ANDROID_PEER_FRAME_BASELINE phase=$peer_presentation_phase_pattern observer_age_ms=[0-9]+ source_state=([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) display_state=([0-9]+|unavailable) dimensions=(120x200|200x120) seq=[0-9]+ timestamp_us=[1-9][0-9]*$" \
    "$RUNTIME_LOG" || true)
[ "${#peer_frame_baselines[@]}" -eq 10 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer frame baselines are absent or duplicated'; }
peer_frame_baseline_phases="$(printf '%s\n' "${peer_frame_baselines[@]}" \
    | sed -nE 's/^ANDROID_PEER_FRAME_BASELINE phase=([^ ]+) .*/\1/p' \
    | LC_ALL=C sort)"
[ "$peer_frame_baseline_phases" = "$peer_presentation_phase_inventory" ] \
    || die "Android peer frame baseline phases differ: $peer_frame_baseline_phases"
mapfile -t peer_presentation_ui_receipts < <(grep -E \
    "^ANDROID_PEER_PRESENTATION_UI=pass phase=$peer_presentation_phase_pattern connecting=retired credential=retired waiting=retired$" \
    "$RUNTIME_LOG" || true)
[ "${#peer_presentation_ui_receipts[@]}" -eq 10 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer presentation UI receipts are absent or duplicated'; }
peer_presentation_ui_phases="$(printf '%s\n' "${peer_presentation_ui_receipts[@]}" \
    | sed -nE 's/^ANDROID_PEER_PRESENTATION_UI=pass phase=([^ ]+) .*/\1/p' \
    | LC_ALL=C sort)"
[ "$peer_presentation_ui_phases" = "$peer_presentation_phase_inventory" ] \
    || die "Android peer presentation UI phases differ: $peer_presentation_ui_phases"
mapfile -t peer_presentation_stage_receipts < <(grep -E \
    '^ANDROID_PEER_PRESENTATION_STAGE=pass phase=(initial|task-relaunch-[1-6]) ordinal=[1-7] server_connection=[1-9][0-9]* display=[0-9]+ server_wire_generation=[1-9][0-9]* viewer_wire_generation=[1-9][0-9]* server_wall_ms=[1-9][0-9]* server_queue_us=[0-9]+ viewer_mailbox_generation=[1-9][0-9]* viewer_wall_ms=[1-9][0-9]* receive_to_admit_us=[0-9]+ admit_to_dequeue_us=[0-9]+ decode_us=[0-9]+ dart_session=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} publication=[1-9][0-9]* dart_wall_ms=[1-9][0-9]* event_queue_us=[0-9]+ take_us=[0-9]+ checkpoint_us=[0-9]+ decode_commit_us=[0-9]+ ui_finalize_us=[0-9]+ dart_total_us=[0-9]+ image_conversions_active=[1-3] image_conversions_waiting=([0-9]|[1-5][0-9]|6[0-4]) image_conversions_peak=[1-3]$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_presentation_stage_receipts[@]}" -eq 7 ] \
    && [ "$(grep -c '^ANDROID_PEER_PRESENTATION_STAGE=' "$RUNTIME_LOG")" -eq 7 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer presentation-stage receipts are absent, malformed, or duplicated'; }
for phase_ordinal in 'initial 1' 'task-relaunch-1 2' 'task-relaunch-2 3' \
    'task-relaunch-3 4' 'task-relaunch-4 5' 'task-relaunch-5 6' \
    'task-relaunch-6 7'; do
    read -r phase ordinal <<<"$phase_ordinal"
    [ "$(printf '%s\n' "${peer_presentation_stage_receipts[@]}" \
        | grep -Ec "^ANDROID_PEER_PRESENTATION_STAGE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
        || die "Android peer presentation-stage binding differs for $phase"
done
mapfile -t peer_resource_samples < <(grep -E \
    '^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=(baseline|task-relaunch-[1-6]) ordinal=[0-6] rss_kib=[1-9][0-9]* threads=[1-9][0-9]* fds=[1-9][0-9]* rss_growth_kib=[0-9]+ thread_growth=[0-9]+ fd_growth=[0-9]+ fd_observer=debuggerd-live-tombstone observer_survival=process-service-peer$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_resource_samples[@]}" -eq 7 ] \
    && [ "$(grep -c '^ANDROID_PEER_RESOURCE_SAMPLE=' "$RUNTIME_LOG")" -eq 7 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer resource samples are absent, malformed, or duplicated'; }
for phase_ordinal in 'baseline 0' 'task-relaunch-1 1' 'task-relaunch-2 2' \
    'task-relaunch-3 3' 'task-relaunch-4 4' 'task-relaunch-5 5' \
    'task-relaunch-6 6'; do
    read -r phase ordinal <<<"$phase_ordinal"
    [ "$(printf '%s\n' "${peer_resource_samples[@]}" \
        | grep -Ec "^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
        || die "Android peer resource-sample binding differs for $phase"
done
[ "$(printf '%s\n' "${peer_resource_samples[@]}" \
    | grep -Ec '^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=baseline ordinal=0 .* rss_growth_kib=0 thread_growth=0 fd_growth=0 fd_observer=debuggerd-live-tombstone observer_survival=process-service-peer$')" -eq 1 ] \
    || die 'Android peer resource baseline has nonzero growth'
mapfile -t peer_resource_bounds < <(grep -E \
    '^ANDROID_PEER_RESOURCE_BOUND=pass samples=7 replacement_samples=6 rss_baseline_kib=[1-9][0-9]* rss_max_kib=[1-9][0-9]* rss_final_kib=[1-9][0-9]* rss_growth_max_kib=[0-9]+ rss_growth_limit_kib=131072 threads_baseline=[1-9][0-9]* threads_max=[1-9][0-9]* threads_final=[1-9][0-9]* thread_growth_max=[0-9]+ thread_growth_limit=8 fds_baseline=[1-9][0-9]* fds_max=[1-9][0-9]* fds_final=[1-9][0-9]* fd_growth_max=[0-9]+ fd_growth_limit=16 fd_observer=debuggerd-live-tombstone observer_survival=process-service-peer$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_resource_bounds[@]}" -eq 1 ] \
    && [ "$(grep -c '^ANDROID_PEER_RESOURCE_BOUND=' "$RUNTIME_LOG")" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android peer aggregate resource bound is absent, malformed, or duplicated'; }
fi
mapfile -t runtime_receipts < <(grep -E \
    '^ANDROID_EMULATOR_APP=pass emulator=37\.1\.11 api=34 abi=x86_64 package=com\.carriez\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=[0-9a-f]{64} signing=test-only acceleration=software gpu=swiftshader framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
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
if [ "$RUNTIME_SCENARIO" = recents ]; then
    readonly expected_recents_cycles=10
    readonly recents_cycle_pattern='([1-9]|10)'
else
    readonly expected_recents_cycles=6
    readonly recents_cycle_pattern='[1-6]'
fi
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
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
mapfile -t lifecycle_receipts < <(grep -E \
    '^ANDROID_EMULATOR_LIFECYCLE=pass task_removals=6 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=(absent|waited-([1-9]|1[0-2])) immersive_cling=(absent|dismissed-1) apk_sha256=[0-9a-f]{64} vm_network=none container_network=none cleanup=joined$' \
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
    '^ANDROID_EMULATOR_PEER_LIFECYCLE=pass auth=cpace server=production address=127\.0\.0\.1:22118 transport=adb-reverse-loopback service=foreground-preserved process=same-across-task-removal task_removals=6 old_sessions=closed replacements=6 initial_credential=missing-credential initial_credential_prompt_observer=(exact|android-accessibility-prefix-240) initial_credential_prompt_ms=[0-9]+ initial_credential_prompt_limit_ms=240000 initial_network_attempts=0 wrong_credential=peer-confirmation-unavailable-prompt wrong_attempts=1 auto_retry=absent credential_prompt_observer=(exact|android-accessibility-prefix-240) credential_prompt_ms=[0-9]+ credential_prompt_limit_ms=240000 auto_retry_observation_ms=140000 correct_credential_connection_ms=[0-9]+ credential_connection_limit_ms=240000 cached_connection_max_ms=[0-9]+ cached_connection_limit_ms=30000 initial_recovery_ms=[0-9]+ background_cycles=3 background_seconds=2,6,12 background_recovery_max_ms=[0-9]+ task_recovery_max_ms=[0-9]+ recovery_limit_ms=8000 freshness_max_ms=[0-9]+ freshness_limit_ms=2000 capture_max_ms=[0-9]+ capture_limit_ms=500 distinct_frames=(1[2-9]|[2-9][0-9]|[1-9][0-9]{2,}) resource_samples=7 resource_bound=pass force_stop=baseline apk_sha256=[0-9a-f]{64} vm_network=none container_network=none server_listener=127\.0\.0\.1:21118 reverse_cleanup=removed x11=unix-only cleanup=joined$' \
    "$RUNTIME_LOG" || true)
[ "${#peer_receipts[@]}" -eq 1 ] \
    || { tail -n 320 "$RUNTIME_LOG" >&2; die 'Android real-peer lifecycle receipt is absent or duplicated'; }
case "${peer_receipts[0]}" in
    *"apk_sha256=$APK_SHA256"*) ;;
    *) die 'Android real-peer lifecycle reported a different APK digest' ;;
esac
else
mapfile -t focused_recents_receipts < <(grep -E \
    "^ANDROID_EMULATOR_RECENTS=pass task_removals=10 actions=10 open_actions=10 task_ids=distinct open=ui-automation-app-switch-key-display-0 driver=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false runtime_uiautomator_sha256=$RECENTS_RUNTIME_UIAUTOMATOR_SHA256 driver_sha256=$RECENTS_DRIVER_SHA256 framework_anr=(absent|waited-([1-9]|1[0-2])) service=never-started relaunch=resumed apk_sha256=$APK_SHA256 vm_network=none container_network=none cleanup=joined$" \
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
    [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$SERVER_MACHINE_ID")" = \
      "$SERVER_MACHINE_ID_ID" ] \
        && [ "$(<"$SERVER_MACHINE_ID")" = "$SERVER_MACHINE_ID_VALUE" ] \
        || die 'private Android peer machine identity changed during execution'
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
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    verify_sha256 "$ONLINE_DIR/cargo-vendor-config.toml" "$SHA256_CARGO_VENDOR_CONFIG"
fi
verify_image android-builder "$ANDROID_BUILDER_CONFIG_ID"
verify_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"
printf '%s\n' "${apk_receipts[0]}" "${recents_driver_build_receipts[0]}" \
    "${recents_driver_stage_receipts[0]}" \
    "${renderer_receipts[0]}" "${runtime_receipts[0]}" \
    "${recents_open_action_receipts[@]}" \
    "${recents_dismiss_action_receipts[@]}" \
    "${recents_dismiss_outcome_receipts[@]}"
if [ "$RUNTIME_SCENARIO" = peer-lifecycle ]; then
    printf '%s\n' "${tombstone_fd_parser_receipts[0]}" \
        "${tombstone_fd_authority_receipts[0]}" \
        "${endpoint_receipts[0]}" "${frame_parser_receipts[0]}" \
        "${frame_observer_self_test_receipts[0]}" \
        "${frame_observer_build_receipts[0]}" \
        "${frame_observer_receipts[0]}" \
        "${peer_frame_baselines[@]}" "${peer_presentation_ui_receipts[@]}" \
        "${peer_presentation_stage_receipts[@]}" \
        "${peer_resource_samples[@]}" "${peer_resource_bounds[0]}" \
        "${lifecycle_receipts[0]}" "${initial_credential_receipts[0]}" \
        "${peer_receipts[0]}"
    runtime_peer=production-loopback-cpace-changing-display
else
    printf '%s\n' "${focused_recents_receipts[0]}"
    runtime_peer=absent
fi
printf 'ANDROID_EMULATOR_RUNTIME_CHECK=pass scenario=%s artifact_commit=%s apk_sha256=%s signing=test-only package=com.carriez.flutter_hbb abi=x86_64 source=commit-bound-retained-artifact builder=%s runtime=%s peer=%s vm_network=none container_network=none inputs=readonly cleanup=joined\n' \
    "$RUNTIME_SCENARIO" \
    "$ARTIFACT_SOURCE_COMMIT" "$APK_SHA256" \
    "$ANDROID_BUILDER_CONFIG_ID" "$DEV_CHECK_IMAGE_CONFIG_ID" "$runtime_peer"

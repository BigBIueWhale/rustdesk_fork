#!/usr/bin/env bash
set -euo pipefail
umask 077

export PATH=/usr/bin:/bin
export LC_ALL=C
readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
[ "$BUILD_UID" -ne 0 ] \
    || { echo "Android Gradle release gate refuses host or container-root execution" >&2; exit 1; }
[ "$BUILD_GID" -ne 0 ] \
    || { echo "Android Gradle release gate refuses a root primary group" >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly CONTAINER_TEST_ROOT=/android-gradle-test

inside_container() {
    [ "$$" -eq 1 ] \
        || { echo "Android Gradle cache test must be the confined container payload" >&2; exit 1; }
    [ "$(/usr/bin/id -u)" -ne 0 ] \
        || { echo "Android Gradle cache test requires non-root execution" >&2; exit 1; }
    [ "$(/usr/bin/id -g)" -ne 0 ] \
        || { echo "Android Gradle cache test requires a non-root primary group" >&2; exit 1; }
    for test_file in \
        android-gradle-cache.py \
        android-gradle-offline.init.gradle \
        android-apk-build.sh \
        test-android-gradle-cache.sh; do
        [ "$(/usr/bin/stat -c '%u:%g' "$CONTAINER_TEST_ROOT/$test_file")" = \
          "$(/usr/bin/id -u):$(/usr/bin/id -g)" ] \
            || { echo "Android Gradle cache test-file ownership differs from the build principal" >&2; exit 1; }
    done

    python3 -I -S "$CONTAINER_TEST_ROOT/android-gradle-cache.py" self-test \
        --init-script "$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle"

    printf 'pre-existing destination\n' > /tmp/gradle-home
    chmod 0400 /tmp/gradle-home
    preexisting_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' /tmp/gradle-home):$(sha256sum /tmp/gradle-home | awk '{print $1}')"
    if python3 -I -S "$CONTAINER_TEST_ROOT/android-gradle-cache.py" self-test \
        --init-script "$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle" \
        >/tmp/preexisting-output 2>&1; then
        echo "Gradle cache self-test adopted a pre-existing destination" >&2
        exit 1
    fi
    preexisting_after="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' /tmp/gradle-home):$(sha256sum /tmp/gradle-home | awk '{print $1}')"
    [ "$preexisting_before" = "$preexisting_after" ]
    grep -Fq 'Gradle cache destination already exists' /tmp/preexisting-output
    chmod 0600 /tmp/gradle-home
    rm /tmp/gradle-home

    install -d -m 0700 /tmp/actual-seed /tmp/project /tmp/home
    printf 'rootProject.name = "rustdesk-offline-contract"\n' > /tmp/project/settings.gradle
    printf '%s\n' \
        'tasks.register("contractHelp") {' \
        '    doLast {' \
        '        println("RUSTDESK_GRADLE_START_PARAMETER_OFFLINE=" + gradle.startParameter.offline)' \
        '    }' \
        '}' > /tmp/project/build.gradle
    chmod 0500 /tmp/actual-seed

    run_gradle_case() {
        local flag="$1" output="$2"
        rm -rf /tmp/gradle-home
        python3 -I -S "$CONTAINER_TEST_ROOT/android-gradle-cache.py" materialize \
            --source /tmp/actual-seed \
            --init-script "$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle"
        if [ "$flag" = unset ]; then
            env -u RUSTDESK_GRADLE_OFFLINE HOME=/tmp/home GRADLE_USER_HOME=/tmp/gradle-home \
                timeout 120 /gradle-distribution/bin/gradle --no-daemon --console=plain \
                    -p /tmp/project contractHelp >"$output" 2>&1
        else
            HOME=/tmp/home GRADLE_USER_HOME=/tmp/gradle-home RUSTDESK_GRADLE_OFFLINE="$flag" \
                timeout 120 /gradle-distribution/bin/gradle --no-daemon --console=plain \
                    -p /tmp/project contractHelp >"$output" 2>&1
        fi
    }

    run_gradle_case 1 /tmp/offline-output
    grep -Fxq 'RUSTDESK_GRADLE_OFFLINE: enabled' /tmp/offline-output
    grep -Fxq 'RUSTDESK_GRADLE_START_PARAMETER_OFFLINE=true' /tmp/offline-output
    grep -Fq 'BUILD SUCCESSFUL' /tmp/offline-output

    run_gradle_case unset /tmp/unset-output
    ! grep -Fq 'RUSTDESK_GRADLE_OFFLINE:' /tmp/unset-output
    grep -Fxq 'RUSTDESK_GRADLE_START_PARAMETER_OFFLINE=false' /tmp/unset-output
    grep -Fq 'BUILD SUCCESSFUL' /tmp/unset-output

    if run_gradle_case 0 /tmp/invalid-output; then
        echo "Gradle accepted an invalid internal offline flag" >&2
        exit 1
    fi
    grep -Fq 'RUSTDESK_GRADLE_OFFLINE must be unset or exactly 1' /tmp/invalid-output
    ! grep -Fxq 'RUSTDESK_GRADLE_OFFLINE: enabled' /tmp/invalid-output

    for invalid in OFFLINE offine arbitrary ''; do
        if APK_MODE="$invalid" /bin/bash "$CONTAINER_TEST_ROOT/android-apk-build.sh" \
            >/tmp/invalid-apk-mode-output 2>&1; then
            echo "Android build accepted invalid APK_MODE '$invalid'" >&2
            exit 1
        fi
        grep -Fq 'APK_MODE must be exactly offline, warm, or rust-check' /tmp/invalid-apk-mode-output
    done
    if env -u APK_MODE /bin/bash "$CONTAINER_TEST_ROOT/android-apk-build.sh" \
        >/tmp/invalid-apk-mode-output 2>&1; then
        echo "Android build accepted absent APK_MODE" >&2
        exit 1
    fi
    grep -Fq 'APK_MODE must be exactly offline, warm, or rust-check' /tmp/invalid-apk-mode-output

    if APK_MODE=offline RUSTDESK_GRADLE_OFFLINE=1 \
        /bin/bash "$CONTAINER_TEST_ROOT/android-apk-build.sh" >/tmp/internal-flag-output 2>&1; then
        echo "Android build accepted an externally supplied internal offline flag" >&2
        exit 1
    fi
    grep -Fq 'RUSTDESK_GRADLE_OFFLINE is build-internal' /tmp/internal-flag-output

    rm -rf /tmp/gradle-home
    echo "ANDROID-GRADLE-CACHE: immutable projection and pinned Gradle offline semantics are GREEN"
}

if [ "${1:-}" = --inside ]; then
    [ "$#" -eq 1 ] \
        || { echo "test-android-gradle-cache: --inside takes no arguments" >&2; exit 2; }
    inside_container
    exit 0
fi

SELF_TEST_VM_AUTHORITY=0
PROBE_IMAGE_ID=""
case "$#:${1:-}" in
    0:) ;;
    2:--self-test-vm-authority)
        SELF_TEST_VM_AUTHORITY=1
        PROBE_IMAGE_ID=$2
        ;;
    *)
        echo "usage: scripts/test-android-gradle-cache.sh [--inside | --self-test-vm-authority PROBE_IMAGE_ID]" >&2
        exit 2
        ;;
esac

readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh
[ -f "$VERIFIER_VM_ENTRY_PREFLIGHT" ] && [ ! -L "$VERIFIER_VM_ENTRY_PREFLIGHT" ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1 ] \
    || { echo "Android Gradle release gate requires the verifier-VM entry preflight" >&2; exit 1; }
/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

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

require_verifier_vm_android_builder() {
    verifier_vm_image_provenance verify-local \
        --role android-builder \
        --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
        --image-ref "$ANDROID_BUILDER_IMAGE_ID" \
        --base "ubuntu:24.04@$SHA256_BASEIMAGE_UBUNTU_2404" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
        --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
        --config-id "$ANDROID_BUILDER_CONFIG_ID" \
        --manifest-id "$ANDROID_BUILDER_MANIFEST_ID" \
        || die "pinned Android builder image provenance verification failed"
}

android_gradle_mount_rejection_run() {
    verifier_vm_docker run --rm --pull=never --network=none --read-only \
        --user "$BUILD_UID:$BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --pids-limit=64 --memory=512m --memory-swap=512m --cpus=1 \
        --ulimit core=0:0 --ulimit nofile=1024:1024 \
        --ulimit fsize=1048576:1048576 \
        --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
        "$@"
}

android_gradle_semantics_run() {
    verifier_vm_docker run --rm --pull=never --network=none --read-only \
        --user "$BUILD_UID:$BUILD_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \
        --ulimit core=0:0 --ulimit nofile=4096:4096 \
        --ulimit fsize=1073741824:1073741824 \
        --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=2g \
        "$@"
}

if [ "$SELF_TEST_VM_AUTHORITY" -eq 1 ]; then
    [[ "$PROBE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "Android Gradle verifier-VM probe image ID is malformed"
    authority_version="$(verifier_vm_docker version \
        --format '{{.Client.Version}}|{{.Server.Version}}')" \
        || die "Android Gradle verifier-VM Docker authority self-test failed"
    [ "$authority_version" = \
      "$VERIFIER_VM_DOCKER_VERSION|$VERIFIER_VM_DOCKER_VERSION" ] \
        || die "verifier-VM Docker authority version differs: $authority_version"
    containers_before="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || die "cannot record the initial guest container inventory"

    readonly PROFILE_PROBE='
        [ "$$" = 1 ]
        profile=$0
        expected_pids=$1
        expected_memory=$2
        expected_cpu=$3
        expected_nofile=$4
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
        [ "$pids_max" = "$expected_pids" ]
        [ "$memory_max" = "$expected_memory" ]
        [ "$swap_max" = 0 ]
        [ "$cpu_quota:$cpu_period" = "$expected_cpu" ]
        [ "$(ulimit -c)" = 0 ]
        [ "$(ulimit -n)" = "$expected_nofile" ]
        [ "$(ulimit -f)" != unlimited ]
        set -- /sys/class/net/*
        [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
        if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
        : >/tmp/allowed-private-write
        printf "profile=%s uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default\n" "$profile"
    '
    mount_profile_output="$(android_gradle_mount_rejection_run \
        "$PROBE_IMAGE_ID" -euc "$PROFILE_PROBE" \
        mount-rejection 64 536870912 100000:100000 1024)" \
        || die "Android Gradle mount-rejection production profile failed"
    [ "$mount_profile_output" = \
      "profile=mount-rejection uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default" ] \
        || die "Android Gradle mount-rejection profile receipt differs: $mount_profile_output"
    semantics_profile_output="$(android_gradle_semantics_run \
        "$PROBE_IMAGE_ID" -euc "$PROFILE_PROBE" \
        semantics 256 4294967296 200000:100000 4096)" \
        || die "Android Gradle semantics production profile failed"
    [ "$semantics_profile_output" = \
      "profile=semantics uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default" ] \
        || die "Android Gradle semantics profile receipt differs: $semantics_profile_output"
    containers_after="$(verifier_vm_docker ps --all --quiet --no-trunc | /usr/bin/sort)" \
        || die "cannot record the final guest container inventory"
    [ "$containers_after" = "$containers_before" ] \
        || die "Android Gradle profile probe left a guest container behind"
    printf 'ANDROID_GRADLE_VM_AUTHORITY=pass uid=%s gid=%s docker=%s profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined\n' \
        "$BUILD_UID" "$BUILD_GID" "$VERIFIER_VM_DOCKER_VERSION"
    exit 0
fi

WORKSPACE=""
WORKSPACE_ID=""
GRADLE_FIXTURE=""

cleanup_workspace() {
    local status=$? cleanup_failed=0
    trap - EXIT HUP INT TERM
    if [ -n "$WORKSPACE" ]; then
        if [ -z "$WORKSPACE_ID" ] || [ ! -d "$WORKSPACE" ] || [ -L "$WORKSPACE" ] \
            || [ "$(/usr/bin/stat -c '%d:%i' -- "$WORKSPACE" 2>/dev/null)" != "$WORKSPACE_ID" ]; then
            echo "test-android-gradle-cache: preserving changed private workspace: $WORKSPACE" >&2
            cleanup_failed=1
        elif ! /usr/bin/env -i PATH=/usr/bin:/bin \
            /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
                --remove-private-root "$WORKSPACE" --expected-identity "$WORKSPACE_ID"; then
            echo "test-android-gradle-cache: failed to remove private workspace: $WORKSPACE" >&2
            cleanup_failed=1
        elif [ -e "$WORKSPACE" ] || [ -L "$WORKSPACE" ]; then
            echo "test-android-gradle-cache: private workspace survived removal: $WORKSPACE" >&2
            cleanup_failed=1
        fi
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}

trap cleanup_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_cmd find readlink stat
require_online_complete
[[ "$ANDROID_BUILDER_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "Android Gradle release gate has a malformed immutable builder image ID"

WORKSPACE="$(umask 077 && /usr/bin/mktemp -d /tmp/rustdesk-android-gradle-gate.XXXXXXXXXX)" \
    || die "cannot create Android Gradle release-gate workspace"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
    || die "Android Gradle release-gate workspace is not a real directory"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ] \
    || die "Android Gradle release-gate workspace is not current-user/current-group mode 0700"
WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORKSPACE")"
require_verifier_vm_android_builder

gradle_home="$(readlink -f -- "$ONLINE_DIR/gradle-home")" \
    || die "cannot resolve the online Gradle cache"
gradle_dist_root="$gradle_home/wrapper/dists/gradle-${ANDROID_GRADLE_WRAPPER}-all"
mapfile -t gradle_roots < <(
    find "$gradle_dist_root" -mindepth 2 -maxdepth 2 -type d \
        -name "gradle-${ANDROID_GRADLE_WRAPPER}" -print 2>/dev/null
)
[ "${#gradle_roots[@]}" -eq 1 ] \
    || die "expected exactly one pinned Gradle ${ANDROID_GRADLE_WRAPPER} distribution"
gradle_root="$(readlink -f -- "${gradle_roots[0]}")" \
    || die "cannot resolve the pinned Gradle distribution"
case "$gradle_root" in
    "$gradle_home"/*) ;;
    *) die "pinned Gradle distribution escapes the online Gradle cache" ;;
esac
[ -f "$gradle_root/bin/gradle" ] && [ -x "$gradle_root/bin/gradle" ] \
    || die "pinned Gradle distribution has no executable launcher"

GRADLE_FIXTURE="$WORKSPACE/fixture"
install -d -m 0700 "$GRADLE_FIXTURE"
install -d -m 0700 "$GRADLE_FIXTURE/seed" "$GRADLE_FIXTURE/overlay"
install -d -m 0500 "$GRADLE_FIXTURE/seed/nested"
printf 'same-filesystem nested bind\n' > "$GRADLE_FIXTURE/overlay/payload"
chmod 0400 "$GRADLE_FIXTURE/overlay/payload"
chmod 0500 "$GRADLE_FIXTURE/seed" "$GRADLE_FIXTURE/overlay"

if android_gradle_mount_rejection_run \
    --mount "type=bind,source=$SCRIPT_DIR/android-gradle-cache.py,target=$CONTAINER_TEST_ROOT/android-gradle-cache.py,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SCRIPT_DIR/android-gradle-offline.init.gradle,target=$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$GRADLE_FIXTURE/seed,target=/seed,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$GRADLE_FIXTURE/overlay,target=/seed/nested,readonly,bind-recursive=disabled" \
    "$ANDROID_BUILDER_IMAGE_ID" \
    python3 -I -S "$CONTAINER_TEST_ROOT/android-gradle-cache.py" materialize \
        --source /seed \
        --init-script "$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle" \
        >"$GRADLE_FIXTURE/mount-output" 2>&1; then
    die "Gradle cache projector accepted a same-filesystem descendant bind mount"
fi
grep -Fq 'Gradle cache seed contains a descendant mount: /seed/nested' \
    "$GRADLE_FIXTURE/mount-output" \
    || die "Gradle cache descendant-mount rejection produced the wrong diagnostic"

android_gradle_semantics_run \
    --mount "type=bind,source=$SCRIPT_DIR/android-gradle-cache.py,target=$CONTAINER_TEST_ROOT/android-gradle-cache.py,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SCRIPT_DIR/android-gradle-offline.init.gradle,target=$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SCRIPT_DIR/android-apk-build.sh,target=$CONTAINER_TEST_ROOT/android-apk-build.sh,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$SCRIPT_DIR/test-android-gradle-cache.sh,target=$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$gradle_root,target=/gradle-distribution,readonly,bind-recursive=disabled" \
    "$ANDROID_BUILDER_IMAGE_ID" \
    /bin/bash "$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh" --inside
require_online_complete

#!/usr/bin/env bash
set -euo pipefail
umask 077

FLUTTER_PEER_CANDIDATE=0
FLUTTER_APP_BUILD_ONLY=0
FLUTTER_APP_BUILD_CONTEXT=
FLUTTER_APP_REPLAY=0
FLUTTER_APP_COMMIT=
FLUTTER_APP_TREE=
FLUTTER_APP_RECIPE_SHA256=
FLUTTER_APP_MANIFEST_SHA256=
FLUTTER_APP_ENGINE_CONTEXT=
FLUTTER_TEST_PROFILE=models
APPLE_CURSOR_ONLY=0
case "$#:${8:-}" in
    7:)
        MODE=authority-smoke
        ;;
    8:--android-execution-probe)
        MODE=android-execution-probe
        ;;
    8:--android-runtime-log-tests)
        MODE=android-runtime-log-tests
        ;;
    8:--fixed-archive-tests)
        MODE=fixed-archive-tests
        ;;
    8:--linux-flutter-artifact-tests)
        MODE=linux-flutter-artifact-tests
        ;;
    8:--android-frame-tests|8:--x11-display-tests)
        MODE=${8#--}
        ;;
    9:--x11-display-tests)
        [ "${9}" = --clipboard-listener ] || exit 2
        MODE=x11-display-tests
        X11_CLIPBOARD_ONLY=1
        ;;
    10:--linux-flutter-engine-prepare|10:--linux-flutter-engine-build)
        MODE=${8#--}
        ENGINE_PREPARE_COMMIT=${9}
        ENGINE_PREPARE_TREE=${10}
        [[ "$ENGINE_PREPARE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$ENGINE_PREPARE_TREE" =~ ^[0-9a-f]{40}$ ]] || exit 2
        ;;
    12:--hbb-common-fs)
        MODE=hbb-common-fs
        ;;
    12:--cpace-recovery-tests)
        MODE=cpace-recovery-tests
        ;;
    12:--linux-pa-authority-tests)
        MODE=linux-pa-authority-tests
        ;;
    12:--linux-service-uid-tests)
        MODE=linux-service-uid-tests
        ;;
    12:--android-rust-lifecycle-tests)
        MODE=android-rust-lifecycle-tests
        ;;
    12:--android-rust-target-check)
        MODE=android-rust-target-check
        ;;
    12:--flutter-model-tests)
        MODE=flutter-model-tests
        ;;
    13:--flutter-model-tests)
        [ "${13}" = --frame-queue ] || exit 2
        MODE=flutter-model-tests
        FLUTTER_TEST_PROFILE=frame-queue
        ;;
    12:--android-owner-tests)
        MODE=android-owner-tests
        ;;
    12:--android-peer-build)
        MODE=android-peer-build
        ;;
    12:--cm-file-replay)
        MODE=cm-file-replay
        ;;
    12:--android-emulator-boot)
        MODE=android-emulator-boot
        ;;
    12:--android-emulator-app)
        MODE=android-emulator-app
        ;;
    17:--android-emulator-runtime)
        [ "${17}" = recents ] || exit 2
        MODE=android-emulator-runtime
        ;;
    20:--android-emulator-runtime)
        [ "${17}" = peer-lifecycle ] || [ "${17}" = controlled-cm ] || exit 2
        MODE=android-emulator-runtime
        ;;
    12:--apple-conform)
        MODE=apple-conform
        ;;
    13:--apple-conform)
        [ "${13}" = --cursor-compile ] || exit 2
        MODE=apple-conform
        APPLE_CURSOR_ONLY=1
        ;;
    18:--linux-flutter-app-replay)
        MODE=flutter-peer-presentation
        FLUTTER_PEER_CANDIDATE=1
        FLUTTER_APP_REPLAY=1
        FLUTTER_APP_COMMIT=${13}
        FLUTTER_APP_TREE=${14}
        FLUTTER_APP_RECIPE_SHA256=${15}
        FLUTTER_APP_MANIFEST_SHA256=${16}
        FLUTTER_APP_BUILD_CONTEXT=${17}
        FLUTTER_APP_ENGINE_CONTEXT=${18}
        [[ "$FLUTTER_APP_COMMIT" =~ ^[0-9a-f]{40}$ ]] && [[ "$FLUTTER_APP_TREE" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$FLUTTER_APP_RECIPE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
            && [[ "$FLUTTER_APP_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
            && [ -n "$FLUTTER_APP_BUILD_CONTEXT" ] && [ "${#FLUTTER_APP_BUILD_CONTEXT}" -le 4096 ] || exit 2
        ;;
    14:--linux-flutter-app-build)
        MODE=flutter-peer-presentation
        FLUTTER_PEER_CANDIDATE=1
        FLUTTER_APP_BUILD_ONLY=1
        FLUTTER_APP_BUILD_CONTEXT=${13}
        FLUTTER_APP_ENGINE_CONTEXT=${14}
        [ -n "$FLUTTER_APP_BUILD_CONTEXT" ] && [ "${#FLUTTER_APP_BUILD_CONTEXT}" -le 4096 ] || exit 2
        ;;
    12:--debian-systemd-lifecycle)
        MODE=debian-systemd-lifecycle
        ;;
    13:--dart-audit)
        MODE=dart-audit
        ;;
    13:--rust-audit)
        MODE=rust-audit
        ;;
    *)
        echo 'usage: smoke-verifier-vm-authority-guest.sh DOCKER_TGZ ENTRY_PREFLIGHT VERSION SIZE SHA256 KERNEL_RELEASE ROOT_UUID [--hbb-common-fs SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --cpace-recovery-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --linux-pa-authority-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --linux-service-uid-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-rust-lifecycle-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-rust-target-check SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --flutter-model-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-owner-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-peer-build SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-emulator-boot SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-emulator-app SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-emulator-runtime SOURCE_ARCHIVE HARNESS_COMMIT HARNESS_TREE SOURCE_ARCHIVE_SHA256 ARTIFACT_COMMIT ARTIFACT_TREE APK_SHA256 TEST_APK_SHA256 recents | --android-emulator-runtime SOURCE_ARCHIVE HARNESS_COMMIT HARNESS_TREE SOURCE_ARCHIVE_SHA256 ARTIFACT_COMMIT ARTIFACT_TREE APK_SHA256 TEST_APK_SHA256 {peer-lifecycle|controlled-cm} PEER_COMMIT PEER_TREE PEER_MANIFEST_SHA256 | --apple-conform SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --linux-flutter-app-build SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 CONTEXT | --linux-flutter-app-replay SOURCE_ARCHIVE HARNESS_COMMIT HARNESS_TREE SOURCE_ARCHIVE_SHA256 APP_COMMIT APP_TREE APP_RECIPE_SHA256 APP_MANIFEST_SHA256 CONTEXT | --dart-audit SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 IMAGE_ARCHIVE | --rust-audit SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 IMAGE_ARCHIVE | --debian-systemd-lifecycle DEV_CHECK_ARCHIVE DEB DEB_SHA256 COMMIT]' >&2
        echo 'The seven base arguments also accept --android-execution-probe, --android-runtime-log-tests, --fixed-archive-tests, or --linux-flutter-artifact-tests.' >&2
        echo 'CM file integration replay accepts --cm-file-replay SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256.' >&2
        echo 'The focused Flutter queue shard appends --frame-queue to --flutter-model-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256.' >&2
        echo 'The focused macOS cursor compiler appends --cursor-compile to --apple-conform SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256.' >&2
        exit 2
        ;;
esac
readonly DOCKER_ARCHIVE=$1
readonly ENTRY_PREFLIGHT=$2
readonly GIT_PACKAGE=/mnt/rustdesk-verifier-inputs/git.deb
readonly EXPECTED_VERSION=$3
readonly EXPECTED_SIZE=$4
readonly EXPECTED_SHA256=$5
readonly EXPECTED_KERNEL_RELEASE=$6
readonly EXPECTED_ROOT_UUID=$7
readonly MODE FLUTTER_PEER_CANDIDATE FLUTTER_APP_BUILD_ONLY FLUTTER_APP_BUILD_CONTEXT
readonly FLUTTER_TEST_PROFILE
readonly FLUTTER_APP_ENGINE_CONTEXT
if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ] || [ "$FLUTTER_APP_REPLAY" -eq 1 ]; then
    [ -n "$FLUTTER_APP_ENGINE_CONTEXT" ] && [ "${#FLUTTER_APP_ENGINE_CONTEXT}" -le 2048 ] || exit 2
fi
readonly FLUTTER_APP_REPLAY FLUTTER_APP_COMMIT FLUTTER_APP_TREE \
    FLUTTER_APP_RECIPE_SHA256 FLUTTER_APP_MANIFEST_SHA256
readonly RUST_TEST_SOURCE_ARCHIVE=${9:-}
readonly RUST_TEST_SOURCE_COMMIT=${10:-}
readonly RUST_TEST_SOURCE_TREE=${11:-}
readonly RUST_TEST_SOURCE_ARCHIVE_SHA256=${12:-}
readonly FLUTTER_SOURCE_ARCHIVE=${9:-}
readonly FLUTTER_SOURCE_COMMIT=${10:-}
readonly FLUTTER_SOURCE_TREE=${11:-}
readonly FLUTTER_SOURCE_ARCHIVE_SHA256=${12:-}
readonly ANDROID_OWNER_SOURCE_ARCHIVE=${9:-}
readonly ANDROID_OWNER_SOURCE_COMMIT=${10:-}
readonly ANDROID_OWNER_SOURCE_TREE=${11:-}
readonly ANDROID_OWNER_SOURCE_ARCHIVE_SHA256=${12:-}
readonly ANDROID_EMULATOR_SOURCE_ARCHIVE=${9:-}
readonly ANDROID_EMULATOR_SOURCE_COMMIT=${10:-}
readonly ANDROID_EMULATOR_SOURCE_TREE=${11:-}
readonly ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256=${12:-}
readonly ANDROID_RUNTIME_ARTIFACT_COMMIT=${13:-}
readonly ANDROID_RUNTIME_ARTIFACT_TREE=${14:-}
readonly ANDROID_RUNTIME_APK_SHA256=${15:-}
readonly ANDROID_RUNTIME_TEST_APK_SHA256=${16:-}
readonly ANDROID_RUNTIME_SCENARIO=${17:-}
readonly ANDROID_RUNTIME_PEER_COMMIT=${18:-}
readonly ANDROID_RUNTIME_PEER_TREE=${19:-}
readonly ANDROID_RUNTIME_PEER_MANIFEST_SHA256=${20:-}
readonly APPLE_SOURCE_ARCHIVE=${9:-}
readonly APPLE_SOURCE_COMMIT=${10:-}
readonly APPLE_SOURCE_TREE=${11:-}
readonly APPLE_SOURCE_ARCHIVE_SHA256=${12:-}
readonly FLUTTER_PEER_SOURCE_ARCHIVE=${9:-}
readonly FLUTTER_PEER_SOURCE_COMMIT=${10:-}
readonly FLUTTER_PEER_SOURCE_TREE=${11:-}
readonly FLUTTER_PEER_SOURCE_ARCHIVE_SHA256=${12:-}
readonly DART_SOURCE_ARCHIVE=${9:-}
readonly DART_SOURCE_COMMIT=${10:-}
readonly DART_SOURCE_TREE=${11:-}
readonly DART_SOURCE_ARCHIVE_SHA256=${12:-}
readonly DART_AUDIT_IMAGE_ARCHIVE=${13:-}
readonly RUST_AUDIT_SOURCE_ARCHIVE=${9:-}
readonly RUST_AUDIT_SOURCE_COMMIT=${10:-}
readonly RUST_AUDIT_SOURCE_TREE=${11:-}
readonly RUST_AUDIT_SOURCE_ARCHIVE_SHA256=${12:-}
readonly RUST_AUDIT_IMAGE_ARCHIVE=${13:-}
readonly DEV_CHECK_ARCHIVE=${9:-}
readonly LIFECYCLE_ARTIFACT=${10:-}
readonly LIFECYCLE_ARTIFACT_SHA256=${11:-}
readonly LIFECYCLE_COMMIT=${12:-}
readonly AUTHORITY_ROOT=/run/rustdesk-verifier-vm
readonly MARKER=$AUTHORITY_ROOT/authority
readonly CONFIG_ROOT=$AUTHORITY_ROOT/docker-config
readonly CONFIG=$CONFIG_ROOT/config.json
readonly ROOT=/var/tmp/rustdesk-verifier-authority
readonly BIN=$ROOT/bin
readonly CLIENT=/usr/bin/docker
readonly DAEMON_PATH=$BIN:/usr/sbin:/usr/bin:/sbin:/bin
readonly DATA=$ROOT/data
readonly EXEC=$ROOT/exec
readonly SOCK=$AUTHORITY_ROOT/docker.sock
readonly PIDFILE=$AUTHORITY_ROOT/docker.pid
readonly DAEMON_IDENTITY=$AUTHORITY_ROOT/docker.identity
readonly LOG=$ROOT/dockerd.log
readonly VERIFY_REPO=/mnt/rustdesk-verifier-inputs/repo
readonly VERIFY_SCRIPT=$VERIFY_REPO/scripts/verify.sh
readonly FRB_SCRIPT=$VERIFY_REPO/scripts/frb-codegen.sh
readonly DART_SCRIPT=$VERIFY_REPO/scripts/dart-verify.sh
readonly SMOKE_SERVER_SCRIPT=$VERIFY_REPO/scripts/smoke-server.sh
readonly RUST_AUDIT_SCRIPT=$VERIFY_REPO/scripts/audit.sh
readonly ANDROID_KEYSTORE_SCRIPT=$VERIFY_REPO/scripts/gen-android-keystore.sh
readonly ANDROID_BUILDER_SCRIPT=$VERIFY_REPO/scripts/build-android.sh
readonly ANDROID_GRADLE_SCRIPT=$VERIFY_REPO/scripts/test-android-gradle-cache.sh
readonly ANDROID_GRADLE_CHECKER=$VERIFY_REPO/scripts/verify-android-gradle-authority.py
readonly ANDROID_BUILDER_IMAGE_CHECKER=$VERIFY_REPO/scripts/verify-android-builder-image-authority.py
readonly DEB_BUILDER_IMAGE_CHECKER=$VERIFY_REPO/scripts/verify-deb-builder-image-authority.py
readonly DEBIAN_BUILDER_SCRIPT=$VERIFY_REPO/scripts/build-debian.sh
readonly DEBIAN_BUILDER_AUTHORITY_CHECKER=$VERIFY_REPO/scripts/verify-debian-builder-authority.py
readonly SYSTEMD_RUNTIME_LIBS_SCRIPT=$VERIFY_REPO/scripts/stage-debian-systemd-runtime-libs.sh
readonly SYSTEMD_LIFECYCLE_SCRIPT=$VERIFY_REPO/scripts/smoke-debian-systemd-lifecycle-guest.sh
readonly WIN_HELPER_IMAGE_CHECKER=$VERIFY_REPO/scripts/verify-win-helper-image-authority.py
readonly WINDOWS_HELPER_AUTHORITY_CHECKER=$VERIFY_REPO/scripts/verify-windows-helper-authority.py
readonly WINDOWS_HELPER_RUNTIME_TEST=$VERIFY_REPO/scripts/test-windows-helper-vm-runtime.sh
readonly ANDROID_RUST_SCRIPT=$VERIFY_REPO/scripts/android-rust-check.sh
readonly ANDROID_EMULATOR_BOOT_SCRIPT=$VERIFY_REPO/scripts/smoke-android-emulator-boot.sh
readonly ANDROID_EMULATOR_APP_SCRIPT=$VERIFY_REPO/scripts/android-emulator-app-check.sh
readonly ANDROID_EMULATOR_APK_VERIFIER=$VERIFY_REPO/scripts/verify-android-emulator-apk.py
readonly OFFLINE_IMAGE_PROVENANCE=$VERIFY_REPO/scripts/offline-image-provenance.py
readonly APPLE_TOOLCHAIN_RELEASE=$VERIFY_REPO/scripts/apple-toolchain-release.py
readonly ONLINE_PUB_CACHE_OUTPUT=$VERIFY_REPO/scripts/online-pub-cache-output.py
readonly ONLINE_GRADLE_OUTPUT=$VERIFY_REPO/scripts/online-gradle-output.py
readonly ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER=$VERIFY_REPO/scripts/verify-online-fetch-gradle-output-authority.py
readonly ONLINE_FETCH_AUTHORITY_CHECKER=$VERIFY_REPO/scripts/verify-online-fetch-container-authority.py
readonly DART_AUDIT_SCRIPT=$VERIFY_REPO/scripts/dart-audit.sh
readonly IMAGE=rustdesk-verifier-authority-probe:v1
readonly CONTAINER=rustdesk-verifier-authority-probe
readonly GIT_RUNTIME_ROOT=/opt/rustdesk-verifier-git
readonly VERIFIER_VM_NOFILE_LIMIT=524544

DAEMON_PID=
CONTAINER_ID=
LIFECYCLE_LIBS_MOUNTED=0
SEALED_INPUTS_MOUNTED=0
RUST_AUDIT_VENDOR_MOUNTED=0
APPLE_VENDOR_MOUNTED=0
ANDROID_RUST_ONLINE_MOUNTED=0
ANDROID_EMULATOR_ONLINE_MOUNTED=0
ANDROID_EMULATOR_RUNTIME_ONLINE_MOUNTED=0
ANDROID_ARTIFACT_OUTPUT_MOUNTED=0
ANDROID_ARTIFACT_INPUT_MOUNTED=0
ANDROID_PEER_ARTIFACT_INPUT_MOUNTED=0
ANDROID_RUNTIME_FAILURE_MOUNTED=0
FLUTTER_PEER_SOURCE_MOUNTED=0
FLUTTER_PEER_ONLINE_MOUNTED=0
FLUTTER_PEER_CANDIDATE_MOUNTED=0
FLUTTER_PEER_FAILURE_MOUNTED=0
FLUTTER_APP_OUTPUT_MOUNTED=0
FLUTTER_APP_INPUT_MOUNTED=0
ENGINE_INPUT_MOUNTS=()
ENGINE_OUTPUT_MOUNTED=0

fail() {
    printf 'verifier-VM guest: %s\n' "$*" >&2
    exit 1
}

provision_git_runtime() {
    local mount_options
    case "$SIZE_VERIFIER_VM_GIT_PACKAGE" in
        0|*[!0-9]*|'') fail 'Git package size pin is malformed' ;;
    esac
    [[ "$SHA256_VERIFIER_VM_GIT_PACKAGE" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Git package digest pin is malformed'
    case "$SIZE_VERIFIER_VM_GIT_BINARY" in
        0|*[!0-9]*|'') fail 'Git binary size pin is malformed' ;;
    esac
    [[ "$SHA256_VERIFIER_VM_GIT_BINARY" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Git binary digest pin is malformed'
    [ -f "$GIT_PACKAGE" ] && [ ! -L "$GIT_PACKAGE" ] \
        && [ "$(/usr/bin/stat -c '%a:%h:%s' -- "$GIT_PACKAGE")" = \
             "400:1:$SIZE_VERIFIER_VM_GIT_PACKAGE" ] \
        || fail 'Git package payload metadata differs'
    mount_options="$(/usr/bin/findmnt -n -o OPTIONS --target "$GIT_PACKAGE")" \
        || fail 'Git package payload mount is absent'
    case ",$mount_options," in *,ro,*) ;; *) fail 'Git package payload is not read-only' ;; esac
    case ",$mount_options," in *,nodev,*) ;; *) fail 'Git package payload permits devices' ;; esac
    case ",$mount_options," in *,nosuid,*) ;; *) fail 'Git package payload permits set-user-ID execution' ;; esac
    case ",$mount_options," in *,noexec,*) ;; *) fail 'Git package payload permits direct execution' ;; esac
    [ "$(/usr/bin/sha256sum "$GIT_PACKAGE" | /usr/bin/awk '{print $1}')" = \
      "$SHA256_VERIFIER_VM_GIT_PACKAGE" ] \
        || fail 'Git package payload digest differs'
    [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Package)" = git ] \
        && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Version)" = \
             "$VERIFIER_VM_GIT_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Architecture)" = amd64 ] \
        || fail 'Git package payload identity differs'

    for destination in /usr/bin/git /usr/lib/git-core /usr/share/git-core; do
        [ ! -e "$destination" ] && [ ! -L "$destination" ] \
            || fail "Git runtime destination is already occupied: $destination"
    done
    [ ! -e "$GIT_RUNTIME_ROOT" ] && [ ! -L "$GIT_RUNTIME_ROOT" ] \
        || fail 'private Git runtime root is already occupied'
    /usr/bin/install -d -m 0700 -- "$GIT_RUNTIME_ROOT"
    /usr/bin/dpkg-deb --extract "$GIT_PACKAGE" "$GIT_RUNTIME_ROOT" \
        || fail 'cannot extract the authenticated Git runtime'
    /usr/bin/chmod -R a-w -- "$GIT_RUNTIME_ROOT"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$GIT_RUNTIME_ROOT")" = 0:0:555 ] \
        || fail 'private Git runtime root metadata differs'
    [ -z "$(/usr/bin/find "$GIT_RUNTIME_ROOT" -xdev \
        \( \( ! -type d -a ! -type f -a ! -type l \) \
           -o \( ! -type l -a \( -perm /022 -o -perm /6000 \) \) \) \
        -print -quit)" ] \
        || fail 'private Git runtime contains a special or writable entry'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GIT_RUNTIME_ROOT/usr/bin/git")" = \
      "0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY" ] \
        && [ "$(/usr/bin/sha256sum "$GIT_RUNTIME_ROOT/usr/bin/git" | /usr/bin/awk '{print $1}')" = \
             "$SHA256_VERIFIER_VM_GIT_BINARY" ] \
        && [ -d "$GIT_RUNTIME_ROOT/usr/lib/git-core" ] \
        && [ ! -L "$GIT_RUNTIME_ROOT/usr/lib/git-core" ] \
        && [ -d "$GIT_RUNTIME_ROOT/usr/share/git-core/templates" ] \
        && [ ! -L "$GIT_RUNTIME_ROOT/usr/share/git-core/templates" ] \
        || fail 'private Git runtime layout or binary identity differs'

    /usr/bin/install -m 0555 -- "$GIT_RUNTIME_ROOT/usr/bin/git" /usr/bin/git
    /bin/cp -a -- "$GIT_RUNTIME_ROOT/usr/lib/git-core" /usr/lib/git-core
    /bin/cp -a -- "$GIT_RUNTIME_ROOT/usr/share/git-core" /usr/share/git-core
    /usr/bin/chmod -R a-w -- /usr/lib/git-core /usr/share/git-core
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- /usr/bin/git)" = \
      "0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY" ] \
        && [ "$(/usr/bin/sha256sum /usr/bin/git | /usr/bin/awk '{print $1}')" = \
             "$SHA256_VERIFIER_VM_GIT_BINARY" ] \
        || fail 'provisioned Git binary identity differs'
    [ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /usr/bin/git --version)" = 'git version 2.39.5' ] \
        || fail 'provisioned Git runtime version differs'
    printf 'VERIFIER_VM_GIT_RUNTIME=pass source=pinned-deb version=2.39.5 root=vm-ephemeral network=none\n'
}

frame_docker() {
    local status=0
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_CONFIG="$CONFIG_ROOT" "$CLIENT" --host "unix://$SOCK" "$@" || status=$?
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT" >/dev/null || return 1
    return "$status"
}

prepare_authority_probe_image() {
    local library
    cp --parents -L /bin/dash "$ROOT/rootfs"
    while IFS= read -r library; do
        [ -f "$library" ] || fail "shell dependency is absent: $library"
        cp --parents -L "$library" "$ROOT/rootfs"
    done < <(ldd /bin/dash | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' | LC_ALL=C sort -u)
    ln -s dash "$ROOT/rootfs/bin/sh"
    # Imported files are root-owned and immutable, but traversable by the numeric nonroot user.
    find "$ROOT/rootfs" -type d -exec chmod 0555 {} +
    find "$ROOT/rootfs" -type f -exec chmod 0555 {} +
    [ -z "$(find "$ROOT/rootfs" \( -type d -o -type f \) -perm /0222 -print -quit)" ] \
        || fail 'probe root filesystem contains a writable directory or file'
    [ "$(stat -c '%u:%g:%a' -- "$ROOT/rootfs")" = 0:0:555 ] \
        || fail 'probe root filesystem root metadata differs'
    tar --numeric-owner --owner=0 --group=0 -C "$ROOT/rootfs" -cf - . \
        | "$CLIENT" --host "unix://$SOCK" import \
            --change 'USER 4000:4000' \
            --change 'ENTRYPOINT ["/bin/dash"]' \
            - "$IMAGE" >"$ROOT/image-id"
    [[ "$(<"$ROOT/image-id")" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail 'probe image ID is malformed'
}

prepare_engine_xvfb() {
    local work=$ROOT/engine-xvfb inspect status=0
    local xvfb_inputs=${1:-/mnt/rustdesk-verifier-inputs/xvfb-debs}
    local xvfb_scripts=${2:-$VERIFY_REPO/scripts}
    install -d -o 1000 -g 1000 -m 0700 "$work" "$work/debs" "$work/root"
    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create --name rustdesk-engine-xvfb-prepare \
            --pull=never --network=none --read-only --user 1000:1000 \
            --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
            --memory=512m --memory-swap=512m --cpus=2 --pids-limit=128 \
            --ulimit nofile=1024:1024 --ulimit core=0:0 --ulimit fsize=536870912:536870912 \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=700,uid=1000,gid=1000 \
            --mount "type=bind,source=$xvfb_scripts/smoke-xvfb-prepare.sh,target=/work/scripts/smoke-xvfb-prepare.sh,readonly" \
            --mount "type=bind,source=$xvfb_scripts/smoke-xvfb-packages.tsv,target=/work/scripts/smoke-xvfb-packages.tsv,readonly" \
            --mount "type=bind,source=$xvfb_scripts/smoke-xvfb-files.tsv,target=/work/scripts/smoke-xvfb-files.tsv,readonly" \
            --mount "type=bind,source=$xvfb_inputs,target=/xvfb-inputs,readonly,bind-recursive=disabled" \
            --mount "type=bind,source=$work/debs,target=/xvfb-debs,bind-recursive=disabled" \
            --mount "type=bind,source=$work/root,target=/xvfb-root,bind-recursive=disabled" \
            --workdir /tmp "$DEV_CHECK_IMAGE_CONFIG_ID" /bin/bash /work/scripts/smoke-xvfb-prepare.sh
    )" || fail 'cannot create the confined engine Xvfb preparation container'
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'engine Xvfb preparation container ID differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' "$CONTAINER_ID")"
    [ "$inspect" = "$DEV_CHECK_IMAGE_CONFIG_ID|1000:1000|none|true|536870912|536870912|2000000000|128|[\"ALL\"]|[\"no-new-privileges\",\"apparmor=docker-default\"]|false||private||private|[]|{}" ] \
        || fail 'engine Xvfb preparation container envelope differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{range $i, $m := .Mounts}}{{if $i}}{{println}}{{end}}{{$m.Type}}|{{$m.Source}}|{{$m.Destination}}|{{$m.RW}}{{end}}' "$CONTAINER_ID" | LC_ALL=C sort)"
    [ "$inspect" = "$(printf '%s\n' \
        "bind|$xvfb_scripts/smoke-xvfb-prepare.sh|/work/scripts/smoke-xvfb-prepare.sh|false" \
        "bind|$xvfb_scripts/smoke-xvfb-packages.tsv|/work/scripts/smoke-xvfb-packages.tsv|false" \
        "bind|$xvfb_scripts/smoke-xvfb-files.tsv|/work/scripts/smoke-xvfb-files.tsv|false" \
        "bind|$xvfb_inputs|/xvfb-inputs|false" \
        "bind|$work/debs|/xvfb-debs|true" "bind|$work/root|/xvfb-root|true" | LC_ALL=C sort)" ] \
        || fail 'engine Xvfb preparation mount envelope differs'
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" || status=$?
    [ "$status" -eq 0 ] \
        && [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail "engine Xvfb preparation exited $status"
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
}

run_linux_flutter_engine_prepare() {
    local role mountpoint options load_output inspect principal refusal
    local helper=$VERIFY_REPO/scripts/prepare-flutter-linux-engine.py
    local patch=$VERIFY_REPO/res/flutter/linux-accessibility-retirement.patch
    local test=$VERIFY_REPO/scripts/test-flutter-linux-accessible-retirement.cc
    local archive=/mnt/rustdesk-verifier-inputs/devcheck.docker.tar.gz
    local work=$ROOT/engine-prepare-work helper_before status=0
    local memory=2g memory_bytes=2147483648 cpus=2 nano_cpus=2000000000
    local -a helper_args=() output_mounts=()
    if [ "$MODE" = linux-flutter-engine-build ]; then
        memory=12g; memory_bytes=12884901888; cpus=4; nano_cpus=4000000000
        helper_args=(--build "$ENGINE_PREPARE_COMMIT" "$ENGINE_PREPARE_TREE")
        mkdir /mnt/rustdesk-flutter-engine-output
        mount -t virtiofs -o rw,nodev,nosuid,noexec rustdesk-flutter-engine-output /mnt/rustdesk-flutter-engine-output \
            || fail 'cannot mount inert engine artifact output'
        ENGINE_OUTPUT_MOUNTED=1
        options="$(findmnt -n -o OPTIONS --target /mnt/rustdesk-flutter-engine-output)"
        for option in rw nodev nosuid noexec; do
            case ",$options," in *,$option,*) ;; *) fail "engine output lacks $option" ;; esac
        done
        [ "$(stat -c '%u:%g:%a' -- /mnt/rustdesk-flutter-engine-output)" = 1000:1000:700 ] \
            && [ -z "$(find /mnt/rustdesk-flutter-engine-output -mindepth 1 -print -quit)" ] \
            || fail 'engine output authority differs'
        output_mounts=(
            --mount "type=bind,source=/mnt/rustdesk-flutter-engine-output,target=/output,bind-recursive=disabled"
            --mount "type=bind,source=$VERIFY_REPO/scripts/publish-artifact-result.py,target=/authority/publish.py,readonly"
        )
    fi
    helper_before="$(sha256sum "$helper" "$patch" "$test" "$VERIFY_REPO/scripts/smoke-xvfb-prepare.sh" \
        "$VERIFY_REPO/scripts/smoke-xvfb-packages.tsv" "$VERIFY_REPO/scripts/smoke-xvfb-files.tsv")"
    [ -f "$helper" ] && [ ! -L "$helper" ] || fail 'engine preparation source is absent'
    for principal in 0:0 4001:4001; do
        status=0
        setpriv --reuid="${principal%:*}" --regid="${principal#*:}" --clear-groups \
            /usr/bin/python3 -I -S "$helper" >"$ROOT/engine-principal-refusal" 2>&1 || status=$?
        refusal="$(<"$ROOT/engine-principal-refusal")"
        [ "$status" -eq 1 ] \
            && [ "$refusal" = 'engine preparation: engine preparation requires UID/GID 1000' ] \
            && [ ! -e "$work" ] \
            || fail "engine preparation principal refusal differs: $principal status=$status $refusal"
    done
    printf 'ENGINE_PREPARE_PRINCIPALS=pass root=refused foreign=refused work=absent\n'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$archive")" = "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$archive" | awk '{print $1}')" = "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'engine preparation image archive differs'
    setpriv --reuid=1000 --regid=1000 --clear-groups /bin/bash "$ENTRY_PREFLIGHT"
    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$archive" --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'engine preparation image verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail 'engine preparation image load receipt differs'
    prepare_engine_xvfb
    mkdir "$work"
    chown 1000:1000 "$work"
    local -a mounts=(
        "${output_mounts[@]}"
        --mount "type=bind,source=$helper,target=/authority/prepare.py,readonly"
        --mount "type=bind,source=$patch,target=/authority/retirement.patch,readonly"
        --mount "type=bind,source=$test,target=/authority/node-test.cc,readonly"
        --mount "type=bind,source=$VERIFY_REPO/scripts/pins.env,target=/authority/pins.env,readonly"
        --mount "type=bind,source=$VERIFY_REPO/scripts/smoke-xvfb-files.tsv,target=/authority/xvfb-files.tsv,readonly"
        --mount "type=bind,source=$ROOT/engine-xvfb/root,target=/xvfb-root,readonly,bind-recursive=disabled"
        --mount "type=bind,source=$ROOT/engine-xvfb/root/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly"
        --mount "type=bind,source=$work,target=/work"
    )
    for role in graph git-metadata sysroots; do
        mountpoint="/mnt/rustdesk-engine-$role"
        mkdir "$mountpoint"
        mount -t virtiofs -o ro,nodev,nosuid,noexec "rustdesk-engine-$role" "$mountpoint" \
            || fail "cannot mount the engine $role input"
        ENGINE_INPUT_MOUNTS+=("$mountpoint")
        options="$(findmnt -n -o OPTIONS --target "$mountpoint")"
        for option in ro nodev nosuid noexec; do
            case ",$options," in *,$option,*) ;; *) fail "engine $role input lacks $option" ;; esac
        done
        [ "$(stat -c '%u:%g:%a' -- "$mountpoint")" = 1000:1000:700 ] \
            || fail "engine $role input principal differs"
        mounts+=(--mount "type=bind,source=$mountpoint,target=/inputs/$role,readonly")
    done
    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create --name rustdesk-engine-prepare \
            --pull=never --network=none --read-only --user 1000:1000 \
            --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
            --memory="$memory" --memory-swap="$memory" --cpus="$cpus" --pids-limit=128 \
            --ulimit nofile=1024:1024 --ulimit core=0:0 --ulimit fsize=536870912:536870912 \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=700,uid=1000,gid=1000 \
            --workdir /work "${mounts[@]}" \
            "$DEV_CHECK_IMAGE_CONFIG_ID" /usr/bin/python3 -I -S /authority/prepare.py "${helper_args[@]}"
    )" || fail 'cannot create the confined engine preparation container'
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'engine preparation container ID differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' "$CONTAINER_ID")"
    [ "$inspect" = "$DEV_CHECK_IMAGE_CONFIG_ID|1000:1000|none|true|$memory_bytes|$memory_bytes|$nano_cpus|128|[\"ALL\"]|[\"no-new-privileges\",\"apparmor=docker-default\"]" ] \
        || fail "engine preparation container envelope differs: $inspect"
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' "$CONTAINER_ID")"
    [ "$inspect" = 'false||private||private|[]|{}' ] \
        || fail 'engine preparation namespace/device/port envelope differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{range $i, $m := .Mounts}}{{if $i}}{{println}}{{end}}{{$m.Type}}|{{$m.Source}}|{{$m.Destination}}|{{$m.RW}}{{end}}' "$CONTAINER_ID" \
        | LC_ALL=C sort)"
    local expected_mounts
    expected_mounts="$(printf '%s\n' \
        "bind|$helper|/authority/prepare.py|false" \
        "bind|$patch|/authority/retirement.patch|false" \
        "bind|$test|/authority/node-test.cc|false" \
        "bind|$VERIFY_REPO/scripts/pins.env|/authority/pins.env|false" \
        "bind|$VERIFY_REPO/scripts/smoke-xvfb-files.tsv|/authority/xvfb-files.tsv|false" \
        "bind|$ROOT/engine-xvfb/root|/xvfb-root|false" \
        "bind|$ROOT/engine-xvfb/root/usr/bin/xkbcomp|/usr/bin/xkbcomp|false" \
        "bind|$work|/work|true" \
        'bind|/mnt/rustdesk-engine-graph|/inputs/graph|false' \
        'bind|/mnt/rustdesk-engine-git-metadata|/inputs/git-metadata|false' \
        'bind|/mnt/rustdesk-engine-sysroots|/inputs/sysroots|false')"
    if [ "$MODE" = linux-flutter-engine-build ]; then
        expected_mounts+=$'\n'"bind|/mnt/rustdesk-flutter-engine-output|/output|true"
        expected_mounts+=$'\n'"bind|$VERIFY_REPO/scripts/publish-artifact-result.py|/authority/publish.py|false"
    fi
    [ "$inspect" = "$(printf '%s\n' "$expected_mounts" | LC_ALL=C sort)" ] \
        || fail "engine preparation mount envelope differs: $inspect"
    status=0
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" || status=$?
    [ "$status" -eq 0 ] || fail "engine preparation exited $status"
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'engine preparation container is not successfully terminal'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        && [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'engine preparation left container/image state'
    [ "$(sha256sum "$helper" "$patch" "$test" "$VERIFY_REPO/scripts/smoke-xvfb-prepare.sh" \
        "$VERIFY_REPO/scripts/smoke-xvfb-packages.tsv" "$VERIFY_REPO/scripts/smoke-xvfb-files.tsv")" = "$helper_before" ] \
        || fail 'engine preparation source changed'
    setpriv --reuid=1000 --regid=1000 --clear-groups /bin/bash "$ENTRY_PREFLIGHT"
    stop_docker_authority
    for mountpoint in "${ENGINE_INPUT_MOUNTS[@]}"; do
        umount "$mountpoint" || fail 'cannot retire an engine input mount'
    done
    ENGINE_INPUT_MOUNTS=()
    if [ "$ENGINE_OUTPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-flutter-engine-output || fail 'cannot retire engine artifact output'
        ENGINE_OUTPUT_MOUNTED=0
    fi
    printf 'FLUTTER_ENGINE_PREPARE_VM=pass commit=%s tree=%s helper_sha256=%s runtime=%s uid=1000 gid=1000 inputs=readonly-landlocked vm_network=none container_network=none cleanup=joined\n' \
        "$ENGINE_PREPARE_COMMIT" "$ENGINE_PREPARE_TREE" "$(sha256sum "$helper" | awk '{print $1}')" \
        "$DEV_CHECK_IMAGE_CONFIG_ID"
}

run_fixed_archive_tests() {
    local work work_id helper_sha checker_sha source_before status=0
    local helper=$VERIFY_REPO/scripts/online-fixed-archive-output.py
    local checker=$VERIFY_REPO/scripts/verify-online-fetch-fixed-archive-authority.py
    local output=$ROOT/fixed-archive-tests.out
    local metadata_test=$VERIFY_REPO/scripts/test-verifier-vm-base-metadata.sh
    local -a sources=("$helper" "$checker" "$VERIFY_REPO/scripts/online-fetch.sh"
        "$VERIFY_REPO/scripts/pins.env" "$VERIFY_REPO/scripts/verify.sh"
        "$VERIFY_REPO/scripts/smoke-verifier-vm-authority.sh"
        "$VERIFY_REPO/res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt"
        "$VERIFY_REPO/res/vcpkg/libvpx/windows-tools.sha512" "$metadata_test"
        "$VERIFY_REPO/scripts/verifier-vm-base-metadata.sh"
        "$VERIFY_REPO/scripts/derive-verifier-vm-boot-assets.sh")
    source_before="$(sha256sum "${sources[@]}")"
    helper_sha="$(sha256sum "$helper" | awk '{print $1}')"
    checker_sha="$(sha256sum "$checker" | awk '{print $1}')"
    setpriv --reuid=4000 --regid=4000 --clear-groups /bin/bash "$ENTRY_PREFLIGHT" >/dev/null
    work="$(setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/mktemp -d /tmp/fixed-archive-tests.XXXXXXXXXX)" \
        || fail 'cannot create fixed-archive test scratch'
    [ "$(stat -c '%u:%g:%a' -- "$work")" = 4000:4000:700 ] \
        || fail 'fixed-archive test scratch authority differs'
    work_id="$(stat -c '%d:%i' -- "$work")"
    /usr/bin/python3 -B -I -S - "$work" "$work_id" <<'PY'
import os
import stat
import sys

parent = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    metadata = os.fstat(parent)
    if (f"{metadata.st_dev}:{metadata.st_ino}" != sys.argv[2]
            or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (4000, 4000, 0o700)):
        raise RuntimeError("base metadata fixture parent differs")
    for name, uid, gid in (("foreign-uid", 4001, 4000), ("foreign-gid", 4000, 4001)):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o400, dir_fd=parent)
        try:
            payload = b"base-metadata-fixture\n"
            if os.write(descriptor, payload) != len(payload):
                raise RuntimeError("base metadata fixture write was incomplete")
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
finally:
    os.close(parent)
PY
    (
        cd "$VERIFY_REPO" &&
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
            /bin/bash "$metadata_test" "$work" &&
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
            /usr/bin/python3 -B -I -S "$checker" --self-test &&
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
            /usr/bin/python3 -B -I -S "$helper" self-test
    ) >"$output" 2>&1 || status=$?
    [ "$(stat -c '%s' -- "$output")" -le 65536 ] \
        || fail 'fixed-archive test diagnostics exceeded their bound'
    [ "$status" -eq 0 ] \
        || { tail -n 80 "$output" >&2; fail "fixed-archive tests failed with status $status"; }
    [ "$(grep -Fxc 'fixed archive transaction self-test: PASS' "$output")" -eq 1 ] \
        && [ "$(grep -Ec '^fixed archive authority mutations: PASS \([1-9][0-9]*\)$' "$output")" -eq 1 ] \
        && [ "$(grep -Fxc 'VERIFIER_VM_BASE_METADATA=pass cases=22 profiles=400,444 source=production metadata=actual cleanup=joined' "$output")" -eq 1 ] \
        && [ "$(wc -l <"$output")" -eq 3 ] \
        || fail 'fixed-archive test results are missing, duplicated or unexpected'
    [ "$(sha256sum "${sources[@]}")" = "$source_before" ] \
        || fail 'fixed-archive test source changed during execution'
    setpriv --reuid=4000 --regid=4000 --clear-groups /bin/bash "$ENTRY_PREFLIGHT" >/dev/null
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        && [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'fixed-archive tests left a container or image'
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -B -I -S "$VERIFY_REPO/scripts/verify-private-tree-closure.py" \
        --remove-empty-private-root "$work" --expected-identity "$work_id" \
        || fail 'fixed-archive test scratch could not be retired'
    [ ! -e "$work" ] && [ ! -L "$work" ] || fail 'fixed-archive test scratch remains'
    stop_docker_authority
    cat "$output"
    printf 'FIXED_ARCHIVE_TESTS_VM=pass uid=4000 gid=4000 helper_sha256=%s checker_sha256=%s source=readonly responses=injected filesystem=actual network=none docker=retired scratch=retired cleanup=joined\n' \
        "$helper_sha" "$checker_sha"
}

run_linux_flutter_artifact_tests() {
    local work work_id principal refusal status source_before test_sha helper_sha context entry
    local test=$VERIFY_REPO/scripts/test-linux-flutter-artifact.py
    local helper=$VERIFY_REPO/scripts/linux-flutter-artifact.py
    local output=$ROOT/linux-flutter-artifact-tests.out
    local receipt='LINUX_FLUTTER_ARTIFACT=pass fixture=system-elf-and-assets cases=23 publication=noclobber admission=exact execution=guest-only cleanup=joined'
    local -a sources=("$test" "$helper" "$ENTRY_PREFLIGHT"
        "$VERIFY_REPO/scripts/publish-artifact-result.py"
        "$VERIFY_REPO/scripts/verify-private-tree-closure.py"
        "$VERIFY_REPO/scripts/test-verifier-vm-run-admission.sh"
        "$VERIFY_REPO/scripts/smoke-verifier-vm-authority.sh")
    local -a command

    source_before="$(sha256sum "${sources[@]}")"
    test_sha="$(sha256sum "$test" | awk '{ print $1 }')"
    helper_sha="$(sha256sum "$helper" | awk '{ print $1 }')"
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT" >/dev/null
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$VERIFY_REPO/scripts/test-verifier-vm-run-admission.sh" \
        || fail 'Linux app build/run admission cases failed'
    work="$(setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/mktemp -d /tmp/linux-flutter-artifact-tests.XXXXXXXXXX)" \
        || fail 'Linux app-capsule test scratch could not be created'
    [[ "$work" =~ ^/tmp/linux-flutter-artifact-tests\.[A-Za-z0-9]{10}$ ]] \
        && [ "$(stat -c '%u:%g:%a' -- "$work")" = 4000:4000:700 ] \
        || fail 'Linux app-capsule test scratch authority differs'
    work_id="$(stat -c '%d:%i' -- "$work")"
    context="$(setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        /usr/bin/python3 -B -I -S - <<'PY'
import json

roles = (
    "rust_archive", "flutter_archive", "flutter_tools_lock", "flutter_project_lock",
    "llvm_archive", "frb_codegen", "vendor_closure", "vendor_config", "vcpkg_closure",
    "pub_cache_closure",
)
print(json.dumps({
    "source_commit": "0" * 40, "source_tree": "0" * 40,
    "builder_config": "sha256:" + "0" * 64, "build_recipe_sha256": "0" * 64,
    "rust_toolchain": "1.75.0-x86_64-unknown-linux-gnu", "flutter_version": "3.47.5",
    "source_date_epoch": "unset", "inputs": {role: "0" * 64 for role in roles},
    "engine": {
        "source_commit": "0" * 40, "source_tree": "0" * 40, "framework_revision": "0" * 40,
        "patch_sha256": "0" * 64, "archive_sha256": "0" * 64, "manifest_sha256": "0" * 64,
        "core": {"bytes": 1, "sha256": "0" * 64}, "icu": {"bytes": 1, "sha256": "0" * 64},
    },
}))
PY
    )" || fail 'Linux app-capsule refusal context could not be constructed'
    for principal in 0 4001; do
        if [ "$principal" -eq 0 ]; then
            refusal='verifier-VM entry preflight: the verifier principal must not be root'
        else
            refusal='verifier-VM entry preflight: VM Docker channel metadata differs'
        fi
        for entry in test materializer; do
            command=(python3 -B -I -S)
            if [ "$entry" = test ]; then
                command+=("$test")
            else
                command+=("$helper" materialize --context "$context"
                    --root "$work/unopened" --root-identity 1:1
                    --parent "$work" --parent-identity "$work_id"
                    --manifest-sha256 0000000000000000000000000000000000000000000000000000000000000000)
            fi
            status=0
            setpriv --reuid="$principal" --regid="$principal" --clear-groups \
                env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
                "${command[@]}" \
                >"$ROOT/linux-flutter-refusal-$entry-$principal.out" \
                2>"$ROOT/linux-flutter-refusal-$entry-$principal.err" || status=$?
            [ "$status" -eq 1 ] && [ ! -s "$ROOT/linux-flutter-refusal-$entry-$principal.out" ] \
                && [ "$(stat -c '%s' -- "$ROOT/linux-flutter-refusal-$entry-$principal.err")" -le 8192 ] \
                && grep -Fxq "$refusal" "$ROOT/linux-flutter-refusal-$entry-$principal.err" \
                || fail "Linux app-capsule $entry refusal differs for UID $principal"
            [ -z "$(find "$work" -mindepth 1 -print -quit)" ] \
                && [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
                && [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
                || fail 'refused Linux app-capsule entry changed scratch or Docker inventory'
        done
    done
    status=0
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
        python3 -B -I -S "$test" >"$output" 2>&1 || status=$?
    [ "$(stat -c '%s' -- "$output")" -le 65536 ] \
        || fail 'Linux app-capsule test output exceeds its bound'
    [ "$status" -eq 0 ] \
        || { tail -n 80 "$output" >&2; fail "Linux app-capsule tests exited with status $status"; }
    grep -Fxq "$receipt" "$output" \
        && [ "$(grep -Fc 'LINUX_FLUTTER_ARTIFACT=' "$output")" -eq 1 ] \
        || fail 'Linux app-capsule result is absent, malformed or duplicated'
    [ "$(sha256sum "${sources[@]}")" = "$source_before" ] \
        || fail 'Linux app-capsule admitted source changed'
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT" >/dev/null
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        && [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Linux app-capsule tests left a container or image'
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        python3 -B -I -S "$VERIFY_REPO/scripts/verify-private-tree-closure.py" \
            --remove-empty-private-root "$work" --expected-identity "$work_id" \
        || fail 'Linux app-capsule test scratch could not be retired'
    [ ! -e "$work" ] && [ ! -L "$work" ] \
        || fail 'Linux app-capsule scratch remains after retirement'
    stop_docker_authority
    cat "$output"
    printf 'LINUX_FLUTTER_ARTIFACT_TESTS_VM=pass cases=23 uid=4000 gid=4000 root=refused foreign=refused materializer=refused-before-files test_sha256=%s helper_sha256=%s source=readonly docker=retired network=none cleanup=joined\n' \
        "$test_sha" "$helper_sha"
}

mount_android_runtime_failure_output() {
    local root=/mnt/rustdesk-android-runtime-failure options
    mkdir "$root" || fail 'cannot create the Android failure-output mountpoint'
    mount -t virtiofs -o rw,nodev,nosuid,noexec rustdesk-android-runtime-failure "$root" \
        || fail 'cannot mount the Android failure-output authority'
    ANDROID_RUNTIME_FAILURE_MOUNTED=1
    options="$(findmnt -n -o OPTIONS --target "$root")" || fail 'Android failure-output mount is absent'
    for option in rw nodev nosuid noexec; do
        case ",$options," in *,$option,*) ;; *) fail "Android failure-output mount lacks $option" ;; esac
    done
    [ "$(stat -c '%u:%g:%a' "$root")" = 1000:1000:700 ] \
        && [ -z "$(find "$root" -mindepth 1 -print -quit)" ] \
        || fail 'Android failure-output root is not a fresh private authority'
}

run_android_runtime_log_tests() {
    local work work_id
    local test=$VERIFY_REPO/scripts/test-android-runtime-progress.py
    local wrapper=$VERIFY_REPO/scripts/android-emulator-runtime-check.sh
    local stage=$VERIFY_REPO/scripts/smoke-android-emulator-boot.sh
    local test_sha wrapper_sha stage_sha image principal refusal status
    local output=$ROOT/android-runtime-log-tests.out
    local unit_receipt='ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof diagnostics=filtered cardinality=1 children=joined'
    local native_receipt='ANDROID_RUNTIME_DOCKER_LOG=pass cases=3 before_eof=observed normal=joined failure=live-log-bound producer=term-stopped cancel=143 pipeline=joined workspace=removed image=caller-owned'
    local stage_receipt='ANDROID_PEER_WARM_STAGE_TEST=pass cases=9 warm_owner=preserved warm_peak=monotone task_owner=fresh missing=refused cardinality=13'
    local ui_receipt='ANDROID_PEER_UI_FINALITY_TEST=pass cases=5 empty=refused foreign=refused disabled=refused residual=refused observed=required'
    local failure_test_receipt='ANDROID_RUNTIME_FAILURE_LOG_TEST=pass cases=7 bytes=1048576 equality=exact oversized=refused symlink=refused hardlink=refused mode=refused occupied=preserved'
    local serial_receipt='VERIFIER_SERIAL_ARCHIVE_TEST=pass cases=4 exact=retained occupied=preserved symlink=refused overflow=bounded'
    local export_work export_work_id export_receipt export_bytes export_sha

    test_sha="$(sha256sum "$test" | awk '{ print $1 }')"
    wrapper_sha="$(sha256sum "$wrapper" | awk '{ print $1 }')"
    stage_sha="$(sha256sum "$stage" | awk '{ print $1 }')"
    prepare_authority_probe_image
    image="$(<"$ROOT/image-id")"
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT" >/dev/null
    work="$(setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/mktemp -d /tmp/android-runtime-log-tests.XXXXXXXXXX)" \
        || fail 'runtime-log test scratch could not be created'
    [[ "$work" =~ ^/tmp/android-runtime-log-tests\.[A-Za-z0-9]{10}$ ]] \
        && [ "$(stat -c '%u:%g:%a' -- "$work")" = 4000:4000:700 ] \
        || fail 'runtime-log test scratch authority differs'
    work_id="$(stat -c '%d:%i' -- "$work")"
    for principal in 0 4001; do
        if [ "$principal" -eq 0 ]; then
            refusal='verifier-VM entry preflight: the verifier principal must not be root'
        else
            refusal='verifier-VM entry preflight: VM Docker channel metadata differs'
        fi
        status=0
        setpriv --reuid="$principal" --regid="$principal" --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
            python3 -B -I -S "$test" --native-docker "$image" \
            >"$ROOT/runtime-log-$principal.out" 2>"$ROOT/runtime-log-$principal.err" \
            || status=$?
        [ "$status" -eq 1 ] && [ ! -s "$ROOT/runtime-log-$principal.out" ] \
            && [ "$(stat -c '%s' -- "$ROOT/runtime-log-$principal.err")" -le 8192 ] \
            && grep -Fxq "$refusal" "$ROOT/runtime-log-$principal.err" \
            || fail "runtime-log entry refusal differs for UID $principal"
        [ -z "$(find "$work" -mindepth 1 -print -quit)" ] \
            && [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
            && [ "$("$CLIENT" --host "unix://$SOCK" image ls -aq --no-trunc | sort -u)" = "$image" ] \
            || fail 'refused runtime-log entry changed scratch or Docker inventory'
    done
    status=0
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent TMPDIR="$work" \
        python3 -B -I -S "$test" --native-docker "$image" \
        >"$output" 2>&1 || status=$?
    [ "$(stat -c '%s' -- "$output")" -le 65536 ] \
        || fail 'runtime-log test output exceeds its bound'
    [ "$status" -eq 0 ] \
        || { tail -n 80 "$output" >&2; fail "runtime-log tests exited with status $status"; }
    grep -Fxq "$unit_receipt" "$output" \
        && [ "$(grep -Fc 'ANDROID_RUNTIME_PROGRESS_TEST=' "$output")" -eq 1 ] \
        && grep -Fxq "$native_receipt" "$output" \
        && [ "$(grep -Fc 'ANDROID_RUNTIME_DOCKER_LOG=' "$output")" -eq 1 ] \
        && grep -Fxq "$stage_receipt" "$output" \
        && [ "$(grep -Fc 'ANDROID_PEER_WARM_STAGE_TEST=' "$output")" -eq 1 ] \
        && grep -Fxq "$ui_receipt" "$output" \
        && [ "$(grep -Fc 'ANDROID_PEER_UI_FINALITY_TEST=' "$output")" -eq 1 ] \
        && grep -Fxq "$failure_test_receipt" "$output" \
        && [ "$(grep -Fc 'ANDROID_RUNTIME_FAILURE_LOG_TEST=' "$output")" -eq 1 ] \
        && grep -Fxq "$serial_receipt" "$output" \
        && [ "$(grep -Fc 'VERIFIER_SERIAL_ARCHIVE_TEST=' "$output")" -eq 1 ] \
        || fail 'runtime-log test results are absent, malformed or duplicated'
    [ "$(sha256sum "$test" | awk '{ print $1 }')" = "$test_sha" ] \
        && [ "$(sha256sum "$wrapper" | awk '{ print $1 }')" = "$wrapper_sha" ] \
        && [ "$(sha256sum "$stage" | awk '{ print $1 }')" = "$stage_sha" ] \
        || fail 'runtime-log test or production wrapper source changed'
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'runtime-log tests left a container'
    frame_docker image rm "$image" >/dev/null \
        || fail 'runtime-log fixture image could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'runtime-log tests left an image'
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        python3 -B -I -S "$VERIFY_REPO/scripts/verify-private-tree-closure.py" \
            --remove-empty-private-root "$work" --expected-identity "$work_id" \
        || fail 'runtime-log test scratch could not be retired'
    [ ! -e "$work" ] && [ ! -L "$work" ] \
        || fail 'runtime-log scratch remains after retirement'
    mount_android_runtime_failure_output
    export_work="$(mktemp -d /tmp/android-failure-export.XXXXXXXXXX)" \
        || fail 'cannot create the failure-export fixture'
    export_work_id="$(stat -c '%d:%i' "$export_work")"
    awk '
        /^preserve_runtime_failure_log\(\) \{$/ { found++; copy = 1 }
        copy { print; if ($0 == "}") copy = 0 }
        END { if (found != 1 || copy) exit 1 }
    ' "$wrapper" >"$export_work/publish.sh" || fail 'cannot extract the actual failure-log publisher'
    printf '%s\n' 'preserve_runtime_failure_log "$1" "$2"' >>"$export_work/publish.sh"
    printf 'ANDROID_PEER_WINDOW_DIAGNOSTIC_BEGIN phase=fixture\nfocus=fixture\nANDROID_PEER_WINDOW_DIAGNOSTIC_END phase=fixture\n' >"$export_work/runtime.log"
    chown -R 1000:1000 "$export_work"
    chmod 400 "$export_work/publish.sh"
    chmod 600 "$export_work/runtime.log"
    export_bytes="$(stat -c '%s' "$export_work/runtime.log")"
    export_sha="$(sha256sum "$export_work/runtime.log" | awk '{ print $1 }')"
    export_receipt="$(setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        /bin/bash --noprofile --norc -euo pipefail "$export_work/publish.sh" \
        "$export_work/runtime.log" /mnt/rustdesk-android-runtime-failure)" \
        || fail 'actual failure-log publisher did not acknowledge the native output mount'
    [ "$export_receipt" = "ANDROID_RUNTIME_FAILURE_LOG=retained bytes=$export_bytes sha256=$export_sha verdict_input=false" ] \
        || fail 'failure-log publisher acknowledgement differs'
    cmp "$export_work/runtime.log" /mnt/rustdesk-android-runtime-failure/android-runtime-failure.log \
        || fail 'native failure-export fixture bytes differ'
    umount /mnt/rustdesk-android-runtime-failure || fail 'cannot retire the failure-output fixture mount'
    ANDROID_RUNTIME_FAILURE_MOUNTED=0
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        python3 -B -I -S "$VERIFY_REPO/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$export_work" --expected-identity "$export_work_id" \
        || fail 'cannot retire the failure-export fixture scratch'
    stop_docker_authority
    printf '%s\n' "$unit_receipt" "$native_receipt" "$stage_receipt" "$ui_receipt" "$failure_test_receipt" "$serial_receipt"
    printf 'ANDROID_RUNTIME_FAILURE_EXPORT_VM=pass bytes=%s sha256=%s fsync=acknowledged mount=retired uid=1000 gid=1000\n' "$export_bytes" "$export_sha"
    printf 'ANDROID_RUNTIME_LOG_TESTS_VM=pass cases=3 stage_cases=9 uid=4000 gid=4000 root=refused foreign=refused test_sha256=%s wrapper_sha256=%s stage_sha256=%s image=retired docker=retired network=none cleanup=joined\n' \
        "$test_sha" "$wrapper_sha" "$stage_sha"
}

run_android_frame_tests() {
    local inputs=/mnt/rustdesk-verifier-inputs
    local work=$ROOT/android-frame-tests load_output phase profile
    local output=$ROOT/android-frame-tests.out status=0
    local native_script=test-android-frame-native.py
    local native_receipt='ANDROID_FRAME_NATIVE=pass source=x11 pixels=actual counter=uint32 age=monotonic whole_cycle=refused network=none uid=4000 cleanup=joined'
    if [ "$MODE" = x11-display-tests ]; then
        native_script=test-x11-display-native.py
        native_receipt='X11_DISPLAY_NATIVE=pass source=production-component xcb=real old=refused screens=2 repeat=32 drop=exact query_error=explicit public_callers=executed allocator_reuse=unclaimed network=none uid=4000 cleanup=joined'
    fi
    if [ "${X11_CLIPBOARD_ONLY:-0}" -eq 1 ]; then
        native_script=test-native-clipboard-listener.py
        native_receipt='CLIPBOARD_LISTENER_NATIVE=pass scope=linux-component source=production master=pinned callbacks=actual old=retained current=joined late_admission=refused startup_observer=retired tests=9 network=none cleanup=joined'
    fi
    local -a mounts command
    load_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$inputs/devcheck.docker.tar.gz" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'Android frame-test certified image could not be loaded'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail 'Android frame-test image load receipt differs'
    install -d -o 4000 -g 4000 -m 0700 "$work" "$work/xvfb-debs" "$work/xvfb-root"
    for phase in prepare native; do
        mounts=(--mount "type=bind,src=$VERIFY_REPO,dst=/work,readonly,bind-recursive=disabled")
        if [ "$phase" = prepare ]; then
            mounts+=(
                --mount "type=bind,src=$inputs/xvfb-debs,dst=/xvfb-inputs,readonly,bind-recursive=disabled"
                --mount "type=bind,src=$work/xvfb-debs,dst=/xvfb-debs,bind-recursive=disabled"
                --mount "type=bind,src=$work/xvfb-root,dst=/xvfb-root,bind-recursive=disabled"
            )
            command=(/bin/bash /work/scripts/smoke-xvfb-prepare.sh)
        else
            local build_size=16m
            if [ "${X11_CLIPBOARD_ONLY:-0}" -eq 1 ]; then
                build_size=512m
            fi
            mounts+=(
                --mount "type=bind,src=$work/xvfb-root,dst=/xvfb-root,readonly,bind-recursive=disabled"
                --mount "type=bind,src=$work/xvfb-root/usr/bin/xkbcomp,dst=/usr/bin/xkbcomp,readonly"
                --tmpfs "/build:rw,exec,nosuid,nodev,size=$build_size,mode=700,uid=4000,gid=4000"
            )
            command=(/usr/bin/python3 -B -I -S "/work/scripts/$native_script")
        fi
        CONTAINER_ID="$(frame_docker create --name "rustdesk-android-frame-$phase" \
            --pull never --network none --user 4000:4000 --read-only --cap-drop ALL \
            --security-opt no-new-privileges --security-opt apparmor=docker-default \
            --cpus 2 --memory 1g --memory-swap 1g --pids-limit 128 \
            --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=700,uid=4000,gid=4000 \
            --env LC_ALL=C --workdir /tmp "${mounts[@]}" --entrypoint '' \
            "$DEV_CHECK_IMAGE_CONFIG_ID" "${command[@]}")" \
            || fail 'Android frame-test container could not be created'
        [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'Android frame-test container identity differs'
        profile="$(frame_docker inspect --format \
            '{{.HostConfig.NetworkMode}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' "$CONTAINER_ID")"
        [ "$profile" = 'none|false|true|4000:4000|1073741824|1073741824|2000000000|128|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]||private||private' ] \
            || fail 'Android frame-test container confinement differs'
        printf 'ANDROID_FRAME_TESTS_PROGRESS stage=%s\n' "$phase"
        status=0
        frame_docker start --attach "$CONTAINER_ID" 2>&1 | tee "$output" || status=$?
        [ "$status" -eq 0 ] && [ "$(stat -c '%s' -- "$output")" -le 65536 ] \
            || fail 'Android frame-test container failed or exceeded output bound'
        [ "$(frame_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
            || fail 'Android frame-test container did not finish cleanly'
        if [ "$phase" = native ]; then
            [ "$(grep -Fxc "$native_receipt" "$output")" -eq 1 ] \
                || fail 'Android native frame-test result is absent or duplicated'
            if [ "$MODE" = x11-display-tests ] && [ "${X11_CLIPBOARD_ONLY:-0}" -eq 0 ]; then
                [ "$(grep -Fxc 'X11_LAYOUT_NATIVE=pass xvfb_depths=24,16 stride_16_odd=1284 pixels=actual capture=production-shm public=production-buffer network=none uid=4000 cleanup=joined' "$output")" -eq 1 ] \
                    || fail 'X11 capture-layout native result is absent or duplicated'
            fi
        fi
        frame_docker rm "$CONTAINER_ID" >/dev/null || fail 'Android frame-test container retirement failed'
        CONTAINER_ID=
    done
    stop_docker_authority
    if [ "${X11_CLIPBOARD_ONLY:-0}" -eq 1 ]; then
        printf 'CLIPBOARD_LISTENER_TESTS_VM=pass image=devcheck source=readonly docker=retired containers=joined\n'
    elif [ "$MODE" = x11-display-tests ]; then
        printf 'X11_DISPLAY_TESTS_VM=pass image=devcheck source=readonly docker=retired containers=joined\n'
    else
        printf 'ANDROID_FRAME_TESTS_VM=pass image=devcheck source=readonly docker=retired containers=joined\n'
    fi
}

network_inventory() {
    awk 'FNR > 1 { print FILENAME ":" $2 ":" $4 }' \
        /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null \
        | LC_ALL=C sort -u
}

stop_docker_authority() {
    local daemon_status=0
    [ -n "$DAEMON_PID" ] || fail 'Docker daemon identity is absent at shutdown'
    kill -TERM "$DAEMON_PID" || fail 'cannot signal the exact guest Docker daemon'
    wait "$DAEMON_PID" || daemon_status=$?
    [ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] \
        || fail "Docker daemon shutdown returned $daemon_status"
    DAEMON_PID=
    [ ! -S "$SOCK" ] || fail 'Docker Unix socket remains after joined daemon shutdown'
    network_inventory >"$ROOT.network-after"
    cmp -s "$ROOT.network-before" "$ROOT.network-after" \
        || fail 'guest network state changed across Docker execution'
    [ ! -e /sys/class/net/docker0 ] || fail 'Docker bridge remains after shutdown'
}

run_debian_systemd_lifecycle() {
    local lifecycle_root=/var/tmp/rustdesk-systemd-lifecycle
    local extracted=$lifecycle_root/artifact-root
    local libraries=$lifecycle_root/runtime-libs
    local binary=$extracted/usr/share/rustdesk/rustdesk
    local archive_before artifact_before load_output stage_output stage_count stage_bytes
    local -a stage_receipt=()
    local lifecycle_network_before lifecycle_network_after

    [[ "$LIFECYCLE_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'lifecycle artifact SHA-256 is malformed'
    [[ "$LIFECYCLE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'lifecycle source commit is malformed'
    [ -f "$DEV_CHECK_ARCHIVE" ] && [ ! -L "$DEV_CHECK_ARCHIVE" ] \
        || fail 'devcheck archive is absent from read-only payload media'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$DEV_CHECK_ARCHIVE")" = \
      "4000:4000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'devcheck archive payload metadata differs'
    [ "$(sha256sum "$DEV_CHECK_ARCHIVE" | awk '{ print $1 }')" = \
      "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'devcheck archive payload digest differs'
    [ -f "$LIFECYCLE_ARTIFACT" ] && [ ! -L "$LIFECYCLE_ARTIFACT" ] \
        || fail 'lifecycle artifact is absent from read-only payload media'
    [ "$(stat -c '%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")" = 4000:4000:400:1 ] \
        || fail 'lifecycle artifact payload metadata differs'
    [ "$(sha256sum "$LIFECYCLE_ARTIFACT" | awk '{ print $1 }')" = \
      "$LIFECYCLE_ARTIFACT_SHA256" ] \
        || fail 'lifecycle artifact payload digest differs'
    archive_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DEV_CHECK_ARCHIVE"):$(sha256sum "$DEV_CHECK_ARCHIVE")"
    artifact_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$LIFECYCLE_ARTIFACT"):$(sha256sum "$LIFECYCLE_ARTIFACT")"

    load_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$DEV_CHECK_ARCHIVE" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'devcheck archive verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail "devcheck archive verification/load receipt differs: $load_output"

    mkdir -p "$extracted"
    chmod 0711 "$lifecycle_root" "$extracted"
    dpkg-deb -x "$LIFECYCLE_ARTIFACT" "$extracted" \
        || fail 'cannot extract the exact lifecycle artifact inside the guest'
    [ -f "$binary" ] && [ ! -L "$binary" ] && [ -x "$binary" ] \
        || fail 'extracted lifecycle executable is absent or ambiguous'
    chown 0:0 "$binary"
    chmod 0555 "$binary"
    [ "$(stat -c '%u:%g:%a:%h' -- "$binary")" = 0:0:555:1 ] \
        || fail 'extracted lifecycle executable metadata differs'
    mkdir "$libraries"
    chown 4000:4000 "$libraries"
    chmod 0700 "$libraries"

    if /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" "$binary" "$libraries" \
        >"$lifecycle_root/root-stage.out" 2>"$lifecycle_root/root-stage.err"; then
        fail 'VM root passed runtime-library staging entry'
    fi
    [ ! -s "$lifecycle_root/root-stage.out" ] \
        || fail 'root runtime-library refusal produced standard output'
    [ "$(<"$lifecycle_root/root-stage.err")" = \
      'Debian systemd runtime-library staging refuses root execution' ] \
        || fail 'root runtime-library refusal diagnostic differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" "$binary" "$libraries" \
        >"$lifecycle_root/foreign-stage.out" 2>"$lifecycle_root/foreign-stage.err"; then
        fail 'foreign principal passed runtime-library staging entry'
    fi
    [ ! -s "$lifecycle_root/foreign-stage.out" ] \
        || fail 'foreign runtime-library refusal produced standard output'
    [ "$(<"$lifecycle_root/foreign-stage.err")" = \
      'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign runtime-library refusal diagnostic differs'
    stage_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" "$binary" "$libraries"
    )" || fail 'authorized runtime-library staging failed'
    mapfile -t stage_receipt <<<"$stage_output"
    [ "${#stage_receipt[@]}" -eq 2 ] \
        && [ "${stage_receipt[0]}" = \
          "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" ] \
        || fail "runtime-library staging authority receipt differs: $stage_output"
    if [[ "${stage_receipt[1]}" =~ ^DEBIAN_SYSTEMD_RUNTIME_LIBS=pass\ runtime_image=$DEV_CHECK_IMAGE_CONFIG_ID\ libraries=([0-9]+)\ bytes=([0-9]+)\ input=readonly\ output=private$ ]]; then
        stage_count=${BASH_REMATCH[1]}
        stage_bytes=${BASH_REMATCH[2]}
    else
        fail "runtime-library staging result receipt differs: $stage_output"
    fi
    [ "$stage_count" -ge 60 ] && [ "$stage_count" -le 256 ] \
        && [ "$stage_bytes" -gt 0 ] && [ "$stage_bytes" -le 1073741824 ] \
        || fail 'runtime-library staging receipt bounds differ'

    chown 0:0 "$libraries" "$libraries"/*
    chmod 0444 "$libraries"/*
    chmod 0555 "$libraries"
    [ -z "$(find "$libraries" -mindepth 1 -maxdepth 1 \
        \( ! -type f -o ! -uid 0 -o ! -gid 0 -o ! -perm 0444 -o -links +1 \) -print -quit)" ] \
        || fail 'sealed runtime-library inventory differs'

    stop_docker_authority
    network_inventory >"$lifecycle_root.network-before"
    lifecycle_network_before="$(sha256sum "$lifecycle_root.network-before")"
    mount --bind "$libraries" "$libraries"
    mount -o remount,bind,ro,nodev,nosuid,noexec "$libraries"
    LIFECYCLE_LIBS_MOUNTED=1
    /bin/bash "$SYSTEMD_LIFECYCLE_SCRIPT" --release-deb \
        "$VERIFY_REPO" "$libraries" "$LIFECYCLE_ARTIFACT" \
        "$LIFECYCLE_ARTIFACT_SHA256" "$LIFECYCLE_COMMIT" \
        || fail 'installed Debian artifact lifecycle failed'
    umount "$libraries" || fail 'cannot retire the read-only runtime-library mount'
    LIFECYCLE_LIBS_MOUNTED=0
    network_inventory >"$lifecycle_root.network-after"
    lifecycle_network_after="$(sha256sum "$lifecycle_root.network-after")"
    [ "$lifecycle_network_after" = "$lifecycle_network_before" ] \
        || fail 'installed lifecycle left guest network state behind'
    [ "$archive_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DEV_CHECK_ARCHIVE"):$(sha256sum "$DEV_CHECK_ARCHIVE")" ] \
        || fail 'devcheck archive changed across the installed lifecycle'
    [ "$artifact_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$LIFECYCLE_ARTIFACT"):$(sha256sum "$LIFECYCLE_ARTIFACT")" ] \
        || fail 'release artifact changed across the installed lifecycle'
    printf 'VERIFIER_VM_DEBIAN_SYSTEMD_LIFECYCLE=pass artifact_sha256=%s commit=%s staging_uid=4000 root=refused foreign=refused docker=retired network=none cleanup=joined\n' \
        "$LIFECYCLE_ARTIFACT_SHA256" "$LIFECYCLE_COMMIT"
}

run_dart_audit() {
    local source_root=$ROOT/dart-audit-source
    local audit_output load_output source_archive_sha source_before image_before
    local lock_sha policy_sha
    local expected_entry="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root"
    local expected_green='VERIFY-DART-AUDIT: green — exact OSV status, telemetry, and structured results contain no unignored advisories against the pinned current Pub snapshot (R-R3/R-S11be)'

    [[ "$DART_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Dart-audit source commit is malformed'
    [[ "$DART_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Dart-audit source tree is malformed'
    [[ "$DART_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Dart-audit source archive digest is malformed'
    [ -f "$DART_SOURCE_ARCHIVE" ] && [ ! -L "$DART_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$DART_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'focused Dart-audit source archive metadata differs'
    source_archive_sha="$(sha256sum "$DART_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$DART_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Dart-audit source archive digest differs'
    [ -f "$DART_AUDIT_IMAGE_ARCHIVE" ] && [ ! -L "$DART_AUDIT_IMAGE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE")" = \
             "4000:4000:400:1:$SIZE_DART_AUDIT_IMAGE_ARCHIVE" ] \
        || fail 'focused Dart-audit image archive metadata differs'
    [ "$(sha256sum "$DART_AUDIT_IMAGE_ARCHIVE" | awk '{ print $1 }')" = \
      "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" ] \
        || fail 'focused Dart-audit image archive digest differs'
    image_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE"):$(sha256sum "$DART_AUDIT_IMAGE_ARCHIVE")"

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$DART_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact focused Dart-audit source archive'
    chmod -R u=rwX,go=rX "$source_root" \
        || fail 'cannot seal the focused Dart-audit source as root-owned read-only input'
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'focused Dart-audit source archive differs from its guest bootstrap'
    for source_path in \
        "$source_root/flutter/pubspec.lock" \
        "$source_root/scripts/dart-audit-ignores.txt" \
        "$source_root/scripts/dart-audit-result.py" \
        "$source_root/scripts/dart-audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh"; do
        [ -f "$source_path" ] && [ ! -L "$source_path" ] \
            || fail "focused Dart-audit source is absent or ambiguous: $source_path"
        [ "$(stat -c '%u:%g:%h' -- "$source_path")" = 0:0:1 ] \
            || fail "focused Dart-audit source authority differs: $source_path"
    done
    [ -z "$(find "$source_root" -mindepth 1 \( -uid 4000 -o -gid 4000 \) -print -quit)" ] \
        || fail 'focused Dart-audit extracted source is writable by the verifier principal'
    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/flutter/pubspec.lock" \
        "$source_root/scripts/dart-audit-ignores.txt" \
        "$source_root/scripts/dart-audit-result.py" \
        "$source_root/scripts/dart-audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh")"
    lock_sha="$(sha256sum "$source_root/flutter/pubspec.lock" | awk '{ print $1 }')"
    policy_sha="$(sha256sum "$source_root/scripts/dart-audit-ignores.txt" | awk '{ print $1 }')"

    entry_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/verify-vm-entry-preflight.sh"
    )" || fail 'focused Dart-audit pre-load VM authority check failed'
    [ "$entry_output" = "$expected_entry" ] \
        || fail "focused Dart-audit pre-load authority receipt differs: $entry_output"
    load_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$source_root/scripts/offline-image-provenance.py" \
                verify-load \
                --archive "$DART_AUDIT_IMAGE_ARCHIVE" \
                --archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" \
                --role dart-audit \
                --expected-id "$DART_AUDIT_IMAGE_ID" \
                --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
                --dockerfile-sha "$SHA256_DART_AUDIT_DOCKERFILE" \
                --scanner-sha "$OSV_SCANNER_SHA256" \
                --scanner-version "$OSV_SCANNER_VERSION" \
                --scalibr-version "$OSV_SCALIBR_VERSION" \
                --scanner-commit "$OSV_SCANNER_COMMIT" \
                --scanner-built-at "$OSV_SCANNER_BUILT_AT" \
                --database-sha "$OSV_DB_PUB_SHA256" \
                --database-size "$OSV_DB_PUB_SIZE" \
                --database-capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH" \
                --database-generation "$OSV_DB_PUB_GENERATION" \
                --config-id "$DART_AUDIT_IMAGE_CONFIG_ID" \
                --manifest-id "$DART_AUDIT_IMAGE_MANIFEST_ID"
    )" || fail 'focused Dart-audit image verification/load failed'
    [ "$load_output" = "loaded and verified dart-audit $DART_AUDIT_IMAGE_ID" ] \
        || fail "focused Dart-audit image load receipt differs: $load_output"
    entry_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/verify-vm-entry-preflight.sh"
    )" || fail 'focused Dart-audit post-load VM authority check failed'
    [ "$entry_output" = "$expected_entry" ] \
        || fail "focused Dart-audit post-load authority receipt differs: $entry_output"

    if /bin/bash "$source_root/scripts/dart-audit.sh" \
        >"$ROOT/root-dart-audit.out" 2>"$ROOT/root-dart-audit.err"; then
        fail 'VM root passed the focused Dart-audit entry'
    fi
    [ ! -s "$ROOT/root-dart-audit.out" ] \
        || fail 'root focused Dart-audit refusal produced standard output'
    [ "$(<"$ROOT/root-dart-audit.err")" = \
      'dart-audit.sh: refuses host or container-root execution' ] \
        || fail 'root focused Dart-audit refusal diagnostic differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/dart-audit.sh" \
        >"$ROOT/foreign-dart-audit.out" 2>"$ROOT/foreign-dart-audit.err"; then
        fail 'foreign principal passed the focused Dart-audit entry'
    fi
    [ ! -s "$ROOT/foreign-dart-audit.out" ] \
        || fail 'foreign focused Dart-audit refusal produced standard output'
    [ "$(<"$ROOT/foreign-dart-audit.err")" = \
      'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign focused Dart-audit refusal diagnostic differs'

    audit_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/dart-audit.sh"
    )" || fail 'focused Dart advisory scan failed'
    [ "$(grep -Fxc "$expected_entry" <<<"$audit_output")" -eq 1 ] \
        || fail 'focused Dart advisory authority receipt is absent or duplicated'
    [ "$(grep -Fxc "$expected_green" <<<"$audit_output")" -eq 1 ] \
        || fail 'focused Dart advisory green verdict is absent or duplicated'
    [ "$source_before" = "$source_archive_sha:$(sha256sum \
        "$source_root/flutter/pubspec.lock" \
        "$source_root/scripts/dart-audit-ignores.txt" \
        "$source_root/scripts/dart-audit-result.py" \
        "$source_root/scripts/dart-audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh")" ] \
        || fail 'focused Dart-audit source changed during execution'
    [ "$image_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE"):$(sha256sum "$DART_AUDIT_IMAGE_ARCHIVE")" ] \
        || fail 'focused Dart-audit image archive changed during execution'
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'focused Dart audit left a container behind'
    "$CLIENT" --host "unix://$SOCK" image rm "$DART_AUDIT_IMAGE_CONFIG_ID" >/dev/null \
        || fail 'cannot retire the focused Dart-audit image'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'focused Dart audit left a Docker image behind'
    stop_docker_authority
    printf '%s\n' "$audit_output"
    printf 'DART_AUDIT_VM=pass commit=%s tree=%s image=%s runtime=%s lock=%s policy=%s uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused source=readonly cleanup=joined\n' \
        "$DART_SOURCE_COMMIT" "$DART_SOURCE_TREE" "$DART_AUDIT_IMAGE_ID" \
        "$DART_AUDIT_IMAGE_CONFIG_ID" "$lock_sha" "$policy_sha"
}

run_rust_audit() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/rust-audit-source
    local vendor=$inputs/cargo-vendor
    local vendor_config=$inputs/cargo-vendor-config.toml
    local projected_vendor=$source_root/online/cargo-vendor
    local projected_config=$source_root/online/cargo-vendor-config.toml
    local audit_output entry_output load_output source_archive_sha source_before image_before
    local input_mount_options vendor_mount_options lock_sha policy_sha
    local expected_entry="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root"
    local expected_green='VERIFY-AUDIT: green — immutable-image cargo-audit and cargo-deny completed offline against one current pinned RustSec snapshot with exact reasoned accepts (R-R3/R-S11bf)'

    [[ "$RUST_AUDIT_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-audit source commit is malformed'
    [[ "$RUST_AUDIT_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-audit source tree is malformed'
    [[ "$RUST_AUDIT_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust-audit source archive digest is malformed'
    [ -f "$RUST_AUDIT_SOURCE_ARCHIVE" ] && [ ! -L "$RUST_AUDIT_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$RUST_AUDIT_SOURCE_ARCHIVE")" = \
             1000:1000:400:1 ] \
        || fail 'focused Rust-audit source archive metadata differs'
    source_archive_sha="$(sha256sum "$RUST_AUDIT_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$RUST_AUDIT_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-audit source archive digest differs'
    [ -f "$RUST_AUDIT_IMAGE_ARCHIVE" ] && [ ! -L "$RUST_AUDIT_IMAGE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$RUST_AUDIT_IMAGE_ARCHIVE")" = \
             "1000:1000:400:1:$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" ] \
        || fail 'focused Rust-audit image archive metadata differs'
    [ "$(sha256sum "$RUST_AUDIT_IMAGE_ARCHIVE" | awk '{ print $1 }')" = \
      "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" ] \
        || fail 'focused Rust-audit image archive digest differs'
    image_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RUST_AUDIT_IMAGE_ARCHIVE"):$(sha256sum "$RUST_AUDIT_IMAGE_ARCHIVE")"

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$RUST_AUDIT_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact focused Rust-audit source archive'
    mkdir -p "$projected_vendor"
    chmod -R u=rwX,go=rX "$source_root" \
        || fail 'cannot seal the focused Rust-audit source as root-owned read-only input'
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'focused Rust-audit source archive differs from its guest bootstrap'
    for source_path in \
        "$source_root/Cargo.lock" \
        "$source_root/deny.toml" \
        "$source_root/scripts/audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/online-input-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/rust-audit-policy.py" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh"; do
        [ -f "$source_path" ] && [ ! -L "$source_path" ] \
            || fail "focused Rust-audit source is absent or ambiguous: $source_path"
        [ "$(stat -c '%u:%g:%h' -- "$source_path")" = 0:0:1 ] \
            || fail "focused Rust-audit source authority differs: $source_path"
    done
    [ -z "$(find "$source_root" -mindepth 1 \
        \( -uid 1000 -o -gid 1000 -o -perm /022 \) -print -quit)" ] \
        || fail 'focused Rust-audit extracted source is writable by the verifier principal'

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Rust-audit input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Rust-audit input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Rust-audit inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Rust-audit inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Rust-audit inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed Rust-audit inputs permit direct execution' ;; esac
    [ -d "$vendor" ] && [ ! -L "$vendor" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$vendor")" = 1000:1000:500 ] \
        || fail 'sealed Rust-audit Cargo vendor root metadata differs'
    [ -f "$vendor_config" ] && [ ! -L "$vendor_config" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$vendor_config")" = \
             "1000:1000:400:1:$SIZE_CARGO_VENDOR_CONFIG" ] \
        && [ "$(sha256sum "$vendor_config" | awk '{ print $1 }')" = \
             "$SHA256_CARGO_VENDOR_CONFIG" ] \
        || fail 'sealed Rust-audit Cargo vendor configuration differs'
    install -o 0 -g 0 -m 0444 -- "$vendor_config" "$projected_config" \
        || fail 'cannot stage the immutable Rust-audit Cargo vendor configuration'
    mount --bind "$vendor" "$projected_vendor" \
        || fail 'cannot project the sealed Rust-audit Cargo vendor closure'
    RUST_AUDIT_VENDOR_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid,noexec "$projected_vendor" \
        || fail 'cannot seal the projected Rust-audit Cargo vendor closure'
    vendor_mount_options="$(findmnt -n -o OPTIONS --target "$projected_vendor")" \
        || fail 'projected Rust-audit Cargo vendor mount is absent'
    case ",$vendor_mount_options," in *,ro,*) ;; *) fail 'projected Rust-audit Cargo vendor is writable' ;; esac
    case ",$vendor_mount_options," in *,nodev,*) ;; *) fail 'projected Rust-audit Cargo vendor permits devices' ;; esac
    case ",$vendor_mount_options," in *,nosuid,*) ;; *) fail 'projected Rust-audit Cargo vendor permits set-user-ID execution' ;; esac
    case ",$vendor_mount_options," in *,noexec,*) ;; *) fail 'projected Rust-audit Cargo vendor permits execution' ;; esac

    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/Cargo.lock" \
        "$source_root/deny.toml" \
        "$source_root/scripts/audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/online-input-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/rust-audit-policy.py" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh" \
        "$projected_config")"
    lock_sha="$(sha256sum "$source_root/Cargo.lock" | awk '{ print $1 }')"
    policy_sha="$(sha256sum "$source_root/deny.toml" | awk '{ print $1 }')"

    entry_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/verify-vm-entry-preflight.sh"
    )" || fail 'focused Rust-audit pre-load VM authority check failed'
    [ "$entry_output" = "$expected_entry" ] \
        || fail "focused Rust-audit pre-load authority receipt differs: $entry_output"
    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$source_root/scripts/offline-image-provenance.py" \
                verify-load \
                --archive "$RUST_AUDIT_IMAGE_ARCHIVE" \
                --archive-sha "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" \
                --role rust-audit \
                --expected-id "$RUST_AUDIT_IMAGE_ID" \
                --base "rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${RUST_AUDIT_BASE_IMAGE_DIGEST}" \
                --dockerfile-sha "$SHA256_RUST_AUDIT_DOCKERFILE" \
                --rust-version "$RUST_AUDIT_RUST_VERSION" \
                --rustc-version "$RUST_AUDIT_RUSTC_VERSION" \
                --cargo-audit-version "$CARGO_AUDIT_VERSION" \
                --cargo-deny-version "$CARGO_DENY_VERSION" \
                --cargo-audit-tag-object "$CARGO_AUDIT_TAG_OBJECT" \
                --cargo-audit-source-commit "$CARGO_AUDIT_SOURCE_COMMIT" \
                --cargo-audit-source-tree "$CARGO_AUDIT_SOURCE_TREE" \
                --cargo-audit-source-archive-sha "$SHA256_CARGO_AUDIT_SOURCE_ARCHIVE" \
                --cargo-audit-signing-key-fingerprint "$CARGO_AUDIT_SIGNING_KEY_FINGERPRINT" \
                --cargo-deny-tag-object "$CARGO_DENY_TAG_OBJECT" \
                --cargo-deny-source-commit "$CARGO_DENY_SOURCE_COMMIT" \
                --cargo-deny-source-tree "$CARGO_DENY_SOURCE_TREE" \
                --cargo-deny-source-archive-sha "$SHA256_CARGO_DENY_SOURCE_ARCHIVE" \
                --cargo-audit-sha "$SHA256_RUST_AUDIT_CARGO_AUDIT" \
                --cargo-deny-sha "$SHA256_RUST_AUDIT_CARGO_DENY" \
                --advisory-db-sha "$ADVISORY_DB_COMMIT" \
                --advisory-db-epoch "$ADVISORY_DB_COMMIT_EPOCH" \
                --config-id "$RUST_AUDIT_IMAGE_CONFIG_ID" \
                --manifest-id "$RUST_AUDIT_IMAGE_MANIFEST_ID"
    )" || fail 'focused Rust-audit image verification/load failed'
    [ "$load_output" = "loaded and verified rust-audit $RUST_AUDIT_IMAGE_ID" ] \
        || fail "focused Rust-audit image load receipt differs: $load_output"
    entry_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/verify-vm-entry-preflight.sh"
    )" || fail 'focused Rust-audit post-load VM authority check failed'
    [ "$entry_output" = "$expected_entry" ] \
        || fail "focused Rust-audit post-load authority receipt differs: $entry_output"

    if /bin/bash "$source_root/scripts/audit.sh" \
        >"$ROOT/root-rust-audit.out" 2>"$ROOT/root-rust-audit.err"; then
        fail 'VM root passed the focused Rust-audit entry'
    fi
    [ ! -s "$ROOT/root-rust-audit.out" ] \
        || fail 'root focused Rust-audit refusal produced standard output'
    [ "$(<"$ROOT/root-rust-audit.err")" = \
      'audit.sh: refuses host or container-root execution' ] \
        || fail 'root focused Rust-audit refusal diagnostic differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/audit.sh" \
        >"$ROOT/foreign-rust-audit.out" 2>"$ROOT/foreign-rust-audit.err"; then
        fail 'foreign principal passed the focused Rust-audit entry'
    fi
    [ ! -s "$ROOT/foreign-rust-audit.out" ] \
        || fail 'foreign focused Rust-audit refusal produced standard output'
    [ "$(<"$ROOT/foreign-rust-audit.err")" = \
      'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign focused Rust-audit refusal diagnostic differs'

    audit_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/audit.sh"
    )" || fail 'focused Rust advisory scan failed'
    [ "$(grep -Fxc "$expected_entry" <<<"$audit_output")" -eq 1 ] \
        || fail 'focused Rust advisory authority receipt is absent or duplicated'
    [ "$(grep -Fxc "$expected_green" <<<"$audit_output")" -eq 1 ] \
        || fail 'focused Rust advisory green verdict is absent or duplicated'
    [ "$(grep -Fxc "verified subtree $SHA256_CARGO_VENDOR_CLOSURE_V1" <<<"$audit_output")" -eq 2 ] \
        || fail 'focused Rust advisory vendor pre/post receipts are absent or duplicated'
    [ "$source_before" = "$source_archive_sha:$(sha256sum \
        "$source_root/Cargo.lock" \
        "$source_root/deny.toml" \
        "$source_root/scripts/audit.sh" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/online-input-provenance.py" \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/rust-audit-policy.py" \
        "$source_root/scripts/verify-private-tree-closure.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh" \
        "$projected_config")" ] \
        || fail 'focused Rust-audit source changed during execution'
    [ "$image_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$RUST_AUDIT_IMAGE_ARCHIVE"):$(sha256sum "$RUST_AUDIT_IMAGE_ARCHIVE")" ] \
        || fail 'focused Rust-audit image archive changed during execution'
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'focused Rust audit left a container behind'
    "$CLIENT" --host "unix://$SOCK" image rm "$RUST_AUDIT_IMAGE_CONFIG_ID" >/dev/null \
        || fail 'cannot retire the focused Rust-audit image'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'focused Rust audit left a Docker image behind'
    stop_docker_authority
    umount "$projected_vendor" \
        || fail 'cannot retire the projected Rust-audit Cargo vendor mount'
    RUST_AUDIT_VENDOR_MOUNTED=0
    umount "$inputs" || fail 'cannot retire the sealed Rust-audit input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$audit_output"
    printf 'RUST_AUDIT_VM=pass commit=%s tree=%s image=%s runtime=%s lock=%s policy=%s vendor=%s uid=1000 gid=1000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused source=readonly vendor_input=readonly-landlocked scanner_root=readonly caps=none nnp=on cleanup=joined\n' \
        "$RUST_AUDIT_SOURCE_COMMIT" "$RUST_AUDIT_SOURCE_TREE" \
        "$RUST_AUDIT_IMAGE_ID" "$RUST_AUDIT_IMAGE_CONFIG_ID" \
        "$lock_sha" "$policy_sha" "$SHA256_CARGO_VENDOR_CLOSURE_V1"
}

run_apple_conform() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/apple-conform-source
    local vendor=$inputs/cargo-vendor
    local vendor_config=$inputs/cargo-vendor-config.toml
    local image_archive=$inputs/verifier-images/apple-check.docker.tar.gz
    local private_vendor_parent=$ROOT/apple-conform-vendor
    local private_vendor=$private_vendor_parent/subtree
    local private_image=$ROOT/apple-check.docker.tar.gz
    local projected_vendor=$source_root/online/cargo-vendor
    local projected_config=$source_root/online/cargo-vendor-config.toml
    local output=$ROOT/apple-conform.out
    local source_archive_sha source_tree_after input_mount_options vendor_mount_options
    local image_before load_output entry_output architecture_output conform_status=0
    local expected_entry="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root"
    local -a image_spec
    local -a conform_statuses
    local -a conform_arguments=()
    if [ "$APPLE_CURSOR_ONLY" -eq 1 ]; then
        conform_arguments=(--cursor-compile)
    fi
    printf 'APPLE_CHECK_STAGE=source-admission cursor_only=%s\n' "$APPLE_CURSOR_ONLY"

    [[ "$APPLE_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Apple-conformance source commit is malformed'
    [[ "$APPLE_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Apple-conformance source tree is malformed'
    [[ "$APPLE_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Apple-conformance source archive digest is malformed'
    [ -f "$APPLE_SOURCE_ARCHIVE" ] && [ ! -L "$APPLE_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$APPLE_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'Apple-conformance source archive metadata differs'
    source_archive_sha="$(sha256sum "$APPLE_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$APPLE_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Apple-conformance source archive digest differs'

    rm -rf -- "$source_root" "$private_vendor_parent" "$private_image"
    mkdir "$source_root"
    tar -xf "$APPLE_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact Apple-conformance source archive'
    [ -z "$(find "$source_root" -mindepth 1 ! -type d ! -type f ! -type l -print -quit)" ] \
        || fail 'Apple-conformance source archive contains a special entry'
    /usr/bin/git -c init.defaultBranch=master -C "$source_root" init -q \
        || fail 'cannot create the sealed Apple-conformance source index'
    mkdir -p "$projected_vendor"
    install -o 0 -g 0 -m 0444 -- "$vendor_config" "$projected_config" 2>/dev/null \
        && fail 'sealed Apple inputs became reachable before their authority mount'
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'Apple-conformance source archive differs from its guest bootstrap'
    chmod -R u=rwX,go=rX "$source_root" \
        || fail 'cannot seal the Apple-conformance source as read-only input'
    [ -z "$(find "$source_root" -mindepth 1 \
        \( -uid 4000 -o -gid 4000 -o -perm /022 \) -print -quit)" ] \
        || fail 'Apple-conformance source is writable by the verifier principal'
    /usr/bin/git -C "$source_root" add -f -- . \
        || fail 'cannot index the sealed Apple-conformance source'
    [ "$(/usr/bin/git -C "$source_root" write-tree)" = "$APPLE_SOURCE_TREE" ] \
        || fail 'Apple-conformance source archive tree differs from pushed master'
    chmod -R u=rwX,go=rX "$source_root/.git" \
        || fail 'cannot expose read-only Apple-conformance Git metadata'
    if ! /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
        diff-files --quiet --ignore-submodules --; then
        /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
            diff-files --name-status --ignore-submodules -- | sed -n '1,30p' >&2
        /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
            diff-files --raw --no-abbrev -- .cargo/config.toml >&2
        /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
            diff-files -- .cargo/config.toml | sed -n '1,40p' >&2
        stat -c 'Apple source file metadata: %a %s %n' \
            "$source_root/.cargo/config.toml" >&2
        fail 'Apple-conformance source differs from its index after sealing'
    fi

    printf 'APPLE_CHECK_STAGE=sealed-input-mount cursor_only=%s\n' "$APPLE_CURSOR_ONLY"
    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Apple-conformance input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Apple-conformance input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Apple inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Apple inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Apple inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed Apple inputs permit direct execution' ;; esac
    [ -d "$vendor" ] && [ ! -L "$vendor" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$vendor")" = 1000:1000:500 ] \
        || fail 'sealed Apple Cargo vendor root metadata differs'
    [ -f "$vendor_config" ] && [ ! -L "$vendor_config" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$vendor_config")" = \
             "1000:1000:400:1:$SIZE_CARGO_VENDOR_CONFIG" ] \
        && [ "$(sha256sum "$vendor_config" | awk '{ print $1 }')" = \
             "$SHA256_CARGO_VENDOR_CONFIG" ] \
        || fail 'sealed Apple Cargo vendor configuration differs'
    [ -f "$image_archive" ] && [ ! -L "$image_archive" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$image_archive")" = \
             "1000:1000:400:1:$SIZE_APPLE_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$image_archive" | awk '{ print $1 }')" = \
             "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed Apple verifier image archive differs'
    image_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$image_archive"):$(sha256sum "$image_archive")"

    printf 'APPLE_CHECK_STAGE=private-vendor-copy cursor_only=%s\n' "$APPLE_CURSOR_ONLY"
    mkdir -m 0700 "$private_vendor_parent"
    cp -a --reflink=never -- "$vendor" "$private_vendor" \
        || fail 'cannot stage the verifier-owned Apple Cargo vendor input'
    chown -R 4000:4000 "$private_vendor_parent" \
        || fail 'cannot assign the Apple Cargo vendor input to the verifier principal'
    [ "$(stat -c '%u:%g:%a' -- "$private_vendor_parent" "$private_vendor")" = \
      $'4000:4000:700\n4000:4000:500' ] \
        || fail 'private Apple Cargo vendor input metadata differs'
    install -o 0 -g 0 -m 0444 -- "$vendor_config" "$projected_config" \
        || fail 'cannot stage the immutable Apple Cargo vendor configuration'
    mount --bind "$private_vendor" "$projected_vendor" \
        || fail 'cannot project the private Apple Cargo vendor snapshot'
    APPLE_VENDOR_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid,noexec "$projected_vendor" \
        || fail 'cannot seal the projected Apple Cargo vendor snapshot'
    vendor_mount_options="$(findmnt -n -o OPTIONS --target "$projected_vendor")" \
        || fail 'projected Apple Cargo vendor mount is absent'
    case ",$vendor_mount_options," in *,ro,*) ;; *) fail 'projected Apple Cargo vendor is writable' ;; esac
    case ",$vendor_mount_options," in *,nodev,*) ;; *) fail 'projected Apple Cargo vendor permits devices' ;; esac
    case ",$vendor_mount_options," in *,nosuid,*) ;; *) fail 'projected Apple Cargo vendor permits set-user-ID execution' ;; esac
    case ",$vendor_mount_options," in *,noexec,*) ;; *) fail 'projected Apple Cargo vendor permits execution' ;; esac
    install -o 4000 -g 4000 -m 0400 -- "$image_archive" "$private_image" \
        || fail 'cannot stage the verifier-owned Apple image archive'
    [ "$(sha256sum "$private_image" | awk '{ print $1 }')" = \
      "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'private Apple image archive differs after staging'

    entry_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            /bin/bash "$source_root/scripts/verify-vm-entry-preflight.sh"
    )" || fail 'Apple-conformance pre-load VM authority check failed'
    [ "$entry_output" = "$expected_entry" ] \
        || fail "Apple-conformance pre-load authority receipt differs: $entry_output"
    image_spec=(
        --role apple-check
        --expected-id "$APPLE_CHECK_IMAGE_ID"
        --base "rd-devcheck@${DEV_CHECK_IMAGE_ID}"
        --base-manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
        --devcheck-base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}"
        --devcheck-dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE"
        --devcheck-debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT"
        --devcheck-security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT"
        --devcheck-source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH"
        --dockerfile-sha "$SHA256_APPLE_CHECK_DOCKERFILE"
        --source-date-epoch "$APPLE_CHECK_SOURCE_DATE_EPOCH"
        --release-helper-sha "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER"
        --provenance-helper-sha "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER"
        --rust-version "$APPLE_RUST_RELEASE_VERSION"
        --release-date "$APPLE_RUST_RELEASE_DATE"
        --signing-fingerprint "$APPLE_RUST_RELEASE_SIGNING_FINGERPRINT"
        --release-public-key-sha "$SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY"
        --release-manifest-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST"
        --release-manifest-signature-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE"
        --rustc-host-sha "$SHA256_APPLE_RUSTC_HOST_COMPONENT"
        --cargo-host-sha "$SHA256_APPLE_CARGO_HOST_COMPONENT"
        --rust-std-host-sha "$SHA256_APPLE_RUST_STD_HOST_COMPONENT"
        --rust-std-aarch64-darwin-sha "$SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT"
        --rust-std-x86-64-darwin-sha "$SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT"
        --rust-std-aarch64-ios-sha "$SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT"
        --cargo-sha "$SHA256_APPLE_CHECK_CARGO"
        --rustc-sha "$SHA256_APPLE_CHECK_RUSTC"
        --dpkg-sha "$SHA256_APPLE_CHECK_DPKG_MANIFEST"
        --toolchain-tree-sha "$APPLE_TOOLCHAIN_TREE_SHA256"
        --toolchain-files "$APPLE_TOOLCHAIN_FILES"
        --toolchain-directories "$APPLE_TOOLCHAIN_DIRECTORIES"
        --toolchain-content-bytes "$APPLE_TOOLCHAIN_CONTENT_BYTES"
        --config-id "$APPLE_CHECK_IMAGE_CONFIG_ID"
        --manifest-id "$APPLE_CHECK_IMAGE_MANIFEST_ID"
    )
    printf 'APPLE_CHECK_STAGE=image-verification-load cursor_only=%s\n' "$APPLE_CURSOR_ONLY"
    load_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$source_root/scripts/offline-image-provenance.py" \
                verify-load \
                --archive "$private_image" \
                --archive-sha "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_APPLE_CHECK_IMAGE_ARCHIVE" \
                "${image_spec[@]}"
    )" || fail 'Apple verifier image verification/load failed'
    [ "$load_output" = "loaded and verified apple-check $APPLE_CHECK_IMAGE_ID" ] \
        || fail "Apple verifier image load receipt differs: $load_output"
    architecture_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            python3 -I -S "$source_root/scripts/verify-apple-verifier-authority.py" \
                --repo "$source_root"
    )" || fail 'Apple verifier authority architecture check failed'
    [ "$architecture_output" = \
      'Apple verifier authority architecture: PASS (VM-only Docker path; exact-image/three-target shape; full workload has an isolated mode)' ] \
        || fail "Apple verifier authority architecture receipt differs: $architecture_output"

    if /bin/bash "$source_root/scripts/apple-conform-check.sh" "${conform_arguments[@]}" \
        >"$ROOT/root-apple-conform.out" 2>"$ROOT/root-apple-conform.err"; then
        fail 'VM root passed the Apple-conformance entry'
    fi
    [ ! -s "$ROOT/root-apple-conform.out" ] \
        || fail 'root Apple-conformance refusal produced standard output'
    [ "$(<"$ROOT/root-apple-conform.err")" = \
      'apple-conform-check refuses host or container-root execution' ] \
        || fail 'root Apple-conformance refusal diagnostic differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/apple-conform-check.sh" "${conform_arguments[@]}" \
        >"$ROOT/foreign-apple-conform.out" 2>"$ROOT/foreign-apple-conform.err"; then
        fail 'foreign principal passed the Apple-conformance entry'
    fi
    [ ! -s "$ROOT/foreign-apple-conform.out" ] \
        || fail 'foreign Apple-conformance refusal produced standard output'
    [ "$(<"$ROOT/foreign-apple-conform.err")" = \
      'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign Apple-conformance refusal diagnostic differs'
    if setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        DOCKER_HOST=unix:///tmp/forbidden-docker.sock \
        /bin/bash "$source_root/scripts/apple-conform-check.sh" "${conform_arguments[@]}" \
        >"$ROOT/caller-apple-conform.out" 2>"$ROOT/caller-apple-conform.err"; then
        fail 'caller Docker authority passed the Apple-conformance entry'
    fi
    [ ! -s "$ROOT/caller-apple-conform.out" ] \
        || fail 'caller-authority Apple-conformance refusal produced standard output'
    [ "$(<"$ROOT/caller-apple-conform.err")" = \
      'FATAL: caller DOCKER_HOST authority is forbidden' ] \
        || fail 'caller-authority Apple-conformance refusal diagnostic differs'

    printf 'APPLE_CHECK_STAGE=workload cursor_only=%s\n' "$APPLE_CURSOR_ONLY"
    set +e
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/apple-conform-check.sh" "${conform_arguments[@]}" \
        2>&1 | (
            set +o posix
            ulimit -f 6144 || exit 1
            exec /usr/bin/tee -- "$output"
        )
    conform_statuses=("${PIPESTATUS[@]}")
    set -e
    [ "${#conform_statuses[@]}" -eq 2 ] && [ "${conform_statuses[1]}" -eq 0 ] \
        || fail 'Apple-conformance live output capture failed'
    conform_status=${conform_statuses[0]}
    printf 'APPLE_CHECK_STAGE=workload-finished cursor_only=%s status=%s\n' \
        "$APPLE_CURSOR_ONLY" "$conform_status"
    [ "$(stat -c '%s' -- "$output")" -le 6291456 ] \
        || fail 'Apple-conformance output exceeds its bound'
    [ "$conform_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "Apple conformance exited with status $conform_status"; }
    if [ "$APPLE_CURSOR_ONLY" -eq 1 ]; then
        [ "$(grep -Fxc '== apple-cursor-compile PASS ==' "$output")" -eq 1 ] \
            || fail 'macOS cursor compile pass verdict is absent or duplicated'
        [ "$(grep -Fxc 'MACOS_CURSOR_COMPONENT_COMPILE=pass targets=2 bindings=real protobuf=generated sdk_shim=none linking=not-run native=false cleanup=joined' "$output")" -eq 1 ] \
            || fail 'macOS cursor component compiler receipt differs'
        for target in aarch64-apple-darwin x86_64-apple-darwin; do
            [ "$(grep -Ec "^MACOS_CURSOR_COMPILE_TARGET=pass target=$target metadata_bytes=[1-9][0-9]* metadata_sha256=[0-9a-f]{64} compiler_log_sha256=[0-9a-f]{64} fixture_sha256=[0-9a-f]{64} lock_sha256=[0-9a-f]{64} dependencies_sha256=[0-9a-f]{64} native=false$" "$output")" -eq 1 ] \
                || fail "macOS cursor compiler metadata receipt differs: $target"
        done
    else
        [ "$(grep -Fxc '== apple-conform-check PASS ==' "$output")" -eq 1 ] \
            || { tail -n 240 "$output" >&2; fail 'Apple-conformance pass verdict is absent or duplicated'; }
        [ "$(grep -Fxc '  targets: aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios' "$output")" -eq 1 ] \
            || fail 'Apple-conformance target matrix receipt differs'
        [ "$(grep -Fc 'hbb_common workspace anchor compiled cleanly' "$output")" -eq 3 ] \
            || { tail -n 240 "$output" >&2; fail 'Apple-conformance workspace-anchor receipts differ'; }
    fi
    [ "$(grep -Fxc "$expected_entry" "$output")" -eq 1 ] \
        || fail 'Apple-conformance VM authority receipt is absent or duplicated'
    source_tree_after="$(/usr/bin/git -c "safe.directory=$source_root" \
        -C "$source_root" write-tree)" \
        || fail 'cannot re-evaluate the Apple-conformance source tree'
    if [ "$source_tree_after" != "$APPLE_SOURCE_TREE" ] \
        || ! /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
             diff-files --quiet --ignore-submodules --; then
        sed -n '/^== (3) cross-compile coherence matrix/,/^== Apple desktop port-forward mapping conformance/p' \
            "$output" | sed -n '1,80p' >&2
        printf 'Apple-conformance source trees: expected=%s after=%s\n' \
            "$APPLE_SOURCE_TREE" "$source_tree_after" >&2
        /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
            diff-files --name-status --ignore-submodules -- | sed -n '1,30p' >&2
        fail 'Apple-conformance source changed during execution'
    fi
    [ "$image_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$image_archive"):$(sha256sum "$image_archive")" ] \
        || fail 'sealed Apple image archive changed during execution'
    [ "$(sha256sum "$private_image" | awk '{ print $1 }')" = \
      "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'private Apple image archive changed during execution'
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'Apple conformance left a container behind'
    "$CLIENT" --host "unix://$SOCK" image rm "$APPLE_CHECK_IMAGE_CONFIG_ID" >/dev/null \
        || fail 'cannot retire the Apple verifier image'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Apple conformance left a Docker image behind'
    stop_docker_authority
    umount "$projected_vendor" \
        || fail 'cannot retire the projected Apple Cargo vendor snapshot'
    APPLE_VENDOR_MOUNTED=0
    umount "$inputs" || fail 'cannot retire the sealed Apple input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$load_output"
    printf '%s\n' "$architecture_output"
    if [ "$APPLE_CURSOR_ONLY" -eq 1 ]; then
        printf 'APPLE_CURSOR_COMPILE_VM=pass commit=%s tree=%s targets=2 image=%s runtime=%s vendor=%s uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused caller=refused source=exact-pushed-readonly inputs=readonly-landlocked evidence=component-compile-not-native cleanup=joined\n' \
            "$APPLE_SOURCE_COMMIT" "$APPLE_SOURCE_TREE" \
            "$APPLE_CHECK_IMAGE_ID" "$APPLE_CHECK_IMAGE_CONFIG_ID" "$SHA256_CARGO_VENDOR_CLOSURE_V1"
    else
        printf 'APPLE_CONFORM_VM=pass commit=%s tree=%s targets=3 image=%s runtime=%s vendor=%s uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused caller=refused source=exact-pushed-readonly inputs=readonly-landlocked evidence=source-conformance-not-native cleanup=joined\n' \
            "$APPLE_SOURCE_COMMIT" "$APPLE_SOURCE_TREE" \
            "$APPLE_CHECK_IMAGE_ID" "$APPLE_CHECK_IMAGE_CONFIG_ID" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1"
    fi
}

generate_focused_rust_flutter_bridge() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local codegen_source=$ROOT/focused-rust-codegen-source
    local codegen_work=$ROOT/focused-rust-codegen-work
    local bridge_root=$ROOT/focused-rust-bridge
    local output=$ROOT/focused-rust-codegen.out
    local builder_archive=$inputs/build-images/deb-builder.docker.tar.gz
    local load_output container_status=0 inspect namespace_inspect freshness_line

    rm -rf -- "$codegen_source" "$codegen_work" "$bridge_root"
    mkdir "$codegen_source" "$codegen_work" "$bridge_root"
    tar -xf "$RUST_TEST_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$codegen_source" \
        || fail 'cannot extract the exact focused Rust source for bridge generation'
    chown -R 1000:1000 "$codegen_source" "$codegen_work" "$bridge_root"
    chmod 0700 "$codegen_work" "$bridge_root"

    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role deb-builder \
                --expected-id "$DEB_BUILDER_IMAGE_ID" \
                --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
                --dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$DEB_BUILDER_CONFIG_ID" \
                --manifest-id "$DEB_BUILDER_MANIFEST_ID"
    )" || fail 'focused Rust bridge builder verification/load failed'
    [ "$load_output" = "loaded and verified deb-builder $DEB_BUILDER_IMAGE_ID" ] \
        || fail "focused Rust bridge builder receipt differs: $load_output"

    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create \
            --name rustdesk-android-rust-bridge-codegen \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=1024 \
            --memory=8g \
            --memory-swap=8g \
            --cpus=4 \
            --ulimit nofile=8192:8192 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --mount "type=bind,source=$codegen_source,target=/source" \
            --mount "type=bind,source=$codegen_work,target=/work" \
            --mount "type=bind,source=$bridge_root,target=/bridge" \
            --mount "type=bind,source=$inputs/pub-cache,target=/online/pub-cache,readonly" \
            --mount "type=bind,source=$inputs/cargo-vendor,target=/online/cargo-vendor,readonly" \
            --mount "type=bind,source=$inputs/rust-1.75.tar.xz,target=/inputs/rust.tar.xz,readonly" \
            --mount "type=bind,source=$inputs/flutter-3.24.5.tar.xz,target=/inputs/flutter.tar.xz,readonly" \
            --mount "type=bind,source=$inputs/llvm-15.0.6.tar.xz,target=/inputs/llvm.tar.xz,readonly" \
            --mount "type=bind,source=$inputs/cargo-vendor-config.toml,target=/inputs/cargo-vendor-config.toml,readonly" \
            --mount "type=bind,source=$inputs/frb-tool/bin/flutter_rust_bridge_codegen,target=/inputs/flutter_rust_bridge_codegen,readonly" \
            --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
            --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
            --env "FRB_CODEGEN_SHA256=$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
            --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g,mode=700,uid=1000,gid=1000 \
            --workdir /source \
            "$DEB_BUILDER_CONFIG_ID" /bin/bash --noprofile --norc -euo pipefail -c '
                set -- /sys/class/net/*
                [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
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
                [ "$uid" = 1000:1000:1000:1000 ]
                [ "$gid" = 1000:1000:1000:1000 ]
                [ "$cap" = 0000000000000000 ]
                [ "$nnp" = 1 ]
                [ "$seccomp" = 2 ]
                IFS= read -r apparmor </proc/self/attr/current
                case "$apparmor" in docker-default\ *) ;; *) exit 92 ;; esac
                mkdir /work/toolchain /work/home /work/cargo-home /work/flutter-shim
                tar -C /work/toolchain -xf /inputs/rust.tar.xz
                tar -C /work/toolchain -xf /inputs/flutter.tar.xz
                tar -C /work/toolchain -xf /inputs/llvm.tar.xz
                mapfile -t rust_installer < <(
                    find /work/toolchain -mindepth 2 -maxdepth 2 -type f -name install.sh -print
                )
                [ "${#rust_installer[@]}" -eq 1 ] && [ -f "${rust_installer[0]}" ]
                "${rust_installer[0]}" --prefix=/work/toolchain/rustinstall \
                    --disable-ldconfig \
                    --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview \
                    >/dev/null
                llvm_roots=(/work/toolchain/clang+llvm-*)
                [ "${#llvm_roots[@]}" -eq 1 ] && [ -d "${llvm_roots[0]}" ]
                LLVM_ROOT="${llvm_roots[0]}"
                mapfile -t clang_headers < <(
                    find "$LLVM_ROOT/lib/clang" -mindepth 2 -maxdepth 2 -type d -name include -print
                )
                [ "${#clang_headers[@]}" -eq 1 ] && [ -d "${clang_headers[0]}" ]
                cp /inputs/flutter_rust_bridge_codegen /work/toolchain/flutter_rust_bridge_codegen
                chmod 0500 /work/toolchain/flutter_rust_bridge_codegen
                export HOME=/work/home CARGO_HOME=/work/cargo-home
                export PUB_CACHE=/online/pub-cache CI=true
                export PUB_HOSTED_URL=https://pub.dev
                export FLUTTER_SUPPRESS_ANALYTICS=true
                export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
                export GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
                export GIT_OPTIONAL_LOCKS=0
                export LIBCLANG_PATH="$LLVM_ROOT/lib"
                export PATH=/work/toolchain/flutter/bin:/work/toolchain/flutter/bin/cache/dart-sdk/bin:/work/toolchain/rustinstall/bin:/usr/bin:/bin
                [ "$(flutter --version --machine | /usr/bin/python3 -c "import json,sys; print(json.load(sys.stdin)[\"frameworkVersion\"])")" = 3.24.5 ]
                {
                    printf "[net]\noffline = true\n"
                    sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                        /inputs/cargo-vendor-config.toml
                } >"$CARGO_HOME/config.toml"
                cp /source/scripts/flutter-offline-shim.sh /work/flutter-shim/flutter
                chmod 0500 /work/flutter-shim/flutter
                export REAL_FLUTTER=/work/toolchain/flutter/bin/flutter
                export PATH=/work/flutter-shim:$PATH
                project_lock="$(sha256sum /source/flutter/pubspec.lock | awk "{print \$1}")"
                tools_lock="$(sha256sum /work/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")"
                (cd /work/toolchain/flutter/packages/flutter_tools \
                    && dart pub get --offline --enforce-lockfile)
                /source/scripts/finalize-flutter-tools-offline.sh \
                    /work/toolchain/flutter \
                    "$RUSTDESK_FLUTTER_VERSION" \
                    "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256"
                "$REAL_FLUTTER" config --no-analytics >/work/flutter-config.out
                (cd /source/flutter && flutter pub get --offline --enforce-lockfile)
                [ "$tools_lock" = "$(sha256sum /work/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")" ]
                [ "$project_lock" = "$(sha256sum /source/flutter/pubspec.lock | awk "{print \$1}")" ]
                codegen_log=/work/codegen.log
                if ! timeout --signal=TERM --kill-after=10s 900s \
                    /work/toolchain/flutter_rust_bridge_codegen \
                        --rust-input ./src/flutter_ffi.rs \
                        --dart-output ./flutter/lib/generated_bridge.dart \
                        --llvm-path "$LLVM_ROOT" \
                        --llvm-compiler-opts="-I${clang_headers[0]}" \
                    >"$codegen_log" 2>&1; then
                    tail -n 160 "$codegen_log" >&2
                    exit 1
                fi
                [ "$(stat -c %s "$codegen_log")" -le 1048576 ]
                ! grep -Fq "[SEVERE]" "$codegen_log" \
                    || { tail -n 160 "$codegen_log" >&2; exit 1; }
                for generated in \
                    /source/src/bridge_generated.rs \
                    /source/src/bridge_generated.io.rs \
                    /source/flutter/lib/generated_bridge.dart \
                    /source/flutter/lib/generated_bridge.freezed.dart; do
                    [ -s "$generated" ] && [ ! -L "$generated" ]
                done
                install -m 0444 /source/src/bridge_generated.rs /bridge/bridge_generated.rs
                install -m 0444 /source/src/bridge_generated.io.rs /bridge/bridge_generated.io.rs
                [ "$project_lock" = "$(sha256sum /source/flutter/pubspec.lock | awk "{print \$1}")" ]
                printf "ANDROID_RUST_FRB=pass flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=%s source=exact-pushed network=none outputs=readonly-publication\n" \
                    "$FRB_CODEGEN_SHA256"
            '
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust bridge container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      'none|true|1000:1000|8589934592|8589934592|4000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
        || fail "focused Rust bridge container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "focused Rust bridge container namespace/device/port authority differs: $namespace_inspect"
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 200 "$output" >&2; fail "focused Rust bridge generation exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || fail 'focused Rust bridge output exceeds its bound'
    freshness_line="$(grep -Fx \
        "FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=$FLUTTER_VERSION lock=$SHA256_FLUTTER_TOOLS_LOCK implicit_pub=prevented" \
        "$output")" \
        || { tail -n 200 "$output" >&2; fail 'focused Rust bridge Flutter-tools receipt is absent'; }
    [ "$(grep -Fc 'FLUTTER_TOOLS_OFFLINE_FRESHNESS=' "$output")" -eq 1 ] \
        || fail 'focused Rust bridge Flutter-tools receipt is duplicated'
    grep -Fxq \
        "ANDROID_RUST_FRB=pass flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=$SHA256_FLUTTER_PEER_FRB_CODEGEN source=exact-pushed network=none outputs=readonly-publication" \
        "$output" \
        || { tail -n 200 "$output" >&2; fail 'focused Rust bridge receipt is absent'; }
    [ "$(grep -Fc 'ANDROID_RUST_FRB=' "$output")" -eq 1 ] \
        || fail 'focused Rust bridge receipt is duplicated'
    [ "$(stat -c '%u:%g:%a:%h' -- \
            "$bridge_root/bridge_generated.rs" \
            "$bridge_root/bridge_generated.io.rs")" = \
      $'1000:1000:444:1\n1000:1000:444:1' ] \
        && [ -s "$bridge_root/bridge_generated.rs" ] \
        && [ -s "$bridge_root/bridge_generated.io.rs" ] \
        || fail 'focused Rust bridge publication metadata differs'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused Rust bridge container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$DEB_BUILDER_CONFIG_ID" >/dev/null
    rm -rf -- "$codegen_source" "$codegen_work"
    printf '%s\n' "$freshness_line"
    printf 'ANDROID_RUST_FRB=pass flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=%s source=exact-pushed network=none outputs=readonly-publication\n' \
        "$SHA256_FLUTTER_PEER_FRB_CODEGEN"
}

run_focused_rust_tests() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/focused-rust-test-source
    local target_root=$ROOT/focused-rust-test-target
    local output=$ROOT/focused-rust-tests.out
    local rust_archive=$inputs/rust-1.75.tar.xz
    local flutter_archive=$inputs/flutter-3.24.5.tar.xz
    local llvm_archive=$inputs/llvm-15.0.6.tar.xz
    local frb_codegen=$inputs/frb-tool/bin/flutter_rust_bridge_codegen
    local pub_cache=$inputs/pub-cache
    local builder_archive=$inputs/build-images/deb-builder.docker.tar.gz
    local vendor=$inputs/cargo-vendor
    local vendor_config=$inputs/cargo-vendor-config.toml
    local pub_validator=$source_root/scripts/online-pub-cache-output.py
    local image_archive image_config image_index toolchain_mode
    local load_output container_status=0 inspect namespace_inspect result_line passed tests_passed=0
    local container_name memory memory_bytes tmpfs_size source_fingerprints
    local source_archive_sha source_before input_mount_options pub_receipt post_pub_receipt
    local path remainder size digest
    local uid_test_artifact_sha
    local -a required_tests result_lines toolchain_mount bridge_mounts bridge_inputs
    local -a pa_mounts=() pa_env=() dependency_mounts=()

    [ "$(stat -c '%u:%g:%a' -- "$SOCK")" = 0:1000:660 ] \
        || fail 'focused Rust-test Docker socket lacks the exact nonroot guest group'

    if [ "$MODE" = hbb-common-fs ]; then
        container_name=rustdesk-hbb-common-fs
        memory=8g
        memory_bytes=8589934592
        tmpfs_size=3g
        image_archive=$inputs/build-images/deb-builder.docker.tar.gz
        image_config=$DEB_BUILDER_CONFIG_ID
        image_index=$DEB_BUILDER_IMAGE_ID
        toolchain_mode=archive
        toolchain_mount=(
            --mount "type=bind,source=$rust_archive,target=/inputs/rust.tar.xz,readonly"
        )
        bridge_mounts=()
        source_fingerprints=(
            Cargo.lock
            libs/hbb_common/src/config.rs
            libs/hbb_common/src/fs.rs
        )
        required_tests=(
            config::tests::config_transaction_faults_preserve_precommit_and_make_postcommit_fatal
            config::tests::config_transaction_traverses_search_only_existing_ancestor
            config::tests::config_transaction_creates_missing_parent_components_privately
            config::tests::config_transaction_rejects_symlink_parent_and_replaces_final_link_itself
            fs::tests::r_s11hm_remove_empty_directory_tree_removes_the_complete_empty_tree
            fs::tests::r_s11hm_remove_empty_directory_tree_reports_a_nonempty_tree
            fs::tests::r_s11hm_nonrecursive_directory_removal_uses_empty_only_finality
            fs::tests::r_s11hm_remove_empty_directory_tree_refuses_a_directory_symlink_root
            fs::tests::r_s11hm_remove_empty_directory_tree_unlinks_nested_symlink_without_traversal
            fs::tests::r_s11hm_retained_directory_refuses_a_replacement_root_edge
            fs::tests::r_s11hm_remove_empty_directory_tree_enforces_depth_bound
            fs::tests::r_s11hm_remove_file_refuses_a_symlinked_parent
            fs::tests::remove_file_rejects_empty_path
            fs::tests::remove_file_rejects_null_byte_path
            fs::tests::create_dir_rejects_empty_path
            fs::tests::create_dir_rejects_null_byte_path
            fs::tests::create_dir_creates_a_legitimate_nested_tree_idempotently
            fs::tests::create_dir_rejects_parent_traversal_before_any_component_is_created
            fs::tests::create_dir_refuses_a_symlink_parent_without_mutating_its_target
            fs::tests::rename_file_rejects_invalid_new_name
            fs::tests::rename_file_accepts_valid_new_name
            fs::tests::rename_file_replaces_a_symlink_leaf_without_touching_its_target
            fs::tests::rename_file_refuses_a_symlink_parent_without_mutating_its_target
            fs::tests::rename_admitted_entry_refuses_a_replaced_source_name
            fs::tests::rename_admitted_entry_stays_with_its_retained_parent_after_path_swap
            fs::tests::abandoned_blocking_receive_result_retires_its_exact_sidecars
            fs::tests::abandoned_blocking_finalize_error_retires_only_its_claim
            fs::tests::new_receive_refuses_existing_sidecars_without_changing_their_bytes
            fs::tests::receive_finalize_refuses_a_real_partial_write_with_matching_staged_length
            fs::tests::send_open_failure_keeps_the_failed_file_number
        )
    elif [ "$MODE" = cpace-recovery-tests ]; then
        container_name=rustdesk-cpace-recovery-tests
        memory=8g
        memory_bytes=8589934592
        tmpfs_size=3g
        image_archive=$inputs/build-images/deb-builder.docker.tar.gz
        image_config=$DEB_BUILDER_CONFIG_ID
        image_index=$DEB_BUILDER_IMAGE_ID
        toolchain_mode=archive
        toolchain_mount=(
            --mount "type=bind,source=$rust_archive,target=/inputs/rust.tar.xz,readonly"
        )
        bridge_mounts=()
        source_fingerprints=(
            Cargo.lock
            libs/cpace_it/Cargo.toml
            libs/cpace_it/tests/handshake.rs
            libs/hbb_common/protos/message.proto
            libs/hbb_common/src/cpace.rs
            libs/hbb_common/src/tcp.rs
            libs/pake/src/lib.rs
        )
        required_tests=(
            wrong_password_aborts_at_confirmation
            initiator_eof_before_step2_remains_plain_io
            initiator_invalid_step4_tag_remains_confirmation
        )
    elif [ "$MODE" = linux-pa-authority-tests ]; then
        container_name=rustdesk-linux-pa-authority-tests
        memory=8g
        memory_bytes=8589934592
        tmpfs_size=3g
        image_archive=$inputs/verifier-images/devcheck.docker.tar.gz
        image_config=$DEV_CHECK_IMAGE_CONFIG_ID
        image_index=$DEV_CHECK_IMAGE_ID
        toolchain_mode=devcheck-image
        toolchain_mount=()
        bridge_mounts=()
        source_fingerprints=(
            Cargo.lock
            scripts/run-pa-runtime-tests.sh
            scripts/verify-pa-runtime-candidate.py
            src/ipc.rs
            src/ipc/pulse_audio.rs
            src/server/audio_service.rs
            src/server/connection.rs
            src/server/service.rs
        )
        required_tests=(
            ipc::test::linux_pulse_audio_channel_uses_closed_bounded_protocol
            ipc::test::r_s11iu_pa_capture_peer_comes_from_the_kernel_socket
            server::audio_service::test::r_s11iu_pa_capture_authority_rejects_missing_wrong_and_stale_tokens
            server::audio_service::test::r_s11iu_pa_capture_authority_rejects_a_stopped_service
            server::audio_service::test::r_s11iu_pa_capture_authority_requires_a_positive_subscriber_id
            server::audio_service::test::r_s11iu_pa_capture_rechecks_exact_current_recipients
            server::service::pa_dispatch_tests::r_s11iu_pa_audio_dispatch_excludes_later_subscribers
            ipc::pulse_audio::tests::record_fragments_preserve_frame_shape_and_bound_stale_audio
            ipc::pulse_audio::tests::accepted_owner_close_interrupts_silent_capture_wait
            ipc::pulse_audio::tests::real_monitor_capture_revokes_after_audio_stops
            ipc::pulse_audio::tests::real_kernel_pa_admission_refuses_same_uid_child_with_token
        )
    elif [ "$MODE" = linux-service-uid-tests ]; then
        container_name=rustdesk-linux-service-uid-tests
        memory=512m
        memory_bytes=536870912
        tmpfs_size=64m
        image_archive=$inputs/verifier-images/devcheck.docker.tar.gz
        image_config=$DEV_CHECK_IMAGE_CONFIG_ID
        image_index=$DEV_CHECK_IMAGE_ID
        toolchain_mode=devcheck-image
        toolchain_mount=()
        bridge_mounts=()
        source_fingerprints=(
            src/ipc.rs
            src/ipc/auth.rs
            src/ipc/uid_policy.rs
            scripts/test-linux-service-uid-policy.rs
            scripts/verify-linux-service-password-ipc.py
        )
        required_tests=(
            uid_policy::tests::test_service_peer_uid_policy
            uid_policy::tests::r_s11e60_linux_service_root_skips_both_uid_lookups
            uid_policy::tests::r_s11e60_linux_service_cached_negative_skips_fresh_uid_lookup
            uid_policy::tests::r_s11e60_linux_service_cache_match_requires_fresh_uid_authority
        )
    else
        [ "$MODE" = android-rust-lifecycle-tests ] \
            || fail "unknown focused Rust-test mode: $MODE"
        container_name=rustdesk-android-rust-lifecycle-tests
        memory=12g
        memory_bytes=12884901888
        tmpfs_size=3g
        image_archive=$inputs/verifier-images/devcheck.docker.tar.gz
        image_config=$DEV_CHECK_IMAGE_CONFIG_ID
        image_index=$DEV_CHECK_IMAGE_ID
        toolchain_mode=devcheck-image
        toolchain_mount=()
        source_fingerprints=(
            Cargo.lock
            flutter/pubspec.lock
            scripts/finalize-flutter-tools-offline.sh
            scripts/flutter-offline-shim.sh
            scripts/online-pub-cache-output.py
            src/lib.rs
            src/android_listener_lifecycle.rs
            src/cli.rs
            src/client.rs
            src/client/io_loop.rs
            src/direct_service.rs
            src/flutter.rs
            src/flutter_ffi.rs
            src/ipc.rs
            src/ipc/auth.rs
            src/ipc/uid_policy.rs
            scripts/verify-linux-service-password-ipc.py
            src/port_forward.rs
            src/privacy_mode.rs
            src/server/connection.rs
            src/server/audio_service.rs
            src/server/display_service.rs
            src/server/service.rs
            src/ui_cm_interface.rs
            src/ui_session_interface.rs
        )
        required_tests=(
            ipc::uid_policy::tests::r_s11e60_linux_service_root_skips_both_uid_lookups
            ipc::uid_policy::tests::r_s11e60_linux_service_cached_negative_skips_fresh_uid_lookup
            ipc::uid_policy::tests::r_s11e60_linux_service_cache_match_requires_fresh_uid_authority
            android_listener_lifecycle::tests::stale_network_callback_cannot_advance_replacement_generation_epoch
            android_listener_lifecycle::tests::worker_must_be_registered_and_converged_before_replacement
            android_listener_lifecycle::tests::invalid_exhausted_and_thread_creation_failure_edges_fail_closed
            client::tests::r_p14c_viewer_credential_prompt_requires_typed_credential_failure
            client::tests::r_p14_viewer_credential_is_fully_prepared_before_socket_keying
            direct_service::direct_connection_task_tests::parent_cancellation_converges_every_owned_child_before_listener_completion
            ui_cm_interface::tests::r_s11is_cm_file_raw_ceiling_rejects_oversize_after_accepting_exact_limit
            ui_cm_interface::tests::r_s11is_cm_file_raw_timeout_retires_authenticated_runner
            ui_cm_interface::tests::r_s11is_desktop_cm_cancellation_drains_selected_file_operation
            ui_cm_interface::tests::r_s11is_desktop_selected_file_child_loss_is_process_fatal
            ui_cm_interface::tests::r_s11is_desktop_read_tick_cancellation_drains_exact_owner
            ui_cm_interface::tests::r_s11is_cm_file_response_refusal_is_returned_to_the_command_owner
            ui_cm_interface::tests::r_s11is_cm_receive_rejects_an_inconsistent_aggregate_size
            ui_cm_interface::tests::r_s11is_read_job_commits_only_after_initial_response_admission
            client::io_loop::tests::r_s11fi_incoming_write_failure_retires_exact_job_and_partial_artifacts
            client::io_loop::tests::r_s11fi_receive_cleanup_identity_failure_is_terminal_and_visible
            client::io_loop::tests::r_s11fi_incoming_nofollow_open_failure_preserves_older_sidecars
            client::io_loop::tests::r_s11fj_download_digest_metadata_failure_is_explicit
            client::io_loop::tests::r_s11fj_download_digest_requires_the_exact_active_file
            client::io_loop::tests::r_s11fj_download_digest_refuses_size_changed_after_listing
            privacy_mode::tests::r_s11iu_privacy_resource_owner_distinguishes_same_id_token_replacement
            privacy_mode::tests::r_s11iu_privacy_activation_commits_only_after_prepare
            privacy_mode::tests::r_s11iu_privacy_activation_deadline_cancels_and_drains_before_return
            privacy_mode::tests::r_s11iu_privacy_activation_future_drop_refuses_late_commit
            privacy_mode::tests::r_s11iu_r_s19a_privacy_retirement_dispatcher_owns_work_off_caller_thread
            server::connection::final_remote_cleanup_state_tests::r_s11iu_final_remote_unclaimed_cleanup_is_superseded_by_admission
            server::connection::final_remote_cleanup_state_tests::r_s11iu_final_remote_claim_blocks_successor_until_completion
            server::connection::final_remote_cleanup_state_tests::r_s11iu_final_remote_cleanup_waits_for_the_last_live_lease
            server::connection::final_remote_cleanup_state_tests::r_s11iu_final_remote_failure_has_one_retry_per_admission
            server::connection::final_remote_cleanup_state_tests::r_s11iu_stale_final_remote_lease_retirement_is_inert
            server::connection::final_remote_cleanup_state_tests::r_s11iu_authenticated_registry_refuses_id_overlap_and_stale_removal
            server::connection::cm_peer_identity_registry_tests::r_s11iu_linux_cm_peer_identity_rejects_collision_and_stale_retirement
            server::connection::cm_peer_identity_registry_tests::r_s11iu_linux_cm_peer_identity_requires_positive_exact_owner
            server::connection::cm_peer_identity_registry_tests::r_s11iu_linux_audio_peer_requires_live_exact_connection_owner
            server::connection_id_allocator_tests::r_s11iu_connection_ids_fail_closed_instead_of_wrapping
            server::connection_id_allocator_tests::r_s11iu_connection_ids_are_unique_across_concurrent_callers
            ipc::test::r_s11iu_pa_capture_peer_comes_from_the_kernel_socket
            server::audio_service::test::r_s11iu_pa_capture_authority_rejects_missing_wrong_and_stale_tokens
            server::audio_service::test::r_s11iu_pa_capture_authority_rejects_a_stopped_service
            server::audio_service::test::r_s11iu_pa_capture_authority_requires_a_positive_subscriber_id
            server::audio_service::test::r_s11iu_pa_capture_rechecks_exact_current_recipients
            server::service::pa_dispatch_tests::r_s11iu_pa_audio_dispatch_excludes_later_subscribers
            server::display_service::tests::r_s11iu_r_t4_resolution_restore_retains_failure_and_concurrent_replacement
            ui_cm_interface::tests::r_s11iu_android_cm_future_terminally_retires_its_registry_owner
            ui_cm_interface::tests::r_s11iu_android_terminal_preempts_queued_file_work
            ui_cm_interface::tests::r_s11iu_android_cm_future_cancellation_retires_its_registry_owner
            ui_cm_interface::tests::r_s11iu_refused_android_callback_preserves_the_existing_cm_owner
            ui_cm_interface::tests::r_s11iu_service_stop_waits_for_callback_admission_publication
            ui_cm_interface::tests::r_s11iu_superseded_android_cm_owner_cannot_dispatch_filesystem_work
            ui_cm_interface::tests::r_s11iu_stale_owner_cannot_mutate_or_retire_a_reused_client_id
            ui_cm_interface::tests::r_s11iu_registry_rejects_stale_and_same_source_active_collisions
            ui_cm_interface::tests::r_s11iu_disconnected_owner_can_be_replaced_but_cannot_retire_replacement
            ui_cm_interface::tests::r_s11iu_generation_exhaustion_does_not_commit_a_client
            ui_cm_interface::tests::r_s11iu_file_log_publication_requires_exact_current_owner
            ui_cm_interface::tests::r_s11iu_cm_voice_state_requires_current_voice_capable_desktop_owner
            ui_cm_interface::tests::r_s11iu_cm_voice_state_requires_current_voice_capable_android_owner
            ui_session_interface::connection_round_ownership_tests::credential_prompt_revokes_every_generic_reconnect
            ui_session_interface::connection_round_ownership_tests::credential_post_admission_failure_revokes_every_generic_reconnect
            ui_session_interface::connection_round_ownership_tests::credential_stale_round_cannot_rearm_recovery
            ui_session_interface::connection_round_ownership_tests::credential_failed_replacement_requires_a_fresh_prompt_attempt
            ui_session_interface::connection_round_ownership_tests::credential_stale_prompt_cannot_mutate_session_or_start_worker
            flutter::mobile_session_lifecycle_tests::r_s11ew_rgba_mailbox_keeps_published_frame_stable_and_promotes_only_latest
            flutter::mobile_session_lifecycle_tests::r_s11ew_rgba_mailboxes_are_exact_per_ui_session_and_display
            flutter::mobile_session_lifecycle_tests::r_s11ew_rgba_without_a_live_consumer_retains_no_frame
            flutter::mobile_session_lifecycle_tests::r_s11ew_display_switch_retires_only_obsolete_exact_mailboxes
            flutter::mobile_session_lifecycle_tests::r_s11ew_rgba_publication_exhaustion_fails_closed
            flutter::mobile_session_lifecycle_tests::r_s11fr_rgba_rearm_replaces_the_token_and_promotes_only_the_latest_frame
            flutter::mobile_session_lifecycle_tests::r_s11fr_rgba_rearm_is_idle_without_a_publication_and_fails_closed_on_exhaustion
            flutter::mobile_session_lifecycle_tests::r_s11fr_failed_rgba_rearm_retires_the_exact_mailbox
            flutter::mobile_session_lifecycle_tests::r_s11iw_stream_replacement_rotates_rgba_and_rejects_predecessor_take
            flutter::mobile_session_lifecycle_tests::r_s11iw_stream_replacement_refusal_retires_only_its_exact_rgba_session
            flutter::mobile_session_lifecycle_tests::r_s11ex_desktop_tab_move_requires_live_source_and_preserves_peer_on_old_close
        )
    fi

    [[ "$RUST_TEST_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-test source commit is malformed'
    [[ "$RUST_TEST_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-test source tree is malformed'
    [[ "$RUST_TEST_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust-test source archive digest is malformed'
    [ -f "$RUST_TEST_SOURCE_ARCHIVE" ] && [ ! -L "$RUST_TEST_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = 4000:4000:400:1 ] \
        || fail 'focused Rust-test source archive metadata differs'
    source_archive_sha="$(sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$RUST_TEST_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-test source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$RUST_TEST_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact focused-test source archive'
    chown -R 1000:1000 "$source_root"
    if [ "$MODE" = android-rust-lifecycle-tests ]; then
        install -o 1000 -g 1000 -m 0444 /dev/null \
            "$source_root/src/bridge_generated.rs"
        install -o 1000 -g 1000 -m 0444 /dev/null \
            "$source_root/src/bridge_generated.io.rs"
        source_fingerprints+=(
            src/bridge_generated.rs
            src/bridge_generated.io.rs
        )
    fi
    mkdir "$target_root"
    chown 1000:1000 "$target_root"
    chmod 0700 "$target_root"
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'focused-test source archive differs from its guest bootstrap'
    source_before="$source_archive_sha:$(
        cd "$source_root"
        sha256sum "${source_fingerprints[@]}"
    )"

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed focused-test input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed focused-test input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed focused-test inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed focused-test inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed focused-test inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed focused-test inputs permit direct execution' ;; esac

    if [ "$MODE" = linux-pa-authority-tests ]; then
        local pa_candidate=/mnt/rustdesk-verifier-inputs/pa-runtime-candidate.tar.gz
        local pa_copy=$ROOT/pa-runtime.tar.gz
        [ -f "$pa_candidate" ] && [ ! -L "$pa_candidate" ] \
            && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$pa_candidate")" = \
                 "4000:4000:400:1:$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" ] \
            && [ "$(sha256sum "$pa_candidate" | awk '{ print $1 }')" = \
                 "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" ] \
            || fail 'PulseAudio runtime candidate input differs'
        install -o 1000 -g 1000 -m 0400 -- "$pa_candidate" "$pa_copy" \
            || fail 'cannot make the private PulseAudio candidate copy'
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$pa_copy")" = \
          "1000:1000:400:1:$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" ] \
            && [ "$(sha256sum "$pa_copy" | awk '{ print $1 }')" = \
                 "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" ] \
            || fail 'private PulseAudio candidate copy differs'
        pa_mounts=(--mount "type=bind,source=$pa_copy,target=/inputs/pa-runtime.tar.gz,readonly")
        pa_env=(
            --env "PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE=$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE"
            --env "PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256=$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256"
            --env "PA_RUNTIME_CANDIDATE_MANIFEST_SHA256=$PA_RUNTIME_CANDIDATE_MANIFEST_SHA256"
            --env "DEV_CHECK_IMAGE_ID=$DEV_CHECK_IMAGE_ID"
            --env "DEV_CHECK_DEBIAN_SNAPSHOT=$DEV_CHECK_DEBIAN_SNAPSHOT"
            --env "DEV_CHECK_SECURITY_SNAPSHOT=$DEV_CHECK_SECURITY_SNAPSHOT"
            --env "PA_RUNTIME_PULSEAUDIO_VERSION=$PA_RUNTIME_PULSEAUDIO_VERSION"
            --env "PA_RUNTIME_PULSEAUDIO_SHA256=$PA_RUNTIME_PULSEAUDIO_SHA256"
            --env "PA_RUNTIME_PULSEAUDIO_SIZE=$PA_RUNTIME_PULSEAUDIO_SIZE"
        )
    fi

    if [ "$MODE" != linux-service-uid-tests ]; then
        dependency_mounts=(
            --mount "type=bind,source=$vendor,target=/vendor,readonly"
            --mount "type=bind,source=$vendor_config,target=/inputs/config.toml,readonly"
        )
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$vendor_config")" = \
          "1000:1000:400:1:$SIZE_CARGO_VENDOR_CONFIG" ] \
            && [ "$(sha256sum "$vendor_config" | awk '{ print $1 }')" = \
                 "$SHA256_CARGO_VENDOR_CONFIG" ] \
            || fail 'sealed Cargo source map differs'
        [ -d "$vendor" ] && [ ! -L "$vendor" ] \
            && [ "$(stat -c '%u:%g:%a' -- "$vendor")" = 1000:1000:500 ] \
            || fail 'sealed Cargo vendor root metadata differs'
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            python3 -I -S "$source_root/scripts/online-input-provenance.py" \
                verify-subtree --tree "$vendor" \
                --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
            || fail 'sealed Cargo vendor closure differs'
    fi
    if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = cpace-recovery-tests ]; then
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$rust_archive")" = \
          "1000:1000:400:1:$SIZE_RUST_1_75" ] \
            && [ "$(sha256sum "$rust_archive" | awk '{ print $1 }')" = "$SHA256_RUST_1_75" ] \
            || fail 'sealed Rust 1.75 archive differs'
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$image_archive")" = \
          "1000:1000:400:1:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
            && [ "$(sha256sum "$image_archive" | awk '{ print $1 }')" = \
                 "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" ] \
            || fail 'sealed Debian-builder image archive differs'
        load_output="$(
            setpriv --reuid=1000 --regid=1000 --clear-groups \
                env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
                DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
                python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                    --archive "$image_archive" \
                    --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
                    --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
                    --role deb-builder \
                    --expected-id "$DEB_BUILDER_IMAGE_ID" \
                    --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
                    --dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
                    --recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
                    --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
                    --bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
                    --bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                    --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                    --config-id "$DEB_BUILDER_CONFIG_ID" \
                    --manifest-id "$DEB_BUILDER_MANIFEST_ID"
        )" || fail 'certified Debian-builder image verification/load failed'
        [ "$load_output" = "loaded and verified deb-builder $DEB_BUILDER_IMAGE_ID" ] \
            || fail "Debian-builder image receipt differs: $load_output"
    else
        if [ "$MODE" = android-rust-lifecycle-tests ]; then
            bridge_inputs=(
                "$rust_archive:$SIZE_RUST_1_75:$SHA256_RUST_1_75"
                "$flutter_archive:$SIZE_FLUTTER_3_24_5:$SHA256_FLUTTER_3_24_5"
                "$llvm_archive:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6"
                "$builder_archive:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE"
            )
        else
            bridge_inputs=()
        fi
        for input in "${bridge_inputs[@]}"; do
            path=${input%%:*}
            remainder=${input#*:}
            size=${remainder%%:*}
            digest=${remainder#*:}
            [ "$(stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
              "1000:1000:400:1:$size" ] \
                && [ "$(sha256sum "$path" | awk '{ print $1 }')" = "$digest" ] \
                || fail "sealed Android Rust bridge input differs: $path"
        done
        if [ "$MODE" = android-rust-lifecycle-tests ]; then
            [ "$(stat -c '%u:%g:%a:%h:%s' -- "$frb_codegen")" = \
              "1000:1000:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
                && [ "$(sha256sum "$frb_codegen" | awk '{ print $1 }')" = \
                     "$SHA256_FLUTTER_PEER_FRB_CODEGEN" ] \
                || fail 'sealed Android Rust FRB generator differs'
            [ -d "$pub_cache" ] && [ ! -L "$pub_cache" ] \
                && [ "$(stat -c '%u:%g:%a' -- "$pub_cache")" = 1000:1000:500 ] \
                || fail 'sealed Android Rust Pub-cache root metadata differs'
            pub_receipt="$(
                setpriv --reuid=1000 --regid=1000 --clear-groups \
                    env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
                    python3 -I -S "$pub_validator" \
                        check-complete --online "$inputs" --uid 1000 --gid 1000
            )" || fail 'sealed Android Rust Pub-cache closure validation failed'
            [ "$pub_receipt" = "sha256=$SHA256_PUB_CACHE_CLOSURE_V1" ] \
                || fail "sealed Android Rust Pub-cache receipt differs: $pub_receipt"
        fi
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$image_archive")" = \
          "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
            && [ "$(sha256sum "$image_archive" | awk '{ print $1 }')" = \
                 "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
            || fail 'sealed development-check image archive differs'
        load_output="$(
            setpriv --reuid=1000 --regid=1000 --clear-groups \
                env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
                DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
                python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                    --archive "$image_archive" \
                    --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                    --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                    --role devcheck \
                    --expected-id "$DEV_CHECK_IMAGE_ID" \
                    --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                    --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                    --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                    --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                    --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                    --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                    --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                    --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                    --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                    --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
        )" || fail 'development-check image verification/load failed'
        [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
            || fail "development-check image receipt differs: $load_output"
        if [ "$MODE" = android-rust-lifecycle-tests ]; then
            generate_focused_rust_flutter_bridge
            bridge_mounts=(
                --mount "type=bind,source=$ROOT/focused-rust-bridge/bridge_generated.rs,target=/source/src/bridge_generated.rs,readonly"
                --mount "type=bind,source=$ROOT/focused-rust-bridge/bridge_generated.io.rs,target=/source/src/bridge_generated.io.rs,readonly"
            )
        fi
    fi

    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create \
            --name "$container_name" \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=1024 \
            --memory="$memory" \
            --memory-swap="$memory" \
            --cpus=4 \
            --ulimit nofile=4096:4096 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --env "RUST_TEST_MODE=$MODE" \
            --env "RUST_TOOLCHAIN_MODE=$toolchain_mode" \
            --env RUSTDESK_CANARY_OFFLINE=1 \
            --mount "type=bind,source=$source_root,target=/source,readonly" \
            --mount "type=bind,source=$target_root,target=/cargo-target" \
            "${dependency_mounts[@]}" \
            "${toolchain_mount[@]}" \
            "${bridge_mounts[@]}" \
            "${pa_mounts[@]}" \
            "${pa_env[@]}" \
            --tmpfs "/tmp:rw,exec,nosuid,nodev,size=$tmpfs_size,mode=700,uid=1000,gid=1000" \
            --workdir /source \
            "$image_config" /bin/bash --noprofile --norc -euo pipefail -c '
                set -- /sys/class/net/*
                [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
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
                [ "$uid" = 1000:1000:1000:1000 ]
                [ "$gid" = 1000:1000:1000:1000 ]
                [ "$cap" = 0000000000000000 ]
                [ "$nnp" = 1 ]
                [ "$seccomp" = 2 ]
                IFS= read -r apparmor </proc/self/attr/current
                case "$apparmor" in docker-default\ *) ;; *) exit 92 ;; esac
                mkdir /tmp/home /tmp/cargo-home
                if [ "$RUST_TEST_MODE" != linux-service-uid-tests ]; then
                    sed "s#^directory = \"/online/cargo-vendor\"#directory = \"/vendor\"#" \
                        /inputs/config.toml >/tmp/cargo-home/config.toml
                    [ "$(grep -Fc '\''directory = "/vendor"'\'' /tmp/cargo-home/config.toml)" -eq 1 ]
                fi
                case "$RUST_TOOLCHAIN_MODE" in
                    archive)
                        mkdir /tmp/toolchain /tmp/rust
                        tar -C /tmp/toolchain -xf /inputs/rust.tar.xz
                        /tmp/toolchain/rust-1.75.0-x86_64-unknown-linux-gnu/install.sh \
                            --prefix=/tmp/rust --disable-ldconfig >/dev/null
                        unset RUSTUP_TOOLCHAIN
                        export RUSTUP_HOME=/nonexistent PATH=/tmp/rust/bin:/usr/bin:/bin
                        ;;
                    devcheck-image)
                        toolchain_bin=/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin
                        [ -x "$toolchain_bin/cargo" ] && [ -x "$toolchain_bin/rustc" ]
                        unset RUSTUP_TOOLCHAIN
                        export RUSTUP_HOME=/nonexistent RUSTC="$toolchain_bin/rustc" \
                            PATH="$toolchain_bin:/usr/bin:/bin"
                        ;;
                    *) exit 94 ;;
                esac
                export HOME=/tmp/home CARGO_HOME=/tmp/cargo-home \
                    CARGO_TARGET_DIR=/cargo-target LANG=C LC_ALL=C CARGO_NET_OFFLINE=true
                [ "$(rustc --version)" = "rustc 1.75.0 (82e1608df 2023-12-21)" ]
                [ "$(cargo --version)" = "cargo 1.75.0 (1d8b05cdd 2023-11-20)" ]
                case "$RUST_TEST_MODE" in
                    hbb-common-fs)
                        cargo test --offline --locked -p hbb_common --lib \
                            config::tests::config_transaction_ --color never -- --test-threads=1
                        cargo test --offline --locked -p hbb_common --lib \
                            fs::tests:: --color never -- --test-threads=1
                        ;;
                    cpace-recovery-tests)
                        cargo test --offline --locked -p cpace_it --test handshake \
                            --color never -- --test-threads=1
                        ;;
                    linux-pa-authority-tests)
                        /bin/bash /source/scripts/run-pa-runtime-tests.sh /inputs/pa-runtime.tar.gz
                        ;;
                    linux-service-uid-tests)
                        python3 -I -S /source/scripts/verify-linux-service-password-ipc.py --repo /source
                        rustc --edition=2021 --test /source/scripts/test-linux-service-uid-policy.rs \
                            -o /cargo-target/uid-policy-tests
                        /cargo-target/uid-policy-tests --test-threads=1 --color never
                        ;;
                    android-rust-lifecycle-tests)
                        python3 -I -S /source/scripts/verify-linux-service-password-ipc.py --repo /source
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            ipc::uid_policy::tests::r_s11e60_ --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            android_listener_lifecycle::tests:: --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            client::tests::r_p14 \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            direct_service::direct_connection_task_tests:: --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            ui_cm_interface::tests::r_s11is_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            client::io_loop::tests::r_s11fi_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            client::io_loop::tests::r_s11fj_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            r_s11iu_ --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            ui_session_interface::connection_round_ownership_tests::credential_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            flutter::mobile_session_lifecycle_tests::r_s11ew_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            flutter::mobile_session_lifecycle_tests::r_s11fr_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            flutter::mobile_session_lifecycle_tests::r_s11iw_ \
                            --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            flutter::mobile_session_lifecycle_tests::r_s11ex_desktop_tab_move_requires_live_source_and_preserves_peer_on_old_close \
                            --color never -- --test-threads=1
                        ;;
                    *) exit 93 ;;
                esac
            '
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust-test container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      "none|true|1000:1000|$memory_bytes|$memory_bytes|4000000000|1024|[\"ALL\"]|[\"no-new-privileges\",\"apparmor=docker-default\"]" ] \
        || fail "focused Rust-test container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "focused Rust-test container namespace/device/port authority differs: $namespace_inspect"
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 200 "$output" >&2; fail "focused Rust tests exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || fail 'focused Rust-test output exceeds its bound'
    if [ "$MODE" = android-rust-lifecycle-tests ] \
       || [ "$MODE" = linux-pa-authority-tests ]; then
        grep -Fq 'R-B10 canary: build confirmed network-isolated (offline compile stage).' "$output" \
            || { tail -n 200 "$output" >&2; fail 'focused Rust build did not execute its offline network canary'; }
    fi
    mapfile -t result_lines < <(
        grep -E '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+s$' "$output"
    )
    if [ "$MODE" = hbb-common-fs ]; then
        [ "${#result_lines[@]}" -eq 2 ] \
            || { tail -n 200 "$output" >&2; fail 'focused filesystem test summary count differs'; }
    elif [ "$MODE" = cpace-recovery-tests ]; then
        [ "${#result_lines[@]}" -eq 1 ] \
            || { tail -n 200 "$output" >&2; fail 'focused CPace recovery summary count differs'; }
    elif [ "$MODE" = linux-pa-authority-tests ]; then
        [ "${#result_lines[@]}" -eq 5 ] \
            || { tail -n 200 "$output" >&2; fail 'focused Linux PulseAudio summary count differs'; }
        grep -Fxq "PA_RUNTIME_ARCHIVE=pass packages=40 base=$DEV_CHECK_IMAGE_ID sha256=$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" "$output" \
            || { tail -n 200 "$output" >&2; fail 'PulseAudio candidate admission receipt is absent'; }
        grep -Fxq 'PA_RUNTIME_MONITOR=pass source=rd_pa_test.monitor signal=sine440 probe=pacat-native' "$output" \
            || { tail -n 200 "$output" >&2; fail 'native PulseAudio monitor probe receipt is absent'; }
        grep -Fxq 'PA_RUNTIME_NATIVE=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 revocation=after-unload same_uid_stolen_token=refused network=none uid=1000 cleanup=joined' "$output" \
            || { tail -n 200 "$output" >&2; fail 'native PulseAudio capture receipt is absent'; }
    elif [ "$MODE" = linux-service-uid-tests ]; then
        [ "${#result_lines[@]}" -eq 1 ] \
            || { tail -n 200 "$output" >&2; fail 'Linux UID-policy summary count differs'; }
        [ "$(grep -Ec '^test uid_policy::tests::.* \.\.\. ok$' "$output")" -eq "${#required_tests[@]}" ] \
            || fail 'Linux UID-policy named test count differs'
        grep -Fxq 'verify-linux-service-password-ipc: ok' "$output" \
            || { tail -n 200 "$output" >&2; fail 'password IPC source guard did not pass'; }
        [ -f "$target_root/uid-policy-tests" ] && [ ! -L "$target_root/uid-policy-tests" ] \
            && [ "$(stat -c '%u:%g:%h' -- "$target_root/uid-policy-tests")" = 1000:1000:1 ] \
            || fail 'compiled UID-policy test artifact metadata differs'
        uid_test_artifact_sha="$(sha256sum "$target_root/uid-policy-tests" | awk '{ print $1 }')"
        [[ "$uid_test_artifact_sha" =~ ^[0-9a-f]{64}$ ]] \
            || fail 'compiled UID-policy test artifact digest is malformed'
    else
        [ "${#result_lines[@]}" -eq 13 ] \
            || { tail -n 200 "$output" >&2; fail 'Android Rust-lifecycle summary count differs'; }
        grep -Fxq 'verify-linux-service-password-ipc: ok' "$output" \
            || { tail -n 200 "$output" >&2; fail 'password IPC source guard did not pass'; }
    fi
    [ "$(grep -Ec '^test result: ' "$output")" -eq "${#result_lines[@]}" ] \
        || fail 'focused Rust-test output contains a non-success result summary'
    for result_line in "${result_lines[@]}"; do
        passed="$(printf '%s\n' "$result_line" | sed -E 's/^test result: ok\. ([0-9]+) passed;.*/\1/')"
        tests_passed=$((tests_passed + passed))
    done
    for test_name in "${required_tests[@]}"; do
        grep -Fxq "test $test_name ... ok" "$output" \
            || { tail -n 200 "$output" >&2; fail "load-bearing Rust test did not pass: $test_name"; }
    done
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused Rust-test container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$image_config" >/dev/null
    [ "$source_before" = \
      "$source_archive_sha:$(
          cd "$source_root"
          sha256sum "${source_fingerprints[@]}"
      )" ] \
        || fail 'focused Rust-test source inputs changed during execution'
    if [ "$MODE" = android-rust-lifecycle-tests ]; then
        post_pub_receipt="$(
            setpriv --reuid=1000 --regid=1000 --clear-groups \
                env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
                python3 -I -S "$pub_validator" \
                    check-complete --online "$inputs" --uid 1000 --gid 1000
        )" || fail 'sealed Android Rust Pub-cache postcondition validation failed'
        [ "$post_pub_receipt" = "$pub_receipt" ] \
            || fail 'sealed Android Rust Pub-cache closure changed during execution'
    fi
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire the sealed focused-test input mount'
    SEALED_INPUTS_MOUNTED=0
    if [ "$MODE" = android-rust-lifecycle-tests ]; then
        grep -E '^test ipc::uid_policy::tests::r_s11e60_.* \.\.\. ok$|^verify-linux-service-password-ipc: ok$' "$output"
    elif [ "$MODE" = linux-service-uid-tests ]; then
        grep -E '^test uid_policy::tests::.* \.\.\. ok$|^verify-linux-service-password-ipc: ok$' "$output"
    fi
    printf '%s\n' "${result_lines[@]}"
    if [ "$MODE" = hbb-common-fs ]; then
        printf 'HBB_COMMON_FS_VM=pass commit=%s tree=%s tests=%s rust=1.75.0 vendor=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$DEB_BUILDER_IMAGE_ID" \
            "$DEB_BUILDER_CONFIG_ID"
    elif [ "$MODE" = cpace-recovery-tests ]; then
        [ "$tests_passed" -eq 20 ] \
            || fail "CPace recovery test count differs: $tests_passed"
        printf 'CPACE_RECOVERY_VM=pass commit=%s tree=%s tests=%s rust=1.75.0 vendor=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$DEB_BUILDER_IMAGE_ID" \
            "$DEB_BUILDER_CONFIG_ID"
    elif [ "$MODE" = linux-pa-authority-tests ]; then
        [ "$tests_passed" -eq "${#required_tests[@]}" ] \
            || fail "Linux PulseAudio authority test count differs: $tests_passed"
        printf 'LINUX_PA_AUTHORITY_VM=pass commit=%s tree=%s tests=%s rust=1.75.0 vendor=%s devcheck_index=%s devcheck_runtime=%s pa_candidate=%s pa_native=monitor-capture-revocation-and-same-uid-peer-refusal uid=1000 gid=1000 vm_network=none container_network=none source=readonly target_dir=private-ephemeral offline_canary=pass root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$image_index" "$image_config" \
            "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256"
    elif [ "$MODE" = linux-service-uid-tests ]; then
        [ "$tests_passed" -eq "${#required_tests[@]}" ] \
            || fail "Linux UID-policy test count differs: $tests_passed"
        printf 'LINUX_SERVICE_UID_VM=pass commit=%s tree=%s tests=%s artifact_sha256=%s target=linux-x86_64 scope=production-uid-policy-and-source-wiring rust=1.75.0 edition=2021 devcheck_index=%s devcheck_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none source=readonly target_dir=private-ephemeral root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$uid_test_artifact_sha" "$image_index" "$image_config"
    else
        [ "$tests_passed" -eq "${#required_tests[@]}" ] \
            || fail "Android Rust-lifecycle test count differs: $tests_passed"
        printf 'ANDROID_RUST_LIFECYCLE_VM=pass commit=%s tree=%s tests=%s target=linux-x86_64 scope=listener-generation-child-convergence-exact-resource-owners-typed-viewer-keying-software-rgba-mailbox-cm-file-framing-and-admission-linux-service-uid-selection rust=1.75.0 flutter=3.24.5 llvm=15.0.6 frb=%s vendor=%s pub_cache=%s bridge_builder=%s devcheck_index=%s devcheck_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none source=readonly generated_bridge=readonly target_dir=private-ephemeral offline_canary=pass root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$SHA256_PUB_CACHE_CLOSURE_V1" \
            "$DEB_BUILDER_CONFIG_ID" "$image_index" "$image_config"
    fi
}

run_android_rust_target_check() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/android-rust-target-source
    local online_mount=$source_root/online/inputs
    local output=$ROOT/android-rust-target-check.out
    local builder_archive=$inputs/build-images/android-builder.docker.tar.gz
    local source_archive_sha source_tree_before source_tree_after
    local input_mount_options online_mount_options load_output workload_status=0
    local entry_count focused_input_verification_count
    local expected_entry="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root"
    local -a git_builder=(
        setpriv --reuid=1000 --regid=1000 --clear-groups
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
        GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
        GIT_NO_REPLACE_OBJECTS=1
    )

    [[ "$RUST_TEST_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android Rust target-check source commit is malformed'
    [[ "$RUST_TEST_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android Rust target-check source tree is malformed'
    [[ "$RUST_TEST_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android Rust target-check source archive digest is malformed'
    [ -f "$RUST_TEST_SOURCE_ARCHIVE" ] && [ ! -L "$RUST_TEST_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'Android Rust target-check source archive metadata differs'
    source_archive_sha="$(sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$RUST_TEST_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android Rust target-check source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$RUST_TEST_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact Android Rust target-check source archive'
    [ -z "$(find "$source_root" -xdev \
        \( ! -type d -a ! -type f \) -print -quit)" ] \
        || fail 'Android Rust target-check source archive contains a special entry'
    chown -R 1000:1000 "$source_root"
    chmod -R u=rwX,go=rX "$source_root"
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'Android Rust target-check source archive differs from its guest bootstrap'
    [ "$(stat -c '%u:%g:%a:%h' -- \
            "$source_root/scripts/android-rust-check.sh" \
            "$source_root/scripts/android-apk-build.sh" \
            "$source_root/scripts/verify-vm-entry-preflight.sh" \
            "$source_root/scripts/verify-android-build-source.py" \
            "$source_root/scripts/verify-private-tree-closure.py" \
            "$source_root/scripts/offline-image-provenance.py" \
            "$source_root/scripts/online-input-provenance.py")" = \
      $'1000:1000:755:1\n1000:1000:755:1\n1000:1000:755:1\n1000:1000:755:1\n1000:1000:755:1\n1000:1000:755:1\n1000:1000:755:1' ] \
        || fail 'Android Rust target-check production entry metadata differs'

    "${git_builder[@]}" /usr/bin/git -c core.hooksPath=/dev/null \
        -c init.defaultBranch=master -C "$source_root" init -q \
        || fail 'cannot initialize the exact Android Rust target-check Git index'
    "${git_builder[@]}" /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$source_root" add -f -- . \
        || fail 'cannot index the exact Android Rust target-check source'
    source_tree_before="$(
        "${git_builder[@]}" /usr/bin/git -c core.hooksPath=/dev/null \
            -C "$source_root" write-tree
    )" || fail 'cannot resolve the Android Rust target-check source tree'
    [ "$source_tree_before" = "$RUST_TEST_SOURCE_TREE" ] \
        || fail 'Android Rust target-check reconstructed source tree differs'

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android Rust target-check input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android Rust target-check input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android Rust target-check inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android Rust target-check inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android Rust target-check inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in
        *,noexec,*) fail 'sealed Android Rust target-check inputs forbid the authenticated toolchain' ;;
    esac

    install -d -o 1000 -g 1000 -m 0755 -- "$source_root/online" "$online_mount"
    mount --bind "$inputs" "$online_mount" \
        || fail 'cannot project the sealed closure into the Android Rust target-check source'
    ANDROID_RUST_ONLINE_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid "$online_mount" \
        || fail 'cannot make the Android Rust target-check input projection read-only'
    online_mount_options="$(findmnt -n -o OPTIONS --target "$online_mount")" \
        || fail 'Android Rust target-check input projection is absent'
    case ",$online_mount_options," in *,ro,*) ;; *) fail 'Android Rust target-check input projection is writable' ;; esac
    case ",$online_mount_options," in *,nodev,*) ;; *) fail 'Android Rust target-check input projection permits devices' ;; esac
    case ",$online_mount_options," in *,nosuid,*) ;; *) fail 'Android Rust target-check input projection permits set-user-ID execution' ;; esac
    case ",$online_mount_options," in
        *,noexec,*) fail 'Android Rust target-check input projection forbids the authenticated toolchain' ;;
    esac

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android-builder image archive differs'
    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role android-builder \
                --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
                --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
                --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$ANDROID_BUILDER_CONFIG_ID" \
                --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
    )" || fail 'certified Android-builder image verification/load failed'
    [ "$load_output" = "loaded and verified android-builder $ANDROID_BUILDER_IMAGE_ID" ] \
        || fail "Android-builder image receipt differs: $load_output"

    if /bin/bash "$source_root/scripts/android-rust-check.sh" --focused-target-check \
        >"$ROOT/root-android-rust-target.out" \
        2>"$ROOT/root-android-rust-target.err"; then
        fail 'VM root passed the Android Rust target-check entry'
    fi
    [ ! -s "$ROOT/root-android-rust-target.out" ] \
        || fail 'root Android Rust target-check refusal produced standard output'
    [ "$(<"$ROOT/root-android-rust-target.err")" = \
      'Android Rust release check refuses host or container-root execution' ] \
        || fail 'root Android Rust target-check refusal diagnostic differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        /bin/bash "$source_root/scripts/android-rust-check.sh" --focused-target-check \
        >"$ROOT/foreign-android-rust-target.out" \
        2>"$ROOT/foreign-android-rust-target.err"; then
        fail 'foreign principal passed the Android Rust target-check entry'
    fi
    [ ! -s "$ROOT/foreign-android-rust-target.out" ] \
        || fail 'foreign Android Rust target-check refusal produced standard output'
    [ "$(<"$ROOT/foreign-android-rust-target.err")" = \
      'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign Android Rust target-check refusal diagnostic differs'

    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/android-rust-check.sh" --focused-target-check \
        >"$output" 2>&1
    workload_status=$?
    set -e
    [ "$workload_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "Android Rust target check exited with status $workload_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 16777216 ] \
        || fail 'Android Rust target-check output exceeds its bound'
    entry_count="$(grep -Fxc "$expected_entry" "$output")"
    [ "$entry_count" -ge 1 ] \
        && [ "$(grep -Fc 'VERIFIER_VM_ENTRY_AUTHORITY=' "$output")" -eq "$entry_count" ] \
        || { tail -n 240 "$output" >&2; fail 'Android Rust target-check entry-authority receipts differ'; }
    [ "$(grep -Fxc 'ANDROID-RUST-CHECK: aarch64 Android Rust library is GREEN' "$output")" -eq 1 ] \
        || { tail -n 240 "$output" >&2; fail 'Android Rust target-check production verdict is absent or duplicated'; }
    [ "$(grep -Fc 'R-B10 canary: build confirmed network-isolated (offline compile stage).' "$output")" -ge 1 ] \
        || { tail -n 240 "$output" >&2; fail 'Android Rust target check did not execute its offline network canary'; }
    focused_input_verification_count="$(grep -Fxc "ANDROID_RUST_FOCUSED_INPUTS=verified vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 pub_cache=$SHA256_PUB_CACHE_CLOSURE_V1 vcpkg_key=$VCPKG_ARM64_ANDROID_OUTPUT_KEY_V1" "$output")"
    [ "$focused_input_verification_count" -eq 2 ] \
        || { tail -n 240 "$output" >&2; fail 'Android Rust target check did not verify its focused Android inputs before and after execution'; }
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'Android Rust target check left a container'
    "$CLIENT" --host "unix://$SOCK" image rm "$ANDROID_BUILDER_CONFIG_ID" >/dev/null \
        || fail 'Android Rust target-check image could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Android Rust target check left an image'

    source_tree_after="$(
        "${git_builder[@]}" /usr/bin/git -c core.hooksPath=/dev/null \
            -C "$source_root" write-tree
    )" || fail 'cannot re-resolve the Android Rust target-check source tree'
    [ "$source_tree_after" = "$source_tree_before" ] \
        && [ "$source_tree_after" = "$RUST_TEST_SOURCE_TREE" ] \
        || fail 'Android Rust target-check Git index changed during execution'
    "${git_builder[@]}" /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$source_root" diff-files --quiet -- \
        || fail 'Android Rust target-check tracked source changed during execution'
    [ "$(sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'Android Rust target-check source archive changed during execution'

    stop_docker_authority
    umount "$online_mount" \
        || fail 'cannot retire the Android Rust target-check input projection'
    ANDROID_RUST_ONLINE_MOUNTED=0
    umount "$inputs" \
        || fail 'cannot retire the sealed Android Rust target-check input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$expected_entry"
    printf 'ANDROID-RUST-CHECK: aarch64 Android Rust library is GREEN\n'
    printf 'ANDROID_RUST_TARGET_VM=pass commit=%s tree=%s target=aarch64-linux-android profile=focused-target-check builder_index=%s builder_runtime=%s vendor=%s pub_cache=%s vcpkg_key=%s uid=1000 gid=1000 root=refused foreign=refused vm_network=none container_network=none inputs=readonly-landlocked source=exact-pushed offline_canary=pass cleanup=joined\n' \
        "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" \
        "$ANDROID_BUILDER_IMAGE_ID" "$ANDROID_BUILDER_CONFIG_ID" \
        "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$SHA256_PUB_CACHE_CLOSURE_V1" \
        "$VCPKG_ARM64_ANDROID_OUTPUT_KEY_V1"
}

stage_android_owner_kotlin_jar() {
    local source_home=$1 staged_home=$2 group=$3 artifact=$4 version=$5
    local size=$6 digest=$7 source_root relative destination
    local -a matches=()

    source_root="$source_home/caches/modules-2/files-2.1/$group/$artifact/$version"
    [ -d "$source_root" ] && [ ! -L "$source_root" ] \
        || fail "sealed Android owner-state artifact root is absent: $group:$artifact:$version"
    mapfile -t matches < <(find "$source_root" -mindepth 2 -maxdepth 2 -type f \
        -name "$artifact-$version.jar" -print | LC_ALL=C sort)
    [ "${#matches[@]}" -eq 1 ] \
        || fail "expected one sealed Android owner-state artifact: $group:$artifact:$version"
    [ ! -L "${matches[0]}" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "${matches[0]}")" = \
             "1000:1000:400:1:$size" ] \
        && [ "$(sha256sum "${matches[0]}" | awk '{ print $1 }')" = "$digest" ] \
        || fail "sealed Android owner-state artifact differs: $group:$artifact:$version"
    relative=${matches[0]#"$source_home"/}
    [ "$relative" != "${matches[0]}" ] && [ -n "$relative" ] \
        || fail "sealed Android owner-state artifact escaped its root: $group:$artifact:$version"
    destination="$staged_home/$relative"
    install -D -o 1000 -g 1000 -m 0400 -- "${matches[0]}" "$destination"
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$destination")" = \
      "1000:1000:400:1:$size" ] \
        && [ "$(sha256sum "$destination" | awk '{ print $1 }')" = "$digest" ] \
        || fail "staged Android owner-state artifact differs: $group:$artifact:$version"
}

run_android_owner_tests() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/android-owner-source
    local output=$ROOT/android-owner-tests.out
    local builder_archive=$inputs/build-images/android-builder.docker.tar.gz
    local gradle_home=$inputs/gradle-home
    local staged_gradle_home=$ROOT/android-owner-gradle-home
    local load_output container_status=0 inspect namespace_inspect result_line
    local source_archive_sha input_mount_options source_before

    [[ "$ANDROID_OWNER_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Android owner-state source commit is malformed'
    [[ "$ANDROID_OWNER_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Android owner-state source tree is malformed'
    [[ "$ANDROID_OWNER_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Android owner-state source archive digest is malformed'
    [ -f "$ANDROID_OWNER_SOURCE_ARCHIVE" ] && [ ! -L "$ANDROID_OWNER_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_OWNER_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'focused Android owner-state source archive metadata differs'
    source_archive_sha="$(sha256sum "$ANDROID_OWNER_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$ANDROID_OWNER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Android owner-state source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$ANDROID_OWNER_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact Android owner-state source archive'
    chown -R 1000:1000 "$source_root"
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'Android owner-state source archive differs from its guest bootstrap'
    [ "$(stat -c '%u:%g:%a:%h' -- \
        "$source_root/scripts/test-android-owner-state.sh")" = 1000:1000:700:1 ] \
        || fail 'Android owner-state executable test entry metadata differs'
    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/test-android-owner-state.sh" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledConnectionType.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledCaptureOwnerState.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledInputOwner.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ExactOwnerBoundedQueue.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainServiceGenerationOwner.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainServiceStatusOwner.kt" \
        "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerState.kt" \
        "$source_root/flutter/android/app/src/test/kotlin/com/carriez/flutter_hbb/AndroidOwnerStateTest.kt" \
        "$source_root/flutter/android/app/src/test/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerStateTest.kt")"

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android owner-state input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android owner-state input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android owner-state inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android owner-state inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android owner-state inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed Android owner-state inputs permit direct execution' ;; esac

    [ -d "$gradle_home" ] && [ ! -L "$gradle_home" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$gradle_home")" = 1000:1000:500 ] \
        || fail 'sealed Android owner-state Gradle seed metadata differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android-builder image archive differs'

    [ ! -e "$staged_gradle_home" ] && [ ! -L "$staged_gradle_home" ] \
        || fail 'private Android owner-state compiler staging root is occupied'
    mkdir "$staged_gradle_home"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlin kotlin-compiler-embeddable "$ANDROID_KOTLIN_VERSION" \
        "$SIZE_ANDROID_KOTLIN_COMPILER_EMBEDDABLE" "$SHA256_ANDROID_KOTLIN_COMPILER_EMBEDDABLE"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlin kotlin-stdlib "$ANDROID_KOTLIN_STDLIB_VERSION" \
        "$SIZE_ANDROID_KOTLIN_STDLIB" "$SHA256_ANDROID_KOTLIN_STDLIB"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlin kotlin-script-runtime "$ANDROID_KOTLIN_VERSION" \
        "$SIZE_ANDROID_KOTLIN_SCRIPT_RUNTIME" "$SHA256_ANDROID_KOTLIN_SCRIPT_RUNTIME"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlin kotlin-reflect "$ANDROID_KOTLIN_COMPILER_REFLECT_VERSION" \
        "$SIZE_ANDROID_KOTLIN_REFLECT" "$SHA256_ANDROID_KOTLIN_REFLECT"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlin kotlin-daemon-embeddable "$ANDROID_KOTLIN_VERSION" \
        "$SIZE_ANDROID_KOTLIN_DAEMON_EMBEDDABLE" "$SHA256_ANDROID_KOTLIN_DAEMON_EMBEDDABLE"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.intellij.deps trove4j "$ANDROID_KOTLIN_COMPILER_TROVE_VERSION" \
        "$SIZE_ANDROID_KOTLIN_COMPILER_TROVE" "$SHA256_ANDROID_KOTLIN_COMPILER_TROVE"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains.kotlinx kotlinx-coroutines-core-jvm "$ANDROID_KOTLIN_COMPILER_COROUTINES_VERSION" \
        "$SIZE_ANDROID_KOTLIN_COMPILER_COROUTINES" "$SHA256_ANDROID_KOTLIN_COMPILER_COROUTINES"
    stage_android_owner_kotlin_jar "$gradle_home" "$staged_gradle_home" \
        org.jetbrains annotations "$ANDROID_KOTLIN_COMPILER_ANNOTATIONS_VERSION" \
        "$SIZE_ANDROID_KOTLIN_COMPILER_ANNOTATIONS" "$SHA256_ANDROID_KOTLIN_COMPILER_ANNOTATIONS"
    find "$staged_gradle_home" -type d -exec chmod 0555 {} +
    [ -z "$(find "$staged_gradle_home" -xdev \
        \( \( ! -type d -a ! -type f \) \
           -o \( -type d -a \( ! -uid 0 -o ! -gid 0 -o ! -perm 0555 \) \) \
           -o \( -type f -a \( ! -uid 1000 -o ! -gid 1000 -o ! -perm 0400 -o -links +1 \) \) \) \
        -print -quit)" ] \
        || fail 'private Android owner-state compiler staging closure is ambiguous'

    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role android-builder \
                --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
                --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
                --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$ANDROID_BUILDER_CONFIG_ID" \
                --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
    )" || fail 'certified Android-builder image verification/load failed'
    [ "$load_output" = "loaded and verified android-builder $ANDROID_BUILDER_IMAGE_ID" ] \
        || fail "Android-builder image receipt differs: $load_output"

    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create \
            --name rustdesk-android-owner-tests \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=128 \
            --memory=1g \
            --memory-swap=1g \
            --cpus=2 \
            --ulimit nofile=512:512 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --mount "type=bind,source=$source_root,target=/source,readonly" \
            --mount "type=bind,source=$staged_gradle_home,target=/online/gradle-home,readonly" \
            --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g,mode=700,uid=1000,gid=1000 \
            --workdir /source \
            "$ANDROID_BUILDER_CONFIG_ID" \
            /bin/bash --noprofile --norc \
                /source/scripts/test-android-owner-state.sh \
                /online/gradle-home /tmp/android-owner-state-test
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Android owner-state container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      'none|true|1000:1000|1073741824|1073741824|2000000000|128|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
        || fail "focused Android owner-state container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "focused Android owner-state container namespace/device/port authority differs: $namespace_inspect"
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 160 "$output" >&2; fail "focused Android owner-state tests exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 65536 ] \
        || fail 'focused Android owner-state output exceeds its bound'
    result_line="$(grep -Fx \
        'ANDROID_OWNER_STATE_SUITE=pass classes=7 scenarios=15 assertions=305 kotlin=2.0.21' \
        "$output")" \
        || { tail -n 160 "$output" >&2; fail 'focused Android owner-state success receipt is absent'; }
    [ "$(grep -Fc 'ANDROID_OWNER_STATE_SUITE=' "$output")" -eq 1 ] \
        || fail 'focused Android owner-state success receipt is duplicated'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused Android owner-state container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$ANDROID_BUILDER_CONFIG_ID" >/dev/null
    [ "$source_before" = \
      "$source_archive_sha:$(sha256sum \
          "$source_root/scripts/pins.env" \
          "$source_root/scripts/test-android-owner-state.sh" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledConnectionType.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledCaptureOwnerState.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledInputOwner.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ExactOwnerBoundedQueue.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainServiceGenerationOwner.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainServiceStatusOwner.kt" \
          "$source_root/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerState.kt" \
          "$source_root/flutter/android/app/src/test/kotlin/com/carriez/flutter_hbb/AndroidOwnerStateTest.kt" \
          "$source_root/flutter/android/app/src/test/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerStateTest.kt")" ] \
        || fail 'focused Android owner-state source inputs changed during execution'
    [ "$(sha256sum "$ANDROID_OWNER_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'focused Android owner-state source archive changed during execution'
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire the sealed Android owner-state input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$result_line"
    printf 'ANDROID_OWNER_STATE_VM=pass commit=%s tree=%s classes=7 scenarios=15 assertions=305 kotlin=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none compiler_inputs=verified-copy-readonly root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
        "$ANDROID_OWNER_SOURCE_COMMIT" "$ANDROID_OWNER_SOURCE_TREE" \
        "$ANDROID_KOTLIN_VERSION" "$ANDROID_BUILDER_IMAGE_ID" \
        "$ANDROID_BUILDER_CONFIG_ID"
}

run_cm_file_replay() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/cm-file-replay-source
    local target=$ROOT/cm-file-replay-target
    local flat=$ROOT/cm-file-replay-flat
    local work=$ROOT/cm-file-replay-work
    local machine_id=$work/server.machine-id
    local machine_id_value=727573746465736b2d73657276657231
    local build_output=$ROOT/cm-file-build.out
    local output=$ROOT/cm-file-replay.out
    local pa_output=$ROOT/cm-pa-product-pair.out
    local pa_candidate=/mnt/rustdesk-verifier-inputs/pa-runtime-candidate.tar.gz
    local pa_copy=$ROOT/cm-pa-runtime.tar.gz
    local xvfb_inputs=$ROOT/cm-xvfb-inputs
    local image=$inputs/verifier-images/devcheck.docker.tar.gz
    local source_sha load_output inspect machine_mount status=0 manifest_sha
    local -a git_builder=(
        setpriv --reuid=1000 --regid=1000 --clear-groups
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
        GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
    )
    [[ "$ANDROID_EMULATOR_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$ANDROID_EMULATOR_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'CM file replay identities are malformed'
    [ -f "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] && [ ! -L "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = 4000:4000:400:1 ] \
        || fail 'CM file replay harness source archive authority differs'
    source_sha="$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_sha" = "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'CM file replay harness archive digest differs'
    [ ! -e "$source_root" ] && [ ! -L "$source_root" ] \
        || fail 'CM file replay source workspace already exists'
    mkdir -m 0700 "$source_root"
    tar -xf "$ANDROID_EMULATOR_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions -C "$source_root" \
        || fail 'cannot extract exact CM file replay harness source'
    [ -z "$(find "$source_root" -xdev \( ! -type d -a ! -type f \) -print -quit)" ] \
        || fail 'CM file replay harness archive contains a non-file entry'
    chown -R 1000:1000 "$source_root"
    "${git_builder[@]}" /usr/bin/git -c init.defaultBranch=master -C "$source_root" init -q
    "${git_builder[@]}" /usr/bin/git -C "$source_root" add -f -- .
    [ "$("${git_builder[@]}" /usr/bin/git -C "$source_root" write-tree)" = \
      "$ANDROID_EMULATOR_SOURCE_TREE" ] \
        || fail 'CM file replay harness archive tree differs from pushed master'
    rm -rf -- "$source_root/.git"
    [ -f "$source_root/scripts/smoke-server-stage.sh" ] \
        && [ -f "$source_root/scripts/smoke-ready.sh" ] \
        && [ -f "$source_root/scripts/smoke-process-guard.py" ] \
        && [ -f "$source_root/scripts/smoke-pa-process-pair-probe.py" ] \
        || fail 'CM file replay harness programs are absent'

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount sealed CM file replay inputs'
    SEALED_INPUTS_MOUNTED=1
    local options
    options="$(findmnt -n -o OPTIONS --target "$inputs")"
    for option in ro nodev nosuid; do
        case ",$options," in *,$option,*) ;; *) fail "CM file input lacks $option" ;; esac
    done
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$image")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$image" | awk '{ print $1 }')" = "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'CM file replay devcheck image differs'
    load_output="$(setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
        python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
            --archive "$image" --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
            --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" --role devcheck \
            --expected-id "$DEV_CHECK_IMAGE_ID" --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
            --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
            --cargo-sha "$SHA256_DEV_CHECK_CARGO" --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
            --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
            --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
            --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID")" \
        || fail 'CM file replay devcheck image verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail 'CM file replay devcheck load receipt differs'
    [ -f "$pa_candidate" ] && [ ! -L "$pa_candidate" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$pa_candidate")" = \
             "4000:4000:400:1:$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$pa_candidate" | awk '{ print $1 }')" = \
             "$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" ] \
        || fail 'CM product-pair PulseAudio candidate differs'
    install -o 1000 -g 1000 -m 0400 -- "$pa_candidate" "$pa_copy"
    install -d -o 1000 -g 1000 -m 0700 "$xvfb_inputs"
    local package count=0 name size digest url extra
    while IFS=$'\t' read -r name size digest url extra; do
        [ -n "$name" ] || continue
        [[ "$name" == \#* ]] && continue
        [ -z "$extra" ] && [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] \
            || fail 'CM product-pair Xvfb manifest differs'
        package=/mnt/rustdesk-verifier-inputs/xvfb-debs/$name.deb
        [ -f "$package" ] && [ ! -L "$package" ] \
            && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$package")" = "4000:4000:400:1:$size" ] \
            && [ "$(sha256sum "$package" | awk '{ print $1 }')" = "$digest" ] \
            || fail "CM product-pair Xvfb package differs: $name"
        install -o 1000 -g 1000 -m 0400 -- "$package" "$xvfb_inputs/$name.deb"
        count=$((count + 1))
    done <"$source_root/scripts/smoke-xvfb-packages.tsv"
    [ "$count" -eq 5 ] || fail 'CM product-pair Xvfb package count differs'
    prepare_engine_xvfb "$xvfb_inputs" "$source_root/scripts"

    install -d -o 1000 -g 1000 -m 0700 "$work" "$target"
    printf 'CM_FILE_BUILD_STAGE=begin commit=%s tree=%s builder=%s\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" "$DEV_CHECK_IMAGE_CONFIG_ID"
    CONTAINER_ID="$("$CLIENT" --host "unix://$SOCK" create \
        --name rustdesk-cm-file-build --pull=never --network=none --read-only \
        --user 1000:1000 --pids-limit=1024 --memory=12g --memory-swap=12g --cpus=4 \
        --ulimit nofile=8192:8192 --ulimit core=0:0 \
        --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g \
        --env HOME=/tmp/android-peer-build --env CARGO_HOME=/tmp/smoke-cargo-home \
        --env CARGO_TARGET_DIR=/smoke-target --env CARGO_INCREMENTAL=0 \
        --env CARGO_NET_OFFLINE=true --env CARGO_NET_RETRY=0 \
        --env "RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
        --env "SMOKE_EXPECTED_RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
        --env "SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256=$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        --env "SMOKE_EXPECTED_VENDOR_CONFIG_SHA256=$SHA256_CARGO_VENDOR_CONFIG" \
        --mount "type=bind,source=$source_root,target=/work,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$inputs,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$target,target=/smoke-target,bind-recursive=disabled" \
        --workdir /work "$DEV_CHECK_IMAGE_CONFIG_ID" \
        /bin/bash --noprofile --norc /work/scripts/smoke-server-stage.sh cm-file-build)"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'CM file build container identity is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' "$CONTAINER_ID")"
    [ "$inspect" = 'none|true|1000:1000|12884901888|12884901888|4000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
        || fail 'CM file build container confinement differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' "$CONTAINER_ID")"
    [ "$inspect" = 'false||private||private' ] \
        || fail 'CM file build container namespace authority differs'
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" 2>&1 \
        | tee "$build_output" || status=$?
    [ "$status" -eq 0 ] && [ "$(stat -c '%s' -- "$build_output")" -le 4194304 ] \
        || { tail -n 160 "$build_output" >&2; fail "CM file build failed: $status"; }
    [ "$(grep -Fxc 'CM_FILE_BUILD=pass server=production viewer=production-session files=10 network=none' "$build_output")" -eq 1 ] \
        || fail 'CM file build product receipt differs'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'CM file build container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'CM file build left a container'
    [ "$(stat -c '%u:%g:%a:%h' -- "$target/android-peer-manifest.sha256")" = 1000:1000:444:1 ] \
        || fail 'CM file build manifest metadata differs'
    install -d -o 1000 -g 1000 -m 0700 "$flat" "$flat/debug" "$flat/debug/examples"
    local relative mode
    while read -r relative mode; do
        [ -f "$target/$relative" ] && [ ! -L "$target/$relative" ] \
            && [ "$(stat -c '%u:%g:%a' -- "$target/$relative")" = "1000:1000:$mode" ] \
            || fail "CM file build artifact authority differs: $relative"
        install -o 1000 -g 1000 -m 0555 -- "$target/$relative" "$flat/$relative"
        [ "$(stat -c '%u:%g:%a:%h' -- "$flat/$relative")" = 1000:1000:555:1 ] \
            && cmp -s -- "$target/$relative" "$flat/$relative" \
            || fail "CM file replay copy differs: $relative"
    done <<'LAYOUT'
debug/rustdesk 755
debug/examples/seed_password 755
debug/examples/probe_client 755
debug/examples/smoke_readiness 755
debug/examples/video_pipeline_probe 755
flutter-peer-source-x11 555
smoke-x11-motion 555
smoke-bind-loopback.so 555
smoke-server-launcher 555
production-viewer-file-tests 555
LAYOUT
    [ "$(wc -l < "$target/android-peer-manifest.sha256")" -eq 10 ] \
        || fail 'CM file build manifest entry count differs'
    (cd "$target" && sha256sum --check --status android-peer-manifest.sha256) \
        || fail 'CM file build artifact digests differ'
    manifest_sha="$(sha256sum "$target/android-peer-manifest.sha256" | awk '{ print $1 }')"
    sed 's/^/CM_FILE_BUILD_ARTIFACT /' "$target/android-peer-manifest.sha256"
    printf 'CM_FILE_PEER_BUILD=pass commit=%s tree=%s builder=%s files=10 network=none\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" "$DEV_CHECK_IMAGE_CONFIG_ID"
    printf '%s\n' "$machine_id_value" >"$machine_id"
    chown 1000:1000 "$machine_id"
    chmod 0400 "$machine_id"
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$machine_id")" = 1000:1000:400:1:33 ] \
        && [ "$(<"$machine_id")" = "$machine_id_value" ] \
        || fail 'CM file replay private machine identity differs'
    CONTAINER_ID="$("$CLIENT" --host "unix://$SOCK" create \
        --name rustdesk-cm-file-replay --pull=never --network=none --read-only \
        --user 1000:1000 --pids-limit=256 --memory=2g --memory-swap=2g --cpus=2 \
        --ulimit nofile=4096:4096 --ulimit core=0:0 \
        --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=256m \
        --mount "type=bind,source=$source_root,target=/work,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$flat,target=/smoke-target,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$machine_id,target=/etc/machine-id,readonly,bind-recursive=disabled" \
        --workdir /work "$DEV_CHECK_IMAGE_CONFIG_ID" \
        /bin/bash --noprofile --norc /work/scripts/smoke-server-stage.sh cm-file-replay)"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'CM file replay container identity is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' "$CONTAINER_ID")"
    [ "$inspect" = 'none|true|1000:1000|2147483648|2147483648|2000000000|256|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
        || fail 'CM file replay container confinement differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' "$CONTAINER_ID")"
    [ "$inspect" = 'false||private||private' ] \
        || fail 'CM file replay container namespace authority differs'
    machine_mount="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{range .Mounts}}{{printf "%s\t%s\t%s\t%t\n" .Type .Source .Destination .RW}}{{end}}' \
        "$CONTAINER_ID" | awk -F '\t' '$3 == "/etc/machine-id" { print }')"
    [ "$machine_mount" = "bind	$machine_id	/etc/machine-id	false" ] \
        || fail 'CM file replay private machine identity mount differs'
    printf 'CM_FILE_REPLAY_STAGE=begin commit=%s manifest_sha256=%s\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$manifest_sha"
    set +e
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" 2>&1 | tee "$output"
    status=$?
    set -e
    [ "$status" -eq 0 ] && [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || { tail -n 160 "$output" >&2; fail "CM file replay failed: $status"; }
    [ "$(grep -Fxc 'CM_FILE_REPLAY=pass auth=cpace cm=post-login-dir prelogin-create=refused postlogin-create=committed premature-write=refused-cleaned short-write=refused-cleaned committed-write=exact-bytes multi-file-write=two-files-four-blocks-exact-bytes peer-error=reported-cleaned cancel=directory-barrier-cleaned owner-loss=staged-then-cleaned reconnect=new-owner-exact-bytes live-owner=contender-refused-first-commit same-peer-overlap=successor-serves-after-predecessor-retire sidecar-collision=refused-preserved cleanup-failure=reported-replacement-preserved digest-cleanup-failure=reported-replacement-preserved direct-read-open-error=terminal-once direct-read-after-error=digest-confirmed-150001-bytes-done-once viewer-download=production-session-exact-bytes viewer-digest-symlink=terminal-preserved viewer-after-refusal=new-connection-exact-bytes network=container-loopback cleanup=server-joined' "$output")" -eq 1 ] \
        || fail 'CM file replay product receipt is absent or duplicated'
    [ "$(grep -Fxc 'PA_PRODUCTION_CM_REFUSAL=pass principal=same-uid-unrelated-process action=silent-connect result=eof-before-750ms endpoint=cm-owned-pa server=production network=container-loopback' "$output")" -eq 1 ] \
        || fail 'production CM _pa wrong-peer refusal receipt is absent or duplicated'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'CM file replay container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'CM file replay left a container'
    CONTAINER_ID="$("$CLIENT" --host "unix://$SOCK" create \
        --name rustdesk-cm-pa-product-pair --pull=never --network=none --read-only \
        --user 1000:1000 --pids-limit=1024 --memory=4g --memory-swap=4g --cpus=2 \
        --ulimit nofile=4096:4096 --ulimit core=0:0 \
        --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=1g \
        --tmpfs /tmp/.X11-unix:rw,nosuid,nodev,noexec,mode=1777,size=1m \
        --env HOME=/tmp/home \
        --env "PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE=$PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE" \
        --env "PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256=$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" \
        --env "PA_RUNTIME_CANDIDATE_MANIFEST_SHA256=$PA_RUNTIME_CANDIDATE_MANIFEST_SHA256" \
        --env "DEV_CHECK_IMAGE_ID=$DEV_CHECK_IMAGE_ID" \
        --env "DEV_CHECK_DEBIAN_SNAPSHOT=$DEV_CHECK_DEBIAN_SNAPSHOT" \
        --env "DEV_CHECK_SECURITY_SNAPSHOT=$DEV_CHECK_SECURITY_SNAPSHOT" \
        --env "PA_RUNTIME_PULSEAUDIO_VERSION=$PA_RUNTIME_PULSEAUDIO_VERSION" \
        --env "PA_RUNTIME_PULSEAUDIO_SHA256=$PA_RUNTIME_PULSEAUDIO_SHA256" \
        --env "PA_RUNTIME_PULSEAUDIO_SIZE=$PA_RUNTIME_PULSEAUDIO_SIZE" \
        --mount "type=bind,source=$source_root,target=/source,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$source_root,target=/work,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$flat,target=/smoke-target,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ROOT/engine-xvfb/root,target=/xvfb-root,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ROOT/engine-xvfb/root/usr/bin/xkbcomp,target=/usr/bin/xkbcomp,readonly" \
        --mount "type=bind,source=$pa_copy,target=/inputs/pa-runtime.tar.gz,readonly" \
        --mount "type=bind,source=$machine_id,target=/etc/machine-id,readonly,bind-recursive=disabled" \
        --workdir /source "$DEV_CHECK_IMAGE_CONFIG_ID" \
        /bin/bash --noprofile --norc /source/scripts/run-pa-runtime-tests.sh \
        /inputs/pa-runtime.tar.gz --product-pair)"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'CM PulseAudio product-pair container identity differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' "$CONTAINER_ID")"
    [ "$inspect" = 'none|true|1000:1000|4294967296|4294967296|2000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
        || fail 'CM PulseAudio product-pair confinement differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{range $i, $m := .Mounts}}{{if $i}}{{println}}{{end}}{{$m.Type}}|{{$m.Source}}|{{$m.Destination}}|{{$m.RW}}{{end}}' \
        "$CONTAINER_ID" | LC_ALL=C sort)"
    local expected_mounts
    expected_mounts="$(printf '%s\n' \
        "bind|$source_root|/source|false" \
        "bind|$source_root|/work|false" \
        "bind|$flat|/smoke-target|false" \
        "bind|$ROOT/engine-xvfb/root|/xvfb-root|false" \
        "bind|$ROOT/engine-xvfb/root/usr/bin/xkbcomp|/usr/bin/xkbcomp|false" \
        "bind|$pa_copy|/inputs/pa-runtime.tar.gz|false" \
        "bind|$machine_id|/etc/machine-id|false" | LC_ALL=C sort)"
    if [ "$inspect" != "$expected_mounts" ]; then
        printf 'CM PulseAudio product-pair actual mounts:\n%s\nexpected mounts:\n%s\n' \
            "$inspect" "$expected_mounts" >&2
        fail 'CM PulseAudio product-pair mount authority differs'
    fi
    printf 'CM_PA_PRODUCT_PAIR_STAGE=begin commit=%s manifest_sha256=%s\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$manifest_sha"
    set +e
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" 2>&1 | tee "$pa_output"
    status=$?
    set -e
    [ "$status" -eq 0 ] && [ "$(stat -c '%s' -- "$pa_output")" -le 4194304 ] \
        || { tail -n 160 "$pa_output" >&2; fail "CM PulseAudio product-pair failed: $status"; }
    [ "$(grep -Fxc "PA_RUNTIME_ARCHIVE=pass packages=40 base=$DEV_CHECK_IMAGE_ID sha256=$PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256" "$pa_output")" -eq 1 ] \
        && [ "$(grep -Fxc 'PA_RUNTIME_MONITOR=pass source=rd_pa_test.monitor signal=sine440 probe=pacat-native' "$pa_output")" -eq 1 ] \
        && [ "$(grep -Ec '^VIDEO_PIPELINE_AUDIO_OK frames=[1-9][0-9]* peak_milli=[1-9][0-9]*$' "$pa_output")" -eq 1 ] \
        || fail 'CM PulseAudio product-pair input or decoded-signal receipt differs'
    [ "$(grep -Fxc 'PA_PRODUCTION_PAIR=pass auth=cpace cm=exact-child source=private-monitor signal=nonzero-opus viewer=remote video=decoded network=container-loopback cleanup=server-motion-xvfb-joined' "$pa_output")" -eq 1 ] \
        && [ "$(grep -Fxc 'PA_RUNTIME_PRODUCT_PAIR=pass daemon=16.1 source=rd_pa_test.monitor signal=sine440 network=none uid=1000 cleanup=joined' "$pa_output")" -eq 1 ] \
        || fail 'CM PulseAudio product-pair native receipts are absent or duplicated'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'CM PulseAudio product-pair container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'CM PulseAudio product-pair left a container'
    [ "$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')" = "$source_sha" ] \
        && [ "$(sha256sum "$target/android-peer-manifest.sha256" | awk '{ print $1 }')" = "$manifest_sha" ] \
        && (cd "$target" && sha256sum --check --status android-peer-manifest.sha256) \
        || fail 'CM file replay source or build changed during execution'
    while read -r relative mode; do
        [ "$(stat -c '%u:%g:%a:%h' -- "$flat/$relative")" = 1000:1000:555:1 ] \
            && cmp -s -- "$target/$relative" "$flat/$relative" \
            || fail "CM file replay copy changed: $relative"
    done <<'LAYOUT'
debug/rustdesk 755
debug/examples/seed_password 755
debug/examples/probe_client 755
debug/examples/smoke_readiness 755
debug/examples/video_pipeline_probe 755
flutter-peer-source-x11 555
smoke-x11-motion 555
smoke-bind-loopback.so 555
smoke-server-launcher 555
production-viewer-file-tests 555
LAYOUT
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire CM file sealed input mount'
    SEALED_INPUTS_MOUNTED=0
    printf 'CM_FILE_REPLAY_VM=pass commit=%s tree=%s builder=%s uid=1000 gid=1000 vm_network=none container_network=none build=guest-disposable cleanup=joined\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" "$DEV_CHECK_IMAGE_CONFIG_ID"
}

run_android_peer_build() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local artifact_output=/mnt/rustdesk-android-artifact-output
    local source_root=$ROOT/android-peer-build-source
    local target=$ROOT/android-peer-build-target
    local flat=$ROOT/android-peer-build-flat
    local output=$ROOT/android-peer-build.out
    local image=$inputs/verifier-images/devcheck.docker.tar.gz
    local source_sha source_before load_output inspect status=0 prepared pending pending_id digest
    local name relative options
    local -a git_builder=(
        setpriv --reuid=1000 --regid=1000 --clear-groups
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
        GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
    )
    [[ "$ANDROID_EMULATOR_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$ANDROID_EMULATOR_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android peer source identity is malformed'
    [ -f "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] && [ ! -L "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = 4000:4000:400:1 ] \
        || fail 'Android peer source archive metadata differs'
    source_sha="$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_sha" = "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android peer source archive digest differs'
    [ ! -e "$source_root" ] && [ ! -L "$source_root" ] \
        || fail 'Android peer source workspace already exists'
    mkdir -m 0700 "$source_root"
    tar -xf "$ANDROID_EMULATOR_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions -C "$source_root"
    [ -z "$(find "$source_root" -xdev \( ! -type d -a ! -type f \) -print -quit)" ] \
        || fail 'Android peer source contains a non-file entry'
    chown -R 1000:1000 "$source_root"
    "${git_builder[@]}" /usr/bin/git -c init.defaultBranch=master -C "$source_root" init -q
    "${git_builder[@]}" /usr/bin/git -C "$source_root" add -f -- .
    [ "$("${git_builder[@]}" /usr/bin/git -C "$source_root" write-tree)" = "$ANDROID_EMULATOR_SOURCE_TREE" ] \
        || fail 'Android peer source archive tree differs from pushed master'
    rm -rf -- "$source_root/.git"
    source_before="$(sha256sum "$source_root/scripts/pins.env" \
        "$source_root/scripts/smoke-server-stage.sh" "$source_root/scripts/android-peer-artifact.py" \
        "$source_root/scripts/publish-artifact-result.py" "$source_root/Cargo.lock")"

    mkdir "$inputs" "$artifact_output"
    mount -t virtiofs -o ro,nodev,nosuid rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount sealed Android peer inputs'
    SEALED_INPUTS_MOUNTED=1
    options="$(findmnt -n -o OPTIONS --target "$inputs")"
    for option in ro nodev nosuid; do
        case ",$options," in *,$option,*) ;; *) fail "Android peer input mount lacks $option" ;; esac
    done
    mount -t virtiofs -o rw,nodev,nosuid,noexec rustdesk-android-artifact-output "$artifact_output" \
        || fail 'cannot mount Android peer output'
    ANDROID_ARTIFACT_OUTPUT_MOUNTED=1
    options="$(findmnt -n -o OPTIONS --target "$artifact_output")"
    for option in rw nodev nosuid noexec; do
        case ",$options," in *,$option,*) ;; *) fail "Android peer output mount lacks $option" ;; esac
    done
    [ "$(stat -c '%u:%g:%a' -- "$artifact_output")" = 1000:1000:700 ] \
        && [ -z "$(find "$artifact_output" -mindepth 1 -maxdepth 1 -print -quit)" ] \
        || fail 'Android peer output was not private and empty at handoff'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$image")" = "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$image" | awk '{ print $1 }')" = "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'Android peer builder archive differs'
    load_output="$(setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
        python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
            --archive "$image" --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
            --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" --role devcheck \
            --expected-id "$DEV_CHECK_IMAGE_ID" --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
            --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
            --cargo-sha "$SHA256_DEV_CHECK_CARGO" --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
            --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
            --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
            --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID")" \
        || fail 'Android peer builder verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail 'Android peer builder load receipt differs'
    install -d -o 1000 -g 1000 -m 0700 "$target" "$flat"
    printf 'ANDROID_PEER_BUILD_STAGE=begin commit=%s tree=%s builder=%s\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" "$DEV_CHECK_IMAGE_CONFIG_ID"
    CONTAINER_ID="$("$CLIENT" --host "unix://$SOCK" create \
        --name rustdesk-android-peer-artifact-build --pull=never --network=none --read-only \
        --user 1000:1000 --pids-limit=1024 --memory=12g --memory-swap=12g --cpus=4 \
        --ulimit nofile=8192:8192 --ulimit core=0:0 \
        --cap-drop=ALL --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g \
        --env HOME=/tmp/android-peer-build --env CARGO_HOME=/tmp/smoke-cargo-home \
        --env CARGO_TARGET_DIR=/smoke-target --env CARGO_INCREMENTAL=0 \
        --env CARGO_NET_OFFLINE=true --env CARGO_NET_RETRY=0 \
        --env "RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
        --env "SMOKE_EXPECTED_RUSTUP_TOOLCHAIN=${RUST_VERSION}.0-x86_64-unknown-linux-gnu" \
        --env "SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256=$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        --env "SMOKE_EXPECTED_VENDOR_CONFIG_SHA256=$SHA256_CARGO_VENDOR_CONFIG" \
        --mount "type=bind,source=$source_root,target=/work,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$inputs,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$target,target=/smoke-target,bind-recursive=disabled" \
        --workdir /work "$DEV_CHECK_IMAGE_CONFIG_ID" \
        /bin/bash --noprofile --norc /work/scripts/smoke-server-stage.sh android-peer-build)"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'Android peer build container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.Devices}}' "$CONTAINER_ID")"
    [ "$inspect" = 'none|true|1000:1000|12884901888|12884901888|4000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]|{}|[]' ] \
        || fail 'Android peer build confinement differs'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}' "$CONTAINER_ID")"
    [ "$inspect" = 'false||private||private' ] || fail 'Android peer build namespace authority differs'
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" 2>&1 \
        | /usr/bin/tee "$output" || status=$?
    [ "$status" -eq 0 ] && [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || { tail -n 200 "$output" >&2; fail "Android peer build failed: $status"; }
    [ "$(grep -Fc 'ANDROID_PEER_BUILD=pass server=production auth=cpace source=x11-changing files=7 network=none' "$output")" -eq 1 ] \
        || fail 'Android peer build receipt differs'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'Android peer build did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    while IFS=' ' read -r name relative; do
        [ -f "$target/$relative" ] && [ ! -L "$target/$relative" ] \
            || fail "Android peer output is not a regular file: $relative"
        install -o 1000 -g 1000 -m 0400 -- "$target/$relative" "$flat/$name"
    done <<'LAYOUT'
rustdesk debug/rustdesk
seed_password debug/examples/seed_password
probe_client debug/examples/probe_client
smoke_readiness debug/examples/smoke_readiness
flutter-peer-source-x11 flutter-peer-source-x11
smoke-bind-loopback.so smoke-bind-loopback.so
smoke-server-launcher smoke-server-launcher
LAYOUT
    chmod 0500 "$flat"
    prepared="$(setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        python3 -I -S "$source_root/scripts/android-peer-artifact.py" prepare \
            --root "$flat" --root-identity "$(stat -c '%d:%i' -- "$flat")" \
            --parent "$artifact_output" --parent-identity "$(stat -c '%d:%i' -- "$artifact_output")" \
            --source-commit "$ANDROID_EMULATOR_SOURCE_COMMIT" --source-tree "$ANDROID_EMULATOR_SOURCE_TREE" \
            --builder-config "$DEV_CHECK_IMAGE_CONFIG_ID" --vendor-closure "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
            --vendor-config "$SHA256_CARGO_VENDOR_CONFIG" \
            --rust-toolchain "${RUST_VERSION}.0-x86_64-unknown-linux-gnu")" \
        || fail 'Android peer capsule preparation failed'
    [[ "$prepared" =~ ^(\.android-peer-pending-[0-9a-f]{64})\ ([0-9]+:[0-9]+)\ ([0-9a-f]{64})$ ]] \
        || fail 'Android peer capsule preparation result is malformed'
    pending=${BASH_REMATCH[1]}
    pending_id=${BASH_REMATCH[2]}
    digest=${BASH_REMATCH[3]}
    [ "$(stat -c '%d:%i' -- "$artifact_output/$pending")" = "$pending_id" ] \
        || fail 'Android peer prepared root identity changed'
    [ "$source_before" = "$(sha256sum "$source_root/scripts/pins.env" \
        "$source_root/scripts/smoke-server-stage.sh" "$source_root/scripts/android-peer-artifact.py" \
        "$source_root/scripts/publish-artifact-result.py" "$source_root/Cargo.lock")" ] \
        && [ "$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')" = "$source_sha" ] \
        || fail 'Android peer source changed during build'
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        && [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Android peer build left a container or image'
    stop_docker_authority
    umount "$artifact_output"
    ANDROID_ARTIFACT_OUTPUT_MOUNTED=0
    umount "$inputs"
    SEALED_INPUTS_MOUNTED=0
    printf 'ANDROID_PEER_ARTIFACT_PREPARED=pass commit=%s tree=%s pending=%s manifest_sha256=%s builder=%s vendor=%s rust=1.75.0 files=7 network=none cleanup=joined\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" "$pending" "$digest" \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$SHA256_CARGO_VENDOR_CLOSURE_V1"
}

provision_android_kvm() {
    /usr/bin/timeout --signal=TERM --kill-after=2s 5s \
        /usr/bin/python3 -I -S - "$EXPECTED_KERNEL_RELEASE" <<'PY'
import os
import stat
import sys

if (os.geteuid(), os.getegid()) != (0, 0) or os.uname().release != sys.argv[1]:
    raise SystemExit("Android KVM provisioning requires the authenticated guest kernel and root")
if "rustdesk.verifier_vm=1" not in open("/proc/cmdline").read().split():
    raise SystemExit("Android KVM provisioning has no guest authority")
if open("/sys/devices/virtual/misc/kvm/dev").read().strip() != "10:232":
    raise SystemExit("Android KVM is not the guest kernel's virtual misc device")
parent = os.lstat("/dev")
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
    raise SystemExit("Android KVM device parent authority differs")
descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(descriptor)
    if (not stat.S_ISCHR(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o660 or before.st_rdev != os.makedev(10, 232)):
        raise SystemExit("Android KVM guest device authority differs")
    if any(name.startswith("system.posix_acl_") for name in os.listxattr(descriptor)):
        raise SystemExit("Android KVM guest device has an ACL")
    os.fchown(descriptor, 0, 1000)
    after = os.fstat(descriptor)
    path = os.lstat("/dev/kvm")
    if (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_nlink) != (
            before.st_dev, before.st_ino, 0, 1000, before.st_mode, 1) or path != after:
        raise SystemExit("Android KVM guest device grant changed identity or authority")
finally:
    os.close(descriptor)
print("ANDROID_KVM_DEVICE=ready scope=guest-virtual owner=0:1000 mode=660 rdev=10:232")
PY
    setpriv --reuid=4001 --regid=4001 --clear-groups \
        /usr/bin/timeout --signal=TERM --kill-after=2s 5s \
        /usr/bin/python3 -I -S - <<'PY'
import errno
import os

try:
    descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
except OSError as error:
    if error.errno != errno.EACCES:
        raise
else:
    os.close(descriptor)
    raise SystemExit("Foreign guest principal acquired Android KVM authority")
print("ANDROID_KVM_FOREIGN=refused uid=4001 gid=4001 reason=kernel-access-denied")
PY
}

run_android_emulator_boot() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/android-emulator-source
    local output=$ROOT/android-emulator-boot.out
    local emulator_archive=$inputs/candidates/android-emulator/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
    local system_archive=$inputs/candidates/android-emulator/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
    local adb=$inputs/inputs/android-sdk/platform-tools/adb
    local runtime_archive=$inputs/inputs/verifier-images/devcheck.docker.tar.gz
    local source_archive_sha source_before inputs_before input_mount_options
    local load_output inspect namespace_inspect device_inspect container_status=0
    local renderer_receipt result_line kvm_receipt
    local -a renderer_lines=() result_lines=()

    [[ "$ANDROID_EMULATOR_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator boot source commit is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator boot source tree is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator boot source archive digest is malformed'
    [ -f "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ ! -L "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'Android emulator boot source archive metadata differs'
    source_archive_sha="$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android emulator boot source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$ANDROID_EMULATOR_SOURCE_ARCHIVE" \
        --no-same-owner --no-same-permissions -C "$source_root" \
        || fail 'cannot extract the exact Android emulator boot source archive'
    [ -z "$(find "$source_root" -mindepth 1 \
        ! -type d ! -type f ! -type l -print -quit)" ] \
        || fail 'Android emulator boot source archive contains a special entry'
    /usr/bin/git -c init.defaultBranch=master -C "$source_root" init -q \
        || fail 'cannot create the Android emulator source index'
    /usr/bin/git -C "$source_root" add -f -- . \
        || fail 'cannot index the exact Android emulator source'
    [ "$(/usr/bin/git -C "$source_root" write-tree)" = \
      "$ANDROID_EMULATOR_SOURCE_TREE" ] \
        || fail 'Android emulator source archive tree differs from pushed master'
    rm -rf -- "$source_root/.git"
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'Android emulator source archive differs from its guest bootstrap'
    [ "$(stat -c '%a:%h' -- \
        "$source_root/scripts/smoke-android-emulator-boot.sh")" = 700:1 ] \
        || fail 'Android emulator boot workload metadata differs'
    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/smoke-android-emulator-boot.sh")"
    chown -R 1000:1000 "$source_root"

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android emulator input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android emulator input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android emulator inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android emulator inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android emulator inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed Android emulator inputs permit direct execution' ;; esac

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$emulator_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_LINUX_X64" ] \
        && [ "$(sha256sum "$emulator_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_LINUX_X64" ] \
        || fail 'sealed Android emulator archive differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$system_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        && [ "$(sha256sum "$system_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        || fail 'sealed Android system-image archive differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$adb")" = \
      "1000:1000:555:1:$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        && [ "$(sha256sum "$adb" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        || fail 'sealed Android adb executable differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$runtime_archive")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$runtime_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed emulator runtime image archive differs'
    inputs_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$emulator_archive" "$system_archive" "$adb" "$runtime_archive"):$({ \
        sha256sum "$emulator_archive" "$system_archive" "$adb" "$runtime_archive"; \
    })"

    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$runtime_archive" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'certified emulator runtime image verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail "emulator runtime image receipt differs: $load_output"

    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create \
            --name rustdesk-android-emulator-boot \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=768 \
            --memory=12g \
            --memory-swap=12g \
            --cpus=4 \
            --shm-size=1g \
            --ulimit nofile=8192:8192 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --device /dev/kvm:/dev/kvm:rw \
            --mount "type=bind,source=$source_root,target=/source,readonly" \
            --mount "type=bind,source=$emulator_archive,target=/inputs/emulator.zip,readonly" \
            --mount "type=bind,source=$system_archive,target=/inputs/system-image.zip,readonly" \
            --mount "type=bind,source=$adb,target=/inputs/adb,readonly" \
            --tmpfs /tmp:rw,exec,nosuid,nodev,size=10g,mode=700,uid=1000,gid=1000 \
            --workdir /source \
            "$DEV_CHECK_IMAGE_CONFIG_ID" \
            /bin/bash --noprofile --norc \
                /source/scripts/smoke-android-emulator-boot.sh \
                /inputs/emulator.zip /inputs/system-image.zip /inputs/adb \
                /tmp/android-emulator-boot
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator boot container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      'none|true|1000:1000|12884901888|12884901888|4000000000|768|1073741824|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
        || fail "Android emulator boot container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|{}' ] \
        || fail "Android emulator container namespace/port authority differs: $namespace_inspect"
    device_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{json .HostConfig.Devices}}' "$CONTAINER_ID")"
    python3 -I -S - "$device_inspect" <<'PY' \
        || fail 'Android emulator boot container device authority differs'
import json
import sys

expected = [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm", "CgroupPermissions": "rw"}]
if json.loads(sys.argv[1]) != expected:
    raise SystemExit("Android runtime requires exactly the guest KVM read/write mapping")
PY
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 200 "$output" >&2; fail "Android emulator boot exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 262144 ] \
        || fail 'Android emulator boot output exceeds its bound'
    mapfile -t renderer_lines < <(grep -E \
        '^ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader angle=(present|absent) gles_sha256=[0-9a-f]{64}$' \
        "$output" || true)
    [ "${#renderer_lines[@]}" -eq 1 ] \
        || { tail -n 200 "$output" >&2; fail 'Android renderer receipt is absent or duplicated'; }
    [ "$(grep -c '^ANDROID_EMULATOR_RENDERER=' "$output")" -eq 1 ] \
        || { tail -n 200 "$output" >&2; fail 'Android renderer receipt is malformed or duplicated'; }
    renderer_receipt=${renderer_lines[0]}
    for kvm_receipt in \
        'ANDROID_EMULATOR_KVM_API=pass scope=guest-virtual api=12 vm_create=closed uid=1000 gid=1000' \
        'ANDROID_EMULATOR_KVM_EXECUTION=pass backend=kvm scope=nested-guest vm_fds=1 vcpu_fds=2'; do
        [ "$(grep -Fxc "$kvm_receipt" "$output")" -eq 1 ] \
            || fail 'Android emulator boot KVM evidence is absent or duplicated'
        printf '%s\n' "$kvm_receipt"
    done
    mapfile -t result_lines < <(grep -E \
        '^ANDROID_EMULATOR_BOOT=pass emulator=37\.1\.11 api=34 abi=x86_64 acceleration=kvm-nested gpu=swiftshader framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
        "$output" || true)
    [ "${#result_lines[@]}" -eq 1 ] \
        || { tail -n 200 "$output" >&2; fail 'Android emulator boot receipt is absent or duplicated'; }
    result_line=${result_lines[0]}
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'Android emulator boot container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null

    [ "$source_before" = \
      "$source_archive_sha:$(sha256sum \
          "$source_root/scripts/pins.env" \
          "$source_root/scripts/smoke-android-emulator-boot.sh")" ] \
        || fail 'Android emulator boot source inputs changed during execution'
    [ "$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'Android emulator boot source archive changed during execution'
    [ "$inputs_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
          "$emulator_archive" "$system_archive" "$adb" "$runtime_archive"):$({ \
          sha256sum "$emulator_archive" "$system_archive" "$adb" "$runtime_archive"; \
      })" ] \
        || fail 'sealed Android emulator inputs changed during execution'
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire the sealed Android emulator input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$renderer_receipt" "$result_line"
    printf 'ANDROID_EMULATOR_BOOT_VM=pass commit=%s tree=%s emulator=%s api=%s abi=x86_64 acceleration=kvm-nested gpu=swiftshader runtime_index=%s runtime_config=%s uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" \
        "$ANDROID_EMULATOR_VERSION" "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" \
        "$DEV_CHECK_IMAGE_ID" "$DEV_CHECK_IMAGE_CONFIG_ID"
}

run_android_emulator_app() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local artifact_output=/mnt/rustdesk-android-artifact-output
    local artifact_destination=android-x86_64-test
    local source_root=$ROOT/android-emulator-app-source
    local source_copy=$ROOT/android-emulator-app-exact-source.tar
    local online_mount=$source_root/online
    local output=$ROOT/android-emulator-app.out
    local emulator_archive=$inputs/candidates/android-emulator/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
    local system_archive=$inputs/candidates/android-emulator/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
    local x86_std=$inputs/candidates/android-emulator/rust-std-1.75-x86_64-linux-android.tar.xz
    local x86_vcpkg=$inputs/candidates/android-emulator/vcpkg/installed/x64-android
    local adb=$inputs/inputs/android-sdk/platform-tools/adb
    local builder_archive=$inputs/inputs/build-images/android-builder.docker.tar.gz
    local runtime_archive=$inputs/inputs/verifier-images/devcheck.docker.tar.gz
    local source_archive_sha input_mount_options online_mount_options artifact_mount_options
    local builder_load runtime_load workload_status=0 source_before
    local apk_receipt test_receipt renderer_receipt smoke_receipt runtime_receipt prepared_receipt
    local check_receipt apk_sha256 test_sha256
    local -a git_builder=(
        setpriv --reuid=1000 --regid=1000 --clear-groups
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
        GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
        GIT_NO_REPLACE_OBJECTS=1
    )

    [[ "$ANDROID_EMULATOR_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator app source commit is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator app source tree is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator app source archive digest is malformed'
    [ -f "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ ! -L "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'Android emulator app source archive metadata differs'
    source_archive_sha="$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android emulator app source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$ANDROID_EMULATOR_SOURCE_ARCHIVE" \
        --no-same-owner --no-same-permissions -C "$source_root" \
        || fail 'cannot extract the exact Android emulator app source archive'
    [ -z "$(find "$source_root" -xdev \
        \( ! -type d -a ! -type f \) -print -quit)" ] \
        || fail 'Android emulator app source archive contains a non-file entry'
    chown -R 1000:1000 "$source_root"
    "${git_builder[@]}" /usr/bin/git -c init.defaultBranch=master \
        -C "$source_root" init -q \
        || fail 'cannot initialize the Android emulator app source index'
    "${git_builder[@]}" /usr/bin/git -C "$source_root" add -f -- . \
        || fail 'cannot index the exact Android emulator app source'
    [ "$("${git_builder[@]}" /usr/bin/git -C "$source_root" write-tree)" = \
      "$ANDROID_EMULATOR_SOURCE_TREE" ] \
        || fail 'Android emulator app source archive tree differs from pushed master'
    rm -rf -- "$source_root/.git"
    [ "$(stat -c '%u:%g:%a:%h' -- \
        "$source_root/scripts/android-emulator-app-check.sh" \
        "$source_root/scripts/android-apk-build.sh" \
        "$source_root/scripts/smoke-android-emulator-boot.sh" \
        "$source_root/scripts/verify-android-emulator-apk.py" \
        "$source_root/scripts/publish-artifact-result.py")" = \
      $'1000:1000:700:1\n1000:1000:700:1\n1000:1000:700:1\n1000:1000:700:1\n1000:1000:700:1' ] \
        || fail 'Android emulator app workload metadata differs'
    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/android-emulator-app-check.sh" \
        "$source_root/scripts/android-apk-build.sh" \
        "$source_root/scripts/smoke-android-emulator-boot.sh" \
        "$source_root/scripts/verify-android-emulator-apk.py" \
        "$source_root/scripts/publish-artifact-result.py")"

    install -o 1000 -g 1000 -m 0400 -- \
        "$ANDROID_EMULATOR_SOURCE_ARCHIVE" "$source_copy"
    [ "$(sha256sum "$source_copy" | awk '{ print $1 }')" = "$source_archive_sha" ] \
        || fail 'private Android emulator app source copy differs'

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android emulator app input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android emulator app input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android emulator app inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android emulator app inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android emulator app inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in
        *,noexec,*) fail 'sealed Android emulator app build inputs unexpectedly forbid the authenticated toolchain' ;;
    esac

    mkdir "$artifact_output"
    chown 1000:1000 "$artifact_output"
    mount -t virtiofs -o rw,nodev,nosuid,noexec \
        rustdesk-android-artifact-output "$artifact_output" \
        || fail 'cannot mount the writable Android artifact output authority'
    ANDROID_ARTIFACT_OUTPUT_MOUNTED=1
    artifact_mount_options="$(findmnt -n -o OPTIONS --target "$artifact_output")" \
        || fail 'Android artifact output mount is absent'
    case ",$artifact_mount_options," in *,rw,*) ;; *) fail 'Android artifact output is read-only' ;; esac
    case ",$artifact_mount_options," in *,nodev,*) ;; *) fail 'Android artifact output permits devices' ;; esac
    case ",$artifact_mount_options," in *,nosuid,*) ;; *) fail 'Android artifact output permits set-user-ID execution' ;; esac
    case ",$artifact_mount_options," in *,noexec,*) ;; *) fail 'Android artifact output permits direct execution' ;; esac
    [ "$(stat -c '%u:%g:%a' -- "$artifact_output")" = 1000:1000:700 ] \
        || fail 'Android artifact output metadata differs'
    [ -z "$(find "$artifact_output" -mindepth 1 -maxdepth 1 -print -quit)" ] \
        || fail 'Android artifact output was not empty at handoff'

    mkdir "$online_mount"
    chown 1000:1000 "$online_mount"
    mount --bind "$inputs" "$online_mount" \
        || fail 'cannot project the sealed closure into the Android emulator app source'
    ANDROID_EMULATOR_ONLINE_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid "$online_mount" \
        || fail 'cannot make the Android emulator app input projection read-only'
    online_mount_options="$(findmnt -n -o OPTIONS --target "$online_mount")" \
        || fail 'Android emulator app input projection is absent'
    case ",$online_mount_options," in *,ro,*) ;; *) fail 'Android emulator app input projection is writable' ;; esac
    case ",$online_mount_options," in *,nodev,*) ;; *) fail 'Android emulator app input projection permits devices' ;; esac
    case ",$online_mount_options," in *,nosuid,*) ;; *) fail 'Android emulator app input projection permits set-user-ID execution' ;; esac
    case ",$online_mount_options," in
        *,noexec,*) fail 'Android emulator app build projection unexpectedly forbids the authenticated toolchain' ;;
    esac

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$emulator_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_LINUX_X64" ] \
        && [ "$(sha256sum "$emulator_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_LINUX_X64" ] \
        || fail 'sealed Android emulator archive differs for app execution'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$system_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        && [ "$(sha256sum "$system_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        || fail 'sealed Android system-image archive differs for app execution'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$x86_std")" = \
      "1000:1000:400:1:$SIZE_RUST_STD_ANDROID_X86_64_1_75" ] \
        && [ "$(sha256sum "$x86_std" | awk '{ print $1 }')" = \
             "$SHA256_RUST_STD_ANDROID_X86_64_1_75" ] \
        || fail 'sealed x86_64 Android Rust std differs'
    python3 -I -S "$source_root/scripts/online-input-provenance.py" verify-subtree \
        --tree "$x86_vcpkg" \
        --expected "$SHA256_ANDROID_EMULATOR_VCPKG_X64_ANDROID_CLOSURE_V1" \
        || fail 'sealed x86_64 Android vcpkg closure differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$adb")" = \
      "1000:1000:555:1:$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        && [ "$(sha256sum "$adb" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        || fail 'sealed Android adb executable differs for app execution'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android-builder archive differs for app execution'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$runtime_archive")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$runtime_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android runtime archive differs for app execution'

    builder_load="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role android-builder \
                --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
                --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
                --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$ANDROID_BUILDER_CONFIG_ID" \
                --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
    )" || fail 'certified Android-builder image verification/load failed for app execution'
    [ "$builder_load" = "loaded and verified android-builder $ANDROID_BUILDER_IMAGE_ID" ] \
        || fail "Android-builder image receipt differs for app execution: $builder_load"
    runtime_load="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$runtime_archive" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'certified Android runtime image verification/load failed for app execution'
    [ "$runtime_load" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail "Android runtime image receipt differs for app execution: $runtime_load"

    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/android-emulator-app-check.sh" \
        "$source_copy" "$source_archive_sha" \
        "$artifact_output" "$artifact_destination" >"$output" 2>&1
    workload_status=$?
    set -e
    [ "$workload_status" -eq 0 ] \
        || { tail -n 320 "$output" >&2; fail "Android emulator app check exited with status $workload_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 2097152 ] \
        || fail 'Android emulator app-check output exceeds its bound'
    apk_receipt="$(grep -E \
        '^ANDROID_EMULATOR_APK=pass sha256=[0-9a-f]{64} package=com\.carriez\.flutter_hbb abi=x86_64 native_libraries=[1-9][0-9]* signer=[0-9A-F]{64} signing=test-only$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android emulator APK receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_APK=' "$output")" -eq 1 ] \
        || fail 'Android emulator APK receipt is duplicated'
    test_receipt="$(grep -E \
        '^ANDROID_EMULATOR_INSTRUMENTATION_PACKAGE=pass sha256=[0-9a-f]{64} package=com\.carriez\.flutter_hbb\.test signer=[0-9A-F]{64} dex=present$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android instrumentation package receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_INSTRUMENTATION_PACKAGE=' "$output")" -eq 1 ] \
        || fail 'Android instrumentation package receipt is duplicated'
    renderer_receipt="$(grep -E \
        '^ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader angle=(present|absent) gles_sha256=[0-9a-f]{64}$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android renderer receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_RENDERER=' "$output")" -eq 1 ] \
        || fail 'Android renderer receipt is duplicated'
    smoke_receipt="$(grep -Fx \
        'ANDROID_EMULATOR_INSTRUMENTATION_SMOKE=pass target=com.carriez.flutter_hbb runner=ControlledCmStopInstrumentation process=main result=ok' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android instrumentation process smoke is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_INSTRUMENTATION_SMOKE=' "$output")" -eq 1 ] \
        || fail 'Android instrumentation process smoke is duplicated'
    runtime_receipt="$(grep -E \
        '^ANDROID_EMULATOR_APP=pass emulator=37\.1\.11 api=34 abi=x86_64 package=com\.carriez\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=[0-9a-f]{64} signing=test-only acceleration=kvm-nested gpu=swiftshader framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android emulator app runtime receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_APP=' "$output")" -eq 1 ] \
        || fail 'Android emulator app runtime receipt is duplicated'
    prepared_receipt="$(grep -E \
        '^ANDROID_EMULATOR_ARTIFACT_PREPARED=pass pending=\.android-x86_64-test-output-pending-[0-9a-f]{64} destination=android-x86_64-test apk_sha256=[0-9a-f]{64} test_sha256=[0-9a-f]{64} signing=test-only publication=atomic-no-clobber$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android emulator artifact preparation receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_ARTIFACT_PREPARED=' "$output")" -eq 1 ] \
        || fail 'Android emulator artifact preparation receipt is duplicated'
    check_receipt="$(grep -E \
        '^ANDROID_EMULATOR_APP_CHECK=pass apk_sha256=[0-9a-f]{64} artifact=prepared-test-only source=exact-archive target=x86_64-linux-android builder=sha256:[0-9a-f]{64} runtime=sha256:[0-9a-f]{64} vm_network=none container_network=none inputs=readonly cleanup=joined$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android emulator app-check receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_APP_CHECK=' "$output")" -eq 1 ] \
        || fail 'Android emulator app-check receipt is duplicated'
    [[ "$apk_receipt" =~ sha256=([0-9a-f]{64}) ]] \
        || fail 'Android emulator APK receipt digest is malformed'
    apk_sha256=${BASH_REMATCH[1]}
    [[ "$test_receipt" =~ sha256=([0-9a-f]{64}) ]] \
        || fail 'Android instrumentation package receipt digest is malformed'
    test_sha256=${BASH_REMATCH[1]}
    case "$runtime_receipt|$prepared_receipt|$check_receipt" in
        *"apk_sha256=$apk_sha256"*"apk_sha256=$apk_sha256"*"apk_sha256=$apk_sha256"*) ;;
        *) fail 'Android emulator app receipts do not identify one APK digest' ;;
    esac
    case "$prepared_receipt" in
        *"test_sha256=$test_sha256"*) ;;
        *) fail 'Android artifact preparation does not identify the installed test APK' ;;
    esac

    "$CLIENT" --host "unix://$SOCK" image rm "$ANDROID_BUILDER_CONFIG_ID" >/dev/null \
        || fail 'Android app builder image could not be retired'
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null \
        || fail 'Android app runtime image could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Android emulator app check left an image'

    [ "$source_before" = \
      "$source_archive_sha:$(sha256sum \
          "$source_root/scripts/pins.env" \
          "$source_root/scripts/android-emulator-app-check.sh" \
          "$source_root/scripts/android-apk-build.sh" \
          "$source_root/scripts/smoke-android-emulator-boot.sh" \
          "$source_root/scripts/verify-android-emulator-apk.py" \
          "$source_root/scripts/publish-artifact-result.py")" ] \
        || fail 'Android emulator app source inputs changed during execution'
    [ "$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'Android emulator app source archive changed during execution'
    [ "$(sha256sum "$source_copy" | awk '{ print $1 }')" = "$source_archive_sha" ] \
        || fail 'private Android emulator app source copy changed during execution'

    umount "$online_mount" \
        || fail 'cannot retire the Android emulator app input projection'
    ANDROID_EMULATOR_ONLINE_MOUNTED=0
    stop_docker_authority
    umount "$inputs" \
        || fail 'cannot retire the sealed Android emulator app input mount'
    SEALED_INPUTS_MOUNTED=0
    umount "$artifact_output" \
        || fail 'cannot retire the Android artifact output mount'
    ANDROID_ARTIFACT_OUTPUT_MOUNTED=0
    printf '%s\n' "$apk_receipt" "$test_receipt" "$renderer_receipt" \
        "$smoke_receipt" "$runtime_receipt" \
        "$prepared_receipt" "$check_receipt"
    printf 'ANDROID_EMULATOR_APP_VM=pass commit=%s tree=%s target=x86_64-linux-android emulator=%s api=%s builder_index=%s builder_runtime=%s runtime_index=%s runtime_config=%s apk_sha256=%s signing=test-only artifact=prepared-test-only output=writable-landlocked uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked source=exact-pushed cleanup=joined\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" \
        "$ANDROID_EMULATOR_VERSION" "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" \
        "$ANDROID_BUILDER_IMAGE_ID" "$ANDROID_BUILDER_CONFIG_ID" \
        "$DEV_CHECK_IMAGE_ID" "$DEV_CHECK_IMAGE_CONFIG_ID" "$apk_sha256"
}

forward_android_runtime_progress() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            'ANDROID_PEER_ARTIFACT_ADMITTED=pass '*)
                printf 'ANDROID_RUNTIME_PROGRESS event=peer-admitted build=absent\n'
                ;;
            'X11_FRAME_SOURCE_BUILD=pass '*)
                printf 'ANDROID_RUNTIME_PROGRESS event=frame-source-built copies=2\n'
                ;;
            'ANDROID_RUNTIME_STAGE '*)
                printf 'ANDROID_RUNTIME_PROGRESS event=runtime-stage %s\n' \
                    "${line#ANDROID_RUNTIME_STAGE }"
                ;;
        esac
    done
}

run_android_emulator_runtime() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local artifact_input=/mnt/rustdesk-android-artifact-input
    local peer_mount=/mnt/rustdesk-android-peer-artifact-input
    local peer_input=$peer_mount/linux-x86_64-peer
    local artifact_destination=$artifact_input/android-x86_64-test
    local apk=$artifact_destination/rustdesk-x86_64-runtime-test.apk
    local checksum=$apk.sha256
    local test_apk=$artifact_destination/rustdesk-x86_64-instrumentation-test.apk
    local test_checksum=$test_apk.sha256
    local staged_apk=$ROOT/android-emulator-runtime-artifact.apk
    local staged_test_apk=$ROOT/android-emulator-runtime-instrumentation.apk
    local source_root=$ROOT/android-emulator-runtime-source
    local online_mount=$source_root/online
    local output=$ROOT/android-emulator-runtime.out
    local emulator_archive=$inputs/candidates/android-emulator/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
    local system_archive=$inputs/candidates/android-emulator/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
    local adb=$inputs/inputs/android-sdk/platform-tools/adb
    local builder_archive=$inputs/inputs/build-images/android-builder.docker.tar.gz
    local runtime_archive=$inputs/inputs/verifier-images/devcheck.docker.tar.gz
    local source_archive_sha input_mount_options artifact_mount_options online_mount_options
    local builder_load runtime_load workload_status=0 source_before inputs_before artifact_before
    local staged_apk_before
    local entry_receipt apk_receipt instrumentation_receipt renderer_receipt runtime_receipt peer_artifact_receipt frame_source_receipt
    local -a runtime_arguments=()
    local lifecycle_receipt task_park_receipt peer_receipt focused_recents_receipt check_receipt
    local resource_bound_receipt
    local checksum_line runtime_peer phase_ordinal phase ordinal
    local recents_build_receipt recents_driver_receipt recents_driver_sha256
    local recents_cycles recents_cycle_pattern recents_cycle recents_task_id
    local recents_task_ids
    local -a recents_action_receipts recents_outcome_receipts cycle_outcomes
    local -a presentation_stage_receipts resource_samples
    local frame_endpoint_receipt frame_parser_receipt
    local frame_observer_self_test_receipt frame_observer_build_receipt
    local frame_observer_receipt frame_observer_dependency_manifest_sha256
    local -a git_builder=(
        setpriv --reuid=1000 --regid=1000 --clear-groups
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
        GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
        GIT_NO_REPLACE_OBJECTS=1
    )

    [[ "$ANDROID_EMULATOR_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator runtime harness commit is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator runtime harness tree is malformed'
    [[ "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator runtime harness archive digest is malformed'
    [[ "$ANDROID_RUNTIME_ARTIFACT_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator runtime artifact commit is malformed'
    [[ "$ANDROID_RUNTIME_ARTIFACT_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android emulator runtime artifact tree is malformed'
    [[ "$ANDROID_RUNTIME_APK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator runtime APK digest is malformed'
    [[ "$ANDROID_RUNTIME_TEST_APK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android emulator runtime instrumentation digest is malformed'
    case "$ANDROID_RUNTIME_SCENARIO" in
        recents|peer-lifecycle|controlled-cm) ;;
        *) fail 'Android emulator runtime scenario differs from recents, peer-lifecycle, or controlled-cm' ;;
    esac
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ] \
       || [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        [[ "$ANDROID_RUNTIME_PEER_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$ANDROID_RUNTIME_PEER_TREE" =~ ^[0-9a-f]{40}$ ]] \
            && [[ "$ANDROID_RUNTIME_PEER_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
            || fail 'Android runtime peer artifact identity is malformed'
    fi
    [ -f "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ ! -L "$ANDROID_EMULATOR_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'Android emulator runtime harness archive metadata differs'
    source_archive_sha="$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android emulator runtime harness archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$ANDROID_EMULATOR_SOURCE_ARCHIVE" \
        --no-same-owner --no-same-permissions -C "$source_root" \
        || fail 'cannot extract the exact Android emulator runtime harness archive'
    [ -z "$(find "$source_root" -xdev \
        \( ! -type d -a ! -type f \) -print -quit)" ] \
        || fail 'Android emulator runtime harness archive contains a non-file entry'
    chown -R 1000:1000 "$source_root"
    "${git_builder[@]}" /usr/bin/git -c init.defaultBranch=master \
        -C "$source_root" init -q \
        || fail 'cannot initialize the Android emulator runtime harness index'
    "${git_builder[@]}" /usr/bin/git -C "$source_root" add -f -- . \
        || fail 'cannot index the exact Android emulator runtime harness'
    [ "$("${git_builder[@]}" /usr/bin/git -C "$source_root" write-tree)" = \
      "$ANDROID_EMULATOR_SOURCE_TREE" ] \
        || fail 'Android emulator runtime harness archive tree differs from pushed master'
    rm -rf -- "$source_root/.git"
    for workload in \
        android-emulator-runtime-check.sh \
        android-emulator-frame-observer.sh \
        android-emulator-frame.py \
        smoke-android-emulator-boot.sh \
        smoke-server-stage.sh \
        smoke-xvfb-prepare.sh \
        smoke-ready.sh \
        online-input-provenance.py \
        verify-android-emulator-apk.py \
        verify-android-apk-manifest.py \
        publish-artifact-result.py \
        offline-image-provenance.py \
        verify-vm-entry-preflight.sh; do
        [ -f "$source_root/scripts/$workload" ] \
            && [ ! -L "$source_root/scripts/$workload" ] \
            && [ "$(stat -c '%u:%g:%a:%h' -- \
                "$source_root/scripts/$workload")" = 1000:1000:700:1 ] \
            || fail "Android emulator runtime workload metadata differs: $workload"
    done
    for workload in pins.env lib.sh online-android-sdk-output.py \
        build-x11-frame-source.py \
        android-peer-artifact.py \
        online-gradle-output.py \
        AndroidRecentsDismiss.java \
        AndroidEmulatorFrameObserver.java \
        android-emulator-frame-observer-dependencies.tsv \
        flutter-peer-source-x11.c \
        smoke-bind-loopback.c smoke-server-launcher.c \
        smoke-xvfb-files.tsv smoke-xvfb-packages.tsv; do
        [ -f "$source_root/scripts/$workload" ] \
            && [ ! -L "$source_root/scripts/$workload" ] \
            && [ "$(stat -c '%u:%g:%a:%h' -- \
                "$source_root/scripts/$workload")" = 1000:1000:600:1 ] \
            || fail "Android emulator runtime data-source metadata differs: $workload"
    done
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
        | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'Android emulator runtime source differs from its guest bootstrap'
    source_before="$source_archive_sha:$(sha256sum \
        "$source_root/scripts/pins.env" \
        "$source_root/scripts/lib.sh" \
        "$source_root/scripts/android-emulator-runtime-check.sh" \
        "$source_root/scripts/android-peer-artifact.py" \
        "$source_root/scripts/publish-artifact-result.py" \
        "$source_root/scripts/AndroidRecentsDismiss.java" \
        "$source_root/scripts/android-emulator-frame-observer.sh" \
        "$source_root/scripts/android-emulator-frame.py" \
        "$source_root/scripts/AndroidEmulatorFrameObserver.java" \
        "$source_root/scripts/android-emulator-frame-observer-dependencies.tsv" \
        "$source_root/scripts/smoke-android-emulator-boot.sh" \
        "$source_root/scripts/smoke-server-stage.sh" \
        "$source_root/scripts/smoke-xvfb-prepare.sh" \
        "$source_root/scripts/smoke-ready.sh" \
        "$source_root/scripts/online-input-provenance.py" \
        "$source_root/scripts/online-gradle-output.py" \
        "$source_root/scripts/flutter-peer-source-x11.c" \
        "$source_root/scripts/build-x11-frame-source.py" \
        "$source_root/scripts/smoke-bind-loopback.c" \
        "$source_root/scripts/smoke-server-launcher.c" \
        "$source_root/scripts/smoke-xvfb-files.tsv" \
        "$source_root/scripts/smoke-xvfb-packages.tsv" \
        "$source_root/scripts/verify-android-emulator-apk.py" \
        "$source_root/scripts/verify-android-apk-manifest.py" \
        "$source_root/scripts/online-android-sdk-output.py" \
        "$source_root/scripts/offline-image-provenance.py" \
        "$source_root/scripts/verify-vm-entry-preflight.sh")"
    frame_observer_dependency_manifest_sha256="$(sha256sum \
        "$source_root/scripts/android-emulator-frame-observer-dependencies.tsv" \
        | awk '{ print $1 }')" \
        || fail 'cannot digest the Android frame-observer dependency manifest'
    [[ "$frame_observer_dependency_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android frame-observer dependency manifest digest is malformed'
    mkdir "$online_mount"
    chown 1000:1000 "$online_mount"
    chmod -R a-w -- "$source_root"

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android runtime input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android runtime input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android runtime inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android runtime inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android runtime inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in
        *,noexec,*) fail 'sealed Android runtime inputs unexpectedly forbid authenticated tools' ;;
    esac

    mkdir "$artifact_input"
    mount -t virtiofs -o ro,nodev,nosuid,noexec \
        rustdesk-android-artifact-input "$artifact_input" \
        || fail 'cannot mount the commit-bound Android runtime artifact authority'
    ANDROID_ARTIFACT_INPUT_MOUNTED=1
    artifact_mount_options="$(findmnt -n -o OPTIONS --target "$artifact_input")" \
        || fail 'Android runtime artifact input mount is absent'
    case ",$artifact_mount_options," in *,ro,*) ;; *) fail 'Android runtime artifact input is writable' ;; esac
    case ",$artifact_mount_options," in *,nodev,*) ;; *) fail 'Android runtime artifact input permits devices' ;; esac
    case ",$artifact_mount_options," in *,nosuid,*) ;; *) fail 'Android runtime artifact input permits set-user-ID execution' ;; esac
    case ",$artifact_mount_options," in *,noexec,*) ;; *) fail 'Android runtime artifact input permits direct execution' ;; esac
    [ "$(stat -c '%u:%g:%a' -- "$artifact_input")" = 1000:1000:700 ] \
        && [ "$(find "$artifact_input" -mindepth 1 -maxdepth 1 -printf '%f\n')" = \
             android-x86_64-test ] \
        || fail 'commit-bound Android runtime artifact root differs'
    [ -d "$artifact_destination" ] && [ ! -L "$artifact_destination" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$artifact_destination")" = \
             1000:1000:700 ] \
        && [ "$(find "$artifact_destination" -mindepth 1 -maxdepth 1 \
            -printf '%f\n' | LC_ALL=C sort)" = \
             $'rustdesk-x86_64-instrumentation-test.apk\nrustdesk-x86_64-instrumentation-test.apk.sha256\nrustdesk-x86_64-runtime-test.apk\nrustdesk-x86_64-runtime-test.apk.sha256' ] \
        || fail 'commit-bound Android runtime artifact inventory differs'
    for artifact_file in "$apk" "$checksum" "$test_apk" "$test_checksum"; do
        [ -f "$artifact_file" ] && [ ! -L "$artifact_file" ] \
            && [ "$(stat -c '%u:%g:%a:%h' -- "$artifact_file")" = \
                 1000:1000:400:1 ] \
            || fail "commit-bound Android runtime artifact metadata differs: $artifact_file"
    done
    checksum_line="$(<"$checksum")"
    [ "$checksum_line" = \
      "$ANDROID_RUNTIME_APK_SHA256  rustdesk-x86_64-runtime-test.apk" ] \
        && [ "$(sha256sum "$apk" | awk '{ print $1 }')" = \
             "$ANDROID_RUNTIME_APK_SHA256" ] \
        || fail 'commit-bound Android runtime artifact digest differs'
    [ "$(<"$test_checksum")" = \
      "$ANDROID_RUNTIME_TEST_APK_SHA256  rustdesk-x86_64-instrumentation-test.apk" ] \
        && [ "$(sha256sum "$test_apk" | awk '{ print $1 }')" = \
             "$ANDROID_RUNTIME_TEST_APK_SHA256" ] \
        || fail 'commit-bound Android instrumentation APK digest differs'
    artifact_before="$(stat -c '%d:%i:%u:%g:%a' -- \
        "$artifact_input" "$artifact_destination"):$(stat -c \
        '%d:%i:%u:%g:%a:%h:%s' -- "$apk" "$checksum" "$test_apk" "$test_checksum"):$(sha256sum \
        "$apk" "$checksum" "$test_apk" "$test_checksum")"
    runtime_arguments=("$staged_apk" "$ANDROID_RUNTIME_APK_SHA256" \
        "$staged_test_apk" "$ANDROID_RUNTIME_TEST_APK_SHA256" \
        "$ANDROID_RUNTIME_ARTIFACT_COMMIT" "$ANDROID_RUNTIME_SCENARIO")
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ] \
       || [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        mkdir "$peer_mount"
        mount -t virtiofs -o ro,nodev,nosuid,noexec \
            rustdesk-android-peer-artifact-input "$peer_mount" \
            || fail 'cannot mount the source-bound Android peer capsule'
        ANDROID_PEER_ARTIFACT_INPUT_MOUNTED=1
        artifact_mount_options="$(findmnt -n -o OPTIONS --target "$peer_mount")"
        for option in ro nodev nosuid noexec; do
            case ",$artifact_mount_options," in
                *,$option,*) ;;
                *) fail "Android peer capsule input lacks $option" ;;
            esac
        done
        [ "$(stat -c '%u:%g:%a' -- "$peer_mount")" = 1000:1000:700 ] \
            && [ "$(find "$peer_mount" -mindepth 1 -maxdepth 1 -printf '%f\n')" = linux-x86_64-peer ] \
            && [ "$(stat -c '%u:%g:%a' -- "$peer_input")" = 1000:1000:500 ] \
            || fail 'Android peer capsule mount metadata differs'
        runtime_arguments+=("$peer_input" "$ANDROID_RUNTIME_PEER_COMMIT" \
            "$ANDROID_RUNTIME_PEER_TREE" "$ANDROID_RUNTIME_PEER_MANIFEST_SHA256")
    fi
    [ ! -e "$staged_apk" ] && [ ! -L "$staged_apk" ] \
        || fail 'Android runtime execution-copy destination already exists'
    [ ! -e "$staged_test_apk" ] && [ ! -L "$staged_test_apk" ] \
        || fail 'Android runtime instrumentation-copy destination already exists'
    install -o 1000 -g 1000 -m 0400 -- "$apk" "$staged_apk" \
        || fail 'cannot stage the authenticated APK on the disposable guest disk'
    install -o 1000 -g 1000 -m 0400 -- "$test_apk" "$staged_test_apk" \
        || fail 'cannot stage the authenticated instrumentation APK on the disposable guest disk'
    [ -f "$staged_apk" ] && [ ! -L "$staged_apk" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$staged_apk")" = \
             "1000:1000:400:1:$(stat -c '%s' -- "$apk")" ] \
        && [ "$(sha256sum "$staged_apk" | awk '{ print $1 }')" = \
             "$ANDROID_RUNTIME_APK_SHA256" ] \
        || fail 'Android runtime execution copy differs from the authenticated artifact'
    [ -f "$staged_test_apk" ] && [ ! -L "$staged_test_apk" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$staged_test_apk")" = \
             "1000:1000:400:1:$(stat -c '%s' -- "$test_apk")" ] \
        && [ "$(sha256sum "$staged_test_apk" | awk '{ print $1 }')" = \
             "$ANDROID_RUNTIME_TEST_APK_SHA256" ] \
        || fail 'Android runtime instrumentation copy differs from the authenticated artifact'
    staged_apk_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$staged_apk" "$staged_test_apk"):$(sha256sum "$staged_apk" "$staged_test_apk")"

    mount --bind "$inputs" "$online_mount" \
        || fail 'cannot project the sealed inputs into the Android runtime harness'
    ANDROID_EMULATOR_RUNTIME_ONLINE_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid "$online_mount" \
        || fail 'cannot make the Android runtime input projection read-only'
    online_mount_options="$(findmnt -n -o OPTIONS --target "$online_mount")" \
        || fail 'Android runtime input projection is absent'
    case ",$online_mount_options," in *,ro,*) ;; *) fail 'Android runtime input projection is writable' ;; esac
    case ",$online_mount_options," in *,nodev,*) ;; *) fail 'Android runtime input projection permits devices' ;; esac
    case ",$online_mount_options," in *,nosuid,*) ;; *) fail 'Android runtime input projection permits set-user-ID execution' ;; esac
    case ",$online_mount_options," in
        *,noexec,*) fail 'Android runtime input projection unexpectedly forbids authenticated tools' ;;
    esac

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$emulator_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_LINUX_X64" ] \
        && [ "$(sha256sum "$emulator_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_LINUX_X64" ] \
        || fail 'sealed Android emulator archive differs for runtime replay'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$system_archive")" = \
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        && [ "$(sha256sum "$system_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64" ] \
        || fail 'sealed Android system-image archive differs for runtime replay'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$adb")" = \
      "1000:1000:555:1:$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        && [ "$(sha256sum "$adb" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1" ] \
        || fail 'sealed Android adb executable differs for runtime replay'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android-builder archive differs for runtime replay'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$runtime_archive")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$runtime_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed Android runtime image archive differs for runtime replay'
    inputs_before="$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$emulator_archive" "$system_archive" "$adb" \
        "$builder_archive" "$runtime_archive"):$(sha256sum \
        "$emulator_archive" "$system_archive" "$adb" \
        "$builder_archive" "$runtime_archive")"

    builder_load="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role android-builder \
                --expected-id "$ANDROID_BUILDER_IMAGE_ID" \
                --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
                --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$ANDROID_BUILDER_CONFIG_ID" \
                --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
    )" || fail 'certified Android-builder image verification/load failed for runtime replay'
    [ "$builder_load" = "loaded and verified android-builder $ANDROID_BUILDER_IMAGE_ID" ] \
        || fail "Android-builder image receipt differs for runtime replay: $builder_load"
    runtime_load="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" verify-load \
                --archive "$runtime_archive" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'certified Android runtime image verification/load failed for runtime replay'
    [ "$runtime_load" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail "Android runtime image receipt differs for runtime replay: $runtime_load"

    mount_android_runtime_failure_output
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/android-emulator-runtime-check.sh" \
        "${runtime_arguments[@]}" \
        2>&1 | tee "$output" | forward_android_runtime_progress
    workload_status=$?
    set -e
    if [ "$workload_status" -ne 0 ]; then
        grep '^ANDROID_PEER_ARTIFACT_ADMITTED=' "$output" >&2 || true
        awk '
            /^ANDROID_FRAMEWORK_DIAGNOSTIC_BEGIN$/ { in_diag = 1 }
            in_diag { print }
            /^ANDROID_FRAMEWORK_DIAGNOSTIC_END$/ { in_diag = 0 }
        ' "$output" >&2
        awk '
            /^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_BEGIN / { in_png = 1; next }
            in_png {
                if (/^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_END( |$)/) in_png = 0
                next
            }
            /^ANDROID_CONNECTION_DIAGNOSTIC_BEGIN$/ { in_diag = 1; next }
            in_diag {
                if (/^ANDROID_CONNECTION_DIAGNOSTIC_END$/) in_diag = 0
                next
            }
            { print }
        ' "$output" | tail -n 320 >&2
        awk '
            /^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_BEGIN / { in_png = 1 }
            in_png { print }
            /^ANDROID_PEER_FRAMEBUFFER_(PNG|RECORD)_END( |$)/ { in_png = 0 }
        ' "$output" >&2
        awk '
            /^ANDROID_CONNECTION_DIAGNOSTIC_BEGIN$/ {
                block = ""
                in_diag = 1
            }
            in_diag { block = block $0 ORS }
            /^ANDROID_CONNECTION_DIAGNOSTIC_END$/ && in_diag {
                last = block
                in_diag = 0
            }
            END { printf "%s", last }
        ' "$output" >&2
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
        ' "$output" >&2
        awk '
            /^ANDROID_RECENTS_(OPEN|GESTURE)_OUTPUT_BEGIN / {
                block = ""
                in_block = 1
            }
            in_block { block = block $0 ORS }
            /^ANDROID_RECENTS_(OPEN|GESTURE)_OUTPUT_END / && in_block {
                print block
                block = ""
                in_block = 0
            }
        ' "$output" >&2
        grep -E '^ANDROID_RECENTS_(OPEN_ACTION|DISMISS_ACTION|DISMISS_OUTCOME|TASK_DIAGNOSTIC|TASK_RECORD)=' \
            "$output" | tail -n 80 >&2 || true
        grep '^ANDROID_PERMANENT_PASSWORD_SUBMIT=' "$output" \
            | tail -n 20 >&2 || true
        grep '^ANDROID_PERMANENT_PASSWORD_ACTION=' "$output" \
            | tail -n 20 >&2 || true
        grep '^ANDROID_MAIN_SERVICE_LOG_' "$output" \
            | tail -n 40 >&2 || true
        grep -E '^ANDROID_PEER_(INITIAL_CREDENTIAL_PROMPT|PASSWORD_INPUT|PASSWORD_ACTION|PASSWORD_SUBMIT|CREDENTIAL_RECOVERY|CONNECTION_WAIT|CONNECTION_READY|CONNECTION_STATE)=' \
            "$output" | tail -n 80 >&2 || true
        grep '^ANDROID_PEER_PROCESS_THREAD ' "$output" \
            | tail -n 64 >&2 || true
        grep '^ANDROID_PEER_FRAME_SAMPLE ' "$output" | tail -n 120 >&2 || true
        grep '^ANDROID_PEER_FRAMEBUFFER_DIAGNOSTIC ' "$output" \
            | tail -n 20 >&2 || true
        grep -E '^(ANDROID_PEER_PRESENTATION_(STAGE|PROGRESS)|.*RUSTDESK_PRESENTATION_PROGRESS )' \
            "$output" | tail -n 160 >&2 || true
        grep '^Android initial UI:' "$output" | tail -n 80 >&2 || true
        grep '^Android emulator boot smoke:' "$output" | tail -n 20 >&2 || true
        fail "Android emulator runtime replay exited with status $workload_status"
    fi
    [ "$(stat -c '%s' -- "$output")" -le 2097152 ] \
        || fail 'Android emulator runtime replay output exceeds its bound'
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ] \
       || [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        peer_artifact_receipt="$(grep -Fx \
            "ANDROID_PEER_ARTIFACT_ADMITTED=pass commit=$ANDROID_RUNTIME_PEER_COMMIT tree=$ANDROID_RUNTIME_PEER_TREE manifest_sha256=$ANDROID_RUNTIME_PEER_MANIFEST_SHA256 builder=$DEV_CHECK_IMAGE_CONFIG_ID files=7 build=absent execution=readonly-guest-copy" \
            "$output")" || fail 'Android peer artifact admission receipt is absent'
        [ "$(grep -c '^ANDROID_PEER_ARTIFACT_ADMITTED=' "$output")" -eq 1 ] \
            || fail 'Android peer artifact admission receipt is duplicated'
    fi
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ]; then
        frame_source_receipt="$(grep -E \
            "^X11_FRAME_SOURCE_BUILD=pass source_sha256=$(sha256sum "$source_root/scripts/flutter-peer-source-x11.c" | awk '{ print $1 }') sha256=[0-9a-f]{64} bytes=[1-9][0-9]* copies=2 equality=byte-identical network=none output=private$" \
            "$output")" || fail 'independent Android display fixture build receipt differs'
        [ "$(grep -c '^X11_FRAME_SOURCE_BUILD=' "$output")" -eq 1 ] \
            || fail 'independent Android display fixture receipt is duplicated'
    fi
    entry_receipt="$(grep -Fx \
        "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android runtime entry-authority receipt is absent'; }
    [ "$(grep -Fc 'VERIFIER_VM_ENTRY_AUTHORITY=' "$output")" -eq 1 ] \
        || fail 'Android runtime entry-authority receipt is duplicated'
    apk_receipt="$(grep -E \
        "^ANDROID_EMULATOR_APK=pass sha256=$ANDROID_RUNTIME_APK_SHA256 package=com\\.carriez\\.flutter_hbb abi=x86_64 native_libraries=[1-9][0-9]* signer=[0-9A-F]{64} signing=test-only$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android runtime APK receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_APK=' "$output")" -eq 1 ] \
        || fail 'Android runtime APK receipt is duplicated'
    instrumentation_receipt="$(grep -Fx \
        'ANDROID_EMULATOR_INSTRUMENTATION_SMOKE=pass target=com.carriez.flutter_hbb runner=ControlledCmStopInstrumentation process=main result=ok' \
        "$output")" \
        || fail 'Android runtime instrumentation execution receipt is absent'
    [ "$(grep -c '^ANDROID_EMULATOR_INSTRUMENTATION_SMOKE=' "$output")" -eq 1 ] \
        || fail 'Android runtime instrumentation execution receipt is duplicated'
    recents_build_receipt="$(grep -E \
        '^ANDROID_RECENTS_GESTURE_BUILD=pass sha256=[0-9a-f]{64} source_sha256=[0-9a-f]{64} android_jar_sha256=[0-9a-f]{64} d8_sha256=[0-9a-f]{64} copies=2 equality=byte-identical network=none output=private-bind$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android Recents gesture-driver build receipt is absent'; }
    [ "$(grep -c '^ANDROID_RECENTS_GESTURE_BUILD=' "$output")" -eq 1 ] \
        || fail 'Android Recents gesture-driver build receipt is duplicated'
    [[ "$recents_build_receipt" =~ \
        sha256=([0-9a-f]{64})\ source_sha256= ]] \
        || fail 'Android Recents gesture-driver build receipt is malformed'
    recents_driver_sha256=${BASH_REMATCH[1]}
    recents_driver_receipt="$(grep -E \
        "^ANDROID_RECENTS_GESTURE_DRIVER=pass sha256=$recents_driver_sha256 framework=android14-ui-automation-direct open=ui-automation-app-switch-key-display-0 events=12 steps=10 step_ms=16 wait_for_animations=false runtime_uiautomator_sha256=[0-9a-f]{64} device_path=/data/local/tmp/rustdesk-recents-dismiss\.jar$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android Recents gesture-driver stage receipt is absent'; }
    [ "$(grep -c '^ANDROID_RECENTS_GESTURE_DRIVER=' "$output")" -eq 1 ] \
        || fail 'Android Recents gesture-driver stage receipt is duplicated'
    [[ "$recents_driver_receipt" =~ \
        runtime_uiautomator_sha256=([0-9a-f]{64})\ device_path= ]] \
        || fail 'Android Recents gesture-driver runtime UiAutomator digest is malformed'
    recents_runtime_uiautomator_sha256=${BASH_REMATCH[1]}
    case "$ANDROID_RUNTIME_SCENARIO" in
        recents)
            recents_cycles=10
            recents_cycle_pattern='([1-9]|10)'
            ;;
        peer-lifecycle)
            recents_cycles=6
            recents_cycle_pattern='[1-6]'
            ;;
        controlled-cm)
            recents_cycles=1
            recents_cycle_pattern=1
            ;;
        *)
            recents_cycles=2
            recents_cycle_pattern='[12]'
            ;;
    esac
    mapfile -t recents_open_action_receipts < <(grep -E \
        "^ANDROID_RECENTS_OPEN_ACTION=injected cycle=$recents_cycle_pattern task_id=[1-9][0-9]* mechanism=android14-ui-automation-app-switch-key keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$recents_driver_sha256$" \
        "$output" || true)
    [ "${#recents_open_action_receipts[@]}" -eq "$recents_cycles" ] \
        && [ "$(grep -c '^ANDROID_RECENTS_OPEN_ACTION=' "$output")" -eq \
             "$recents_cycles" ] \
        || { tail -n 320 "$output" >&2; fail 'Android Recents-open action receipts differ'; }
    for recents_open_action_receipt in "${recents_open_action_receipts[@]}"; do
        [[ "$recents_open_action_receipt" =~ \
            driver_elapsed_ms=([0-9]+)\ driver_sha256= ]] \
            || fail 'Android Recents-open driver elapsed time is malformed'
        recents_open_elapsed_ms=${BASH_REMATCH[1]}
        [ "$recents_open_elapsed_ms" -le 5000 ] \
            || fail 'Android Recents-open driver elapsed time is outside its bound'
    done
    mapfile -t recents_action_receipts < <(grep -E \
        "^ANDROID_RECENTS_DISMISS_ACTION=injected cycle=$recents_cycle_pattern task_id=[1-9][0-9]* bounds=[0-9]+,[0-9]+,[0-9]+,[0-9]+ start=[0-9]+,[0-9]+ end=[0-9]+,0 framework=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$recents_driver_sha256$" \
        "$output" || true)
    [ "${#recents_action_receipts[@]}" -eq "$recents_cycles" ] \
        && [ "$(grep -c '^ANDROID_RECENTS_DISMISS_ACTION=' "$output")" -eq \
             "$recents_cycles" ] \
        || { tail -n 320 "$output" >&2; fail 'Android Recents action receipts differ'; }
    recents_action_geometry_pattern='bounds=([0-9]+),([0-9]+),([0-9]+),([0-9]+) start=([0-9]+),([0-9]+) end=([0-9]+),0 '
    for recents_action_receipt in "${recents_action_receipts[@]}"; do
        [[ "$recents_action_receipt" =~ $recents_action_geometry_pattern ]] \
            || fail 'Android Recents action geometry is malformed'
        recents_left=${BASH_REMATCH[1]}
        recents_top=${BASH_REMATCH[2]}
        recents_right=${BASH_REMATCH[3]}
        recents_bottom=${BASH_REMATCH[4]}
        recents_start_x=${BASH_REMATCH[5]}
        recents_start_y=${BASH_REMATCH[6]}
        recents_end_x=${BASH_REMATCH[7]}
        [ "$recents_right" -gt "$recents_left" ] \
            && [ "$recents_bottom" -gt "$recents_top" ] \
            && [ "$recents_start_x" -eq \
                 "$(((recents_left + recents_right) / 2))" ] \
            && [ "$recents_start_y" -eq \
                 "$(((recents_top + recents_bottom) / 2))" ] \
            && [ "$recents_end_x" -eq "$recents_start_x" ] \
            || fail 'Android Recents action did not use the exact visible-task center'
        [[ "$recents_action_receipt" =~ \
            driver_elapsed_ms=([0-9]+)\ driver_sha256= ]] \
            || fail 'Android Recents driver elapsed time is malformed'
        recents_driver_elapsed_ms=${BASH_REMATCH[1]}
        [ "$recents_driver_elapsed_ms" -ge 160 ] \
            && [ "$recents_driver_elapsed_ms" -le 5000 ] \
            || fail 'Android Recents driver elapsed time is outside its bound'
    done
    mapfile -t recents_outcome_receipts < <(grep -E \
        "^ANDROID_RECENTS_DISMISS_OUTCOME=pass cycle=$recents_cycle_pattern task_id=[1-9][0-9]* actions=1$" \
        "$output" || true)
    [ "${#recents_outcome_receipts[@]}" -eq "$recents_cycles" ] \
        && [ "$(grep -c '^ANDROID_RECENTS_DISMISS_OUTCOME=' "$output")" -eq \
             "$recents_cycles" ] \
        || { tail -n 320 "$output" >&2; fail 'Android Recents outcome receipts differ'; }
    recents_task_ids=
    for recents_cycle in $(seq 1 "$recents_cycles"); do
        mapfile -t cycle_outcomes < <(printf '%s\n' \
            "${recents_outcome_receipts[@]}" | grep -E \
            "^ANDROID_RECENTS_DISMISS_OUTCOME=pass cycle=$recents_cycle task_id=[1-9][0-9]* actions=1$" || true)
        [ "${#cycle_outcomes[@]}" -eq 1 ] \
            || fail "Android Recents cycle $recents_cycle outcome differs"
        [[ "${cycle_outcomes[0]}" =~ task_id=([1-9][0-9]*)\ actions=1$ ]] \
            || fail "Android Recents cycle $recents_cycle task binding is malformed"
        recents_task_id=${BASH_REMATCH[1]}
        [ "$(printf '%s\n' "${recents_open_action_receipts[@]}" | grep -Ec \
            "^ANDROID_RECENTS_OPEN_ACTION=injected cycle=$recents_cycle task_id=$recents_task_id mechanism=android14-ui-automation-app-switch-key keycode=187 events=2 display_id=0 source=keyboard device=virtual-keyboard wait_for_animations=false driver_elapsed_ms=[0-9]+ driver_sha256=$recents_driver_sha256$" || true)" -eq 1 ] \
            || fail "Android Recents cycle $recents_cycle open/outcome binding differs"
        [ "$(printf '%s\n' "${recents_action_receipts[@]}" | grep -Ec \
            "^ANDROID_RECENTS_DISMISS_ACTION=injected cycle=$recents_cycle task_id=$recents_task_id .* driver_sha256=$recents_driver_sha256$" || true)" -eq 1 ] \
            || fail "Android Recents cycle $recents_cycle action/outcome binding differs"
        case " $recents_task_ids " in
            *" $recents_task_id "*)
                fail "Android Recents cycle $recents_cycle reused a task ID"
                ;;
        esac
        recents_task_ids="${recents_task_ids:+$recents_task_ids }$recents_task_id"
    done
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ]; then
    frame_endpoint_receipt="$(grep -Fx \
        'ANDROID_EMULATOR_FRAME_ENDPOINT=pass connect=127.0.0.1:8554 bind=[::]:8554 namespace=loopback-only transport=grpc-stream network=container-none' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android frame-endpoint receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_FRAME_ENDPOINT=' "$output")" -eq 1 ] \
        || fail 'Android frame-endpoint receipt is duplicated'
    frame_parser_receipt="$(grep -Fx \
        'ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=pass format=counter32 source=monotonic-publication alias=refused' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android frame-parser receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=' "$output")" -eq 1 ] \
        || fail 'Android frame-parser receipt is duplicated'
    frame_observer_self_test_receipt="$(grep -Fx \
        'ANDROID_EMULATOR_FRAME_OBSERVER_SELF_TEST=pass scenarios=7' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android frame-observer self-test receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_FRAME_OBSERVER_SELF_TEST=' "$output")" -eq 1 ] \
        || fail 'Android frame-observer self-test receipt is duplicated'
    frame_observer_build_receipt="$(grep -E \
        "^ANDROID_EMULATOR_FRAME_OBSERVER_BUILD=pass protoc=3\\.20\\.1 protobuf=3\\.22\\.3 grpc=1\\.57\\.0 jars=31 generated_sources=[1-9][0-9]* dependency_manifest_sha256=$frame_observer_dependency_manifest_sha256 network=container-loopback output=private-bind$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android frame-observer build receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_FRAME_OBSERVER_BUILD=' "$output")" -eq 1 ] \
        || fail 'Android frame-observer build receipt is duplicated'
    frame_observer_receipt="$(grep -E \
        '^ANDROID_EMULATOR_FRAME_OBSERVER=pass endpoint=127\.0\.0\.1:8554 transport=grpc-stream format=rgb888 orientation=bottom-up frames_received=[1-9][0-9]* frames_published=[1-9][0-9]* last_seq=[0-9]+ cleanup=joined$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android frame-observer runtime receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_FRAME_OBSERVER=' "$output")" -eq 1 ] \
        || fail 'Android frame-observer runtime receipt is duplicated'
    fi
    renderer_receipt="$(grep -E \
        '^ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader angle=(present|absent) gles_sha256=[0-9a-f]{64}$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android renderer receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_RENDERER=' "$output")" -eq 1 ] \
        || fail 'Android renderer receipt is duplicated'
    runtime_receipt="$(grep -E \
        "^ANDROID_EMULATOR_APP=pass emulator=37\\.1\\.11 api=34 abi=x86_64 package=com\\.carriez\\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=$ANDROID_RUNTIME_APK_SHA256 signing=test-only acceleration=kvm-nested gpu=swiftshader framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android runtime app receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_APP=' "$output")" -eq 1 ] \
        || fail 'Android runtime app receipt is duplicated'
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ]; then
    lifecycle_receipt="$(grep -E \
        "^ANDROID_EMULATOR_LIFECYCLE=pass task_removals=6 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=absent immersive_cling=(absent|dismissed-1) apk_sha256=$ANDROID_RUNTIME_APK_SHA256 vm_network=none container_network=none cleanup=joined$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android lifecycle runtime receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_LIFECYCLE=' "$output")" -eq 1 ] \
        || fail 'Android lifecycle runtime receipt is duplicated'
    task_park_receipt="$(grep -E \
        '^ANDROID_PEER_TASK_PARK=pass samples=6 interval_seconds=20 elapsed_ms=[1-9][0-9]* task=absent process=stable service=foreground-preserved keyed_sessions=unchanged peer_connections=0$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android removed-task hold receipt is absent'; }
    [ "$(grep -c '^ANDROID_PEER_TASK_PARK=' "$output")" -eq 1 ] \
        || fail 'Android removed-task hold receipt is duplicated'
    [[ "$task_park_receipt" =~ elapsed_ms=([1-9][0-9]*)\ task=absent ]] \
        && [ "${BASH_REMATCH[1]}" -ge 120000 ] \
        && [ "${BASH_REMATCH[1]}" -le 180000 ] \
        || fail 'Android removed-task hold duration is outside its bounded schedule'
    initial_credential_receipt="$(grep -E \
        '^ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=pass reason=missing-credential observer=(exact|android-accessibility-prefix-240) observed_network_attempts=0 pre_session_failure_delta=0 key_failure_delta=0 keyed_session_delta=0 established=0 prompt_ms=[0-9]+ prompt_limit_ms=240000$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android initial credential prompt receipt is absent'; }
    [ "$(grep -c '^ANDROID_PEER_INITIAL_CREDENTIAL_PROMPT=' "$output")" -eq 1 ] \
        || fail 'Android initial credential prompt receipt is malformed or duplicated'
    mapfile -t presentation_stage_receipts < <(grep -E \
        '^ANDROID_PEER_PRESENTATION_STAGE=pass phase=(initial|warm-reconnect-[1-6]|task-relaunch-[1-6]) ordinal=([1-9]|1[0-3]) server_connection=[1-9][0-9]* display=[0-9]+ server_wire_generation=[1-9][0-9]* viewer_wire_generation=[1-9][0-9]* server_wall_ms=[1-9][0-9]* server_queue_us=[0-9]+ viewer_mailbox_generation=[1-9][0-9]* viewer_wall_ms=[1-9][0-9]* receive_to_admit_us=[0-9]+ admit_to_dequeue_us=[0-9]+ decode_us=[0-9]+ dart_session=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} publication=[1-9][0-9]* dart_wall_ms=[1-9][0-9]* event_queue_us=[0-9]+ take_us=[0-9]+ checkpoint_us=[0-9]+ decode_commit_us=[0-9]+ ui_finalize_us=[0-9]+ dart_total_us=[0-9]+ image_conversions_active=[1-3] image_conversions_waiting=([0-9]|[1-5][0-9]|6[0-4]) image_conversions_peak=[1-3] client_owner=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        "$output" || true)
    [ "${#presentation_stage_receipts[@]}" -eq 13 ] \
        && [ "$(grep -c '^ANDROID_PEER_PRESENTATION_STAGE=' "$output")" -eq 13 ] \
        || { tail -n 320 "$output" >&2; fail 'Android presentation-stage receipts are absent, malformed, or duplicated'; }
    for phase_ordinal in 'initial 1' 'warm-reconnect-1 2' 'warm-reconnect-2 3' \
        'warm-reconnect-3 4' 'warm-reconnect-4 5' 'warm-reconnect-5 6' \
        'warm-reconnect-6 7' 'task-relaunch-1 8' 'task-relaunch-2 9' \
        'task-relaunch-3 10' 'task-relaunch-4 11' 'task-relaunch-5 12' \
        'task-relaunch-6 13'; do
        read -r phase ordinal <<<"$phase_ordinal"
        [ "$(printf '%s\n' "${presentation_stage_receipts[@]}" \
            | grep -Ec "^ANDROID_PEER_PRESENTATION_STAGE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
            || fail "Android presentation-stage binding differs for $phase"
    done
    mapfile -t resource_samples < <(grep -E \
        '^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=(baseline|warm-reconnect-[1-6]|task-relaunch-[1-6]) ordinal=([0-9]|1[0-2]) rss_kib=[1-9][0-9]* threads=[1-9][0-9]* rss_growth_kib=[0-9]+ thread_growth=[0-9]+ handles=unobserved handle_reason=release-apk-nonroot-procfs-denied observer_survival=process-service-peer$' \
        "$output" || true)
    [ "${#resource_samples[@]}" -eq 13 ] \
        && [ "$(grep -c '^ANDROID_PEER_RESOURCE_SAMPLE=' "$output")" -eq 13 ] \
        || { tail -n 320 "$output" >&2; fail 'Android peer resource samples are absent, malformed, or duplicated'; }
    for phase_ordinal in 'baseline 0' 'warm-reconnect-1 1' 'warm-reconnect-2 2' \
        'warm-reconnect-3 3' 'warm-reconnect-4 4' 'warm-reconnect-5 5' \
        'warm-reconnect-6 6' 'task-relaunch-1 7' 'task-relaunch-2 8' \
        'task-relaunch-3 9' 'task-relaunch-4 10' 'task-relaunch-5 11' \
        'task-relaunch-6 12'; do
        read -r phase ordinal <<<"$phase_ordinal"
        [ "$(printf '%s\n' "${resource_samples[@]}" \
            | grep -Ec "^ANDROID_PEER_RESOURCE_SAMPLE=pass phase=$phase ordinal=$ordinal ")" -eq 1 ] \
            || fail "Android peer resource-sample binding differs for $phase"
    done
    resource_bound_receipt="$(grep -E \
        '^ANDROID_PEER_RESOURCE_BOUND=partial samples=13 replacement_samples=12 rss_baseline_kib=[1-9][0-9]* rss_max_kib=[1-9][0-9]* rss_final_kib=[1-9][0-9]* rss_growth_max_kib=[0-9]+ rss_growth_limit_kib=131072 threads_baseline=[1-9][0-9]* threads_max=[1-9][0-9]* threads_final=[1-9][0-9]* thread_growth_max=[0-9]+ thread_growth_limit=8 handles=unobserved handle_bound=open handle_reason=release-apk-nonroot-procfs-denied observer_survival=process-service-peer$' \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android peer aggregate resource bound is absent'; }
    [ "$(grep -c '^ANDROID_PEER_RESOURCE_BOUND=' "$output")" -eq 1 ] \
        || fail 'Android peer aggregate resource bound is duplicated'
    peer_receipt="$(grep -E \
        "^ANDROID_EMULATOR_PEER_LIFECYCLE=pass auth=cpace server=production address=127\\.0\\.0\\.1:22118 transport=adb-reverse-loopback service=foreground-preserved process=same-across-task-removal task_removals=6 old_sessions=closed replacements=6 warm_reconnects=6 warm_owner=preserved warm_recovery_max_ms=[0-9]+ initial_credential=missing-credential initial_credential_prompt_observer=(exact|android-accessibility-prefix-240) initial_credential_prompt_ms=[0-9]+ initial_credential_prompt_limit_ms=240000 initial_network_attempts=0 wrong_credential=peer-confirmation-unavailable-prompt wrong_attempts=1 auto_retry=absent credential_prompt_observer=(exact|android-accessibility-prefix-240) credential_prompt_ms=[0-9]+ credential_prompt_limit_ms=240000 auto_retry_observation_ms=140000 correct_credential_connection_ms=[0-9]+ credential_connection_limit_ms=240000 cached_connection_max_ms=[0-9]+ cached_connection_limit_ms=30000 initial_recovery_ms=[0-9]+ background_cycles=3 background_seconds=2,6,120 background_recovery_max_ms=[0-9]+ task_recovery_max_ms=[0-9]+ recovery_limit_ms=8000 freshness_max_ms=[0-9]+ freshness_limit_ms=2000 capture_max_ms=[0-9]+ capture_limit_ms=500 distinct_frames=(1[2-9]|[2-9][0-9]|[1-9][0-9]{2,}) resource_samples=13 resource_bound=partial-rss-threads handle_bound=open force_stop=baseline apk_sha256=$ANDROID_RUNTIME_APK_SHA256 vm_network=none container_network=none server_listener=127\\.0\\.0\\.1:21118 reverse_cleanup=removed x11=unix-only cleanup=joined$" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android real-peer lifecycle receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_PEER_LIFECYCLE=' "$output")" -eq 1 ] \
        || fail 'Android real-peer lifecycle receipt is duplicated'
        runtime_peer=production-loopback-cpace-changing-display
    elif [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        controlled_cm_receipt="$(grep -Fx \
            'ANDROID_CONTROLLED_CM_FILE=pass initiator=linux-probe responder=android-mainservice auth=cpace login=filetransfer cm=admitted directory=reply transport=adb-forward-loopback forward_cleanup=removed password_transport=stdin' \
            "$output")" || fail 'Android controlled-CM positive receipt is absent'
        controlled_stop_receipt="$(grep -Fx \
            'ANDROID_CONTROLLED_CM_STOP=pass command=production-ui-stop service=absent process=same live_keyed_cm=closed fresh_keyed_cm=refused forward_cleanup=removed force_stop=absent restart=keyed-cm-file-reply' \
            "$output")" || fail 'Android controlled-CM Stop receipt is absent'
        controlled_restart_receipt="$(grep -Fx \
            'ANDROID_CONTROLLED_CM_RESTART=pass auth=cpace login=filetransfer cm=admitted directory=reply service=foreground process=same forward_cleanup=removed force_stop=absent' \
            "$output")" || fail 'Android controlled-CM restart receipt is absent'
        controlled_lifecycle_receipt="$(grep -Fx \
            "ANDROID_EMULATOR_CONTROLLED_CM=pass task_removals=1 service=foreground-across-task-relaunch-then-stopped process=same positive=filetransfer-dir-reply stopped=live-keyed-cm-closed-and-fresh-refused restart=filetransfer-dir-reply framework_anr=absent apk_sha256=$ANDROID_RUNTIME_APK_SHA256 vm_network=none container_network=none cleanup=joined" \
            "$output")" || fail 'Android controlled-CM lifecycle receipt is absent'
        for marker in ANDROID_CONTROLLED_CM_FILE ANDROID_CONTROLLED_CM_STOP ANDROID_CONTROLLED_CM_RESTART ANDROID_EMULATOR_CONTROLLED_CM; do
            [ "$(grep -c "^$marker=" "$output")" -eq 1 ] \
                || fail "Android controlled-CM receipt is duplicated: $marker"
        done
        runtime_peer=production-loopback-cpace-controlled-cm
    else
        focused_recents_receipt="$(grep -E \
            "^ANDROID_EMULATOR_RECENTS=pass task_removals=10 actions=10 open_actions=10 task_ids=distinct open=ui-automation-app-switch-key-display-0 driver=android14-ui-automation-direct events=12 steps=10 step_ms=16 wait_for_animations=false runtime_uiautomator_sha256=$recents_runtime_uiautomator_sha256 driver_sha256=$recents_driver_sha256 framework_anr=absent service=never-started relaunch=resumed apk_sha256=$ANDROID_RUNTIME_APK_SHA256 vm_network=none container_network=none cleanup=joined$" \
            "$output")" \
            || { tail -n 320 "$output" >&2; fail 'focused Android Recents runtime receipt is absent'; }
        [ "$(grep -c '^ANDROID_EMULATOR_RECENTS=' "$output")" -eq 1 ] \
            || fail 'focused Android Recents runtime receipt is duplicated'
        runtime_peer=absent
    fi
    check_receipt="$(grep -Fx \
        "ANDROID_EMULATOR_RUNTIME_CHECK=pass scenario=$ANDROID_RUNTIME_SCENARIO artifact_commit=$ANDROID_RUNTIME_ARTIFACT_COMMIT apk_sha256=$ANDROID_RUNTIME_APK_SHA256 test_sha256=$ANDROID_RUNTIME_TEST_APK_SHA256 signing=test-only package=com.carriez.flutter_hbb abi=x86_64 source=commit-bound-retained-artifact builder=$ANDROID_BUILDER_CONFIG_ID runtime=$DEV_CHECK_IMAGE_CONFIG_ID peer=$runtime_peer vm_network=none container_network=none inputs=readonly cleanup=joined" \
        "$output")" \
        || { tail -n 320 "$output" >&2; fail 'Android emulator runtime-check receipt is absent'; }
    [ "$(grep -c '^ANDROID_EMULATOR_RUNTIME_CHECK=' "$output")" -eq 1 ] \
        || fail 'Android emulator runtime-check receipt is duplicated'

    "$CLIENT" --host "unix://$SOCK" image rm "$ANDROID_BUILDER_CONFIG_ID" >/dev/null \
        || fail 'Android runtime verifier image could not be retired'
    "$CLIENT" --host "unix://$SOCK" image rm "$DEV_CHECK_IMAGE_CONFIG_ID" >/dev/null \
        || fail 'Android emulator runtime image could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Android emulator runtime replay left an image'
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'Android emulator runtime replay left a container'

    [ "$source_before" = \
      "$source_archive_sha:$(sha256sum \
          "$source_root/scripts/pins.env" \
          "$source_root/scripts/lib.sh" \
          "$source_root/scripts/android-emulator-runtime-check.sh" \
          "$source_root/scripts/android-peer-artifact.py" \
          "$source_root/scripts/publish-artifact-result.py" \
          "$source_root/scripts/AndroidRecentsDismiss.java" \
          "$source_root/scripts/android-emulator-frame-observer.sh" \
          "$source_root/scripts/android-emulator-frame.py" \
          "$source_root/scripts/AndroidEmulatorFrameObserver.java" \
          "$source_root/scripts/android-emulator-frame-observer-dependencies.tsv" \
          "$source_root/scripts/smoke-android-emulator-boot.sh" \
          "$source_root/scripts/smoke-server-stage.sh" \
          "$source_root/scripts/smoke-xvfb-prepare.sh" \
          "$source_root/scripts/smoke-ready.sh" \
          "$source_root/scripts/online-input-provenance.py" \
          "$source_root/scripts/online-gradle-output.py" \
          "$source_root/scripts/flutter-peer-source-x11.c" \
          "$source_root/scripts/build-x11-frame-source.py" \
          "$source_root/scripts/smoke-bind-loopback.c" \
          "$source_root/scripts/smoke-server-launcher.c" \
          "$source_root/scripts/smoke-xvfb-files.tsv" \
          "$source_root/scripts/smoke-xvfb-packages.tsv" \
          "$source_root/scripts/verify-android-emulator-apk.py" \
          "$source_root/scripts/verify-android-apk-manifest.py" \
          "$source_root/scripts/online-android-sdk-output.py" \
          "$source_root/scripts/offline-image-provenance.py" \
          "$source_root/scripts/verify-vm-entry-preflight.sh")" ] \
        || fail 'Android emulator runtime harness inputs changed during execution'
    [ "$(sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'Android emulator runtime harness archive changed during execution'
    [ "$inputs_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
          "$emulator_archive" "$system_archive" "$adb" \
          "$builder_archive" "$runtime_archive"):$(sha256sum \
          "$emulator_archive" "$system_archive" "$adb" \
          "$builder_archive" "$runtime_archive")" ] \
        || fail 'sealed Android runtime inputs changed during execution'
    [ "$artifact_before" = \
      "$(stat -c '%d:%i:%u:%g:%a' -- \
          "$artifact_input" "$artifact_destination"):$(stat -c \
          '%d:%i:%u:%g:%a:%h:%s' -- "$apk" "$checksum" "$test_apk" "$test_checksum"):$(sha256sum \
          "$apk" "$checksum" "$test_apk" "$test_checksum")" ] \
        || fail 'commit-bound Android runtime artifact changed during execution'
    [ "$staged_apk_before" = \
      "$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
          "$staged_apk" "$staged_test_apk"):$(sha256sum "$staged_apk" "$staged_test_apk")" ] \
        || fail 'Android runtime execution pair changed during execution'
    rm -- "$staged_apk" "$staged_test_apk" \
        || fail 'cannot retire the Android runtime execution pair'
    [ ! -e "$staged_apk" ] && [ ! -L "$staged_apk" ] \
        && [ ! -e "$staged_test_apk" ] && [ ! -L "$staged_test_apk" ] \
        || fail 'Android runtime execution pair survived retirement'

    umount "$online_mount" \
        || fail 'cannot retire the Android runtime input projection'
    ANDROID_EMULATOR_RUNTIME_ONLINE_MOUNTED=0
    stop_docker_authority
    umount "$artifact_input" \
        || fail 'cannot retire the commit-bound Android runtime artifact mount'
    ANDROID_ARTIFACT_INPUT_MOUNTED=0
    umount /mnt/rustdesk-android-runtime-failure || fail 'cannot retire the Android failure-output mount'
    ANDROID_RUNTIME_FAILURE_MOUNTED=0
    if [ "$ANDROID_PEER_ARTIFACT_INPUT_MOUNTED" -eq 1 ]; then
        umount "$peer_mount" || fail 'cannot retire the Android peer capsule mount'
        ANDROID_PEER_ARTIFACT_INPUT_MOUNTED=0
    fi
    umount "$inputs" \
        || fail 'cannot retire the sealed Android runtime input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$entry_receipt" "$apk_receipt" "$instrumentation_receipt" \
        "$recents_build_receipt" "$recents_driver_receipt" \
        "${recents_open_action_receipts[@]}" \
        "${recents_action_receipts[@]}" "${recents_outcome_receipts[@]}" \
        "$renderer_receipt" "$runtime_receipt"
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ] \
       || [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        printf '%s\n' "$peer_artifact_receipt"
    fi
    if [ "$ANDROID_RUNTIME_SCENARIO" = peer-lifecycle ]; then
        printf '%s\n' "$frame_source_receipt"
        printf '%s\n' "$frame_endpoint_receipt" "$frame_parser_receipt" \
            "$frame_observer_self_test_receipt" "$frame_observer_build_receipt" \
            "$frame_observer_receipt" "$lifecycle_receipt" "$task_park_receipt" \
            "$initial_credential_receipt" \
            "${presentation_stage_receipts[@]}" \
            "${resource_samples[@]}" "$resource_bound_receipt" \
            "$peer_receipt"
    elif [ "$ANDROID_RUNTIME_SCENARIO" = controlled-cm ]; then
        printf '%s\n' "$controlled_cm_receipt" "$controlled_stop_receipt" \
            "$controlled_lifecycle_receipt"
    else
        printf '%s\n' "$focused_recents_receipt"
    fi
    printf '%s\n' "$check_receipt"
    printf 'ANDROID_EMULATOR_RUNTIME_VM=pass scenario=%s harness_commit=%s harness_tree=%s artifact_commit=%s artifact_tree=%s apk_sha256=%s test_sha256=%s target=x86_64-linux-android emulator=%s api=%s builder_index=%s builder_runtime=%s runtime_index=%s runtime_config=%s signing=test-only peer=%s uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked artifact=readonly-landlocked source=exact-pushed cleanup=joined\n' \
        "$ANDROID_RUNTIME_SCENARIO" \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" \
        "$ANDROID_RUNTIME_ARTIFACT_COMMIT" "$ANDROID_RUNTIME_ARTIFACT_TREE" \
        "$ANDROID_RUNTIME_APK_SHA256" "$ANDROID_RUNTIME_TEST_APK_SHA256" "$ANDROID_EMULATOR_VERSION" \
        "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" "$ANDROID_BUILDER_IMAGE_ID" \
        "$ANDROID_BUILDER_CONFIG_ID" "$DEV_CHECK_IMAGE_ID" \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$runtime_peer"
}

run_flutter_model_tests() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/flutter-model-source
    local work_root=$ROOT/flutter-model-work
    local output=$ROOT/flutter-model-tests.out
    local result_validator=$ROOT/flutter-model-result-validator.py
    local pub_validator=$ROOT/flutter-pub-cache-validator.py
    local cargo_validator=$ROOT/flutter-cargo-vendor-validator.py
    local rust_archive=$inputs/rust-1.75.tar.xz
    local flutter_archive=$inputs/flutter-3.24.5.tar.xz
    local llvm_archive=$inputs/llvm-15.0.6.tar.xz
    local cargo_vendor=$inputs/cargo-vendor
    local cargo_config=$inputs/cargo-vendor-config.toml
    local frb_codegen=$inputs/frb-tool/bin/flutter_rust_bridge_codegen
    local pub_cache=$inputs/pub-cache
    local builder_archive=$inputs/build-images/deb-builder.docker.tar.gz
    local load_output container_status=0 inspect namespace_inspect result_line
    local source_archive_sha input_mount_options cargo_receipt pub_receipt post_pub_receipt
    local tools_freshness_line source_authority source_writable=true
    local memory=8g memory_bytes=8589934592 result_prefix=FLUTTER_MODEL_TEST_JSON
    local expected_result='suites=23 tests=196' queue_sha256 tests_sha256
    local -a toolchain_mounts=()
    local source_mount="type=bind,source=$source_root,target=/source"
    if [ "$FLUTTER_TEST_PROFILE" = frame-queue ]; then
        memory=2g
        memory_bytes=2147483648
        result_prefix=FLUTTER_FRAME_QUEUE_TEST_JSON
        expected_result='suites=1 tests=24'
        source_mount+=,readonly
        source_writable=false
        printf 'FLUTTER_FRAME_QUEUE_STAGE=verify-source-and-inputs\n'
    else
        toolchain_mounts=(
            --mount "type=bind,source=$cargo_vendor,target=/online/cargo-vendor,readonly"
            --mount "type=bind,source=$rust_archive,target=/inputs/rust.tar.xz,readonly"
            --mount "type=bind,source=$llvm_archive,target=/inputs/llvm.tar.xz,readonly"
            --mount "type=bind,source=$cargo_config,target=/inputs/cargo-vendor-config.toml,readonly"
            --mount "type=bind,source=$frb_codegen,target=/inputs/flutter_rust_bridge_codegen,readonly"
        )
    fi

    [[ "$FLUTTER_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Flutter-test source commit is malformed'
    [[ "$FLUTTER_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Flutter-test source tree is malformed'
    [[ "$FLUTTER_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Flutter-test source archive digest is malformed'
    [ -f "$FLUTTER_SOURCE_ARCHIVE" ] && [ ! -L "$FLUTTER_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FLUTTER_SOURCE_ARCHIVE")" = \
             4000:4000:400:1 ] \
        || fail 'focused Flutter-test source archive metadata differs'
    source_archive_sha="$(sha256sum "$FLUTTER_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$FLUTTER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Flutter-test source archive digest differs'

    rm -rf -- "$source_root" "$work_root"
    mkdir "$source_root" "$work_root"
    tar -xf "$FLUTTER_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact focused Flutter-test source archive'
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'focused Flutter-test source archive differs from its guest bootstrap'
    [ -f "$source_root/scripts/verify-flutter-model-test-result.py" ] \
        && [ ! -L "$source_root/scripts/verify-flutter-model-test-result.py" ] \
        || fail 'focused Flutter-test result validator is absent or ambiguous'
    [ -f "$source_root/scripts/test-flutter-model-test-result.py" ] \
        && [ ! -L "$source_root/scripts/test-flutter-model-test-result.py" ] \
        || fail 'focused Flutter-test parser regression is absent or ambiguous'
    [ -f "$source_root/scripts/online-pub-cache-output.py" ] \
        && [ ! -L "$source_root/scripts/online-pub-cache-output.py" ] \
        || fail 'focused Flutter-test Pub-cache validator is absent or ambiguous'
    [ -f "$source_root/scripts/online-input-provenance.py" ] \
        && [ ! -L "$source_root/scripts/online-input-provenance.py" ] \
        || fail 'focused Flutter-test Cargo-vendor validator is absent or ambiguous'
    install -o 0 -g 0 -m 0444 -- \
        "$source_root/scripts/verify-flutter-model-test-result.py" \
        "$result_validator"
    install -o 0 -g 0 -m 0444 -- \
        "$source_root/scripts/online-pub-cache-output.py" "$pub_validator"
    install -o 0 -g 0 -m 0444 -- \
        "$source_root/scripts/online-input-provenance.py" "$cargo_validator"
    [ "$(stat -c '%u:%g:%a:%h' -- \
            "$result_validator" "$pub_validator" "$cargo_validator")" = \
      $'0:0:444:1\n0:0:444:1\n0:0:444:1' ] \
        || fail 'focused Flutter-test immutable validator metadata differs'
    chown -R 1000:1000 "$source_root" "$work_root"
    chmod 0700 "$work_root"

    mkdir "$inputs"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed focused-test input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed focused-test input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed focused-test inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed focused-test inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed focused-test inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed focused-test inputs permit direct execution' ;; esac

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$flutter_archive")" = \
      "1000:1000:400:1:$SIZE_FLUTTER_3_24_5" ] \
        && [ "$(sha256sum "$flutter_archive" | awk '{ print $1 }')" = \
             "$SHA256_FLUTTER_3_24_5" ] \
        || fail 'sealed Flutter 3.24.5 archive differs'
    if [ "$FLUTTER_TEST_PROFILE" = models ]; then
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$rust_archive")" = \
          "1000:1000:400:1:$SIZE_RUST_1_75" ] \
            && [ "$(sha256sum "$rust_archive" | awk '{ print $1 }')" = \
                 "$SHA256_RUST_1_75" ] \
            || fail 'sealed Rust 1.75.0 archive differs'
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$llvm_archive")" = \
          "1000:1000:400:1:$SIZE_LLVM_15_0_6" ] \
            && [ "$(sha256sum "$llvm_archive" | awk '{ print $1 }')" = \
                 "$SHA256_LLVM_15_0_6" ] \
            || fail 'sealed LLVM 15.0.6 archive differs'
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$cargo_config")" = \
          "1000:1000:400:1:$SIZE_CARGO_VENDOR_CONFIG" ] \
            && [ "$(sha256sum "$cargo_config" | awk '{ print $1 }')" = \
                 "$SHA256_CARGO_VENDOR_CONFIG" ] \
            || fail 'sealed Cargo-vendor configuration differs'
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$frb_codegen")" = \
          "1000:1000:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
            && [ "$(sha256sum "$frb_codegen" | awk '{ print $1 }')" = \
                 "$SHA256_FLUTTER_PEER_FRB_CODEGEN" ] \
            || fail 'sealed FRB generator differs'
        [ -d "$cargo_vendor" ] && [ ! -L "$cargo_vendor" ] \
            && [ "$(stat -c '%u:%g:%a' -- "$cargo_vendor")" = 1000:1000:500 ] \
            || fail 'sealed Cargo-vendor root metadata differs'
        cargo_receipt="$(
            setpriv --reuid=1000 --regid=1000 --clear-groups \
                env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
                python3 -I -S "$cargo_validator" verify-subtree \
                    --tree "$cargo_vendor" \
                    --expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"
        )" || fail 'sealed Cargo-vendor closure validation failed'
        [ "$cargo_receipt" = \
          "verified subtree $SHA256_CARGO_VENDOR_CLOSURE_V1" ] \
            || fail "sealed Cargo-vendor closure receipt differs: $cargo_receipt"
    fi
    [ -d "$pub_cache" ] && [ ! -L "$pub_cache" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$pub_cache")" = 1000:1000:500 ] \
        || fail 'sealed Pub-cache root metadata differs'
    pub_receipt="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            python3 -I -S "$pub_validator" \
                check-complete --online "$inputs" --uid 1000 --gid 1000
    )" || fail 'sealed Pub-cache closure validation failed'
    [ "$pub_receipt" = \
      "sha256=$SHA256_PUB_CACHE_CLOSURE_V1" ] \
        || fail "sealed Pub-cache closure receipt differs: $pub_receipt"
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Debian-builder image archive differs'

    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$VERIFY_REPO/scripts/offline-image-provenance.py" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role deb-builder \
                --expected-id "$DEB_BUILDER_IMAGE_ID" \
                --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
                --dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$DEB_BUILDER_CONFIG_ID" \
                --manifest-id "$DEB_BUILDER_MANIFEST_ID"
    )" || fail 'certified Debian-builder image verification/load failed'
    [ "$load_output" = "loaded and verified deb-builder $DEB_BUILDER_IMAGE_ID" ] \
        || fail "Debian-builder image receipt differs: $load_output"

    CONTAINER_ID="$(
        "$CLIENT" --host "unix://$SOCK" create \
            --name rustdesk-flutter-model-tests \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=2048 \
            --memory="$memory" \
            --memory-swap="$memory" \
            --cpus=4 \
            --shm-size=1g \
            --ulimit nofile=8192:8192 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --mount "$source_mount" \
            --mount "type=bind,source=$work_root,target=/work" \
            --mount "type=bind,source=$pub_cache,target=/online/pub-cache,readonly" \
            --mount "type=bind,source=$flutter_archive,target=/inputs/flutter.tar.xz,readonly" \
            "${toolchain_mounts[@]}" \
            --mount "type=bind,source=$result_validator,target=/authority/result.py,readonly" \
            --env "FLUTTER_TEST_PROFILE=$FLUTTER_TEST_PROFILE" \
            --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
            --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
            --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g,mode=700,uid=1000,gid=1000 \
            --workdir /source/flutter \
            "$DEB_BUILDER_CONFIG_ID" /bin/bash --noprofile --norc -euo pipefail -c '
                set -- /sys/class/net/*
                [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
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
                [ "$uid" = 1000:1000:1000:1000 ]
                [ "$gid" = 1000:1000:1000:1000 ]
                [ "$cap" = 0000000000000000 ]
                [ "$nnp" = 1 ]
                [ "$seccomp" = 2 ]
                IFS= read -r apparmor </proc/self/attr/current
                case "$apparmor" in docker-default\ *) ;; *) exit 92 ;; esac
                mkdir /work/toolchain /work/home /work/flutter-shim
                tar -C /work/toolchain -xf /inputs/flutter.tar.xz
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    mkdir /work/cargo-home
                    tar -C /work/toolchain -xf /inputs/rust.tar.xz
                    tar -C /work/toolchain -xf /inputs/llvm.tar.xz
                    rust_installer=(/work/toolchain/rust-1.*/install.sh)
                    [ "${#rust_installer[@]}" -eq 1 ] && [ -f "${rust_installer[0]}" ]
                    "${rust_installer[0]}" --prefix=/work/toolchain/rustinstall \
                        --disable-ldconfig \
                        --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview \
                        >/dev/null
                    llvm_roots=(/work/toolchain/clang+llvm-*)
                    [ "${#llvm_roots[@]}" -eq 1 ] && [ -d "${llvm_roots[0]}" ]
                    LLVM_ROOT="${llvm_roots[0]}"
                    clang_headers=("$LLVM_ROOT"/lib/clang/*/include)
                    [ "${#clang_headers[@]}" -eq 1 ] && [ -d "${clang_headers[0]}" ]
                    cp /inputs/flutter_rust_bridge_codegen \
                        /work/toolchain/flutter_rust_bridge_codegen
                    chmod 0500 /work/toolchain/flutter_rust_bridge_codegen
                    export CARGO_HOME=/work/cargo-home LIBCLANG_PATH="$LLVM_ROOT/lib"
                fi
                export HOME=/work/home
                export PUB_CACHE=/online/pub-cache CI=true
                export PUB_HOSTED_URL=https://pub.dev
                export FLUTTER_SUPPRESS_ANALYTICS=true
                export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
                export GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
                export GIT_OPTIONAL_LOCKS=0
                export PATH=/work/toolchain/flutter/bin:/work/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    export PATH=/work/toolchain/rustinstall/bin:$PATH
                fi
                [ "$(flutter --version --machine | /usr/bin/python3 -c "import json,sys; print(json.load(sys.stdin)[\"frameworkVersion\"])")" = 3.24.5 ]
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    {
                        printf "[net]\noffline = true\n"
                        sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" \
                            /inputs/cargo-vendor-config.toml
                    } >"$CARGO_HOME/config.toml"
                fi
                cp /source/scripts/flutter-offline-shim.sh /work/flutter-shim/flutter
                chmod 0500 /work/flutter-shim/flutter
                export REAL_FLUTTER=/work/toolchain/flutter/bin/flutter
                export PATH=/work/flutter-shim:$PATH
                project_root=/source/flutter
                if [ "$FLUTTER_TEST_PROFILE" = frame-queue ]; then
                    cp -a /source/flutter /work/project
                    project_root=/work/project
                fi
                cd "$project_root"
                project_lock="$(sha256sum pubspec.lock | awk "{print \$1}")"
                tools_lock="$(sha256sum /work/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")"
                if ! (cd /work/toolchain/flutter/packages/flutter_tools \
                    && dart pub get --offline --enforce-lockfile) \
                    >/work/tools-pub.out 2>/work/tools-pub.err; then
                    tail -n 120 /work/tools-pub.out /work/tools-pub.err >&2
                    exit 1
                fi
                /source/scripts/finalize-flutter-tools-offline.sh \
                    /work/toolchain/flutter \
                    "$RUSTDESK_FLUTTER_VERSION" \
                    "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256"
                if ! "$REAL_FLUTTER" config --no-analytics \
                    >/work/flutter-config.out 2>/work/flutter-config.err; then
                    tail -n 120 /work/flutter-config.out /work/flutter-config.err >&2
                    exit 1
                fi
                [ "$(stat -c %s /work/flutter-config.out)" -le 1048576 ]
                [ "$(stat -c %s /work/flutter-config.err)" -le 1048576 ]
                if ! flutter pub get --offline --enforce-lockfile \
                    >/work/project-pub.out 2>/work/project-pub.err; then
                    tail -n 120 /work/project-pub.out /work/project-pub.err >&2
                    exit 1
                fi
                [ "$tools_lock" = "$(sha256sum /work/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")" ]
                [ "$project_lock" = "$(sha256sum pubspec.lock | awk "{print \$1}")" ]
                format_status=0
                : >/work/format.diff
                format_paths=(lib/models/latest_frame_queue.dart test/latest_frame_queue_test.dart)
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    format_paths+=(
                        lib/models/android_permission_request_coordinator.dart
                        lib/models/rgba_publication_order.dart
                        lib/common/widgets/overlay.dart
                        lib/common/remote_key_routing.dart
                        lib/common/widgets/permanent_password_dialog.dart
                        lib/common/widgets/custom_password.dart
                        lib/models/reconnect_schedule_authority.dart
                        lib/mobile/pages/remote_page.dart
                        lib/mobile/pages/view_camera_page.dart
                        test/blockable_overlay_test.dart
                        test/android_permission_request_coordinator_test.dart
                        test/remote_key_routing_test.dart
                        test/permanent_password_dialog_lifecycle_test.dart
                        test/reconnect_schedule_authority_test.dart
                        test/rgba_publication_order_test.dart
                    )
                fi
                for format_path in "${format_paths[@]}"; do
                    formatted=/work/$(basename "$format_path").formatted
                    dart format --output=show "$format_path" \
                        >"$formatted" 2>>/work/format.err
                    format_summary="$(tail -n 1 "$formatted")"
                    [[ "$format_summary" =~ ^Formatted\ 1\ file\ \([01]\ changed\)\ in\ [0-9.]+\ seconds\.$ ]]
                    sed -i "\$d" "$formatted"
                    if ! diff -u "$format_path" "$formatted" \
                        >>/work/format.diff; then
                        format_status=1
                    fi
                done
                [ "$(stat -c %s /work/format.diff)" -le 1048576 ]
                [ "$(stat -c %s /work/format.err)" -le 1048576 ]
                if [ "$format_status" -ne 0 ]; then
                    cat /work/format.diff >&2
                    cat /work/format.err >&2
                    exit 1
                fi
                /usr/bin/python3 -I -S \
                    /source/scripts/verify-display-selection-finality.py --repo /source
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    codegen_log=/work/codegen.log
                    if ! (cd /source && \
                        /work/toolchain/flutter_rust_bridge_codegen \
                            --rust-input ./src/flutter_ffi.rs \
                            --dart-output ./flutter/lib/generated_bridge.dart \
                            --llvm-path "$LLVM_ROOT" \
                            --llvm-compiler-opts="-I${clang_headers[0]}") \
                        >"$codegen_log" 2>&1; then
                        tail -n 160 "$codegen_log" >&2
                        exit 1
                    fi
                    [ "$(stat -c %s "$codegen_log")" -le 1048576 ]
                    ! grep -Fq "[SEVERE]" "$codegen_log" \
                        || { tail -n 160 "$codegen_log" >&2; exit 1; }
                    for generated in \
                        /source/src/bridge_generated.rs \
                        /source/src/bridge_generated.io.rs \
                        /source/flutter/lib/generated_bridge.dart \
                        /source/flutter/lib/generated_bridge.freezed.dart; do
                        [ -s "$generated" ] && [ ! -L "$generated" ]
                    done
                    sed -i "s/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g" \
                        /source/flutter/lib/generated_bridge.dart
                fi
                [ "$project_lock" = "$(sha256sum pubspec.lock | awk "{print \$1}")" ]
                tests=(test/latest_frame_queue_test.dart)
                test_budget=90s
                if [ "$FLUTTER_TEST_PROFILE" = models ]; then
                    tests=(
                        test/global_event_dispatcher_test.dart
                        test/server_status_refresh_loop_test.dart
                        test/server_model_test.dart
                        test/display_selection_queue_test.dart
                        test/file_command_session_ownership_test.dart
                        test/file_dialog_event_loop_test.dart
                        test/mobile_file_session_lifecycle_test.dart
                        test/session_event_queue_test.dart
                        test/latest_frame_queue_test.dart
                        test/session_stream_finality_test.dart
                        test/mobile_session_start_queue_test.dart
                        test/desktop_texture_lifecycle_test.dart
                        test/desktop_tab_retirement_test.dart
                        test/presentation_recovery_test.dart
                        test/reconnect_schedule_authority_test.dart
                        test/rgba_publication_order_test.dart
                        test/owned_image_paint_test.dart
                        test/blockable_overlay_test.dart
                        test/custom_cursor_registry_test.dart
                        test/start_ellipsis_text_test.dart
                        test/permanent_password_dialog_lifecycle_test.dart
                        test/android_permission_request_coordinator_test.dart
                        test/remote_key_routing_test.dart
                    )
                    [ "${#tests[@]}" -eq 23 ]
                    test_budget=900s
                fi
                for test_path in "${tests[@]}"; do
                    [ -f "$test_path" ] && [ ! -L "$test_path" ]
                done
                if ! timeout --signal=TERM --kill-after=10s "$test_budget" \
                    flutter test --no-pub --reporter json --concurrency=4 \
                        --timeout=30s \
                        "${tests[@]}" >/work/test.json 2>/work/test.err; then
                    tail -c 4194304 /work/test.json >&2
                    tail -c 1048576 /work/test.err >&2
                    exit 1
                fi
                [ "$(stat -c %s /work/test.err)" -le 1048576 ]
                [ ! -s /work/test.err ] || tail -n 120 /work/test.err >&2
                /usr/bin/python3 -I -S /source/scripts/test-flutter-model-test-result.py
                printf "FLUTTER_TEST_RESULT_PARSER=pass tests=3\n"
                /usr/bin/python3 -I -S /authority/result.py \
                    /work/test.json --profile "$FLUTTER_TEST_PROFILE"
                if [ "$FLUTTER_TEST_PROFILE" = frame-queue ]; then
                    cmp /source/flutter/lib/models/latest_frame_queue.dart lib/models/latest_frame_queue.dart
                    cmp /source/flutter/test/latest_frame_queue_test.dart test/latest_frame_queue_test.dart
                    [ ! -e /work/toolchain/rustinstall ]
                    [ ! -e /work/toolchain/flutter_rust_bridge_codegen ]
                    [ ! -e /inputs/rust.tar.xz ]
                    [ ! -e /inputs/llvm.tar.xz ]
                    [ ! -e /online/cargo-vendor ]
                    [ ! -e lib/generated_bridge.dart ]
                fi
            '
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Flutter-test container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      "none|true|1000:1000|$memory_bytes|$memory_bytes|4000000000|2048|1073741824|[\"ALL\"]|[\"no-new-privileges\",\"apparmor=docker-default\"]" ] \
        || fail "focused Flutter-test container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "focused Flutter-test container namespace/device/port authority differs: $namespace_inspect"
    source_authority="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{range .Mounts}}{{if eq .Destination "/source"}}{{.Source}}|{{.Type}}|{{.RW}}{{end}}{{end}}' \
        "$CONTAINER_ID")"
    [ "$source_authority" = "$source_root|bind|$source_writable" ] \
        || fail 'focused Flutter-test source mount authority differs'
    if [ "$FLUTTER_TEST_PROFILE" = frame-queue ]; then
        printf 'FLUTTER_FRAME_QUEUE_STAGE=run-production-queue-tests\n'
    fi
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -c 6291456 "$output" >&2; fail "focused Flutter model tests exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || fail 'focused Flutter-test output exceeds its bound'
    tools_freshness_line="$(grep -Fx \
        "FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=$FLUTTER_VERSION lock=$SHA256_FLUTTER_TOOLS_LOCK implicit_pub=prevented" \
        "$output")" \
        || { tail -n 240 "$output" >&2; fail 'Flutter-tools offline-freshness receipt is absent'; }
    [ "$(grep -Fc 'FLUTTER_TOOLS_OFFLINE_FRESHNESS=' "$output")" -eq 1 ] \
        || fail 'Flutter-tools offline-freshness receipt is duplicated'
    [ "$(grep -Fxc 'FLUTTER_TEST_RESULT_PARSER=pass tests=3' "$output")" -eq 1 ] \
        || fail 'Flutter-test result parser regression receipt differs'
    result_line="$(grep -Fx "$result_prefix=pass $expected_result" "$output")" \
        || { tail -n 240 "$output" >&2; fail 'focused Flutter-test success summary is absent'; }
    [ "$(grep -Fc "$result_prefix=" "$output")" -eq 1 ] \
        || fail 'focused Flutter-test result summary is duplicated'
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused Flutter-test container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$DEB_BUILDER_CONFIG_ID" >/dev/null
    [ "$(sha256sum "$FLUTTER_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'focused Flutter-test source archive changed during execution'
    post_pub_receipt="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
            python3 -I -S "$pub_validator" \
                check-complete --online "$inputs" --uid 1000 --gid 1000
    )" || fail 'sealed Pub-cache postcondition validation failed'
    [ "$post_pub_receipt" = "$pub_receipt" ] \
        || fail 'sealed Pub-cache closure changed during execution'
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire the sealed focused-test input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$tools_freshness_line"
    printf 'FLUTTER_TEST_RESULT_PARSER=pass tests=3\n'
    printf '%s\n' "$result_line"
    if [ "$FLUTTER_TEST_PROFILE" = frame-queue ]; then
        queue_sha256="$(sha256sum "$source_root/flutter/lib/models/latest_frame_queue.dart" | awk '{print $1}')"
        tests_sha256="$(sha256sum "$source_root/flutter/test/latest_frame_queue_test.dart" | awk '{print $1}')"
        printf 'FLUTTER_FRAME_QUEUE_TESTS_VM=pass commit=%s tree=%s suites=1 tests=24 flutter=3.24.5 queue=%s tests_source=%s pub_cache=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none source=readonly root=readonly caps=none nnp=on apparmor=docker-default evidence=production-dart-queue-tests cleanup=joined\n' \
            "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" \
            "$queue_sha256" "$tests_sha256" "$SHA256_PUB_CACHE_CLOSURE_V1" \
            "$DEB_BUILDER_IMAGE_ID" "$DEB_BUILDER_CONFIG_ID"
    else
        printf 'FLUTTER_MODEL_TESTS_VM=pass commit=%s tree=%s suites=23 tests=196 flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=%s cargo_vendor=%s pub_cache=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default evidence=generated-bridge-model-tests cleanup=joined\n' \
            "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" \
            "$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
            "$SHA256_PUB_CACHE_CLOSURE_V1" \
            "$DEB_BUILDER_IMAGE_ID" "$DEB_BUILDER_CONFIG_ID"
    fi
}

run_flutter_peer_presentation() {
    local sealed_root=/mnt/rustdesk-sealed-inputs
    local candidate_root=/mnt/rustdesk-flutter-candidate-input
    local failure_root=/mnt/rustdesk-flutter-peer-failure
    local app_output=/mnt/rustdesk-linux-flutter-app-output
    local app_input=/mnt/rustdesk-linux-flutter-app-input
    local engine_input=/mnt/rustdesk-linux-flutter-engine-input
    local inputs=$sealed_root
    local source_root=$ROOT/flutter-peer-source
    local peer_script=$source_root/scripts/smoke-flutter-peer-presentation.sh
    local provenance=$source_root/scripts/offline-image-provenance.py
    local devcheck_archive= builder_archive= candidate_archive=
    local output=$ROOT/flutter-peer-presentation.out
    local source_archive_sha load_output mount_options peer_status=0 trace_abort
    local -a peer_args=()
    local -a peer_environment=()

    [[ "$FLUTTER_PEER_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$FLUTTER_PEER_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Flutter-peer source identity is malformed'
    [ -f "$FLUTTER_PEER_SOURCE_ARCHIVE" ] && [ ! -L "$FLUTTER_PEER_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$FLUTTER_PEER_SOURCE_ARCHIVE")" = \
             1000:1000:400:1 ] \
        || fail 'focused Flutter-peer source archive metadata differs'
    source_archive_sha="$(sha256sum "$FLUTTER_PEER_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Flutter-peer source archive digest differs'

    mkdir "$sealed_root"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$sealed_root" \
        || fail 'cannot mount the sealed Flutter-peer input authority'
    SEALED_INPUTS_MOUNTED=1
    mount_options="$(findmnt -n -o OPTIONS --target "$sealed_root")" \
        || fail 'sealed Flutter-peer input mount is absent'
    case ",$mount_options," in *,ro,*) ;; *) fail 'sealed Flutter-peer inputs are writable' ;; esac
    case ",$mount_options," in *,nodev,*) ;; *) fail 'sealed Flutter-peer inputs permit devices' ;; esac
    case ",$mount_options," in *,nosuid,*) ;; *) fail 'sealed Flutter-peer inputs permit set-user-ID execution' ;; esac
    case ",$mount_options," in *,noexec,*) ;; *) fail 'sealed Flutter-peer inputs permit direct execution' ;; esac

    [ "$(stat -c '%u:%g:%a' -- "$sealed_root")" = 1000:1000:700 ] \
        || fail 'sealed Flutter-peer authority root metadata differs'
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        mkdir "$engine_input"
        mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-linux-flutter-engine-input "$engine_input" \
            || fail 'cannot mount the selected inert Flutter engine capsule'
        ENGINE_INPUT_MOUNTS+=("$engine_input")
        mount_options="$(findmnt -n -o OPTIONS --target "$engine_input")"
        for option in ro nodev nosuid noexec; do
            case ",$mount_options," in *,$option,*) ;; *) fail "Flutter engine input lacks $option" ;; esac
        done
        [ "$(stat -c '%u:%g:%a' -- "$engine_input")" = 1000:1000:700 ] \
            || fail 'selected Flutter engine capsule owner/mode differs'
        mkdir "$app_output"
        mount -t virtiofs -o rw,nodev,nosuid,noexec rustdesk-linux-flutter-app-output "$app_output" \
            || fail 'cannot mount the inert Linux Flutter app output authority'
        FLUTTER_APP_OUTPUT_MOUNTED=1
        mount_options="$(findmnt -n -o OPTIONS --target "$app_output")"
        for option in rw nodev nosuid noexec; do
            case ",$mount_options," in *,$option,*) ;; *) fail "Linux Flutter app output lacks $option" ;; esac
        done
        [ "$(stat -c '%u:%g:%a' -- "$app_output")" = 1000:1000:700 ] \
            && [ -z "$(find "$app_output" -mindepth 1 -print -quit)" ] \
            || fail 'Linux Flutter app output authority metadata differs'
    else
    mkdir "$app_input"
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-linux-flutter-app-input "$app_input" \
        || fail 'cannot mount the inert Linux Flutter app input authority'
    FLUTTER_APP_INPUT_MOUNTED=1
    mount_options="$(findmnt -n -o OPTIONS --target "$app_input")"
    for option in ro nodev nosuid noexec; do
        case ",$mount_options," in *,$option,*) ;; *) fail "Linux Flutter app input lacks $option" ;; esac
    done
    [ "$(stat -c '%u:%g:%a' -- "$app_input")" = 1000:1000:700 ] \
        && [ "$(find "$app_input" -mindepth 1 -maxdepth 1 -printf '%f\n')" = linux-x86_64-flutter-app ] \
        || fail 'Linux Flutter app input parent authority differs'
    mkdir "$failure_root"
    mount -t virtiofs -o rw,nodev,nosuid,noexec \
        rustdesk-flutter-failure-output "$failure_root" \
        || fail 'cannot mount the bounded Flutter peer failure-output authority'
    FLUTTER_PEER_FAILURE_MOUNTED=1
    mount_options="$(findmnt -n -o OPTIONS --target "$failure_root")" \
        || fail 'Flutter peer failure-output mount is absent'
    case ",$mount_options," in *,rw,*) ;; *) fail 'Flutter peer failure-output authority is not writable' ;; esac
    case ",$mount_options," in *,nodev,*) ;; *) fail 'Flutter peer failure-output authority permits devices' ;; esac
    case ",$mount_options," in *,nosuid,*) ;; *) fail 'Flutter peer failure-output authority permits set-user-ID execution' ;; esac
    case ",$mount_options," in *,noexec,*) ;; *) fail 'Flutter peer failure-output authority permits direct execution' ;; esac
    [ "$(stat -c '%u:%g:%a' -- "$failure_root")" = 1000:1000:700 ] \
        && [ -z "$(find "$failure_root" -mindepth 1 -print -quit)" ] \
        || fail 'Flutter peer failure-output authority metadata differs'
    printf '/diagnostic/core.%%p\n' > /proc/sys/kernel/core_pattern \
        || fail 'cannot establish the VM-local bounded Flutter core pattern'
    [ "$(cat /proc/sys/kernel/core_pattern)" = '/diagnostic/core.%p' ] \
        || fail 'VM-local Flutter core pattern differs'
    peer_environment=("RUSTDESK_FAILURE_ARTIFACT_DIR=$failure_root")
    fi
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        mkdir "$candidate_root"
        mount -t virtiofs -o ro,nodev,nosuid,noexec \
            rustdesk-flutter-candidate-input "$candidate_root" \
            || fail 'cannot mount the sealed Flutter candidate authority'
        FLUTTER_PEER_CANDIDATE_MOUNTED=1
        mount_options="$(findmnt -n -o OPTIONS --target "$candidate_root")" \
            || fail 'sealed Flutter candidate mount is absent'
        case ",$mount_options," in *,ro,*) ;; *) fail 'sealed Flutter candidate is writable' ;; esac
        case ",$mount_options," in *,nodev,*) ;; *) fail 'sealed Flutter candidate permits devices' ;; esac
        case ",$mount_options," in *,nosuid,*) ;; *) fail 'sealed Flutter candidate permits set-user-ID execution' ;; esac
        case ",$mount_options," in *,noexec,*) ;; *) fail 'sealed Flutter candidate permits direct execution' ;; esac
        [ "$(stat -c '%u:%g:%a' -- "$candidate_root")" = 1000:1000:700 ] \
            && [ "$(find "$candidate_root" -mindepth 1 -maxdepth 1 \
                -printf '%f\n' | LC_ALL=C sort)" = \
                 $'flutter-'"${FLUTTER_PRESENTATION_CANDIDATE_VERSION}"$'.tar.xz\npub-cache\npubspec.lock.discovery' ] \
            || fail 'candidate Flutter-peer closure namespace differs'
        candidate_archive="$candidate_root/flutter-${FLUTTER_PRESENTATION_CANDIDATE_VERSION}.tar.xz"
        candidate_lock="$candidate_root/pubspec.lock.discovery"
        candidate_pub_cache="$candidate_root/pub-cache"
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$candidate_archive")" = \
          "1000:1000:400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ] \
            && [ "$(sha256sum "$candidate_archive" | awk '{ print $1 }')" = \
                 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" ] \
            || fail 'candidate Flutter SDK archive differs'
        [ -f "$candidate_lock" ] && [ ! -L "$candidate_lock" ] \
            && [ "$(stat -c '%u:%g:%a:%h' -- "$candidate_lock")" = \
                 1000:1000:400:1 ] \
            && [ "$(sha256sum "$candidate_lock" | awk '{ print $1 }')" = \
                 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK" ] \
            || fail 'candidate Flutter project lock differs'
        [ -d "$candidate_pub_cache" ] && [ ! -L "$candidate_pub_cache" ] \
            && [ "$(stat -c '%u:%g:%a' -- "$candidate_pub_cache")" = \
                 1000:1000:500 ] \
            || fail 'candidate Flutter Pub cache metadata differs'
    fi
    devcheck_archive=$inputs/verifier-images/devcheck.docker.tar.gz
    builder_archive=$inputs/build-images/deb-builder.docker.tar.gz

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$devcheck_archive")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$devcheck_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed devcheck image archive differs'
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Debian-builder image archive differs'
    fi

    mkdir "$source_root"
    tar -xf "$FLUTTER_PEER_SOURCE_ARCHIVE" --no-same-owner -C "$source_root" \
        || fail 'cannot extract the exact Flutter-peer source archive'
    chown -R 1000:1000 "$source_root"
    chmod -R go-w "$source_root"
    [ -z "$(find "$source_root" -xdev ! -type l \
        \( -perm /022 -o -perm /6000 \) -print -quit)" ] \
        || fail 'exact Flutter-peer source has unsafe writable or special-bit metadata'
    install -d -m 0755 -o 1000 -g 1000 "$source_root/online/inputs"
    [ -f "$peer_script" ] && [ ! -L "$peer_script" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$peer_script")" = 1000:1000:755:1 ] \
        || fail 'exact Flutter-peer entry is absent or ambiguous'
    [ -f "$provenance" ] && [ ! -L "$provenance" ] \
        || fail 'exact offline-image verifier is absent or ambiguous'

    mount --bind "$source_root" "$source_root" \
        || fail 'cannot bind the exact Flutter-peer source read-only'
    mount -o remount,bind,ro,nodev,nosuid,noexec "$source_root" \
        || fail 'cannot seal the exact Flutter-peer source mount'
    FLUTTER_PEER_SOURCE_MOUNTED=1
    mount --bind "$inputs" "$source_root/online/inputs" \
        || fail 'cannot project sealed Flutter-peer inputs into the exact source'
    mount -o remount,bind,ro,nodev,nosuid,noexec "$source_root/online/inputs" \
        || fail 'cannot seal the Flutter-peer input projection'
    FLUTTER_PEER_ONLINE_MOUNTED=1
    case ",$(findmnt -n -o OPTIONS --target "$source_root")," in
        *,ro,*) ;;
        *) fail 'exact Flutter-peer source remains writable' ;;
    esac
    case ",$(findmnt -n -o OPTIONS --target "$source_root/online/inputs")," in
        *,ro,*) ;;
        *) fail 'Flutter-peer input projection remains writable' ;;
    esac
    cmp -s "$peer_script" "$FLUTTER_PEER_SCRIPT" \
        || fail 'sealed and exact-source Flutter-peer entries differ'

    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$provenance" verify-load \
                --archive "$devcheck_archive" \
                --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
                --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
                --role devcheck \
                --expected-id "$DEV_CHECK_IMAGE_ID" \
                --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
                --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
                --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
                --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
                --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
                --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
                --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH" \
                --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
                --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
    )" || fail 'devcheck archive verification/load failed'
    [ "$load_output" = "loaded and verified devcheck $DEV_CHECK_IMAGE_ID" ] \
        || fail "devcheck archive verification/load receipt differs: $load_output"

    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
    load_output="$(
        setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            DOCKER_HOST="unix://$SOCK" DOCKER_CONFIG="$CONFIG_ROOT" \
            python3 -I -S "$provenance" verify-load \
                --archive "$builder_archive" \
                --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
                --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
                --role deb-builder \
                --expected-id "$DEB_BUILDER_IMAGE_ID" \
                --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
                --dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
                --recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
                --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
                --bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
                --bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID" \
                --source-date-epoch "$SOURCE_DATE_EPOCH_PIN" \
                --config-id "$DEB_BUILDER_CONFIG_ID" \
                --manifest-id "$DEB_BUILDER_MANIFEST_ID"
    )" || fail 'certified Debian-builder image verification/load failed'
    [ "$load_output" = "loaded and verified deb-builder $DEB_BUILDER_IMAGE_ID" ] \
        || fail "Debian-builder image receipt differs: $load_output"
    fi

    if /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
        >"$ROOT/flutter-peer-root.out" 2>"$ROOT/flutter-peer-root.err"; then
        fail 'VM root passed the Flutter full-peer workload entry'
    fi
    [ ! -s "$ROOT/flutter-peer-root.out" ] \
        && [ "$(<"$ROOT/flutter-peer-root.err")" = \
          'flutter peer presentation smoke refuses host or container-root execution' ] \
        || fail 'root Flutter full-peer workload refusal differs'
    if setpriv --reuid=4001 --regid=4001 --clear-groups \
        /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
        >"$ROOT/flutter-peer-foreign.out" 2>"$ROOT/flutter-peer-foreign.err"; then
        fail 'foreign principal passed the Flutter full-peer workload entry'
    fi
    [ ! -s "$ROOT/flutter-peer-foreign.out" ] \
        && [ "$(<"$ROOT/flutter-peer-foreign.err")" = \
          'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
        || fail 'foreign Flutter full-peer workload refusal differs'
    if setpriv --reuid=1000 --regid=1000 --clear-groups \
        env DOCKER_HOST=unix:///tmp/forbidden-docker.sock \
        /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
        >"$ROOT/flutter-peer-caller.out" 2>"$ROOT/flutter-peer-caller.err"; then
        fail 'caller Docker authority passed the Flutter full-peer workload entry'
    fi
    [ ! -s "$ROOT/flutter-peer-caller.out" ] \
        && [ "$(<"$ROOT/flutter-peer-caller.err")" = \
          'FATAL: caller DOCKER_HOST authority is forbidden' ] \
        || fail 'caller-authority Flutter full-peer workload refusal differs'

    peer_args=(
        --source-archive "$FLUTTER_PEER_SOURCE_ARCHIVE"
        --commit "$FLUTTER_PEER_SOURCE_COMMIT"
        --tree "$FLUTTER_PEER_SOURCE_TREE"
        --archive-sha256 "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256"
    )
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        peer_args+=(--flutter-presentation-candidate "$candidate_archive")
    fi
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        peer_args+=(--build-app "$FLUTTER_APP_BUILD_CONTEXT")
    else
        peer_args+=(--replay-app "$FLUTTER_APP_BUILD_CONTEXT" \
            --app-commit "$FLUTTER_APP_COMMIT" --app-tree "$FLUTTER_APP_TREE" \
            --app-recipe-sha256 "$FLUTTER_APP_RECIPE_SHA256" \
            --app-manifest-sha256 "$FLUTTER_APP_MANIFEST_SHA256")
    fi
    peer_args+=(--engine-context "$FLUTTER_APP_ENGINE_CONTEXT")
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        "${peer_environment[@]}" \
        /bin/bash "$peer_script" "${peer_args[@]}" \
        2>&1 | tee "$output"
    peer_status=${PIPESTATUS[0]}
    set -e
    [ "$peer_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "Flutter full-peer workload exited with status $peer_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 8388608 ] \
        || fail 'Flutter full-peer workload output exceeds its bound'
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        local recipe_sha
        recipe_sha="$(sha256sum "$source_root/scripts/smoke-flutter-peer-presentation-stage.sh" | awk '{print $1}')"
        [ "$(grep -Ec "^LINUX_FLUTTER_APP_PREPARED=pass commit=$FLUTTER_PEER_SOURCE_COMMIT tree=$FLUTTER_PEER_SOURCE_TREE pending=[.]linux-flutter-pending-[0-9a-f]{64} manifest_sha256=[0-9a-f]{64} recipe_sha256=$recipe_sha epoch=$SOURCE_DATE_EPOCH_PIN drivers=excluded network=none containers=joined$" "$output")" -eq 1 ] \
            || fail 'actual Linux Flutter app preparation receipt is absent or duplicated'
    else
    [ "$(grep -Fxc "LINUX_FLUTTER_APP_ADMITTED=pass harness_commit=$FLUTTER_PEER_SOURCE_COMMIT app_commit=$FLUTTER_APP_COMMIT app_tree=$FLUTTER_APP_TREE manifest_sha256=$FLUTTER_APP_MANIFEST_SHA256 execution=vm-private build=absent" "$output")" -eq 1 ] \
        && [ "$(grep -Fxc 'LINUX_FLUTTER_DRIVERS_COMPILED=pass files=3 builds=2 equality=bytes app=unbuilt' "$output")" -eq 1 ] \
        || fail 'Linux replay app admission or native driver compilation receipt differs'
    if grep -Eq '^LINUX_FLUTTER_APP_COMPILED=|^FLUTTER_PEER_BUILD_PHASE=' "$output"; then
        fail 'Linux replay unexpectedly built an app'
    fi
    [ "$(grep -Fxc \
      "FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=$FLUTTER_PEER_SOURCE_COMMIT tree=$FLUTTER_PEER_SOURCE_TREE archive_sha256=$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256 flutter=$FLUTTER_PEER_RUNTIME_VERSION tools=$FLUTTER_PEER_TOOLS_MODE scope=linux-x11-full-peer-focus-reconnect-resource network=owned-none-namespace app_commit=$FLUTTER_APP_COMMIT app_tree=$FLUTTER_APP_TREE manifest_sha256=$FLUTTER_APP_MANIFEST_SHA256 build=absent" \
      "$output")" -eq 1 ] \
        || fail 'Flutter full-peer product verdict is absent or duplicated'
    [ "$(grep -Fxc 'FLUTTER_PEER_RUNTIME_CYCLES_OK cycles=6 instrumentation=none' "$output")" -eq 1 ] \
        || fail 'Flutter full-peer repeated lifecycle verdict is absent or duplicated'
    for cycle in 1 2 3 4 5 6; do
        [ "$(grep -Fxc \
          "FLUTTER_PEER_RUNTIME_CYCLE_OK cycle=$cycle instrumentation=none viewer=joined server=joined" \
          "$output")" -eq 1 ] \
            || fail "Flutter full-peer lifecycle cycle $cycle is absent or duplicated"
    done
    fi
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'Flutter full-peer workload left a container'
    local -a retired_images=("$DEV_CHECK_IMAGE_CONFIG_ID")
    [ "$FLUTTER_APP_BUILD_ONLY" -eq 0 ] || retired_images+=("$DEB_BUILDER_CONFIG_ID")
    "$CLIENT" --host "unix://$SOCK" image rm "${retired_images[@]}" >/dev/null \
        || fail 'Flutter full-peer images could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Flutter full-peer workload left an image'
    [ "$(sha256sum "$FLUTTER_PEER_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'focused Flutter-peer source archive changed during execution'
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        [ "$(stat -c '%u:%g:%a:%h:%s' -- "$candidate_archive")" = \
          "1000:1000:400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ] \
            && [ "$(sha256sum "$candidate_archive" | awk '{ print $1 }')" = \
                 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" ] \
            || fail 'candidate Flutter SDK archive changed during execution'
        [ "$(stat -c '%u:%g:%a:%h' -- "$candidate_lock")" = 1000:1000:400:1 ] \
            && [ "$(sha256sum "$candidate_lock" | awk '{ print $1 }')" = \
                 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK" ] \
            && [ "$(stat -c '%u:%g:%a' -- "$candidate_pub_cache")" = \
                 1000:1000:500 ] \
            || fail 'candidate Flutter dependency closure changed during execution'
    fi

    stop_docker_authority
    umount "$source_root/online/inputs" \
        || fail 'cannot retire the Flutter-peer input projection'
    FLUTTER_PEER_ONLINE_MOUNTED=0
    umount "$source_root" || fail 'cannot retire the read-only Flutter-peer source mount'
    FLUTTER_PEER_SOURCE_MOUNTED=0
    if [ "$FLUTTER_PEER_CANDIDATE_MOUNTED" -eq 1 ]; then
        umount "$candidate_root" || fail 'cannot retire the sealed Flutter candidate mount'
        FLUTTER_PEER_CANDIDATE_MOUNTED=0
    fi
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        umount "$engine_input" || fail 'cannot retire the selected inert engine mount'
        ENGINE_INPUT_MOUNTS=()
        umount "$app_output" || fail 'cannot retire the inert Linux Flutter app output mount'
        FLUTTER_APP_OUTPUT_MOUNTED=0
    else
        umount "$app_input" || fail 'cannot retire the inert Linux Flutter app input mount'
        FLUTTER_APP_INPUT_MOUNTED=0
        umount "$failure_root" || fail 'cannot retire the Flutter peer failure-output mount'
        FLUTTER_PEER_FAILURE_MOUNTED=0
    fi
    umount "$sealed_root" || fail 'cannot retire the sealed Flutter-peer input mount'
    SEALED_INPUTS_MOUNTED=0
    if [ "$FLUTTER_APP_BUILD_ONLY" -eq 1 ]; then
        printf 'LINUX_FLUTTER_APP_BUILD_VM=pass commit=%s tree=%s archive=%s flutter=%s epoch=%s builder=%s root=refused foreign=refused caller=refused network=none inputs=readonly-landlocked drivers=excluded cleanup=joined\n' \
            "$FLUTTER_PEER_SOURCE_COMMIT" "$FLUTTER_PEER_SOURCE_TREE" "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" \
            "$FLUTTER_PEER_RUNTIME_VERSION" "$SOURCE_DATE_EPOCH_PIN" "$DEB_BUILDER_CONFIG_ID"
    else
    printf 'LINUX_FLUTTER_APP_REPLAY_VM=pass harness_commit=%s harness_tree=%s archive=%s app_commit=%s app_tree=%s manifest_sha256=%s driver_runtime=%s uid=1000 gid=1000 root=refused foreign=refused caller=refused vm_network=none container_network=owned-none-namespace artifact=readonly-landlocked build=absent cleanup=joined\n' \
        "$FLUTTER_PEER_SOURCE_COMMIT" "$FLUTTER_PEER_SOURCE_TREE" "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" \
        "$FLUTTER_APP_COMMIT" "$FLUTTER_APP_TREE" "$FLUTTER_APP_MANIFEST_SHA256" "$DEV_CHECK_IMAGE_CONFIG_ID"
    fi
}

cleanup() {
    local status=$? daemon_status=0
    trap - EXIT HUP INT TERM
    if [ "$ENGINE_OUTPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-flutter-engine-output 2>/dev/null || status=1
        ENGINE_OUTPUT_MOUNTED=0
    fi
    if [ "$LIFECYCLE_LIBS_MOUNTED" -eq 1 ]; then
        umount /var/tmp/rustdesk-systemd-lifecycle/runtime-libs 2>/dev/null \
            || status=1
        LIFECYCLE_LIBS_MOUNTED=0
    fi
    if [ -n "$CONTAINER_ID" ] && [ -x "$CLIENT" ]; then
        "$CLIENT" --host "unix://$SOCK" rm -f "$CONTAINER_ID" >/dev/null 2>&1 \
            || status=1
        CONTAINER_ID=
    fi
    if [ -n "$DAEMON_PID" ]; then
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -TERM "$DAEMON_PID" 2>/dev/null || daemon_status=1
        fi
        wait "$DAEMON_PID" 2>/dev/null || daemon_status=$?
        [ "$daemon_status" -eq 0 ] || [ "$daemon_status" -eq 143 ] || status=1
        DAEMON_PID=
    fi
    if [ "$FLUTTER_PEER_ONLINE_MOUNTED" -eq 1 ]; then
        umount "$ROOT/flutter-peer-source/online/inputs" 2>/dev/null || status=1
        FLUTTER_PEER_ONLINE_MOUNTED=0
    fi
    if [ "$FLUTTER_PEER_SOURCE_MOUNTED" -eq 1 ]; then
        umount "$ROOT/flutter-peer-source" 2>/dev/null || status=1
        FLUTTER_PEER_SOURCE_MOUNTED=0
    fi
    if [ "$FLUTTER_PEER_CANDIDATE_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-flutter-candidate-input 2>/dev/null || status=1
        FLUTTER_PEER_CANDIDATE_MOUNTED=0
    fi
    if [ "$FLUTTER_PEER_FAILURE_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-flutter-peer-failure 2>/dev/null || status=1
        FLUTTER_PEER_FAILURE_MOUNTED=0
    fi
    if [ "$FLUTTER_APP_OUTPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-linux-flutter-app-output 2>/dev/null || status=1
        FLUTTER_APP_OUTPUT_MOUNTED=0
    fi
    if [ "$FLUTTER_APP_INPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-linux-flutter-app-input 2>/dev/null || status=1
        FLUTTER_APP_INPUT_MOUNTED=0
    fi
    if [ "$RUST_AUDIT_VENDOR_MOUNTED" -eq 1 ]; then
        umount "$ROOT/rust-audit-source/online/cargo-vendor" 2>/dev/null || status=1
        RUST_AUDIT_VENDOR_MOUNTED=0
    fi
    if [ "$APPLE_VENDOR_MOUNTED" -eq 1 ]; then
        umount "$ROOT/apple-conform-source/online/cargo-vendor" 2>/dev/null || status=1
        APPLE_VENDOR_MOUNTED=0
    fi
    if [ "$ANDROID_RUST_ONLINE_MOUNTED" -eq 1 ]; then
        umount "$ROOT/android-rust-target-source/online/inputs" 2>/dev/null || status=1
        ANDROID_RUST_ONLINE_MOUNTED=0
    fi
    if [ "$ANDROID_EMULATOR_ONLINE_MOUNTED" -eq 1 ]; then
        umount "$ROOT/android-emulator-app-source/online" 2>/dev/null || status=1
        ANDROID_EMULATOR_ONLINE_MOUNTED=0
    fi
    if [ "$ANDROID_EMULATOR_RUNTIME_ONLINE_MOUNTED" -eq 1 ]; then
        umount "$ROOT/android-emulator-runtime-source/online" 2>/dev/null || status=1
        ANDROID_EMULATOR_RUNTIME_ONLINE_MOUNTED=0
    fi
    if [ "$ANDROID_ARTIFACT_OUTPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-android-artifact-output 2>/dev/null || status=1
        ANDROID_ARTIFACT_OUTPUT_MOUNTED=0
    fi
    if [ "$ANDROID_ARTIFACT_INPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-android-artifact-input 2>/dev/null || status=1
        ANDROID_ARTIFACT_INPUT_MOUNTED=0
    fi
    if [ "$ANDROID_PEER_ARTIFACT_INPUT_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-android-peer-artifact-input 2>/dev/null || status=1
        ANDROID_PEER_ARTIFACT_INPUT_MOUNTED=0
    fi
    if [ "$ANDROID_RUNTIME_FAILURE_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-android-runtime-failure 2>/dev/null || status=1
        ANDROID_RUNTIME_FAILURE_MOUNTED=0
    fi
    if [ "$SEALED_INPUTS_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-sealed-inputs 2>/dev/null || status=1
        SEALED_INPUTS_MOUNTED=0
    fi
    for engine_mount in "${ENGINE_INPUT_MOUNTS[@]}"; do
        umount "$engine_mount" 2>/dev/null || status=1
    done
    ENGINE_INPUT_MOUNTS=()
    if [ "$status" -ne 0 ] && [ -f "$LOG" ]; then
        tail -n 160 "$LOG" >&2 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || fail 'guest authority probe must run as VM-local root'
[ "$(id -g)" = 0 ] || fail 'guest authority probe must have a VM-local root primary group'
ulimit -Hn "$VERIFIER_VM_NOFILE_LIMIT" \
    || fail 'verifier descriptor hard limit cannot be established'
ulimit -Sn "$VERIFIER_VM_NOFILE_LIMIT" \
    || fail 'verifier descriptor soft limit cannot be established'
[ "$(ulimit -Sn):$(ulimit -Hn)" = \
  "$VERIFIER_VM_NOFILE_LIMIT:$VERIFIER_VM_NOFILE_LIMIT" ] \
    || fail 'verifier descriptor limit differs'
[ "$(cat /proc/1/comm)" = systemd ] || fail 'guest PID 1 is not systemd'
[ -r /etc/os-release ] || fail 'guest OS identity is absent'
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail 'guest is not the pinned Debian bookworm base'
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail 'Docker version pin is malformed'
case "$EXPECTED_SIZE" in 0|*[!0-9]*|'') fail 'Docker size pin is malformed' ;; esac
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'Docker digest pin is malformed'
[[ "$EXPECTED_KERNEL_RELEASE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-cloud-amd64$ ]] \
    || fail 'kernel-release pin is malformed'
[[ "$EXPECTED_ROOT_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || fail 'root-filesystem UUID pin is malformed'
[ "$(uname -r)" = "$EXPECTED_KERNEL_RELEASE" ] \
    || fail 'running guest kernel release differs'
expected_cmdline="root=UUID=$EXPECTED_ROOT_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.verifier_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=ssh.service systemd.mask=ssh.socket"
[ "$(< /proc/cmdline)" = "$expected_cmdline" ] \
    || fail 'running guest kernel command line differs'
for masked_unit in systemd-networkd-wait-online.service ssh.service ssh.socket; do
    mask="/run/systemd/generator.early/$masked_unit"
    [ -L "$mask" ] && [ "$(readlink -- "$mask")" = /dev/null ] \
        || fail "runtime boot mask is absent: $masked_unit"
done
[ -f "$DOCKER_ARCHIVE" ] && [ ! -L "$DOCKER_ARCHIVE" ] \
    || fail 'Docker bundle is not one regular payload file'
[ -f "$ENTRY_PREFLIGHT" ] && [ ! -L "$ENTRY_PREFLIGHT" ] \
    || fail 'verifier-entry preflight is not one regular payload file'
for verify_source in verify.sh cleanup.sh verify-cleanup-authority.py \
    verify-release.sh build-release.sh \
    publish-github-release.sh finalize-release-set.py \
    verify-release-workspace-runtime.sh apple-conform-check.sh \
    apple-toolchain-release.py \
    smoke-flutter-peer-presentation.sh finalize-flutter-tools-offline.sh \
    frb-codegen.sh dart-verify.sh smoke-server.sh \
    audit.sh rust-audit-policy.py verify-rust-audit-authority.py Dockerfile.audit \
    gen-android-keystore.sh android-keystore-generate.sh \
    verify-android-keystore-authority.py \
    build-android.sh android-apk-build.sh verify-android-builder-authority.py \
    test-android-gradle-cache.sh verify-android-gradle-authority.py \
    verify-android-builder-image-authority.py \
    verify-deb-builder-image-authority.py build-debian.sh \
    verify-debian-builder-authority.py \
    stage-debian-systemd-runtime-libs.sh \
    smoke-debian-systemd-lifecycle-guest.sh \
    smoke-debian-systemd-loginctl.sh \
    verify-win-helper-image-authority.py verify-windows-helper-authority.py \
    test-windows-helper-vm-runtime.sh windows-helper-runtime.sh \
    windows-helper-extract-kernel.py windows-golden-inspect.sh \
    build-windows-vm.sh provision-windows-vm.sh verify-windows-golden.sh \
    Dockerfile.android-builder Dockerfile.deb-builder \
    Dockerfile.win-helper Dockerfile.builder-bootstrap-seal \
    Dockerfile.android-builder-certify Dockerfile.deb-builder-certify \
    Dockerfile.win-helper-certify offline-image-provenance.py \
    online-fetch.sh online-fetch-vm.sh online-fetch-vm-guest.sh \
    verify-online-fetch-vm-entry.sh verify-online-fetch-container-authority.py \
    verify-online-fetch-virtiofs-rename.py launch-landlocked-virtiofsd.py \
    online-pub-cache-output.py online-gradle-output.py \
    verify-online-fetch-gradle-output-authority.py android-gradle-cache.py \
    android-rust-check.sh \
    smoke-android-emulator-boot.sh android-emulator-app-check.sh \
    android-emulator-runtime-check.sh AndroidRecentsDismiss.java \
    verify-android-emulator-apk.py \
    verify-android-apk-manifest.py publish-artifact-result.py \
    android-peer-artifact.py test-android-peer-artifact.py test-android-runtime-progress.py \
    bounded-unix-stream-capture.py \
    linux-flutter-artifact.py test-linux-flutter-artifact.py \
    dart-audit.sh dart-audit-result.py \
    verify-dart-verifier-authority.py verify-dart-audit-authority.py \
    smoke-verifier-vm-authority.sh smoke-verifier-vm-authority-guest.sh \
    verify-vm-entry-preflight.sh verify-scan.sh \
    verify-private-tree-closure.py lib.sh pins.env; do
    verify_path="$VERIFY_REPO/scripts/$verify_source"
    [ -f "$verify_path" ] && [ ! -L "$verify_path" ] \
        || fail "main verifier entry source is absent or ambiguous: $verify_source"
done
[ -f "$VERIFY_REPO/flutter/android/gradle/wrapper/gradle-wrapper.properties" ] \
    && [ ! -L "$VERIFY_REPO/flutter/android/gradle/wrapper/gradle-wrapper.properties" ] \
    || fail 'Gradle wrapper authority input is absent or ambiguous'
for repository_source in requirements.html HARDENING_STATUS.md; do
    [ -f "$VERIFY_REPO/$repository_source" ] && [ ! -L "$VERIFY_REPO/$repository_source" ] \
        || fail "FRB source-gate input is absent or ambiguous: $repository_source"
done
[ -f "$VERIFY_REPO/res/rustdesk.service" ] \
    && [ ! -L "$VERIFY_REPO/res/rustdesk.service" ] \
    || fail 'installed-systemd production unit source is absent or ambiguous'
[ "$(/usr/bin/stat -c '%a:%h' -- "$SYSTEMD_RUNTIME_LIBS_SCRIPT")" = 755:1 ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$SYSTEMD_LIFECYCLE_SCRIPT")" = 755:1 ] \
    && [ "$(/usr/bin/stat -c '%a:%h' -- "$VERIFY_REPO/scripts/smoke-debian-systemd-loginctl.sh")" = 755:1 ] \
    || fail 'installed-systemd lifecycle script metadata differs'
# shellcheck source=/dev/null
source "$VERIFY_REPO/scripts/pins.env"
FLUTTER_PEER_RUNTIME_VERSION=$FLUTTER_VERSION
FLUTTER_PEER_TOOLS_MODE=offline-resolved
if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
    FLUTTER_PEER_RUNTIME_VERSION=$FLUTTER_PRESENTATION_CANDIDATE_VERSION
fi
readonly FLUTTER_PEER_RUNTIME_VERSION FLUTTER_PEER_TOOLS_MODE
provision_git_runtime
readonly RELEASE_PARENT_SCRIPT="$VERIFY_REPO/scripts/build-release.sh"
readonly RELEASE_WORKSPACE_RUNTIME_TEST="$VERIFY_REPO/scripts/verify-release-workspace-runtime.sh"
readonly APPLE_CHECK_SCRIPT="$VERIFY_REPO/scripts/apple-conform-check.sh"
readonly FLUTTER_PEER_SCRIPT="$VERIFY_REPO/scripts/smoke-flutter-peer-presentation.sh"
[ "$ENTRY_PREFLIGHT" = "$VERIFY_REPO/scripts/verify-vm-entry-preflight.sh" ] \
    || fail 'main verifier and guest probe use different entry-preflight paths'
entry_source_metadata="$(stat -c '%F:%u:%g:%a:%h' -- \
    "$VERIFY_REPO/scripts/verify-vm-entry-preflight.sh")" \
    || fail 'main verifier entry-preflight metadata cannot be read'
[ "$(stat -c '%s:%h' -- "$DOCKER_ARCHIVE")" = "$EXPECTED_SIZE:1" ] \
    || fail 'Docker bundle size or link count differs inside the guest'
[ "$(sha256sum "$DOCKER_ARCHIVE" | awk '{print $1}')" = "$EXPECTED_SHA256" ] \
    || fail 'Docker bundle digest differs inside the guest'
mount_options="$(findmnt -n -o OPTIONS --target "$DOCKER_ARCHIVE")" \
    || fail 'Docker bundle payload mount is absent'
case ",$mount_options," in *,ro,*) ;; *) fail 'Docker payload is not read-only' ;; esac
case ",$mount_options," in *,nodev,*) ;; *) fail 'Docker payload permits devices' ;; esac
case ",$mount_options," in *,nosuid,*) ;; *) fail 'Docker payload permits set-user-ID execution' ;; esac
case ",$mount_options," in *,noexec,*) ;; *) fail 'Docker payload permits direct execution' ;; esac
printf 'VERIFIER_VM_ENTRY_SOURCE=metadata=%s mount=noexec-readonly\n' \
    "$entry_source_metadata"

[ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ] \
    || fail 'AppArmor kernel enforcement is not enabled'
parser="$(PATH="$DAEMON_PATH" command -v apparmor_parser)" \
    || fail 'pinned cloud base AppArmor parser is not on the daemon search path'
parser="$(readlink -f -- "$parser")" \
    || fail 'pinned cloud base AppArmor parser cannot be resolved'
[ -f "$parser" ] && [ ! -L "$parser" ] && [ -x "$parser" ] \
    || fail 'pinned cloud base AppArmor parser is not one executable file'
[ "$(stat -c '%u:%g:%a:%h' -- "$parser")" = 0:0:755:1 ] \
    || fail 'pinned cloud base AppArmor parser metadata differs'
case "$("$parser" --version 2>&1 | head -n 1)" in
    'AppArmor parser version '*) ;;
    *) fail 'pinned cloud base AppArmor parser identity differs' ;;
esac

mapfile -t interfaces < <(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[ "${#interfaces[@]}" -eq 1 ] && [ "${interfaces[0]}" = lo ] \
    || fail "networkless VM has an unexpected interface inventory: ${interfaces[*]}"
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'guest IPv4 forwarding is enabled before Docker'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'guest IPv6 forwarding is enabled before Docker'
network_inventory >"$ROOT.network-before"

mkdir -p "$AUTHORITY_ROOT" "$BIN" "$CONFIG_ROOT" "$DATA" "$EXEC" \
    "$ROOT/rootfs/bin" "$ROOT/rootfs/lib" "$ROOT/rootfs/lib64"
chmod 0755 "$AUTHORITY_ROOT"
chmod 0755 "$ROOT"
chmod 0700 "$DATA" "$EXEC"
archive_inventory="$(tar -tzf "$DOCKER_ARCHIVE")" || fail 'Docker bundle inventory cannot be read'
[ "$archive_inventory" = $'docker/\ndocker/runc\ndocker/containerd\ndocker/docker-init\ndocker/dockerd\ndocker/containerd-shim-runc-v2\ndocker/docker-proxy\ndocker/docker\ndocker/ctr' ] \
    || fail 'Docker bundle has a noncanonical member inventory or order'
tar -xzf "$DOCKER_ARCHIVE" --strip-components=1 --no-same-owner --no-same-permissions \
    -C "$BIN" \
    docker/runc docker/containerd docker/docker-init docker/dockerd \
    docker/containerd-shim-runc-v2 docker/docker-proxy docker/docker docker/ctr
[ ! -e "$CLIENT" ] && [ ! -L "$CLIENT" ] \
    || fail 'pinned cloud base unexpectedly supplies a Docker client'
mv -- "$BIN/docker" "$CLIENT"
chmod 0555 "$BIN" "$BIN"/* "$CLIENT"
[ "$(find "$BIN" -mindepth 1 -maxdepth 1 -type f -perm 0555 | wc -l)" -eq 7 ] \
    || fail 'extracted Docker binary inventory differs'
[ -z "$(find "$BIN" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
    || fail 'extracted Docker bundle contains a non-regular entry'
[ "$(stat -c '%u:%g:%a:%h' -- "$CLIENT")" = 0:0:555:1 ] \
    || fail 'fixed VM Docker client metadata differs'

docker_version="$("$CLIENT" --version)"
dockerd_version="$($BIN/dockerd --version)"
case "$docker_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker client version differs: $docker_version" ;; esac
case "$dockerd_version" in "Docker version $EXPECTED_VERSION,"*) ;; *) fail "Docker daemon version differs: $dockerd_version" ;; esac
printf '{}\n' >"$CONFIG"
printf 'rustdesk-verifier-vm-authority-v1 docker=%s\n' "$EXPECTED_VERSION" >"$MARKER"
chmod 0444 "$CONFIG" "$MARKER"
chmod 0555 "$CONFIG_ROOT"
[ "$(sha256sum "$CONFIG" | awk '{ print $1 }')" = \
  ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356 ] \
    || fail 'canonical empty Docker configuration digest differs'

PATH="$DAEMON_PATH" \
    "$BIN/dockerd" \
        --host "unix://$SOCK" \
        --pidfile "$PIDFILE" \
        --data-root "$DATA" \
        --exec-root "$EXEC" \
        --bridge none \
        --iptables=false \
        --ip6tables=false \
        --ip-forward=false \
        --ip-masq=false \
        --userland-proxy=false \
        --group root \
        --log-level error \
        >"$LOG" 2>&1 &
DAEMON_PID=$!
[[ "$DAEMON_PID" =~ ^[1-9][0-9]*$ ]] || fail 'Docker daemon PID is malformed'

ready=0
server_version=
for _ in $(seq 1 300); do
    server_version=
    if [ -S "$SOCK" ]; then
        server_version="$(
            "$CLIENT" --host "unix://$SOCK" info --format '{{.ServerVersion}}' \
                2>/dev/null
        )" || server_version=
    fi
    if [ "$server_version" = "$EXPECTED_VERSION" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
done
[ "$ready" -eq 1 ] || fail 'guest-only Docker daemon did not become ready'
[ "$server_version" = "$EXPECTED_VERSION" ] || fail 'Docker server version differs'
[ "$(<"$PIDFILE")" = "$DAEMON_PID" ] || fail 'Docker daemon PID file differs'
docker_socket_gid=4000
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = cpace-recovery-tests ] \
   || [ "$MODE" = linux-pa-authority-tests ] \
   || [ "$MODE" = linux-service-uid-tests ] \
   || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ] \
   || [ "$MODE" = flutter-model-tests ] \
   || [ "$MODE" = android-owner-tests ] \
   || [ "$MODE" = android-peer-build ] || [ "$MODE" = cm-file-replay ] \
   || [ "$MODE" = android-emulator-boot ] \
   || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ] \
   || [ "$MODE" = flutter-peer-presentation ] \
   || [ "$MODE" = rust-audit ] \
   || [ "$MODE" = linux-flutter-engine-prepare ] || [ "$MODE" = linux-flutter-engine-build ]; then
    docker_socket_gid=1000
fi
chown "0:$docker_socket_gid" "$SOCK"
chmod 0660 "$SOCK"
chmod 0444 "$PIDFILE"
[ "$(stat -c '%u:%g:%a' -- "$SOCK")" = "0:$docker_socket_gid:660" ] \
    || fail 'Docker Unix socket authority differs'
[ "$(readlink -f -- "/proc/$DAEMON_PID/exe")" = "$BIN/dockerd" ] \
    || fail 'Docker daemon executable identity differs before generation publication'
daemon_start="$(awk '{ print $22 }' "/proc/$DAEMON_PID/stat")" \
    || fail 'Docker daemon start time cannot be read'
[[ "$daemon_start" =~ ^[1-9][0-9]*$ ]] || fail 'Docker daemon start time is malformed'
printf 'pid=%s start=%s daemon_sha256=%s client_sha256=%s\n' \
    "$DAEMON_PID" "$daemon_start" \
    "$(sha256sum "$BIN/dockerd" | awk '{ print $1 }')" \
    "$(sha256sum "$CLIENT" | awk '{ print $1 }')" \
    >"$DAEMON_IDENTITY"
chmod 0444 "$DAEMON_IDENTITY"
[ ! -e /sys/class/net/docker0 ] || fail 'Docker created a guest bridge despite --bridge=none'
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] \
    || fail 'Docker enabled guest IPv4 forwarding'
[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
    || fail 'Docker enabled guest IPv6 forwarding'
network_inventory >"$ROOT.network-during"
cmp -s "$ROOT.network-before" "$ROOT.network-during" \
    || fail 'guest Docker created an INET listener'

if [ "$MODE" = debian-systemd-lifecycle ]; then
    run_debian_systemd_lifecycle
    printf 'VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=%s direct_boot=on boot_masks=on docker=%s vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off lifecycle=installed-debian-artifact\n' \
        "$EXPECTED_KERNEL_RELEASE" "$EXPECTED_VERSION"
    exit 0
fi

if [ "$MODE" = linux-flutter-engine-prepare ] || [ "$MODE" = linux-flutter-engine-build ]; then
    run_linux_flutter_engine_prepare
    exit 0
fi

if [ "$MODE" = fixed-archive-tests ]; then
    run_fixed_archive_tests
    exit 0
fi

if [ "$MODE" = linux-flutter-artifact-tests ]; then
    run_linux_flutter_artifact_tests
    exit 0
fi

if [ "$MODE" = android-frame-tests ] || [ "$MODE" = x11-display-tests ]; then
    run_android_frame_tests
    exit 0
fi

if [ "$MODE" = android-runtime-log-tests ]; then
    run_android_runtime_log_tests
    exit 0
fi

if [ "$MODE" = android-execution-probe ]; then
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT"
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
        /usr/bin/timeout --signal=TERM --kill-after=2s 5s \
        /usr/bin/python3 -I -S - "$EXPECTED_KERNEL_RELEASE" <<'PY'
import hashlib
import os
import re
import stat
import sys

if (os.geteuid(), os.getegid()) != (4000, 4000):
    raise SystemExit("Android execution probe requires the exact nonroot guest principal")
release = os.uname().release
if release != sys.argv[1]:
    raise SystemExit("Android execution probe kernel differs")
config_path = f"/boot/config-{release}"
descriptor = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
try:
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1
            or not 0 < before.st_size <= 1024 * 1024):
        raise SystemExit("Android execution probe kernel config authority differs")
    with os.fdopen(descriptor, "rb", closefd=False) as source:
        config = source.read(1024 * 1024 + 1)
    after = os.fstat(descriptor)
    if len(config) != before.st_size or any(
            getattr(after, field) != getattr(before, field)
            for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                          "st_size", "st_mtime_ns", "st_ctime_ns")):
        raise SystemExit("Android execution probe kernel config changed")
finally:
    os.close(descriptor)
options = {}
for line in config.decode("ascii").splitlines():
    match = re.fullmatch(r"(CONFIG_KVM(?:_INTEL|_AMD)?)=([ym])", line)
    disabled = re.fullmatch(r"# (CONFIG_KVM(?:_INTEL|_AMD)?) is not set", line)
    if match or disabled:
        key, value = (match.group(1), match.group(2)) if match else (disabled.group(1), "n")
        if key in options:
            raise SystemExit("Android execution probe kernel config is ambiguous")
        options[key] = value
if "CONFIG_KVM" not in options:
    raise SystemExit("Android execution probe has no explicit KVM kernel setting")
with open("/proc/cpuinfo", encoding="ascii") as source:
    cpuinfo = source.read(1024 * 1024 + 1)
if len(cpuinfo) > 1024 * 1024:
    raise SystemExit("Android execution probe CPU inventory exceeds its bound")
flags = [set(line.split(":", 1)[1].split()) for line in cpuinfo.splitlines()
         if line.startswith("flags\t")]
if not flags:
    raise SystemExit("Android execution probe CPU flags are absent")
extensions = set.intersection(*flags) & {"vmx", "svm"}
if len(extensions) > 1:
    raise SystemExit("Android execution probe CPU virtualization is ambiguous")
virtualization = next(iter(extensions), "none")
module_root = f"/lib/modules/{release}/kernel/arch/x86/kvm"
module_files = 0
for name in ("kvm", "kvm-intel", "kvm-amd"):
    for suffix in (".ko", ".ko.xz", ".ko.zst"):
        path = f"{module_root}/{name}{suffix}"
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SystemExit("Android execution probe module authority differs")
        module_files += 1
try:
    device = os.lstat("/dev/kvm")
except FileNotFoundError:
    device_state, access = "absent", "unobserved"
else:
    if not stat.S_ISCHR(device.st_mode) or device.st_uid != 0 or os.major(device.st_rdev) != 10 or os.minor(device.st_rdev) != 232:
        raise SystemExit("Android execution probe KVM device authority differs")
    device_state = "present"
    access = "rw" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "denied"
print(f"ANDROID_EXECUTION_PROBE=observed kernel={release} "
      f"config_sha256={hashlib.sha256(config).hexdigest()} cpus={len(flags)} "
      f"virtualization={virtualization} kvm={options['CONFIG_KVM']} "
      f"intel={options.get('CONFIG_KVM_INTEL', 'n')} amd={options.get('CONFIG_KVM_AMD', 'n')} "
      f"module_files={module_files} device={device_state} access={access} "
      "uid=4000 gid=4000 vm_network=none")
PY
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ENTRY_PREFLIGHT"
    stop_docker_authority
    printf 'ANDROID_EXECUTION_PROBE_FINALITY=pass docker=retired emulator=unexecuted module_loads=none device_changes=none cleanup=joined\n'
    exit 0
fi

if [ "$MODE" = dart-audit ]; then
    run_dart_audit
    exit 0
fi

if [ "$MODE" = rust-audit ]; then
    run_rust_audit
    exit 0
fi

if [ "$MODE" = apple-conform ]; then
    run_apple_conform
    exit 0
fi

if [ "$MODE" = hbb-common-fs ]; then
    run_focused_rust_tests
    exit 0
fi

if [ "$MODE" = cpace-recovery-tests ]; then
    run_focused_rust_tests
    exit 0
fi

if [ "$MODE" = linux-pa-authority-tests ]; then
    run_focused_rust_tests
    exit 0
fi

if [ "$MODE" = linux-service-uid-tests ]; then
    run_focused_rust_tests
    exit 0
fi

if [ "$MODE" = android-rust-lifecycle-tests ]; then
    run_focused_rust_tests
    exit 0
fi

if [ "$MODE" = android-rust-target-check ]; then
    run_android_rust_target_check
    exit 0
fi

if [ "$MODE" = android-owner-tests ]; then
    run_android_owner_tests
    exit 0
fi

if [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    provision_android_kvm
fi

if [ "$MODE" = android-peer-build ]; then
    run_android_peer_build
    exit 0
fi

if [ "$MODE" = cm-file-replay ]; then
    run_cm_file_replay
    exit 0
fi

if [ "$MODE" = android-emulator-boot ]; then
    run_android_emulator_boot
    exit 0
fi

if [ "$MODE" = android-emulator-app ]; then
    run_android_emulator_app
    exit 0
fi

if [ "$MODE" = android-emulator-runtime ]; then
    run_android_emulator_runtime
    exit 0
fi

if [ "$MODE" = flutter-model-tests ]; then
    run_flutter_model_tests
    exit 0
fi

if [ "$MODE" = flutter-peer-presentation ]; then
    run_flutter_peer_presentation
    exit 0
fi

if [ "$MODE" = authority-smoke ]; then
    publication_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            /usr/bin/python3 -I -S \
                "$VERIFY_REPO/scripts/publish-artifact-result.py" --self-test
    )" || fail 'numeric-nonroot artifact publication self-test failed'
    [ "$publication_output" = 'publish-artifact-result self-test: ok' ] \
        || fail "artifact publication result differs: $publication_output"
    printf 'VERIFIER_VM_ARTIFACT_PUBLICATION=pass android_pair=atomic checksums=both tamper=refused cleanup=joined\n'
    cleanup_source_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /usr/bin/python3 -I -S \
                "$VERIFY_REPO/scripts/verify-cleanup-authority.py" --repo "$VERIFY_REPO"
    )" || fail 'numeric-nonroot cleanup source invariant failed'
    [ "$cleanup_source_output" = 'verify-cleanup-authority: ok (source only)' ] \
        || fail "cleanup source result differs: $cleanup_source_output"
    cleanup_runtime_output="$(
        setpriv --reuid=4000 --regid=4000 --clear-groups \
            /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
            /usr/bin/python3 -I -S - "$VERIFY_REPO" <<'PY'
import pathlib
import shutil
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="rustdesk-cleanup-", dir="/tmp") as root_name:
    root = pathlib.Path(root_name)
    scripts = root / "scripts"
    scripts.mkdir(mode=0o700)
    for name in ("cleanup.sh", "lib.sh"):
        shutil.copyfile(source / "scripts" / name, scripts / name)
    state = root / ".harness-state"
    winvm = state / "winvm"
    winvm.mkdir(parents=True)
    protected = root / "protected"
    protected.mkdir()
    sentinel = protected / "sentinel.qcow2"
    sentinel.write_bytes(b"retained")
    (state / "overlays").symlink_to(protected, target_is_directory=True)
    monitor = winvm / "monitor.sock"
    monitor.write_bytes(b"retained")
    child = subprocess.Popen(("/bin/sleep", "30"), stdin=subprocess.DEVNULL)
    try:
        pid_file = winvm / "old.pid"
        pid_file.write_text(str(child.pid) + "\n", encoding="ascii")
        result = subprocess.run(
            ("/bin/bash", str(scripts / "cleanup.sh")),
            cwd=root,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"},
            capture_output=True,
            timeout=8,
        )
        if result.returncode or result.stdout or b"no generic ephemeral cleanup performed" not in result.stderr:
            raise RuntimeError("default cleanup did not return its report-only result")
        try:
            child.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise RuntimeError("default cleanup signaled the decoy process")
        if not pid_file.is_file() or not monitor.is_file():
            raise RuntimeError("default cleanup deleted decoy PID/socket state")
        if sentinel.read_bytes() != b"retained":
            raise RuntimeError("default cleanup deleted the symlink-target overlay")
        print("CLEANUP_DEFAULT_VM=pass uid=4000 process=preserved pidfile=preserved overlay=preserved source=checked cleanup=joined")
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
PY
    )" || fail 'numeric-nonroot default cleanup decoy-state test failed'
    [ "$cleanup_runtime_output" = \
      'CLEANUP_DEFAULT_VM=pass uid=4000 process=preserved pidfile=preserved overlay=preserved source=checked cleanup=joined' ] \
        || fail "cleanup default-path result differs: $cleanup_runtime_output"
    printf '%s\n' "$cleanup_runtime_output"
fi

run_admission_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$VERIFY_REPO/scripts/test-verifier-vm-run-admission.sh"
)" || fail 'numeric-nonroot verifier-VM run admission test failed'
[ "$run_admission_output" = \
  'VERIFIER_VM_RUN_ADMISSION=pass retained=refused file=refused symlink=refused lock=refused unsafe=refused concurrent=16 winners=1 cross_root_marker=refused active_lock=retained app_capsule=refused cleanup=joined' ] \
    || fail "verifier-VM run admission result differs: $run_admission_output"
printf '%s\n' "$run_admission_output"

peer_artifact_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$VERIFY_REPO/scripts/test-android-peer-artifact.py"
)" || fail 'numeric-nonroot Android peer artifact authority test failed'
[ "$peer_artifact_output" = \
  'ANDROID_PEER_ARTIFACT=pass fixture=system-elf files=7 cases=22 publication=noclobber admission=exact execution=guest-only cleanup=joined' ] \
    || fail "Android peer artifact authority result differs: $peer_artifact_output"
printf '%s\n' "$peer_artifact_output"

runtime_progress_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$VERIFY_REPO/scripts/test-android-runtime-progress.py"
)" || fail 'numeric-nonroot Android runtime progress test failed'
[ "$runtime_progress_output" = \
  'ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof diagnostics=filtered cardinality=1 children=joined' ] \
    || fail "Android runtime progress result differs: $runtime_progress_output"
printf '%s\n' "$runtime_progress_output"

if /bin/bash "$VERIFY_SCRIPT" --self-test-workspace \
    >"$ROOT/root-entry.out" 2>"$ROOT/root-entry.err"; then
    fail 'VM root passed the main verifier entry'
fi
[ ! -s "$ROOT/root-entry.out" ] \
    || fail 'root main-verifier refusal produced standard output'
[ "$(<"$ROOT/root-entry.err")" = \
  'verify: refuses host or container-root execution' ] \
    || fail 'root main-verifier refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$VERIFY_SCRIPT" --self-test-workspace \
    >"$ROOT/foreign-entry.out" 2>"$ROOT/foreign-entry.err"; then
    fail 'foreign numeric principal passed the main verifier entry'
fi
[ ! -s "$ROOT/foreign-entry.out" ] \
    || fail 'foreign main-verifier refusal produced standard output'
foreign_entry_error="$(<"$ROOT/foreign-entry.err")"
if [ "$foreign_entry_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-entry.err")" -le 4096 ] \
        || fail 'foreign main-verifier refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign main-verifier diagnostic was %q\n' \
        "$foreign_entry_error" >&2
    fail 'foreign main-verifier refusal diagnostic differs'
fi
main_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$VERIFY_SCRIPT" --self-test-workspace
)" || fail 'numeric-nonroot main verifier entry failed'
expected_main_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
verify workspace self-test: OK"
[ "$main_entry_output" = "$expected_main_entry_output" ] \
    || fail "main verifier entry result differs: $main_entry_output"
printf '%s\n' "$main_entry_output"
printf 'VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused nofile=524544 workspace_fixtures=actual workspace_cleanup=joined\n'

# build-release.sh deliberately resolves the invoking principal through the
# guest's passwd database before it closes its environment.  Give both test
# principals real, isolated guest identities so UID 4000 exercises the admitted
# path and UID 4001 reaches the VM channel-authority rejection.
for principal in 4000 4001; do
    ! getent passwd "$principal" >/dev/null \
        || fail "release-parent fixture UID $principal already exists"
    ! getent group "$principal" >/dev/null \
        || fail "release-parent fixture GID $principal already exists"
    /usr/sbin/groupadd --gid "$principal" "rustdesk-verifier-$principal" \
        || fail "cannot create release-parent fixture GID $principal"
    /usr/sbin/useradd --uid "$principal" --gid "$principal" \
        --home-dir "/home/rustdesk-verifier-$principal" --no-create-home \
        --shell /usr/sbin/nologin "rustdesk-verifier-$principal" \
        || fail "cannot create release-parent fixture UID $principal"
    install -d -m 0700 -o "$principal" -g "$principal" \
        "/home/rustdesk-verifier-$principal" \
        || fail "cannot create release-parent fixture home for UID $principal"
    [ "$(getent passwd "$principal" | awk -F: '{ print $3 ":" $4 ":" $6 }')" = \
      "$principal:$principal:/home/rustdesk-verifier-$principal" ] \
        || fail "release-parent fixture identity $principal differs"
done

if /bin/bash "$RELEASE_PARENT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-release-parent.out" 2>"$ROOT/root-release-parent.err"; then
    fail 'VM root passed the release-parent entry'
fi
[ ! -s "$ROOT/root-release-parent.out" ] \
    || fail 'root release-parent refusal produced standard output'
[ "$(<"$ROOT/root-release-parent.err")" = \
  'build-release: refuses host or container-root release authority' ] \
    || fail 'root release-parent refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$RELEASE_PARENT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-release-parent.out" 2>"$ROOT/foreign-release-parent.err"; then
    fail 'foreign numeric principal passed the release-parent entry'
fi
[ ! -s "$ROOT/foreign-release-parent.out" ] \
    || fail 'foreign release-parent refusal produced standard output'
foreign_release_parent_error="$(<"$ROOT/foreign-release-parent.err")"
if [ "$foreign_release_parent_error" != \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-release-parent.err")" -le 4096 ] \
        || fail 'foreign release-parent refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign release-parent diagnostic was %q\n' \
        "$foreign_release_parent_error" >&2
    fail 'foreign release-parent refusal diagnostic differs'
fi
release_parent_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$RELEASE_PARENT_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot release-parent verifier-VM entry failed'
[ "$release_parent_output" = \
  'RELEASE_PARENT_VM_AUTHORITY=pass uid=4000 gid=4000 network=none channel=guest-unix parent_docker=absent cleanup=descriptor-bound children=vm-only' ] \
    || fail "release-parent verifier-VM entry result differs: $release_parent_output"
printf '%s\n' "$release_parent_output"
printf 'VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only\n'

if /bin/bash "$RELEASE_WORKSPACE_RUNTIME_TEST" --self-test-vm-runtime \
    >"$ROOT/root-release-workspace-runtime.out" \
    2>"$ROOT/root-release-workspace-runtime.err"; then
    fail 'VM root passed the release-workspace runtime entry'
fi
[ ! -s "$ROOT/root-release-workspace-runtime.out" ] \
    || fail 'root release-workspace refusal produced standard output'
[ "$(<"$ROOT/root-release-workspace-runtime.err")" = \
  'release-workspace-runtime: requires UID/GID 4000' ] \
    || fail 'root release-workspace refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$RELEASE_WORKSPACE_RUNTIME_TEST" --self-test-vm-runtime \
    >"$ROOT/foreign-release-workspace-runtime.out" \
    2>"$ROOT/foreign-release-workspace-runtime.err"; then
    fail 'foreign numeric principal passed the release-workspace runtime entry'
fi
[ ! -s "$ROOT/foreign-release-workspace-runtime.out" ] \
    || fail 'foreign release-workspace refusal produced standard output'
[ "$(<"$ROOT/foreign-release-workspace-runtime.err")" = \
  'release-workspace-runtime: requires UID/GID 4000' ] \
    || fail 'foreign release-workspace refusal diagnostic differs'
release_workspace_runtime_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$RELEASE_WORKSPACE_RUNTIME_TEST" --self-test-vm-runtime
)" || fail 'numeric-nonroot release-workspace runtime failed'
[ "$release_workspace_runtime_output" = \
  'RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined' ] \
    || fail "release-workspace runtime result differs: $release_workspace_runtime_output"
printf '%s\n' "$release_workspace_runtime_output"
printf 'VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 root=refused foreign=refused network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined\n'

if /bin/bash "$APPLE_CHECK_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-apple-check.out" 2>"$ROOT/root-apple-check.err"; then
    fail 'VM root passed the Apple-check entry'
fi
[ ! -s "$ROOT/root-apple-check.out" ] \
    || fail 'root Apple-check refusal produced standard output'
[ "$(<"$ROOT/root-apple-check.err")" = \
  'apple-conform-check refuses host or container-root execution' ] \
    || fail 'root Apple-check refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$APPLE_CHECK_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-apple-check.out" 2>"$ROOT/foreign-apple-check.err"; then
    fail 'foreign numeric principal passed the Apple-check entry'
fi
[ ! -s "$ROOT/foreign-apple-check.out" ] \
    || fail 'foreign Apple-check refusal produced standard output'
foreign_apple_error="$(<"$ROOT/foreign-apple-check.err")"
if [ "$foreign_apple_error" != \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-apple-check.err")" -le 4096 ] \
        || fail 'foreign Apple-check refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Apple-check diagnostic was %q\n' \
        "$foreign_apple_error" >&2
    fail 'foreign Apple-check refusal diagnostic differs'
fi
while IFS='|' read -r authority_name authority_value authority_error; do
    caller_out="$ROOT/caller-$authority_name-apple-check.out"
    caller_err="$ROOT/caller-$authority_name-apple-check.err"
    if setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/env "$authority_name=$authority_value" \
        /bin/bash "$APPLE_CHECK_SCRIPT" --self-test-vm-authority \
        >"$caller_out" 2>"$caller_err"; then
        fail "caller $authority_name authority passed the Apple-check entry"
    fi
    [ ! -s "$caller_out" ] \
        || fail "caller $authority_name Apple-check refusal produced standard output"
    [ "$(<"$caller_err")" = "$authority_error" ] \
        || fail "caller $authority_name Apple-check refusal diagnostic differs"
done <<'EOF'
DOCKER_HOST|unix:///tmp/forbidden-docker.sock|FATAL: caller DOCKER_HOST authority is forbidden
APPLE_TARGET|aarch64-apple-ios|FATAL: caller APPLE_TARGET authority is forbidden
EOF
apple_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$APPLE_CHECK_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Apple-check verifier-VM entry failed'
expected_apple_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
APPLE_CHECK_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$apple_entry_output" = "$expected_apple_entry_output" ] \
    || fail "Apple-check verifier-VM entry result differs: $apple_entry_output"
printf '%s\n' "$apple_entry_output"
printf 'VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-flutter-peer.out" 2>"$ROOT/root-flutter-peer.err"; then
    fail 'VM root passed the Flutter full-peer entry'
fi
[ ! -s "$ROOT/root-flutter-peer.out" ] \
    || fail 'root Flutter full-peer refusal produced standard output'
[ "$(<"$ROOT/root-flutter-peer.err")" = \
  'flutter peer presentation smoke refuses host or container-root execution' ] \
    || fail 'root Flutter full-peer refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-flutter-peer.out" 2>"$ROOT/foreign-flutter-peer.err"; then
    fail 'foreign numeric principal passed the Flutter full-peer entry'
fi
[ ! -s "$ROOT/foreign-flutter-peer.out" ] \
    || fail 'foreign Flutter full-peer refusal produced standard output'
foreign_flutter_peer_error="$(<"$ROOT/foreign-flutter-peer.err")"
if [ "$foreign_flutter_peer_error" != \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-flutter-peer.err")" -le 4096 ] \
        || fail 'foreign Flutter full-peer refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Flutter full-peer diagnostic was %q\n' \
        "$foreign_flutter_peer_error" >&2
    fail 'foreign Flutter full-peer refusal diagnostic differs'
fi
if setpriv --reuid=4000 --regid=4000 --clear-groups \
    /usr/bin/env DOCKER_HOST=unix:///tmp/forbidden-docker.sock \
    /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/caller-flutter-peer.out" 2>"$ROOT/caller-flutter-peer.err"; then
    fail 'caller Docker authority passed the Flutter full-peer entry'
fi
[ ! -s "$ROOT/caller-flutter-peer.out" ] \
    || fail 'caller Docker-authority Flutter full-peer refusal produced standard output'
[ "$(<"$ROOT/caller-flutter-peer.err")" = \
  'FATAL: caller DOCKER_HOST authority is forbidden' ] \
    || fail 'caller Docker-authority Flutter full-peer refusal diagnostic differs'
flutter_peer_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Flutter full-peer verifier-VM entry failed'
expected_flutter_peer_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
FLUTTER_PEER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed workload=unexecuted"
[ "$flutter_peer_entry_output" = "$expected_flutter_peer_entry_output" ] \
    || fail "Flutter full-peer verifier-VM entry result differs: $flutter_peer_entry_output"
printf '%s\n' "$flutter_peer_entry_output"
printf 'VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$EXPECTED_VERSION"

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$FRB_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-frb-entry.out" 2>"$ROOT/foreign-frb-entry.err"; then
    fail 'foreign numeric principal passed the FRB verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-frb-entry.out" ] \
    || fail 'foreign FRB verifier-VM refusal produced standard output'
foreign_frb_error="$(<"$ROOT/foreign-frb-entry.err")"
if [ "$foreign_frb_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-frb-entry.err")" -le 4096 ] \
        || fail 'foreign FRB verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign FRB diagnostic was %q\n' \
        "$foreign_frb_error" >&2
    fail 'foreign FRB verifier-VM refusal diagnostic differs'
fi
frb_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$FRB_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot FRB verifier-VM entry failed'
expected_frb_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
FRB_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$frb_entry_output" = "$expected_frb_entry_output" ] \
    || fail "FRB verifier-VM entry result differs: $frb_entry_output"
printf '%s\n' "$frb_entry_output"
printf 'VERIFIER_VM_FRB_ENTRY=pass uid=4000 gid=4000 foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$DART_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-dart-entry.out" 2>"$ROOT/root-dart-entry.err"; then
    fail 'VM root passed the Dart verifier entry'
fi
[ ! -s "$ROOT/root-dart-entry.out" ] \
    || fail 'root Dart verifier refusal produced standard output'
[ "$(<"$ROOT/root-dart-entry.err")" = \
  'dart-verify refuses host or container-root execution' ] \
    || fail 'root Dart verifier refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$DART_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-dart-entry.out" 2>"$ROOT/foreign-dart-entry.err"; then
    fail 'foreign numeric principal passed the Dart verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-dart-entry.out" ] \
    || fail 'foreign Dart verifier-VM refusal produced standard output'
foreign_dart_error="$(<"$ROOT/foreign-dart-entry.err")"
if [ "$foreign_dart_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-dart-entry.err")" -le 4096 ] \
        || fail 'foreign Dart verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Dart diagnostic was %q\n' \
        "$foreign_dart_error" >&2
    fail 'foreign Dart verifier-VM refusal diagnostic differs'
fi
dart_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$DART_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Dart verifier-VM entry failed'
expected_dart_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DART_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed frb=chained"
[ "$dart_entry_output" = "$expected_dart_entry_output" ] \
    || fail "Dart verifier-VM entry result differs: $dart_entry_output"
printf '%s\n' "$dart_entry_output"
printf 'VERIFIER_VM_DART_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed frb=chained\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-smoke-server-entry.out" 2>"$ROOT/root-smoke-server-entry.err"; then
    fail 'VM root passed the server-smoke verifier entry'
fi
[ ! -s "$ROOT/root-smoke-server-entry.out" ] \
    || fail 'root server-smoke refusal produced standard output'
[ "$(<"$ROOT/root-smoke-server-entry.err")" = \
  'smoke: refuses host or container-root execution' ] \
    || fail 'root server-smoke refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-smoke-server-entry.out" 2>"$ROOT/foreign-smoke-server-entry.err"; then
    fail 'foreign numeric principal passed the server-smoke verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-smoke-server-entry.out" ] \
    || fail 'foreign server-smoke verifier-VM refusal produced standard output'
foreign_smoke_server_error="$(<"$ROOT/foreign-smoke-server-entry.err")"
if [ "$foreign_smoke_server_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-smoke-server-entry.err")" -le 4096 ] \
        || fail 'foreign server-smoke verifier-VM refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign server-smoke diagnostic was %q\n' \
        "$foreign_smoke_server_error" >&2
    fail 'foreign server-smoke verifier-VM refusal diagnostic differs'
fi
smoke_server_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$SMOKE_SERVER_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot server-smoke verifier-VM entry failed'
expected_smoke_server_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
SMOKE_SERVER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$smoke_server_entry_output" = "$expected_smoke_server_entry_output" ] \
    || fail "server-smoke verifier-VM entry result differs: $smoke_server_entry_output"
printf '%s\n' "$smoke_server_entry_output"
printf 'VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-rust-audit-entry.out" 2>"$ROOT/root-rust-audit-entry.err"; then
    fail 'VM root passed the Rust-audit verifier entry'
fi
[ ! -s "$ROOT/root-rust-audit-entry.out" ] \
    || fail 'root Rust-audit refusal produced standard output'
[ "$(<"$ROOT/root-rust-audit-entry.err")" = \
  'audit.sh: refuses host or container-root execution' ] \
    || fail 'root Rust-audit refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-rust-audit-entry.out" 2>"$ROOT/foreign-rust-audit-entry.err"; then
    fail 'foreign numeric principal passed the Rust-audit verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-rust-audit-entry.out" ] \
    || fail 'foreign Rust-audit verifier-VM refusal produced standard output'
foreign_rust_audit_error="$(<"$ROOT/foreign-rust-audit-entry.err")"
if [ "$foreign_rust_audit_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-rust-audit-entry.err")" -le 4096 ] \
        || fail 'foreign Rust-audit refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Rust-audit diagnostic was %q\n' \
        "$foreign_rust_audit_error" >&2
    fail 'foreign Rust-audit refusal diagnostic differs'
fi
rust_audit_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$RUST_AUDIT_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Rust-audit verifier-VM entry failed'
expected_rust_audit_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
RUST_AUDIT_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$rust_audit_entry_output" = "$expected_rust_audit_entry_output" ] \
    || fail "Rust-audit verifier-VM entry result differs: $rust_audit_entry_output"
printf '%s\n' "$rust_audit_entry_output"
printf 'VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

rust_audit_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-rust-audit-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Rust-audit compact source gate failed'
[ "$rust_audit_source_gate_output" = 'verify-rust-audit-authority: ok' ] \
    || fail "Rust-audit compact source-gate result differs: $rust_audit_source_gate_output"
printf '%s\n' "$rust_audit_source_gate_output"
printf 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass\n'

rust_audit_result_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/rust-audit-policy.py" --self-test
)" || fail 'Rust-audit policy/result behavioral gate failed'
[ "$rust_audit_result_gate_output" = \
  'rust-audit-policy self-test: ok (20 policy/freshness/result decisions)' ] \
    || fail "Rust-audit policy/result result differs: $rust_audit_result_gate_output"
printf '%s\n' "$rust_audit_result_gate_output"
printf 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20\n'

if /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-keystore-entry.out" 2>"$ROOT/root-android-keystore-entry.err"; then
    fail 'VM root passed the Android-keystore verifier entry'
fi
[ ! -s "$ROOT/root-android-keystore-entry.out" ] \
    || fail 'root Android-keystore refusal produced standard output'
[ "$(<"$ROOT/root-android-keystore-entry.err")" = \
  'Android signing identity generation refuses host or container-root execution' ] \
    || fail 'root Android-keystore refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-keystore-entry.out" 2>"$ROOT/foreign-android-keystore-entry.err"; then
    fail 'foreign numeric principal passed the Android-keystore verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-keystore-entry.out" ] \
    || fail 'foreign Android-keystore verifier-VM refusal produced standard output'
foreign_android_keystore_error="$(<"$ROOT/foreign-android-keystore-entry.err")"
if [ "$foreign_android_keystore_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-keystore-entry.err")" -le 4096 ] \
        || fail 'foreign Android-keystore refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-keystore diagnostic was %q\n' \
        "$foreign_android_keystore_error" >&2
    fail 'foreign Android-keystore refusal diagnostic differs'
fi
android_keystore_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-keystore verifier-VM entry failed'
expected_android_keystore_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_KEYSTORE_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed identity=untouched"
[ "$android_keystore_entry_output" = "$expected_android_keystore_entry_output" ] \
    || fail "Android-keystore verifier-VM entry result differs: $android_keystore_entry_output"
printf '%s\n' "$android_keystore_entry_output"
printf 'VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed identity=untouched\n' \
    "$EXPECTED_VERSION"

android_keystore_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-android-keystore-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Android-keystore compact source gate failed'
[ "$android_keystore_source_gate_output" = 'verify-android-keystore-authority: ok' ] \
    || fail "Android-keystore compact source-gate result differs: $android_keystore_source_gate_output"
printf '%s\n' "$android_keystore_source_gate_output"
printf 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass\n'

if /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-builder-entry.out" 2>"$ROOT/root-android-builder-entry.err"; then
    fail 'VM root passed the Android-builder verifier entry'
fi
[ ! -s "$ROOT/root-android-builder-entry.out" ] \
    || fail 'root Android-builder refusal produced standard output'
[ "$(<"$ROOT/root-android-builder-entry.err")" = \
  'Android artifact building refuses host or container-root execution' ] \
    || fail 'root Android-builder refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-builder-entry.out" 2>"$ROOT/foreign-android-builder-entry.err"; then
    fail 'foreign numeric principal passed the Android-builder verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-builder-entry.out" ] \
    || fail 'foreign Android-builder verifier-VM refusal produced standard output'
foreign_android_builder_error="$(<"$ROOT/foreign-android-builder-entry.err")"
if [ "$foreign_android_builder_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-builder-entry.err")" -le 4096 ] \
        || fail 'foreign Android-builder refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-builder diagnostic was %q\n' \
        "$foreign_android_builder_error" >&2
    fail 'foreign Android-builder refusal diagnostic differs'
fi
android_builder_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-builder verifier-VM entry failed'
expected_android_builder_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_BUILDER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed source=untouched signing=untouched output=untouched"
[ "$android_builder_entry_output" = "$expected_android_builder_entry_output" ] \
    || fail "Android-builder verifier-VM entry result differs: $android_builder_entry_output"
printf '%s\n' "$android_builder_entry_output"
printf 'VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched signing=untouched output=untouched\n' \
    "$EXPECTED_VERSION"

android_builder_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-android-builder-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Android-builder compact source gate failed'
[ "$android_builder_source_gate_output" = 'verify-android-builder-authority: ok' ] \
    || fail "Android-builder compact source-gate result differs: $android_builder_source_gate_output"
printf '%s\n' "$android_builder_source_gate_output"
printf 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass\n'

android_gradle_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ANDROID_GRADLE_CHECKER" \
        --repo "$VERIFY_REPO"
)" || fail 'Android Gradle compact source gate failed'
[ "$android_gradle_source_gate_output" = 'verify-android-gradle-authority: ok' ] \
    || fail "Android Gradle compact source-gate result differs: $android_gradle_source_gate_output"
printf '%s\n' "$android_gradle_source_gate_output"
printf 'VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass\n'

android_image_source_gate_status=0
android_image_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ANDROID_BUILDER_IMAGE_CHECKER" \
        --repo "$VERIFY_REPO"
)" || android_image_source_gate_status=$?
[ "${#android_image_source_gate_output}" -le 4096 ] \
    || fail 'Android builder-image source-gate diagnostic exceeded its bound'
[ "$android_image_source_gate_status" -eq 0 ] \
    || fail "Android builder-image compact source gate failed: $android_image_source_gate_output"
[ "$android_image_source_gate_output" = \
  'verify-android-builder-image-authority: ok' ] \
    || fail "Android builder-image source-gate result differs: $android_image_source_gate_output"
printf '%s\n' "$android_image_source_gate_output"
printf 'VERIFIER_VM_ANDROID_IMAGE_SOURCE_GATE=pass\n'

deb_image_source_gate_status=0
deb_image_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$DEB_BUILDER_IMAGE_CHECKER" \
        --repo "$VERIFY_REPO"
)" || deb_image_source_gate_status=$?
[ "${#deb_image_source_gate_output}" -le 4096 ] \
    || fail 'Debian builder-image source-gate diagnostic exceeded its bound'
[ "$deb_image_source_gate_status" -eq 0 ] \
    || fail "Debian builder-image compact source gate failed: $deb_image_source_gate_output"
[ "$deb_image_source_gate_output" = \
  'verify-deb-builder-image-authority: ok' ] \
    || fail "Debian builder-image source-gate result differs: $deb_image_source_gate_output"
printf '%s\n' "$deb_image_source_gate_output"
printf 'VERIFIER_VM_DEB_IMAGE_SOURCE_GATE=pass\n'

debian_builder_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$DEBIAN_BUILDER_AUTHORITY_CHECKER" \
        --repo "$VERIFY_REPO"
)" || fail 'Debian builder compact source gate failed'
[ "$debian_builder_source_gate_output" = 'verify-debian-builder-authority: ok' ] \
    || fail "Debian builder source-gate result differs: $debian_builder_source_gate_output"
printf '%s\n' "$debian_builder_source_gate_output"
printf 'VERIFIER_VM_DEBIAN_BUILDER_SOURCE_GATE=pass\n'

win_helper_image_source_gate_status=0
win_helper_image_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$WIN_HELPER_IMAGE_CHECKER" \
        --repo "$VERIFY_REPO"
)" || win_helper_image_source_gate_status=$?
[ "${#win_helper_image_source_gate_output}" -le 4096 ] \
    || fail 'Windows helper-image source-gate diagnostic exceeded its bound'
[ "$win_helper_image_source_gate_status" -eq 0 ] \
    || fail "Windows helper-image compact source gate failed: $win_helper_image_source_gate_output"
[ "$win_helper_image_source_gate_output" = \
  'verify-win-helper-image-authority: ok' ] \
    || fail "Windows helper-image source-gate result differs: $win_helper_image_source_gate_output"
printf '%s\n' "$win_helper_image_source_gate_output"
printf 'VERIFIER_VM_WIN_HELPER_IMAGE_SOURCE_GATE=pass\n'

windows_helper_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$WINDOWS_HELPER_AUTHORITY_CHECKER" \
        --repo "$VERIFY_REPO"
)" || fail 'Windows helper compact source gate failed'
[ "$windows_helper_source_gate_output" = 'verify-windows-helper-authority: ok' ] \
    || fail "Windows helper source-gate result differs: $windows_helper_source_gate_output"
printf '%s\n' "$windows_helper_source_gate_output"
printf 'VERIFIER_VM_WINDOWS_HELPER_SOURCE_GATE=pass\n'

apple_toolchain_release_status=0
apple_toolchain_release_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$APPLE_TOOLCHAIN_RELEASE" self-test
)" || apple_toolchain_release_status=$?
[ "${#apple_toolchain_release_output}" -le 4096 ] \
    || fail 'Apple toolchain release-helper self-test diagnostic exceeded its bound'
[ "$apple_toolchain_release_status" -eq 0 ] \
    || fail "Apple toolchain release-helper self-test failed: $apple_toolchain_release_output"
[ "$apple_toolchain_release_output" = \
  'apple-toolchain-release: self-test ok' ] \
    || fail "Apple toolchain release-helper result differs: $apple_toolchain_release_output"
printf '%s\n' "$apple_toolchain_release_output"
printf 'VERIFIER_VM_APPLE_TOOLCHAIN_RELEASE=pass uid=4000 gid=4000 network=none\n'

offline_image_provenance_status=0
offline_image_provenance_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$OFFLINE_IMAGE_PROVENANCE" --self-test
)" || offline_image_provenance_status=$?
[ "${#offline_image_provenance_output}" -le 4096 ] \
    || fail 'offline image-provenance diagnostic exceeded its bound'
[ "$offline_image_provenance_status" -eq 0 ] \
    || fail "offline image-provenance behavioral self-test failed: $offline_image_provenance_output"
[ "$offline_image_provenance_output" = \
  'offline image provenance self-test: PASS' ] \
    || fail "offline image-provenance result differs: $offline_image_provenance_output"
printf '%s\n' "$offline_image_provenance_output"
printf 'VERIFIER_VM_OFFLINE_IMAGE_PROVENANCE=pass uid=4000 gid=4000 android_decisions=40 debian_decisions=9 windows_decisions=22\n'

online_gradle_source_status=0
online_gradle_source_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER" \
        --repo "$VERIFY_REPO" --self-test
)" || online_gradle_source_status=$?
[ "${#online_gradle_source_output}" -le 4096 ] \
    || fail 'online Gradle output source-gate diagnostic exceeded its bound'
[ "$online_gradle_source_status" -eq 0 ] \
    || fail "online Gradle output source gate failed: $online_gradle_source_output"
[[ "$online_gradle_source_output" =~ ^verify-online-fetch-gradle-output-authority:\ PASS\ \([0-9]+\ mutations\ rejected\)$ ]] \
    || fail "online Gradle output source-gate result differs: $online_gradle_source_output"
printf '%s\n' "$online_gradle_source_output"
printf 'VERIFIER_VM_ONLINE_GRADLE_SOURCE_GATE=pass uid=4000 gid=4000\n'

online_fetch_authority_status=0
online_fetch_authority_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ONLINE_FETCH_AUTHORITY_CHECKER" \
        --repo "$VERIFY_REPO"
)" || online_fetch_authority_status=$?
[ "${#online_fetch_authority_output}" -le 4096 ] \
    || fail 'online-fetch authority diagnostic exceeded its bound'
[ "$online_fetch_authority_status" -eq 0 ] \
    || fail "online-fetch authority source gate failed: $online_fetch_authority_output"
[ "$online_fetch_authority_output" = 'online-fetch VM authority: PASS' ] \
    || fail "online-fetch authority result differs: $online_fetch_authority_output"
printf '%s\n' "$online_fetch_authority_output"
printf 'VERIFIER_VM_ONLINE_FETCH_SOURCE_GATE=pass uid=4000 gid=4000\n'

pub_cache_output_status=0
pub_cache_output_result="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ONLINE_PUB_CACHE_OUTPUT" self-test
)" || pub_cache_output_status=$?
[ "${#pub_cache_output_result}" -le 4096 ] \
    || fail 'Pub-cache replacement-finality diagnostic exceeded its bound'
[ "$pub_cache_output_status" -eq 0 ] \
    || fail "Pub-cache replacement-finality self-test failed: $pub_cache_output_result"
[ "$pub_cache_output_result" = 'ONLINE PUB CACHE OUTPUT SELF-TEST: PASS' ] \
    || fail "Pub-cache replacement-finality result differs: $pub_cache_output_result"

gradle_output_status=0
gradle_output_result="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S "$ONLINE_GRADLE_OUTPUT" self-test
)" || gradle_output_status=$?
[ "${#gradle_output_result}" -le 4096 ] \
    || fail 'Gradle replacement-finality diagnostic exceeded its bound'
[ "$gradle_output_status" -eq 0 ] \
    || fail "Gradle replacement-finality self-test failed: $gradle_output_result"
[ "$gradle_output_result" = 'online-gradle-output: self-test OK' ] \
    || fail "Gradle replacement-finality result differs: $gradle_output_result"
printf '%s\n%s\n' "$pub_cache_output_result" "$gradle_output_result"
printf 'VERIFIER_VM_ONLINE_REPLACEMENT_FINALITY=pass uid=4000 gid=4000 pub_cache=actual gradle=actual residue=absent recovery=replaced-staged\n'

if /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-android-rust-entry.out" 2>"$ROOT/root-android-rust-entry.err"; then
    fail 'VM root passed the Android-Rust verifier entry'
fi
[ ! -s "$ROOT/root-android-rust-entry.out" ] \
    || fail 'root Android-Rust refusal produced standard output'
[ "$(<"$ROOT/root-android-rust-entry.err")" = \
  'Android Rust release check refuses host or container-root execution' ] \
    || fail 'root Android-Rust refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-android-rust-entry.out" 2>"$ROOT/foreign-android-rust-entry.err"; then
    fail 'foreign numeric principal passed the Android-Rust verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-android-rust-entry.out" ] \
    || fail 'foreign Android-Rust verifier-VM refusal produced standard output'
foreign_android_rust_error="$(<"$ROOT/foreign-android-rust-entry.err")"
if [ "$foreign_android_rust_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-android-rust-entry.err")" -le 4096 ] \
        || fail 'foreign Android-Rust refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Android-Rust diagnostic was %q\n' \
        "$foreign_android_rust_error" >&2
    fail 'foreign Android-Rust refusal diagnostic differs'
fi
android_rust_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_RUST_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Android-Rust verifier-VM entry failed'
expected_android_rust_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_RUST_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed source=untouched online=untouched workload=unexecuted"
[ "$android_rust_entry_output" = "$expected_android_rust_entry_output" ] \
    || fail "Android-Rust verifier-VM entry result differs: $android_rust_entry_output"
printf '%s\n' "$android_rust_entry_output"
printf 'VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched online=untouched workload=unexecuted\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/root-dart-audit-entry.out" 2>"$ROOT/root-dart-audit-entry.err"; then
    fail 'VM root passed the Dart-audit verifier entry'
fi
[ ! -s "$ROOT/root-dart-audit-entry.out" ] \
    || fail 'root Dart-audit refusal produced standard output'
[ "$(<"$ROOT/root-dart-audit-entry.err")" = \
  'dart-audit.sh: refuses host or container-root execution' ] \
    || fail 'root Dart-audit refusal diagnostic differs'

if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority \
    >"$ROOT/foreign-dart-audit-entry.out" 2>"$ROOT/foreign-dart-audit-entry.err"; then
    fail 'foreign numeric principal passed the Dart-audit verifier-VM entry'
fi
[ ! -s "$ROOT/foreign-dart-audit-entry.out" ] \
    || fail 'foreign Dart-audit verifier-VM refusal produced standard output'
foreign_dart_audit_error="$(<"$ROOT/foreign-dart-audit-entry.err")"
if [ "$foreign_dart_audit_error" != \
    'verifier-VM entry preflight: VM Docker channel metadata differs' ]; then
    [ "$(stat -c '%s' "$ROOT/foreign-dart-audit-entry.err")" -le 4096 ] \
        || fail 'foreign Dart-audit refusal diagnostic exceeded its bound'
    printf 'verifier-VM guest: foreign Dart-audit diagnostic was %q\n' \
        "$foreign_dart_audit_error" >&2
    fail 'foreign Dart-audit refusal diagnostic differs'
fi
dart_audit_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$DART_AUDIT_SCRIPT" --self-test-vm-authority
)" || fail 'numeric-nonroot Dart-audit verifier-VM entry failed'
expected_dart_audit_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DART_AUDIT_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION channel=guest-unix prepost=replayed"
[ "$dart_audit_entry_output" = "$expected_dart_audit_entry_output" ] \
    || fail "Dart-audit verifier-VM entry result differs: $dart_audit_entry_output"
printf '%s\n' "$dart_audit_entry_output"
printf 'VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$EXPECTED_VERSION"

dart_audit_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-dart-audit-authority.py" \
        --repo "$VERIFY_REPO"
)" || fail 'Dart-audit compact source gate failed'
[ "$dart_audit_source_gate_output" = 'verify-dart-audit-authority: ok' ] \
    || fail "Dart-audit compact source-gate result differs: $dart_audit_source_gate_output"
printf '%s\n' "$dart_audit_source_gate_output"
printf 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass\n'

dart_audit_result_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/dart-audit-result.py" --self-test
)" || fail 'Dart-audit result behavioral gate failed'
[ "$dart_audit_result_gate_output" = \
  'dart-audit-result self-test: ok (31 policy/freshness/status/schema decisions)' ] \
    || fail "Dart-audit result behavioral result differs: $dart_audit_result_gate_output"
printf '%s\n' "$dart_audit_result_gate_output"
printf 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31\n'

dart_frb_source_gate_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /usr/bin/python3 -I -S \
        "$VERIFY_REPO/scripts/verify-dart-verifier-authority.py" \
        --repo "$VERIFY_REPO" --self-test
)" || fail 'Dart/FRB verifier-VM focused source/mutation gate failed'
if [[ "$dart_frb_source_gate_output" =~ ^verify-dart-verifier-authority:\ ok\ \(([1-9][0-9]*)\ mutations\ rejected\)$ ]]; then
    dart_frb_source_gate_mutations=${BASH_REMATCH[1]}
else
    fail "Dart/FRB verifier-VM focused source/mutation result differs: $dart_frb_source_gate_output"
fi
printf '%s\n' "$dart_frb_source_gate_output"
printf 'VERIFIER_VM_DART_FRB_SOURCE_GATE=pass mutations=%s\n' "$dart_frb_source_gate_mutations"

prepare_authority_probe_image

if /bin/bash "$DEBIAN_BUILDER_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/root-debian-builder-entry.out" 2>"$ROOT/root-debian-builder-entry.err"; then
    fail 'VM root passed the Debian builder verifier entry'
fi
[ ! -s "$ROOT/root-debian-builder-entry.out" ] \
    || fail 'root Debian builder refusal produced standard output'
[ "$(<"$ROOT/root-debian-builder-entry.err")" = \
  'Debian artifact building refuses host or container-root execution' ] \
    || fail 'root Debian builder refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$DEBIAN_BUILDER_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/foreign-debian-builder-entry.out" 2>"$ROOT/foreign-debian-builder-entry.err"; then
    fail 'foreign principal passed the Debian builder verifier entry'
fi
[ ! -s "$ROOT/foreign-debian-builder-entry.out" ] \
    || fail 'foreign Debian builder refusal produced standard output'
[ "$(<"$ROOT/foreign-debian-builder-entry.err")" = \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
    || fail 'foreign Debian builder refusal diagnostic differs'
debian_builder_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$DEBIAN_BUILDER_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")"
)" || fail 'authorized Debian builder verifier entry failed'
expected_debian_builder_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DEBIAN_BUILDER_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined"
[ "$debian_builder_entry_output" = "$expected_debian_builder_entry_output" ] \
    || fail "Debian builder verifier entry result differs: $debian_builder_entry_output"
printf '%s\n' "$debian_builder_entry_output"
printf 'VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/root-systemd-libs-entry.out" 2>"$ROOT/root-systemd-libs-entry.err"; then
    fail 'VM root passed the systemd runtime-library verifier entry'
fi
[ ! -s "$ROOT/root-systemd-libs-entry.out" ] \
    || fail 'root systemd runtime-library refusal produced standard output'
[ "$(<"$ROOT/root-systemd-libs-entry.err")" = \
  'Debian systemd runtime-library staging refuses root execution' ] \
    || fail 'root systemd runtime-library refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/foreign-systemd-libs-entry.out" 2>"$ROOT/foreign-systemd-libs-entry.err"; then
    fail 'foreign principal passed the systemd runtime-library verifier entry'
fi
[ ! -s "$ROOT/foreign-systemd-libs-entry.out" ] \
    || fail 'foreign systemd runtime-library refusal produced standard output'
[ "$(<"$ROOT/foreign-systemd-libs-entry.err")" = \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
    || fail 'foreign systemd runtime-library refusal diagnostic differs'
systemd_libs_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$SYSTEMD_RUNTIME_LIBS_SCRIPT" \
            --self-test-vm-authority "$(<"$ROOT/image-id")"
)" || fail 'authorized systemd runtime-library verifier entry failed'
expected_systemd_libs_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
DEBIAN_SYSTEMD_RUNTIME_LIBS_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined"
[ "$systemd_libs_entry_output" = "$expected_systemd_libs_entry_output" ] \
    || fail "systemd runtime-library verifier entry result differs: $systemd_libs_entry_output"
printf '%s\n' "$systemd_libs_entry_output"
printf 'VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$ANDROID_GRADLE_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/root-android-gradle-entry.out" 2>"$ROOT/root-android-gradle-entry.err"; then
    fail 'VM root passed the Android Gradle verifier entry'
fi
[ ! -s "$ROOT/root-android-gradle-entry.out" ] \
    || fail 'root Android Gradle refusal produced standard output'
[ "$(<"$ROOT/root-android-gradle-entry.err")" = \
  'Android Gradle release gate refuses host or container-root execution' ] \
    || fail 'root Android Gradle refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$ANDROID_GRADLE_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")" \
    >"$ROOT/foreign-android-gradle-entry.out" 2>"$ROOT/foreign-android-gradle-entry.err"; then
    fail 'foreign principal passed the Android Gradle verifier entry'
fi
[ ! -s "$ROOT/foreign-android-gradle-entry.out" ] \
    || fail 'foreign Android Gradle refusal produced standard output'
[ "$(<"$ROOT/foreign-android-gradle-entry.err")" = \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
    || fail 'foreign Android Gradle refusal diagnostic differs'
android_gradle_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$ANDROID_GRADLE_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")"
)" || fail 'authorized Android Gradle verifier entry failed'
expected_android_gradle_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
ANDROID_GRADLE_VM_AUTHORITY=pass uid=4000 gid=4000 docker=$EXPECTED_VERSION profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined"
[ "$android_gradle_entry_output" = "$expected_android_gradle_entry_output" ] \
    || fail "Android Gradle verifier entry result differs: $android_gradle_entry_output"
printf '%s\n' "$android_gradle_entry_output"
printf 'VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined\n' \
    "$EXPECTED_VERSION"

if /bin/bash "$WINDOWS_HELPER_RUNTIME_TEST" "$(<"$ROOT/image-id")" \
    >"$ROOT/root-windows-helper.out" 2>"$ROOT/root-windows-helper.err"; then
    fail 'VM root passed the Windows helper runtime test entry'
fi
[ ! -s "$ROOT/root-windows-helper.out" ] \
    || fail 'root Windows helper refusal produced standard output'
[ "$(<"$ROOT/root-windows-helper.err")" = \
  'Windows helper VM runtime test refuses root execution' ] \
    || fail 'root Windows helper refusal diagnostic differs'
if setpriv --reuid=4001 --regid=4001 --clear-groups \
    /bin/bash "$WINDOWS_HELPER_RUNTIME_TEST" "$(<"$ROOT/image-id")" \
    >"$ROOT/foreign-windows-helper.out" 2>"$ROOT/foreign-windows-helper.err"; then
    fail 'foreign principal passed the Windows helper runtime test entry'
fi
[ ! -s "$ROOT/foreign-windows-helper.out" ] \
    || fail 'foreign Windows helper refusal produced standard output'
[ "$(<"$ROOT/foreign-windows-helper.err")" = \
  'verifier-VM entry preflight: VM Docker channel metadata differs' ] \
    || fail 'foreign Windows helper refusal diagnostic differs'
windows_helper_runtime_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$WINDOWS_HELPER_RUNTIME_TEST" "$(<"$ROOT/image-id")"
)" || fail 'authorized Windows helper runtime test failed'
[ "$windows_helper_runtime_output" = \
  'WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined' ] \
    || fail "Windows helper runtime result differs: $windows_helper_runtime_output"
printf '%s\n' "$windows_helper_runtime_output"

CONTAINER_ID="$(
    "$CLIENT" --host "unix://$SOCK" create \
        --name "$CONTAINER" \
        --pull=never \
        --network=none \
        --read-only \
        --pids-limit=16 \
        --memory=64m \
        --memory-swap=64m \
        --cpus=0.5 \
        --ulimit nofile=64:64 \
        --ulimit core=0:0 \
        --ulimit fsize=1048576:1048576 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --security-opt=apparmor=docker-default \
        --user 4000:4000 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m,mode=700,uid=4000,gid=4000 \
        "$IMAGE" -euc '
            [ "$$" = 1 ]
            uid= gid= cap= nnp= seccomp= apparmor=
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
            case "$apparmor" in docker-default\ *) ;; *) exit 92 ;; esac
            IFS= read -r pids_max </sys/fs/cgroup/pids.max
            IFS= read -r memory_max </sys/fs/cgroup/memory.max
            IFS= read -r swap_max </sys/fs/cgroup/memory.swap.max
            IFS=" " read -r cpu_quota cpu_period </sys/fs/cgroup/cpu.max
            [ "$pids_max" = 16 ]
            [ "$memory_max" = 67108864 ]
            [ "$swap_max" = 0 ]
            [ "$cpu_quota:$cpu_period" = 50000:100000 ]
            [ "$(ulimit -c)" = 0 ]
            [ "$(ulimit -n)" = 64 ]
            [ "$(ulimit -f)" != unlimited ]
            set -- /sys/class/net/*
            [ "$#" -eq 1 ] && [ "$1" = /sys/class/net/lo ]
            if (: >/forbidden-root-write) 2>/dev/null; then exit 91; fi
            : >/tmp/allowed-private-write
            [ -f /tmp/allowed-private-write ]
            printf "VERIFIER_INNER_CONTAINER=pass uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default\n"
        '
)"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'probe container ID is malformed'
inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
    "$CONTAINER_ID")"
[ "$inspect" = 'none|true|4000:4000|67108864|67108864|500000000|16|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
    || fail "probe container authority differs: $inspect"
namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.Binds}}|{{json .HostConfig.PortBindings}}' \
    "$CONTAINER_ID")"
[ "$namespace_inspect" = 'false||private||private|[]|null|{}' ] \
    || fail "probe container namespace/device/port authority differs: $namespace_inspect"
container_output="$("$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID")" \
    || fail 'probe container execution failed'
[ "$container_output" = 'VERIFIER_INNER_CONTAINER=pass uid=4000 network=none root=readonly caps=none nnp=on seccomp=filter apparmor=docker-default' ] \
    || fail "probe container result differs: $container_output"
[ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
    || fail 'probe container did not exit cleanly'
"$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=
"$CLIENT" --host "unix://$SOCK" image rm "$IMAGE" >/dev/null

stop_docker_authority

printf 'VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=%s direct_boot=on boot_masks=on docker=%s vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default\n' \
    "$EXPECTED_KERNEL_RELEASE" "$EXPECTED_VERSION"

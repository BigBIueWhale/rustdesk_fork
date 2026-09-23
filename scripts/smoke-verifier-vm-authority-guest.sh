#!/usr/bin/env bash
set -euo pipefail
umask 077

FLUTTER_PEER_CANDIDATE=0
case "$#:${8:-}" in
    7:)
        MODE=authority-smoke
        ;;
    12:--hbb-common-fs)
        MODE=hbb-common-fs
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
    12:--android-owner-tests)
        MODE=android-owner-tests
        ;;
    12:--android-emulator-boot)
        MODE=android-emulator-boot
        ;;
    12:--apple-conform)
        MODE=apple-conform
        ;;
    12:--flutter-peer-presentation)
        MODE=flutter-peer-presentation
        ;;
    12:--flutter-peer-presentation-candidate)
        MODE=flutter-peer-presentation
        FLUTTER_PEER_CANDIDATE=1
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
        echo 'usage: smoke-verifier-vm-authority-guest.sh DOCKER_TGZ ENTRY_PREFLIGHT VERSION SIZE SHA256 KERNEL_RELEASE ROOT_UUID [--hbb-common-fs SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-rust-lifecycle-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-rust-target-check SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --flutter-model-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-owner-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --android-emulator-boot SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --apple-conform SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --flutter-peer-presentation SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --flutter-peer-presentation-candidate SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --dart-audit SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 IMAGE_ARCHIVE | --rust-audit SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 IMAGE_ARCHIVE | --debian-systemd-lifecycle DEV_CHECK_ARCHIVE DEB DEB_SHA256 COMMIT]' >&2
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
readonly MODE FLUTTER_PEER_CANDIDATE
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
FLUTTER_PEER_SOURCE_MOUNTED=0
FLUTTER_PEER_ONLINE_MOUNTED=0

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
    /usr/bin/git -C "$source_root" add -f -- . \
        || fail 'cannot index the exact Apple-conformance source'
    [ "$(/usr/bin/git -C "$source_root" write-tree)" = "$APPLE_SOURCE_TREE" ] \
        || fail 'Apple-conformance source archive tree differs from pushed master'
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

    if /bin/bash "$source_root/scripts/apple-conform-check.sh" \
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
        /bin/bash "$source_root/scripts/apple-conform-check.sh" \
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
        /bin/bash "$source_root/scripts/apple-conform-check.sh" \
        >"$ROOT/caller-apple-conform.out" 2>"$ROOT/caller-apple-conform.err"; then
        fail 'caller Docker authority passed the Apple-conformance entry'
    fi
    [ ! -s "$ROOT/caller-apple-conform.out" ] \
        || fail 'caller-authority Apple-conformance refusal produced standard output'
    [ "$(<"$ROOT/caller-apple-conform.err")" = \
      'FATAL: caller DOCKER_HOST authority is forbidden' ] \
        || fail 'caller-authority Apple-conformance refusal diagnostic differs'

    set +e
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /bin/bash "$source_root/scripts/apple-conform-check.sh" \
        >"$output" 2>&1
    conform_status=$?
    set -e
    [ "$(stat -c '%s' -- "$output")" -le 6291456 ] \
        || fail 'Apple-conformance output exceeds its bound'
    [ "$conform_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "Apple conformance exited with status $conform_status"; }
    [ "$(grep -Fxc '== apple-conform-check PASS ==' "$output")" -eq 1 ] \
        || { tail -n 240 "$output" >&2; fail 'Apple-conformance pass verdict is absent or duplicated'; }
    [ "$(grep -Fxc '  targets: aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios' "$output")" -eq 1 ] \
        || fail 'Apple-conformance target matrix receipt differs'
    [ "$(grep -Fc 'hbb_common workspace anchor compiled cleanly' "$output")" -eq 3 ] \
        || { tail -n 240 "$output" >&2; fail 'Apple-conformance workspace-anchor receipts differ'; }
    [ "$(grep -Fxc "$expected_entry" "$output")" -eq 1 ] \
        || fail 'Apple-conformance VM authority receipt is absent or duplicated'

    source_tree_after="$(/usr/bin/git -c "safe.directory=$source_root" \
        -C "$source_root" write-tree)" \
        || fail 'cannot re-evaluate the Apple-conformance source tree'
    [ "$source_tree_after" = "$APPLE_SOURCE_TREE" ] \
        && /usr/bin/git -c "safe.directory=$source_root" -C "$source_root" \
             diff-files --quiet --ignore-submodules -- \
        || fail 'Apple-conformance source changed during execution'
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
    cat "$output"
    printf 'APPLE_CONFORM_VM=pass commit=%s tree=%s targets=3 image=%s runtime=%s vendor=%s uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused caller=refused source=exact-pushed-readonly inputs=readonly-landlocked evidence=source-conformance-not-native cleanup=joined\n' \
        "$APPLE_SOURCE_COMMIT" "$APPLE_SOURCE_TREE" \
        "$APPLE_CHECK_IMAGE_ID" "$APPLE_CHECK_IMAGE_CONFIG_ID" \
        "$SHA256_CARGO_VENDOR_CLOSURE_V1"
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
    local -a required_tests result_lines toolchain_mount bridge_mounts

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
        source_fingerprints=(Cargo.lock libs/hbb_common/src/fs.rs)
        required_tests=(
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
            src/direct_service.rs
            src/flutter.rs
            src/flutter_ffi.rs
            src/privacy_mode.rs
            src/server/connection.rs
            src/server/display_service.rs
            src/ui_cm_interface.rs
        )
        required_tests=(
            android_listener_lifecycle::tests::stale_network_callback_cannot_advance_replacement_generation_epoch
            android_listener_lifecycle::tests::worker_must_be_registered_and_converged_before_replacement
            android_listener_lifecycle::tests::invalid_exhausted_and_thread_creation_failure_edges_fail_closed
            direct_service::direct_connection_task_tests::parent_cancellation_converges_every_owned_child_before_listener_completion
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
            server::display_service::tests::r_s11iu_r_t4_resolution_restore_retains_failure_and_concurrent_replacement
            ui_cm_interface::tests::r_s11iu_android_cm_future_terminally_retires_its_registry_owner
            ui_cm_interface::tests::r_s11iu_android_cm_future_cancellation_retires_its_registry_owner
            ui_cm_interface::tests::r_s11iu_superseded_android_cm_owner_cannot_dispatch_filesystem_work
            ui_cm_interface::tests::r_s11iu_stale_owner_cannot_mutate_or_retire_a_reused_client_id
            ui_cm_interface::tests::r_s11iu_registry_rejects_stale_and_same_source_active_collisions
            ui_cm_interface::tests::r_s11iu_disconnected_owner_can_be_replaced_but_cannot_retire_replacement
            ui_cm_interface::tests::r_s11iu_generation_exhaustion_does_not_commit_a_client
            ui_cm_interface::tests::r_s11iu_file_log_publication_requires_exact_current_owner
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
    if [ "$MODE" = hbb-common-fs ]; then
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
        for input in \
            "$rust_archive:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
            "$flutter_archive:$SIZE_FLUTTER_3_24_5:$SHA256_FLUTTER_3_24_5" \
            "$llvm_archive:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6" \
            "$builder_archive:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE"; do
            path=${input%%:*}
            remainder=${input#*:}
            size=${remainder%%:*}
            digest=${remainder#*:}
            [ "$(stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
              "1000:1000:400:1:$size" ] \
                && [ "$(sha256sum "$path" | awk '{ print $1 }')" = "$digest" ] \
                || fail "sealed Android Rust bridge input differs: $path"
        done
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
        generate_focused_rust_flutter_bridge
        bridge_mounts=(
            --mount "type=bind,source=$ROOT/focused-rust-bridge/bridge_generated.rs,target=/source/src/bridge_generated.rs,readonly"
            --mount "type=bind,source=$ROOT/focused-rust-bridge/bridge_generated.io.rs,target=/source/src/bridge_generated.io.rs,readonly"
        )
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
            --mount "type=bind,source=$vendor,target=/vendor,readonly" \
            --mount "type=bind,source=$vendor_config,target=/inputs/config.toml,readonly" \
            "${toolchain_mount[@]}" \
            "${bridge_mounts[@]}" \
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
                sed "s#^directory = \"/online/cargo-vendor\"#directory = \"/vendor\"#" \
                    /inputs/config.toml >/tmp/cargo-home/config.toml
                [ "$(grep -Fc '\''directory = "/vendor"'\'' /tmp/cargo-home/config.toml)" -eq 1 ]
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
                            fs::tests:: --color never -- --test-threads=1
                        ;;
                    android-rust-lifecycle-tests)
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            android_listener_lifecycle::tests:: --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config \
                            direct_service::direct_connection_task_tests:: --color never -- --test-threads=1
                        cargo test --offline --locked --lib --features linux-pkg-config,flutter \
                            r_s11iu_ --color never -- --test-threads=1
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
    if [ "$MODE" = android-rust-lifecycle-tests ]; then
        grep -Fq 'R-B10 canary: build confirmed network-isolated (offline compile stage).' "$output" \
            || { tail -n 200 "$output" >&2; fail 'focused Rust build did not execute its offline network canary'; }
    fi
    mapfile -t result_lines < <(
        grep -E '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+s$' "$output"
    )
    if [ "$MODE" = hbb-common-fs ]; then
        [ "${#result_lines[@]}" -eq 1 ] \
            || { tail -n 200 "$output" >&2; fail 'focused filesystem test summary count differs'; }
    else
        [ "${#result_lines[@]}" -eq 3 ] \
            || { tail -n 200 "$output" >&2; fail 'Android Rust-lifecycle summary count differs'; }
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
    printf '%s\n' "${result_lines[@]}"
    if [ "$MODE" = hbb-common-fs ]; then
        printf 'HBB_COMMON_FS_VM=pass commit=%s tree=%s tests=%s rust=1.75.0 vendor=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
            "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$tests_passed" \
            "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$DEB_BUILDER_IMAGE_ID" \
            "$DEB_BUILDER_CONFIG_ID"
    else
        [ "$tests_passed" -eq 24 ] \
            || fail "Android Rust-lifecycle test count differs: $tests_passed"
        printf 'ANDROID_RUST_LIFECYCLE_VM=pass commit=%s tree=%s tests=%s target=linux-x86_64 scope=listener-generation-child-convergence-and-exact-resource-owners rust=1.75.0 flutter=3.24.5 llvm=15.0.6 frb=%s vendor=%s pub_cache=%s bridge_builder=%s devcheck_index=%s devcheck_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none source=readonly generated_bridge=readonly target_dir=private-ephemeral offline_canary=pass root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
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
    local entry_count online_verification_count
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
    mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs "$inputs" \
        || fail 'cannot mount the sealed Android Rust target-check input authority'
    SEALED_INPUTS_MOUNTED=1
    input_mount_options="$(findmnt -n -o OPTIONS --target "$inputs")" \
        || fail 'sealed Android Rust target-check input mount is absent'
    case ",$input_mount_options," in *,ro,*) ;; *) fail 'sealed Android Rust target-check inputs are writable' ;; esac
    case ",$input_mount_options," in *,nodev,*) ;; *) fail 'sealed Android Rust target-check inputs permit devices' ;; esac
    case ",$input_mount_options," in *,nosuid,*) ;; *) fail 'sealed Android Rust target-check inputs permit set-user-ID execution' ;; esac
    case ",$input_mount_options," in *,noexec,*) ;; *) fail 'sealed Android Rust target-check inputs permit direct execution' ;; esac

    install -d -o 1000 -g 1000 -m 0755 -- "$source_root/online" "$online_mount"
    mount --bind "$inputs" "$online_mount" \
        || fail 'cannot project the sealed closure into the Android Rust target-check source'
    ANDROID_RUST_ONLINE_MOUNTED=1
    mount -o remount,bind,ro,nodev,nosuid,noexec "$online_mount" \
        || fail 'cannot make the Android Rust target-check input projection read-only'
    online_mount_options="$(findmnt -n -o OPTIONS --target "$online_mount")" \
        || fail 'Android Rust target-check input projection is absent'
    case ",$online_mount_options," in *,ro,*) ;; *) fail 'Android Rust target-check input projection is writable' ;; esac
    case ",$online_mount_options," in *,nodev,*) ;; *) fail 'Android Rust target-check input projection permits devices' ;; esac
    case ",$online_mount_options," in *,nosuid,*) ;; *) fail 'Android Rust target-check input projection permits set-user-ID execution' ;; esac
    case ",$online_mount_options," in *,noexec,*) ;; *) fail 'Android Rust target-check input projection permits direct execution' ;; esac

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

    if /bin/bash "$source_root/scripts/android-rust-check.sh" \
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
        /bin/bash "$source_root/scripts/android-rust-check.sh" \
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
        /bin/bash "$source_root/scripts/android-rust-check.sh" \
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
    online_verification_count="$(grep -Fxc "verified $SHA256_ONLINE_CLOSURE_V1" "$output")"
    [ "$online_verification_count" -eq 2 ] \
        || { tail -n 240 "$output" >&2; fail 'Android Rust target check did not verify the full online closure before and after execution'; }
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
    printf 'ANDROID_RUST_TARGET_VM=pass commit=%s tree=%s target=aarch64-linux-android profile=release-check builder_index=%s builder_runtime=%s online=%s uid=1000 gid=1000 root=refused foreign=refused vm_network=none container_network=none inputs=readonly-landlocked source=exact-pushed offline_canary=pass cleanup=joined\n' \
        "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" \
        "$ANDROID_BUILDER_IMAGE_ID" "$ANDROID_BUILDER_CONFIG_ID" \
        "$SHA256_ONLINE_CLOSURE_V1"
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
        'ANDROID_OWNER_STATE_SUITE=pass classes=7 scenarios=15 assertions=293 kotlin=2.0.21' \
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
    printf 'ANDROID_OWNER_STATE_VM=pass commit=%s tree=%s classes=7 scenarios=15 assertions=293 kotlin=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none compiler_inputs=verified-copy-readonly root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
        "$ANDROID_OWNER_SOURCE_COMMIT" "$ANDROID_OWNER_SOURCE_TREE" \
        "$ANDROID_KOTLIN_VERSION" "$ANDROID_BUILDER_IMAGE_ID" \
        "$ANDROID_BUILDER_CONFIG_ID"
}

run_android_emulator_boot() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/android-emulator-source
    local output=$ROOT/android-emulator-boot.out
    local emulator_archive=$inputs/candidates/android-emulator/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip
    local system_archive=$inputs/candidates/android-emulator/arm64-v8a-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip
    local adb=$inputs/inputs/android-sdk/platform-tools/adb
    local runtime_archive=$inputs/inputs/verifier-images/devcheck.docker.tar.gz
    local source_archive_sha source_before inputs_before input_mount_options
    local load_output inspect namespace_inspect container_status=0 result_line
    local -a result_lines=()

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
      "1000:1000:400:1:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_ARM64" ] \
        && [ "$(sha256sum "$system_archive" | awk '{ print $1 }')" = \
             "$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_ARM64" ] \
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
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "Android emulator container namespace/device/port authority differs: $namespace_inspect"
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 200 "$output" >&2; fail "Android emulator boot exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 262144 ] \
        || fail 'Android emulator boot output exceeds its bound'
    mapfile -t result_lines < <(grep -E \
        '^ANDROID_EMULATOR_BOOT=pass emulator=37\.1\.11 api=34 abi=arm64-v8a acceleration=software framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined$' \
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
    printf '%s\n' "$result_line"
    printf 'ANDROID_EMULATOR_BOOT_VM=pass commit=%s tree=%s emulator=%s api=%s abi=arm64-v8a acceleration=software runtime_index=%s runtime_config=%s uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_EMULATOR_SOURCE_TREE" \
        "$ANDROID_EMULATOR_VERSION" "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" \
        "$DEV_CHECK_IMAGE_ID" "$DEV_CHECK_IMAGE_CONFIG_ID"
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
    local tools_freshness_line

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
            --memory=8g \
            --memory-swap=8g \
            --cpus=4 \
            --shm-size=1g \
            --ulimit nofile=8192:8192 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --mount "type=bind,source=$source_root,target=/source" \
            --mount "type=bind,source=$work_root,target=/work" \
            --mount "type=bind,source=$pub_cache,target=/online/pub-cache,readonly" \
            --mount "type=bind,source=$cargo_vendor,target=/online/cargo-vendor,readonly" \
            --mount "type=bind,source=$flutter_archive,target=/inputs/flutter.tar.xz,readonly" \
            --mount "type=bind,source=$rust_archive,target=/inputs/rust.tar.xz,readonly" \
            --mount "type=bind,source=$llvm_archive,target=/inputs/llvm.tar.xz,readonly" \
            --mount "type=bind,source=$cargo_config,target=/inputs/cargo-vendor-config.toml,readonly" \
            --mount "type=bind,source=$frb_codegen,target=/inputs/flutter_rust_bridge_codegen,readonly" \
            --mount "type=bind,source=$result_validator,target=/authority/result.py,readonly" \
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
                mkdir /work/toolchain /work/home /work/cargo-home /work/flutter-shim
                tar -C /work/toolchain -xf /inputs/rust.tar.xz
                tar -C /work/toolchain -xf /inputs/flutter.tar.xz
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
                [ "$project_lock" = "$(sha256sum /source/flutter/pubspec.lock | awk "{print \$1}")" ]
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
                [ "$project_lock" = "$(sha256sum /source/flutter/pubspec.lock | awk "{print \$1}")" ]
                tests=(
                    test/global_event_dispatcher_test.dart
                    test/server_status_refresh_loop_test.dart
                    test/display_selection_queue_test.dart
                    test/session_event_queue_test.dart
                    test/latest_frame_queue_test.dart
                    test/session_stream_finality_test.dart
                    test/mobile_session_start_queue_test.dart
                    test/desktop_texture_lifecycle_test.dart
                    test/desktop_tab_retirement_test.dart
                    test/presentation_recovery_test.dart
                    test/rgba_publication_order_test.dart
                    test/custom_cursor_registry_test.dart
                    test/start_ellipsis_text_test.dart
                )
                [ "${#tests[@]}" -eq 13 ]
                for test_path in "${tests[@]}"; do
                    [ -f "$test_path" ] && [ ! -L "$test_path" ]
                done
                if ! timeout --signal=TERM --kill-after=10s 900s \
                    flutter test --no-pub --reporter json --concurrency=4 \
                        --timeout=30s \
                        "${tests[@]}" >/work/test.json 2>/work/test.err; then
                    tail -n 240 /work/test.json /work/test.err >&2
                    exit 1
                fi
                [ "$(stat -c %s /work/test.err)" -le 1048576 ]
                [ ! -s /work/test.err ] || tail -n 120 /work/test.err >&2
                /usr/bin/python3 -I -S /authority/result.py /work/test.json
            '
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Flutter-test container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      'none|true|1000:1000|8589934592|8589934592|4000000000|2048|1073741824|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
        || fail "focused Flutter-test container authority differs: $inspect"
    namespace_inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}' \
        "$CONTAINER_ID")"
    [ "$namespace_inspect" = 'false||private||private|[]|{}' ] \
        || fail "focused Flutter-test container namespace/device/port authority differs: $namespace_inspect"
    "$CLIENT" --host "unix://$SOCK" start --attach "$CONTAINER_ID" \
        >"$output" 2>&1 || container_status=$?
    [ "$container_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "focused Flutter model tests exited with status $container_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 4194304 ] \
        || fail 'focused Flutter-test output exceeds its bound'
    tools_freshness_line="$(grep -Fx \
        "FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=$FLUTTER_VERSION lock=$SHA256_FLUTTER_TOOLS_LOCK implicit_pub=prevented" \
        "$output")" \
        || { tail -n 240 "$output" >&2; fail 'Flutter-tools offline-freshness receipt is absent'; }
    [ "$(grep -Fc 'FLUTTER_TOOLS_OFFLINE_FRESHNESS=' "$output")" -eq 1 ] \
        || fail 'Flutter-tools offline-freshness receipt is duplicated'
    result_line="$(grep -Fx 'FLUTTER_MODEL_TEST_JSON=pass suites=13 tests=107' "$output")" \
        || { tail -n 240 "$output" >&2; fail 'focused Flutter-test success summary is absent'; }
    [ "$(grep -Fc 'FLUTTER_MODEL_TEST_JSON=' "$output")" -eq 1 ] \
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
    printf '%s\n' "$result_line"
    printf 'FLUTTER_MODEL_TESTS_VM=pass commit=%s tree=%s suites=13 tests=107 flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=%s cargo_vendor=%s pub_cache=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default evidence=generated-bridge-model-tests cleanup=joined\n' \
        "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" \
        "$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
        "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        "$SHA256_PUB_CACHE_CLOSURE_V1" \
        "$DEB_BUILDER_IMAGE_ID" "$DEB_BUILDER_CONFIG_ID"
}

run_flutter_peer_presentation() {
    local sealed_root=/mnt/rustdesk-sealed-inputs
    local inputs=
    local source_root=$ROOT/flutter-peer-source
    local peer_script=$source_root/scripts/smoke-flutter-peer-presentation.sh
    local provenance=$source_root/scripts/offline-image-provenance.py
    local devcheck_archive= builder_archive= candidate_archive=
    local output=$ROOT/flutter-peer-presentation.out
    local source_archive_sha load_output mount_options peer_status=0 trace_abort
    local -a peer_args=()

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
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        [ "$(find "$sealed_root" -mindepth 1 -maxdepth 1 -printf '%f\n' \
            | LC_ALL=C sort)" = $'candidates\ninputs' ] \
            || fail 'candidate Flutter-peer authority root inventory differs'
        [ "$(stat -c '%u:%g:%a' -- "$sealed_root/inputs")" = 1000:1000:700 ] \
            && [ "$(stat -c '%u:%g:%a' -- "$sealed_root/candidates")" = \
                 1000:1000:700 ] \
            && [ "$(find "$sealed_root/candidates" -mindepth 1 -maxdepth 1 \
                -printf '%f\n' | LC_ALL=C sort)" = flutter-presentation ] \
            || fail 'candidate Flutter-peer namespace differs'
        [ "$(stat -c '%u:%g:%a' -- \
            "$sealed_root/candidates/flutter-presentation")" = 1000:1000:700 ] \
            && [ "$(find "$sealed_root/candidates/flutter-presentation" \
                -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" = \
                 $'flutter-'"${FLUTTER_PRESENTATION_CANDIDATE_VERSION}"$'.tar.xz\npub-cache\npubspec.lock.discovery' ] \
            || fail 'candidate Flutter-peer closure namespace differs'
        candidate_archive="$sealed_root/candidates/flutter-presentation/flutter-${FLUTTER_PRESENTATION_CANDIDATE_VERSION}.tar.xz"
        candidate_lock="$sealed_root/candidates/flutter-presentation/pubspec.lock.discovery"
        candidate_pub_cache="$sealed_root/candidates/flutter-presentation/pub-cache"
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
        inputs=$sealed_root/inputs
    else
        inputs=$sealed_root
    fi
    devcheck_archive=$inputs/verifier-images/devcheck.docker.tar.gz
    builder_archive=$inputs/build-images/deb-builder.docker.tar.gz

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$devcheck_archive")" = \
      "1000:1000:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        && [ "$(sha256sum "$devcheck_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'sealed devcheck image archive differs'
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$builder_archive")" = \
      "1000:1000:400:1:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" ] \
        && [ "$(sha256sum "$builder_archive" | awk '{ print $1 }')" = \
             "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" ] \
        || fail 'sealed Debian-builder image archive differs'

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
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        peer_args+=(--flutter-presentation-candidate "$candidate_archive")
    fi
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        /bin/bash "$peer_script" "${peer_args[@]}" \
        2>&1 | tee "$output"
    peer_status=${PIPESTATUS[0]}
    set -e
    [ "$peer_status" -eq 0 ] \
        || { tail -n 240 "$output" >&2; fail "Flutter full-peer workload exited with status $peer_status"; }
    [ "$(stat -c '%s' -- "$output")" -le 8388608 ] \
        || fail 'Flutter full-peer workload output exceeds its bound'
    [ "$(grep -Fxc \
      "FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=$FLUTTER_PEER_SOURCE_COMMIT tree=$FLUTTER_PEER_SOURCE_TREE archive_sha256=$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256 flutter=$FLUTTER_PEER_RUNTIME_VERSION tools=$FLUTTER_PEER_TOOLS_MODE scope=linux-x11-full-peer-focus-reconnect-resource network=owned-none-namespace" \
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
    [ -z "$("$CLIENT" --host "unix://$SOCK" ps -aq)" ] \
        || fail 'Flutter full-peer workload left a container'
    "$CLIENT" --host "unix://$SOCK" image rm \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$DEB_BUILDER_CONFIG_ID" >/dev/null \
        || fail 'Flutter full-peer images could not be retired'
    [ -z "$("$CLIENT" --host "unix://$SOCK" image ls -aq)" ] \
        || fail 'Flutter full-peer workload left an image'
    [ "$(sha256sum "$FLUTTER_PEER_SOURCE_ARCHIVE" | awk '{ print $1 }')" = \
      "$source_archive_sha" ] \
        || fail 'focused Flutter-peer source archive changed during execution'
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
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
    umount "$sealed_root" || fail 'cannot retire the sealed Flutter-peer input mount'
    SEALED_INPUTS_MOUNTED=0
    printf 'FLUTTER_PEER_PRESENTATION_VM=pass commit=%s tree=%s archive=%s flutter=%s tools=%s candidate=%s devcheck_index=%s devcheck_runtime=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 nofile=524544 root=refused foreign=refused caller=refused vm_network=none container_network=owned-none-namespace inputs=readonly-landlocked cleanup=joined\n' \
        "$FLUTTER_PEER_SOURCE_COMMIT" "$FLUTTER_PEER_SOURCE_TREE" \
        "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" "$FLUTTER_PEER_RUNTIME_VERSION" \
        "$FLUTTER_PEER_TOOLS_MODE" "$FLUTTER_PEER_CANDIDATE" "$DEV_CHECK_IMAGE_ID" \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$DEB_BUILDER_IMAGE_ID" "$DEB_BUILDER_CONFIG_ID"
}

cleanup() {
    local status=$? daemon_status=0
    trap - EXIT HUP INT TERM
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
    if [ "$SEALED_INPUTS_MOUNTED" -eq 1 ]; then
        umount /mnt/rustdesk-sealed-inputs 2>/dev/null || status=1
        SEALED_INPUTS_MOUNTED=0
    fi
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
for verify_source in verify.sh verify-release.sh build-release.sh \
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
    smoke-android-emulator-boot.sh \
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
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ] \
   || [ "$MODE" = flutter-model-tests ] \
   || [ "$MODE" = android-owner-tests ] \
   || [ "$MODE" = android-emulator-boot ] \
   || [ "$MODE" = flutter-peer-presentation ] \
   || [ "$MODE" = rust-audit ]; then
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

if [ "$MODE" = android-emulator-boot ]; then
    run_android_emulator_boot
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

cp --parents -L /bin/dash "$ROOT/rootfs"
while IFS= read -r library; do
    [ -f "$library" ] || fail "shell dependency is absent: $library"
    cp --parents -L "$library" "$ROOT/rootfs"
done < <(ldd /bin/dash | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' | LC_ALL=C sort -u)
ln -s dash "$ROOT/rootfs/bin/sh"
# The staging parent remains root-private, while the filesystem imported into
# the image must be traversable by its declared numeric non-root user. Make the
# entire minimal image root-owned and immutable before serialization.
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

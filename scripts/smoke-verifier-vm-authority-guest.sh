#!/usr/bin/env bash
set -euo pipefail
umask 077

case "$#:${8:-}" in
    7:)
        MODE=authority-smoke
        ;;
    12:--hbb-common-fs)
        MODE=hbb-common-fs
        ;;
    12:--flutter-model-tests)
        MODE=flutter-model-tests
        ;;
    12:--debian-systemd-lifecycle)
        MODE=debian-systemd-lifecycle
        ;;
    *)
        echo 'usage: smoke-verifier-vm-authority-guest.sh DOCKER_TGZ ENTRY_PREFLIGHT VERSION SIZE SHA256 KERNEL_RELEASE ROOT_UUID [--hbb-common-fs SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --flutter-model-tests SOURCE_ARCHIVE COMMIT TREE SOURCE_ARCHIVE_SHA256 | --debian-systemd-lifecycle DEV_CHECK_ARCHIVE DEB DEB_SHA256 COMMIT]' >&2
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
readonly MODE
readonly HBB_SOURCE_ARCHIVE=${9:-}
readonly HBB_SOURCE_COMMIT=${10:-}
readonly HBB_SOURCE_TREE=${11:-}
readonly HBB_SOURCE_ARCHIVE_SHA256=${12:-}
readonly FLUTTER_SOURCE_ARCHIVE=${9:-}
readonly FLUTTER_SOURCE_COMMIT=${10:-}
readonly FLUTTER_SOURCE_TREE=${11:-}
readonly FLUTTER_SOURCE_ARCHIVE_SHA256=${12:-}
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
readonly OFFLINE_IMAGE_PROVENANCE=$VERIFY_REPO/scripts/offline-image-provenance.py
readonly DART_AUDIT_SCRIPT=$VERIFY_REPO/scripts/dart-audit.sh
readonly IMAGE=rustdesk-verifier-authority-probe:v1
readonly CONTAINER=rustdesk-verifier-authority-probe
readonly GIT_RUNTIME_ROOT=/opt/rustdesk-verifier-git

DAEMON_PID=
CONTAINER_ID=
LIFECYCLE_LIBS_MOUNTED=0
SEALED_INPUTS_MOUNTED=0

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
                --source-commit "$DEV_CHECK_SOURCE_COMMIT" \
                --source-repository "$DEV_CHECK_SOURCE_REPOSITORY" \
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
    if [[ "${stage_receipt[1]}" =~ ^DEBIAN_SYSTEMD_RUNTIME_LIBS=pass\ image=$DEV_CHECK_IMAGE_ID\ libraries=([0-9]+)\ bytes=([0-9]+)\ input=readonly\ output=private$ ]]; then
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

run_hbb_common_fs() {
    local inputs=/mnt/rustdesk-sealed-inputs
    local source_root=$ROOT/hbb-common-fs-source
    local output=$ROOT/hbb-common-fs.out
    local rust_archive=$inputs/rust-1.75.tar.xz
    local vendor=$inputs/cargo-vendor
    local vendor_config=$inputs/cargo-vendor-config.toml
    local builder_archive=$inputs/build-images/deb-builder.docker.tar.gz
    local load_output container_status=0 inspect namespace_inspect result_line tests_passed
    local source_archive_sha source_before input_mount_options
    local -a required_tests=(
        r_s11hm_remove_empty_directory_tree_removes_the_complete_empty_tree
        r_s11hm_remove_empty_directory_tree_reports_a_nonempty_tree
        r_s11hm_nonrecursive_directory_removal_uses_empty_only_finality
        r_s11hm_remove_empty_directory_tree_refuses_a_directory_symlink_root
        r_s11hm_remove_empty_directory_tree_unlinks_nested_symlink_without_traversal
        r_s11hm_retained_directory_refuses_a_replacement_root_edge
        r_s11hm_remove_empty_directory_tree_enforces_depth_bound
        r_s11hm_remove_file_refuses_a_symlinked_parent
        remove_file_rejects_empty_path
        remove_file_rejects_null_byte_path
        create_dir_rejects_empty_path
        create_dir_rejects_null_byte_path
        create_dir_creates_a_legitimate_nested_tree_idempotently
        create_dir_rejects_parent_traversal_before_any_component_is_created
        create_dir_refuses_a_symlink_parent_without_mutating_its_target
        rename_file_rejects_invalid_new_name
        rename_file_accepts_valid_new_name
        rename_file_replaces_a_symlink_leaf_without_touching_its_target
        rename_file_refuses_a_symlink_parent_without_mutating_its_target
        rename_admitted_entry_refuses_a_replaced_source_name
        rename_admitted_entry_stays_with_its_retained_parent_after_path_swap
    )

    [[ "$HBB_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-test source commit is malformed'
    [[ "$HBB_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'focused Rust-test source tree is malformed'
    [[ "$HBB_SOURCE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust-test source archive digest is malformed'
    [ -f "$HBB_SOURCE_ARCHIVE" ] && [ ! -L "$HBB_SOURCE_ARCHIVE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$HBB_SOURCE_ARCHIVE")" = 4000:4000:400:1 ] \
        || fail 'focused Rust-test source archive metadata differs'
    source_archive_sha="$(sha256sum "$HBB_SOURCE_ARCHIVE" | awk '{ print $1 }')"
    [ "$source_archive_sha" = "$HBB_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-test source archive digest differs'

    rm -rf -- "$source_root"
    mkdir "$source_root"
    tar -xf "$HBB_SOURCE_ARCHIVE" --no-same-owner --no-same-permissions \
        -C "$source_root" \
        || fail 'cannot extract the exact focused-test source archive'
    chown -R 1000:1000 "$source_root"
    [ "$(sha256sum "$source_root/scripts/smoke-verifier-vm-authority-guest.sh" \
              | awk '{ print $1 }')" = \
      "$(sha256sum "${BASH_SOURCE[0]}" | awk '{ print $1 }')" ] \
        || fail 'focused-test source archive differs from its guest bootstrap'
    source_before="$source_archive_sha:$(sha256sum "$source_root/Cargo.lock" \
        "$source_root/libs/hbb_common/src/fs.rs")"

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

    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$rust_archive")" = \
      "1000:1000:400:1:$SIZE_RUST_1_75" ] \
        && [ "$(sha256sum "$rust_archive" | awk '{ print $1 }')" = "$SHA256_RUST_1_75" ] \
        || fail 'sealed Rust 1.75 archive differs'
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
            --name rustdesk-hbb-common-fs \
            --pull=never \
            --network=none \
            --read-only \
            --pids-limit=1024 \
            --memory=8g \
            --memory-swap=8g \
            --cpus=4 \
            --ulimit nofile=4096:4096 \
            --ulimit core=0:0 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --security-opt=apparmor=docker-default \
            --user 1000:1000 \
            --mount "type=bind,source=$source_root,target=/source" \
            --mount "type=bind,source=$vendor,target=/vendor,readonly" \
            --mount "type=bind,source=$vendor_config,target=/inputs/config.toml,readonly" \
            --mount "type=bind,source=$rust_archive,target=/inputs/rust.tar.xz,readonly" \
            --tmpfs /tmp:rw,exec,nosuid,nodev,size=10g,mode=700,uid=1000,gid=1000 \
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
                mkdir /tmp/toolchain /tmp/rust /tmp/home /tmp/cargo-home /tmp/cargo-target
                tar -C /tmp/toolchain -xf /inputs/rust.tar.xz
                /tmp/toolchain/rust-1.75.0-x86_64-unknown-linux-gnu/install.sh \
                    --prefix=/tmp/rust --disable-ldconfig >/dev/null
                sed "s#^directory = \"/online/cargo-vendor\"#directory = \"/vendor\"#" \
                    /inputs/config.toml >/tmp/cargo-home/config.toml
                [ "$(grep -Fc '\''directory = "/vendor"'\'' /tmp/cargo-home/config.toml)" -eq 1 ]
                export HOME=/tmp/home CARGO_HOME=/tmp/cargo-home \
                    CARGO_TARGET_DIR=/tmp/cargo-target RUSTUP_HOME=/nonexistent \
                    RUSTUP_TOOLCHAIN= PATH=/tmp/rust/bin:/usr/bin:/bin \
                    LANG=C LC_ALL=C CARGO_NET_OFFLINE=true
                [ "$(rustc --version)" = "rustc 1.75.0 (82e1608df 2023-12-21)" ]
                [ "$(cargo --version)" = "cargo 1.75.0 (1d8b05cdd 2023-11-20)" ]
                cargo test --offline --locked -p hbb_common --lib \
                    fs::tests:: --color never -- --test-threads=1
            '
    )"
    [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'focused Rust-test container ID is malformed'
    inspect="$("$CLIENT" --host "unix://$SOCK" inspect --format \
        '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$CONTAINER_ID")"
    [ "$inspect" = \
      'none|true|1000:1000|8589934592|8589934592|4000000000|1024|["ALL"]|["no-new-privileges","apparmor=docker-default"]' ] \
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
    result_line="$(grep -E '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+s$' "$output")" \
        || { tail -n 200 "$output" >&2; fail 'focused Rust-test success summary is absent'; }
    [ "$(grep -Ec '^test result: ' "$output")" -eq 1 ] \
        || fail 'focused Rust-test result summary is duplicated'
    tests_passed="$(printf '%s\n' "$result_line" | sed -E 's/^test result: ok\. ([0-9]+) passed;.*/\1/')"
    for test_name in "${required_tests[@]}"; do
        grep -Fxq "test fs::tests::$test_name ... ok" "$output" \
            || { tail -n 200 "$output" >&2; fail "load-bearing filesystem test did not pass: $test_name"; }
    done
    [ "$("$CLIENT" --host "unix://$SOCK" inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
        || fail 'focused Rust-test container did not exit cleanly'
    "$CLIENT" --host "unix://$SOCK" rm "$CONTAINER_ID" >/dev/null
    CONTAINER_ID=
    "$CLIENT" --host "unix://$SOCK" image rm "$DEB_BUILDER_CONFIG_ID" >/dev/null
    [ "$source_before" = \
      "$source_archive_sha:$(sha256sum "$source_root/Cargo.lock" \
          "$source_root/libs/hbb_common/src/fs.rs")" ] \
        || fail 'focused Rust-test source inputs changed during execution'
    stop_docker_authority
    umount "$inputs" || fail 'cannot retire the sealed focused-test input mount'
    SEALED_INPUTS_MOUNTED=0
    printf '%s\n' "$result_line"
    printf 'HBB_COMMON_FS_VM=pass commit=%s tree=%s tests=%s rust=1.75.0 vendor=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined\n' \
        "$HBB_SOURCE_COMMIT" "$HBB_SOURCE_TREE" "$tests_passed" \
        "$SHA256_CARGO_VENDOR_CLOSURE_V1" "$DEB_BUILDER_IMAGE_ID" \
        "$DEB_BUILDER_CONFIG_ID"
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
                )
                [ "${#tests[@]}" -eq 12 ]
                for test_path in "${tests[@]}"; do
                    [ -f "$test_path" ] && [ ! -L "$test_path" ]
                done
                if ! timeout --signal=TERM --kill-after=10s 900s \
                    flutter test --no-pub --reporter json --concurrency=4 \
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
    result_line="$(grep -Fx 'FLUTTER_MODEL_TEST_JSON=pass suites=12 tests=102' "$output")" \
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
    printf '%s\n' "$result_line"
    printf 'FLUTTER_MODEL_TESTS_VM=pass commit=%s tree=%s suites=12 tests=102 flutter=3.24.5 rust=1.75.0 llvm=15.0.6 frb=%s cargo_vendor=%s pub_cache=%s builder_index=%s builder_runtime=%s uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default evidence=generated-bridge-model-tests cleanup=joined\n' \
        "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" \
        "$SHA256_FLUTTER_PEER_FRB_CODEGEN" \
        "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        "$SHA256_PUB_CACHE_CLOSURE_V1" \
        "$DEB_BUILDER_IMAGE_ID" "$DEB_BUILDER_CONFIG_ID"
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
    smoke-flutter-peer-presentation.sh frb-codegen.sh dart-verify.sh smoke-server.sh \
    audit.sh rust-audit-policy.py verify-rust-audit-authority.py \
    gen-android-keystore.sh android-keystore-generate.sh \
    verify-android-keystore-authority.py \
    build-android.sh verify-android-builder-authority.py \
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
    online-fetch.sh android-rust-check.sh \
    dart-audit.sh dart-audit-result.py \
    verify-dart-verifier-authority.py verify-dart-audit-authority.py \
    smoke-verifier-vm-authority.sh smoke-verifier-vm-authority-guest.sh \
    verify-vm-entry-preflight.sh verify-scan.sh \
    verify-private-tree-closure.py lib.sh pins.env; do
    verify_path="$VERIFY_REPO/scripts/$verify_source"
    [ -f "$verify_path" ] && [ ! -L "$verify_path" ] \
        || fail "main verifier entry source is absent or ambiguous: $verify_source"
done
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
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = flutter-model-tests ]; then
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

if [ "$MODE" = hbb-common-fs ]; then
    run_hbb_common_fs
    exit 0
fi

if [ "$MODE" = flutter-model-tests ]; then
    run_flutter_model_tests
    exit 0
fi

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
ulimit -Hn 524544 || fail 'verifier descriptor hard limit cannot be established'
ulimit -Sn 524544 || fail 'verifier descriptor soft limit cannot be established'
[ "$(ulimit -Sn):$(ulimit -Hn)" = 524544:524544 ] \
    || fail 'verifier descriptor limit differs'
main_entry_output="$(
    setpriv --reuid=4000 --regid=4000 --clear-groups \
        /bin/bash "$VERIFY_SCRIPT" --self-test-workspace
)" || fail 'numeric-nonroot main verifier entry failed'
expected_main_entry_output="VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$EXPECTED_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root
verify workspace self-test: OK"
[ "$main_entry_output" = "$expected_main_entry_output" ] \
    || fail "main verifier entry result differs: $main_entry_output"
printf '%s\n' "$main_entry_output"
printf 'VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 foreign=refused nofile=524544 workspace_cleanup=joined\n'

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

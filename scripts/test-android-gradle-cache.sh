#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_TEST_ROOT=/android-gradle-test
HOST_FIXTURE=""

cleanup_host_fixture() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$HOST_FIXTURE" ] && [ -d "$HOST_FIXTURE" ]; then
        chmod -R u+rwX "$HOST_FIXTURE" 2>/dev/null || status=1
        rm -rf -- "$HOST_FIXTURE" || status=1
    fi
    exit "$status"
}

trap cleanup_host_fixture EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

inside_container() {
    [ "$(id -u)" -ne 0 ] \
        || { echo "Android Gradle cache test requires non-root execution" >&2; exit 1; }
    for test_file in \
        android-gradle-cache.py \
        android-gradle-offline.init.gradle \
        android-apk-build.sh \
        test-android-gradle-cache.sh; do
        [ "$(stat -c '%u:%g' "$CONTAINER_TEST_ROOT/$test_file")" = "$(id -u):$(id -g)" ] \
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
        grep -Fq 'APK_MODE must be exactly offline or warm' /tmp/invalid-apk-mode-output
    done
    if env -u APK_MODE /bin/bash "$CONTAINER_TEST_ROOT/android-apk-build.sh" \
        >/tmp/invalid-apk-mode-output 2>&1; then
        echo "Android build accepted absent APK_MODE" >&2
        exit 1
    fi
    grep -Fq 'APK_MODE must be exactly offline or warm' /tmp/invalid-apk-mode-output

    if APK_MODE=offline RUSTDESK_GRADLE_OFFLINE=1 \
        /bin/bash "$CONTAINER_TEST_ROOT/android-apk-build.sh" >/tmp/internal-flag-output 2>&1; then
        echo "Android build accepted an externally supplied internal offline flag" >&2
        exit 1
    fi
    grep -Fq 'RUSTDESK_GRADLE_OFFLINE is build-internal' /tmp/internal-flag-output

    rm -rf /tmp/gradle-home
    echo "ANDROID-GRADLE-CACHE: immutable projection and pinned Gradle offline semantics are GREEN"
}

case "${1:-}" in
    --inside)
        [ "$#" -eq 1 ] \
            || { echo "test-android-gradle-cache: --inside takes no arguments" >&2; exit 2; }
        inside_container
        ;;
    "")
        # shellcheck source=scripts/lib.sh
        source "$SCRIPT_DIR/lib.sh"
        load_pins
        require_cmd docker find readlink stat
        require_online_complete
        require_pinned_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID"

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

        HOST_FIXTURE="$(mktemp -d /tmp/android-gradle-mount-test.XXXXXXXXXX)" \
            || die "cannot create Gradle mount-crossing fixture"
        install -d -m 0700 "$HOST_FIXTURE/seed" "$HOST_FIXTURE/overlay"
        install -d -m 0500 "$HOST_FIXTURE/seed/nested"
        printf 'same-filesystem nested bind\n' > "$HOST_FIXTURE/overlay/payload"
        chmod 0400 "$HOST_FIXTURE/overlay/payload"
        chmod 0500 "$HOST_FIXTURE/seed" "$HOST_FIXTURE/overlay"
        # ANDROID_GRADLE_MOUNT_REJECTION_DOCKER_BEGIN
        if docker run --rm --pull=never --network=none --read-only \
            --user "$(id -u):$(id -g)" \
            --cap-drop=ALL \
            --security-opt no-new-privileges \
            --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
            -v "$SCRIPT_DIR/android-gradle-cache.py:$CONTAINER_TEST_ROOT/android-gradle-cache.py:ro" \
            -v "$SCRIPT_DIR/android-gradle-offline.init.gradle:$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle:ro" \
            -v "$HOST_FIXTURE/seed:/seed:ro" \
            -v "$HOST_FIXTURE/overlay:/seed/nested:ro" \
            "$ANDROID_BUILDER_IMAGE_ID" \
            python3 -I -S "$CONTAINER_TEST_ROOT/android-gradle-cache.py" materialize \
                --source /seed \
                --init-script "$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle" \
                >"$HOST_FIXTURE/mount-output" 2>&1; then
            die "Gradle cache projector accepted a same-filesystem descendant bind mount"
        fi
        grep -Fq 'Gradle cache seed contains a descendant mount: /seed/nested' \
            "$HOST_FIXTURE/mount-output" \
            || die "Gradle cache descendant-mount rejection produced the wrong diagnostic"
        # ANDROID_GRADLE_MOUNT_REJECTION_DOCKER_END

        # ANDROID_GRADLE_SEMANTICS_DOCKER_BEGIN
        docker run --rm --pull=never --network=none --read-only \
            --user "$(id -u):$(id -g)" \
            --cap-drop=ALL \
            --security-opt no-new-privileges \
            --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
            -v "$SCRIPT_DIR/android-gradle-cache.py:$CONTAINER_TEST_ROOT/android-gradle-cache.py:ro" \
            -v "$SCRIPT_DIR/android-gradle-offline.init.gradle:$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle:ro" \
            -v "$SCRIPT_DIR/android-apk-build.sh:$CONTAINER_TEST_ROOT/android-apk-build.sh:ro" \
            -v "$SCRIPT_DIR/test-android-gradle-cache.sh:$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh:ro" \
            -v "$gradle_root:/gradle-distribution:ro" \
            "$ANDROID_BUILDER_IMAGE_ID" \
            /bin/bash "$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh" --inside
        # ANDROID_GRADLE_SEMANTICS_DOCKER_END
        ;;
    *)
        echo "usage: scripts/test-android-gradle-cache.sh [--inside]" >&2
        exit 2
        ;;
esac

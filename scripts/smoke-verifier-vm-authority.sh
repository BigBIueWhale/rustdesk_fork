#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
[ "$HOST_UID" -ne 0 ] \
    || { echo 'verifier-VM authority smoke: host or container-root execution is forbidden' >&2; exit 1; }
[ "$HOST_GID" -ne 0 ] \
    || { echo 'verifier-VM authority smoke: a root primary group is forbidden' >&2; exit 1; }
readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

MODE=authority-smoke
LIFECYCLE_ARTIFACT=
LIFECYCLE_ARTIFACT_SHA256=
LIFECYCLE_COMMIT=
DEV_CHECK_ARCHIVE=
FLUTTER_PEER_CANDIDATE=0
ANDROID_RUNTIME_ARTIFACT_COMMIT=
ANDROID_RUNTIME_APK_SHA256=
case "$#:${1:-}" in
    0:)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'verifier-VM input/run overrides are lifecycle-internal' >&2; exit 2; }
        ;;
    1:--hbb-common-fs)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Rust-test input/run overrides are forbidden' >&2; exit 2; }
        MODE=hbb-common-fs
        ;;
    1:--android-rust-lifecycle-tests)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Android Rust-lifecycle input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-rust-lifecycle-tests
        ;;
    1:--android-rust-target-check)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'Android Rust target-check input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-rust-target-check
        ;;
    1:--flutter-model-tests)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Flutter-test input/run overrides are forbidden' >&2; exit 2; }
        MODE=flutter-model-tests
        ;;
    1:--android-owner-tests)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Android owner-state input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-owner-tests
        ;;
    1:--android-emulator-boot)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'Android emulator boot input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-emulator-boot
        ;;
    1:--android-emulator-app)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'Android emulator app input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-emulator-app
        ;;
    5:--android-emulator-runtime)
        [ "$2" = --artifact-commit ] && [ "$4" = --apk-sha256 ] \
            || { echo 'invalid Android emulator runtime argument order' >&2; exit 2; }
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'Android emulator runtime input/run overrides are forbidden' >&2; exit 2; }
        MODE=android-emulator-runtime
        ANDROID_RUNTIME_ARTIFACT_COMMIT=$3
        ANDROID_RUNTIME_APK_SHA256=$5
        ;;
    1:--apple-conform)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'Apple conformance input/run overrides are forbidden' >&2; exit 2; }
        MODE=apple-conform
        ;;
    1:--dart-audit)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Dart-audit input/run overrides are forbidden' >&2; exit 2; }
        MODE=dart-audit
        ;;
    1:--rust-audit)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Rust-audit input/run overrides are forbidden' >&2; exit 2; }
        MODE=rust-audit
        ;;
    1:--flutter-peer-presentation)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'focused Flutter peer input/run overrides are forbidden' >&2; exit 2; }
        MODE=flutter-peer-presentation
        ;;
    1:--flutter-peer-presentation-candidate)
        [ -z "${VERIFIER_VM_INPUT_ROOT+x}" ] \
            && [ -z "${VERIFIER_VM_RUN_ROOT+x}" ] \
            || { echo 'candidate Flutter peer input/run overrides are forbidden' >&2; exit 2; }
        MODE=flutter-peer-presentation
        FLUTTER_PEER_CANDIDATE=1
        ;;
    9:--debian-systemd-lifecycle)
        [ "$2" = --release-deb ] && [ "$4" = --sha256 ] \
            && [ "$6" = --commit ] && [ "$8" = --devcheck-archive ] \
            || { echo 'invalid Debian systemd lifecycle argument order' >&2; exit 2; }
        MODE=debian-systemd-lifecycle
        LIFECYCLE_ARTIFACT=$3
        LIFECYCLE_ARTIFACT_SHA256=$5
        LIFECYCLE_COMMIT=$7
        DEV_CHECK_ARCHIVE=$9
        [ -n "${VERIFIER_VM_INPUT_ROOT:-}" ] \
            && [ -n "${VERIFIER_VM_RUN_ROOT:-}" ] \
            || { echo 'Debian systemd lifecycle requires private VM input and run roots' >&2; exit 2; }
        ;;
    *)
        printf 'usage: %s [--hbb-common-fs | --android-rust-lifecycle-tests | --android-rust-target-check | --flutter-model-tests | --android-owner-tests | --android-emulator-boot | --android-emulator-app | --android-emulator-runtime --artifact-commit COMMIT --apk-sha256 SHA256 | --apple-conform | --flutter-peer-presentation | --flutter-peer-presentation-candidate | --dart-audit | --rust-audit | --debian-systemd-lifecycle --release-deb ABSOLUTE_DEB --sha256 SHA256 --commit COMMIT --devcheck-archive ABSOLUTE_ARCHIVE]\n' "${0##*/}" >&2
        exit 2
        ;;
esac
readonly MODE LIFECYCLE_ARTIFACT LIFECYCLE_ARTIFACT_SHA256 LIFECYCLE_COMMIT \
    DEV_CHECK_ARCHIVE FLUTTER_PEER_CANDIDATE ANDROID_RUNTIME_ARTIFACT_COMMIT \
    ANDROID_RUNTIME_APK_SHA256
readonly INPUT_ROOT="${VERIFIER_VM_INPUT_ROOT:-$REPO_ROOT/.harness-state/verifier-vm}"
readonly RUN_ROOT="${VERIFIER_VM_RUN_ROOT:-$INPUT_ROOT}"
readonly IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly BASE="$INPUT_ROOT/$IMAGE_NAME"
readonly DOCKER_BUNDLE="$INPUT_ROOT/docker-${VERIFIER_VM_DOCKER_VERSION}.tgz"
readonly GIT_PACKAGE="$INPUT_ROOT/git_${VERIFIER_VM_GIT_PACKAGE_FILENAME_VERSION}_amd64.deb"
readonly BOOT_ROOT="$INPUT_ROOT/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"
readonly KERNEL="$BOOT_ROOT/vmlinuz"
readonly INITRD="$BOOT_ROOT/initrd.img"
readonly VIRTIOFSD_PACKAGE="$INPUT_ROOT/virtiofsd_${VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION}_amd64.deb"
readonly VIRTIOFSD_LAUNCHER="$SCRIPT_DIR/launch-landlocked-virtiofsd.py"
readonly ONLINE_INPUTS="$REPO_ROOT/online/inputs"
readonly ANDROID_EMULATOR_CANDIDATE_ROOT="$REPO_ROOT/online/candidates/android-emulator"
readonly ANDROID_EMULATOR_ARCHIVE="$ANDROID_EMULATOR_CANDIDATE_ROOT/emulator-linux_x64-${ANDROID_EMULATOR_ARCHIVE_BUILD}.zip"
readonly ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE="$ANDROID_EMULATOR_CANDIDATE_ROOT/x86_64-${ANDROID_EMULATOR_SYSTEM_IMAGE_API}_r${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}.zip"
readonly ANDROID_EMULATOR_ADB="$ONLINE_INPUTS/android-sdk/platform-tools/adb"
readonly ANDROID_EMULATOR_X86_STD="$ANDROID_EMULATOR_CANDIDATE_ROOT/rust-std-1.75-x86_64-linux-android.tar.xz"
readonly ANDROID_EMULATOR_X86_VCPKG="$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg/installed/x64-android"
readonly ANDROID_EMULATOR_FLUTTER_MAVEN="$ANDROID_EMULATOR_CANDIDATE_ROOT/flutter-maven"
readonly ANDROID_EMULATOR_FLUTTER_EMBEDDING_JAR="$ANDROID_EMULATOR_FLUTTER_MAVEN/flutter_embedding_release-${FLUTTER_ANDROID_MAVEN_VERSION}.jar"
readonly ANDROID_EMULATOR_FLUTTER_EMBEDDING_POM="$ANDROID_EMULATOR_FLUTTER_MAVEN/flutter_embedding_release-${FLUTTER_ANDROID_MAVEN_VERSION}.pom"
readonly ANDROID_EMULATOR_FLUTTER_X86_64_JAR="$ANDROID_EMULATOR_FLUTTER_MAVEN/x86_64_release-${FLUTTER_ANDROID_MAVEN_VERSION}.jar"
readonly ANDROID_EMULATOR_FLUTTER_X86_64_POM="$ANDROID_EMULATOR_FLUTTER_MAVEN/x86_64_release-${FLUTTER_ANDROID_MAVEN_VERSION}.pom"
readonly FLUTTER_PEER_CANDIDATE_ROOT="$REPO_ROOT/online/candidates/flutter-presentation"
readonly FLUTTER_PEER_CANDIDATE_ARCHIVE="$FLUTTER_PEER_CANDIDATE_ROOT/flutter-${FLUTTER_PRESENTATION_CANDIDATE_VERSION}.tar.xz"
readonly FLUTTER_PEER_CANDIDATE_LOCK="$FLUTTER_PEER_CANDIDATE_ROOT/pubspec.lock.discovery"
readonly FLUTTER_PEER_CANDIDATE_PUB_CACHE="$FLUTTER_PEER_CANDIDATE_ROOT/pub-cache"
readonly RUST_TEST_ARCHIVE="$ONLINE_INPUTS/rust-${RUST_VERSION}.tar.xz"
readonly FLUTTER_TEST_ARCHIVE="$ONLINE_INPUTS/flutter-${FLUTTER_VERSION}.tar.xz"
readonly LLVM_TEST_ARCHIVE="$ONLINE_INPUTS/llvm-${LLVM_VERSION}.tar.xz"
readonly FRB_CODEGEN="$ONLINE_INPUTS/frb-tool/bin/flutter_rust_bridge_codegen"
readonly PUB_CACHE_ROOT="$ONLINE_INPUTS/pub-cache"
readonly CARGO_VENDOR_ROOT="$ONLINE_INPUTS/cargo-vendor"
readonly CARGO_VENDOR_CONFIG="$ONLINE_INPUTS/cargo-vendor-config.toml"
readonly DEB_BUILDER_ARCHIVE="$ONLINE_INPUTS/build-images/deb-builder.docker.tar.gz"
readonly ANDROID_BUILDER_ARCHIVE="$ONLINE_INPUTS/build-images/android-builder.docker.tar.gz"
readonly DEV_CHECK_IMAGE_ARCHIVE="$ONLINE_INPUTS/verifier-images/devcheck.docker.tar.gz"
readonly APPLE_CHECK_IMAGE_ARCHIVE="$ONLINE_INPUTS/verifier-images/apple-check.docker.tar.gz"
readonly DART_AUDIT_IMAGE_ARCHIVE="$ONLINE_INPUTS/verifier-images/dart-audit.docker.tar.gz"
readonly RUST_AUDIT_IMAGE_ARCHIVE="$ONLINE_INPUTS/verifier-images/rust-audit.docker.tar.gz"
FLUTTER_PEER_FLUTTER_VERSION=$FLUTTER_VERSION
FLUTTER_PEER_FLUTTER_ARCHIVE=$FLUTTER_TEST_ARCHIVE
FLUTTER_PEER_FLUTTER_SHA256=$SHA256_FLUTTER_3_24_5
FLUTTER_PEER_FLUTTER_SIZE=$SIZE_FLUTTER_3_24_5
FLUTTER_PEER_TOOLS_MODE=offline-resolved
FLUTTER_PEER_PUB_CACHE_ROOT=$PUB_CACHE_ROOT
SEALED_INPUT_ROOT=$ONLINE_INPUTS
if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
    FLUTTER_PEER_FLUTTER_VERSION=$FLUTTER_PRESENTATION_CANDIDATE_VERSION
    FLUTTER_PEER_FLUTTER_ARCHIVE=$FLUTTER_PEER_CANDIDATE_ARCHIVE
    FLUTTER_PEER_FLUTTER_SHA256=$SHA256_FLUTTER_PRESENTATION_CANDIDATE
    FLUTTER_PEER_FLUTTER_SIZE=$SIZE_FLUTTER_PRESENTATION_CANDIDATE
    FLUTTER_PEER_PUB_CACHE_ROOT=$FLUTTER_PEER_CANDIDATE_PUB_CACHE
fi
if [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    SEALED_INPUT_ROOT=$REPO_ROOT/online
fi
readonly FLUTTER_PEER_FLUTTER_VERSION FLUTTER_PEER_FLUTTER_ARCHIVE \
    FLUTTER_PEER_FLUTTER_SHA256 FLUTTER_PEER_FLUTTER_SIZE \
    FLUTTER_PEER_TOOLS_MODE FLUTTER_PEER_PUB_CACHE_ROOT SEALED_INPUT_ROOT
readonly OUTER_SOURCE="${BASH_SOURCE[0]}"
readonly GUEST_SCRIPT="$SCRIPT_DIR/smoke-verifier-vm-authority-guest.sh"
readonly ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-vm-entry-preflight.sh"
readonly VERIFY_SCRIPT="$SCRIPT_DIR/verify.sh"
readonly VERIFY_RELEASE_SOURCE="$SCRIPT_DIR/verify-release.sh"
readonly RELEASE_PARENT_SOURCE="$SCRIPT_DIR/build-release.sh"
readonly RELEASE_PUBLISHER_SOURCE="$SCRIPT_DIR/publish-github-release.sh"
readonly RELEASE_FINALIZER_SOURCE="$SCRIPT_DIR/finalize-release-set.py"
readonly RELEASE_WORKSPACE_RUNTIME_TEST="$SCRIPT_DIR/verify-release-workspace-runtime.sh"
readonly FORK_VERSION_SOURCE="$SCRIPT_DIR/fork-version.sh"
readonly APPLE_CHECK_SOURCE="$SCRIPT_DIR/apple-conform-check.sh"
readonly APPLE_TOOLCHAIN_RELEASE_SOURCE="$SCRIPT_DIR/apple-toolchain-release.py"
readonly FLUTTER_PEER_SOURCE="$SCRIPT_DIR/smoke-flutter-peer-presentation.sh"
readonly FLUTTER_TOOLS_FINALIZER_SOURCE="$SCRIPT_DIR/finalize-flutter-tools-offline.sh"
readonly VERIFY_SCAN_SOURCE="$SCRIPT_DIR/verify-scan.sh"
readonly FRB_CODEGEN_SOURCE="$SCRIPT_DIR/frb-codegen.sh"
readonly DART_VERIFY_SOURCE="$SCRIPT_DIR/dart-verify.sh"
readonly SMOKE_SERVER_SOURCE="$SCRIPT_DIR/smoke-server.sh"
readonly RUST_AUDIT_SOURCE="$SCRIPT_DIR/audit.sh"
readonly RUST_AUDIT_POLICY_SOURCE="$SCRIPT_DIR/rust-audit-policy.py"
readonly RUST_AUDIT_CHECKER="$SCRIPT_DIR/verify-rust-audit-authority.py"
readonly RUST_AUDIT_DOCKERFILE_SOURCE="$SCRIPT_DIR/Dockerfile.audit"
readonly ANDROID_KEYSTORE_SOURCE="$SCRIPT_DIR/gen-android-keystore.sh"
readonly ANDROID_KEYSTORE_INNER="$SCRIPT_DIR/android-keystore-generate.sh"
readonly ANDROID_KEYSTORE_CHECKER="$SCRIPT_DIR/verify-android-keystore-authority.py"
readonly ANDROID_BUILDER_SOURCE="$SCRIPT_DIR/build-android.sh"
readonly ANDROID_APK_BUILD_SOURCE="$SCRIPT_DIR/android-apk-build.sh"
readonly ANDROID_BUILDER_CHECKER="$SCRIPT_DIR/verify-android-builder-authority.py"
readonly ANDROID_GRADLE_SOURCE="$SCRIPT_DIR/test-android-gradle-cache.sh"
readonly ANDROID_GRADLE_CHECKER="$SCRIPT_DIR/verify-android-gradle-authority.py"
readonly ANDROID_BUILDER_IMAGE_CHECKER="$SCRIPT_DIR/verify-android-builder-image-authority.py"
readonly DEB_BUILDER_IMAGE_CHECKER="$SCRIPT_DIR/verify-deb-builder-image-authority.py"
readonly DEBIAN_BUILDER_SOURCE="$SCRIPT_DIR/build-debian.sh"
readonly DEBIAN_BUILDER_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-debian-builder-authority.py"
readonly SYSTEMD_RUNTIME_LIBS_SOURCE="$SCRIPT_DIR/stage-debian-systemd-runtime-libs.sh"
readonly SYSTEMD_LIFECYCLE_GUEST_SOURCE="$SCRIPT_DIR/smoke-debian-systemd-lifecycle-guest.sh"
readonly SYSTEMD_LOGINCTL_SOURCE="$SCRIPT_DIR/smoke-debian-systemd-loginctl.sh"
readonly DEBIAN_PACKAGE_AUTHORITY_SOURCE="$SCRIPT_DIR/verify-debian-package-authority.py"
readonly SYSTEMD_UNIT_SOURCE="$REPO_ROOT/res/rustdesk.service"
readonly DEV_CHECK_DOCKERFILE_SOURCE="$SCRIPT_DIR/Dockerfile.devcheck"
readonly WIN_HELPER_IMAGE_CHECKER="$SCRIPT_DIR/verify-win-helper-image-authority.py"
readonly WINDOWS_HELPER_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-windows-helper-authority.py"
readonly WINDOWS_HELPER_RUNTIME_TEST="$SCRIPT_DIR/test-windows-helper-vm-runtime.sh"
readonly ANDROID_BUILDER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.android-builder"
readonly DEB_BUILDER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.deb-builder"
readonly WIN_HELPER_DOCKERFILE="$SCRIPT_DIR/Dockerfile.win-helper"
readonly BUILDER_BOOTSTRAP_SEAL_DOCKERFILE="$SCRIPT_DIR/Dockerfile.builder-bootstrap-seal"
readonly ANDROID_BUILDER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.android-builder-certify"
readonly DEB_BUILDER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.deb-builder-certify"
readonly WIN_HELPER_CERTIFICATION_DOCKERFILE="$SCRIPT_DIR/Dockerfile.win-helper-certify"
readonly WINDOWS_HELPER_RUNTIME_SOURCE="$SCRIPT_DIR/windows-helper-runtime.sh"
readonly WINDOWS_HELPER_EXTRACTOR="$SCRIPT_DIR/windows-helper-extract-kernel.py"
readonly WINDOWS_GOLDEN_INSPECTOR="$SCRIPT_DIR/windows-golden-inspect.sh"
readonly WINDOWS_BUILD_SOURCE="$SCRIPT_DIR/build-windows-vm.sh"
readonly WINDOWS_PROVISION_SOURCE="$SCRIPT_DIR/provision-windows-vm.sh"
readonly WINDOWS_GOLDEN_SOURCE="$SCRIPT_DIR/verify-windows-golden.sh"
readonly ANDROID_RUST_SOURCE="$SCRIPT_DIR/android-rust-check.sh"
readonly ANDROID_EMULATOR_BOOT_SOURCE="$SCRIPT_DIR/smoke-android-emulator-boot.sh"
readonly ANDROID_EMULATOR_APP_SOURCE="$SCRIPT_DIR/android-emulator-app-check.sh"
readonly ANDROID_EMULATOR_RUNTIME_SOURCE="$SCRIPT_DIR/android-emulator-runtime-check.sh"
readonly ANDROID_EMULATOR_APK_VERIFIER="$SCRIPT_DIR/verify-android-emulator-apk.py"
readonly ANDROID_APK_MANIFEST_VERIFIER="$SCRIPT_DIR/verify-android-apk-manifest.py"
readonly ARTIFACT_RESULT_PUBLISHER_SOURCE="$SCRIPT_DIR/publish-artifact-result.py"
readonly ANDROID_ARTIFACT_STATE_ROOT="$REPO_ROOT/.harness-state/android-emulator-artifacts"
readonly ANDROID_ARTIFACT_DESTINATION=android-x86_64-test
readonly OFFLINE_IMAGE_PROVENANCE_SOURCE="$SCRIPT_DIR/offline-image-provenance.py"
readonly ONLINE_FETCH_SOURCE="$SCRIPT_DIR/online-fetch.sh"
readonly ONLINE_FETCH_VM_SOURCE="$SCRIPT_DIR/online-fetch-vm.sh"
readonly ONLINE_FETCH_VM_GUEST_SOURCE="$SCRIPT_DIR/online-fetch-vm-guest.sh"
readonly ONLINE_FETCH_ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"
readonly ONLINE_FETCH_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-online-fetch-container-authority.py"
readonly ONLINE_FETCH_RENAME_CHECKER="$SCRIPT_DIR/verify-online-fetch-virtiofs-rename.py"
readonly ONLINE_PUB_CACHE_OUTPUT_SOURCE="$SCRIPT_DIR/online-pub-cache-output.py"
readonly ONLINE_GRADLE_OUTPUT_SOURCE="$SCRIPT_DIR/online-gradle-output.py"
readonly ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-online-fetch-gradle-output-authority.py"
readonly ANDROID_GRADLE_CACHE_PROJECTOR="$SCRIPT_DIR/android-gradle-cache.py"
readonly ANDROID_GRADLE_WRAPPER_PROPERTIES="$REPO_ROOT/flutter/android/gradle/wrapper/gradle-wrapper.properties"
readonly DART_AUDIT_SOURCE="$SCRIPT_DIR/dart-audit.sh"
readonly DART_AUDIT_RESULT_SOURCE="$SCRIPT_DIR/dart-audit-result.py"
readonly DART_AUTHORITY_CHECKER="$SCRIPT_DIR/verify-dart-verifier-authority.py"
readonly DART_AUDIT_CHECKER="$SCRIPT_DIR/verify-dart-audit-authority.py"
readonly REQUIREMENTS_SOURCE="$REPO_ROOT/requirements.html"
readonly HARDENING_SOURCE="$REPO_ROOT/HARDENING_STATUS.md"
readonly BOOT_DERIVER="$SCRIPT_DIR/derive-verifier-vm-boot-assets.sh"
readonly CAPTURE_HELPER="$SCRIPT_DIR/bounded-unix-stream-capture.py"
readonly CLEANUP_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly LIB_SOURCE="$SCRIPT_DIR/lib.sh"
readonly PIN_SOURCE="$SCRIPT_DIR/pins.env"
readonly SERIAL_LIMIT=8388608
if [ "$MODE" = android-emulator-boot ] \
   || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    readonly VM_CPUS=8
else
    readonly VM_CPUS=4
fi
if [ "$MODE" = debian-systemd-lifecycle ]; then
    readonly VM_TIMEOUT_SECONDS=480
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=2048
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    readonly VM_TIMEOUT_SECONDS=2400
    readonly OVERLAY_SIZE=40G
    readonly VM_MEMORY=16384
elif [ "$MODE" = android-rust-target-check ]; then
    readonly VM_TIMEOUT_SECONDS=3600
    readonly OVERLAY_SIZE=40G
    readonly VM_MEMORY=16384
elif [ "$MODE" = hbb-common-fs ]; then
    readonly VM_TIMEOUT_SECONDS=1800
    readonly OVERLAY_SIZE=16G
    readonly VM_MEMORY=8192
elif [ "$MODE" = flutter-model-tests ]; then
    readonly VM_TIMEOUT_SECONDS=1800
    readonly OVERLAY_SIZE=24G
    readonly VM_MEMORY=8192
elif [ "$MODE" = android-owner-tests ]; then
    readonly VM_TIMEOUT_SECONDS=300
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=2048
elif [ "$MODE" = android-emulator-boot ]; then
    readonly VM_TIMEOUT_SECONDS=7200
    readonly OVERLAY_SIZE=32G
    readonly VM_MEMORY=16384
elif [ "$MODE" = android-emulator-app ]; then
    readonly VM_TIMEOUT_SECONDS=21600
    readonly OVERLAY_SIZE=64G
    readonly VM_MEMORY=24576
elif [ "$MODE" = android-emulator-runtime ]; then
    readonly VM_TIMEOUT_SECONDS=900
    readonly OVERLAY_SIZE=24G
    readonly VM_MEMORY=16384
elif [ "$MODE" = apple-conform ]; then
    readonly VM_TIMEOUT_SECONDS=3600
    readonly OVERLAY_SIZE=40G
    readonly VM_MEMORY=16384
elif [ "$MODE" = flutter-peer-presentation ]; then
    readonly VM_TIMEOUT_SECONDS=7200
    readonly OVERLAY_SIZE=48G
    readonly VM_MEMORY=24576
elif [ "$MODE" = dart-audit ]; then
    readonly VM_TIMEOUT_SECONDS=300
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=2048
elif [ "$MODE" = rust-audit ]; then
    readonly VM_TIMEOUT_SECONDS=600
    readonly OVERLAY_SIZE=8G
    readonly VM_MEMORY=4096
else
    readonly VM_TIMEOUT_SECONDS=90
    readonly OVERLAY_SIZE=6G
    readonly VM_MEMORY=2048
fi

RUN=
RUN_ID=
VM_OWNER_PID=
VM_OWNER_START=
VM_PID=
VM_START=
CAPTURE_PID=
CAPTURE_START=
KERNEL_FD=
INITRD_FD=
ANDROID_ARTIFACT_INPUT_FD=
VIRTIOFSD_PIDS=()
VIRTIOFSD_STARTS=()
VIRTIOFSD_LOGS=()
VIRTIOFS_SOCKETS=()
VIRTIOFSD_BINARY=
ARTIFACT_OUTPUT_FD=
ARTIFACT_OUTPUT_PARENT=
ARTIFACT_OUTPUT_PARENT_ID=
ARTIFACT_PUBLISHED=0
ARTIFACT_STATE_ROOT_CREATED=0
ARTIFACT_STATE_ROOT_ID=
ANDROID_ARTIFACT_PENDING=
ANDROID_ARTIFACT_SHA256=
ANDROID_ARTIFACT_INPUT_ROOT=
ANDROID_ARTIFACT_INPUT_ID=
ANDROID_ARTIFACT_INPUT_INVENTORY=
ANDROID_RUNTIME_ARTIFACT_TREE=
RUN_COMPLETE=0

fail() {
    printf 'verifier-VM authority smoke: %s\n' "$*" >&2
    exit 1
}

ANDROID_OWNER_KOTLIN_JARS=()
append_android_owner_kotlin_jar() {
    local group=$1 artifact=$2 version=$3 root
    local -a matches=()
    root="$ONLINE_INPUTS/gradle-home/caches/modules-2/files-2.1/$group/$artifact/$version"
    [ -d "$root" ] && [ ! -L "$root" ] \
        || fail "focused Android owner-state artifact root is absent: $group:$artifact:$version"
    mapfile -t matches < <(/usr/bin/find "$root" -mindepth 2 -maxdepth 2 -type f \
        -name "$artifact-$version.jar" -print | LC_ALL=C /usr/bin/sort)
    [ "${#matches[@]}" -eq 1 ] \
        || fail "expected one focused Android owner-state artifact: $group:$artifact:$version"
    ANDROID_OWNER_KOTLIN_JARS+=("${matches[0]}")
}
if [ "$MODE" = android-owner-tests ]; then
    append_android_owner_kotlin_jar org.jetbrains.kotlin kotlin-compiler-embeddable "$ANDROID_KOTLIN_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.kotlin kotlin-stdlib "$ANDROID_KOTLIN_STDLIB_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.kotlin kotlin-script-runtime "$ANDROID_KOTLIN_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.kotlin kotlin-reflect "$ANDROID_KOTLIN_COMPILER_REFLECT_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.kotlin kotlin-daemon-embeddable "$ANDROID_KOTLIN_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.intellij.deps trove4j "$ANDROID_KOTLIN_COMPILER_TROVE_VERSION"
    append_android_owner_kotlin_jar org.jetbrains.kotlinx kotlinx-coroutines-core-jvm "$ANDROID_KOTLIN_COMPILER_COROUTINES_VERSION"
    append_android_owner_kotlin_jar org.jetbrains annotations "$ANDROID_KOTLIN_COMPILER_ANNOTATIONS_VERSION"
fi
readonly -a ANDROID_OWNER_KOTLIN_JARS

git_closed() {
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
        GIT_NO_REPLACE_OBJECTS=1 \
        /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

process_start_time() {
    local pid=$1
    [ -r "/proc/$pid/stat" ] || return 1
    /usr/bin/awk '{ print $22 }' "/proc/$pid/stat"
}

is_exact_vm_process() {
    [ -n "$VM_PID" ] && [ -n "$VM_START" ] \
        && [ -r "/proc/$VM_PID/stat" ] \
        && [ "$(process_start_time "$VM_PID" 2>/dev/null)" = "$VM_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$VM_PID/exe" 2>/dev/null)" = \
             /usr/bin/qemu-system-x86_64 ]
}

is_exact_vm_owner_process() {
    [ -n "$VM_OWNER_PID" ] && [ -n "$VM_OWNER_START" ] \
        && [ -r "/proc/$VM_OWNER_PID/stat" ] \
        && [ "$(process_start_time "$VM_OWNER_PID" 2>/dev/null)" = "$VM_OWNER_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$VM_OWNER_PID/exe" 2>/dev/null)" = \
             /usr/bin/timeout ]
}

is_exact_capture_process() {
    [ -n "$CAPTURE_PID" ] && [ -n "$CAPTURE_START" ] \
        && [ -r "/proc/$CAPTURE_PID/stat" ] \
        && [ "$(process_start_time "$CAPTURE_PID" 2>/dev/null)" = "$CAPTURE_START" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$CAPTURE_PID/exe" 2>/dev/null)" = \
             "$(/usr/bin/readlink -f /usr/bin/python3)" ]
}

is_exact_virtiofsd_process() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2
    [ -n "$pid" ] && [ -n "$start" ] \
        && [ -n "$VIRTIOFSD_BINARY" ] \
        && [ -r "/proc/$pid/stat" ] \
        && [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
        && [ "$(/usr/bin/readlink -f "/proc/$pid/exe" 2>/dev/null)" = \
             "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null)" != Z ]
}

is_owned_virtiofsd_generation() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2 executable
    [ -n "$pid" ] && [ -n "$start" ] \
        && [ -n "$VIRTIOFSD_BINARY" ] \
        && [ -r "/proc/$pid/stat" ] \
        && [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
        && [ "$(/usr/bin/awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null)" != Z ] \
        || return 1
    executable="$(/usr/bin/readlink -f "/proc/$pid/exe" 2>/dev/null)" \
        || return 1
    [ "$executable" = "$VIRTIOFSD_BINARY" ] \
        || [ "$executable" = "$(/usr/bin/readlink -f /usr/bin/python3)" ]
}

virtiofsd_seccomp_enforced() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2 task_status task_count=0
    is_exact_virtiofsd_process "$pid" "$start" || return 1
    for task_status in /proc/"$pid"/task/[0-9]*/status; do
        [ -r "$task_status" ] || return 1
        [ "$(/usr/bin/awk '/^Seccomp:/ { print $2 }' "$task_status" 2>/dev/null)" = 2 ] \
            || return 1
        task_count=$((task_count + 1))
    done
    [ "$task_count" -ge 1 ]
}

terminate_owned_virtiofsd_generation() {
    [ "$#" -eq 2 ] || return 1
    local pid=$1 start=$2 signal attempt
    [ -r "/proc/$pid/stat" ] || return 0
    [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
        || return 0
    [ "$(/usr/bin/awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null)" != Z ] \
        || return 0
    is_owned_virtiofsd_generation "$pid" "$start" || return 1
    for signal in TERM KILL; do
        /usr/bin/kill -"$signal" "$pid" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            [ -r "/proc/$pid/stat" ] || return 0
            [ "$(process_start_time "$pid" 2>/dev/null)" = "$start" ] \
                || return 0
            [ "$(/usr/bin/awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null)" != Z ] \
                || return 0
            is_owned_virtiofsd_generation "$pid" "$start" || return 1
            /usr/bin/sleep 0.01
        done
    done
    return 1
}

start_virtiofsd() {
    [ "$#" -eq 5 ] || fail 'internal virtiofsd launch argument count differs'
    local authority=$1 shared_dir=$2 shared_identity=$3 socket=$4 log=$5
    local index pid start receipt ready=0
    /usr/bin/python3 -I -S "$VIRTIOFSD_LAUNCHER" \
        --binary "$VIRTIOFSD_BINARY" \
        --binary-sha256 "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY" \
        --authority "$authority" \
        --shared-dir "$shared_dir" --shared-identity "$shared_identity" \
        --socket "$socket" --uid "$HOST_UID" --gid "$HOST_GID" \
        >"$log" 2>&1 &
    pid=$!
    index=${#VIRTIOFSD_PIDS[@]}
    VIRTIOFSD_PIDS[index]=$pid
    VIRTIOFSD_STARTS[index]=
    VIRTIOFSD_LOGS[index]=$log
    VIRTIOFS_SOCKETS[index]=$socket
    start="$(process_start_time "$pid")" \
        || fail "cannot record the $authority virtiofsd generation"
    VIRTIOFSD_STARTS[index]=$start
    for _ in $(/usr/bin/seq 1 600); do
        if is_exact_virtiofsd_process "$pid" "$start" \
           && verify_private_socket "$socket" \
           && [ "$(/usr/bin/awk '/^NoNewPrivs:/ { print $2 }' "/proc/$pid/status")" = 1 ]; then
            ready=1
            break
        fi
        is_owned_virtiofsd_generation "$pid" "$start" || break
        /usr/bin/sleep 0.05
    done
    [ "$ready" -eq 1 ] \
        || { /usr/bin/tail -n 120 "$log" >&2; fail "$authority virtiofsd did not become ready"; }
    [ "$(/usr/bin/awk '/^Uid:/ { print $2":"$3":"$4":"$5 }' "/proc/$pid/status")" = \
      "$HOST_UID:$HOST_UID:$HOST_UID:$HOST_UID" ] \
        && [ "$(/usr/bin/awk '/^Gid:/ { print $2":"$3":"$4":"$5 }' "/proc/$pid/status")" = \
             "$HOST_GID:$HOST_GID:$HOST_GID:$HOST_GID" ] \
        || fail "$authority virtiofsd process identity differs"
    receipt="$(/usr/bin/grep '^VIRTIOFSD_LANDLOCK=' "$log")" \
        || fail "$authority virtiofsd Landlock receipt is absent"
    [[ "$receipt" =~ ^VIRTIOFSD_LANDLOCK=pass\ abi=([0-9]+)\ uid=$HOST_UID\ gid=$HOST_GID\ filesystem=$authority-only\ tcp=denied\ socket=prebound\ seccomp=kill$ ]] \
        && [ "${BASH_REMATCH[1]}" -ge 8 ] \
        || fail "$authority virtiofsd Landlock receipt differs"
}

terminate_exact_vm_process() {
    local signal attempt
    is_exact_vm_process || return 0
    for signal in TERM KILL; do
        kill -"$signal" "$VM_PID" 2>/dev/null || return 1
        for attempt in $(/usr/bin/seq 1 100); do
            is_exact_vm_process || return 0
            /usr/bin/sleep 0.01
        done
    done
    ! is_exact_vm_process
}

capture_listeners() {
    /usr/bin/ss -H -lntu | LC_ALL=C /usr/bin/sort -u
}

capture_listener_details() {
    /usr/bin/ss -H -lntup 2>/dev/null | LC_ALL=C /usr/bin/sort -u
}

capture_process_generations() {
    local proc pid owner start executable
    for proc in /proc/[0-9]*; do
        [ -d "$proc" ] || continue
        pid=${proc#/proc/}
        owner="$(/usr/bin/stat -c '%u' -- "$proc" 2>/dev/null)" || continue
        [ "$owner" = "$HOST_UID" ] || continue
        start="$(process_start_time "$pid" 2>/dev/null)" || continue
        executable="$(/usr/bin/readlink -f "$proc/exe" 2>/dev/null)" || continue
        /usr/bin/printf '%s\t%s\t%s\n' "$pid" "$start" "$executable"
    done | LC_ALL=C /usr/bin/sort -n
}

admit_preexisting_external_listener_drift() {
    local additions=$1 details=$2 stage=$3 listener
    local protocol state receive_queue send_queue local_endpoint peer_endpoint remainder
    local matching_details pids pid owner start executable generation
    while IFS= read -r listener; do
        [ -n "$listener" ] || continue
        read -r protocol state receive_queue send_queue local_endpoint peer_endpoint remainder \
            <<<"$listener"
        matching_details="$(
            /usr/bin/awk \
                -v protocol="$protocol" -v state="$state" \
                -v local_endpoint="$local_endpoint" -v peer_endpoint="$peer_endpoint" \
                '$1 == protocol && $2 == state && $5 == local_endpoint && $6 == peer_endpoint' \
                "$details"
        )"
        [ -n "$matching_details" ] || return 1
        pids="$(
            /usr/bin/printf '%s\n' "$matching_details" \
                | /usr/bin/grep -oE 'pid=[1-9][0-9]*' \
                | /usr/bin/cut -d= -f2 \
                | LC_ALL=C /usr/bin/sort -nu
        )" || pids=
        [ -n "$pids" ] || return 1
        while IFS= read -r pid; do
            [ -n "$pid" ] || continue
            owner="$(/usr/bin/stat -c '%u' -- "/proc/$pid" 2>/dev/null)" || return 1
            [ "$owner" = "$HOST_UID" ] || return 1
            start="$(process_start_time "$pid" 2>/dev/null)" || return 1
            executable="$(/usr/bin/readlink -f "/proc/$pid/exe" 2>/dev/null)" \
                || return 1
            generation="${pid}"$'\t'"${start}"$'\t'"${executable}"
            /usr/bin/grep -Fqx -- "$generation" "$LISTENER_PROCESSES_BEFORE" \
                || return 1
        done <<<"$pids"
        /usr/bin/printf 'stage=%s %s owners=%s\n' \
            "$stage" "$listener" \
            "$(/usr/bin/tr '\n' ',' <<<"$pids" | /usr/bin/sed 's/,$//')" \
            >>"$EXTERNAL_LISTENER_DRIFT"
    done <"$additions"
}

flutter_peer_input_inventory() {
    local -a directories=(
        "$ONLINE_INPUTS"
        "$FLUTTER_PEER_PUB_CACHE_ROOT"
        "$CARGO_VENDOR_ROOT"
        "$ONLINE_INPUTS/vcpkg/installed/x64-linux"
        "$ONLINE_INPUTS/xvfb-debs"
        "$ONLINE_INPUTS/atspi-debs"
    )
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        directories=(
            "$FLUTTER_PEER_CANDIDATE_ROOT"
            "${directories[@]}"
        )
    fi
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${directories[@]}"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$RUST_TEST_ARCHIVE" "$FLUTTER_PEER_FLUTTER_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
        "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
        "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_PEER_FLUTTER_ARCHIVE" \
        "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
        "$DEB_BUILDER_ARCHIVE" "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$FLUTTER_PEER_CANDIDATE_LOCK"
        /usr/bin/sha256sum -- "$FLUTTER_PEER_CANDIDATE_LOCK"
    fi
}

android_owner_input_inventory() {
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$ONLINE_INPUTS/gradle-home"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE" \
        "${ANDROID_OWNER_KOTLIN_JARS[@]}"
    /usr/bin/sha256sum -- "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE" \
        "${ANDROID_OWNER_KOTLIN_JARS[@]}"
}

android_emulator_input_inventory() {
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
        "$SEALED_INPUT_ROOT" "$REPO_ROOT/online/candidates" \
        "$ANDROID_EMULATOR_CANDIDATE_ROOT" "$ONLINE_INPUTS" \
        "$ANDROID_EMULATOR_FLUTTER_MAVEN" \
        "$ONLINE_INPUTS/android-sdk" "$ONLINE_INPUTS/android-sdk/platform-tools" \
        "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg" \
        "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg/installed" \
        "$ANDROID_EMULATOR_X86_VCPKG"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$ANDROID_EMULATOR_ARCHIVE" "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE" \
        "$ANDROID_EMULATOR_X86_STD" "$ANDROID_EMULATOR_ADB" \
        "$DEV_CHECK_IMAGE_ARCHIVE" "$ANDROID_BUILDER_ARCHIVE" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_JAR" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_POM" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_JAR" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_POM" \
        "$VIRTIOFSD_PACKAGE"
    /usr/bin/sha256sum -- \
        "$ANDROID_EMULATOR_ARCHIVE" "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE" \
        "$ANDROID_EMULATOR_X86_STD" "$ANDROID_EMULATOR_ADB" \
        "$DEV_CHECK_IMAGE_ARCHIVE" "$ANDROID_BUILDER_ARCHIVE" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_JAR" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_POM" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_JAR" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_POM" \
        "$VIRTIOFSD_PACKAGE"
    /usr/bin/find "$ANDROID_EMULATOR_X86_VCPKG" -mindepth 1 -type d \
        -printf '%p\0' | LC_ALL=C /usr/bin/sort -z \
        | /usr/bin/xargs -0 -r /usr/bin/stat -c '%d:%i:%u:%g:%a'
    /usr/bin/find "$ANDROID_EMULATOR_X86_VCPKG" -type f -printf '%p\0' \
        | LC_ALL=C /usr/bin/sort -z \
        | /usr/bin/xargs -0 -r /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s'
    /usr/bin/find "$ANDROID_EMULATOR_X86_VCPKG" -type f -printf '%p\0' \
        | LC_ALL=C /usr/bin/sort -z \
        | /usr/bin/xargs -0 -r /usr/bin/sha256sum
}

android_emulator_runtime_input_inventory() {
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
        "$SEALED_INPUT_ROOT" "$REPO_ROOT/online/candidates" \
        "$ANDROID_EMULATOR_CANDIDATE_ROOT" "$ONLINE_INPUTS" \
        "$ONLINE_INPUTS/android-sdk" "$ONLINE_INPUTS/android-sdk/platform-tools"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$ANDROID_EMULATOR_ARCHIVE" "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE" \
        "$ANDROID_EMULATOR_ADB" "$DEV_CHECK_IMAGE_ARCHIVE" \
        "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    /usr/bin/sha256sum -- \
        "$ANDROID_EMULATOR_ARCHIVE" "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE" \
        "$ANDROID_EMULATOR_ADB" "$DEV_CHECK_IMAGE_ARCHIVE" \
        "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
}

android_runtime_artifact_inventory() {
    local destination apk checksum
    destination="$ANDROID_ARTIFACT_INPUT_ROOT/$ANDROID_ARTIFACT_DESTINATION"
    apk="$destination/rustdesk-x86_64-runtime-test.apk"
    checksum="$apk.sha256"
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
        "$ANDROID_ARTIFACT_INPUT_ROOT" "$destination"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$apk" "$checksum"
    /usr/bin/sha256sum -- "$apk" "$checksum"
    /usr/bin/find "$ANDROID_ARTIFACT_INPUT_ROOT" -xdev -mindepth 1 \
        -printf '%P:%y\n' | LC_ALL=C /usr/bin/sort
}

android_rust_target_input_inventory() {
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS"
    /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
        "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    /usr/bin/sha256sum -- "$ANDROID_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
}

require_exact_fixed_receipt() {
    local expected=$1 label=$2
    local -a receipts=()
    mapfile -t receipts < <(/usr/bin/grep -Fo -- "$expected" "$SERIAL_LOG" || true)
    [ "${#receipts[@]}" -eq 1 ] && [ "${receipts[0]}" = "$expected" ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail "$label is absent or duplicated"; }
}

publish_android_runtime_artifact() {
    local pending_path pending_id destination artifact checksum checksum_line
    [ "$MODE" = android-emulator-app ] \
        && [ -n "$ANDROID_ARTIFACT_PENDING" ] \
        && [ -n "$ANDROID_ARTIFACT_SHA256" ] \
        && [ -n "$ARTIFACT_OUTPUT_PARENT" ] \
        || fail 'Android artifact publication authority is incomplete'
    [ -d "$ARTIFACT_OUTPUT_PARENT" ] && [ ! -L "$ARTIFACT_OUTPUT_PARENT" ] \
        && [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ARTIFACT_OUTPUT_PARENT")" = \
             "$ARTIFACT_OUTPUT_PARENT_ID:$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$ARTIFACT_OUTPUT_FD")" = \
             "$ARTIFACT_OUTPUT_PARENT_ID" ] \
        || fail 'commit-bound Android artifact output authority changed'
    [ "$ANDROID_ARTIFACT_PENDING" != "$ANDROID_ARTIFACT_DESTINATION" ] \
        || fail 'Android artifact pending and destination names collide'
    pending_path="$ARTIFACT_OUTPUT_PARENT/$ANDROID_ARTIFACT_PENDING"
    [ -d "$pending_path" ] && [ ! -L "$pending_path" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$pending_path")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'prepared Android artifact output metadata differs'
    pending_id="$(/usr/bin/stat -c '%d:%i' -- "$pending_path")"
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
        /usr/bin/python3 -I -S "$ARTIFACT_RESULT_PUBLISHER_SOURCE" \
            --commit \
            --artifact-kind android-x86_64-test \
            --output-parent "$ARTIFACT_OUTPUT_PARENT" \
            --output-parent-identity "$ARTIFACT_OUTPUT_PARENT_ID" \
            --pending "$ANDROID_ARTIFACT_PENDING" \
            --pending-identity "$pending_id" \
            --destination "$ANDROID_ARTIFACT_DESTINATION" \
        || fail 'prepared Android artifact could not be committed'
    destination="$ARTIFACT_OUTPUT_PARENT/$ANDROID_ARTIFACT_DESTINATION"
    artifact="$destination/rustdesk-x86_64-runtime-test.apk"
    checksum="$artifact.sha256"
    [ -d "$destination" ] && [ ! -L "$destination" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$destination")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$ARTIFACT_OUTPUT_PARENT" -mindepth 1 -maxdepth 1 -printf '%f\n')" = \
             "$ANDROID_ARTIFACT_DESTINATION" ] \
        && [ "$(/usr/bin/find "$destination" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
             $'rustdesk-x86_64-runtime-test.apk\nrustdesk-x86_64-runtime-test.apk.sha256' ] \
        || fail 'published Android artifact inventory differs'
    for file in "$artifact" "$checksum"; do
        [ -f "$file" ] && [ ! -L "$file" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$file")" = \
                 "$HOST_UID:$HOST_GID:400:1" ] \
            || fail 'published Android artifact file metadata differs'
    done
    checksum_line="$(<"$checksum")"
    [ "$checksum_line" = \
      "$ANDROID_ARTIFACT_SHA256  rustdesk-x86_64-runtime-test.apk" ] \
        && [ "$(/usr/bin/sha256sum "$artifact" | /usr/bin/awk '{ print $1 }')" = \
             "$ANDROID_ARTIFACT_SHA256" ] \
        || fail 'published Android artifact digest differs'
    ARTIFACT_PUBLISHED=1
}

reconcile_socket() {
    local path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        verify_private_socket "$path" || return 1
        /usr/bin/rm -- "$path" || return 1
    fi
}

verify_private_socket() {
    local path=$1 mode
    [ -S "$path" ] && [ ! -L "$path" ] || return 1
    [ "$(/usr/bin/stat -c '%u:%g' -- "$path")" = "$HOST_UID:$HOST_GID" ] \
        || return 1
    mode="$(/usr/bin/stat -c '%a' -- "$path")" || return 1
    [ $((8#$mode & 077)) -eq 0 ] || return 1
}

cleanup() {
    local status=$? cleanup_failed=0 index pid start socket
    trap - EXIT HUP INT TERM
    if [ -n "$VM_OWNER_PID" ]; then
        if is_exact_vm_owner_process; then
            kill -TERM "$VM_OWNER_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$VM_OWNER_PID" 2>/dev/null || true
        VM_OWNER_PID=
        VM_OWNER_START=
    fi
    terminate_exact_vm_process || cleanup_failed=1
    VM_PID=
    VM_START=
    for index in "${!VIRTIOFSD_PIDS[@]}"; do
        pid=${VIRTIOFSD_PIDS[index]}
        start=${VIRTIOFSD_STARTS[index]}
        if terminate_owned_virtiofsd_generation "$pid" "$start"; then
            wait "$pid" 2>/dev/null || true
        else
            cleanup_failed=1
        fi
    done
    VIRTIOFSD_PIDS=()
    VIRTIOFSD_STARTS=()
    if [ -n "$CAPTURE_PID" ]; then
        if is_exact_capture_process; then
            kill -TERM "$CAPTURE_PID" 2>/dev/null || cleanup_failed=1
        fi
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=
        CAPTURE_START=
    fi
    if [ -n "$KERNEL_FD" ]; then
        exec {KERNEL_FD}<&- || cleanup_failed=1
        KERNEL_FD=
    fi
    if [ -n "$INITRD_FD" ]; then
        exec {INITRD_FD}<&- || cleanup_failed=1
        INITRD_FD=
    fi
    if [ -n "$ANDROID_ARTIFACT_INPUT_FD" ]; then
        exec {ANDROID_ARTIFACT_INPUT_FD}<&- || cleanup_failed=1
        ANDROID_ARTIFACT_INPUT_FD=
    fi
    if [ -n "$ARTIFACT_OUTPUT_FD" ]; then
        exec {ARTIFACT_OUTPUT_FD}<&- || cleanup_failed=1
        ARTIFACT_OUTPUT_FD=
    fi
    if [ -n "$RUN" ] && [ -d "$RUN" ] && [ ! -L "$RUN" ] \
       && [ "$(/usr/bin/stat -c '%d:%i' -- "$RUN" 2>/dev/null)" = "$RUN_ID" ]; then
        reconcile_socket "$RUN/serial.sock" || cleanup_failed=1
        reconcile_socket "$RUN/qmp.sock" || cleanup_failed=1
        for socket in "${VIRTIOFS_SOCKETS[@]}"; do
            reconcile_socket "$socket" || cleanup_failed=1
        done
        if [ "$RUN_COMPLETE" -eq 1 ] && [ "$status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
            /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
                --remove-private-root "$RUN" --expected-identity "$RUN_ID" \
                || cleanup_failed=1
        else
            printf 'verifier-VM authority smoke: retaining failed private evidence at %s\n' \
                "$RUN" >&2
        fi
    elif [ -n "$RUN" ]; then
        cleanup_failed=1
    fi
    if [ "$ARTIFACT_PUBLISHED" -eq 0 ] && [ -n "$ARTIFACT_OUTPUT_PARENT" ]; then
        if [ -d "$ARTIFACT_OUTPUT_PARENT" ] && [ ! -L "$ARTIFACT_OUTPUT_PARENT" ] \
           && [ "$(/usr/bin/stat -c '%d:%i' -- "$ARTIFACT_OUTPUT_PARENT" 2>/dev/null)" = \
                "$ARTIFACT_OUTPUT_PARENT_ID" ]; then
            /usr/bin/python3 -I -S "$CLEANUP_HELPER" \
                --remove-private-root "$ARTIFACT_OUTPUT_PARENT" \
                --expected-identity "$ARTIFACT_OUTPUT_PARENT_ID" \
                || cleanup_failed=1
        else
            cleanup_failed=1
        fi
    fi
    if [ "$ARTIFACT_PUBLISHED" -eq 0 ] \
       && [ "$ARTIFACT_STATE_ROOT_CREATED" -eq 1 ]; then
        /usr/bin/python3 -I -S "$CLEANUP_HELPER" \
            --remove-empty-private-root "$ANDROID_ARTIFACT_STATE_ROOT" \
            --expected-identity "$ARTIFACT_STATE_ROOT_ID" \
            || cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" = Linux:x86_64 ] \
    || fail 'verifier VM requires a Linux x86_64 orchestration host'
for tool in /usr/bin/awk /usr/bin/chmod /usr/bin/cmp /usr/bin/comm /usr/bin/env \
    /usr/bin/find /usr/bin/findmnt /usr/bin/install \
    /usr/bin/dpkg-deb /usr/bin/git /usr/bin/grep /usr/bin/id /usr/bin/mkdir /usr/bin/mktemp /usr/bin/python3 \
    /usr/bin/qemu-img /usr/bin/qemu-system-x86_64 /usr/bin/readlink /usr/bin/rm \
    /usr/bin/seq /usr/bin/sha256sum /usr/bin/sha512sum /usr/bin/sleep /usr/bin/sort \
    /usr/bin/ss /usr/bin/stat /usr/bin/tail /usr/bin/timeout /usr/bin/uname /usr/bin/wc \
    /usr/bin/xorriso; do
    resolved="$(/usr/bin/readlink -f -- "$tool" 2>/dev/null)" \
        || fail "cannot resolve fixed host orchestration tool: $tool"
    [ -f "$resolved" ] && [ ! -L "$resolved" ] && [ -x "$resolved" ] \
        || fail "fixed host orchestration tool is unavailable: $tool"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$resolved")" = 0:0:755:1 ] \
        || fail "fixed host orchestration tool metadata changed: $tool"
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || fail '/dev/kvm is unavailable to the invoking non-root user'
[ -d "$INPUT_ROOT" ] && [ ! -L "$INPUT_ROOT" ] \
    || fail 'verifier-VM inputs are absent; run scripts/online-fetch.sh --verifier-vm-inputs'
for private_root in "$INPUT_ROOT" "$RUN_ROOT"; do
    [ -d "$private_root" ] && [ ! -L "$private_root" ] \
        || fail "verifier-VM private root is absent or ambiguous: $private_root"
    [ "$(/usr/bin/readlink -f -- "$private_root" 2>/dev/null)" = "$private_root" ] \
        || fail "verifier-VM private root is not absolute and canonical: $private_root"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$private_root")" = \
      "$HOST_UID:$HOST_GID:700" ] \
        || fail "verifier-VM private root is not current-user/current-group mode 0700: $private_root"
done
for input in "$BASE:$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" \
    "$DOCKER_BUNDLE:$SIZE_VERIFIER_VM_DOCKER_STATIC" \
    "$GIT_PACKAGE:$SIZE_VERIFIER_VM_GIT_PACKAGE"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "verifier-VM input is absent or symlinked: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
      "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "verifier-VM input metadata differs: $path"
done
verify_sha512 "$BASE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
verify_sha256 "$DOCKER_BUNDLE" "$SHA256_VERIFIER_VM_DOCKER_STATIC"
verify_sha256 "$GIT_PACKAGE" "$SHA256_VERIFIER_VM_GIT_PACKAGE"
[ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Package)" = git ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Version)" = \
         "$VERIFIER_VM_GIT_PACKAGE_VERSION" ] \
    && [ "$(/usr/bin/dpkg-deb --field "$GIT_PACKAGE" Architecture)" = amd64 ] \
    || fail 'authenticated verifier-VM Git package identity differs'
/usr/bin/qemu-img check -q "$BASE" || fail 'Debian verifier-VM base failed qcow2 validation'
if [ "$MODE" = hbb-common-fs ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed focused-test input root metadata differs'
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed focused-test input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
elif [ "$MODE" = apple-conform ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Apple-conformance input root metadata differs'
    for input in \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$APPLE_CHECK_IMAGE_ARCHIVE:$SIZE_APPLE_CHECK_IMAGE_ARCHIVE:$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Apple-conformance input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Apple-conformance Cargo vendor root metadata differs'
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android Rust-lifecycle input root metadata differs'
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$FLUTTER_TEST_ARCHIVE:$SIZE_FLUTTER_3_24_5:$SHA256_FLUTTER_3_24_5" \
        "$LLVM_TEST_ARCHIVE:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$DEV_CHECK_IMAGE_ARCHIVE:$SIZE_DEV_CHECK_IMAGE_ARCHIVE:$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Android Rust-lifecycle input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    [ -f "$FRB_CODEGEN" ] && [ ! -L "$FRB_CODEGEN" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$FRB_CODEGEN")" = \
             "$HOST_UID:$HOST_GID:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
        || fail "sealed Android Rust-lifecycle executable metadata differs: $FRB_CODEGEN"
    verify_sha256 "$FRB_CODEGEN" "$SHA256_FLUTTER_PEER_FRB_CODEGEN"
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
    [ -d "$PUB_CACHE_ROOT" ] && [ ! -L "$PUB_CACHE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$PUB_CACHE_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Pub-cache root metadata differs'
elif [ "$MODE" = android-rust-target-check ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android Rust target-check input root metadata differs'
    for input in \
        "$ANDROID_BUILDER_ARCHIVE:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Android Rust target-check input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    android_rust_target_input_inventory >/dev/null \
        || fail 'cannot inventory Android Rust target-check inputs'
elif [ "$MODE" = flutter-model-tests ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed focused-test input root metadata differs'
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$FLUTTER_TEST_ARCHIVE:$SIZE_FLUTTER_3_24_5:$SHA256_FLUTTER_3_24_5" \
        "$LLVM_TEST_ARCHIVE:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed focused-test input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    [ -f "$FRB_CODEGEN" ] && [ ! -L "$FRB_CODEGEN" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$FRB_CODEGEN")" = \
             "$HOST_UID:$HOST_GID:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
        || fail "sealed focused-test executable metadata differs: $FRB_CODEGEN"
    verify_sha256 "$FRB_CODEGEN" "$SHA256_FLUTTER_PEER_FRB_CODEGEN"
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$PUB_CACHE_ROOT" ] && [ ! -L "$PUB_CACHE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$PUB_CACHE_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Pub-cache root metadata differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
elif [ "$MODE" = android-owner-tests ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android owner-state input root metadata differs'
    [ -d "$ONLINE_INPUTS/gradle-home" ] && [ ! -L "$ONLINE_INPUTS/gradle-home" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS/gradle-home")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Android owner-state Gradle root metadata differs'
    for input in \
        "$ANDROID_BUILDER_ARCHIVE:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Android owner-state input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ "${#ANDROID_OWNER_KOTLIN_JARS[@]}" -eq 8 ] \
        || fail 'focused Android owner-state Kotlin compiler closure differs'
    android_owner_input_inventory >/dev/null \
        || fail 'cannot inventory focused Android owner-state inputs'
elif [ "$MODE" = android-emulator-runtime ]; then
    [ -d "$SEALED_INPUT_ROOT" ] && [ ! -L "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/readlink -f -- "$SEALED_INPUT_ROOT")" = \
             "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$SEALED_INPUT_ROOT")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android runtime authority root metadata differs'
    [ -d "$REPO_ROOT/online/candidates" ] \
        && [ ! -L "$REPO_ROOT/online/candidates" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$REPO_ROOT/online/candidates")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail 'Android runtime candidate namespace metadata differs'
    [ -d "$ANDROID_EMULATOR_CANDIDATE_ROOT" ] \
        && [ ! -L "$ANDROID_EMULATOR_CANDIDATE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_CANDIDATE_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$ANDROID_EMULATOR_CANDIDATE_ROOT" \
            -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
             $'emulator-linux_x64-'"${ANDROID_EMULATOR_ARCHIVE_BUILD}"$'.zip\nflutter-maven\nrust-std-1.75-x86_64-linux-android.tar.xz\nvcpkg\nx86_64-'"${ANDROID_EMULATOR_SYSTEM_IMAGE_API}"'_r'"${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}"'.zip' ] \
        || fail 'Android runtime candidate closure namespace differs'
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android runtime input root metadata differs'
    [ -d "$ONLINE_INPUTS/android-sdk" ] \
        && [ ! -L "$ONLINE_INPUTS/android-sdk" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ONLINE_INPUTS/android-sdk")" = "$HOST_UID:$HOST_GID:555" ] \
        && [ -d "$ONLINE_INPUTS/android-sdk/platform-tools" ] \
        && [ ! -L "$ONLINE_INPUTS/android-sdk/platform-tools" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ONLINE_INPUTS/android-sdk/platform-tools")" = \
             "$HOST_UID:$HOST_GID:555" ] \
        || fail 'sealed Android runtime SDK directory metadata differs'
    for input in \
        "$ANDROID_EMULATOR_ARCHIVE:$SIZE_ANDROID_EMULATOR_LINUX_X64:$SHA256_ANDROID_EMULATOR_LINUX_X64:400" \
        "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64:$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64:400" \
        "$ANDROID_EMULATOR_ADB:$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1:$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1:555" \
        "$DEV_CHECK_IMAGE_ARCHIVE:$SIZE_DEV_CHECK_IMAGE_ARCHIVE:$SHA256_DEV_CHECK_IMAGE_ARCHIVE:400" \
        "$ANDROID_BUILDER_ARCHIVE:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE:400" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE:400"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        remainder=${remainder#*:}
        digest=${remainder%%:*}
        mode=${remainder##*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:$mode:1:$size" ] \
            || fail "sealed Android runtime input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    android_emulator_runtime_input_inventory >/dev/null \
        || fail 'cannot inventory the sealed Android runtime inputs'
elif [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ]; then
    [ -d "$SEALED_INPUT_ROOT" ] && [ ! -L "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/readlink -f -- "$SEALED_INPUT_ROOT")" = \
             "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$SEALED_INPUT_ROOT")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android emulator authority root metadata differs'
    [ -d "$REPO_ROOT/online/candidates" ] \
        && [ ! -L "$REPO_ROOT/online/candidates" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$REPO_ROOT/online/candidates")" = "$HOST_UID:$HOST_GID:700" ] \
        || fail 'Android emulator candidate namespace metadata differs'
    [ -d "$ANDROID_EMULATOR_CANDIDATE_ROOT" ] \
        && [ ! -L "$ANDROID_EMULATOR_CANDIDATE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_CANDIDATE_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$ANDROID_EMULATOR_CANDIDATE_ROOT" \
            -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
             $'emulator-linux_x64-'"${ANDROID_EMULATOR_ARCHIVE_BUILD}"$'.zip\nflutter-maven\nrust-std-1.75-x86_64-linux-android.tar.xz\nvcpkg\nx86_64-'"${ANDROID_EMULATOR_SYSTEM_IMAGE_API}"'_r'"${ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE_REVISION}"'.zip' ] \
        || fail 'Android emulator candidate closure namespace differs'
    [ -d "$ANDROID_EMULATOR_FLUTTER_MAVEN" ] \
        && [ ! -L "$ANDROID_EMULATOR_FLUTTER_MAVEN" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_FLUTTER_MAVEN")" = "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$ANDROID_EMULATOR_FLUTTER_MAVEN" \
            -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
             $'flutter_embedding_release-'"${FLUTTER_ANDROID_MAVEN_VERSION}"$'.jar\nflutter_embedding_release-'"${FLUTTER_ANDROID_MAVEN_VERSION}"$'.pom\nx86_64_release-'"${FLUTTER_ANDROID_MAVEN_VERSION}"$'.jar\nx86_64_release-'"${FLUTTER_ANDROID_MAVEN_VERSION}"'.pom' ] \
        || fail 'Android emulator Flutter Maven candidate namespace differs'
    [ -d "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg" ] \
        && [ ! -L "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg")" = "$HOST_UID:$HOST_GID:700" ] \
        && [ -d "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg/installed" ] \
        && [ ! -L "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg/installed" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_CANDIDATE_ROOT/vcpkg/installed")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        && [ -d "$ANDROID_EMULATOR_X86_VCPKG" ] \
        && [ ! -L "$ANDROID_EMULATOR_X86_VCPKG" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ANDROID_EMULATOR_X86_VCPKG")" = "$HOST_UID:$HOST_GID:500" ] \
        || fail 'Android emulator x86_64 native candidate namespace differs'
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-input-provenance.py" verify-subtree \
        --tree "$ANDROID_EMULATOR_X86_VCPKG" \
        --expected "$SHA256_ANDROID_EMULATOR_VCPKG_X64_ANDROID_CLOSURE_V1" \
        || fail 'Android emulator x86_64 native candidate closure differs'
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Android emulator input root metadata differs'
    [ -d "$ONLINE_INPUTS/android-sdk" ] \
        && [ ! -L "$ONLINE_INPUTS/android-sdk" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ONLINE_INPUTS/android-sdk")" = "$HOST_UID:$HOST_GID:555" ] \
        && [ -d "$ONLINE_INPUTS/android-sdk/platform-tools" ] \
        && [ ! -L "$ONLINE_INPUTS/android-sdk/platform-tools" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
            "$ONLINE_INPUTS/android-sdk/platform-tools")" = \
             "$HOST_UID:$HOST_GID:555" ] \
        || fail 'sealed Android platform-tools directory metadata differs'
    for input in \
        "$ANDROID_EMULATOR_ARCHIVE:$SIZE_ANDROID_EMULATOR_LINUX_X64:$SHA256_ANDROID_EMULATOR_LINUX_X64:400" \
        "$ANDROID_EMULATOR_SYSTEM_IMAGE_ARCHIVE:$SIZE_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64:$SHA256_ANDROID_EMULATOR_SYSTEM_IMAGE_X86_64:400" \
        "$ANDROID_EMULATOR_X86_STD:$SIZE_RUST_STD_ANDROID_X86_64_1_75:$SHA256_RUST_STD_ANDROID_X86_64_1_75:400" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_JAR:$SIZE_FLUTTER_ANDROID_EMBEDDING_RELEASE_JAR:$SHA256_FLUTTER_ANDROID_EMBEDDING_RELEASE_JAR:400" \
        "$ANDROID_EMULATOR_FLUTTER_EMBEDDING_POM:$SIZE_FLUTTER_ANDROID_EMBEDDING_RELEASE_POM:$SHA256_FLUTTER_ANDROID_EMBEDDING_RELEASE_POM:400" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_JAR:$SIZE_FLUTTER_ANDROID_X86_64_RELEASE_JAR:$SHA256_FLUTTER_ANDROID_X86_64_RELEASE_JAR:400" \
        "$ANDROID_EMULATOR_FLUTTER_X86_64_POM:$SIZE_FLUTTER_ANDROID_X86_64_RELEASE_POM:$SHA256_FLUTTER_ANDROID_X86_64_RELEASE_POM:400" \
        "$ANDROID_EMULATOR_ADB:$SIZE_ANDROID_PLATFORM_TOOLS_ADB_37_0_1:$SHA256_ANDROID_PLATFORM_TOOLS_ADB_37_0_1:555" \
        "$DEV_CHECK_IMAGE_ARCHIVE:$SIZE_DEV_CHECK_IMAGE_ARCHIVE:$SHA256_DEV_CHECK_IMAGE_ARCHIVE:400" \
        "$ANDROID_BUILDER_ARCHIVE:$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE:400" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE:400"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        remainder=${remainder#*:}
        digest=${remainder%%:*}
        mode=${remainder##*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:$mode:1:$size" ] \
            || fail "sealed Android emulator input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    android_emulator_input_inventory >/dev/null \
        || fail 'cannot inventory the sealed Android emulator inputs'
elif [ "$MODE" = flutter-peer-presentation ]; then
    [ -d "$SEALED_INPUT_ROOT" ] && [ ! -L "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/readlink -f -- "$SEALED_INPUT_ROOT")" = "$SEALED_INPUT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$SEALED_INPUT_ROOT")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Flutter-peer authority root metadata differs'
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Flutter-peer input root metadata differs'
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        [ -d "$FLUTTER_PEER_CANDIDATE_ROOT" ] \
            && [ ! -L "$FLUTTER_PEER_CANDIDATE_ROOT" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a' -- \
                "$FLUTTER_PEER_CANDIDATE_ROOT")" = "$HOST_UID:$HOST_GID:700" ] \
            && [ "$(/usr/bin/find "$FLUTTER_PEER_CANDIDATE_ROOT" \
                -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
                 $'flutter-'"${FLUTTER_PRESENTATION_CANDIDATE_VERSION}"$'.tar.xz\npub-cache\npubspec.lock.discovery' ] \
            || fail 'candidate Flutter-peer closure namespace differs'
        [ -f "$FLUTTER_PEER_CANDIDATE_LOCK" ] \
            && [ ! -L "$FLUTTER_PEER_CANDIDATE_LOCK" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- \
                "$FLUTTER_PEER_CANDIDATE_LOCK")" = "$HOST_UID:$HOST_GID:400:1" ] \
            && [ "$(/usr/bin/sha256sum "$FLUTTER_PEER_CANDIDATE_LOCK" \
                | /usr/bin/awk '{print $1}')" = \
                 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK" ] \
            || fail 'candidate Flutter-peer project lock differs'
    fi
    for input in \
        "$RUST_TEST_ARCHIVE:$SIZE_RUST_1_75:$SHA256_RUST_1_75" \
        "$FLUTTER_PEER_FLUTTER_ARCHIVE:$FLUTTER_PEER_FLUTTER_SIZE:$FLUTTER_PEER_FLUTTER_SHA256" \
        "$LLVM_TEST_ARCHIVE:$SIZE_LLVM_15_0_6:$SHA256_LLVM_15_0_6" \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$DEB_BUILDER_ARCHIVE:$DEB_BUILDER_IMAGE_ARCHIVE_SIZE:$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        "$DEV_CHECK_IMAGE_ARCHIVE:$SIZE_DEV_CHECK_IMAGE_ARCHIVE:$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Flutter-peer input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    [ -f "$FRB_CODEGEN" ] && [ ! -L "$FRB_CODEGEN" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$FRB_CODEGEN")" = \
             "$HOST_UID:$HOST_GID:500:1:$SIZE_FLUTTER_PEER_FRB_CODEGEN" ] \
        || fail "sealed Flutter-peer executable metadata differs: $FRB_CODEGEN"
    verify_sha256 "$FRB_CODEGEN" "$SHA256_FLUTTER_PEER_FRB_CODEGEN"
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$FLUTTER_PEER_PUB_CACHE_ROOT" ] && [ ! -L "$FLUTTER_PEER_PUB_CACHE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$FLUTTER_PEER_PUB_CACHE_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed selected Flutter-peer Pub-cache root metadata differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Flutter-peer Cargo vendor root metadata differs'
elif [ "$MODE" = rust-audit ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Rust-audit input root metadata differs'
    for input in \
        "$CARGO_VENDOR_CONFIG:$SIZE_CARGO_VENDOR_CONFIG:$SHA256_CARGO_VENDOR_CONFIG" \
        "$RUST_AUDIT_IMAGE_ARCHIVE:$SIZE_RUST_AUDIT_IMAGE_ARCHIVE:$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
        "$VIRTIOFSD_PACKAGE:$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE:$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE"; do
        path=${input%%:*}
        remainder=${input#*:}
        size=${remainder%%:*}
        digest=${remainder#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
                 "$HOST_UID:$HOST_GID:400:1:$size" ] \
            || fail "sealed Rust-audit input metadata differs: $path"
        verify_sha256 "$path" "$digest"
    done
    verify_sha512 "$VIRTIOFSD_PACKAGE" "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Package)" = virtiofsd ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Version)" = \
             "$VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION" ] \
        && [ "$(/usr/bin/dpkg-deb --field "$VIRTIOFSD_PACKAGE" Architecture)" = amd64 ] \
        || fail 'authenticated virtiofsd package identity differs'
    [ -d "$CARGO_VENDOR_ROOT" ] && [ ! -L "$CARGO_VENDOR_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$CARGO_VENDOR_ROOT")" = \
             "$HOST_UID:$HOST_GID:500" ] \
        || fail 'sealed Cargo vendor root metadata differs'
elif [ "$MODE" = dart-audit ]; then
    [ -d "$ONLINE_INPUTS" ] && [ ! -L "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/readlink -f -- "$ONLINE_INPUTS")" = "$ONLINE_INPUTS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_INPUTS")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'sealed Dart-audit input root metadata differs'
    [ -f "$DART_AUDIT_IMAGE_ARCHIVE" ] && [ ! -L "$DART_AUDIT_IMAGE_ARCHIVE" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE")" = \
             "$HOST_UID:$HOST_GID:400:1:$SIZE_DART_AUDIT_IMAGE_ARCHIVE" ] \
        || fail 'sealed Dart-audit image archive metadata differs'
    verify_sha256 "$DART_AUDIT_IMAGE_ARCHIVE" "$SHA256_DART_AUDIT_IMAGE_ARCHIVE"
fi
/usr/bin/python3 -I -S - "$BASE" <<'PY'
import json
import subprocess
import sys

data = json.loads(
    subprocess.check_output(
        ["/usr/bin/qemu-img", "info", "--output=json", sys.argv[1]],
        text=True,
    )
)
if data.get("format") != "qcow2" or data.get("backing-filename") is not None:
    raise SystemExit("verifier-VM base is not one standalone qcow2 image")
if data.get("virtual-size") != 3 * 1024 * 1024 * 1024:
    raise SystemExit("verifier-VM base virtual size differs")
PY
for source in "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" \
    "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" "$RUST_AUDIT_DOCKERFILE_SOURCE" \
    "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" \
    "$ANDROID_BUILDER_SOURCE" "$ANDROID_APK_BUILD_SOURCE" "$ANDROID_BUILDER_CHECKER" \
    "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" \
    "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" \
    "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" \
    "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" \
    "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
    "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" \
    "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" \
    "$WINDOWS_HELPER_RUNTIME_TEST" \
    "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" \
    "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" \
    "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
    "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" \
    "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" \
    "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" \
    "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" \
    "$ANDROID_RUST_SOURCE" "$ANDROID_EMULATOR_BOOT_SOURCE" \
    "$ANDROID_EMULATOR_APP_SOURCE" "$ANDROID_EMULATOR_RUNTIME_SOURCE" \
    "$ANDROID_EMULATOR_APK_VERIFIER" "$ANDROID_APK_MANIFEST_VERIFIER" \
    "$ARTIFACT_RESULT_PUBLISHER_SOURCE" \
    "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" \
    "$ONLINE_FETCH_VM_SOURCE" "$ONLINE_FETCH_VM_GUEST_SOURCE" \
    "$ONLINE_FETCH_ENTRY_PREFLIGHT" "$ONLINE_FETCH_AUTHORITY_CHECKER" \
    "$ONLINE_FETCH_RENAME_CHECKER" \
    "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" \
    "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" \
    "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" \
    "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" \
    "$LIB_SOURCE" "$PIN_SOURCE"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "verifier-VM source is absent or symlinked: $source"
done
[ -x "$GUEST_SCRIPT" ] && [ -x "$ENTRY_PREFLIGHT" ] && [ -x "$VERIFY_SCRIPT" ] \
    && [ -x "$VERIFY_RELEASE_SOURCE" ] \
    && [ -x "$RELEASE_PARENT_SOURCE" ] \
    && [ -x "$RELEASE_PUBLISHER_SOURCE" ] \
    && [ -x "$RELEASE_FINALIZER_SOURCE" ] \
    && [ -x "$RELEASE_WORKSPACE_RUNTIME_TEST" ] \
    && [ -x "$FRB_CODEGEN_SOURCE" ] \
    && [ -x "$FLUTTER_PEER_SOURCE" ] \
    && [ -x "$DART_VERIFY_SOURCE" ] \
    && [ -x "$SMOKE_SERVER_SOURCE" ] \
    && [ -x "$RUST_AUDIT_SOURCE" ] \
    && [ -x "$ANDROID_KEYSTORE_SOURCE" ] \
    && [ -x "$ANDROID_BUILDER_SOURCE" ] \
    && [ -x "$ANDROID_GRADLE_SOURCE" ] \
    && [ -x "$DEBIAN_BUILDER_SOURCE" ] \
    && [ -x "$SYSTEMD_RUNTIME_LIBS_SOURCE" ] \
    && [ -x "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" ] \
    && [ -x "$SYSTEMD_LOGINCTL_SOURCE" ] \
    && [ -x "$ANDROID_RUST_SOURCE" ] \
    && [ -x "$ANDROID_EMULATOR_APP_SOURCE" ] \
    && [ -x "$ANDROID_EMULATOR_RUNTIME_SOURCE" ] \
    && [ -x "$DART_AUDIT_SOURCE" ] \
    && [ -x "$WINDOWS_HELPER_RUNTIME_TEST" ] \
    && [ -x "$CAPTURE_HELPER" ] && [ -x "$CLEANUP_HELPER" ] \
    || fail 'verifier-VM scripts must be executable'
[ -x "$BOOT_DERIVER" ] || fail 'verifier-VM boot deriver must be executable'
[ "$MODE" = authority-smoke ] || [ "$MODE" = debian-systemd-lifecycle ] \
    || [ -x "$VIRTIOFSD_LAUNCHER" ] \
    || fail 'sealed-input virtiofsd launcher must be executable'
VERIFIER_VM_INPUT_ROOT="$INPUT_ROOT" "$BOOT_DERIVER"
[ -d "$BOOT_ROOT" ] && [ ! -L "$BOOT_ROOT" ] \
    || fail 'direct-boot cache is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BOOT_ROOT")" = "$HOST_UID:$HOST_GID:500" ] \
    || fail 'direct-boot cache directory metadata differs'
[ "$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" = xx ] \
    || fail 'direct-boot cache inventory differs'
for input in "$KERNEL:$SIZE_VERIFIER_VM_KERNEL" "$INITRD:$SIZE_VERIFIER_VM_INITRD"; do
    path=${input%:*}
    size=${input##*:}
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "direct-boot input is absent or symlinked: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
      "$HOST_UID:$HOST_GID:400:1:$size" ] \
        || fail "direct-boot input metadata differs: $path"
done
verify_sha256 "$KERNEL" "$SHA256_VERIFIER_VM_KERNEL"
verify_sha256 "$INITRD" "$SHA256_VERIFIER_VM_INITRD"

RUST_TEST_SOURCE_COMMIT=
RUST_TEST_SOURCE_TREE=
RUST_TEST_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Rust workloads require the one checked-out master authority'
    RUST_TEST_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Rust-workload source commit'
    RUST_TEST_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Rust-workload source tree'
    [ "$RUST_TEST_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$RUST_TEST_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Rust-workload source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Rust workloads require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

APPLE_SOURCE_COMMIT=
APPLE_SOURCE_TREE=
APPLE_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = apple-conform ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'Apple conformance requires the one checked-out master authority'
    APPLE_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve Apple-conformance source commit'
    APPLE_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve Apple-conformance source tree'
    [ "$APPLE_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$APPLE_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'Apple-conformance source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'Apple conformance requires a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

FLUTTER_SOURCE_COMMIT=
FLUTTER_SOURCE_TREE=
FLUTTER_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = flutter-model-tests ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Flutter tests require the one checked-out master authority'
    FLUTTER_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Flutter-test source commit'
    FLUTTER_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Flutter-test source tree'
    [ "$FLUTTER_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$FLUTTER_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Flutter-test source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Flutter tests require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

ANDROID_OWNER_SOURCE_COMMIT=
ANDROID_OWNER_SOURCE_TREE=
ANDROID_OWNER_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = android-owner-tests ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Android owner-state tests require the one checked-out master authority'
    ANDROID_OWNER_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Android owner-state source commit'
    ANDROID_OWNER_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Android owner-state source tree'
    [ "$ANDROID_OWNER_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$ANDROID_OWNER_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Android owner-state source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Android owner-state tests require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

ANDROID_EMULATOR_SOURCE_COMMIT=
ANDROID_EMULATOR_SOURCE_TREE=
ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'Android emulator workloads require the one checked-out master authority'
    ANDROID_EMULATOR_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve Android emulator harness source commit'
    ANDROID_EMULATOR_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve Android emulator harness source tree'
    [ "$ANDROID_EMULATOR_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$ANDROID_EMULATOR_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'Android emulator harness source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'Android emulator workloads require a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

FLUTTER_PEER_SOURCE_COMMIT=
FLUTTER_PEER_SOURCE_TREE=
FLUTTER_PEER_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = flutter-peer-presentation ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Flutter peer requires the one checked-out master authority'
    FLUTTER_PEER_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Flutter-peer source commit'
    FLUTTER_PEER_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Flutter-peer source tree'
    [ "$FLUTTER_PEER_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$FLUTTER_PEER_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Flutter-peer source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Flutter peer requires a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

DART_SOURCE_COMMIT=
DART_SOURCE_TREE=
DART_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = dart-audit ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Dart audit requires the one checked-out master authority'
    DART_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Dart-audit source commit'
    DART_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Dart-audit source tree'
    [ "$DART_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$DART_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Dart-audit source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Dart audit requires a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

RUST_AUDIT_SOURCE_COMMIT=
RUST_AUDIT_SOURCE_TREE=
RUST_AUDIT_SOURCE_ARCHIVE_SHA256=
if [ "$MODE" = rust-audit ]; then
    [ "$(git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD)" = refs/heads/master ] \
        || fail 'focused Rust audit requires the one checked-out master authority'
    RUST_AUDIT_SOURCE_COMMIT="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve focused Rust-audit source commit'
    RUST_AUDIT_SOURCE_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve focused Rust-audit source tree'
    [ "$RUST_AUDIT_SOURCE_COMMIT" = \
      "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/heads/master)" ] \
        && [ "$RUST_AUDIT_SOURCE_COMMIT" = \
             "$(git_closed -C "$REPO_ROOT" rev-parse --verify refs/remotes/origin/master)" ] \
        || fail 'focused Rust-audit source differs from pushed master'
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
        || fail 'focused Rust audit requires a clean source tree'
    [ -z "$(git_closed -C "$REPO_ROOT" for-each-ref --format='%(refname)' refs/replace)" ] \
        || fail 'Git replacement refs are forbidden'
fi

LIFECYCLE_ARTIFACT_ID=
DEV_CHECK_ARCHIVE_ID=
if [ "$MODE" = flutter-peer-presentation ]; then
    for required_directory in \
        "$ONLINE_INPUTS/vcpkg/installed/x64-linux" \
        "$ONLINE_INPUTS/xvfb-debs" \
        "$ONLINE_INPUTS/atspi-debs"; do
        [ -d "$required_directory" ] && [ ! -L "$required_directory" ] \
            || fail "focused Flutter-peer input directory is absent or ambiguous: $required_directory"
    done
fi
if [ "$MODE" = debian-systemd-lifecycle ]; then
    case "$LIFECYCLE_ARTIFACT:$DEV_CHECK_ARCHIVE" in
        /*:/*) ;;
        *) fail 'lifecycle artifact and devcheck archive paths must be absolute' ;;
    esac
    for lifecycle_input in "$LIFECYCLE_ARTIFACT" "$DEV_CHECK_ARCHIVE"; do
        [ -f "$lifecycle_input" ] && [ ! -L "$lifecycle_input" ] \
            || fail "lifecycle input is absent or ambiguous: $lifecycle_input"
        [ "$(/usr/bin/readlink -f -- "$lifecycle_input" 2>/dev/null)" = \
          "$lifecycle_input" ] \
            || fail "lifecycle input path is not canonical: $lifecycle_input"
    done
    [[ "$LIFECYCLE_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'lifecycle artifact SHA-256 is malformed'
    [[ "$LIFECYCLE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'lifecycle source commit is malformed'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'lifecycle artifact is not current-user/current-group mode 0400 with one link'
    [ "$(/usr/bin/sha256sum "$LIFECYCLE_ARTIFACT" | /usr/bin/awk '{ print $1 }')" = \
      "$LIFECYCLE_ARTIFACT_SHA256" ] \
        || fail 'lifecycle artifact digest differs'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$DEV_CHECK_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1:$SIZE_DEV_CHECK_IMAGE_ARCHIVE" ] \
        || fail 'devcheck archive metadata differs'
    verify_sha256 "$DEV_CHECK_ARCHIVE" "$SHA256_DEV_CHECK_IMAGE_ARCHIVE"
    [ "$(/usr/bin/dpkg-deb -f "$LIFECYCLE_ARTIFACT" Package 2>/dev/null)" = rustdesk ] \
        || fail 'lifecycle artifact package identity differs'
    [ "$(/usr/bin/dpkg-deb -f "$LIFECYCLE_ARTIFACT" Architecture 2>/dev/null)" = amd64 ] \
        || fail 'lifecycle artifact architecture differs'
    current_commit="$(git_closed -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
        || fail 'cannot resolve lifecycle source commit'
    [ "$current_commit" = "$LIFECYCLE_COMMIT" ] \
        || fail 'lifecycle source does not equal the artifact commit'
    if git_closed -C "$REPO_ROOT" symbolic-ref --quiet HEAD >/dev/null 2>&1; then
        fail 'lifecycle source must be one detached release snapshot'
    fi
    [ -z "$(git_closed -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all 2>/dev/null)" ] \
        || fail 'lifecycle source snapshot is dirty'
    [ -z "$(git_closed -C "$REPO_ROOT" clean -nffdx 2>/dev/null)" ] \
        || fail 'lifecycle source snapshot retains generated state'
    [ "$(/usr/bin/sha256sum "$DEV_CHECK_DOCKERFILE_SOURCE" | /usr/bin/awk '{ print $1 }')" = \
      "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || fail 'current devcheck Dockerfile differs from its reviewed pin'
    [[ "$DEV_CHECK_DEBIAN_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
        && [[ "$DEV_CHECK_SECURITY_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
        && [[ "$DEV_CHECK_SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] \
        || fail 'devcheck reproducible-acquisition pins are malformed'
    /usr/bin/python3 -I -S "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
        --repo "$REPO_ROOT" --deb "$LIFECYCLE_ARTIFACT" \
        || fail 'lifecycle artifact failed independent package verification'
    LIFECYCLE_ARTIFACT_ID="$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")"
    DEV_CHECK_ARCHIVE_ID="$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$DEV_CHECK_ARCHIVE")"
fi

if [ "$MODE" = android-emulator-runtime ]; then
    [[ "$ANDROID_RUNTIME_ARTIFACT_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android runtime artifact source commit is malformed'
    [[ "$ANDROID_RUNTIME_APK_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'Android runtime APK digest is malformed'
    [ "$(git_closed -C "$REPO_ROOT" rev-parse --verify \
        "${ANDROID_RUNTIME_ARTIFACT_COMMIT}^{commit}" 2>/dev/null)" = \
      "$ANDROID_RUNTIME_ARTIFACT_COMMIT" ] \
        || fail 'Android runtime artifact source commit is absent'
    git_closed -C "$REPO_ROOT" merge-base --is-ancestor \
        "$ANDROID_RUNTIME_ARTIFACT_COMMIT" refs/remotes/origin/master \
        || fail 'Android runtime artifact source commit is not on pushed master history'
    ANDROID_RUNTIME_ARTIFACT_TREE="$(git_closed -C "$REPO_ROOT" rev-parse --verify \
        "${ANDROID_RUNTIME_ARTIFACT_COMMIT}^{tree}")" \
        || fail 'cannot resolve Android runtime artifact source tree'
    [[ "$ANDROID_RUNTIME_ARTIFACT_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'Android runtime artifact source tree is malformed'
    [ -d "$ANDROID_ARTIFACT_STATE_ROOT" ] \
        && [ ! -L "$ANDROID_ARTIFACT_STATE_ROOT" ] \
        && [ "$(/usr/bin/readlink -f -- "$ANDROID_ARTIFACT_STATE_ROOT")" = \
             "$ANDROID_ARTIFACT_STATE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ANDROID_ARTIFACT_STATE_ROOT")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        || fail 'Android runtime artifact state root metadata differs'
    ANDROID_ARTIFACT_INPUT_ROOT="$ANDROID_ARTIFACT_STATE_ROOT/$ANDROID_RUNTIME_ARTIFACT_COMMIT"
    [ -d "$ANDROID_ARTIFACT_INPUT_ROOT" ] \
        && [ ! -L "$ANDROID_ARTIFACT_INPUT_ROOT" ] \
        && [ "$(/usr/bin/readlink -f -- "$ANDROID_ARTIFACT_INPUT_ROOT")" = \
             "$ANDROID_ARTIFACT_INPUT_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ANDROID_ARTIFACT_INPUT_ROOT")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$ANDROID_ARTIFACT_INPUT_ROOT" \
            -mindepth 1 -maxdepth 1 -printf '%f\n')" = \
             "$ANDROID_ARTIFACT_DESTINATION" ] \
        || fail 'commit-bound Android runtime artifact root differs'
    artifact_destination="$ANDROID_ARTIFACT_INPUT_ROOT/$ANDROID_ARTIFACT_DESTINATION"
    artifact_apk="$artifact_destination/rustdesk-x86_64-runtime-test.apk"
    artifact_checksum="$artifact_apk.sha256"
    [ -d "$artifact_destination" ] && [ ! -L "$artifact_destination" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$artifact_destination")" = \
             "$HOST_UID:$HOST_GID:700" ] \
        && [ "$(/usr/bin/find "$artifact_destination" -mindepth 1 -maxdepth 1 \
            -printf '%f\n' | LC_ALL=C /usr/bin/sort)" = \
             $'rustdesk-x86_64-runtime-test.apk\nrustdesk-x86_64-runtime-test.apk.sha256' ] \
        || fail 'Android runtime artifact destination inventory differs'
    for artifact_file in "$artifact_apk" "$artifact_checksum"; do
        [ -f "$artifact_file" ] && [ ! -L "$artifact_file" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$artifact_file")" = \
                 "$HOST_UID:$HOST_GID:400:1" ] \
            || fail "Android runtime artifact file metadata differs: $artifact_file"
    done
    [ "$(<"$artifact_checksum")" = \
      "$ANDROID_RUNTIME_APK_SHA256  rustdesk-x86_64-runtime-test.apk" ] \
        && [ "$(/usr/bin/sha256sum "$artifact_apk" | /usr/bin/awk '{ print $1 }')" = \
             "$ANDROID_RUNTIME_APK_SHA256" ] \
        || fail 'Android runtime artifact digest differs'
    [ -z "$(/usr/bin/findmnt -rn -o TARGET --submounts \
        "$ANDROID_ARTIFACT_INPUT_ROOT")" ] \
        || fail 'Android runtime artifact root contains a descendant mount'
    ANDROID_ARTIFACT_INPUT_ID="$(/usr/bin/stat -c '%d:%i' -- \
        "$ANDROID_ARTIFACT_INPUT_ROOT")"
    ANDROID_ARTIFACT_INPUT_INVENTORY="$(android_runtime_artifact_inventory)" \
        || fail 'cannot inventory the commit-bound Android runtime artifact'
    exec {ANDROID_ARTIFACT_INPUT_FD}<"$ANDROID_ARTIFACT_INPUT_ROOT" \
        || fail 'cannot retain the commit-bound Android runtime artifact root'
    [ "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$ANDROID_ARTIFACT_INPUT_FD")" = \
      "$ANDROID_ARTIFACT_INPUT_ID" ] \
        || fail 'retained Android runtime artifact root identity differs'
fi

RUN="$(/usr/bin/mktemp -d "$RUN_ROOT/run.XXXXXXXXXX")" \
    || fail 'cannot create the private verifier-VM run'
RUN_ID="$(/usr/bin/stat -c '%d:%i' -- "$RUN")"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RUN")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'verifier-VM run is not current-user/current-group mode 0700'
readonly OVERLAY=$RUN/overlay.qcow2
readonly PAYLOAD=$RUN/payload.iso
readonly SEED=$RUN/seed.iso
readonly SERIAL_SOCKET=$RUN/serial.sock
readonly SERIAL_LOG=$RUN/serial.log
readonly CAPTURE_RECEIPT=$RUN/capture.receipt
readonly QMP_SOCKET=$RUN/qmp.sock
readonly QEMU_PIDFILE=$RUN/qemu.pid
readonly LISTENERS_BEFORE=$RUN/listeners.before
readonly LISTENERS_BEFORE_DETAIL=$RUN/listeners.before.detail
readonly LISTENERS_DURING=$RUN/listeners.during
readonly LISTENERS_DURING_DETAIL=$RUN/listeners.during.detail
readonly LISTENERS_AFTER=$RUN/listeners.after
readonly LISTENERS_AFTER_DETAIL=$RUN/listeners.after.detail
readonly NEW_DURING=$RUN/listeners.new-during
readonly NEW_AFTER=$RUN/listeners.new-after
readonly LISTENER_PROCESSES_BEFORE=$RUN/listener-processes.before
readonly EXTERNAL_LISTENER_DRIFT=$RUN/listeners.preexisting-external-drift
readonly RUST_TEST_SOURCE_ARCHIVE=$RUN/source.tar
readonly APPLE_SOURCE_ARCHIVE=$RUN/apple-source.tar
readonly FLUTTER_SOURCE_ARCHIVE=$RUN/flutter-source.tar
readonly ANDROID_OWNER_SOURCE_ARCHIVE=$RUN/android-owner-source.tar
readonly ANDROID_EMULATOR_SOURCE_ARCHIVE=$RUN/android-emulator-source.tar
readonly FLUTTER_PEER_SOURCE_ARCHIVE=$RUN/flutter-peer-source.tar
readonly DART_SOURCE_ARCHIVE=$RUN/dart-source.tar
readonly RUST_AUDIT_SOURCE_ARCHIVE=$RUN/rust-audit-source.tar
readonly VIRTIOFS_SOCKET=$RUN/vfs-input.sock
readonly VIRTIOFSD_LOG=$RUN/virtiofsd-input.log
readonly FLUTTER_CANDIDATE_VIRTIOFS_SOCKET=$RUN/vfs-flutter-candidate.sock
readonly FLUTTER_CANDIDATE_VIRTIOFSD_LOG=$RUN/virtiofsd-flutter-candidate.log
readonly ARTIFACT_VIRTIOFS_SOCKET=$RUN/vfs-artifact.sock
readonly ARTIFACT_VIRTIOFSD_LOG=$RUN/virtiofsd-artifact.log
readonly ARTIFACT_INPUT_VIRTIOFS_SOCKET=$RUN/vfs-artifact-input.sock
readonly ARTIFACT_INPUT_VIRTIOFSD_LOG=$RUN/virtiofsd-artifact-input.log

if [ "$MODE" = android-emulator-app ]; then
    if [ -e "$ANDROID_ARTIFACT_STATE_ROOT" ] \
       || [ -L "$ANDROID_ARTIFACT_STATE_ROOT" ]; then
        [ -d "$ANDROID_ARTIFACT_STATE_ROOT" ] \
            && [ ! -L "$ANDROID_ARTIFACT_STATE_ROOT" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ANDROID_ARTIFACT_STATE_ROOT")" = \
                 "$HOST_UID:$HOST_GID:700" ] \
            || fail 'Android artifact state root metadata differs'
    else
        /usr/bin/install -d -m 0700 -- "$ANDROID_ARTIFACT_STATE_ROOT"
        ARTIFACT_STATE_ROOT_CREATED=1
    fi
    ARTIFACT_STATE_ROOT_ID="$(/usr/bin/stat -c '%d:%i' -- "$ANDROID_ARTIFACT_STATE_ROOT")"
    [ -z "$(/usr/bin/findmnt -rn -o TARGET --submounts "$ANDROID_ARTIFACT_STATE_ROOT")" ] \
        || fail 'Android artifact state root contains a descendant mount'
    ARTIFACT_OUTPUT_PARENT="$ANDROID_ARTIFACT_STATE_ROOT/$ANDROID_EMULATOR_SOURCE_COMMIT"
    [ ! -e "$ARTIFACT_OUTPUT_PARENT" ] && [ ! -L "$ARTIFACT_OUTPUT_PARENT" ] \
        || fail 'commit-bound Android artifact output already exists'
    /usr/bin/install -d -m 0700 -- "$ARTIFACT_OUTPUT_PARENT"
    ARTIFACT_OUTPUT_PARENT_ID="$(/usr/bin/stat -c '%d:%i' -- "$ARTIFACT_OUTPUT_PARENT")"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ARTIFACT_OUTPUT_PARENT")" = \
      "$HOST_UID:$HOST_GID:700" ] \
        && [ -z "$(/usr/bin/find "$ARTIFACT_OUTPUT_PARENT" -mindepth 1 -print -quit)" ] \
        || fail 'commit-bound Android artifact output metadata differs'
    exec {ARTIFACT_OUTPUT_FD}<"$ARTIFACT_OUTPUT_PARENT" \
        || fail 'cannot retain the commit-bound Android artifact output'
    [ "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$ARTIFACT_OUTPUT_FD")" = \
      "$ARTIFACT_OUTPUT_PARENT_ID" ] \
        || fail 'retained Android artifact output identity differs'
fi

base_before="$(/usr/bin/sha512sum "$BASE")"
docker_before="$(/usr/bin/sha256sum "$DOCKER_BUNDLE")"
git_package_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$GIT_PACKAGE"):$(/usr/bin/sha256sum "$GIT_PACKAGE")"
boot_root_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")"
kernel_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")"
initrd_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")"
sources_before="$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" "$RUST_AUDIT_DOCKERFILE_SOURCE" "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" "$ANDROID_BUILDER_SOURCE" "$ANDROID_APK_BUILD_SOURCE" "$ANDROID_BUILDER_CHECKER" "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" "$WINDOWS_HELPER_RUNTIME_TEST" "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" "$ANDROID_RUST_SOURCE" "$ANDROID_EMULATOR_BOOT_SOURCE" "$ANDROID_EMULATOR_APP_SOURCE" "$ANDROID_EMULATOR_RUNTIME_SOURCE" "$ANDROID_EMULATOR_APK_VERIFIER" "$ANDROID_APK_MANIFEST_VERIFIER" "$ARTIFACT_RESULT_PUBLISHER_SOURCE" "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" "$ONLINE_FETCH_VM_SOURCE" "$ONLINE_FETCH_VM_GUEST_SOURCE" "$ONLINE_FETCH_ENTRY_PREFLIGHT" "$ONLINE_FETCH_AUTHORITY_CHECKER" "$ONLINE_FETCH_RENAME_CHECKER" "$ONLINE_PUB_CACHE_OUTPUT_SOURCE" "$ONLINE_GRADLE_OUTPUT_SOURCE" "$ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER" "$ANDROID_GRADLE_CACHE_PROJECTOR" "$ANDROID_GRADLE_WRAPPER_PROPERTIES" "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" "$LIB_SOURCE" "$PIN_SOURCE")"
focused_inputs_before=
if [ "$MODE" = hbb-common-fs ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
elif [ "$MODE" = apple-conform ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$CARGO_VENDOR_CONFIG" "$APPLE_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- \
            "$CARGO_VENDOR_CONFIG" "$APPLE_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
elif [ "$MODE" = android-rust-target-check ]; then
    focused_inputs_before="$(android_rust_target_input_inventory)" \
        || fail 'cannot inventory the sealed Android Rust target-check inputs'
elif [ "$MODE" = flutter-peer-presentation ]; then
    focused_inputs_before="$(flutter_peer_input_inventory)" \
        || fail 'cannot inventory the sealed Flutter full-peer inputs'
elif [ "$MODE" = flutter-model-tests ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
elif [ "$MODE" = android-owner-tests ]; then
    focused_inputs_before="$(android_owner_input_inventory)" \
        || fail 'cannot inventory the sealed Android owner-state inputs'
elif [ "$MODE" = android-emulator-runtime ]; then
    focused_inputs_before="$(android_emulator_runtime_input_inventory)" \
        || fail 'cannot inventory the sealed Android runtime inputs'
elif [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ]; then
    focused_inputs_before="$(android_emulator_input_inventory)" \
        || fail 'cannot inventory the sealed Android emulator inputs'
elif [ "$MODE" = dart-audit ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE"
        /usr/bin/sha256sum -- "$DART_AUDIT_IMAGE_ARCHIVE"
    )"
elif [ "$MODE" = rust-audit ]; then
    focused_inputs_before="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$CARGO_VENDOR_CONFIG" "$RUST_AUDIT_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- \
            "$CARGO_VENDOR_CONFIG" "$RUST_AUDIT_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
fi
capture_process_generations >"$LISTENER_PROCESSES_BEFORE"
capture_listeners >"$LISTENERS_BEFORE"
capture_listener_details >"$LISTENERS_BEFORE_DETAIL"
: >"$EXTERNAL_LISTENER_DRIFT"
/usr/bin/qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "$OVERLAY_SIZE"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OVERLAY")" = "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'pass-private overlay metadata differs'

if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$RUST_TEST_SOURCE_COMMIT" \
        >"$RUST_TEST_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Rust-workload source archive'
    /usr/bin/chmod 0400 "$RUST_TEST_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Rust-workload source archive metadata differs'
    RUST_TEST_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = apple-conform ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$APPLE_SOURCE_COMMIT" \
        >"$APPLE_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact Apple-conformance source archive'
    /usr/bin/chmod 0400 "$APPLE_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$APPLE_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'Apple-conformance source archive metadata differs'
    APPLE_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$APPLE_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = flutter-model-tests ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$FLUTTER_SOURCE_COMMIT" \
        >"$FLUTTER_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Flutter-test source archive'
    /usr/bin/chmod 0400 "$FLUTTER_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Flutter-test source archive metadata differs'
    FLUTTER_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$FLUTTER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = android-owner-tests ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$ANDROID_OWNER_SOURCE_COMMIT" \
        >"$ANDROID_OWNER_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Android owner-state source archive'
    /usr/bin/chmod 0400 "$ANDROID_OWNER_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$ANDROID_OWNER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Android owner-state source archive metadata differs'
    ANDROID_OWNER_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$ANDROID_OWNER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$ANDROID_EMULATOR_SOURCE_COMMIT" \
        >"$ANDROID_EMULATOR_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact Android emulator harness source archive'
    /usr/bin/chmod 0400 "$ANDROID_EMULATOR_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'Android emulator harness source archive metadata differs'
    ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = flutter-peer-presentation ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$FLUTTER_PEER_SOURCE_COMMIT" \
        >"$FLUTTER_PEER_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Flutter-peer source archive'
    /usr/bin/chmod 0400 "$FLUTTER_PEER_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_PEER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Flutter-peer source archive metadata differs'
    FLUTTER_PEER_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$FLUTTER_PEER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
elif [ "$MODE" = dart-audit ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$DART_SOURCE_COMMIT" \
        >"$DART_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Dart-audit source archive'
    /usr/bin/chmod 0400 "$DART_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DART_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Dart-audit source archive metadata differs'
    DART_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$DART_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
elif [ "$MODE" = rust-audit ]; then
    git_closed -C "$REPO_ROOT" archive --format=tar "$RUST_AUDIT_SOURCE_COMMIT" \
        >"$RUST_AUDIT_SOURCE_ARCHIVE" \
        || fail 'cannot create the exact focused Rust-audit source archive'
    /usr/bin/chmod 0400 "$RUST_AUDIT_SOURCE_ARCHIVE"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_AUDIT_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'focused Rust-audit source archive metadata differs'
    RUST_AUDIT_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$RUST_AUDIT_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }'
    )"
    /usr/bin/install -d -m 0700 -- "$RUN/virtiofsd-package"
    /usr/bin/dpkg-deb --extract "$VIRTIOFSD_PACKAGE" "$RUN/virtiofsd-package" \
        || fail 'cannot extract the authenticated virtiofsd package privately'
    VIRTIOFSD_BINARY="$RUN/virtiofsd-package/usr/libexec/virtiofsd"
    [ -f "$VIRTIOFSD_BINARY" ] && [ ! -L "$VIRTIOFSD_BINARY" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%h:%s' -- "$VIRTIOFSD_BINARY")" = \
             "$HOST_UID:$HOST_GID:1:$SIZE_VERIFIER_VM_VIRTIOFSD_BINARY" ] \
        || fail 'extracted virtiofsd binary is absent or ambiguous'
    /usr/bin/chmod 0500 "$VIRTIOFSD_BINARY"
    verify_sha256 "$VIRTIOFSD_BINARY" "$SHA256_VERIFIER_VM_VIRTIOFSD_BINARY"
fi

payload_identity=()
lifecycle_payload_grafts=()
if [ "$MODE" = debian-systemd-lifecycle ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=(
        "devcheck.docker.tar.gz=$DEV_CHECK_ARCHIVE"
        "artifact/rustdesk-x86_64.deb=$LIFECYCLE_ARTIFACT"
    )
elif [ "$MODE" = hbb-common-fs ] || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$RUST_TEST_SOURCE_ARCHIVE")
elif [ "$MODE" = apple-conform ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$APPLE_SOURCE_ARCHIVE")
elif [ "$MODE" = flutter-model-tests ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$FLUTTER_SOURCE_ARCHIVE")
elif [ "$MODE" = android-owner-tests ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$ANDROID_OWNER_SOURCE_ARCHIVE")
elif [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=("source.tar=$ANDROID_EMULATOR_SOURCE_ARCHIVE")
elif [ "$MODE" = flutter-peer-presentation ]; then
    payload_identity=(-uid 1000 -gid 1000)
    lifecycle_payload_grafts=("source.tar=$FLUTTER_PEER_SOURCE_ARCHIVE")
elif [ "$MODE" = dart-audit ]; then
    payload_identity=(-uid 4000 -gid 4000)
    lifecycle_payload_grafts=(
        "source.tar=$DART_SOURCE_ARCHIVE"
        "dart-audit.docker.tar.gz=$DART_AUDIT_IMAGE_ARCHIVE"
    )
elif [ "$MODE" = rust-audit ]; then
    payload_identity=(-uid 1000 -gid 1000)
    lifecycle_payload_grafts=(
        "source.tar=$RUST_AUDIT_SOURCE_ARCHIVE"
        "rust-audit.docker.tar.gz=$RUST_AUDIT_IMAGE_ARCHIVE"
    )
fi
/usr/bin/xorriso -as mkisofs -quiet -iso-level 3 -volid RD_VERIFIER_INPUTS \
    -joliet -rock "${payload_identity[@]}" -graft-points -output "$PAYLOAD" \
    "guest.sh=$GUEST_SCRIPT" \
    "repo/scripts/verify.sh=$VERIFY_SCRIPT" \
    "repo/scripts/verify-release.sh=$VERIFY_RELEASE_SOURCE" \
    "repo/scripts/build-release.sh=$RELEASE_PARENT_SOURCE" \
    "repo/scripts/publish-github-release.sh=$RELEASE_PUBLISHER_SOURCE" \
    "repo/scripts/finalize-release-set.py=$RELEASE_FINALIZER_SOURCE" \
    "repo/scripts/verify-release-workspace-runtime.sh=$RELEASE_WORKSPACE_RUNTIME_TEST" \
    "repo/scripts/fork-version.sh=$FORK_VERSION_SOURCE" \
    "repo/scripts/apple-conform-check.sh=$APPLE_CHECK_SOURCE" \
    "repo/scripts/apple-toolchain-release.py=$APPLE_TOOLCHAIN_RELEASE_SOURCE" \
    "repo/scripts/smoke-flutter-peer-presentation.sh=$FLUTTER_PEER_SOURCE" \
    "repo/scripts/finalize-flutter-tools-offline.sh=$FLUTTER_TOOLS_FINALIZER_SOURCE" \
    "repo/scripts/frb-codegen.sh=$FRB_CODEGEN_SOURCE" \
    "repo/scripts/dart-verify.sh=$DART_VERIFY_SOURCE" \
    "repo/scripts/smoke-server.sh=$SMOKE_SERVER_SOURCE" \
    "repo/scripts/audit.sh=$RUST_AUDIT_SOURCE" \
    "repo/scripts/rust-audit-policy.py=$RUST_AUDIT_POLICY_SOURCE" \
    "repo/scripts/verify-rust-audit-authority.py=$RUST_AUDIT_CHECKER" \
    "repo/scripts/Dockerfile.audit=$RUST_AUDIT_DOCKERFILE_SOURCE" \
    "repo/scripts/gen-android-keystore.sh=$ANDROID_KEYSTORE_SOURCE" \
    "repo/scripts/android-keystore-generate.sh=$ANDROID_KEYSTORE_INNER" \
    "repo/scripts/verify-android-keystore-authority.py=$ANDROID_KEYSTORE_CHECKER" \
    "repo/scripts/build-android.sh=$ANDROID_BUILDER_SOURCE" \
    "repo/scripts/android-apk-build.sh=$ANDROID_APK_BUILD_SOURCE" \
    "repo/scripts/verify-android-builder-authority.py=$ANDROID_BUILDER_CHECKER" \
    "repo/scripts/test-android-gradle-cache.sh=$ANDROID_GRADLE_SOURCE" \
    "repo/scripts/verify-android-gradle-authority.py=$ANDROID_GRADLE_CHECKER" \
    "repo/scripts/verify-android-builder-image-authority.py=$ANDROID_BUILDER_IMAGE_CHECKER" \
    "repo/scripts/verify-deb-builder-image-authority.py=$DEB_BUILDER_IMAGE_CHECKER" \
    "repo/scripts/build-debian.sh=$DEBIAN_BUILDER_SOURCE" \
    "repo/scripts/verify-debian-builder-authority.py=$DEBIAN_BUILDER_AUTHORITY_CHECKER" \
    "repo/scripts/stage-debian-systemd-runtime-libs.sh=$SYSTEMD_RUNTIME_LIBS_SOURCE" \
    "repo/scripts/smoke-debian-systemd-lifecycle-guest.sh=$SYSTEMD_LIFECYCLE_GUEST_SOURCE" \
    "repo/scripts/smoke-debian-systemd-loginctl.sh=$SYSTEMD_LOGINCTL_SOURCE" \
    "repo/scripts/verify-debian-package-authority.py=$DEBIAN_PACKAGE_AUTHORITY_SOURCE" \
    "repo/scripts/verify-win-helper-image-authority.py=$WIN_HELPER_IMAGE_CHECKER" \
    "repo/scripts/verify-windows-helper-authority.py=$WINDOWS_HELPER_AUTHORITY_CHECKER" \
    "repo/scripts/test-windows-helper-vm-runtime.sh=$WINDOWS_HELPER_RUNTIME_TEST" \
    "repo/scripts/Dockerfile.android-builder=$ANDROID_BUILDER_DOCKERFILE" \
    "repo/scripts/Dockerfile.deb-builder=$DEB_BUILDER_DOCKERFILE" \
    "repo/scripts/Dockerfile.win-helper=$WIN_HELPER_DOCKERFILE" \
    "repo/scripts/Dockerfile.builder-bootstrap-seal=$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" \
    "repo/scripts/Dockerfile.android-builder-certify=$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/Dockerfile.deb-builder-certify=$DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/Dockerfile.win-helper-certify=$WIN_HELPER_CERTIFICATION_DOCKERFILE" \
    "repo/scripts/windows-helper-runtime.sh=$WINDOWS_HELPER_RUNTIME_SOURCE" \
    "repo/scripts/windows-helper-extract-kernel.py=$WINDOWS_HELPER_EXTRACTOR" \
    "repo/scripts/windows-golden-inspect.sh=$WINDOWS_GOLDEN_INSPECTOR" \
    "repo/scripts/build-windows-vm.sh=$WINDOWS_BUILD_SOURCE" \
    "repo/scripts/provision-windows-vm.sh=$WINDOWS_PROVISION_SOURCE" \
    "repo/scripts/verify-windows-golden.sh=$WINDOWS_GOLDEN_SOURCE" \
    "repo/scripts/android-rust-check.sh=$ANDROID_RUST_SOURCE" \
    "repo/scripts/smoke-android-emulator-boot.sh=$ANDROID_EMULATOR_BOOT_SOURCE" \
    "repo/scripts/android-emulator-app-check.sh=$ANDROID_EMULATOR_APP_SOURCE" \
    "repo/scripts/android-emulator-runtime-check.sh=$ANDROID_EMULATOR_RUNTIME_SOURCE" \
    "repo/scripts/verify-android-emulator-apk.py=$ANDROID_EMULATOR_APK_VERIFIER" \
    "repo/scripts/verify-android-apk-manifest.py=$ANDROID_APK_MANIFEST_VERIFIER" \
    "repo/scripts/publish-artifact-result.py=$ARTIFACT_RESULT_PUBLISHER_SOURCE" \
    "repo/scripts/offline-image-provenance.py=$OFFLINE_IMAGE_PROVENANCE_SOURCE" \
    "repo/scripts/online-fetch.sh=$ONLINE_FETCH_SOURCE" \
    "repo/scripts/online-fetch-vm.sh=$ONLINE_FETCH_VM_SOURCE" \
    "repo/scripts/online-fetch-vm-guest.sh=$ONLINE_FETCH_VM_GUEST_SOURCE" \
    "repo/scripts/verify-online-fetch-vm-entry.sh=$ONLINE_FETCH_ENTRY_PREFLIGHT" \
    "repo/scripts/verify-online-fetch-container-authority.py=$ONLINE_FETCH_AUTHORITY_CHECKER" \
    "repo/scripts/verify-online-fetch-virtiofs-rename.py=$ONLINE_FETCH_RENAME_CHECKER" \
    "repo/scripts/launch-landlocked-virtiofsd.py=$VIRTIOFSD_LAUNCHER" \
    "repo/scripts/online-pub-cache-output.py=$ONLINE_PUB_CACHE_OUTPUT_SOURCE" \
    "repo/scripts/online-gradle-output.py=$ONLINE_GRADLE_OUTPUT_SOURCE" \
    "repo/scripts/verify-online-fetch-gradle-output-authority.py=$ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER" \
    "repo/scripts/android-gradle-cache.py=$ANDROID_GRADLE_CACHE_PROJECTOR" \
    "repo/flutter/android/gradle/wrapper/gradle-wrapper.properties=$ANDROID_GRADLE_WRAPPER_PROPERTIES" \
    "repo/scripts/dart-audit.sh=$DART_AUDIT_SOURCE" \
    "repo/scripts/dart-audit-result.py=$DART_AUDIT_RESULT_SOURCE" \
    "repo/scripts/verify-dart-verifier-authority.py=$DART_AUTHORITY_CHECKER" \
    "repo/scripts/verify-dart-audit-authority.py=$DART_AUDIT_CHECKER" \
    "repo/scripts/verify-vm-entry-preflight.sh=$ENTRY_PREFLIGHT" \
    "repo/scripts/verify-scan.sh=$VERIFY_SCAN_SOURCE" \
    "repo/scripts/verify-private-tree-closure.py=$CLEANUP_HELPER" \
    "repo/scripts/smoke-verifier-vm-authority.sh=$OUTER_SOURCE" \
    "repo/scripts/smoke-verifier-vm-authority-guest.sh=$GUEST_SCRIPT" \
    "repo/scripts/lib.sh=$LIB_SOURCE" "repo/scripts/pins.env=$PIN_SOURCE" \
    "repo/requirements.html=$REQUIREMENTS_SOURCE" \
    "repo/HARDENING_STATUS.md=$HARDENING_SOURCE" \
    "repo/res/rustdesk.service=$SYSTEMD_UNIT_SOURCE" \
    "repo/scripts/Dockerfile.devcheck=$DEV_CHECK_DOCKERFILE_SOURCE" \
    "docker.tgz=$DOCKER_BUNDLE" \
    "git.deb=$GIT_PACKAGE" \
    "${lifecycle_payload_grafts[@]}"
/usr/bin/chmod 0400 "$PAYLOAD"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$PAYLOAD")" = \
  "$HOST_UID:$HOST_GID:400:1" ] \
    || fail 'read-only payload media metadata differs'
/usr/bin/mkdir "$RUN/seed"
/usr/bin/chmod 0700 "$RUN/seed"
guest_invocation="bash /mnt/rustdesk-verifier-inputs/guest.sh /mnt/rustdesk-verifier-inputs/docker.tgz /mnt/rustdesk-verifier-inputs/repo/scripts/verify-vm-entry-preflight.sh $VERIFIER_VM_DOCKER_VERSION $SIZE_VERIFIER_VM_DOCKER_STATIC $SHA256_VERIFIER_VM_DOCKER_STATIC $VERIFIER_VM_KERNEL_RELEASE $VERIFIER_VM_ROOT_FILESYSTEM_UUID"
if [ "$MODE" = debian-systemd-lifecycle ]; then
    guest_invocation+=" --debian-systemd-lifecycle /mnt/rustdesk-verifier-inputs/devcheck.docker.tar.gz /mnt/rustdesk-verifier-inputs/artifact/rustdesk-x86_64.deb $LIFECYCLE_ARTIFACT_SHA256 $LIFECYCLE_COMMIT"
elif [ "$MODE" = hbb-common-fs ]; then
    guest_invocation+=" --hbb-common-fs /mnt/rustdesk-verifier-inputs/source.tar $RUST_TEST_SOURCE_COMMIT $RUST_TEST_SOURCE_TREE $RUST_TEST_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    guest_invocation+=" --android-rust-lifecycle-tests /mnt/rustdesk-verifier-inputs/source.tar $RUST_TEST_SOURCE_COMMIT $RUST_TEST_SOURCE_TREE $RUST_TEST_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-rust-target-check ]; then
    guest_invocation+=" --android-rust-target-check /mnt/rustdesk-verifier-inputs/source.tar $RUST_TEST_SOURCE_COMMIT $RUST_TEST_SOURCE_TREE $RUST_TEST_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = apple-conform ]; then
    guest_invocation+=" --apple-conform /mnt/rustdesk-verifier-inputs/source.tar $APPLE_SOURCE_COMMIT $APPLE_SOURCE_TREE $APPLE_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = flutter-model-tests ]; then
    guest_invocation+=" --flutter-model-tests /mnt/rustdesk-verifier-inputs/source.tar $FLUTTER_SOURCE_COMMIT $FLUTTER_SOURCE_TREE $FLUTTER_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-owner-tests ]; then
    guest_invocation+=" --android-owner-tests /mnt/rustdesk-verifier-inputs/source.tar $ANDROID_OWNER_SOURCE_COMMIT $ANDROID_OWNER_SOURCE_TREE $ANDROID_OWNER_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-emulator-boot ]; then
    guest_invocation+=" --android-emulator-boot /mnt/rustdesk-verifier-inputs/source.tar $ANDROID_EMULATOR_SOURCE_COMMIT $ANDROID_EMULATOR_SOURCE_TREE $ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-emulator-app ]; then
    guest_invocation+=" --android-emulator-app /mnt/rustdesk-verifier-inputs/source.tar $ANDROID_EMULATOR_SOURCE_COMMIT $ANDROID_EMULATOR_SOURCE_TREE $ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256"
elif [ "$MODE" = android-emulator-runtime ]; then
    guest_invocation+=" --android-emulator-runtime /mnt/rustdesk-verifier-inputs/source.tar $ANDROID_EMULATOR_SOURCE_COMMIT $ANDROID_EMULATOR_SOURCE_TREE $ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256 $ANDROID_RUNTIME_ARTIFACT_COMMIT $ANDROID_RUNTIME_ARTIFACT_TREE $ANDROID_RUNTIME_APK_SHA256"
elif [ "$MODE" = flutter-peer-presentation ]; then
    if [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        guest_invocation+=" --flutter-peer-presentation-candidate /mnt/rustdesk-verifier-inputs/source.tar $FLUTTER_PEER_SOURCE_COMMIT $FLUTTER_PEER_SOURCE_TREE $FLUTTER_PEER_SOURCE_ARCHIVE_SHA256"
    else
        guest_invocation+=" --flutter-peer-presentation /mnt/rustdesk-verifier-inputs/source.tar $FLUTTER_PEER_SOURCE_COMMIT $FLUTTER_PEER_SOURCE_TREE $FLUTTER_PEER_SOURCE_ARCHIVE_SHA256"
    fi
elif [ "$MODE" = dart-audit ]; then
    guest_invocation+=" --dart-audit /mnt/rustdesk-verifier-inputs/source.tar $DART_SOURCE_COMMIT $DART_SOURCE_TREE $DART_SOURCE_ARCHIVE_SHA256 /mnt/rustdesk-verifier-inputs/dart-audit.docker.tar.gz"
elif [ "$MODE" = rust-audit ]; then
    guest_invocation+=" --rust-audit /mnt/rustdesk-verifier-inputs/source.tar $RUST_AUDIT_SOURCE_COMMIT $RUST_AUDIT_SOURCE_TREE $RUST_AUDIT_SOURCE_ARCHIVE_SHA256 /mnt/rustdesk-verifier-inputs/rust-audit.docker.tar.gz"
fi
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'finish() {' \
    '    status=$?' \
    '    trap - EXIT' \
    '    if [ "$status" -eq 0 ]; then' \
    '        echo VERIFIER_VM_CLOUD_INIT=pass' \
    '    else' \
    '        echo VERIFIER_VM_CLOUD_INIT=fail status=$status' \
    '    fi' \
    '    sync' \
    '    systemctl poweroff --no-block || poweroff -f' \
    '    exit "$status"' \
    '}' \
    'trap finish EXIT' \
    'mkdir -p /mnt/rustdesk-verifier-inputs' \
    'mount -L RD_VERIFIER_INPUTS -o ro,nodev,nosuid,noexec /mnt/rustdesk-verifier-inputs' \
    "$guest_invocation" \
    >"$RUN/seed/user-data"
printf '%s\n' \
    'instance-id: rustdesk-verifier-authority-v1' \
    'local-hostname: rustdesk-verifier-authority' \
    >"$RUN/seed/meta-data"
printf '%s\n' 'version: 2' 'ethernets: {}' >"$RUN/seed/network-config"
(
    cd "$RUN/seed"
    /usr/bin/xorriso -as mkisofs -quiet -volid CIDATA -joliet -rock \
        -output "$SEED" user-data meta-data network-config
)
/usr/bin/chmod 0400 "$SEED"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$SEED")" = \
  "$HOST_UID:$HOST_GID:400:1" ] \
    || fail 'read-only cloud-init media metadata differs'

exec {KERNEL_FD}<"$KERNEL" || fail 'cannot retain the exact verifier-VM kernel'
exec {INITRD_FD}<"$INITRD" || fail 'cannot retain the exact verifier-VM initramfs'
[ "$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "/proc/$$/fd/$KERNEL_FD")" = \
  "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL")" ] \
    || fail 'retained kernel descriptor identity differs'
[ "$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "/proc/$$/fd/$INITRD_FD")" = \
  "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD")" ] \
    || fail 'retained initramfs descriptor identity differs'
memory_args=(-m "$VM_MEMORY")
focused_qemu_args=()
if [ "$MODE" = hbb-common-fs ] || [ "$MODE" = android-rust-lifecycle-tests ] \
   || [ "$MODE" = android-rust-target-check ] \
   || [ "$MODE" = apple-conform ] \
   || [ "$MODE" = flutter-model-tests ] \
   || [ "$MODE" = android-owner-tests ] \
   || [ "$MODE" = android-emulator-boot ] \
   || [ "$MODE" = android-emulator-app ] \
   || [ "$MODE" = android-emulator-runtime ] \
   || [ "$MODE" = flutter-peer-presentation ] \
   || [ "$MODE" = rust-audit ]; then
    start_virtiofsd sealed-input "$SEALED_INPUT_ROOT" \
        "$(/usr/bin/stat -c '%d:%i' -- "$SEALED_INPUT_ROOT")" \
        "$VIRTIOFS_SOCKET" "$VIRTIOFSD_LOG"
    focused_qemu_args=(
        -chardev "socket,id=sealed-input,path=$VIRTIOFS_SOCKET"
        -device "vhost-user-fs-pci,chardev=sealed-input,tag=rustdesk-sealed-inputs,queue-size=1024"
    )
    if [ "$MODE" = flutter-peer-presentation ] \
       && [ "$FLUTTER_PEER_CANDIDATE" -eq 1 ]; then
        start_virtiofsd sealed-input "$FLUTTER_PEER_CANDIDATE_ROOT" \
            "$(/usr/bin/stat -c '%d:%i' -- "$FLUTTER_PEER_CANDIDATE_ROOT")" \
            "$FLUTTER_CANDIDATE_VIRTIOFS_SOCKET" "$FLUTTER_CANDIDATE_VIRTIOFSD_LOG"
        focused_qemu_args+=(
            -chardev "socket,id=flutter-candidate-input,path=$FLUTTER_CANDIDATE_VIRTIOFS_SOCKET"
            -device "vhost-user-fs-pci,chardev=flutter-candidate-input,tag=rustdesk-flutter-candidate-input,queue-size=1024"
        )
    elif [ "$MODE" = android-emulator-app ]; then
        start_virtiofsd bounded-result "$ARTIFACT_OUTPUT_PARENT" \
            "$ARTIFACT_OUTPUT_PARENT_ID" \
            "$ARTIFACT_VIRTIOFS_SOCKET" "$ARTIFACT_VIRTIOFSD_LOG"
        focused_qemu_args+=(
            -chardev "socket,id=artifact-output,path=$ARTIFACT_VIRTIOFS_SOCKET"
            -device "vhost-user-fs-pci,chardev=artifact-output,tag=rustdesk-android-artifact-output,queue-size=1024"
        )
    elif [ "$MODE" = android-emulator-runtime ]; then
        start_virtiofsd sealed-input "$ANDROID_ARTIFACT_INPUT_ROOT" \
            "$ANDROID_ARTIFACT_INPUT_ID" \
            "$ARTIFACT_INPUT_VIRTIOFS_SOCKET" "$ARTIFACT_INPUT_VIRTIOFSD_LOG"
        focused_qemu_args+=(
            -chardev "socket,id=artifact-input,path=$ARTIFACT_INPUT_VIRTIOFS_SOCKET"
            -device "vhost-user-fs-pci,chardev=artifact-input,tag=rustdesk-android-artifact-input,queue-size=1024"
        )
    fi
    memory_args=(
        -m "$VM_MEMORY"
        -object "memory-backend-memfd,id=mem,size=${VM_MEMORY}M,share=on"
        -numa node,memdev=mem
    )
    capture_listeners >"$LISTENERS_DURING"
    /usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$NEW_DURING"
    if [ -s "$NEW_DURING" ]; then
        capture_listener_details >"$LISTENERS_DURING_DETAIL"
        admit_preexisting_external_listener_drift \
            "$NEW_DURING" "$LISTENERS_DURING_DETAIL" virtiofsd-start \
            || { /usr/bin/cat "$LISTENERS_DURING_DETAIL" >&2; fail 'sealed-input virtiofsd created or coincided with an unattributable host INET listener'; }
    fi
fi
vm_started_seconds=$SECONDS
/usr/bin/timeout --signal=TERM --kill-after=10s "${VM_TIMEOUT_SECONDS}s" \
    /usr/bin/qemu-system-x86_64 \
        -name rustdesk-verifier-authority \
        -machine q35 \
        -accel kvm \
        -cpu host \
        "${memory_args[@]}" \
        -smp "$VM_CPUS" \
        -no-reboot \
        -no-user-config \
        -nodefaults \
        -display none \
        -parallel none \
        -nic none \
        -kernel "/proc/self/fd/$KERNEL_FD" \
        -initrd "/proc/self/fd/$INITRD_FD" \
        -append "root=UUID=$VERIFIER_VM_ROOT_FILESYSTEM_UUID rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.verifier_vm=1 systemd.mask=systemd-networkd-wait-online.service systemd.mask=ssh.service systemd.mask=ssh.socket" \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
        -pidfile "$QEMU_PIDFILE" \
        -chardev "socket,id=serial0,path=$SERIAL_SOCKET,server=on,wait=on" \
        -device isa-serial,chardev=serial0 \
        -qmp "unix:$QMP_SOCKET,server=on,wait=off" \
        "${focused_qemu_args[@]}" \
        -drive "file=$OVERLAY,if=virtio,format=qcow2,cache=none" \
        -drive "file=$SEED,if=virtio,format=raw,media=cdrom,readonly=on" \
        -drive "file=$PAYLOAD,if=virtio,format=raw,media=cdrom,readonly=on" &
VM_OWNER_PID=$!
VM_OWNER_START="$(process_start_time "$VM_OWNER_PID")" \
    || fail 'cannot record QEMU timeout-owner process identity'

for _ in $(/usr/bin/seq 1 200); do
    [ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] && break
    kill -0 "$VM_OWNER_PID" 2>/dev/null || fail 'QEMU owner exited before creating private channels'
    /usr/bin/sleep 0.05
done
[ -S "$SERIAL_SOCKET" ] && [ -s "$QEMU_PIDFILE" ] \
    || fail 'QEMU serial channel and process identity did not become ready'
is_exact_vm_owner_process || fail 'QEMU timeout-owner process identity changed'
verify_private_socket "$SERIAL_SOCKET" \
    || fail 'QEMU serial channel is not one current-user-private Unix socket'
[ -f "$QEMU_PIDFILE" ] && [ ! -L "$QEMU_PIDFILE" ] \
    || fail 'QEMU PID record is absent or symlinked'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$QEMU_PIDFILE")" = \
  "$HOST_UID:$HOST_GID:600:1" ] \
    || fail 'QEMU PID record metadata differs'
VM_PID="$(<"$QEMU_PIDFILE")"
[[ "$VM_PID" =~ ^[1-9][0-9]*$ ]] || fail 'QEMU PID file is malformed'
[ "$(/usr/bin/readlink -f "/proc/$VM_PID/exe")" = /usr/bin/qemu-system-x86_64 ] \
    || fail 'QEMU PID does not identify the fixed hypervisor'
VM_START="$(process_start_time "$VM_PID")" || fail 'cannot record QEMU process identity'
for index in "${!VIRTIOFSD_PIDS[@]}"; do
    virtiofsd_pid=${VIRTIOFSD_PIDS[index]}
    virtiofsd_start=${VIRTIOFSD_STARTS[index]}
    virtiofsd_log=${VIRTIOFSD_LOGS[index]}
    virtiofsd_seccomp_ready=0
    for _ in $(/usr/bin/seq 1 1000); do
        if virtiofsd_seccomp_enforced "$virtiofsd_pid" "$virtiofsd_start"; then
            virtiofsd_seccomp_ready=1
            break
        fi
        is_exact_virtiofsd_process "$virtiofsd_pid" "$virtiofsd_start" \
            || { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail 'virtiofsd exited during QEMU startup'; }
        /usr/bin/sleep 0.01
    done
    [ "$virtiofsd_seccomp_ready" -eq 1 ] \
        || { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail 'virtiofsd did not enforce seccomp after QEMU connected'; }
done

/usr/bin/python3 -I -S "$CAPTURE_HELPER" \
    --socket "$SERIAL_SOCKET" --output "$SERIAL_LOG" --max-bytes "$SERIAL_LIMIT" \
    >"$CAPTURE_RECEIPT" &
CAPTURE_PID=$!
CAPTURE_START="$(process_start_time "$CAPTURE_PID")" \
    || fail 'cannot record bounded serial-capture process identity'
for _ in $(/usr/bin/seq 1 200); do
    [ -S "$QMP_SOCKET" ] && break
    kill -0 "$VM_OWNER_PID" 2>/dev/null || fail 'QEMU owner exited before creating its QMP channel'
    kill -0 "$CAPTURE_PID" 2>/dev/null || fail 'bounded serial capture exited during QEMU startup'
    /usr/bin/sleep 0.05
done
[ -S "$QMP_SOCKET" ] || fail 'QEMU private QMP channel did not become ready'
is_exact_capture_process || fail 'bounded serial-capture process identity changed'
verify_private_socket "$QMP_SOCKET" \
    || fail 'QEMU control channel is not one current-user-private Unix socket'
capture_listeners >"$LISTENERS_DURING"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$NEW_DURING"
if [ -s "$NEW_DURING" ]; then
    capture_listener_details >"$LISTENERS_DURING_DETAIL"
    admit_preexisting_external_listener_drift \
        "$NEW_DURING" "$LISTENERS_DURING_DETAIL" qemu-start \
        || { /usr/bin/cat "$LISTENERS_DURING_DETAIL" >&2; fail 'QEMU created or coincided with an unattributable host INET listener'; }
fi
vm_status=0
wait "$VM_OWNER_PID" || vm_status=$?
VM_OWNER_PID=
VM_OWNER_START=
vm_elapsed_seconds=$((SECONDS - vm_started_seconds))
capture_status=0
wait "$CAPTURE_PID" || capture_status=$?
CAPTURE_PID=
CAPTURE_START=
[ "$vm_status" -eq 0 ] || { tail -n 240 "$SERIAL_LOG" >&2; fail "networkless verifier VM exited with status $vm_status"; }
[ "$capture_status" -eq 0 ] || fail "bounded serial capture exited with status $capture_status"
for index in "${!VIRTIOFSD_PIDS[@]}"; do
    virtiofsd_pid=${VIRTIOFSD_PIDS[index]}
    virtiofsd_start=${VIRTIOFSD_STARTS[index]}
    virtiofsd_log=${VIRTIOFSD_LOGS[index]}
    for _ in $(/usr/bin/seq 1 1000); do
        [ -r "/proc/$virtiofsd_pid/stat" ] || break
        [ "$(process_start_time "$virtiofsd_pid" 2>/dev/null)" = "$virtiofsd_start" ] \
            || break
        [ "$(/usr/bin/awk '{ print $3 }' "/proc/$virtiofsd_pid/stat" 2>/dev/null)" != Z ] \
            || break
        is_exact_virtiofsd_process "$virtiofsd_pid" "$virtiofsd_start" \
            || { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail 'virtiofsd executable identity changed'; }
        /usr/bin/sleep 0.01
    done
    is_owned_virtiofsd_generation "$virtiofsd_pid" "$virtiofsd_start" \
        && { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail 'virtiofsd did not retire after QEMU disconnected'; }
    virtiofsd_status=0
    wait "$virtiofsd_pid" || virtiofsd_status=$?
    [ "$virtiofsd_status" -eq 0 ] \
        || { /usr/bin/tail -n 120 "$virtiofsd_log" >&2; fail "virtiofsd exited with status $virtiofsd_status"; }
done
VIRTIOFSD_PIDS=()
VIRTIOFSD_STARTS=()
grep -Fxq "bounded-unix-stream-capture: PASS bytes=$(stat -c '%s' "$SERIAL_LOG")" "$CAPTURE_RECEIPT" \
    || fail 'bounded serial-capture receipt differs'
if [ -r "/proc/$VM_PID/stat" ] && [ "$(process_start_time "$VM_PID" 2>/dev/null)" = "$VM_START" ]; then
    fail 'exact QEMU process remains after joined VM completion'
fi
capture_listeners >"$LISTENERS_AFTER"
/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_AFTER" >"$NEW_AFTER"
[ "$(/usr/bin/grep -Ec 'VERIFIER_VM_CLOUD_INIT=fail status=[1-9][0-9]*' "$SERIAL_LOG")" -eq 0 ] \
    || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'guest workload reported failure'; }
if [ -s "$NEW_AFTER" ]; then
    capture_listener_details >"$LISTENERS_AFTER_DETAIL"
    admit_preexisting_external_listener_drift \
        "$NEW_AFTER" "$LISTENERS_AFTER_DETAIL" after-cleanup \
        || { /usr/bin/cat "$LISTENERS_AFTER_DETAIL" >&2; fail 'verifier VM left or coincided with an unattributable host INET listener'; }
fi
reconcile_socket "$SERIAL_SOCKET" || fail 'serial channel cleanup is ambiguous'
reconcile_socket "$QMP_SOCKET" || fail 'QMP channel cleanup is ambiguous'
for socket in "${VIRTIOFS_SOCKETS[@]}"; do
    reconcile_socket "$socket" \
        || fail 'virtiofsd channel cleanup is ambiguous'
done
require_exact_fixed_receipt \
    'VERIFIER_VM_GIT_RUNTIME=pass source=pinned-deb version=2.39.5 root=vm-ephemeral network=none' \
    'authenticated verifier-VM Git runtime marker'

if [ "$MODE" = debian-systemd-lifecycle ]; then
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_NORMAL_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'normal systemd restart marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_STOP_START=pass generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd stop/start marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*SYSTEMD_CRASH_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36} nrestarts=[1-9][0-9]*' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd crash/restart marker is absent'; }
    /usr/bin/grep -Eq \
        '^.*DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=pass os=debian-12 systemd=252 seat_uid=4001 portable_uid=4000 crash_generation=[0-9a-f-]{36}' \
        "$SERIAL_LOG" \
        || { tail -n 240 "$SERIAL_LOG" >&2; fail 'installed Debian lifecycle marker is absent'; }
    require_exact_fixed_receipt \
        "DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=pass sha256=$LIFECYCLE_ARTIFACT_SHA256 commit=$LIFECYCLE_COMMIT" \
        'exact release-artifact lifecycle marker'
    require_exact_fixed_receipt \
        "VERIFIER_VM_DEBIAN_SYSTEMD_LIFECYCLE=pass artifact_sha256=$LIFECYCLE_ARTIFACT_SHA256 commit=$LIFECYCLE_COMMIT staging_uid=4000 root=refused foreign=refused docker=retired network=none cleanup=joined" \
        'verifier-VM installed-lifecycle marker'
    require_exact_fixed_receipt \
        "VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=$VERIFIER_VM_KERNEL_RELEASE direct_boot=on boot_masks=on docker=$VERIFIER_VM_DOCKER_VERSION vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off lifecycle=installed-debian-artifact" \
        'lifecycle guest authority marker'
elif [ "$MODE" = authority-smoke ]; then
/usr/bin/grep -Fq \
    "VERIFIER_VM_AUTHORITY_SMOKE=pass guest=debian-12 kernel=$VERIFIER_VM_KERNEL_RELEASE direct_boot=on boot_masks=on docker=$VERIFIER_VM_DOCKER_VERSION vm_network=none daemon_bridge=none daemon_forwarding=off daemon_firewall=off inner_uid=4000 inner_network=none inner_root=readonly inner_caps=none inner_nnp=on inner_seccomp=filter inner_apparmor=docker-default" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest authority result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=4000 gid=4000 network=none docker=$VERIFIER_VM_DOCKER_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'guest verifier-entry authority marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_MAIN_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused nofile=524544 workspace_fixtures=actual workspace_cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'main verifier exact-entry result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_FRB_ENTRY=pass uid=4000 gid=4000 foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'FRB verifier-VM entry result marker is absent'; }
/usr/bin/grep -Fq \
    "VERIFIER_VM_DART_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed frb=chained" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart verifier-VM entry result marker is absent'; }
/usr/bin/grep -Fq \
    'VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'release-parent verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 root=refused foreign=refused network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'release-workspace runtime marker is absent'; }
printf 'VERIFIER_VM_RELEASE_WORKSPACE_RUNTIME=pass uid=4000 gid=4000 root=refused foreign=refused network=none release=actual reset=actual publisher=actual closure=actual cleanup=joined\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Apple-check verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Flutter full-peer verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused docker=%s prepost=replayed workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'server-smoke verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_SMOKE_SERVER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart-audit result-behavior marker is absent'; }
printf 'VERIFIER_VM_DART_AUDIT_RESULT_GATE=pass decisions=31\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit verifier-VM entry result marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit compact source-gate marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Rust-audit result-behavior marker is absent'; }
printf 'VERIFIER_VM_RUST_AUDIT_RESULT_GATE=pass decisions=20\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed identity=untouched" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-keystore verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed identity=untouched\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-keystore compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed source=untouched signing=untouched output=untouched" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-builder verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched signing=untouched output=untouched\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-builder compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DEB_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DEB_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_DEBIAN_BUILDER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian builder compact source-gate marker is absent'; }
printf 'VERIFIER_VM_DEBIAN_BUILDER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Debian builder verifier-VM runtime marker is absent'; }
printf 'VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-compiler runtime=real source=private-fixture-only online=unchanged workload=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    "VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'systemd runtime-library verifier-VM marker is absent'; }
printf 'VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq 'VERIFIER_VM_WIN_HELPER_IMAGE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper image compact source-gate marker is absent'; }
printf 'VERIFIER_VM_WIN_HELPER_IMAGE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq 'VERIFIER_VM_WINDOWS_HELPER_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper compact source-gate marker is absent'; }
printf 'VERIFIER_VM_WINDOWS_HELPER_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    'WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Windows helper runtime marker is absent'; }
printf 'WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined\n'
/usr/bin/grep -Fq 'VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android Gradle compact source-gate marker is absent'; }
printf 'VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android Gradle verifier-VM runtime marker is absent'; }
printf 'VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s profiles=mount-rejection,semantics runtime=real source=untouched online=untouched gradle=unexecuted cleanup=joined\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
/usr/bin/grep -Fq \
    'VERIFIER_VM_APPLE_TOOLCHAIN_RELEASE=pass uid=4000 gid=4000 network=none' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Apple toolchain release-helper behavior marker is absent'; }
printf 'VERIFIER_VM_APPLE_TOOLCHAIN_RELEASE=pass uid=4000 gid=4000 network=none\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_OFFLINE_IMAGE_PROVENANCE=pass uid=4000 gid=4000 android_decisions=40 debian_decisions=9 windows_decisions=22' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'offline image-provenance behavior marker is absent'; }
printf 'VERIFIER_VM_OFFLINE_IMAGE_PROVENANCE=pass uid=4000 gid=4000 android_decisions=40 debian_decisions=9 windows_decisions=22\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_ONLINE_GRADLE_SOURCE_GATE=pass uid=4000 gid=4000' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'online Gradle source-gate marker is absent'; }
printf 'VERIFIER_VM_ONLINE_GRADLE_SOURCE_GATE=pass uid=4000 gid=4000\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_ONLINE_FETCH_SOURCE_GATE=pass uid=4000 gid=4000' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'online-fetch source-gate marker is absent'; }
printf 'VERIFIER_VM_ONLINE_FETCH_SOURCE_GATE=pass uid=4000 gid=4000\n'
/usr/bin/grep -Fq \
    'VERIFIER_VM_ONLINE_REPLACEMENT_FINALITY=pass uid=4000 gid=4000 pub_cache=actual gradle=actual residue=absent recovery=replaced-staged' \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'online replacement-finality behavior marker is absent'; }
printf 'VERIFIER_VM_ONLINE_REPLACEMENT_FINALITY=pass uid=4000 gid=4000 pub_cache=actual gradle=actual residue=absent recovery=replaced-staged\n'
/usr/bin/grep -Fq \
    "VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=$VERIFIER_VM_DOCKER_VERSION prepost=replayed source=untouched online=untouched workload=unexecuted" \
    "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Android-Rust verifier-VM entry marker is absent'; }
printf 'VERIFIER_VM_ANDROID_RUST_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused docker=%s prepost=replayed source=untouched online=untouched workload=unexecuted\n' \
    "$VERIFIER_VM_DOCKER_VERSION"
mapfile -t dart_frb_source_gate_receipts < <(
    /usr/bin/grep -Eo 'VERIFIER_VM_DART_FRB_SOURCE_GATE=pass mutations=[1-9][0-9]*' "$SERIAL_LOG"
)
[ "${#dart_frb_source_gate_receipts[@]}" -eq 1 ] \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'Dart/FRB verifier-VM source-gate result marker is absent or duplicated'; }
printf '%s\n' "${dart_frb_source_gate_receipts[0]}"
/usr/bin/grep -Fq 'VERIFIER_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'cloud-init completion marker is absent'; }
elif [ "$MODE" = hbb-common-fs ]; then
    mapfile -t hbb_common_fs_receipts < <(
        /usr/bin/grep -Eo \
            "HBB_COMMON_FS_VM=pass commit=$RUST_TEST_SOURCE_COMMIT tree=$RUST_TEST_SOURCE_TREE tests=[1-9][0-9]* rust=1\\.75\\.0 vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 builder_index=$DEB_BUILDER_IMAGE_ID builder_runtime=$DEB_BUILDER_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#hbb_common_fs_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'focused hbb_common filesystem test receipt is absent or duplicated'; }
    printf '%s\n' "${hbb_common_fs_receipts[0]}"
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Rust-test cloud-init completion marker'
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    require_exact_fixed_receipt \
        "ANDROID_RUST_LIFECYCLE_VM=pass commit=$RUST_TEST_SOURCE_COMMIT tree=$RUST_TEST_SOURCE_TREE tests=24 target=linux-x86_64 scope=listener-generation-child-convergence-and-exact-resource-owners rust=1.75.0 flutter=3.24.5 llvm=15.0.6 frb=$SHA256_FLUTTER_PEER_FRB_CODEGEN vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 pub_cache=$SHA256_PUB_CACHE_CLOSURE_V1 bridge_builder=$DEB_BUILDER_CONFIG_ID devcheck_index=$DEV_CHECK_IMAGE_ID devcheck_runtime=$DEV_CHECK_IMAGE_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none source=readonly generated_bridge=readonly target_dir=private-ephemeral offline_canary=pass root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined" \
        'focused Android Rust-lifecycle receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Android Rust-lifecycle cloud-init completion marker'
elif [ "$MODE" = android-rust-target-check ]; then
    require_exact_fixed_receipt \
        "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none docker=$VERIFIER_VM_DOCKER_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
        'Android Rust target-check entry-authority receipt'
    require_exact_fixed_receipt \
        'ANDROID-RUST-CHECK: aarch64 Android Rust library is GREEN' \
        'Android Rust target-check production verdict'
    require_exact_fixed_receipt \
        "ANDROID_RUST_TARGET_VM=pass commit=$RUST_TEST_SOURCE_COMMIT tree=$RUST_TEST_SOURCE_TREE target=aarch64-linux-android profile=release-check builder_index=$ANDROID_BUILDER_IMAGE_ID builder_runtime=$ANDROID_BUILDER_CONFIG_ID online=$SHA256_ONLINE_CLOSURE_V1 uid=1000 gid=1000 root=refused foreign=refused vm_network=none container_network=none inputs=readonly-landlocked source=exact-pushed offline_canary=pass cleanup=joined" \
        'Android Rust target-check VM receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'Android Rust target-check cloud-init completion marker'
elif [ "$MODE" = apple-conform ]; then
    require_exact_fixed_receipt \
        "loaded and verified apple-check $APPLE_CHECK_IMAGE_ID" \
        'Apple verifier image load receipt'
    require_exact_fixed_receipt \
        'Apple verifier authority architecture: PASS (VM-only Docker path; exact-image/three-target shape; full workload has an isolated mode)' \
        'Apple verifier authority architecture receipt'
    require_exact_fixed_receipt \
        '== apple-conform-check PASS ==' \
        'Apple source-conformance verdict'
    require_exact_fixed_receipt \
        "APPLE_CONFORM_VM=pass commit=$APPLE_SOURCE_COMMIT tree=$APPLE_SOURCE_TREE targets=3 image=$APPLE_CHECK_IMAGE_ID runtime=$APPLE_CHECK_IMAGE_CONFIG_ID vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused caller=refused source=exact-pushed-readonly inputs=readonly-landlocked evidence=source-conformance-not-native cleanup=joined" \
        'Apple-conformance VM receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'Apple-conformance cloud-init completion marker'
elif [ "$MODE" = android-owner-tests ]; then
    require_exact_fixed_receipt \
        "ANDROID_OWNER_STATE_VM=pass commit=$ANDROID_OWNER_SOURCE_COMMIT tree=$ANDROID_OWNER_SOURCE_TREE classes=7 scenarios=15 assertions=293 kotlin=$ANDROID_KOTLIN_VERSION builder_index=$ANDROID_BUILDER_IMAGE_ID builder_runtime=$ANDROID_BUILDER_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none compiler_inputs=verified-copy-readonly root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined" \
        'focused Android owner-state test receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Android owner-state cloud-init completion marker'
elif [ "$MODE" = android-emulator-boot ]; then
    require_exact_fixed_receipt \
        "ANDROID_EMULATOR_BOOT_VM=pass commit=$ANDROID_EMULATOR_SOURCE_COMMIT tree=$ANDROID_EMULATOR_SOURCE_TREE emulator=$ANDROID_EMULATOR_VERSION api=$ANDROID_EMULATOR_SYSTEM_IMAGE_API abi=x86_64 acceleration=software runtime_index=$DEV_CHECK_IMAGE_ID runtime_config=$DEV_CHECK_IMAGE_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked root=readonly caps=none nnp=on apparmor=docker-default cleanup=joined" \
        'Android emulator boot VM receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'Android emulator boot cloud-init completion marker'
elif [ "$MODE" = android-emulator-app ]; then
    mapfile -t android_artifact_receipts < <(
        /usr/bin/grep -Eo \
            'ANDROID_EMULATOR_ARTIFACT_PREPARED=pass pending=\.android-x86_64-test-output-pending-[0-9a-f]{64} destination=android-x86_64-test apk_sha256=[0-9a-f]{64} signing=test-only publication=atomic-no-clobber' \
            "$SERIAL_LOG" || true
    )
    [ "${#android_artifact_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'Android artifact preparation receipt is absent or duplicated'; }
    [[ "${android_artifact_receipts[0]}" =~ ^ANDROID_EMULATOR_ARTIFACT_PREPARED=pass\ pending=(\.android-x86_64-test-output-pending-[0-9a-f]{64})\ destination=android-x86_64-test\ apk_sha256=([0-9a-f]{64})\ signing=test-only\ publication=atomic-no-clobber$ ]] \
        || fail 'Android artifact preparation receipt is malformed'
    ANDROID_ARTIFACT_PENDING=${BASH_REMATCH[1]}
    ANDROID_ARTIFACT_SHA256=${BASH_REMATCH[2]}
    require_exact_fixed_receipt \
        "ANDROID_EMULATOR_APP_CHECK=pass apk_sha256=$ANDROID_ARTIFACT_SHA256 artifact=prepared-test-only source=exact-archive target=x86_64-linux-android builder=$ANDROID_BUILDER_CONFIG_ID runtime=$DEV_CHECK_IMAGE_CONFIG_ID vm_network=none container_network=none inputs=readonly cleanup=joined" \
        'Android emulator app-check receipt'
    require_exact_fixed_receipt \
        "ANDROID_EMULATOR_APP_VM=pass commit=$ANDROID_EMULATOR_SOURCE_COMMIT tree=$ANDROID_EMULATOR_SOURCE_TREE target=x86_64-linux-android emulator=$ANDROID_EMULATOR_VERSION api=$ANDROID_EMULATOR_SYSTEM_IMAGE_API builder_index=$ANDROID_BUILDER_IMAGE_ID builder_runtime=$ANDROID_BUILDER_CONFIG_ID runtime_index=$DEV_CHECK_IMAGE_ID runtime_config=$DEV_CHECK_IMAGE_CONFIG_ID apk_sha256=$ANDROID_ARTIFACT_SHA256 signing=test-only artifact=prepared-test-only output=writable-landlocked uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked source=exact-pushed cleanup=joined" \
        'Android emulator app VM receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'Android emulator app cloud-init completion marker'
elif [ "$MODE" = android-emulator-runtime ]; then
    require_exact_fixed_receipt \
        "VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none docker=$VERIFIER_VM_DOCKER_VERSION channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root" \
        'Android emulator runtime entry-authority receipt'
    mapfile -t android_runtime_apk_receipts < <(
        /usr/bin/grep -Eo \
            "ANDROID_EMULATOR_APK=pass sha256=$ANDROID_RUNTIME_APK_SHA256 package=com\\.carriez\\.flutter_hbb abi=x86_64 native_libraries=[1-9][0-9]* signer=[0-9A-F]{64} signing=test-only" \
            "$SERIAL_LOG" || true
    )
    [ "${#android_runtime_apk_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'Android runtime APK receipt is absent or duplicated'; }
    mapfile -t android_runtime_app_receipts < <(
        /usr/bin/grep -Eo \
            "ANDROID_EMULATOR_APP=pass emulator=37\\.1\\.11 api=34 abi=x86_64 package=com\\.carriez\\.flutter_hbb activity=MainActivity launch_wait=(ok|timeout) state=resumed process=stable-five-seconds apk_sha256=$ANDROID_RUNTIME_APK_SHA256 signing=test-only acceleration=software framebuffer=(480x800|800x480) selinux=Enforcing vm_network=none container_network=none cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#android_runtime_app_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'Android runtime app receipt is absent or duplicated'; }
    mapfile -t android_lifecycle_receipts < <(
        /usr/bin/grep -Eo \
            "ANDROID_EMULATOR_LIFECYCLE=pass task_removals=2 task_result=removed service=foreground-preserved process=same-across-task-removal media_projection=ready-across-relaunch relaunch=resumed force_stop=process-and-service-stopped post_force_stop=new-process-service-stopped framework_anr=(absent|waited-([1-9]|1[0-2])) apk_sha256=$ANDROID_RUNTIME_APK_SHA256 vm_network=none container_network=none cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#android_lifecycle_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'Android lifecycle runtime receipt is absent or duplicated'; }
    require_exact_fixed_receipt \
        "ANDROID_EMULATOR_RUNTIME_CHECK=pass artifact_commit=$ANDROID_RUNTIME_ARTIFACT_COMMIT apk_sha256=$ANDROID_RUNTIME_APK_SHA256 signing=test-only package=com.carriez.flutter_hbb abi=x86_64 source=commit-bound-retained-artifact builder=$ANDROID_BUILDER_CONFIG_ID runtime=$DEV_CHECK_IMAGE_CONFIG_ID vm_network=none container_network=none inputs=readonly cleanup=joined" \
        'Android emulator runtime-check receipt'
    require_exact_fixed_receipt \
        "ANDROID_EMULATOR_RUNTIME_VM=pass harness_commit=$ANDROID_EMULATOR_SOURCE_COMMIT harness_tree=$ANDROID_EMULATOR_SOURCE_TREE artifact_commit=$ANDROID_RUNTIME_ARTIFACT_COMMIT artifact_tree=$ANDROID_RUNTIME_ARTIFACT_TREE apk_sha256=$ANDROID_RUNTIME_APK_SHA256 target=x86_64-linux-android emulator=$ANDROID_EMULATOR_VERSION api=$ANDROID_EMULATOR_SYSTEM_IMAGE_API builder_index=$ANDROID_BUILDER_IMAGE_ID builder_runtime=$ANDROID_BUILDER_CONFIG_ID runtime_index=$DEV_CHECK_IMAGE_ID runtime_config=$DEV_CHECK_IMAGE_CONFIG_ID signing=test-only uid=1000 gid=1000 vm_network=none container_network=none inputs=readonly-landlocked artifact=readonly-landlocked source=exact-pushed cleanup=joined" \
        'Android emulator runtime VM receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'Android emulator runtime cloud-init completion marker'
elif [ "$MODE" = flutter-peer-presentation ]; then
    require_exact_fixed_receipt \
        "FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=$FLUTTER_PEER_SOURCE_COMMIT tree=$FLUTTER_PEER_SOURCE_TREE archive_sha256=$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256 flutter=$FLUTTER_PEER_FLUTTER_VERSION tools=$FLUTTER_PEER_TOOLS_MODE scope=linux-x11-full-peer-focus-reconnect-resource network=owned-none-namespace" \
        'focused Flutter full-peer product verdict'
    require_exact_fixed_receipt \
        "FLUTTER_PEER_PRESENTATION_VM=pass commit=$FLUTTER_PEER_SOURCE_COMMIT tree=$FLUTTER_PEER_SOURCE_TREE archive=$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256 flutter=$FLUTTER_PEER_FLUTTER_VERSION tools=$FLUTTER_PEER_TOOLS_MODE candidate=$FLUTTER_PEER_CANDIDATE devcheck_index=$DEV_CHECK_IMAGE_ID devcheck_runtime=$DEV_CHECK_IMAGE_CONFIG_ID builder_index=$DEB_BUILDER_IMAGE_ID builder_runtime=$DEB_BUILDER_CONFIG_ID uid=1000 gid=1000 nofile=524544 root=refused foreign=refused caller=refused vm_network=none container_network=owned-none-namespace inputs=readonly-landlocked cleanup=joined" \
        'focused Flutter full-peer VM verdict'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Flutter full-peer cloud-init completion marker'
elif [ "$MODE" = dart-audit ]; then
    require_exact_fixed_receipt \
        'VERIFY-DART-AUDIT: green — exact OSV status, telemetry, and structured results contain no unignored advisories against the pinned current Pub snapshot (R-R3/R-S11be)' \
        'focused Dart advisory verdict'
    mapfile -t dart_audit_receipts < <(
        /usr/bin/grep -Eo \
            "DART_AUDIT_VM=pass commit=$DART_SOURCE_COMMIT tree=$DART_SOURCE_TREE image=$DART_AUDIT_IMAGE_ID runtime=$DART_AUDIT_IMAGE_CONFIG_ID lock=[0-9a-f]{64} policy=[0-9a-f]{64} uid=4000 gid=4000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused source=readonly cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#dart_audit_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'focused Dart-audit receipt is absent or duplicated'; }
    printf '%s\n' "${dart_audit_receipts[0]}"
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Dart-audit cloud-init completion marker'
elif [ "$MODE" = rust-audit ]; then
    require_exact_fixed_receipt \
        'VERIFY-AUDIT: green — immutable-image cargo-audit and cargo-deny completed offline against one current pinned RustSec snapshot with exact reasoned accepts (R-R3/R-S11bf)' \
        'focused Rust advisory verdict'
    mapfile -t rust_audit_receipts < <(
        /usr/bin/grep -Eo \
            "RUST_AUDIT_VM=pass commit=$RUST_AUDIT_SOURCE_COMMIT tree=$RUST_AUDIT_SOURCE_TREE image=$RUST_AUDIT_IMAGE_ID runtime=$RUST_AUDIT_IMAGE_CONFIG_ID lock=[0-9a-f]{64} policy=[0-9a-f]{64} vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 uid=1000 gid=1000 nofile=524544 vm_network=none container_network=none root=refused foreign=refused source=readonly vendor_input=readonly-landlocked scanner_root=readonly caps=none nnp=on cleanup=joined" \
            "$SERIAL_LOG" || true
    )
    [ "${#rust_audit_receipts[@]}" -eq 1 ] \
        || { /usr/bin/tail -n 240 "$SERIAL_LOG" >&2; fail 'focused Rust-audit receipt is absent or duplicated'; }
    printf '%s\n' "${rust_audit_receipts[0]}"
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Rust-audit cloud-init completion marker'
else
    require_exact_fixed_receipt \
        "FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass version=$FLUTTER_VERSION lock=$SHA256_FLUTTER_TOOLS_LOCK implicit_pub=prevented" \
        'focused Flutter-tools offline freshness receipt'
    require_exact_fixed_receipt \
        "FLUTTER_MODEL_TESTS_VM=pass commit=$FLUTTER_SOURCE_COMMIT tree=$FLUTTER_SOURCE_TREE suites=13 tests=107 flutter=$FLUTTER_VERSION rust=1.75.0 llvm=$LLVM_VERSION frb=$SHA256_FLUTTER_PEER_FRB_CODEGEN cargo_vendor=$SHA256_CARGO_VENDOR_CLOSURE_V1 pub_cache=$SHA256_PUB_CACHE_CLOSURE_V1 builder_index=$DEB_BUILDER_IMAGE_ID builder_runtime=$DEB_BUILDER_CONFIG_ID uid=1000 gid=1000 vm_network=none container_network=none root=readonly caps=none nnp=on apparmor=docker-default evidence=generated-bridge-model-tests cleanup=joined" \
        'focused Flutter model-test receipt'
    require_exact_fixed_receipt \
        'VERIFIER_VM_CLOUD_INIT=pass' \
        'focused Flutter-test cloud-init completion marker'
fi
[ "$MODE" != debian-systemd-lifecycle ] || /usr/bin/grep -Fq \
    'VERIFIER_VM_CLOUD_INIT=pass' "$SERIAL_LOG" \
    || { tail -n 240 "$SERIAL_LOG" >&2; fail 'lifecycle cloud-init completion marker is absent'; }
[ "$(/usr/bin/sha512sum "$BASE")" = "$base_before" ] \
    || fail 'read-only Debian base changed'
[ "$(/usr/bin/sha256sum "$DOCKER_BUNDLE")" = "$docker_before" ] \
    || fail 'read-only Docker bundle changed'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$GIT_PACKAGE"):$(/usr/bin/sha256sum "$GIT_PACKAGE")" = \
  "$git_package_before" ] \
    || fail 'read-only Git package changed'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$BOOT_ROOT")" = "$boot_root_before" ] \
    || fail 'direct-boot cache directory changed during execution'
[ "$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" = xx ] \
    || fail 'direct-boot cache inventory changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$KERNEL"):$(/usr/bin/sha256sum "$KERNEL")" = "$kernel_before" ] \
    || fail 'direct-boot kernel changed during execution'
[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$INITRD"):$(/usr/bin/sha256sum "$INITRD")" = "$initrd_before" ] \
    || fail 'direct-boot initramfs changed during execution'
[ "$(/usr/bin/sha256sum "$OUTER_SOURCE" "$GUEST_SCRIPT" "$ENTRY_PREFLIGHT" "$VERIFY_SCRIPT" "$VERIFY_RELEASE_SOURCE" "$RELEASE_PARENT_SOURCE" "$RELEASE_PUBLISHER_SOURCE" "$RELEASE_FINALIZER_SOURCE" "$RELEASE_WORKSPACE_RUNTIME_TEST" "$FORK_VERSION_SOURCE" "$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE" "$VERIFY_SCAN_SOURCE" "$FRB_CODEGEN_SOURCE" "$DART_VERIFY_SOURCE" "$SMOKE_SERVER_SOURCE" "$RUST_AUDIT_SOURCE" "$RUST_AUDIT_POLICY_SOURCE" "$RUST_AUDIT_CHECKER" "$RUST_AUDIT_DOCKERFILE_SOURCE" "$ANDROID_KEYSTORE_SOURCE" "$ANDROID_KEYSTORE_INNER" "$ANDROID_KEYSTORE_CHECKER" "$ANDROID_BUILDER_SOURCE" "$ANDROID_APK_BUILD_SOURCE" "$ANDROID_BUILDER_CHECKER" "$ANDROID_GRADLE_SOURCE" "$ANDROID_GRADLE_CHECKER" "$ANDROID_BUILDER_IMAGE_CHECKER" "$DEB_BUILDER_IMAGE_CHECKER" "$DEBIAN_BUILDER_SOURCE" "$DEBIAN_BUILDER_AUTHORITY_CHECKER" "$SYSTEMD_RUNTIME_LIBS_SOURCE" "$SYSTEMD_LIFECYCLE_GUEST_SOURCE" "$SYSTEMD_LOGINCTL_SOURCE" "$DEBIAN_PACKAGE_AUTHORITY_SOURCE" "$SYSTEMD_UNIT_SOURCE" "$DEV_CHECK_DOCKERFILE_SOURCE" "$WIN_HELPER_IMAGE_CHECKER" "$WINDOWS_HELPER_AUTHORITY_CHECKER" "$WINDOWS_HELPER_RUNTIME_TEST" "$ANDROID_BUILDER_DOCKERFILE" "$DEB_BUILDER_DOCKERFILE" "$WIN_HELPER_DOCKERFILE" "$BUILDER_BOOTSTRAP_SEAL_DOCKERFILE" "$ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" "$DEB_BUILDER_CERTIFICATION_DOCKERFILE" "$WIN_HELPER_CERTIFICATION_DOCKERFILE" "$WINDOWS_HELPER_RUNTIME_SOURCE" "$WINDOWS_HELPER_EXTRACTOR" "$WINDOWS_GOLDEN_INSPECTOR" "$WINDOWS_BUILD_SOURCE" "$WINDOWS_PROVISION_SOURCE" "$WINDOWS_GOLDEN_SOURCE" "$ANDROID_RUST_SOURCE" "$ANDROID_EMULATOR_BOOT_SOURCE" "$ANDROID_EMULATOR_APP_SOURCE" "$ANDROID_EMULATOR_RUNTIME_SOURCE" "$ANDROID_EMULATOR_APK_VERIFIER" "$ANDROID_APK_MANIFEST_VERIFIER" "$ARTIFACT_RESULT_PUBLISHER_SOURCE" "$OFFLINE_IMAGE_PROVENANCE_SOURCE" "$ONLINE_FETCH_SOURCE" "$ONLINE_FETCH_VM_SOURCE" "$ONLINE_FETCH_VM_GUEST_SOURCE" "$ONLINE_FETCH_ENTRY_PREFLIGHT" "$ONLINE_FETCH_AUTHORITY_CHECKER" "$ONLINE_FETCH_RENAME_CHECKER" "$ONLINE_PUB_CACHE_OUTPUT_SOURCE" "$ONLINE_GRADLE_OUTPUT_SOURCE" "$ONLINE_GRADLE_OUTPUT_AUTHORITY_CHECKER" "$ANDROID_GRADLE_CACHE_PROJECTOR" "$ANDROID_GRADLE_WRAPPER_PROPERTIES" "$DART_AUDIT_SOURCE" "$DART_AUDIT_RESULT_SOURCE" "$DART_AUTHORITY_CHECKER" "$DART_AUDIT_CHECKER" "$REQUIREMENTS_SOURCE" "$HARDENING_SOURCE" "$BOOT_DERIVER" "$CAPTURE_HELPER" "$CLEANUP_HELPER" "$VIRTIOFSD_LAUNCHER" "$LIB_SOURCE" "$PIN_SOURCE")" = "$sources_before" ] \
    || fail 'verifier-VM harness source changed during execution'
if [ "$MODE" = hbb-common-fs ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed focused-test inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$RUST_TEST_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-test source archive changed during execution'
elif [ "$MODE" = apple-conform ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$CARGO_VENDOR_CONFIG" "$APPLE_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- \
            "$CARGO_VENDOR_CONFIG" "$APPLE_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Apple-conformance inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$APPLE_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$APPLE_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$APPLE_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Apple-conformance source archive changed during execution'
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$DEV_CHECK_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Android Rust-lifecycle inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$RUST_TEST_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Android Rust-lifecycle source archive changed during execution'
elif [ "$MODE" = android-rust-target-check ]; then
    focused_inputs_after="$(android_rust_target_input_inventory)" \
        || fail 'cannot re-inventory the sealed Android Rust target-check inputs'
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Android Rust target-check inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_TEST_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$RUST_TEST_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$RUST_TEST_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android Rust target-check source archive changed during execution'
elif [ "$MODE" = flutter-model-tests ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
            "$ONLINE_INPUTS" "$PUB_CACHE_ROOT" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" "$LLVM_TEST_ARCHIVE" \
            "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" "$DEB_BUILDER_ARCHIVE" \
            "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- "$RUST_TEST_ARCHIVE" "$FLUTTER_TEST_ARCHIVE" \
            "$LLVM_TEST_ARCHIVE" "$CARGO_VENDOR_CONFIG" "$FRB_CODEGEN" \
            "$DEB_BUILDER_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed focused-test inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$FLUTTER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$FLUTTER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Flutter-test source archive changed during execution'
elif [ "$MODE" = android-owner-tests ]; then
    focused_inputs_after="$(android_owner_input_inventory)" \
        || fail 'cannot re-inventory the sealed Android owner-state inputs'
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Android owner-state inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$ANDROID_OWNER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$ANDROID_OWNER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$ANDROID_OWNER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Android owner-state source archive changed during execution'
elif [ "$MODE" = android-emulator-runtime ]; then
    focused_inputs_after="$(android_emulator_runtime_input_inventory)" \
        || fail 'cannot re-inventory the sealed Android runtime inputs'
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Android runtime inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android emulator runtime harness source archive changed during execution'
    [ "$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$ANDROID_ARTIFACT_INPUT_FD")" = \
      "$ANDROID_ARTIFACT_INPUT_ID" ] \
        && [ "$(android_runtime_artifact_inventory)" = \
             "$ANDROID_ARTIFACT_INPUT_INVENTORY" ] \
        || fail 'commit-bound Android runtime artifact changed during execution'
elif [ "$MODE" = android-emulator-boot ] || [ "$MODE" = android-emulator-app ]; then
    focused_inputs_after="$(android_emulator_input_inventory)" \
        || fail 'cannot re-inventory the sealed Android emulator inputs'
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Android emulator inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$ANDROID_EMULATOR_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$ANDROID_EMULATOR_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$ANDROID_EMULATOR_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'Android emulator source archive changed during execution'
elif [ "$MODE" = flutter-peer-presentation ]; then
    focused_inputs_after="$(flutter_peer_input_inventory)"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Flutter full-peer inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLUTTER_PEER_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$FLUTTER_PEER_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$FLUTTER_PEER_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Flutter-peer source archive changed during execution'
elif [ "$MODE" = dart-audit ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$DART_AUDIT_IMAGE_ARCHIVE"
        /usr/bin/sha256sum -- "$DART_AUDIT_IMAGE_ARCHIVE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Dart-audit image input changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$DART_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$DART_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$DART_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Dart-audit source archive changed during execution'
elif [ "$MODE" = rust-audit ]; then
    focused_inputs_after="$(
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$ONLINE_INPUTS" "$CARGO_VENDOR_ROOT"
        /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- \
            "$CARGO_VENDOR_CONFIG" "$RUST_AUDIT_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
        /usr/bin/sha256sum -- \
            "$CARGO_VENDOR_CONFIG" "$RUST_AUDIT_IMAGE_ARCHIVE" "$VIRTIOFSD_PACKAGE"
    )"
    [ "$focused_inputs_after" = "$focused_inputs_before" ] \
        || fail 'sealed Rust-audit inputs changed during execution'
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$RUST_AUDIT_SOURCE_ARCHIVE")" = \
      "$HOST_UID:$HOST_GID:400:1" ] \
        && [ "$(/usr/bin/sha256sum "$RUST_AUDIT_SOURCE_ARCHIVE" | /usr/bin/awk '{ print $1 }')" = \
             "$RUST_AUDIT_SOURCE_ARCHIVE_SHA256" ] \
        || fail 'focused Rust-audit source archive changed during execution'
fi
if [ "$MODE" = debian-systemd-lifecycle ]; then
    [ "$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$LIFECYCLE_ARTIFACT")" = \
      "$LIFECYCLE_ARTIFACT_ID" ] \
        || fail 'lifecycle artifact identity changed during execution'
    [ "$(/usr/bin/sha256sum "$LIFECYCLE_ARTIFACT" | /usr/bin/awk '{ print $1 }')" = \
      "$LIFECYCLE_ARTIFACT_SHA256" ] \
        || fail 'lifecycle artifact bytes changed during execution'
    [ "$(/usr/bin/stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$DEV_CHECK_ARCHIVE")" = \
      "$DEV_CHECK_ARCHIVE_ID" ] \
        || fail 'devcheck archive identity changed during execution'
    verify_sha256 "$DEV_CHECK_ARCHIVE" "$SHA256_DEV_CHECK_IMAGE_ARCHIVE"
fi

if [ "$MODE" = android-emulator-app ]; then
    publish_android_runtime_artifact
fi
external_listener_drift_count="$(/usr/bin/wc -l <"$EXTERNAL_LISTENER_DRIFT")"
/usr/bin/printf 'VERIFIER_VM_HOST_LISTENER_AUDIT=pass complete_snapshots=before,during,after harness_additions=none preexisting_process_drift=%s\n' \
    "$external_listener_drift_count"
RUN_COMPLETE=1
if [ "$MODE" = authority-smoke ]; then
    printf 'VERIFIER_VM_OUTER_AUTHORITY=pass host_uid=%s network=none boot=direct kernel=sha256 initrd=sha256 channels=unix listeners=no-harness-addition base=sha512 docker=sha256 output_bound=%s cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$SERIAL_LIMIT" "$vm_elapsed_seconds"
elif [ "$MODE" = debian-systemd-lifecycle ]; then
    printf 'VERIFIER_VM_OUTER_AUTHORITY=pass host_uid=%s network=none boot=direct kernel=sha256 initrd=sha256 channels=unix listeners=no-harness-addition base=sha512 docker=sha256 mode=debian-systemd-lifecycle output_bound=%s cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$SERIAL_LIMIT" "$vm_elapsed_seconds"
elif [ "$MODE" = hbb-common-fs ]; then
    printf 'HBB_COMMON_FS_VM_OUTER=pass host_uid=%s commit=%s tree=%s network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" "$vm_elapsed_seconds"
elif [ "$MODE" = android-rust-lifecycle-tests ]; then
    printf 'ANDROID_RUST_LIFECYCLE_VM_OUTER=pass host_uid=%s commit=%s tree=%s target=linux-x86_64 scope=listener-generation-child-convergence-and-exact-resource-owners network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = android-rust-target-check ]; then
    printf 'ANDROID_RUST_TARGET_VM_OUTER=pass host_uid=%s commit=%s tree=%s target=aarch64-linux-android profile=release-check network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only evidence=production-cargo-ndk-check cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$RUST_TEST_SOURCE_COMMIT" "$RUST_TEST_SOURCE_TREE" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = apple-conform ]; then
    printf 'APPLE_CONFORM_VM_OUTER=pass host_uid=%s commit=%s tree=%s targets=3 image=%s runtime=%s network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only evidence=source-conformance-not-native cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$APPLE_SOURCE_COMMIT" "$APPLE_SOURCE_TREE" \
        "$APPLE_CHECK_IMAGE_ID" "$APPLE_CHECK_IMAGE_CONFIG_ID" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = android-owner-tests ]; then
    printf 'ANDROID_OWNER_STATE_VM_OUTER=pass host_uid=%s commit=%s tree=%s network=none listeners=no-harness-addition inputs=readonly-landlocked compiler_inputs=verified-copy-readonly docker=guest-only evidence=compiled-production-state-machines cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$ANDROID_OWNER_SOURCE_COMMIT" "$ANDROID_OWNER_SOURCE_TREE" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = android-emulator-boot ]; then
    printf 'ANDROID_EMULATOR_BOOT_VM_OUTER=pass host_uid=%s commit=%s tree=%s emulator=%s api=%s abi=x86_64 acceleration=software runtime=%s network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only product=android-framework-boot-and-framebuffer cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$ANDROID_EMULATOR_SOURCE_COMMIT" \
        "$ANDROID_EMULATOR_SOURCE_TREE" "$ANDROID_EMULATOR_VERSION" \
        "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" "$DEV_CHECK_IMAGE_CONFIG_ID" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = android-emulator-app ]; then
    printf 'ANDROID_EMULATOR_APP_VM_OUTER=pass host_uid=%s commit=%s tree=%s emulator=%s api=%s abi=x86_64 builder=%s runtime=%s apk_sha256=%s signing=test-only artifact=published-test-only destination=%s/%s network=none listeners=no-harness-addition inputs=readonly-landlocked output=writable-landlocked docker=guest-only product=real-apk-install-launch-render cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$ANDROID_EMULATOR_SOURCE_COMMIT" \
        "$ANDROID_EMULATOR_SOURCE_TREE" "$ANDROID_EMULATOR_VERSION" \
        "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" "$ANDROID_BUILDER_CONFIG_ID" \
        "$DEV_CHECK_IMAGE_CONFIG_ID" "$ANDROID_ARTIFACT_SHA256" \
        "$ANDROID_EMULATOR_SOURCE_COMMIT" "$ANDROID_ARTIFACT_DESTINATION" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = android-emulator-runtime ]; then
    printf 'ANDROID_EMULATOR_RUNTIME_VM_OUTER=pass host_uid=%s harness_commit=%s harness_tree=%s artifact_commit=%s artifact_tree=%s apk_sha256=%s signing=test-only emulator=%s api=%s abi=x86_64 builder=%s runtime=%s network=none listeners=no-harness-addition inputs=readonly-landlocked artifact=readonly-landlocked docker=guest-only product=real-retained-apk-install-launch-render-task-remove-relaunch-force-stop cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$ANDROID_EMULATOR_SOURCE_COMMIT" \
        "$ANDROID_EMULATOR_SOURCE_TREE" "$ANDROID_RUNTIME_ARTIFACT_COMMIT" \
        "$ANDROID_RUNTIME_ARTIFACT_TREE" "$ANDROID_RUNTIME_APK_SHA256" \
        "$ANDROID_EMULATOR_VERSION" "$ANDROID_EMULATOR_SYSTEM_IMAGE_API" \
        "$ANDROID_BUILDER_CONFIG_ID" "$DEV_CHECK_IMAGE_CONFIG_ID" \
        "$vm_elapsed_seconds"
elif [ "$MODE" = flutter-peer-presentation ]; then
    printf 'FLUTTER_PEER_PRESENTATION_VM_OUTER=pass host_uid=%s commit=%s tree=%s flutter=%s tools=%s candidate=%s network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only product=linux-x11-full-peer-focus-reconnect-resource cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$FLUTTER_PEER_SOURCE_COMMIT" "$FLUTTER_PEER_SOURCE_TREE" \
        "$FLUTTER_PEER_FLUTTER_VERSION" "$FLUTTER_PEER_TOOLS_MODE" \
        "$FLUTTER_PEER_CANDIDATE" "$vm_elapsed_seconds"
elif [ "$MODE" = dart-audit ]; then
    printf 'DART_AUDIT_VM_OUTER=pass host_uid=%s commit=%s tree=%s image=%s runtime=%s network=none listeners=no-harness-addition inputs=readonly-media docker=guest-only cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$DART_SOURCE_COMMIT" "$DART_SOURCE_TREE" \
        "$DART_AUDIT_IMAGE_ID" "$DART_AUDIT_IMAGE_CONFIG_ID" "$vm_elapsed_seconds"
elif [ "$MODE" = rust-audit ]; then
    printf 'RUST_AUDIT_VM_OUTER=pass host_uid=%s commit=%s tree=%s image=%s runtime=%s network=none listeners=no-harness-addition inputs=readonly-media,readonly-landlocked docker=guest-only cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$RUST_AUDIT_SOURCE_COMMIT" "$RUST_AUDIT_SOURCE_TREE" \
        "$RUST_AUDIT_IMAGE_ID" "$RUST_AUDIT_IMAGE_CONFIG_ID" "$vm_elapsed_seconds"
else
    printf 'FLUTTER_MODEL_TESTS_VM_OUTER=pass host_uid=%s commit=%s tree=%s network=none listeners=no-harness-addition inputs=readonly-landlocked docker=guest-only evidence=generated-bridge-model-tests cleanup=joined elapsed_seconds=%s\n' \
        "$HOST_UID" "$FLUTTER_SOURCE_COMMIT" "$FLUTTER_SOURCE_TREE" "$vm_elapsed_seconds"
fi

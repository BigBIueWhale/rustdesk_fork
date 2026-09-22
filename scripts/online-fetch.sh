#!/usr/bin/env bash
# scripts/online-fetch.sh — the ONE networked step (R-B10).
#
# The repository is build-oriented and offline-by-construction. This is the only
# script permitted to touch the network; it materializes every resource the repo
# does not embed into ./online/inputs/ or the private verifier-VM input cache (both
# git-ignored, NOT vendored — pinning != vendoring, R-R1), each verified against
# its pin in scripts/pins.env. Any mismatch aborts fail-closed. The build scripts
# then run with the network namespace removed (--network=none) and refuse to run
# if ./online/inputs is incomplete or any SHA fails.
#
# This reconciles R-R1's "pinning != vendoring" with the offline build: the bulky
# pinned world is CACHED, not committed — re-creatable from pins.env and
# re-verifiable, never trusted from the network at build time.
#
# Run order (R-B10): acquire the authenticated VM bootstrap inputs once, then
# online-fetch.sh launches the sole networked transaction in a disposable
# ordinary-user QEMU VM. Only that guest owns a NIC and its Docker/BuildKit
# daemons; build-* remains networkless and cleanup.sh retires operator-owned
# build state.
#
# R-B12 requires each first pin be established by an audited, dual-sourced
# bootstrap (publisher hash/signature cross-checked) and recorded in pins.env
# BEFORE this script is allowed to fetch it. The fixed-archive transaction
# rejects SHA_PENDING, wrong lengths, and wrong digests before publication.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

# R-S11dh bootstrap is deliberately dispatched before any Docker client, socket,
# context, or configuration is inspected. These are inert VM inputs, not a host
# Docker transaction: exact HTTPS bytes enter current-user-private harness state,
# and only the disposable acquisition guest may execute the package or Docker bytes.
acquire_verifier_vm_inputs() {
    [ "$#" -eq 0 ] || die "--verifier-vm-inputs takes no arguments"
    local uid gid state_root vm_root transaction transaction_id staging=
    local image_name image_path docker_name docker_path buildx_name buildx_path
    local buildkit_name buildkit_path
    local git_name git_path
    local virtiofsd_name virtiofsd_path
    uid="$(/usr/bin/id -u)"
    gid="$(/usr/bin/id -g)"
    [ "$uid" -ne 0 ] || die "verifier-VM input acquisition refuses root"
    [ "$gid" -ne 0 ] || die "verifier-VM input acquisition refuses a root primary group"
    for tool in /usr/bin/chmod /usr/bin/curl /usr/bin/env /usr/bin/install /usr/bin/ln /usr/bin/mktemp \
        /usr/bin/rm /usr/bin/rmdir /usr/bin/sha256sum /usr/bin/sha512sum /usr/bin/stat; do
        [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] \
            || die "verifier-VM acquisition tool is unavailable: $tool"
        [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$tool")" = "0:0:755:1" ] \
            || die "verifier-VM acquisition tool metadata changed: $tool"
    done
    state_root="$REPO_ROOT/.harness-state"
    vm_root="$state_root/verifier-vm"
    if [ -e "$state_root" ] || [ -L "$state_root" ]; then
        [ -d "$state_root" ] && [ ! -L "$state_root" ] \
            || die "harness-state root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$state_root")" = "$uid:$gid:700" ] \
            || die "harness-state root is not current-user/current-group mode 0700"
    else
        /usr/bin/install -d -m 0700 -- "$state_root"
    fi
    if [ -e "$vm_root" ] || [ -L "$vm_root" ]; then
        [ -d "$vm_root" ] && [ ! -L "$vm_root" ] \
            || die "verifier-VM input root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$vm_root")" = "$uid:$gid:700" ] \
            || die "verifier-VM input root is not current-user/current-group mode 0700"
    else
        /usr/bin/install -d -m 0700 -- "$vm_root"
    fi
    transaction="$(/usr/bin/mktemp -d "$vm_root/acquire.XXXXXXXXXX")" \
        || die "cannot create the private verifier-VM acquisition transaction"
    transaction_id="$(/usr/bin/stat -c '%d:%i' -- "$transaction")"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$transaction")" = "$uid:$gid:700" ] \
        || die "verifier-VM acquisition transaction has unexpected metadata"

    cleanup_verifier_vm_acquisition() {
        local status=$?
        trap - EXIT HUP INT TERM
        if [ -n "$staging" ] && { [ -e "$staging" ] || [ -L "$staging" ]; }; then
            if [ -f "$staging" ] && [ ! -L "$staging" ] \
               && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$staging" 2>/dev/null)" = "$uid:$gid:1" ]; then
                /usr/bin/rm -f -- "$staging" || status=1
            else
                printf '[harness:FATAL] refusing ambiguous verifier-VM staging cleanup: %s\n' \
                    "$staging" >&2
                status=1
            fi
        fi
        if [ -d "$transaction" ] && [ ! -L "$transaction" ] \
           && [ "$(/usr/bin/stat -c '%d:%i' -- "$transaction" 2>/dev/null)" = "$transaction_id" ]; then
            /usr/bin/rmdir -- "$transaction" || status=1
        else
            printf '[harness:FATAL] verifier-VM acquisition transaction identity changed: %s\n' \
                "$transaction" >&2
            status=1
        fi
        exit "$status"
    }
    trap cleanup_verifier_vm_acquisition EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    acquire_verifier_vm_file() {
        [ "$#" -eq 6 ] || die "internal verifier-VM acquisition argument error"
        local label=$1 url=$2 destination=$3 expected_size=$4 algorithm=$5 expected_digest=$6
        local observed_digest metadata
        case "$expected_size" in 0|*[!0-9]*|'') die "$label size pin is malformed" ;; esac
        case "$algorithm" in
            sha256)
                [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] \
                    || die "$label SHA-256 pin is malformed"
                ;;
            sha512)
                [[ "$expected_digest" =~ ^[0-9a-f]{128}$ ]] \
                    || die "$label SHA-512 pin is malformed"
                ;;
            *) die "$label digest algorithm is unsupported" ;;
        esac
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            [ -f "$destination" ] && [ ! -L "$destination" ] \
                || die "$label cache path is not one real file"
            metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$destination")"
            [ "$metadata" = "$uid:$gid:400:1:$expected_size" ] \
                || die "$label cached metadata differs"
            observed_digest="$("/usr/bin/${algorithm}sum" "$destination")"
            [ "${observed_digest%% *}" = "$expected_digest" ] \
                || die "$label cached digest differs"
            log "$label already cached and authenticated"
            return 0
        fi
        staging="$(/usr/bin/mktemp "$transaction/input.XXXXXXXXXX")" \
            || die "cannot allocate $label staging file"
        /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
            /usr/bin/curl --disable --proto '=https' --tlsv1.2 \
                --fail --silent --show-error --location \
                --max-time 1800 --speed-time 60 --speed-limit 1024 \
                --max-filesize "$expected_size" --output "$staging" "$url" \
            || die "$label download failed"
        [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$staging")" \
          = "$uid:$gid:600:1:$expected_size" ] \
            || die "$label staged metadata differs"
        observed_digest="$("/usr/bin/${algorithm}sum" "$staging")"
        [ "${observed_digest%% *}" = "$expected_digest" ] \
            || die "$label staged digest differs"
        /usr/bin/chmod 0400 -- "$staging"
        /usr/bin/ln -- "$staging" "$destination" \
            || die "$label no-clobber publication failed"
        /usr/bin/rm -- "$staging"
        staging=
        [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$destination")" \
          = "$uid:$gid:400:1:$expected_size" ] \
            || die "$label published metadata differs"
        observed_digest="$("/usr/bin/${algorithm}sum" "$destination")"
        [ "${observed_digest%% *}" = "$expected_digest" ] \
            || die "$label published digest differs"
        log "$label authenticated and published"
    }

    image_name="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
    image_path="$vm_root/$image_name"
    docker_name="docker-${VERIFIER_VM_DOCKER_VERSION}.tgz"
    docker_path="$vm_root/$docker_name"
    buildx_name="buildx-v${VERIFIER_VM_BUILDX_VERSION}.linux-amd64"
    buildx_path="$vm_root/$buildx_name"
    buildkit_name="buildkit-v${VERIFIER_VM_BUILDKIT_VERSION}.linux-amd64.tar.gz"
    buildkit_path="$vm_root/$buildkit_name"
    git_name="git_${VERIFIER_VM_GIT_PACKAGE_FILENAME_VERSION}_amd64.deb"
    git_path="$vm_root/$git_name"
    virtiofsd_name="virtiofsd_${VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION}_amd64.deb"
    virtiofsd_path="$vm_root/$virtiofsd_name"
    acquire_verifier_vm_file \
        "Debian verifier-VM base" \
        "https://cloud.debian.org/images/cloud/bookworm/${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}/$image_name" \
        "$image_path" "$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" sha512 \
        "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
    acquire_verifier_vm_file \
        "Docker verifier-VM static bundle" \
        "https://download.docker.com/linux/static/stable/x86_64/$docker_name" \
        "$docker_path" "$SIZE_VERIFIER_VM_DOCKER_STATIC" sha256 \
        "$SHA256_VERIFIER_VM_DOCKER_STATIC"
    acquire_verifier_vm_file \
        "Buildx verifier-VM CLI plugin" \
        "https://github.com/docker/buildx/releases/download/v${VERIFIER_VM_BUILDX_VERSION}/$buildx_name" \
        "$buildx_path" "$SIZE_VERIFIER_VM_BUILDX" sha256 \
        "$SHA256_VERIFIER_VM_BUILDX"
    acquire_verifier_vm_file \
        "BuildKit verifier-VM daemon bundle" \
        "https://github.com/moby/buildkit/releases/download/v${VERIFIER_VM_BUILDKIT_VERSION}/$buildkit_name" \
        "$buildkit_path" "$SIZE_VERIFIER_VM_BUILDKIT" sha256 \
        "$SHA256_VERIFIER_VM_BUILDKIT"
    acquire_verifier_vm_file \
        "Git verifier-VM runtime package" \
        "https://deb.debian.org/debian/pool/main/g/git/$git_name" \
        "$git_path" "$SIZE_VERIFIER_VM_GIT_PACKAGE" sha256 \
        "$SHA256_VERIFIER_VM_GIT_PACKAGE"
    acquire_verifier_vm_file \
        "virtiofsd verifier-VM device backend" \
        "https://archive.ubuntu.com/ubuntu/pool/universe/r/rust-virtiofsd/$virtiofsd_name" \
        "$virtiofsd_path" "$SIZE_VERIFIER_VM_VIRTIOFSD_PACKAGE" sha512 \
        "$SHA512_VERIFIER_VM_VIRTIOFSD_PACKAGE"
    [ "$(/usr/bin/sha256sum "$virtiofsd_path" | /usr/bin/awk '{print $1}')" \
      = "$SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE" ] \
        || die "virtiofsd verifier-VM device backend SHA-256 differs"
    log "verifier-VM inputs ready: $vm_root"
    cleanup_verifier_vm_acquisition
}

if [ "${1:-}" = "--verifier-vm-inputs" ]; then
    [ "$#" -eq 1 ] || die "--verifier-vm-inputs takes no arguments"
    acquire_verifier_vm_inputs
    exit 0
fi

# Every non-bootstrap operation crosses one executable acquisition-VM boundary.
# A caller cannot opt into the inner implementation with an environment flag:
# the inner entry independently requires the exact direct-boot command line,
# root-authored daemon generation, source identity, NIC, one atomic virtiofs
# cache mount, and two narrow 9p mounts before it inspects the guest Docker socket.
if [ "${RUSTDESK_ONLINE_FETCH_VM_GUEST:-}" != 1 ]; then
    exec "$SCRIPT_DIR/online-fetch-vm.sh" "$@"
fi
"$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"
ONLINE_FETCH_VM_AUTHORITY_PROBE=0
if [ "${1:-}" = --vm-authority-probe ]; then
    [ "$#" -eq 1 ] || die "--vm-authority-probe takes no arguments"
    ONLINE_FETCH_VM_AUTHORITY_PROBE=1
fi
readonly ONLINE_FETCH_VM_AUTHORITY_PROBE

readonly DOCKER_BIN=/usr/bin/docker
readonly BUILDX_SOURCE=/opt/rustdesk-online-fetch-vm/docker-buildx
readonly GIT_RUNTIME_ROOT=/opt/rustdesk-online-fetch-git
readonly GIT_BIN=$GIT_RUNTIME_ROOT/usr/bin/git
readonly GIT_EXEC_PATH=$GIT_RUNTIME_ROOT/usr/lib/git-core
readonly GIT_TEMPLATE_DIR=$GIT_RUNTIME_ROOT/usr/share/git-core/templates
readonly TAR_BIN=/usr/bin/tar
readonly FLOCK_BIN=/usr/bin/flock
readonly FIXED_ARCHIVE_HELPER="$SCRIPT_DIR/online-fixed-archive-output.py"
readonly OSV_PUB_DISCOVERY_HELPER="$SCRIPT_DIR/discover-osv-pub-database.py"
readonly LIBVPX_LOCAL_OUTPUT_HELPER="$SCRIPT_DIR/online-libvpx-local-output.py"
readonly CARGO_VENDOR_OUTPUT_HELPER="$SCRIPT_DIR/online-cargo-vendor-output.py"
readonly WINDOWS_ENGINE_OUTPUT_HELPER="$SCRIPT_DIR/online-windows-engine-output.py"
readonly FLUTTER_PUB_CACHE_OUTPUT_HELPER="$SCRIPT_DIR/online-flutter-pub-cache-output.py"
readonly WIX_NUGET_RETIRE_HELPER="$SCRIPT_DIR/online-wix-nuget-retire.py"
readonly VCPKG_NATIVE_PRODUCER="$SCRIPT_DIR/build-vcpkg-native-output.sh"
readonly RETIRED_ONLINE_INPUT_ROOT="$ONLINE_STATE_ROOT/retired"
readonly VCPKG_FIXED_ARCHIVE_MANIFEST="$REPO_ROOT/res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt"
readonly FLUTTER_PEER_PACKAGE_MANIFEST="$SCRIPT_DIR/smoke-xvfb-packages.tsv"
readonly ONLINE_FETCH_DOCKER_HOST=unix:///var/run/docker.sock
readonly ONLINE_FETCH_BUILDKIT_ENDPOINT=unix:///run/rustdesk-online-fetch-buildkit/buildkitd.sock
readonly ONLINE_FETCH_BUILDX_BUILDER=rustdesk-online-fetch
readonly ONLINE_FETCH_UID="$(/usr/bin/id -u)"
readonly ONLINE_FETCH_GID="$(/usr/bin/id -g)"
[ "$ONLINE_STATE_ROOT" = "$REPO_ROOT/online" ] \
    && [ "$ONLINE_DIR" = "$ONLINE_STATE_ROOT/inputs" ] \
    || die "online-fetch cache layout differs from the one supported state-root/inputs model"
[ "$ONLINE_FETCH_UID" -ne 0 ] || die "online-fetch refuses host or container-root execution"
[ "$ONLINE_FETCH_GID" -ne 0 ] || die "online-fetch refuses a root primary group"
[ -x "$DOCKER_BIN" ] || die "trusted Docker client is unavailable: $DOCKER_BIN"
[ "$(stat -c '%u:%g:%a:%h' -- "$DOCKER_BIN")" = "0:0:755:1" ] \
    || die "trusted Docker client metadata changed"
[ -f "$BUILDX_SOURCE" ] && [ ! -L "$BUILDX_SOURCE" ] && [ -x "$BUILDX_SOURCE" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$BUILDX_SOURCE")" = \
         "0:0:555:1:$SIZE_VERIFIER_VM_BUILDX" ] \
    || die "trusted Buildx source metadata changed"
[ "$(/usr/bin/sha256sum "$BUILDX_SOURCE" | /usr/bin/awk '{print $1}')" = \
  "$SHA256_VERIFIER_VM_BUILDX" ] \
    || die "trusted Buildx source bytes changed"
[ -x "$GIT_BIN" ] || die "trusted Git client is unavailable: $GIT_BIN"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$GIT_RUNTIME_ROOT")" = "0:0:555" ] \
    || die "trusted Git runtime root metadata changed"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GIT_BIN")" = \
  "0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY" ] \
    || die "trusted Git client metadata changed"
[ "$(/usr/bin/sha256sum "$GIT_BIN" | /usr/bin/awk '{print $1}')" = \
  "$SHA256_VERIFIER_VM_GIT_BINARY" ] \
    || die "trusted Git client bytes changed"
[ -d "$GIT_EXEC_PATH" ] && [ ! -L "$GIT_EXEC_PATH" ] \
    && [ -d "$GIT_TEMPLATE_DIR" ] && [ ! -L "$GIT_TEMPLATE_DIR" ] \
    || die "trusted Git runtime layout changed"
[ -x "$TAR_BIN" ] || die "trusted tar client is unavailable: $TAR_BIN"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$TAR_BIN")" = "0:0:755:1" ] \
    || die "trusted tar client metadata changed"
[ -x "$FLOCK_BIN" ] || die "trusted flock client is unavailable: $FLOCK_BIN"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLOCK_BIN")" = "0:0:755:1" ] \
    || die "trusted flock client metadata changed"
[ -S /var/run/docker.sock ] || die "the fixed local Docker socket is unavailable"
case "${DOCKER_HOST:-$ONLINE_FETCH_DOCKER_HOST}" in
    "$ONLINE_FETCH_DOCKER_HOST") ;;
    *) die "online-fetch must use the fixed local Docker endpoint" ;;
esac
for variable in DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS; do
    [ -z "${!variable+x}" ] || die "$variable must not influence online acquisition"
done

readonly -a FIXED_ARCHIVE_ARGS=(
    --entry
    "android-cmdline-tools.zip"
    "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_BUILD}_latest.zip"
    "$SIZE_ANDROID_CMDLINE_TOOLS"
    "$SHA256_ANDROID_CMDLINE_TOOLS"
    "dl.google.com"
    --entry
    "android-ndk-${ANDROID_NDK_VERSION}.zip"
    "https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip"
    "$SIZE_ANDROID_NDK_R28C"
    "$SHA256_ANDROID_NDK_R28C"
    "dl.google.com"
    --entry
    "flutter-${FLUTTER_VERSION}.tar.xz"
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    "$SIZE_FLUTTER_3_24_5"
    "$SHA256_FLUTTER_3_24_5"
    "storage.googleapis.com"
    --entry
    "flutter-windows-${FLUTTER_VERSION}.zip"
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${FLUTTER_VERSION}-stable.zip"
    "$SIZE_FLUTTER_WIN_3_24_5"
    "$SHA256_FLUTTER_WIN_3_24_5"
    "storage.googleapis.com"
    --entry
    "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz"
    "https://github.com/fzyzcjy/flutter_rust_bridge/archive/refs/tags/v${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz"
    "$SIZE_FRB_1_80_1"
    "$SHA256_FRB_1_80_1"
    "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "llvm-${LLVM_VERSION}.tar.xz"
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
    "$SIZE_LLVM_15_0_6"
    "$SHA256_LLVM_15_0_6"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "llvm-windows-${LLVM_VERSION}.exe"
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-win64.exe"
    "$SIZE_LLVM_WIN_15_0_6"
    "$SHA256_LLVM_WIN_15_0_6"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl"
    "https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl"
    "$SIZE_OLEFILE_0_47"
    "$SHA256_OLEFILE_0_47"
    "files.pythonhosted.org"
    --entry
    "python-windows-${PYTHON_VERSION}.exe"
    "https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-amd64.exe"
    "$SIZE_PYTHON_WIN_3_11_9"
    "$SHA256_PYTHON_WIN_3_11_9"
    "www.python.org,python.org"
    --entry
    "rust-${RUST_VERSION}.tar.xz"
    "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz"
    "$SIZE_RUST_1_75"
    "$SHA256_RUST_1_75"
    "static.rust-lang.org"
    --entry
    "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz"
    "https://static.rust-lang.org/dist/2023-12-28/rust-std-${RUST_VERSION}.0-aarch64-linux-android.tar.xz"
    "$SIZE_RUST_STD_ANDROID_1_75"
    "$SHA256_RUST_STD_ANDROID_1_75"
    "static.rust-lang.org"
    --entry
    "vcpkg-${VCPKG_BASELINE}.tar.gz"
    "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz"
    "$SIZE_VCPKG_120DEAC3"
    "$SHA256_VCPKG_120DEAC3"
    "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "win/Git-2.45.2-64-bit.exe"
    "https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe"
    "$SIZE_GIT_WIN_2_45_2"
    "$SHA256_GIT_WIN_2_45_2"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "win/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi"
    "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-pc-windows-msvc.msi"
    "$SIZE_RUST_MSVC_1_75"
    "$SHA256_RUST_MSVC_1_75"
    "static.rust-lang.org"
)

readonly -a RUST_TEST_FIXED_ARCHIVE_ARGS=(
    --entry
    "rust-${RUST_VERSION}.tar.xz"
    "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz"
    "$SIZE_RUST_1_75"
    "$SHA256_RUST_1_75"
    "static.rust-lang.org"
)
readonly -a FLUTTER_TEST_FIXED_ARCHIVE_ARGS=(
    --entry
    "flutter-${FLUTTER_VERSION}.tar.xz"
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    "$SIZE_FLUTTER_3_24_5"
    "$SHA256_FLUTTER_3_24_5"
    "storage.googleapis.com"
    --entry
    "llvm-${LLVM_VERSION}.tar.xz"
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
    "$SIZE_LLVM_15_0_6"
    "$SHA256_LLVM_15_0_6"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "rust-${RUST_VERSION}.tar.xz"
    "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz"
    "$SIZE_RUST_1_75"
    "$SHA256_RUST_1_75"
    "static.rust-lang.org"
)
readonly -a ANDROID_BUILD_FIXED_ARCHIVE_ARGS=(
    --entry
    "android-cmdline-tools.zip"
    "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_BUILD}_latest.zip"
    "$SIZE_ANDROID_CMDLINE_TOOLS"
    "$SHA256_ANDROID_CMDLINE_TOOLS"
    "dl.google.com"
    --entry
    "android-ndk-${ANDROID_NDK_VERSION}.zip"
    "https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip"
    "$SIZE_ANDROID_NDK_R28C"
    "$SHA256_ANDROID_NDK_R28C"
    "dl.google.com"
    --entry
    "flutter-${FLUTTER_VERSION}.tar.xz"
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    "$SIZE_FLUTTER_3_24_5"
    "$SHA256_FLUTTER_3_24_5"
    "storage.googleapis.com"
    --entry
    "llvm-${LLVM_VERSION}.tar.xz"
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
    "$SIZE_LLVM_15_0_6"
    "$SHA256_LLVM_15_0_6"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    --entry
    "rust-${RUST_VERSION}.tar.xz"
    "https://static.rust-lang.org/dist/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz"
    "$SIZE_RUST_1_75"
    "$SHA256_RUST_1_75"
    "static.rust-lang.org"
    --entry
    "rust-std-${RUST_VERSION}-aarch64-linux-android.tar.xz"
    "https://static.rust-lang.org/dist/2023-12-28/rust-std-${RUST_VERSION}.0-aarch64-linux-android.tar.xz"
    "$SIZE_RUST_STD_ANDROID_1_75"
    "$SHA256_RUST_STD_ANDROID_1_75"
    "static.rust-lang.org"
    --entry
    "vcpkg-${VCPKG_BASELINE}.tar.gz"
    "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz"
    "$SIZE_VCPKG_120DEAC3"
    "$SHA256_VCPKG_120DEAC3"
    "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
)
readonly -a DART_AUDIT_FIXED_INPUT_ARGS=(
    --entry
    "dart-audit-inputs/Pub-all.zip"
    "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/Pub%2Fall.zip?alt=media&generation=${OSV_DB_PUB_GENERATION}"
    "$OSV_DB_PUB_SIZE"
    "$OSV_DB_PUB_SHA256"
    "storage.googleapis.com"
    --entry
    "dart-audit-inputs/osv-scanner"
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
    "$OSV_SCANNER_SIZE"
    "$OSV_SCANNER_SHA256"
    "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
)
readonly -a WIX_NUGET_FIXED_ARCHIVE_ARGS=(
    --entry
    "wix-nuget-packages/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.firewall.wixext/${WIX_NUGET_VERSION}/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_FIREWALL"
    "$SHA256_WIX_NUGET_FIREWALL"
    "api.nuget.org"
    --entry
    "wix-nuget-packages/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.heat/${WIX_NUGET_VERSION}/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_HEAT"
    "$SHA256_WIX_NUGET_HEAT"
    "api.nuget.org"
    --entry
    "wix-nuget-packages/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.netfx.wixext/${WIX_NUGET_VERSION}/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_NETFX"
    "$SHA256_WIX_NUGET_NETFX"
    "api.nuget.org"
    --entry
    "wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.sdk/${WIX_NUGET_VERSION}/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_SDK"
    "$SHA256_WIX_NUGET_SDK"
    "api.nuget.org"
    --entry
    "wix-nuget-packages/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.ui.wixext/${WIX_NUGET_VERSION}/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_UI"
    "$SHA256_WIX_NUGET_UI"
    "api.nuget.org"
    --entry
    "wix-nuget-packages/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg"
    "https://api.nuget.org/v3-flatcontainer/wixtoolset.util.wixext/${WIX_NUGET_VERSION}/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg"
    "$SIZE_WIX_NUGET_UTIL"
    "$SHA256_WIX_NUGET_UTIL"
    "api.nuget.org"
)
declare -a VCPKG_FIXED_ARCHIVE_ARGS=()
declare -a FLUTTER_PEER_FIXED_ARCHIVE_ARGS=()
readonly SYSTEMD_SMOKE_IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly -a SYSTEMD_SMOKE_IMAGE_ARGS=(
    --entry
    "$SYSTEMD_SMOKE_IMAGE_NAME"
    "https://cloud.debian.org/images/cloud/bookworm/${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}/$SYSTEMD_SMOKE_IMAGE_NAME"
    "$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE"
    "$SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE"
    "cloud.debian.org,laotzu.ftp.acc.umu.se"
)

ONLINE_FETCH_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-online-fetch.XXXXXXXXXX)" \
    || die "cannot create the private online-fetch workspace"
ONLINE_FETCH_TMP_ID="$(stat -c '%d:%i' -- "$ONLINE_FETCH_TMP")"
readonly ONLINE_FETCH_TMP ONLINE_FETCH_TMP_ID
cleanup_online_fetch_tmp() {
    local status=$? cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "$ONLINE_FETCH_TMP" ]; then
        if [ ! -d "$ONLINE_FETCH_TMP" ] || [ -L "$ONLINE_FETCH_TMP" ] \
           || [ "$(stat -c '%d:%i' -- "$ONLINE_FETCH_TMP" 2>/dev/null)" != "$ONLINE_FETCH_TMP_ID" ]; then
            echo "[FATAL] online-fetch private workspace identity changed: $ONLINE_FETCH_TMP" >&2
            cleanup_failed=1
        elif ! /usr/bin/python3 "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$ONLINE_FETCH_TMP" --expected-identity "$ONLINE_FETCH_TMP_ID"; then
            echo "[FATAL] online-fetch private workspace cleanup failed: $ONLINE_FETCH_TMP" >&2
            cleanup_failed=1
        elif [ -e "$ONLINE_FETCH_TMP" ] || [ -L "$ONLINE_FETCH_TMP" ]; then
            echo "[FATAL] online-fetch private workspace remains after cleanup: $ONLINE_FETCH_TMP" >&2
            cleanup_failed=1
        fi
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$status" -ne 0 ] || status=1
    exit "$status"
}
trap cleanup_online_fetch_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly ONLINE_FETCH_DOCKER_CONFIG="$ONLINE_FETCH_TMP/docker-config"
readonly ONLINE_FETCH_BUILDX_DIR="$ONLINE_FETCH_DOCKER_CONFIG/cli-plugins"
readonly ONLINE_FETCH_BUILDX_PLUGIN="$ONLINE_FETCH_BUILDX_DIR/docker-buildx"
install -d -m 0700 "$ONLINE_FETCH_DOCKER_CONFIG" "$ONLINE_FETCH_BUILDX_DIR"
install -m 0500 "$BUILDX_SOURCE" "$ONLINE_FETCH_BUILDX_PLUGIN"
printf '{}\n' >"$ONLINE_FETCH_DOCKER_CONFIG/config.json"
chmod 0600 "$ONLINE_FETCH_DOCKER_CONFIG/config.json"
export DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST"
export DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG"

assert_online_fetch_docker_authority() {
    [ "$(stat -c '%u:%g:%a:%h' -- "$DOCKER_BIN")" = "0:0:755:1" ] \
        || die "trusted Docker client metadata changed"
    [ -S /var/run/docker.sock ] || die "the fixed local Docker socket changed"
    [ -d "$ONLINE_FETCH_DOCKER_CONFIG" ] && [ ! -L "$ONLINE_FETCH_DOCKER_CONFIG" ] \
        || die "private Docker configuration directory changed"
    [ "$(stat -c '%u:%g:%a' -- "$ONLINE_FETCH_DOCKER_CONFIG")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Docker configuration directory metadata changed"
    [ -f "$ONLINE_FETCH_DOCKER_CONFIG/config.json" ] \
        && [ ! -L "$ONLINE_FETCH_DOCKER_CONFIG/config.json" ] \
        || die "private Docker configuration file changed"
    [ "$(stat -c '%u:%g:%a:%h' -- "$ONLINE_FETCH_DOCKER_CONFIG/config.json")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:600:1" ] \
        || die "private Docker configuration file metadata changed"
    [ "$(cat "$ONLINE_FETCH_DOCKER_CONFIG/config.json")" = "{}" ] \
        || die "private Docker configuration bytes changed"
    [ -d "$ONLINE_FETCH_BUILDX_DIR" ] && [ ! -L "$ONLINE_FETCH_BUILDX_DIR" ] \
        && [ "$(stat -c '%u:%g:%a' -- "$ONLINE_FETCH_BUILDX_DIR")" = \
             "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Buildx plugin directory changed"
    [ -f "$ONLINE_FETCH_BUILDX_PLUGIN" ] && [ ! -L "$ONLINE_FETCH_BUILDX_PLUGIN" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$ONLINE_FETCH_BUILDX_PLUGIN")" = \
             "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:500:1:$SIZE_VERIFIER_VM_BUILDX" ] \
        || die "private Buildx plugin metadata changed"
    [ "$(/usr/bin/sha256sum "$ONLINE_FETCH_BUILDX_PLUGIN" | /usr/bin/awk '{print $1}')" = \
      "$SHA256_VERIFIER_VM_BUILDX" ] \
        || die "private Buildx plugin bytes changed"
    [ "$(/usr/bin/find "$ONLINE_FETCH_BUILDX_DIR" -mindepth 1 -maxdepth 1 \
          -printf '%f\n')" = docker-buildx ] \
        || die "private Docker CLI plugin inventory changed"
}

online_docker() {
    local status=0
    assert_online_fetch_docker_authority
    env -i \
        PATH=/usr/bin:/bin \
        HOME="$ONLINE_FETCH_TMP" \
        DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST" \
        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \
        "$DOCKER_BIN" \
        --host "$ONLINE_FETCH_DOCKER_HOST" \
        --config "$ONLINE_FETCH_DOCKER_CONFIG" \
        "$@" || status=$?
    assert_online_fetch_docker_authority
    return "$status"
}

online_docker_without_vcs() {
    local status=0
    assert_online_fetch_docker_authority
    env -i \
        PATH=/usr/bin:/bin \
        HOME="$ONLINE_FETCH_TMP" \
        DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST" \
        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \
        BUILDX_GIT_INFO=false \
        "$DOCKER_BIN" \
        --host "$ONLINE_FETCH_DOCKER_HOST" \
        --config "$ONLINE_FETCH_DOCKER_CONFIG" \
        "$@" || status=$?
    assert_online_fetch_docker_authority
    return "$status"
}

assert_online_fetch_buildx_version() {
    local version
    assert_online_fetch_docker_authority
    version="$(
        env -i \
            PATH=/usr/bin:/bin \
            HOME="$ONLINE_FETCH_TMP" \
            DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST" \
            DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \
            "$DOCKER_BIN" \
            --host "$ONLINE_FETCH_DOCKER_HOST" \
            --config "$ONLINE_FETCH_DOCKER_CONFIG" \
            buildx version
    )" || die "cannot execute the exact private Buildx plugin"
    [ "$version" = \
      "github.com/docker/buildx v${VERIFIER_VM_BUILDX_VERSION} ${VERIFIER_VM_BUILDX_COMMIT}" ] \
        || die "private Buildx plugin version differs: $version"
    assert_online_fetch_docker_authority
}

assert_no_buildx_container_driver() {
    local names
    names="$(online_docker ps -a --format '{{.Names}}')" \
        || die "cannot inspect the guest container inventory"
    if /usr/bin/grep -Eq '^buildx_buildkit_' <<<"$names"; then
        die "a Buildx-managed builder container exists"
    fi
}

assert_online_fetch_containerd_image_store() {
    local driver_status
    driver_status="$(online_docker info --format '{{json .DriverStatus}}')" \
        || die "cannot inspect the guest Docker image store"
    [ "$driver_status" = '[["driver-type","io.containerd.snapshotter.v1"]]' ] \
        || die "the guest Docker daemon is not using its separate containerd image store: $driver_status"
}

create_online_fetch_buildx_builder() {
    local builder
    assert_online_fetch_containerd_image_store
    assert_no_buildx_container_driver
    builder="$(
        online_docker_without_vcs buildx create \
            --name "$ONLINE_FETCH_BUILDX_BUILDER" \
            --driver remote "$ONLINE_FETCH_BUILDKIT_ENDPOINT"
    )" || die "cannot create the exact remote Buildx builder"
    [ "$builder" = "$ONLINE_FETCH_BUILDX_BUILDER" ] \
        || die "remote Buildx builder creation returned an unexpected identity: $builder"
    assert_no_buildx_container_driver
}

assert_online_fetch_buildx_driver() {
    local inspect driver endpoint status buildkit_version worker_labels label
    local -a names=()
    assert_online_fetch_containerd_image_store
    assert_no_buildx_container_driver
    inspect="$(
        online_docker_without_vcs buildx \
            --builder "$ONLINE_FETCH_BUILDX_BUILDER" inspect --bootstrap
    )" || die "cannot inspect and bootstrap the exact remote Buildx builder"
    mapfile -t names < <(
        /usr/bin/awk -F ':' '
            {
                key=$1
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (key == "Name") {
                    value=substr($0, index($0, ":") + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                }
            }
        ' <<<"$inspect"
    )
    driver="$(
        /usr/bin/awk -F ':' '
            $1 == "Driver" {
                value=substr($0, index($0, ":") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
            }
        ' <<<"$inspect"
    )"
    endpoint="$(
        /usr/bin/awk -F ':' '
            {
                key=$1
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (key == "Endpoint") {
                    value=substr($0, index($0, ":") + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                }
            }
        ' <<<"$inspect"
    )"
    status="$(
        /usr/bin/awk -F ':' '
            {
                key=$1
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (key == "Status") {
                    value=substr($0, index($0, ":") + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                }
            }
        ' <<<"$inspect"
    )"
    buildkit_version="$(
        /usr/bin/awk -F ':' '
            {
                key=$1
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (key == "BuildKit version") {
                    value=substr($0, index($0, ":") + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                }
            }
        ' <<<"$inspect"
    )"
    worker_labels="$(
        /usr/bin/awk -F ':' '
            {
                key=$1
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (key ~ /^org[.]mobyproject[.]buildkit[.]worker[.]/) {
                    value=substr($0, index($0, ":") + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print key "=" value
                }
            }
        ' <<<"$inspect"
    )"
    [ "${#names[@]}" -eq 2 ] \
        && [ "${names[0]}" = "$ONLINE_FETCH_BUILDX_BUILDER" ] \
        && [ "${names[1]}" = "${ONLINE_FETCH_BUILDX_BUILDER}0" ] \
        || die "remote Buildx builder or node identity differs"
    [ "$driver" = remote ] \
        || die "the exact Buildx builder is not using the remote driver: $driver"
    [ "$endpoint" = "$ONLINE_FETCH_BUILDKIT_ENDPOINT" ] \
        || die "the exact Buildx builder endpoint differs: $endpoint"
    [ "$status" = running ] \
        || die "the exact Buildx builder is not running: $status"
    [ "$buildkit_version" = "v${VERIFIER_VM_BUILDKIT_VERSION}" ] \
        || die "the exact remote BuildKit version differs: $buildkit_version"
    for label in \
        'org.mobyproject.buildkit.worker.executor=oci' \
        'org.mobyproject.buildkit.worker.network=cni' \
        'org.mobyproject.buildkit.worker.oci.process-mode=sandbox' \
        'org.mobyproject.buildkit.worker.snapshotter=overlayfs'; do
        [ "$(/usr/bin/grep -Fxc "$label" <<<"$worker_labels")" -eq 1 ] \
            || die "the exact remote BuildKit worker label differs: $label"
    done
    assert_no_buildx_container_driver
}

online_buildx_build() {
    local status=0
    assert_online_fetch_buildx_driver
    online_docker_without_vcs buildx \
        --builder "$ONLINE_FETCH_BUILDX_BUILDER" build "$@" || status=$?
    assert_online_fetch_buildx_driver
    return "$status"
}

assert_online_fetch_buildx_version
create_online_fetch_buildx_builder
assert_online_fetch_buildx_driver
printf 'ONLINE_FETCH_BUILDX_AUTHORITY=pass version=%s commit=%s plugin=private driver=remote buildkit=%s endpoint=guest-unix network=bridge snapshotter=overlayfs process_sandbox=enabled builder=%s managed_container=absent image_store=separate\n' \
    "$VERIFIER_VM_BUILDX_VERSION" "$VERIFIER_VM_BUILDX_COMMIT" \
    "$VERIFIER_VM_BUILDKIT_VERSION" "$ONLINE_FETCH_BUILDX_BUILDER"
if [ "$ONLINE_FETCH_VM_AUTHORITY_PROBE" -eq 1 ]; then
    exit 0
fi

online_image_provenance() {
    local status=0
    assert_online_fetch_docker_authority
    env -i \
        PATH=/usr/bin:/bin \
        HOME="$ONLINE_FETCH_TMP" \
        DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST" \
        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \
        /usr/bin/python3 "$LIB_DIR/offline-image-provenance.py" "$@" || status=$?
    assert_online_fetch_docker_authority
    return "$status"
}

assert_online_fetch_source_tools() {
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GIT_BIN")" = \
      "0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY" ] \
        || die "trusted Git client metadata changed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$TAR_BIN")" = "0:0:755:1" ] \
        || die "trusted tar client metadata changed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$FLOCK_BIN")" = "0:0:755:1" ] \
        || die "trusted flock client metadata changed"
}

online_source_git() {
    local status=0
    assert_online_fetch_source_tools
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        HOME="$ONLINE_FETCH_TMP" \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null \
        GIT_ATTR_NOSYSTEM=1 \
        GIT_EXEC_PATH="$GIT_EXEC_PATH" \
        GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR" \
        GIT_ALLOW_PROTOCOL=file \
        GIT_NO_REPLACE_OBJECTS=1 \
        GIT_OPTIONAL_LOCKS=0 \
        "$GIT_BIN" \
        -c core.hooksPath=/dev/null \
        -c core.attributesFile=/dev/null \
        -c core.fsmonitor=false \
        -C "$REPO_ROOT" \
        "$@" || status=$?
    assert_online_fetch_source_tools
    return "$status"
}

verify_gradle_live_checkout_state() {
    local phase="$1" dirt index_flags sparse sparse_status=0 status=0
    if sparse="$(online_source_git config --local --no-includes --bool core.sparseCheckout)"; then
        if [ "$sparse" = true ]; then
            echo "[FATAL] $phase: sparse checkout is forbidden" >&2
            status=1
        fi
    else
        sparse_status=$?
        if [ "$sparse_status" -ne 1 ]; then
            echo "[FATAL] $phase: cannot inspect sparse-checkout state" >&2
            status=1
        fi
    fi
    if index_flags="$(online_source_git ls-files -v)"; then
        if printf '%s\n' "$index_flags" \
            | /usr/bin/awk 'substr($0,1,1) != "H" { found=1 } END { exit found ? 0 : 1 }'
        then
            echo "[FATAL] $phase: assume-unchanged, skip-worktree, or noncanonical index flags are forbidden" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot inspect tracked-file index flags" >&2
        status=1
    fi
    if ! online_source_git diff --no-ext-diff --quiet --ignore-submodules=none --; then
        echo "[FATAL] $phase: tracked worktree bytes differ from the index" >&2
        status=1
    fi
    if ! online_source_git diff --cached --no-ext-diff --quiet --ignore-submodules=none --; then
        echo "[FATAL] $phase: index differs from HEAD" >&2
        status=1
    fi
    if dirt="$(online_source_git status --porcelain=v1 --untracked-files=all)"; then
        if [ -n "$dirt" ]; then
            echo "[FATAL] $phase: source tree is not clean, including untracked files:
$dirt" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot inspect source-tree status" >&2
        status=1
    fi
    return "$status"
}

verify_clean_live_checkout_state() {
    local phase="$1" attributes grafts replacements status=0
    verify_gradle_live_checkout_state "$phase" || status=$?
    if attributes="$(online_source_git rev-parse --git-path info/attributes)"; then
        case "$attributes" in
            /*) ;;
            *) attributes="$REPO_ROOT/$attributes" ;;
        esac
        if [ -e "$attributes" ] || [ -L "$attributes" ]; then
            echo "[FATAL] $phase: repository-local Git attributes are forbidden" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot resolve repository-local Git attributes" >&2
        status=1
    fi
    if grafts="$(online_source_git rev-parse --git-path info/grafts)"; then
        case "$grafts" in
            /*) ;;
            *) grafts="$REPO_ROOT/$grafts" ;;
        esac
        if [ -e "$grafts" ] || [ -L "$grafts" ]; then
            echo "[FATAL] $phase: Git graft state is forbidden" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot resolve Git graft authority" >&2
        status=1
    fi
    if replacements="$(
        online_source_git for-each-ref --format='%(refname)' refs/replace
    )"; then
        if [ -n "$replacements" ]; then
            echo "[FATAL] $phase: Git replacement refs are forbidden" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot inspect Git replacement refs" >&2
        status=1
    fi
    return "$status"
}

# Online acquisition intentionally retains outbound bridge networking. It never
# publishes a port or joins a host namespace. Every producer otherwise receives
# the same immutable, numeric-nonroot, capability-free, resource-bounded floor.
online_docker_run() {
    online_docker run --rm --pull=never --network=bridge --read-only \
        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=2048 --memory=16g --memory-swap=16g --cpus=4 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g \
        "$@"
}

# Host-side archive expansion is not an acquisition-network consumer. Keep its
# otherwise identical immutable non-root authority on an explicitly networkless
# profile with non-executable bounded scratch.
online_docker_run_offline() {
    online_docker run --rm --pull=never --network=none --read-only \
        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=512 --memory=4g --memory-swap=4g --cpus=2 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m \
        "$@"
}

# Offline Cargo resolution installs the pinned Rust toolchain in scratch before it
# parses the complete 2.3 GiB vendor closure. Give that semantic check executable,
# bounded scratch without granting it acquisition networking or any writable input.
online_docker_run_cargo_semantic() {
    online_docker run --rm --pull=never --network=none --read-only \
        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=4g \
        "$@"
}

# Pub resolution needs the pinned Flutter SDK and a complete cache in executable
# scratch. Both the networked cache producer and the archive projection replay use
# this one networkless, non-root, capability-free semantic authority.
online_docker_run_pub_semantic() {
    online_docker run --rm --pull=never --network=none --read-only \
        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=512 --memory=8g --memory-swap=8g --cpus=4 \
        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=5g \
        "$@"
}

# Exact archive acquisition needs outbound HTTPS but no compiler-sized scratch,
# executable temporary storage, or broad cache/source authority.
online_docker_run_archive_acquisition() {
    online_docker run --rm --pull=never --network=bridge --read-only \
        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m \
        "$@"
}

prepare_online_root() {
    if [ -e "$ONLINE_STATE_ROOT" ] || [ -L "$ONLINE_STATE_ROOT" ]; then
        [ -d "$ONLINE_STATE_ROOT" ] && [ ! -L "$ONLINE_STATE_ROOT" ] \
            || die "online cache state root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g' -- "$ONLINE_STATE_ROOT")" = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" ] \
            || die "online cache state root is not owned by the acquisition identity"
        /usr/bin/chmod 0700 "$ONLINE_STATE_ROOT"
    else
        /usr/bin/install -d -m 0700 "$ONLINE_STATE_ROOT"
    fi
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_STATE_ROOT")" = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "online cache state root is not current-user-private mode 0700"
    if [ -e "$ONLINE_DIR" ] || [ -L "$ONLINE_DIR" ]; then
        [ -d "$ONLINE_DIR" ] && [ ! -L "$ONLINE_DIR" ] \
            || die "online cache root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g' -- "$ONLINE_DIR")" = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" ] \
            || die "online cache root is not owned by the acquisition identity"
        /usr/bin/chmod 0700 "$ONLINE_DIR"
    else
        /usr/bin/install -d -m 0700 "$ONLINE_DIR"
    fi
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_DIR")" = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "online cache root is not current-user-private mode 0700"
}

prepare_retired_online_input_root() {
    [ -d "$ONLINE_STATE_ROOT" ] && [ ! -L "$ONLINE_STATE_ROOT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$ONLINE_STATE_ROOT")" \
             = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "online cache state root is not acquisition-identity-owned mode 0700"
    if [ -e "$RETIRED_ONLINE_INPUT_ROOT" ] || [ -L "$RETIRED_ONLINE_INPUT_ROOT" ]; then
        [ -d "$RETIRED_ONLINE_INPUT_ROOT" ] && [ ! -L "$RETIRED_ONLINE_INPUT_ROOT" ] \
            || die "retired online-input root is not one real directory"
    else
        /usr/bin/install -d -m 0700 -- "$RETIRED_ONLINE_INPUT_ROOT"
    fi
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$RETIRED_ONLINE_INPUT_ROOT")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "retired online-input root is not acquisition-identity-owned mode 0700"
    [ "$(/usr/bin/stat -c '%d' -- "$RETIRED_ONLINE_INPUT_ROOT")" \
       = "$(/usr/bin/stat -c '%d' -- "$ONLINE_DIR")" ] \
        || die "retired online-input root is not on the online filesystem"
}

retire_archived_online_input() {
    [ "$#" -eq 2 ] || die "retired online-input cleanup requires PATH and LABEL"
    local archive="$1" label="$2" archive_parent archive_id
    archive_parent="$(/usr/bin/dirname -- "$archive")" \
        || die "cannot derive $label archive parent"
    [ "$archive_parent" = "$RETIRED_ONLINE_INPUT_ROOT" ] \
        || die "$label archive is outside the retired online-input root"
    [ -d "$archive" ] && [ ! -L "$archive" ] \
        || die "$label archive is not one real directory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$archive")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "$label archive is not acquisition-identity-owned mode 0700"
    archive_id="$(/usr/bin/stat -c '%d:%i' -- "$archive")" \
        || die "cannot record $label archive identity"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$archive" --expected-identity "$archive_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore $label archive traversal before retirement"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$archive" --expected-identity "$archive_id" \
        || die "cannot retire the exact $label archive"
    [ ! -e "$archive" ] && [ ! -L "$archive" ] \
        || die "$label archive survived exact retirement"
}

retire_empty_online_input_root() {
    [ "$#" -eq 0 ] || die "retired online-input root cleanup takes no arguments"
    [ -d "$RETIRED_ONLINE_INPUT_ROOT" ] && [ ! -L "$RETIRED_ONLINE_INPUT_ROOT" ] \
        || die "retired online-input root is not one real directory before cleanup"
    local retired_root_id
    retired_root_id="$(/usr/bin/stat -c '%d:%i' -- "$RETIRED_ONLINE_INPUT_ROOT")" \
        || die "cannot record retired online-input root identity"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-empty-private-root "$RETIRED_ONLINE_INPUT_ROOT" \
        --expected-identity "$retired_root_id" \
        || die "cannot retire the empty online-input record root"
    [ ! -e "$RETIRED_ONLINE_INPUT_ROOT" ] && [ ! -L "$RETIRED_ONLINE_INPUT_ROOT" ] \
        || die "empty retired online-input root survived cleanup"
}

retire_empty_online_input_root_if_present() {
    [ "$#" -eq 0 ] || die "conditional retired online-input root cleanup takes no arguments"
    if [ ! -e "$RETIRED_ONLINE_INPUT_ROOT" ] && [ ! -L "$RETIRED_ONLINE_INPUT_ROOT" ]; then
        return 0
    fi
    prepare_retired_online_input_root
    retire_empty_online_input_root
}

reconcile_retired_online_input_archives() {
    [ "$#" -eq 0 ] || die "retired online-input reconciliation takes no arguments"
    if [ ! -e "$RETIRED_ONLINE_INPUT_ROOT" ] && [ ! -L "$RETIRED_ONLINE_INPUT_ROOT" ]; then
        return 0
    fi
    prepare_retired_online_input_root
    local archives=() archive archive_name
    mapfile -d '' archives < <(
        /usr/bin/find "$RETIRED_ONLINE_INPUT_ROOT" -mindepth 1 -maxdepth 1 -print0
    ) || die "cannot enumerate retired online-input archives"
    for archive in "${archives[@]}"; do
        archive_name="${archive##*/}"
        [[ "$archive_name" =~ ^(pub-cache|gradle-home)-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$ ]] \
            || die "retired online-input root contains an unknown entry: $archive_name"
        retire_archived_online_input "$archive" "interrupted completed replacement"
        log "Interrupted completed online-input replacement archive was exactly retired: $archive_name"
    done
    retire_empty_online_input_root
}
assert_online_fetch_docker_authority

# The installed-systemd behavior gate needs a real PID-1/cgroup environment but
# must never borrow the host manager or host cgroup tree. Keep its immutable,
# publisher-hashed Debian base in the private harness state used for VM images.
# This explicit mode remains the sole network acquisition path; the smoke itself
# runs QEMU with `-nic none` and a throwaway CoW overlay.
fetch_debian_systemd_smoke_image() {
    local harness_state="$REPO_ROOT/.harness-state"
    local state_dir="$harness_state/debian-systemd-smoke"
    local dest="$state_dir/$SYSTEMD_SMOKE_IMAGE_NAME"
    local metadata
    if [ -e "$harness_state" ] || [ -L "$harness_state" ]; then
        [ -d "$harness_state" ] && [ ! -L "$harness_state" ] \
            || die "harness state root is not one real directory"
    else
        /usr/bin/install -d -m 0700 -- "$harness_state"
    fi
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$harness_state")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "harness state root is not acquisition-identity-owned mode 0700"
    if [ -e "$state_dir" ] || [ -L "$state_dir" ]; then
        [ -d "$state_dir" ] && [ ! -L "$state_dir" ] \
            || die "systemd smoke state directory is not one real directory"
    else
        /usr/bin/install -d -m 0700 -- "$state_dir"
    fi
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$state_dir")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "systemd smoke state directory is not acquisition-identity-owned mode 0700"
    stage_archive_bundle systemd "$state_dir" .rustdesk-debian-systemd-image \
        "pinned Debian systemd smoke image"
    verify_sha512 "$dest" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$dest")"
    case "$metadata" in
        "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" | \
        "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:444:1") ;;
        *) die "systemd smoke image is outside its closed read-only metadata profiles" ;;
    esac
    log "Debian systemd smoke image acquired transactionally and SHA512-verified: $dest"
}

libvpx_live_native_key() {
    (
        printf 'VCPKG_BASELINE=%s\n' "$VCPKG_BASELINE"
        printf 'LIBVPX_SOURCE_REF=%s\n' "$LIBVPX_SOURCE_REF"
        printf 'SHA512_LIBVPX_SOURCE=%s\n' "$SHA512_LIBVPX_SOURCE"
        printf 'LIBVPX_FIX_COMMIT=%s\n' "$LIBVPX_FIX_COMMIT"
        printf 'SHA512_LIBVPX_PATCH=%s\n' "$SHA512_LIBVPX_PATCH"
        cd "$REPO_ROOT"
        find res/vcpkg/libvpx -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            sha256sum "$file"
        done
    ) | sha256sum | awk '{print $1}'
}

LIBVPX_SOURCE_AUTHORITY_COMMIT=""
LIBVPX_SOURCE_AUTHORITY_TREE=""
LIBVPX_SOURCE_AUTHORITY_BLOB=""
LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY=""
LIBVPX_SOURCE_AUTHORITY_ROOT=""
LIBVPX_SOURCE_AUTHORITY_PATCH=""
LIBVPX_SOURCE_AUTHORITY_ROOT_ID=""
LIBVPX_SOURCE_AUTHORITY_PATCH_ID=""

libvpx_native_key_for_commit() {
    local commit="$1" inventory entry metadata mode type object file digest count=0
    inventory="$(
        umask 077
        /usr/bin/mktemp "$ONLINE_FETCH_TMP/libvpx-source-tree.XXXXXXXXXX"
    )" || die "cannot create the exact libvpx source inventory"
    online_source_git ls-tree -rz --full-tree "$commit" -- res/vcpkg/libvpx \
        >"$inventory" \
        || die "cannot enumerate the committed libvpx source tree"
    (
        printf 'VCPKG_BASELINE=%s\n' "$VCPKG_BASELINE"
        printf 'LIBVPX_SOURCE_REF=%s\n' "$LIBVPX_SOURCE_REF"
        printf 'SHA512_LIBVPX_SOURCE=%s\n' "$SHA512_LIBVPX_SOURCE"
        printf 'LIBVPX_FIX_COMMIT=%s\n' "$LIBVPX_FIX_COMMIT"
        printf 'SHA512_LIBVPX_PATCH=%s\n' "$SHA512_LIBVPX_PATCH"
        while IFS= read -r -d '' entry; do
            metadata="${entry%%$'\t'*}"
            file="${entry#*$'\t'}"
            read -r mode type object <<<"$metadata"
            [ "$type" = blob ] && { [ "$mode" = 100644 ] || [ "$mode" = 100755 ]; } \
                || die "committed libvpx source contains a symlink, submodule, or special entry: $file"
            case "$file" in
                res/vcpkg/libvpx/*) ;;
                *) die "committed libvpx source inventory escaped its exact subtree: $file" ;;
            esac
            digest="$(
                online_source_git cat-file blob "$object" \
                    | /usr/bin/sha256sum \
                    | /usr/bin/awk '{print $1}'
            )" || die "cannot hash committed libvpx source object: $file"
            printf '%s  %s\n' "$digest" "$file"
            count=$((count + 1))
        done <"$inventory"
        [ "$count" -gt 0 ] || die "committed libvpx source tree is empty"
    ) | /usr/bin/sha256sum | /usr/bin/awk '{print $1}'
}

verify_libvpx_private_source_authority() {
    local phase="$1" directory current
    [ "$LIBVPX_SOURCE_AUTHORITY_ROOT" = "$ONLINE_FETCH_TMP/libvpx-source-authority" ] \
        && [ "$LIBVPX_SOURCE_AUTHORITY_PATCH" \
             = "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch" ] \
        || { echo "[FATAL] $phase: private libvpx source paths changed" >&2; return 1; }
    for directory in \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg/libvpx"
    do
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
                 = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:500" ] \
            || { echo "[FATAL] $phase: private libvpx source directory changed" >&2; return 1; }
    done
    [ "$(/usr/bin/stat -c '%d:%i' -- "$LIBVPX_SOURCE_AUTHORITY_ROOT")" \
       = "$LIBVPX_SOURCE_AUTHORITY_ROOT_ID" ] \
        || { echo "[FATAL] $phase: private libvpx source root identity changed" >&2; return 1; }
    [ -f "$LIBVPX_SOURCE_AUTHORITY_PATCH" ] && [ ! -L "$LIBVPX_SOURCE_AUTHORITY_PATCH" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$LIBVPX_SOURCE_AUTHORITY_PATCH")" \
             = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$LIBVPX_SOURCE_AUTHORITY_PATCH")" \
             = "$LIBVPX_SOURCE_AUTHORITY_PATCH_ID" ] \
        || { echo "[FATAL] $phase: private libvpx patch metadata changed" >&2; return 1; }
    current="$(
        online_source_git hash-object --no-filters -- "$LIBVPX_SOURCE_AUTHORITY_PATCH"
    )" || { echo "[FATAL] $phase: cannot hash the private libvpx patch" >&2; return 1; }
    [ "$current" = "$LIBVPX_SOURCE_AUTHORITY_BLOB" ] \
        || { echo "[FATAL] $phase: private libvpx patch differs from its committed blob" >&2; return 1; }
    current="$(
        /usr/bin/sha512sum "$LIBVPX_SOURCE_AUTHORITY_PATCH" | /usr/bin/awk '{print $1}'
    )" || { echo "[FATAL] $phase: cannot digest the private libvpx patch" >&2; return 1; }
    [ "$current" = "$SHA512_LIBVPX_PATCH" ] \
        || { echo "[FATAL] $phase: private libvpx patch differs from its SHA-512 pin" >&2; return 1; }
}

materialize_libvpx_private_source_authority() {
    LIBVPX_SOURCE_AUTHORITY_ROOT="$ONLINE_FETCH_TMP/libvpx-source-authority"
    LIBVPX_SOURCE_AUTHORITY_PATCH="$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch"
    [ ! -e "$LIBVPX_SOURCE_AUTHORITY_ROOT" ] && [ ! -L "$LIBVPX_SOURCE_AUTHORITY_ROOT" ] \
        || die "private libvpx source authority already exists"
    (
        umask 077
        /usr/bin/mkdir -p "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg/libvpx"
    ) || die "cannot create the private libvpx source authority"
    (
        set -o noclobber
        online_source_git cat-file blob "$LIBVPX_SOURCE_AUTHORITY_BLOB" \
            >"$LIBVPX_SOURCE_AUTHORITY_PATCH"
    ) || die "cannot exclusively materialize the committed libvpx patch blob"
    /usr/bin/chmod 0400 "$LIBVPX_SOURCE_AUTHORITY_PATCH"
    /usr/bin/chmod 0500 \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg/libvpx" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res/vcpkg" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT/res" \
        "$LIBVPX_SOURCE_AUTHORITY_ROOT"
    LIBVPX_SOURCE_AUTHORITY_ROOT_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$LIBVPX_SOURCE_AUTHORITY_ROOT"
    )"
    LIBVPX_SOURCE_AUTHORITY_PATCH_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$LIBVPX_SOURCE_AUTHORITY_PATCH"
    )"
    verify_libvpx_private_source_authority "after private libvpx source materialization" \
        || die "cannot establish the private libvpx source authority"
}

prepare_libvpx_source_authority() {
    local entry metadata mode type blob path current_key
    [ -z "$LIBVPX_SOURCE_AUTHORITY_COMMIT" ] \
        || die "libvpx source authority was initialized more than once"
    LIBVPX_SOURCE_AUTHORITY_COMMIT="$(
        online_source_git rev-parse --verify 'HEAD^{commit}'
    )" || die "cannot resolve the committed libvpx source identity"
    LIBVPX_SOURCE_AUTHORITY_TREE="$(
        online_source_git rev-parse --verify "${LIBVPX_SOURCE_AUTHORITY_COMMIT}^{tree}"
    )" || die "cannot resolve the committed libvpx source tree"
    [[ "$LIBVPX_SOURCE_AUTHORITY_COMMIT" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] \
        || die "committed libvpx source identity is malformed"
    [[ "$LIBVPX_SOURCE_AUTHORITY_TREE" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] \
        || die "committed libvpx source tree identity is malformed"
    verify_clean_live_checkout_state "before committed libvpx local publication" \
        || die "libvpx local publication requires one clean canonical committed source tree"
    entry="$(
        online_source_git ls-tree --full-tree "$LIBVPX_SOURCE_AUTHORITY_COMMIT" \
            -- res/vcpkg/libvpx/0005-cve-2026-1861.patch
    )" || die "cannot resolve the committed libvpx security patch"
    [ "$(printf '%s\n' "$entry" | /usr/bin/wc -l)" -eq 1 ] \
        || die "committed libvpx security patch has ambiguous Git state"
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    read -r mode type blob <<<"$metadata"
    [ "$mode" = 100644 ] && [ "$type" = blob ] \
        && [ "$path" = res/vcpkg/libvpx/0005-cve-2026-1861.patch ] \
        || die "committed libvpx security patch is not one ordinary tracked blob"
    [ "$(
        online_source_git hash-object --no-filters -- \
            res/vcpkg/libvpx/0005-cve-2026-1861.patch
    )" = "$blob" ] \
        || die "live libvpx security patch differs from its committed blob"
    LIBVPX_SOURCE_AUTHORITY_BLOB="$blob"
    LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY="$(
        libvpx_native_key_for_commit "$LIBVPX_SOURCE_AUTHORITY_COMMIT"
    )" || die "cannot derive the committed libvpx native-input key"
    current_key="$(libvpx_live_native_key)" \
        || die "cannot derive the live libvpx native-input key"
    [ "$current_key" = "$LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY" ] \
        || die "live libvpx inputs differ from the committed native-input authority"
    materialize_libvpx_private_source_authority
}

verify_libvpx_source_authority() {
    local phase="$1" current entry metadata mode type blob path current_key status=0
    if [ -z "$LIBVPX_SOURCE_AUTHORITY_COMMIT" ] \
       || [ -z "$LIBVPX_SOURCE_AUTHORITY_TREE" ] \
       || [ -z "$LIBVPX_SOURCE_AUTHORITY_BLOB" ] \
       || [ -z "$LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY" ]; then
        echo "[FATAL] $phase: committed libvpx source authority is uninitialized" >&2
        return 1
    fi
    if current="$(online_source_git rev-parse --verify 'HEAD^{commit}')"; then
        [ "$current" = "$LIBVPX_SOURCE_AUTHORITY_COMMIT" ] || {
            echo "[FATAL] $phase: source commit changed" >&2
            status=1
        }
    else
        echo "[FATAL] $phase: cannot re-resolve source commit" >&2
        status=1
    fi
    if current="$(
        online_source_git rev-parse --verify "${LIBVPX_SOURCE_AUTHORITY_COMMIT}^{tree}"
    )"; then
        [ "$current" = "$LIBVPX_SOURCE_AUTHORITY_TREE" ] || {
            echo "[FATAL] $phase: source tree changed" >&2
            status=1
        }
    else
        echo "[FATAL] $phase: cannot re-resolve source tree" >&2
        status=1
    fi
    if entry="$(
        online_source_git ls-tree --full-tree "$LIBVPX_SOURCE_AUTHORITY_COMMIT" \
            -- res/vcpkg/libvpx/0005-cve-2026-1861.patch
    )"; then
        metadata="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        read -r mode type blob <<<"$metadata"
        if [ "$mode" != 100644 ] || [ "$type" != blob ] \
           || [ "$blob" != "$LIBVPX_SOURCE_AUTHORITY_BLOB" ] \
           || [ "$path" != res/vcpkg/libvpx/0005-cve-2026-1861.patch ]; then
            echo "[FATAL] $phase: committed libvpx patch identity changed" >&2
            status=1
        fi
    else
        echo "[FATAL] $phase: cannot re-resolve committed libvpx patch" >&2
        status=1
    fi
    if ! verify_clean_live_checkout_state "$phase"; then
        status=1
    fi
    if current="$(
        online_source_git hash-object --no-filters -- \
            res/vcpkg/libvpx/0005-cve-2026-1861.patch
    )"; then
        [ "$current" = "$LIBVPX_SOURCE_AUTHORITY_BLOB" ] || {
            echo "[FATAL] $phase: live libvpx patch differs from its committed blob" >&2
            status=1
        }
    else
        echo "[FATAL] $phase: cannot hash the live libvpx patch" >&2
        status=1
    fi
    if current_key="$(libvpx_live_native_key)"; then
        [ "$current_key" = "$LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY" ] || {
            echo "[FATAL] $phase: live libvpx input key changed" >&2
            status=1
        }
    else
        echo "[FATAL] $phase: cannot recompute the live libvpx input key" >&2
        status=1
    fi
    return "$status"
}

libvpx_native_key() {
    [ -n "$LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY" ] \
        || die "committed libvpx source authority is uninitialized"
    printf '%s\n' "$LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY"
}

vcpkg_native_output_key() {
    local kind="$1" builder="$2" ports unexpected_overlay
    case "$kind" in
        x64-linux)
            ports="libvpx libyuv opus"
            ;;
        arm64-android)
            ports="libvpx libyuv opus oboe"
            ;;
        *)
            die "unsupported vcpkg native output kind: $kind"
            ;;
    esac
    [ -d "$REPO_ROOT/res/vcpkg" ] && [ ! -L "$REPO_ROOT/res/vcpkg" ] \
        || die "vcpkg overlay root is not one real directory"
    unexpected_overlay="$(
        cd "$REPO_ROOT"
        find res/vcpkg -mindepth 1 ! -type d ! -type f -print -quit
    )"
    [ -z "$unexpected_overlay" ] \
        || die "vcpkg overlay contains an unhashable non-file entry: $unexpected_overlay"
    (
        printf 'FORMAT=rustdesk-vcpkg-native-output-v1\n'
        printf 'KIND=%s\n' "$kind"
        printf 'PORTS=%s\n' "$ports"
        printf 'BUILDER=%s\n' "$builder"
        printf 'VCPKG_BASELINE=%s\n' "$VCPKG_BASELINE"
        printf 'SHA256_VCPKG=%s\n' "$SHA256_VCPKG_120DEAC3"
        printf 'LIBVPX_NATIVE_KEY=%s\n' "$(libvpx_native_key)"
        printf 'LIBYUV_COMMIT=%s\n' "$LIBYUV_COMMIT"
        printf 'SHA512_LIBYUV=%s\n' "$SHA512_LIBYUV"
        if [ "$kind" = arm64-android ]; then
            printf 'ANDROID_NDK_VERSION=%s\n' "$ANDROID_NDK_VERSION"
            printf 'SHA256_ANDROID_NDK=%s\n' "$SHA256_ANDROID_NDK_R28C"
        fi
        cd "$REPO_ROOT"
        find res/vcpkg -type d -print0 | LC_ALL=C sort -z \
            | while IFS= read -r -d '' directory; do
                printf 'OVERLAY_DIRECTORY\0%s\0' "$directory"
            done
        find res/vcpkg -type f -print0 | LC_ALL=C sort -z \
            | while IFS= read -r -d '' file; do
                printf 'OVERLAY_FILE\0%s\0' "$file"
                sha256sum "$file" | cut -d' ' -f1 | tr -d '\n'
                printf '\0'
            done
    ) | sha256sum | awk '{print $1}'
}

require_libvpx_distfiles() {
    local dir="$ONLINE_DIR/vcpkg-distfiles"
    verify_libvpx_source_authority "before libvpx distfile consumption" \
        || die "committed libvpx source authority changed before consumption"
    verify_libvpx_private_source_authority "before libvpx distfile consumption" \
        || die "private libvpx source authority changed before consumption"
    [ -f "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" ] \
        && [ ! -L "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" ] \
        || die "libvpx source capture missing — stage_vcpkg_distfiles must run first"
    [ "$(sha512sum "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" | awk '{print $1}')" \
       = "$SHA512_LIBVPX_SOURCE" ] \
        || die "libvpx source capture SHA512 mismatch"
    /usr/bin/python3 -I -S "$LIBVPX_LOCAL_OUTPUT_HELPER" check \
        --online "$ONLINE_DIR" \
        --source-root "$LIBVPX_SOURCE_AUTHORITY_ROOT" \
        --source-patch "$LIBVPX_SOURCE_AUTHORITY_PATCH" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        --fix-commit "$LIBVPX_FIX_COMMIT" \
        --patch-sha512 "$SHA512_LIBVPX_PATCH" \
        --native-key "$(libvpx_native_key)" \
        --source-commit "$LIBVPX_SOURCE_AUTHORITY_COMMIT" \
        --source-tree "$LIBVPX_SOURCE_AUTHORITY_TREE" \
        --source-blob "$LIBVPX_SOURCE_AUTHORITY_BLOB" \
        || die "libvpx committed patch/native-key publication is incomplete or unsafe"
}

require_libyuv_distfile() {
    local archive="$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz"
    [ -f "$archive" ] && [ ! -L "$archive" ] \
        || die "libyuv source capture missing — stage_vcpkg_distfiles must run first"
    [ "$(sha512sum "$archive" | awk '{print $1}')" = "$SHA512_LIBYUV" ] \
        || die "libyuv source capture SHA512 mismatch"
}

# ── Rust crate world: vendor the committed lockfile (incl. git-sourced records) ──
# Cargo receives one exact committed source snapshot, one pinned Rust archive, and
# two private outputs. The live checkout, broad online cache, and final names are
# never producer mounts. A separate networkless Cargo process must resolve the
# lockfile from the sealed candidate before the host authorizes publication.
cargo_vendor_output_tool() {
    [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ] \
        || die "Cargo vendor output authority requires the exact source snapshot"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/online-cargo-vendor-output.py" "$@"
}

cargo_vendor_output_args() {
    printf '%s\0' \
        --source-commit "$GRADLE_SOURCE_COMMIT" \
        --source-tree "$GRADLE_SOURCE_TREE" \
        --source-archive-sha256 "$GRADLE_SOURCE_ARCHIVE_SHA256" \
        --builder "$DEB_BUILDER_CONFIG_ID" \
        --rust-sha256 "$SHA256_RUST_1_75" \
        --vendor-sha256 "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        --config-sha256 "$SHA256_CARGO_VENDOR_CONFIG" \
        --config-vendor-path "/online/cargo-vendor" \
        --config-size "$SIZE_CARGO_VENDOR_CONFIG" \
        --files "$CARGO_VENDOR_FILES_V1" \
        --directories "$CARGO_VENDOR_DIRECTORIES_V1" \
        --content-bytes "$CARGO_VENDOR_CONTENT_BYTES_V1"
}

maintenance_print_cargo_vendor_candidate() {
    local candidate staging raw raw_before raw_after config_sha256 config_size
    local restore_nullglob=0
    local -a candidates=()
    if ! shopt -q nullglob; then
        shopt -s nullglob
        restore_nullglob=1
    fi
    candidates=("$ONLINE_DIR"/.rustdesk-cargo-vendor.*.tree)
    [ "$restore_nullglob" -eq 0 ] || shopt -u nullglob
    [ "${#candidates[@]}" -eq 1 ] \
        || die "maintenance Cargo vendor inspection requires exactly one retained candidate"
    candidate=${candidates[0]}
    [[ "${candidate##*/}" =~ ^\.rustdesk-cargo-vendor\.[A-Za-z0-9_]{8,64}\.tree$ ]] \
        || die "retained Cargo vendor candidate name is malformed"
    [ -d "$candidate" ] && [ ! -L "$candidate" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$candidate")" = \
             "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "retained Cargo vendor candidate metadata differs"
    staging=${candidate%.tree}
    raw=$staging/raw-config.toml
    [ -d "$staging" ] && [ ! -L "$staging" ] \
        && [ -f "$raw" ] && [ ! -L "$raw" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$raw")" = \
             "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:600:1" ] \
        || die "retained Cargo vendor transaction metadata differs"
    raw_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$raw"):$(/usr/bin/sha256sum "$raw")"
    config_sha256="$(
        /usr/bin/sed 's#^directory = "/outputs/vendor"$#directory = "/online/cargo-vendor"#' "$raw" \
            | /usr/bin/sha256sum | /usr/bin/awk '{ print $1 }'
    )"
    config_size="$(
        /usr/bin/sed 's#^directory = "/outputs/vendor"$#directory = "/online/cargo-vendor"#' "$raw" \
            | /usr/bin/wc -c
    )"
    raw_after="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$raw"):$(/usr/bin/sha256sum "$raw")"
    [ "$raw_after" = "$raw_before" ] \
        || die "retained Cargo vendor raw config changed during inspection"
    printf 'cargo_vendor_config_sha256=%s\ncargo_vendor_config_size=%s\n' \
        "$config_sha256" "$config_size"
    /usr/bin/python3 -I -S "$LIB_DIR/online-input-provenance.py" \
        maintenance-print-root --tree "$candidate"
}

retire_cargo_vendor_output_staging() {
    local staging="$1" staging_id="$2" disposition candidate candidate_id
    local output_args=()
    mapfile -d '' output_args < <(cargo_vendor_output_args)
    disposition="$(
        cargo_vendor_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${output_args[@]}"
    )" || die "cannot reconcile private Cargo vendor staging"
    log "Cargo vendor staging reconciliation: $disposition"
    candidate="${staging}.tree"
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        [ -d "$candidate" ] && [ ! -L "$candidate" ] \
            || die "reserved Cargo vendor tree is not one real directory: $candidate"
        candidate_id="$(/usr/bin/stat -c '%d:%i' -- "$candidate")"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
            --root "$candidate" --expected-identity "$candidate_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "cannot restore private Cargo vendor candidate traversal"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
            --remove-private-root "$candidate" --expected-identity "$candidate_id" \
            || die "cannot retire private Cargo vendor candidate"
    fi
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Cargo vendor transaction traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Cargo vendor transaction"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        && [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
        || die "private Cargo vendor transaction survived retirement"
}

recover_cargo_vendor_output_staging() {
    local reserved=() staging staging_id base
    mapfile -d '' reserved < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-cargo-vendor.*" -print0
    )
    for staging in "${reserved[@]}"; do
        case "$staging" in
            *.tree)
                [[ "${staging##*/}" =~ ^\.rustdesk-cargo-vendor\.[A-Za-z0-9_]{8,64}\.tree$ ]] \
                    || die "reserved Cargo vendor candidate name is malformed: $staging"
                base="${staging%.tree}"
                [ -d "$base" ] && [ ! -L "$base" ] \
                    || die "orphaned Cargo vendor candidate has no transaction: $staging"
                ;;
            *)
                [[ "${staging##*/}" =~ ^\.rustdesk-cargo-vendor\.[A-Za-z0-9_]{8,64}$ ]] \
                    || die "reserved Cargo vendor transaction name is malformed: $staging"
                [ -d "$staging" ] && [ ! -L "$staging" ] \
                    || die "reserved Cargo vendor transaction is not one real directory: $staging"
                ;;
        esac
    done
    for staging in "${reserved[@]}"; do
        case "$staging" in
            *.tree) continue ;;
        esac
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_cargo_vendor_output_staging "$staging" "$staging_id"
    done
}

verify_cargo_vendor_source_unchanged() {
    (
        prepare_gradle_source
        retire_gradle_source_build
    )
}

vendor_cargo() {
    local builder="$DEB_BUILDER_CONFIG_ID"
    local producer_status=0 source_status=0 input_status=0
    local output_status=0 semantic_status=0 publication_status=0
    local lock_fd staging staging_id candidate
    local output_args=()
    require_online_fetch_builder_image deb-builder "$builder"
    assert_online_fetch_source_tools
    [ -f "$CARGO_VENDOR_OUTPUT_HELPER" ] && [ ! -L "$CARGO_VENDOR_OUTPUT_HELPER" ] \
        || die "Cargo vendor output helper is not one real source file"
    verify_sha256 \
        "$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75"
    prepare_gradle_source
    retire_gradle_source_build
    mapfile -d '' output_args < <(cargo_vendor_output_args)
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Cargo vendor serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Cargo vendor transaction already owns the online root"
    recover_cargo_vendor_output_staging
    if [ -e "$ONLINE_DIR/cargo-vendor" ] || [ -L "$ONLINE_DIR/cargo-vendor" ] \
       || [ -e "$ONLINE_DIR/cargo-vendor-config.toml" ] \
       || [ -L "$ONLINE_DIR/cargo-vendor-config.toml" ]
    then
        cargo_vendor_output_tool check-complete \
            --online "$ONLINE_DIR" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${output_args[@]}" \
            || die "existing Cargo vendor closure is incomplete, stale, or unsafe"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Cargo vendor transaction lock"
        exec {lock_fd}<&-
        log "Cargo vendor closure and source map already exact, skipping"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-cargo-vendor.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Cargo vendor staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! cargo_vendor_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${output_args[@]}"
    then
        retire_cargo_vendor_output_staging "$staging" "$staging_id"
        die "cannot prepare private Cargo vendor staging"
    fi
    candidate="${staging}.tree"
    log "vendoring the exact committed lockfile into one private checked output"
    online_docker_run \
        --env "RUSTDESK_RUST_VERSION=$RUST_VERSION" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY,target=/source,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz,target=/inputs/rust.tar.xz,readonly" \
        --mount "type=bind,source=$candidate,target=/outputs/vendor" \
        --mount "type=bind,source=$staging/raw-config.toml,target=/outputs/raw-config.toml" \
        --workdir /source \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
            umask 077
            mkdir /tmp/toolchain /tmp/rust /tmp/home /tmp/cargo-home /tmp/cargo-target
            tar -C /tmp/toolchain -xf /inputs/rust.tar.xz
            installer="/tmp/toolchain/rust-${RUSTDESK_RUST_VERSION}.0-x86_64-unknown-linux-gnu/install.sh"
            "$installer" --prefix=/tmp/rust --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu >/dev/null
            export HOME=/tmp/home
            export CARGO_HOME=/tmp/cargo-home
            export CARGO_TARGET_DIR=/tmp/cargo-target
            export CARGO_NET_GIT_FETCH_WITH_CLI=false
            export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
            export GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0
            export PATH=/tmp/rust/bin:/usr/bin:/bin
            cargo vendor --locked --versioned-dirs \
                --manifest-path /source/Cargo.toml /outputs/vendor \
                > /outputs/raw-config.toml
        ' || producer_status=$?
    verify_sha256 \
        "$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
        || input_status=$?
    verify_cargo_vendor_source_unchanged || source_status=$?
    cargo_vendor_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$producer_status" -eq 0 ] && [ "$source_status" -eq 0 ] \
       && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]
    then
        online_docker_run_cargo_semantic \
            --env "RUSTDESK_RUST_VERSION=$RUST_VERSION" \
            --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY,target=/source,readonly,bind-recursive=disabled" \
            --mount "type=bind,source=$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz,target=/inputs/rust.tar.xz,readonly" \
            --mount "type=bind,source=$candidate,target=/vendor,readonly,bind-recursive=disabled" \
            --mount "type=bind,source=$staging/cargo-vendor-config.toml,target=/inputs/config.toml,readonly" \
            --workdir /source \
            "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
                umask 077
                mkdir /tmp/toolchain /tmp/rust /tmp/home /tmp/cargo-home /tmp/cargo-target
                tar -C /tmp/toolchain -xf /inputs/rust.tar.xz
                installer="/tmp/toolchain/rust-${RUSTDESK_RUST_VERSION}.0-x86_64-unknown-linux-gnu/install.sh"
                "$installer" --prefix=/tmp/rust --disable-ldconfig \
                    --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu >/dev/null
                /usr/bin/python3 -I -S -c "import sys; from pathlib import Path; source = Path(\"/inputs/config.toml\").read_bytes(); lines = source.splitlines(keepends=True); matches = [index for index, line in enumerate(lines) if line.startswith(b\"directory = \")]; len(matches) == 1 or sys.exit(\"Cargo vendor directory authority is ambiguous\"); lines[matches[0]] = b\"directory = \\\"/vendor\\\"\\n\"; Path(\"/tmp/cargo-home/config.toml\").write_bytes(b\"\".join(lines))"
                chmod 0400 /tmp/cargo-home/config.toml
                export HOME=/tmp/home
                export CARGO_HOME=/tmp/cargo-home
                export CARGO_TARGET_DIR=/tmp/cargo-target
                export CARGO_NET_OFFLINE=true CARGO_NET_RETRY=0
                export CARGO_NET_GIT_FETCH_WITH_CLI=false
                export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
                export GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0
                export PATH=/tmp/rust/bin:/usr/bin:/bin
                cargo fetch --offline --locked --manifest-path /source/Cargo.toml
            ' || semantic_status=$?
    fi
    verify_sha256 \
        "$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
        || input_status=$?
    verify_cargo_vendor_source_unchanged || source_status=$?
    if [ "$producer_status" -eq 0 ] && [ "$source_status" -eq 0 ] \
       && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ] \
       && [ "$semantic_status" -eq 0 ]
    then
        cargo_vendor_output_tool authorize \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${output_args[@]}" \
            || output_status=$?
    fi
    if [ "$producer_status" -eq 0 ] && [ "$source_status" -eq 0 ] \
       && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ] \
       && [ "$semantic_status" -eq 0 ]
    then
        cargo_vendor_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_cargo_vendor_output_staging "$staging" "$staging_id"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Cargo vendor transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "Cargo vendor source authority changed"
    [ "$input_status" -eq 0 ] || die "Cargo vendor pinned input changed"
    [ "$output_status" -eq 0 ] || die "Cargo vendor output verification failed"
    [ "$producer_status" -eq 0 ] || die "Cargo vendor producer failed"
    [ "$semantic_status" -eq 0 ] || die "Cargo vendor offline resolution failed"
    [ "$publication_status" -eq 0 ] || die "Cargo vendor publication failed"
    log "Cargo vendor closure resolved, sealed, and no-clobber published"
}

# ── Fixed archive transactions ────────────────────────────────────────────────
# Remote bytes receive one private output transaction, not the online root or a
# final name. The host independently checks every exact length/digest before a
# descriptor-relative no-clobber publication. The admitted manifests are the
# fourteen toolchain/installer archives, the exact seven-archive Android build
# projection, the two Dart-audit rebuild inputs, the vcpkg/Xvfb full-peer
# projection, six signed WiX packages, 33 vcpkg source/tool distfiles, and the
# one dated Debian systemd image.
load_flutter_peer_fixed_archive_manifest() {
    local name size digest url extra host manifest_sha256 count=0
    local -a expected_names=(libfontenc1 libxfont2 libxkbfile1 x11-xkb-utils xvfb)
    [ "${#FLUTTER_PEER_FIXED_ARCHIVE_ARGS[@]}" -eq 0 ] \
        || die "Flutter-peer fixed-archive manifest was loaded more than once"
    [ -f "$FLUTTER_PEER_PACKAGE_MANIFEST" ] \
        && [ ! -L "$FLUTTER_PEER_PACKAGE_MANIFEST" ] \
        || die "Flutter-peer package manifest is not one real file"
    manifest_sha256="$(/usr/bin/sha256sum "$FLUTTER_PEER_PACKAGE_MANIFEST" \
        | /usr/bin/awk '{print $1}')"
    FLUTTER_PEER_FIXED_ARCHIVE_ARGS=(
        --entry
        "vcpkg-${VCPKG_BASELINE}.tar.gz"
        "https://github.com/microsoft/vcpkg/archive/${VCPKG_BASELINE}.tar.gz"
        "$SIZE_VCPKG_120DEAC3"
        "$SHA256_VCPKG_120DEAC3"
        "github.com,codeload.github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
    )
    while IFS=$'\t' read -r name size digest url extra || [ -n "${name:-}" ]; do
        [ -n "${name:-}" ] || continue
        [[ "$name" == \#* ]] && continue
        [ -z "${extra:-}" ] \
            || die "Flutter-peer package manifest has an extra field: $name"
        [ "$count" -lt "${#expected_names[@]}" ] \
            && [ "$name" = "${expected_names[$count]}" ] \
            || die "Flutter-peer package manifest name/order differs: $name"
        [[ "$size" =~ ^[1-9][0-9]*$ ]] \
            && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
            || die "Flutter-peer package size or digest is malformed: $name"
        case "$url" in
            https://deb.debian.org/debian/pool/*.deb) host=deb.debian.org ;;
            https://security.debian.org/debian-security/pool/*.deb) host=security.debian.org ;;
            *) die "Flutter-peer package URL is outside the exact Debian HTTPS pools: $name" ;;
        esac
        FLUTTER_PEER_FIXED_ARCHIVE_ARGS+=(
            --entry "xvfb-debs/$name.deb" "$url" "$size" "$digest" "$host"
        )
        count=$((count + 1))
    done <"$FLUTTER_PEER_PACKAGE_MANIFEST"
    [ "$count" -eq "${#expected_names[@]}" ] \
        || die "Flutter-peer package manifest must contain exactly five packages"
    [ "$(/usr/bin/sha256sum "$FLUTTER_PEER_PACKAGE_MANIFEST" \
        | /usr/bin/awk '{print $1}')" = "$manifest_sha256" ] \
        || die "Flutter-peer package manifest changed while loading"
    readonly -a FLUTTER_PEER_FIXED_ARCHIVE_ARGS
}

load_vcpkg_fixed_archive_manifest() {
    local name size digest url hosts extra tool_name tool_hash tool_extra count=0
    local manifest_sha256
    declare -A acquisition_tools=()
    [ "${#VCPKG_FIXED_ARCHIVE_ARGS[@]}" -eq 0 ] \
        || die "vcpkg fixed-archive manifest was loaded more than once"
    [ -f "$VCPKG_FIXED_ARCHIVE_MANIFEST" ] && [ ! -L "$VCPKG_FIXED_ARCHIVE_MANIFEST" ] \
        || die "vcpkg fixed-archive acquisition manifest is not one real file"
    [ "$(/usr/bin/sha256sum "$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512" \
         | /usr/bin/awk '{print $1}')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST" ] \
        || die "libvpx Windows tool manifest differs from its pin"
    manifest_sha256="$(/usr/bin/sha256sum "$VCPKG_FIXED_ARCHIVE_MANIFEST" | /usr/bin/awk '{print $1}')"
    [ "$manifest_sha256" = "$SHA256_VCPKG_FIXED_ARCHIVE_ACQUISITION" ] \
        || die "vcpkg fixed-archive acquisition manifest differs from its pin"
    while IFS='|' read -r name size digest url hosts extra; do
        [ -n "$name" ] && [ -n "$size" ] && [ -n "$digest" ] \
            && [ -n "$url" ] && [ -n "$hosts" ] && [ -z "$extra" ] \
            || die "vcpkg fixed-archive acquisition manifest has a malformed record"
        case "$name" in
            "vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz")
                ;;
            vcpkg-distfiles/windows-tools/*)
                tool_name="${name#vcpkg-distfiles/windows-tools/}"
                [ -n "$tool_name" ] && [ -z "${acquisition_tools[$tool_name]+x}" ] \
                    || die "vcpkg fixed-archive manifest has a duplicate tool name"
                acquisition_tools["$tool_name"]=1
                ;;
            *)
                die "vcpkg fixed-archive manifest has an unexpected destination: $name"
                ;;
        esac
        VCPKG_FIXED_ARCHIVE_ARGS+=(--entry "$name" "$url" "$size" "$digest" "$hosts")
        count=$((count + 1))
    done <"$VCPKG_FIXED_ARCHIVE_MANIFEST"
    [ "$count" -eq 33 ] \
        || die "vcpkg fixed-archive acquisition manifest must contain exactly 33 records"
    while read -r tool_hash tool_name tool_extra; do
        [ -n "$tool_hash" ] && [ -n "$tool_name" ] && [ -z "$tool_extra" ] \
            || die "libvpx Windows tool manifest has a malformed record"
        case "$tool_hash" in
            *[!0-9a-f]*|'') die "libvpx Windows tool manifest has a malformed SHA-512" ;;
        esac
        [ "${#tool_hash}" -eq 128 ] \
            || die "libvpx Windows tool manifest has a malformed SHA-512 length"
        [ -n "${acquisition_tools[$tool_name]+x}" ] \
            || die "vcpkg fixed-archive manifest omits Windows tool: $tool_name"
        unset 'acquisition_tools[$tool_name]'
    done <"$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512"
    [ "${#acquisition_tools[@]}" -eq 0 ] \
        || die "vcpkg fixed-archive manifest adds a noncanonical Windows tool"
    [ "$(/usr/bin/sha256sum "$VCPKG_FIXED_ARCHIVE_MANIFEST" | /usr/bin/awk '{print $1}')" \
       = "$manifest_sha256" ] \
        || die "vcpkg fixed-archive acquisition manifest changed while loading"
    readonly -a VCPKG_FIXED_ARCHIVE_ARGS
}

archive_bundle_tool() {
    local kind="$1" root="$2" command="$3" staging="$4" helper_sha256="$5" builder="$6"
    local -a archive_args=()
    shift 6
    case "$kind" in
        android-build) archive_args=("${ANDROID_BUILD_FIXED_ARCHIVE_ARGS[@]}") ;;
        dart-audit) archive_args=("${DART_AUDIT_FIXED_INPUT_ARGS[@]}") ;;
        flutter-peer) archive_args=("${FLUTTER_PEER_FIXED_ARCHIVE_ARGS[@]}") ;;
        flutter-test) archive_args=("${FLUTTER_TEST_FIXED_ARCHIVE_ARGS[@]}") ;;
        rust-test) archive_args=("${RUST_TEST_FIXED_ARCHIVE_ARGS[@]}") ;;
        systemd) archive_args=("${SYSTEMD_SMOKE_IMAGE_ARGS[@]}") ;;
        toolchain) archive_args=("${FIXED_ARCHIVE_ARGS[@]}") ;;
        vcpkg) archive_args=("${VCPKG_FIXED_ARCHIVE_ARGS[@]}") ;;
        wix) archive_args=("${WIX_NUGET_FIXED_ARCHIVE_ARGS[@]}") ;;
        *) die "unknown fixed-archive bundle kind: $kind" ;;
    esac
    /usr/bin/python3 -I -S "$FIXED_ARCHIVE_HELPER" "$command" \
        --online "$root" --staging "$staging" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        --builder-id "$builder" --helper-sha256 "$helper_sha256" \
        "${archive_args[@]}" "$@"
}

retire_archive_bundle_staging() {
    local staging="$1" expected_identity="$2"
    /usr/bin/python3 "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$expected_identity"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "fixed-archive transaction staging remains after retirement"
}

reconcile_archive_bundle_transactions() {
    local kind="$1" root="$2" prefix="$3" helper_sha256="$4" builder="$5"
    local staging staging_identity restore_nullglob=0
    local -a transactions=()
    if ! shopt -q nullglob; then
        shopt -s nullglob
        restore_nullglob=1
    fi
    transactions=("$root"/"$prefix".*)
    [ "$restore_nullglob" -eq 0 ] || shopt -u nullglob
    for staging in "${transactions[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "fixed-archive transaction path is not one real directory: $staging"
        staging_identity="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        if [ -e "$staging/state.json" ] || [ -L "$staging/state.json" ]; then
            archive_bundle_tool "$kind" "$root" reconcile "$staging" "$helper_sha256" "$builder"
        fi
        retire_archive_bundle_staging "$staging" "$staging_identity"
    done
}

stage_archive_bundle() {
    local kind="$1" root="$2" prefix="$3" label="$4"
    local builder="${5:-$ANDROID_BUILDER_CONFIG_ID}"
    local builder_role="${6:-android-builder}"
    local lock_fd helper_sha256 staging staging_identity action
    local producer_status=0 verification_status=0 publication_status=0
    verify_or_load_online_fetch_builder_image "$builder_role" "$builder"
    require_online_fetch_builder_image "$builder_role" "$builder"
    [ -f "$FIXED_ARCHIVE_HELPER" ] && [ ! -L "$FIXED_ARCHIVE_HELPER" ] \
        || die "fixed-archive helper is not one real source file"
    helper_sha256="$(/usr/bin/sha256sum "$FIXED_ARCHIVE_HELPER" | /usr/bin/awk '{print $1}')"
    exec {lock_fd}<"$root" \
        || die "cannot open the publication root for fixed-archive transaction locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another fixed-archive transaction owns the publication root"
    reconcile_archive_bundle_transactions "$kind" "$root" "$prefix" "$helper_sha256" "$builder"
    staging="$(umask 077 && /usr/bin/mktemp -d "$root/$prefix.XXXXXXXXXX")" \
        || die "cannot create private fixed-archive transaction staging"
    staging_identity="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    action="$(archive_bundle_tool "$kind" "$root" prepare "$staging" "$helper_sha256" "$builder")" \
        || die "cannot prepare fixed-archive transaction"
    case "$action" in
        complete)
            archive_bundle_tool "$kind" "$root" reconcile "$staging" "$helper_sha256" "$builder" \
                || die "cannot reconcile complete fixed-archive transaction"
            retire_archive_bundle_staging "$staging" "$staging_identity"
            "$FLOCK_BIN" --unlock "$lock_fd" \
                || die "cannot release the fixed-archive transaction lock"
            exec {lock_fd}<&-
            log "all $label are present and exact"
            return 0
            ;;
        acquire) ;;
        *) die "fixed-archive transaction returned an unknown action: $action" ;;
    esac
    log "acquiring missing $label through the private transaction"
    if [ "$kind" = rust-test ]; then
        online_docker_run_archive_acquisition \
            --env "RUSTDESK_RUST_TEST_SIZE=$SIZE_RUST_1_75" \
            --env "RUSTDESK_RUST_TEST_SHA256=$SHA256_RUST_1_75" \
            --env "RUSTDESK_RUST_TEST_VERSION=$RUST_VERSION" \
            --mount "type=bind,source=$staging/output,target=/outputs" \
            "$(online_fetch_builder_runtime_ref "$builder")" \
            /bin/bash --noprofile --norc -euo pipefail -c '
                umask 077
                output="/outputs/rust-${RUSTDESK_RUST_TEST_VERSION}.tar.xz"
                /usr/bin/curl --disable --proto "=https" --proto-redir "=https" \
                    --tlsv1.2 --fail --silent --show-error --location --max-redirs 0 \
                    --max-time 300 --speed-time 60 --speed-limit 1024 \
                    --max-filesize "$RUSTDESK_RUST_TEST_SIZE" --output "$output" \
                    "https://static.rust-lang.org/dist/rust-${RUSTDESK_RUST_TEST_VERSION}.0-x86_64-unknown-linux-gnu.tar.xz"
                [ "$(/usr/bin/stat -c %s -- "$output")" = "$RUSTDESK_RUST_TEST_SIZE" ]
                printf "%s  %s\n" "$RUSTDESK_RUST_TEST_SHA256" "$output" \
                    | /usr/bin/sha256sum -c -
                /bin/chmod 0400 "$output"
            ' || producer_status=$?
    else
        online_docker_run_archive_acquisition \
            --mount "type=bind,source=$FIXED_ARCHIVE_HELPER,target=/online-fixed-archive-output.py,readonly" \
            --mount "type=bind,source=$staging/state.json,target=/state.json,readonly" \
            --mount "type=bind,source=$staging/output,target=/outputs" \
            "$(online_fetch_builder_runtime_ref "$builder")" \
            /usr/bin/python3 -I -S /online-fixed-archive-output.py acquire \
                --state /state.json --output /outputs \
                --builder-id "$builder" --helper-sha256 "$helper_sha256" \
            || producer_status=$?
    fi
    if [ "$producer_status" -eq 0 ]; then
        archive_bundle_tool "$kind" "$root" verify "$staging" "$helper_sha256" "$builder" \
            || verification_status=$?
    fi
    if [ "$producer_status" -eq 0 ] && [ "$verification_status" -eq 0 ]; then
        archive_bundle_tool "$kind" "$root" publish "$staging" "$helper_sha256" "$builder" \
            || publication_status=$?
    fi
    archive_bundle_tool "$kind" "$root" reconcile "$staging" "$helper_sha256" "$builder" \
        || die "fixed-archive transaction is incoherent and was preserved at $staging"
    retire_archive_bundle_staging "$staging" "$staging_identity"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the fixed-archive transaction lock"
    exec {lock_fd}<&-
    [ "$producer_status" -eq 0 ] || die "fixed-archive acquisition failed"
    [ "$verification_status" -eq 0 ] || die "fixed-archive host verification failed"
    [ "$publication_status" -eq 0 ] || die "fixed-archive publication failed"
    log "$label acquired, verified, and no-clobber published"
}

stage_fixed_archives() {
    stage_archive_bundle toolchain "$ONLINE_DIR" .rustdesk-fixed-archives \
        "fixed toolchain and installer archives"
}

stage_rust_test_inputs() {
    verify_or_load_deb_builder_image
    stage_archive_bundle rust-test "$ONLINE_DIR" .rustdesk-rust-test-archive \
        "pinned Rust test toolchain archive" "$DEB_BUILDER_CONFIG_ID" deb-builder
    vendor_cargo
}

stage_flutter_test_inputs() {
    verify_or_load_android_builder_image
    stage_archive_bundle flutter-test "$ONLINE_DIR" .rustdesk-flutter-test-archive \
        "pinned Flutter test toolchain archive" "$ANDROID_BUILDER_CONFIG_ID" android-builder
    verify_or_load_deb_builder_image
    vendor_cargo
    build_frb_codegen reproduce
    stage_pub_cache
}

stage_flutter_peer_inputs() {
    load_flutter_peer_fixed_archive_manifest
    stage_archive_bundle flutter-peer "$ONLINE_DIR" \
        .rustdesk-flutter-peer-archives \
        "pinned Linux full-peer vcpkg/Xvfb inputs" \
        "$ANDROID_BUILDER_CONFIG_ID" android-builder
    verify_or_load_deb_builder_image
    stage_vcpkg_distfiles
    stage_vcpkg_natives
    log "Linux full-peer acquisition inputs are exact and no-clobber published"
}

stage_android_build_inputs() {
    verify_or_load_android_builder_image
    stage_archive_bundle android-build "$ONLINE_DIR" \
        .rustdesk-android-build-archives \
        "pinned Android build toolchain archives" \
        "$ANDROID_BUILDER_CONFIG_ID" android-builder
    verify_or_load_deb_builder_image
    vendor_cargo
    build_frb_codegen reproduce
    stage_pub_cache
    stage_vcpkg_distfiles
    stage_android_ndk
    stage_vcpkg_natives_arm64
    stage_cargo_ndk
    stage_android_sdk
    stage_gradle
    log "canonical Android producer outputs are acquired and individually checked; no-NIC workload transport remains separate"
}

validate_dart_audit_inputs() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    require_online_fetch_builder_image android-builder "$builder"
    online_docker_run_offline \
        --mount "type=bind,source=$SCRIPT_DIR/dart-audit-image-input.py,target=/authority/dart-audit-image-input.py,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ONLINE_DIR/dart-audit-inputs/osv-scanner,target=/inputs/osv-scanner,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ONLINE_DIR/dart-audit-inputs/Pub-all.zip,target=/inputs/Pub-all.zip,readonly,bind-recursive=disabled" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S /authority/dart-audit-image-input.py \
        --scanner /inputs/osv-scanner \
        --scanner-size "$OSV_SCANNER_SIZE" \
        --scanner-sha256 "$OSV_SCANNER_SHA256" \
        --database /inputs/Pub-all.zip \
        --database-size "$OSV_DB_PUB_SIZE" \
        --database-sha256 "$OSV_DB_PUB_SHA256" \
        --database-md5 "$OSV_DB_PUB_MD5_BASE64" \
        --database-crc32c "$OSV_DB_PUB_CRC32C_BASE64" \
        --database-records "$OSV_DB_PUB_RECORDS" \
        --database-uncompressed-bytes "$OSV_DB_PUB_UNCOMPRESSED_BYTES"
}

stage_dart_audit_inputs() {
    stage_archive_bundle dart-audit "$ONLINE_DIR" .rustdesk-dart-audit-inputs \
        "fixed Dart advisory image inputs"
    validate_dart_audit_inputs \
        || die "Dart advisory image inputs failed their independent structural validation"
}

maintenance_discover_osv_pub_database() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local validator="$SCRIPT_DIR/dart-audit-image-input.py"
    local validator_sha256
    verify_or_load_online_fetch_builder_image android-builder "$builder"
    require_online_fetch_builder_image android-builder "$builder"
    for source in "$OSV_PUB_DISCOVERY_HELPER" "$validator"; do
        [ -f "$source" ] && [ ! -L "$source" ] \
            || die "OSV Pub discovery source is absent or ambiguous: $source"
    done
    validator_sha256="$(/usr/bin/sha256sum "$validator" | /usr/bin/awk '{print $1}')"
    online_docker_run_offline \
        --mount "type=bind,source=$validator,target=/authority/dart-audit-image-input.py,readonly,bind-recursive=disabled" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S /authority/dart-audit-image-input.py --self-test
    online_docker_run_offline \
        --mount "type=bind,source=$OSV_PUB_DISCOVERY_HELPER,target=/authority/discover-osv-pub-database.py,readonly,bind-recursive=disabled" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S /authority/discover-osv-pub-database.py --self-test
    online_docker_run_archive_acquisition \
        --mount "type=bind,source=$OSV_PUB_DISCOVERY_HELPER,target=/authority/discover-osv-pub-database.py,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$validator,target=/authority/dart-audit-image-input.py,readonly,bind-recursive=disabled" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S /authority/discover-osv-pub-database.py \
            --validator /authority/dart-audit-image-input.py \
            --validator-sha256 "$validator_sha256"
}

stage_vcpkg_fixed_archives() {
    load_vcpkg_fixed_archive_manifest
    stage_archive_bundle vcpkg "$ONLINE_DIR" .rustdesk-vcpkg-fixed-archives \
        "fixed libvpx source and Windows tool archives"
}

require_windows_operator_toolchain() {
    if [ -f "$ONLINE_DIR/win/rustup-init.exe" ] && [ ! -L "$ONLINE_DIR/win/rustup-init.exe" ]; then
        verify_sha256 "$ONLINE_DIR/win/rustup-init.exe" "${SHA256_RUSTUP_INIT_WIN}"
    else
        die "online/win/rustup-init.exe missing — it is operator-captured because the upstream 'latest' URL drifts. Stage and deliberately re-pin it outside this fixed-archive transaction before provisioning Windows"
    fi
}

require_image_pin() {
    local name="$1" value="${!1:-}"
    [ -n "$value" ] || die "pins.env is missing $name"
    [ "$value" != "$SHA_PENDING" ] || die "$name is not established"
}

deb_builder_certification_candidate_spec_args() {
    printf '%s\0' \
        --role deb-builder \
        --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
        --bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN"
}

deb_builder_certification_spec_args() {
    deb_builder_certification_candidate_spec_args
    printf '%s\0' \
        --config-id "$DEB_BUILDER_CONFIG_ID" \
        --manifest-id "$DEB_BUILDER_MANIFEST_ID"
}

deb_builder_image_spec_args() {
    printf '%s\0' --expected-id "$DEB_BUILDER_IMAGE_ID"
    deb_builder_certification_spec_args
}

deb_builder_bootstrap_spec_args() {
    printf '%s\0' \
        --role deb-builder-bootstrap \
        --expected-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --dockerfile-sha "$SHA256_DEB_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST" \
        --config-id "$DEB_BUILDER_BOOTSTRAP_CONFIG_ID" \
        --manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID"
}

require_deb_builder_bootstrap_pins() {
    local names=(
        SHA256_BASEIMAGE_UBUNTU_1804
        SHA256_DEB_BUILDER_DOCKERFILE
        SHA256_DEB_BUILDER_DPKG_MANIFEST
        DEB_BUILDER_BOOTSTRAP_IMAGE_ID
        DEB_BUILDER_BOOTSTRAP_CONFIG_ID
        DEB_BUILDER_BOOTSTRAP_MANIFEST_ID
        DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

require_deb_builder_certification_input_pins() {
    require_deb_builder_bootstrap_pins
    require_image_pin SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE
    require_image_pin SOURCE_DATE_EPOCH_PIN
}

require_deb_builder_image_pins() {
    local names=(
        DEB_BUILDER_IMAGE_ID
        DEB_BUILDER_CONFIG_ID
        DEB_BUILDER_MANIFEST_ID
        DEB_BUILDER_IMAGE_ARCHIVE_SIZE
        SHA256_DEB_BUILDER_IMAGE_ARCHIVE
        SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE
        SHA256_DEB_BUILDER_DOCKERFILE
        SHA256_DEB_BUILDER_DPKG_MANIFEST
        DEB_BUILDER_BOOTSTRAP_IMAGE_ID
        DEB_BUILDER_BOOTSTRAP_CONFIG_ID
        DEB_BUILDER_BOOTSTRAP_MANIFEST_ID
        DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT
        SOURCE_DATE_EPOCH_PIN
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

android_builder_certification_candidate_spec_args() {
    printf '%s\0' \
        --role android-builder \
        --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
        --bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN"
}

android_builder_certification_spec_args() {
    android_builder_certification_candidate_spec_args
    printf '%s\0' \
        --config-id "$ANDROID_BUILDER_CONFIG_ID" \
        --manifest-id "$ANDROID_BUILDER_MANIFEST_ID"
}

android_builder_image_spec_args() {
    printf '%s\0' --expected-id "$ANDROID_BUILDER_IMAGE_ID"
    android_builder_certification_spec_args
}

android_builder_bootstrap_spec_args() {
    printf '%s\0' \
        --role android-builder-bootstrap \
        --expected-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID" \
        --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" \
        --config-id "$ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID" \
        --manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"
}

require_android_builder_bootstrap_pins() {
    local names=(
        SHA256_BASEIMAGE_UBUNTU_2404
        SHA256_ANDROID_BUILDER_DOCKERFILE
        SHA256_ANDROID_BUILDER_DPKG_MANIFEST
        ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID
        ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID
        ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID
        ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

require_android_builder_certification_input_pins() {
    require_android_builder_bootstrap_pins
    require_image_pin SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE
    require_image_pin SOURCE_DATE_EPOCH_PIN
}

require_android_builder_image_pins() {
    local names=(
        ANDROID_BUILDER_IMAGE_ID
        ANDROID_BUILDER_CONFIG_ID
        ANDROID_BUILDER_MANIFEST_ID
        ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE
        SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE
        SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE
        SHA256_ANDROID_BUILDER_DOCKERFILE
        SHA256_ANDROID_BUILDER_DPKG_MANIFEST
        ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID
        ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID
        ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID
        ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT
        SOURCE_DATE_EPOCH_PIN
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

win_helper_certification_candidate_spec_args() {
    printf '%s\0' \
        --role win-helper \
        --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE" \
        --recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE" \
        --dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST" \
        --bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID" \
        --bootstrap-manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID" \
        --source-date-epoch "$SOURCE_DATE_EPOCH_PIN"
}

win_helper_certification_spec_args() {
    win_helper_certification_candidate_spec_args
    printf '%s\0' \
        --config-id "$WIN_HELPER_CONFIG_ID" \
        --manifest-id "$WIN_HELPER_MANIFEST_ID"
}

win_helper_image_spec_args() {
    printf '%s\0' --expected-id "$WIN_HELPER_IMAGE_ID"
    win_helper_certification_spec_args
}

win_helper_bootstrap_spec_args() {
    printf '%s\0' \
        --role win-helper-bootstrap \
        --expected-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID" \
        --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE" \
        --dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST" \
        --config-id "$WIN_HELPER_BOOTSTRAP_CONFIG_ID" \
        --manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"
}

require_win_helper_bootstrap_pins() {
    local names=(
        SHA256_BASEIMAGE_UBUNTU_2404
        SHA256_WIN_HELPER_DOCKERFILE
        SHA256_WIN_HELPER_DPKG_MANIFEST
        WIN_HELPER_BOOTSTRAP_IMAGE_ID
        WIN_HELPER_BOOTSTRAP_CONFIG_ID
        WIN_HELPER_BOOTSTRAP_MANIFEST_ID
        WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

require_win_helper_certification_input_pins() {
    require_win_helper_bootstrap_pins
    require_image_pin SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE
    require_image_pin SOURCE_DATE_EPOCH_PIN
}

require_win_helper_image_pins() {
    local names=(
        WIN_HELPER_IMAGE_ID
        WIN_HELPER_CONFIG_ID
        WIN_HELPER_MANIFEST_ID
        WIN_HELPER_IMAGE_ARCHIVE_SIZE
        SHA256_WIN_HELPER_IMAGE_ARCHIVE
        SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE
        SHA256_WIN_HELPER_DOCKERFILE
        SHA256_WIN_HELPER_DPKG_MANIFEST
        WIN_HELPER_BOOTSTRAP_IMAGE_ID
        WIN_HELPER_BOOTSTRAP_CONFIG_ID
        WIN_HELPER_BOOTSTRAP_MANIFEST_ID
        WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE
        SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE
        SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT
        SOURCE_DATE_EPOCH_PIN
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

verify_or_load_deb_builder_image() {
    require_deb_builder_image_pins
    local args=()
    mapfile -d '' args < <(deb_builder_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/build-images/deb-builder.docker.tar.gz" \
        --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}"
    online_image_provenance verify-local \
        --publication-index-runtime \
        --image-ref "$DEB_BUILDER_IMAGE_ID" \
        "${args[@]}"
}

verify_or_load_android_builder_image() {
    require_android_builder_image_pins
    local args=()
    mapfile -d '' args < <(android_builder_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/build-images/android-builder.docker.tar.gz" \
        --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}"
    online_image_provenance verify-local \
        --publication-index-runtime \
        --image-ref "$ANDROID_BUILDER_IMAGE_ID" \
        "${args[@]}"
}

verify_or_load_win_helper_image() {
    require_win_helper_image_pins
    local args=()
    mapfile -d '' args < <(win_helper_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/build-images/win-helper.docker.tar.gz" \
        --archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \
        --archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}"
    online_image_provenance verify-local \
        --publication-index-runtime \
        --image-ref "$WIN_HELPER_IMAGE_ID" \
        "${args[@]}"
}

verify_or_load_online_fetch_builder_image() {
    [ "$#" -eq 2 ] \
        || die "online builder loading requires ROLE CONFIG_ID"
    case "$1:$2" in
        "deb-builder:$DEB_BUILDER_CONFIG_ID")
            verify_or_load_deb_builder_image
            ;;
        "android-builder:$ANDROID_BUILDER_CONFIG_ID")
            verify_or_load_android_builder_image
            ;;
        "win-helper:$WIN_HELPER_CONFIG_ID")
            verify_or_load_win_helper_image
            ;;
        *) die "online builder role/config pair is outside the closed certified set" ;;
    esac
}

load_builder_images() {
    verify_or_load_deb_builder_image
    verify_or_load_android_builder_image
    verify_or_load_win_helper_image
}

devcheck_image_spec_args() {
    printf '%s\0' \
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
}

require_devcheck_recipe_pins() {
    local names=(
        DEV_CHECK_BASE_IMAGE_ID DEV_CHECK_DEBIAN_SNAPSHOT
        DEV_CHECK_SECURITY_SNAPSHOT DEV_CHECK_SOURCE_DATE_EPOCH
        SHA256_DEV_CHECK_DOCKERFILE SHA256_DEV_CHECK_CARGO
        SHA256_DEV_CHECK_RUSTC
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.devcheck" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || die "current devcheck Dockerfile differs from its acquisition pin"
    [[ "$DEV_CHECK_DEBIAN_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
        && [[ "$DEV_CHECK_SECURITY_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
        || die "devcheck Debian snapshot timestamps are malformed"
    [[ "$DEV_CHECK_SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] \
        || die "devcheck source-date epoch is malformed"
}

require_devcheck_image_pins() {
    require_devcheck_recipe_pins
    local names=(
        DEV_CHECK_IMAGE_ID DEV_CHECK_IMAGE_CONFIG_ID
        DEV_CHECK_IMAGE_MANIFEST_ID SHA256_DEV_CHECK_DPKG_MANIFEST
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

devcheck_candidate_spec_args() {
    [ "$#" -eq 1 ] || die "internal devcheck candidate specification error"
    printf '%s\0' \
        --role devcheck-candidate \
        --expected-id "$1" \
        --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
        --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
        --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
        --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
        --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
        --debian-snapshot "$DEV_CHECK_DEBIAN_SNAPSHOT" \
        --security-snapshot "$DEV_CHECK_SECURITY_SNAPSHOT" \
        --source-date-epoch "$DEV_CHECK_SOURCE_DATE_EPOCH"
}

verify_or_load_devcheck_image() {
    require_devcheck_image_pins
    require_image_pin SHA256_DEV_CHECK_IMAGE_ARCHIVE
    require_image_pin SIZE_DEV_CHECK_IMAGE_ARCHIVE
    case "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_DEV_CHECK_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local args=()
    mapfile -d '' args < <(devcheck_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz" \
        --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
        "${args[@]}"
}

prepare_devcheck_build_context() {
    [ "$#" -eq 1 ] || die "internal devcheck context preparation error"
    local context="$1"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private devcheck build context already exists"
    /usr/bin/install -d -m 0700 "$context"
    /usr/bin/install -m 0400 "$SCRIPT_DIR/Dockerfile.devcheck" "$context/Dockerfile"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$context/Dockerfile")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private devcheck build context metadata differs"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f \
        | /usr/bin/wc -l)" -eq 1 ] \
        && [ -f "$context/Dockerfile" ] && [ ! -L "$context/Dockerfile" ] \
        && [ -z "$({ /usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
            ! -type f -print -quit; })" ] \
        || die "private devcheck build context inventory differs"
}

build_devcheck_image() {
    [ "$#" -eq 3 ] || die "internal devcheck build error"
    local context="$1" tag="$2" dpkg_sha="$3"
    online_buildx_build \
        --network=default --pull=false --no-cache \
        --platform=linux/amd64 --provenance=mode=max \
        --output=type=docker,rewrite-timestamp=true \
        --build-arg "BASE_IMAGE_REF=rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
        --build-arg "DEV_CHECK_DEBIAN_SNAPSHOT=${DEV_CHECK_DEBIAN_SNAPSHOT}" \
        --build-arg "DEV_CHECK_SECURITY_SNAPSHOT=${DEV_CHECK_SECURITY_SNAPSHOT}" \
        --build-arg "DEV_CHECK_DOCKERFILE_SHA256=${SHA256_DEV_CHECK_DOCKERFILE}" \
        --build-arg "DEV_CHECK_DPKG_MANIFEST_SHA256=${dpkg_sha}" \
        --build-arg "SOURCE_DATE_EPOCH=${DEV_CHECK_SOURCE_DATE_EPOCH}" \
        --tag "$tag" --file "$context/Dockerfile" "$context"
}

maintenance_discover_devcheck_image() {
    require_devcheck_recipe_pins
    local context="$ONLINE_FETCH_TMP/devcheck-discovery-context"
    local tag="rd-devcheck-discovery:non-authoritative"
    local image_id result
    prepare_devcheck_build_context "$context"
    build_devcheck_image "$context" "$tag" \
        0000000000000000000000000000000000000000000000000000000000000000
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the devcheck discovery image"
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "devcheck discovery image identity is malformed"
    result="$(
        online_docker run --rm --pull=never --network=none --read-only \
            --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \
            --cap-drop=ALL --security-opt=no-new-privileges \
            --pids-limit=32 --memory=256m --memory-swap=256m --cpus=1 \
            "$tag" /bin/bash --noprofile --norc -euo pipefail -c \
            'sha256sum /usr/local/share/rustdesk-devcheck-provenance/dpkg-manifest.tsv | cut -d " " -f 1'
    )" || die "cannot derive the devcheck package-manifest identity"
    [[ "$result" =~ ^[0-9a-f]{64}$ ]] \
        || die "derived devcheck package-manifest identity is malformed"
    printf 'SHA256_DEV_CHECK_DPKG_MANIFEST="%s"\n' "$result"
    printf 'discovery_image_id=%s\n' "$image_id"
}

capture_devcheck_rebuild() {
    [ "$#" -eq 2 ] || die "internal devcheck rebuild capture error"
    local output="$1" expected_id="$2"
    local args=()
    mapfile -d '' args < <(devcheck_candidate_spec_args "$expected_id")
    online_image_provenance maintenance-capture \
        --output "$output" "${args[@]}"
}

image_capture_field() {
    [ "$#" -eq 2 ] || die "internal image capture parsing error"
    local result="$1" field="$2"
    [ "$({ /usr/bin/grep -c "^${field}=" <<<"$result"; })" -eq 1 ] \
        || die "image capture result has no unique ${field}"
    /usr/bin/sed -n "s/^${field}=//p" <<<"$result"
}

maintenance_build_devcheck_image_candidate() {
    require_devcheck_recipe_pins
    require_image_pin SHA256_DEV_CHECK_DPKG_MANIFEST
    local directory="$ONLINE_DIR/verifier-images"
    local context="$ONLINE_FETCH_TMP/devcheck-build-context"
    local first_archive="$ONLINE_FETCH_TMP/devcheck-rebuild-a.docker.tar.gz"
    local second_archive="$directory/.devcheck-candidate.docker.tar.gz.part"
    local candidate="$directory/devcheck-candidate.docker.tar.gz"
    local tag="rd-devcheck:authenticated-v2"
    local first_id second_id first_result second_result
    local first_manifest second_manifest first_config second_config
    local archive_sha archive_size lock_fd
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "devcheck image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the devcheck image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another devcheck image archive transaction owns the archive root"
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
        || die "devcheck candidate archive already exists"
    [ ! -e "$second_archive" ] && [ ! -L "$second_archive" ] \
        || die "stale devcheck candidate publication staging exists"
    prepare_devcheck_build_context "$context"

    build_devcheck_image "$context" "$tag" "$SHA256_DEV_CHECK_DPKG_MANIFEST"
    first_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the first devcheck rebuild"
    first_result="$(capture_devcheck_rebuild "$first_archive" "$first_id")" \
        || die "first devcheck rebuild capture failed"

    build_devcheck_image "$context" "$tag" "$SHA256_DEV_CHECK_DPKG_MANIFEST"
    second_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the second devcheck rebuild"
    second_result="$(capture_devcheck_rebuild "$second_archive" "$second_id")" \
        || die "second devcheck rebuild capture failed"

    first_manifest="$(image_capture_field "$first_result" manifest_id)"
    second_manifest="$(image_capture_field "$second_result" manifest_id)"
    first_config="$(image_capture_field "$first_result" config_id)"
    second_config="$(image_capture_field "$second_result" config_id)"
    [ "$first_manifest:$first_config" = "$second_manifest:$second_config" ] \
        || die "independent devcheck rebuilds produced different runtime identities"
    archive_sha="$(image_capture_field "$second_result" sha256)"
    archive_size="$(image_capture_field "$second_result" bytes)"
    online_image_provenance maintenance-rename-noreplace \
        --source "$second_archive" --destination "$candidate" \
        || die "devcheck candidate publication failed"
    /usr/bin/rm -f -- "$first_archive" \
        || die "cannot retire the first verified devcheck rebuild archive"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the devcheck image archive lock"
    exec {lock_fd}<&-
    printf 'DEV_CHECK_IMAGE_ID="%s"\n' "$second_id"
    printf 'DEV_CHECK_IMAGE_CONFIG_ID="%s"\n' "$second_config"
    printf 'DEV_CHECK_IMAGE_MANIFEST_ID="%s"\n' "$second_manifest"
    printf 'SHA256_DEV_CHECK_IMAGE_ARCHIVE="%s"\n' "$archive_sha"
    printf 'SIZE_DEV_CHECK_IMAGE_ARCHIVE="%s"\n' "$archive_size"
    printf 'reproducible_runtime=%s\n' "$second_manifest:$second_config"
    printf 'candidate=%s\n' "$candidate"
}

maintenance_promote_devcheck_image_candidate() {
    require_devcheck_image_pins
    require_image_pin SHA256_DEV_CHECK_IMAGE_ARCHIVE
    require_image_pin SIZE_DEV_CHECK_IMAGE_ARCHIVE
    local directory="$ONLINE_DIR/verifier-images"
    local candidate="$directory/devcheck-candidate.docker.tar.gz"
    local final="$directory/devcheck.docker.tar.gz"
    local lock_fd args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "devcheck image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the devcheck image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another devcheck image archive transaction owns the archive root"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] \
        || die "devcheck candidate archive is absent or unsafe"
    [ ! -e "$final" ] && [ ! -L "$final" ] \
        || die "final devcheck archive already exists"
    mapfile -d '' args < <(devcheck_image_spec_args)
    online_image_provenance verify-archive \
        --archive "$candidate" \
        --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
        "${args[@]}" \
        || die "devcheck candidate differs from the final pins"
    online_image_provenance maintenance-rename-noreplace \
        --source "$candidate" --destination "$final" \
        || die "devcheck candidate promotion failed"
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$final" \
        --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
        "${args[@]}" \
        || die "promoted devcheck archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the devcheck image archive lock"
    exec {lock_fd}<&-
    printf 'promoted=%s\n' "$final"
}

apple_check_image_spec_args() {
    printf '%s\0' \
        --role apple-check \
        --expected-id "$APPLE_CHECK_IMAGE_ID" \
        --base "rd-devcheck@${DEV_CHECK_IMAGE_ID}" \
        --base-manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID" \
        --dockerfile-sha "$SHA256_APPLE_CHECK_DOCKERFILE" \
        --source-date-epoch "$APPLE_CHECK_SOURCE_DATE_EPOCH" \
        --release-helper-sha "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER" \
        --provenance-helper-sha "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER" \
        --rust-version "$APPLE_RUST_RELEASE_VERSION" \
        --release-date "$APPLE_RUST_RELEASE_DATE" \
        --signing-fingerprint "$APPLE_RUST_RELEASE_SIGNING_FINGERPRINT" \
        --release-public-key-sha "$SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY" \
        --release-manifest-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST" \
        --release-manifest-signature-sha "$SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE" \
        --rustc-host-sha "$SHA256_APPLE_RUSTC_HOST_COMPONENT" \
        --cargo-host-sha "$SHA256_APPLE_CARGO_HOST_COMPONENT" \
        --rust-std-host-sha "$SHA256_APPLE_RUST_STD_HOST_COMPONENT" \
        --rust-std-aarch64-darwin-sha "$SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT" \
        --rust-std-x86-64-darwin-sha "$SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT" \
        --rust-std-aarch64-ios-sha "$SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT" \
        --cargo-sha "$SHA256_APPLE_CHECK_CARGO" \
        --rustc-sha "$SHA256_APPLE_CHECK_RUSTC" \
        --dpkg-sha "$SHA256_APPLE_CHECK_DPKG_MANIFEST" \
        --toolchain-tree-sha "$APPLE_TOOLCHAIN_TREE_SHA256" \
        --toolchain-files "$APPLE_TOOLCHAIN_FILES" \
        --toolchain-directories "$APPLE_TOOLCHAIN_DIRECTORIES" \
        --toolchain-content-bytes "$APPLE_TOOLCHAIN_CONTENT_BYTES" \
        --config-id "$APPLE_CHECK_IMAGE_CONFIG_ID" \
        --manifest-id "$APPLE_CHECK_IMAGE_MANIFEST_ID"
}

require_apple_check_image_pins() {
    local names=(
        APPLE_CHECK_IMAGE_ID APPLE_CHECK_IMAGE_CONFIG_ID
        APPLE_CHECK_IMAGE_MANIFEST_ID DEV_CHECK_IMAGE_ID
        DEV_CHECK_IMAGE_MANIFEST_ID SHA256_APPLE_CHECK_DOCKERFILE
        APPLE_CHECK_SOURCE_DATE_EPOCH
        SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER
        SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER
        APPLE_RUST_RELEASE_VERSION APPLE_RUST_RELEASE_DATE
        APPLE_RUST_RELEASE_SIGNING_FINGERPRINT
        SHA256_APPLE_RUST_RELEASE_PUBLIC_KEY
        SHA256_APPLE_RUST_RELEASE_MANIFEST
        SHA256_APPLE_RUST_RELEASE_MANIFEST_SIGNATURE
        SHA256_APPLE_RUSTC_HOST_COMPONENT
        SHA256_APPLE_CARGO_HOST_COMPONENT
        SHA256_APPLE_RUST_STD_HOST_COMPONENT
        SHA256_APPLE_RUST_STD_AARCH64_DARWIN_COMPONENT
        SHA256_APPLE_RUST_STD_X86_64_DARWIN_COMPONENT
        SHA256_APPLE_RUST_STD_AARCH64_IOS_COMPONENT
        SHA256_APPLE_CHECK_CARGO SHA256_APPLE_CHECK_RUSTC
        SHA256_APPLE_CHECK_DPKG_MANIFEST
        APPLE_TOOLCHAIN_TREE_SHA256 APPLE_TOOLCHAIN_FILES
        APPLE_TOOLCHAIN_DIRECTORIES APPLE_TOOLCHAIN_CONTENT_BYTES
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    for name in APPLE_TOOLCHAIN_FILES APPLE_TOOLCHAIN_DIRECTORIES \
        APPLE_TOOLCHAIN_CONTENT_BYTES; do
        case "${!name}" in
            0|*[!0-9]*|'') die "$name is not one positive decimal integer" ;;
        esac
    done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.apple-check" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_CHECK_DOCKERFILE" ] \
        || die "current Apple check Dockerfile differs from the archived image recipe"
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/apple-toolchain-release.py" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER" ] \
        || die "current Apple release helper differs from the archived image input"
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/apple-toolchain-provenance.py" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER" ] \
        || die "current Apple provenance helper differs from the archived image input"
}

verify_or_load_apple_check_image() {
    require_apple_check_image_pins
    require_image_pin SHA256_APPLE_CHECK_IMAGE_ARCHIVE
    require_image_pin SIZE_APPLE_CHECK_IMAGE_ARCHIVE
    case "$SIZE_APPLE_CHECK_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_APPLE_CHECK_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local args=()
    mapfile -d '' args < <(apple_check_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/verifier-images/apple-check.docker.tar.gz" \
        --archive-sha "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_APPLE_CHECK_IMAGE_ARCHIVE" \
        "${args[@]}"
}

maintenance_capture_apple_check_image() {
    require_apple_check_image_pins
    local directory="$ONLINE_DIR/verifier-images"
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || die "Apple check image archive root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
          = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
            || die "Apple check image archive root is not current-user-private mode 0700"
    else
        /usr/bin/install -d -m 0700 "$directory"
    fi
    local lock_fd
    exec {lock_fd}<"$directory" \
        || die "cannot open the Apple check image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Apple check image archive transaction owns the archive root"
    local args=() result
    mapfile -d '' args < <(apple_check_image_spec_args)
    result="$(
        online_image_provenance maintenance-capture \
            --publication-index-runtime \
            --output "$directory/apple-check.docker.tar.gz" \
            "${args[@]}"
    )" || die "Apple check image archive capture failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Apple check image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

dart_audit_contract_spec_args() {
    [ "$#" -eq 2 ] || die "internal Dart advisory specification error"
    local role="$1" expected_id="$2"
    printf '%s\0' \
        --role "$role" \
        --expected-id "$expected_id" \
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
        --database-generation "$OSV_DB_PUB_GENERATION"
}

dart_audit_image_spec_args() {
    dart_audit_contract_spec_args dart-audit "$DART_AUDIT_IMAGE_ID"
    printf '%s\0' \
        --config-id "$DART_AUDIT_IMAGE_CONFIG_ID" \
        --manifest-id "$DART_AUDIT_IMAGE_MANIFEST_ID"
}

dart_audit_candidate_spec_args() {
    [ "$#" -eq 1 ] || die "internal Dart advisory candidate specification error"
    dart_audit_contract_spec_args dart-audit-candidate "$1"
}

require_dart_audit_recipe_pins() {
    local names=(
        SHA256_BASEIMAGE_UBUNTU_1804 SHA256_DART_AUDIT_DOCKERFILE
        OSV_SCANNER_SHA256 OSV_SCANNER_VERSION OSV_SCALIBR_VERSION
        OSV_SCANNER_COMMIT OSV_SCANNER_BUILT_AT
        OSV_DB_PUB_SHA256 OSV_DB_PUB_SIZE OSV_DB_PUB_CAPTURE_EPOCH
        OSV_DB_PUB_GENERATION
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.dart-audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DART_AUDIT_DOCKERFILE" ] \
        || die "current Dart advisory Dockerfile differs from the archived image recipe"
    [[ "$OSV_DB_PUB_CAPTURE_EPOCH" =~ ^[1-9][0-9]*$ ]] \
        || die "Dart advisory source-date epoch is malformed"
}

require_dart_audit_image_pins() {
    require_dart_audit_recipe_pins
    local names=(
        DART_AUDIT_IMAGE_ID DART_AUDIT_IMAGE_CONFIG_ID
        DART_AUDIT_IMAGE_MANIFEST_ID
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
}

verify_or_load_dart_audit_image() {
    require_dart_audit_image_pins
    require_image_pin SHA256_DART_AUDIT_IMAGE_ARCHIVE
    require_image_pin SIZE_DART_AUDIT_IMAGE_ARCHIVE
    case "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_DART_AUDIT_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local args=()
    mapfile -d '' args < <(dart_audit_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/verifier-images/dart-audit.docker.tar.gz" \
        --archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}"
}

rust_audit_contract_spec_args() {
    [ "$#" -eq 2 ] || die "internal Rust advisory contract specification error"
    local role="$1" expected_id="$2"
    printf '%s\0' \
        --role "$role" \
        --expected-id "$expected_id" \
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
        --advisory-db-epoch "$ADVISORY_DB_COMMIT_EPOCH"
}

rust_audit_image_spec_args() {
    rust_audit_contract_spec_args rust-audit "$RUST_AUDIT_IMAGE_ID"
    printf '%s\0' \
        --config-id "$RUST_AUDIT_IMAGE_CONFIG_ID" \
        --manifest-id "$RUST_AUDIT_IMAGE_MANIFEST_ID"
}

rust_audit_candidate_spec_args() {
    [ "$#" -eq 1 ] || die "internal Rust advisory candidate specification error"
    rust_audit_contract_spec_args rust-audit-candidate "$1"
}

require_rust_audit_image_pins() {
    local names=(
        RUST_AUDIT_IMAGE_ID RUST_AUDIT_IMAGE_CONFIG_ID
        RUST_AUDIT_IMAGE_MANIFEST_ID RUST_AUDIT_BASE_IMAGE_DIGEST
        SHA256_RUST_AUDIT_DOCKERFILE
        RUST_AUDIT_RUST_VERSION RUST_AUDIT_RUSTC_VERSION
        CARGO_AUDIT_VERSION CARGO_DENY_VERSION
        CARGO_AUDIT_TAG_OBJECT CARGO_AUDIT_SOURCE_COMMIT
        CARGO_AUDIT_SOURCE_TREE SHA256_CARGO_AUDIT_SOURCE_ARCHIVE
        CARGO_AUDIT_SIGNING_KEY_FINGERPRINT
        CARGO_DENY_TAG_OBJECT CARGO_DENY_SOURCE_COMMIT
        CARGO_DENY_SOURCE_TREE SHA256_CARGO_DENY_SOURCE_ARCHIVE
        SHA256_RUST_AUDIT_CARGO_AUDIT SHA256_RUST_AUDIT_CARGO_DENY
        ADVISORY_DB_COMMIT ADVISORY_DB_COMMIT_EPOCH
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_RUST_AUDIT_DOCKERFILE" ] \
        || die "current Rust advisory Dockerfile differs from the archived image recipe"
}

verify_or_load_rust_audit_image() {
    require_rust_audit_image_pins
    require_image_pin SHA256_RUST_AUDIT_IMAGE_ARCHIVE
    require_image_pin SIZE_RUST_AUDIT_IMAGE_ARCHIVE
    case "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_RUST_AUDIT_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local args=()
    mapfile -d '' args < <(rust_audit_image_spec_args)
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$ONLINE_DIR/verifier-images/rust-audit.docker.tar.gz" \
        --archive-sha "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}"
}

# Networked bootstrap acquisition produces a private, non-authoritative
# candidate archive before its disposable Docker store disappears. Promotion
# to the exact bootstrap name is a separate pin-reviewed operation, and the
# promoted bootstrap still requires the networkless nonroot certification
# transaction before it can become release authority.
BUILT_BOOTSTRAP_IMAGE_ID=
BUILT_BOOTSTRAP_DPKG_SHA256=
BUILT_BOOTSTRAP_RECIPE_SHA256=

builder_bootstrap_candidate_spec_args() {
    [ "$#" -eq 5 ] || die "internal bootstrap candidate specification error"
    local role="$1" target_id="$2" base="$3" dockerfile_sha="$4" dpkg_sha="$5"
    printf '%s\0' \
        --role "${role}-bootstrap-candidate" \
        --expected-id "$target_id" \
        --base "$base" \
        --dockerfile-sha "$dockerfile_sha" \
        --dpkg-sha "$dpkg_sha"
}

capture_builder_bootstrap_candidate() {
    [ "$#" -eq 8 ] || die "internal bootstrap candidate capture error"
    local display="$1" prefix="$2" filename="$3" role="$4"
    local target_id="$5" base="$6" dockerfile_sha="$7" dpkg_sha="$8"
    local directory="$ONLINE_DIR/build-images"
    local output="$directory/$filename"
    local layout="$ONLINE_FETCH_TMP/${filename%.docker.tar.gz}.oci"
    local result archive_sha archive_size manifest_id config_id
    local layout_sha captured_image captured_path args=()
    [ ! -e "$output" ] && [ ! -L "$output" ] \
        || die "$display bootstrap candidate archive already exists"
    [ ! -e "$layout" ] && [ ! -L "$layout" ] \
        || die "$display bootstrap candidate OCI workspace already exists"
    mapfile -d '' args < <(
        builder_bootstrap_candidate_spec_args \
            "$role" "$target_id" "$base" "$dockerfile_sha" "$dpkg_sha"
    )
    /usr/bin/install -d -m 0700 "$layout"
    result="$(
        online_image_provenance maintenance-capture-bootstrap-candidate \
            --output "$output" \
            --layout-output "$layout" \
            "${args[@]}"
    )" || die "$display bootstrap candidate archive capture failed"
    local field
    for field in image_id manifest_id config_id layout_sha256 archive sha256 bytes; do
        [ "$(/usr/bin/grep -c "^${field}=" <<<"$result")" -eq 1 ] \
            || die "$display bootstrap candidate capture result is malformed"
    done
    captured_image="$(/usr/bin/sed -n 's/^image_id=//p' <<<"$result")"
    manifest_id="$(/usr/bin/sed -n 's/^manifest_id=//p' <<<"$result")"
    config_id="$(/usr/bin/sed -n 's/^config_id=//p' <<<"$result")"
    captured_path="$(/usr/bin/sed -n 's/^archive=//p' <<<"$result")"
    archive_sha="$(/usr/bin/sed -n 's/^sha256=//p' <<<"$result")"
    archive_size="$(/usr/bin/sed -n 's/^bytes=//p' <<<"$result")"
    layout_sha="$(/usr/bin/sed -n 's/^layout_sha256=//p' <<<"$result")"
    [ "$captured_image" = "$config_id" ] \
        && [ "$captured_image" != "$target_id" ] \
        && [ "$captured_path" = "$output" ] \
        && [[ "$manifest_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$config_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] \
        && [[ "$archive_size" =~ ^[1-9][0-9]*$ ]] \
        && [[ "$layout_sha" =~ ^[0-9a-f]{64}$ ]] \
        || die "$display bootstrap candidate capture identities are malformed"
    printf '%s_BOOTSTRAP_IMAGE_ID="%s"\n' "$prefix" "$captured_image"
    printf '%s_BOOTSTRAP_CONFIG_ID="%s"\n' "$prefix" "$config_id"
    printf '%s_BOOTSTRAP_MANIFEST_ID="%s"\n' "$prefix" "$manifest_id"
    printf '%s_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="%s"\n' "$prefix" "$archive_size"
    printf 'SHA256_%s_DOCKERFILE="%s"\n' "$prefix" "$dockerfile_sha"
    printf 'SHA256_%s_DPKG_MANIFEST="%s"\n' "$prefix" "$dpkg_sha"
    printf 'SHA256_%s_BOOTSTRAP_IMAGE_ARCHIVE="%s"\n' "$prefix" "$archive_sha"
    printf 'SHA256_%s_BOOTSTRAP_OCI_LAYOUT="%s"\n' "$prefix" "$layout_sha"
    printf 'acquisition_target_id=%s\n' "$target_id"
    printf 'candidate=%s\n' "$output"
}

build_builder_bootstrap_image() {
    [ "$#" -eq 4 ] || die "internal bootstrap discovery specification error"
    local display="$1" role="$2" base="$3" dockerfile_name="$4"
    local dockerfile="$LIB_DIR/$dockerfile_name"
    local seal_dockerfile="$LIB_DIR/Dockerfile.builder-bootstrap-seal"
    local discovery_tag="rustdesk-fork-harness-bootstrap-discovery:local"
    local candidate_tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-${role}-bootstrap-candidate"
    local recipe_sha discovery_id discovery_result observed_discovery_id
    local dpkg_sha candidate_id
    case "$role" in
        android-builder|deb-builder|win-helper) ;;
        *) die "unsupported bootstrap discovery role: $role" ;;
    esac
    [ -f "$dockerfile" ] && [ ! -L "$dockerfile" ] \
        || die "$display bootstrap discovery Dockerfile is absent or unsafe"
    [ -f "$seal_dockerfile" ] && [ ! -L "$seal_dockerfile" ] \
        || die "$display bootstrap seal Dockerfile is absent or unsafe"
    recipe_sha="$(/usr/bin/sha256sum "$dockerfile" | /usr/bin/awk '{print $1}')"
    [[ "$recipe_sha" =~ ^[0-9a-f]{64}$ ]] \
        || die "$display bootstrap discovery Dockerfile identity is malformed"
    online_docker build \
        --network=default --pull=false --no-cache --platform=linux/amd64 \
        --build-arg "BASE_DIGEST=${base#*@}" \
        --build-arg "DOCKERFILE_SHA256=${recipe_sha}" \
        -t "$discovery_tag" -f "$dockerfile" "$LIB_DIR"
    discovery_id="$(
        online_docker image inspect --format '{{.Id}}' "$discovery_tag"
    )" || die "cannot resolve the $display bootstrap discovery image"
    [[ "$discovery_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "$display bootstrap discovery image identity is malformed"
    discovery_result="$(
        online_image_provenance maintenance-inspect-bootstrap-discovery \
            --image-ref "$discovery_tag" \
            --role "${role}-bootstrap-candidate" \
            --expected-id "$discovery_id" \
            --base "$base" \
            --dockerfile-sha "$recipe_sha"
    )" || die "$display bootstrap discovery inspection failed"
    [ "$(/usr/bin/grep -c '^discovery_image_id=' <<<"$discovery_result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^dpkg_sha256=' <<<"$discovery_result")" -eq 1 ] \
        && [ "$(/usr/bin/wc -l <<<"$discovery_result")" -eq 2 ] \
        || die "$display bootstrap discovery result is malformed"
    observed_discovery_id="$(
        /usr/bin/sed -n 's/^discovery_image_id=//p' <<<"$discovery_result"
    )"
    dpkg_sha="$(/usr/bin/sed -n 's/^dpkg_sha256=//p' <<<"$discovery_result")"
    [ "$observed_discovery_id" = "$discovery_id" ] \
        && [[ "$dpkg_sha" =~ ^[0-9a-f]{64}$ ]] \
        || die "$display bootstrap discovery identities are malformed"
    observed_discovery_id="$(
        online_docker image inspect --format '{{.Id}}' "$discovery_tag"
    )" || die "cannot re-resolve the $display bootstrap discovery image"
    [ "$observed_discovery_id" = "$discovery_id" ] \
        || die "$display bootstrap discovery handle changed before sealing"
    online_docker build \
        --network=none --pull=false --no-cache --platform=linux/amd64 \
        --build-arg "DPKG_MANIFEST_SHA256=${dpkg_sha}" \
        -t "$candidate_tag" - <"$seal_dockerfile"
    candidate_id="$(
        online_docker image inspect --format '{{.Id}}' "$candidate_tag"
    )" || die "cannot resolve the $display bootstrap candidate"
    [[ "$candidate_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "$display bootstrap candidate identity is malformed"
    online_image_provenance maintenance-verify-bootstrap-seal \
        --discovery-image-ref "$discovery_tag" \
        --discovery-id "$discovery_id" \
        --image-ref "$candidate_tag" \
        --role "${role}-bootstrap-candidate" \
        --expected-id "$candidate_id" \
        --base "$base" \
        --dockerfile-sha "$recipe_sha" \
        --dpkg-sha "$dpkg_sha" \
        || die "$display bootstrap metadata seal verification failed"
    BUILT_BOOTSTRAP_IMAGE_ID="$candidate_id"
    BUILT_BOOTSTRAP_DPKG_SHA256="$dpkg_sha"
    BUILT_BOOTSTRAP_RECIPE_SHA256="$recipe_sha"
}

build_deb_builder_bootstrap_image() {
    build_builder_bootstrap_image \
        "Debian builder" deb-builder \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        Dockerfile.deb-builder
}

# Explicit networked bootstrap acquisition only. This image is not release
# authority; maintenance_build_android_builder_certified_candidate authenticates
# an exact captured bootstrap through a separate networkless nonroot build.
build_android_builder_bootstrap_image() {
    build_builder_bootstrap_image \
        "Android builder" android-builder \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        Dockerfile.android-builder
}

# ── The Windows VM helper bootstrap: genisoimage + libguestfs + MSI tooling ──
# The Windows artifact path uses host-side helper containers for UDF media creation,
# libguestfs inspection/extraction, and MSI canonicalization. Those helpers are build
# inputs, so their apt installs belong HERE (the one networked phase), not inside
# build-windows-vm.sh/provision-windows-vm.sh/verify-windows-golden.sh.
# This acquisition result is bootstrap material only; a separate networkless
# certification transaction creates the release helper.
build_windows_helper_bootstrap_image() {
    build_builder_bootstrap_image \
        "Windows helper" win-helper \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        Dockerfile.win-helper
}

maintenance_build_deb_builder_bootstrap_candidate() {
    require_cmd python3
    local directory="$ONLINE_DIR/build-images" lock_fd result
    /usr/bin/install -d -m 0700 "$directory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$directory/deb-builder-bootstrap-candidate.docker.tar.gz" ] \
        && [ ! -L "$directory/deb-builder-bootstrap-candidate.docker.tar.gz" ] \
        || die "Debian builder bootstrap candidate archive already exists"
    online_docker pull "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}"
    BUILT_BOOTSTRAP_IMAGE_ID=
    BUILT_BOOTSTRAP_DPKG_SHA256=
    BUILT_BOOTSTRAP_RECIPE_SHA256=
    build_deb_builder_bootstrap_image
    result="$(capture_builder_bootstrap_candidate \
        "Debian builder" DEB_BUILDER \
        deb-builder-bootstrap-candidate.docker.tar.gz \
        deb-builder "$BUILT_BOOTSTRAP_IMAGE_ID" \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        "$BUILT_BOOTSTRAP_RECIPE_SHA256" \
        "$BUILT_BOOTSTRAP_DPKG_SHA256")"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

maintenance_build_android_builder_bootstrap_candidate() {
    require_cmd python3
    local directory="$ONLINE_DIR/build-images" lock_fd result
    /usr/bin/install -d -m 0700 "$directory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$directory/android-builder-bootstrap-candidate.docker.tar.gz" ] \
        && [ ! -L "$directory/android-builder-bootstrap-candidate.docker.tar.gz" ] \
        || die "Android builder bootstrap candidate archive already exists"
    online_docker pull "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"
    BUILT_BOOTSTRAP_IMAGE_ID=
    BUILT_BOOTSTRAP_DPKG_SHA256=
    BUILT_BOOTSTRAP_RECIPE_SHA256=
    build_android_builder_bootstrap_image
    result="$(capture_builder_bootstrap_candidate \
        "Android builder" ANDROID_BUILDER \
        android-builder-bootstrap-candidate.docker.tar.gz \
        android-builder "$BUILT_BOOTSTRAP_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        "$BUILT_BOOTSTRAP_RECIPE_SHA256" \
        "$BUILT_BOOTSTRAP_DPKG_SHA256")"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

maintenance_build_win_helper_bootstrap_candidate() {
    require_cmd python3
    local directory="$ONLINE_DIR/build-images" lock_fd result
    /usr/bin/install -d -m 0700 "$directory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$directory/win-helper-bootstrap-candidate.docker.tar.gz" ] \
        && [ ! -L "$directory/win-helper-bootstrap-candidate.docker.tar.gz" ] \
        || die "Windows helper bootstrap candidate archive already exists"
    online_docker pull "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"
    BUILT_BOOTSTRAP_IMAGE_ID=
    BUILT_BOOTSTRAP_DPKG_SHA256=
    BUILT_BOOTSTRAP_RECIPE_SHA256=
    build_windows_helper_bootstrap_image
    result="$(capture_builder_bootstrap_candidate \
        "Windows helper" WIN_HELPER \
        win-helper-bootstrap-candidate.docker.tar.gz \
        win-helper "$BUILT_BOOTSTRAP_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        "$BUILT_BOOTSTRAP_RECIPE_SHA256" \
        "$BUILT_BOOTSTRAP_DPKG_SHA256")"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

maintenance_build_deb_builder_certified_candidate() {
    require_deb_builder_certification_input_pins
    local archive="$ONLINE_DIR/build-images/deb-builder-bootstrap.docker.tar.gz"
    local directory="$ONLINE_DIR/build-images"
    local context="$ONLINE_FETCH_TMP/deb-builder-certification-context"
    local layout="$ONLINE_FETCH_TMP/deb-builder-bootstrap-oci"
    local candidate_oci="$ONLINE_FETCH_TMP/deb-builder-certified-candidate.oci.tar"
    local candidate_archive="$directory/deb-builder-certified-candidate.docker.tar.gz"
    local export_name="rd-deb-builder-certified:authenticated-v1"
    local materialization layout_sha image_id manifest_id config_id
    local archive_sha archive_size result
    local lock_fd bootstrap_args=() contract_args=() candidate_args=()
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.deb-builder-certify" \
        | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE" ] \
        || die "Debian builder certification Dockerfile differs from its pin"
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Debian builder certification context already exists"
    [ ! -e "$layout" ] && [ ! -L "$layout" ] \
        || die "private Debian builder bootstrap OCI layout already exists"
    [ ! -e "$candidate_oci" ] && [ ! -L "$candidate_oci" ] \
        || die "private certified Debian builder OCI export already exists"
    [ ! -e "$candidate_archive" ] && [ ! -L "$candidate_archive" ] \
        || die "private certified Debian builder archive already exists"
    /usr/bin/install -d -m 0700 "$context" "$layout"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.deb-builder-certify" \
        "$context/Dockerfile"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Debian builder certification context metadata differs"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$context/Dockerfile")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private Debian builder certification Dockerfile metadata differs"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f \
        -name Dockerfile | /usr/bin/wc -l)" -eq 1 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
            ! -type f -print -quit)" ] \
        || die "private Debian builder certification context inventory differs"
    mapfile -d '' bootstrap_args < <(deb_builder_bootstrap_spec_args)
    materialization="$(
        online_image_provenance materialize-oci-layout \
            --archive "$archive" \
            --archive-sha "$SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE" \
            --archive-size "$DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
            --output "$layout" \
            "${bootstrap_args[@]}"
    )" || die "Debian builder bootstrap OCI materialization failed"
    layout_sha="$(printf '%s\n' "$materialization" \
        | /usr/bin/sed -n 's/^layout_sha256=//p')"
    [ "$layout_sha" = "$SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT" ] \
        || die "Debian builder bootstrap OCI layout differs from its pin"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Debian builder bootstrap OCI layout verification failed"
    (
        umask 077
        online_buildx_build \
            --network=none --pull=false --no-cache \
            --platform=linux/amd64 --provenance=mode=max \
            --output="type=oci,name=${export_name},dest=${candidate_oci},tar=true,compression=gzip,oci-mediatypes=true,rewrite-timestamp=true" \
            --build-context \
            "deb-builder-bootstrap=oci-layout://${layout}@${DEB_BUILDER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "DEB_BUILDER_BOOTSTRAP_IMAGE_ID=${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}" \
            --build-arg "DEB_BUILDER_BOOTSTRAP_MANIFEST_ID=${DEB_BUILDER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "DEB_BUILDER_RECIPE_SHA256=${SHA256_DEB_BUILDER_DOCKERFILE}" \
            --build-arg "DEB_BUILDER_DPKG_MANIFEST_SHA256=${SHA256_DEB_BUILDER_DPKG_MANIFEST}" \
            --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}" \
            --file "$context/Dockerfile" \
            "$context"
    ) || die "certified Debian builder candidate build failed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$candidate_oci")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:600:1" ] \
        || die "private certified Debian builder OCI export metadata differs"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Debian builder bootstrap OCI layout changed during the build"
    mapfile -d '' contract_args \
        < <(deb_builder_certification_candidate_spec_args)
    result="$(
        online_image_provenance maintenance-normalize-certified-oci \
            --input "$candidate_oci" \
            --output "$candidate_archive" \
            --bootstrap-layout "$layout" \
            "${contract_args[@]}"
    )" || die "certified Debian builder candidate OCI normalization failed"
    [ "$(/usr/bin/grep -c '^image_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^manifest_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^config_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^sha256=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^bytes=' <<<"$result")" -eq 1 ] \
        || die "certified Debian builder normalization result is malformed"
    image_id="$(/usr/bin/sed -n 's/^image_id=//p' <<<"$result")"
    manifest_id="$(/usr/bin/sed -n 's/^manifest_id=//p' <<<"$result")"
    config_id="$(/usr/bin/sed -n 's/^config_id=//p' <<<"$result")"
    archive_sha="$(/usr/bin/sed -n 's/^sha256=//p' <<<"$result")"
    archive_size="$(/usr/bin/sed -n 's/^bytes=//p' <<<"$result")"
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$manifest_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$config_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] \
        && [[ "$archive_size" =~ ^[1-9][0-9]*$ ]] \
        || die "certified Debian builder normalization identities are malformed"
    candidate_args=(
        --expected-id "$image_id"
        "${contract_args[@]}"
        --config-id "$config_id"
        --manifest-id "$manifest_id"
    )
    online_image_provenance verify-load \
        --archive "$candidate_archive" \
        --archive-sha "$archive_sha" \
        --archive-size "$archive_size" \
        "${candidate_args[@]}" \
        || die "certified Debian builder candidate load/runtime verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'DEB_BUILDER_IMAGE_ID="%s"\n' "$image_id"
    printf '%s\n' "$result"
}

maintenance_build_android_builder_certified_candidate() {
    require_android_builder_certification_input_pins
    local archive="$ONLINE_DIR/build-images/android-builder-bootstrap.docker.tar.gz"
    local directory="$ONLINE_DIR/build-images"
    local context="$ONLINE_FETCH_TMP/android-builder-certification-context"
    local layout="$ONLINE_FETCH_TMP/android-builder-bootstrap-oci"
    local candidate_oci="$ONLINE_FETCH_TMP/android-builder-certified-candidate.oci.tar"
    local candidate_archive="$directory/android-builder-certified-candidate.docker.tar.gz"
    local export_name="rd-android-builder-certified:authenticated-v1"
    local materialization layout_sha image_id manifest_id config_id
    local archive_sha archive_size result
    local lock_fd bootstrap_args=() contract_args=() candidate_args=()
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.android-builder-certify" \
        | /usr/bin/awk '{print $1}')" \
       = "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE" ] \
        || die "Android builder certification Dockerfile differs from its pin"
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Android builder certification context already exists"
    [ ! -e "$layout" ] && [ ! -L "$layout" ] \
        || die "private Android builder bootstrap OCI layout already exists"
    [ ! -e "$candidate_oci" ] && [ ! -L "$candidate_oci" ] \
        || die "private certified Android builder OCI export already exists"
    [ ! -e "$candidate_archive" ] && [ ! -L "$candidate_archive" ] \
        || die "private certified Android builder archive already exists"
    /usr/bin/install -d -m 0700 "$context" "$layout"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.android-builder-certify" \
        "$context/Dockerfile"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Android builder certification context metadata differs"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$context/Dockerfile")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private Android builder certification Dockerfile metadata differs"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f \
        -name Dockerfile | /usr/bin/wc -l)" -eq 1 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
            ! -type f -print -quit)" ] \
        || die "private Android builder certification context inventory differs"
    mapfile -d '' bootstrap_args < <(android_builder_bootstrap_spec_args)
    materialization="$(
        online_image_provenance materialize-oci-layout \
            --archive "$archive" \
            --archive-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE" \
            --archive-size "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
            --output "$layout" \
            "${bootstrap_args[@]}"
    )" || die "Android builder bootstrap OCI materialization failed"
    layout_sha="$(printf '%s\n' "$materialization" \
        | /usr/bin/sed -n 's/^layout_sha256=//p')"
    [ "$layout_sha" = "$SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT" ] \
        || die "Android builder bootstrap OCI layout differs from its pin"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Android builder bootstrap OCI layout verification failed"
    (
        umask 077
        online_buildx_build \
            --network=none --pull=false --no-cache \
            --platform=linux/amd64 --provenance=mode=max \
            --output="type=oci,name=${export_name},dest=${candidate_oci},tar=true,compression=gzip,oci-mediatypes=true,rewrite-timestamp=true" \
            --build-context \
            "android-builder-bootstrap=oci-layout://${layout}@${ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID=${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}" \
            --build-arg "ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID=${ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "ANDROID_BUILDER_RECIPE_SHA256=${SHA256_ANDROID_BUILDER_DOCKERFILE}" \
            --build-arg "ANDROID_BUILDER_DPKG_MANIFEST_SHA256=${SHA256_ANDROID_BUILDER_DPKG_MANIFEST}" \
            --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}" \
            --file "$context/Dockerfile" \
            "$context"
    ) || die "certified Android builder candidate build failed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$candidate_oci")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:600:1" ] \
        || die "private certified Android builder OCI export metadata differs"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Android builder bootstrap OCI layout changed during the build"
    mapfile -d '' contract_args \
        < <(android_builder_certification_candidate_spec_args)
    result="$(
        online_image_provenance maintenance-normalize-certified-oci \
            --input "$candidate_oci" \
            --output "$candidate_archive" \
            --bootstrap-layout "$layout" \
            "${contract_args[@]}"
    )" || die "certified Android builder candidate OCI normalization failed"
    [ "$(/usr/bin/grep -c '^image_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^manifest_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^config_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^sha256=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^bytes=' <<<"$result")" -eq 1 ] \
        || die "certified Android builder normalization result is malformed"
    image_id="$(/usr/bin/sed -n 's/^image_id=//p' <<<"$result")"
    manifest_id="$(/usr/bin/sed -n 's/^manifest_id=//p' <<<"$result")"
    config_id="$(/usr/bin/sed -n 's/^config_id=//p' <<<"$result")"
    archive_sha="$(/usr/bin/sed -n 's/^sha256=//p' <<<"$result")"
    archive_size="$(/usr/bin/sed -n 's/^bytes=//p' <<<"$result")"
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$manifest_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$config_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] \
        && [[ "$archive_size" =~ ^[1-9][0-9]*$ ]] \
        || die "certified Android builder normalization identities are malformed"
    candidate_args=(
        --expected-id "$image_id"
        "${contract_args[@]}"
        --config-id "$config_id"
        --manifest-id "$manifest_id"
    )
    online_image_provenance verify-load \
        --archive "$candidate_archive" \
        --archive-sha "$archive_sha" \
        --archive-size "$archive_size" \
        "${candidate_args[@]}" \
        || die "certified Android builder candidate load/runtime verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'ANDROID_BUILDER_IMAGE_ID="%s"\n' "$image_id"
    printf '%s\n' "$result"
}

maintenance_build_win_helper_certified_candidate() {
    require_win_helper_certification_input_pins
    local archive="$ONLINE_DIR/build-images/win-helper-bootstrap.docker.tar.gz"
    local directory="$ONLINE_DIR/build-images"
    local context="$ONLINE_FETCH_TMP/win-helper-certification-context"
    local layout="$ONLINE_FETCH_TMP/win-helper-bootstrap-oci"
    local candidate_oci="$ONLINE_FETCH_TMP/win-helper-certified-candidate.oci.tar"
    local candidate_archive="$directory/win-helper-certified-candidate.docker.tar.gz"
    local export_name="rd-win-helper-certified:authenticated-v1"
    local materialization layout_sha image_id manifest_id config_id
    local archive_sha archive_size result
    local lock_fd bootstrap_args=() contract_args=() candidate_args=()
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.win-helper-certify" \
        | /usr/bin/awk '{print $1}')" \
       = "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE" ] \
        || die "Windows helper certification Dockerfile differs from its pin"
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Windows helper certification context already exists"
    [ ! -e "$layout" ] && [ ! -L "$layout" ] \
        || die "private Windows helper bootstrap OCI layout already exists"
    [ ! -e "$candidate_oci" ] && [ ! -L "$candidate_oci" ] \
        || die "private certified Windows helper OCI export already exists"
    [ ! -e "$candidate_archive" ] && [ ! -L "$candidate_archive" ] \
        || die "private certified Windows helper archive already exists"
    /usr/bin/install -d -m 0700 "$context" "$layout"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.win-helper-certify" \
        "$context/Dockerfile"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Windows helper certification context metadata differs"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$context/Dockerfile")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private Windows helper certification Dockerfile metadata differs"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f \
        -name Dockerfile | /usr/bin/wc -l)" -eq 1 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
            ! -type f -print -quit)" ] \
        || die "private Windows helper certification context inventory differs"
    mapfile -d '' bootstrap_args < <(win_helper_bootstrap_spec_args)
    materialization="$(
        online_image_provenance materialize-oci-layout \
            --archive "$archive" \
            --archive-sha "$SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE" \
            --archive-size "$WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
            --output "$layout" \
            "${bootstrap_args[@]}"
    )" || die "Windows helper bootstrap OCI materialization failed"
    layout_sha="$(printf '%s\n' "$materialization" \
        | /usr/bin/sed -n 's/^layout_sha256=//p')"
    [ "$layout_sha" = "$SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT" ] \
        || die "Windows helper bootstrap OCI layout differs from its pin"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Windows helper bootstrap OCI layout verification failed"
    (
        umask 077
        online_buildx_build \
            --network=none --pull=false --no-cache \
            --platform=linux/amd64 --provenance=mode=max \
            --output="type=oci,name=${export_name},dest=${candidate_oci},tar=true,compression=gzip,oci-mediatypes=true,rewrite-timestamp=true" \
            --build-context \
            "win-helper-bootstrap=oci-layout://${layout}@${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "WIN_HELPER_BOOTSTRAP_IMAGE_ID=${WIN_HELPER_BOOTSTRAP_IMAGE_ID}" \
            --build-arg "WIN_HELPER_BOOTSTRAP_MANIFEST_ID=${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}" \
            --build-arg "WIN_HELPER_RECIPE_SHA256=${SHA256_WIN_HELPER_DOCKERFILE}" \
            --build-arg "WIN_HELPER_DPKG_MANIFEST_SHA256=${SHA256_WIN_HELPER_DPKG_MANIFEST}" \
            --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}" \
            --file "$context/Dockerfile" \
            "$context"
    ) || die "certified Windows helper candidate build failed"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$candidate_oci")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:600:1" ] \
        || die "private certified Windows helper OCI export metadata differs"
    online_image_provenance verify-oci-layout \
        --layout "$layout" \
        --layout-sha "$SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT" \
        >/dev/null \
        || die "Windows helper bootstrap OCI layout changed during the build"
    mapfile -d '' contract_args \
        < <(win_helper_certification_candidate_spec_args)
    result="$(
        online_image_provenance maintenance-normalize-certified-oci \
            --input "$candidate_oci" \
            --output "$candidate_archive" \
            --bootstrap-layout "$layout" \
            "${contract_args[@]}"
    )" || die "certified Windows helper candidate OCI normalization failed"
    [ "$(/usr/bin/grep -c '^image_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^manifest_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^config_id=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^sha256=' <<<"$result")" -eq 1 ] \
        && [ "$(/usr/bin/grep -c '^bytes=' <<<"$result")" -eq 1 ] \
        || die "certified Windows helper normalization result is malformed"
    image_id="$(/usr/bin/sed -n 's/^image_id=//p' <<<"$result")"
    manifest_id="$(/usr/bin/sed -n 's/^manifest_id=//p' <<<"$result")"
    config_id="$(/usr/bin/sed -n 's/^config_id=//p' <<<"$result")"
    archive_sha="$(/usr/bin/sed -n 's/^sha256=//p' <<<"$result")"
    archive_size="$(/usr/bin/sed -n 's/^bytes=//p' <<<"$result")"
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$manifest_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$config_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        && [[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] \
        && [[ "$archive_size" =~ ^[1-9][0-9]*$ ]] \
        || die "certified Windows helper normalization identities are malformed"
    candidate_args=(
        --expected-id "$image_id"
        "${contract_args[@]}"
        --config-id "$config_id"
        --manifest-id "$manifest_id"
    )
    online_image_provenance verify-load \
        --archive "$candidate_archive" \
        --archive-sha "$archive_sha" \
        --archive-size "$archive_size" \
        "${candidate_args[@]}" \
        || die "certified Windows helper candidate load/runtime verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'WIN_HELPER_IMAGE_ID="%s"\n' "$image_id"
    printf '%s\n' "$result"
}

maintenance_promote_deb_builder_certified_candidate() {
    require_deb_builder_image_pins
    local directory="$ONLINE_DIR/build-images"
    local candidate="$directory/deb-builder-certified-candidate.docker.tar.gz"
    local final="$directory/deb-builder.docker.tar.gz"
    local lock_fd args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] \
        || die "certified Debian builder candidate archive is absent or unsafe"
    [ ! -e "$final" ] && [ ! -L "$final" ] \
        || die "final certified Debian builder archive already exists"
    mapfile -d '' args < <(deb_builder_image_spec_args)
    online_image_provenance verify-archive \
        --archive "$candidate" \
        --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "certified Debian builder candidate differs from the final pins"
    online_image_provenance maintenance-rename-noreplace \
        --source "$candidate" \
        --destination "$final" \
        || die "certified Debian builder candidate promotion failed"
    online_image_provenance verify-load \
        --archive "$final" \
        --archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "promoted Debian builder archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'promoted=%s\n' "$final"
}

maintenance_promote_android_builder_certified_candidate() {
    require_android_builder_image_pins
    local directory="$ONLINE_DIR/build-images"
    local candidate="$directory/android-builder-certified-candidate.docker.tar.gz"
    local final="$directory/android-builder.docker.tar.gz"
    local lock_fd args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] \
        || die "certified Android builder candidate archive is absent or unsafe"
    [ ! -e "$final" ] && [ ! -L "$final" ] \
        || die "final certified Android builder archive already exists"
    mapfile -d '' args < <(android_builder_image_spec_args)
    online_image_provenance verify-archive \
        --archive "$candidate" \
        --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "certified Android builder candidate differs from the final pins"
    online_image_provenance maintenance-rename-noreplace \
        --source "$candidate" \
        --destination "$final" \
        || die "certified Android builder candidate promotion failed"
    online_image_provenance verify-load \
        --archive "$final" \
        --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \
        --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "promoted Android builder archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'promoted=%s\n' "$final"
}

maintenance_promote_win_helper_certified_candidate() {
    require_win_helper_image_pins
    local directory="$ONLINE_DIR/build-images"
    local candidate="$directory/win-helper-certified-candidate.docker.tar.gz"
    local final="$directory/win-helper.docker.tar.gz"
    local lock_fd args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] \
        || die "certified Windows helper candidate archive is absent or unsafe"
    [ ! -e "$final" ] && [ ! -L "$final" ] \
        || die "final certified Windows helper archive already exists"
    mapfile -d '' args < <(win_helper_image_spec_args)
    online_image_provenance verify-archive \
        --archive "$candidate" \
        --archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \
        --archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "certified Windows helper candidate differs from the final pins"
    online_image_provenance maintenance-rename-noreplace \
        --source "$candidate" \
        --destination "$final" \
        || die "certified Windows helper candidate promotion failed"
    online_image_provenance verify-load \
        --archive "$final" \
        --archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \
        --archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE" \
        "${args[@]}" \
        || die "promoted Windows helper archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'promoted=%s\n' "$final"
}

maintenance_build_apple_check_image_candidate() {
    require_devcheck_image_pins
    require_apple_check_image_pins
    verify_or_load_devcheck_image
    local context="$ONLINE_FETCH_TMP/apple-check-build-context"
    local base_layout="$ONLINE_FETCH_TMP/apple-check-base-oci"
    local candidate_archive="$ONLINE_FETCH_TMP/apple-check-candidate.docker.tar.gz"
    local tag="rd-apple-check:authenticated-v1"
    local image_id base_identity base_materialization base_layout_sha result
    local base_args=()
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Apple check build context already exists"
    [ ! -e "$base_layout" ] && [ ! -L "$base_layout" ] \
        || die "private Apple check base OCI layout already exists"
    [ ! -e "$candidate_archive" ] && [ ! -L "$candidate_archive" ] \
        || die "private Apple check candidate archive already exists"
    /usr/bin/install -d -m 0700 "$context" "$base_layout"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.apple-check" "$context/Dockerfile"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/apple-toolchain-release.py" \
        "$SCRIPT_DIR/apple-toolchain-provenance.py" \
        "$context/"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f \
        | /usr/bin/wc -l)" -eq 3 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
            ! -type f -print -quit)" ] \
        || die "private Apple check build context has an unexpected inventory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Apple check build context metadata differs"
    while IFS= read -r input; do
        [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$input")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
            || die "private Apple check input metadata differs: $input"
    done < <(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 \
        -type f -print | LC_ALL=C /usr/bin/sort)
    [ "$(/usr/bin/sha256sum "$context/Dockerfile" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_CHECK_DOCKERFILE" ] \
        || die "private Apple check Dockerfile bytes differ"
    [ "$(/usr/bin/sha256sum "$context/apple-toolchain-release.py" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER" ] \
        || die "private Apple release helper bytes differ"
    [ "$(/usr/bin/sha256sum "$context/apple-toolchain-provenance.py" \
        | /usr/bin/awk '{print $1}')" = "$SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER" ] \
        || die "private Apple provenance helper bytes differ"
    base_identity="$(
        online_docker image inspect --format '{{.Id}}|{{.Os}}|{{.Architecture}}' \
            "$DEV_CHECK_IMAGE_ID"
    )" || die "the exact Apple check base image is not already present"
    [ "$base_identity" = "$DEV_CHECK_IMAGE_ID|linux|amd64" ] \
        || die "the local Apple check base image differs from its exact Linux/amd64 pin"
    mapfile -d '' base_args < <(devcheck_image_spec_args)
    base_materialization="$(
        online_image_provenance materialize-oci-layout \
            --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz" \
            --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
            --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
            --output "$base_layout" \
            "${base_args[@]}"
    )" || die "Apple check base OCI materialization failed"
    base_layout_sha="$(printf '%s\n' "$base_materialization" \
        | /usr/bin/sed -n 's/^layout_sha256=//p')"
    [[ "$base_layout_sha" =~ ^[0-9a-f]{64}$ ]] \
        || die "Apple check base OCI layout identity is malformed"
    online_image_provenance verify-oci-layout \
        --layout "$base_layout" --layout-sha "$base_layout_sha" \
        >/dev/null \
        || die "Apple check base OCI layout verification failed"
    online_buildx_build \
        --network=default --pull=false --no-cache \
        --platform=linux/amd64 --provenance=mode=max \
        --output=type=docker,rewrite-timestamp=true \
        --build-context \
        "rd-devcheck@${DEV_CHECK_IMAGE_ID}=oci-layout://${base_layout}@${DEV_CHECK_IMAGE_MANIFEST_ID}" \
        --build-arg "DEV_CHECK_IMAGE_REF=rd-devcheck@${DEV_CHECK_IMAGE_ID}" \
        --build-arg "DEV_CHECK_IMAGE_ID=${DEV_CHECK_IMAGE_ID}" \
        --build-arg "DEV_CHECK_IMAGE_MANIFEST_ID=${DEV_CHECK_IMAGE_MANIFEST_ID}" \
        --build-arg "SOURCE_DATE_EPOCH=${APPLE_CHECK_SOURCE_DATE_EPOCH}" \
        --build-arg "APPLE_CHECK_DOCKERFILE_SHA256=${SHA256_APPLE_CHECK_DOCKERFILE}" \
        --build-arg "APPLE_TOOLCHAIN_RELEASE_HELPER_SHA256=${SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER}" \
        --build-arg "APPLE_TOOLCHAIN_PROVENANCE_HELPER_SHA256=${SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER}" \
        --build-arg "APPLE_TOOLCHAIN_TREE_SHA256=${APPLE_TOOLCHAIN_TREE_SHA256}" \
        --build-arg "APPLE_TOOLCHAIN_FILES=${APPLE_TOOLCHAIN_FILES}" \
        --build-arg "APPLE_TOOLCHAIN_DIRECTORIES=${APPLE_TOOLCHAIN_DIRECTORIES}" \
        --build-arg "APPLE_TOOLCHAIN_CONTENT_BYTES=${APPLE_TOOLCHAIN_CONTENT_BYTES}" \
        --tag "$tag" \
        --file "$context/Dockerfile" \
        "$context"
    online_image_provenance verify-oci-layout \
        --layout "$base_layout" --layout-sha "$base_layout_sha" \
        >/dev/null \
        || die "Apple check base OCI layout changed during the build"
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the Apple check candidate"
    local args=() position
    mapfile -d '' args < <(apple_check_image_spec_args)
    for ((position = 0; position + 1 < ${#args[@]}; position++)); do
        if [ "${args[position]}" = "--expected-id" ]; then
            args[position + 1]="$image_id"
            break
        fi
    done
    [ "${args[position]:-}" = "--expected-id" ] \
        || die "Apple check candidate spec has no expected image identity"
    online_image_provenance verify-local \
        --publication-index-runtime \
        --image-ref "$tag" "${args[@]}" \
        || die "Apple check candidate runtime verification failed"
    result="$(
        online_image_provenance maintenance-capture \
            --publication-index-runtime \
            --output "$candidate_archive" \
            "${args[@]}"
    )" || die "Apple check candidate provenance capture failed"
    /usr/bin/rm -f -- "$candidate_archive" \
        || die "cannot remove the verified private Apple check candidate archive"
    printf 'APPLE_CHECK_IMAGE_ID="%s"\n' "$image_id"
    printf '%s\n' "$result"
}

prepare_dart_audit_build_context() {
    [ "$#" -eq 1 ] || die "internal Dart advisory context preparation error"
    local context="$1"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Dart advisory build context already exists"
    /usr/bin/install -d -m 0700 "$context"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.dart-audit" "$context/Dockerfile.dart-audit"
    /usr/bin/install -m 0400 \
        "$ONLINE_DIR/dart-audit-inputs/osv-scanner" "$context/osv-scanner"
    /usr/bin/install -m 0400 \
        "$ONLINE_DIR/dart-audit-inputs/Pub-all.zip" "$context/Pub-all.zip"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l)" -eq 3 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
        || die "private Dart advisory build context has an unexpected inventory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Dart advisory build context metadata differs"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' "$context/Dockerfile.dart-audit")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private Dart advisory Dockerfile metadata differs"
    [ "$(/usr/bin/sha256sum "$context/Dockerfile.dart-audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DART_AUDIT_DOCKERFILE" ] \
        || die "private Dart advisory Dockerfile bytes differ"
    [ "$(/usr/bin/sha256sum "$context/osv-scanner" | /usr/bin/awk '{print $1}')" \
       = "$OSV_SCANNER_SHA256" ] \
        || die "private Dart advisory scanner bytes differ"
    [ "$(/usr/bin/sha256sum "$context/Pub-all.zip" | /usr/bin/awk '{print $1}')" \
       = "$OSV_DB_PUB_SHA256" ] \
        || die "private Dart advisory database bytes differ"
}

build_dart_audit_image() {
    [ "$#" -eq 2 ] || die "internal Dart advisory build error"
    local context="$1" tag="$2"
    online_buildx_build \
        --network=none --pull=false --no-cache \
        --platform=linux/amd64 --provenance=mode=max \
        --output=type=docker,rewrite-timestamp=true \
        --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --build-arg "SOURCE_DATE_EPOCH=${OSV_DB_PUB_CAPTURE_EPOCH}" \
        --build-arg "OSV_SCANNER_VERSION=${OSV_SCANNER_VERSION}" \
        --build-arg "OSV_SCANNER_SHA256=${OSV_SCANNER_SHA256}" \
        --build-arg "OSV_DB_PUB_SHA256=${OSV_DB_PUB_SHA256}" \
        --build-arg "OSV_DB_PUB_SIZE=${OSV_DB_PUB_SIZE}" \
        --build-arg "OSV_DB_PUB_CAPTURE_EPOCH=${OSV_DB_PUB_CAPTURE_EPOCH}" \
        --build-arg "OSV_DB_PUB_GENERATION=${OSV_DB_PUB_GENERATION}" \
        --build-arg "DART_AUDIT_DOCKERFILE_SHA256=${SHA256_DART_AUDIT_DOCKERFILE}" \
        --tag "$tag" \
        --file "$context/Dockerfile.dart-audit" \
        "$context"
}

capture_dart_audit_rebuild() {
    [ "$#" -eq 2 ] || die "internal Dart advisory rebuild capture error"
    local output="$1" expected_id="$2"
    local args=()
    mapfile -d '' args < <(dart_audit_candidate_spec_args "$expected_id")
    online_image_provenance maintenance-capture \
        --output "$output" "${args[@]}"
}

maintenance_build_dart_audit_image_candidate() {
    require_dart_audit_recipe_pins
    require_image_pin OSV_SCANNER_SIZE
    stage_dart_audit_inputs
    local directory="$ONLINE_DIR/verifier-images"
    local context="$ONLINE_FETCH_TMP/dart-audit-build-context"
    local first_archive="$ONLINE_FETCH_TMP/dart-audit-rebuild-a.docker.tar.gz"
    local second_archive="$directory/.dart-audit-candidate.docker.tar.gz.part"
    local candidate="$directory/dart-audit-candidate.docker.tar.gz"
    local tag="rd-dart-audit-candidate:provenance-v1"
    local base_identity first_id second_id first_result second_result
    local first_manifest second_manifest first_config second_config
    local archive_sha archive_size lock_fd
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "Dart advisory image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the Dart advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Dart advisory image archive transaction owns the archive root"
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
        || die "Dart advisory candidate archive already exists"
    [ ! -e "$second_archive" ] && [ ! -L "$second_archive" ] \
        || die "stale Dart advisory candidate publication staging exists"

    online_docker pull --platform=linux/amd64 \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" >/dev/null
    base_identity="$(
        online_docker image inspect --format '{{.Id}}|{{.Os}}|{{.Architecture}}' \
            "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}"
    )" || die "cannot inspect the exact Dart advisory base image"
    [ "$base_identity" = "${SHA256_BASEIMAGE_UBUNTU_1804}|linux|amd64" ] \
        || die "the local Dart advisory base image differs from its exact Linux/amd64 pin"
    prepare_dart_audit_build_context "$context"

    build_dart_audit_image "$context" "$tag"
    first_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the first Dart advisory rebuild"
    first_result="$(capture_dart_audit_rebuild "$first_archive" "$first_id")" \
        || die "first Dart advisory rebuild capture failed"

    build_dart_audit_image "$context" "$tag"
    second_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the second Dart advisory rebuild"
    second_result="$(capture_dart_audit_rebuild "$second_archive" "$second_id")" \
        || die "second Dart advisory rebuild capture failed"

    first_manifest="$(image_capture_field "$first_result" manifest_id)"
    second_manifest="$(image_capture_field "$second_result" manifest_id)"
    first_config="$(image_capture_field "$first_result" config_id)"
    second_config="$(image_capture_field "$second_result" config_id)"
    [ "$first_manifest:$first_config" = "$second_manifest:$second_config" ] \
        || die "independent Dart advisory rebuilds produced different runtime identities"
    archive_sha="$(image_capture_field "$second_result" sha256)"
    archive_size="$(image_capture_field "$second_result" bytes)"
    online_image_provenance maintenance-rename-noreplace \
        --source "$second_archive" --destination "$candidate" \
        || die "Dart advisory candidate publication failed"
    /usr/bin/rm -f -- "$first_archive" \
        || die "cannot retire the first verified Dart advisory rebuild archive"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Dart advisory image archive lock"
    exec {lock_fd}<&-
    printf 'DART_AUDIT_IMAGE_ID="%s"\n' "$second_id"
    printf 'DART_AUDIT_IMAGE_CONFIG_ID="%s"\n' "$second_config"
    printf 'DART_AUDIT_IMAGE_MANIFEST_ID="%s"\n' "$second_manifest"
    printf 'SHA256_DART_AUDIT_IMAGE_ARCHIVE="%s"\n' "$archive_sha"
    printf 'SIZE_DART_AUDIT_IMAGE_ARCHIVE="%s"\n' "$archive_size"
    printf 'reproducible_runtime=%s\n' "$second_manifest:$second_config"
    printf 'candidate=%s\n' "$candidate"
}

maintenance_promote_dart_audit_image_candidate() {
    require_dart_audit_image_pins
    require_image_pin SHA256_DART_AUDIT_IMAGE_ARCHIVE
    require_image_pin SIZE_DART_AUDIT_IMAGE_ARCHIVE
    case "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_DART_AUDIT_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local directory="$ONLINE_DIR/verifier-images"
    local candidate="$directory/dart-audit-candidate.docker.tar.gz"
    local final="$directory/dart-audit.docker.tar.gz"
    local lock_fd promotion_state args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "Dart advisory image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the Dart advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Dart advisory image archive transaction owns the archive root"
    mapfile -d '' args < <(dart_audit_image_spec_args)
    if [ -f "$candidate" ] && [ ! -L "$candidate" ] \
       && [ ! -e "$final" ] && [ ! -L "$final" ]; then
        online_image_provenance verify-archive \
            --archive "$candidate" \
            --archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" \
            --archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" \
            "${args[@]}" \
            || die "Dart advisory candidate differs from the final pins"
        online_image_provenance maintenance-rename-noreplace \
            --source "$candidate" --destination "$final" \
            || die "Dart advisory candidate promotion failed"
        promotion_state=renamed
    elif [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
         && [ -f "$final" ] && [ ! -L "$final" ]; then
        promotion_state=resumed
    else
        die "Dart advisory promotion requires exactly one safe candidate or final archive"
    fi
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$final" \
        --archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}" \
        || die "promoted Dart advisory archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Dart advisory image archive lock"
    exec {lock_fd}<&-
    printf 'promotion_state=%s\n' "$promotion_state"
    printf 'promoted=%s\n' "$final"
}

build_rust_audit_image() {
    [ "$#" -eq 2 ] || die "internal Rust advisory build error"
    local context="$1" tag="$2"
    online_buildx_build \
        --network=default --pull=true --no-cache \
        --platform=linux/amd64 --provenance=mode=max \
        --output=type=docker,rewrite-timestamp=true \
        --build-arg "RUST_AUDIT_RUST_VERSION=${RUST_AUDIT_RUST_VERSION}" \
        --build-arg "BASE_DIGEST=${RUST_AUDIT_BASE_IMAGE_DIGEST}" \
        --build-arg "SOURCE_DATE_EPOCH=${ADVISORY_DB_COMMIT_EPOCH}" \
        --build-arg "CARGO_AUDIT_VERSION=${CARGO_AUDIT_VERSION}" \
        --build-arg "CARGO_DENY_VERSION=${CARGO_DENY_VERSION}" \
        --build-arg "CARGO_AUDIT_TAG_OBJECT=${CARGO_AUDIT_TAG_OBJECT}" \
        --build-arg "CARGO_AUDIT_SOURCE_COMMIT=${CARGO_AUDIT_SOURCE_COMMIT}" \
        --build-arg "CARGO_AUDIT_SOURCE_TREE=${CARGO_AUDIT_SOURCE_TREE}" \
        --build-arg "SHA256_CARGO_AUDIT_SOURCE_ARCHIVE=${SHA256_CARGO_AUDIT_SOURCE_ARCHIVE}" \
        --build-arg "CARGO_DENY_TAG_OBJECT=${CARGO_DENY_TAG_OBJECT}" \
        --build-arg "CARGO_DENY_SOURCE_COMMIT=${CARGO_DENY_SOURCE_COMMIT}" \
        --build-arg "CARGO_DENY_SOURCE_TREE=${CARGO_DENY_SOURCE_TREE}" \
        --build-arg "SHA256_CARGO_DENY_SOURCE_ARCHIVE=${SHA256_CARGO_DENY_SOURCE_ARCHIVE}" \
        --build-arg "ADVISORY_DB_SHA=${ADVISORY_DB_COMMIT}" \
        --build-arg "ADVISORY_DB_COMMIT_EPOCH=${ADVISORY_DB_COMMIT_EPOCH}" \
        --tag "$tag" \
        --file "$context/Dockerfile.audit" \
        "$context"
}

capture_rust_audit_rebuild() {
    [ "$#" -eq 2 ] || die "internal Rust advisory rebuild capture error"
    local output="$1" expected_id="$2"
    local args=()
    mapfile -d '' args < <(rust_audit_candidate_spec_args "$expected_id")
    online_image_provenance maintenance-capture \
        --output "$output" "${args[@]}"
}

maintenance_build_rust_audit_image_candidate() {
    local names=(
        RUST_AUDIT_BASE_IMAGE_DIGEST
        RUST_AUDIT_RUST_VERSION RUST_AUDIT_RUSTC_VERSION
        CARGO_AUDIT_VERSION CARGO_DENY_VERSION
        CARGO_AUDIT_TAG_OBJECT CARGO_AUDIT_SOURCE_COMMIT
        CARGO_AUDIT_SOURCE_TREE SHA256_CARGO_AUDIT_SOURCE_ARCHIVE
        CARGO_AUDIT_SIGNING_KEY_FINGERPRINT
        CARGO_DENY_TAG_OBJECT CARGO_DENY_SOURCE_COMMIT
        CARGO_DENY_SOURCE_TREE SHA256_CARGO_DENY_SOURCE_ARCHIVE
        SHA256_RUST_AUDIT_CARGO_AUDIT SHA256_RUST_AUDIT_CARGO_DENY
        ADVISORY_DB_COMMIT ADVISORY_DB_COMMIT_EPOCH
        SHA256_RUST_AUDIT_DOCKERFILE
    )
    local name first_id second_id first_result second_result
    local first_manifest second_manifest first_config second_config
    local archive_sha archive_size lock_fd
    local tag="rd-rust-audit-candidate:provenance-v1"
    local context="$ONLINE_FETCH_TMP/rust-audit-build-context"
    local directory="$ONLINE_DIR/verifier-images"
    local first_archive="$directory/.rust-audit-rebuild-a.docker.tar.gz.part"
    local second_archive="$directory/.rust-audit-candidate.docker.tar.gz.part"
    local candidate="$directory/rust-audit-candidate.docker.tar.gz"
    for name in "${names[@]}"; do require_image_pin "$name"; done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_RUST_AUDIT_DOCKERFILE" ] \
        || die "Rust advisory Dockerfile differs from its pin"
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Rust advisory build context already exists"
    /usr/bin/install -d -m 0700 "$context"
    /usr/bin/install -m 0400 \
        "$SCRIPT_DIR/Dockerfile.audit" "$context/Dockerfile.audit"
    [ "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l)" -eq 1 ] \
        && [ -z "$(/usr/bin/find "$context" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
        || die "private Rust advisory build context has an unexpected inventory"
    [ "$(/usr/bin/stat -c '%u:%g:%a' "$context")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "private Rust advisory build context metadata differs"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' "$context/Dockerfile.audit")" \
       = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:400:1" ] \
        || die "private Rust advisory Dockerfile metadata differs"
    [ "$(/usr/bin/sha256sum "$context/Dockerfile.audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_RUST_AUDIT_DOCKERFILE" ] \
        || die "private Rust advisory Dockerfile bytes differ"
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /usr/bin/install -d -m 0700 "$directory"
    fi
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "Rust advisory image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the Rust advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Rust advisory image archive transaction owns the archive root"
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
        || die "Rust advisory candidate archive already exists"
    [ ! -e "$first_archive" ] && [ ! -L "$first_archive" ] \
        || die "stale first Rust advisory rebuild staging exists"
    [ ! -e "$second_archive" ] && [ ! -L "$second_archive" ] \
        || die "stale Rust advisory candidate publication staging exists"

    build_rust_audit_image "$context" "$tag"
    first_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the first Rust advisory rebuild"
    first_result="$(capture_rust_audit_rebuild "$first_archive" "$first_id")" \
        || die "first Rust advisory rebuild capture failed"

    build_rust_audit_image "$context" "$tag"
    second_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the second Rust advisory rebuild"
    second_result="$(capture_rust_audit_rebuild "$second_archive" "$second_id")" \
        || die "second Rust advisory rebuild capture failed"

    first_manifest="$(image_capture_field "$first_result" manifest_id)"
    second_manifest="$(image_capture_field "$second_result" manifest_id)"
    first_config="$(image_capture_field "$first_result" config_id)"
    second_config="$(image_capture_field "$second_result" config_id)"
    [ "$first_manifest:$first_config" = "$second_manifest:$second_config" ] \
        || die "independent Rust advisory rebuilds produced different runtime identities: first=$first_manifest:$first_config second=$second_manifest:$second_config"
    archive_sha="$(image_capture_field "$second_result" sha256)"
    archive_size="$(image_capture_field "$second_result" bytes)"
    online_image_provenance maintenance-rename-noreplace \
        --source "$second_archive" --destination "$candidate" \
        || die "Rust advisory candidate publication failed"
    /usr/bin/rm -f -- "$first_archive" \
        || die "cannot retire the first verified Rust advisory rebuild archive"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Rust advisory image archive lock"
    exec {lock_fd}<&-
    printf 'RUST_AUDIT_IMAGE_ID="%s"\n' "$second_id"
    printf 'RUST_AUDIT_IMAGE_CONFIG_ID="%s"\n' "$second_config"
    printf 'RUST_AUDIT_IMAGE_MANIFEST_ID="%s"\n' "$second_manifest"
    printf 'SHA256_RUST_AUDIT_IMAGE_ARCHIVE="%s"\n' "$archive_sha"
    printf 'SIZE_RUST_AUDIT_IMAGE_ARCHIVE="%s"\n' "$archive_size"
    printf 'reproducible_runtime=%s\n' "$second_manifest:$second_config"
    printf 'candidate=%s\n' "$candidate"
}

maintenance_promote_rust_audit_image_candidate() {
    require_rust_audit_image_pins
    require_image_pin SHA256_RUST_AUDIT_IMAGE_ARCHIVE
    require_image_pin SIZE_RUST_AUDIT_IMAGE_ARCHIVE
    case "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" in
        0|*[!0-9]*|'') die "SIZE_RUST_AUDIT_IMAGE_ARCHIVE is not one positive decimal integer" ;;
    esac
    local directory="$ONLINE_DIR/verifier-images"
    local candidate="$directory/rust-audit-candidate.docker.tar.gz"
    local final="$directory/rust-audit.docker.tar.gz"
    local lock_fd promotion_state args=()
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "Rust advisory image archive root is not current-user-private mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the Rust advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Rust advisory image archive transaction owns the archive root"
    mapfile -d '' args < <(rust_audit_image_spec_args)
    if [ -f "$candidate" ] && [ ! -L "$candidate" ] \
       && [ ! -e "$final" ] && [ ! -L "$final" ]; then
        online_image_provenance verify-archive \
            --archive "$candidate" \
            --archive-sha "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
            --archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" \
            "${args[@]}" \
            || die "Rust advisory candidate differs from the final pins"
        online_image_provenance maintenance-rename-noreplace \
            --source "$candidate" --destination "$final" \
            || die "Rust advisory candidate promotion failed"
        promotion_state=renamed
    elif [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
         && [ -f "$final" ] && [ ! -L "$final" ]; then
        promotion_state=resumed
    else
        die "Rust advisory promotion requires exactly one safe candidate or final archive"
    fi
    online_image_provenance verify-load \
        --publication-index-runtime \
        --archive "$final" \
        --archive-sha "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}" \
        || die "promoted Rust advisory archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Rust advisory image archive lock"
    exec {lock_fd}<&-
    printf 'promotion_state=%s\n' "$promotion_state"
    printf 'promoted=%s\n' "$final"
}

promote_builder_bootstrap_candidate() {
    [ "$#" -ge 7 ] || die "internal bootstrap candidate promotion error"
    local display="$1" candidate_name="$2" final_name="$3"
    local archive_sha="$4" archive_size="$5" expected_layout_sha="$6"
    shift 6
    local directory="$ONLINE_DIR/build-images"
    local candidate="$directory/$candidate_name"
    local final="$directory/$final_name"
    local layout="$ONLINE_FETCH_TMP/${candidate_name%.docker.tar.gz}-promotion.oci"
    local materialization observed_layout_sha lock_fd
    local args=("$@")
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
           = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
        || die "builder image archive root must be current-user-owned mode 0700"
    exec {lock_fd}<"$directory" \
        || die "cannot open the builder image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another builder image archive transaction owns the archive root"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] \
        || die "$display bootstrap candidate archive is absent or unsafe"
    [ ! -e "$final" ] && [ ! -L "$final" ] \
        || die "$display final bootstrap archive already exists"
    [ ! -e "$layout" ] && [ ! -L "$layout" ] \
        || die "$display bootstrap promotion OCI workspace already exists"
    online_image_provenance verify-archive \
        --archive "$candidate" \
        --archive-sha "$archive_sha" \
        --archive-size "$archive_size" \
        "${args[@]}" \
        || die "$display bootstrap candidate differs from the reviewed pins"
    /usr/bin/install -d -m 0700 "$layout"
    materialization="$(
        online_image_provenance materialize-oci-layout \
            --archive "$candidate" \
            --archive-sha "$archive_sha" \
            --archive-size "$archive_size" \
            --output "$layout" \
            "${args[@]}"
    )" || die "$display bootstrap candidate layout verification failed"
    [ "$(/usr/bin/grep -c '^layout_sha256=' <<<"$materialization")" -eq 1 ] \
        || die "$display bootstrap candidate layout result is malformed"
    observed_layout_sha="$(
        /usr/bin/sed -n 's/^layout_sha256=//p' <<<"$materialization"
    )"
    [ "$observed_layout_sha" = "$expected_layout_sha" ] \
        || die "$display bootstrap candidate layout differs from the reviewed pin"
    online_image_provenance maintenance-rename-noreplace \
        --source "$candidate" \
        --destination "$final" \
        || die "$display bootstrap candidate promotion failed"
    online_image_provenance verify-archive \
        --archive "$final" \
        --archive-sha "$archive_sha" \
        --archive-size "$archive_size" \
        "${args[@]}" \
        || die "$display promoted bootstrap archive verification failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the builder image archive lock"
    exec {lock_fd}<&-
    printf 'promoted=%s\n' "$final"
}

maintenance_promote_deb_builder_bootstrap_candidate() {
    require_deb_builder_bootstrap_pins
    local args=()
    mapfile -d '' args < <(deb_builder_bootstrap_spec_args)
    promote_builder_bootstrap_candidate \
        "Debian builder" \
        deb-builder-bootstrap-candidate.docker.tar.gz \
        deb-builder-bootstrap.docker.tar.gz \
        "$SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE" \
        "$DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
        "$SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        "${args[@]}"
}

maintenance_promote_android_builder_bootstrap_candidate() {
    require_android_builder_bootstrap_pins
    local args=()
    mapfile -d '' args < <(android_builder_bootstrap_spec_args)
    promote_builder_bootstrap_candidate \
        "Android builder" \
        android-builder-bootstrap-candidate.docker.tar.gz \
        android-builder-bootstrap.docker.tar.gz \
        "$SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE" \
        "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
        "$SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT" \
        "${args[@]}"
}

maintenance_promote_win_helper_bootstrap_candidate() {
    require_win_helper_bootstrap_pins
    local args=()
    mapfile -d '' args < <(win_helper_bootstrap_spec_args)
    promote_builder_bootstrap_candidate \
        "Windows helper" \
        win-helper-bootstrap-candidate.docker.tar.gz \
        win-helper-bootstrap.docker.tar.gz \
        "$SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE" \
        "$WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE" \
        "$SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT" \
        "${args[@]}"
}

online_fetch_builder_runtime_ref() {
    [ "$#" -eq 1 ] || die "online builder runtime selection requires one config ID"
    case "$1" in
        "$DEB_BUILDER_CONFIG_ID") printf '%s\n' "$DEB_BUILDER_IMAGE_ID" ;;
        "$ANDROID_BUILDER_CONFIG_ID") printf '%s\n' "$ANDROID_BUILDER_IMAGE_ID" ;;
        "$WIN_HELPER_CONFIG_ID") printf '%s\n' "$WIN_HELPER_IMAGE_ID" ;;
        *) die "online builder config ID is outside the closed certified set" ;;
    esac
}

require_online_fetch_builder_image() {
    local role="$1" config_id="$2" runtime_ref
    local args=()
    case "$role:$config_id" in
        "deb-builder:$DEB_BUILDER_CONFIG_ID")
            mapfile -d '' args < <(deb_builder_image_spec_args)
            ;;
        "android-builder:$ANDROID_BUILDER_CONFIG_ID")
            mapfile -d '' args < <(android_builder_image_spec_args)
            ;;
        "win-helper:$WIN_HELPER_CONFIG_ID")
            mapfile -d '' args < <(win_helper_image_spec_args)
            ;;
        *) die "online builder role/config pair is outside the closed certified set" ;;
    esac
    runtime_ref="$(online_fetch_builder_runtime_ref "$config_id")"
    assert_online_fetch_docker_authority
    online_image_provenance verify-local \
        --publication-index-runtime --image-ref "$runtime_ref" \
        "${args[@]}" >/dev/null
    assert_online_fetch_docker_authority
}

cargo_tool_output_tool() {
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-cargo-tool-output.py" "$@"
}

cargo_tool_output_semantic_args() {
    local kind="$1" tool_version
    case "$kind" in
        frb) tool_version="$FLUTTER_RUST_BRIDGE_VERSION" ;;
        cargo-ndk) tool_version="$CARGO_NDK_VERSION" ;;
        *) die "unsupported networked Cargo tool kind: $kind" ;;
    esac
    printf '%s\0' \
        --kind "$kind" \
        --tool-version "$tool_version" \
        --rust-version "$RUST_VERSION"
}

retire_cargo_tool_output_staging() {
    local staging="$1" staging_id="$2" kind="$3" disposition
    disposition="$(
        cargo_tool_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            --kind "$kind"
    )" || die "cannot reconcile private $kind Cargo tool staging"
    log "$kind Cargo tool staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private $kind Cargo tool staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private $kind Cargo tool staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private $kind Cargo tool staging survived retirement"
}

recover_cargo_tool_output_staging() {
    local kind="$1" stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-cargo-tool-$kind.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved $kind Cargo tool staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_cargo_tool_output_staging "$staging" "$staging_id" "$kind"
    done
}

stage_cargo_installed_tool() {
    local kind="$1" builder="$2" existing_mode="${3:-reuse}"
    local role package binary tool_version features destination
    case "$kind:$builder" in
        "frb:$DEB_BUILDER_CONFIG_ID")
            role=deb-builder
            package=flutter_rust_bridge_codegen
            binary=flutter_rust_bridge_codegen
            tool_version="$FLUTTER_RUST_BRIDGE_VERSION"
            features=uuid
            destination=frb-tool
            ;;
        "cargo-ndk:$ANDROID_BUILDER_CONFIG_ID")
            role=android-builder
            package=cargo-ndk
            binary=cargo-ndk
            tool_version="$CARGO_NDK_VERSION"
            features=
            destination=cargo-ndk-tool
            ;;
        *) die "networked Cargo tool request is outside the closed producer set" ;;
    esac
    case "$existing_mode" in
        reuse|reproduce) ;;
        *) die "unsupported existing Cargo tool disposition: $existing_mode" ;;
    esac
    local status=0 input_status=0 output_status=0 publication_status=0
    local existing=0 reproduced_sha256= reproduced_size=
    local lock_fd staging staging_id output_id
    local semantic_args=()
    require_online_fetch_builder_image "$role" "$builder"
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for $kind Cargo tool serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Cargo tool output transaction already owns the online root"
    verify_sha256 \
        "$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75"
    recover_cargo_tool_output_staging "$kind"
    mapfile -d '' semantic_args < <(cargo_tool_output_semantic_args "$kind")
    if [ -e "$ONLINE_DIR/$destination" ] || [ -L "$ONLINE_DIR/$destination" ]; then
        cargo_tool_output_tool check-complete \
            --online "$ONLINE_DIR" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}" \
            || die "existing $kind Cargo tool is incomplete or structurally unsafe"
        if [ "$existing_mode" = reuse ]; then
            "$FLOCK_BIN" --unlock "$lock_fd" \
                || die "cannot release the $kind Cargo tool transaction lock"
            exec {lock_fd}<&-
            log "$kind Cargo tool already staged and semantically verified, skipping"
            return 0
        fi
        existing=1
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-cargo-tool-$kind.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private $kind Cargo tool staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! cargo_tool_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${semantic_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed $kind Cargo tool preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed $kind Cargo tool preparation left non-retirable private staging"
        die "cannot prepare private $kind Cargo tool staging"
    fi
    output_id="$(/usr/bin/stat -c '%d:%i' -- "$staging/output")"
    log "installing pinned $package $tool_version into private checked output; ./online/inputs is read-only"
    online_docker_run \
        --env CARGO_TOOL_PACKAGE="$package" \
        --env CARGO_TOOL_BINARY="$binary" \
        --env CARGO_TOOL_VERSION="$tool_version" \
        --env CARGO_TOOL_FEATURES="$features" \
        --env RUST_VERSION="$RUST_VERSION" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/tool" \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
            toolchain="/tmp/toolchain"
            archive="/online/rust-${RUST_VERSION}.tar.xz"
            installer="$toolchain/rust-${RUST_VERSION}.0-x86_64-unknown-linux-gnu/install.sh"
            mkdir -p "$toolchain" /tmp/home /tmp/cargo-home /tmp/cargo-target
            tar -C "$toolchain" -xf "$archive"
            "$installer" --prefix=/tmp/rust --disable-ldconfig \
                --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu >/dev/null
            export HOME=/tmp/home
            export CARGO_HOME=/tmp/cargo-home
            export CARGO_TARGET_DIR=/tmp/cargo-target
            export PATH=/tmp/rust/bin:$PATH
            install_args=(
                cargo install "$CARGO_TOOL_PACKAGE"
                --version "$CARGO_TOOL_VERSION"
                --locked
                --root /outputs/tool
                --bin "$CARGO_TOOL_BINARY"
                --target x86_64-unknown-linux-gnu
                --profile release
            )
            if [ -n "$CARGO_TOOL_FEATURES" ]; then
                install_args+=(--features "$CARGO_TOOL_FEATURES")
            fi
            "${install_args[@]}"
        ' || status=$?
    (
        verify_sha256 \
            "$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75"
    ) || input_status=$?
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging/output" --expected-identity "$output_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private $kind Cargo tool output traversal"
    cargo_tool_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${semantic_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
        if [ "$existing" -eq 1 ]; then
            cargo_tool_output_tool compare-existing \
                --online "$ONLINE_DIR" --staging "$staging" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${semantic_args[@]}" \
                || publication_status=$?
            if [ "$publication_status" -eq 0 ]; then
                reproduced_sha256="$(/usr/bin/sha256sum \
                    "$ONLINE_DIR/$destination/bin/$binary" | /usr/bin/awk '{ print $1 }')"
                reproduced_size="$(/usr/bin/stat -c %s -- \
                    "$ONLINE_DIR/$destination/bin/$binary")"
            fi
        else
            cargo_tool_output_tool publish \
                --online "$ONLINE_DIR" --staging "$staging" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${semantic_args[@]}" \
                || publication_status=$?
        fi
    fi
    retire_cargo_tool_output_staging "$staging" "$staging_id" "$kind"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the $kind Cargo tool transaction lock"
    exec {lock_fd}<&-
    [ "$input_status" -eq 0 ] || die "networked $kind Cargo tool input postcondition failed"
    [ "$output_status" -eq 0 ] || die "networked $kind Cargo tool output postcondition failed"
    [ "$status" -eq 0 ] || die "networked $kind Cargo tool producer failed"
    [ "$publication_status" -eq 0 ] \
        || die "networked $kind Cargo tool publication/reproduction failed"
    if [ "$existing" -eq 1 ]; then
        log "$kind Cargo tool independently reproduced byte-for-byte: size=$reproduced_size sha256=$reproduced_sha256"
    fi
}

# ── The FRB codegen tool (R-B7): built FOR ubuntu:18.04, staged to ./online/inputs/frb-tool ──
# build_one needs flutter_rust_bridge_codegen to (re)generate the bridge; it cannot
# `cargo install` it offline (its deps are not in the main vendor set), so build it HERE
# (networked) in the deb-builder image with the pinned rust — exactly as upstream's
# bridge.yml does: `cargo install ... --version <pin> --features uuid --locked`.
build_frb_codegen() {
    case "${1:-reuse}" in
        reuse|reproduce) ;;
        *) die "build_frb_codegen accepts only reuse or reproduce" ;;
    esac
    local builder="$DEB_BUILDER_CONFIG_ID"
    stage_cargo_installed_tool frb "$builder" "${1:-reuse}"
}

# ── The flutter pub cache (R-B7): hosted + git deps, staged to ./online/inputs/pub-cache ──
# Pub receives the canonical cache path but only through one nested private output
# mount. The exact pinned Flutter archive and committed source authority remain
# read-only. Both the app and pinned flutter_tools lockfiles are enforced.
pub_cache_output_tool() {
    [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ] \
        || die "Pub-cache output authority requires the exact source snapshot"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/online-pub-cache-output.py" "$@"
}

pub_cache_provenance_args() {
    printf '%s\0' \
        --source-commit "$GRADLE_SOURCE_COMMIT" \
        --source-tree "$GRADLE_SOURCE_TREE" \
        --source-archive-sha256 "$GRADLE_SOURCE_ARCHIVE_SHA256" \
        --flutter-version "$FLUTTER_VERSION" \
        --flutter-archive-sha256 "$SHA256_FLUTTER_3_24_5"
}

retire_pub_cache_output_staging() {
    local staging="$1" staging_id="$2" disposition archive
    disposition="$(
        pub_cache_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
    )" || die "cannot reconcile private Pub-cache output staging"
    log "Pub-cache output staging reconciliation: $disposition"
    if [ "$disposition" = replaced ] || [ "$disposition" = replaced-staged ]; then
        prepare_retired_online_input_root
        archive="$(
            pub_cache_output_tool archive-replaced \
                --online "$ONLINE_DIR" --staging "$staging" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
        )" || die "cannot archive the completed Pub-cache replacement record"
        [ -d "$archive" ] && [ ! -L "$archive" ] \
            || die "Pub-cache replacement-record archive is not one real directory"
        [ ! -e "$staging" ] && [ ! -L "$staging" ] \
            || die "private Pub-cache staging survived archival"
        retire_archived_online_input "$archive" "completed Pub-cache replacement"
        retire_empty_online_input_root
        log "Displaced Pub cache and its completed replacement record were exactly retired"
        return 0
    fi
    case "$disposition" in
        unpublished|published|unselected-while-occupied|replacement-prepared) ;;
        *) die "private Pub-cache output staging has an unknown disposition" ;;
    esac
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Pub-cache output staging traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Pub-cache output staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Pub-cache output staging survived retirement"
    retire_empty_online_input_root_if_present
}

recover_pub_cache_output_staging() {
    local stale=() staging staging_id
    reconcile_retired_online_input_archives
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name '.rustdesk-pub-cache.*' -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Pub-cache output staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_pub_cache_output_staging "$staging" "$staging_id"
    done
}

prepare_pub_cache_output_staging() {
    PUB_CACHE_OUTPUT_STAGING="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-pub-cache.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Pub-cache output staging"
    PUB_CACHE_OUTPUT_STAGING_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$PUB_CACHE_OUTPUT_STAGING"
    )"
    readonly PUB_CACHE_OUTPUT_STAGING PUB_CACHE_OUTPUT_STAGING_ID
    if ! pub_cache_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$PUB_CACHE_OUTPUT_STAGING" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${PUB_CACHE_PROVENANCE_ARGS[@]}"
    then
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
            --root "$PUB_CACHE_OUTPUT_STAGING" \
            --expected-identity "$PUB_CACHE_OUTPUT_STAGING_ID" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Pub-cache output preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
            --remove-private-root "$PUB_CACHE_OUTPUT_STAGING" \
            --expected-identity "$PUB_CACHE_OUTPUT_STAGING_ID" \
            || die "failed Pub-cache output preparation left non-retirable private staging"
        die "cannot prepare private Pub-cache output staging"
    fi
    PUB_CACHE_OUTPUT_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$PUB_CACHE_OUTPUT_STAGING/output"
    )"
    readonly PUB_CACHE_OUTPUT_ID
}

restore_pub_cache_output_traversal() {
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$PUB_CACHE_OUTPUT_STAGING/output" \
        --expected-identity "$PUB_CACHE_OUTPUT_ID" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Pub-cache output traversal"
}

verify_pub_cache_resolution() {
    local cache="$1" builder="$DEB_BUILDER_CONFIG_ID"
    [ -d "$cache" ] && [ ! -L "$cache" ] \
        || die "Pub-cache semantic candidate is not one real directory"
    online_docker_run_pub_semantic \
        --mount "type=bind,source=$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$cache,target=/online/pub-cache,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY,target=/authority,readonly,bind-recursive=disabled" \
        --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
        --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
        --workdir /tmp \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
        umask 077
        mkdir /tmp/toolchain /tmp/home /tmp/project
        tar -C /tmp/toolchain -xf /inputs/flutter.tar.xz
        cp -a /authority/flutter/. /tmp/project/
        chmod -R u+rwX /tmp/project
        export HOME=/tmp/home PUB_CACHE=/online/pub-cache CI=true
        export PUB_HOSTED_URL=https://pub.dev
        export FLUTTER_SUPPRESS_ANALYTICS=true
        export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0
        export PATH=/tmp/toolchain/flutter/bin:/tmp/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin
        authority_lock="$(sha256sum /authority/flutter/pubspec.lock | awk "{print \$1}")"
        tools_lock="$(sha256sum /tmp/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")"
        (cd /tmp/toolchain/flutter/packages/flutter_tools \
            && dart pub get --offline --enforce-lockfile >/dev/null)
        [ "$tools_lock" = "$(sha256sum /tmp/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")" ]
        /authority/scripts/finalize-flutter-tools-offline.sh \
            /tmp/toolchain/flutter \
            "$RUSTDESK_FLUTTER_VERSION" \
            "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256"
        (cd /tmp/project && dart pub get --offline --enforce-lockfile >/dev/null)
        (cd /tmp/project && flutter pub get --offline --enforce-lockfile >/dev/null)
        [ "$authority_lock" = "$(sha256sum /tmp/project/pubspec.lock | awk "{print \$1}")" ]

        git_specs=(
          "dash_chat_2|bd6b5b41254e57c5bcece202ebfb234de63e6487|.|https://github.com/rustdesk-org/Dash-Chat-2"
          "dynamic_layouts|24cb88413fa5181d949ddacbb30a65d5c459e7d9|.|https://github.com/rustdesk-org/dynamic_layouts.git"
          "window_size|eb3964990cf19629c89ff8cb4a37640c7b3d5601|plugins/window_size|https://github.com/google/flutter-desktop-embedding.git"
        )
        [ "${#git_specs[@]}" -eq 3 ]
        for spec in "${git_specs[@]}"; do
            IFS="|" read -r package resolved package_path url <<<"$spec"
            checkouts=(/online/pub-cache/git/*-"$resolved")
            [ "${#checkouts[@]}" -eq 1 ] && [ -d "${checkouts[0]}" ]
            checkout="${checkouts[0]}"
            [ "$(cat "$checkout/.git/pub-packages")" = "$package_path" ]
            [ "$(/usr/bin/git -c safe.directory="$checkout" -C "$checkout" rev-parse --verify "HEAD^{commit}")" = "$resolved" ]
            [ -z "$(/usr/bin/git -c safe.directory="$checkout" -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]
            /usr/bin/git -c safe.directory="$checkout" -C "$checkout" diff --no-ext-diff --quiet --
            /usr/bin/git -c safe.directory="$checkout" -C "$checkout" diff --cached --no-ext-diff --quiet --
            remote="$(
                /usr/bin/git -c safe.directory="$checkout" -C "$checkout" \
                    config --path --get remote.origin.url
            )"
            case "$remote" in /online/pub-cache/git/cache/*) ;; *) exit 1 ;; esac
            [ -d "$remote" ] && [ ! -L "$remote" ]
            [ "$(
                /usr/bin/git -c safe.directory="$remote" --git-dir="$remote" \
                    config --get remote.origin.url
            )" = "$url" ]
            /usr/bin/git -c safe.directory="$checkout" -C "$checkout" \
                fsck --full --no-dangling --no-reflogs >/dev/null
            /usr/bin/git -c safe.directory="$remote" --git-dir="$remote" \
                fsck --full --no-dangling --no-reflogs >/dev/null
            /usr/bin/git -c safe.directory="$remote" --git-dir="$remote" \
                cat-file -e "${resolved}^{commit}"
            tree_listing=/tmp/pub-cache-git-tree
            /usr/bin/git -c safe.directory="$checkout" -C "$checkout" \
                ls-tree -rz --full-tree -r HEAD >"$tree_listing"
            bad_mode=""
            while IFS= read -r -d "" entry; do
                mode="${entry%% *}"
                case "$mode" in 100644|100755|120000) ;; *) bad_mode="$mode"; break ;; esac
            done <"$tree_listing"
            rm -f -- "$tree_listing"
            [ -z "$bad_mode" ]
            [ -f "$checkout/$package_path/pubspec.yaml" ]
            grep -qE "^name:[[:space:]]*$package\$" "$checkout/$package_path/pubspec.yaml"
        done
    '
}

produce_pub_cache_candidate() {
    local output="$1" builder="$DEB_BUILDER_CONFIG_ID"
    [ -d "$output" ] && [ ! -L "$output" ] \
        || die "Pub-cache producer output is not one real directory"
    online_docker_run \
        --mount "type=bind,source=$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$output,target=/online/pub-cache" \
        --mount "type=bind,source=$GRADLE_SOURCE_BUILD/flutter,target=/project-source,readonly,bind-recursive=disabled" \
        --workdir /tmp \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
        umask 077
        mkdir /tmp/toolchain /tmp/home /tmp/project
        tar -C /tmp/toolchain -xf /inputs/flutter.tar.xz
        cp -a /project-source/. /tmp/project/
        chmod -R u+rwX /tmp/project
        export HOME=/tmp/home PUB_CACHE=/online/pub-cache CI=true
        export PUB_HOSTED_URL=https://pub.dev
        export FLUTTER_SUPPRESS_ANALYTICS=true
        export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0
        export PATH=/tmp/toolchain/flutter/bin:/tmp/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin
        project_lock="$(sha256sum /project-source/pubspec.lock | awk "{print \$1}")"
        tools_lock="$(sha256sum /tmp/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")"
        (cd /tmp/toolchain/flutter/packages/flutter_tools \
            && dart pub get --enforce-lockfile)
        [ "$tools_lock" = "$(sha256sum /tmp/toolchain/flutter/packages/flutter_tools/pubspec.lock | awk "{print \$1}")" ]
        (cd /tmp/project && flutter pub get --enforce-lockfile)
        [ "$project_lock" = "$(sha256sum /tmp/project/pubspec.lock | awk "{print \$1}")" ]
        rm -rf -- \
            "$PUB_CACHE/_temp" \
            "$PUB_CACHE/log" \
            "$PUB_CACHE/README.md" \
            "$PUB_CACHE/hosted/pub.dev/.cache"
        while IFS= read -r -d "" checkout; do
            rm -rf -- "$checkout/.git/logs"
            rm -f -- \
                "$checkout/.git/FETCH_HEAD" \
                "$checkout/.git/ORIG_HEAD" \
                "$checkout/.git/COMMIT_EDITMSG" \
                "$checkout/.git/index" \
                "$checkout/.git/index.lock"
            /usr/bin/git -c safe.directory="$checkout" -c index.version=2 \
                -C "$checkout" read-tree HEAD
        done < <(find "$PUB_CACHE/git" -mindepth 1 -maxdepth 1 -type d \
            ! -name cache -print0 | LC_ALL=C sort -z)
        while IFS= read -r -d "" bare; do
            rm -rf -- "$bare/logs"
            rm -f -- "$bare/FETCH_HEAD" "$bare/ORIG_HEAD"
        done < <(find "$PUB_CACHE/git/cache" -mindepth 1 -maxdepth 1 -type d \
            -print0 | LC_ALL=C sort -z)
    '
}

stage_pub_cache() {
    local builder="$DEB_BUILDER_CONFIG_ID"
    local status=0 reproduction_status=0 source_status=0 input_status=0 output_status=0
    local reproduction_output_status=0 semantic_status=0 reproduction_semantic_status=0
    local pin_status=0 publication_status=0
    local lock_fd receipt="" seal_receipt="" digest="" reproduction_receipt="" reproduction_digest=""
    local reproduction="" current=0 replace_existing=0
    require_online_fetch_builder_image deb-builder "$builder"
    assert_online_fetch_source_tools
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Pub-cache output serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Pub-cache output transaction already owns the online root"
    prepare_gradle_source
    verify_sha256 "$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5"
    recover_pub_cache_output_staging
    mapfile -d '' PUB_CACHE_PROVENANCE_ARGS < <(pub_cache_provenance_args)
    readonly PUB_CACHE_PROVENANCE_ARGS
    if [ -e "$ONLINE_DIR/pub-cache" ] || [ -L "$ONLINE_DIR/pub-cache" ]; then
        if receipt="$(
            pub_cache_output_tool check-complete \
                --online "$ONLINE_DIR" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
        )" \
           && [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]] \
           && [ "${BASH_REMATCH[1]}" = "$SHA256_PUB_CACHE_CLOSURE_V1" ] \
           && verify_pub_cache_resolution "$ONLINE_DIR/pub-cache"
        then
            current=1
        elif seal_receipt="$(
            pub_cache_output_tool seal-exact-existing \
                --online "$ONLINE_DIR" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                --expected-digest "$SHA256_PUB_CACHE_CLOSURE_V1"
        )" \
           && [[ "$seal_receipt" =~ ^sha256=([0-9a-f]{64})$ ]] \
           && [ "${BASH_REMATCH[1]}" = "$SHA256_PUB_CACHE_CLOSURE_V1" ] \
           && receipt="$(
               pub_cache_output_tool check-complete \
                   --online "$ONLINE_DIR" \
                   --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
           )" \
           && [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]] \
           && [ "${BASH_REMATCH[1]}" = "$SHA256_PUB_CACHE_CLOSURE_V1" ] \
           && verify_pub_cache_resolution "$ONLINE_DIR/pub-cache"
        then
            current=1
            log "Exact pinned Pub cache root finality was recovered without replacing its closure"
        else
            replace_existing=1
            log "existing Pub cache is stale, unpinned, or semantically incomplete; preparing one verified replacement"
        fi
    fi
    if [ "$current" -eq 0 ]; then
        prepare_pub_cache_output_staging
        log "staging both enforced Pub lock closures into one private output; ./online/inputs remains read-only"
        produce_pub_cache_candidate "$PUB_CACHE_OUTPUT_STAGING/output" || status=$?
        if [ "$status" -eq 0 ]; then
            reproduction="$ONLINE_FETCH_TMP/pub-cache-reproduction"
            [ ! -e "$reproduction" ] && [ ! -L "$reproduction" ] \
                || die "private Pub-cache reproduction root already exists"
            /usr/bin/install -d -m 0700 "$reproduction" \
                || die "cannot create private Pub-cache reproduction root"
            log "independently reproducing the cold Pub closure before publication"
            produce_pub_cache_candidate "$reproduction" || reproduction_status=$?
        fi
    fi
    (verify_gradle_source_unchanged) || source_status=$?
    retire_gradle_source_build
    verify_sha256 "$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
        || input_status=$?
    if [ "$current" -eq 0 ]; then
        restore_pub_cache_output_traversal
        receipt="$(
            pub_cache_output_tool verify \
                --online "$ONLINE_DIR" --staging "$PUB_CACHE_OUTPUT_STAGING" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${PUB_CACHE_PROVENANCE_ARGS[@]}"
        )" || output_status=$?
        if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then
            digest="${BASH_REMATCH[1]}"
        else
            output_status=1
        fi
        if [ "$status" -eq 0 ] && [ "$reproduction_status" -eq 0 ] \
           && [ "$source_status" -eq 0 ] && [ "$input_status" -eq 0 ] \
           && [ "$output_status" -eq 0 ]; then
            reproduction_receipt="$(
                pub_cache_output_tool verify-reproduction \
                    --cache "$reproduction" \
                    --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
            )" || reproduction_output_status=$?
            if [[ "$reproduction_receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then
                reproduction_digest="${BASH_REMATCH[1]}"
            else
                reproduction_output_status=1
            fi
            if [ "$reproduction_output_status" -eq 0 ] \
               && [ "$reproduction_digest" != "$digest" ]; then
                if ! pub_cache_output_tool compare-reproductions \
                    --first-cache "$PUB_CACHE_OUTPUT_STAGING/output" \
                    --second-cache "$reproduction" \
                    --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
                then
                    : # The bounded diagnostic is emitted by the trusted helper.
                fi
                log "independent Pub-cache reproductions differ: first=$digest second=$reproduction_digest"
                reproduction_output_status=1
            fi
        fi
        if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
           && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
            verify_pub_cache_resolution "$PUB_CACHE_OUTPUT_STAGING/output" \
                || semantic_status=$?
        fi
        if [ "$status" -eq 0 ] && [ "$reproduction_status" -eq 0 ] \
           && [ "$source_status" -eq 0 ] && [ "$input_status" -eq 0 ] \
           && [ "$output_status" -eq 0 ] && [ "$reproduction_output_status" -eq 0 ] \
           && [ "$semantic_status" -eq 0 ]; then
            verify_pub_cache_resolution "$reproduction" \
                || reproduction_semantic_status=$?
        fi
        if [ "$status" -eq 0 ] && [ "$reproduction_status" -eq 0 ] \
           && [ "$source_status" -eq 0 ] && [ "$input_status" -eq 0 ] \
           && [ "$output_status" -eq 0 ] && [ "$reproduction_output_status" -eq 0 ] \
           && [ "$semantic_status" -eq 0 ] && [ "$reproduction_semantic_status" -eq 0 ] \
           && [ "$digest" != "$SHA256_PUB_CACHE_CLOSURE_V1" ]; then
            log "reproduced Pub-cache closure differs from its committed pin: sha256=$digest"
            pin_status=1
        fi
        if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
           && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ] \
           && [ "$reproduction_status" -eq 0 ] \
           && [ "$reproduction_output_status" -eq 0 ] \
           && [ "$semantic_status" -eq 0 ] \
           && [ "$reproduction_semantic_status" -eq 0 ] \
           && [ "$pin_status" -eq 0 ]; then
            if [ "$replace_existing" -eq 1 ]; then
                prepare_retired_online_input_root
                pub_cache_output_tool replace \
                    --online "$ONLINE_DIR" --staging "$PUB_CACHE_OUTPUT_STAGING" \
                    --retired-root "$RETIRED_ONLINE_INPUT_ROOT" \
                    --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                    "${PUB_CACHE_PROVENANCE_ARGS[@]}" \
                    --expected-digest "$digest" \
                    || publication_status=$?
            else
                pub_cache_output_tool publish \
                    --online "$ONLINE_DIR" --staging "$PUB_CACHE_OUTPUT_STAGING" \
                    --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                    "${PUB_CACHE_PROVENANCE_ARGS[@]}" \
                    --expected-digest "$digest" \
                    || publication_status=$?
            fi
        fi
        retire_pub_cache_output_staging \
            "$PUB_CACHE_OUTPUT_STAGING" "$PUB_CACHE_OUTPUT_STAGING_ID"
    fi
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Pub-cache output transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "networked Pub-cache source postcondition failed"
    [ "$input_status" -eq 0 ] || die "networked Pub-cache Flutter-input postcondition failed"
    [ "$output_status" -eq 0 ] || die "networked Pub-cache output postcondition failed"
    [ "$status" -eq 0 ] || die "networked Pub-cache producer failed"
    [ "$reproduction_status" -eq 0 ] || die "independent Pub-cache producer failed"
    [ "$reproduction_output_status" -eq 0 ] || die "independent Pub-cache output differs"
    [ "$semantic_status" -eq 0 ] || die "networkless Pub-cache semantic replay failed"
    [ "$reproduction_semantic_status" -eq 0 ] \
        || die "independent networkless Pub-cache semantic replay failed"
    [ "$pin_status" -eq 0 ] || die "reproduced Pub-cache closure is not the committed closure"
    [ "$publication_status" -eq 0 ] || die "networked Pub-cache output publication failed"
    log "Pub cache is cold-reproduced, structurally closed, pin-bound, and both enforced lockfiles resolve offline"
}

# ── vcpkg overlay distfiles (R-B12(a)) ─────────────────────────────────────────
# libvpx uses a SHA512-pinned v1.15.2 archive plus the exact upstream d5f35ac8
# security patch. The overlay consumes only these captures through file:// URLs.
# libyuv fetches from googlesource, whose gitiles
# `+archive` tarballs are EMPIRICALLY non-reproducible (two fetches differ — even decompressed),
# so the URL can't be SHA-pinned and R-R1 forbids vendoring. Capture a deterministic
# `git archive --format=tar | gzip -n` of the pinned commit into ./online/inputs + verify its SHA512
# against pins.env; the libyuv overlay portfile then consumes /online/libyuv-<commit>.tar.gz
# (file://, SHA512-verified) on the Linux build hosts — both stage_vcpkg_natives + _arm64 mount the
# SAME file. (The Windows golden VM has no ./online/inputs capture, so the portfile falls back to
# vcpkg_from_git.) MUST run before stage_vcpkg_natives[_arm64]. The archive is byte-deterministic
# given the image's git (this SHA512 was computed in this deb-builder, git 2.17.1 — re-pin if it
# changes; same class as the SHA256_VCPKG_120DEAC3 GitHub-archive caveat in pins.env).
stage_libvpx_distfiles() {
    local lock_fd action
    stage_vcpkg_fixed_archives
    prepare_libvpx_source_authority
    [ -f "$LIBVPX_LOCAL_OUTPUT_HELPER" ] \
        && [ ! -L "$LIBVPX_LOCAL_OUTPUT_HELPER" ] \
        || die "libvpx local-output helper is not one real source file"
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for libvpx local-output serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another online-output transaction already owns the online root"
    verify_libvpx_private_source_authority "before committed libvpx local publication" \
        || die "private libvpx source authority changed before local publication"
    action="$(
        /usr/bin/python3 -I -S "$LIBVPX_LOCAL_OUTPUT_HELPER" publish \
            --online "$ONLINE_DIR" \
            --source-root "$LIBVPX_SOURCE_AUTHORITY_ROOT" \
            --source-patch "$LIBVPX_SOURCE_AUTHORITY_PATCH" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            --fix-commit "$LIBVPX_FIX_COMMIT" \
            --patch-sha512 "$SHA512_LIBVPX_PATCH" \
            --native-key "$(libvpx_native_key)" \
            --source-commit "$LIBVPX_SOURCE_AUTHORITY_COMMIT" \
            --source-tree "$LIBVPX_SOURCE_AUTHORITY_TREE" \
            --source-blob "$LIBVPX_SOURCE_AUTHORITY_BLOB"
    )" || die "cannot publish the committed libvpx patch/native-key transaction"
    case "$action" in
        complete | published) ;;
        *) die "libvpx local-output helper returned an unknown disposition: $action" ;;
    esac
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the libvpx local-output transaction lock"
    exec {lock_fd}<&-
    verify_libvpx_private_source_authority "after committed libvpx local publication" \
        || die "private libvpx source authority changed during local publication"
    verify_libvpx_source_authority "after committed libvpx local publication" \
        || die "committed libvpx source authority changed during local publication"
    require_libvpx_distfiles
    log "libvpx source, committed security patch, native key, and Windows inputs are exact"
}

libyuv_distfile_output_tool() {
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-libyuv-distfile-output.py" "$@"
}

libyuv_distfile_output_args() {
    printf '%s\0' \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --commit "$LIBYUV_COMMIT" \
        --sha512 "$SHA512_LIBYUV"
}

retire_libyuv_distfile_staging() {
    local staging="$1" staging_id="$2" disposition
    local output_args=()
    mapfile -d '' output_args < <(libyuv_distfile_output_args)
    disposition="$(
        libyuv_distfile_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private libyuv distfile staging"
    log "libyuv distfile staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private libyuv distfile staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private libyuv distfile staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private libyuv distfile staging survived retirement"
}

recover_libyuv_distfile_staging() {
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-libyuv-distfile.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved libyuv distfile staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_libyuv_distfile_staging "$staging" "$staging_id"
    done
}

stage_vcpkg_distfiles() {
    stage_libvpx_distfiles
    local builder="$DEB_BUILDER_CONFIG_ID"
    local status=0 output_status=0 publication_status=0
    local lock_fd staging staging_id
    local output_args=()
    require_online_fetch_builder_image deb-builder "$builder"
    case "$SHA512_LIBYUV" in
        *"${SHA_PENDING}"*) die "libyuv distfile SHA512 is the R-B12 sentinel — record it in pins.env first" ;;
    esac
    mapfile -d '' output_args < <(libyuv_distfile_output_args)
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for libyuv distfile serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another libyuv distfile output transaction already owns the online root"
    recover_libyuv_distfile_staging
    if [ -e "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" ] \
       || [ -L "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" ]; then
        libyuv_distfile_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing libyuv distfile is incomplete or structurally unsafe"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the libyuv distfile transaction lock"
        exec {lock_fd}<&-
        log "vcpkg distfile (libyuv) already captured and structurally verified"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-libyuv-distfile.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private libyuv distfile staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! libyuv_distfile_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed libyuv preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed libyuv preparation left non-retirable private staging"
        die "cannot prepare private libyuv distfile staging"
    fi
    log "capturing the pinned libyuv Git tree into one private checked output"
    online_docker_run \
        --env LIBYUV_COMMIT="$LIBYUV_COMMIT" \
        --env SHA512_LIBYUV="$SHA512_LIBYUV" \
        --mount "type=bind,source=$staging/output,target=/outputs/libyuv.tar.gz" \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
            export HOME=/tmp/home
            export GIT_CONFIG_NOSYSTEM=1
            export GIT_CONFIG_GLOBAL=/dev/null
            export GIT_ATTR_NOSYSTEM=1
            export GIT_NO_REPLACE_OBJECTS=1
            mkdir -p "$HOME" /tmp/src
            cd /tmp/src
            git init -q
            git remote add origin https://chromium.googlesource.com/libyuv/libyuv
            if ! git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
                fetch -q --depth 1 origin "$LIBYUV_COMMIT"
            then
                cd /tmp
                rm -rf /tmp/src
                git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
                    clone -q --no-checkout \
                    https://chromium.googlesource.com/libyuv/libyuv /tmp/src
                cd /tmp/src
            fi
            git cat-file -e "${LIBYUV_COMMIT}^{commit}"
            git -c core.autocrlf=false -c core.hooksPath=/dev/null \
                -c core.attributesFile=/dev/null \
                archive --format=tar "$LIBYUV_COMMIT" \
                | gzip -n > /outputs/libyuv.tar.gz
            got="$(sha512sum /outputs/libyuv.tar.gz | cut -d" " -f1)"
            [ "$got" = "$SHA512_LIBYUV" ] || {
                echo "R-B12(a) libyuv SHA512 mismatch: got $got want $SHA512_LIBYUV" >&2
                exit 1
            }
        ' || status=$?
    libyuv_distfile_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
        libyuv_distfile_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_libyuv_distfile_staging "$staging" "$staging_id"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the libyuv distfile transaction lock"
    exec {lock_fd}<&-
    [ "$output_status" -eq 0 ] || die "networked libyuv distfile output postcondition failed"
    [ "$status" -eq 0 ] || die "networked libyuv distfile producer failed"
    [ "$publication_status" -eq 0 ] || die "networked libyuv distfile publication failed"
    log "vcpkg distfile captured (libyuv, SHA512-verified and checked-published)"
}

# ── The vcpkg-built native codecs (R-R1 pinned overlay ports): vpx/yuv/opus ──
# scrap + magnum-opus (libs/scrap/build.rs; the magnum-opus git dep) link these STATICALLY
# from VCPKG_ROOT/installed/x64-linux when the linux-pkg-config feature is OFF — the shipped
# .deb feature set (build-debian.sh: --flutter --unix-file-copy-paste). `vcpkg install`
# downloads each port's source and compiles it, so it belongs in this ONE networked step; the
# built x64-linux tree is then staged read-only for the offline build. Built from the repo's
# patched, pinned res/vcpkg overlay ports atop the baseline registry snapshot (the vcpkg
# source archive is pinned at VCPKG_BASELINE). vcpkg's bootstrap needs `zip` (in the image).
vcpkg_native_output_tool() {
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-vcpkg-native-output.py" "$@"
}

vcpkg_native_output_pin() {
    case "$1" in
        x64-linux) printf '%s\n' "$VCPKG_X64_LINUX_OUTPUT_KEY_V1" ;;
        arm64-android) printf '%s\n' "$VCPKG_ARM64_ANDROID_OUTPUT_KEY_V1" ;;
        *) die "unsupported vcpkg native output kind: $1" ;;
    esac
}

checked_vcpkg_native_output_key() {
    local kind=$1 builder=$2 actual expected
    actual="$(vcpkg_native_output_key "$kind" "$builder")"
    expected="$(vcpkg_native_output_pin "$kind")"
    [ "$actual" = "$expected" ] \
        || die "$kind vcpkg native producer-recipe key differs from its pin"
    printf '%s\n' "$actual"
}

vcpkg_native_output_args() {
    local kind="$1" builder="$2"
    printf '%s\0' \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --kind "$kind" \
        --output-key "$(checked_vcpkg_native_output_key "$kind" "$builder")" \
        --libvpx-key "$(libvpx_native_key)" \
        --builder "$builder"
}

retire_vcpkg_native_output_staging() {
    local staging="$1" staging_id="$2" kind="$3" builder="$4" disposition
    local output_args=()
    mapfile -d '' output_args < <(vcpkg_native_output_args "$kind" "$builder")
    disposition="$(
        vcpkg_native_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private $kind vcpkg native staging"
    log "$kind vcpkg native staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private $kind vcpkg native staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private $kind vcpkg native staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private $kind vcpkg native staging survived retirement"
}

recover_vcpkg_native_output_staging() {
    local kind="$1" builder="$2"
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-vcpkg-native-${kind}.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved $kind vcpkg native staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_vcpkg_native_output_staging "$staging" "$staging_id" "$kind" "$builder"
    done
}

stage_vcpkg_natives() {
    local builder="$DEB_BUILDER_CONFIG_ID"
    local status=0 source_status=0 output_status=0 publication_status=0
    local lock_fd staging staging_id
    local output_args=()
    require_online_fetch_builder_image deb-builder "$builder"
    require_libvpx_distfiles
    require_libyuv_distfile
    verify_sha256 \
        "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "$SHA256_VCPKG_120DEAC3"
    mapfile -d '' output_args < <(vcpkg_native_output_args x64-linux "$builder")
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for x64-linux vcpkg native serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another vcpkg native output transaction already owns the online root"
    recover_vcpkg_native_output_staging x64-linux "$builder"
    if [ -e "$ONLINE_DIR/vcpkg/installed/x64-linux" ] \
       || [ -L "$ONLINE_DIR/vcpkg/installed/x64-linux" ]; then
        vcpkg_native_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing x64-linux vcpkg native output is incomplete, stale, or unsafe"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the x64-linux vcpkg native transaction lock"
        exec {lock_fd}<&-
        log "x64-linux vcpkg native codecs already staged and structurally verified"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-vcpkg-native-x64-linux.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private x64-linux vcpkg native staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! vcpkg_native_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed x64-linux preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed x64-linux preparation left non-retirable private staging"
        die "cannot prepare private x64-linux vcpkg native staging"
    fi
    log "building the exact x64-linux vcpkg native consumer projection"
    online_docker_run \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$REPO_ROOT/res/vcpkg,target=/overlay,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$VCPKG_NATIVE_PRODUCER,target=/producer/build-vcpkg-native-output.sh,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/native" \
        --env RUSTDESK_VCPKG_BASELINE="$VCPKG_BASELINE" \
        --env RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        --env VCPKG_NATIVE_OUTPUT_KEY="$(checked_vcpkg_native_output_key x64-linux "$builder")" \
        --env LIBVPX_NATIVE_KEY="$(libvpx_native_key)" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /bin/bash --noprofile --norc \
            /producer/build-vcpkg-native-output.sh x64-linux \
        || status=$?
    verify_libvpx_source_authority "after x64-linux vcpkg native production" \
        || source_status=$?
    vcpkg_native_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ]; then
        vcpkg_native_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_vcpkg_native_output_staging "$staging" "$staging_id" x64-linux "$builder"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the x64-linux vcpkg native transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "committed libvpx source changed during x64-linux native production"
    [ "$output_status" -eq 0 ] || die "x64-linux vcpkg native output postcondition failed"
    [ "$status" -eq 0 ] || die "x64-linux vcpkg native producer failed"
    [ "$publication_status" -eq 0 ] || die "x64-linux vcpkg native publication failed"
    log "x64-linux vcpkg natives checked and published (5 static libraries)"
}

maintenance_reproduce_vcpkg_x64() {
    local builder="$DEB_BUILDER_CONFIG_ID"
    local key lock_fd status=0 source_status=0
    local output_args=()
    verify_or_load_deb_builder_image
    prepare_libvpx_source_authority
    require_libvpx_distfiles
    require_libyuv_distfile
    verify_sha256 \
        "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "$SHA256_VCPKG_120DEAC3"
    key="$(checked_vcpkg_native_output_key x64-linux "$builder")"
    mapfile -d '' output_args < <(vcpkg_native_output_args x64-linux "$builder")
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for x64-linux reproducibility"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another online-output transaction already owns the online root"
    vcpkg_native_output_tool check-complete \
        --online "$ONLINE_DIR" "${output_args[@]}" \
        || die "cached x64-linux vcpkg native output is incomplete, stale, or unsafe"
    online_docker_run \
        --tmpfs /outputs:rw,noexec,nosuid,nodev,mode=0700,size=64m \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$REPO_ROOT/res/vcpkg,target=/overlay,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$VCPKG_NATIVE_PRODUCER,target=/producer/build-vcpkg-native-output.sh,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$SCRIPT_DIR/online-input-provenance.py,target=/producer/online-input-provenance.py,readonly,bind-recursive=disabled" \
        --env RUSTDESK_VCPKG_BASELINE="$VCPKG_BASELINE" \
        --env RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        --env VCPKG_NATIVE_OUTPUT_KEY="$key" \
        --env LIBVPX_NATIVE_KEY="$(libvpx_native_key)" \
        --env RUSTDESK_VCPKG_X64_LINUX_SHA256="$SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /bin/bash --noprofile --norc -euo pipefail -c '
            install -d -m 0700 /outputs/native
            /bin/bash /producer/build-vcpkg-native-output.sh x64-linux
            /usr/bin/python3 -I -S /producer/online-input-provenance.py verify-subtree \
                --tree /online/vcpkg/installed/x64-linux \
                --expected "$RUSTDESK_VCPKG_X64_LINUX_SHA256"
            /usr/bin/python3 -I -S /producer/online-input-provenance.py verify-subtree \
                --tree /outputs/native \
                --expected "$RUSTDESK_VCPKG_X64_LINUX_SHA256"
            printf "VCPKG_X64_REPRODUCTION=pass sha256=%s output_key=%s builds=acquisition-cache+fresh\n" \
                "$RUSTDESK_VCPKG_X64_LINUX_SHA256" "$VCPKG_NATIVE_OUTPUT_KEY"
        ' || status=$?
    verify_libvpx_source_authority "after x64-linux reproducibility build" \
        || source_status=$?
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the x64-linux reproducibility lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] \
        || die "committed libvpx source changed during x64-linux reproducibility"
    [ "$status" -eq 0 ] || die "fresh x64-linux vcpkg reproduction differed"
}

# ── The Android NDK r28c, extracted for the cargo-ndk JNI cross-compile ─────────
# The archive is one immutable read-only input. Its checked extractor receives one
# fresh private output root and no online namespace or final-name authority.
android_ndk_output_tool() {
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-android-ndk-output.py" "$@"
}

android_ndk_output_args() {
    local builder="$1"
    printf '%s\0' \
        --archive "$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip" \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --version "$ANDROID_NDK_VERSION" \
        --sha256 "$SHA256_ANDROID_NDK_R28C" \
        --builder "$builder"
}

retire_android_ndk_output_staging() {
    local staging="$1" staging_id="$2" builder="$3" disposition
    local output_args=()
    mapfile -d '' output_args < <(android_ndk_output_args "$builder")
    disposition="$(
        android_ndk_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private Android NDK staging"
    log "Android NDK staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Android NDK staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Android NDK staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Android NDK staging survived retirement"
}

recover_android_ndk_output_staging() {
    local builder="$1"
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-android-ndk.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Android NDK staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_android_ndk_output_staging \
            "$staging" "$staging_id" "$builder"
    done
}

stage_android_ndk() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 output_status=0 publication_status=0
    local lock_fd staging staging_id
    local output_args=()
    local archive="$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip"
    require_online_fetch_builder_image android-builder "$builder"
    verify_sha256 "$archive" "$SHA256_ANDROID_NDK_R28C"
    mapfile -d '' output_args < <(android_ndk_output_args "$builder")
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Android NDK serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Android NDK output transaction already owns the online root"
    recover_android_ndk_output_staging "$builder"
    if [ -e "$ONLINE_DIR/android-ndk" ] || [ -L "$ONLINE_DIR/android-ndk" ]; then
        android_ndk_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing Android NDK output is incomplete, stale, or unsafe"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Android NDK output transaction lock"
        exec {lock_fd}<&-
        log "Android NDK already staged and exactly archive-verified"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-android-ndk.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Android NDK staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! android_ndk_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Android NDK preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed Android NDK preparation left non-retirable private staging"
        die "cannot prepare private Android NDK staging"
    fi
    log "extracting exact Android NDK ${ANDROID_NDK_VERSION} into private checked output"
    online_docker_run_offline \
        --mount "type=bind,source=$archive,target=/inputs/android-ndk.zip,readonly" \
        --mount "type=bind,source=$SCRIPT_DIR/online-android-ndk-output.py,target=/authority/online-android-ndk-output.py,readonly" \
        --mount "type=bind,source=$staging/output,target=/outputs/android-ndk" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S \
        /authority/online-android-ndk-output.py extract \
        --archive /inputs/android-ndk.zip \
        --output /outputs/android-ndk \
        --version "$ANDROID_NDK_VERSION" \
        --sha256 "$SHA256_ANDROID_NDK_R28C" \
        || status=$?
    if [ ! -f "$archive" ] || [ -L "$archive" ] || \
       [ "$(/usr/bin/sha256sum -- "$archive" | /usr/bin/awk '{print $1}')" != \
         "$SHA256_ANDROID_NDK_R28C" ]
    then
        echo "[FATAL] Android NDK archive changed during extraction" >&2
        output_status=1
    fi
    android_ndk_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
        android_ndk_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_android_ndk_output_staging \
        "$staging" "$staging_id" "$builder"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Android NDK output transaction lock"
    exec {lock_fd}<&-
    [ "$output_status" -eq 0 ] || die "Android NDK output postcondition failed"
    [ "$status" -eq 0 ] || die "Android NDK extractor failed"
    [ "$publication_status" -eq 0 ] || die "Android NDK publication failed"
    log "Android NDK checked and published without broad online write authority"
}

# ── The vcpkg-built arm64-android native codecs (R-R1 pinned overlay) ─────────────
# The android JNI lib (scrap + magnum-opus, cross-compiled by cargo-ndk for
# aarch64-linux-android) links the codecs STATICALLY from VCPKG_ROOT/installed/arm64-android.
# vcpkg's arm64-android triplet cross-compiles them with the NDK clang (ANDROID_NDK_HOME) — no
# host gcc-8 needed (ARM NEON, not x86 AVX2). CLASSIC mode (--overlay-ports + explicit ports),
# not manifest mode: manifest mode needs the vcpkg tree to be a git checkout (to resolve the
# builtin-baseline), but ./online/inputs stages the pinned TARBALL (no .git) — classic mode over the
# tarball baseline ports + the overlay is equivalent + git-free.
stage_vcpkg_natives_arm64() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 source_status=0 output_status=0 publication_status=0
    local lock_fd staging staging_id
    local output_args=()
    require_online_fetch_builder_image android-builder "$builder"
    require_libvpx_distfiles
    require_libyuv_distfile
    [ -d "$ONLINE_DIR/android-ndk/toolchains" ] || die "android NDK not extracted — stage_android_ndk must run first"
    verify_sha256 \
        "$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip" \
        "$SHA256_ANDROID_NDK_R28C"
    verify_sha256 \
        "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "$SHA256_VCPKG_120DEAC3"
    mapfile -d '' output_args < <(vcpkg_native_output_args arm64-android "$builder")
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for arm64-android vcpkg native serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another vcpkg native output transaction already owns the online root"
    recover_vcpkg_native_output_staging arm64-android "$builder"
    if [ -e "$ONLINE_DIR/vcpkg/installed/arm64-android" ] \
       || [ -L "$ONLINE_DIR/vcpkg/installed/arm64-android" ]; then
        vcpkg_native_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing arm64-android vcpkg native output is incomplete, stale, or unsafe"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the arm64-android vcpkg native transaction lock"
        exec {lock_fd}<&-
        log "arm64-android vcpkg native codecs already staged and structurally verified"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-vcpkg-native-arm64-android.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private arm64-android vcpkg native staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! vcpkg_native_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed arm64-android preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed arm64-android preparation left non-retirable private staging"
        die "cannot prepare private arm64-android vcpkg native staging"
    fi
    log "building the exact arm64-android vcpkg native consumer projection"
    online_docker_run \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$REPO_ROOT/res/vcpkg,target=/overlay,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$VCPKG_NATIVE_PRODUCER,target=/producer/build-vcpkg-native-output.sh,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/native" \
        --env RUSTDESK_VCPKG_BASELINE="$VCPKG_BASELINE" \
        --env RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        --env VCPKG_NATIVE_OUTPUT_KEY="$(checked_vcpkg_native_output_key arm64-android "$builder")" \
        --env LIBVPX_NATIVE_KEY="$(libvpx_native_key)" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /bin/bash --noprofile --norc \
            /producer/build-vcpkg-native-output.sh arm64-android \
        || status=$?
    verify_libvpx_source_authority "after arm64-android vcpkg native production" \
        || source_status=$?
    vcpkg_native_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ]; then
        vcpkg_native_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_vcpkg_native_output_staging \
        "$staging" "$staging_id" arm64-android "$builder"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the arm64-android vcpkg native transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "committed libvpx source changed during arm64-android native production"
    [ "$output_status" -eq 0 ] || die "arm64-android vcpkg native output postcondition failed"
    [ "$status" -eq 0 ] || die "arm64-android vcpkg native producer failed"
    [ "$publication_status" -eq 0 ] || die "arm64-android vcpkg native publication failed"
    log "arm64-android vcpkg natives checked and published (6 static libraries)"
}

# ── cargo-ndk (R-B7): the JNI cross-compile orchestrator, staged ───────────────────
# ndk_arm64.sh runs `cargo ndk ... build` to cross-compile librustdesk.so for android;
# cargo-ndk is NOT in the main cargo-vendor set, so `cargo install` it HERE (networked) in
# the android-builder image with the pinned rust — exactly as upstream's android job does
# (`cargo install cargo-ndk --version <pin> --locked`). A host-target tool → ./online/inputs/cargo-ndk-tool.
stage_cargo_ndk() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    stage_cargo_installed_tool cargo-ndk "$builder"
}

# ── The exact Android SDK archive closure ──────────────────────────────────────
# SDK package aliases are repository-resolution inputs, not content pins. Fetch seven
# exact Google archive names under independently recorded hashes, combine them with
# the already pinned command-line-tools archive, validate every ZIP member and output
# byte, then publish one sealed tree. The producer receives only two read-only files
# and two fresh private writable directories; it never sees online, the repository,
# Docker, a final name, or any host namespace/device/port.
android_sdk_output_tool() {
    /usr/bin/python3 -I -S "$SCRIPT_DIR/online-android-sdk-output.py" "$@"
}

android_sdk_output_args() {
    local builder="$1"
    printf '%s\0' \
        --cmdline-archive "$ONLINE_DIR/android-cmdline-tools.zip" \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --builder "$builder" \
        --package-pin "cmdline-tools=$SHA256_ANDROID_CMDLINE_TOOLS" \
        --package-pin "platform-tools=$SHA256_ANDROID_PLATFORM_TOOLS_37_0_1" \
        --package-pin "build-tools-30.0.3=$SHA256_ANDROID_BUILD_TOOLS_30_0_3" \
        --package-pin "build-tools-34.0.0=$SHA256_ANDROID_BUILD_TOOLS_34_0_0" \
        --package-pin "platform-31=$SHA256_ANDROID_PLATFORM_31" \
        --package-pin "platform-32=$SHA256_ANDROID_PLATFORM_32" \
        --package-pin "platform-33=$SHA256_ANDROID_PLATFORM_33" \
        --package-pin "platform-34=$SHA256_ANDROID_PLATFORM_34"
}

retire_android_sdk_output_staging() {
    local staging="$1" staging_id="$2" builder="$3" disposition
    local output_args=()
    mapfile -d '' output_args < <(android_sdk_output_args "$builder")
    disposition="$(
        android_sdk_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private Android SDK staging"
    log "Android SDK staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Android SDK staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Android SDK staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Android SDK staging survived retirement"
}

recover_android_sdk_output_staging() {
    local builder="$1"
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-android-sdk.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Android SDK staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_android_sdk_output_staging \
            "$staging" "$staging_id" "$builder"
    done
}

stage_android_sdk() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 output_status=0 publication_status=0
    local lock_fd staging staging_id
    local output_args=() container_pins=()
    local cmdline_archive="$ONLINE_DIR/android-cmdline-tools.zip"
    require_online_fetch_builder_image android-builder "$builder"
    [ -f "$cmdline_archive" ] && [ ! -L "$cmdline_archive" ] \
        || die "Android command-line-tools archive is absent or unsafe"
    verify_sha256 "$cmdline_archive" "$SHA256_ANDROID_CMDLINE_TOOLS"
    mapfile -d '' output_args < <(android_sdk_output_args "$builder")
    container_pins=(
        --package-pin "cmdline-tools=$SHA256_ANDROID_CMDLINE_TOOLS"
        --package-pin "platform-tools=$SHA256_ANDROID_PLATFORM_TOOLS_37_0_1"
        --package-pin "build-tools-30.0.3=$SHA256_ANDROID_BUILD_TOOLS_30_0_3"
        --package-pin "build-tools-34.0.0=$SHA256_ANDROID_BUILD_TOOLS_34_0_0"
        --package-pin "platform-31=$SHA256_ANDROID_PLATFORM_31"
        --package-pin "platform-32=$SHA256_ANDROID_PLATFORM_32"
        --package-pin "platform-33=$SHA256_ANDROID_PLATFORM_33"
        --package-pin "platform-34=$SHA256_ANDROID_PLATFORM_34"
    )
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Android SDK serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Android SDK transaction already owns the online root"
    recover_android_sdk_output_staging "$builder"
    if [ -e "$ONLINE_DIR/android-sdk" ] || [ -L "$ONLINE_DIR/android-sdk" ]; then
        android_sdk_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing Android SDK is incomplete, stale, or structurally unsafe; retire it explicitly before reacquisition"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Android SDK transaction lock"
        exec {lock_fd}<&-
        log "Android SDK already staged and exact-closure verified"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-android-sdk.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Android SDK staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! android_sdk_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Android SDK preparation left non-restorable staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed Android SDK preparation left non-retirable staging"
        die "cannot prepare private Android SDK staging"
    fi
    log "acquiring and composing the exact Android SDK archive closure"
    online_docker_run_archive_acquisition \
        --mount "type=bind,source=$cmdline_archive,target=/inputs/android-cmdline-tools.zip,readonly" \
        --mount "type=bind,source=$SCRIPT_DIR/online-android-sdk-output.py,target=/authority/online-android-sdk-output.py,readonly" \
        --mount "type=bind,source=$staging/downloads,target=/outputs/downloads" \
        --mount "type=bind,source=$staging/output,target=/outputs/sdk" \
        "$(online_fetch_builder_runtime_ref "$builder")" \
        /usr/bin/python3 -I -S \
        /authority/online-android-sdk-output.py acquire \
        --cmdline-archive /inputs/android-cmdline-tools.zip \
        --downloads /outputs/downloads \
        --output /outputs/sdk \
        "${container_pins[@]}" \
        || status=$?
    if [ ! -f "$cmdline_archive" ] || [ -L "$cmdline_archive" ] || \
       [ "$(/usr/bin/sha256sum -- "$cmdline_archive" | /usr/bin/awk '{print $1}')" != \
         "$SHA256_ANDROID_CMDLINE_TOOLS" ]
    then
        echo "[FATAL] Android command-line-tools archive changed during acquisition" >&2
        output_status=1
    fi
    android_sdk_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
        android_sdk_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_android_sdk_output_staging \
        "$staging" "$staging_id" "$builder"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Android SDK transaction lock"
    exec {lock_fd}<&-
    [ "$output_status" -eq 0 ] || die "Android SDK output postcondition failed"
    [ "$status" -eq 0 ] || die "Android SDK acquisition failed"
    [ "$publication_status" -eq 0 ] || die "Android SDK publication failed"
    log "Android SDK checked, sealed, and published without broad online authority"
}

# ── The warm gradle cache (R-B7): GRADLE_USER_HOME, populated by ONE online apk build ──
# `flutter build apk` drives gradle, which downloads the gradle distribution + the AGP/kotlin/
# plugin deps from google()/mavenCentral()/gradlePluginPortal(); the offline build_apk
# (--network=none) cannot. Populate the cache HERE (the ONE networked step) by running the SAME
# shared android build flow online (APK_MODE=warm, scripts/android-apk-build.sh). The producer
# writes one guest-local /outputs/gradle-home and never mounts the durable candidate. JVM archive
# inputs that cannot be safely memory-mapped through virtiofs are independently validated,
# guest-local projections of the exact SDK and Rustls Maven closures, nested read-only over /online.
# After the container terminates, the transaction revalidates those inputs and imports the quiescent
# output into private same-filesystem staging. build_apk later projects the Gradle cache into private
# writable execution state whose tracked init authority enables offline mode.
prepare_gradle_source() {
    local archive_attribute_status=0 invalid_tree_entry current
    if [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ]; then
        [ -d "$GRADLE_SOURCE_AUTHORITY" ] && [ ! -L "$GRADLE_SOURCE_AUTHORITY" ] \
            || die "retained exact source authority changed before reuse"
        [ -f "$GRADLE_SOURCE_ARCHIVE" ] && [ ! -L "$GRADLE_SOURCE_ARCHIVE" ] \
            || die "retained exact source archive changed before reuse"
        current="$(online_source_git rev-parse --verify 'HEAD^{commit}')" \
            || die "cannot re-resolve the exact Gradle-warm source commit"
        [ "$current" = "$GRADLE_SOURCE_COMMIT" ] \
            || die "the live source commit changed before exact-source reuse"
        current="$(online_source_git rev-parse --verify "${GRADLE_SOURCE_COMMIT}^{tree}")" \
            || die "cannot re-resolve the exact Gradle-warm source tree"
        [ "$current" = "$GRADLE_SOURCE_TREE" ] \
            || die "the live source tree changed before exact-source reuse"
        verify_clean_live_checkout_state "before exact-source reuse" \
            || die "exact-source reuse requires one clean canonical committed source tree"
        [ "$(/usr/bin/sha256sum "$GRADLE_SOURCE_ARCHIVE" | /usr/bin/awk '{print $1}')" \
           = "$GRADLE_SOURCE_ARCHIVE_SHA256" ] \
            || die "retained exact source archive changed before reuse"
        GRADLE_SOURCE_BUILD="$ONLINE_FETCH_TMP/gradle-source-build"
        [ ! -e "$GRADLE_SOURCE_BUILD" ] && [ ! -L "$GRADLE_SOURCE_BUILD" ] \
            || die "exact writable source path was not retired before reuse"
        /usr/bin/install -d -m 0700 "$GRADLE_SOURCE_BUILD"
        "$TAR_BIN" --extract --file="$GRADLE_SOURCE_ARCHIVE" \
            --directory="$GRADLE_SOURCE_BUILD" --no-same-owner --no-same-permissions \
            || die "cannot recreate the exact writable source"
        invalid_tree_entry="$(/usr/bin/find "$GRADLE_SOURCE_BUILD" \
            \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)" \
            || die "cannot inspect the recreated exact source"
        [ -z "$invalid_tree_entry" ] \
            || die "recreated exact source contains a symlink or special entry: $invalid_tree_entry"
        /usr/bin/chmod -R u=rwX,go=rX "$GRADLE_SOURCE_BUILD"
        GRADLE_SOURCE_BUILD_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_SOURCE_BUILD")"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-android-build-source.py" \
            --reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD" \
            || die "recreated writable source does not match its exact commit authority"
        return 0
    fi
    GRADLE_SOURCE_COMMIT="$(online_source_git rev-parse --verify 'HEAD^{commit}')" \
        || die "cannot resolve the exact Gradle-warm source commit"
    GRADLE_SOURCE_TREE="$(online_source_git rev-parse --verify "${GRADLE_SOURCE_COMMIT}^{tree}")" \
        || die "cannot resolve the exact Gradle-warm source tree"
    [[ "$GRADLE_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] \
        || die "Gradle-warm source commit ID is malformed"
    [[ "$GRADLE_SOURCE_TREE" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] \
        || die "Gradle-warm source tree ID is malformed"
    verify_clean_live_checkout_state "before Gradle warming" \
        || die "Gradle warming requires one clean canonical committed source tree"
    invalid_tree_entry="$(
        online_source_git ls-tree -rz --full-tree "$GRADLE_SOURCE_COMMIT" \
            | /usr/bin/python3 -I -S -c '
import sys

for entry in sys.stdin.buffer.read().split(b"\0"):
    if not entry:
        continue
    metadata, path = entry.split(b"\t", 1)
    mode = metadata.split(b" ", 1)[0]
    if mode not in (b"100644", b"100755"):
        print("{} {}".format(mode.decode("ascii", "replace"), path.decode("utf-8", "replace")))
        break
'
    )" || die "cannot inspect the exact Gradle-warm source tree"
    [ -z "$invalid_tree_entry" ] \
        || die "Gradle-warm source commit contains a symlink or special entry: $invalid_tree_entry"
    if online_source_git grep -q -E 'export-(ignore|subst)' \
        "$GRADLE_SOURCE_COMMIT" -- .gitattributes '**/.gitattributes'
    then
        die "Gradle-warm source commit contains an archive-transforming Git attribute"
    else
        archive_attribute_status=$?
        [ "$archive_attribute_status" -eq 1 ] \
            || die "cannot inspect Gradle-warm source archive attributes"
    fi

    GRADLE_SOURCE_ARCHIVE="$ONLINE_FETCH_TMP/gradle-source.tar"
    GRADLE_SOURCE_AUTHORITY="$ONLINE_FETCH_TMP/gradle-source-authority"
    GRADLE_SOURCE_BUILD="$ONLINE_FETCH_TMP/gradle-source-build"
    [ ! -e "$GRADLE_SOURCE_ARCHIVE" ] && [ ! -L "$GRADLE_SOURCE_ARCHIVE" ] \
        || die "Gradle source archive path was not freshly absent"
    /usr/bin/install -d -m 0700 "$GRADLE_SOURCE_AUTHORITY" "$GRADLE_SOURCE_BUILD"
    online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT" >"$GRADLE_SOURCE_ARCHIVE" \
        || die "cannot archive the exact Gradle-warm source commit"
    [ -s "$GRADLE_SOURCE_ARCHIVE" ] && [ ! -L "$GRADLE_SOURCE_ARCHIVE" ] \
        || die "Gradle source archive is missing or invalid"
    /usr/bin/chmod 0400 "$GRADLE_SOURCE_ARCHIVE"
    GRADLE_SOURCE_ARCHIVE_SHA256="$(
        /usr/bin/sha256sum "$GRADLE_SOURCE_ARCHIVE" | /usr/bin/awk '{print $1}'
    )"
    "$TAR_BIN" --extract --file="$GRADLE_SOURCE_ARCHIVE" \
        --directory="$GRADLE_SOURCE_AUTHORITY" --no-same-owner --no-same-permissions \
        || die "cannot extract the Gradle source authority"
    "$TAR_BIN" --extract --file="$GRADLE_SOURCE_ARCHIVE" \
        --directory="$GRADLE_SOURCE_BUILD" --no-same-owner --no-same-permissions \
        || die "cannot extract the Gradle writable source"
    invalid_tree_entry="$(/usr/bin/find "$GRADLE_SOURCE_AUTHORITY" "$GRADLE_SOURCE_BUILD" \
        \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)" \
        || die "cannot inspect the Gradle source snapshots"
    [ -z "$invalid_tree_entry" ] \
        || die "Gradle source snapshot contains a symlink or special entry: $invalid_tree_entry"
    /usr/bin/chmod -R a=rX "$GRADLE_SOURCE_AUTHORITY"
    /usr/bin/chmod -R u=rwX,go=rX "$GRADLE_SOURCE_BUILD"
    GRADLE_SOURCE_BUILD_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_SOURCE_BUILD")"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-android-build-source.py" \
        --reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD" \
        || die "Gradle writable source does not match its exact commit authority"
}

verify_gradle_source_unchanged() {
    local after_archive="$ONLINE_FETCH_TMP/gradle-source-after.tar" current status=0
    if ! /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-android-build-source.py" \
        --reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD" --allow-extras
    then
        echo "[FATAL] networked Gradle warming changed a committed source input" >&2
        status=1
    fi
    if current="$(online_source_git rev-parse --verify 'HEAD^{commit}')"; then
        if [ "$current" != "$GRADLE_SOURCE_COMMIT" ]; then
            echo "[FATAL] the live source commit changed during Gradle warming" >&2
            status=1
        fi
    else
        echo "[FATAL] cannot re-resolve the Gradle-warm source commit" >&2
        status=1
    fi
    if current="$(online_source_git rev-parse --verify "${GRADLE_SOURCE_COMMIT}^{tree}")"; then
        if [ "$current" != "$GRADLE_SOURCE_TREE" ]; then
            echo "[FATAL] the live source tree changed during Gradle warming" >&2
            status=1
        fi
    else
        echo "[FATAL] cannot re-resolve the Gradle-warm source tree" >&2
        status=1
    fi
    if ! verify_clean_live_checkout_state "after Gradle warming"; then
        status=1
    fi
    if [ -e "$after_archive" ] || [ -L "$after_archive" ]; then
        echo "[FATAL] Gradle source postcondition archive path was not freshly absent" >&2
        status=1
    elif online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT" >"$after_archive"; then
        if [ "$(/usr/bin/sha256sum "$after_archive" | /usr/bin/awk '{print $1}')" != "$GRADLE_SOURCE_ARCHIVE_SHA256" ]; then
            echo "[FATAL] Gradle source commit archive changed during warming" >&2
            status=1
        fi
        /usr/bin/rm -f -- "$after_archive"
    else
        echo "[FATAL] cannot rearchive the exact Gradle-warm source commit" >&2
        status=1
    fi
    return "$status"
}

retire_gradle_source_build() {
    [ -d "$GRADLE_SOURCE_BUILD" ] && [ ! -L "$GRADLE_SOURCE_BUILD" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_SOURCE_BUILD")" = "$GRADLE_SOURCE_BUILD_ID" ] \
        || die "private Gradle writable source identity changed before retirement"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$GRADLE_SOURCE_BUILD" \
        --expected-identity "$GRADLE_SOURCE_BUILD_ID" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Gradle source directory traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$GRADLE_SOURCE_BUILD" \
        --expected-identity "$GRADLE_SOURCE_BUILD_ID" \
        || die "cannot retire the private Gradle writable source"
    [ ! -e "$GRADLE_SOURCE_BUILD" ] && [ ! -L "$GRADLE_SOURCE_BUILD" ] \
        || die "private Gradle writable source survived retirement"
    GRADLE_SOURCE_BUILD=""
}

gradle_output_tool() {
    [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ] \
        || die "Gradle output authority requires the exact source snapshot"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/online-gradle-output.py" "$@"
}

gradle_output_semantic_args() {
    printf '%s\0' \
        --gradle-version "$ANDROID_GRADLE_WRAPPER" \
        --gradle-sha256 "$SHA256_ANDROID_GRADLE_WRAPPER_ALL" \
        --build-tools "$ANDROID_BUILD_TOOLS" \
        --compile-sdk "$ANDROID_COMPILE_SDK"
}

retire_gradle_output_staging() {
    local staging="$1" staging_id="$2" disposition archived
    disposition="$(
        gradle_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
    )" || die "cannot reconcile private Gradle output staging"
    log "Gradle output staging reconciliation: $disposition"
    if [ "$disposition" = replaced ] || [ "$disposition" = replaced-staged ]; then
        prepare_retired_online_input_root
        archived="$(
            gradle_output_tool archive-replaced \
                --online "$ONLINE_DIR" --staging "$staging" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
        )" || die "cannot archive the completed Gradle replacement record"
        [ -d "$archived" ] && [ ! -L "$archived" ] \
            || die "Gradle replacement-record archive is not one real directory"
        [ ! -e "$staging" ] && [ ! -L "$staging" ] \
            || die "Gradle replacement-record archival left online staging"
        retire_archived_online_input "$archived" "completed Gradle replacement"
        retire_empty_online_input_root
        log "Displaced Gradle output and its completed replacement record were exactly retired"
        return 0
    fi
    case "$disposition" in
        unpublished|published|unselected-while-occupied|replacement-prepared) ;;
        *) die "unknown Gradle output reconciliation disposition: $disposition" ;;
    esac
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Gradle output staging traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Gradle output staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Gradle output staging survived retirement"
    retire_empty_online_input_root_if_present
}

recover_gradle_output_staging() {
    local stale=() staging staging_id
    reconcile_retired_online_input_archives
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name '.rustdesk-gradle-warm.*' -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Gradle output staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_gradle_output_staging "$staging" "$staging_id"
    done
}

prepare_gradle_output_staging() {
    local semantic_args=("$@")
    GRADLE_OUTPUT_STAGING="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-gradle-warm.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Gradle output staging"
    GRADLE_OUTPUT_STAGING_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_OUTPUT_STAGING")"
    readonly GRADLE_OUTPUT_STAGING GRADLE_OUTPUT_STAGING_ID
    if ! gradle_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${semantic_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
            --root "$GRADLE_OUTPUT_STAGING" \
            --expected-identity "$GRADLE_OUTPUT_STAGING_ID" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Gradle output preparation left non-restorable private staging"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
            --remove-private-root "$GRADLE_OUTPUT_STAGING" \
            --expected-identity "$GRADLE_OUTPUT_STAGING_ID" \
            || die "failed Gradle output preparation left non-retirable private staging"
        die "cannot prepare private Gradle output staging"
    fi
    GRADLE_OUTPUT_CACHE_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$GRADLE_OUTPUT_STAGING/gradle-home"
    )"
    readonly GRADLE_OUTPUT_CACHE_ID
}

restore_gradle_output_traversal() {
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$GRADLE_OUTPUT_STAGING/gradle-home" \
        --expected-identity "$GRADLE_OUTPUT_CACHE_ID" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Gradle cache output traversal"
}

prepare_gradle_producer_output() {
    GRADLE_PRODUCER_OUTPUT="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_FETCH_TMP/gradle-producer.XXXXXXXXXX"
    )" || die "cannot create private guest-local Gradle producer output"
    GRADLE_PRODUCER_OUTPUT_ID="$(
        /usr/bin/stat -c '%d:%i' -- "$GRADLE_PRODUCER_OUTPUT"
    )" || die "cannot identify private guest-local Gradle producer output"
    [ "${GRADLE_PRODUCER_OUTPUT_ID%%:*}" != "$(/usr/bin/stat -c '%d' -- "$ONLINE_DIR")" ] \
        || die "Gradle producer output is not guest-local storage"
    readonly GRADLE_PRODUCER_OUTPUT GRADLE_PRODUCER_OUTPUT_ID
}

rewrite_android_sdk_cmdline_archive_arg() {
    local output_name="$1" replacement="$2"
    shift 2
    local -n output_arguments="$output_name"
    local index found=0
    output_arguments=("$@")
    for ((index = 0; index < ${#output_arguments[@]}; index++)); do
        if [ "${output_arguments[$index]}" = --cmdline-archive ]; then
            [ "$found" -eq 0 ] \
                || die "Android SDK arguments contain duplicate command-line archive options"
            [ "$((index + 1))" -lt "${#output_arguments[@]}" ] \
                || die "Android SDK command-line archive option has no value"
            output_arguments[$((index + 1))]="$replacement"
            found=1
            index=$((index + 1))
        fi
    done
    [ "$found" -eq 1 ] \
        || die "Android SDK arguments omit the command-line archive option"
}

prepare_gradle_jvm_input_projections() {
    local sdk_args=("$@")
    local projected_sdk_args=()
    local maven_relative="cargo-vendor/rustls-platform-verifier-android-0.1.1/maven"
    local online_device
    online_device="$(/usr/bin/stat -c '%d' -- "$ONLINE_DIR")" \
        || die "cannot identify the canonical online-input filesystem"
    GRADLE_SDK_PROJECTION_ROOT="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_FETCH_TMP/gradle-sdk-projection.XXXXXXXXXX"
    )" || die "cannot create guest-local Android SDK projection root"
    GRADLE_MAVEN_PROJECTION_ROOT="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_FETCH_TMP/gradle-maven-projection.XXXXXXXXXX"
    )" || die "cannot create guest-local Maven projection root"
    GRADLE_SDK_PROJECTION="$GRADLE_SDK_PROJECTION_ROOT/android-sdk"
    GRADLE_SDK_PROJECTED_CMDLINE_ARCHIVE="$GRADLE_SDK_PROJECTION_ROOT/android-cmdline-tools.zip"
    GRADLE_MAVEN_SOURCE="$ONLINE_DIR/$maven_relative"
    GRADLE_MAVEN_PROJECTION="$GRADLE_MAVEN_PROJECTION_ROOT/maven"
    /usr/bin/cp --recursive --no-dereference --preserve=mode,timestamps \
        --no-preserve=ownership,xattr \
        -- "$ONLINE_DIR/android-sdk" "$GRADLE_SDK_PROJECTION" \
        || die "cannot project the exact Android SDK onto guest-local storage"
    /usr/bin/cp --no-dereference --preserve=mode,timestamps \
        --no-preserve=ownership,xattr \
        -- "$ONLINE_DIR/android-cmdline-tools.zip" "$GRADLE_SDK_PROJECTED_CMDLINE_ARCHIVE" \
        || die "cannot project the Android command-line-tools archive onto guest-local storage"
    /usr/bin/cp --recursive --no-dereference --preserve=mode,timestamps \
        --no-preserve=ownership,xattr \
        -- "$GRADLE_MAVEN_SOURCE" "$GRADLE_MAVEN_PROJECTION" \
        || die "cannot project the exact Android Maven repository onto guest-local storage"
    GRADLE_SDK_PROJECTION_ROOT_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_SDK_PROJECTION_ROOT")"
    GRADLE_SDK_PROJECTION_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_SDK_PROJECTION")"
    GRADLE_MAVEN_PROJECTION_ROOT_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_MAVEN_PROJECTION_ROOT")"
    GRADLE_MAVEN_SOURCE_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_MAVEN_SOURCE")"
    GRADLE_MAVEN_PROJECTION_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_MAVEN_PROJECTION")"
    [ "${GRADLE_SDK_PROJECTION_ID%%:*}" != "$online_device" ] \
        && [ "${GRADLE_MAVEN_PROJECTION_ID%%:*}" != "$online_device" ] \
        || die "Gradle JVM input projection is not guest-local storage"
    readonly GRADLE_SDK_PROJECTION_ROOT GRADLE_SDK_PROJECTION \
        GRADLE_SDK_PROJECTED_CMDLINE_ARCHIVE \
        GRADLE_SDK_PROJECTION_ROOT_ID GRADLE_SDK_PROJECTION_ID \
        GRADLE_MAVEN_PROJECTION_ROOT GRADLE_MAVEN_SOURCE GRADLE_MAVEN_PROJECTION \
        GRADLE_MAVEN_PROJECTION_ROOT_ID GRADLE_MAVEN_SOURCE_ID GRADLE_MAVEN_PROJECTION_ID
    rewrite_android_sdk_cmdline_archive_arg \
        projected_sdk_args "$GRADLE_SDK_PROJECTED_CMDLINE_ARCHIVE" "${sdk_args[@]}"
    android_sdk_output_tool check-complete \
        --online "$GRADLE_SDK_PROJECTION_ROOT" "${projected_sdk_args[@]}" \
        || die "guest-local Android SDK projection differs from its canonical closure"
    verify_gradle_maven_projection \
        || die "guest-local Android Maven projection differs from its canonical closure"
}

verify_gradle_maven_projection() {
    local source_device source_inode projection_device projection_inode
    IFS=: read -r source_device source_inode <<<"$GRADLE_MAVEN_SOURCE_ID"
    IFS=: read -r projection_device projection_inode <<<"$GRADLE_MAVEN_PROJECTION_ID"
    gradle_output_tool verify-maven-projection \
        --source "$GRADLE_MAVEN_SOURCE" --projection "$GRADLE_MAVEN_PROJECTION" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        --source-device "$source_device" --source-inode "$source_inode" \
        --projection-device "$projection_device" --projection-inode "$projection_inode"
}

verify_gradle_jvm_input_projections() {
    local sdk_args=("$@")
    local projected_sdk_args=()
    rewrite_android_sdk_cmdline_archive_arg \
        projected_sdk_args "$GRADLE_SDK_PROJECTED_CMDLINE_ARCHIVE" "${sdk_args[@]}"
    android_sdk_output_tool check-complete \
        --online "$ONLINE_DIR" "${sdk_args[@]}" \
        || return 1
    android_sdk_output_tool check-complete \
        --online "$GRADLE_SDK_PROJECTION_ROOT" "${projected_sdk_args[@]}" \
        || return 1
    verify_gradle_maven_projection >/dev/null
}

retire_gradle_jvm_input_projections() {
    local root root_id label
    for root in "$GRADLE_SDK_PROJECTION_ROOT" "$GRADLE_MAVEN_PROJECTION_ROOT"; do
        if [ "$root" = "$GRADLE_SDK_PROJECTION_ROOT" ]; then
            root_id="$GRADLE_SDK_PROJECTION_ROOT_ID"
            label="Android SDK projection"
        else
            root_id="$GRADLE_MAVEN_PROJECTION_ROOT_ID"
            label="Android Maven projection"
        fi
        [ -d "$root" ] && [ ! -L "$root" ] \
            && [ "$(/usr/bin/stat -c '%d:%i' -- "$root")" = "$root_id" ] \
            || die "$label root identity changed before retirement"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
            --root "$root" --expected-identity "$root_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "cannot restore $label traversal"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
            --remove-private-root "$root" --expected-identity "$root_id" \
            || die "cannot retire guest-local $label"
        [ ! -e "$root" ] && [ ! -L "$root" ] \
            || die "guest-local $label survived retirement"
    done
}

retire_gradle_producer_output() {
    [ -d "$GRADLE_PRODUCER_OUTPUT" ] && [ ! -L "$GRADLE_PRODUCER_OUTPUT" ] \
        && [ "$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_PRODUCER_OUTPUT")" = "$GRADLE_PRODUCER_OUTPUT_ID" ] \
        || die "guest-local Gradle producer-output identity changed before retirement"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$GRADLE_PRODUCER_OUTPUT" \
        --expected-identity "$GRADLE_PRODUCER_OUTPUT_ID" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore guest-local Gradle producer-output traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$GRADLE_PRODUCER_OUTPUT" \
        --expected-identity "$GRADLE_PRODUCER_OUTPUT_ID" \
        || die "cannot retire guest-local Gradle producer output"
    [ ! -e "$GRADLE_PRODUCER_OUTPUT" ] && [ ! -L "$GRADLE_PRODUCER_OUTPUT" ] \
        || die "guest-local Gradle producer output survived retirement"
}

stage_gradle() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 source_status=0 jvm_input_status=0 producer_status=0 import_status=0 output_status=0 publication_status=0
    local lock_fd semantic_args=() sdk_args=()
    local producer_receipt="" producer_receipt_after="" receipt="" digest="" current=0 replace_existing=0
    local producer_device="" producer_inode=""
    require_online_fetch_builder_image android-builder "$builder"
    assert_online_fetch_source_tools
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Gradle output serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Gradle output transaction already owns the online root"
    [ -d "$ONLINE_DIR/android-sdk/build-tools" ] || die "android SDK not staged — stage_android_sdk must run first"
    [ -d "$ONLINE_DIR/vcpkg/installed/arm64-android" ] || die "arm64-android vcpkg not staged — stage_vcpkg_natives_arm64 must run first"
    [ -x "$ONLINE_DIR/cargo-ndk-tool/bin/cargo-ndk" ] || die "cargo-ndk not staged — stage_cargo_ndk must run first"
    prepare_gradle_source
    recover_gradle_output_staging
    mapfile -d '' semantic_args < <(gradle_output_semantic_args)
    mapfile -d '' sdk_args < <(android_sdk_output_args "$builder")
    android_sdk_output_tool check-complete \
        --online "$ONLINE_DIR" "${sdk_args[@]}" \
        || die "exact Android SDK input is incomplete, stale, or unsafe"
    if [ -e "$ONLINE_DIR/gradle-home" ] || [ -L "$ONLINE_DIR/gradle-home" ]; then
        if gradle_output_tool check-complete \
            --online "$ONLINE_DIR" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}"
        then
            current=1
        else
            replace_existing=1
            log "existing Gradle cache is stale or semantically incomplete; preparing one verified replacement"
        fi
    fi
    if [ "$current" -eq 1 ]; then
        retire_gradle_source_build
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Gradle output transaction lock"
        exec {lock_fd}<&-
        log "gradle cache already warm and semantically verified, skipping"
        return 0
    fi
    prepare_gradle_output_staging "${semantic_args[@]}"
    prepare_gradle_jvm_input_projections "${sdk_args[@]}"
    prepare_gradle_producer_output
    IFS=: read -r producer_device producer_inode <<<"$GRADLE_PRODUCER_OUTPUT_ID"
    [[ "$producer_device" =~ ^[0-9]+$ ]] && [[ "$producer_inode" =~ ^[1-9][0-9]*$ ]] \
        || die "guest-local Gradle producer-output identity is malformed"
    log "warming Gradle into guest-local private output; the durable candidate, exact SDK, and ./online/inputs remain outside producer write authority"
    online_docker_run \
        --env APK_MODE=warm \
        --env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home \
        --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
        --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
        --mount "type=bind,source=$GRADLE_SOURCE_BUILD,target=/src" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_SDK_PROJECTION,target=/online/android-sdk,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_MAVEN_PROJECTION,target=/online/cargo-vendor/rustls-platform-verifier-android-0.1.1/maven,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_PRODUCER_OUTPUT,target=/outputs/gradle-home" \
        --workdir /src \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc /authority/android-apk-build.sh \
        || status=$?
    (verify_gradle_source_unchanged) || source_status=$?
    retire_gradle_source_build
    verify_gradle_jvm_input_projections "${sdk_args[@]}" || jvm_input_status=$?
    retire_gradle_jvm_input_projections
    producer_receipt="$(
        gradle_output_tool verify-producer \
            --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
            --producer-output "$GRADLE_PRODUCER_OUTPUT" \
            --producer-device "$producer_device" --producer-inode "$producer_inode" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}"
    )" || producer_status=$?
    if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
        && [ "$jvm_input_status" -eq 0 ] && [ "$producer_status" -eq 0 ]; then
        if /usr/bin/find "$GRADLE_OUTPUT_STAGING/gradle-home" -mindepth 1 -print -quit \
            | /usr/bin/grep -q .
        then
            echo "[FATAL] durable Gradle candidate was not empty before trusted import" >&2
            import_status=1
        else
            /usr/bin/cp --recursive --no-dereference --preserve=mode,timestamps \
                --no-preserve=ownership,xattr \
                -- "$GRADLE_PRODUCER_OUTPUT"/. "$GRADLE_OUTPUT_STAGING/gradle-home"/ \
                || import_status=$?
        fi
    else
        import_status=1
    fi
    producer_receipt_after="$(
        gradle_output_tool verify-producer \
            --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
            --producer-output "$GRADLE_PRODUCER_OUTPUT" \
            --producer-device "$producer_device" --producer-inode "$producer_inode" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}"
    )" || producer_status=$?
    if [ "$producer_receipt" != "$producer_receipt_after" ]; then
        echo "[FATAL] guest-local Gradle producer output changed across trusted import" >&2
        producer_status=1
    fi
    retire_gradle_producer_output
    restore_gradle_output_traversal
    receipt="$(
        gradle_output_tool verify \
            --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}"
    )" || output_status=$?
    if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then
        digest="${BASH_REMATCH[1]}"
    else
        output_status=1
    fi
    if [ "$receipt" != "$producer_receipt" ]; then
        echo "[FATAL] durable Gradle candidate differs from the validated guest-local producer output" >&2
        output_status=1
    fi
    if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
        && [ "$jvm_input_status" -eq 0 ] \
        && [ "$producer_status" -eq 0 ] && [ "$import_status" -eq 0 ] \
        && [ "$output_status" -eq 0 ]; then
        if [ "$replace_existing" -eq 1 ]; then
            prepare_retired_online_input_root
            gradle_output_tool replace \
                --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
                --retired-root "$RETIRED_ONLINE_INPUT_ROOT" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${semantic_args[@]}" \
                --expected-digest "$digest" \
                || publication_status=$?
        else
            gradle_output_tool publish \
                --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${semantic_args[@]}" \
                --expected-digest "$digest" \
                || publication_status=$?
        fi
    fi
    retire_gradle_output_staging "$GRADLE_OUTPUT_STAGING" "$GRADLE_OUTPUT_STAGING_ID"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Gradle output transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"
    [ "$jvm_input_status" -eq 0 ] || die "networked Gradle JVM-input projection postcondition failed"
    [ "$producer_status" -eq 0 ] || die "networked Gradle producer-output postcondition failed"
    [ "$import_status" -eq 0 ] || die "networked Gradle trusted import failed"
    [ "$output_status" -eq 0 ] || die "networked Gradle output postcondition failed"
    [ "$status" -eq 0 ] || die "networked Gradle warming failed"
    [ "$publication_status" -eq 0 ] || die "networked Gradle output publication failed"
    log "gradle cache warmed ($(du -sh "$ONLINE_DIR/gradle-home" 2>/dev/null | cut -f1))"
}

# ── The windows flutter ENGINE (precache --windows): ~780MB of windows-x64{,-profile,-release} ──
windows_engine_output_tool() {
    /usr/bin/python3 -I -S "$WINDOWS_ENGINE_OUTPUT_HELPER" "$@"
}

windows_engine_output_args() {
    printf '%s\0' \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --flutter-version "$FLUTTER_VERSION" \
        --builder "$ANDROID_BUILDER_CONFIG_ID" \
        --source-sha256 "$SHA256_FLUTTER_3_24_5" \
        --sha256 "$SHA256_FLUTTER_WIN_ENGINE" \
        --size "$SIZE_FLUTTER_WIN_ENGINE"
}

verify_windows_engine_source() {
    local phase="$1"
    local source="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
    [ -f "$source" ] && [ ! -L "$source" ] \
        || die "$phase: Flutter source archive is not one real file"
    [ "$(/usr/bin/stat -c '%s' -- "$source")" = "$SIZE_FLUTTER_3_24_5" ] \
        || die "$phase: Flutter source archive length changed"
    verify_sha256 "$source" "$SHA256_FLUTTER_3_24_5"
}

retire_windows_engine_staging() {
    local staging="$1" staging_id="$2" disposition
    local output_args=()
    mapfile -d '' output_args < <(windows_engine_output_args)
    disposition="$(
        windows_engine_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private Windows-engine staging"
    log "Windows-engine staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Windows-engine staging traversal"
    /usr/bin/python3 -I -S \
        "$LIB_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Windows-engine staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Windows-engine staging survived retirement"
}

recover_windows_engine_staging() {
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-windows-engine.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Windows-engine staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_windows_engine_staging "$staging" "$staging_id"
    done
}

# ── The Windows Flutter engine (`precache --windows`): 817,399,293 bytes ────────
# The §12.2 golden provision's in-VM download stalls over guest slirp NAT, so the
# exact Flutter 3.24.5 Linux SDK acquires the host-independent Windows engine here.
# The networked tool sees the source archive read-only and one private output inode
# writable. It never sees the online root or the durable output name. An independent
# networkless process verifies the exact digest and closed 73-file tar contract
# before descriptor-relative, durable, no-clobber publication.
stage_windows_engine() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 source_status=0 output_status=0 semantic_status=0
    local publication_status=0 lock_fd staging staging_id
    local source="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
    local destination="$ONLINE_DIR/flutter-windows-engine.tar.gz"
    local output_args=()
    require_online_fetch_builder_image android-builder "$builder"
    [ -f "$WINDOWS_ENGINE_OUTPUT_HELPER" ] \
        && [ ! -L "$WINDOWS_ENGINE_OUTPUT_HELPER" ] \
        || die "Windows-engine output helper is not one real source file"
    (verify_windows_engine_source "before Windows-engine transaction")
    mapfile -d '' output_args < <(windows_engine_output_args)
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Windows-engine serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another online-output transaction already owns the online root"
    recover_windows_engine_staging
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        windows_engine_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing Windows-engine archive is incomplete or unsafe"
        (verify_windows_engine_source "after Windows-engine occupied-output validation")
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Windows-engine transaction lock"
        exec {lock_fd}<&-
        log "Windows Flutter engine already staged and exactly validated"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-windows-engine.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Windows-engine staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! windows_engine_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$LIB_DIR/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Windows-engine preparation left non-restorable staging"
        /usr/bin/python3 -I -S \
            "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed Windows-engine preparation left non-retirable staging"
        die "cannot prepare private Windows-engine staging"
    fi
    log "acquiring the pinned Windows Flutter engine into one private output"
    online_docker_run \
        --env FLUTTER_VERSION="$FLUTTER_VERSION" \
        --env SHA256_FLUTTER_WIN_ENGINE="$SHA256_FLUTTER_WIN_ENGINE" \
        --env SIZE_FLUTTER_WIN_ENGINE="$SIZE_FLUTTER_WIN_ENGINE" \
        --mount "type=bind,source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/engine.tar.gz" \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
            umask 077
            /usr/bin/mkdir -p /tmp/toolchain /tmp/home
            /usr/bin/tar -C /tmp/toolchain -xf /inputs/flutter.tar.xz
            export HOME=/tmp/home
            export CI=true
            export FLUTTER_SUPPRESS_ANALYTICS=true
            export GIT_CONFIG_NOSYSTEM=1
            export GIT_CONFIG_GLOBAL=/dev/null
            export GIT_ATTR_NOSYSTEM=1
            export GIT_NO_REPLACE_OBJECTS=1
            export GIT_OPTIONAL_LOCKS=0
            export PATH=/tmp/toolchain/flutter/bin:/tmp/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin
            cd /tmp/toolchain/flutter
            flutter precache --windows >/dev/null
            {
                /usr/bin/find \
                    bin/cache/artifacts/engine/windows-x64 \
                    bin/cache/artifacts/engine/windows-x64-profile \
                    bin/cache/artifacts/engine/windows-x64-release \
                    -type f -print
                /usr/bin/printf "%s\n" \
                    bin/cache/libimobiledevice.stamp \
                    bin/cache/usbmuxd.stamp \
                    bin/cache/windows-sdk.stamp
            } | /usr/bin/sort -u > /tmp/stage.txt
            [ "$(/usr/bin/wc -l < /tmp/stage.txt)" -eq 73 ] || {
                echo "precache output does not match the exact 73-file Windows projection: got $(/usr/bin/wc -l < /tmp/stage.txt) (debug=$(/usr/bin/find bin/cache/artifacts/engine/windows-x64 -type f -print | /usr/bin/wc -l), profile=$(/usr/bin/find bin/cache/artifacts/engine/windows-x64-profile -type f -print | /usr/bin/wc -l), release=$(/usr/bin/find bin/cache/artifacts/engine/windows-x64-release -type f -print | /usr/bin/wc -l))" >&2
                exit 1
            }
            /usr/bin/find \
                bin/cache/artifacts/engine/windows-x64 \
                bin/cache/artifacts/engine/windows-x64-profile \
                bin/cache/artifacts/engine/windows-x64-release \
                -type f -exec /usr/bin/chmod 0666 {} +
            /usr/bin/chmod 0644 \
                bin/cache/artifacts/engine/windows-x64/gen_snapshot.exe \
                bin/cache/artifacts/engine/windows-x64-profile/gen_snapshot.exe \
                bin/cache/artifacts/engine/windows-x64-release/gen_snapshot.exe \
                bin/cache/libimobiledevice.stamp \
                bin/cache/usbmuxd.stamp \
                bin/cache/windows-sdk.stamp
            /usr/bin/tar --sort=name --mtime=@1700000000 \
                --owner=0 --group=0 --numeric-owner \
                -cf - -T /tmp/stage.txt \
                | /usr/bin/gzip -n -9 \
                | /usr/bin/python3 -c "import os
import sys
limit = int(os.environ[\"SIZE_FLUTTER_WIN_ENGINE\"])
written = 0
while True:
    block = sys.stdin.buffer.read(1024 * 1024)
    if not block:
        break
    if written + len(block) > limit:
        raise SystemExit(\"Windows engine output exceeded its byte bound\")
    sys.stdout.buffer.write(block)
    written += len(block)
if written != limit:
    raise SystemExit(\"Windows engine output length differs from its pin\")
" > /outputs/engine.tar.gz
            got="$(
                /usr/bin/sha256sum /outputs/engine.tar.gz \
                    | /usr/bin/cut -d" " -f1
            )"
            [ "$got" = "$SHA256_FLUTTER_WIN_ENGINE" ] || {
                echo "Windows engine SHA-256 mismatch: got $got" >&2
                exit 1
            }
        ' || status=$?
    (verify_windows_engine_source "after Windows-engine producer") \
        || source_status=$?
    windows_engine_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] \
       && [ "$source_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ]; then
        online_docker_run_offline \
            --mount "type=bind,source=$WINDOWS_ENGINE_OUTPUT_HELPER,target=/authority/online-windows-engine-output.py,readonly,bind-recursive=disabled" \
            --mount "type=bind,source=$staging/output,target=/inputs/engine.tar.gz,readonly,bind-recursive=disabled" \
            "$(online_fetch_builder_runtime_ref "$builder")" /usr/bin/python3 -I -S \
                /authority/online-windows-engine-output.py verify-archive \
                --archive /inputs/engine.tar.gz \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                --sha256 "$SHA256_FLUTTER_WIN_ENGINE" \
                --size "$SIZE_FLUTTER_WIN_ENGINE" \
                || semantic_status=$?
    else
        semantic_status=1
    fi
    (verify_windows_engine_source "after Windows-engine semantic validation") \
        || source_status=$?
    if [ "$status" -eq 0 ] \
       && [ "$source_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ] \
       && [ "$semantic_status" -eq 0 ]; then
        windows_engine_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_windows_engine_staging "$staging" "$staging_id"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Windows-engine transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "Windows-engine source postcondition failed"
    [ "$output_status" -eq 0 ] || die "Windows-engine output postcondition failed"
    [ "$status" -eq 0 ] || die "Windows-engine acquisition producer failed"
    [ "$semantic_status" -eq 0 ] || die "Windows-engine semantic replay failed"
    [ "$publication_status" -eq 0 ] || die "Windows-engine publication failed"
    log "Windows Flutter engine acquired, independently validated, and checked-published"
}

# ── The Windows flutter_tools Pub cache (§12.2): exact hosted closure ───────────
flutter_pub_cache_output_tool() {
    [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ] \
        || die "Flutter Pub-cache output authority requires the exact source snapshot"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py" "$@"
}

flutter_pub_cache_output_args() {
    local source_digest="$1"
    printf '%s\0' \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --flutter-version "$FLUTTER_VERSION" \
        --builder "$ANDROID_BUILDER_CONFIG_ID" \
        --source-digest "$source_digest" \
        --flutter-source-sha256 "$SHA256_FLUTTER_3_24_5" \
        --flutter-tools-lock-sha256 "$SHA256_FLUTTER_TOOLS_LOCK" \
        --sha256 "$SHA256_FLUTTER_PUB_CACHE" \
        --size "$SIZE_FLUTTER_PUB_CACHE"
}

verify_flutter_pub_cache_source() {
    local phase="$1" receipt
    receipt="$(
        pub_cache_output_tool check-complete \
            --online "$ONLINE_DIR" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
    )" || die "$phase: Pub-cache source projection is incomplete or unsafe"
    if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    else
        die "$phase: Pub-cache source validator returned a malformed receipt"
    fi
}

verify_flutter_pub_cache_flutter_source() {
    local phase="$1" source="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
    [ -f "$source" ] && [ ! -L "$source" ] \
        || die "$phase: Flutter source archive is not one real file"
    [ "$(/usr/bin/stat -c '%s' -- "$source")" = "$SIZE_FLUTTER_3_24_5" ] \
        || die "$phase: Flutter source archive length changed"
    verify_sha256 "$source" "$SHA256_FLUTTER_3_24_5"
}

retire_flutter_pub_cache_staging() {
    local staging="$1" staging_id="$2" source_digest="$3" disposition
    local output_args=()
    mapfile -d '' output_args < <(flutter_pub_cache_output_args "$source_digest")
    disposition="$(
        flutter_pub_cache_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}"
    )" || die "cannot reconcile private Flutter Pub-cache staging"
    log "Flutter Pub-cache staging reconciliation: $disposition"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
        --root "$staging" --expected-identity "$staging_id" \
        --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
        || die "cannot restore private Flutter Pub-cache staging traversal"
    /usr/bin/python3 -I -S \
        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
        --remove-private-root "$staging" --expected-identity "$staging_id" \
        || die "cannot retire private Flutter Pub-cache staging"
    [ ! -e "$staging" ] && [ ! -L "$staging" ] \
        || die "private Flutter Pub-cache staging survived retirement"
}

recover_flutter_pub_cache_staging() {
    local source_digest="$1"
    local stale=() staging staging_id
    mapfile -d '' stale < <(
        /usr/bin/find "$ONLINE_DIR" -mindepth 1 -maxdepth 1 \
            -name ".rustdesk-flutter-pub-cache.*" -print0
    )
    for staging in "${stale[@]}"; do
        [ -d "$staging" ] && [ ! -L "$staging" ] \
            || die "reserved Flutter Pub-cache staging entry is not one real directory: $staging"
        staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
        retire_flutter_pub_cache_staging \
            "$staging" "$staging_id" "$source_digest"
    done
}

verify_flutter_pub_cache_archive_resolution() {
    local archive="$1" builder="$ANDROID_BUILDER_CONFIG_ID"
    local source="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
    [ -f "$archive" ] && [ ! -L "$archive" ] \
        || die "Flutter Pub-cache semantic input is not one real file"
    online_docker_run_pub_semantic \
        --mount "type=bind,source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$archive,target=/inputs/pub-cache.tar.gz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py,target=/authority/online-flutter-pub-cache-output.py,readonly,bind-recursive=disabled" \
        --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
        --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SHA256=$SHA256_FLUTTER_PUB_CACHE" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SIZE=$SIZE_FLUTTER_PUB_CACHE" \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
        umask 077
        /usr/bin/mkdir /tmp/toolchain /tmp/pub-cache /tmp/home
        /usr/bin/cp /inputs/pub-cache.tar.gz /tmp/pub-cache.tar.gz
        /usr/bin/chmod 0400 /tmp/pub-cache.tar.gz
        /usr/bin/python3 -I -S \
            /authority/online-flutter-pub-cache-output.py verify-archive \
            --archive /tmp/pub-cache.tar.gz \
            --uid "'"$ONLINE_FETCH_UID"'" --gid "'"$ONLINE_FETCH_GID"'" \
            --sha256 "$RUSTDESK_FLUTTER_PUB_CACHE_SHA256" \
            --size "$RUSTDESK_FLUTTER_PUB_CACHE_SIZE"
        /usr/bin/tar -C /tmp/toolchain --extract --file=/inputs/flutter.tar.xz \
            --no-same-owner --no-same-permissions
        /usr/bin/tar -C /tmp/pub-cache --extract --file=/tmp/pub-cache.tar.gz \
            --no-same-owner --no-same-permissions
        export HOME=/tmp/home
        export PUB_CACHE=/tmp/pub-cache
        export PUB_HOSTED_URL=https://pub.dev
        export CI=true
        export FLUTTER_SUPPRESS_ANALYTICS=true
        export GIT_CONFIG_NOSYSTEM=1
        export GIT_CONFIG_GLOBAL=/dev/null
        export GIT_ATTR_NOSYSTEM=1
        export GIT_NO_REPLACE_OBJECTS=1
        export GIT_OPTIONAL_LOCKS=0
        export PATH=/tmp/toolchain/flutter/bin:/tmp/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin
        tools=/tmp/toolchain/flutter/packages/flutter_tools
        before="$(
            /usr/bin/sha256sum "$tools/pubspec.lock" \
                | /usr/bin/cut -d" " -f1
        )"
        [ "$before" = "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ]
        (
            cd "$tools"
            dart pub get --offline --enforce-lockfile >/dev/null
        )
        after="$(
            /usr/bin/sha256sum "$tools/pubspec.lock" \
                | /usr/bin/cut -d" " -f1
        )"
        [ "$after" = "$before" ]
    '
}

# Flutter's Windows SDK bundles only flutter_tools runtime dependencies. The
# exact hosted + hosted-hashes projection supplies its locked development closure
# to the networkless Windows provision. Packaging is itself offline: the complete
# source cache is read-only, one pre-created private inode is the only writable
# host mount, and an independent process validates the complete logical archive
# and resolves the pinned flutter_tools lock before no-clobber publication.
stage_flutter_pub_cache() {
    local builder="$ANDROID_BUILDER_CONFIG_ID"
    local status=0 source_status=0 input_status=0 output_status=0
    local semantic_status=0 publication_status=0 lock_fd staging staging_id
    local source_digest after_digest
    local destination="$ONLINE_DIR/flutter-pub-cache.tar.gz"
    local source="$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz"
    local output_args=()
    require_online_fetch_builder_image android-builder "$builder"
    assert_online_fetch_source_tools
    prepare_gradle_source
    retire_gradle_source_build
    [ -f "$FLUTTER_PUB_CACHE_OUTPUT_HELPER" ] \
        && [ ! -L "$FLUTTER_PUB_CACHE_OUTPUT_HELPER" ] \
        || die "Flutter Pub-cache output helper is not one real source file"
    [ -f "$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py" ] \
        && [ ! -L "$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py" ] \
        || die "exact source authority lacks the Flutter Pub-cache output helper"
    verify_flutter_pub_cache_flutter_source \
        "before Flutter Pub-cache transaction"
    exec {lock_fd}<"$ONLINE_DIR" \
        || die "cannot open the online root for Flutter Pub-cache serialization"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another online-output transaction already owns the online root"
    source_digest="$(
        verify_flutter_pub_cache_source \
            "before Flutter Pub-cache transaction"
    )"
    mapfile -d '' output_args < <(flutter_pub_cache_output_args "$source_digest")
    recover_flutter_pub_cache_staging "$source_digest"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        flutter_pub_cache_output_tool check-complete \
            --online "$ONLINE_DIR" "${output_args[@]}" \
            || die "existing Flutter Pub-cache archive is incomplete or unsafe"
        verify_flutter_pub_cache_archive_resolution "$destination" \
            || die "existing Flutter Pub-cache archive fails offline flutter_tools resolution"
        after_digest="$(
            verify_flutter_pub_cache_source \
                "after occupied Flutter Pub-cache validation"
        )"
        [ "$after_digest" = "$source_digest" ] \
            || die "Pub-cache source changed during occupied-output validation"
        verify_flutter_pub_cache_flutter_source \
            "after occupied Flutter Pub-cache validation"
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Flutter Pub-cache transaction lock"
        exec {lock_fd}<&-
        log "Windows flutter_tools Pub cache already staged and exactly validated"
        return 0
    fi
    staging="$(
        umask 077
        /usr/bin/mktemp -d \
            "$ONLINE_DIR/.rustdesk-flutter-pub-cache.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Flutter Pub-cache staging"
    staging_id="$(/usr/bin/stat -c '%d:%i' -- "$staging")"
    if ! flutter_pub_cache_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}"
    then
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py" \
            --root "$staging" --expected-identity "$staging_id" \
            --owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID" \
            || die "failed Flutter Pub-cache preparation left non-restorable staging"
        /usr/bin/python3 -I -S \
            "$GRADLE_SOURCE_AUTHORITY/scripts/verify-private-tree-closure.py" \
            --remove-private-root "$staging" --expected-identity "$staging_id" \
            || die "failed Flutter Pub-cache preparation left non-retirable staging"
        die "cannot prepare private Flutter Pub-cache staging"
    fi
    log "packaging the exact flutter_tools Pub cache into one private output"
    online_docker_run_offline \
        --mount "type=bind,source=$ONLINE_DIR/pub-cache,target=/inputs/pub-cache,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py,target=/authority/online-flutter-pub-cache-output.py,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/pub-cache.tar.gz" \
        --env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SHA256=$SHA256_FLUTTER_PUB_CACHE" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SIZE=$SIZE_FLUTTER_PUB_CACHE" \
        "$(online_fetch_builder_runtime_ref "$builder")" /bin/bash --noprofile --norc -euo pipefail -c '
        export LC_ALL=C
        lock=/tmp/flutter-tools.pubspec.lock
        /usr/bin/tar -xOf /inputs/flutter.tar.xz \
            flutter/packages/flutter_tools/pubspec.lock >"$lock"
        [ "$(/usr/bin/sha256sum "$lock" | /usr/bin/cut -d" " -f1)" \
            = "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ]
        cd /inputs/pub-cache
        /usr/bin/python3 -I -S \
            /authority/online-flutter-pub-cache-output.py \
            write-projection-manifest \
            --cache /inputs/pub-cache --lockfile "$lock" \
            --lock-sha256 "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" \
            | /usr/bin/tar --null --verbatim-files-from --no-recursion \
            --hard-dereference --sort=name --mtime=@1700000000 \
            --owner=0 --group=0 --numeric-owner \
            --mode="u+rwX,go+rX,go-w" \
            --files-from=- -cf - \
            | /usr/bin/python3 -I -S \
                /authority/online-flutter-pub-cache-output.py normalize-tar \
            | /usr/bin/gzip -n -9 \
            | /usr/bin/python3 -I -S \
                /authority/online-flutter-pub-cache-output.py write-bounded \
                --output /outputs/pub-cache.tar.gz \
                --uid "'"$ONLINE_FETCH_UID"'" --gid "'"$ONLINE_FETCH_GID"'" \
                --sha256 "$RUSTDESK_FLUTTER_PUB_CACHE_SHA256" \
                --size "$RUSTDESK_FLUTTER_PUB_CACHE_SIZE"
    ' || status=$?
    if after_digest="$(
        verify_flutter_pub_cache_source \
            "after Flutter Pub-cache producer"
    )"; then
        [ "$after_digest" = "$source_digest" ] || source_status=1
    else
        source_status=1
    fi
    verify_flutter_pub_cache_flutter_source \
        "after Flutter Pub-cache producer" \
        || input_status=$?
    flutter_pub_cache_output_tool verify \
        --online "$ONLINE_DIR" --staging "$staging" \
        "${output_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] \
       && [ "$source_status" -eq 0 ] \
       && [ "$input_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ]; then
        verify_flutter_pub_cache_archive_resolution "$staging/output" \
            || semantic_status=$?
    else
        semantic_status=1
    fi
    if after_digest="$(
        verify_flutter_pub_cache_source \
            "after Flutter Pub-cache semantic validation"
    )"; then
        [ "$after_digest" = "$source_digest" ] || source_status=1
    else
        source_status=1
    fi
    verify_flutter_pub_cache_flutter_source \
        "after Flutter Pub-cache semantic validation" \
        || input_status=$?
    if [ "$status" -eq 0 ] \
       && [ "$source_status" -eq 0 ] \
       && [ "$input_status" -eq 0 ] \
       && [ "$output_status" -eq 0 ] \
       && [ "$semantic_status" -eq 0 ]; then
        flutter_pub_cache_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            "${output_args[@]}" \
            || publication_status=$?
    fi
    retire_flutter_pub_cache_staging \
        "$staging" "$staging_id" "$source_digest"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Flutter Pub-cache transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "Flutter Pub-cache source postcondition failed"
    [ "$input_status" -eq 0 ] || die "Flutter source postcondition failed"
    [ "$output_status" -eq 0 ] || die "Flutter Pub-cache output postcondition failed"
    [ "$status" -eq 0 ] || die "Flutter Pub-cache packager failed"
    [ "$semantic_status" -eq 0 ] || die "Flutter Pub-cache semantic replay failed"
    [ "$publication_status" -eq 0 ] || die "Flutter Pub-cache publication failed"
    log "Windows flutter_tools Pub cache exactly validated and checked-published"
}

# ── The exact signed WiX v4.0.5 NuGet source (§12.2 milestone-2, the .msi) ──────
# NuGet itself owns package signature verification and global-cache extraction.
# Acquire only the exact SDK + five extension .nupkg files through the common
# bounded transaction. The Windows guest consumes this directory as a read-only
# local package source, requires the pinned WiX author certificate, and restores
# into a fresh private global-packages directory with its committed lock file.
stage_windows_wix_nuget() {
    stage_archive_bundle wix "$ONLINE_DIR" .rustdesk-wix-nuget-packages \
        "fixed signed WiX NuGet packages"
    /usr/bin/python3 -I -S "$WIX_NUGET_RETIRE_HELPER" retire \
        --online "$ONLINE_DIR" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        --package "wix-nuget-packages/wixtoolset.firewall.wixext.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_FIREWALL" "$SHA256_WIX_NUGET_FIREWALL" \
        --package "wix-nuget-packages/wixtoolset.heat.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_HEAT" "$SHA256_WIX_NUGET_HEAT" \
        --package "wix-nuget-packages/wixtoolset.netfx.wixext.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_NETFX" "$SHA256_WIX_NUGET_NETFX" \
        --package "wix-nuget-packages/wixtoolset.sdk.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_SDK" "$SHA256_WIX_NUGET_SDK" \
        --package "wix-nuget-packages/wixtoolset.ui.wixext.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_UI" "$SHA256_WIX_NUGET_UI" \
        --package "wix-nuget-packages/wixtoolset.util.wixext.${WIX_NUGET_VERSION}.nupkg" "$SIZE_WIX_NUGET_UTIL" "$SHA256_WIX_NUGET_UTIL" \
        --legacy-six-size "$SIZE_WIX_NUGET_LEGACY_SIX" \
        --legacy-six-sha256 "$SHA256_WIX_NUGET_LEGACY_SIX" \
        --legacy-eight-size "$SIZE_WIX_NUGET_LEGACY_EIGHT" \
        --legacy-eight-sha256 "$SHA256_WIX_NUGET_LEGACY_EIGHT"
    log "exact signed WiX local-feed packages staged; obsolete expanded-cache archive absent"
}

main() {
    if [ "${1:-}" != "--debian-systemd-smoke-image" ]; then
        prepare_online_root
    fi
    case "${1:-}" in
        --libvpx-distfiles)
            [ "$#" -eq 1 ] || die "--libvpx-distfiles takes no arguments"
            stage_libvpx_distfiles
            return 0
            ;;
        --wix-nuget-packages)
            [ "$#" -eq 1 ] || die "--wix-nuget-packages takes no arguments"
            stage_windows_wix_nuget
            return 0
            ;;
        --maintenance-build-deb-builder-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-deb-builder-bootstrap-candidate takes no arguments"
            maintenance_build_deb_builder_bootstrap_candidate
            return 0
            ;;
        --maintenance-build-android-builder-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-android-builder-bootstrap-candidate takes no arguments"
            maintenance_build_android_builder_bootstrap_candidate
            return 0
            ;;
        --maintenance-build-win-helper-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-win-helper-bootstrap-candidate takes no arguments"
            maintenance_build_win_helper_bootstrap_candidate
            return 0
            ;;
        --maintenance-promote-deb-builder-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-deb-builder-bootstrap-candidate takes no arguments"
            maintenance_promote_deb_builder_bootstrap_candidate
            return 0
            ;;
        --maintenance-promote-android-builder-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-android-builder-bootstrap-candidate takes no arguments"
            maintenance_promote_android_builder_bootstrap_candidate
            return 0
            ;;
        --maintenance-promote-win-helper-bootstrap-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-win-helper-bootstrap-candidate takes no arguments"
            maintenance_promote_win_helper_bootstrap_candidate
            return 0
            ;;
        --maintenance-build-deb-builder-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-deb-builder-certified-candidate takes no arguments"
            maintenance_build_deb_builder_certified_candidate
            return 0
            ;;
        --maintenance-promote-deb-builder-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-deb-builder-certified-candidate takes no arguments"
            maintenance_promote_deb_builder_certified_candidate
            return 0
            ;;
        --maintenance-build-android-builder-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-android-builder-certified-candidate takes no arguments"
            maintenance_build_android_builder_certified_candidate
            return 0
            ;;
        --maintenance-promote-android-builder-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-android-builder-certified-candidate takes no arguments"
            maintenance_promote_android_builder_certified_candidate
            return 0
            ;;
        --maintenance-build-win-helper-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-build-win-helper-certified-candidate takes no arguments"
            maintenance_build_win_helper_certified_candidate
            return 0
            ;;
        --maintenance-promote-win-helper-certified-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-promote-win-helper-certified-candidate takes no arguments"
            maintenance_promote_win_helper_certified_candidate
            return 0
            ;;
        --maintenance-build-apple-check-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-build-apple-check-image-candidate takes no arguments"
            maintenance_build_apple_check_image_candidate
            return 0
            ;;
        --maintenance-build-dart-audit-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-build-dart-audit-image-candidate takes no arguments"
            maintenance_build_dart_audit_image_candidate
            return 0
            ;;
        --maintenance-promote-dart-audit-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-promote-dart-audit-image-candidate takes no arguments"
            maintenance_promote_dart_audit_image_candidate
            return 0
            ;;
        --maintenance-build-rust-audit-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-build-rust-audit-image-candidate takes no arguments"
            maintenance_build_rust_audit_image_candidate
            return 0
            ;;
        --maintenance-promote-rust-audit-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-promote-rust-audit-image-candidate takes no arguments"
            maintenance_promote_rust_audit_image_candidate
            return 0
            ;;
        --maintenance-discover-devcheck-image)
            [ "$#" -eq 1 ] || die "--maintenance-discover-devcheck-image takes no arguments"
            maintenance_discover_devcheck_image
            return 0
            ;;
        --maintenance-discover-osv-pub-database)
            [ "$#" -eq 1 ] \
                || die "--maintenance-discover-osv-pub-database takes no arguments"
            maintenance_discover_osv_pub_database
            return 0
            ;;
        --maintenance-build-devcheck-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-build-devcheck-image-candidate takes no arguments"
            maintenance_build_devcheck_image_candidate
            return 0
            ;;
        --maintenance-promote-devcheck-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-promote-devcheck-image-candidate takes no arguments"
            maintenance_promote_devcheck_image_candidate
            return 0
            ;;
        --dart-audit-inputs)
            [ "$#" -eq 1 ] || die "--dart-audit-inputs takes no arguments"
            stage_dart_audit_inputs
            return 0
            ;;
        --rust-test-inputs)
            [ "$#" -eq 1 ] || die "--rust-test-inputs takes no arguments"
            stage_rust_test_inputs
            return 0
            ;;
        --flutter-test-inputs)
            [ "$#" -eq 1 ] || die "--flutter-test-inputs takes no arguments"
            stage_flutter_test_inputs
            return 0
            ;;
        --flutter-peer-inputs)
            [ "$#" -eq 1 ] || die "--flutter-peer-inputs takes no arguments"
            stage_flutter_peer_inputs
            return 0
            ;;
        --android-build-inputs)
            [ "$#" -eq 1 ] || die "--android-build-inputs takes no arguments"
            stage_android_build_inputs
            return 0
            ;;
        --maintenance-capture-apple-check-image)
            [ "$#" -eq 1 ] || die "--maintenance-capture-apple-check-image takes no arguments"
            maintenance_capture_apple_check_image
            return 0
            ;;
        --devcheck-image)
            [ "$#" -eq 1 ] || die "--devcheck-image takes no arguments"
            verify_or_load_devcheck_image
            return 0
            ;;
        --apple-check-image)
            [ "$#" -eq 1 ] || die "--apple-check-image takes no arguments"
            verify_or_load_apple_check_image
            return 0
            ;;
        --dart-audit-image)
            [ "$#" -eq 1 ] || die "--dart-audit-image takes no arguments"
            verify_or_load_dart_audit_image
            return 0
            ;;
        --rust-audit-image)
            [ "$#" -eq 1 ] || die "--rust-audit-image takes no arguments"
            verify_or_load_rust_audit_image
            return 0
            ;;
        --maintenance-print-online-closure)
            [ "$#" -eq 1 ] || die "--maintenance-print-online-closure takes no arguments"
            python3 "$LIB_DIR/online-input-provenance.py" maintenance-print-root --tree "$ONLINE_DIR"
            return 0
            ;;
        --maintenance-reproduce-vcpkg-x64)
            [ "$#" -eq 1 ] || die "--maintenance-reproduce-vcpkg-x64 takes no arguments"
            maintenance_reproduce_vcpkg_x64
            return 0
            ;;
        --maintenance-print-cargo-vendor-candidate)
            [ "$#" -eq 1 ] \
                || die "--maintenance-print-cargo-vendor-candidate takes no arguments"
            maintenance_print_cargo_vendor_candidate
            return 0
            ;;
        --maintenance-write-online-closure)
            [ "$#" -eq 1 ] || die "--maintenance-write-online-closure takes no arguments"
            python3 "$LIB_DIR/online-input-provenance.py" maintenance-write-record --tree "$ONLINE_DIR"
            return 0
            ;;
        --verify-offline-inputs)
            [ "$#" -eq 1 ] || die "--verify-offline-inputs takes no arguments"
            verify_online_pinned_archives
            load_builder_images
            verify_or_load_devcheck_image
            verify_or_load_apple_check_image
            verify_or_load_dart_audit_image
            verify_or_load_rust_audit_image
            require_online_complete
            return 0
            ;;
        --debian-systemd-smoke-image)
            [ "$#" -eq 1 ] || die "--debian-systemd-smoke-image takes no arguments"
            fetch_debian_systemd_smoke_image
            return 0
            ;;
        '') ;;
        *) die "usage: scripts/online-fetch.sh [--verifier-vm-inputs|--rust-test-inputs|--flutter-test-inputs|--flutter-peer-inputs|--android-build-inputs|--libvpx-distfiles|--wix-nuget-packages|--dart-audit-inputs|--maintenance-discover-osv-pub-database|--maintenance-build-deb-builder-bootstrap-candidate|--maintenance-build-android-builder-bootstrap-candidate|--maintenance-build-win-helper-bootstrap-candidate|--maintenance-promote-deb-builder-bootstrap-candidate|--maintenance-promote-android-builder-bootstrap-candidate|--maintenance-promote-win-helper-bootstrap-candidate|--maintenance-build-deb-builder-certified-candidate|--maintenance-promote-deb-builder-certified-candidate|--maintenance-build-android-builder-certified-candidate|--maintenance-promote-android-builder-certified-candidate|--maintenance-build-win-helper-certified-candidate|--maintenance-promote-win-helper-certified-candidate|--maintenance-discover-devcheck-image|--maintenance-build-devcheck-image-candidate|--maintenance-promote-devcheck-image-candidate|--maintenance-build-apple-check-image-candidate|--maintenance-build-dart-audit-image-candidate|--maintenance-promote-dart-audit-image-candidate|--maintenance-build-rust-audit-image-candidate|--maintenance-promote-rust-audit-image-candidate|--maintenance-capture-apple-check-image|--maintenance-reproduce-vcpkg-x64|--devcheck-image|--apple-check-image|--dart-audit-image|--rust-audit-image|--maintenance-print-online-closure|--maintenance-print-cargo-vendor-candidate|--maintenance-write-online-closure|--verify-offline-inputs|--debian-systemd-smoke-image]" ;;
    esac
    log "online-fetch: materializing the SHA-256-verified ./online/inputs cache (R-B10)"
    load_builder_images
    verify_or_load_devcheck_image
    verify_or_load_apple_check_image
    verify_or_load_dart_audit_image
    verify_or_load_rust_audit_image
    stage_dart_audit_inputs
    stage_fixed_archives
    vendor_cargo
    verify_online_glob_cardinality
    build_frb_codegen
    stage_pub_cache
    stage_vcpkg_distfiles
    stage_vcpkg_natives
    stage_android_ndk
    stage_vcpkg_natives_arm64
    stage_cargo_ndk
    stage_android_sdk
    stage_gradle
    require_windows_operator_toolchain
    stage_windows_engine
    stage_flutter_pub_cache
    stage_windows_wix_nuget
    verify_online_pinned_archives
    require_online_complete
    log "online-fetch complete — ./online/inputs equals its pinned closure. Builds run --network=none."
}

main "$@"

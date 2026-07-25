#!/usr/bin/env bash
# scripts/online-fetch.sh — the ONE networked step (R-B10).
#
# The repository is build-oriented and offline-by-construction. This is the only
# script permitted to touch the network; it materializes every resource the repo
# does not embed into ./online/ (git-ignored, NOT vendored — pinning != vendoring,
# R-R1), each verified against its pinned SHA-256 in scripts/pins.env. Any mismatch
# aborts fail-closed. The build scripts then run with the network namespace removed
# (--network=none) and refuse to run if ./online is incomplete or any SHA fails.
#
# This reconciles R-R1's "pinning != vendoring" with the offline build: the bulky
# pinned world is CACHED, not committed — re-creatable from pins.env and
# re-verifiable, never trusted from the network at build time.
#
# Run order (R-B10): host-provision.sh -> online-fetch.sh (once, or on a pins.env
# change) -> build-* (offline) -> cleanup.sh
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

readonly DOCKER_BIN=/usr/bin/docker
readonly GIT_BIN=/usr/bin/git
readonly TAR_BIN=/usr/bin/tar
readonly FLOCK_BIN=/usr/bin/flock
readonly FIXED_ARCHIVE_HELPER="$SCRIPT_DIR/online-fixed-archive-output.py"
readonly LIBVPX_LOCAL_OUTPUT_HELPER="$SCRIPT_DIR/online-libvpx-local-output.py"
readonly CARGO_VENDOR_OUTPUT_HELPER="$SCRIPT_DIR/online-cargo-vendor-output.py"
readonly WINDOWS_ENGINE_OUTPUT_HELPER="$SCRIPT_DIR/online-windows-engine-output.py"
readonly FLUTTER_PUB_CACHE_OUTPUT_HELPER="$SCRIPT_DIR/online-flutter-pub-cache-output.py"
readonly WIX_NUGET_RETIRE_HELPER="$SCRIPT_DIR/online-wix-nuget-retire.py"
readonly VCPKG_FIXED_ARCHIVE_MANIFEST="$REPO_ROOT/res/vcpkg/libvpx/fixed-archive-acquisition-v1.txt"
readonly ONLINE_FETCH_DOCKER_HOST=unix:///var/run/docker.sock
readonly ONLINE_FETCH_UID="$(/usr/bin/id -u)"
readonly ONLINE_FETCH_GID="$(/usr/bin/id -g)"
[ "$ONLINE_FETCH_UID" -ne 0 ] || die "online-fetch refuses host or container-root execution"
[ "$ONLINE_FETCH_GID" -ne 0 ] || die "online-fetch refuses a root primary group"
[ -x "$DOCKER_BIN" ] || die "trusted Docker client is unavailable: $DOCKER_BIN"
[ "$(stat -c '%u:%g:%a:%h' -- "$DOCKER_BIN")" = "0:0:755:1" ] \
    || die "trusted Docker client metadata changed"
[ -x "$GIT_BIN" ] || die "trusted Git client is unavailable: $GIT_BIN"
[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$GIT_BIN")" = "0:0:755:1" ] \
    || die "trusted Git client metadata changed"
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
install -d -m 0700 "$ONLINE_FETCH_DOCKER_CONFIG"
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
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$GIT_BIN")" = "0:0:755:1" ] \
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
    local phase="$1" grafts replacements status=0
    verify_gradle_live_checkout_state "$phase" || status=$?
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
    [ -f "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" ] \
        && [ ! -L "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" ] \
        || die "libvpx source capture missing — stage_vcpkg_distfiles must run first"
    [ "$(sha512sum "$dir/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" | awk '{print $1}')" \
       = "$SHA512_LIBVPX_SOURCE" ] \
        || die "libvpx source capture SHA512 mismatch"
    /usr/bin/python3 -I -S "$LIBVPX_LOCAL_OUTPUT_HELPER" check \
        --online "$ONLINE_DIR" \
        --source-root "$REPO_ROOT" \
        --source-patch "$REPO_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch" \
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
        --builder "$DEB_BUILDER_IMAGE_ID" \
        --rust-sha256 "$SHA256_RUST_1_75" \
        --vendor-sha256 "$SHA256_CARGO_VENDOR_CLOSURE_V1" \
        --config-sha256 "$SHA256_CARGO_VENDOR_CONFIG" \
        --config-vendor-path "$REPO_ROOT/online/cargo-vendor" \
        --config-size "$SIZE_CARGO_VENDOR_CONFIG" \
        --files "$CARGO_VENDOR_FILES_V1" \
        --directories "$CARGO_VENDOR_DIRECTORIES_V1" \
        --content-bytes "$CARGO_VENDOR_CONTENT_BYTES_V1"
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
    local builder="$DEB_BUILDER_IMAGE_ID"
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
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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
            "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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
# fourteen toolchain/installer archives, the two Dart-audit rebuild inputs, six
# signed WiX packages, 33 vcpkg source/tool distfiles, and the one dated Debian
# systemd image.
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
        dart-audit) archive_args=("${DART_AUDIT_FIXED_INPUT_ARGS[@]}") ;;
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
    local builder="$ANDROID_BUILDER_IMAGE_ID"
    local lock_fd helper_sha256 staging staging_identity action
    local producer_status=0 verification_status=0 publication_status=0
    require_online_fetch_builder_image android-builder "$builder"
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
    online_docker_run_archive_acquisition \
        --mount "type=bind,source=$FIXED_ARCHIVE_HELPER,target=/online-fixed-archive-output.py,readonly" \
        --mount "type=bind,source=$staging/state.json,target=/state.json,readonly" \
        --mount "type=bind,source=$staging/output,target=/outputs" \
        "$builder" \
        /usr/bin/python3 -I -S /online-fixed-archive-output.py acquire \
            --state /state.json --output /outputs \
            --builder-id "$builder" --helper-sha256 "$helper_sha256" \
        || producer_status=$?
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

validate_dart_audit_inputs() {
    local builder="$ANDROID_BUILDER_IMAGE_ID"
    require_online_fetch_builder_image android-builder "$builder"
    online_docker_run_offline \
        --mount "type=bind,source=$SCRIPT_DIR/dart-audit-image-input.py,target=/authority/dart-audit-image-input.py,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ONLINE_DIR/dart-audit-inputs/osv-scanner,target=/inputs/osv-scanner,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$ONLINE_DIR/dart-audit-inputs/Pub-all.zip,target=/inputs/Pub-all.zip,readonly,bind-recursive=disabled" \
        "$builder" \
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

verify_or_load_builder_image() {
    local role="$1" image_id="$2" base="$3" dockerfile_sha="$4" dpkg_sha="$5" archive_sha="$6"
    local archive="$ONLINE_DIR/build-images/${role}.docker.tar.gz"
    require_cmd python3
    online_image_provenance verify-load \
        --archive "$archive" --archive-sha "$archive_sha" \
        --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
    online_image_provenance verify-local \
        --image-ref "$image_id" --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
}

load_builder_images() {
    local names=(
        DEB_BUILDER_IMAGE_ID SHA256_DEB_BUILDER_DOCKERFILE SHA256_DEB_BUILDER_DPKG_MANIFEST SHA256_DEB_BUILDER_IMAGE_ARCHIVE
        ANDROID_BUILDER_IMAGE_ID SHA256_ANDROID_BUILDER_DOCKERFILE SHA256_ANDROID_BUILDER_DPKG_MANIFEST SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE
        WIN_HELPER_IMAGE_ID SHA256_WIN_HELPER_DOCKERFILE SHA256_WIN_HELPER_DPKG_MANIFEST SHA256_WIN_HELPER_IMAGE_ARCHIVE
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    verify_or_load_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID" \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" "$SHA256_DEB_BUILDER_DOCKERFILE" \
        "$SHA256_DEB_BUILDER_DPKG_MANIFEST" "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE"
    verify_or_load_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_ANDROID_BUILDER_DOCKERFILE" \
        "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"
    verify_or_load_builder_image win-helper "$WIN_HELPER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_WIN_HELPER_DOCKERFILE" \
        "$SHA256_WIN_HELPER_DPKG_MANIFEST" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"
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
        --source-commit "$DEV_CHECK_SOURCE_COMMIT" \
        --source-repository "$DEV_CHECK_SOURCE_REPOSITORY" \
        --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
        --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"
}

require_devcheck_image_pins() {
    local names=(
        DEV_CHECK_IMAGE_ID DEV_CHECK_BASE_IMAGE_ID
        DEV_CHECK_IMAGE_CONFIG_ID DEV_CHECK_IMAGE_MANIFEST_ID
        DEV_CHECK_SOURCE_COMMIT DEV_CHECK_SOURCE_REPOSITORY
        SHA256_DEV_CHECK_DOCKERFILE SHA256_DEV_CHECK_DPKG_MANIFEST
        SHA256_DEV_CHECK_CARGO SHA256_DEV_CHECK_RUSTC
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    local historical_sha
    online_source_git merge-base --is-ancestor "$DEV_CHECK_SOURCE_COMMIT" HEAD \
        || die "devcheck provenance source revision is not an ancestor of the current source"
    historical_sha="$(
        online_source_git show "$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck" \
            | /usr/bin/sha256sum | /usr/bin/awk '{print $1}'
    )" || die "cannot read the devcheck provenance Dockerfile from its source revision"
    [ "$historical_sha" = "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || die "devcheck provenance revision does not contain the reviewed Dockerfile"
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.devcheck" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DEV_CHECK_DOCKERFILE" ] \
        || die "current devcheck Dockerfile differs from the archived image recipe"
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
        --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz" \
        --archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE" \
        "${args[@]}"
}

maintenance_capture_devcheck_image() {
    require_devcheck_image_pins
    local directory="$ONLINE_DIR/verifier-images"
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || die "devcheck image archive root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
          = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
            || die "devcheck image archive root is not current-user-private mode 0700"
    else
        /usr/bin/install -d -m 0700 "$directory"
    fi
    local lock_fd
    exec {lock_fd}<"$directory" \
        || die "cannot open the devcheck image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another devcheck image archive transaction owns the archive root"
    local args=() result
    mapfile -d '' args < <(devcheck_image_spec_args)
    result="$(
        online_image_provenance maintenance-capture \
            --output "$directory/devcheck.docker.tar.gz" \
            "${args[@]}"
    )" || die "devcheck image archive capture failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the devcheck image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
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
            --output "$directory/apple-check.docker.tar.gz" \
            "${args[@]}"
    )" || die "Apple check image archive capture failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Apple check image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

dart_audit_image_spec_args() {
    printf '%s\0' \
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
}

require_dart_audit_image_pins() {
    local names=(
        DART_AUDIT_IMAGE_ID DART_AUDIT_IMAGE_CONFIG_ID
        DART_AUDIT_IMAGE_MANIFEST_ID SHA256_BASEIMAGE_UBUNTU_1804
        SHA256_DART_AUDIT_DOCKERFILE
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
        --archive "$ONLINE_DIR/verifier-images/dart-audit.docker.tar.gz" \
        --archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}"
}

maintenance_capture_dart_audit_image() {
    require_dart_audit_image_pins
    local directory="$ONLINE_DIR/verifier-images"
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || die "Dart advisory image archive root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
          = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
            || die "Dart advisory image archive root is not current-user-private mode 0700"
    else
        /usr/bin/install -d -m 0700 "$directory"
    fi
    local lock_fd
    exec {lock_fd}<"$directory" \
        || die "cannot open the Dart advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Dart advisory image archive transaction owns the archive root"
    local args=() result
    mapfile -d '' args < <(dart_audit_image_spec_args)
    result="$(
        online_image_provenance maintenance-capture \
            --output "$directory/dart-audit.docker.tar.gz" \
            "${args[@]}"
    )" || die "Dart advisory image archive capture failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Dart advisory image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

rust_audit_image_spec_args() {
    printf '%s\0' \
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
        --archive "$ONLINE_DIR/verifier-images/rust-audit.docker.tar.gz" \
        --archive-sha "$SHA256_RUST_AUDIT_IMAGE_ARCHIVE" \
        --archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE" \
        "${args[@]}"
}

maintenance_capture_rust_audit_image() {
    require_rust_audit_image_pins
    local directory="$ONLINE_DIR/verifier-images"
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || die "Rust advisory image archive root is not one real directory"
        [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$directory")" \
          = "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700" ] \
            || die "Rust advisory image archive root is not current-user-private mode 0700"
    else
        /usr/bin/install -d -m 0700 "$directory"
    fi
    local lock_fd
    exec {lock_fd}<"$directory" \
        || die "cannot open the Rust advisory image archive root for locking"
    "$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \
        || die "another Rust advisory image archive transaction owns the archive root"
    local args=() result
    mapfile -d '' args < <(rust_audit_image_spec_args)
    result="$(
        online_image_provenance maintenance-capture \
            --output "$directory/rust-audit.docker.tar.gz" \
            "${args[@]}"
    )" || die "Rust advisory image archive capture failed"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Rust advisory image archive lock"
    exec {lock_fd}<&-
    printf '%s\n' "$result"
}

# Explicit maintenance candidate builds. Captured images remain the release authority.
build_deb_builder_image() {
    require_image_pin SHA256_DEB_BUILDER_DOCKERFILE
    require_image_pin SHA256_DEB_BUILDER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder-candidate"
    online_docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_DEB_BUILDER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_DEB_BUILDER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.deb-builder" "$LIB_DIR"
    local image_id
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")"
    online_image_provenance verify-local --image-ref "$tag" \
        --role deb-builder --expected-id "$image_id" --base "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" \
        --dockerfile-sha "$SHA256_DEB_BUILDER_DOCKERFILE" --dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST"
    printf 'DEB_BUILDER_IMAGE_ID="%s"\n' "$image_id"
}

# ── The pinned .apk build image (R-B7/B8): ubuntu:24.04 + the android build-deps ────
# build-android.sh runs --network=none; the NDK r28c prebuilt clang needs a modern glibc, so
# this is FROM ubuntu:24.04 (not the bionic deb-builder). Dockerfile.android-builder bakes the
# vcpkg/cargo-ndk/gradle system deps; the rust/flutter/NDK toolchains stay in ./online.
build_android_builder_image() {
    require_image_pin SHA256_ANDROID_BUILDER_DOCKERFILE
    require_image_pin SHA256_ANDROID_BUILDER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-android-builder-candidate"
    online_docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_ANDROID_BUILDER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_ANDROID_BUILDER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.android-builder" "$LIB_DIR"
    local image_id
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")"
    online_image_provenance verify-local --image-ref "$tag" \
        --role android-builder --expected-id "$image_id" --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE" --dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"
    printf 'ANDROID_BUILDER_IMAGE_ID="%s"\n' "$image_id"
}

# ── The pinned Windows VM helper image: genisoimage + libguestfs + MSI tooling ──
# The Windows artifact path uses host-side helper containers for UDF media creation,
# libguestfs inspection/extraction, and MSI canonicalization. Those helpers are build
# inputs, so their apt installs belong HERE (the one networked phase), not inside
# build-windows-vm.sh/provision-windows-vm.sh/verify-windows-golden.sh.
build_windows_helper_image() {
    require_image_pin SHA256_WIN_HELPER_DOCKERFILE
    require_image_pin SHA256_WIN_HELPER_DPKG_MANIFEST
    local tag="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-helper-candidate"
    online_docker build --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --build-arg "DOCKERFILE_SHA256=${SHA256_WIN_HELPER_DOCKERFILE}" \
        --build-arg "DPKG_MANIFEST_SHA256=${SHA256_WIN_HELPER_DPKG_MANIFEST}" \
        --no-cache \
        -t "$tag" -f "$LIB_DIR/Dockerfile.win-helper" "$LIB_DIR"
    local image_id
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")"
    online_image_provenance verify-local --image-ref "$tag" \
        --role win-helper --expected-id "$image_id" --base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" \
        --dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE" --dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"
    printf 'WIN_HELPER_IMAGE_ID="%s"\n' "$image_id"
}

maintenance_build_image_candidates() {
    require_cmd python3
    online_docker pull "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}"
    online_docker pull "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"
    build_deb_builder_image
    build_android_builder_image
    build_windows_helper_image
}

maintenance_build_apple_check_image_candidate() {
    require_devcheck_image_pins
    require_apple_check_image_pins
    verify_or_load_devcheck_image
    local context="$ONLINE_FETCH_TMP/apple-check-build-context"
    local candidate_archive="$ONLINE_FETCH_TMP/apple-check-candidate.docker.tar.gz"
    local tag="rd-apple-check:authenticated-v1"
    local image_id base_identity result
    [ ! -e "$context" ] && [ ! -L "$context" ] \
        || die "private Apple check build context already exists"
    [ ! -e "$candidate_archive" ] && [ ! -L "$candidate_archive" ] \
        || die "private Apple check candidate archive already exists"
    /usr/bin/install -d -m 0700 "$context"
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
    online_docker buildx build \
        --network=default --pull=false --no-cache \
        --platform=linux/amd64 --provenance=mode=max \
        --output=type=docker,rewrite-timestamp=true \
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
        --image-ref "$tag" "${args[@]}" \
        || die "Apple check candidate runtime verification failed"
    result="$(
        online_image_provenance maintenance-capture \
            --output "$candidate_archive" \
            "${args[@]}"
    )" || die "Apple check candidate provenance capture failed"
    /usr/bin/rm -f -- "$candidate_archive" \
        || die "cannot remove the verified private Apple check candidate archive"
    printf 'APPLE_CHECK_IMAGE_ID="%s"\n' "$image_id"
    printf '%s\n' "$result"
}

maintenance_build_dart_audit_image_candidate() {
    local names=(
        SHA256_BASEIMAGE_UBUNTU_1804
        OSV_SCANNER_VERSION OSV_SCALIBR_VERSION OSV_SCANNER_COMMIT
        OSV_SCANNER_BUILT_AT OSV_SCANNER_SIZE OSV_SCANNER_SHA256
        OSV_DB_PUB_SHA256 OSV_DB_PUB_SIZE OSV_DB_PUB_CAPTURE_EPOCH
        OSV_DB_PUB_GENERATION SHA256_DART_AUDIT_DOCKERFILE
    )
    local name base_identity image_id
    local tag="rd-dart-audit-candidate:provenance-v1"
    local context="$ONLINE_FETCH_TMP/dart-audit-build-context"
    for name in "${names[@]}"; do require_image_pin "$name"; done
    [ "$(/usr/bin/sha256sum "$SCRIPT_DIR/Dockerfile.dart-audit" | /usr/bin/awk '{print $1}')" \
       = "$SHA256_DART_AUDIT_DOCKERFILE" ] \
        || die "Dart advisory Dockerfile differs from its pin"
    stage_dart_audit_inputs
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
    base_identity="$(
        online_docker image inspect --format '{{.Id}}|{{.Os}}|{{.Architecture}}' \
            "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}"
    )" || die "the exact Dart advisory base image is not already present"
    [ "$base_identity" = "${SHA256_BASEIMAGE_UBUNTU_1804}|linux|amd64" ] \
        || die "the local Dart advisory base image differs from its exact Linux/amd64 pin"
    online_docker buildx build \
        --network=none --pull=false --no-cache \
        --platform=linux/amd64 --provenance=mode=max --load \
        --build-arg "BASE_DIGEST=${SHA256_BASEIMAGE_UBUNTU_1804}" \
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
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the Dart advisory candidate"
    online_image_provenance verify-local \
        --image-ref "$tag" \
        --role dart-audit \
        --expected-id "$image_id" \
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
    printf 'DART_AUDIT_IMAGE_ID="%s"\n' "$image_id"
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
    local name image_id
    local tag="rd-rust-audit-candidate:provenance-v1"
    local context="$ONLINE_FETCH_TMP/rust-audit-build-context"
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
    online_docker buildx build \
        --network=default --pull=true --no-cache \
        --platform=linux/amd64 --provenance=mode=max --load \
        --build-arg "RUST_AUDIT_RUST_VERSION=${RUST_AUDIT_RUST_VERSION}" \
        --build-arg "BASE_DIGEST=${RUST_AUDIT_BASE_IMAGE_DIGEST}" \
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
    image_id="$(online_docker image inspect --format '{{.Id}}' "$tag")" \
        || die "cannot resolve the Rust advisory candidate"
    online_image_provenance verify-local \
        --image-ref "$tag" \
        --role rust-audit \
        --expected-id "$image_id" \
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
    printf 'RUST_AUDIT_IMAGE_ID="%s"\n' "$image_id"
}

capture_builder_image() {
    local role="$1" image_id="$2" base="$3" dockerfile_sha="$4" dpkg_sha="$5" output="$6"
    online_image_provenance maintenance-capture \
        --output "$output" \
        --role "$role" --expected-id "$image_id" --base "$base" \
        --dockerfile-sha "$dockerfile_sha" --dpkg-sha "$dpkg_sha"
}

maintenance_capture_builder_images() {
    local names=(
        DEB_BUILDER_IMAGE_ID SHA256_DEB_BUILDER_DOCKERFILE SHA256_DEB_BUILDER_DPKG_MANIFEST
        ANDROID_BUILDER_IMAGE_ID SHA256_ANDROID_BUILDER_DOCKERFILE SHA256_ANDROID_BUILDER_DPKG_MANIFEST
        WIN_HELPER_IMAGE_ID SHA256_WIN_HELPER_DOCKERFILE SHA256_WIN_HELPER_DPKG_MANIFEST
    )
    local name
    for name in "${names[@]}"; do require_image_pin "$name"; done
    local dir="$ONLINE_DIR/build-images"
    local deb="$dir/deb-builder.docker.tar.gz" android="$dir/android-builder.docker.tar.gz" win="$dir/win-helper.docker.tar.gz"
    local deb_tmp="$dir/.deb-builder.docker.tar.gz.part" android_tmp="$dir/.android-builder.docker.tar.gz.part" win_tmp="$dir/.win-helper.docker.tar.gz.part"
    [ ! -e "$deb" ] && [ ! -e "$android" ] && [ ! -e "$win" ] || die "one or more final builder archives already exist"
    [ ! -e "$deb_tmp" ] && [ ! -e "$android_tmp" ] && [ ! -e "$win_tmp" ] || die "stale builder archive capture temporary exists"
    require_pinned_builder_image deb-builder
    require_pinned_builder_image android-builder
    require_pinned_builder_image win-helper
    mkdir -p "$dir"
    local deb_result android_result win_result
    trap 'rm -f "$deb_tmp" "$android_tmp" "$win_tmp"' EXIT HUP INT TERM
    deb_result="$(capture_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID" \
        "ubuntu:18.04@${SHA256_BASEIMAGE_UBUNTU_1804}" "$SHA256_DEB_BUILDER_DOCKERFILE" "$SHA256_DEB_BUILDER_DPKG_MANIFEST" "$deb_tmp")"
    android_result="$(capture_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_ANDROID_BUILDER_DOCKERFILE" "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST" "$android_tmp")"
    win_result="$(capture_builder_image win-helper "$WIN_HELPER_IMAGE_ID" \
        "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}" "$SHA256_WIN_HELPER_DOCKERFILE" "$SHA256_WIN_HELPER_DPKG_MANIFEST" "$win_tmp")"
    local deb_sha android_sha win_sha
    deb_sha="$(printf '%s\n' "$deb_result" | sed -n 's/^sha256=//p')"
    android_sha="$(printf '%s\n' "$android_result" | sed -n 's/^sha256=//p')"
    win_sha="$(printf '%s\n' "$win_result" | sed -n 's/^sha256=//p')"
    case "$deb_sha$android_sha$win_sha" in *[!0-9a-f]*|'') die "builder capture returned malformed archive hashes" ;; esac
    [ "${#deb_sha}" -eq 64 ] && [ "${#android_sha}" -eq 64 ] && [ "${#win_sha}" -eq 64 ] \
        || die "builder capture returned malformed archive hash lengths"
    mv "$deb_tmp" "$deb"
    mv "$android_tmp" "$android"
    mv "$win_tmp" "$win"
    trap - EXIT HUP INT TERM
    printf 'SHA256_DEB_BUILDER_IMAGE_ARCHIVE="%s"\n' "$deb_sha"
    printf 'SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE="%s"\n' "$android_sha"
    printf 'SHA256_WIN_HELPER_IMAGE_ARCHIVE="%s"\n' "$win_sha"
}

require_online_fetch_builder_image() {
    local role="$1" image_id="$2"
    assert_online_fetch_docker_authority
    require_pinned_builder_image "$role" "$image_id"
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
    local kind="$1" builder="$2"
    local role package binary tool_version features destination
    case "$kind:$builder" in
        "frb:$DEB_BUILDER_IMAGE_ID")
            role=deb-builder
            package=flutter_rust_bridge_codegen
            binary=flutter_rust_bridge_codegen
            tool_version="$FLUTTER_RUST_BRIDGE_VERSION"
            features=uuid
            destination=frb-tool
            ;;
        "cargo-ndk:$ANDROID_BUILDER_IMAGE_ID")
            role=android-builder
            package=cargo-ndk
            binary=cargo-ndk
            tool_version="$CARGO_NDK_VERSION"
            features=
            destination=cargo-ndk-tool
            ;;
        *) die "networked Cargo tool request is outside the closed producer set" ;;
    esac
    local status=0 input_status=0 output_status=0 publication_status=0
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
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the $kind Cargo tool transaction lock"
        exec {lock_fd}<&-
        log "$kind Cargo tool already staged and semantically verified, skipping"
        return 0
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
    log "installing pinned $package $tool_version into private checked output; ./online is read-only"
    online_docker_run \
        --env CARGO_TOOL_PACKAGE="$package" \
        --env CARGO_TOOL_BINARY="$binary" \
        --env CARGO_TOOL_VERSION="$tool_version" \
        --env CARGO_TOOL_FEATURES="$features" \
        --env RUST_VERSION="$RUST_VERSION" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/tool" \
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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
        cargo_tool_output_tool publish \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}" \
            || publication_status=$?
    fi
    retire_cargo_tool_output_staging "$staging" "$staging_id" "$kind"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the $kind Cargo tool transaction lock"
    exec {lock_fd}<&-
    [ "$input_status" -eq 0 ] || die "networked $kind Cargo tool input postcondition failed"
    [ "$output_status" -eq 0 ] || die "networked $kind Cargo tool output postcondition failed"
    [ "$status" -eq 0 ] || die "networked $kind Cargo tool producer failed"
    [ "$publication_status" -eq 0 ] || die "networked $kind Cargo tool publication failed"
}

# ── The FRB codegen tool (R-B7): built FOR ubuntu:18.04, staged to ./online/frb-tool ──
# build_one needs flutter_rust_bridge_codegen to (re)generate the bridge; it cannot
# `cargo install` it offline (its deps are not in the main vendor set), so build it HERE
# (networked) in the deb-builder image with the pinned rust — exactly as upstream's
# bridge.yml does: `cargo install ... --version <pin> --features uuid --locked`.
build_frb_codegen() {
    local builder="$DEB_BUILDER_IMAGE_ID"
    stage_cargo_installed_tool frb "$builder"
}

# ── The flutter pub cache (R-B7): hosted + git deps, staged to ./online/pub-cache ──
# Pub receives the canonical cache path but only through one nested private output
# mount. The complete online input closure and the exact committed source authority
# remain read-only. Both the app and pinned flutter_tools lockfiles are enforced.
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
    local staging="$1" staging_id="$2" disposition
    disposition="$(
        pub_cache_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
    )" || die "cannot reconcile private Pub-cache output staging"
    log "Pub-cache output staging reconciliation: $disposition"
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
}

recover_pub_cache_output_staging() {
    local stale=() staging staging_id
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
    local cache="$1" builder="$DEB_BUILDER_IMAGE_ID"
    [ -d "$cache" ] && [ ! -L "$cache" ] \
        || die "Pub-cache semantic candidate is not one real directory"
    online_docker_run_pub_semantic \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$cache,target=/online/pub-cache,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY,target=/authority,readonly,bind-recursive=disabled" \
        --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
        --workdir /tmp \
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
        umask 077
        mkdir /tmp/toolchain /tmp/home /tmp/project
        tar -C /tmp/toolchain -xf "/online/flutter-${RUSTDESK_FLUTTER_VERSION}.tar.xz"
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
        (cd /tmp/project && dart pub get --offline --enforce-lockfile >/dev/null)
        (cd /tmp/project && flutter pub get --offline --enforce-lockfile >/dev/null)
        [ "$authority_lock" = "$(sha256sum /tmp/project/pubspec.lock | awk "{print \$1}")" ]

        git_specs=(
          "dash_chat_2|bd6b5b41254e57c5bcece202ebfb234de63e6487|.|https://github.com/rustdesk-org/Dash-Chat-2"
          "desktop_multi_window|b47e8385e5a75d38319ad706a64b0ead3108b093|.|https://github.com/rustdesk-org/rustdesk_desktop_multi_window"
          "dynamic_layouts|24cb88413fa5181d949ddacbb30a65d5c459e7d9|.|https://github.com/rustdesk-org/dynamic_layouts.git"
          "flutter_gpu_texture_renderer|08a471bb8ceccdd50483c81cdfa8b81b07b14b87|.|https://github.com/rustdesk-org/flutter_gpu_texture_renderer"
          "texture_rgba_renderer|42797e0f03141dc2b585f76c64a13974508058b4|.|https://github.com/rustdesk-org/flutter_texture_rgba_renderer"
          "uni_links|f416118d843a7e9ed117c7bb7bdc2deda5a9e86f|uni_links|https://github.com/rustdesk-org/uni_links"
          "window_manager|85789bfe6e4cfaf4ecc00c52857467fdb7f26879|.|https://github.com/rustdesk-org/window_manager"
          "window_size|eb3964990cf19629c89ff8cb4a37640c7b3d5601|plugins/window_size|https://github.com/google/flutter-desktop-embedding.git"
        )
        [ "${#git_specs[@]}" -eq 8 ]
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
            bad_mode="$(
                /usr/bin/git -c safe.directory="$checkout" -C "$checkout" \
                    ls-tree -rz --full-tree -r HEAD \
                    | /usr/bin/python3 -I -S -c "
import sys
for entry in sys.stdin.buffer.read().split(b'\0'):
    if not entry:
        continue
    metadata, path = entry.split(b'\t', 1)
    mode = metadata.split(b' ', 1)[0]
    if mode not in (b'100644', b'100755', b'120000'):
        print(mode.decode('ascii', 'replace'), path.decode('utf-8', 'replace'))
        break
"
            )"
            [ -z "$bad_mode" ]
            [ -f "$checkout/$package_path/pubspec.yaml" ]
            grep -qE "^name:[[:space:]]*$package\$" "$checkout/$package_path/pubspec.yaml"
        done
    '
}

stage_pub_cache() {
    local builder="$DEB_BUILDER_IMAGE_ID"
    local status=0 source_status=0 input_status=0 output_status=0 semantic_status=0 publication_status=0
    local lock_fd receipt="" digest="" existing=0
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
        existing=1
        receipt="$(
            pub_cache_output_tool check-complete \
                --online "$ONLINE_DIR" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
        )" || output_status=$?
        if [ "$output_status" -eq 0 ]; then
            verify_pub_cache_resolution "$ONLINE_DIR/pub-cache" || semantic_status=$?
        fi
    else
        prepare_pub_cache_output_staging
        log "staging both enforced Pub lock closures into one private output; ./online remains read-only"
        online_docker_run \
            --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
            --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
            --mount "type=bind,source=$PUB_CACHE_OUTPUT_STAGING/output,target=/online/pub-cache" \
            --mount "type=bind,source=$GRADLE_SOURCE_BUILD/flutter,target=/project-source,readonly,bind-recursive=disabled" \
            --workdir /tmp/project \
            "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
            umask 077
            mkdir /tmp/toolchain /tmp/home /tmp/project
            tar -C /tmp/toolchain -xf "/online/flutter-${RUSTDESK_FLUTTER_VERSION}.tar.xz"
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
            rm -rf -- "$PUB_CACHE/_temp" "$PUB_CACHE/log" "$PUB_CACHE/README.md"
        ' || status=$?
    fi
    (verify_gradle_source_unchanged) || source_status=$?
    retire_gradle_source_build
    verify_sha256 "$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
        || input_status=$?
    if [ "$existing" -eq 0 ]; then
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
        if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
           && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
            verify_pub_cache_resolution "$PUB_CACHE_OUTPUT_STAGING/output" \
                || semantic_status=$?
        fi
        if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \
           && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ] \
           && [ "$semantic_status" -eq 0 ]; then
            pub_cache_output_tool publish \
                --online "$ONLINE_DIR" --staging "$PUB_CACHE_OUTPUT_STAGING" \
                --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
                "${PUB_CACHE_PROVENANCE_ARGS[@]}" \
                --expected-digest "$digest" \
                || publication_status=$?
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
    [ "$semantic_status" -eq 0 ] || die "networkless Pub-cache semantic replay failed"
    [ "$publication_status" -eq 0 ] || die "networked Pub-cache output publication failed"
    log "Pub cache is structurally closed and both enforced lockfiles resolve offline"
}

# ── vcpkg overlay distfiles (R-B12(a)) ─────────────────────────────────────────
# libvpx uses a SHA512-pinned v1.15.2 archive plus the exact upstream d5f35ac8
# security patch. The overlay consumes only these captures through file:// URLs.
# libyuv fetches from googlesource, whose gitiles
# `+archive` tarballs are EMPIRICALLY non-reproducible (two fetches differ — even decompressed),
# so the URL can't be SHA-pinned and R-R1 forbids vendoring. Capture a deterministic
# `git archive --format=tar | gzip -n` of the pinned commit into ./online + verify its SHA512
# against pins.env; the libyuv overlay portfile then consumes /online/libyuv-<commit>.tar.gz
# (file://, SHA512-verified) on the Linux build hosts — both stage_vcpkg_natives + _arm64 mount the
# SAME file. (The Windows golden VM has no ./online capture, so the portfile falls back to
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
    action="$(
        /usr/bin/python3 -I -S "$LIBVPX_LOCAL_OUTPUT_HELPER" publish \
            --online "$ONLINE_DIR" \
            --source-root "$REPO_ROOT" \
            --source-patch "$REPO_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch" \
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
    local builder="$DEB_BUILDER_IMAGE_ID"
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
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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

vcpkg_native_output_args() {
    local kind="$1" builder="$2"
    printf '%s\0' \
        --uid "$ONLINE_FETCH_UID" \
        --gid "$ONLINE_FETCH_GID" \
        --kind "$kind" \
        --output-key "$(vcpkg_native_output_key "$kind" "$builder")" \
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
    local builder="$DEB_BUILDER_IMAGE_ID"
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
        --mount "type=bind,source=$staging/output,target=/outputs/native" \
        --env RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        --env VCPKG_NATIVE_OUTPUT_KEY="$(vcpkg_native_output_key x64-linux "$builder")" \
        --env LIBVPX_NATIVE_KEY="$(libvpx_native_key)" \
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
            export HOME=/tmp/home; mkdir -p "$HOME"
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            export VCPKG_BINARY_SOURCES=clear
            # Build the native codecs with the pinned gcc-8 toolchain used by the
            # offline deb-builder image, keeping C/C++ object generation stable. The
            # outputs are C-ABI static libs → link fine into the gcc/rust cargo build.
            export CC=/usr/bin/gcc-8 CXX=/usr/bin/g++-8
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet x64-linux --overlay-ports=/overlay \
                libvpx libyuv opus
            install -d -m 0700 /outputs/native/include /outputs/native/lib
            cp -a "$VR"/installed/x64-linux/include/. /outputs/native/include/
            for archive in libjpeg.a libopus.a libturbojpeg.a libvpx.a libyuv.a; do
                cp -a "$VR/installed/x64-linux/lib/$archive" /outputs/native/lib/
            done
            printf "%s\n" "$VCPKG_NATIVE_OUTPUT_KEY" \
                > /outputs/native/.rustdesk-vcpkg-native-output-key-v1
            printf "%s\n" "$LIBVPX_NATIVE_KEY" \
                > /outputs/native/.rustdesk-libvpx-native-key
        ' || status=$?
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
    local builder="$ANDROID_BUILDER_IMAGE_ID"
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
        "$builder" \
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
# builtin-baseline), but ./online stages the pinned TARBALL (no .git) — classic mode over the
# tarball baseline ports + the overlay is equivalent + git-free.
stage_vcpkg_natives_arm64() {
    local builder="$ANDROID_BUILDER_IMAGE_ID"
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
        --mount "type=bind,source=$staging/output,target=/outputs/native" \
        --env RUSTDESK_VCPKG_DISTFILES_DIR=/online/vcpkg-distfiles \
        --env VCPKG_NATIVE_OUTPUT_KEY="$(vcpkg_native_output_key arm64-android "$builder")" \
        --env LIBVPX_NATIVE_KEY="$(libvpx_native_key)" \
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
            export HOME=/tmp/home; mkdir -p "$HOME"
            export ANDROID_NDK_HOME=/online/android-ndk
            VR=/tmp/vcpkg; mkdir -p "$VR"
            tar -C "$VR" --strip-components=1 -xzf /online/vcpkg-'"${VCPKG_BASELINE}"'.tar.gz
            export VCPKG_DISABLE_METRICS=1
            export VCPKG_BINARY_SOURCES=clear
            "$VR"/bootstrap-vcpkg.sh -disableMetrics >/dev/null
            "$VR"/vcpkg install --triplet arm64-android --overlay-ports=/overlay \
                libvpx libyuv opus oboe
            install -d -m 0700 /outputs/native/include /outputs/native/lib
            cp -a "$VR"/installed/arm64-android/include/. /outputs/native/include/
            for archive in libjpeg.a liboboe.a libopus.a libturbojpeg.a libvpx.a libyuv.a; do
                cp -a "$VR/installed/arm64-android/lib/$archive" /outputs/native/lib/
            done
            printf "%s\n" "$VCPKG_NATIVE_OUTPUT_KEY" \
                > /outputs/native/.rustdesk-vcpkg-native-output-key-v1
            printf "%s\n" "$LIBVPX_NATIVE_KEY" \
                > /outputs/native/.rustdesk-libvpx-native-key
        ' || status=$?
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
# (`cargo install cargo-ndk --version <pin> --locked`). A host-target tool → ./online/cargo-ndk-tool.
stage_cargo_ndk() {
    local builder="$ANDROID_BUILDER_IMAGE_ID"
    stage_cargo_installed_tool cargo-ndk "$builder"
}

# ── The exact Android SDK archive closure ──────────────────────────────────────
# SDK package aliases are repository-resolution inputs, not content pins. Fetch six
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
    local builder="$ANDROID_BUILDER_IMAGE_ID"
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
        "$builder" \
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
# shared android build flow online (APK_MODE=warm, scripts/android-apk-build.sh) — it writes
# one private /outputs/gradle-home candidate. The exact SDK closure is already complete and stays
# read-only throughout warming. build_apk later projects the Gradle cache into private writable
# execution state whose tracked init authority enables offline mode.
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
        verify_gradle_live_checkout_state "before exact-source reuse" \
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
    verify_gradle_live_checkout_state "before Gradle warming" \
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
    if ! verify_gradle_live_checkout_state "after Gradle warming"; then
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
    local staging="$1" staging_id="$2" disposition
    disposition="$(
        gradle_output_tool recover \
            --online "$ONLINE_DIR" --staging "$staging" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
    )" || die "cannot reconcile private Gradle output staging"
    log "Gradle output staging reconciliation: $disposition"
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
}

recover_gradle_output_staging() {
    local stale=() staging staging_id
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
    GRADLE_OUTPUT_STAGING="$(
        umask 077
        /usr/bin/mktemp -d "$ONLINE_DIR/.rustdesk-gradle-warm.XXXXXXXXXX"
    )" || die "cannot create same-filesystem private Gradle output staging"
    GRADLE_OUTPUT_STAGING_ID="$(/usr/bin/stat -c '%d:%i' -- "$GRADLE_OUTPUT_STAGING")"
    readonly GRADLE_OUTPUT_STAGING GRADLE_OUTPUT_STAGING_ID
    if ! gradle_output_tool prepare \
        --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID"
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

stage_gradle() {
    local builder="$ANDROID_BUILDER_IMAGE_ID"
    local status=0 source_status=0 output_status=0 publication_status=0
    local lock_fd semantic_args=() sdk_args=()
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
        gradle_output_tool check-complete \
            --online "$ONLINE_DIR" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}" \
            || die "existing Gradle/SDK output is incomplete or structurally unsafe"
        retire_gradle_source_build
        "$FLOCK_BIN" --unlock "$lock_fd" \
            || die "cannot release the Gradle output transaction lock"
        exec {lock_fd}<&-
        log "gradle cache already warm and semantically verified, skipping"
        return 0
    fi
    prepare_gradle_output_staging
    log "warming Gradle into one private cache output; the exact SDK and ./online remain read-only"
    online_docker_run \
        --env APK_MODE=warm \
        --env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home \
        --mount "type=bind,source=$GRADLE_SOURCE_BUILD,target=/src" \
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly" \
        --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home" \
        --workdir /src \
        "$builder" /bin/bash --noprofile --norc /authority/android-apk-build.sh \
        || status=$?
    (verify_gradle_source_unchanged) || source_status=$?
    retire_gradle_source_build
    restore_gradle_output_traversal
    gradle_output_tool verify \
        --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
        --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
        "${semantic_args[@]}" \
        || output_status=$?
    if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] && [ "$output_status" -eq 0 ]; then
        gradle_output_tool publish \
            --online "$ONLINE_DIR" --staging "$GRADLE_OUTPUT_STAGING" \
            --uid "$ONLINE_FETCH_UID" --gid "$ONLINE_FETCH_GID" \
            "${semantic_args[@]}" \
            || publication_status=$?
    fi
    retire_gradle_output_staging "$GRADLE_OUTPUT_STAGING" "$GRADLE_OUTPUT_STAGING_ID"
    "$FLOCK_BIN" --unlock "$lock_fd" \
        || die "cannot release the Gradle output transaction lock"
    exec {lock_fd}<&-
    [ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"
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
        --builder "$ANDROID_BUILDER_IMAGE_ID" \
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
    local builder="$ANDROID_BUILDER_IMAGE_ID"
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
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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
                /usr/bin/printf '%s\n' \
                    bin/cache/libimobiledevice.stamp \
                    bin/cache/usbmuxd.stamp \
                    bin/cache/windows-sdk.stamp
            } | /usr/bin/sort -u > /tmp/stage.txt
            [ "$(/usr/bin/wc -l < /tmp/stage.txt)" -eq 73 ] || {
                echo "precache output does not match the exact 73-file Windows projection" >&2
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
            "$builder" /usr/bin/python3 -I -S \
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
        --builder "$ANDROID_BUILDER_IMAGE_ID" \
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
    local archive="$1" builder="$ANDROID_BUILDER_IMAGE_ID"
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
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
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
        [ -d /tmp/pub-cache/hosted/pub.dev/.cache ]
        /usr/bin/find /tmp/pub-cache/hosted/pub.dev/.cache \
            -type f -exec /usr/bin/touch -- {} +
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
    local builder="$ANDROID_BUILDER_IMAGE_ID"
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
        --mount "type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/online-flutter-pub-cache-output.py,target=/authority/online-flutter-pub-cache-output.py,readonly,bind-recursive=disabled" \
        --mount "type=bind,source=$staging/output,target=/outputs/pub-cache.tar.gz" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SHA256=$SHA256_FLUTTER_PUB_CACHE" \
        --env "RUSTDESK_FLUTTER_PUB_CACHE_SIZE=$SIZE_FLUTTER_PUB_CACHE" \
        "$builder" /bin/bash --noprofile --norc -euo pipefail -c '
        export LC_ALL=C
        cd /inputs/pub-cache
        /usr/bin/tar --sort=name --mtime=@1700000000 \
            --owner=0 --group=0 --numeric-owner \
            --mode="u+rwX,go+rX,go-w" \
            -cf - hosted hosted-hashes \
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
            load_builder_images
            stage_windows_wix_nuget
            return 0
            ;;
        --maintenance-build-image-candidates)
            [ "$#" -eq 1 ] || die "--maintenance-build-image-candidates takes no arguments"
            maintenance_build_image_candidates
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
        --maintenance-build-rust-audit-image-candidate)
            [ "$#" -eq 1 ] || die "--maintenance-build-rust-audit-image-candidate takes no arguments"
            maintenance_build_rust_audit_image_candidate
            return 0
            ;;
        --dart-audit-inputs)
            [ "$#" -eq 1 ] || die "--dart-audit-inputs takes no arguments"
            stage_dart_audit_inputs
            return 0
            ;;
        --maintenance-capture-builder-images)
            [ "$#" -eq 1 ] || die "--maintenance-capture-builder-images takes no arguments"
            maintenance_capture_builder_images
            return 0
            ;;
        --maintenance-capture-devcheck-image)
            [ "$#" -eq 1 ] || die "--maintenance-capture-devcheck-image takes no arguments"
            maintenance_capture_devcheck_image
            return 0
            ;;
        --maintenance-capture-apple-check-image)
            [ "$#" -eq 1 ] || die "--maintenance-capture-apple-check-image takes no arguments"
            maintenance_capture_apple_check_image
            return 0
            ;;
        --maintenance-capture-dart-audit-image)
            [ "$#" -eq 1 ] || die "--maintenance-capture-dart-audit-image takes no arguments"
            maintenance_capture_dart_audit_image
            return 0
            ;;
        --maintenance-capture-rust-audit-image)
            [ "$#" -eq 1 ] || die "--maintenance-capture-rust-audit-image takes no arguments"
            maintenance_capture_rust_audit_image
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
        *) die "usage: scripts/online-fetch.sh [--libvpx-distfiles|--wix-nuget-packages|--dart-audit-inputs|--maintenance-build-image-candidates|--maintenance-build-apple-check-image-candidate|--maintenance-build-dart-audit-image-candidate|--maintenance-build-rust-audit-image-candidate|--maintenance-capture-builder-images|--maintenance-capture-devcheck-image|--maintenance-capture-apple-check-image|--maintenance-capture-dart-audit-image|--maintenance-capture-rust-audit-image|--devcheck-image|--apple-check-image|--dart-audit-image|--rust-audit-image|--maintenance-print-online-closure|--maintenance-write-online-closure|--verify-offline-inputs|--debian-systemd-smoke-image]" ;;
    esac
    log "online-fetch: materializing the SHA-256-verified ./online cache (R-B10)"
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
    log "online-fetch complete — ./online equals its pinned closure. Builds run --network=none."
}

main "$@"

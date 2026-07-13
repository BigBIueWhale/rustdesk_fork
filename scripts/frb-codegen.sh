#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

SOURCE_ROOT=""
OUTPUT_ROOT=""
FRB_ONLINE_ROOT=""
WORK_ROOT=""
GENERATED_BRIDGES=(
    src/bridge_generated.rs
    src/bridge_generated.io.rs
    flutter/lib/generated_bridge.dart
    flutter/lib/generated_bridge.freezed.dart
)

usage() {
    printf 'usage: %s --source-root DIR --online-root READ_ONLY_DIR --output-root ABSENT_DIR\n' "${0##*/}" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-root)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            SOURCE_ROOT="$2"
            shift 2
            ;;
        --output-root)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --online-root)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            FRB_ONLINE_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "unknown frb-codegen argument: $1"
            ;;
    esac
done

[ -n "$SOURCE_ROOT" ] && [ -n "$FRB_ONLINE_ROOT" ] && [ -n "$OUTPUT_ROOT" ] \
    || { usage; exit 2; }

assert_safe_path() {
    local value="$1" label="$2"
    [ -n "$value" ] || die "$label is empty"
    [ "${value#/}" != "$value" ] || die "$label must be absolute: $value"
    case "$value" in
        *','*|*':'*) die "$label contains a Docker/libvirt option delimiter: $value" ;;
    esac
    if LC_ALL=C printf '%s' "$value" | grep -q '[[:cntrl:]]'; then
        die "$label contains a control character"
    fi
}

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$WORK_ROOT" ] && [ -d "$WORK_ROOT" ]; then
        chmod -R u+rwX "$WORK_ROOT" 2>/dev/null || :
        rm -rf -- "$WORK_ROOT"
    fi
    exit "$status"
}
signal_exit() {
    local status="$1"
    trap - HUP INT TERM
    exit "$status"
}
trap cleanup EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

require_cmd docker git python3 realpath
SOURCE_ROOT="$(realpath -e -- "$SOURCE_ROOT")"
ONLINE_DIR="$(realpath -e -- "$FRB_ONLINE_ROOT")"
export ONLINE_DIR
OUTPUT_PARENT="$(realpath -e -- "$(dirname "$OUTPUT_ROOT")")"
OUTPUT_ROOT="$OUTPUT_PARENT/$(basename "$OUTPUT_ROOT")"
assert_safe_path "$SOURCE_ROOT" "FRB source root"
assert_safe_path "$OUTPUT_ROOT" "FRB output root"
assert_safe_path "$ONLINE_DIR" "FRB online snapshot"
[ -d "$SOURCE_ROOT" ] && [ ! -L "$SOURCE_ROOT" ] || die "FRB source root is not a regular directory"
[ -d "$ONLINE_DIR" ] && [ ! -L "$ONLINE_DIR" ] || die "FRB online snapshot is not a regular directory"
[ -d "$OUTPUT_PARENT" ] && [ ! -L "$OUTPUT_PARENT" ] || die "FRB output parent is not a regular directory"
{ [ ! -e "$OUTPUT_ROOT" ] && [ ! -L "$OUTPUT_ROOT" ]; } || die "FRB output root must not exist: $OUTPUT_ROOT"
case "$OUTPUT_ROOT/" in
    "$SOURCE_ROOT/"*) die "FRB output root must not be inside the source snapshot" ;;
esac

require_online_complete
verify_online_shas \
    "rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
    "flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
    "llvm-${LLVM_VERSION}.tar.xz" "$SHA256_LLVM_15_0_6" \
    "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "$SHA256_FRB_1_80_1"
python3 - "$ONLINE_DIR" "$FLUTTER_RUST_BRIDGE_VERSION" "$RUST_VERSION" "$FLUTTER_VERSION" "$LLVM_VERSION" <<'PY'
import json
import os
import stat
import sys

root, version, rust_version, flutter_version, llvm_version = sys.argv[1:]
def assert_read_only_tree(tree, label, allow_symlinks):
    for directory, names, files in os.walk(tree, topdown=True, followlinks=False):
        for name in [".", *names, *files]:
            path = directory if name == "." else os.path.join(directory, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                if not allow_symlinks:
                    raise SystemExit(f"{label} contains a symlink: {path}")
                continue
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise SystemExit(f"{label} contains a special file: {path}")
            if info.st_mode & 0o222:
                raise SystemExit(f"{label} has a writable entry: {path}")

assert_read_only_tree(root, "FRB online snapshot", True)

for relative in (
    f"rust-{rust_version}.tar.xz",
    f"flutter-{flutter_version}.tar.xz",
    f"llvm-{llvm_version}.tar.xz",
    f"frb-{version}.tar.gz",
    "frb-tool/.crates2.json",
    "frb-tool/bin/flutter_rust_bridge_codegen",
):
    path = os.path.join(root, relative)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size == 0:
        raise SystemExit(f"FRB input is not one nonempty regular file: {relative}")

metadata_path = os.path.join(root, "frb-tool", ".crates2.json")
with open(metadata_path, "rb") as stream:
    raw = stream.read()
if not raw or raw[:1] != b"{" or b"\r" in raw or b"\0" in raw:
    raise SystemExit("FRB installation metadata is not canonical JSON")
metadata = json.loads(raw)
key = f"flutter_rust_bridge_codegen {version} (registry+https://github.com/rust-lang/crates.io-index)"
if set(metadata) != {"installs"} or set(metadata["installs"]) != {key}:
    raise SystemExit("FRB installation metadata does not identify exactly the pinned generator")
install = metadata["installs"][key]
required = {
    "all_features": False,
    "bins": ["flutter_rust_bridge_codegen"],
    "features": ["uuid"],
    "no_default_features": False,
    "profile": "release",
    "target": "x86_64-unknown-linux-gnu",
    "version_req": f"={version}",
}
if set(install) != {*required, "rustc"} or any(install[name] != value for name, value in required.items()):
    raise SystemExit("FRB installation metadata does not match the pinned build contract")
if not isinstance(install["rustc"], str) or not install["rustc"].startswith(f"rustc {rust_version}.0 "):
    raise SystemExit("FRB generator was not built by the pinned Rust toolchain")

binary = os.path.join(root, "frb-tool", "bin", "flutter_rust_bridge_codegen")
info = os.lstat(binary)
if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or not info.st_mode & 0o111:
    raise SystemExit("FRB generator is not one nonempty executable regular file")
PY
python3 - "$SOURCE_ROOT" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
for directory, names, files in os.walk(root, topdown=True, followlinks=False):
    for name in [".", *names, *files]:
        path = directory if name == "." else os.path.join(directory, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"FRB source snapshot contains a symlink: {path}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SystemExit(f"FRB source snapshot contains a special file: {path}")
        if info.st_mode & 0o222:
            raise SystemExit(f"FRB source snapshot has a writable entry: {path}")
PY

IMAGE_ID="${FRB_IMAGE_ID:-}"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "FRB image has a malformed immutable ID: $IMAGE_ID"
[ "$IMAGE_ID" = "${DEB_BUILDER_IMAGE_ID:-}" ] \
    || die "FRB_IMAGE_ID does not equal the audited deb-builder image pin"
require_pinned_builder_image deb-builder "$IMAGE_ID"

WORK_ROOT="$(mktemp -d "$OUTPUT_PARENT/.frb-work.XXXXXXXX")"
WORK_SOURCE="$WORK_ROOT/source"
PUBLISH_ROOT="$WORK_ROOT/publish"
mkdir -p "$WORK_SOURCE" "$PUBLISH_ROOT"
cp -a --reflink=auto "$SOURCE_ROOT/." "$WORK_SOURCE/"
chmod -R u+rwX "$WORK_SOURCE"

PUBSPEC_LOCK_SOURCE="$SOURCE_ROOT/flutter/pubspec.lock"
PUBSPEC_LOCK_WORK="$WORK_SOURCE/flutter/pubspec.lock"
[ -f "$PUBSPEC_LOCK_SOURCE" ] && [ ! -L "$PUBSPEC_LOCK_SOURCE" ] \
    || die "source snapshot flutter/pubspec.lock is not a regular file"
pubspec_lock_before="$(sha256sum "$PUBSPEC_LOCK_SOURCE" | awk '{print $1}')"

for relative in "${GENERATED_BRIDGES[@]}"; do
    rm -f -- "$WORK_SOURCE/$relative"
    { [ ! -e "$WORK_SOURCE/$relative" ] && [ ! -L "$WORK_SOURCE/$relative" ]; } \
        || die "could not establish an absent FRB output: $relative"
done

log "generating FRB outputs from private source snapshot with image $IMAGE_ID"
docker run --rm --network=none --read-only --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777 \
    --mount "type=bind,source=$WORK_SOURCE,target=/src" \
    --mount "type=bind,source=$ONLINE_DIR,target=/online,readonly" \
    --workdir /src "$IMAGE_ID" \
    bash -euo pipefail -c '
        TC=/tmp/rustdesk-frb-toolchain
        HOME=/tmp/rustdesk-frb-home
        CARGO_HOME=/tmp/rustdesk-frb-cargo
        SHIM=/tmp/rustdesk-frb-shim
        rm -rf "$TC" "$HOME" "$CARGO_HOME" "$SHIM"
        mkdir -p "$TC" "$HOME" "$CARGO_HOME" "$SHIM"
        export HOME CARGO_HOME
        tar -C "$TC" -xf /online/rust-'"$RUST_VERSION"'.tar.xz
        tar -C "$TC" -xf /online/flutter-'"$FLUTTER_VERSION"'.tar.xz
        tar -C "$TC" -xf /online/llvm-'"$LLVM_VERSION"'.tar.xz
        rust_installer=("$TC"/rust-1.*/install.sh)
        [ "${#rust_installer[@]}" -eq 1 ] && [ -f "${rust_installer[0]}" ]
        "${rust_installer[0]}" --prefix="$TC/rustinstall" --disable-ldconfig \
            --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
        llvm_roots=("$TC"/clang+llvm-*)
        [ "${#llvm_roots[@]}" -eq 1 ] && [ -d "${llvm_roots[0]}" ]
        LLVM_ROOT="${llvm_roots[0]}"
        export LIBCLANG_PATH="$LLVM_ROOT/lib"
        export PATH="$TC/flutter/bin:$TC/rustinstall/bin:$CARGO_HOME/bin:$PATH"
        export REAL_FLUTTER="$TC/flutter/bin/flutter"
        cp /src/scripts/flutter-offline-shim.sh "$SHIM/flutter"
        chmod +x "$SHIM/flutter"
        export PATH="$SHIM:$PATH"
        {
            printf "[net]\noffline = true\n"
            sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" /online/cargo-vendor-config.toml
        } > "$CARGO_HOME/config.toml"
        git config --global --add safe.directory /src
        export PUB_CACHE=/online/pub-cache CI=true
        (cd flutter && dart pub get --offline)
        (cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline)
        clang_headers=("$LLVM_ROOT"/lib/clang/*/include)
        [ "${#clang_headers[@]}" -eq 1 ] && [ -d "${clang_headers[0]}" ]
        /online/frb-tool/bin/flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
            --dart-output ./flutter/lib/generated_bridge.dart \
            --llvm-path "$LLVM_ROOT" \
            --llvm-compiler-opts="-I${clang_headers[0]}"
    '

pubspec_lock_after="$(sha256sum "$PUBSPEC_LOCK_WORK" | awk '{print $1}')"
[ "$pubspec_lock_after" = "$pubspec_lock_before" ] \
    || die "flutter/pubspec.lock changed during FRB generation"
[ "$(sha256sum "$PUBSPEC_LOCK_SOURCE" | awk '{print $1}')" = "$pubspec_lock_before" ] \
    || die "the immutable source snapshot changed during FRB generation"

for relative in "${GENERATED_BRIDGES[@]}"; do
    generated="$WORK_SOURCE/$relative"
    [ -f "$generated" ] && [ ! -L "$generated" ] && [ -s "$generated" ] \
        || die "FRB did not produce a nonempty regular file: $relative"
    [ "$(stat -c %u "$generated")" = "$(id -u)" ] \
        || die "FRB output is not owned by the invoking uid: $relative"
    [ "$(stat -c %g "$generated")" = "$(id -g)" ] \
        || die "FRB output is not owned by the invoking gid: $relative"
    mkdir -p "$PUBLISH_ROOT/$(dirname "$relative")"
    install -m 0644 "$generated" "$PUBLISH_ROOT/$relative"
done

(
    cd "$PUBLISH_ROOT"
    sha256sum "${GENERATED_BRIDGES[@]}" > .frb-manifest.sha256
)
mv -T --no-clobber -- "$PUBLISH_ROOT" "$OUTPUT_ROOT"
[ ! -e "$PUBLISH_ROOT" ] && [ ! -L "$PUBLISH_ROOT" ] \
    || die "FRB output root appeared during atomic publication"
rm -rf -- "$WORK_SOURCE"
rmdir "$WORK_ROOT"
WORK_ROOT=""
log "FRB outputs published atomically to $OUTPUT_ROOT"

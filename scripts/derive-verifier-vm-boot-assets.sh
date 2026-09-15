#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly UID_NOW="$(/usr/bin/id -u)"
readonly GID_NOW="$(/usr/bin/id -g)"
readonly STATE_ROOT="$REPO_ROOT/.harness-state/verifier-vm"
readonly IMAGE_NAME="debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2"
readonly BASE="$STATE_ROOT/$IMAGE_NAME"
readonly BOOT_ROOT="$STATE_ROOT/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"
readonly KERNEL="$BOOT_ROOT/vmlinuz"
readonly INITRD="$BOOT_ROOT/initrd.img"
readonly DERIVER_SOURCE="${BASH_SOURCE[0]}"
readonly LIB_SOURCE="$SCRIPT_DIR/lib.sh"
readonly PIN_SOURCE="$SCRIPT_DIR/pins.env"
readonly CLEANUP_HELPER="$SCRIPT_DIR/verify-private-tree-closure.py"
readonly DISK_SIZE=$((3 * 1024 * 1024 * 1024))
readonly SECTOR_SIZE=512
readonly PARTITION_BYTES=$((VERIFIER_VM_ROOT_PARTITION_SECTORS * SECTOR_SIZE))

TRANSACTION=
TRANSACTION_ID=

fail() {
    printf 'verifier-VM boot derivation: %s\n' "$*" >&2
    exit 1
}

verify_digest() {
    [ "$#" -eq 3 ] || fail 'internal digest-verification argument error'
    local algorithm=$1 path=$2 expected=$3 observed
    observed="$("/usr/bin/${algorithm}sum" -- "$path")" \
        || fail "cannot hash boot asset: $path"
    [ "${observed%% *}" = "$expected" ] \
        || fail "boot asset digest differs: $path"
}

verify_boot_cache() {
    local inventory path size digest
    [ -d "$BOOT_ROOT" ] && [ ! -L "$BOOT_ROOT" ] \
        || fail 'direct-boot cache is not one real directory'
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$BOOT_ROOT")" = "$UID_NOW:$GID_NOW:500" ] \
        || fail 'direct-boot cache directory metadata differs'
    inventory="$(/usr/bin/find "$BOOT_ROOT" -mindepth 1 -maxdepth 1 -printf x)" \
        || fail 'cannot inventory direct-boot cache'
    [ "$inventory" = xx ] || fail 'direct-boot cache inventory differs'
    for specification in \
        "$KERNEL:$SIZE_VERIFIER_VM_KERNEL:$SHA256_VERIFIER_VM_KERNEL" \
        "$INITRD:$SIZE_VERIFIER_VM_INITRD:$SHA256_VERIFIER_VM_INITRD"; do
        path=${specification%%:*}
        specification=${specification#*:}
        size=${specification%%:*}
        digest=${specification#*:}
        [ -f "$path" ] && [ ! -L "$path" ] \
            || fail "direct-boot asset is absent or symlinked: $path"
        [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
          "$UID_NOW:$GID_NOW:400:1:$size" ] \
            || fail "direct-boot asset metadata differs: $path"
        verify_digest sha256 "$path" "$digest"
    done
}

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [ -n "$TRANSACTION" ]; then
        if [ -d "$TRANSACTION" ] && [ ! -L "$TRANSACTION" ] \
           && [ "$(/usr/bin/stat -c '%d:%i' -- "$TRANSACTION" 2>/dev/null)" = \
                "$TRANSACTION_ID" ]; then
            /usr/bin/python3 -I -S "$CLEANUP_HELPER" \
                --remove-private-root "$TRANSACTION" \
                --expected-identity "$TRANSACTION_ID" \
                || cleanup_status=1
        else
            printf 'verifier-VM boot derivation: transaction identity changed: %s\n' \
                "$TRANSACTION" >&2
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

[ "$UID_NOW" -ne 0 ] || fail 'host or container-root execution is forbidden'
[ "$GID_NOW" -ne 0 ] || fail 'a root primary group is forbidden'
[[ "$VERIFIER_VM_KERNEL_RELEASE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-cloud-amd64$ ]] \
    || fail 'kernel-release pin is malformed'
[[ "$VERIFIER_VM_ROOT_PARTITION_TYPE_GUID" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] \
    || fail 'root-partition type GUID pin is malformed'
[[ "$VERIFIER_VM_ROOT_PARTITION_UNIQUE_GUID" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] \
    || fail 'root-partition unique GUID pin is malformed'
[[ "$VERIFIER_VM_ROOT_FILESYSTEM_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || fail 'root-filesystem UUID pin is malformed'
for numeric_pin in VERIFIER_VM_ROOT_PARTITION_FIRST_SECTOR \
    VERIFIER_VM_ROOT_PARTITION_SECTORS SIZE_VERIFIER_VM_KERNEL \
    SIZE_VERIFIER_VM_INITRD; do
    value=${!numeric_pin}
    case "$value" in 0|*[!0-9]*|'') fail "$numeric_pin is malformed" ;; esac
done
for digest_pin in SHA256_VERIFIER_VM_KERNEL SHA256_VERIFIER_VM_INITRD; do
    [[ "${!digest_pin}" =~ ^[0-9a-f]{64}$ ]] \
        || fail "$digest_pin is malformed"
done

for tool in /usr/bin/awk /usr/bin/chmod /usr/bin/dd /usr/bin/dirname \
    /usr/bin/env /usr/bin/find /usr/bin/grep /usr/bin/id /usr/bin/mkdir \
    /usr/bin/mktemp /usr/bin/mv /usr/bin/pwd /usr/bin/python3 \
    /usr/bin/qemu-img /usr/bin/readlink /usr/bin/sha256sum \
    /usr/bin/sha512sum /usr/bin/stat /usr/sbin/debugfs /usr/sbin/sgdisk; do
    resolved="$(/usr/bin/readlink -f -- "$tool" 2>/dev/null)" \
        || fail "cannot resolve fixed derivation tool: $tool"
    [ -f "$resolved" ] && [ ! -L "$resolved" ] && [ -x "$resolved" ] \
        || fail "fixed derivation tool is unavailable: $tool"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$resolved")" = 0:0:755:1 ] \
        || fail "fixed derivation tool metadata changed: $tool"
done
for source in "$DERIVER_SOURCE" "$LIB_SOURCE" "$PIN_SOURCE" "$CLEANUP_HELPER"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "boot-derivation source is absent or ambiguous: $source"
done
[ -x "$DERIVER_SOURCE" ] && [ -x "$CLEANUP_HELPER" ] \
    || fail 'boot-derivation executable source is not executable'
sources_before="$(/usr/bin/sha256sum "$DERIVER_SOURCE" "$LIB_SOURCE" "$PIN_SOURCE" "$CLEANUP_HELPER")"

[ -d "$STATE_ROOT" ] && [ ! -L "$STATE_ROOT" ] \
    || fail 'verifier-VM state root is absent or ambiguous'
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STATE_ROOT")" = "$UID_NOW:$GID_NOW:700" ] \
    || fail 'verifier-VM state root is not current-user/current-group mode 0700'
[ -f "$BASE" ] && [ ! -L "$BASE" ] \
    || fail 'authenticated Debian verifier-VM base is absent'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$BASE")" = \
  "$UID_NOW:$GID_NOW:400:1:$SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE" ] \
    || fail 'Debian verifier-VM base metadata differs'
verify_digest sha512 "$BASE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
base_before="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BASE"):$(/usr/bin/sha512sum "$BASE")"
/usr/bin/qemu-img check -q "$BASE" || fail 'Debian verifier-VM base failed qcow2 validation'
/usr/bin/python3 -I -S - "$BASE" "$DISK_SIZE" <<'PY'
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
if data.get("virtual-size") != int(sys.argv[2]):
    raise SystemExit("verifier-VM base virtual size differs")
PY

if [ -e "$BOOT_ROOT" ] || [ -L "$BOOT_ROOT" ]; then
    verify_boot_cache
    [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BASE"):$(/usr/bin/sha512sum "$BASE")" = \
      "$base_before" ] || fail 'authenticated base changed during cache validation'
    [ "$(/usr/bin/sha256sum "$DERIVER_SOURCE" "$LIB_SOURCE" "$PIN_SOURCE" "$CLEANUP_HELPER")" = \
      "$sources_before" ] || fail 'boot-derivation source changed during cache validation'
    printf 'VERIFIER_VM_BOOT_ASSETS=pass source=authenticated-qcow2 cache=existing kernel=%s\n' \
        "$VERIFIER_VM_KERNEL_RELEASE"
    exit 0
fi

TRANSACTION="$(/usr/bin/mktemp -d "$STATE_ROOT/derive-boot.XXXXXXXXXX")" \
    || fail 'cannot create the private boot-derivation transaction'
TRANSACTION_ID="$(/usr/bin/stat -c '%d:%i' -- "$TRANSACTION")"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$TRANSACTION")" = "$UID_NOW:$GID_NOW:700" ] \
    || fail 'boot-derivation transaction metadata differs'
readonly RAW="$TRANSACTION/base.raw"
readonly PARTITION="$TRANSACTION/root.ext4"
readonly GPT_INFO="$TRANSACTION/partition.info"
readonly FS_INFO="$TRANSACTION/filesystem.info"
readonly STAGING="$TRANSACTION/direct-boot-${VERIFIER_VM_KERNEL_RELEASE}"

/usr/bin/qemu-img convert -f qcow2 -O raw -- "$BASE" "$RAW" \
    || fail 'cannot convert the authenticated base to a sparse raw image'
[ -f "$RAW" ] && [ ! -L "$RAW" ] \
    || fail 'derived raw image is absent or symlinked'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$RAW")" = \
  "$UID_NOW:$GID_NOW:600:1:$DISK_SIZE" ] \
    || fail 'derived raw image metadata differs'

/usr/sbin/sgdisk -i 1 "$RAW" >"$GPT_INFO" \
    || fail 'cannot inspect the authenticated image partition table'
[ "$(/usr/bin/grep -c '^Partition GUID code:' "$GPT_INFO")" = 1 ] \
    || fail 'root-partition type record is ambiguous'
[ "$(/usr/bin/grep -c '^Partition unique GUID:' "$GPT_INFO")" = 1 ] \
    || fail 'root-partition identity record is ambiguous'
[ "$(/usr/bin/grep -c '^First sector:' "$GPT_INFO")" = 1 ] \
    || fail 'root-partition first-sector record is ambiguous'
[ "$(/usr/bin/grep -c '^Last sector:' "$GPT_INFO")" = 1 ] \
    || fail 'root-partition last-sector record is ambiguous'
[ "$(/usr/bin/grep -c '^Partition size:' "$GPT_INFO")" = 1 ] \
    || fail 'root-partition size record is ambiguous'
partition_type="$(/usr/bin/awk '/^Partition GUID code:/ { print $4 }' "$GPT_INFO")"
partition_guid="$(/usr/bin/awk '/^Partition unique GUID:/ { print $4 }' "$GPT_INFO")"
partition_first="$(/usr/bin/awk '/^First sector:/ { print $3 }' "$GPT_INFO")"
partition_last="$(/usr/bin/awk '/^Last sector:/ { print $3 }' "$GPT_INFO")"
partition_sectors="$(/usr/bin/awk '/^Partition size:/ { print $3 }' "$GPT_INFO")"
[ "$partition_type" = "$VERIFIER_VM_ROOT_PARTITION_TYPE_GUID" ] \
    || fail 'root-partition type differs'
[ "$partition_guid" = "$VERIFIER_VM_ROOT_PARTITION_UNIQUE_GUID" ] \
    || fail 'root-partition identity differs'
[ "$partition_first" = "$VERIFIER_VM_ROOT_PARTITION_FIRST_SECTOR" ] \
    || fail 'root-partition first sector differs'
[ "$partition_sectors" = "$VERIFIER_VM_ROOT_PARTITION_SECTORS" ] \
    || fail 'root-partition sector count differs'
[ "$partition_last" = \
  "$((VERIFIER_VM_ROOT_PARTITION_FIRST_SECTOR + VERIFIER_VM_ROOT_PARTITION_SECTORS - 1))" ] \
    || fail 'root-partition final sector differs'

/usr/bin/dd if="$RAW" of="$PARTITION" bs="$SECTOR_SIZE" \
    skip="$VERIFIER_VM_ROOT_PARTITION_FIRST_SECTOR" \
    count="$VERIFIER_VM_ROOT_PARTITION_SECTORS" conv=sparse status=none \
    || fail 'cannot extract the exact root partition'
[ -f "$PARTITION" ] && [ ! -L "$PARTITION" ] \
    || fail 'derived root partition is absent or symlinked'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$PARTITION")" = \
  "$UID_NOW:$GID_NOW:600:1:$PARTITION_BYTES" ] \
    || fail 'derived root-partition metadata differs'

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C DEBUGFS_PAGER=/usr/bin/cat \
    /usr/sbin/debugfs -R stats "$PARTITION" >"$FS_INFO" 2>&1 \
    || fail 'cannot inspect the derived root filesystem'
/usr/bin/grep -Fxq "Filesystem UUID:          $VERIFIER_VM_ROOT_FILESYSTEM_UUID" "$FS_INFO" \
    || fail 'root-filesystem UUID differs'
/usr/bin/grep -Fxq 'Filesystem magic number:  0xEF53' "$FS_INFO" \
    || fail 'root-filesystem magic differs'
/usr/bin/grep -Fxq 'Filesystem state:         clean' "$FS_INFO" \
    || fail 'root filesystem is not clean'

/usr/bin/mkdir -- "$STAGING"
[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STAGING")" = "$UID_NOW:$GID_NOW:700" ] \
    || fail 'boot-asset staging directory metadata differs'
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C DEBUGFS_PAGER=/usr/bin/cat \
    /usr/sbin/debugfs -R \
        "dump /boot/vmlinuz-$VERIFIER_VM_KERNEL_RELEASE $STAGING/vmlinuz" \
        "$PARTITION" >/dev/null 2>&1 \
    || fail 'cannot extract the pinned verifier-VM kernel'
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C DEBUGFS_PAGER=/usr/bin/cat \
    /usr/sbin/debugfs -R \
        "dump /boot/initrd.img-$VERIFIER_VM_KERNEL_RELEASE $STAGING/initrd.img" \
        "$PARTITION" >/dev/null 2>&1 \
    || fail 'cannot extract the pinned verifier-VM initramfs'
/usr/bin/chmod 0400 -- "$STAGING/vmlinuz" "$STAGING/initrd.img"
for specification in \
    "$STAGING/vmlinuz:$SIZE_VERIFIER_VM_KERNEL:$SHA256_VERIFIER_VM_KERNEL" \
    "$STAGING/initrd.img:$SIZE_VERIFIER_VM_INITRD:$SHA256_VERIFIER_VM_INITRD"; do
    path=${specification%%:*}
    specification=${specification#*:}
    size=${specification%%:*}
    digest=${specification#*:}
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" = \
      "$UID_NOW:$GID_NOW:400:1:$size" ] \
        || fail "staged boot-asset metadata differs: $path"
    verify_digest sha256 "$path" "$digest"
done
staging_identity="$(/usr/bin/stat -c '%d:%i' -- "$STAGING")"
/usr/bin/mv -T --no-clobber -- "$STAGING" "$BOOT_ROOT" \
    || fail 'direct-boot cache publication failed'
if [ -e "$STAGING" ] || [ -L "$STAGING" ]; then
    # A concurrent current-user publisher won. Its cache must still be exact;
    # our independently derived staging tree remains transaction-owned cleanup.
    verify_boot_cache
else
    [ "$(/usr/bin/stat -c '%d:%i' -- "$BOOT_ROOT")" = "$staging_identity" ] \
        || fail 'published direct-boot cache identity differs'
    # Linux requires write permission on a moved directory because its `..`
    # entry changes. Seal the exact published inode immediately after rename;
    # an interruption between these operations leaves mode 0700 and therefore
    # fails closed on the next invocation rather than normalizing ambiguity.
    /usr/bin/chmod 0500 -- "$BOOT_ROOT"
    verify_boot_cache
fi

[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$BASE"):$(/usr/bin/sha512sum "$BASE")" = \
  "$base_before" ] || fail 'authenticated base changed during boot-asset derivation'
[ "$(/usr/bin/sha256sum "$DERIVER_SOURCE" "$LIB_SOURCE" "$PIN_SOURCE" "$CLEANUP_HELPER")" = \
  "$sources_before" ] || fail 'boot-derivation source changed during execution'
printf 'VERIFIER_VM_BOOT_ASSETS=pass source=authenticated-qcow2 cache=published kernel=%s\n' \
    "$VERIFIER_VM_KERNEL_RELEASE"

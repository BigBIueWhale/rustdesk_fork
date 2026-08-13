#!/usr/bin/env bash
# scripts/provision-windows-vm.sh — build the golden Windows 11 KVM template
# (R-B8, R-B12(c), §12.2).
#
# Windows cannot be cross-built from Linux (MSVC + WiX are Windows-only), but it
# can be a VIRTUAL MACHINE on the same Linux x86_64 host (licensed to virtualize
# Windows on any hardware, unlike macOS). This builds the persistent, immutable
# TEMPLATE — a golden Win11 image provisioned to the pinned toolchain and nothing
# more (R-B8). Each build then spins a fresh, throwaway copy-on-write overlay of it
# (build-windows.ps1 runs inside), and its creating transaction destroys it
# ("cattle, not pets") — so every Windows build starts from the byte-identical
# baseline and the recorded SHA-256 (R-B2) is reproducible.
#
# Run order (R-B10): host-provision.sh (qemu-system-x86 + session libvirt
# client/driver pieces + swtpm/ovmf; never system libvirt default networking) ->
# online-fetch.sh (stages the Win11 ISO + VS Build Tools offline layout) ->
# provision-windows-vm.sh (once) -> build-windows.ps1 (per build) -> cleanup.sh.
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C
readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || { printf 'provision-windows-vm refuses host or container-root execution\n' >&2; exit 1; }
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || { printf 'provision-windows-vm refuses a root primary group\n' >&2; exit 1; }
SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
# shellcheck source=scripts/windows-helper-runtime.sh
source "$SCRIPT_DIR/windows-helper-runtime.sh"
# shellcheck source=scripts/windows-libvirt-storage-pools.sh
source "$SCRIPT_DIR/windows-libvirt-storage-pools.sh"

STATE_DIR="$REPO_ROOT/.harness-state"
GOLDEN="$STATE_DIR/win11-golden.qcow2"
DOMAIN="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-golden"
CONTROL_TIMEOUT_SECONDS=30
PROCESS_ADMISSION_SECONDS=10
PROCESS_STOP_SECONDS=10
CREATE_TIMEOUT_SECONDS=300
VM_TIMEOUT_SECONDS=7800
PROVISION_DOMAIN_UUID=""
PROVISION_DOMAIN_CREATION_STARTED=0
PROVISION_VIRT_PID=""
PROVISION_VIRT_START=""
PROVISION_VM_DEADLINE=""
CLEANUP_ACTIVE=0
AUTOUNATTEND_ISO="$STATE_DIR/autounattend.iso"   # the PROVISION CD: autounattend.xml + the setup .ps1
TOOLCHAINS_ISO="$STATE_DIR/toolchains.iso"        # the TOOLCHAINS CD: the staged ./online windows artifacts
SRC_ISO="$STATE_DIR/src.iso"                      # the SRC CD: the committed repo (res/vcpkg etc.) for warming

verify_sha512_file() {
    local file="$1" expected="$2"
    [ -f "$file" ] && [ ! -L "$file" ] \
        || die "required SHA512-pinned file is not regular: $file"
    [ "$(sha512sum "$file" | awk '{print $1}')" = "$expected" ] \
        || die "SHA512 mismatch for $file"
}

verify_libvpx_windows_tools() {
    local hash name extra count=0
    [ "$(sha256sum "$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512" | awk '{print $1}')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST" ] \
        || die "libvpx Windows tool manifest does not match its pin"
    while read -r hash name extra; do
        [ -n "$hash" ] && [ -n "$name" ] && [ -z "$extra" ] \
            || die "malformed libvpx Windows tool manifest entry"
        [[ "$hash" =~ ^[0-9a-f]{128}$ ]] || die "malformed libvpx Windows tool SHA512"
        [[ "$name" =~ ^[A-Za-z0-9._~+-]+$ ]] || die "malformed libvpx Windows tool name"
        verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/windows-tools/$name" "$hash"
        count=$((count + 1))
    done <"$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512"
    [ "$count" = 32 ] || die "libvpx Windows tool manifest must contain exactly 32 entries"
}

preflight() {
    require_cmd virt-install virsh qemu-img xorriso setsid timeout awk sha256sum sha512sum
    assert_no_build_host_network_residual
    [[ "$DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "HARNESS_PREFIX contains an invalid domain-name character"
    [ "${#DOMAIN}" -le 63 ] || die "golden domain name is too long"
    [ -d /usr/share/OVMF ] || die "OVMF (UEFI firmware) not found — run host-provision.sh first (R-B11)"
    [ -e /dev/kvm ] || die "/dev/kvm absent — Windows helper libguestfs inspection needs it"
    require_online_complete
    windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"
    [ -f "$SCRIPT_DIR/autounattend.xml" ]    || die "scripts/autounattend.xml missing (the unattended-install answer file)"
    [ -f "$SCRIPT_DIR/win-guest-setup.ps1" ] || die "scripts/win-guest-setup.ps1 missing (the guest toolchain installer)"
    # Win11 ISO + VS Build Tools are EVERGREEN (not stably SHA-addressable upstream),
    # so R-B12(c) pins the CAPTURED offline layout by SHA-256 instead. Verify it.
    verify_sha256 "$ONLINE_DIR/win11.iso"                "${SHA256_WIN11_ISO}"
    verify_sha256 "$ONLINE_DIR/vs-buildtools.layout.tar" "${SHA256_VS_BUILDTOOLS}"
    # The publisher-pinned windows toolchains (online-fetch fetch_windows_toolchains).
    verify_sha256 "$ONLINE_DIR/flutter-windows-${FLUTTER_VERSION}.zip" "${SHA256_FLUTTER_WIN_3_24_5}"
    verify_sha256 "$ONLINE_DIR/llvm-windows-${LLVM_VERSION}.exe"       "${SHA256_LLVM_WIN_15_0_6}"
    verify_sha256 "$ONLINE_DIR/python-windows-${PYTHON_VERSION}.exe"   "${SHA256_PYTHON_WIN_3_11_9}"
    # The windows flutter engine (offline-staged, deterministic) — pinned by SHA (R-B12), not just existence.
    verify_sha256 "$ONLINE_DIR/flutter-windows-engine.tar.gz"          "${SHA256_FLUTTER_WIN_ENGINE}"
    # The flutter_tools pub cache (offline-staged, deterministic) — pre-placed before the in-VM offline
    # flutter_tools resolve; without it `dart pub get --offline` fails "version solving failed" (the
    # SDK zip's bundled cache lacks flutter_tools' dev deps). Pinned by SHA (R-B12), not just existence.
    verify_sha256 "$ONLINE_DIR/flutter-pub-cache.tar.gz"               "${SHA256_FLUTTER_PUB_CACHE}"
    # R-B12 / §12.3 (trust nobody — distrust ./online, re-verify by SHA): these installers ARE the
    # compiler + git + rustup that build the shipped Windows binary. A bare existence check let a
    # poisoned/wrong re-stage seed the golden invisibly (the golden qcow2 SHA then just certifies
    # whatever was seeded). Verify each against its pin, fail-closed — never provision from unverified
    # bytes. (rust-msvc + git are dual-source-pinned; rustup-init is operator-captured evergreen.)
    verify_sha256 "$ONLINE_DIR/win/rust-1.75.0-x86_64-pc-windows-msvc.msi" "${SHA256_RUST_MSVC_1_75}"
    verify_sha256 "$ONLINE_DIR/win/Git-2.45.2-64-bit.exe"                  "${SHA256_GIT_WIN_2_45_2}"
    verify_sha256 "$ONLINE_DIR/win/rustup-init.exe"                        "${SHA256_RUSTUP_INIT_WIN}"
    verify_sha256 "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz"             "${SHA256_VCPKG_120DEAC3}"
    verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" "$SHA512_LIBVPX_SOURCE"
    verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch" "$SHA512_LIBVPX_PATCH"
    verify_sha512_file "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"
    [ -f "$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt" ] \
        && [ ! -L "$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt" ] \
        || die "libvpx native key is missing"
    verify_libvpx_windows_tools
    log "preflight OK — building the golden Win11 template (immutable, pinned)"
}

build_media() {
    # The proven 3-disk config = PROVISION CD + TOOLCHAINS CD + the win11.iso. A 4th (SRC) CD
    # coincided with Setup never running FirstLogonCommands (no toolchain, no log/transcript), so
    # res/vcpkg is FOLDED INTO the PROVISION CD instead — win-guest-setup.ps1 reads its overlay ports
    # from there. The PROVISION CD is built from a staging dir (autounattend.xml + win-guest-setup.ps1
    # at root, res/ as a subdir Setup ignores).
    log "building the PROVISION CD (autounattend.xml + win-guest-setup.ps1 + res/ for the vcpkg warm)"
    local psnap="$STATE_DIR/prov-snap"; rm -rf "$psnap"; mkdir -p "$psnap"
    cp "$SCRIPT_DIR/autounattend.xml" "$SCRIPT_DIR/win-guest-setup.ps1" "$psnap/"
    cp -a "$REPO_ROOT/res" "$psnap/res"
    ( cd "$psnap" && xorriso -as mkisofs -quiet -o "$AUTOUNATTEND_ISO" -V PROVISION -J -R . )
    rm -rf "$psnap"
    log "building the TOOLCHAINS CD (the staged ./online windows artifacts)"
    xorriso -as mkisofs -quiet -o "$TOOLCHAINS_ISO" -V TOOLCHAINS -J -R -graft-points \
        "/flutter-windows-${FLUTTER_VERSION}.zip=$ONLINE_DIR/flutter-windows-${FLUTTER_VERSION}.zip" \
        "/llvm-windows-${LLVM_VERSION}.exe=$ONLINE_DIR/llvm-windows-${LLVM_VERSION}.exe" \
        "/python-windows-${PYTHON_VERSION}.exe=$ONLINE_DIR/python-windows-${PYTHON_VERSION}.exe" \
        "/vs-buildtools.layout.tar=$ONLINE_DIR/vs-buildtools.layout.tar" \
        "/vcpkg-${VCPKG_BASELINE}.tar.gz=$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "/win/Git-2.45.2-64-bit.exe=$ONLINE_DIR/win/Git-2.45.2-64-bit.exe" \
        "/win/rust-1.75.0-x86_64-pc-windows-msvc.msi=$ONLINE_DIR/win/rust-1.75.0-x86_64-pc-windows-msvc.msi" \
        "/win/rustup-init.exe=$ONLINE_DIR/win/rustup-init.exe" \
        "/flutter-windows-engine.tar.gz=$ONLINE_DIR/flutter-windows-engine.tar.gz" \
        "/flutter-pub-cache.tar.gz=$ONLINE_DIR/flutter-pub-cache.tar.gz" \
        "/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz=$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" \
        "/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch=$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch" \
        "/vcpkg-distfiles/libvpx-native-key.txt=$ONLINE_DIR/vcpkg-distfiles/libvpx-native-key.txt" \
        "/vcpkg-distfiles/libyuv-${LIBYUV_COMMIT}.tar.gz=$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" \
        "/vcpkg-distfiles/windows-tools=$ONLINE_DIR/vcpkg-distfiles/windows-tools"
}

# golden_has_done_marker: true iff C:\guest-setup-done.txt contains the exact v3 receipt in the
# golden qcow2 — the DEFINITIVE completion signal. The guest writes it only after it has verified
# that the persistent builder account's password cannot expire, and immediately before shutdown. Read
# read-only via libguestfs-in-docker; the caller MUST invoke this only when the domain is OFF (the
# qcow2 is write-locked while it runs). A libguestfs error (e.g. a reboot relocked the image
# mid-read) returns non-zero -> treated as "not done yet", so this never yields a false positive.
golden_has_done_marker() {
    windows_helper_kvm_guestfish_run \
        --mount "type=bind,source=$GOLDEN,target=/authority/golden.qcow2,readonly" \
        -- /bin/bash --noprofile --norc \
            /authority/windows-golden-inspect.sh marker \
        >/dev/null 2>&1
}

assert_uuid() {
    [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
        || die "kernel random UUID is malformed: $1"
}

monotonic_seconds() {
    local uptime
    IFS=' ' read -r uptime _ </proc/uptime
    printf '%s\n' "${uptime%%.*}"
}

process_identity() {
    local pid="$1" stat
    [ -r "/proc/$pid/stat" ] || return 1
    stat="$(<"/proc/$pid/stat")" || return 1
    stat="${stat##*) }"
    set -- $stat
    [ "$#" -ge 20 ] || return 1
    printf '%s %s %s %s\n' "$1" "${20}" "$3" "$4"
}

process_start_time() {
    local identity
    identity="$(process_identity "$1")" || return 1
    set -- $identity
    printf '%s\n' "$2"
}

owned_virt_process_matches() {
    local identity state start group session
    [ -n "$PROVISION_VIRT_PID" ] && [ -n "$PROVISION_VIRT_START" ] || return 1
    identity="$(process_identity "$PROVISION_VIRT_PID" 2>/dev/null)" || return 1
    read -r state start group session <<<"$identity"
    [ "$start" = "$PROVISION_VIRT_START" ] \
        && [ "$group" = "$PROVISION_VIRT_PID" ] \
        && [ "$session" = "$PROVISION_VIRT_PID" ]
}

wait_for_owned_virt_process_group() {
    local deadline identity state start group session
    [ -n "$PROVISION_VIRT_PID" ] && [ -n "$PROVISION_VIRT_START" ] || return 1
    deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))
    while true; do
        identity="$(process_identity "$PROVISION_VIRT_PID" 2>/dev/null)" || return 1
        read -r state start group session <<< "$identity"
        [ "$start" = "$PROVISION_VIRT_START" ] || return 1
        [ "$state" != Z ] && [ "$state" != X ] || return 1
        if [ "$group" = "$PROVISION_VIRT_PID" ] \
            && [ "$session" = "$PROVISION_VIRT_PID" ]; then
            return 0
        fi
        [ "$(monotonic_seconds)" -lt "$deadline" ] || return 1
        sleep 0.05
    done
}

owned_virt_process_is_live() {
    local identity state start group session
    [ -n "$PROVISION_VIRT_PID" ] && [ -n "$PROVISION_VIRT_START" ] || return 1
    identity="$(process_identity "$PROVISION_VIRT_PID" 2>/dev/null)" || return 1
    read -r state start group session <<<"$identity"
    [ "$start" = "$PROVISION_VIRT_START" ] \
        && [ "$group" = "$PROVISION_VIRT_PID" ] \
        && [ "$session" = "$PROVISION_VIRT_PID" ] \
        && [ "$state" != Z ] && [ "$state" != X ]
}

owned_virt_process_group_is_live() {
    local path stat state group session
    [ -n "$PROVISION_VIRT_PID" ] || return 1
    for path in /proc/[0-9]*/stat; do
        [ -r "$path" ] || continue
        stat="$(<"$path")" || continue
        stat="${stat##*) }"
        set -- $stat
        [ "$#" -ge 4 ] || continue
        state="$1"
        group="$3"
        session="$4"
        if [ "$group" = "$PROVISION_VIRT_PID" ] \
            && [ "$session" = "$PROVISION_VIRT_PID" ] \
            && [ "$state" != Z ] && [ "$state" != X ]; then
            return 0
        fi
    done
    return 1
}

stop_owned_virt_process() {
    [ -n "$PROVISION_VIRT_PID" ] || return 0
    [ -n "$PROVISION_VIRT_START" ] || return 1
    if ! owned_virt_process_matches; then
        [ ! -e "/proc/$PROVISION_VIRT_PID" ] || return 1
        owned_virt_process_group_is_live && return 1
        wait "$PROVISION_VIRT_PID" 2>/dev/null || :
        PROVISION_VIRT_PID=""
        PROVISION_VIRT_START=""
        return 0
    fi
    if owned_virt_process_is_live; then
        kill -TERM -- "-$PROVISION_VIRT_PID" || return 1
        local deadline
        deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
        while owned_virt_process_group_is_live \
            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            sleep 1
        done
        if owned_virt_process_group_is_live; then
            owned_virt_process_matches || return 1
            kill -KILL -- "-$PROVISION_VIRT_PID" || return 1
            deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
            while owned_virt_process_group_is_live \
                && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                sleep 1
            done
            owned_virt_process_group_is_live && return 1
        fi
    fi
    owned_virt_process_group_is_live && return 1
    if owned_virt_process_matches; then
        local identity state
        identity="$(process_identity "$PROVISION_VIRT_PID")" || return 1
        state="${identity%% *}"
        [ "$state" = Z ] || [ "$state" = X ] || return 1
    fi
    wait "$PROVISION_VIRT_PID" 2>/dev/null || :
    PROVISION_VIRT_PID=""
    PROVISION_VIRT_START=""
}

virsh_bounded() {
    windows_libvirt_virsh_bounded "$@"
}

domain_name_is_listed() {
    local names
    names="$(virsh_bounded list --all --name)" || return 2
    printf '%s\n' "$names" |
        awk -v wanted="$DOMAIN" '$0 == wanted { found=1 } END { exit !found }'
}

domain_uuid_is_listed() {
    local uuids
    [ -n "$PROVISION_DOMAIN_UUID" ] || return 1
    uuids="$(virsh_bounded list --all --uuid)" || return 2
    printf '%s\n' "$uuids" |
        awk -v wanted="$PROVISION_DOMAIN_UUID" '$0 == wanted { found=1 } END { exit !found }'
}

require_domain_identity_absent() {
    if domain_name_is_listed; then
        die "golden domain name already exists; refusing to mutate it: $DOMAIN"
    else
        local listed_status=$?
        [ "$listed_status" = 1 ] \
            || die "cannot prove that the golden domain name is unused"
    fi
    if domain_uuid_is_listed; then
        die "kernel-random golden domain UUID already exists; refusing to mutate it"
    else
        local listed_status=$?
        [ "$listed_status" = 1 ] \
            || die "cannot prove that the golden domain UUID is unused"
    fi
}

prove_owned_domain() {
    local actual_name
    [ -n "$PROVISION_DOMAIN_UUID" ] || return 1
    actual_name="$(virsh_bounded domname "$PROVISION_DOMAIN_UUID" 2>/dev/null)" || return 1
    [ "$actual_name" = "$DOMAIN" ]
}

wait_for_owned_domain_creation() {
    local deadline listed_status
    deadline=$(( $(monotonic_seconds) + CREATE_TIMEOUT_SECONDS ))
    while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        if domain_uuid_is_listed; then
            prove_owned_domain \
                || die "provision UUID appeared under an unexpected domain name"
            return 0
        else
            listed_status=$?
            [ "$listed_status" = 1 ] \
                || die "cannot inspect session domains while waiting for creation"
        fi
        owned_virt_process_is_live \
            || die "virt-install exited before creating the UUID-bound golden domain"
        sleep 1
    done
    die "virt-install did not create the UUID-bound golden domain within ${CREATE_TIMEOUT_SECONDS}s"
}

stop_and_undefine_owned_domain() {
    [ -n "$PROVISION_DOMAIN_UUID" ] || return 0
    if [ "$PROVISION_DOMAIN_CREATION_STARTED" = 0 ]; then
        PROVISION_DOMAIN_UUID=""
        PROVISION_VM_DEADLINE=""
        return 0
    fi
    if ! prove_owned_domain; then
        if domain_uuid_is_listed; then
            warn "provision UUID exists under an unexpected name; preserving it"
            return 1
        else
            local listed_status=$?
            if [ "$listed_status" = 1 ]; then
                PROVISION_DOMAIN_UUID=""
                PROVISION_DOMAIN_CREATION_STARTED=0
                PROVISION_VM_DEADLINE=""
                return 0
            fi
            return 1
        fi
    fi

    local state deadline listed_status
    state="$(virsh_bounded domstate "$PROVISION_DOMAIN_UUID")" || return 1
    case "$state" in
        "shut off") ;;
        *)
            virsh_bounded destroy "$PROVISION_DOMAIN_UUID" >/dev/null || return 1
            deadline=$(( $(monotonic_seconds) + 60 ))
            while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                if domain_uuid_is_listed; then
                    prove_owned_domain || return 1
                    state="$(virsh_bounded domstate "$PROVISION_DOMAIN_UUID")" || return 1
                    [ "$state" = "shut off" ] && break
                else
                    listed_status=$?
                    if [ "$listed_status" = 1 ]; then
                        PROVISION_DOMAIN_UUID=""
                        PROVISION_DOMAIN_CREATION_STARTED=0
                        PROVISION_VM_DEADLINE=""
                        return 0
                    fi
                    return 1
                fi
                sleep 1
            done
            prove_owned_domain || return 1
            [ "$(virsh_bounded domstate "$PROVISION_DOMAIN_UUID")" = "shut off" ] || return 1
            ;;
    esac
    virsh_bounded undefine "$PROVISION_DOMAIN_UUID" --nvram >/dev/null || return 1
    if domain_uuid_is_listed; then
        return 1
    else
        listed_status=$?
        [ "$listed_status" = 1 ] || return 1
        PROVISION_DOMAIN_UUID=""
        PROVISION_DOMAIN_CREATION_STARTED=0
        PROVISION_VM_DEADLINE=""
        return 0
    fi
}

seal_golden_read_only() {
    python3 - "$GOLDEN" "$(id -u)" "$(id -g)" "$SHA256_WIN11_GOLDEN_QCOW2" <<'PY'
import hashlib
import os
import stat
import sys

path, uid_text, gid_text, expected = sys.argv[1:]
uid = int(uid_text)
gid = int(gid_text)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != uid
        or before.st_gid != gid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
    ):
        raise SystemExit("golden is not a current-principal mode-0400/0600 single-link regular file")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 8 * 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    sampled = os.fstat(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(sampled, field) for field in stable_fields):
        raise SystemExit("golden identity changed while its pre-seal digest was sampled")
    if digest.hexdigest() != expected:
        raise SystemExit("golden pre-seal bytes do not match the pinned SHA-256")
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    sealed_digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 8 * 1024 * 1024)
        if not chunk:
            break
        sealed_digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        not stat.S_ISREG(after.st_mode)
        or after.st_uid != uid
        or after.st_gid != gid
        or after.st_nlink != 1
        or stat.S_IMODE(after.st_mode) != 0o400
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or sealed_digest.hexdigest() != expected
    ):
        raise SystemExit("golden read-only seal did not preserve the exact pinned file")
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

build_golden() {
    mkdir -p "$STATE_DIR"
    # Reuse an existing golden ONLY if it actually finished with the exact v3 receipt. A qcow2 left behind by
    # a FAILED or older provision has no compatible receipt — silently reusing it falsely reports success on
    # a stale image. A present qcow2 is now immutable/pinned input: mismatch or no marker fails loud so the
    # operator can delete/re-provision deliberately instead of the script mutating a present-but-wrong file.
    if [ -f "$GOLDEN" ]; then
        verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"
        if golden_has_done_marker; then
            seal_golden_read_only
            log "golden already exists + has the done-marker: $GOLDEN (delete to force a rebuild)"; return 0
        fi
        die "golden exists but lacks the exact v3 completion receipt (stale/failed/incompatible provision): $GOLDEN — delete it deliberately before rebuilding"
    fi
    windows_libvirt_transaction_open "$STATE_DIR" \
        || die "cannot create the private golden-provision libvirt transaction"
    build_media
    PROVISION_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"
    assert_uuid "$PROVISION_DOMAIN_UUID"
    require_domain_identity_absent
    windows_libvirt_ensure_transient_pools "$STATE_DIR" "$ONLINE_DIR" \
        || die "cannot establish exact transient pools for golden-provision storage"
    windows_libvirt_require_targets_owned "$STATE_DIR" "$ONLINE_DIR" \
        || die "golden-provision storage is not exclusively transaction-owned"
    windows_libvirt_prepare_domain "$DOMAIN" "$PROVISION_DOMAIN_UUID" \
        || die "cannot bind golden-provision domain residue ownership"
    # NB no --tpm: this host's session libvirt offers only TPM 'passthrough' (a physical TPM),
    # not the swtpm 'emulator' backend, and qemu:///system is permission-denied. autounattend.xml
    # bypasses Win11 Setup's TPM/SecureBoot gates instead — fine for a throwaway BUILD VM (TPM is
    # an install gate, not a build input; the .exe/.msi is byte-identical).
    log "creating golden qcow2 + installing Win11 (UEFI via OVMF; TPM bypassed in autounattend)"
    qemu-img create -f qcow2 "$GOLDEN" 80G
    # The UNATTENDED install: win11.iso boots, Setup auto-applies autounattend.xml off the
    # PROVISION CD (Win11 Pro -> the SATA disk; Setup has the AHCI driver built-in, whereas a
    # virtio disk would need the virtio-win drivers loaded in WinPE), then the first-logon
    # win-guest-setup.ps1 installs the pinned toolchain off the TOOLCHAINS CD and shuts down.
    # Network is ON for THIS one golden-build step (vcpkg bootstrap + the §3.2 native build +
    # the WiX/NuGet warm) — the NAT'd guest never LISTENS; the per-build overlay is --network=none.
    # VNC binds 127.0.0.1 only (never 0.0.0.0), to diagnose a stuck unattended install.
    # A prior unowned domain with this name is an operator-reconciliation error, not
    # cleanup authority. Re-prove absence immediately before creation and never
    # destroy a domain merely because its mutable name collides with this one.
    require_domain_identity_absent
    # NIC model=e1000e (NOT virt-install's default): Win11 ships an inbox e1000e driver but NOT one for the
    # default qemu NIC, so the default guest has NO working network -> the provision-time `flutter pub get`
    # residual download fails its TLS handshake ("Handshake error in client"), which ALSO explains the
    # historical "98-call stall" (= 98 dead-NIC timeouts). The working rdwinvm SSH VM uses e1000e over the
    # same slirp `-netdev user`, proving the model is the fix. (slirp NAT; the guest never LISTENS.)
    PROVISION_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))
    PROVISION_DOMAIN_CREATION_STARTED=1
    /usr/bin/setsid --wait "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}" \
        /usr/bin/virt-install \
        --connect qemu:///session \
        --name "$DOMAIN" \
        --uuid "$PROVISION_DOMAIN_UUID" \
        --osinfo win11 \
        --memory 16384 --vcpus 8 \
        --disk "path=$GOLDEN,format=qcow2,bus=sata" \
        --disk "path=$AUTOUNATTEND_ISO,device=cdrom" \
        --disk "path=$TOOLCHAINS_ISO,device=cdrom" \
        --cdrom "$ONLINE_DIR/win11.iso" \
        --boot uefi \
        --network user,model=e1000e \
        --graphics vnc,listen=127.0.0.1 \
        --noautoconsole --wait -1 &
    PROVISION_VIRT_PID=$!
    PROVISION_VIRT_START="$(process_start_time "$PROVISION_VIRT_PID")" \
        || die "could not bind the virt-install process identity"
    wait_for_owned_virt_process_group \
        || die "could not prove virt-install process-group admission"
    wait_for_owned_domain_creation
    windows_libvirt_require_targets_owned "$STATE_DIR" "$ONLINE_DIR" \
        || die "virt-install changed golden-provision storage-pool ownership"
    # Clear the UEFI "Press any key to boot from CD or DVD" prompt: headless, it otherwise falls
    # through to "BdsDxe: No bootable option or device was found" and the install never starts.
    # send-key ENTER (linux keycode 28) through its ~5s window. (This backgrounded script's own
    # sleeps are fine — only FOREGROUND sleep is harness-blocked.)
    log "clearing the UEFI boot-from-CD prompt (send-key ENTER)"
    local send_key_ok=0
    for _ in $(seq 1 20); do
        if virsh_bounded send-key "$PROVISION_DOMAIN_UUID" --codeset linux 28 >/dev/null; then
            send_key_ok=1
        fi
        sleep 1
    done
    [ "$send_key_ok" = 1 ] \
        || die "could not send the UEFI boot key to the owned golden domain"
    log "unattended install + toolchain setup underway (~1-2h; the guest powers off when done)"
    # virt-install --wait returns at the FIRST guest shutdown — the OS-install REBOOT — not the final
    # power-off. The guest then keeps running (OOBE -> first-logon -> win-guest-setup: toolchain +
    # precache + vcpkg-natives -> Stop-Computer). A power-off ALONE is NOT completion: the OOBE/logon
    # reboots also go transiently 'off' (and can exceed 2 min here — that false-tripped the old
    # off-count heuristic into declaring success before setup even ran), and a FAILED setup leaves the
    # domain idle at the desktop ('running') forever. So gate completion on the DEFINITIVE marker
    # C:\guest-setup-done.txt: whenever the domain is stably off (qcow2 unlocked), read the exact receipt via
    # libguestfs — present => built, absent => a transient reboot (keep waiting) or a real failure (timeout).
    while owned_virt_process_group_is_live; do
        [ "$(monotonic_seconds)" -lt "$PROVISION_VM_DEADLINE" ] \
            || die "golden provisioning exceeded 130m before the first guest shutdown"
        sleep 10
    done
    if ! owned_virt_process_matches && [ -e "/proc/$PROVISION_VIRT_PID" ]; then
        die "virt-install process identity changed before it could be reaped"
    fi
    local vi_status
    if wait "$PROVISION_VIRT_PID"; then
        vi_status=0
    else
        vi_status=$?
    fi
    PROVISION_VIRT_PID=""
    PROVISION_VIRT_START=""
    [ "$vi_status" = 0 ] || die "virt-install failed with exit $vi_status"
    # Preserve the old 130-minute allowance after the first guest shutdown,
    # independently of the newly bounded install-to-first-shutdown phase.
    PROVISION_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))
    log "waiting for win-guest-setup to COMPLETE (gated on guest-setup-done.txt, not a bare power-off)"
    local mins=0 offstreak=0 checked=0 state
    while true; do
        [ "$(monotonic_seconds)" -lt "$PROVISION_VM_DEADLINE" ] \
            || die "golden provisioning exceeded 130m without the v3 completion receipt — setup failed or stuck at the desktop"
        sleep 60
        [ "$(monotonic_seconds)" -lt "$PROVISION_VM_DEADLINE" ] \
            || die "golden provisioning exceeded 130m without the v3 completion receipt — setup failed or stuck at the desktop"
        mins=$((mins + 1))
        prove_owned_domain || die "owned golden domain disappeared or changed identity"
        state="$(virsh_bounded domstate "$PROVISION_DOMAIN_UUID")" \
            || die "cannot read the owned golden domain state"
        case "$state" in
            "shut off")
                offstreak=$((offstreak + 1))
                # Stably off for 2 min => the qcow2 is unlocked; check the marker
                # once per off-streak.
                if [ "$offstreak" -ge 2 ] && [ "$checked" -eq 0 ]; then
                    checked=1
                    if golden_has_done_marker; then
                        verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"
                        stop_and_undefine_owned_domain \
                            || die "completed golden domain could not be undefined safely"
                        seal_golden_read_only
                        log "golden Win11 template built: $GOLDEN (exact v3 completion receipt present) — clone an overlay, never boot this"
                        break
                    fi
                    log "domain off but no done-marker yet (mins=$mins) — transient reboot, still waiting"
                fi
                ;;
            crashed) die "golden provisioning domain crashed" ;;
            running|blocked|paused|"in shutdown"|pmsuspended)
                offstreak=0
                checked=0
                ;;
            *) die "golden provisioning domain entered an unknown state: $state" ;;
        esac
    done
}

main() {
    windows_helper_authority_open
    preflight
    build_golden
    windows_libvirt_transaction_close \
        || die "golden-provision libvirt authority did not retire after domain finality"
    log "Per-build usage (build-windows.ps1): create a CoW overlay and a transient"
    log "domain over \$GOLDEN, share C:\\src + C:\\online read-only, run the build,"
    log "copy out the .exe/.msi + SHA-256, then let the creating transaction retire it."
}

cleanup_provision() {
    local status=$?
    local cleanup_failed=0
    [ "$CLEANUP_ACTIVE" = 0 ] || exit "$status"
    CLEANUP_ACTIVE=1
    trap - EXIT
    trap '' HUP INT TERM

    if ! stop_owned_virt_process; then
        cleanup_failed=1
        warn "preserving the domain because the owned virt-install process group did not terminate conclusively"
    elif ! stop_and_undefine_owned_domain; then
        cleanup_failed=1
        warn "could not prove exact terminal cleanup of the provision-owned domain"
    elif ! windows_libvirt_transaction_close; then
        cleanup_failed=1
        warn "could not prove exact terminal cleanup of provision-owned transient libvirt state"
    fi
    windows_helper_authority_close || cleanup_failed=1
    if [ "$cleanup_failed" != 0 ] && [ "$status" = 0 ]; then
        status=1
    fi
    exit "$status"
}

signal_exit() {
    local status="$1"
    trap - HUP INT TERM
    exit "$status"
}

trap cleanup_provision EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

main "$@"

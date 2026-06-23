#!/usr/bin/env bash
# scripts/provision-windows-vm.sh — build the golden Windows 11 KVM template
# (R-B8, R-B12(c), §12.2).
#
# Windows cannot be cross-built from Linux (MSVC + WiX are Windows-only), but it
# can be a VIRTUAL MACHINE on the same Linux x86_64 host (licensed to virtualize
# Windows on any hardware, unlike macOS). This builds the persistent, immutable
# TEMPLATE — a golden Win11 image provisioned to the pinned toolchain and nothing
# more (R-B8). Each build then spins a fresh, throwaway copy-on-write overlay of it
# (build-windows.ps1 runs inside), and is destroyed afterwards by cleanup.sh
# ("cattle, not pets") — so every Windows build starts from the byte-identical
# baseline and the recorded SHA-256 (R-B2) is reproducible.
#
# Run order (R-B10): host-provision.sh (qemu-kvm/libvirt/swtpm/ovmf) ->
# online-fetch.sh (stages the Win11 ISO + VS Build Tools offline layout) ->
# provision-windows-vm.sh (once) -> build-windows.ps1 (per build) -> cleanup.sh.
#
# NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

STATE_DIR="$REPO_ROOT/.harness-state"
GOLDEN="$STATE_DIR/win11-golden.qcow2"
DOMAIN="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-golden"
AUTOUNATTEND_ISO="$STATE_DIR/autounattend.iso"   # the PROVISION CD: autounattend.xml + the setup .ps1
TOOLCHAINS_ISO="$STATE_DIR/toolchains.iso"        # the TOOLCHAINS CD: the staged ./online windows artifacts
SRC_ISO="$STATE_DIR/src.iso"                      # the SRC CD: the committed repo (res/vcpkg etc.) for warming

preflight() {
    require_cmd virt-install virsh qemu-img xorriso
    [ -d /usr/share/OVMF ] || die "OVMF (UEFI firmware) not found — run host-provision.sh first (R-B11)"
    require_online_complete
    [ -f "$SCRIPT_DIR/autounattend.xml" ]    || die "scripts/autounattend.xml missing (the unattended-install answer file)"
    [ -f "$SCRIPT_DIR/win-guest-setup.ps1" ] || die "scripts/win-guest-setup.ps1 missing (the guest toolchain installer)"
    # Win11 ISO + VS Build Tools are EVERGREEN (not stably SHA-addressable upstream),
    # so R-B12(c) pins the CAPTURED offline layout by SHA-256 instead. Verify it.
    verify_sha256 "$ONLINE_DIR/win11.iso"                "${SHA256_WIN11_ISO}"
    verify_sha256 "$ONLINE_DIR/vs-buildtools.layout.tar" "${SHA256_VS_BUILDTOOLS}"
    # The publisher-pinned windows toolchains (online-fetch fetch_windows_toolchains).
    verify_sha256 "$ONLINE_DIR/flutter-windows-${FLUTTER_VERSION}.zip" "${SHA256_FLUTTER_WIN_3_24_5}"
    verify_sha256 "$ONLINE_DIR/llvm-windows-${LLVM_VERSION}.exe"       "${SHA256_LLVM_WIN_15_0_6}"
    for f in "win/Git-2.45.2-64-bit.exe" "win/rust-1.75.0-x86_64-pc-windows-msvc.msi" \
             "win/rustup-init.exe" "vcpkg-${VCPKG_BASELINE}.tar.gz"; do
        [ -f "$ONLINE_DIR/$f" ] || die "windows toolchain artifact missing in ./online: $f (stage it before provisioning)"
    done
    log "preflight OK — building the golden Win11 template (immutable, pinned)"
}

build_media() {
    # Two small CDs Windows Setup + the first-logon script read. xorriso graft-points map the
    # already-verified ./online artifacts straight in (no multi-GB copy into a staging dir).
    log "building the PROVISION CD (autounattend.xml + win-guest-setup.ps1)"
    xorriso -as mkisofs -quiet -o "$AUTOUNATTEND_ISO" -V PROVISION -J -R -graft-points \
        "/autounattend.xml=$SCRIPT_DIR/autounattend.xml" \
        "/win-guest-setup.ps1=$SCRIPT_DIR/win-guest-setup.ps1"
    log "building the TOOLCHAINS CD (the staged ./online windows artifacts)"
    xorriso -as mkisofs -quiet -o "$TOOLCHAINS_ISO" -V TOOLCHAINS -J -R -graft-points \
        "/flutter-windows-${FLUTTER_VERSION}.zip=$ONLINE_DIR/flutter-windows-${FLUTTER_VERSION}.zip" \
        "/llvm-windows-${LLVM_VERSION}.exe=$ONLINE_DIR/llvm-windows-${LLVM_VERSION}.exe" \
        "/vs-buildtools.layout.tar=$ONLINE_DIR/vs-buildtools.layout.tar" \
        "/vcpkg-${VCPKG_BASELINE}.tar.gz=$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "/win/Git-2.45.2-64-bit.exe=$ONLINE_DIR/win/Git-2.45.2-64-bit.exe" \
        "/win/rust-1.75.0-x86_64-pc-windows-msvc.msi=$ONLINE_DIR/win/rust-1.75.0-x86_64-pc-windows-msvc.msi" \
        "/win/rustup-init.exe=$ONLINE_DIR/win/rustup-init.exe"
    # The SRC CD = the COMMITTED repo (git archive HEAD: tracked files only, so no ./online,
    # ./target, ./.git, ./.harness-state). win-guest-setup.ps1 reads res/vcpkg off it to warm the
    # vcpkg x64-windows natives into the golden (the per-build is --network=none).
    log "building the SRC CD (committed repo source for the vcpkg-native warm)"
    local snap="$STATE_DIR/src-snap"
    rm -rf "$snap"; mkdir -p "$snap"
    git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$snap"
    ( cd "$snap" && xorriso -as mkisofs -quiet -o "$SRC_ISO" -V SRC -J -R . )
    rm -rf "$snap"
}

build_golden() {
    mkdir -p "$STATE_DIR"
    [ ! -f "$GOLDEN" ] || { log "golden image already exists: $GOLDEN (delete to rebuild)"; return 0; }
    build_media
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
    virt-install \
        --name "$DOMAIN" \
        --osinfo win11 \
        --memory 16384 --vcpus 8 \
        --disk "path=$GOLDEN,format=qcow2,bus=sata" \
        --disk "path=$AUTOUNATTEND_ISO,device=cdrom" \
        --disk "path=$TOOLCHAINS_ISO,device=cdrom" \
        --disk "path=$SRC_ISO,device=cdrom" \
        --cdrom "$ONLINE_DIR/win11.iso" \
        --boot uefi \
        --network user \
        --graphics vnc,listen=127.0.0.1 \
        --noautoconsole --wait -1 &
    local vi_pid=$!
    # Clear the UEFI "Press any key to boot from CD or DVD" prompt: headless, it otherwise falls
    # through to "BdsDxe: No bootable option or device was found" and the install never starts.
    # send-key ENTER (linux keycode 28) through its ~5s window. (This backgrounded script's own
    # sleeps are fine — only FOREGROUND sleep is harness-blocked.)
    log "clearing the UEFI boot-from-CD prompt (send-key ENTER)"
    for _ in $(seq 1 20); do
        virsh -c qemu:///session send-key "$DOMAIN" --codeset linux 28 >/dev/null 2>&1 || true
        sleep 1
    done
    log "unattended install + toolchain setup underway (~1-2h; the guest powers off when done)"
    wait "$vi_pid"
    log "golden Win11 template built: $GOLDEN — DO NOT boot it for builds; clone an overlay instead"
}

main() {
    preflight
    build_golden
    log "Per-build usage (build-windows.ps1): create a CoW overlay and a transient"
    log "domain over \$GOLDEN, share C:\\src + C:\\online read-only, run the build,"
    log "copy out the .exe/.msi + SHA-256, then destroy the overlay (cleanup.sh)."
}

main "$@"

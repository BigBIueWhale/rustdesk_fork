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

preflight() {
    require_cmd virt-install virsh qemu-img swtpm
    [ -d /usr/share/OVMF ] || die "OVMF (UEFI firmware) not found — run host-provision.sh first (R-B11)"
    require_online_complete
    # Win11 ISO + VS Build Tools are EVERGREEN (not stably SHA-addressable upstream),
    # so R-B12(c) pins the CAPTURED offline layout by SHA-256 instead. Verify it.
    verify_sha256 "$ONLINE_DIR/win11.iso"           "${SHA256_WIN11_ISO}"
    verify_sha256 "$ONLINE_DIR/vs-buildtools.layout.tar" "${SHA256_VS_BUILDTOOLS}"
    log "preflight OK — building the golden Win11 template (immutable, pinned)"
}

build_golden() {
    mkdir -p "$STATE_DIR"
    [ ! -f "$GOLDEN" ] || { log "golden image already exists: $GOLDEN (delete to rebuild)"; return 0; }
    log "creating golden qcow2 + installing Win11 (TPM 2.0 via swtpm, UEFI via OVMF)"
    qemu-img create -f qcow2 "$GOLDEN" 80G
    # An UNATTENDED install (autounattend.xml) drives Setup with no interaction,
    # then a guest provisioning pass installs EXACTLY the pinned toolchain — Rust
    # 1.75, Flutter 3.24.5, LLVM 15.0.6, WiX v4, the VS Build Tools (MSVC), vcpkg
    # @120deac3 — and stages ./online into C:\online. The autounattend + the guest
    # setup script live next to this file; the toolchain installers come from the
    # offline VS Build Tools layout and ./online, never the network.
    virt-install \
        --name "$DOMAIN" \
        --osinfo win11 \
        --memory 16384 --vcpus 8 \
        --disk "path=$GOLDEN,format=qcow2,bus=virtio" \
        --cdrom "$ONLINE_DIR/win11.iso" \
        --tpm "backend.type=emulator,backend.version=2.0,model=tpm-crb" \
        --boot uefi \
        --network none \
        --noautoconsole --wait -1
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

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
    # The windows flutter engine (offline-staged, deterministic) — pinned by SHA (R-B12), not just existence.
    verify_sha256 "$ONLINE_DIR/flutter-windows-engine.tar.gz"          "${SHA256_FLUTTER_WIN_ENGINE}"
    # The flutter_tools pub cache (offline-staged, deterministic) — pre-placed before the in-VM offline
    # flutter_tools resolve; without it `dart pub get --offline` fails "version solving failed" (the
    # SDK zip's bundled cache lacks flutter_tools' dev deps). Pinned by SHA (R-B12), not just existence.
    verify_sha256 "$ONLINE_DIR/flutter-pub-cache.tar.gz"               "${SHA256_FLUTTER_PUB_CACHE}"
    for f in "win/Git-2.45.2-64-bit.exe" "win/rust-1.75.0-x86_64-pc-windows-msvc.msi" \
             "win/rustup-init.exe" "vcpkg-${VCPKG_BASELINE}.tar.gz"; do
        [ -f "$ONLINE_DIR/$f" ] || die "windows toolchain artifact missing in ./online: $f (stage it before provisioning)"
    done
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
        "/vs-buildtools.layout.tar=$ONLINE_DIR/vs-buildtools.layout.tar" \
        "/vcpkg-${VCPKG_BASELINE}.tar.gz=$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz" \
        "/win/Git-2.45.2-64-bit.exe=$ONLINE_DIR/win/Git-2.45.2-64-bit.exe" \
        "/win/rust-1.75.0-x86_64-pc-windows-msvc.msi=$ONLINE_DIR/win/rust-1.75.0-x86_64-pc-windows-msvc.msi" \
        "/win/rustup-init.exe=$ONLINE_DIR/win/rustup-init.exe" \
        "/flutter-windows-engine.tar.gz=$ONLINE_DIR/flutter-windows-engine.tar.gz" \
        "/flutter-pub-cache.tar.gz=$ONLINE_DIR/flutter-pub-cache.tar.gz" \
        "/flutter_tools-package_config.json=$ONLINE_DIR/flutter_tools-package_config.json"
}

# golden_has_done_marker: true iff C:\guest-setup-done.txt exists in the golden qcow2 — the
# DEFINITIVE completion signal (win-guest-setup writes it LAST, right before Stop-Computer). Read
# read-only via libguestfs-in-docker; the caller MUST invoke this only when the domain is OFF (the
# qcow2 is write-locked while it runs). A libguestfs error (e.g. a reboot relocked the image
# mid-read) returns non-zero -> treated as "not done yet", so this never yields a false positive.
golden_has_done_marker() {
    docker run --rm --device /dev/kvm -v "$STATE_DIR:/state:ro" debian:stable-slim bash -c '
        apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libguestfs-tools linux-image-generic >/dev/null 2>&1
        export LIBGUESTFS_BACKEND=direct
        virt-cat -a /state/win11-golden.qcow2 /guest-setup-done.txt >/dev/null 2>&1
    ' >/dev/null 2>&1
}

build_golden() {
    mkdir -p "$STATE_DIR"
    # Reuse an existing golden ONLY if it actually finished (has the done-marker). A qcow2 left behind by
    # a FAILED provision has no marker — silently reusing it (the old behaviour) falsely reports success on
    # a stale image, so rebuild it instead. (Delete the marker'd golden by hand to force a fresh rebuild.)
    if [ -f "$GOLDEN" ]; then
        if golden_has_done_marker; then
            log "golden already exists + has the done-marker: $GOLDEN (delete to force a rebuild)"; return 0
        fi
        log "golden exists but LACKS the done-marker (stale/failed provision) — deleting + rebuilding: $GOLDEN"
        rm -f "$GOLDEN"
    fi
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
    # Clear any stale domain definition holding this qcow2 FIRST: a prior failed/killed run leaves the
    # domain defined-but-off, and virt-install then errors "Disk ... already in use by other guests"
    # and never boots the VM -> the done-marker poll waits forever on a 196K (empty) qcow2. This was the
    # real cause of repeated 196K stalls. Destroy (may already be off) + undefine; ignore errors.
    virsh -c qemu:///session destroy "$DOMAIN" >/dev/null 2>&1 || true
    virsh -c qemu:///session undefine --nvram "$DOMAIN" >/dev/null 2>&1 || true
    # NIC model=e1000e (NOT virt-install's default): Win11 ships an inbox e1000e driver but NOT one for the
    # default qemu NIC, so the default guest has NO working network -> the provision-time `flutter pub get`
    # residual download fails its TLS handshake ("Handshake error in client"), which ALSO explains the
    # historical "98-call stall" (= 98 dead-NIC timeouts). The working rdwinvm SSH VM uses e1000e over the
    # same slirp `-netdev user`, proving the model is the fix. (slirp NAT; the guest never LISTENS.)
    virt-install \
        --name "$DOMAIN" \
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
    # virt-install --wait returns at the FIRST guest shutdown — the OS-install REBOOT — not the final
    # power-off. The guest then keeps running (OOBE -> first-logon -> win-guest-setup: toolchain +
    # precache + vcpkg-natives -> Stop-Computer). A power-off ALONE is NOT completion: the OOBE/logon
    # reboots also go transiently 'off' (and can exceed 2 min here — that false-tripped the old
    # off-count heuristic into declaring success before setup even ran), and a FAILED setup leaves the
    # domain idle at the desktop ('running') forever. So gate completion on the DEFINITIVE marker
    # C:\guest-setup-done.txt: whenever the domain is stably off (qcow2 unlocked), read the marker via
    # libguestfs — present => built, absent => a transient reboot (keep waiting) or a real failure (timeout).
    wait "$vi_pid" 2>/dev/null || true
    log "waiting for win-guest-setup to COMPLETE (gated on guest-setup-done.txt, not a bare power-off)"
    local mins=0 offstreak=0 checked=0
    while true; do
        sleep 60; mins=$((mins + 1))
        if [ "$(virsh -c qemu:///session domstate "$DOMAIN" 2>/dev/null)" = "running" ]; then
            offstreak=0; checked=0
        else
            offstreak=$((offstreak + 1))
            # stably off for 2 min => the qcow2 is unlocked; check the marker ONCE per off-streak.
            if [ "$offstreak" -ge 2 ] && [ "$checked" -eq 0 ]; then
                checked=1
                if golden_has_done_marker; then
                    log "golden Win11 template built: $GOLDEN (guest-setup-done.txt present) — clone an overlay, never boot this"
                    break
                fi
                log "domain off but no done-marker yet (mins=$mins) — transient reboot, still waiting"
            fi
        fi
        [ "$mins" -gt 130 ] && die "golden provisioning exceeded 130m without guest-setup-done.txt — setup failed or stuck at the desktop; force the domain off + virt-cat C:\\setup-transcript.txt to find where win-guest-setup stopped"
    done
}

main() {
    preflight
    build_golden
    log "Per-build usage (build-windows.ps1): create a CoW overlay and a transient"
    log "domain over \$GOLDEN, share C:\\src + C:\\online read-only, run the build,"
    log "copy out the .exe/.msi + SHA-256, then destroy the overlay (cleanup.sh)."
}

main "$@"

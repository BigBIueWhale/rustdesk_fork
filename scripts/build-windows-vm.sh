#!/usr/bin/env bash
# scripts/build-windows-vm.sh — the PER-BUILD Windows .exe/.msi build (R-B7/B9, R-B2, §12.2).
#
# provision-windows-vm.sh builds the golden Win11 template ONCE (toolchain + vcpkg natives + the
# per-build logon harness). This runs PER BUILD: a throwaway copy-on-write overlay of that golden is
# booted with the committed repo (the BUILD CD) and a writable OUTPUT disk; the golden's logon task
# runs run-build.ps1 (cargo + flutter + the portable installer) and powers off; the host reads the
# artifacts back off the OUTPUT disk. Every build starts from the byte-identical golden (R-B2), runs
# --network=none (offline), and the overlay is destroyed afterwards ("cattle, not pets").
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

STATE_DIR="$REPO_ROOT/.harness-state"
GOLDEN="$STATE_DIR/win11-golden.qcow2"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
DOMAIN="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-build"
OVERLAY="$STATE_DIR/win-build-overlay.qcow2"
BUILD_ISO="$STATE_DIR/win-build-src.iso"
OUTPUT_IMG="$STATE_DIR/win-build-output.img"
GL="docker run --rm --device /dev/kvm"   # the root-free libguestfs-in-docker driver
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"

preflight() {
    require_cmd qemu-img virt-install virsh xorriso mkfs.vfat docker git
    [ -f "$GOLDEN" ] || die "golden image missing ($GOLDEN) — run scripts/provision-windows-vm.sh first"
    log "preflight OK — per-build over $GOLDEN, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

build_media() {
    # The BUILD CD = the COMMITTED repo (git archive HEAD: no ./online ./target ./.git) + run-build.ps1
    # at root (the golden's logon task runs it) + the SOURCE_DATE_EPOCH stamp (R-B2).
    log "building the BUILD CD (committed repo + run-build.ps1 + SOURCE_DATE_EPOCH)"
    local snap="$STATE_DIR/build-snap"; rm -rf "$snap"; mkdir -p "$snap"
    git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$snap"
    cp "$SCRIPT_DIR/run-build.ps1" "$snap/run-build.ps1"
    printf '%s' "$SOURCE_DATE_EPOCH" > "$snap/.source_date_epoch"
    ( cd "$snap" && xorriso -as mkisofs -quiet -o "$BUILD_ISO" -V BUILD -J -R . )
    rm -rf "$snap"
    # The OUTPUT disk = a raw FAT image labelled OUTPUT; run-build.ps1 writes dist/ here, the host reads it.
    log "creating the OUTPUT disk (FAT, label OUTPUT)"
    rm -f "$OUTPUT_IMG"
    qemu-img create -f raw "$OUTPUT_IMG" 3G >/dev/null
    mkfs.vfat -n OUTPUT "$OUTPUT_IMG" >/dev/null
}

prep_overlay() {
    log "cloning the golden into a throwaway CoW overlay"
    rm -f "$OVERLAY"
    qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$OVERLAY" >/dev/null
    # The per-build domain gets a FRESH UEFI nvram (no "Windows Boot Manager" entry — the golden's was
    # not carried over), so seed the removable-media fallback \EFI\BOOT\BOOTX64.EFI from the Windows
    # bootloader; OVMF then boots the disk. libguestfs, root-free.
    log "seeding the UEFI fallback bootloader for the fresh-nvram boot"
    $GL -v "$STATE_DIR:/state" ubuntu:24.04 bash -c '
      apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libguestfs-tools linux-image-generic >/dev/null 2>&1
      export LIBGUESTFS_BACKEND=direct
      guestfish --rw -a /state/win-build-overlay.qcow2 run : \
        mount /dev/sda1 / : mkdir-p /EFI/BOOT : \
        cp /EFI/Microsoft/Boot/bootmgfw.efi /EFI/BOOT/BOOTX64.EFI' 2>&1 | grep -iE 'error|fail' && die "fallback-bootloader seeding failed" || true
}

run_build() {
    log "booting the transient build VM (--network=none; the golden task runs run-build.ps1, ~30-60min)"
    virt-install --connect qemu:///session --name "$DOMAIN" --osinfo win11 --memory 16384 --vcpus 8 \
        --disk "path=$OVERLAY,format=qcow2,bus=sata" \
        --disk "path=$BUILD_ISO,device=cdrom" \
        --disk "path=$OUTPUT_IMG,format=raw,bus=sata" \
        --boot uefi --network none --graphics vnc,listen=127.0.0.1 \
        --noautoconsole --wait -1 &
    local vi_pid=$!
    wait "$vi_pid" 2>/dev/null || true
    # poll for the real power-off (run-build.ps1's Stop-Computer); 2 consecutive 60s "not running".
    local off=0 mins=0
    while [ "$off" -lt 2 ]; do
        sleep 60; mins=$((mins + 1))
        if [ "$(virsh -c qemu:///session domstate "$DOMAIN" 2>/dev/null)" = "running" ]; then off=0; else off=$((off + 1)); fi
        [ "$mins" -gt 120 ] && { log "WARN: build exceeded 2h — capturing OUTPUT anyway"; virsh -c qemu:///session destroy "$DOMAIN" 2>/dev/null || true; break; }
    done
    virsh -c qemu:///session undefine --nvram "$DOMAIN" 2>/dev/null || true
}

extract() {
    mkdir -p "$OUT_DIR"
    log "extracting artifacts from the OUTPUT disk (libguestfs, root-free)"
    $GL -v "$STATE_DIR:/state:ro" -v "$OUT_DIR:/out" ubuntu:24.04 bash -c '
      apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libguestfs-tools linux-image-generic >/dev/null 2>&1
      export LIBGUESTFS_BACKEND=direct
      guestfish --ro -a /state/win-build-output.img run : mount /dev/sda / : glob copy-out "/*" /out' 2>&1 | grep -iE 'error|fail' || true
    rm -f "$OVERLAY" "$BUILD_ISO" "$OUTPUT_IMG"
    [ -f "$OUT_DIR/rustdesk-setup.exe" ] || die "no rustdesk-setup.exe produced — see $OUT_DIR/build-log.txt"
    sha256sum "$OUT_DIR/rustdesk-setup.exe" | tee "$OUT_DIR/rustdesk-setup.exe.sha256"
    [ -f "$OUT_DIR/rustdesk.msi" ] && sha256sum "$OUT_DIR/rustdesk.msi" | tee "$OUT_DIR/rustdesk.msi.sha256" || log "NOTE: no .msi (WiX is milestone 2)"
}

main() {
    preflight
    build_media
    prep_overlay
    run_build
    extract
    log "build-windows-vm.sh complete: $OUT_DIR (the per-build overlay was destroyed — R-B2 from the golden)"
}

main "$@"

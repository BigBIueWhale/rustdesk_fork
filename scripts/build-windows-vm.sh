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
OFFLINE_ISO="$STATE_DIR/win-build-offline.iso"   # UDF CD: offline cargo-vendor + its source map + the flutter pub-cache
GL="docker run --rm --device /dev/kvm"   # the root-free libguestfs-in-docker driver
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"

preflight() {
    require_cmd qemu-img virt-install virsh xorriso mkfs.vfat docker git
    [ -f "$GOLDEN" ] || die "golden image missing ($GOLDEN) — run scripts/provision-windows-vm.sh first"
    # The per-build is --network=none: the offline crate + dart-pkg sets MUST be staged (online-fetch.sh).
    [ -d "$ONLINE_DIR/cargo-vendor" ]             || die "online/cargo-vendor missing — run scripts/online-fetch.sh"
    [ -f "$ONLINE_DIR/cargo-vendor-config.toml" ] || die "online/cargo-vendor-config.toml missing — run scripts/online-fetch.sh"
    [ -d "$ONLINE_DIR/pub-cache" ]                || die "online/pub-cache missing — run scripts/online-fetch.sh (stage_pub_cache)"
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
    # The pre-generated FRB bridges (R-B7) — git archive excludes them (gitignored) and the guest
    # cannot run FRB itself, so ship the host-generated, platform-agnostic bridges on the BUILD CD.
    # generated_bridge.freezed.dart is the freezed/build_runner `part` of generated_bridge.dart (its
    # @freezed EventToUI types); the windows build runs --no-pub (no in-VM build_runner) so it MUST be
    # shipped too, else the dart kernel compile (flutter_assemble) fails "cannot find ...freezed.dart"
    # + "_$EventToUI not found". It tracks generated_bridge.dart (build_runner regenerates on source change).
    for f in src/bridge_generated.rs src/bridge_generated.io.rs flutter/lib/generated_bridge.dart flutter/lib/generated_bridge.freezed.dart; do
        [ -f "$REPO_ROOT/$f" ] || die "FRB bridge $f missing — generate_bridges (main) should have produced it"
        mkdir -p "$snap/$(dirname "$f")"; cp "$REPO_ROOT/$f" "$snap/$f"
    done
    ( cd "$snap" && xorriso -as mkisofs -quiet -o "$BUILD_ISO" -V BUILD -J -R . )
    rm -rf "$snap"
    # The offline cargo-vendor (2.6G) + flutter pub-cache as ONE UDF CD — UDF is Windows-readable AND
    # handles the deep crate paths / large size that plain Joliet (-J) would truncate or reject. One
    # combined CD (not two) keeps the device count low (a 4th provision CD once broke FirstLogonCommands).
    log "building the OFFLINE UDF media (cargo-vendor + source map + pub-cache) via genisoimage -udf -D"
    rm -f "$OFFLINE_ISO"
    # The host xorriso (this libisofs build) lacks UDF -- `-as mkisofs -udf` -> "Unsupported option '-udf'" --
    # and no UDF tool is installed here, so build the UDF bridge with genisoimage IN A CONTAINER. `-udf` makes
    # it Windows-readable; `-D` (disable deep-relocation) keeps the deep crate/git paths in place -- WITHOUT it
    # genisoimage silently DROPS every dir >6 levels ("Directories too deep ... ignored"), e.g. git-dep example/
    # + .git/ trees, shrinking a ~2.8G medium to ~1G and breaking the offline build. The OFFLINE medium's
    # byte-layout need NOT be R-B2-deterministic: the .exe is derived from the file CONTENTS (cargo-vendor +
    # pub-cache, which ARE the pinned inputs), not from this medium's byte order.
    local off_name; off_name="$(basename "$OFFLINE_ISO")"
    docker run --rm -v "$ONLINE_DIR:/online:ro" -v "$STATE_DIR:/out" -e OFF_NAME="$off_name" debian:stable-slim bash -euc '
        apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq genisoimage >/dev/null 2>&1
        genisoimage -udf -D -r -quiet -V OFFLINE -o "/out/$OFF_NAME" -graft-points \
            /cargo-vendor=/online/cargo-vendor \
            /cargo-vendor-config.toml=/online/cargo-vendor-config.toml \
            /pub-cache=/online/pub-cache
    ' || die "OFFLINE UDF media build (genisoimage in docker) failed"
    [ -f "$OFFLINE_ISO" ] || die "OFFLINE UDF media not produced"
    # The OUTPUT disk = a PARTITIONED FAT disk (MBR table + one FAT partition, type 0x0c FAT32-LBA, label
    # OUTPUT). NOT a raw whole-disk FAT ("superfloppy"): Windows does not mount a partition-table-less FAT on a
    # FIXED (SATA) disk, so the golden's golden-logon.ps1 `Get-Volume -FileSystemLabel OUTPUT` found nothing,
    # golden-logon.ps1 exited, and run-build.ps1 NEVER ran (diagnosed: zero run-build-progress.txt markers on
    # two stalls). libguestfs partitions + FAT-formats it root-free; extract() reads /dev/sda1 to match.
    log "creating the OUTPUT disk (partitioned FAT, label OUTPUT)"
    rm -f "$OUTPUT_IMG"
    qemu-img create -f raw "$OUTPUT_IMG" 3G >/dev/null
    local out_name; out_name="$(basename "$OUTPUT_IMG")"
    $GL -v "$STATE_DIR:/state" -e OUT_NAME="$out_name" ubuntu:24.04 bash -c '
      apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libguestfs-tools linux-image-generic >/dev/null 2>&1
      export LIBGUESTFS_BACKEND=direct
      guestfish -a "/state/$OUT_NAME" run : part-disk /dev/sda mbr : part-set-mbr-id /dev/sda 1 0x0c : mkfs vfat /dev/sda1 label:OUTPUT' \
      || die "OUTPUT disk partition+format failed"
}

prep_overlay() {
    log "cloning the golden into a throwaway CoW overlay"
    rm -f "$OVERLAY"
    # RELATIVE backing path (basename), created from inside $STATE_DIR, so the backing chain resolves BOTH on
    # the host (virt-install) AND inside the libguestfs-in-docker container (which mounts $STATE_DIR at /state).
    # An ABSOLUTE host backing path is a dangling reference in the container -> the appliance qemu can't open
    # the backing file and exits 1 ("appliance closed the connection unexpectedly / guestfs_launch failed").
    ( cd "$STATE_DIR" && qemu-img create -f qcow2 -F qcow2 -b "$(basename "$GOLDEN")" "$(basename "$OVERLAY")" >/dev/null )
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
    # --import: boot the EXISTING golden overlay (no OS install) — without an install method virt-install
    # refuses ("An install method must be specified"). The first --disk (the overlay) is the boot disk.
    virt-install --connect qemu:///session --name "$DOMAIN" --osinfo win11 --memory 16384 --vcpus 8 \
        --import \
        --disk "path=$OVERLAY,format=qcow2,bus=sata" \
        --disk "path=$BUILD_ISO,device=cdrom" \
        --disk "path=$OFFLINE_ISO,device=cdrom" \
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
      guestfish --ro -a /state/win-build-output.img run : mount /dev/sda1 / : glob copy-out "/*" /out
      chown -R '"$(id -u):$(id -g)"' /out' 2>&1 | grep -iE 'error|fail' || true
    # glob copy-out runs as ROOT in the docker -> the extracted files (incl. rustdesk-setup.exe + its
    # .sha256 from the VM) land root-owned, so the host-side `sha256sum | tee ...sha256` below hit EACCES
    # AFTER the .exe was already extracted (a SPURIOUS PERBUILD-FAILED). The chown above (still root, in
    # the docker) hands them to the invoking user so the tee + any later dist/ ops succeed. Drop the
    # FAT system dirs the copy-out also drags in (they are not artifacts).
    rm -rf "$OUT_DIR/System Volume Information" "$OUT_DIR/"'$RECYCLE.BIN' 2>/dev/null || true
    rm -f "$OVERLAY" "$BUILD_ISO" "$OFFLINE_ISO" "$OUTPUT_IMG"
    [ -f "$OUT_DIR/rustdesk-setup.exe" ] || die "no rustdesk-setup.exe produced — see $OUT_DIR/build-log.txt"
    # R-B2: canonicalize the portable packer's own PE so the .exe is BYTE-reproducible. Every CONTENT source is
    # already pinned (/Brepro PE timestamps for flutter+cargo, SOURCE_DATE_EPOCH for app_metadata/gen_version ->
    # the 78 embedded files are byte-identical). The lone residuals are the packer's COFF TimeDateStamp + the
    # MSVC /Brepro debug-repro hash + winres's HashMap-ordered VS_VERSION_INFO strings; canonicalize-pe.py zeros
    # the first two and sorts the version strings. PROVEN: two pre-canonical builds -> identical SHA after this.
    python3 "$SCRIPT_DIR/canonicalize-pe.py" "$OUT_DIR/rustdesk-setup.exe"
    sha256sum "$OUT_DIR/rustdesk-setup.exe" | tee "$OUT_DIR/rustdesk-setup.exe.sha256"
    [ -f "$OUT_DIR/rustdesk.msi" ] && sha256sum "$OUT_DIR/rustdesk.msi" | tee "$OUT_DIR/rustdesk.msi.sha256" || log "NOTE: no .msi (WiX is milestone 2)"
}

main() {
    preflight
    log "pre-generating the FRB bridges on the host (offline; the guest consumes them — R-B7)"
    bash "$SCRIPT_DIR/frb-codegen.sh"
    build_media
    prep_overlay
    run_build
    extract
    log "build-windows-vm.sh complete: $OUT_DIR (the per-build overlay was destroyed — R-B2 from the golden)"
}

main "$@"

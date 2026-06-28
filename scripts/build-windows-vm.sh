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
WIN_HELPER_IMAGE="${HARNESS_PREFIX:-rustdesk-fork-harness}-win-helper"
GL="docker run --rm --network=none --device /dev/kvm"   # the root-free, offline libguestfs-in-docker driver
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"
WINDOWS_BUILD_SOURCE="${WINDOWS_BUILD_SOURCE:-head}" # head = committed release source; worktree = tracked dirty tree for local validation

preflight() {
    require_cmd qemu-img virt-install virsh xorriso mkfs.vfat docker git
    assert_no_build_host_network_residual
    [ -f "$GOLDEN" ] || die "golden image missing ($GOLDEN) — run scripts/provision-windows-vm.sh first"
    verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"
    docker image inspect "$WIN_HELPER_IMAGE" >/dev/null 2>&1 || die "Windows helper image missing: $WIN_HELPER_IMAGE — run scripts/online-fetch.sh"
    # The per-build is --network=none: the offline crate + dart-pkg sets MUST be staged (online-fetch.sh).
    [ -d "$ONLINE_DIR/cargo-vendor" ]             || die "online/cargo-vendor missing — run scripts/online-fetch.sh"
    [ -f "$ONLINE_DIR/cargo-vendor-config.toml" ] || die "online/cargo-vendor-config.toml missing — run scripts/online-fetch.sh"
    [ -d "$ONLINE_DIR/pub-cache" ]                || die "online/pub-cache missing — run scripts/online-fetch.sh (stage_pub_cache)"
    [ -f "$ONLINE_DIR/wix-nuget.tar.gz" ]         || die "online/wix-nuget.tar.gz missing — run scripts/online-fetch.sh (stage_windows_wix_nuget); the .msi WiX NuGet set"
    log "preflight OK — per-build over $GOLDEN, offline, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
}

build_media() {
    # The BUILD CD = a tracked source snapshot (no ./online ./target ./.git) + run-build.ps1 at root
    # (the golden's logon task runs it) + the SOURCE_DATE_EPOCH stamp (R-B2). Release builds default
    # to committed HEAD; local completion validation can set WINDOWS_BUILD_SOURCE=worktree so dirty
    # tracked edits/deletions plus untracked, non-ignored source additions are what the VM compiles
    # instead of a stale git archive.
    local snap="$STATE_DIR/build-snap"; rm -rf "$snap"; mkdir -p "$snap"
    case "$WINDOWS_BUILD_SOURCE" in
        head)
            log "building the BUILD CD (committed HEAD + run-build.ps1 + SOURCE_DATE_EPOCH)"
            git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$snap"
            ;;
        worktree)
            log "building the BUILD CD (tracked + untracked non-ignored worktree + run-build.ps1 + SOURCE_DATE_EPOCH)"
            (
                cd "$REPO_ROOT"
                git ls-files --cached --others --exclude-standard -z | while IFS= read -r -d '' f; do
                    { [ -e "$f" ] || [ -L "$f" ]; } && printf '%s\0' "$f"
                done | tar --null -T - -cf -
            ) | tar -x -C "$snap"
            ;;
        *)
            die "WINDOWS_BUILD_SOURCE must be 'head' or 'worktree' (got '$WINDOWS_BUILD_SOURCE')"
            ;;
    esac
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
    docker run --rm --network=none -v "$ONLINE_DIR:/online:ro" -v "$STATE_DIR:/out" -e OFF_NAME="$off_name" "$WIN_HELPER_IMAGE" bash -euc '
        # The WiX NuGet set (for the .msi) ships on this same OFFLINE CD; /online is ro, so extract the
        # staged tar to a writable /tmp dir and graft it (build-windows.ps1 copies it off the CD to a
        # writable global-packages dir + sets NUGET_PACKAGES for the offline msbuild restore).
        mkdir -p /tmp/wix-nuget && tar xzf /online/wix-nuget.tar.gz -C /tmp/wix-nuget
        genisoimage -udf -D -r -quiet -V OFFLINE -o "/out/$OFF_NAME" -graft-points \
            /cargo-vendor=/online/cargo-vendor \
            /cargo-vendor-config.toml=/online/cargo-vendor-config.toml \
            /pub-cache=/online/pub-cache \
            /wix-nuget=/tmp/wix-nuget
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
    $GL -v "$STATE_DIR:/state" -e OUT_NAME="$out_name" "$WIN_HELPER_IMAGE" bash -c '
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
    $GL -v "$STATE_DIR:/state" "$WIN_HELPER_IMAGE" bash -c '
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
    $GL -v "$STATE_DIR:/state:ro" -v "$OUT_DIR:/out" "$WIN_HELPER_IMAGE" bash -c '
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
    # HONESTY GATE (added 2026-06-24): run-build.ps1 writes `build-windows.ps1 exit=N` to
    # run-build-progress.txt. extract() MUST fail when N != 0 — otherwise a failed in-VM compile silently
    # ships the STALE rustdesk-setup.exe left in the golden's warm target\release by a prior build (the exe
    # FILE exists, so the `-f` check below passes), reporting a FALSE success with a byte-identical .exe.
    # (Diagnosed: an R-X9 cfg-windows error E0433 shipped the prior 3ea44c8f .exe with build-windows.ps1
    # exit=1 yet build-windows-vm.sh exit 0.) The marker is the ground truth for the in-VM build.
    if [ -f "$OUT_DIR/run-build-progress.txt" ]; then
        bw_exit="$(grep -oE 'build-windows\.ps1 exit=[-0-9]+' "$OUT_DIR/run-build-progress.txt" | tail -1 | grep -oE '[-0-9]+$')"
        [ "$bw_exit" = "0" ] || die "in-VM build FAILED (build-windows.ps1 exit=${bw_exit:-<absent>}) — the extracted rustdesk-setup.exe is STALE (prior build's, from the golden's warm target). See $OUT_DIR/build-log.txt"
    else
        die "run-build-progress.txt absent from the OUTPUT disk — the in-VM build never reached a phase marker; see $OUT_DIR/build-log.txt"
    fi
    [ -f "$OUT_DIR/rustdesk-setup.exe" ] || die "no rustdesk-setup.exe produced — see $OUT_DIR/build-log.txt"
    # R-B2: canonicalize the portable packer's own PE so the .exe is BYTE-reproducible. Every CONTENT source is
    # already pinned (/Brepro PE timestamps for flutter+cargo, SOURCE_DATE_EPOCH for app_metadata/gen_version ->
    # the 78 embedded files are byte-identical). The lone residuals are the packer's COFF TimeDateStamp + the
    # MSVC /Brepro debug-repro hash + winres's HashMap-ordered VS_VERSION_INFO strings; canonicalize-pe.py zeros
    # the first two and sorts the version strings. PROVEN: two pre-canonical builds -> identical SHA after this.
    python3 "$SCRIPT_DIR/canonicalize-pe.py" "$OUT_DIR/rustdesk-setup.exe"
    sha256sum "$OUT_DIR/rustdesk-setup.exe" | tee "$OUT_DIR/rustdesk-setup.exe.sha256"
    # The .msi is now REQUIRED (build-windows.ps1 builds it via the WiX msbuild step); a missing one means
    # that step failed -- fail LOUD rather than silently shipping only the .exe (R-B7/§12.2 .exe AND .msi).
    [ -f "$OUT_DIR/rustdesk.msi" ] || die "no rustdesk.msi produced — the WiX .msi step (build-windows.ps1) failed; see $OUT_DIR/build-log.txt"
    # R-B2: canonicalize the .msi's OLE2 \x05SummaryInformation -- the package-code GUID (PID_REVNUMBER,
    # random per build) + the create/last-save FILETIMEs are the SOLE .msi non-determinism (PROVEN against
    # the REAL WiX .msi: canon -> deterministic package code {3A06D467..} + FILETIMEs zeroed to 1601, the
    # .msi stays valid; the CAB + tables are deterministic). olefile is NOT stdlib (unlike canonicalize-pe.py
    # for the .exe), so run it in the pinned debian image. The package code is a deterministic uuid5 of the
    # Cargo.toml version (same per version -> byte-reproducible). Then record the canonicalized SHA.
    local msi_ver; msi_ver="$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*=[[:space:]]*"\(.*\)".*/\1/')"
    docker run --rm --network=none -e MSI_VER="$msi_ver" -v "$OUT_DIR:/out" -v "$SCRIPT_DIR:/s:ro" "$WIN_HELPER_IMAGE" bash -euc '
        python3 /s/canonicalize-msi.py /out/rustdesk.msi "$MSI_VER"
    ' || die ".msi OLE2 canonicalization (R-B2) failed"
    sha256sum "$OUT_DIR/rustdesk.msi" | tee "$OUT_DIR/rustdesk.msi.sha256"
}

main() {
    preflight
    log "pre-generating the FRB bridges on the host (offline; the guest consumes them — R-B7)"
    bash "$SCRIPT_DIR/frb-codegen.sh"
    build_media
    prep_overlay
    run_build
    extract
    # R-B2 double-build — the assertion build-debian.sh already makes, now mirrored for Windows.
    # (Android is EXEMPT by §12.1: "Integrity is the recorded SHA-256, NOT cross-rebuild byte-identity".
    # Windows is NOT exempt — it ACHIEVES byte-identity via canonicalize-pe/canonicalize-msi + the FIXED
    # golden + SOURCE_DATE_EPOCH-pinned BUILD_DATE — so a second build of identical source MUST be
    # byte-identical (A==B), or the recorded-SHA bar is unfalsifiable.) Default-on like build-debian;
    # DOUBLE_BUILD=0 skips it for a quick single build (the 2nd VM cycle is the slow part).
    if [ "${DOUBLE_BUILD:-1}" = "1" ]; then
        local exe1 msi1
        exe1="$(awk '{print $1}' "$OUT_DIR/rustdesk-setup.exe.sha256")"
        msi1="$(awk '{print $1}' "$OUT_DIR/rustdesk.msi.sha256")"
        log "R-B2 double-build: rebuilding the same source from the byte-identical golden to assert A==B"
        local saved_out="$OUT_DIR"
        OUT_DIR="$saved_out/_rebuild"; rm -rf "$OUT_DIR"
        build_media; prep_overlay; run_build; extract
        local exe2 msi2
        exe2="$(awk '{print $1}' "$OUT_DIR/rustdesk-setup.exe.sha256")"
        msi2="$(awk '{print $1}' "$OUT_DIR/rustdesk.msi.sha256")"
        rm -rf "$OUT_DIR"; OUT_DIR="$saved_out"
        [ "$exe1" = "$exe2" ] || die "R-B2 double-build .exe SHA mismatch ($exe1 vs $exe2) — fix PE/BUILD_DATE determinism"
        [ "$msi1" = "$msi2" ] || die "R-B2 double-build .msi SHA mismatch ($msi1 vs $msi2) — fix MSI canonicalizer determinism"
        log "R-B2 double-build determinism OK (A==B): exe=$exe1 msi=$msi1"
    fi
    log "build-windows-vm.sh complete: $OUT_DIR (the per-build overlay was destroyed — R-B2 from the golden)"
}

main "$@"

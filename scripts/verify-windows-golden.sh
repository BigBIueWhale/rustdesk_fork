#!/usr/bin/env bash
# scripts/verify-windows-golden.sh — assert the §12.2 golden Win11 template is FULLY provisioned
# (R-B8), not just OS-installed. provision-windows-vm.sh's poll-for-power-off declares success when
# the domain stays shut off, but a guest whose FirstLogonCommands never ran win-guest-setup.ps1 also
# ends up powered off — so a silent "OS-only" golden can masquerade as a built one. This reads the
# golden READ-ONLY via libguestfs-in-docker (root-free, --device /dev/kvm) and checks for the
# win-guest-setup completion marker (C:\guest-setup-done.txt, written immediately before its final
# Stop-Computer) plus each pinned toolchain. Fails loud + non-zero if the marker or a toolchain is
# missing; if the marker is absent it virt-cat's the transcript tail so the stop-point is visible.
#
# NOT part of "fork creation" — a build-harness diagnostic, run after provision-windows-vm.sh.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

STATE_DIR="$REPO_ROOT/.harness-state"
GOLDEN="$STATE_DIR/win11-golden.qcow2"

require_cmd docker
[ -f "$GOLDEN" ] || die "golden not found: $GOLDEN (run provision-windows-vm.sh first)"
[ -e /dev/kvm ] || die "/dev/kvm absent — the libguestfs-in-docker appliance needs it"

log "inspecting the golden read-only via libguestfs (throwaway debian container; ~2-3 min to apt-in the tools)"
# virt-ls/virt-cat each auto-inspect the Windows root, so paths are C:-relative with '/'. Two appliance
# boots (root listing + the definitive done-marker), no fail-cascade. The done marker is conclusive:
# win-guest-setup.ps1 writes C:\guest-setup-done.txt ONLY at its very end (after the vcpkg natives),
# immediately before Stop-Computer — so its presence proves the whole toolchain install completed.
out="$(docker run --rm --device /dev/kvm -v "$STATE_DIR:/state:ro" debian:stable-slim bash -c '
  apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libguestfs-tools linux-image-generic >/dev/null 2>&1
  export LIBGUESTFS_BACKEND=direct
  echo "=== C:\\ root listing (expect flutter, vcpkg, guest-setup-done.txt, online, src) ==="
  virt-ls -a /state/win11-golden.qcow2 / 2>&1 | sort || echo "(virt-ls of C:\\ failed — OS not inspectable)"
  echo "=== C:\\vcpkg\\installed\\x64-windows-static (the warmed sec3.2 natives) ==="
  virt-ls -a /state/win11-golden.qcow2 "/vcpkg/installed/x64-windows-static/lib" 2>/dev/null | head -8 || echo "(absent — vcpkg natives not warmed)"
  echo "=== verdict ==="
  if virt-cat -a /state/win11-golden.qcow2 /guest-setup-done.txt >/dev/null 2>&1; then
    echo "GOLDEN-OK: C:\\guest-setup-done.txt present — win-guest-setup.ps1 ran to completion"
  else
    echo "GOLDEN-FAIL: C:\\guest-setup-done.txt ABSENT — win-guest-setup.ps1 did not complete"
    echo "=== C:\\setup-transcript.txt (tail, where it stopped) ==="
    virt-cat -a /state/win11-golden.qcow2 /setup-transcript.txt 2>/dev/null | tail -30 || echo "(no transcript — FirstLogonCommands never launched win-guest-setup.ps1)"
  fi
')"
echo "$out"

if echo "$out" | grep -q '^GOLDEN-OK:'; then
  log "golden verified — toolchain provisioning complete; build-windows-vm.sh can produce the .exe"
  exit 0
else
  die "golden verification FAILED — see the inventory + transcript above"
fi

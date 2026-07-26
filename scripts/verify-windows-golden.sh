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
umask 077
export PATH=/usr/bin:/bin
readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || { printf 'verify-windows-golden refuses host or container-root execution\n' >&2; exit 1; }
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || { printf 'verify-windows-golden refuses a root primary group\n' >&2; exit 1; }
SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
# shellcheck source=scripts/windows-helper-runtime.sh
source "$SCRIPT_DIR/windows-helper-runtime.sh"

STATE_DIR="$REPO_ROOT/.harness-state"
GOLDEN="$STATE_DIR/win11-golden.qcow2"

assert_no_build_host_network_residual
[ -f "$GOLDEN" ] || die "golden not found: $GOLDEN (run provision-windows-vm.sh first)"
[ -e /dev/kvm ] || die "/dev/kvm absent — the libguestfs-in-docker appliance needs it"
verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"

cleanup_windows_helper_authority() {
  local status=$?
  trap - EXIT
  windows_helper_authority_close || status=1
  exit "$status"
}
trap cleanup_windows_helper_authority EXIT

windows_helper_authority_open
windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"

log "inspecting the golden read-only via libguestfs (offline Windows helper image)"
# virt-ls/virt-cat each auto-inspect the Windows root, so paths are C:-relative with '/'. Two appliance
# boots (root listing + the definitive done-marker), no fail-cascade. The done marker is conclusive:
# win-guest-setup.ps1 writes C:\guest-setup-done.txt ONLY at its very end (after the vcpkg natives),
# immediately before Stop-Computer — so its presence proves the whole toolchain install completed.
out="$(
  windows_helper_kvm_guestfish_run \
    --mount "type=bind,source=$GOLDEN,target=/authority/golden.qcow2,readonly" \
    -- /bin/bash --noprofile --norc \
      /authority/windows-golden-inspect.sh inventory
)"
echo "$out"

if echo "$out" | grep -q '^GOLDEN-OK:'; then
  log "golden verified — toolchain provisioning complete; build-windows-vm.sh can produce the .exe"
  exit 0
else
  die "golden verification FAILED — see the inventory + transcript above"
fi

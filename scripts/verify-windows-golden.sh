#!/usr/bin/env bash
# Verify the pinned Windows golden hash and exact completed-setup receipt inside the admitted VM.
# Native toolchain readiness, Windows installation and build acceptance remain separate checks.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || { printf 'verify-windows-golden refuses host or container-root execution\n' >&2; exit 1; }
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || { printf 'verify-windows-golden refuses a root primary group\n' >&2; exit 1; }
readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
/usr/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null
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

log "checking the exact golden completion receipt read-only via libguestfs"
windows_helper_kvm_guestfish_run \
    --mount "type=bind,source=$GOLDEN,target=/authority/golden.qcow2,readonly" \
    -- /bin/bash --noprofile --norc \
      /authority/windows-golden-inspect.sh marker
log "golden hash and exact completed-setup receipt verified"

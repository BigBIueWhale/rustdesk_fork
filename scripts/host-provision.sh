#!/usr/bin/env bash
# scripts/host-provision.sh — additive, idempotent host provisioning (R-B11).
#
# Installs ONLY the host-level runtimes the EPHEMERAL build environments need — the
# container engine (Debian/Android build in Docker) and, for the Windows VM,
# qemu-kvm + libvirt + swtpm + OVMF — plus the few tools the scripts themselves
# call. The pinned TOOLCHAINS never land on the host: they live in the ephemeral
# image / VM (R-B8). Provisioning is additive and idempotent — for each package it
# checks whether the host already has it and installs ONLY what is absent,
# recording exactly what it added so cleanup.sh can reverse precisely.
#
# Run order (R-B10): host-provision.sh (once) -> online-fetch.sh -> build-* -> cleanup.sh
#
# THIS SCRIPT IS NOT RUN as part of "fork creation" — it is a checked-in build
# artifact. It installs packages, so an operator runs it deliberately, once.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# The provisioned manifest is build STATE, not cache: it MUST live OUTSIDE the
# disposable ./online so a cache wipe cannot strand the reversal (R-B11). (R-B11's
# prose says "./online/.provisioned" but its own parenthetical overrides that — the
# manifest lives here, at a stable repo-root state dir, instead.)
STATE_DIR="$REPO_ROOT/.harness-state"
PROVISIONED_FILE="$STATE_DIR/provisioned"

# Host must be the one Linux x86_64 box the matrix targets (R-B8).
assert_host() {
    [ "$(uname -s)" = "Linux" ] || die "host-provision.sh runs on the Linux x86_64 build host only (R-B8); got $(uname -s)"
    [ "$(uname -m)" = "x86_64" ] || die "host arch must be x86_64 (R-B8); got $(uname -m)"
    command -v apt-get >/dev/null 2>&1 || die "this provisioner targets a Debian/Ubuntu host (apt-get) — adapt for another distro deliberately, do not guess"
}

# pkg_installed: true iff the dpkg package is installed.
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# provision_pkg NAME: install NAME only if absent, and record that WE added it so
# the reversal touches only what we installed (never a pre-existing package).
provision_pkg() {
    local pkg="$1"
    if pkg_installed "$pkg"; then
        log "already present (not recorded, will not be removed): $pkg"
        return 0
    fi
    log "installing host runtime: $pkg"
    sudo apt-get install -y --no-install-recommends "$pkg"
    mkdir -p "$STATE_DIR"
    # Record only on a confirmed fresh install (idempotent: no duplicate lines).
    grep -qxF "$pkg" "$PROVISIONED_FILE" 2>/dev/null || echo "$pkg" >> "$PROVISIONED_FILE"
}

main() {
    assert_host
    log "additive host provisioning (only the absent packages are installed + recorded)"
    sudo apt-get update

    # Container engine for the Debian .deb and Android .apk builds (R-B8/§12.1).
    # Docker is upstream's path; podman is an acceptable drop-in (choose one).
    provision_pkg docker.io

    # Windows x86_64 .exe/.msi build runs in an ephemeral KVM Windows 11 guest on
    # this same host (§12.2). The hypervisor stack, all host-level.
    #
    # Package names verified against the build host, Ubuntu 24.04 LTS (R-B8). Two
    # correctness notes that a spec-literal "qemu-kvm + libvirt + swtpm + OVMF"
    # (R-B11) misses on a real 24.04 box:
    #   1. `qemu-kvm` was REMOVED in Ubuntu 24.04 — `apt-cache policy qemu-kvm`
    #      has no candidate, so the old line aborted the whole script under set -e.
    #      The KVM-capable system emulator is `qemu-system-x86`.
    #   2. This installer uses --no-install-recommends, so a package that is only a
    #      Recommends (qemu-utils) or no dependency at all (virtinst, osinfo-db) is
    #      NOT pulled transitively and MUST be listed explicitly — otherwise
    #      provision-windows-vm.sh's `require_cmd virt-install virsh qemu-img swtpm`
    #      fails preflight even though the apt step "succeeded".
    provision_pkg qemu-system-x86       # the KVM hypervisor (the 24.04 name for ex-`qemu-kvm`)
    provision_pkg qemu-utils            # qemu-img — golden qcow2 + CoW overlays (only a Recommends of virtinst)
    provision_pkg libvirt-daemon-system # libvirtd (systemd auto-enables + starts it on install)
    provision_pkg libvirt-clients       # virsh
    provision_pkg virtinst              # virt-install — builds the golden image (not pulled transitively)
    provision_pkg osinfo-db             # the OS database `virt-install --osinfo win11` needs (not a hard dep)
    provision_pkg swtpm                 # vTPM 2.0 the Win11 guest requires
    provision_pkg ovmf                  # UEFI firmware for the guest

    # The few tools the scripts call.
    provision_pkg ca-certificates
    provision_pkg curl
    provision_pkg jq

    log "host provisioning complete. Reverse with: scripts/cleanup.sh --reverse-host (R-B11)"
    [ -f "$PROVISIONED_FILE" ] && log "recorded installs: $(tr '\n' ' ' < "$PROVISIONED_FILE")" || log "nothing was installed (host already provisioned)"
}

main "$@"

#!/usr/bin/env bash
# scripts/cleanup.sh — reversible-only teardown that never touches what pre-existed
# (R-B11). The cleanup surface is exactly the inverse of what the harness created.
#
#   scripts/cleanup.sh                 # default: remove ONLY harness-created
#                                      #   ephemeral artifacts (always safe — we made them)
#   scripts/cleanup.sh --build-host-network
#                                      # explicit: remove old harness-created
#                                      #   system-libvirt default networking
#   scripts/cleanup.sh --reverse-host  # SEPARATE, explicit: remove ONLY the host
#                                      #   packages recorded as installed-by-us
#
# No --force, no heuristics. The host reversal removes only packages recorded in
# the provisioned manifest; it MUST NOT remove or downgrade anything that
# pre-existed, and MUST refuse (fail-closed) if that manifest is absent rather than
# guess. The build-host-network reversal is similarly manifest-gated: it tears
# down libvirt's default NAT network only when the manifest proves the harness
# installed libvirt-daemon-system; otherwise it fails closed instead of touching
# pre-existing host state. NOT run as part of "fork creation" — a checked-in build
# artifact.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

STATE_DIR="$REPO_ROOT/.harness-state"
PROVISIONED_FILE="$STATE_DIR/provisioned"

# Everything the harness creates is named with this stable prefix so teardown can
# target exactly it and nothing else (the build-* scripts MUST use it).
HARNESS_PREFIX="rustdesk-fork-harness"

# ── Host-network audit / old system-libvirt default-network cleanup ──────────
harness_installed_pkg() {
    local pkg="$1"
    [ -f "$PROVISIONED_FILE" ] && grep -qxF "$pkg" "$PROVISIONED_FILE"
}

system_libvirt_network_dirty() {
    ip link show virbr0 >/dev/null 2>&1 && return 0
    ss -ltnup 2>/dev/null | grep -Eq '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' && return 0
    return 1
}

assert_no_system_libvirt_network() {
    if ip link show virbr0 >/dev/null 2>&1; then
        die "virbr0 still exists — build-host network cleanup incomplete (R-B11a)"
    fi
    if ss -ltnup 2>/dev/null | grep -Eq '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67'; then
        ss -ltnup 2>/dev/null | grep -E '192[.]168[.]122[.]1:53|0[.]0[.]0[.]0%virbr0:67' || true
        die "libvirt default-network DNS/DHCP listener still present (R-B11a)"
    fi
}

sudo_noninteractive_available() {
    sudo -n true >/dev/null 2>&1
}

system_virsh() {
    if virsh --connect qemu:///system list --all >/dev/null 2>&1; then
        virsh --connect qemu:///system "$@"
        return $?
    fi
    if sudo_noninteractive_available && sudo -n virsh --connect qemu:///system list --all >/dev/null 2>&1; then
        sudo -n virsh --connect qemu:///system "$@"
        return $?
    fi
    return 125
}

cleanup_build_host_network() {
    require_cmd ip ss
    if ! system_libvirt_network_dirty; then
        log "system libvirt default network not present (no virbr0 / no 192.168.122.1:53 / no virbr0 DHCP listener)"
        return 0
    fi

    harness_installed_pkg libvirt-daemon-system \
        || die "system libvirt default networking is present, but $PROVISIONED_FILE does not prove the harness installed libvirt-daemon-system; refusing to touch pre-existing host state (R-B11a)"

    command -v virsh >/dev/null 2>&1 || die "virbr0/libvirt dnsmasq present, but virsh is not installed — cannot safely undo the harness-created default network"

    log "tearing down harness-created system libvirt default network (default net / virbr0 / dnsmasq)"
    local rc=0
    system_virsh net-destroy default || rc=$?
    [ "$rc" = "0" ] || [ "$rc" = "1" ] || [ "$rc" = "125" ] || true
    if [ "$rc" = "125" ]; then
        die "system libvirt default network is present, but this session lacks noninteractive sudo; run scripts/cleanup.sh --build-host-network with privileges (R-B11a)"
    fi
    rc=0
    system_virsh net-autostart --disable default || rc=$?
    [ "$rc" = "0" ] || [ "$rc" = "1" ] || [ "$rc" = "125" ] || true
    [ "$rc" != "125" ] || die "cannot disable default libvirt autostart without noninteractive sudo (R-B11a)"
    rc=0
    system_virsh net-undefine default || rc=$?
    [ "$rc" = "0" ] || [ "$rc" = "1" ] || [ "$rc" = "125" ] || true
    [ "$rc" != "125" ] || die "cannot undefine default libvirt network without noninteractive sudo (R-B11a)"

    assert_no_system_libvirt_network
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
        die "net.ipv4.ip_forward is still 1 after default-network teardown; cleanup cannot prove whether this is harness-attributable, so fail closed (R-B11a)"
    fi
    log "build-host network cleanup complete."
}

# ── Default: remove only harness-created ephemeral artifacts ──────────────────
clean_ephemeral() {
    log "removing harness-created ephemeral artifacts (prefix: $HARNESS_PREFIX)"

    # Docker: containers then images bearing our prefix (we tagged them).
    if command -v docker >/dev/null 2>&1; then
        local ids
        ids="$(docker ps -aq --filter "name=${HARNESS_PREFIX}" 2>/dev/null || true)"
        [ -z "$ids" ] || { log "docker rm: $ids"; docker rm -f $ids >/dev/null; }
        ids="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep "^${HARNESS_PREFIX}" || true)"
        [ -z "$ids" ] || { log "docker rmi: $ids"; echo "$ids" | xargs -r docker rmi -f >/dev/null; }
    fi

    # Direct QEMU harness leftovers: old provisioner/debug VMs used pidfiles under
    # .harness-state/winvm and loopback-only VNC/SSH forwards. They are still
    # harness-created ephemeral artifacts, so cleanup owns them.
    local pidfile pid
    for pidfile in "$STATE_DIR"/winvm/*.pid "$STATE_DIR"/winvm/qemu.pid; do
        [ -f "$pidfile" ] || continue
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [ -n "${pid:-}" ] && kill -0 "$pid" >/dev/null 2>&1; then
            log "stopping harness qemu process from $pidfile: pid=$pid"
            kill "$pid" >/dev/null 2>&1 || true
            sleep 2
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
        rm -f "$pidfile"
    done
    rm -f "$STATE_DIR"/winvm/*.sock "$STATE_DIR"/winvm/monitor.sock "$STATE_DIR"/winvm/tpm.sock 2>/dev/null || true

    # libvirt session: transient build domains + their copy-on-write qcow2 overlays.
    if command -v virsh >/dev/null 2>&1; then
        local doms d
        doms="$(virsh --connect qemu:///session list --all --name 2>/dev/null | grep "^${HARNESS_PREFIX}" || true)"
        for d in $doms; do
            log "virsh qemu:///session destroy/undefine: $d"
            virsh --connect qemu:///session destroy "$d" >/dev/null 2>&1 || true
            virsh --connect qemu:///session undefine --nvram "$d" >/dev/null 2>&1 || true
        done
    fi
    # qcow2 overlays the harness wrote under its own overlay dir only.
    if [ -d "$STATE_DIR/overlays" ]; then
        log "removing qcow2 overlays under $STATE_DIR/overlays"
        rm -f "$STATE_DIR/overlays/"*.qcow2 2>/dev/null || true
    fi

    log "ephemeral cleanup done. Host packages are left intact (use --reverse-host to undo those)."
}

# ── Explicit: reverse ONLY the host packages we installed ─────────────────────
reverse_host() {
    [ -f "$PROVISIONED_FILE" ] || die "no provisioned manifest at $PROVISIONED_FILE — refusing to guess what to remove (R-B11 fail-closed)"
    local pkgs
    pkgs="$(grep -v '^[[:space:]]*$' "$PROVISIONED_FILE" || true)"
    [ -n "$pkgs" ] || { log "manifest is empty — nothing the harness installed; removing nothing."; return 0; }
    if echo "$pkgs" | grep -qxF libvirt-daemon-system; then
        cleanup_build_host_network
    fi
    log "reversing ONLY harness-installed host packages (never pre-existing): $(echo "$pkgs" | tr '\n' ' ')"
    # shellcheck disable=SC2086
    sudo apt-get remove -y $pkgs
    rm -f "$PROVISIONED_FILE"
    rmdir "$STATE_DIR" 2>/dev/null || true
    log "host reversal complete."
}

main() {
    case "${1:-}" in
        "")             clean_ephemeral ;;
        --build-host-network) cleanup_build_host_network ;;
        --reverse-host) reverse_host ;;
        *)              die "unknown argument: $1 (use no args, --build-host-network, or --reverse-host)" ;;
    esac
}

main "$@"

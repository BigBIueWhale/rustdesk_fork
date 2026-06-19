#!/usr/bin/env bash
# scripts/cleanup.sh — reversible-only teardown that never touches what pre-existed
# (R-B11). The cleanup surface is exactly the inverse of what the harness created.
#
#   scripts/cleanup.sh                 # default: remove ONLY harness-created
#                                      #   ephemeral artifacts (always safe — we made them)
#   scripts/cleanup.sh --reverse-host  # SEPARATE, explicit: remove ONLY the host
#                                      #   packages recorded as installed-by-us
#
# No --force, no heuristics. The host reversal removes only packages recorded in
# the provisioned manifest; it MUST NOT remove or downgrade anything that
# pre-existed, and MUST refuse (fail-closed) if that manifest is absent rather than
# guess. NOT run as part of "fork creation" — a checked-in build artifact.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

STATE_DIR="$REPO_ROOT/.harness-state"
PROVISIONED_FILE="$STATE_DIR/provisioned"

# Everything the harness creates is named with this stable prefix so teardown can
# target exactly it and nothing else (the build-* scripts MUST use it).
HARNESS_PREFIX="rustdesk-fork-harness"

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

    # libvirt: transient build domains + their copy-on-write qcow2 overlays.
    if command -v virsh >/dev/null 2>&1; then
        local doms d
        doms="$(virsh list --all --name 2>/dev/null | grep "^${HARNESS_PREFIX}" || true)"
        for d in $doms; do
            log "virsh destroy/undefine: $d"
            virsh destroy "$d" >/dev/null 2>&1 || true
            virsh undefine --nvram "$d" >/dev/null 2>&1 || true
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
        --reverse-host) reverse_host ;;
        *)              die "unknown argument: $1 (use no args, or --reverse-host)" ;;
    esac
}

main "$@"

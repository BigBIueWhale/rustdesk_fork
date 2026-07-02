#!/usr/bin/env bash
# scripts/build-release.sh — the ONE fail-loud release orchestrator (R-B2/R-B8/§12).
#
# The DEFAULT invocation IS the correct, complete, reproducible release build. No flags, no env, no
# manual ordering: it re-verifies the whole environment, does a from-scratch clean, builds ALL THREE
# targets (each self-double-builds A==B and dies on any mismatch), collates the four artifact SHA-256s
# into dist/SHA256SUMS stamped with the exact HEAD, and returns ONE green/red verdict. Every missing
# prerequisite gives a precise "run scripts/X" error, so an operator on a fresh machine iterates on the
# errors until it is perfect — it is structurally impossible to silently ship a wrong/stale/partial set.
#
# Trust nobody: this orchestrator asserts its own preconditions AND each per-target script re-asserts
# ITS pins / images / online-SHAs / keystore / golden independently (§12.3). Nothing trusts a sibling.
#
# Modes:
#   (default)       full release: preflight -> clean -> deb + android + windows -> SHA256SUMS -> verdict
#   --doctor        preflight ONLY: diagnose the environment + every prerequisite, build NOTHING
#   --skip-windows  deb + android only (when the §12.2 KVM/Windows host is deliberately absent)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
DO_WINDOWS=1
DOCTOR=0
for a in "$@"; do
    case "$a" in
        --doctor)       DOCTOR=1 ;;
        --skip-windows) DO_WINDOWS=0 ;;
        -h|--help)      sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument '$a' — usage: build-release.sh [--doctor] [--skip-windows]" ;;
    esac
done

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" show -s --format=%ct "$RUSTDESK_COMMIT" 2>/dev/null || echo 1700000000)}"
HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
HEAD_SHORT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# ── Preflight: assert EVERYTHING before building anything (fail loud, all at once) ─────────────────
release_preflight() {
    require_cmd docker git sha256sum
    assert_repo_state
    assert_source_date_epoch
    require_online_complete
    # An official release MUST build from a clean, committed HEAD, or the artifacts do not correspond
    # to the recorded source (R-B2/R-B7).
    [ -z "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] \
        || die "working tree is DIRTY — an official release must build from a clean committed HEAD. Commit or stash first (git status)."
    for s in build-debian.sh build-android.sh; do
        [ -f "$SCRIPT_DIR/$s" ] || die "scripts/$s missing (corrupt checkout?)"
    done
    # Operator-supplied secrets: surface EVERYTHING missing here, not one failure three hours in.
    [ -n "${ANDROID_KEYSTORE:-}" ] && [ -f "${ANDROID_KEYSTORE:-/nonexistent}" ] \
        || die "ANDROID_KEYSTORE unset or not found — the signed APK needs the stable R-B2 key. Generate it ONCE with: scripts/gen-android-keystore.sh <out.jks> <pass-file>  then: export ANDROID_KEYSTORE=<out.jks> ANDROID_KEYSTORE_PASS_FILE=<pass-file>"
    [ -n "${ANDROID_KEYSTORE_PASS_FILE:-}" ] && [ -f "${ANDROID_KEYSTORE_PASS_FILE:-/nonexistent}" ] \
        || die "ANDROID_KEYSTORE_PASS_FILE unset or not found (the keystore password, supplied via file — never argv/env, R-B2)"
    if [ "$DO_WINDOWS" = 1 ]; then
        [ -f "$SCRIPT_DIR/build-windows-vm.sh" ] || die "scripts/build-windows-vm.sh missing"
        [ -f "$REPO_ROOT/.harness-state/win11-golden.qcow2" ] \
            || die "the Windows golden VM is missing (.harness-state/win11-golden.qcow2). Provision it ONCE: scripts/provision-windows-vm.sh — or pass --skip-windows to build deb+android only."
    fi
    log "release preflight OK — HEAD $HEAD_SHORT, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, windows=$DO_WINDOWS"
    log "  (each per-target build re-asserts its own pins / image / ./online SHAs / keystore / golden — §12.3)"
}

# ── From-scratch clean (assume NOTHING about tree state; docker-root clears root-owned build output) ──
clean_from_scratch() {
    local img="${HARNESS_PREFIX:-rustdesk-fork-harness}-deb-builder"
    log "from-scratch clean: host target/ + flutter/build (a genuine cold build; safe on any tree state)"
    if docker image inspect "$img" >/dev/null 2>&1; then
        docker run --rm -v "$REPO_ROOT:/src" -w /src "$img" \
            rm -rf /src/target /src/flutter/build /src/flutter/.flutter-plugins-dependencies /src/flutter/.flutter-plugins
    else
        # No builder image yet: host rm is enough (nothing root-owned exists before the first build).
        rm -rf "$REPO_ROOT/target" "$REPO_ROOT/flutter/build" \
               "$REPO_ROOT/flutter/.flutter-plugins-dependencies" "$REPO_ROOT/flutter/.flutter-plugins"
    fi
}

# ── Per-artifact result assertion (produced THIS run, non-empty, sha recorded) ─────────────────────
declare -a MANIFEST=()
record_artifact() { # PATH LABEL
    local p="$1" label="$2"
    [ -f "$p" ] || die "$label was not produced ($p missing) — the build did not emit it (see output above)"
    [ -s "$p" ] || die "$label is empty ($p) — refusing to publish a zero-byte artifact"
    MANIFEST+=("$(sha256sum "$p" | awk '{print $1}')  $(basename "$p")")
    log "  artifact OK: $(basename "$p")"
}

main() {
    release_preflight
    if [ "$DOCTOR" = 1 ]; then
        log "DOCTOR mode: environment + prerequisites verified; nothing built. Remove --doctor to build the release."
        exit 0
    fi
    clean_from_scratch

    # Each build self-double-builds A==B (DOUBLE_BUILD default) and dies on mismatch. deb+android share
    # the flutter tree, so they run SERIAL; windows uses its own VM.
    log "==== [1/3] Debian (x86_64 .deb) ===="
    OUT_DIR="$OUT_DIR" bash "$SCRIPT_DIR/build-debian.sh"
    record_artifact "$OUT_DIR/rustdesk-x86_64.deb" "Debian .deb"

    log "==== [2/3] Android (aarch64 .apk) ===="
    OUT_DIR="$OUT_DIR" bash "$SCRIPT_DIR/build-android.sh"
    record_artifact "$OUT_DIR/rustdesk-arm64.apk" "Android .apk"

    if [ "$DO_WINDOWS" = 1 ]; then
        log "==== [3/3] Windows (x86_64 .exe + .msi) ===="
        OUT_DIR="$OUT_DIR" bash "$SCRIPT_DIR/build-windows-vm.sh"
        record_artifact "$OUT_DIR/rustdesk-setup.exe" "Windows .exe"
        record_artifact "$OUT_DIR/rustdesk.msi"       "Windows .msi"
    else
        warn "[3/3] Windows SKIPPED (--skip-windows) — this is NOT a complete release set"
    fi

    # SHA256SUMS: the live source->hash manifest, stamped with the exact HEAD it was built from. This
    # REPLACES the hand-written stale manifest (R-B2 integrity = the pinned SHA verified over the
    # operator's trusted channel; there is no code-signing, R-P5).
    {
        printf '# rustdesk-fork release artifacts — R-B2 reproducible (double-build A==B per target)\n'
        printf '# HEAD %s   SOURCE_DATE_EPOCH %s   built %s\n' "$HEAD" "$SOURCE_DATE_EPOCH" \
            "$(git -C "$REPO_ROOT" show -s --format=%cI "$HEAD" 2>/dev/null || echo '?')"
        [ "$DO_WINDOWS" = 1 ] || printf '# WARNING: --skip-windows — .exe/.msi absent, NOT a full release set\n'
        printf '%s\n' "${MANIFEST[@]}"
    } > "$OUT_DIR/SHA256SUMS"
    log "wrote $OUT_DIR/SHA256SUMS (HEAD $HEAD_SHORT):"
    sed 's/^/    /' "$OUT_DIR/SHA256SUMS" >&2

    log "RELEASE OK — all ${#MANIFEST[@]} artifacts built cold, self-double-build A==B, at HEAD $HEAD_SHORT"
}

main "$@"

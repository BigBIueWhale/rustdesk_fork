#!/usr/bin/env bash
# Fixed container-side libguestfs operations for the Windows golden image.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'windows-golden-inspect: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "requires exactly one fixed operation"
readonly GOLDEN=/authority/golden.qcow2
readonly EXPECTED_RECEIPT=$'rustdesk-windows-golden-v3\nbuilder-password-never-expires=true\nbuilder-logon-task=interactive\nsetup-complete=true'
[ -f "$GOLDEN" ] && [ ! -L "$GOLDEN" ] || fail "golden input must be a regular file"

case "$1" in
    marker)
        marker="$({ /usr/bin/virt-cat -a "$GOLDEN" /guest-setup-done.txt \
            | /usr/bin/tr -d '\r'; } 2>/dev/null)" \
            || fail "cannot read the golden completion receipt"
        [ "$marker" = "$EXPECTED_RECEIPT" ] \
            || fail "golden completion receipt is absent or incompatible"
        ;;
    inventory)
        printf '%s\n' '=== C:\ root listing (expect flutter, vcpkg, guest-setup-done.txt, online, src) ==='
        /usr/bin/virt-ls -a "$GOLDEN" / 2>&1 | /usr/bin/sort \
            || printf '%s\n' '(virt-ls of C:\ failed — OS not inspectable)'
        printf '%s\n' '=== C:\vcpkg\installed\x64-windows-static (the warmed sec3.2 natives) ==='
        /usr/bin/virt-ls -a "$GOLDEN" \
            '/vcpkg/installed/x64-windows-static/lib' 2>/dev/null \
            | /usr/bin/head -8 \
            || printf '%s\n' '(absent — vcpkg natives not warmed)'
        printf '%s\n' '=== C:\flutter\bin\cache\artifacts\engine (the precached windows engine, for the offline flutter build) ==='
        /usr/bin/virt-ls -a "$GOLDEN" \
            '/flutter/bin/cache/artifacts/engine' 2>/dev/null \
            | /usr/bin/grep -i windows \
            || printf '%s\n' '(no windows engine — flutter precache --windows did not run)'
        printf '%s\n' '=== verdict ==='
        marker="$({ /usr/bin/virt-cat -a "$GOLDEN" /guest-setup-done.txt \
            | /usr/bin/tr -d '\r'; } 2>/dev/null || :)"
        if [ "$marker" = "$EXPECTED_RECEIPT" ]; then
            printf '%s\n' 'GOLDEN-OK: exact v3 completion receipt present — setup completed with a non-expiring builder password and interactive logon task'
        else
            printf '%s\n' 'GOLDEN-FAIL: exact v3 completion receipt ABSENT — setup is incomplete or incompatible'
            printf '%s\n' '=== C:\setup-transcript.txt (tail, where it stopped) ==='
            /usr/bin/virt-cat -a "$GOLDEN" /setup-transcript.txt 2>/dev/null \
                | /usr/bin/tail -30 \
                || printf '%s\n' '(no transcript — FirstLogonCommands never launched win-guest-setup.ps1)'
        fi
        ;;
    *)
        fail "unknown operation"
        ;;
esac

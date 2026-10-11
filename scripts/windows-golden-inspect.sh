#!/usr/bin/env bash
# Fixed read-only completion receipt assertion for the Windows golden image.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

fail() {
    printf 'windows-golden-inspect: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] && [ "$1" = marker ] || fail "requires the fixed marker operation"
readonly GOLDEN=/authority/golden.qcow2
[ -f "$GOLDEN" ] && [ ! -L "$GOLDEN" ] || fail "golden input must be a regular file"

# pipefail preserves a failed libguestfs read even if it emitted matching bytes.
# One extra byte distinguishes exact EOF from any suffix without capturing an unbounded stream.
/usr/bin/virt-cat -a "$GOLDEN" /guest-setup-done.txt \
    | /usr/bin/python3 -I -S -c '
import sys
expected = (
    b"rustdesk-windows-golden-v4\r\n"
    b"builder-password-never-expires=true\r\n"
    b"builder-logon-task=interactive\r\n"
    b"setup-complete=true\r\n"
)
if sys.stdin.buffer.read(len(expected) + 1) != expected:
    raise SystemExit("golden completion receipt is absent or incompatible")
'

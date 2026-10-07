#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'base metadata test requires one private scratch directory'
readonly work=$1
readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
[ "$HOST_UID" -ne 0 ] && [ "$HOST_GID" -ne 0 ] || fail 'base metadata test refuses root'
[ -d "$work" ] && [ ! -L "$work" ] \
    && [ "$(/usr/bin/readlink -f -- "$work")" = "$work" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$work")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'base metadata test scratch authority differs'
readonly SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null
readonly source_file=$SCRIPT_DIR/verifier-vm-base-metadata.sh
readonly source_sha="$(/usr/bin/sha256sum "$source_file")"
source "$source_file"

readonly subject=$work/base
readonly output=$work/base-metadata.result
printf 'base-metadata-fixture\n' >"$subject"
readonly fixture_size="$(/usr/bin/stat -c '%s' -- "$subject")"
cases=0
accept() {
    local path=$1 length=$2 label=$3 status=0
    (verify_debian_vm_base_metadata "$path" "$length") >"$output" 2>&1 || status=$?
    [ "$status" -eq 0 ] && [ ! -s "$output" ] \
        || { /usr/bin/cat "$output" >&2; fail "base metadata acceptance failed: $label"; }
    cases=$((cases + 1))
}
refuse() {
    local path=$1 length=$2 label=$3 message=$4 status=0
    (verify_debian_vm_base_metadata "$path" "$length") >"$output" 2>&1 || status=$?
    [ "$status" -eq 1 ] \
        && [ "$(/usr/bin/grep -Fxc "$message: $path" "$output")" -eq 1 ] \
        && [ "$(/usr/bin/wc -l <"$output")" -eq 1 ] \
        || { /usr/bin/cat "$output" >&2; fail "base metadata refusal failed: $label"; }
    cases=$((cases + 1))
}
for mode in 0400 0444; do
    /usr/bin/chmod "$mode" "$subject"
    accept "$subject" "$fixture_size" "$mode"
done
for mode in 0000 0200 0404 0440 0500 0600 0644 0664 0777 1400 2400 4400; do
    /usr/bin/chmod "$mode" "$subject"
    refuse "$subject" "$fixture_size" "$mode" 'Debian verifier-VM base metadata differs'
done
/usr/bin/chmod 0400 "$subject"
refuse "$subject" "$((fixture_size + 1))" length 'Debian verifier-VM base metadata differs'
/usr/bin/ln "$subject" "$work/hardlink"
refuse "$subject" "$fixture_size" hardlink 'Debian verifier-VM base metadata differs'
/usr/bin/rm -- "$work/hardlink"
/usr/bin/ln -s base "$work/symlink"
refuse "$work/symlink" "$fixture_size" symlink 'Debian verifier-VM base is absent or symlinked'
refuse "$work/missing" "$fixture_size" missing 'Debian verifier-VM base is absent or symlinked'
/usr/bin/mkdir "$work/directory"
refuse "$work/directory" "$fixture_size" directory 'Debian verifier-VM base is absent or symlinked'
/usr/bin/mkfifo "$work/fifo"
refuse "$work/fifo" "$fixture_size" fifo 'Debian verifier-VM base is absent or symlinked'
[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$work/foreign-uid")" = "4001:$HOST_GID:400:1:$fixture_size" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$work/foreign-gid")" = "$HOST_UID:4001:400:1:$fixture_size" ] \
    || fail 'base metadata foreign fixtures differ'
refuse "$work/foreign-uid" "$fixture_size" foreign-uid 'Debian verifier-VM base metadata differs'
refuse "$work/foreign-gid" "$fixture_size" foreign-gid 'Debian verifier-VM base metadata differs'
[ "$cases" -eq 22 ] || fail 'base metadata case inventory differs'
[ "$(/usr/bin/sha256sum "$source_file")" = "$source_sha" ] || fail 'base metadata source changed'
/usr/bin/rm -- "$subject" "$output" \
    "$work/symlink" "$work/fifo" "$work/foreign-uid" "$work/foreign-gid"
/usr/bin/rmdir -- "$work/directory"
printf 'VERIFIER_VM_BASE_METADATA=pass cases=22 profiles=400,444 source=production metadata=actual cleanup=joined\n'

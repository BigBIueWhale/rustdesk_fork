#!/usr/bin/env bash

verify_debian_vm_base_metadata() {
    local path=$1 size=$2 uid gid metadata
    uid="$(/usr/bin/id -u)" || fail 'cannot derive Debian verifier-VM base owner'
    gid="$(/usr/bin/id -g)" || fail 'cannot derive Debian verifier-VM base group'
    [ "$uid" -ne 0 ] && [ "$gid" -ne 0 ] \
        || fail 'Debian verifier-VM base admission refuses root UID or GID'
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "Debian verifier-VM base is absent or symlinked: $path"
    metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$path")" \
        || fail "cannot inspect Debian verifier-VM base metadata: $path"
    case "$metadata" in
        "$uid:$gid:400:1:$size") ;;
        *) fail "Debian verifier-VM base metadata differs: $path" ;;
    esac
}

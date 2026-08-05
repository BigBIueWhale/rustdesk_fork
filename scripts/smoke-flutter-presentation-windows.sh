#!/usr/bin/env bash
# Exact-commit native Windows Flutter presentation evidence in an isolated VM.
set -euo pipefail
export PATH=/usr/bin:/bin
export LC_ALL=C
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly WINDOWS_HELPER_BUILD_UID="$(id -u)"
readonly WINDOWS_HELPER_BUILD_GID="$(id -g)"
[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ] \
    || die "Windows presentation smoke refuses host or container-root execution"
[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ] \
    || die "Windows presentation smoke refuses a root primary group"
# shellcheck source=scripts/windows-helper-runtime.sh
source "$SCRIPT_DIR/windows-helper-runtime.sh"

readonly GOLDEN="${WINDOWS_GOLDEN_IMAGE:-$REPO_ROOT/.harness-state/win11-golden.qcow2}"
readonly STATE_DIR="${HARNESS_STATE_DIR:-$REPO_ROOT/.harness-state}"
readonly DOMAIN_PREFIX="${WINDOWS_PRESENTATION_DOMAIN_PREFIX:-rustdesk-presentation}"
readonly VM_TIMEOUT_SECONDS=3600
readonly CREATE_TIMEOUT_SECONDS=300
readonly CONTROL_TIMEOUT_SECONDS=30
readonly PROCESS_ADMISSION_SECONDS=10
readonly PROCESS_STOP_SECONDS=10
readonly DESKTOP_MULTI_WINDOW_COMMIT=b47e8385e5a75d38319ad706a64b0ead3108b093
readonly DESKTOP_MULTI_WINDOW_TREE=ee184480a0e519b9f51f7496d3d90674782481d6

RUN_ROOT=""
RUN_ROOT_ID=""
SOURCE_ROOT=""
SOURCE_COMMIT=""
SOURCE_TREE=""
SOURCE_ISO=""
OUTPUT_IMAGE=""
OVERLAY=""
EVIDENCE_DIR=""
CURRENT_DOMAIN=""
CURRENT_DOMAIN_UUID=""
CURRENT_DOMAIN_CREATION_STARTED=0
CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0
CURRENT_VIRT_PID=""
CURRENT_VIRT_START=""
CURRENT_VM_DEADLINE=""
CLEANUP_ACTIVE=0
CLEANUP_FAILED=0
RUN_COMPLETE=0
GOLDEN_BEFORE=""
LISTENERS_BEFORE=""
LISTENERS_DURING=""
NEW_LISTENERS=""

monotonic_seconds() {
    local uptime
    IFS=' ' read -r uptime _ </proc/uptime
    printf '%s\n' "${uptime%%.*}"
}

process_identity() {
    local pid="$1" value
    [ -r "/proc/$pid/stat" ] || return 1
    value="$(<"/proc/$pid/stat")" || return 1
    value="${value##*) }"
    set -- $value
    [ "$#" -ge 20 ] || return 1
    printf '%s %s %s %s\n' "$1" "${20}" "$3" "$4"
}

process_start_time() {
    local identity
    identity="$(process_identity "$1")" || return 1
    set -- $identity
    printf '%s\n' "$2"
}

owned_process_matches() {
    local identity state start group session
    [ -n "$CURRENT_VIRT_PID" ] && [ -n "$CURRENT_VIRT_START" ] || return 1
    identity="$(process_identity "$CURRENT_VIRT_PID" 2>/dev/null)" || return 1
    read -r state start group session <<<"$identity"
    [ "$start" = "$CURRENT_VIRT_START" ] \
        && [ "$group" = "$CURRENT_VIRT_PID" ] \
        && [ "$session" = "$CURRENT_VIRT_PID" ]
}

owned_process_group_is_live() {
    local path value state group session
    [ -n "$CURRENT_VIRT_PID" ] || return 1
    for path in /proc/[0-9]*/stat; do
        [ -r "$path" ] || continue
        value="$(<"$path")" || continue
        value="${value##*) }"
        set -- $value
        [ "$#" -ge 4 ] || continue
        state="$1"
        group="$3"
        session="$4"
        if [ "$group" = "$CURRENT_VIRT_PID" ] \
            && [ "$session" = "$CURRENT_VIRT_PID" ] \
            && [ "$state" != Z ] && [ "$state" != X ]; then
            return 0
        fi
    done
    return 1
}

wait_for_owned_process_group() {
    local deadline identity state start group session
    deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))
    while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        identity="$(process_identity "$CURRENT_VIRT_PID" 2>/dev/null)" || return 1
        read -r state start group session <<<"$identity"
        [ "$start" = "$CURRENT_VIRT_START" ] || return 1
        [ "$state" != Z ] && [ "$state" != X ] || return 1
        if [ "$group" = "$CURRENT_VIRT_PID" ] \
            && [ "$session" = "$CURRENT_VIRT_PID" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

stop_owned_process() {
    [ -n "$CURRENT_VIRT_PID" ] || return 0
    [ -n "$CURRENT_VIRT_START" ] || return 1
    if ! owned_process_matches; then
        [ ! -e "/proc/$CURRENT_VIRT_PID" ] || return 1
        owned_process_group_is_live && return 1
        wait "$CURRENT_VIRT_PID" 2>/dev/null || :
        CURRENT_VIRT_PID=""
        CURRENT_VIRT_START=""
        return 0
    fi
    if owned_process_group_is_live; then
        kill -TERM -- "-$CURRENT_VIRT_PID" || return 1
        local deadline
        deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
        while owned_process_group_is_live \
            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            sleep 0.1
        done
        if owned_process_group_is_live; then
            kill -KILL -- "-$CURRENT_VIRT_PID" || return 1
            deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))
            while owned_process_group_is_live \
                && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
                sleep 0.1
            done
        fi
    fi
    owned_process_group_is_live && return 1
    wait "$CURRENT_VIRT_PID" 2>/dev/null || :
    CURRENT_VIRT_PID=""
    CURRENT_VIRT_START=""
}

virsh_bounded() {
    setsid --wait \
        timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \
        virsh --connect qemu:///session "$@" </dev/null
}

domain_name_is_listed() {
    local names
    names="$(virsh_bounded list --all --name)" || return 2
    printf '%s\n' "$names" \
        | awk -v wanted="$CURRENT_DOMAIN" '$0 == wanted { found=1 } END { exit !found }'
}

domain_uuid_is_listed() {
    local uuids
    uuids="$(virsh_bounded list --all --uuid)" || return 2
    printf '%s\n' "$uuids" \
        | awk -v wanted="$CURRENT_DOMAIN_UUID" '$0 == wanted { found=1 } END { exit !found }'
}

require_domain_identity_absent() {
    local status
    if domain_name_is_listed; then
        die "generated presentation domain name already exists"
    else
        status=$?
        [ "$status" = 1 ] || die "cannot prove presentation domain-name absence"
    fi
    if domain_uuid_is_listed; then
        die "generated presentation domain UUID already exists"
    else
        status=$?
        [ "$status" = 1 ] || die "cannot prove presentation domain-UUID absence"
    fi
}

prove_owned_domain() {
    local actual_name
    [ -n "$CURRENT_DOMAIN" ] && [ -n "$CURRENT_DOMAIN_UUID" ] || return 1
    actual_name="$(virsh_bounded domname "$CURRENT_DOMAIN_UUID" 2>/dev/null)" \
        || return 1
    [ "$actual_name" = "$CURRENT_DOMAIN" ]
}

clear_domain_authority() {
    CURRENT_DOMAIN=""
    CURRENT_DOMAIN_UUID=""
    CURRENT_DOMAIN_CREATION_STARTED=0
    CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0
    CURRENT_VM_DEADLINE=""
}

stop_and_undefine_owned_domain() {
    [ -n "$CURRENT_DOMAIN_UUID" ] || return 0
    if [ "$CURRENT_DOMAIN_CREATION_STARTED" = 0 ]; then
        clear_domain_authority
        return 0
    fi
    if [ "$CURRENT_DOMAIN_OWNERSHIP_COMMITTED" = 0 ]; then
        if domain_uuid_is_listed; then
            warn "ambiguous uncommitted presentation UUID exists; preserving it"
            return 1
        else
            local listed_status=$?
            [ "$listed_status" = 1 ] || return 1
            clear_domain_authority
            return 0
        fi
    fi
    if ! prove_owned_domain; then
        if domain_uuid_is_listed; then
            warn "presentation UUID exists under an unexpected name; preserving it"
            return 1
        else
            local listed_status=$?
            [ "$listed_status" = 1 ] || return 1
            clear_domain_authority
            return 0
        fi
    fi
    local state deadline
    state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" || return 1
    if [ "$state" != "shut off" ]; then
        virsh_bounded destroy "$CURRENT_DOMAIN_UUID" >/dev/null || return 1
        deadline=$(( $(monotonic_seconds) + 60 ))
        while [ "$(monotonic_seconds)" -lt "$deadline" ]; do
            prove_owned_domain || return 1
            state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" || return 1
            [ "$state" = "shut off" ] && break
            sleep 1
        done
        [ "$state" = "shut off" ] || return 1
    fi
    virsh_bounded undefine "$CURRENT_DOMAIN_UUID" --nvram >/dev/null || return 1
    if domain_uuid_is_listed; then
        return 1
    else
        local listed_status=$?
        [ "$listed_status" = 1 ] || return 1
    fi
    clear_domain_authority
}

remove_run_root() {
    [ -n "$RUN_ROOT" ] && [ -n "$RUN_ROOT_ID" ] || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$RUN_ROOT" --expected-identity "$RUN_ROOT_ID" \
        || return 1
    [ ! -e "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ] || return 1
    RUN_ROOT=""
    RUN_ROOT_ID=""
}

cleanup() {
    local status=$?
    [ "$CLEANUP_ACTIVE" = 0 ] || exit "$status"
    CLEANUP_ACTIVE=1
    trap - EXIT HUP INT TERM
    if ! stop_owned_process; then
        CLEANUP_FAILED=1
        warn "preserving presentation domain after inconclusive virt-install cleanup"
    elif ! stop_and_undefine_owned_domain; then
        CLEANUP_FAILED=1
        warn "preserving presentation run state after inconclusive domain cleanup"
    fi
    if ! windows_helper_authority_close; then
        CLEANUP_FAILED=1
    fi
    if [ "$RUN_COMPLETE" = 1 ] && [ "$CLEANUP_FAILED" = 0 ] && [ -n "$RUN_ROOT" ]; then
        remove_run_root || CLEANUP_FAILED=1
    elif [ -n "$RUN_ROOT" ]; then
        warn "retaining failed Windows presentation run at $RUN_ROOT"
    fi
    if [ "$CLEANUP_FAILED" != 0 ] && [ "$status" = 0 ]; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

capture_listeners() {
    ss -H -lnt | LC_ALL=C sort -u
}

validate_new_listeners() {
    python3 - "$LISTENERS_BEFORE" "$LISTENERS_DURING" "$NEW_LISTENERS" <<'PY'
import ipaddress
import pathlib
import sys

before_path, during_path, output_path = map(pathlib.Path, sys.argv[1:])

def endpoints(path):
    result = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 4:
            raise SystemExit(f"malformed ss line: {line!r}")
        result.add(fields[3])
    return result

new = sorted(endpoints(during_path) - endpoints(before_path))
for endpoint in new:
    if endpoint.startswith("["):
        address = endpoint[1:endpoint.index("]")]
    else:
        address = endpoint.rsplit(":", 1)[0]
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError as error:
        raise SystemExit(f"new listener address is not numeric: {endpoint!r}") from error
    if not parsed.is_loopback:
        raise SystemExit(f"presentation VM created a non-loopback listener: {endpoint}")
output_path.write_text("".join(f"{item}\n" for item in new), encoding="ascii")
PY
}

golden_has_contract() {
    windows_helper_guestfish_run \
        --mount "type=bind,source=$GOLDEN,target=/authority/golden.qcow2,readonly" \
        -- /bin/bash --noprofile --norc \
            /authority/windows-golden-inspect.sh marker
}

preflight() {
    require_cmd git tar python3 qemu-img virt-install virsh ss timeout setsid awk sha256sum stat
    assert_no_build_host_network_residual
    assert_clean_worktree
    [[ "$DOMAIN_PREFIX" =~ ^[A-Za-z0-9._-]+$ ]] \
        && [ "${#DOMAIN_PREFIX}" -le 40 ] \
        || die "Windows presentation domain prefix is invalid"
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
        || die "Windows presentation state directory is absent or symlinked"
    [ "$(stat -c '%u:%a' "$STATE_DIR")" = "$WINDOWS_HELPER_BUILD_UID:700" ] \
        || die "Windows presentation state directory must be current-UID mode 0700"
    [ -f "$GOLDEN" ] && [ ! -L "$GOLDEN" ] \
        || die "Windows presentation golden is absent or symlinked"
    verify_sha256 "$GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"
    GOLDEN_BEFORE="$(sha256sum "$GOLDEN" | awk '{print $1}')"
    [ -d "$ONLINE_DIR" ] && [ ! -L "$ONLINE_DIR" ] \
        || die "canonical offline input directory is absent"
    [ -f "$ONLINE_DIR/build-images/win-helper.docker.tar.gz" ] \
        && [ ! -L "$ONLINE_DIR/build-images/win-helper.docker.tar.gz" ] \
        || die "pinned Windows helper archive is absent"
    SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"
    SOURCE_TREE="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{tree}')"
    [[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] \
        || die "exact presentation source identity is malformed"
    RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-presentation-run.XXXXXXXX")"
    chmod 0700 "$RUN_ROOT"
    RUN_ROOT_ID="$(stat -c '%d:%i' "$RUN_ROOT")"
    SOURCE_ROOT="$RUN_ROOT/source"
    SOURCE_ISO="$RUN_ROOT/source.iso"
    OUTPUT_IMAGE="$RUN_ROOT/output.img"
    OVERLAY="$RUN_ROOT/overlay.qcow2"
    LISTENERS_BEFORE="$RUN_ROOT/listeners-before.txt"
    LISTENERS_DURING="$RUN_ROOT/listeners-during.txt"
    NEW_LISTENERS="$RUN_ROOT/new-listeners.txt"
    capture_listeners >"$LISTENERS_BEFORE"
    windows_helper_authority_open
    windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"
    golden_has_contract \
        || die "Windows presentation golden lacks the exact non-expiring-builder contract"
}

materialize_source() {
    local dep_repo actual_tree media_output
    mkdir -m 0700 "$SOURCE_ROOT"
    git -C "$REPO_ROOT" archive --format=tar "$SOURCE_COMMIT" -- \
        scripts/run-flutter-presentation-windows.ps1 \
        scripts/flutter-presentation-probe-windows-controller.ps1 \
        scripts/flutter-presentation-probe-windows-focus-sink.ps1 \
        scripts/flutter-presentation-probe-windows.dart \
        scripts/flutter-presentation-probe-windows-pubspec.yaml \
        scripts/flutter-presentation-probe-desktop-multi-window-pubspec.yaml \
        scripts/windows-presentation-source-manifest.py \
        flutter/lib/models/presentation_recovery.dart \
        flutter/third_party/texture_rgba_renderer \
        | tar -x -C "$SOURCE_ROOT"
    cp -- "$SOURCE_ROOT/scripts/run-flutter-presentation-windows.ps1" \
        "$SOURCE_ROOT/run-build.ps1"
    cmp -s -- "$SOURCE_ROOT/run-build.ps1" \
        "$SOURCE_ROOT/scripts/run-flutter-presentation-windows.ps1" \
        || die "generated presentation root runner differs from its source"
    mapfile -d '' dep_repos < <(
        find "$ONLINE_DIR/pub-cache/git/cache" -mindepth 1 -maxdepth 1 -type d \
            -name 'rustdesk_desktop_multi_window-*' -print0
    )
    [ "${#dep_repos[@]}" = 1 ] \
        || die "pinned desktop_multi_window bare repository count is not exactly one"
    dep_repo="${dep_repos[0]}"
    [ "$(git -c safe.directory="$dep_repo" -C "$dep_repo" \
        rev-parse "$DESKTOP_MULTI_WINDOW_COMMIT")" = \
        "$DESKTOP_MULTI_WINDOW_COMMIT" ] \
        || die "desktop_multi_window commit is absent from its offline repository"
    actual_tree="$(git -c safe.directory="$dep_repo" -C "$dep_repo" \
        rev-parse "$DESKTOP_MULTI_WINDOW_COMMIT^{tree}")"
    [ "$actual_tree" = "$DESKTOP_MULTI_WINDOW_TREE" ] \
        || die "desktop_multi_window commit has an unexpected tree"
    mkdir -p "$SOURCE_ROOT/third_party/desktop_multi_window"
    git -c safe.directory="$dep_repo" -C "$dep_repo" \
        archive --format=tar "$DESKTOP_MULTI_WINDOW_COMMIT" \
        | tar -x -C "$SOURCE_ROOT/third_party/desktop_multi_window"
    cp -- "$SOURCE_ROOT/scripts/flutter-presentation-probe-desktop-multi-window-pubspec.yaml" \
        "$SOURCE_ROOT/third_party/desktop_multi_window/pubspec.yaml"
    printf '{"commit":"%s","tree":"%s"}\n' \
        "$DESKTOP_MULTI_WINDOW_COMMIT" "$DESKTOP_MULTI_WINDOW_TREE" \
        >"$SOURCE_ROOT/third_party/desktop_multi_window/.rustdesk-source-identity.json"

    windows_helper_small_run \
        --mount "type=bind,source=$SOURCE_ROOT,target=/source" \
        -- /usr/bin/python3 -I -B \
            /source/scripts/windows-presentation-source-manifest.py \
            --root /source --manifest /source/.presentation-source-manifest.json \
            --write --source-commit "$SOURCE_COMMIT" --source-tree "$SOURCE_TREE"
    windows_helper_small_run \
        --mount "type=bind,source=$SOURCE_ROOT,target=/source,readonly" \
        -- /usr/bin/python3 -I -B \
            /source/scripts/windows-presentation-source-manifest.py \
            --root /source --manifest /source/.presentation-source-manifest.json --verify
    media_output="$RUN_ROOT/media-output"
    mkdir -m 0700 "$media_output"
    windows_helper_media_run \
        --mount "type=bind,source=$SOURCE_ROOT,target=/source,readonly" \
        --mount "type=bind,source=$media_output,target=/out" \
        -- /usr/bin/genisoimage -udf -D -r -f -quiet -V PRESENTATION \
            -o /out/source.iso /source
    [ -s "$media_output/source.iso" ] \
        || die "confined Windows helper produced no presentation source ISO"
    mv -- "$media_output/source.iso" "$SOURCE_ISO"
    rmdir -- "$media_output"
}

prepare_disks() {
    qemu-img create -f raw "$OUTPUT_IMAGE" 1G >/dev/null
    windows_helper_guestfish_run \
        --mount "type=bind,source=$OUTPUT_IMAGE,target=/authority/output.img" \
        -- /usr/bin/guestfish -a /authority/output.img run : \
            part-disk /dev/sda mbr : \
            part-set-mbr-id /dev/sda 1 0x0c : \
            mkfs vfat /dev/sda1 label:OUTPUT
    (
        cd "$RUN_ROOT"
        qemu-img create -f qcow2 -F qcow2 -b ../win11-golden.qcow2 \
            overlay.qcow2 >/dev/null
    )
    windows_helper_guestfish_run \
        --mount "type=bind,source=$OVERLAY,target=/authority/pass/overlay.qcow2" \
        --mount "type=bind,source=$GOLDEN,target=/authority/win11-golden.qcow2,readonly" \
        -- /usr/bin/guestfish --rw -a /authority/pass/overlay.qcow2 run : \
            mount /dev/sda1 / : \
            mkdir-p /EFI/BOOT : \
            cp /EFI/Microsoft/Boot/bootmgfw.efi /EFI/BOOT/BOOTX64.EFI
}

verify_domain_xml() {
    local xml="$RUN_ROOT/domain.xml"
    virsh_bounded dumpxml "$CURRENT_DOMAIN_UUID" >"$xml" \
        || die "cannot inspect presentation domain XML"
    python3 - "$xml" "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID" \
        "$OVERLAY" "$SOURCE_ISO" "$OUTPUT_IMAGE" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

xml, name, uuid, *expected_disks = sys.argv[1:]
root = ET.parse(xml).getroot()
if root.findtext("name") != name or root.findtext("uuid") != uuid:
    raise SystemExit("presentation domain identity mismatch")
if root.findall("./devices/interface"):
    raise SystemExit("presentation domain unexpectedly has a network interface")
if root.findall("./devices/hostdev") or root.findall("./devices/filesystem"):
    raise SystemExit("presentation domain unexpectedly has host device/filesystem authority")
actual_disks = []
for disk in root.findall("./devices/disk"):
    source = disk.find("source")
    if source is not None and "file" in source.attrib:
        actual_disks.append(os.path.realpath(source.attrib["file"]))
if sorted(actual_disks) != sorted(os.path.realpath(path) for path in expected_disks):
    raise SystemExit(f"presentation domain disk set mismatch: {actual_disks!r}")
graphics = root.findall("./devices/graphics")
if len(graphics) != 1 or graphics[0].get("type") != "vnc" or graphics[0].get("listen") != "127.0.0.1":
    raise SystemExit("presentation VNC graphics is not exactly loopback-bound")
listens = graphics[0].findall("listen")
if len(listens) != 1 or listens[0].get("type") != "address" or listens[0].get("address") != "127.0.0.1":
    raise SystemExit("presentation VNC child listen is not exactly loopback-bound")
PY
}

launch_domain() {
    CURRENT_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"
    [[ "$CURRENT_DOMAIN_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
        || die "kernel presentation UUID is malformed"
    CURRENT_DOMAIN="$DOMAIN_PREFIX-${SOURCE_COMMIT:0:8}-${CURRENT_DOMAIN_UUID:0:8}"
    [ "${#CURRENT_DOMAIN}" -le 63 ] || die "presentation domain name is too long"
    require_domain_identity_absent
    CURRENT_DOMAIN_CREATION_STARTED=1
    setsid --wait virt-install --connect qemu:///session \
        --name "$CURRENT_DOMAIN" --uuid "$CURRENT_DOMAIN_UUID" \
        --osinfo win11 --memory 8192 --vcpus 4 --import \
        --disk "path=$OVERLAY,format=qcow2,bus=sata" \
        --disk "path=$SOURCE_ISO,device=cdrom" \
        --disk "path=$OUTPUT_IMAGE,format=raw,bus=sata" \
        --boot uefi --network none --graphics vnc,listen=127.0.0.1 \
        --noautoconsole &
    CURRENT_VIRT_PID=$!
    CURRENT_VIRT_START="$(process_start_time "$CURRENT_VIRT_PID")" \
        || die "cannot bind presentation virt-install process identity"
    wait_for_owned_process_group \
        || die "cannot prove presentation virt-install process-group admission"
    local deadline rc
    deadline=$(( $(monotonic_seconds) + CREATE_TIMEOUT_SECONDS ))
    while owned_process_group_is_live \
        && [ "$(monotonic_seconds)" -lt "$deadline" ]; do
        sleep 1
    done
    if owned_process_group_is_live; then
        stop_owned_process || die "presentation virt-install creation cleanup failed"
        die "presentation virt-install exceeded its creation deadline"
    fi
    if ! owned_process_matches && [ -e "/proc/$CURRENT_VIRT_PID" ]; then
        die "presentation virt-install identity changed before reap"
    fi
    if wait "$CURRENT_VIRT_PID"; then rc=0; else rc=$?; fi
    CURRENT_VIRT_PID=""
    CURRENT_VIRT_START=""
    [ "$rc" = 0 ] || die "presentation virt-install failed with exit $rc"
    domain_uuid_is_listed \
        || die "presentation virt-install did not create its exact UUID"
    prove_owned_domain || die "presentation domain identity cannot be proven"
    CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1
    verify_domain_xml
    capture_listeners >"$LISTENERS_DURING"
    validate_new_listeners
    CURRENT_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))
    [ "$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" = running ] \
        || die "presentation domain is not running after creation"
}

wait_for_domain() {
    local state
    while :; do
        prove_owned_domain || die "presentation domain disappeared before shutdown"
        state="$(virsh_bounded domstate "$CURRENT_DOMAIN_UUID")" \
            || die "cannot read presentation domain state"
        case "$state" in
            "shut off") break ;;
            crashed) die "presentation domain crashed" ;;
            running|blocked|paused|"in shutdown"|pmsuspended) ;;
            *) die "presentation domain entered unknown state: $state" ;;
        esac
        if [ "$(monotonic_seconds)" -ge "$CURRENT_VM_DEADLINE" ]; then
            stop_and_undefine_owned_domain \
                || die "timed-out presentation domain cleanup failed"
            die "native Windows presentation probe exceeded one hour"
        fi
        sleep 10
    done
    stop_and_undefine_owned_domain \
        || die "completed presentation domain cleanup failed"
}

extract_and_validate() {
    local extracted="$RUN_ROOT/extracted"
    mkdir -m 0700 "$extracted"
    windows_helper_guestfish_run \
        --mount "type=bind,source=$OUTPUT_IMAGE,target=/authority/output.img,readonly" \
        --mount "type=bind,source=$extracted,target=/out" \
        -- /usr/bin/guestfish --ro -a /authority/output.img run : \
            mount /dev/sda1 / : \
            glob copy-out '/*' /out
    for system_dir in "System Volume Information" '$RECYCLE.BIN'; do
        if [ -e "$extracted/$system_dir" ] || [ -L "$extracted/$system_dir" ]; then
            [ -d "$extracted/$system_dir" ] && [ ! -L "$extracted/$system_dir" ] \
                || die "unexpected presentation output system entry: $system_dir"
            rm -rf -- "$extracted/$system_dir"
        fi
    done
    python3 - "$extracted" "$SOURCE_COMMIT" "$SOURCE_TREE" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
commit, tree = sys.argv[2:]
required = {
    "windows-presentation-result.json",
    "windows-presentation-progress.txt",
    "windows-presentation-source-verify.stdout.txt",
    "windows-presentation-controller.stdout.txt",
    "windows-presentation-app.stdout.txt",
    "windows-presentation-pubspec.lock",
}
missing = sorted(name for name in required if not (root / name).is_file())
if missing:
    raise SystemExit(f"presentation evidence is missing: {missing!r}")
if (root / "windows-presentation-runner-failure.txt").exists():
    raise SystemExit("guest presentation runner recorded failure")
progress = (root / "windows-presentation-progress.txt").read_text(encoding="ascii").splitlines()
if progress != ["source-found", "source-verified", "probe-built", "probe-passed"]:
    raise SystemExit(f"unexpected presentation progress: {progress!r}")
result = json.loads((root / "windows-presentation-result.json").read_text(encoding="utf-8-sig"))
if sorted(result) != sorted([
    "format", "verdict", "source_commit", "source_tree",
    "real_windows_flutter_engine", "real_desktop_compositor_pixels",
    "real_guest_pointer_input", "no_guest_network_interface_expected",
    "recovery_limit_ms", "initial", "cycles",
]):
    raise SystemExit("presentation result envelope is not exact")
if result["format"] != "rustdesk-windows-presentation-result-v1" or result["verdict"] != "pass":
    raise SystemExit("presentation result is not a pass")
if result["source_commit"] != commit or result["source_tree"] != tree:
    raise SystemExit("presentation source identity differs")
for field in (
    "real_windows_flutter_engine", "real_desktop_compositor_pixels",
    "real_guest_pointer_input", "no_guest_network_interface_expected",
):
    if result[field] is not True:
        raise SystemExit(f"presentation fact is not true: {field}")
if result["recovery_limit_ms"] != 2500:
    raise SystemExit("presentation recovery limit differs")
cycles = result["cycles"]
if not isinstance(cycles, list) or len(cycles) != 2:
    raise SystemExit("presentation cycle count differs")
if [cycle.get("name") for cycle in cycles] != [
    "minimize-restore", "focus-loss-real-pointer-return"
]:
    raise SystemExit("presentation cycle names differ")
for cycle in cycles:
    if cycle.get("queued_frames") != 128:
        raise SystemExit("presentation queued-frame count differs")
    elapsed = cycle.get("allowed_to_visible_ms")
    if isinstance(elapsed, bool) or not isinstance(elapsed, int) or not 0 <= elapsed <= 2500:
        raise SystemExit("presentation recovery latency exceeds its bound")
    after = cycle.get("after_rearm")
    if not isinstance(after, dict) or after.get("visible") is not True:
        raise SystemExit("presentation compositor did not show the post-rearm frame")
if cycles[1].get("pointer_down_delivered") is not True:
    raise SystemExit("presentation guest pointer-down was not delivered")
lock_lines = (root / "windows-presentation-pubspec.lock").read_text(
    encoding="utf-8-sig"
).splitlines()
try:
    package_start = lock_lines.index("packages:") + 1
    package_end = lock_lines.index("sdks:")
except ValueError as error:
    raise SystemExit("presentation pubspec lock envelope is malformed") from error
blocks = {}
current = None
for line in lock_lines[package_start:package_end]:
    if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
        current = line.strip()[:-1]
        if current in blocks:
            raise SystemExit("presentation pubspec lock repeats a package")
        blocks[current] = []
    elif current is not None:
        blocks[current].append(line.strip())
expected_packages = {
    "characters": ("hosted", 'version: "1.3.0"'),
    "collection": ("hosted", 'version: "1.18.0"'),
    "desktop_multi_window": ("path", 'version: "0.1.0"'),
    "flutter": ("sdk", 'version: "0.0.0"'),
    "material_color_utilities": ("hosted", 'version: "0.11.1"'),
    "meta": ("hosted", 'version: "1.15.0"'),
    "sky_engine": ("sdk", 'version: "0.0.99"'),
    "texture_rgba_renderer": ("path", 'version: "0.0.16+rustdesk.1"'),
    "vector_math": ("hosted", 'version: "2.1.4"'),
}
if set(blocks) != set(expected_packages):
    raise SystemExit(f"presentation pubspec package set differs: {sorted(blocks)!r}")
for package, (source, version) in expected_packages.items():
    lines = blocks[package]
    if f"source: {source}" not in lines or version not in lines:
        raise SystemExit(f"presentation pubspec identity differs: {package}")
state = root / "windows-presentation-state"
for name, expected in {
    "app-finished": "ok\n",
    "rearm-requested-1": "requested\n",
    "renotified-1": "accepted\n",
    "rearm-requested-2": "requested\n",
    "renotified-2": "accepted\n",
    "pointer-down-2": "delivered\n",
}.items():
    if (state / name).read_text(encoding="utf-8") != expected:
        raise SystemExit(f"presentation state marker differs: {name}")
if "WINDOWS_PRESENTATION_CONTROLLER_OK" not in (
    root / "windows-presentation-controller.stdout.txt"
).read_text(encoding="utf-8-sig"):
    raise SystemExit("presentation controller success marker is absent")
if "WINDOWS_PRESENTATION_PROBE_OK" not in (
    root / "windows-presentation-app.stdout.txt"
).read_text(encoding="utf-8-sig"):
    raise SystemExit("presentation app success marker is absent")
PY
    EVIDENCE_DIR="$STATE_DIR/windows-presentation-evidence-${SOURCE_COMMIT:0:12}"
    [ ! -e "$EVIDENCE_DIR" ] && [ ! -L "$EVIDENCE_DIR" ] \
        || die "exact Windows presentation evidence directory already exists"
    mkdir -m 0700 "$EVIDENCE_DIR"
    cp -a -- "$extracted/." "$EVIDENCE_DIR/"
    cp -- "$RUN_ROOT/domain.xml" "$EVIDENCE_DIR/domain.xml"
    cp -- "$NEW_LISTENERS" "$EVIDENCE_DIR/new-host-listeners.txt"
    python3 - "$EVIDENCE_DIR" "$SOURCE_COMMIT" "$SOURCE_TREE" \
        "$SHA256_WIN11_GOLDEN_QCOW2" "$SOURCE_ISO" "$RUN_ROOT/domain.xml" <<'PY'
import hashlib
import json
import pathlib
import sys

evidence = pathlib.Path(sys.argv[1])
commit, tree, golden, source_iso, domain_xml = sys.argv[2:]

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

record = {
    "format": "rustdesk-windows-presentation-host-validation-v1",
    "source_commit": commit,
    "source_tree": tree,
    "golden_sha256": golden,
    "source_iso_sha256": digest(source_iso),
    "domain_xml_sha256": digest(domain_xml),
    "guest_result_sha256": digest(evidence / "windows-presentation-result.json"),
    "domain_network_interfaces": 0,
    "vnc_listen": "127.0.0.1",
}
(evidence / "host-validation.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

verify_unchanged_inputs() {
    [ "$(sha256sum "$GOLDEN" | awk '{print $1}')" = "$GOLDEN_BEFORE" ] \
        || die "Windows golden changed during presentation evidence"
    [ "$(git -C "$REPO_ROOT" rev-parse HEAD)" = "$SOURCE_COMMIT" ] \
        && [ "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE" ] \
        || die "exact source identity changed during presentation evidence"
    assert_clean_worktree
}

main() {
    preflight
    materialize_source
    prepare_disks
    launch_domain
    wait_for_domain
    extract_and_validate
    verify_unchanged_inputs
    RUN_COMPLETE=1
    log "native Windows presentation evidence passed: $EVIDENCE_DIR"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail
umask 077

export PATH=/usr/bin:/bin
readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
[ "$HOST_UID" -ne 0 ] \
    || { echo "Debian systemd VM smoke refuses host or container-root execution" >&2; exit 1; }
[ "$HOST_GID" -ne 0 ] \
    || { echo "Debian systemd VM smoke refuses a root primary group" >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
cd "$SCRIPT_DIR/.."

# Host-side orchestrator for one disposable, networkless Debian KVM guest. It
# never invokes sudo, never enters the host PID/cgroup namespaces, and never
# talks to the host service manager. The production source and the dependency
# bundle are mounted read-only; all package/systemd writes land only in a CoW
# overlay deleted on exit.
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins

readonly IMAGE=${SYSTEMD_SMOKE_IMAGE:-$PWD/.harness-state/debian-systemd-smoke/debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2}
readonly SOURCE_BINARY=$PWD/target/debug/rustdesk
readonly GUEST_SCRIPT=$PWD/scripts/smoke-debian-systemd-lifecycle-guest.sh
readonly STATE_DIR=${SYSTEMD_SMOKE_STATE_DIR:-$PWD/.harness-state/debian-systemd-smoke}

MODE=source
RELEASE_DEB=
EXPECTED_DEB_SHA256=
EXPECTED_COMMIT=
ARTIFACT_ID=
case "$#" in
    0) ;;
    6)
        [ "$1" = --release-deb ] && [ "$3" = --sha256 ] && [ "$5" = --commit ] \
            || { printf 'usage: %s [--release-deb ABSOLUTE_DEB --sha256 SHA256 --commit COMMIT]\n' "${0##*/}" >&2; exit 2; }
        MODE=release-deb
        RELEASE_DEB=$2
        EXPECTED_DEB_SHA256=$4
        EXPECTED_COMMIT=$6
        ;;
    *)
        printf 'usage: %s [--release-deb ABSOLUTE_DEB --sha256 SHA256 --commit COMMIT]\n' "${0##*/}" >&2
        exit 2
        ;;
esac

fail() {
    printf 'Debian systemd VM smoke: %s\n' "$*" >&2
    exit 1
}

WORK=

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
        && ! remove_local_docker_authority; then
        warn "preserving changed private Debian systemd-lifecycle Docker authority: $WORK"
        status=1
    elif [ -n "$WORK" ] && [ -d "$WORK" ]; then
        if ! chmod -R u+rwX "$WORK" 2>/dev/null \
            || ! rm -rf -- "$WORK"; then
            status=1
        fi
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
    || fail 'systemd VM smoke requires the pinned Linux x86_64 build host'
for command in cmp git install mktemp python3 qemu-img qemu-system-x86_64 readlink sha256sum sha512sum stat timeout xorriso; do
    command -v "$command" >/dev/null || fail "required host command is absent: $command"
done
[ "$MODE" != release-deb ] || for command in dpkg-deb; do
    command -v "$command" >/dev/null || fail "required release-artifact command is absent: $command"
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || fail '/dev/kvm is not available to the unprivileged build user'
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
    || fail "private systemd smoke state is absent; run scripts/online-fetch.sh --debian-systemd-smoke-image"
[ "$(readlink -f -- "$STATE_DIR" 2>/dev/null)" = "$STATE_DIR" ] \
    || fail 'systemd smoke state directory must be an absolute canonical path'
[ "$(stat -c '%u:%a' "$STATE_DIR")" = "$HOST_UID:700" ] \
    || fail 'systemd smoke state directory is not current-user-owned mode 0700'
WORK=$(mktemp -d "$STATE_DIR/run.XXXXXXXXXX")
[ "$(stat -c '%u:%g:%a' "$WORK")" = "$HOST_UID:$HOST_GID:700" ] \
    || fail 'VM scratch directory is not current-user/current-group mode 0700'
readonly WORK
initialize_local_docker_authority "$WORK/docker-config" "debian-systemd-lifecycle"
[ -f "$IMAGE" ] && [ ! -L "$IMAGE" ] \
    || fail "pinned Debian cloud image is absent; run scripts/online-fetch.sh --debian-systemd-smoke-image"
IMAGE_METADATA="$(stat -c '%u:%g:%a:%h' "$IMAGE")"
case "$IMAGE_METADATA" in
    "$HOST_UID:$HOST_GID:400:1" | "$HOST_UID:$HOST_GID:444:1") ;;
    *) fail 'Debian cloud image is outside its current-user read-only metadata profiles' ;;
esac
verify_sha512 "$IMAGE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"
qemu-img check -q "$IMAGE" || fail 'Debian cloud image failed qemu-img integrity check'
python3 - "$IMAGE" <<'PY'
import json
import subprocess
import sys

image = sys.argv[1]
info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", image]))
if info.get("format") != "qcow2" or info.get("backing-filename") is not None:
    raise SystemExit("Debian systemd VM base is not a standalone qcow2")
if info.get("virtual-size", 0) < 3 * 1024 * 1024 * 1024:
    raise SystemExit("Debian systemd VM base has an unexpected virtual size")
PY
[ "$MODE" != source ] || {
    [ -f "$SOURCE_BINARY" ] && [ ! -L "$SOURCE_BINARY" ] && [ -x "$SOURCE_BINARY" ] \
        || fail 'actual target/debug/rustdesk is absent; run the smoke build stage first'
}
[ -f "$GUEST_SCRIPT" ] && [ ! -L "$GUEST_SCRIPT" ] && [ -x "$GUEST_SCRIPT" ] \
    || fail 'systemd guest lifecycle script is absent or non-executable'
for variable in \
    DEV_CHECK_IMAGE_ID DEV_CHECK_BASE_IMAGE_ID \
    DEV_CHECK_IMAGE_CONFIG_ID DEV_CHECK_IMAGE_MANIFEST_ID \
    DEV_CHECK_SOURCE_COMMIT DEV_CHECK_SOURCE_REPOSITORY \
    SHA256_DEV_CHECK_DOCKERFILE SHA256_DEV_CHECK_DPKG_MANIFEST \
    SHA256_DEV_CHECK_CARGO SHA256_DEV_CHECK_RUSTC; do
    [ -n "${!variable:-}" ] || fail "pins.env is missing $variable"
done
[[ "$DEV_CHECK_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'immutable devcheck image ID is malformed'
[[ "$DEV_CHECK_BASE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'immutable devcheck base image ID is malformed'
[[ "$DEV_CHECK_IMAGE_CONFIG_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'immutable devcheck config ID is malformed'
[[ "$DEV_CHECK_IMAGE_MANIFEST_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail 'immutable devcheck manifest ID is malformed'
[[ "$DEV_CHECK_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || fail 'immutable devcheck source commit is malformed'
[ "$(sha256sum "$SCRIPT_DIR/Dockerfile.devcheck" | awk '{print $1}')" = \
    "$SHA256_DEV_CHECK_DOCKERFILE" ] \
    || fail 'current devcheck Dockerfile differs from its reviewed pin'
GIT_CONFIG_NOSYSTEM=1 \
GIT_CONFIG_GLOBAL=/dev/null \
GIT_CONFIG_SYSTEM=/dev/null \
    git --no-replace-objects merge-base --is-ancestor "$DEV_CHECK_SOURCE_COMMIT" HEAD \
    || fail 'devcheck provenance source commit is not an ancestor of lifecycle source'
historical_devcheck_sha="$(
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
        git --no-replace-objects cat-file blob \
            "$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck" \
        | sha256sum \
        | awk '{print $1}'
)" || fail 'cannot read the devcheck Dockerfile from its provenance source commit'
[ "$historical_devcheck_sha" = "$SHA256_DEV_CHECK_DOCKERFILE" ] \
    || fail 'devcheck provenance source commit has different Dockerfile bytes'

if [ "$MODE" = release-deb ]; then
    case "$RELEASE_DEB" in
        /*) ;;
        *) fail 'release .deb path must be absolute' ;;
    esac
    [ -f "$RELEASE_DEB" ] && [ ! -L "$RELEASE_DEB" ] && [ -s "$RELEASE_DEB" ] \
        || fail 'release .deb must be a non-symlink regular non-empty file'
    [ "$(readlink -f -- "$RELEASE_DEB" 2>/dev/null)" = "$RELEASE_DEB" ] \
        || fail 'release .deb path must be canonical and contain no symlinked component'
    [[ "$EXPECTED_DEB_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'release .deb SHA-256 must be one lowercase 64-hex digest'
    [[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'release source commit must be one lowercase 40-hex identity'
    [ "$(stat -c '%u:%g:%a:%h' -- "$RELEASE_DEB")" = "$HOST_UID:$HOST_GID:400:1" ] \
        || fail 'release .deb must be current-user/current-group mode 0400 with one link'
    [ "$(sha256sum "$RELEASE_DEB" | awk '{print $1}')" = "$EXPECTED_DEB_SHA256" ] \
        || fail 'release .deb SHA-256 differs from the release transaction'
    [ "$(git --no-replace-objects -c core.hooksPath=/dev/null rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" = "$EXPECTED_COMMIT" ] \
        || fail 'release-artifact lifecycle source is not at the expected commit'
    if git --no-replace-objects -c core.hooksPath=/dev/null symbolic-ref --quiet HEAD >/dev/null 2>&1; then
        fail 'release-artifact lifecycle source must be a detached release snapshot'
    fi
    [ -z "$(git --no-replace-objects -c core.hooksPath=/dev/null status --porcelain=v1 --untracked-files=all 2>/dev/null)" ] \
        || fail 'release-artifact lifecycle source snapshot is dirty'
    [ -z "$(git --no-replace-objects -c core.hooksPath=/dev/null clean -nffdx 2>/dev/null)" ] \
        || fail 'release-artifact lifecycle source snapshot retains generated state'
    [ "$(dpkg-deb -f "$RELEASE_DEB" Package 2>/dev/null)" = rustdesk ] \
        || fail 'release .deb package identity is not rustdesk'
    [ "$(dpkg-deb -f "$RELEASE_DEB" Architecture 2>/dev/null)" = amd64 ] \
        || fail 'release .deb architecture is not amd64'
    python3 scripts/verify-debian-package-authority.py --repo "$PWD" --deb "$RELEASE_DEB" \
        || fail 'release .deb failed the independent package-authority verifier'
    ARTIFACT_ID=$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$RELEASE_DEB") \
        || fail 'cannot record release .deb identity'
fi

readonly LIBS=$WORK/runtime-libs
readonly EXTRACTED=$WORK/extracted-deb
readonly OVERLAY=$WORK/guest.qcow2
readonly SEED=$WORK/seed.iso
readonly PAYLOAD=$WORK/payload.iso
readonly SERIAL=$WORK/serial.log
readonly MARKERS=$WORK/markers.log
SOURCE_FILES=(
    res/rustdesk.service
    scripts/smoke-debian-systemd-loginctl.sh
    scripts/smoke-debian-systemd-lifecycle-guest.sh
)
if [ "$MODE" = source ]; then
    SOURCE_FILES+=(
        "$SOURCE_BINARY" res/rustdesk.init
        res/DEBIAN/preinst res/DEBIAN/postinst res/DEBIAN/prerm res/DEBIAN/postrm
    )
else
    SOURCE_FILES+=(scripts/verify-debian-package-authority.py)
fi
readonly SOURCE_HASH_BEFORE=$(sha256sum "${SOURCE_FILES[@]}")

BINARY=$SOURCE_BINARY
if [ "$MODE" = release-deb ]; then
    dpkg-deb -x "$RELEASE_DEB" "$EXTRACTED" \
        || fail 'cannot extract the release .deb into private lifecycle scratch'
    BINARY=$EXTRACTED/usr/share/rustdesk/rustdesk
fi
[ -f "$BINARY" ] && [ ! -L "$BINARY" ] && [ -x "$BINARY" ] \
    || fail 'selected RustDesk lifecycle executable is absent or non-executable'
case "$BINARY" in
    *,*) fail 'selected RustDesk lifecycle executable path contains a Docker --mount delimiter' ;;
esac

local_docker_image_provenance verify-local \
    --role devcheck \
    --expected-id "$DEV_CHECK_IMAGE_ID" \
    --image-ref "$DEV_CHECK_IMAGE_ID" \
    --base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}" \
    --dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE" \
    --dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST" \
    --cargo-sha "$SHA256_DEV_CHECK_CARGO" \
    --rustc-sha "$SHA256_DEV_CHECK_RUSTC" \
    --source-commit "$DEV_CHECK_SOURCE_COMMIT" \
    --source-repository "$DEV_CHECK_SOURCE_REPOSITORY" \
    --config-id "$DEV_CHECK_IMAGE_CONFIG_ID" \
    --manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID" \
    || fail 'immutable devcheck image provenance verification failed'

install -d -m 0700 -- "$LIBS"
[ "$(stat -c '%u:%g:%a:%h' -- "$LIBS")" = "$HOST_UID:$HOST_GID:700:2" ] \
    || fail 'runtime dependency output is not a private current-user directory'
case "$LIBS" in
    *,*) fail 'runtime dependency output path contains a Docker --mount delimiter' ;;
esac
local_docker run --rm --pull=never --network=none --read-only \
    --pids-limit=64 --memory=1g --memory-swap=1g --cpus=1 \
    --ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --user "$HOST_UID:$HOST_GID" \
    --mount "type=bind,source=$BINARY,target=/work/rustdesk-lifecycle-input,readonly,bind-recursive=disabled" \
    --mount "type=bind,source=$LIBS,target=/out,bind-recursive=disabled" \
    "$DEV_CHECK_IMAGE_ID" /bin/bash --noprofile --norc -euo pipefail -c '
        binary=$1
        ldd_output="$(ldd "$binary")"
        case "$ldd_output" in
            *"not found"*) printf "%s\n" "$ldd_output" >&2; exit 1 ;;
        esac
        while IFS= read -r library; do
            [ -f "$library" ] || { printf "missing ldd library: %s\n" "$library" >&2; exit 1; }
            cp -L --no-preserve=ownership -- "$library" "/out/$(basename "$library")"
        done < <(
            printf "%s\n" "$ldd_output" \
                | awk '\''/=> \/[^ ]+/{print $3} /^[[:space:]]*\//{print $1}'\'' \
                | sort -u
        )
        for pattern in \
            /usr/lib/x86_64-linux-gnu/libxdo.so* \
            /usr/lib/x86_64-linux-gnu/libva.so* \
            /usr/lib/x86_64-linux-gnu/libva-drm.so* \
            /usr/lib/x86_64-linux-gnu/libva-x11.so* \
            /usr/lib/x86_64-linux-gnu/libvdpau.so*; do
            for library in $pattern; do
                [ -f "$library" ] || continue
                cp -L --no-preserve=ownership -- "$library" "/out/$(basename "$library")"
            done
        done
    ' _ /work/rustdesk-lifecycle-input \
    || fail 'runtime dependency staging container failed'
[ "$(stat -c '%u:%g:%a:%h' -- "$LIBS")" = "$HOST_UID:$HOST_GID:700:2" ] \
    || fail 'runtime dependency output directory metadata changed during staging'
bad_library_entry="$(find "$LIBS" -mindepth 1 ! -type f -print -quit)" \
    || fail 'cannot inspect runtime dependency output shape'
[ -z "$bad_library_entry" ] \
    || fail "runtime dependency output contains a non-regular or nested entry: $bad_library_entry"
library_count=$(find "$LIBS" -mindepth 1 -maxdepth 1 -type f | wc -l)
[ "$library_count" -ge 60 ] && [ "$library_count" -le 256 ] \
    || fail "runtime dependency bundle count is outside 60..256: $library_count files"
library_bytes=0
while IFS= read -r -d '' library; do
    [ "$(stat -c '%u:%g:%h' -- "$library")" = "$HOST_UID:$HOST_GID:1" ] \
        || fail "runtime dependency output has wrong owner or link count: $library"
    library_size="$(stat -c '%s' -- "$library")" \
        || fail "cannot read runtime dependency size: $library"
    [ "$library_size" -gt 0 ] \
        || fail "runtime dependency output is empty: $library"
    library_bytes=$((library_bytes + library_size))
done < <(find "$LIBS" -mindepth 1 -maxdepth 1 -type f -print0)
[ "$library_bytes" -le 1073741824 ] \
    || fail "runtime dependency bundle exceeds 1 GiB: $library_bytes bytes"
find "$LIBS" -mindepth 1 -maxdepth 1 -type f -exec chmod 0444 {} +
chmod 0755 "$LIBS"

qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$OVERLAY" 8G

# The Debian genericcloud kernel intentionally omits 9p. Build one immutable
# ISO9660 payload directly from the exact source files and staged libraries;
# unlike a shared directory, the guest has no write protocol back to the host.
payload_grafts=(
    "source/res/rustdesk.service=$PWD/res/rustdesk.service"
    "source/scripts/smoke-debian-systemd-loginctl.sh=$PWD/scripts/smoke-debian-systemd-loginctl.sh"
    "source/scripts/smoke-debian-systemd-lifecycle-guest.sh=$PWD/scripts/smoke-debian-systemd-lifecycle-guest.sh"
    "runtime-libs=$LIBS"
)
if [ "$MODE" = source ]; then
    payload_grafts+=(
        "source/target/debug/rustdesk=$BINARY"
        "source/res/rustdesk.init=$PWD/res/rustdesk.init"
        "source/res/DEBIAN=$PWD/res/DEBIAN"
    )
    guest_invocation='bash /mnt/rustdesk-fixture/source/scripts/smoke-debian-systemd-lifecycle-guest.sh /mnt/rustdesk-fixture/source /mnt/rustdesk-fixture/runtime-libs'
else
    payload_grafts+=("artifact/rustdesk-x86_64.deb=$RELEASE_DEB")
    guest_invocation="bash /mnt/rustdesk-fixture/source/scripts/smoke-debian-systemd-lifecycle-guest.sh --release-deb /mnt/rustdesk-fixture/source /mnt/rustdesk-fixture/runtime-libs /mnt/rustdesk-fixture/artifact/rustdesk-x86_64.deb $EXPECTED_DEB_SHA256 $EXPECTED_COMMIT"
fi
xorriso -as mkisofs -quiet -iso-level 3 -volid RD_SYSTEMD_SMOKE -joliet -rock \
    -graft-points -output "$PAYLOAD" "${payload_grafts[@]}"
chmod 0444 "$PAYLOAD"

mkdir "$WORK/seed"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'finish() {' \
    '    status=$?' \
    '    trap - EXIT' \
    '    if [ "$status" -eq 0 ]; then' \
    '        echo RUSTDESK_SYSTEMD_CLOUD_INIT=pass' \
    '    else' \
    '        echo RUSTDESK_SYSTEMD_CLOUD_INIT=fail status=$status' \
    '    fi' \
    '    sync' \
    '    systemctl poweroff --no-block || poweroff -f' \
    '    exit "$status"' \
    '}' \
    'trap finish EXIT' \
    'mkdir -p /mnt/rustdesk-fixture' \
    'mount -L RD_SYSTEMD_SMOKE -o ro,nodev,nosuid /mnt/rustdesk-fixture' \
    "$guest_invocation" \
    >"$WORK/seed/user-data"
printf '%s\n' \
    'instance-id: rustdesk-systemd-smoke-v1' \
    'local-hostname: rustdesk-systemd-smoke' \
    >"$WORK/seed/meta-data"
printf '%s\n' \
    'version: 2' \
    'ethernets: {}' \
    >"$WORK/seed/network-config"
(
    cd "$WORK/seed"
    xorriso -as mkisofs -quiet -volid CIDATA -joliet -rock \
        -output "$SEED" user-data meta-data network-config
)
chmod 0444 "$SEED"

qemu_status=0
timeout --signal=TERM --kill-after=10s 420s \
    qemu-system-x86_64 \
        -name rustdesk-systemd-smoke \
        -accel kvm \
        -cpu host \
        -machine q35 \
        -m 2048 \
        -smp 2 \
        -no-reboot \
        -nographic \
        -nic none \
        -drive "file=$OVERLAY,if=virtio,format=qcow2,cache=none" \
        -drive "file=$SEED,if=virtio,format=raw,media=cdrom,readonly=on" \
        -drive "file=$PAYLOAD,if=virtio,format=raw,media=cdrom,readonly=on" \
        >"$SERIAL" 2>&1 || qemu_status=$?
if [ "$qemu_status" -ne 0 ]; then
    tail -n 240 "$SERIAL" >&2
    fail "networkless Debian systemd VM exited with status $qemu_status"
fi

# cloud-init prefixes console output with its timestamp/process label, and a
# serial console may use CRLF. Extract only our fixed marker namespaces before
# validating exact results; reject conflicting duplicate marker values.
python3 - "$SERIAL" "$MARKERS" <<'PY'
import re
import sys

serial_path, marker_path = sys.argv[1:]
marker_names = (
    "SYSTEMD_NORMAL_RESTART=",
    "SYSTEMD_STOP_START=",
    "SYSTEMD_CRASH_RESTART=",
    "DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=",
    "DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=",
    "RUSTDESK_SYSTEMD_CLOUD_INIT=",
)
ansi_escape = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
text = open(serial_path, "rb").read().decode("utf-8", errors="replace")
text = ansi_escape.sub("", text).replace("\r", "\n")
found = {name: set() for name in marker_names}
for line in text.splitlines():
    for name in marker_names:
        marker_start = line.find(name)
        if marker_start >= 0:
            found[name].add(line[marker_start:].strip())

with open(marker_path, "w", encoding="utf-8", newline="\n") as marker_file:
    for name in marker_names:
        values = found[name]
        if len(values) > 1:
            raise SystemExit(f"conflicting serial markers for {name}: {sorted(values)!r}")
        if values:
            marker_file.write(next(iter(values)) + "\n")
PY
grep -Eq '^SYSTEMD_NORMAL_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36}$' "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'normal systemd restart result marker is absent'; }
grep -Eq '^SYSTEMD_STOP_START=pass generation=[0-9a-f-]{36}$' "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'systemd stop/start result marker is absent'; }
grep -Eq '^SYSTEMD_CRASH_RESTART=pass prior_generation=[0-9a-f-]{36} generation=[0-9a-f-]{36} nrestarts=[1-9][0-9]*$' "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'systemd crash/restart result marker is absent'; }
grep -Eq '^DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=pass os=debian-12 systemd=252 seat_uid=4001 portable_uid=4000 crash_generation=[0-9a-f-]{36}$' "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'guest installed-systemd lifecycle result marker is absent'; }
grep -Eq '^RUSTDESK_SYSTEMD_CLOUD_INIT=pass$' "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'cloud-init completion marker is absent'; }
[ "$MODE" != release-deb ] || grep -Fxq \
    "DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=pass sha256=$EXPECTED_DEB_SHA256 commit=$EXPECTED_COMMIT" \
    "$MARKERS" \
    || { tail -n 240 "$SERIAL" >&2; fail 'exact final .deb lifecycle marker is absent'; }

SOURCE_HASH_AFTER=$(sha256sum "${SOURCE_FILES[@]}")
[ "$SOURCE_HASH_AFTER" = "$SOURCE_HASH_BEFORE" ] \
    || fail 'read-only source fixtures changed across the VM lifecycle'
if [ "$MODE" = release-deb ]; then
    [ "$(stat -c '%d:%i:%s:%u:%g:%a:%h' -- "$RELEASE_DEB" 2>/dev/null)" = "$ARTIFACT_ID" ] \
        || fail 'release .deb identity changed across the VM lifecycle'
    [ "$(sha256sum "$RELEASE_DEB" | awk '{print $1}')" = "$EXPECTED_DEB_SHA256" ] \
        || fail 'release .deb bytes changed across the VM lifecycle'
fi

cat "$MARKERS"
printf 'DEBIAN_SYSTEMD_VM_ISOLATION=pass network=none accel=kvm source=ro base=sha512 libraries=%s mode=%s\n' \
    "$library_count" "$MODE"

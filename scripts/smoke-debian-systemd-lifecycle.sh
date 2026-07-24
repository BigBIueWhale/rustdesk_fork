#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

# Host-side orchestrator for one disposable, networkless Debian KVM guest. It
# never invokes sudo, never enters the host PID/cgroup namespaces, and never
# talks to the host service manager. The production source and the dependency
# bundle are mounted read-only; all package/systemd writes land only in a CoW
# overlay deleted on exit.
source scripts/lib.sh
load_pins

readonly IMAGE=${SYSTEMD_SMOKE_IMAGE:-$PWD/.harness-state/debian-systemd-smoke/debian-12-genericcloud-amd64-${DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD}.qcow2}
readonly SOURCE_BINARY=$PWD/target/debug/rustdesk
readonly DEV_IMAGE=${SYSTEMD_SMOKE_DEV_IMAGE:-rd-devcheck}
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

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
        chmod u+w "$WORK" "$WORK/runtime-libs" 2>/dev/null || true
        rm -rf -- "$WORK" || status=1
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" -ne 0 ] || fail 'host orchestrator must run unprivileged'
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
    || fail 'systemd VM smoke requires the pinned Linux x86_64 build host'
for command in docker qemu-img qemu-system-x86_64 sha256sum sha512sum timeout xorriso; do
    command -v "$command" >/dev/null || fail "required host command is absent: $command"
done
[ "$MODE" != release-deb ] || for command in dpkg-deb git python3 readlink stat; do
    command -v "$command" >/dev/null || fail "required release-artifact command is absent: $command"
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || fail '/dev/kvm is not available to the unprivileged build user'
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
    || fail "private systemd smoke state is absent; run scripts/online-fetch.sh --debian-systemd-smoke-image"
[ "$(stat -c '%u:%a' "$STATE_DIR")" = "$(id -u):700" ] \
    || fail 'systemd smoke state directory is not current-user-owned mode 0700'
[ -f "$IMAGE" ] && [ ! -L "$IMAGE" ] \
    || fail "pinned Debian cloud image is absent; run scripts/online-fetch.sh --debian-systemd-smoke-image"
IMAGE_METADATA="$(stat -c '%u:%g:%a:%h' "$IMAGE")"
case "$IMAGE_METADATA" in
    "$(id -u):$(id -g):400:1" | "$(id -u):$(id -g):444:1") ;;
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
docker image inspect "$DEV_IMAGE" >/dev/null 2>&1 \
    || fail "runtime dependency image is absent: $DEV_IMAGE"

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
    [ "$(stat -c '%u:%g:%a:%h' -- "$RELEASE_DEB")" = "$(id -u):$(id -g):400:1" ] \
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

WORK=$(mktemp -d "$STATE_DIR/run.XXXXXXXXXX")
[ "$(stat -c '%u:%a' "$WORK")" = "$(id -u):700" ] \
    || fail 'VM scratch directory is not current-user-owned mode 0700'
readonly WORK
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
container_binary=/work/target/debug/rustdesk
docker_mounts=(-v "$PWD:/work:ro")
if [ "$MODE" = release-deb ]; then
    dpkg-deb -x "$RELEASE_DEB" "$EXTRACTED" \
        || fail 'cannot extract the release .deb into private lifecycle scratch'
    BINARY=$EXTRACTED/usr/share/rustdesk/rustdesk
    container_binary=/artifact-root/usr/share/rustdesk/rustdesk
    docker_mounts+=(-v "$EXTRACTED:/artifact-root:ro")
fi
[ -f "$BINARY" ] && [ ! -L "$BINARY" ] && [ -x "$BINARY" ] \
    || fail 'selected RustDesk lifecycle executable is absent or non-executable'

mkdir "$LIBS"
host_uid=$(id -u)
host_gid=$(id -g)
docker run --rm --network none --read-only --pids-limit 64 \
    --cap-drop ALL --security-opt no-new-privileges \
    --user "$host_uid:$host_gid" \
    "${docker_mounts[@]}" \
    -v "$LIBS:/out:rw" \
    "$DEV_IMAGE" bash --noprofile --norc -euo pipefail -c '
        binary=$1
        while IFS= read -r library; do
            [ -f "$library" ] || { printf "missing ldd library: %s\n" "$library" >&2; exit 1; }
            cp -L --no-preserve=ownership -- "$library" "/out/$(basename "$library")"
        done < <(
            ldd "$binary" \
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
    ' _ "$container_binary"
library_count=$(find "$LIBS" -mindepth 1 -maxdepth 1 -type f | wc -l)
[ "$library_count" -ge 60 ] \
    || fail "runtime dependency bundle is unexpectedly small: $library_count files"
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

trap - EXIT HUP INT TERM
rm -rf -- "$WORK"

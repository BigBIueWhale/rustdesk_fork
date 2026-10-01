#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly REPO="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
readonly PREFLIGHT="$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"
"$PREFLIGHT"
[ "$#" -eq 0 ] || { echo 'engine bootstrap discovery takes no arguments' >&2; exit 2; }
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"
readonly UID_NUMBER="$(/usr/bin/id -u)"
readonly GID_NUMBER="$(/usr/bin/id -g)"
readonly SDK="$REPO/online/candidates/flutter-presentation/flutter-${FLUTTER_PRESENTATION_CANDIDATE_VERSION}.tar.xz"
readonly OUTPUT="$REPO/online/candidates/flutter-linux-engine-bootstrap"
readonly HELPER="$SCRIPT_DIR/discover-flutter-linux-engine-bootstrap.py"
WORK=
WORK_ID=
CONTAINER_ID=

fail() { printf 'engine bootstrap discovery: %s\n' "$*" >&2; exit 1; }

docker_client() {
    local status=0
    "$PREFLIGHT" >/dev/null
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$WORK" \
        /usr/bin/docker --host unix:///var/run/docker.sock --config "$WORK/docker" \
        "$@" || status=$?
    "$PREFLIGHT" >/dev/null
    return "$status"
}

cleanup() {
    local status=$? cleanup_failed=0
    trap - EXIT HUP INT TERM
    # The CID file retains ownership even if cancellation interrupts create's return.
    if [ -n "$WORK" ] && [ -e "$WORK/container.id" ]; then
        [ -f "$WORK/container.id" ] && [ ! -L "$WORK/container.id" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$WORK/container.id")" = "$UID_NUMBER:$GID_NUMBER:1" ] \
            || cleanup_failed=1
        if [ "$cleanup_failed" -eq 0 ]; then
            CONTAINER_ID="$(/usr/bin/cat "$WORK/container.id")"
            if [[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]]; then
                docker_client rm -f "$CONTAINER_ID" >/dev/null || cleanup_failed=1
            else
                cleanup_failed=1
            fi
        fi
    fi
    if [ -n "$WORK" ] && [ "$cleanup_failed" -eq 0 ]; then
        /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$WORK" --expected-identity "$WORK_ID" \
            || cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || { echo 'engine discovery cleanup failed; state retained' >&2; status=1; }
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || fail 'discovery output is already occupied'
for root in "$REPO/online/candidates" "$REPO/online/candidates/flutter-presentation"; do
    [ -d "$root" ] && [ ! -L "$root" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$root")" = "$UID_NUMBER:$GID_NUMBER:700" ] \
        || fail 'candidate parent authority differs'
done
[ -f "$SDK" ] && [ ! -L "$SDK" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$SDK")" = \
         "$UID_NUMBER:$GID_NUMBER:400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ] \
    || fail 'publisher-pinned SDK metadata differs'
WORK="$(/usr/bin/mktemp -d /var/tmp/rustdesk-engine-discovery.XXXXXXXXXX)"
WORK_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORK")"
/usr/bin/install -d -m 0700 "$WORK/docker"
/usr/bin/printf '{}\n' >"$WORK/docker/config.json"
# Reuse the actual acquisition entry and provenance loader, not a parallel image loader.
/bin/bash "$SCRIPT_DIR/online-fetch.sh" --devcheck-image
/usr/bin/mkdir -m 0700 -- "$OUTPUT"
helper_before="$(/usr/bin/sha256sum "$HELPER")"
docker_client create --cidfile "$WORK/container.id" --pull=never \
    --network=bridge --read-only --user "$UID_NUMBER:$GID_NUMBER" \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=64 --memory=512m --memory-swap=512m --cpus=2 \
    --log-driver=none \
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=700,uid=$UID_NUMBER,gid=$GID_NUMBER" \
    --mount "type=bind,src=$SDK,dst=/sdk.tar.xz,readonly,bind-nonrecursive" \
    --mount "type=bind,src=$HELPER,dst=/discover.py,readonly,bind-nonrecursive" \
    --mount "type=bind,src=$OUTPUT,dst=/output,bind-nonrecursive" \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint /usr/bin/python3 "$DEV_CHECK_IMAGE_ID" -I -S /discover.py \
    --source-commit "$RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT" \
    --framework-revision "$FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION" \
    --sdk-size "$SIZE_FLUTTER_PRESENTATION_CANDIDATE" \
    --sdk-sha256 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" >/dev/null
CONTAINER_ID="$(/usr/bin/cat "$WORK/container.id")"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'created container identity differs'
docker_client inspect "$CONTAINER_ID" >"$WORK/inspect.json"
/usr/bin/python3 -I -S - "$WORK/inspect.json" "$UID_NUMBER:$GID_NUMBER" \
    "$DEV_CHECK_IMAGE_ID" "$SDK" "$HELPER" "$OUTPUT" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as source:
    records = json.load(source)
assert len(records) == 1
record = records[0]
config, host = record['Config'], record['HostConfig']
assert config['User'] == sys.argv[2] and config['Image'] == sys.argv[3]
assert config['Entrypoint'] == ['/usr/bin/python3']
assert host['NetworkMode'] == 'bridge' and host['ReadonlyRootfs'] is True
assert host['Privileged'] is False and host['CapDrop'] == ['ALL']
assert not host['CapAdd'] and host['SecurityOpt'] == ['no-new-privileges']
assert host['PidsLimit'] == 64 and host['Memory'] == 536870912
assert host['MemorySwap'] == 536870912 and host['NanoCpus'] == 2000000000
assert not host['PortBindings'] and host['PublishAllPorts'] is False
assert not host['Devices'] and not host['DeviceRequests']
assert not host['PidMode'] and not host['UsernsMode']
assert host['IpcMode'] == 'private' and not host['Binds']
assert host['LogConfig'] == {'Type': 'none', 'Config': {}}
assert set(host['Tmpfs']) == {'/tmp'}
expected = {'/sdk.tar.xz': (sys.argv[4], False),
            '/discover.py': (sys.argv[5], False), '/output': (sys.argv[6], True)}
binds = {}
for mount in record['Mounts']:
    if mount['Type'] == 'tmpfs':
        assert mount['Destination'] == '/tmp'
        continue
    assert mount['Type'] == 'bind' and mount['Propagation'] == 'rprivate'
    assert mount['Destination'] not in binds
    binds[mount['Destination']] = (mount['Source'], mount['RW'])
assert binds == expected
print('ENGINE_BOOTSTRAP_CONTAINER=pass uid=' + sys.argv[2] +
      ' network=guest-bridge ports=none capabilities=none root=readonly')
PY
docker_client start --attach "$CONTAINER_ID"
[ "$(docker_client inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
    || fail 'metadata acquisition did not exit cleanly'
docker_client rm "$CONTAINER_ID" >/dev/null
/usr/bin/rm -- "$WORK/container.id"
CONTAINER_ID=
[ "$(/usr/bin/sha256sum "$HELPER")" = "$helper_before" ] || fail 'discovery source changed'
[ "$(/usr/bin/find "$OUTPUT" -mindepth 1 -maxdepth 1 -printf '%f\n')" = discovery.json ] \
    && [ -f "$OUTPUT/discovery.json" ] && [ ! -L "$OUTPUT/discovery.json" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OUTPUT/discovery.json")" = "$UID_NUMBER:$GID_NUMBER:400:1" ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$OUTPUT/discovery.json")" -le 262144 ] \
    || fail 'bounded discovery publication differs'

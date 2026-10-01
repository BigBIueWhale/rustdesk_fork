#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly REPO="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
readonly PREFLIGHT="$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"
"$PREFLIGHT"
MODE=discovery
case "$#:${1:-}" in
    0:) ;;
    1:--stage-tools) MODE=tools ;;
    1:--probe-tools) MODE=probe ;;
    *) echo 'engine bootstrap expects no arguments, --stage-tools or --probe-tools' >&2; exit 2 ;;
esac
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"
readonly UID_NUMBER="$(/usr/bin/id -u)"
readonly GID_NUMBER="$(/usr/bin/id -g)"
if [ "$MODE" = discovery ]; then
    INPUT="$REPO/online/candidates/flutter-presentation/flutter-${FLUTTER_PRESENTATION_CANDIDATE_VERSION}.tar.xz"
    INPUT_PARENT="$REPO/online/candidates/flutter-presentation"
    INPUT_DEST=/sdk.tar.xz
    INPUT_SIZE=$SIZE_FLUTTER_PRESENTATION_CANDIDATE
    OUTPUT="$REPO/online/candidates/flutter-linux-engine-bootstrap"
    HELPER="$SCRIPT_DIR/discover-flutter-linux-engine-bootstrap.py"
    PHASE=discovery
    ARGUMENTS=(--source-commit "$RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT"
        --framework-revision "$FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION"
        --sdk-size "$SIZE_FLUTTER_PRESENTATION_CANDIDATE"
        --sdk-sha256 "$SHA256_FLUTTER_PRESENTATION_CANDIDATE")
else
    INPUT="$REPO/online/candidates/flutter-linux-engine-bootstrap/discovery.json"
    INPUT_PARENT="$REPO/online/candidates/flutter-linux-engine-bootstrap"
    INPUT_DEST=/discovery.json
    INPUT_SIZE=$SIZE_FLUTTER_ENGINE_BOOTSTRAP_DISCOVERY
    OUTPUT="$REPO/online/candidates/flutter-linux-engine-bootstrap-tools"
    HELPER="$SCRIPT_DIR/stage-flutter-linux-engine-bootstrap.py"
    PHASE=acquire
    ARGUMENTS=(--source-commit "$RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT"
        --framework-revision "$FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION"
        --discovery-size "$SIZE_FLUTTER_ENGINE_BOOTSTRAP_DISCOVERY"
        --discovery-sha256 "$SHA256_FLUTTER_ENGINE_BOOTSTRAP_DISCOVERY"
        --depot-revision "$FLUTTER_ENGINE_DEPOT_TOOLS_REVISION"
        --depot-tree "$FLUTTER_ENGINE_DEPOT_TOOLS_TREE"
        --cipd-version "$FLUTTER_ENGINE_CIPD_VERSION"
        --cipd-instance "$FLUTTER_ENGINE_CIPD_INSTANCE"
        --cipd-sha256 "$SHA256_FLUTTER_ENGINE_CIPD_CLIENT")
    if [ "$MODE" = probe ]; then
        PHASE=probe
        ARGUMENTS+=(--tools-source-commit "$FLUTTER_ENGINE_BOOTSTRAP_TOOLS_SOURCE_COMMIT"
            --tools-manifest-size "$SIZE_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST"
            --tools-manifest-sha256 "$SHA256_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST")
    fi
fi
readonly INPUT INPUT_PARENT INPUT_DEST INPUT_SIZE OUTPUT HELPER MODE PHASE
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

if [ "$MODE" = probe ]; then
    [ -d "$OUTPUT" ] && [ ! -L "$OUTPUT" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$OUTPUT")" = "$UID_NUMBER:$GID_NUMBER:700" ] \
        || fail 'sealed bootstrap candidate is absent or ambiguous'
else
    [ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || fail 'discovery output is already occupied'
fi
for root in "$REPO/online/candidates" "$INPUT_PARENT"; do
    [ -d "$root" ] && [ ! -L "$root" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$root")" = "$UID_NUMBER:$GID_NUMBER:700" ] \
        || fail 'candidate parent authority differs'
done
[ -f "$INPUT" ] && [ ! -L "$INPUT" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$INPUT")" = \
         "$UID_NUMBER:$GID_NUMBER:400:1:$INPUT_SIZE" ] \
    || fail 'source-bound bootstrap input metadata differs'
WORK="$(/usr/bin/mktemp -d /var/tmp/rustdesk-engine-discovery.XXXXXXXXXX)"
WORK_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORK")"
/usr/bin/install -d -m 0700 "$WORK/docker"
/usr/bin/printf '{}\n' >"$WORK/docker/config.json"
# Reuse the actual acquisition entry and provenance loader, not a parallel image loader.
/bin/bash "$SCRIPT_DIR/online-fetch.sh" --devcheck-image
[ "$MODE" = probe ] || /usr/bin/mkdir -m 0700 -- "$OUTPUT"
helper_before="$(/usr/bin/sha256sum "$HELPER")"
phase=$PHASE
network=bridge
output_mount="type=bind,src=$OUTPUT,dst=/output,bind-nonrecursive"
phase_arguments=()
memory=512m
memory_bytes=536870912
tmp_size=16m
if [ "$MODE" != discovery ]; then
    memory=1g
    memory_bytes=1073741824
    tmp_size=512m
    phase_arguments=(--phase "$phase")
fi
scratch=(--tmpfs "/tmp:rw,noexec,nosuid,nodev,size=$tmp_size,mode=700,uid=$UID_NUMBER,gid=$GID_NUMBER")
if [ "$MODE" != discovery ]; then
    if [ "$phase" = probe ]; then
        network=none
        output_mount+=,readonly
        scratch+=(--tmpfs "/build:rw,exec,nosuid,nodev,size=64m,mode=700,uid=$UID_NUMBER,gid=$GID_NUMBER")
    fi
fi
docker_client create --cidfile "$WORK/container.id" --pull=never \
    --network="$network" --read-only --user "$UID_NUMBER:$GID_NUMBER" \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=64 --memory="$memory" --memory-swap="$memory" --cpus=2 \
    --log-driver=none \
    "${scratch[@]}" \
    --mount "type=bind,src=$INPUT,dst=$INPUT_DEST,readonly,bind-nonrecursive" \
    --mount "type=bind,src=$HELPER,dst=/bootstrap.py,readonly,bind-nonrecursive" \
    --mount "$output_mount" \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint /usr/bin/python3 "$DEV_CHECK_IMAGE_ID" -I -S /bootstrap.py \
    "${ARGUMENTS[@]}" "${phase_arguments[@]}" >/dev/null
CONTAINER_ID="$(/usr/bin/cat "$WORK/container.id")"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'created container identity differs'
docker_client inspect "$CONTAINER_ID" >"$WORK/inspect.json"
/usr/bin/python3 -I -S - "$WORK/inspect.json" "$UID_NUMBER:$GID_NUMBER" \
    "$DEV_CHECK_IMAGE_ID" "$INPUT" "$HELPER" "$OUTPUT" "$INPUT_DEST" "$network" "$phase" \
    "$memory_bytes" "$tmp_size" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as source:
    records = json.load(source)
assert len(records) == 1
record = records[0]
config, host = record['Config'], record['HostConfig']
assert config['User'] == sys.argv[2] and config['Image'] == sys.argv[3]
assert config['Entrypoint'] == ['/usr/bin/python3']
assert host['NetworkMode'] == sys.argv[8] and host['ReadonlyRootfs'] is True
assert host['Privileged'] is False and host['CapDrop'] == ['ALL']
assert not host['CapAdd'] and host['SecurityOpt'] == ['no-new-privileges']
assert host['PidsLimit'] == 64 and host['Memory'] == int(sys.argv[10])
assert host['MemorySwap'] == int(sys.argv[10]) and host['NanoCpus'] == 2000000000
assert not host['PortBindings'] and host['PublishAllPorts'] is False
assert not host['Devices'] and not host['DeviceRequests']
assert not host['PidMode'] and not host['UsernsMode']
assert host['IpcMode'] == 'private' and not host['Binds']
assert host['LogConfig'] == {'Type': 'none', 'Config': {}}
assert set(host['Tmpfs']) == ({'/tmp', '/build'} if sys.argv[9] == 'probe' else {'/tmp'})
uid, gid = sys.argv[2].split(':')
assert host['Tmpfs']['/tmp'] == ('rw,noexec,nosuid,nodev,size=' + sys.argv[11] +
                                ',mode=700,uid=' + uid + ',gid=' + gid)
if sys.argv[9] == 'probe':
    assert host['Tmpfs']['/build'] == ('rw,exec,nosuid,nodev,size=64m,mode=700,uid=' +
                                      uid + ',gid=' + gid)
expected = {sys.argv[7]: (sys.argv[4], False),
            '/bootstrap.py': (sys.argv[5], False),
            '/output': (sys.argv[6], sys.argv[9] != 'probe')}
binds = {}
for mount in record['Mounts']:
    if mount['Type'] == 'tmpfs':
        assert mount['Destination'] in host['Tmpfs']
        continue
    assert mount['Type'] == 'bind' and mount['Propagation'] == 'rprivate'
    assert mount['Destination'] not in binds
    binds[mount['Destination']] = (mount['Source'], mount['RW'])
assert binds == expected
print('ENGINE_BOOTSTRAP_CONTAINER=pass uid=' + sys.argv[2] +
      ' phase=' + sys.argv[9] + ' network=' + sys.argv[8] +
      ' ports=none capabilities=none root=readonly')
PY
docker_client start --attach "$CONTAINER_ID"
[ "$(docker_client inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$CONTAINER_ID")" = exited:0 ] \
    || fail 'metadata acquisition did not exit cleanly'
docker_client rm "$CONTAINER_ID" >/dev/null
/usr/bin/rm -- "$WORK/container.id"
CONTAINER_ID=
[ "$(/usr/bin/sha256sum "$HELPER")" = "$helper_before" ] || fail 'discovery source changed'
if [ "$MODE" != discovery ]; then
    [ "$(/usr/bin/find "$OUTPUT" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)" = \
      $'cipd-client\ndepot-tools.tar\nmanifest.json' ] || fail 'bootstrap tool inventory differs'
    for file in cipd-client depot-tools.tar manifest.json; do
        [ -f "$OUTPUT/$file" ] && [ ! -L "$OUTPUT/$file" ] \
            && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OUTPUT/$file")" = "$UID_NUMBER:$GID_NUMBER:400:1" ] \
            && [ "$(/usr/bin/stat -c '%s' -- "$OUTPUT/$file")" -le 67108864 ] \
            || fail 'bootstrap tool publication differs'
    done
    exit 0
fi
[ "$(/usr/bin/find "$OUTPUT" -mindepth 1 -maxdepth 1 -printf '%f\n')" = discovery.json ] \
    && [ -f "$OUTPUT/discovery.json" ] && [ ! -L "$OUTPUT/discovery.json" ] \
    && [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$OUTPUT/discovery.json")" = "$UID_NUMBER:$GID_NUMBER:400:1" ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$OUTPUT/discovery.json")" -le 262144 ] \
    || fail 'bounded discovery publication differs'

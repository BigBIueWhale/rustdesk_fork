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
    1:--stage-graph) MODE=graph ;;
    1:--stage-git-metadata) MODE=git-metadata ;;
    *) echo 'engine bootstrap expects no arguments, --stage-tools, --probe-tools, --stage-graph or --stage-git-metadata' >&2; exit 2 ;;
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
    if [ "$MODE" = probe ] || [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
        [ "$MODE" != probe ] || PHASE=probe
        ARGUMENTS+=(--tools-source-commit "$FLUTTER_ENGINE_BOOTSTRAP_TOOLS_SOURCE_COMMIT"
            --tools-manifest-size "$SIZE_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST"
            --tools-manifest-sha256 "$SHA256_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST")
    fi
    if [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
        OUTPUT="$REPO/online/candidates/flutter-linux-engine-graph"
        HELPER="$SCRIPT_DIR/stage-flutter-linux-engine-graph.py"
        PHASE=graph
        ARGUMENTS+=(--epoch "$SOURCE_DATE_EPOCH_PIN")
        if [ "$MODE" = git-metadata ]; then
            OUTPUT="$REPO/online/candidates/flutter-linux-engine-git-metadata"
            PHASE=git-metadata
            ARGUMENTS+=(--graph-source-commit "$FLUTTER_ENGINE_GRAPH_SOURCE_COMMIT"
                --graph-manifest-size "$SIZE_FLUTTER_ENGINE_GRAPH_MANIFEST"
                --graph-manifest-sha256 "$SHA256_FLUTTER_ENGINE_GRAPH_MANIFEST"
                --engine-content-hash "$FLUTTER_PRESENTATION_CANDIDATE_ENGINE_REVISION")
        fi
    fi
fi
readonly INPUT INPUT_PARENT INPUT_DEST INPUT_SIZE OUTPUT HELPER MODE PHASE
WORK=
WORK_ID=
CONTAINER_ID=
COMMON_HELPER=
TOOLS=
GRAPH_WORK=
GRAPH_MANIFEST=

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
if [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
    COMMON_HELPER="$SCRIPT_DIR/stage-flutter-linux-engine-bootstrap.py"
fi
if [ "$MODE" = graph ]; then
    TOOLS="$REPO/online/candidates/flutter-linux-engine-bootstrap-tools"
    [ -d "$TOOLS" ] && [ ! -L "$TOOLS" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$TOOLS")" = "$UID_NUMBER:$GID_NUMBER:700" ] \
        || fail 'sealed graph bootstrap input is absent or ambiguous'
fi
if [ "$MODE" = git-metadata ]; then
    graph_root="$REPO/online/candidates/flutter-linux-engine-graph"
    GRAPH_MANIFEST="$graph_root/manifest.json"
    [ -d "$graph_root" ] && [ ! -L "$graph_root" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$graph_root")" = "$UID_NUMBER:$GID_NUMBER:700" ] \
        && [ -f "$GRAPH_MANIFEST" ] && [ ! -L "$GRAPH_MANIFEST" ] \
        && [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "$GRAPH_MANIFEST")" = \
             "$UID_NUMBER:$GID_NUMBER:400:1:$SIZE_FLUTTER_ENGINE_GRAPH_MANIFEST" ] \
        || fail 'sealed engine graph manifest is absent or ambiguous'
fi
WORK="$(/usr/bin/mktemp -d /var/tmp/rustdesk-engine-discovery.XXXXXXXXXX)"
WORK_ID="$(/usr/bin/stat -c '%d:%i' -- "$WORK")"
/usr/bin/install -d -m 0700 "$WORK/docker"
/usr/bin/printf '{}\n' >"$WORK/docker/config.json"
# Reuse the actual acquisition entry and provenance loader, not a parallel image loader.
/bin/bash "$SCRIPT_DIR/online-fetch.sh" --devcheck-image
[ "$MODE" = probe ] || /usr/bin/mkdir -m 0700 -- "$OUTPUT"
helper_sources=("$HELPER")
[ -z "$COMMON_HELPER" ] || helper_sources+=("$COMMON_HELPER")
helper_before="$(/usr/bin/sha256sum "${helper_sources[@]}")"
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
if [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
    memory=2g
    memory_bytes=2147483648
    tmp_size=16m
    GRAPH_WORK="$WORK/graph-work"
    /usr/bin/mkdir -m 0700 -- "$GRAPH_WORK"
fi
scratch=(--tmpfs "/tmp:rw,noexec,nosuid,nodev,size=$tmp_size,mode=700,uid=$UID_NUMBER,gid=$GID_NUMBER")
extra_mounts=()
if [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
    extra_mounts=(
        --mount "type=bind,src=$COMMON_HELPER,dst=/bootstrap-common.py,readonly,bind-nonrecursive"
        --mount "type=bind,src=$GRAPH_WORK,dst=/work,bind-nonrecursive")
    if [ "$MODE" = graph ]; then
        extra_mounts+=(--mount "type=bind,src=$TOOLS,dst=/tools,readonly,bind-nonrecursive")
    else
        extra_mounts+=(--mount "type=bind,src=$GRAPH_MANIFEST,dst=/graph-manifest.json,readonly,bind-nonrecursive")
    fi
fi
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
    "${extra_mounts[@]}" \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint /usr/bin/python3 "$DEV_CHECK_IMAGE_ID" -I -S /bootstrap.py \
    "${ARGUMENTS[@]}" "${phase_arguments[@]}" >/dev/null
CONTAINER_ID="$(/usr/bin/cat "$WORK/container.id")"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || fail 'created container identity differs'
docker_client inspect "$CONTAINER_ID" >"$WORK/inspect.json"
/usr/bin/python3 -I -S - "$WORK/inspect.json" "$UID_NUMBER:$GID_NUMBER" \
    "$DEV_CHECK_IMAGE_ID" "$INPUT" "$HELPER" "$OUTPUT" "$INPUT_DEST" "$network" "$phase" \
    "$memory_bytes" "$tmp_size" "$COMMON_HELPER" "$TOOLS" "$GRAPH_WORK" "$GRAPH_MANIFEST" <<'PY'
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
if sys.argv[9] in ('graph', 'git-metadata'):
    expected.update({'/bootstrap-common.py': (sys.argv[12], False),
                     '/work': (sys.argv[14], True)})
    if sys.argv[9] == 'graph':
        assert sys.argv[15] == ''
        expected['/tools'] = (sys.argv[13], False)
    else:
        assert sys.argv[13] == ''
        expected['/graph-manifest.json'] = (sys.argv[15], False)
else:
    assert sys.argv[12:] == ['', '', '', '']
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
[ "$(/usr/bin/sha256sum "${helper_sources[@]}")" = "$helper_before" ] || fail 'discovery source changed'
if [ "$MODE" = graph ] || [ "$MODE" = git-metadata ]; then
    /usr/bin/python3 -I -S - "$OUTPUT" "$RUSTDESK_ONLINE_FETCH_VM_SOURCE_COMMIT" \
        "$FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION" \
        "$SHA256_FLUTTER_ENGINE_BOOTSTRAP_DISCOVERY" \
        "$SHA256_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST" "$MODE" \
        "$SHA256_FLUTTER_ENGINE_GRAPH_MANIFEST" "$FLUTTER_ENGINE_GRAPH_SOURCE_COMMIT" \
        "$FLUTTER_PRESENTATION_CANDIDATE_ENGINE_REVISION" <<'PY'
import hashlib, json, os, re, stat, sys
root = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
try:
    def verify(name, maximum, expected=None):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            assert (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (os.getuid(), os.getgid(), 0o400)
            assert 0 < before.st_size <= maximum
            if expected is None:
                payload = source.read(maximum + 1)
                assert len(payload) == before.st_size
                result = json.loads(payload)
            else:
                assert before.st_size == expected['bytes']
                assert hashlib.file_digest(source, 'sha256').hexdigest() == expected['sha256']
                result = before.st_size
            after = os.fstat(source.fileno())
            assert all(getattr(before, key) == getattr(after, key) for key in fields)
            return result
    manifest = verify('manifest.json', 1048576)
    metadata = sys.argv[6] == 'git-metadata'
    assert manifest['format'] == ('rustdesk-flutter-linux-engine-git-metadata-v1' if metadata else 'rustdesk-flutter-linux-engine-graph-v1')
    assert [manifest[key] for key in ('source_commit', 'framework_revision', 'discovery_sha256', 'tools_manifest_sha256')] == sys.argv[2:6]
    assert manifest['complete_engine_closure'] is False and manifest['hooks_executed'] is False
    assert 0 < len(manifest['git']) <= 256 and len(manifest['cipd']) <= 256
    if metadata:
        assert len(manifest['git']) == 3 and not manifest['cipd']
        assert [manifest[key] for key in ('graph_manifest_sha256', 'graph_source_commit', 'engine_content_hash')] == sys.argv[7:10]
        assert [entry['destination'] for entry in manifest['git']] == ['.', 'engine/src/flutter/third_party/dart', 'engine/src/flutter/third_party/skia']
    expected_names = {'manifest.json'}
    total = 0
    for kind in ('git', 'cipd'):
        for index, entry in enumerate(manifest[kind]):
            name = '%s-%03d.tar' % (kind, index)
            assert entry['file'] == name and name not in expected_names
            assert re.fullmatch('[0-9a-f]{64}', entry['sha256'])
            total += verify(name, 1073741824 if metadata else 4294967296, entry)
            expected_names.add(name)
    assert set(os.listdir(root)) == expected_names
    assert total == manifest['acquired_bytes'] and total + os.stat('manifest.json', dir_fd=root).st_size <= (3221225472 if metadata else 25769803776)
    print(('ENGINE_GIT_METADATA_PUBLICATION' if metadata else 'ENGINE_GRAPH_PUBLICATION') + '=pass files=' + str(len(expected_names)) + ' bytes=' + str(total) + ' hooks=deferred complete_engine_closure=no')
finally:
    os.close(root)
PY
    exit 0
fi
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

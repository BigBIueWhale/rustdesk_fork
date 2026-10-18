#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$#" -eq 0 ] && [ "$PWD" = /source ] && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    && [ "${CARGO_TARGET_DIR:-}" = /cargo-target ] \
    || { echo 'Recording output test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/recording-output
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
python3 -I -S - <<'PY'
import errno,socket
with socket.socket() as canary:
    canary.settimeout(1)
    try:
        canary.connect(('192.0.2.1',9))
    except OSError as error:
        assert error.errno == errno.ENETUNREACH, error
    else:
        raise SystemExit('Recording compile canary connected')
print('R-B10 canary: build confirmed network-isolated (offline compile stage).')
PY
printf 'RECORDING_OUTPUT_BUILD=started target=scrap-libtest budget_seconds=240\n'
build_started=$SECONDS
build_status=0
timeout --signal=TERM --kill-after=5s 240s \
    cargo test --offline --locked --package scrap --lib --features linux-pkg-config \
    --no-run --message-format=json --color never >"$WORK/build.json" || build_status=$?
if [ "$build_status" -ne 0 ]; then
    tail -c 16000 "$WORK/build.json" >&2
    exit "$build_status"
fi
test_executable=$(python3 -I -S - "$WORK/build.json" <<'PY'
import json,re,sys
with open(sys.argv[1], 'rb') as stream:
    output = stream.read(4 * 1024 * 1024 + 1)
if len(output) > 4 * 1024 * 1024:
    sys.exit('Recording Cargo metadata exceeds bound')
artifacts=[];finished=[]
for line in output.splitlines():
    if not line.startswith(b'{'): continue
    value=json.loads(line)
    if value.get('reason') == 'build-finished': finished.append(value.get('success'))
    if (value.get('reason') == 'compiler-artifact' and value.get('manifest_path') == '/source/libs/scrap/Cargo.toml'
            and value.get('target', {}).get('name') == 'scrap'
            and value.get('target', {}).get('src_path') == '/source/libs/scrap/src/lib.rs'
            and value.get('profile', {}).get('test') is True):
        p=value['profile']
        if (p.get('debuginfo'),p.get('opt_level'),p.get('debug_assertions'),p.get('overflow_checks')) != (0,'0',True,True):
            sys.exit('Recording compiler profile differs')
        artifacts.append(value.get('executable'))
if finished != [True] or len(artifacts) != 1 or not isinstance(artifacts[0],str) or not re.fullmatch(r'/cargo-target/debug/deps/scrap-[0-9a-f]{16}',artifacts[0]):
    sys.exit('Recording build lacks one exact completed scrap test artifact')
print(artifacts[0])
PY
)
[ -f "$test_executable" ] && [ ! -L "$test_executable" ] && [ -x "$test_executable" ] \
    && [ "$(stat -c '%u:%g:%h' "$test_executable")" = 1000:1000:1 ]
artifact_sha=$(sha256sum "$test_executable" | cut -d ' ' -f 1)
printf 'RECORDING_OUTPUT_BUILD=pass seconds=%s artifact_sha256=%s\n' "$((SECONDS-build_started))" "$artifact_sha"
execution_started=$SECONDS
status=0
timeout --signal=TERM --kill-after=5s 30s "$test_executable" common::record::tests:: \
    --color never --test-threads=1 >"$WORK/native.log" 2>&1 || status=$?
cat "$WORK/native.log"
if [ "$status" -ne 0 ]; then
    tail -c 16000 "$WORK/native.log" | sed 's/^/RECORDING_OUTPUT_FAILURE=/'
fi
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
execution_seconds=$((SECONDS-execution_started))
if [ "$status" -ne 0 ]; then
    printf 'RECORDING_OUTPUT_ARTIFACT=complete sha256=%s executable=%s tests=32 exit_code=%s unchanged=before-after execution_seconds=%s\n' \
        "$artifact_sha" "$test_executable" "$status" "$execution_seconds"
    exit "$status"
fi
parent_started=$SECONDS
printf 'RECORDING_OUTPUT_PARENT_BUILD=started target=linux-libcheck tier=integration budget_seconds=180\n'
parent_status=0
timeout --signal=TERM --kill-after=5s 180s \
    cargo check --offline --locked --lib --features linux-pkg-config \
    --message-format=json --color never >"$WORK/parent-check.json" || parent_status=$?
if [ "$parent_status" -ne 0 ]; then
    tail -c 16000 "$WORK/parent-check.json" >&2
    exit "$parent_status"
fi
python3 -I -S - "$WORK/parent-check.json" <<'PY'
import json,sys
with open(sys.argv[1], 'rb') as stream:
    output=stream.read(4*1024*1024+1)
if len(output)>4*1024*1024:
    sys.exit('Recording parent-check metadata exceeds bound')
finished=[];parents=[]
for line in output.splitlines():
    if not line.startswith(b'{'): continue
    value=json.loads(line)
    if value.get('reason')=='build-finished': finished.append(value.get('success'))
    if (value.get('reason')=='compiler-artifact' and value.get('manifest_path')=='/source/Cargo.toml'
            and value.get('target',{}).get('name')=='librustdesk'
            and value.get('target',{}).get('src_path')=='/source/src/lib.rs'
            and value.get('profile',{}).get('test') is False):
        parents.append(value)
if finished != [True] or len(parents)!=1:
    sys.exit('Recording check lacks one exact successful production parent')
print('RECORDING_OUTPUT_PARENT_CHECK=pass target=librustdesk features=linux-pkg-config runtime=unexecuted')
PY
printf 'RECORDING_OUTPUT_PARENT_BUILD=pass seconds=%s\n' "$((SECONDS-parent_started))"
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'RECORDING_OUTPUT_ARTIFACT=complete sha256=%s executable=%s tests=32 exit_code=%s unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$status" "$execution_seconds"
exit "$status"

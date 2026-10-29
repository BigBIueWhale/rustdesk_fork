#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$PWD" = /source ] && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'PAKE timing entry differs' >&2; exit 1; }
case "$#:${1:-}" in
    0:) allocation_probe=0 ;;
    1:--allocation) allocation_probe=1 ;;
    *) exit 2 ;;
esac
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 RUSTFLAGS='-C target-cpu=x86-64'
unset CARGO_ENCODED_RUSTFLAGS
if [ "$allocation_probe" -eq 1 ]; then
    export RUSTFLAGS="$RUSTFLAGS --cfg pake_allocation_probe"
    printf 'PAKE_ALLOCATION_BUILD=observer=thread-local counts=alloc-realloc source=production cfg=pake_allocation_probe\n'
fi
rustc -vV | sed 's/^/PAKE_TIMING_COMPILER=/'
cargo tree --offline --locked -p pake -e features --prefix none | sed 's/^/PAKE_TIMING_DEPENDENCY=/'
printf 'PAKE_TIMING_BUILD=release opt=3 lto=true codegen_units=1 debug=0 target_cpu=x86-64 test_panic=unwind lock_sha256=%s\n' \
    "$(sha256sum Cargo.lock | cut -d ' ' -f 1)"
cargo test --offline --locked --release -p pake --lib --no-run \
    --message-format=json-render-diagnostics >/cargo-target/pake-timing-build.json
test_executable="$(python3 -I -S - <<'PY'
import json,re,sys
from pathlib import Path
raw=Path('/cargo-target/pake-timing-build.json').read_bytes()
assert len(raw)<=4*1024*1024
messages=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
assert [m.get('success') for m in messages if m.get('reason')=='build-finished']==[True]
backend=[m for m in messages if m.get('reason')=='build-script-executed'
         and 'curve25519-dalek' in m.get('package_id','')]
assert len(backend)==1
print('PAKE_TIMING_BACKEND='+json.dumps({key:backend[0][key]
      for key in ('package_id','cfgs','env')},sort_keys=True),file=sys.stderr)
artifacts=[m for m in messages if m.get('reason')=='compiler-artifact'
           and m.get('manifest_path')=='/source/libs/pake/Cargo.toml'
           and m.get('target',{}).get('name')=='pake'
           and m.get('target',{}).get('kind')==['lib']
           and m.get('target',{}).get('src_path')=='/source/libs/pake/src/lib.rs'
           and m.get('profile',{}).get('test') is True]
assert len(artifacts)==1
artifact=artifacts[0]
assert artifact['profile']['opt_level']=='3' and not artifact['profile']['debug_assertions']
assert re.fullmatch('/cargo-target/release/deps/pake-[0-9a-f]{16}',artifact['executable'])
print(artifact['executable'])
PY
)"
[ -f "$test_executable" ] && [ ! -L "$test_executable" ] && [ -x "$test_executable" ] \
    && [ "$(stat -c '%u:%g:%h' "$test_executable")" = 1000:1000:1 ]
cpu="$(python3 -I -S -c 'import os; print(min(os.sched_getaffinity(0)))')"
python3 -I -S - "$cpu" <<'PY'
import json,platform,sys
from pathlib import Path
cpu=Path('/proc/cpuinfo').read_text().split('\n\n')[0]
fields=dict(line.split(':',1) for line in cpu.splitlines() if ':' in line)
fields={k.strip():v.strip() for k,v in fields.items()}
print('PAKE_TIMING_MACHINE='+json.dumps({'kernel':platform.release(),'machine':platform.machine(),
 'guest_cpu':int(sys.argv[1]),'model':fields.get('model name'),'microcode':fields.get('microcode'),
 'flags':fields.get('flags'),'clock':'std::time::Instant','host_affinity':'uncontrolled'},sort_keys=True))
PY
artifact_sha="$(sha256sum "$test_executable" | cut -d ' ' -f 1)"
printf 'PAKE_TIMING_ARTIFACT_BEFORE=sha256=%s\n' "$artifact_sha"
if [ "$allocation_probe" -eq 1 ]; then
    timeout --signal=TERM --kill-after=5s 30s taskset -c "$cpu" "$test_executable" tests:: \
        --skip nfc_normalization_tests:: --skip timing_tests:: --test-threads=1 --color never --show-output
    timeout --signal=TERM --kill-after=5s 30s taskset -c "$cpu" "$test_executable" \
        --exact allocation_probe::no_transient_secret_heap_copies --test-threads=1 --color never --show-output
    [ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
    printf 'PAKE_ALLOCATION_ARTIFACT=pass sha256=%s tests=18 optimized=true unchanged=before-after\n' "$artifact_sha"
    exit 0
fi
timeout --signal=TERM --kill-after=5s 90s taskset -c "$cpu" "$test_executable" \
    --exact timing_tests::optimized_timing_evidence --ignored --test-threads=1 --color never --show-output
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'PAKE_TIMING_ARTIFACT=pass sha256=%s tests=1 optimized=true unchanged=before-after\n' "$artifact_sha"

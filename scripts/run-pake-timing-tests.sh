#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$PWD" = /source ] && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'PAKE timing entry differs' >&2; exit 1; }
allocation_probe=0
backend_comparison=
case "$#:${1:-}" in
    0:) ;;
    1:--allocation) allocation_probe=1 ;;
    1:--backend-default) backend_comparison=default ;;
    1:--backend-serial) backend_comparison=serial ;;
    *) exit 2 ;;
esac
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 RUSTFLAGS='-C target-cpu=x86-64'
unset CARGO_ENCODED_RUSTFLAGS
if [ "$backend_comparison" = serial ]; then
    export RUSTFLAGS="$RUSTFLAGS --cfg curve25519_dalek_backend=\"serial\""
fi
if [ -n "$backend_comparison" ]; then
    printf 'PAKE_TIMING_BACKEND_COMPARISON=selection:%s\n' "$backend_comparison"
fi
if [ "$allocation_probe" -eq 1 ]; then
    bash -n scripts/verify.sh
    export RUSTFLAGS="$RUSTFLAGS --cfg pake_allocation_probe"
    printf 'PAKE_ALLOCATION_BUILD=observer=thread-local counts=alloc-realloc source=production cfg=pake_allocation_probe\n'
else
    mkdir -m 700 /cargo-target/pake-linker
    cat > /cargo-target/pake-linker/cc <<'CC'
#!/bin/bash
set -euo pipefail
for argument in "$@"; do
    case "$argument" in
        /cargo-target/release/deps/pake-????????????????)
            exec /usr/bin/cc "$@" -Wl,-Map=/cargo-target/pake-timing.map ;;
    esac
done
exec /usr/bin/cc "$@"
CC
    chmod 700 /cargo-target/pake-linker/cc
    export PATH="/cargo-target/pake-linker:$PATH"
    printf 'PAKE_TIMING_LINK_MAP=driver=/usr/bin/cc output=/cargo-target/pake-timing.map strip=unchanged\n'
fi
rustc -vV | sed 's/^/PAKE_TIMING_COMPILER=/'
cargo tree --offline --locked -p pake -e features --prefix none | sed 's/^/PAKE_TIMING_DEPENDENCY=/'
printf 'PAKE_TIMING_BUILD=release opt=3 lto=true codegen_units=1 debug=0 target_cpu=x86-64 test_panic=unwind lock_sha256=%s\n' \
    "$(sha256sum Cargo.lock | cut -d ' ' -f 1)"
cargo test --offline --locked --release -p pake --lib --no-run \
    --message-format=json-render-diagnostics >/cargo-target/pake-timing-build.json
test_executable="$(python3 -I -S - "$backend_comparison" <<'PY'
import json,re,sys
from pathlib import Path
raw=Path('/cargo-target/pake-timing-build.json').read_bytes()
assert len(raw)<=4*1024*1024
messages=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
assert [m.get('success') for m in messages if m.get('reason')=='build-finished']==[True]
backend=[m for m in messages if m.get('reason')=='build-script-executed'
         and 'curve25519-dalek' in m.get('package_id','')]
assert len(backend)==1
expected='serial' if sys.argv[1]=='serial' else 'simd'
assert f'curve25519_dalek_backend="{expected}"' in backend[0]['cfgs']
assert 'curve25519_dalek_bits="64"' in backend[0]['cfgs']
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
    printf 'PAKE_ALLOCATION_ARTIFACT=pass sha256=%s tests=21 optimized=true unchanged=before-after\n' "$artifact_sha"
    exit 0
fi
python3 -I -S - "$test_executable" "$backend_comparison" <<'PY'
import base64,hashlib,json,re,subprocess,sys,zlib
from pathlib import Path
artifact=sys.argv[1]
map_bytes=Path('/cargo-target/pake-timing.map').read_bytes()
assert len(map_bytes)<=4*1024*1024
sections=[(int(address,16),int(size,16),name) for name,address,size in
    re.findall(r'(?m)^ \.text\.(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s',map_bytes.decode())
    if int(address,16)>0 and int(size,16)>0]
def edwards_mul(name):
    return ('edwards..EdwardsPoint$u20$as$u20$core..ops..arith..Mul' in name
            and 'scalar..Scalar' in name)
selected=[entry for entry in sections if (edwards_mul(entry[2]) if sys.argv[2]=='serial'
    else all(part in entry[2] for part in ('variable_base','spec_avx2','3mul')))]
assert len(selected)==1, ('multiplication symbol count',selected)
if sys.argv[2]=='serial':
    assert not any('spec_avx' in name or 'cpuid_avx' in name for _,_,name in sections)
related=[entry for entry in sections if any(part in entry[2] for part in
    ('from_bytes_mod_order_wide','montgomery_mul','cpuid_avx2','subtle9black_box','McdtStatusScope'))
    or edwards_mul(entry[2])
    or ('avx2..field..FieldElement2625x4' in entry[2] and '9_impl_mul' in entry[2])
    or ('ristretto..RistrettoPoint' in entry[2] and '7zeroize' in entry[2])
    or (sys.argv[2]=='serial' and (
        ('serial..u64..field..FieldElement51' in entry[2] and '3mul' in entry[2])
        or 'FieldElement515pow2k' in entry[2] or 'ProjectivePoint6double' in entry[2]
        or ('ProjectiveNielsPoint' in entry[2] and '3add' in entry[2])
        or ('LookupTable' in entry[2] and '6select' in entry[2])))]
related=[entry for entry in related if entry!=selected[0]]
assert 5<=len(related)<=16
def disassemble(entry):
    start,size,name=entry
    assert 0<size<=64*1024
    assembly=subprocess.check_output(['objdump','-d','--demangle',
        '--start-address='+str(start),'--stop-address='+str(start+size),artifact],timeout=10)
    assert 0<len(assembly)<=1024*1024
    encoded=base64.b64encode(zlib.compress(assembly,9)).decode()
    assert len(encoded)<=128*1024
    return {'symbol':name,'address':start,'code_bytes':size,'text_bytes':len(assembly),
        'text_sha256':hashlib.sha256(assembly).hexdigest(),'encoding':'zlib-base64','data':encoded}
record=disassemble(selected[0])
record['related']=[disassemble(entry) for entry in related]
assert sum(len(item['data']) for item in [record,*record['related']])<=256*1024
version=subprocess.check_output(['objdump','--version'],timeout=10).decode().splitlines()[0]
relocations=subprocess.check_output(['objdump','-R',artifact],timeout=10)
assert len(relocations)<=4*1024*1024
copy_relocations=[line for line in relocations.decode().splitlines()
    if re.search(r'\s(?:memcpy|memmove|memset)(?:@|$)',line)]
assert 1<=len(copy_relocations)<=8 and sum(map(len,copy_relocations))<=2048
record.update({
    'link_map_sha256':hashlib.sha256(map_bytes).hexdigest(),
    'backend_comparison':sys.argv[2],
    'copy_relocations':copy_relocations,
    'dalek_symbols':[entry for entry in sections if 'curve25519_dalek' in entry[2]],
    'objdump':version})
print('PAKE_TIMING_DISASSEMBLY='+json.dumps(record,sort_keys=True))
PY
test_status=0
timing_test=optimized_timing_evidence
if [ -n "$backend_comparison" ]; then
    timing_test=backend_long_timing_evidence
    timeout --signal=TERM --kill-after=5s 30s taskset -c "$cpu" "$test_executable" tests:: \
        --skip nfc_normalization_tests:: --skip timing_tests:: --test-threads=1 --color never --show-output \
        || test_status=$?
fi
if [ "$test_status" -eq 0 ]; then
    timeout --signal=TERM --kill-after=5s 150s taskset -c "$cpu" "$test_executable" \
        --exact "timing_tests::$timing_test" --ignored --test-threads=1 --color never --show-output \
        || test_status=$?
fi
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'PAKE_TIMING_ARTIFACT_AFTER=sha256=%s test_exit=%s unchanged=true\n' "$artifact_sha" "$test_status"
[ "$test_status" -eq 0 ] || exit "$test_status"
if [ -n "$backend_comparison" ]; then
    printf 'PAKE_TIMING_BACKEND_ARTIFACT=pass selection=%s sha256=%s tests=21 optimized=true unchanged=before-after\n' \
        "$backend_comparison" "$artifact_sha"
    exit 0
fi
printf 'PAKE_TIMING_ARTIFACT=pass sha256=%s tests=1 optimized=true unchanged=before-after\n' "$artifact_sha"

#!/usr/bin/env python3
"""Check real capture metadata under a one-shot allocation refusal."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

assert len(sys.argv) == 2 and os.getuid() == os.getgid() == 1000
assert Path.cwd() == Path('/source')
executable = Path(sys.argv[1])
assert re.fullmatch(r'/cargo-target/debug/deps/scrap-[0-9a-f]{16}', str(executable))
metadata = executable.lstat()
assert stat.S_ISREG(metadata.st_mode)
assert (metadata.st_uid, metadata.st_gid, metadata.st_nlink) == (1000, 1000, 1)
artifact_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
passed = 0
for operation, name, allocation_bytes in (
        ('construct', 'construction_needs_no_allocation', 32),
        ('read', 'stride_read_needs_no_allocation', 8),
        ('convert', 'warmed_yuv_conversion_needs_no_allocation', 70),
        ('format', 'encoder_format_snapshot_and_frame_conversion_need_no_allocation', 32)):
    case = 'capture_metadata_tests::' + name
    result = subprocess.run([str(executable), '--exact', case, '--format', 'terse',
                             '--test-threads=1', '--show-output'],
                            capture_output=True, text=True, timeout=15)
    assert len(result.stdout) + len(result.stderr) <= 16384
    print(result.stdout, end='', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='', flush=True)
    if result.returncode == -6:
        assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == 1
        assert result.stderr == f'memory allocation of {allocation_bytes} bytes failed\n'
        print(f'CAPTURE_METADATA_RESULT=observed operation={operation} child_exit=-6 '
              f'refused_bytes={allocation_bytes} artifact_sha256={artifact_sha} children=joined', flush=True)
        continue
    assert result.returncode == 0 and not result.stderr
    assert 'VIDEO_ALLOCATOR=refused' not in result.stdout
    assert result.stdout.count('test result: ok. 1 passed; 0 failed;') == 1
    if operation == 'convert':
        details = 'combinations=9 allocations=0 pixels=exact unsupported=3'
    elif operation == 'format':
        details = 'combinations=3 allocations=0 pixels=exact samples=6528 snapshot=preserved'
    else:
        details = 'stride=16 allocations=0 pixels=exact'
    assert result.stdout.count(f'CAPTURE_METADATA_NATIVE=pass operation={operation} {details}\n') == 1
    if operation == 'convert':
        cases = re.findall(r'^CAPTURE_YUV_CASE=pass (.+)$', result.stdout, re.MULTILINE)
        expected = {f'source={source} destination={destination} pixels=exact allocation=unused'
                    for source in ('BGRA', 'RGBA', 'RGB565LE') for destination in ('I420', 'NV12', 'I444')}
        assert len(cases) == len(set(cases)) == 9 and set(cases) == expected
    elif operation == 'format':
        cases = re.findall(r'^CAPTURE_ENCODER_CASE=pass (.+)$', result.stdout, re.MULTILINE)
        expected = {f'codec={codec} i444={chroma} snapshot=preserved allocations=0 pixels=exact samples={samples}'
                    for codec, chroma, samples in [('VP8', 'false', 1632), ('VP9', 'false', 1632), ('VP9', 'true', 3264)]}
        assert len(cases) == len(set(cases)) == 3 and set(cases) == expected
    print(f'CAPTURE_METADATA_RESULT=pass operation={operation} {details} '
          f'artifact_sha256={artifact_sha} children=joined', flush=True)
    passed += 1
assert hashlib.sha256(executable.read_bytes()).hexdigest() == artifact_sha
sys.exit(0 if passed == 4 else 1)

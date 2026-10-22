#!/usr/bin/env python3
"""Check native capture metadata, plane layout and fallible conversion storage."""
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
        ('format', 'encoder_format_snapshot_and_frame_conversion_need_no_allocation', 32),
        ('layout', 'plane_layout_is_checked_and_v_stride_is_independent', None),
        ('output', 'output_allocation_failures_preserve_buffers_and_retry', 32),
        ('intermediate', 'intermediate_allocation_failures_preserve_buffers_and_retry', 24)):
    module = 'yuv_storage_tests::' if operation in ('layout', 'output', 'intermediate') else 'capture_metadata_tests::'
    case = module + name
    result = subprocess.run([str(executable), '--exact', case, '--format', 'terse',
                             '--test-threads=1', '--show-output'],
                            capture_output=True, text=True, timeout=15)
    assert len(result.stdout) + len(result.stderr) <= 16384
    print(result.stdout, end='', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='', flush=True)
    if operation == 'layout' and result.returncode == 101:
        assert result.stdout.count('test result: FAILED. 0 passed; 1 failed;') == 1
        assert case in result.stdout
        assert result.stdout.count('CAPTURE_LAYOUT_OBSERVED=v_plane stride_u=4 stride_v=8 first=128 second=165\n') == 1
        print(f'CAPTURE_METADATA_RESULT=observed operation=layout child_exit=101 '
              f'independent_v_stride=false artifact_sha256={artifact_sha} children=joined', flush=True)
        continue
    if result.returncode == -6:
        assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == 1
        assert result.stderr == f'memory allocation of {allocation_bytes} bytes failed\n'
        print(f'CAPTURE_METADATA_RESULT=observed operation={operation} child_exit=-6 '
              f'refused_bytes={allocation_bytes} artifact_sha256={artifact_sha} children=joined', flush=True)
        continue
    assert result.returncode == 0 and not result.stderr
    refusals = {'output': 9, 'intermediate': 3}.get(operation, 0)
    assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == refusals
    assert result.stdout.count('test result: ok. 1 passed; 0 failed;') == 1
    if operation == 'convert':
        details = 'combinations=9 allocations=0 pixels=exact unsupported=3'
    elif operation == 'format':
        details = 'combinations=3 allocations=0 pixels=exact samples=6528 snapshot=preserved'
    elif operation == 'layout':
        details = 'independent_v_stride=true invalid=19 storage_bytes=56 pixels=exact state=preserved'
    elif operation in ('output', 'intermediate'):
        details = (f'combinations={refusals} refusals={refusals} pixels=exact '
                   f'state=preserved retries={refusals} warmed=allocation-free')
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
        encoded = re.findall(r'^CAPTURE_ENCODER_ENCODE=pass codec=(VP8|VP9) i444=(false|true) '
                             r'dimensions=34x32 pixels=1088 alpha=255 max_error=([0-3])$', result.stdout, re.MULTILINE)
        assert len(encoded) == 3 and {(codec, chroma) for codec, chroma, _ in encoded} == {
            ('VP8', 'false'), ('VP9', 'false'), ('VP9', 'true')}
    elif operation == 'layout':
        cases = re.findall(r'^CAPTURE_LAYOUT_REFUSAL=pass case=([a-z0-9-]+) buffers=preserved outcome=error$',
                           result.stdout, re.MULTILINE)
        expected = {'zero-width', 'zero-height', 'narrow-destination', 'short-destination',
                    'short-y-stride', 'short-u-stride', 'short-v-stride', 'overlapping-y-u',
                    'overlapping-u-v', 'u-offset-overflow', 'v-offset-overflow',
                    'width-outside-native-int', 'height-outside-native-int', 'stride-outside-native-int',
                    'short-nv12-stride', 'short-i444-stride', 'zero-buffer-length',
                    'short-buffer-length', 'buffer-length-outside-address-space'}
        assert len(cases) == len(set(cases)) == 19 and set(cases) == expected
    elif operation in ('output', 'intermediate'):
        cases = re.findall(r'^CAPTURE_STORAGE_CASE=pass stage=' + operation + r' (.+)$', result.stdout, re.MULTILINE)
        pairs = ([(source, destination) for source in ('BGRA', 'RGBA', 'RGB565LE')
                  for destination in ('I420', 'NV12', 'I444')] if operation == 'output' else
                 [('RGB565LE', 'NV12'), ('RGBA', 'I444'), ('RGB565LE', 'I444')])
        expected = {f'source={source} destination={destination} state=preserved retry=pass warmed=allocation-free'
                    for source, destination in pairs}
        assert len(cases) == len(set(cases)) == len(expected) and set(cases) == expected
    print(f'CAPTURE_METADATA_RESULT=pass operation={operation} {details} '
          f'artifact_sha256={artifact_sha} children=joined', flush=True)
    passed += 1
assert hashlib.sha256(executable.read_bytes()).hexdigest() == artifact_sha
sys.exit(0 if passed == 7 else 1)

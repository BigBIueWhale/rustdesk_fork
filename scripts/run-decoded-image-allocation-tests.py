#!/usr/bin/env python3
"""Run real decoded-image allocation failures in separately owned native children."""
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
for warmed, name in ((False, 'decoded_image_allocation_failure_preserves_output_and_retries'),
                     (True, 'warmed_decoded_image_conversion_needs_no_allocation')):
    case = 'decoded_image_tests::' + name
    result = subprocess.run([str(executable), '--exact', case, '--format', 'terse',
                             '--test-threads=1', '--show-output'],
                            capture_output=True, text=True, timeout=15)
    assert len(result.stdout) + len(result.stderr) <= 16384
    print(result.stdout, end='', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='', flush=True)
    warmed_text = str(warmed).lower()
    if result.returncode == -6:
        assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == 1
        sizes = re.findall(r'memory allocation of ([0-9]+) bytes failed', result.stderr)
        assert len(sizes) == 1 and int(sizes[0]) == (16 if warmed else 4352)
        print(f'VIDEO_RGB_ALLOC_RESULT=observed warmed={warmed_text} child_exit=-6 '
              f'refused_bytes={sizes[0]} artifact_sha256={artifact_sha} children=joined', flush=True)
        continue
    assert result.returncode == 0 and not result.stderr
    refusals = 0 if warmed else 12
    assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == refusals
    assert result.stdout.count('test result: ok. 1 passed; 0 failed;') == 1
    assert result.stdout.count(f'VIDEO_RGB_ALLOC_NATIVE=pass warmed={warmed_text} combinations=12 '
                               f'refusals={refusals} pixels=exact state=preserved\n') == 1
    cases = re.findall(r'^VIDEO_RGB_ALLOC_CASE=pass (.+)$', result.stdout, re.MULTILINE)
    expected = {f'codec={codec} i444={chroma} format={pixel_format} alignment={alignment} '
                f'warmed={warmed_text} pixels=exact state=preserved'
                for codec, chroma in [('VP8', 'false'), ('VP9', 'false'), ('VP9', 'true')]
                for pixel_format in ['ARGB', 'ABGR'] for alignment in [0, 64]}
    assert len(cases) == len(set(cases)) == 12 and set(cases) == expected
    print(f'VIDEO_RGB_ALLOC_RESULT=pass warmed={warmed_text} combinations=12 refusals={refusals} '
          f'pixels=exact state=preserved artifact_sha256={artifact_sha} children=joined', flush=True)
    passed += 1
assert hashlib.sha256(executable.read_bytes()).hexdigest() == artifact_sha
sys.exit(0 if passed == 2 else 1)

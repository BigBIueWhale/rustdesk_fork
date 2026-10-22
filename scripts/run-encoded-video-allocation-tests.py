#!/usr/bin/env python3
"""Observe native packet-storage refusal and decoder recovery in one owned child."""
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
case = ('common::vpxcodec::encoded_video_tests::'
        'message_allocation_failure_recovers_current_pixels_with_keyframe')
result = subprocess.run([str(executable), '--exact', case, '--format', 'terse',
                         '--test-threads=1', '--show-output'],
                        capture_output=True, text=True, timeout=15)
assert len(result.stdout) + len(result.stderr) <= 16384
print(result.stdout, end='', flush=True)
if result.stderr:
    print(result.stderr, file=sys.stderr, end='', flush=True)
assert hashlib.sha256(executable.read_bytes()).hexdigest() == artifact_sha
if result.returncode == -6:
    assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == 1
    assert result.stdout.count('VIDEO_MESSAGE_ALLOC_ATTEMPT=observed ') == 1
    sizes = re.findall(r'memory allocation of ([0-9]+) bytes failed', result.stderr)
    assert len(sizes) == 1 and 0 < int(sizes[0]) <= 64 * 1024 * 1024
    print(f'VIDEO_MESSAGE_ALLOC_RESULT=observed child_exit=-6 refused_bytes={sizes[0]} '
          f'artifact_sha256={artifact_sha} children=joined', flush=True)
    sys.exit(1)
assert result.returncode == 0 and not result.stderr
assert result.stdout.count('VIDEO_ALLOCATOR=refused\n') == 9
assert result.stdout.count('test result: ok. 1 passed; 0 failed;') == 1
cases = re.findall(r'^VIDEO_MESSAGE_ALLOC_CASE=pass (.+)$', result.stdout, re.MULTILINE)
expected = {f'codec={codec} i444={i444} cycle={cycle} refused=TryReserveError '
            f'recovery_key=true fresh_decoder=true next_key=false pixels=checked'
            for codec, i444 in [('VP8', 'false'), ('VP9', 'false'), ('VP9', 'true')]
            for cycle in range(3)}
assert len(cases) == len(set(cases)) == 9 and set(cases) == expected
assert result.stdout.count('VIDEO_MESSAGE_ALLOC_NATIVE=pass combinations=3 refusals=9 '
                           'recoveries=9 next_nonkeys=9 decoded=30 pixels=30720 tail=0\n') == 1
print(f'VIDEO_MESSAGE_ALLOC_RESULT=pass combinations=3 refusals=9 recoveries=9 '
      f'next_nonkeys=9 decoded=30 pixels=30720 tail=0 '
      f'artifact_sha256={artifact_sha} children=joined', flush=True)

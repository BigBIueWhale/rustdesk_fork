#!/usr/bin/env python3
"""Run the actual Android parent-library scroll regression in the owned emulator."""

import hashlib
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys


def main():
    if len(sys.argv) != 4 or (os.getuid(), os.getgid()) != (1000, 1000):
        raise ValueError('expected the isolated nonroot emulator invocation')
    adb, serial, work = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    if not work.is_dir() or work.is_symlink() or not re.fullmatch(r'emulator-[0-9]+', serial):
        raise ValueError('emulator work identity differs')
    binary = Path('/inputs/android-scroll-tests')
    cpp = Path('/inputs/libc++_shared.so')
    identities = {}
    for path, maximum in [(binary, 256 * 1024**2), (cpp, 16 * 1024**2)]:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000
                or info.st_nlink != 1 or not 0 < info.st_size < maximum):
            raise ValueError('native test input identity differs')
        identities[path] = hashlib.sha256(path.read_bytes()).hexdigest()

    def command(*args, timeout=15):
        result = subprocess.run([adb, '-s', serial, *args], check=True,
                                capture_output=True, timeout=timeout)
        if len(result.stdout) + len(result.stderr) > 8192:
            raise ValueError('ADB control output exceeds bound')
        return result.stdout.decode().strip().replace('\r', '')

    remote = command('shell', 'mktemp', '-d', '/data/local/tmp/rustdesk-scroll.XXXXXXXXXX')
    if not re.fullmatch(r'/data/local/tmp/rustdesk-scroll\.[A-Za-z0-9]{10}', remote):
        raise ValueError('native test workspace differs')
    metadata = command('shell', 'stat', '-c', '%u:%g:%a:%d:%i', remote)
    if not re.fullmatch(r'2000:2000:700:[0-9]+:[0-9]+', metadata):
        raise ValueError('native test workspace authority differs')
    for source, name in [(binary, 'scroll-tests'), (cpp, 'libc++_shared.so')]:
        command('push', str(source), remote + '/' + name, timeout=30)
        command('shell', 'chmod', '500' if source == binary else '400', remote + '/' + name)
        digest = command('shell', 'sha256sum', remote + '/' + name).split()[0]
        if digest != identities[source]:
            raise ValueError('staged Android input digest differs')

    output = work / 'scroll-tests.out'
    def limit_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    # A normally returned shell command has reaped the exact libtest process. If
    # transport/timeout fails, preserve this directory for emulator/VM retirement.
    with output.open('xb') as log:
        completed = subprocess.run([
            adb, '-s', serial, 'shell',
            f'LD_LIBRARY_PATH={remote} RUSTDESK_SCROLL_TEST_ROOT={remote} '
            f'{remote}/scroll-tests '
            'ui_session_interface::scroll_direction_tests::saved_preference_controls_emitted_scroll_commands '
            '--exact --nocapture --test-threads=1',
        ], stdout=log, stderr=subprocess.STDOUT, timeout=30, preexec_fn=limit_output)
    text = output.read_text().replace('\r', '')
    if len(text) >= 65536:
        raise ValueError('native test output reached its ceiling')
    print(text, end='', flush=True)
    if command('shell', 'stat', '-c', '%u:%g:%a:%d:%i', remote) != metadata:
        raise ValueError('native test workspace changed')
    for source, name in [(binary, 'scroll-tests'), (cpp, 'libc++_shared.so')]:
        if (hashlib.sha256(source.read_bytes()).hexdigest() != identities[source]
                or command('shell', 'sha256sum', remote + '/' + name).split()[0] != identities[source]):
            raise ValueError('native test input changed')
    command('shell', 'rm', '-rf', remote)
    absent = subprocess.run([adb, '-s', serial, 'shell', 'test', '!', '-e', remote],
                            capture_output=True, timeout=15)
    if absent.returncode != 0:
        raise ValueError('native test workspace survived cleanup')
    print(f'ANDROID_SCROLL_TEST_EXIT code={completed.returncode} cleanup=removed', flush=True)
    if completed.returncode != 0:
        raise ValueError('production scroll regression failed')
    expected = [
        f'SCROLL_DIRECTION_PHASE phase={phase} reversed={reverse} commands=18 mismatches=0'
        for phase, reverse in enumerate(('false', 'true', 'false'))
    ]
    observed = [line for line in text.splitlines() if line.startswith('SCROLL_DIRECTION_PHASE ')]
    # libtest may prefix the first nocapture line with its test name.
    first = expected[0]
    if len(observed) == 2 and text.count(first) == 1:
        observed.insert(0, first)
    if (observed != expected
            or text.count('SCROLL_DIRECTION_NATIVE target=android commands=54 mismatches=0 peer=absent channel=retired') != 1
            or 'test result: ok. 1 passed; 0 failed;' not in text):
        raise ValueError('native test result is absent or incomplete')
    print('ANDROID_SCROLL_TEST_NATIVE=pass target=android commands=54 phases=3 '
          f'binary_sha256={identities[binary]} cleanup=removed', flush=True)


if __name__ == '__main__':
    main()

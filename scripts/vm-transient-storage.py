#!/usr/bin/env python3
"""Ordinary-user RAM scratch admission and monitoring for owned QEMU runs."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import tempfile
import time

GIB = 1024 ** 3
SCRATCH_LIMIT = 16 * GIB
HEADROOM = 6 * GIB
OVERHEAD = GIB


def require(condition, message):
    if not condition:
        raise ValueError(message)


def available_memory():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise ValueError('MemAvailable is unavailable')


def tmpfs_root():
    require(os.geteuid() != 0 and os.getegid() != 0, 'host root is forbidden')
    mount = Path('/dev/shm')
    metadata = mount.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o1777 and mount.resolve() == mount,
            '/dev/shm authority differs')
    result = subprocess.run(['/usr/bin/findmnt', '-rn', '-o', 'TARGET,FSTYPE',
                             '--target', str(mount)], check=True, capture_output=True,
                            text=True, timeout=5)
    require(result.stdout.split() == ['/dev/shm', 'tmpfs'],
            'VM scratch requires the existing /dev/shm tmpfs; disk fallback is forbidden')
    return mount


def preflight(memory_mib):
    mount = tmpfs_root()
    required = memory_mib * 1024 ** 2 + SCRATCH_LIMIT + HEADROOM + OVERHEAD
    available = available_memory()
    require(available >= required,
            f'VM refused: RAM requires {required // 1024 ** 2} MiB including scratch '
            f'and headroom; only {available // 1024 ** 2} MiB available')
    filesystem = os.statvfs(mount)
    require(filesystem.f_bavail * filesystem.f_frsize >= SCRATCH_LIMIT + OVERHEAD,
            'VM refused: /dev/shm has insufficient capacity for bounded scratch')
    return mount


def private_directory(path, expected=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        require((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
                == (os.geteuid(), os.getegid(), 0o700), 'RAM scratch ownership differs')
        require(Path(path).resolve() == Path(path), 'RAM scratch path is not canonical')
        if expected is not None:
            require(f'{metadata.st_dev}:{metadata.st_ino}' == expected,
                    'RAM scratch creation identity differs')
        require(metadata.st_dev == Path('/dev/shm').stat().st_dev,
                'RAM scratch left the authenticated tmpfs')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def reserve(memory_mib):
    mount = preflight(memory_mib)
    root = mount / f'rustdesk-fork-vm-{os.geteuid()}'
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = private_directory(root)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not os.listdir(descriptor),
                f'earlier RAM workspace remains at {root}; reconcile its exact owners first')
        workspace = Path(tempfile.mkdtemp(prefix='run.', dir=root))
        metadata = workspace.stat()
        print(workspace)
        print(f'{metadata.st_dev}:{metadata.st_ino}')
    finally:
        os.close(descriptor)


def allocation(path):
    total = 0
    entries = 0
    for directory, children, files in os.walk(path, followlinks=False):
        for name in children + files:
            entries += 1
            require(entries <= 256, 'RAM scratch inventory exceeds its bound')
            metadata = (Path(directory) / name).lstat()
            require(metadata.st_dev == Path(path).stat().st_dev
                    and metadata.st_uid == os.geteuid()
                    and metadata.st_gid == os.getegid()
                    and (stat.S_ISDIR(metadata.st_mode)
                         or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)),
                    'RAM scratch contains an unexpected object')
            total += metadata.st_blocks * 512
    return total


def publish(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, sort_keys=True)
        output.write('\n')


def watch(args):
    tmpfs_root()
    descriptor = private_directory(args.workspace, args.identity)
    require(os.getppid() == args.parent, 'storage monitor is not the harness child')
    parent = os.pidfd_open(args.parent)
    poll = select.poll()
    poll.register(parent, select.POLLIN)
    began = time.monotonic()
    peak = 0
    overlay_peak = 0
    minimum_memory = available_memory()
    samples = 0
    qemu_identity = None
    qemu_write_bytes = 0
    reason = 'completed'
    try:
        publish(args.ready, {'workspace': args.workspace, 'identity': args.identity})
        while True:
            private = os.stat(args.workspace, follow_symlinks=False)
            require(f'{private.st_dev}:{private.st_ino}' == args.identity,
                    'live RAM workspace identity changed')
            used = allocation(args.workspace)
            peak = max(peak, used)
            overlay = Path(args.workspace) / 'overlay.qcow2'
            if overlay.exists():
                overlay_peak = max(overlay_peak, overlay.stat().st_blocks * 512)
            minimum_memory = min(minimum_memory, available_memory())
            samples += 1
            pidfile = Path(args.run) / 'qemu.pid'
            if pidfile.exists():
                metadata = pidfile.lstat()
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                        and metadata.st_uid == os.geteuid() and metadata.st_size <= 32,
                        'owned QEMU pidfile differs')
                value = pidfile.read_text().strip()
                if value.isdecimal():
                    process = Path('/proc') / value
                    try:
                        start = process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
                        current = (value, start)
                        if qemu_identity is None:
                            require(process.joinpath('exe').resolve()
                                    == Path('/usr/bin/qemu-system-x86_64'),
                                    'owned QEMU executable differs')
                            qemu_identity = current
                        if qemu_identity == current:
                            for line in process.joinpath('io').read_text().splitlines():
                                if line.startswith('write_bytes:'):
                                    qemu_write_bytes = max(qemu_write_bytes, int(line.split()[1]))
                    except (FileNotFoundError, ProcessLookupError):
                        pass
            if used > SCRATCH_LIMIT or minimum_memory < HEADROOM:
                reason = 'scratch-budget' if used > SCRATCH_LIMIT else 'memory-headroom'
                signal.pidfd_send_signal(parent, signal.SIGTERM)
                break
            if Path(args.stop).exists():
                break
            if poll.poll(100):
                reason = 'harness-owner-exited'
                break
    except BaseException as error:
        reason = f'{type(error).__name__}: {error}'
        if not poll.poll(0):
            signal.pidfd_send_signal(parent, signal.SIGTERM)
    finally:
        publish(args.receipt, {
            'storage': 'existing-/dev/shm-tmpfs', 'workspace': args.workspace,
            'identity': args.identity, 'scratch_limit_bytes': SCRATCH_LIMIT,
            'headroom_bytes': HEADROOM, 'guest_memory_mib': args.memory_mib,
            'peak_allocated_bytes': peak, 'overlay_peak_allocated_bytes': overlay_peak,
            'minimum_mem_available_bytes': minimum_memory, 'samples': samples,
            'observed_qemu_block_write_bytes': qemu_write_bytes,
            'elapsed_seconds': round(time.monotonic() - began, 3), 'reason': reason,
            'tmpfs_swap_disabled': False,
        })
        os.close(parent)
        os.close(descriptor)
    require(reason == 'completed', f'VM storage guard refused the run: {reason}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('preflight', 'reserve', 'check', 'watch'))
    parser.add_argument('--memory-mib', type=int, required=True)
    parser.add_argument('--workspace')
    parser.add_argument('--identity')
    parser.add_argument('--parent', type=int)
    parser.add_argument('--run')
    parser.add_argument('--ready')
    parser.add_argument('--stop')
    parser.add_argument('--receipt')
    args = parser.parse_args()
    require(2048 <= args.memory_mib <= 24576, 'guest memory is outside the fixed profile bounds')
    if args.operation == 'preflight':
        preflight(args.memory_mib)
    elif args.operation == 'reserve':
        reserve(args.memory_mib)
    elif args.operation == 'check':
        descriptor = private_directory(args.workspace, args.identity)
        try:
            # Only QEMU may write after this check. Its hard 8 GiB file limit
            # bounds the remaining growth independently of the polling monitor.
            require(allocation(args.workspace) <= SCRATCH_LIMIT - 8 * GIB,
                    'prepared inputs leave insufficient RAM overlay capacity')
            require(available_memory() >= args.memory_mib * 1024 ** 2 + HEADROOM + OVERHEAD,
                    'RAM headroom changed before QEMU launch')
        finally:
            os.close(descriptor)
    else:
        watch(args)


if __name__ == '__main__':
    main()

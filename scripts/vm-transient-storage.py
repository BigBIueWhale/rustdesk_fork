#!/usr/bin/env python3
"""Ordinary-user RAM scratch admission and monitoring for owned QEMU runs."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import resource
import socket
import stat
import subprocess
import tempfile
import time

GIB = 1024 ** 3
SCRATCH_LIMIT = 16 * GIB
HEADROOM = 6 * GIB
OVERHEAD = GIB


def storage_limits(profile, memory_mib):
    if profile == 'ledger-token-count':
        require(memory_mib == 2048, 'ledger storage profile requires its 2 GiB guest')
        # Preparation may provision the boot cache; the counting guest builds no artifacts.
        return 4 * GIB, GIB
    if profile == 'hbb-common-fs':
        require(memory_mib == 6144, 'filesystem storage profile requires its 6 GiB guest')
        return 6 * GIB, 4 * GIB
    if profile == 'cpace-recovery-tests':
        require(memory_mib == 8192, 'CPace storage profile requires its 8 GiB guest')
        return 6 * GIB, 4 * GIB
    if profile == 'flutter-credential-dialog':
        require(memory_mib == 4096, 'dialog storage profile requires its 4 GiB guest')
        return 7 * GIB, 6 * GIB
    if profile == 'linux-service-build':
        require(memory_mib == 8192, 'service build storage profile requires its 8 GiB guest')
        # Prepared inputs share one GiB beside the unchanged eight-GiB overlay ceiling.
        return 9 * GIB, 8 * GIB
    if profile == 'x11-focus':
        require(memory_mib == 4096, 'focus storage profile requires its 4 GiB guest')
        # The unchanged 8 GiB QEMU ceiling leaves at most 1 GiB for prepared media.
        return 9 * GIB, 8 * GIB
    if profile == 'linux-pa-playback':
        require(memory_mib == 4096, 'playback storage profile requires its 4 GiB guest')
        return 9 * GIB, 8 * GIB
    require(profile == 'standard', 'unknown VM storage profile')
    return SCRATCH_LIMIT, 8 * GIB


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


def preflight(memory_mib, profile='standard'):
    scratch_limit, _ = storage_limits(profile, memory_mib)
    mount = tmpfs_root()
    required = memory_mib * 1024 ** 2 + scratch_limit + HEADROOM + OVERHEAD
    available = available_memory()
    require(available >= required,
            f'VM refused: RAM requires {required // 1024 ** 2} MiB including scratch '
            f'and headroom; only {available // 1024 ** 2} MiB available')
    filesystem = os.statvfs(mount)
    require(filesystem.f_bavail * filesystem.f_frsize >= scratch_limit + OVERHEAD,
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


def reserve(memory_mib, profile='standard'):
    mount = preflight(memory_mib, profile)
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
            try:
                metadata = (Path(directory) / name).lstat()
            except FileNotFoundError:
                # Boot preparation retires its exact raw/partition files while
                # this observer samples the live workspace.
                continue
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


def qemu_output_receipt(run):
    try:
        descriptor = os.open(Path(run) / 'storage.qemu-io',
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
                == (os.geteuid(), os.getegid(), 0o600)
                and 0 < metadata.st_size <= 4096, 'QEMU output receipt authority differs')
        data = source.read(4097)
        require(len(data) == metadata.st_size, 'QEMU output receipt size differs')
    value = json.loads(data)
    require(isinstance(value, dict)
            and set(value) == {'qemu_pid', 'returncode', 'write_bytes'}
            and all(type(value[key]) is int for key in value),
            'QEMU output receipt shape differs')
    require(value['qemu_pid'] > 0 and -64 <= value['returncode'] <= 255
            and value['write_bytes'] >= 0 and value['write_bytes'] % 512 == 0,
            'QEMU output receipt values differ')
    return value


def run_qemu(args):
    _, overlay_limit = storage_limits(args.storage_profile, args.memory_mib)
    require(args.qemu and args.qemu[0] == '/usr/bin/qemu-system-x86_64',
            'storage supervisor requires the fixed QEMU executable')
    require(Path(args.qmp) == Path(args.run) / 'qmp.sock', 'QMP path differs')
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            'QEMU supervisor requires waitable children')
    # The shared guest RAM memfd must be sized before lowering RLIMIT_FSIZE.
    # -S prevents guest disk writes until the final hard limit is installed.
    initial_limit = max(overlay_limit, args.memory_mib * 1024 ** 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (initial_limit, initial_limit))
    output_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_oublock
    child = subprocess.Popen(args.qemu + ['-S'], close_fds=False)
    try:
        child_identity = os.pidfd_open(child.pid)
    except BaseException:
        child.kill()
        child.wait()
        raise
    cancelled = False

    def cancel(signum, frame):
        nonlocal cancelled
        cancelled = True
        try:
            signal.pidfd_send_signal(child_identity, signum)
        except ProcessLookupError:
            pass

    handlers = {s: signal.signal(s, cancel) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        deadline = time.monotonic() + 15
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(10)
            while True:
                require(not cancelled, 'QEMU startup cancelled')
                try:
                    metadata = Path(args.qmp).lstat()
                    require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid()
                            and metadata.st_gid == os.getegid()
                            and stat.S_IMODE(metadata.st_mode) & 0o077 == 0,
                            'QMP is not the owned private socket')
                    channel.connect(args.qmp)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    require(time.monotonic() < deadline, 'paused QEMU QMP startup timed out')
                    time.sleep(0.05)
            with channel.makefile('rb') as incoming:
                def receive():
                    line = incoming.readline(65537)
                    require(line.endswith(b'\n') and len(line) <= 65536, 'QMP frame differs')
                    value = json.loads(line)
                    require(isinstance(value, dict), 'QMP response is not an object')
                    return value

                def execute(name):
                    channel.sendall(json.dumps({'execute': name, 'id': name}).encode() + b'\n')
                    for _ in range(16):
                        value = receive()
                        if value.get('id') == name:
                            require('return' in value and 'error' not in value, 'QMP command failed')
                            return value['return']
                        require('event' in value, 'unexpected QMP response')
                    raise ValueError('QMP event budget exceeded')

                require('QMP' in receive(), 'QMP greeting is absent')
                execute('qmp_capabilities')
                require(execute('query-status').get('status') in ('prelaunch', 'paused'),
                        'guest ran before its storage limit was installed')
                require(not cancelled, 'QEMU storage admission cancelled')
                # This remains our unreaped direct child: its PID cannot be
                # recycled between the process proof and prlimit syscall.
                resource.prlimit(child.pid, resource.RLIMIT_FSIZE, (overlay_limit, overlay_limit))
                require(resource.prlimit(child.pid, resource.RLIMIT_FSIZE)
                        == (overlay_limit, overlay_limit),
                        'QEMU hard file limit differs')
                publish(Path(args.run) / 'storage.limit', {
                    'qemu_pid': child.pid, 'hard_file_limit_bytes': overlay_limit,
                    'storage_profile': args.storage_profile,
                    'guest_memory_mib': args.memory_mib, 'guest_started_paused': True,
                    'limit_installed_before_guest_execution': True,
                })
                execute('cont')
        return child.wait()
    finally:
        if child.returncode is None:
            try:
                signal.pidfd_send_signal(child_identity, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    signal.pidfd_send_signal(child_identity, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        os.close(child_identity)
        # This supervisor creates and waits for only this child. Linux accounts
        # its output in 512-byte blocks; no PID-file process lookup is needed.
        output_blocks = resource.getrusage(resource.RUSAGE_CHILDREN).ru_oublock - output_before
        require(output_blocks >= 0, 'QEMU child output accounting decreased')
        publish(Path(args.run) / 'storage.qemu-io', {
            'qemu_pid': child.pid, 'returncode': child.returncode,
            'write_bytes': output_blocks * 512,
        })


def watch(args):
    scratch_limit, overlay_limit = storage_limits(args.storage_profile, args.memory_mib)
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
    qemu_io = None
    durable_peak = 0
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
            durable = 0
            for entry in Path(args.run).rglob('*'):
                metadata = entry.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    durable += metadata.st_blocks * 512
            durable_peak = max(durable_peak, durable)
            samples += 1
            if used > scratch_limit or minimum_memory < HEADROOM:
                reason = 'scratch-budget' if used > scratch_limit else 'memory-headroom'
                signal.pidfd_send_signal(parent, signal.SIGTERM)
                break
            if Path(args.stop).exists():
                # The controller writes stop only after joining the supervisor,
                # so its receipt is complete. A missing observation stays unavailable.
                qemu_io = qemu_output_receipt(args.run)
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
            'identity': args.identity, 'scratch_limit_bytes': scratch_limit,
            'storage_profile': args.storage_profile, 'overlay_limit_bytes': overlay_limit,
            'headroom_bytes': HEADROOM, 'guest_memory_mib': args.memory_mib,
            'peak_allocated_bytes': peak, 'overlay_peak_allocated_bytes': overlay_peak,
            'minimum_mem_available_bytes': minimum_memory, 'samples': samples,
            'observed_qemu_block_write_bytes': qemu_io['write_bytes'] if qemu_io else None,
            'qemu_io': qemu_io,
            'qemu_io_source': 'supervisor-waited-child-rusage' if qemu_io else 'unavailable',
            'durable_run_peak_allocated_bytes': durable_peak,
            'elapsed_seconds': round(time.monotonic() - began, 3), 'reason': reason,
            'tmpfs_swap_disabled': False,
        })
        os.close(parent)
        os.close(descriptor)
    require(reason == 'completed', f'VM storage guard refused the run: {reason}')


def main():
    require(os.geteuid() != 0 and os.getegid() != 0, 'host root is forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('preflight', 'reserve', 'check', 'watch', 'run'))
    parser.add_argument('--memory-mib', type=int, required=True)
    parser.add_argument('--storage-profile',
                        choices=('standard', 'hbb-common-fs', 'cpace-recovery-tests',
                                 'flutter-credential-dialog', 'linux-service-build',
                                 'ledger-token-count', 'x11-focus', 'linux-pa-playback'),
                        default='standard')
    parser.add_argument('--workspace')
    parser.add_argument('--identity')
    parser.add_argument('--parent', type=int)
    parser.add_argument('--run')
    parser.add_argument('--ready')
    parser.add_argument('--stop')
    parser.add_argument('--receipt')
    parser.add_argument('--qmp')
    parser.add_argument('--qemu', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    require(2048 <= args.memory_mib <= 24576, 'guest memory is outside the fixed profile bounds')
    scratch_limit, overlay_limit = storage_limits(args.storage_profile, args.memory_mib)
    if args.operation == 'preflight':
        preflight(args.memory_mib, args.storage_profile)
    elif args.operation == 'reserve':
        reserve(args.memory_mib, args.storage_profile)
    elif args.operation == 'check':
        descriptor = private_directory(args.workspace, args.identity)
        try:
            # Only QEMU may write after this check. Its selected hard file limit
            # bounds the remaining growth independently of the polling monitor.
            require(allocation(args.workspace) <= scratch_limit - overlay_limit,
                    'prepared inputs leave insufficient RAM overlay capacity')
            require(available_memory() >= args.memory_mib * 1024 ** 2 + HEADROOM + OVERHEAD,
                    'RAM headroom changed before QEMU launch')
        finally:
            os.close(descriptor)
    elif args.operation == 'watch':
        watch(args)
    else:
        result = run_qemu(args)
        raise SystemExit(result if result >= 0 else 128 - result)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Observe Remote pixels and viewer/network recovery through the installed service."""
from contextlib import ExitStack, closing, contextmanager
import base64
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


SCRIPT = Path('/mnt/rustdesk-verifier-inputs/repo/scripts/test-linux-installed-remote.py')
COORD = Path('/coord')
NETWORK_ENDPOINT = '/netem.sock'
ALLOCATION_PRELOAD = Path('/usr/share/rustdesk/libheaptrack_preload.so')
ALLOCATOR_PRELOAD = Path('/usr/share/rustdesk/liballocator_observer.so')
NETWORK_HOLDS = [6000, 2000, 6000, 1750, 5750, 2250, 6250, 2500, 6500]
NETWORK_PROFILES = {
    'network': ['delay'] + ['loss'] * 8,
    'loss': ['random3', 'random8', 'burst'],
    'congestion': ['jitter', 'bandwidth', 'bandwidth-jitter'],
    'backoff': ['loss'],
    'expired': ['loss'] * 3,
    'input-recovery': ['loss'] * 3,
    'input-loss': ['random3', 'random8', 'burst'],
    'input-congestion': ['jitter', 'bandwidth', 'bandwidth-jitter'],
    'input-animation-congestion': ['jitter', 'bandwidth', 'bandwidth-jitter'],
    'input-congestion-soak': ['jitter', 'bandwidth', 'bandwidth-jitter'] * 4,
}
SOAK_SCENARIOS = ('input-soak', 'input-congestion-soak')
INPUT_SCENARIOS = ('input-recovery', 'input-loss', 'input-congestion', *SOAK_SCENARIOS)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def guard(settings, uid):
    settings.guard(uid)
    require(Path(__file__).resolve() == SCRIPT and os.getgid() == uid,
            'installed Remote guest identity differs')


def network_request(request, refused=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        channel.connect(NETWORK_ENDPOINT)
        _, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require((uid, gid) == (0, 0), 'network controller is not guest root')
        channel.sendall(request)
        require(channel.recv(128) == (b'REFUSED' if refused else b'ATTACHED'),
                'installed network attachment result differs')


def observe_network(settings, actor, network, supervise=None):
    spec = importlib.util.spec_from_file_location('peer_netem', SCRIPT.with_name('flutter-peer-netem.py'))
    netem = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(netem)
    owner = netem.Impairment(None, congestion=network in ('congestion', 'input-congestion', 'input-congestion-soak',
                                                        'input-animation-congestion'),
                            long_soak=network in ('input-congestion-soak', 'input-animation-congestion'))
    driver_pid = driver_fd = None
    expected = [request for profile in NETWORK_PROFILES[network] for request in (profile, 'healthy')]
    profiles, refusals = [], 0
    expiry_until = expiry_next = expiry_samples = expiry_bytes = 0
    require(not os.path.lexists(NETWORK_ENDPOINT), 'installed network endpoint occupied')
    subprocess.run(['modprobe', 'ifb', 'numifbs=0'], env=netem.ENV, check=True, timeout=3)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(NETWORK_ENDPOINT)
        identity = Path(NETWORK_ENDPOINT).lstat()
        os.chown(NETWORK_ENDPOINT, 4001, 4001)
        os.chmod(NETWORK_ENDPOINT, 0o600)
        listener.listen(1)
        listener.settimeout(0.2)
        deadline = time.monotonic() + (15180 if network == 'input-congestion-soak'
                                       else 960 if network in ('input-animation-congestion', 'expired')
                                       else 300 if network == 'input-recovery' else 360 if network in INPUT_SCENARIOS else 240)
        try:
            while actor.poll() is None:
                require(time.monotonic() < deadline, 'installed network actor deadline exceeded')
                if supervise is not None:
                    supervise()
                # Expiry requires replacement; its native observer binds the old
                # and new socket inodes to the retained viewer's actual descriptors.
                if network != 'expired':
                    owner.observe_transport()
                elif expiry_next <= time.monotonic_ns() < expiry_until:
                    # Retain a bounded diagnostic around restoration. Replacement
                    # socket ownership still belongs to the native pixel observer.
                    started = time.monotonic_ns()
                    raw = owner.run('ss', '-H', '-O', '-n', '-t', '-i', '-e', '-o',
                                    'state', 'established', '(', 'sport', '=', ':21118',
                                    'or', 'dport', '=', ':21118', ')')
                    completed = time.monotonic_ns()
                    require(len(raw.encode()) <= 8192 and expiry_samples < 120,
                            'expiry transport diagnostic exceeds its bound')
                    expiry_next = started + 200_000_000
                    expiry_samples += 1
                    observation = 'LINUX_INSTALLED_EXPIRED_TCP=' + json.dumps({
                        'sequence': expiry_samples, 'cycle': len(profiles) // 2,
                        'started_us': started // 1000, 'completed_us': completed // 1000,
                        'namespace': os.fstat(owner.namespace).st_ino, 'raw': raw,
                    }, sort_keys=True)
                    expiry_bytes += len(observation.encode()) + 1
                    require(expiry_bytes <= 262144, 'expiry transport evidence exceeds its byte bound')
                    print(observation, flush=True)
                try:
                    channel, _ = listener.accept()
                except socket.timeout:
                    continue
                with channel:
                    channel.settimeout(3)
                    pid, uid, gid = struct.unpack('3i', channel.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    require((uid, gid) == (4001, 4001), 'foreign network controller requester')
                    data, _, flags, _ = channel.recvmsg(128)
                    require(not flags and 0 < len(data) < 128, 'network request frame differs')
                    if pid == actor.pid:
                        require(actor.poll() is None, 'network actor exited')
                        if data == b'attach':
                            owner.attach_installed(pid)
                            channel.sendall(b'ATTACHED')
                        else:
                            require(data == b'healthy' and refusals == 0 and owner.namespace is None,
                                    'unexpected actor operation')
                            refusals += 1
                            channel.sendall(b'REFUSED')
                        continue
                    require(owner.namespace is not None and len(profiles) < len(expected),
                            'network observer request outside its lifetime')
                    if driver_fd is None:
                        driver_fd = os.pidfd_open(pid)
                        driver_pid = pid
                        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                        require(int(fields[1]) == actor.pid and os.path.samefile(
                            f'/proc/{pid}/exe', settings.WORK / 'presentation-driver'),
                            'requester is not the actor-owned pixel observer')
                    require(pid == driver_pid and netem.alive(driver_fd)
                            and os.stat(f'/proc/{pid}/ns/net').st_ino == os.fstat(owner.namespace).st_ino,
                            'network observer generation changed')
                    request = data.decode('ascii')
                    require(request == expected[len(profiles)], 'network profile order differs')
                    owner.profile(request)
                    reply = owner.snapshot(request)
                    profiles.append(request)
                    channel.sendall(reply)
                    if network == 'expired' and request == 'healthy':
                        expiry_next = time.monotonic_ns()
                        expiry_until = expiry_next + 8_000_000_000
            require(actor.wait() == 0 and profiles == expected and refusals == 1,
                    'installed network scenario did not finish')
            if network == 'expired':
                sizes = owner.packet_sizes()
                require(sizes['oversized'] == owner.packet_size_baseline['oversized']
                        and sizes['at_mtu'] > owner.packet_size_baseline['at_mtu'],
                        'expiry packet-size coverage differs')
                print('LINUX_INSTALLED_EXPIRED_PACKETS=' + json.dumps(sizes, sort_keys=True), flush=True)
            else:
                owner.validate_observations()
        finally:
            try:
                if actor.poll() is None:
                    actor.terminate()
                actor.wait(timeout=20)
            finally:
                try:
                    owner.close()
                finally:
                    if driver_fd is not None:
                        os.close(driver_fd)
                    current = Path(NETWORK_ENDPOINT).lstat()
                    require(stat.S_ISSOCK(current.st_mode)
                            and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                            'installed network endpoint changed')
                    os.unlink(NETWORK_ENDPOINT)
    print(f'LINUX_INSTALLED_NETWORK_RETIRED=pass profiles={len(expected)} actor_wrong_role=refused '
          'observer=exact-child loopback=restored ingress=removed interface=removed socket=removed', flush=True)


@contextmanager
def soak_progress(actor, log, timeout):
    began = last_progress = time.monotonic()
    pending = b''
    started = False
    with log.open('rb') as output:
        def supervise():
            nonlocal pending, last_progress, started
            require((actor.poll() is None or (COORD / 'soak.done').exists())
                    and time.monotonic() - began < timeout,
                    'installed input soak actor exited or timed out')
            require(os.fstat(output.fileno()).st_size <= 6291456, 'installed soak log exceeds its bound')
            pending += output.read(65536)
            lines = pending.split(b'\n')
            pending = lines.pop()
            require(len(pending) <= 8192, 'installed soak progress line exceeds its bound')
            for line in lines:
                if line.startswith((b'FLUTTER_PEER_INPUT_SOAK_PROGRESS ',
                                    b'FLUTTER_PEER_INPUT_SOAK_WINDOW_COMPLETE ',
                                    b'FLUTTER_PEER_INPUT_CONGESTION_SOAK_BEGIN ',
                                    b'FLUTTER_PEER_INPUT_CONGESTION_SOAK_RECOVERED ')):
                    print('LINUX_INSTALLED_SOAK_LIVE ' + line.decode('ascii'), flush=True)
                    last_progress = time.monotonic()
            if not started:
                require(time.monotonic() - began < 90, 'installed input soak did not begin')
                if os.path.lexists(COORD / 'soak.begin'):
                    started = True
                    last_progress = time.monotonic()
            require(time.monotonic() - last_progress < 120, 'installed input soak progress stopped')
        yield supervise


def observe_soak(record, actor, log):
    spec = importlib.util.spec_from_file_location('peer_soak', SCRIPT.with_name('flutter-peer-soak.py'))
    soak = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(soak)
    start = Path(f'/proc/{actor.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
    with soak_progress(actor, log, 14820) as supervise:
        while not os.path.lexists(COORD / 'soak.begin'):
            supervise()
            time.sleep(0.05)
        # The retained actor owns and supervises the source, viewer and pixel driver.
        # Observe the non-dumpable service child from guest root, not from that actor.
        with closing(soak.observe(record['pid'], str(record['start']), actor.pid, start,
                                  'input-soak', 4001, 4001)) as observation:
            for _ in observation:
                supervise()


def observe_impaired_soak(settings, record, actor, log):
    start = Path(f'/proc/{actor.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
    resource_log = settings.WORK / 'installed-soak-resources.log'
    observer = None
    with resource_log.open('xb') as output, soak_progress(actor, log, 15180) as progress:
        def supervise():
            nonlocal observer
            progress()
            if observer is None and os.path.lexists(COORD / 'soak.begin'):
                observer = subprocess.Popen([
                    '/usr/bin/python3', '-B', '-I', '-S', str(SCRIPT.with_name('flutter-peer-soak.py')),
                    '--installed', str(record['pid']), str(record['start']), str(actor.pid), start,
                    'input-congestion-soak'], env=settings.ENV, stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.STDOUT)
            require(os.fstat(output.fileno()).st_size <= 131072, 'installed soak resource log exceeds its bound')
            if observer is not None:
                require(observer.poll() in (None, 0), 'installed soak resource observer failed')
        try:
            # Keep one-second resource sampling independent of 200-ms network observations.
            observe_network(settings, actor, 'input-congestion-soak', supervise)
            require(observer is not None and observer.wait(timeout=5) == 0,
                    'installed soak resource observer did not finish')
        finally:
            if observer is not None:
                if observer.poll() is None:
                    observer.terminate()
                observer.wait(timeout=10)
                print('LINUX_INSTALLED_SOAK_OBSERVER=' + json.dumps(
                    dict(pid=observer.pid, exit=observer.returncode, cleanup='joined')), flush=True)
            require(resource_log.stat().st_size <= 131072, 'installed soak resource output exceeds its bound')
            print(resource_log.read_text(), end='', flush=True)


class AllocationTrace:
    """Own the guest-only collector pipe and offline report processes."""

    def __init__(self):
        self.root = COORD / 'heaptrack'
        self.root.mkdir(mode=0o700)
        self.fifo = self.root / 'raw.pipe'
        self.raw = self.root / 'raw.gz'
        self.anchor = None
        self.collector = None
        self.jobs = []
        self.viewer_pid = None

    def start(self, environment):
        os.mkfifo(self.fifo, 0o600)
        self.anchor = os.open(self.fifo, os.O_RDWR | os.O_CLOEXEC)
        with os.fdopen(os.open(self.fifo, os.O_RDONLY | os.O_CLOEXEC), 'rb') as reader, \
                self.raw.open('xb') as output, (self.root / 'compressor.log').open('xb') as errors:
            self.collector = subprocess.Popen(
                ['/usr/bin/prlimit', '--fsize=134217728', '--', '/usr/bin/gzip', '-1', '-c'],
                stdin=reader, stdout=output, stderr=errors, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            self.jobs.append(self.collector)
        return {**environment, 'LD_PRELOAD': str(ALLOCATION_PRELOAD),
                'DUMP_HEAPTRACK_OUTPUT': str(self.fifo)}

    def connected(self, viewer):
        expected = self.fifo.stat()
        deadline = time.monotonic() + 10
        while viewer.poll() is None and time.monotonic() < deadline:
            for fd in Path(f'/proc/{viewer.pid}/fd').iterdir():
                try:
                    current = fd.stat()
                except FileNotFoundError:
                    continue
                if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                    require(str(ALLOCATION_PRELOAD) in
                            Path(f'/proc/{viewer.pid}/maps').read_text(), 'viewer collector mapping absent')
                    self.viewer_pid = viewer.pid
                    os.close(self.anchor)
                    self.anchor = None
                    print('LINUX_INSTALLED_HEAPTRACK_ATTACHED=' + json.dumps({
                        'viewer': viewer.pid, 'monotonic_ns': time.monotonic_ns(),
                        'fifo_inode': expected.st_ino, 'acceptance': 'diagnostic-only'}), file=sys.stderr, flush=True)
                    return
            time.sleep(0.02)
        raise RuntimeError('viewer did not open its allocation trace')

    def stop_jobs(self):
        for process in reversed(self.jobs):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def finish(self):
        if self.anchor is not None:
            os.close(self.anchor)
            self.anchor = None
        try:
            if self.collector is None:
                return
            require(self.collector.wait(timeout=15) == 0 and self.viewer_pid is not None,
                    'allocation trace compressor or viewer attachment failed')
            require(0 < self.raw.stat().st_size <= 134217728, 'compressed allocation trace exceeds its bound')
            interpreted = self.root / 'interpreted.gz'
            env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(self.root)}
            with interpreted.open('xb') as output, (self.root / 'interpret.log').open('xb') as errors:
                unpack = subprocess.Popen(['/usr/bin/gzip', '-dc', str(self.raw)],
                                          stdout=subprocess.PIPE, stderr=errors, env=env)
                self.jobs.append(unpack)
                interpret = subprocess.Popen(['/usr/lib/heaptrack/libexec/heaptrack_interpret'],
                                             stdin=unpack.stdout, stdout=subprocess.PIPE, stderr=errors, env=env)
                self.jobs.append(interpret)
                unpack.stdout.close()
                compress = subprocess.Popen(
                    ['/usr/bin/prlimit', '--fsize=134217728', '--', '/usr/bin/gzip', '-1', '-c'],
                    stdin=interpret.stdout, stdout=output, stderr=errors, env=env)
                self.jobs.append(compress)
                interpret.stdout.close()
                deadline = time.monotonic() + 120
                for process in (unpack, interpret, compress):
                    require(process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                            'allocation trace interpretation failed')
            require(0 < interpreted.stat().st_size <= 134217728, 'interpreted allocation trace exceeds its bound')
            report = self.root / 'report.txt'
            timeline = self.root / 'timeline.massif'
            with report.open('xb') as output:
                analyze = subprocess.Popen([
                    '/usr/bin/prlimit', '--fsize=16777216', '--', '/usr/bin/heaptrack_print', str(interpreted),
                    '--merge-backtraces=false', '--print-peaks=true', '--print-leaks=true',
                    '--print-allocators=false', '--print-temporary=false', '--peak-limit=30',
                    '--disable-builtin-suppressions', '--disable-embedded-suppressions',
                    '--print-massif=' + str(timeline), '--massif-detailed-freq=0'],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, env=env)
                self.jobs.append(analyze)
                code = analyze.wait(timeout=120)
                require(code == 0, f'allocation report failed: exit={code}')
            def identity(path):
                with path.open('rb') as stream:
                    return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
            print('LINUX_INSTALLED_HEAPTRACK_COMPLETE=' + json.dumps({
                'viewer': self.viewer_pid, 'raw': identity(self.raw), 'interpreted': identity(interpreted),
                'report': identity(report), 'timeline': identity(timeline),
                'processes': [{'pid': p.pid, 'exit': p.returncode} for p in self.jobs],
                'acceptance': 'diagnostic-only', 'retained': 'reports-only',
                'end_state': 'viewer-retired-by-fixture'}), file=sys.stderr, flush=True)
        finally:
            self.stop_jobs()
            print('LINUX_INSTALLED_HEAPTRACK_PROCESSES=' + json.dumps([
                {'pid': p.pid, 'exit': p.returncode} for p in self.jobs]), file=sys.stderr, flush=True)
            # Preserve tool errors even if collection, interpretation or analysis fails.
            for name in ('compressor.log', 'interpret.log', 'report.txt'):
                path = self.root / name
                if not path.exists():
                    continue
                limit = 262144 if name == 'report.txt' else 65536
                with path.open('rb') as stream:
                    data = stream.read(limit)
                print(f'LINUX_INSTALLED_HEAPTRACK_REPORT_BEGIN name={name} '
                      f'bytes={path.stat().st_size} retained={len(data)}', file=sys.stderr, flush=True)
                print(data.decode('utf-8', errors='replace'), end='', file=sys.stderr, flush=True)
                print('\nLINUX_INSTALLED_HEAPTRACK_REPORT_END name=' + name, file=sys.stderr, flush=True)
            timeline = self.root / 'timeline.massif'
            if timeline.exists():
                # Heaptrack emits a snapshot every 10 ms, even with detailed stacks disabled.
                # Keep every sample within a separate bounded compressed evidence record.
                require(timeline.stat().st_size <= 16777216, 'allocation timeline exceeds its guest bound')
                data = timeline.read_bytes()
                packed = gzip.compress(data, mtime=0)
                require(len(packed) <= 786432, 'allocation timeline exceeds its evidence bound')
                print('LINUX_INSTALLED_HEAPTRACK_TIMELINE=' + json.dumps({
                    'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'encoding': 'gzip+base64', 'data': base64.b64encode(packed).decode('ascii')}),
                    file=sys.stderr, flush=True)


class AllocatorSnapshots:
    """Sample all glibc arenas without wrapping allocation calls."""

    def __init__(self):
        self.path = COORD / 'allocator.raw'
        self.output = self.path.open('xb')
        self.fd = self.output.fileno()
        self.viewer_pid = None

    def start(self, environment):
        return {**environment, 'LD_PRELOAD': str(ALLOCATOR_PRELOAD), 'RUSTDESK_ALLOCATOR_FD': str(self.fd)}

    def connected(self, viewer):
        expected = self.path.stat()
        deadline = time.monotonic() + 10
        while viewer.poll() is None and time.monotonic() < deadline:
            if self.path.stat().st_size:
                current = Path(f'/proc/{viewer.pid}/fd/{self.fd}').stat()
                with self.path.open('rb') as stream:
                    header = stream.readline(256)
                require((current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
                        and header.startswith(f'ALLOCATOR_BEGIN pid={viewer.pid} sequence=0 '.encode())
                        and str(ALLOCATOR_PRELOAD) in Path(f'/proc/{viewer.pid}/maps').read_text(),
                        'allocator observer attachment differs')
                self.viewer_pid = viewer.pid
                self.output.close()
                print('LINUX_INSTALLED_ALLOCATOR_ATTACHED=' + json.dumps({
                    'viewer': viewer.pid, 'inode': expected.st_ino, 'acceptance': 'diagnostic-only'}),
                    file=sys.stderr, flush=True)
                return
            time.sleep(0.02)
        raise RuntimeError('viewer allocator observer did not start')

    def finish(self):
        self.output.close()
        require(0 < self.path.stat().st_size <= 67108864, 'allocator snapshots exceed their guest bound')
        data = self.path.read_bytes()
        packed = gzip.compress(data, mtime=0)
        require(len(packed) <= 786432, 'allocator snapshots exceed their evidence bound')
        print('LINUX_INSTALLED_ALLOCATOR_RAW=' + json.dumps({
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'encoding': 'gzip+base64', 'data': base64.b64encode(packed).decode('ascii')}),
            file=sys.stderr, flush=True)
        samples, previous = 0, 0
        with self.path.open('rb') as stream:
            while True:
                header = stream.readline(256)
                if header.startswith(b'ALLOCATOR_COMPLETE '):
                    require(header == f'ALLOCATOR_COMPLETE pid={self.viewer_pid} samples={samples} failed=0\n'.encode()
                            and not stream.read(1) and samples >= 2, 'allocator completion differs')
                    break
                match = re.fullmatch(rb'ALLOCATOR_BEGIN pid=(\d+) sequence=(\d+) begin_ns=(\d+) end_ns=(\d+) bytes=(\d+)\n', header)
                require(match is not None and samples < 1000, 'allocator sample header differs')
                pid, sequence, began, ended, size = map(int, match.groups())
                require(pid == self.viewer_pid and sequence == samples and previous < began <= ended
                        and 0 < size < 262144, 'allocator sample identity or extent differs')
                xml = stream.read(size)
                require(len(xml) == size and stream.readline(32) == b'ALLOCATOR_END\n',
                        'allocator sample is incomplete')
                root = ET.fromstring(xml)
                require(root.tag == 'malloc' and root.attrib == {'version': '1'}, 'allocator format differs')
                heaps = root.findall('heap')
                require(0 < len(heaps) <= 256 and [h.attrib for h in heaps] ==
                        [{'nr': str(i)} for i in range(len(heaps))], 'allocator arena inventory differs')
                def counters(element):
                    def value(tag, kind):
                        values = element.findall(f"{tag}[@type='{kind}']")
                        require(len(values) == 1 and values[0].get('size', '').isdigit(),
                                'allocator counter absent or duplicated')
                        return int(values[0].get('size'))
                    return {'system_bytes': value('system', 'current'),
                            'fast_free_bytes': value('total', 'fast'), 'rest_free_bytes': value('total', 'rest')}
                total, main = counters(root), counters(heaps[0])
                arena_values = [counters(h) for h in heaps]
                require(all(sum(h[key] for h in arena_values) == total[key]
                            for key in ('fast_free_bytes', 'rest_free_bytes')),
                        'allocator free-space totals do not reconcile')
                # glibc reads system_mem twice after releasing each arena lock.
                # Preserve concurrent differences rather than assert an atomic snapshot.
                system_delta = sum(h['system_bytes'] for h in arena_values) - total['system_bytes']
                mmap, = root.findall("total[@type='mmap']")
                print('LINUX_INSTALLED_ALLOCATOR_SAMPLE=' + json.dumps({
                    'sequence': sequence, 'begin_ns': began, 'end_ns': ended,
                    'duration_ns': ended - began, 'arenas': len(heaps),
                    'all_arenas': total, 'main_arena': main, 'mmap_bytes': int(mmap.attrib['size']),
                    'system_sum_delta_bytes': system_delta,
                }, sort_keys=True), file=sys.stderr, flush=True)
                samples += 1
                previous = ended
        print(f'LINUX_INSTALLED_ALLOCATOR_COMPLETE viewer={self.viewer_pid} samples={samples} '
              'interposition=none acceptance=diagnostic-only', file=sys.stderr, flush=True)


def session(network=False, heaptrack=False, allocator=False):
    require(network is False or network in NETWORK_PROFILES or network in ('input-soak', 'input-animation'),
            'unknown Remote scenario')
    require(not heaptrack or network == 'expired', 'allocation tracing requires the expiry diagnostic')
    require(not allocator or (network == 'expired' and not heaptrack), 'allocator diagnostic differs')
    spec = importlib.util.spec_from_file_location('installed_settings', SCRIPT.with_name('test-linux-installed-settings.py'))
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)
    guard(settings, 4001)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (268435456, 268435456))
    def cancelled(_signal, _frame):
        raise RuntimeError('installed Remote session cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
            'cannot retain Remote viewer descendants')
    environment = {**settings.ENV, 'HOME': '/home/rdreceiver4001', 'USER': 'rdreceiver4001',
                   'XDG_RUNTIME_DIR': '/run/user/4001', 'XDG_SESSION_TYPE': 'x11',
                   'XDG_DATA_DIRS': '/usr/local/share:/usr/share', 'GDK_BACKEND': 'x11',
                   'LIBGL_ALWAYS_SOFTWARE': '1'}
    processes = []
    viewer = None
    trace = None
    with ExitStack() as files:
        environment = files.enter_context(settings.recording_display(environment, 79, '1600x1200x24'))
        def log(name):
            return files.enter_context((COORD / name).open('xb'))
        try:
            bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
                                   env=environment, stdout=subprocess.PIPE, stderr=sys.stderr)
            processes.append(bus)
            require(select.select([bus.stdout], [], [], 5)[0], 'Remote session bus did not start')
            address = bus.stdout.readline(4096).decode().strip()
            require(address.startswith('unix:'), 'Remote session bus is not local')
            environment['DBUS_SESSION_BUS_ADDRESS'] = address
            authority = COORD / 'observer-Xauthority'
            with authority.open('xb') as combined:
                for path in (Path('/run/user/4001/gdm/Xauthority'), Path(environment['XAUTHORITY'])):
                    info = path.lstat()
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 4001
                            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                            and 0 < info.st_size <= 4096, 'Remote display authority differs')
                    combined.write(path.read_bytes())
            source = subprocess.Popen([str(settings.WORK / 'presentation-source'),
                                       *(['--input-animation'] if network in ('input-animation', 'input-animation-congestion', 'expired') else
                                         ['--input-response', str(COORD)] if network in INPUT_SCENARIOS else [])],
                env={**environment, 'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                     'RUSTDESK_PRESENTATION_TRACE': '1'},
                stdout=log('frame-source.log'), stderr=log('source-error.log'))
            processes.append(source)
            deadline = time.monotonic() + 5
            while (COORD / 'frame-source.log').stat().st_size == 0:
                require(source.poll() is None and time.monotonic() < deadline,
                        'installed Remote source did not publish')
                time.sleep(0.05)
            if network in NETWORK_PROFILES:
                deadline = time.monotonic() + 5
                while not Path(NETWORK_ENDPOINT).exists():
                    require(time.monotonic() < deadline, 'network controller did not start')
                    time.sleep(0.05)
                network_request(b'healthy', refused=True)
                network_request(b'attach')
            viewer_environment = environment
            if heaptrack:
                trace = AllocationTrace()
                viewer_environment = trace.start(environment)
            elif allocator:
                trace = AllocatorSnapshots()
                viewer_environment = trace.start(environment)
            viewer = subprocess.Popen(['/usr/share/rustdesk/rustdesk', '--connect', '127.0.0.1'],
                                      env=viewer_environment, stdin=subprocess.DEVNULL,
                                      stdout=log('viewer.log'), stderr=subprocess.STDOUT,
                                      pass_fds=(trace.fd,) if allocator else ())
            processes.append(viewer)
            if trace is not None:
                trace.connected(viewer)
            start = Path(f'/proc/{viewer.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
            driver_args = [str(settings.WORK / 'presentation-driver'), ':77', ':79',
                           str(viewer.pid), start,
                           {'network': '--network-impairment', 'loss': '--network-loss',
                            'congestion': '--network-congestion', 'backoff': '--network-backoff',
                            'input-recovery': '--input-recovery', 'input-loss': '--input-loss',
                            'input-congestion': '--input-congestion',
                            'input-animation': '--input-animation',
                            'input-animation-congestion': '--input-animation-congestion',
                            'expired': '--expired-connection',
                            'input-soak': '--input-soak',
                            'input-congestion-soak': '--input-congestion-soak'}.get(network, '--viewer-suspend')]
            if network in SOAK_SCENARIOS:
                # Fixed shell text duplicates the inherited log as the native progress FD.
                driver_args = ['/bin/bash', '--noprofile', '--norc', '-c', 'exec "$@" 3>&2',
                               'installed-input-soak', *driver_args]
            driver = subprocess.Popen(driver_args,
                                      env={**environment, 'XAUTHORITY': str(authority)},
                                      stdout=log('driver.log'),
                                      stderr=None if network in SOAK_SCENARIOS else subprocess.STDOUT)
            processes.append(driver)
            clock = Path('/proc/self/ns/time').stat()
            for process in (source, viewer, driver):
                current = Path(f'/proc/{process.pid}/ns/time').stat()
                require((current.st_dev, current.st_ino) == (clock.st_dev, clock.st_ino),
                        'Remote observer and source clocks differ')
            if network in SOAK_SCENARIOS:
                deadline = time.monotonic() + (15120 if network == 'input-congestion-soak' else 14760)
                while driver.poll() is None:
                    require(source.poll() is None and bus.poll() is None and time.monotonic() < deadline,
                            'installed input soak source/bus exited or driver timed out')
                    require(viewer.poll() is None or (COORD / 'soak.done').exists(),
                            'installed input soak viewer exited before completion')
                    for name in ('driver.log', 'source-error.log', 'frame-source.log', 'viewer.log'):
                        require((COORD / name).stat().st_size <= 2097152,
                                'installed input soak output exceeds its bound')
                    time.sleep(0.1)
            require(driver.wait(timeout=900 if network in ('input-animation-congestion', 'expired')
                                else 240 if network == 'input-recovery' else 300 if network in INPUT_SCENARIOS
                                else 180 if network else 120) == 0,
                    'installed Remote pixel observer failed')
            require(viewer.wait(timeout=10) == 0, 'Remote viewer did not close normally')
            require(source.poll() is None, 'Remote source retired before the viewer')
            source.terminate()
            require(source.wait(timeout=8) == 0, 'Remote source cleanup failed')
            require((COORD / 'frame-source.log').read_text().count('FLUTTER_PEER_SOURCE_COMPLETE ') == 1,
                    'Remote source completion absent or duplicated')
            print(json.dumps({'viewer': viewer.pid, 'source': source.pid, 'clock_inode': clock.st_ino,
                              'viewer_exit': 0, 'source_exit': 0, 'driver_exit': 0}), flush=True)
        finally:
            print('LINUX_INSTALLED_REMOTE_PROCESSES=' + json.dumps([
                {'pid': process.pid, 'exit_before_cleanup': process.poll()}
                for process in processes], sort_keys=True), file=sys.stderr, flush=True)
            try:
                try:
                    for process in reversed(processes):
                        if process.poll() is None:
                            if process is viewer:
                                process.send_signal(signal.SIGCONT)
                            process.terminate()
                        process.wait(timeout=8)
                finally:
                    if trace is not None:
                        trace.finish()
            finally:
                settings.retire_children()
                for name in ('driver.log', 'source-error.log', 'frame-source.log', 'viewer.log'):
                    path = COORD / name
                    if path.exists():
                        require(path.stat().st_size <= (2097152 if network in SOAK_SCENARIOS
                                                       else 1048576 if network in ('input-animation-congestion', 'expired') else 131072),
                                'Remote observer output exceeds its bound')
                        print(path.read_text(), end='', file=sys.stderr, flush=True)
    require(not (heaptrack or allocator), 'allocation tracing is diagnostic; ordinary acceptance remains unproved')


def server_log_snapshot(settings, receiver, record, phase):
    descriptor = os.pidfd_open(record['pid'])
    try:
        require(not select.select([descriptor], [], [], 0)[0] and receiver.child_record() == record,
                'Remote server log owner changed before observation')
        path, data = settings.owned_log(
            Path('/home/rdreceiver4001/.local/share/logs/RustDesk/server'), record['pid'], 4001)
        offset = max(0, len(data) - 65536)
        if offset:
            offset = data.index(b'\n', offset) + 1
        began = time.monotonic_ns()
        realtime = time.time_ns()
        ended = time.monotonic_ns()
        require(not select.select([descriptor], [], [], 0)[0] and receiver.child_record() == record,
                'Remote server log owner changed during observation')
        print('LINUX_INSTALLED_REMOTE_SERVER_LOG=' + json.dumps({
            'phase': phase, **record, 'path': str(path), 'prefix_bytes': len(data),
            'prefix_sha256': hashlib.sha256(data).hexdigest(), 'offset': offset,
            'data_base64': base64.b64encode(data[offset:]).decode('ascii'),
            'monotonic_before_ns': began, 'realtime_ns': realtime, 'monotonic_after_ns': ended,
        }, sort_keys=True), flush=True)
    finally:
        os.close(descriptor)


def cm_log_snapshot():
    # Retain this fixture user's startup logs even if the helper has already exited.
    # These files are diagnostic evidence; they do not prove a live CM peer identity.
    directory = Path('/home/rdreceiver4001/.local/share/logs/RustDesk/cm')
    if not directory.exists():
        print('LINUX_INSTALLED_CM_LOGS=' + json.dumps({'directory': str(directory), 'present': False}), flush=True)
        return
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 4001)
                and not info.st_mode & 0o022, 'CM diagnostic directory authority differs')
    paths = sorted(directory.glob('*.log'))
    require(len(paths) <= 8, 'CM diagnostic log count exceeds its bound')
    print('LINUX_INSTALLED_CM_LOGS=' + json.dumps({
        'directory': str(directory), 'present': True, 'files': len(paths),
    }), flush=True)
    total = 0
    for path in paths:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            before = os.fstat(stream.fileno())
            total += before.st_size
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 4001
                    and before.st_nlink == 1 and not before.st_mode & 0o022 and total <= 65536,
                    'CM diagnostic log authority or size differs')
            data = stream.read(before.st_size)
            after, current = os.fstat(stream.fileno()), path.lstat()
        require(len(data) == before.st_size and after.st_size >= before.st_size
                and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                'CM diagnostic log changed during observation')
        print('LINUX_INSTALLED_CM_LOG=' + json.dumps({
            'path': str(path), 'identity': f'{before.st_dev}:{before.st_ino}',
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'data_base64': base64.b64encode(data).decode('ascii'),
            'authority': 'fixture-user-file', 'live_process': 'unproved',
        }, sort_keys=True), flush=True)


class CmFaultTrace:
    """One-shot guest diagnostic; preserve signal delivery after reading a fault."""

    def __init__(self, pid, directory):
        require(os.uname().machine == 'x86_64', 'CM fault observer requires the pinned x86_64 guest')
        self.pid, self.directory = pid, directory
        self.attached = False
        self.stopped = None
        self.signals = 0
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        self.libc.ptrace.restype = ctypes.c_long
        self.call(0x4206)  # SEIZE; execution continues until an ordinary signal.
        self.attached = True

    def call(self, request, address=0, data=0):
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, self.pid, address, data)
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'exact guest CM ptrace operation failed')
        return result

    def detach(self):
        self.call(17, data=self.stopped)  # DETACH and preserve the pending signal.
        self.attached = False
        self.stopped = None

    def poll(self):
        if not self.attached:
            return
        pid, status = os.waitpid(self.pid, os.WNOHANG | 0x40000000)  # __WALL
        if not pid:
            return
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.attached = False
            print('LINUX_INSTALLED_CM_TRACE_EXIT=' + json.dumps({
                'pid': self.pid, 'wait_status': status, 'exit_code': os.waitstatus_to_exitcode(status),
            }), flush=True)
            return
        require(os.WIFSTOPPED(status), 'CM trace returned an unknown state')
        self.stopped = 0 if status >> 16 else os.WSTOPSIG(status)
        require(not status >> 16, 'unexpected CM trace event')
        self.signals += 1
        require(self.signals <= 64, 'CM trace signal bound exceeded')
        if self.stopped != signal.SIGSEGV:
            self.call(7, data=self.stopped)  # CONT; do not suppress other signals.
            self.stopped = None
            return
        try:
            registers = (ctypes.c_ulonglong * 27)()
            info = ctypes.create_string_buffer(128)
            self.call(12, data=ctypes.byref(registers))  # GETREGS, Linux x86_64 user_regs_struct.
            self.call(0x4202, data=ctypes.byref(info))  # GETSIGINFO.
            signo, error, code = struct.unpack_from('iii', info.raw)
            fault, = struct.unpack_from('Q', info.raw, 16)
            require(signo == signal.SIGSEGV, 'CM fault siginfo differs')
            with os.fdopen(os.open('maps', os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.directory), 'rb') as source:
                raw = source.read(262145)
            require(len(raw) <= 262144, 'CM fault mapping inventory exceeds its bound')
            mappings = []
            for line in raw.decode().splitlines():
                fields = line.split(None, 5)
                start, end = (int(value, 16) for value in fields[0].split('-'))
                mappings.append((start, end, fields))
            def mapping(address):
                for start, end, fields in mappings:
                    if start <= address < end:
                        return {'address': address, 'range': fields[0], 'permissions': fields[1],
                                'file_offset': int(fields[2], 16) + address - start,
                                'device': fields[3], 'inode': int(fields[4]),
                                'path': fields[5] if len(fields) == 6 else ''}
                return None
            instruction, stack = int(registers[16]), int(registers[19])
            stack_mapping = mapping(stack)
            require(stack_mapping is not None and stack_mapping['path'] == '[stack]',
                    'CM fault stack is not the main-thread stack')
            # The top word is only a return-address candidate, not an unwound frame.
            candidate = self.call(2, address=stack) & ((1 << 64) - 1)  # PEEKDATA.
            caller = mapping(candidate)
            if caller is not None and 'x' not in caller['permissions']:
                caller = None
            print('LINUX_INSTALLED_CM_FAULT=' + json.dumps({
                'pid': self.pid, 'signal': signo, 'errno': error, 'code': code,
                'fault_address': fault, 'instruction': mapping(instruction),
                'stack_return_candidate': caller, 'mapping_count': len(mappings),
                'acceptance': 'diagnostic-only; main-thread signal-stop',
            }, sort_keys=True), flush=True)
        finally:
            self.detach()

    def close(self):
        if not self.attached:
            return
        if self.stopped is None:
            try:
                self.call(0x4207)  # INTERRUPT solely to detach during observer cleanup.
            except ProcessLookupError:
                # An exit racing the interrupt still requires its exact wait below.
                pass
            deadline = time.monotonic() + 3
            while True:
                pid, status = os.waitpid(self.pid, os.WNOHANG | 0x40000000)
                if pid:
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                        self.attached = False
                        return
                    require(os.WIFSTOPPED(status), 'CM trace cleanup state differs')
                    self.stopped = 0 if status >> 16 else os.WSTOPSIG(status)
                    break
                require(time.monotonic() < deadline, 'CM trace cleanup deadline exceeded')
                time.sleep(0.005)
        self.detach()


def observe_cm_startup(receiver, record, actor):
    """Identify the exact CM child, then observe its startup fault in the guest."""
    def read_at(directory, name):
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory), 'rb') as stream:
            data = stream.read(8193)
        require(len(data) <= 8192, 'CM process diagnostic exceeds its bound')
        return data

    def process_state(directory):
        fields = read_at(directory, 'stat').decode().rsplit(') ', 1)[1].split()
        require(len(fields) >= 50, 'CM process stat is incomplete')
        return {'state': fields[0], 'parent': int(fields[1]), 'start': int(fields[19]),
                'threads': int(fields[17]), 'cpu_ticks': int(fields[11]) + int(fields[12]),
                'wait_status': int(fields[49]) if fields[0] == 'Z' else None}

    began = previous = time.monotonic_ns()
    maximum_gap = samples = vanished = 0
    observation = None
    trace = None
    with ExitStack() as resources:
        server_fd = os.pidfd_open(record['pid'])
        resources.callback(os.close, server_fd)
        require(receiver.child_record() == record and not select.select([server_fd], [], [], 0)[0],
                'CM observation server identity differs')
        image = os.stat(f"/proc/{record['pid']}/exe")
        try:
            while True:
                now = time.monotonic_ns()
                maximum_gap = max(maximum_gap, now - previous)
                previous = now
                samples += 1
                require(now - began < 180_000_000_000, 'CM observation deadline exceeded')
                require(not select.select([server_fd], [], [], 0)[0], 'CM observation server exited')
                if observation is None:
                    tasks = list(Path(f"/proc/{record['pid']}/task").iterdir())
                    require(len(tasks) <= 256, 'CM observation server thread bound exceeded')
                    candidates = set()
                    for task in tasks:
                        try:
                            candidates.update(map(int, (task / 'children').read_text().split()))
                        except FileNotFoundError:
                            vanished += 1
                    require(len(candidates) <= 64, 'CM observation child bound exceeded')
                    for pid in sorted(candidates):
                        with ExitStack() as candidate:
                            try:
                                descriptor = os.pidfd_open(pid)
                                candidate.callback(os.close, descriptor)
                                directory = os.open(f'/proc/{pid}', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                                candidate.callback(os.close, directory)
                                first = process_state(directory)
                                argv = read_at(directory, 'cmdline').split(b'\0')
                                if len(argv) != 3 or argv[1:] != [b'--cm', b'']:
                                    continue
                                executable = os.stat('exe', dir_fd=directory)
                                status = dict(line.split(':', 1) for line in
                                              read_at(directory, 'status').decode().splitlines())
                                current = process_state(directory)
                                require(first['start'] == current['start']
                                        and first['parent'] == current['parent'] == record['pid']
                                        and (executable.st_dev, executable.st_ino) == (image.st_dev, image.st_ino)
                                        and list(map(int, status['Uid'].split())) == [4001] * 4,
                                        'CM observation child identity differs')
                                if select.select([descriptor], [], [], 0)[0]:
                                    vanished += 1
                                    continue
                            except (FileNotFoundError, ProcessLookupError):
                                vanished += 1
                                continue
                            observation = {'pid': pid, 'first': current, 'last': current,
                                           'image': f'{image.st_dev}:{image.st_ino}',
                                           'status': {key: status[key].strip() for key in
                                                      ('Uid', 'Gid', 'NoNewPrivs', 'Seccomp', 'CapEff')},
                                           'exit_observed': False, 'reaped': False}
                            resources.enter_context(candidate.pop_all())
                            trace = CmFaultTrace(pid, directory)
                            resources.callback(trace.close)
                            break
                elif not observation['reaped']:
                    try:
                        current = process_state(directory)
                    except (FileNotFoundError, ProcessLookupError):
                        observation['reaped'] = True
                    else:
                        require(current['start'] == observation['first']['start']
                                and current['parent'] == record['pid'], 'CM observation identity changed')
                        observation['last'] = current
                        if current['state'] == 'Z':
                            observation['exit_observed'] = True
                            observation['exit_code'] = os.waitstatus_to_exitcode(current['wait_status'])
                if trace is not None:
                    trace.poll()
                if actor.poll() is not None:
                    break
                time.sleep(0.005)
        finally:
            print('LINUX_INSTALLED_CM_PROCESS=' + json.dumps({
                'server': record, 'child': observation, 'samples': samples,
                'maximum_sample_gap_ns': maximum_gap, 'vanished_candidates': vanished,
                'duration_ns': time.monotonic_ns() - began, 'method': 'procfs-and-main-thread-signal-trace',
                'coverage': 'first-observed-exact-cm; short-lived children may be missed',
            }, sort_keys=True), flush=True)
    require(False, 'CM fault tracing is diagnostic; ordinary acceptance remains unproved')


def scenario(settings, receiver, record, network=False, heaptrack=False, allocator=False):
    require(network is False or network in NETWORK_PROFILES or network in ('input-soak', 'input-animation'),
            'unknown Remote scenario')
    require(not heaptrack or network == 'expired', 'allocation tracing requires the expiry diagnostic')
    require(not allocator or (network == 'expired' and not heaptrack), 'allocator diagnostic differs')
    guard(settings, 0)
    COORD.mkdir(mode=0o700)
    os.chown(COORD, 4001, 4001)
    credential, profile = receiver.credential(), settings.user_credential()
    listener = receiver.direct_listener(record)
    require(listener is not None, 'installed Remote listener absent')
    actor = None
    preload_identity = None
    preload = ALLOCATOR_PRELOAD if allocator else ALLOCATION_PRELOAD
    log = settings.WORK / 'installed-remote.log'
    try:
        if network is False or network == 'expired':
            server_log_snapshot(settings, receiver, record, 'before')
        if heaptrack or allocator:
            # Keep the diagnostic beside the unchanged runner in this guest only.
            # Heaptrack's dlopen wrapper also needs that location for $ORIGIN.
            original = settings.WORK / 'prepared/allocator-first.so' if allocator else Path('/usr/lib/heaptrack/libheaptrack_preload.so')
            if allocator:
                manifest = json.loads((settings.WORK / 'prepared/manifest.json').read_text())
                require(manifest['allocator-first.so'] == {'bytes': original.stat().st_size,
                        'sha256': settings.digest(original)}, 'prepared allocator observer differs')
            info = original.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == (1000 if allocator else 0)
                    and not info.st_mode & 0o022 and 0 < info.st_size <= 1048576,
                    'installed allocation collector authority differs')
            payload = original.read_bytes()
            with preload.open('xb') as output:
                output.write(payload)
                os.fchmod(output.fileno(), 0o444)
                preload_identity = os.fstat(output.fileno())
            require(preload.read_bytes() == payload, 'allocation collector copy differs')
            print(('LINUX_INSTALLED_ALLOCATOR_PRELOAD=' if allocator else 'LINUX_INSTALLED_HEAPTRACK_PRELOAD=') + json.dumps({
                'path': str(preload), 'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'acceptance': 'diagnostic-only'}), flush=True)
        with log.open('xb') as output:
            actor = subprocess.Popen([*settings.ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S',
                                      str(SCRIPT), '--session-' + network if network else '--session',
                                      *(['--heaptrack'] if heaptrack else ['--allocator'] if allocator else [])], env=settings.ENV,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=output)
            if network is False:
                observe_cm_startup(receiver, record, actor)
            elif network == 'input-soak':
                observe_soak(record, actor, log)
            elif network == 'input-congestion-soak':
                observe_impaired_soak(settings, record, actor, log)
            elif network in NETWORK_PROFILES:
                observe_network(settings, actor, network)
            raw, _ = actor.communicate(timeout=180)
            require(actor.returncode == 0 and len(raw) <= 4096, 'installed Remote session failed')
            result = json.loads(raw)
            require(set(result) == {'viewer', 'source', 'clock_inode', 'viewer_exit', 'source_exit', 'driver_exit'}
                    and all(result[key] == 0 for key in ('viewer_exit', 'source_exit', 'driver_exit')),
                    'installed Remote session result differs')
        require(receiver.child_record() == record and receiver.credential() == credential
                and settings.user_credential() == profile and receiver.direct_listener(record) == listener,
                'installed Remote changed its child, credentials or listener')
        print('LINUX_INSTALLED_REMOTE_PRESENTATION=' + json.dumps({
            **record, **result, 'listener_inode': listener, 'credential': 'unchanged',
            'profile': 'unchanged', 'session_exit': 0,
            'scenario': network or 'suspend',
            'holds_ms': NETWORK_HOLDS if network == 'network' else [18000] if network == 'backoff'
                        else [65000] * 3 if network == 'expired'
                        else [2000, 6000, 2000] if network == 'input-recovery'
                        else [] if network in ('input-soak', 'input-animation')
                        else [20000] * 12 if network == 'input-congestion-soak'
                        else [20000] * 3 if network else [2000, 6000, 12000],
            'recovery_limit_ms': 2500, 'freshness_limit_ms': 1000,
        }, sort_keys=True), flush=True)
    finally:
        if actor is not None:
            if actor.poll() is None:
                actor.terminate()
            actor.wait(timeout=270 if heaptrack else 20)
            actor.stdout.close()
        if preload_identity is not None:
            current = preload.lstat()
            require((current.st_dev, current.st_ino) == (preload_identity.st_dev, preload_identity.st_ino),
                    'allocation collector copy identity changed')
            preload.unlink()
        if log.exists():
            require(log.stat().st_size <= (6291456 if network in (*SOAK_SCENARIOS, 'input-animation-congestion')
                                          else 2097152 if network == 'expired'
                                          else 2097152 if network == 'input-recovery' else 4194304 if network in INPUT_SCENARIOS
                                          else 1048576),
                    'installed Remote output exceeds its bound')
            print(log.read_text(), end='', flush=True)
        if network is False or network == 'expired':
            server_log_snapshot(settings, receiver, record, 'after')
        if network is False:
            cm_log_snapshot()


if __name__ == '__main__':
    heaptrack = sys.argv[1:] == ['--session-expired', '--heaptrack']
    allocator = sys.argv[1:] == ['--session-expired', '--allocator']
    if heaptrack or allocator:
        sys.argv.pop()
    require(sys.argv[1:] in (['--session'], ['--session-network'], ['--session-loss'], ['--session-congestion'],
                            ['--session-backoff'], ['--session-input-recovery'], ['--session-input-loss'],
                            ['--session-input-congestion'], ['--session-input-soak'],
                            ['--session-input-congestion-soak'], ['--session-input-animation'],
                            ['--session-input-animation-congestion'], ['--session-expired']),
            'closed installed Remote session request required')
    session(network={'--session-network': 'network', '--session-loss': 'loss',
                     '--session-congestion': 'congestion', '--session-backoff': 'backoff',
                     '--session-input-recovery': 'input-recovery', '--session-input-loss': 'input-loss',
                     '--session-input-congestion': 'input-congestion',
                     '--session-input-animation': 'input-animation',
                     '--session-input-animation-congestion': 'input-animation-congestion',
                     '--session-expired': 'expired',
                     '--session-input-soak': 'input-soak',
                     '--session-input-congestion-soak': 'input-congestion-soak'}.get(sys.argv[1], False),
            heaptrack=heaptrack, allocator=allocator)

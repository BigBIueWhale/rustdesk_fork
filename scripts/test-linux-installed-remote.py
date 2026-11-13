#!/usr/bin/env python3
"""Observe Remote pixels and viewer/network recovery through the installed service."""
from contextlib import ExitStack, closing, contextmanager
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


SCRIPT = Path('/mnt/rustdesk-verifier-inputs/repo/scripts/test-linux-installed-remote.py')
COORD = Path('/coord')
NETWORK_ENDPOINT = '/netem.sock'
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
        return {**environment, 'LD_PRELOAD': '/usr/lib/heaptrack/libheaptrack_preload.so',
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
                    require('/usr/lib/heaptrack/libheaptrack_preload.so' in
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
                    '/usr/bin/prlimit', '--fsize=1048576', '--', '/usr/bin/heaptrack_print', str(interpreted),
                    '--merge-backtraces=false', '--print-peaks=true', '--print-leaks=true',
                    '--print-allocators=false', '--print-temporary=false', '--peak-limit=30',
                    '--disable-builtin-suppressions', '--disable-embedded-suppressions',
                    '--print-massif=' + str(timeline), '--massif-detailed-freq=0'],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, env=env)
                self.jobs.append(analyze)
                require(analyze.wait(timeout=120) == 0, 'allocation report failed')
            for name in ('compressor.log', 'interpret.log', 'report.txt', 'timeline.massif'):
                path = self.root / name
                limit = 1048576 if name == 'timeline.massif' else 262144 if name == 'report.txt' else 65536
                require(path.stat().st_size <= limit, 'allocation report exceeds its evidence bound')
                print('LINUX_INSTALLED_HEAPTRACK_REPORT_BEGIN name=' + name,
                      file=sys.stderr, flush=True)
                print(path.read_text(), end='', file=sys.stderr, flush=True)
                print('LINUX_INSTALLED_HEAPTRACK_REPORT_END name=' + name,
                      file=sys.stderr, flush=True)
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


def session(network=False, heaptrack=False):
    require(network is False or network in NETWORK_PROFILES or network in ('input-soak', 'input-animation'),
            'unknown Remote scenario')
    require(not heaptrack or network == 'expired', 'allocation tracing requires the expiry diagnostic')
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
            viewer = subprocess.Popen(['/usr/share/rustdesk/rustdesk', '--connect', '127.0.0.1'],
                                      env=viewer_environment, stdin=subprocess.DEVNULL,
                                      stdout=log('viewer.log'), stderr=subprocess.STDOUT)
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
    require(not heaptrack, 'allocation tracing is diagnostic; ordinary acceptance remains unproved')


def scenario(settings, receiver, record, network=False, heaptrack=False):
    require(network is False or network in NETWORK_PROFILES or network in ('input-soak', 'input-animation'),
            'unknown Remote scenario')
    require(not heaptrack or network == 'expired', 'allocation tracing requires the expiry diagnostic')
    guard(settings, 0)
    COORD.mkdir(mode=0o700)
    os.chown(COORD, 4001, 4001)
    credential, profile = receiver.credential(), settings.user_credential()
    listener = receiver.direct_listener(record)
    require(listener is not None, 'installed Remote listener absent')
    actor = None
    log = settings.WORK / 'installed-remote.log'
    try:
        with log.open('xb') as output:
            actor = subprocess.Popen([*settings.ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S',
                                      str(SCRIPT), '--session-' + network if network else '--session',
                                      *(['--heaptrack'] if heaptrack else [])], env=settings.ENV,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=output)
            if network == 'input-soak':
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
        if log.exists():
            require(log.stat().st_size <= (6291456 if network in (*SOAK_SCENARIOS, 'input-animation-congestion')
                                          else 2097152 if network == 'expired'
                                          else 2097152 if network == 'input-recovery' else 4194304 if network in INPUT_SCENARIOS
                                          else 1048576),
                    'installed Remote output exceeds its bound')
            print(log.read_text(), end='', flush=True)


if __name__ == '__main__':
    heaptrack = sys.argv[1:] == ['--session-expired', '--heaptrack']
    if heaptrack:
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
            heaptrack=heaptrack)

"""Guest-only providers and output observation for installed Remote audio."""

import array
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import time


MEDIA = Path('/mnt/rustdesk-verifier-inputs')
SCRIPT = MEDIA / 'repo/scripts/test-linux-installed-audio.py'
WORK = Path('/var/tmp/rustdesk-linux-service-receiver/installed-audio')
ROOT = WORK / 'root'
MODULES = ROOT / 'usr/lib/pulse-16.1+dfsg1/modules'
COORD = Path('/coord')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def guard(settings, uid):
    settings.guard(uid)
    require(Path(__file__).resolve() == SCRIPT and os.getgid() == uid,
            'installed audio fixture identity differs')


def prepare(settings):
    guard(settings, 0)
    pins = dict(re.findall(r'^([A-Z0-9_]+)="([^"]*)"', (MEDIA / 'repo/scripts/pins.env').read_text(), re.M))
    WORK.mkdir(mode=0o755)
    WORK.chmod(0o755)
    packages = WORK / 'packages'
    for path in (packages, ROOT):
        path.mkdir(mode=0o700)
        os.chown(path, 1000, 1000)
    arguments = {'archive': str(MEDIA / 'pa-runtime-candidate.tar.gz'), 'output': str(packages),
                 'sha256': pins['PA_RUNTIME_CANDIDATE_ARCHIVE_SHA256'],
                 'size': pins['PA_RUNTIME_CANDIDATE_ARCHIVE_SIZE'],
                 'manifest-sha256': pins['PA_RUNTIME_CANDIDATE_MANIFEST_SHA256'],
                 'base': pins['DEV_CHECK_IMAGE_ID'], 'debian-snapshot': pins['DEV_CHECK_DEBIAN_SNAPSHOT'],
                 'security-snapshot': pins['DEV_CHECK_SECURITY_SNAPSHOT'],
                 'version': pins['PA_RUNTIME_PULSEAUDIO_VERSION'],
                 'pa-sha256': pins['PA_RUNTIME_PULSEAUDIO_SHA256'], 'pa-size': pins['PA_RUNTIME_PULSEAUDIO_SIZE']}
    print(settings.run([*settings.ordinary(1000), '/usr/bin/python3', '-B', '-I', '-S',
                        str(SCRIPT.with_name('verify-pa-runtime-candidate.py')),
                        *[item for key, value in arguments.items() for item in ('--' + key, value)]],
                       timeout=60), end='', flush=True)
    archives = sorted(packages.glob('*.deb'))
    require(len(archives) == 40, 'installed audio package closure differs')
    for archive in archives:
        settings.run([*settings.ordinary(1000), '/usr/bin/dpkg-deb', '--extract', str(archive), str(ROOT)])
    base_library = settings.WORK / 'prepared/audio-libgomp.so.1'
    manifest = json.loads((settings.WORK / 'prepared/manifest.json').read_text())
    require(manifest['audio-libgomp.so.1'] == {'bytes': base_library.stat().st_size,
            'sha256': settings.digest(base_library)}, 'audio base dependency differs')
    target = ROOT / 'usr/lib/x86_64-linux-gnu/libgomp.so.1'
    require(not os.path.lexists(target), 'audio base dependency conflicts with a package')
    shutil.copyfile(base_library, target)
    # These tools run with explicit modules, without package configuration or units.
    for relative in ('etc', 'lib/systemd'):
        path = ROOT / relative
        require(path.is_dir() and not path.is_symlink(), 'audio package configuration directory differs')
        shutil.rmtree(path)
    paths = [ROOT, *ROOT.rglob('*')]
    require(len(paths) <= 12000, 'installed audio runtime file count exceeds its bound')
    total = 0
    for path in paths:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode),
                'installed audio runtime contains a special file')
        if path.is_symlink():
            require(path.resolve().is_relative_to(ROOT), 'installed audio runtime link leaves its private root')
        else:
            total += info.st_size if path.is_file() else 0
            path.chmod(0o755 if path.is_dir() or info.st_mode & 0o111 else 0o644)
        os.chown(path, 0, 0, follow_symlinks=False)
    require(total <= 268435456, 'installed audio runtime exceeds its byte bound')
    tools = {name: settings.digest(ROOT / 'usr/bin' / name) for name in ('pulseaudio', 'pactl', 'pacat')}
    print('LINUX_INSTALLED_AUDIO_RUNTIME=' + json.dumps({
        'archive_sha256': arguments['sha256'], 'files': len(paths), 'bytes': total, 'tools': tools,
        'base_libgomp': manifest['audio-libgomp.so.1'],
        'scope': 'private fixture tools; product libraries remain installed dependencies',
    }, sort_keys=True), flush=True)


class SignalSamples:
    def __init__(self):
        self.pending = bytearray()
        self.counts = {'silent': 0, 'tone': 0, 'other': 0}
        self.samples = 0
        self.maximum_rms = self.maximum_coherence = 0
        self.tone_rms = []
        self.coefficients = [(math.cos(2 * math.pi * 440 * n / 48000),
                              math.sin(2 * math.pi * 440 * n / 48000)) for n in range(4800)]

    def read(self, process, timeout=0):
        require(process.poll() is None, 'installed audio observer exited')
        if not select.select([process.stdout], [], [], timeout)[0]:
            return False
        data = os.read(process.stdout.fileno(), 65536)
        require(data, 'installed audio monitor closed')
        self.pending.extend(data)
        while len(self.pending) >= 38400:
            values = array.array('f', self.pending[:38400])
            del self.pending[:38400]
            require(sys.byteorder == 'little' and all(math.isfinite(x) and abs(x) <= 1.1 for x in values),
                    'installed audio samples are invalid')
            left = values[::2]
            energy = sum(x * x for x in left)
            rms = math.sqrt(energy / len(left))
            real = sum(x * c for x, (c, _) in zip(left, self.coefficients))
            imaginary = sum(x * s for x, (_, s) in zip(left, self.coefficients))
            coherence = 2 * (real * real + imaginary * imaginary) / (len(left) * energy) if energy else 0
            self.maximum_rms = max(self.maximum_rms, rms)
            self.maximum_coherence = max(self.maximum_coherence, coherence)
            kind = 'silent' if rms <= 0.000001 else 'tone' if 0.02 <= rms <= 0.8 and coherence >= 0.8 else 'other'
            self.counts[kind] += 1
            if kind == 'tone':
                self.tone_rms.append(rms)
            self.samples += len(left)
            require(self.samples <= 48000 * 150, 'installed audio observation exceeds its duration bound')
        return True

    def summary(self):
        return {'windows': self.counts.copy(), 'maximum_rms': self.maximum_rms,
                'maximum_coherence': self.maximum_coherence}


class AudioFixture:
    def __init__(self, settings, environment, processes, files):
        guard(settings, 4001)
        self.settings, self.processes, self.files = settings, processes, files
        self.environment = environment
        self.environments, self.daemons, self.sockets = {}, [], []
        self.signal = SignalSamples()
        self.source_signal = SignalSamples()
        self.source_monitor = None
        self.last_report = 0
        self.timeline = []
        self.owner = None
        self.snapshot = None
        libraries = ':'.join(str(ROOT / p) for p in ('usr/lib/x86_64-linux-gnu/pulseaudio',
                                                     'usr/lib/x86_64-linux-gnu', 'lib/x86_64-linux-gnu'))
        libraries += ':' + str(MODULES)
        for role in ('controlled', 'viewer'):
            runtime = Path('/run/user/4001/pulse') if role == 'controlled' else COORD / 'viewer-pulse'
            runtime.mkdir(mode=0o700, exist_ok=True)
            info = runtime.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 4001
                    and stat.S_IMODE(info.st_mode) == 0o700, 'audio runtime directory authority differs')
            endpoint = runtime / 'native'
            require(not os.path.lexists(endpoint), 'audio fixture endpoint is occupied')
            self.sockets.append(endpoint)
            env = {**environment, 'LD_LIBRARY_PATH': libraries, 'PULSE_RUNTIME_PATH': str(runtime),
                   'PULSE_SERVER': 'unix:' + str(endpoint), 'PULSE_DLPATH': str(MODULES)}
            if role == 'viewer':
                bus_log = files.enter_context((COORD / 'audio-viewer-bus.log').open('xb'))
                bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
                                       env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=bus_log)
                processes.append(bus)
                files.callback(bus.stdout.close)
                require(select.select([bus.stdout], [], [], 5)[0], 'viewer audio bus did not start')
                address = bus.stdout.readline(4096).decode().strip()
                require(address.startswith('unix:'), 'viewer audio bus is not local')
                env['DBUS_SESSION_BUS_ADDRESS'] = address
            self.environments[role] = env
            log = files.enter_context((COORD / ('audio-' + role + '.log')).open('xb'))
            process = subprocess.Popen([str(ROOT / 'usr/bin/pulseaudio'), '-n', '--daemonize=no',
                '--use-pid-file=no', '--exit-idle-time=-1', '--log-target=stderr',
                '--dl-search-path=' + str(MODULES),
                '--load=module-native-protocol-unix socket=' + str(endpoint),
                '--load=module-null-sink sink_name=' + role + ' rate=48000 channels=2'],
                env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            self.daemons.append(process)
            deadline = time.monotonic() + 5
            while not endpoint.exists():
                require(process.poll() is None and time.monotonic() < deadline,
                        'installed audio daemon did not publish its socket')
                time.sleep(0.02)
            self.query(role, 'info')
        self.viewer_environment = {**environment, 'PULSE_SERVER': self.environments['viewer']['PULSE_SERVER']}
        self.query('controlled', 'load-module', 'module-sine', 'sink=controlled', 'frequency=440')
        self.monitor = self.record('controlled')
        deadline = time.monotonic() + 5
        while self.signal.counts['tone'] < 3 and time.monotonic() < deadline:
            self.sample()
        print('LINUX_INSTALLED_AUDIO_SOURCE=' + json.dumps(self.signal.summary()), file=sys.stderr, flush=True)
        require(self.signal.counts['tone'] >= 3, 'controlled audio monitor did not produce the expected tone')
        self.monitor.terminate()
        require(self.monitor.wait(timeout=5) in (0, -15), 'controlled audio probe did not retire')
        self.signal = SignalSamples()
        require(self.query('viewer', '--format=json', 'list', 'sink-inputs') == [],
                'viewer output is occupied before connection')
        self.monitor = self.record('viewer')
        deadline = time.monotonic() + 5
        while self.signal.counts['silent'] < 3:
            require(time.monotonic() < deadline and not self.signal.counts['tone'] and not self.signal.counts['other'],
                    'viewer output was not silent before the Remote connection')
            self.sample()
        print('LINUX_INSTALLED_AUDIO_BASELINE=' + json.dumps(self.signal.counts), file=sys.stderr, flush=True)
        self.source_monitor = self.record('controlled', adjust_latency=False)

    def record(self, role, adjust_latency=True):
        label = role if adjust_latency else role + '-continuous'
        log = self.files.enter_context((COORD / ('audio-' + label + '-monitor.log')).open('xb'))
        process = subprocess.Popen([str(ROOT / 'usr/bin/pacat'), '--record', '--raw',
            '--device=' + role + '.monitor', '--format=float32le', '--rate=48000', '--channels=2',
            *(['--latency-msec=50'] if adjust_latency else [])],
            env=self.environments[role], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=log)
        self.processes.append(process)
        os.set_blocking(process.stdout.fileno(), False)
        self.files.callback(process.stdout.close)
        return process

    def query(self, role, *arguments):
        value = self.settings.run([str(ROOT / 'usr/bin/pactl'), *arguments],
                                  env=self.environments[role], timeout=3)
        return json.loads(value) if arguments[0] == '--format=json' else value

    def sample(self):
        require(all(p.poll() is None for p in self.daemons),
                'installed audio provider or observer exited')
        drained = self.source_monitor is not None and self.source_signal.read(self.source_monitor)
        self.signal.read(self.monitor, 0 if drained else 0.05)
        now = time.monotonic()
        if self.source_monitor is not None and now - self.last_report >= 1:
            report = {
                'monotonic_ms': int(now * 1000), 'source': self.source_signal.summary(),
                'viewer': self.signal.summary(), 'source_adjust_latency': False,
            }
            require(len(self.timeline) < 150, 'audio timeline exceeds its bound')
            self.timeline.append(report)
            print('LINUX_INSTALLED_AUDIO_TIMELINE=' + json.dumps(report), file=sys.stderr, flush=True)
            self.last_report = now

    def recordings(self):
        streams = self.query('controlled', '--format=json', 'list', 'source-outputs')
        observer = [s for s in streams if int(s['properties']['application.process.id']) == self.source_monitor.pid]
        require(len(observer) == 1, 'continuous source observer is absent or ambiguous')
        return [s for s in streams if s is not observer[0]]

    def observe_owner(self, viewer):
        if self.snapshot is None and self.signal.samples >= 48000 * 5:
            self.snapshot = {role: self.query(role, '--format=json', 'list', kind)
                             for role, kind in (('viewer', 'sink-inputs'), ('controlled', 'source-outputs'))}
            print('LINUX_INSTALLED_AUDIO_STREAMS=' + json.dumps(self.snapshot), file=sys.stderr, flush=True)
        if self.owner is not None or self.signal.counts['tone'] < 3:
            return
        playback = self.query('viewer', '--format=json', 'list', 'sink-inputs')
        recording = self.recordings()
        require(len(playback) == len(recording) == 1, 'installed audio stream ownership is ambiguous')
        require(int(playback[0]['properties']['application.process.id']) == viewer.pid,
                'audio playback is not attributed to the retained viewer')
        require(all(p['corked'] is False and p['mute'] is False for p in (*playback, *recording)),
                'installed audio stream is inactive')
        sources = self.query('controlled', '--format=json', 'list', 'sources')
        source, = [s for s in sources if s['name'] == 'controlled.monitor']
        sinks = self.query('viewer', '--format=json', 'list', 'sinks')
        sink, = [s for s in sinks if s['name'] == 'viewer']
        require(recording[0]['source'] == source['index'] and playback[0]['sink'] == sink['index'],
                'installed audio stream uses the wrong source or output')
        self.owner = {'viewer': viewer.pid, 'cm': int(recording[0]['properties']['application.process.id']),
                      'recording': recording[0]['index'], 'source': source['index'],
                      'playback': playback[0]['index'], 'sink': sink['index']}

    def complete(self):
        print('LINUX_INSTALLED_AUDIO_SAMPLES=' + json.dumps({
            **self.signal.summary(), 'owner': self.owner, 'source': self.source_signal.summary(),
        }), file=sys.stderr, flush=True)
        baseline, = re.findall(r'^FLUTTER_PEER_SUSPEND_BASELINE_OK (.*)$',
                               (COORD / 'driver.log').read_text(), re.M)
        fields = dict(item.split('=', 1) for item in baseline.split())
        steady = [row for row in self.timeline if int(fields['started_ms']) + 3000
                  <= row['monotonic_ms'] <= int(fields['ended_ms'])]
        require(len(steady) >= 2 and steady[-1]['monotonic_ms'] - steady[0]['monotonic_ms'] >= 15000,
                'audio steady observation interval is insufficient')
        counts = {role: {kind: steady[-1][role]['windows'][kind] - steady[0][role]['windows'][kind]
                         for kind in ('silent', 'tone', 'other')} for role in ('source', 'viewer')}
        print('LINUX_INSTALLED_AUDIO_STEADY=' + json.dumps({
            'start_ms': steady[0]['monotonic_ms'], 'end_ms': steady[-1]['monotonic_ms'],
            'windows': counts, 'minimum_tone_percent': 95, 'window_ms': 100,
        }), file=sys.stderr, flush=True)
        for role, windows in counts.items():
            require(sum(windows.values()) >= 100 and windows['tone'] * 100 >= sum(windows.values()) * 95,
                    role + ' steady audio did not retain the expected tone')
        recoveries = re.findall(r'^FLUTTER_PEER_SUSPEND_RECOVERY_OK (.*)$',
                                (COORD / 'driver.log').read_text(), re.M)
        require(len(recoveries) == 3, 'audio recovery phases are incomplete')
        for cycle, line in enumerate(recoveries, 1):
            phase = dict(item.split('=', 1) for item in line.split())
            require(int(phase['cycle']) == cycle and int(phase['healthy_ms']) == 15000
                    and 0 <= int(phase['healthy_started_ms']) - int(phase['resumed_ms']) <= 2500,
                    'audio recovery phase identity or timing differs')
            rows = [row for row in self.timeline if int(phase['healthy_started_ms'])
                    <= row['monotonic_ms'] <= int(phase['healthy_ended_ms'])]
            require(len(rows) >= 2 and rows[-1]['monotonic_ms'] - rows[0]['monotonic_ms'] >= 13000,
                    'audio recovery observation interval is insufficient')
            windows = {role: {kind: rows[-1][role]['windows'][kind] - rows[0][role]['windows'][kind]
                             for kind in ('silent', 'tone', 'other')} for role in ('source', 'viewer')}
            print('LINUX_INSTALLED_AUDIO_RECOVERY=' + json.dumps({
                'cycle': cycle, 'resumed_ms': int(phase['resumed_ms']),
                'start_ms': rows[0]['monotonic_ms'], 'end_ms': rows[-1]['monotonic_ms'],
                'windows': windows, 'minimum_tone_percent': 95, 'window_ms': 100,
                'scope': 'post-suspension output continuity; audio age unmeasured',
            }), file=sys.stderr, flush=True)
            for role, counts in windows.items():
                require(sum(counts.values()) >= 130 and counts['tone'] * 100 >= sum(counts.values()) * 95,
                        role + ' audio did not remain continuous after suspension ' + str(cycle))
        require(self.owner is not None, 'installed Remote audio stream ownership was not observed')
        deadline = time.monotonic() + 5
        initial_silence = self.signal.counts['silent']
        while True:
            self.sample()
            if (self.signal.counts['silent'] >= initial_silence + 3
                    and self.query('viewer', '--format=json', 'list', 'sink-inputs') == []
                    and self.recordings() == []):
                break
            require(time.monotonic() < deadline, 'installed audio did not retire after viewer close')
        print('LINUX_INSTALLED_AUDIO_PLAYBACK=' + json.dumps({
            **self.owner, 'windows': self.signal.counts, 'window_frames': 4800, 'rate': 48000,
            'tone_hz': 440, 'tone_rms_min': min(self.signal.tone_rms), 'tone_rms_max': max(self.signal.tone_rms),
            'retired': True, 'scope': 'native null-sink output; physical audibility unproved',
        }, sort_keys=True), file=sys.stderr, flush=True)

    def retired(self):
        require(all(p.poll() == 0 for p in self.daemons) and self.monitor.poll() in (0, -15)
                and self.source_monitor.poll() in (0, -15)
                and all(not os.path.lexists(p) for p in self.sockets), 'audio fixture did not retire')
        print('LINUX_INSTALLED_AUDIO_RETIRED=' + json.dumps({
            'daemons': [{'pid': p.pid, 'exit': p.returncode} for p in self.daemons],
            'monitor': self.monitor.pid, 'monitor_exit': self.monitor.returncode, 'sockets': 'absent',
            'source_monitor': self.source_monitor.pid, 'source_monitor_exit': self.source_monitor.returncode,
        }), file=sys.stderr, flush=True)

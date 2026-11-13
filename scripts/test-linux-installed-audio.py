"""Guest-only providers and output observation for installed Remote audio."""

import array
import json
import math
import os
from pathlib import Path
import re
import select
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
        'scope': 'private fixture tools; product libraries remain installed dependencies',
    }, sort_keys=True), flush=True)


class AudioFixture:
    def __init__(self, settings, environment, processes, files):
        guard(settings, 4001)
        self.settings, self.processes, self.files = settings, processes, files
        self.environment = environment
        self.environments, self.daemons, self.sockets = {}, [], []
        self.pending = bytearray()
        self.counts = {'silent': 0, 'tone': 0, 'other': 0}
        self.samples = 0
        self.owner = None
        self.tone_rms = []
        self.coefficients = [(math.cos(2 * math.pi * 440 * n / 48000),
                              math.sin(2 * math.pi * 440 * n / 48000)) for n in range(4800)]
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
        require(self.query('viewer', '--format=json', 'list', 'sink-inputs') == [],
                'viewer output is occupied before connection')
        log = files.enter_context((COORD / 'audio-monitor.log').open('xb'))
        self.monitor = subprocess.Popen([str(ROOT / 'usr/bin/pacat'), '--record', '--raw',
            '--device=viewer.monitor', '--format=float32le', '--rate=48000', '--channels=2',
            '--latency-msec=50'], env=self.environments['viewer'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=log)
        processes.append(self.monitor)
        os.set_blocking(self.monitor.stdout.fileno(), False)
        files.callback(self.monitor.stdout.close)
        deadline = time.monotonic() + 5
        while self.counts['silent'] < 3:
            require(time.monotonic() < deadline and not self.counts['tone'] and not self.counts['other'],
                    'viewer output was not silent before the Remote connection')
            self.sample()
        print('LINUX_INSTALLED_AUDIO_BASELINE=' + json.dumps(self.counts), file=sys.stderr, flush=True)

    def query(self, role, *arguments):
        value = self.settings.run([str(ROOT / 'usr/bin/pactl'), *arguments],
                                  env=self.environments[role], timeout=3)
        return json.loads(value) if arguments[0] == '--format=json' else value

    def sample(self):
        require(all(p.poll() is None for p in [*self.daemons, self.monitor]),
                'installed audio provider or observer exited')
        if not select.select([self.monitor.stdout], [], [], 0.05)[0]:
            return
        data = os.read(self.monitor.stdout.fileno(), 65536)
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
            kind = 'silent' if rms <= 0.000001 else 'tone' if 0.02 <= rms <= 0.8 and coherence >= 0.8 else 'other'
            self.counts[kind] += 1
            if kind == 'tone':
                self.tone_rms.append(rms)
            self.samples += len(left)
            require(self.samples <= 48000 * 150, 'installed audio observation exceeds its duration bound')

    def observe_owner(self, viewer):
        if self.owner is not None or self.counts['tone'] < 3:
            return
        playback = self.query('viewer', '--format=json', 'list', 'sink-inputs')
        recording = self.query('controlled', '--format=json', 'list', 'source-outputs')
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
        require(self.owner is not None and self.counts['tone'] >= 8, 'installed Remote did not play the expected tone')
        deadline = time.monotonic() + 5
        initial_silence = self.counts['silent']
        while True:
            self.sample()
            if (self.counts['silent'] >= initial_silence + 3
                    and self.query('viewer', '--format=json', 'list', 'sink-inputs') == []
                    and self.query('controlled', '--format=json', 'list', 'source-outputs') == []):
                break
            require(time.monotonic() < deadline, 'installed audio did not retire after viewer close')
        print('LINUX_INSTALLED_AUDIO_PLAYBACK=' + json.dumps({
            **self.owner, 'windows': self.counts, 'window_frames': 4800, 'rate': 48000,
            'tone_hz': 440, 'tone_rms_min': min(self.tone_rms), 'tone_rms_max': max(self.tone_rms),
            'retired': True, 'scope': 'native null-sink output; physical audibility unproved',
        }, sort_keys=True), file=sys.stderr, flush=True)

    def retired(self):
        require(all(p.poll() == 0 for p in self.daemons) and self.monitor.poll() in (0, -15)
                and all(not os.path.lexists(p) for p in self.sockets), 'audio fixture did not retire')
        print('LINUX_INSTALLED_AUDIO_RETIRED=' + json.dumps({
            'daemons': [{'pid': p.pid, 'exit': p.returncode} for p in self.daemons],
            'monitor': self.monitor.pid, 'monitor_exit': self.monitor.returncode, 'sockets': 'absent',
        }), file=sys.stderr, flush=True)

#!/usr/bin/env python3
"""Presented camera pixels from the actual package's supervised desktop child."""
from contextlib import ExitStack
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import signal
import stat
import subprocess
import sys


SCRIPT = Path('/mnt/rustdesk-verifier-inputs/repo/scripts/test-linux-installed-camera.py')
COORD = Path('/coord')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPT.with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def guard(settings, uid):
    settings.guard(uid)
    require(Path(__file__).resolve() == SCRIPT and os.getgid() == uid
            and os.uname().release == '6.1.0-50-amd64', 'installed camera guest identity differs')
    node = Path('/dev/video2').lstat()
    require(stat.S_ISCHR(node.st_mode) and os.major(node.st_rdev) == 81
            and (node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode)) == (4001, 4001, 0o600)
            and sorted(p.name for p in Path('/dev').glob('video*')) == ['video2'],
            'installed camera device authority differs')


def session():
    settings = module('installed_settings', 'test-linux-installed-settings.py')
    guard(settings, 4001)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    print('LINUX_INSTALLED_CAMERA_FILE_LIMIT=' + json.dumps(resource.getrlimit(resource.RLIMIT_FSIZE)),
          file=sys.stderr, flush=True)
    def cancelled(_signal, _frame):
        raise RuntimeError('installed camera session cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    camera = module('camera_controls', 'flutter-peer-camera.py')
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
            'cannot retain camera viewer descendants')
    environment = {**settings.ENV, 'HOME': '/home/rdreceiver4001', 'USER': 'rdreceiver4001',
                   'XDG_RUNTIME_DIR': '/run/user/4001', 'XDG_SESSION_TYPE': 'x11',
                   'XDG_DATA_DIRS': '/usr/local/share:/usr/share', 'GDK_BACKEND': 'x11',
                   'LIBGL_ALWAYS_SOFTWARE': '1'}
    processes = []
    with ExitStack() as files:
        environment = files.enter_context(settings.recording_display(environment, 79, '1600x1200x24'))
        try:
            bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
                                   env=environment, stdout=subprocess.PIPE, stderr=sys.stderr)
            processes.append(bus)
            require(select.select([bus.stdout], [], [], 5)[0], 'camera session bus did not start')
            address = bus.stdout.readline(4096).decode().strip()
            require(address.startswith('unix:'), 'camera session bus is not local')
            environment['DBUS_SESSION_BUS_ADDRESS'] = address
            camera.color(1)
            viewer = subprocess.Popen(['/usr/share/rustdesk/rustdesk', '--view-camera', '127.0.0.1'],
                                      env=environment, stdin=subprocess.DEVNULL,
                                      stdout=sys.stderr, stderr=sys.stderr)
            processes.append(viewer)
            start = Path(f'/proc/{viewer.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
            driver_log = files.enter_context((COORD / 'driver.log').open('xb'))
            driver = subprocess.Popen([str(settings.WORK / 'camera-driver'), ':79', ':79',
                                       str(viewer.pid), start, '--camera-reacquire'], env=environment,
                                      stdout=driver_log, stderr=subprocess.STDOUT)
            processes.append(driver)
            camera.wait_for(viewer.pid, start, lambda: camera.marker('camera.reacquire.green'),
                            'installed green pixels')
            print(json.dumps({'stage': 'green', 'viewer': viewer.pid}), flush=True)
            require(sys.stdin.readline() == 'continue\n', 'camera owner did not admit the next color')
            camera.color(2)
            camera.marker('camera.reacquire.blue', True)
            require(driver.wait(timeout=25) == 0, 'installed camera pixel observer failed')
            require(viewer.wait(timeout=10) == 0, 'camera viewer did not close normally')
            print(json.dumps({'stage': 'closed', 'viewer': viewer.pid}), flush=True)
            require(sys.stdin.readline() == 'continue\n', 'camera owner did not observe retirement')
        finally:
            print('LINUX_INSTALLED_CAMERA_PROCESSES=' + json.dumps([
                {'pid': process.pid, 'exit_before_cleanup': process.poll()}
                for process in processes], sort_keys=True), file=sys.stderr, flush=True)
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
            settings.retire_children()
            path = COORD / 'driver.log'
            if path.exists():
                require(path.stat().st_size <= 131072, 'camera observer output exceeds its bound')
                print(path.read_text(), end='', file=sys.stderr, flush=True)


def scenario(settings, receiver, record):
    guard(settings, 0)
    camera = module('camera_controls', 'flutter-peer-camera.py')
    COORD.mkdir(mode=0o700)
    os.chown(COORD, 4001, 4001)
    credential, profile = receiver.credential(), settings.user_credential()
    camera.retained(record['pid'], str(record['start']), 0, 'installed-before-viewer')
    log = settings.WORK / 'installed-camera.log'
    actor = None

    def unchanged():
        require(receiver.child_record() == record and receiver.credential() == credential
                and settings.user_credential() == profile
                and receiver.direct_listener(record) is not None
                and not camera.descriptors(record['supervisor']),
                'installed camera changed its child, authority, listener or supervisor device ownership')

    def reply(stage):
        require(select.select([actor.stdout], [], [], 70)[0], 'installed camera session deadline')
        raw = actor.stdout.readline(4096)
        require(raw and raw.endswith(b'\n'), 'installed camera session ended before ' + stage)
        response = json.loads(raw)
        require(set(response) == {'stage', 'viewer'} and response['stage'] == stage
                and type(response['viewer']) is int and response['viewer'] > 1,
                'installed camera session response differs')
        return response['viewer']

    try:
        with log.open('xb') as output:
            actor = subprocess.Popen([*settings.ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S',
                                      str(SCRIPT), '--session'], env=settings.ENV,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=output)
            viewer = reply('green')
            camera.retained(record['pid'], str(record['start']), 1, 'installed-green')
            unchanged()
            actor.stdin.write(b'continue\n')
            actor.stdin.flush()
            require(reply('closed') == viewer, 'installed camera replaced its viewer')
            camera.retained(record['pid'], str(record['start']), 0, 'installed-after-viewer')
            unchanged()
            actor.stdin.write(b'continue\n')
            actor.stdin.flush()
            require(actor.wait(timeout=15) == 0, 'installed camera session cleanup failed')
        print('LINUX_INSTALLED_CAMERA_PRESENTATION=' + json.dumps({
            **record, 'viewer': viewer, 'colors': ['green', 'blue'], 'pixel_samples_per_color': 3,
            'pixels_per_sample': 24000, 'credential': 'unchanged', 'profile': 'unchanged',
            'camera_descriptors': [0, 1, 0], 'supervisor_camera_descriptors': 0,
            'viewer_exit': 0, 'session_exit': 0,
        }, sort_keys=True), flush=True)
    finally:
        if actor is not None:
            actor.stdin.close()
            if actor.poll() is None:
                actor.terminate()
            actor.wait(timeout=15)
            actor.stdout.close()
        if log.exists():
            require(log.stat().st_size <= 1048576, 'installed camera output exceeds its bound')
            print(log.read_text(), end='', flush=True)


if __name__ == '__main__':
    require(sys.argv[1:] == ['--session'], 'closed installed camera session request required')
    session()

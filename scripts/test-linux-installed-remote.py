#!/usr/bin/env python3
"""Observe Remote pixels and paused-viewer recovery through the installed service."""
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
import time


SCRIPT = Path('/mnt/rustdesk-verifier-inputs/repo/scripts/test-linux-installed-remote.py')
COORD = Path('/coord')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def guard(settings, uid):
    settings.guard(uid)
    require(Path(__file__).resolve() == SCRIPT and os.getgid() == uid,
            'installed Remote guest identity differs')


def session():
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
            source = subprocess.Popen([str(settings.WORK / 'presentation-source')],
                env={**environment, 'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                     'RUSTDESK_PRESENTATION_TRACE': '1'},
                stdout=log('frame-source.log'), stderr=log('source-error.log'))
            processes.append(source)
            deadline = time.monotonic() + 5
            while (COORD / 'frame-source.log').stat().st_size == 0:
                require(source.poll() is None and time.monotonic() < deadline,
                        'installed Remote source did not publish')
                time.sleep(0.05)
            viewer = subprocess.Popen(['/usr/share/rustdesk/rustdesk', '--connect', '127.0.0.1'],
                                      env=environment, stdin=subprocess.DEVNULL,
                                      stdout=log('viewer.log'), stderr=subprocess.STDOUT)
            processes.append(viewer)
            start = Path(f'/proc/{viewer.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
            driver = subprocess.Popen([str(settings.WORK / 'presentation-driver'), ':77', ':79',
                                       str(viewer.pid), start, '--viewer-suspend'],
                                      env={**environment, 'XAUTHORITY': str(authority)},
                                      stdout=log('driver.log'), stderr=subprocess.STDOUT)
            processes.append(driver)
            clock = Path('/proc/self/ns/time').stat()
            for process in (source, viewer, driver):
                current = Path(f'/proc/{process.pid}/ns/time').stat()
                require((current.st_dev, current.st_ino) == (clock.st_dev, clock.st_ino),
                        'Remote observer and source clocks differ')
            require(driver.wait(timeout=120) == 0, 'installed Remote pixel observer failed')
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
            for process in reversed(processes):
                if process.poll() is None:
                    if process is viewer:
                        process.send_signal(signal.SIGCONT)
                    process.terminate()
                process.wait(timeout=8)
            settings.retire_children()
            for name in ('driver.log', 'source-error.log', 'frame-source.log', 'viewer.log'):
                path = COORD / name
                if path.exists():
                    require(path.stat().st_size <= 131072, 'Remote observer output exceeds its bound')
                    print(path.read_text(), end='', file=sys.stderr, flush=True)


def scenario(settings, receiver, record):
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
                                      str(SCRIPT), '--session'], env=settings.ENV,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=output)
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
            'profile': 'unchanged', 'session_exit': 0, 'holds_ms': [2000, 6000, 12000],
            'recovery_limit_ms': 2500, 'freshness_limit_ms': 1000,
        }, sort_keys=True), flush=True)
    finally:
        if actor is not None:
            if actor.poll() is None:
                actor.terminate()
            actor.wait(timeout=20)
            actor.stdout.close()
        if log.exists():
            require(log.stat().st_size <= 1048576, 'installed Remote output exceeds its bound')
            print(log.read_text(), end='', flush=True)


if __name__ == '__main__':
    require(sys.argv[1:] == ['--session'], 'closed installed Remote session request required')
    session()

#!/usr/bin/env python3
"""Real Flutter password controls with the installed service, in the owned VM only."""

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time

MEDIA = Path('/mnt/rustdesk-verifier-inputs')
SCRIPT = MEDIA / 'repo/scripts/test-linux-installed-settings.py'
WORK = Path('/var/tmp/rustdesk-linux-service-receiver')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def run(argv, *, env=ENV, timeout=30):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    if len(result.stdout) + len(result.stderr) > 131072:
        raise RuntimeError('installed settings command exceeded its output bound')
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}: {result.stdout[-8192:]} {result.stderr[-8192:]}')
    return result.stdout


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def guard(uid=0):
    marker = Path('/run/rustdesk-verifier-vm').lstat()
    if (os.geteuid() != uid or marker.st_uid != 0 or not stat.S_ISDIR(marker.st_mode)
            or Path('/proc/1/comm').read_text().strip() != 'systemd'
            or sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']
            or Path(__file__).resolve() != SCRIPT):
        raise RuntimeError('installed settings require the owned zero-NIC systemd VM')


def receiver_module():
    spec = importlib.util.spec_from_file_location('installed_receiver', SCRIPT.with_name('test-linux-service-receiver-native.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ordinary(uid):
    return ['/usr/bin/setpriv', f'--reuid={uid}', f'--regid={uid}', '--clear-groups',
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']


def install(source, target, mode=0o644):
    target = Path(target)
    missing = []
    parent = target.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir()
        parent.chmod(0o755)
    shutil.copyfile(source, target)
    target.chmod(mode)
    if digest(source) != digest(target):
        raise RuntimeError(f'installed copy differs: {target}')


def prepare():
    if os.getuid() != 1000 or not Path('/.dockerenv').is_file():
        raise RuntimeError('settings runtime preparation requires the ordinary isolated container')
    for kind in ('xvfb', 'atspi'):
        print(run(['/bin/bash', f'/work/scripts/smoke-{kind}-prepare.sh'], timeout=60), end='', flush=True)
    flags = run(['/usr/bin/pkg-config', '--cflags', '--libs', 'x11', 'xtst', 'xi',
                 'atspi-2', 'gobject-2.0', 'gtk+-3.0']).split()
    for copy in ('first', 'second'):
        run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             '/work/scripts/linux-installed-settings-x11.c', *flags, '-o', f'/out/driver-{copy}'], timeout=60)
    if digest('/out/driver-first') != digest('/out/driver-second'):
        raise RuntimeError('repeated settings driver builds differ')
    libraries = Path('/out/libraries')
    libraries.mkdir()
    roots = []
    for path in Path('/app/bundle').rglob('*'):
        if path.is_file():
            with path.open('rb') as stream:
                if stream.read(4) == b'\x7fELF':
                    roots.append(path)
    roots += [Path('/out/driver-first'), Path('/xvfb-root/usr/bin/Xvfb'),
              Path('/xvfb-root/usr/bin/xkbcomp'), Path('/usr/bin/dbus-daemon'),
              Path('/atspi-root/usr/libexec/at-spi-bus-launcher'),
              Path('/atspi-root/usr/libexec/at-spi2-registryd')]
    dynamic = [Path('/usr/lib/x86_64-linux-gnu') / name for name in
               ('dri/swrast_dri.so', 'libEGL_mesa.so.0', 'libGLX_mesa.so.0',
                'libEGL.so.1', 'libGLESv2.so.2', 'libGL.so.1', 'libGLX.so.0')]
    if not all(p.is_file() for p in dynamic):
        raise RuntimeError('pinned image lacks the software renderer closure')
    roots += dynamic
    environment = {**ENV, 'LD_LIBRARY_PATH': '/app/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu'}
    for executable in roots:
        listing = run(['/usr/bin/ldd', str(executable)], env=environment)
        if 'not found' in listing:
            raise RuntimeError(f'missing settings runtime dependency: {listing}')
        dependencies = [Path(m) for m in re.findall(r'(?:=>\s+|^\s*)(/\S+)\s+\(', listing, re.M)]
        if executable in dynamic:
            dependencies.append(executable)
        for source in dependencies:
            if str(source).startswith('/app/'):
                continue
            target = libraries / source.name
            if target.exists():
                if digest(target) != digest(source):
                    raise RuntimeError(f'runtime dependency basename collision: {source.name}')
            else:
                shutil.copyfile(source, target)
    for source, name in (('/usr/share/X11/xkb', 'xkb'),
                         ('/usr/share/fonts/truetype/dejavu', 'fonts')):
        shutil.copytree(source, '/out/' + name)
    vendor = Path('/usr/share/glvnd/egl_vendor.d/50_mesa.json')
    if json.loads(vendor.read_text()) != {'file_format_version': '1.0.0',
                                         'ICD': {'library_path': 'libEGL_mesa.so.0'}}:
        raise RuntimeError('pinned Mesa vendor discovery differs')
    shutil.copyfile(vendor, '/out/50_mesa.json')
    records = {str(p.relative_to('/out')): {'sha256': digest(p), 'bytes': p.stat().st_size}
               for p in Path('/out').rglob('*') if p.is_file()}
    if sum(r['bytes'] for r in records.values()) > 268435456:
        raise RuntimeError('settings runtime closure exceeds 256 MiB')
    Path('/out/manifest.json').write_text(json.dumps(records, sort_keys=True))
    print(f'LINUX_INSTALLED_SETTINGS_PREPARED=pass driver_builds=2 equality=bytes runtime_files={len(records)}', flush=True)


def prepare_runtime(source, execution, image, client, sock, config):
    prepared = WORK / 'prepared'
    prepared.mkdir(mode=0o700)
    os.chown(prepared, 1000, 1000)
    mounts = [(str(source), '/work', True), (str(execution), '/app', True),
              (str(prepared), '/out', False)]
    for kind in ('xvfb', 'atspi'):
        mounts.append((str(source / 'online/inputs' / (kind + '-debs')), f'/{kind}-inputs', True))
        for suffix in ('debs', 'root'):
            path = WORK / f'{kind}-{suffix}'
            path.mkdir(mode=0o700)
            os.chown(path, 1000, 1000)
            mounts.append((str(path), f'/{kind}-{suffix}', False))
    docker_env = {**ENV, 'HOME': '/nonexistent', 'DOCKER_CONFIG': config}
    command = [*ordinary(1000), client, '--host', 'unix://' + sock]

    def docker(args, timeout=30):
        return run([*command, *args], env=docker_env, timeout=timeout)

    args = ['create', '--pull=never', '--network=none', '--read-only', '--user=1000:1000',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--security-opt=apparmor=docker-default',
            '--cgroupns=private', '--ipc=private', '--memory=1g', '--memory-swap=1g', '--cpus=2',
            '--pids-limit=128', '--ulimit=core=0:0', '--ulimit=fsize=268435456:268435456',
            '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=700,uid=1000,gid=1000']
    for host, target, readonly in mounts:
        args += ['--mount', f'type=bind,source={host},target={target},bind-recursive=disabled' + (',readonly' if readonly else '')]
    args += [image, '/usr/bin/python3', '-B', '-I', '-S', '/work/scripts/test-linux-installed-settings.py', '--prepare']
    container = docker(args).strip()
    if re.fullmatch('[0-9a-f]{64}', container) is None:
        raise RuntimeError('settings preparation container identity differs')
    try:
        detail, = json.loads(docker(['inspect', container]))
        host = detail['HostConfig']
        required = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                    'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                    'CapDrop': ['ALL'], 'Devices': [], 'PortBindings': {},
                    'Memory': 1073741824, 'MemorySwap': 1073741824, 'NanoCpus': 2000000000,
                    'PidsLimit': 128, 'SecurityOpt': ['no-new-privileges', 'apparmor=docker-default']}
        actual_mounts = sorted((m['Source'], m['Destination'], not m['RW']) for m in detail['Mounts'])
        if (detail['Image'] != image or detail['Config']['User'] != '1000:1000'
                or any(host.get(k) != v for k, v in required.items()) or actual_mounts != sorted(mounts)):
            raise RuntimeError('settings preparation container authority differs')
        print(docker(['start', '--attach', container], timeout=180), end='', flush=True)
        if docker(['inspect', '--format', '{{.State.Status}}:{{.State.ExitCode}}', container]).strip() != 'exited:0':
            raise RuntimeError('settings preparation did not exit successfully')
    finally:
        # This exact guest-only container owns every compiler/preparer descendant.
        if docker(['inspect', '--format', '{{.State.Running}}', container]).strip() == 'true':
            docker(['kill', container])
        docker(['wait', container])
        docker(['rm', container])
    records = json.loads((prepared / 'manifest.json').read_text())
    for name, record in records.items():
        path = prepared / name
        if path.is_symlink() or path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise RuntimeError('prepared runtime bytes changed')
    return prepared


def install_runtime(prepared):
    runtime = Path('/usr/local/lib/rustdesk-settings-fixture')
    runtime.mkdir(mode=0o755)
    runtime.chmod(0o755)
    for library in (prepared / 'libraries').iterdir():
        if re.match(r'^(ld-linux|lib(c|m|pthread|dl|rt|util|anl|resolv)\.so\.)', library.name):
            continue  # The signed OS packages own libc and its matching interpreter.
        install(library, runtime / library.name)
    Path('/etc/ld.so.conf.d/rustdesk-settings-fixture.conf').write_text(str(runtime) + '\n')
    for path in (WORK / 'atspi-root/usr').rglob('*'):
        if path.is_file():
            relative = path.relative_to(WORK / 'atspi-root')
            install(path, Path('/') / relative, 0o755 if 'libexec' in path.parts else 0o644)
    install(WORK / 'xvfb-root/usr/bin/Xvfb', WORK / 'Xvfb', 0o755)
    install(WORK / 'xvfb-root/usr/bin/xkbcomp', '/usr/bin/xkbcomp', 0o755)
    for path in (WORK / 'xvfb-root/usr/lib').rglob('*.so*'):
        if path.is_file():
            install(path, runtime / path.name)
    for name in ('xkb', 'fonts'):
        shutil.copytree(prepared / name, WORK / name)
        for path in [WORK / name, *(WORK / name).rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
    install(prepared / 'driver-first', WORK / 'settings-driver', 0o755)
    install(prepared / '50_mesa.json', '/usr/share/glvnd/egl_vendor.d/50_mesa.json')
    (WORK / 'fonts.conf').write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd">'
        f'<fontconfig><dir>{WORK}/fonts</dir><cachedir>/tmp/rustdesk-font-cache</cachedir></fontconfig>')
    (WORK / 'fonts.conf').chmod(0o644)
    run(['/usr/sbin/ldconfig'])
    listing = run([*ordinary(4001), '/usr/bin/ldd', str(WORK / 'Xvfb')])
    if 'not found' in listing:
        raise RuntimeError(f'ordinary desktop cannot load its installed runtime: {listing}')


def retire_children():
    deadline = time.monotonic() + 8
    while True:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if not pid:
                    break
            except ChildProcessError:
                return
        children = Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
        for child in children:
            try:
                fd = os.pidfd_open(int(child))
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(fd, signal.SIGTERM)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        if time.monotonic() >= deadline:
            raise RuntimeError('owned GUI/session descendants did not retire')
        time.sleep(0.05)


def session():
    guard(4001)
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot retain GUI descendants')
    environment = {**ENV, 'HOME': '/home/rdreceiver4001', 'USER': 'rdreceiver4001',
                   'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                   'XDG_RUNTIME_DIR': '/run/user/4001', 'XDG_SESSION_TYPE': 'x11',
                   'XDG_DATA_DIRS': '/usr/local/share:/usr/share', 'GDK_BACKEND': 'x11',
                   'LIBGL_ALWAYS_SOFTWARE': '1', 'LIBGL_DRIVERS_PATH': '/usr/local/lib/rustdesk-settings-fixture',
                   'FONTCONFIG_FILE': str(WORK / 'fonts.conf')}
    bus = app = None
    try:
        bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
                               env=environment, stdout=subprocess.PIPE, stderr=sys.stderr)
        if not select.select([bus.stdout], [], [], 5)[0]:
            raise RuntimeError('owned session bus did not start')
        address = bus.stdout.readline(4096).decode().strip()
        if not address.startswith('unix:'):
            raise RuntimeError('owned session bus is not local')
        environment['DBUS_SESSION_BUS_ADDRESS'] = address
        app = subprocess.Popen(['/usr/share/rustdesk/rustdesk'], env=environment,
                               stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
        stages = ('open', 'cancel', 'reopen', 'submit', 'denied', 'reopen', 'submit', 'denied')
        for stage in stages:
            output = run([str(WORK / 'settings-driver'), str(app.pid), stage], env=environment, timeout=40)
            print(output, end='', file=sys.stderr, flush=True)
            if app.poll() is not None:
                raise RuntimeError('GUI exited during the settings workflow')
            print(json.dumps({'stage': stage, 'pid': app.pid}), flush=True)
            if sys.stdin.readline() != 'continue\n':
                raise RuntimeError('GUI scenario lost its owning controller')
    finally:
        for process in (app, bus):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
        retire_children()


def scenario(receiver):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('installed settings require absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    process = None
    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        record = receiver.ready()
        receiver.change(0, 'Installed-baseline-2026!', True)
        before = receiver.credential()
        print('LINUX_INSTALLED_SETTINGS_BASELINE=pass service=actual credential=root-provisioned '
              'child=supervised desktop=pam-logind-x11', flush=True)
        process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S', str(SCRIPT), '--session'],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for stage in ('open', 'cancel', 'reopen', 'submit', 'denied', 'reopen', 'submit', 'denied'):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('installed GUI stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'installed GUI ended before stage {stage}')
            event = json.loads(raw)
            if event.get('stage') != stage or receiver.credential() != before or receiver.child_record() != record:
                raise RuntimeError(f'installed GUI stage or protected credential differs: {event}')
            print('LINUX_INSTALLED_SETTINGS_OBSERVED=' + json.dumps({**event, 'credential_unchanged': True,
                  'service_generation': record['generation']}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('installed GUI session did not retire successfully')
        journal = run(['/usr/bin/journalctl', '--unit=rustdesk.service', '--no-pager', '-o', 'cat'])
        refusals = [line for line in journal.splitlines()
                    if 'polkit denied action=com.carriez.RustDesk.set-unattended-password' in line
                    and f'subject={event["pid"]},' in line]
        if len(refusals) != 2 or receiver.credential() != before:
            raise RuntimeError('visible errors do not match two actual service authorization refusals')
        print('LINUX_INSTALLED_SETTINGS_REFUSALS=' + json.dumps(refusals), flush=True)
    finally:
        if process is not None:
            if process.poll() is None:
                process.stdin.close()  # EOF makes the owning controller drain its actual children.
                process.wait(timeout=50)
            for pipe in (process.stdin, process.stdout):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
        if Path('/sys/fs/cgroup/system.slice/rustdesk.service').exists():
            raise RuntimeError('installed service cgroup remains after stop')


def main(arguments):
    guard()
    source, app_input, context, manifest_sha, commit, provider, image, client, sock, config, archive_sha, polkit_manifest = arguments
    source, app_input, provider = Path(source), Path(app_input), Path(provider)
    receiver = receiver_module()
    receiver.guard()
    WORK.mkdir(mode=0o711)
    WORK.chmod(0o711)
    parent = WORK / 'app'
    parent.mkdir(mode=0o700)
    os.chown(parent, 1000, 1000)
    def identity(path):
        info = path.stat()
        return f'{info.st_dev}:{info.st_ino}'
    execution = run([*ordinary(1000), '/usr/bin/python3', '-B', '-I', '-S',
        str(source / 'scripts/linux-flutter-artifact.py'), 'materialize', '--root', str(app_input),
        '--root-identity', identity(app_input), '--parent', str(parent), '--parent-identity', identity(parent),
        '--context', context, '--manifest-sha256', manifest_sha], timeout=60).strip()
    if execution != str(parent / 'materialized-flutter-app'):
        raise RuntimeError('materialized app destination differs')
    execution = Path(execution)
    prepared = prepare_runtime(source, execution, image, client, sock, config)
    receiver.install_polkit(archive_sha, polkit_manifest)
    install_runtime(prepared)
    manifest = json.loads((app_input / 'app-manifest.json').read_text())
    if digest(app_input / 'app-manifest.json') != manifest_sha or manifest['context'] != json.loads(context):
        raise RuntimeError('installed app manifest changed')
    bundle = Path('/usr/share/rustdesk')
    if bundle.exists():
        raise RuntimeError('installed app destination was occupied')
    for name, record in manifest['files'].items():
        path = execution / name
        if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise RuntimeError('materialized payload differs before installation')
        if name.startswith('bundle/'):
            install(path, bundle / name[len('bundle/'):], 0o755 if name == 'bundle/rustdesk' else 0o644)
    for path in [bundle, *(p for p in bundle.rglob('*') if p.is_dir())]:
        path.chmod(0o755)
    install(bundle / 'rustdesk', bundle / 'rustdesk-service-child', 0o711)
    Path('/usr/bin/rustdesk').symlink_to('../share/rustdesk/rustdesk')
    install(provider / 'libxdo.so.3', '/usr/lib/rustdesk-fork/libxdo.so.3')
    Path('/usr/lib/rustdesk-fork').chmod(0o755)
    receiver.installed_desktop(lambda: scenario(receiver), settings=True)
    for name, record in manifest['files'].items():
        if name.startswith('bundle/') and digest(bundle / name[len('bundle/'):]) != record['sha256']:
            raise RuntimeError('installed application changed during execution')
    print(f'LINUX_INSTALLED_SETTINGS_NATIVE=pass cases=3 app_commit={commit} manifest_sha256={manifest_sha} '
          'ui=actual service=actual cancellation=before-submit denial=no-agent credential=unchanged cleanup=joined', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']:
        prepare()
    elif sys.argv[1:] == ['--session']:
        session()
    elif len(sys.argv) == 14 and sys.argv[1] == '--run':
        main(sys.argv[2:])
    else:
        raise SystemExit('closed installed-settings arguments required')

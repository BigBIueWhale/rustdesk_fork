#!/usr/bin/env python3
"""Real Flutter password controls with the installed service, in the owned VM only."""

import ctypes
import errno
from contextlib import ExitStack, contextmanager
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import runpy
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import termios
import time

MEDIA = Path('/mnt/rustdesk-verifier-inputs')
SCRIPT = MEDIA / 'repo/scripts/test-linux-installed-settings.py'
WORK = Path('/var/tmp/rustdesk-linux-service-receiver')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
BASELINE_PASSWORD = 'Installed-baseline-2026!'
GUI_PASSWORD = 'InstalledGui2026'
CONCURRENT_PASSWORD = 'InstalledConcurrent2026'
GRAPHICAL_AGENT = Path('/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1')
GRAPHICAL_AGENT_SHA = '2a7cec811453d11b56cde55a4fba340767c7e996931179a474d4e5d5fcb70df0'
STAGES = ('open', 'fill', 'cancel', 'reopen', 'submit', 'denied', 'reopen', 'submit', 'denied',
          'reopen', 'fill', 'submit-approved', 'applied', 'reopen', 'submit', 'denied',
          'recording-open', 'recording-denied', 'recording-enable-submit', 'recording-enable',
          'recording-disable-submit', 'recording-disable', 'recording-enable-submit', 'recording-enable')
RESTART_STAGES = ('open', 'fill', 'submit', 'failed', 'reopen', 'submit', 'denied', 'recording-restarted')
LIVE_RECORDING_STAGES = ('recording-live', 'recording-disable-submit', 'recording-live-disabled',
                         'recording-enable-submit', 'recording-live-enabled', 'recording-live-finished')
UNCERTAIN_STAGES = (('open', 'fill', 'submit-approved') + ('pending',) * 21
                    + ('uncertain', 'uncertain-preserved', 'cancel', 'reopen', 'submit', 'denied'))
ADMIN_FAILURE_STAGES = ('open', 'fill', 'submit', 'denied', 'reopen', 'fill',
                        'submit-approved', 'applied', 'reopen', 'submit', 'denied')
GRAPHICAL_STAGES = ('open', 'fill', 'submit', 'denied', 'reopen', 'fill', 'submit',
                    'agent-select', 'agent-password', 'agent-cancel', 'denied',
                    'reopen', 'fill', 'submit-approved', 'pending', 'applied', 'reopen', 'submit', 'denied')
RECORDING_GRAPHICAL_STAGES = ('recording-open', 'recording-enable-submit', 'recording-cancelled',
    'recording-enable-submit', 'recording-agent-select', 'recording-agent-password',
    'recording-agent-cancel', 'recording-cancelled', 'recording-enable-submit',
    'recording-enable', 'recording-disable-submit', 'recording-disable', 'recording-return-security')


def run(argv, *, env=ENV, timeout=30, output_limit=131072):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    if len(result.stdout) + len(result.stderr) > output_limit:
        raise RuntimeError('installed settings command exceeded its output bound')
    if result.returncode:
        if argv[0] == str(WORK / 'settings-driver'):
            print(result.stdout, end='', file=sys.stderr, flush=True)
            print(result.stderr, end='', file=sys.stderr, flush=True)
            raise RuntimeError(f'installed settings driver exited {result.returncode}')
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


def prepare_drivers(graphical=False, camera=False, remote=False):
    flags = run(['/usr/bin/pkg-config', '--cflags', '--libs', 'x11', 'xtst', 'xi',
                 'atspi-2', 'gobject-2.0', 'gtk+-3.0', 'vpx']).split()
    for copy in ('first', 'second'):
        run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             '/work/scripts/' + ('flutter-peer-presentation-x11.c' if camera or remote else 'linux-installed-settings-x11.c'),
             *flags, '-o', f'/out/driver-{copy}'], timeout=60)
    if digest('/out/driver-first') != digest('/out/driver-second'):
        raise RuntimeError('repeated settings driver builds differ')
    if camera:
        return
    source_flags = run(['/usr/bin/pkg-config', '--cflags', '--libs', 'x11']).split()
    for copy in ('first', 'second'):
        run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             *([] if remote else ['-DSOURCE_WIDTH=1024U', '-DSOURCE_HEIGHT=768U']),
             '/work/scripts/flutter-peer-source-x11.c', *source_flags,
             '-o', f'/out/source-{copy}'], timeout=60)
    if digest('/out/source-first') != digest('/out/source-second'):
        raise RuntimeError('repeated recording source builds differ')
    if remote:
        return
    run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
         '/work/scripts/test-x11-frame-oracle.c', *flags, '-o', '/out/frame-oracle'], timeout=60)
    print(run(['/out/frame-oracle', '--unit']), end='', flush=True)
    if graphical:
        for copy in ('first', 'second'):
            run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                 '/work/scripts/linux-polkit-dialog-x11.c', *flags, '-o', f'/out/agent-driver-{copy}'], timeout=60)
        if digest('/out/agent-driver-first') != digest('/out/agent-driver-second'):
            raise RuntimeError('repeated graphical-agent driver builds differ')


def upgrade_manifest(source, inputs):
    pins = dict(re.findall(r'^([A-Z0-9_]+)="([^"]*)"', (source / 'scripts/pins.env').read_text(), re.M))
    manifest = inputs / 'app-manifest.json'
    core = inputs / 'librustdesk.so'
    for path, limit in ((manifest, 524288), (core, int(pins['DEBIAN_UPGRADE_CORE_SIZE']))):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise RuntimeError('Debian upgrade input type or size differs')
    if (digest(manifest) != pins['DEBIAN_UPGRADE_APP_MANIFEST_SHA256']
            or digest(core) != pins['DEBIAN_UPGRADE_CORE_SHA256']
            or core.stat().st_size != int(pins['DEBIAN_UPGRADE_CORE_SIZE'])):
        raise RuntimeError('Debian upgrade input identity differs')
    previous = json.loads(manifest.read_text())
    if (previous['context']['source_commit'] != pins['DEBIAN_UPGRADE_APP_COMMIT']
            or previous['files']['bundle/lib/librustdesk.so'] != {
                'bytes': core.stat().st_size, 'sha256': digest(core)}):
        raise RuntimeError('Debian upgrade source manifest differs')
    return previous


def historical_conffiles(source, inputs):
    pins = dict(re.findall(r'^([A-Z0-9_]+)="([^"]*)"', (source / 'scripts/pins.env').read_text(), re.M))
    contents = {}
    for name, key in (('startwm.sh', 'STARTWM'), ('xorg.conf', 'XORG')):
        path = inputs / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 8192
                or digest(path) != pins['DEBIAN_CONFFILE_' + key + '_SHA256']):
            raise RuntimeError('historical conffile input differs')
        contents[name] = path.read_bytes()
    return contents


def prepare_package(single=False, graphical=False, settings=False, upgrade=False, conffiles=False, camera=False, remote=False):
    if os.getuid() != 1000 or not Path('/.dockerenv').is_file():
        raise RuntimeError('candidate packaging requires the ordinary isolated container')
    os.chdir('/work')
    epoch, = re.findall(r'^SOURCE_DATE_EPOCH_PIN="([0-9]+)"$', Path('scripts/pins.env').read_text(), re.M)
    os.environ['SOURCE_DATE_EPOCH'] = epoch
    os.environ['DPKG_DEB_THREADS_MAX'] = '2'
    module = runpy.run_path('/work/build.py')
    version = module['get_version']()
    bundle = Path('/app/bundle')
    original = {str(p.relative_to(bundle)): digest(p) for p in bundle.rglob('*') if p.is_file()}
    selected = [(name, bundle, original) for name in (('first',) if single else ('first', 'second'))]
    if upgrade:
        previous = upgrade_manifest(Path('/work'), Path('/upgrade-input'))
        expected = {name[len('bundle/'):]: value for name, value in previous['files'].items()
                    if name.startswith('bundle/')}
        if (set(expected) != set(original)
                or [name for name in original if original[name] != expected[name]['sha256']]
                != ['lib/librustdesk.so']):
            raise RuntimeError('upgrade baseline must differ in exactly its authenticated Rust core')
        previous_bundle = Path('/out/previous-bundle')
        shutil.copytree(bundle, previous_bundle)
        previous_bundle.chmod(0o700)
        for path in previous_bundle.rglob('*'):
            path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.copyfile('/upgrade-input/librustdesk.so', previous_bundle / 'lib/librustdesk.so')
        for name, record in expected.items():
            path = previous_bundle / name
            if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
                raise RuntimeError('reconstructed previous application differs from its complete manifest')
        selected.append(('previous', previous_bundle, {name: r['sha256'] for name, r in expected.items()}))
    archives = []
    for name, selected_bundle, selected_files in selected:
        stage = Path('/out') / (name + '-stage')
        archive = Path('/out') / (name + '.deb')
        module['package_flutter_deb'](version, selected_bundle, stage, archive)
        print(run(['/usr/bin/python3', '-B', '-I', '-S',
                   '/work/scripts/verify-debian-package-authority.py', '--repo', '/work',
                   '--deb', str(archive)], timeout=60), end='', flush=True)
        extracted = Path('/out') / (name + '-extracted')
        run(['/usr/bin/dpkg-deb', '--extract', str(archive), str(extracted)], timeout=60)
        for relative, expected_sha in selected_files.items():
            if digest(extracted / 'usr/share/rustdesk' / relative) != expected_sha:
                raise RuntimeError('candidate archive changed a retained application payload')
        child = extracted / 'usr/share/rustdesk/rustdesk-service-child'
        if digest(child) != selected_files['rustdesk'] or stat.S_IMODE(child.stat().st_mode) != 0o711:
            raise RuntimeError('candidate service-child image differs')
        archives.append({'sha256': digest(archive), 'bytes': archive.stat().st_size})
        shutil.rmtree(stage)
        shutil.rmtree(extracted)
    if upgrade:
        shutil.rmtree(previous_bundle)
        print('LINUX_DEBIAN_UPGRADE_PACKAGES=' + json.dumps({
            'previous_app': previous['context']['source_commit'],
            'previous_manifest_sha256': digest('/upgrade-input/app-manifest.json'),
            'previous': archives[1], 'current': archives[0], 'version': version,
            'application_files': len(original), 'changed_payloads': ['lib/librustdesk.so'],
            'packaging': 'current-production-constructor',
        }, sort_keys=True), flush=True)
    if not single and archives[0] != archives[1]:
        raise RuntimeError('independent packaging stages produced different archives')
    if original != {str(p.relative_to(bundle)): digest(p) for p in bundle.rglob('*') if p.is_file()}:
        raise RuntimeError('candidate packaging changed its retained application input')
    print('LINUX_DEBIAN_CANDIDATE_PACKAGE=' + json.dumps({
        'archive': archives[0], 'version': version, 'source_date_epoch': epoch,
        'application_files': len(original), 'packager_sha256': digest('/work/build.py'),
        'validator_sha256': digest('/work/scripts/verify-debian-package-authority.py'),
        'dpkg_deb_sha256': digest('/usr/bin/dpkg-deb'),
        'scope': 'retained-application-packaging-only', 'builds': len(archives),
    }, sort_keys=True), flush=True)
    if conffiles:
        contents = historical_conffiles(Path('/work'), Path('/conffile-input'))
        stage = Path('/out/conffile-stage')
        (stage / 'DEBIAN').mkdir(parents=True, mode=0o755)
        (stage / 'etc/rustdesk').mkdir(parents=True, mode=0o755)
        (stage / 'DEBIAN/control').write_text(
            f'Package: rustdesk\nVersion: {version}\nArchitecture: amd64\n'
            'Maintainer: RustDesk isolated fixture <nobody@example.invalid>\n'
            'Description: conffile-only predecessor fixture\n')
        (stage / 'DEBIAN/conffiles').write_text(''.join('/etc/rustdesk/' + name + '\n' for name in contents))
        for name, data in contents.items():
            (stage / 'etc/rustdesk' / name).write_bytes(data)
        for path in [stage, *stage.rglob('*')]:
            path.chmod(0o755 if path.is_dir() or path.name == 'startwm.sh' else 0o644)
            os.utime(path, (int(epoch), int(epoch)))
        module['build_debian_archive'](stage, Path('/out/conffile-predecessor.deb'))
        if Path('/out/conffile-predecessor.deb').stat().st_size > 16384:
            raise RuntimeError('conffile predecessor archive exceeds its bound')
        shutil.rmtree(stage)
        refused = Path('/out/conffile-refused-stage')
        run(['/usr/bin/dpkg-deb', '--raw-extract', '/out/first.deb', str(refused)], timeout=60)
        preinst = refused / 'DEBIAN/preinst'
        before = preinst.read_text()
        if before != Path('/work/res/DEBIAN/preinst').read_text() or before.count('\nexit 0\n') != 1:
            raise RuntimeError('conffile abort fixture preinst differs')
        preinst.write_text(before.replace('\nexit 0\n', '\nexit 1\n'))
        module['build_debian_archive'](refused, Path('/out/conffile-refused.deb'))
        shutil.rmtree(refused)
    if single:
        print(run(['/bin/bash', '/work/scripts/smoke-xvfb-prepare.sh'], timeout=60), end='', flush=True)
        shutil.copytree('/usr/share/X11/xkb', '/out/xkb')
    if graphical or settings or camera or remote:
        if not camera and not remote:
            print(run(['/usr/bin/python3', '-B', '-I', '-S', '/work/scripts/test-installed-settings-log.py']),
                  end='', flush=True)
        prepare_drivers(graphical=graphical, camera=camera, remote=remote)
        print(run(['/bin/bash', '/work/scripts/smoke-atspi-prepare.sh'], timeout=60), end='', flush=True)
    records = {str(p.relative_to('/out')): {'sha256': digest(p), 'bytes': p.stat().st_size}
               for p in Path('/out').rglob('*') if p.is_file()}
    if sum(r['bytes'] for r in records.values()) > 268435456:
        raise RuntimeError('candidate packages exceed 256 MiB')
    Path('/out/manifest.json').write_text(json.dumps(records, sort_keys=True))


def prepare_runtime(source, execution, image, client, sock, config, graphical=False,
                    package_install=False, settings=False, upgrade=False, conffiles=False, camera=False, remote=False):
    prepared = WORK / 'prepared'
    prepared.mkdir(mode=0o700)
    os.chown(prepared, 1000, 1000)
    mounts = [(str(source), '/work', True), (str(execution), '/app', True),
              (str(prepared), '/out', False)]
    if upgrade:
        mounts.append((str(MEDIA / 'debian-upgrade'), '/upgrade-input', True))
    if conffiles:
        mounts.append((str(MEDIA / 'debian-conffiles'), '/conffile-input', True))
    for kind in (('xvfb', 'atspi') if graphical or settings or camera or remote else ('xvfb',) if package_install else ()):
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
    args += [image, '/usr/bin/python3', '-B', '-I', '-S', '/work/scripts/test-linux-installed-settings.py',
             '--prepare-package-remote' if remote else '--prepare-package-camera' if camera
             else '--prepare-package-conffiles' if conffiles else '--prepare-package-upgrade' if upgrade
             else '--prepare-package-graphical' if graphical
             else '--prepare-package-settings' if settings
             else '--prepare-package-install' if package_install
             else '--prepare-package']
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


def install_graphical_agent(archive_sha):
    archive = MEDIA / 'polkit-agent-candidate.tar.gz'
    if archive.stat().st_size != 65409 or digest(archive) != archive_sha:
        raise RuntimeError('graphical agent archive identity differs')
    filename = 'policykit-1-gnome_0.105-8_amd64.deb'
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        if (sorted(m.name for m in members) != ['contract', 'manifest.tsv', 'packages/' + filename]
                or any(not m.isfile() or m.uid != 0 or m.gid != 0 or m.mode != 0o400
                       or m.size > 65536 for m in members)):
            raise RuntimeError('graphical agent archive inventory differs')
        package = tar.extractfile('packages/' + filename).read()
    if (len(package) != 64908 or hashlib.sha256(package).hexdigest() !=
            'e6694d1c1ad3c81c4803882fe797497668adbc2f0735651f20a02ff656475fb5'):
        raise RuntimeError('publisher-pinned graphical package differs')
    path = WORK / filename
    with path.open('xb') as stream:
        stream.write(package)
    run(['/usr/bin/dpkg', '--install', str(path)],
        env={**ENV, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'DEBIAN_FRONTEND': 'noninteractive'})
    if digest(GRAPHICAL_AGENT) != GRAPHICAL_AGENT_SHA:
        raise RuntimeError('packaged graphical agent executable differs')
    listing = run([*ordinary(4001), '/usr/bin/ldd', str(GRAPHICAL_AGENT)])
    if 'not found' in listing:
        raise RuntimeError('installed graphical agent dependencies are incomplete: ' + listing)
    print(f'LINUX_INSTALLED_GRAPHICAL_AGENT=pass package=0.105-8 sha256={GRAPHICAL_AGENT_SHA}', flush=True)


def session(restarted=False, uncertain=False, admin_failure=False, graphical=False):
    guard(4001)
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot retain GUI descendants')
    environment = {**ENV, 'HOME': '/home/rdreceiver4001', 'USER': 'rdreceiver4001',
                   'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                   'XDG_RUNTIME_DIR': '/run/user/4001', 'XDG_SESSION_TYPE': 'x11',
                   'XDG_DATA_DIRS': '/usr/local/share:/usr/share', 'GDK_BACKEND': 'x11',
                   'LIBGL_ALWAYS_SOFTWARE': '1'}
    bus = app = agent = None
    displays = ExitStack()
    try:
        if restarted:
            environment = displays.enter_context(recording_display(environment, 78, '1024x768x24'))
        font = run(['/usr/bin/fc-match', '-f', '%{file}', 'sans-serif'], env=environment).strip()
        if not font.startswith('/usr/share/fonts/truetype/dejavu/') or not Path(font).is_file():
            raise RuntimeError(f'ordinary desktop has no installed sans-serif font: {font}')
        print(f'LINUX_INSTALLED_SETTINGS_FONT=pass path={font} sha256={digest(font)}',
              file=sys.stderr, flush=True)
        bus = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--print-address=1'],
                               env=environment, stdout=subprocess.PIPE, stderr=sys.stderr)
        if not select.select([bus.stdout], [], [], 5)[0]:
            raise RuntimeError('owned session bus did not start')
        address = bus.stdout.readline(4096).decode().strip()
        if not address.startswith('unix:'):
            raise RuntimeError('owned session bus is not local')
        environment['DBUS_SESSION_BUS_ADDRESS'] = address
        if graphical:
            agent = subprocess.Popen([str(GRAPHICAL_AGENT)], env=environment,
                                     stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
        app_command = ['/usr/share/rustdesk/rustdesk']
        if graphical:
            app_command = ['/usr/bin/setpriv', '--no-new-privs', *app_command]
        app = subprocess.Popen(app_command, env=environment,
                               stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
        stages = (GRAPHICAL_STAGES if graphical else ADMIN_FAILURE_STAGES if admin_failure else UNCERTAIN_STAGES if uncertain
                  else RESTART_STAGES if restarted else STAGES)
        for stage in stages:
            if stage.startswith('agent-'):
                if agent is None or agent.poll() is not None:
                    raise RuntimeError('graphical agent exited before password-entry cancellation')
                action = {'agent-select': 'select', 'agent-password': 'password', 'agent-cancel': 'cancel-password'}[stage]
                driver = [str(WORK / 'agent-driver'), str(agent.pid), action, 'unattended-password']
            else:
                driver = [str(WORK / 'settings-driver'), str(app.pid), stage]
            output = run(driver, env=environment,
                         timeout=40, output_limit=524288)
            print(output, end='', file=sys.stderr, flush=True)
            if app.poll() is not None:
                raise RuntimeError('GUI exited during the settings workflow')
            print(json.dumps({'stage': stage, 'pid': app.pid,
                              **({'agent_pid': agent.pid if agent is not None else None} if graphical else {})}), flush=True)
            command = sys.stdin.readline()
            if graphical and command == 'recording\n' and agent is not None:
                recording_graphical_session(environment, app, agent)
                command = sys.stdin.readline()
            if graphical and command == 'recording-concurrent\n' and agent is not None:
                recording_concurrent_session(environment, app, agent)
                command = sys.stdin.readline()
            if graphical and command in ('cancel\n', 'authenticate\n') and agent is not None:
                if agent.poll() is not None:
                    raise RuntimeError('graphical authentication agent exited before its dialog action')
                print(run([str(WORK / 'agent-driver'), str(agent.pid), command.strip(), 'unattended-password'], env=environment,
                          timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
            elif graphical and command == 'retire-agent\n' and agent is not None:
                agent.terminate()
                agent.wait(timeout=8)
                agent = None
            elif command != 'continue\n':
                raise RuntimeError('GUI scenario lost its owning controller')
        if restarted:
            recording_session(environment, app.pid)
        if graphical:
            if agent is not None or sys.stdin.readline() != 'recording-stop\n':
                raise RuntimeError('recording shutdown lost its owning controller')
            agent = subprocess.Popen([str(GRAPHICAL_AGENT)], env=environment,
                                     stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
            recording_stop_session(environment, app, agent)
    finally:
        for process in (app, agent, bus):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
        displays.close()
        retire_children()


def recording_stop_session(environment, app, agent):
    guard(4001)
    stages = (
        ('open', ('recording-open',)),
        ('approval-submit', ('recording-enable-submit',)),
        ('approval-password', ('agent-select', 'agent-password')),
        ('approval-restarted', ('agent-retired', 'recording-stop-unapproved')),
        ('commit-submit', ('recording-enable-submit',)),
        ('commit-authorized', ('agent-authenticate',)),
        ('commit-restarted', ('recording-stop-committed',)),
        ('disable-submit', ('recording-disable-submit',)),
        ('disabled', ('recording-disable',)),
    )
    for stage, actions in stages:
        output = ''
        for action in actions:
            command = ([str(WORK / 'agent-driver'), str(agent.pid), action.removeprefix('agent-'), 'incoming-recording']
                       if action.startswith('agent-') else [str(WORK / 'settings-driver'), str(app.pid), action])
            output += run(command, env=environment, timeout=40, output_limit=524288)
        print(output, end='', file=sys.stderr, flush=True)
        if app.poll() is not None or agent.poll() is not None:
            raise RuntimeError('recording shutdown lost its GUI or agent')
        outcome = {}
        if stage.endswith('-restarted'):
            matches = re.findall(r'^LINUX_INSTALLED_RECORDING_STOP_RESULT=pass committed=([01]) '
                                 r'outcome=(Applied|Denied|Uncertain) pid=' + str(app.pid) + r'$', output, re.M)
            if len(matches) != 1 or matches[0][0] != ('1' if stage == 'commit-restarted' else '0'):
                raise RuntimeError('restarted recording state has no exact UI result')
            outcome['outcome'] = matches[0][1]
        print(json.dumps({'stage': stage, 'pid': app.pid, 'agent_pid': agent.pid, **outcome}), flush=True)
        command = sys.stdin.readline()
        if command == 'authenticate\n' and stage == 'disable-submit':
            print(run([str(WORK / 'agent-driver'), str(agent.pid), 'authenticate', 'incoming-recording'],
                      env=environment, timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
        elif command != 'continue\n':
            raise RuntimeError('recording shutdown lost its controller')


def recording_graphical_session(environment, app, agent):
    guard(4001)
    for stage in RECORDING_GRAPHICAL_STAGES:
        if app.poll() is not None or agent.poll() is not None:
            raise RuntimeError('recording cancellation lost its GUI or agent')
        if stage.startswith('recording-agent-'):
            action = {'recording-agent-select': 'select', 'recording-agent-password': 'password',
                      'recording-agent-cancel': 'cancel-password'}[stage]
            driver = [str(WORK / 'agent-driver'), str(agent.pid), action, 'incoming-recording']
        else:
            driver = [str(WORK / 'settings-driver'), str(app.pid), stage]
        print(run(driver, env=environment, timeout=40, output_limit=524288),
              end='', file=sys.stderr, flush=True)
        print(json.dumps({'stage': stage, 'pid': app.pid, 'agent_pid': agent.pid}), flush=True)
        command = sys.stdin.readline()
        if command in ('cancel\n', 'authenticate\n'):
            print(run([str(WORK / 'agent-driver'), str(agent.pid), command.strip(), 'incoming-recording'],
                      env=environment, timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
        elif command != 'continue\n':
            raise RuntimeError('recording cancellation lost its owning controller')


def recording_concurrent_session(environment, app, agent):
    guard(4001)
    secondary = None

    def checkpoint(stage, expected, **fields):
        if app.poll() is not None or agent.poll() is not None:
            raise RuntimeError('recording concurrency lost its GUI or agent')
        print(json.dumps({'stage': stage, 'pid': app.pid, 'secondary_pid': secondary.pid,
                          'agent_pid': agent.pid, **fields}), flush=True)
        command = sys.stdin.readline().strip()
        if command not in expected:
            raise RuntimeError('recording concurrency lost its owning controller')
        if command == 'authenticate':
            print(run([str(WORK / 'agent-driver'), str(agent.pid), command, 'incoming-recording'],
                      env=environment, timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
        return command

    def drive(gui, env, stage):
        output = run([str(WORK / 'settings-driver'), str(gui.pid), stage], env=env,
                     timeout=40, output_limit=524288)
        print(output, end='', file=sys.stderr, flush=True)
        return output

    with recording_display(environment, 78, '1024x768x24') as other_environment:
        try:
            secondary = subprocess.Popen(['/usr/bin/setpriv', '--no-new-privs', '/usr/share/rustdesk/rustdesk'],
                env=other_environment, stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
            drive(app, environment, 'recording-open')
            drive(secondary, other_environment, 'recording-settings-open')
            checkpoint('ready', ('continue',))
            drivers = []
            try:
                for gui, env in ((app, environment), (secondary, other_environment)):
                    drivers.append(subprocess.Popen([str(WORK / 'settings-driver'), str(gui.pid),
                        'recording-race-submit'], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, bufsize=0))
                for driver in drivers:
                    deadline = time.monotonic() + 10
                    total = 0
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([driver.stdout], [], [], remaining)[0]:
                            raise RuntimeError('recording click did not reach its ready barrier')
                        line = driver.stdout.readline(4096)
                        total += len(line)
                        if not line.endswith(b'\n') or total > 524288:
                            raise RuntimeError('recording click barrier output is incomplete or excessive')
                        print(line.decode(), end='', file=sys.stderr, flush=True)
                        if line == b'LINUX_INSTALLED_RECORDING_RACE_READY\n':
                            break
                for driver in drivers:
                    driver.stdin.write(b'G')
                    driver.stdin.close()
                    driver.stdin = None
                for driver in drivers:
                    output, _ = driver.communicate(timeout=15)
                    if len(output) > 524288:
                        raise RuntimeError('recording concurrent click exceeded its output bound')
                    print(output.decode(), end='', file=sys.stderr, flush=True)
                    if driver.returncode != 0:
                        raise RuntimeError('recording concurrent click failed')
            finally:
                for driver in drivers:
                    if driver.poll() is None:
                        driver.terminate()
                    driver.wait(timeout=8)
            owner = checkpoint('submitted', ('primary', 'secondary'))
            winner, winner_env, loser, loser_env = ((app, environment, secondary, other_environment)
                if owner == 'primary' else (secondary, other_environment, app, environment))
            drive(winner, winner_env, 'recording-race-pending')
            output = drive(loser, loser_env, 'recording-race-refused')
            outcomes = re.findall(r'^LINUX_INSTALLED_RECORDING_RACE_REFUSAL=pass outcome=(Denied|Failed) pid='
                                  + str(loser.pid) + r'$', output, re.M)
            if len(outcomes) != 1:
                raise RuntimeError('competing recording request has no explicit unsuccessful result')
            checkpoint('contended', ('authenticate',), owner=owner, refused=outcomes[0])
            drive(winner, winner_env, 'recording-enable')
            drive(loser, loser_env, 'recording-race-observed-enabled')
            checkpoint('applied', ('continue',))
            drive(loser, loser_env, 'recording-disable-submit')
            checkpoint('retry-submitted', ('authenticate',))
            drive(loser, loser_env, 'recording-disable')
            drive(winner, winner_env, 'recording-disable')
            checkpoint('retry-applied', ('continue',))
            drive(secondary, other_environment, 'recording-enable-submit')
            checkpoint('depart-submit', ('continue',))
            for action in ('select', 'password'):
                print(run([str(WORK / 'agent-driver'), str(agent.pid), action, 'incoming-recording'],
                          env=environment, timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
            checkpoint('depart-password', ('depart',))
            secondary.terminate()
            exit_status = secondary.wait(timeout=8)
            print(run([str(WORK / 'agent-driver'), str(agent.pid), 'retired', 'incoming-recording'],
                      env=environment, timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
            drive(app, environment, 'recording-disable')
            checkpoint('depart-retired', ('continue',), exit_status=exit_status)
            drive(app, environment, 'recording-enable-submit')
            checkpoint('recovery-submit', ('authenticate',))
            drive(app, environment, 'recording-enable')
            checkpoint('recovery-enabled', ('continue',))
            drive(app, environment, 'recording-disable-submit')
            checkpoint('recovery-disable-submit', ('authenticate',))
            drive(app, environment, 'recording-disable')
            checkpoint('recovery-disabled', ('continue',))
        finally:
            if secondary is not None:
                if secondary.poll() is None:
                    secondary.terminate()
                secondary.wait(timeout=8)
    drive(app, environment, 'recording-return-security')
    checkpoint('retired', ('continue',))


@contextmanager
def recording_display(environment, number, geometry):
    guard(4001)
    coord = Path('/coord')
    authority = coord / f'Xauthority-{number}'
    def field(value):
        return struct.pack('!H', len(value)) + value
    with os.fdopen(os.open(authority, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as auth:
        auth.write(struct.pack('!H', 65535) + field(b'') + field(str(number).encode())
                   + field(b'MIT-MAGIC-COOKIE-1') + field(os.urandom(16)))
    path = coord / f'xvfb-{number}.log'
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
        process = subprocess.Popen([str(WORK / 'Xvfb'), f':{number}', '-nolisten', 'tcp',
            '-auth', str(authority), '-screen', '0', geometry,
            '-xkbdir', str(WORK / 'xkb'), '-fp', 'built-ins'], env=ENV, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not Path(f'/tmp/.X11-unix/X{number}').exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('recording fixture X11 display did not start')
                time.sleep(0.05)
            yield {**environment, 'DISPLAY': f':{number}', 'XAUTHORITY': str(authority)}
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=8)
            if path.stat().st_size > 131072:
                raise RuntimeError('recording display diagnostic exceeds its bound')
            print(path.read_text(), end='', file=sys.stderr, flush=True)


def recording_session(environment, gui_pid):
    """Toggle installed recording while one authenticated viewer stays connected."""
    guard(4001)
    coord = Path('/coord')
    home = Path('/home/rdreceiver4001')
    if list(home.glob('incoming_*.webm')) or list((coord / 'output').iterdir()):
        raise RuntimeError('installed recording output is not initially empty')
    processes = []
    with ExitStack() as files:
        viewer_environment = files.enter_context(recording_display(environment, 79, '1600x1200x24'))
        def log(name):
            return files.enter_context(os.fdopen(os.open(coord / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb'))
        def driver(pid, stage, env=environment, *arguments):
            output = run([str(WORK / 'settings-driver'), str(pid), stage, *arguments],
                         env=env, timeout=60, output_limit=524288)
            print(output, end='', file=sys.stderr, flush=True)
            return output

        def checkpoint(stage):
            print(json.dumps({'stage': stage, 'pid': gui_pid, 'viewer_pid': viewer.pid}), flush=True)
            if sys.stdin.readline() != 'continue\n':
                raise RuntimeError('live recording lost its owning controller')

        connection = None
        def sample(stage):
            nonlocal connection
            output = driver(viewer.pid, stage, viewer_environment)
            current, = re.findall(r'local=([0-9A-F:]+) remote=([0-9A-F:]+) inode=([0-9]+)', output)
            if connection is not None and current != connection:
                raise RuntimeError('live recording replaced the authenticated connection')
            connection = current
            if (stage != 'recording-viewer-close' and viewer.poll() is not None) or source.poll() is not None:
                raise RuntimeError('live recording lost its exact source or viewer')

        def inventory():
            result = {}
            paths = sorted(home.glob('incoming_*.webm'))
            if not 1 <= len(paths) <= 8:
                raise RuntimeError(f'installed recording produced {len(paths)} files')
            for path in paths:
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 4001 or info.st_gid != 4001
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                        or not 0 < info.st_size <= 1048576):
                    raise RuntimeError('installed recording file authority or bound differs')
                result[path.name] = {'device': info.st_dev, 'inode': info.st_ino,
                                    'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns, 'sha256': digest(path)}
            return result

        def retain_output(started, stopped, enabled):
            # Finalization is first observed through the real UI. Preserve the exact
            # completed files for the existing bounded native decoder.
            original = inventory()
            for name, info in original.items():
                path = home / name
                destination = coord / 'output' / name
                path.rename(destination)
                moved = destination.lstat()
                if ((moved.st_dev, moved.st_ino, moved.st_size) != (info['device'], info['inode'], info['bytes'])
                        or digest(destination) != info['sha256']):
                    raise RuntimeError('retained recording differs from the finalized output')
                print('LINUX_INSTALLED_RECORDING_SAVED=' + json.dumps({
                    'path': str(path), **info, 'uid': 4001, 'mode': '0600', 'inode_preserved': True,
                    'epoch': 'after-enable' if enabled else 'before-disable'}, sort_keys=True), file=sys.stderr, flush=True)
            driver(gui_pid, 'recording-output' if enabled else 'recording-output-disabled',
                   environment, str(started), str(stopped))

        try:
            source = subprocess.Popen([str(WORK / 'recording-source')],
                env={**environment, 'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                     'RUSTDESK_PRESENTATION_TRACE': '1'},
                stdout=log('frame-source.log'), stderr=log('source-error.log'))
            processes.append(source)
            deadline = time.monotonic() + 5
            while (coord / 'frame-source.log').stat().st_size == 0:
                if source.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('installed recording source did not publish')
                time.sleep(0.05)
            started = time.monotonic_ns() // 1000
            viewer = subprocess.Popen(['/usr/share/rustdesk/rustdesk', '--connect', '127.0.0.1'],
                env=viewer_environment, stdin=subprocess.DEVNULL,
                stdout=log('viewer.log'), stderr=subprocess.STDOUT)
            processes.append(viewer)
            package_process(viewer.pid)
            sample('recording-viewer-open')
            driver(gui_pid, 'recording-live')
            checkpoint('recording-live')
            driver(gui_pid, 'recording-disable-submit')
            checkpoint('recording-disable-submit')
            driver(gui_pid, 'recording-live-disabled')
            stopped = time.monotonic_ns() // 1000
            disabled = inventory()
            sample('recording-viewer-sample')
            driver(gui_pid, 'recording-live-disabled')
            if inventory() != disabled:
                raise RuntimeError('disabled recording still changed its completed output')
            retain_output(started, stopped, False)
            (coord / 'output').rename(coord / 'before-disable')
            (coord / 'output').mkdir(mode=0o700)
            print('LINUX_INSTALLED_RECORDING_DISABLED=pass frames=12 files=unchanged bytes=unchanged '
                  'connection=retained status=idle', file=sys.stderr, flush=True)
            checkpoint('recording-live-disabled')
            started = time.monotonic_ns() // 1000
            driver(gui_pid, 'recording-enable-submit')
            checkpoint('recording-enable-submit')
            driver(gui_pid, 'recording-live-enabled')
            checkpoint('recording-live-enabled')
            sample('recording-viewer-close')
            # The controller closes the actual remote window before process retirement.
            if viewer.poll() is None:
                viewer.terminate()
            viewer.wait(timeout=8)
            # Capture may finish after the viewer exits. Keep its source visible
            # until the service's actual status confirms the recording is closed.
            driver(gui_pid, 'recording-restarted')
            stopped = time.monotonic_ns() // 1000
            source.terminate()
            if source.wait(timeout=8) != 0:
                raise RuntimeError('installed source did not complete cleanly')
            retain_output(started, stopped, True)
            checkpoint('recording-live-finished')
            print('LINUX_INSTALLED_RECORDING_LIVE=pass app=installed service=actual '
                  'password=actual-ui viewer_frames=36 connection=retained enabled=recording disabled=idle '
                  'disabled_output=unchanged epochs=2 recording=native-decoded counters=source-bound '
                  'finalization=actual-ui truncation=refused owner=4001', file=sys.stderr, flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
            for name in ('source-error.log', 'viewer.log'):
                path = coord / name
                if path.exists():
                    if path.stat().st_size > 131072:
                        raise RuntimeError('installed recording diagnostic exceeds its bound')
                    print(path.read_text(), end='', file=sys.stderr, flush=True)


def owned_log(directory, pid, uid, retained=None):
    # The complete optimized application logs to files, unlike the debug receiver.
    for parent in [directory, *directory.parents]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid) or info.st_mode & 0o022:
            raise RuntimeError('product log ancestry authority differs')
    held = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            info = fd.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            held.add((info.st_dev, info.st_ino))
    files = list(directory.glob('*.log'))
    if len(files) > 32:
        raise RuntimeError('service log file count exceeds the product bound')
    active = []
    for path in files:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & 0o022):
            raise RuntimeError('service log file authority differs')
        if (info.st_dev, info.st_ino) in held:
            active.append(path)
    if len(active) != 1:
        raise RuntimeError('the retained process must own exactly one current product log')
    path, = active
    # Capture a fixed prefix of this append-only log. Production rotates at 4 MiB;
    # the observation cap permits that file plus a final record, not an unbounded read.
    limit = 8 * 1024 * 1024
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or before.st_mode & 0o022 or (before.st_dev, before.st_ino) not in held):
            raise RuntimeError('opened service log authority differs')
        if before.st_size > limit:
            raise RuntimeError(f'service log snapshot exceeds {limit} bytes: {before.st_size}')
        data = stream.read(before.st_size)
        after = os.fstat(stream.fileno())
        current = path.lstat()
        if retained is not None:
            retained.append((path, os.fdopen(os.dup(stream.fileno()), 'rb'), uid))
    if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or after.st_uid != uid or after.st_nlink != 1 or after.st_mode & 0o022
            or not before.st_size <= after.st_size <= limit or len(data) != before.st_size):
        raise RuntimeError(f'service log snapshot changed: before={before.st_size} '
                           f'after={after.st_size} read={len(data)}')
    # A concurrent append may leave the captured prefix inside a UTF-8 log record.
    data = data[:data.rfind(b'\n') + 1]
    print('LINUX_INSTALLED_SETTINGS_LOG_SNAPSHOT=' + json.dumps({
        'path': str(path), 'file_bytes_before': before.st_size, 'file_bytes_after': after.st_size,
        'prefix_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}, sort_keys=True), flush=True)
    return path, data


def service_refusals(record, requester, start, count, exit_status=2,
                     action='com.carriez.RustDesk.set-unattended-password'):
    path, data = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
    messages = data.decode().splitlines()
    prefix = (f'polkit denied action={action}, '
              f'subject={requester},{start},4001, status=exit status: ')
    refusals = [line for line in messages if line.endswith(prefix + str(exit_status))]
    print('LINUX_INSTALLED_SETTINGS_SERVICE_LOG=' + json.dumps(
        {'path': str(path), 'supervisor': record['supervisor'], 'bytes': len(data),
         'sha256': hashlib.sha256(data).hexdigest(), 'refusals': refusals}, sort_keys=True), flush=True)
    if len(refusals) != count:
        print('LINUX_INSTALLED_SETTINGS_SERVICE_DIAGNOSTIC=' + json.dumps(
            [line for line in messages if 'password' in line.lower()][-20:]), flush=True)
        raise RuntimeError('visible errors do not match actual service authorization refusals')
    return refusals


@contextmanager
def administrator(receiver, requester):
    for name, mode, sha in (
            ('/usr/bin/pkttyagent', 0o755, '820110471dd023bf8272a05dd0910d876c0d2c54f3c91ed49d6cc93598f7f814'),
            ('/usr/lib/polkit-1/polkit-agent-helper-1', 0o4755, '8eb4c2d5f21698a41a0d6cdafb49c889c4ace55cada690c2cea118073fe05bab')):
        info = Path(name).lstat()
        if (not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, mode)
                or digest(name) != sha):
            raise RuntimeError('packaged authentication agent authority differs')
    if (digest('/usr/share/polkit-1/actions/com.carriez.RustDesk.policy') !=
            digest(MEDIA / 'repo/res/com.carriez.RustDesk.policy')
            or 'rdreceiver4003' not in grp.getgrnam('sudo').gr_mem):
        raise RuntimeError('administrator or shipped policy identity differs')
    master, slave = pty.openpty()
    notify_read, notify_write = os.pipe()
    agent = None
    try:
        os.fchown(slave, 4001, 4001)
        os.fchmod(slave, 0o600)
        agent = subprocess.Popen(['/usr/bin/python3', '-B', '-I', '-S', str(Path(receiver.__file__)),
                                  '--polkit-agent', f'{requester[0]},{requester[1]}', str(notify_write)],
                                 env=ENV, pass_fds=(notify_write,), stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        slave = None
        os.close(notify_write)
        notify_write = None
        if not select.select([notify_read], [], [], 5)[0] or os.read(notify_read, 1) or agent.poll() is not None:
            raise RuntimeError('actual polkit agent did not register for the GUI generation')
        proc = Path(f'/proc/{agent.pid}')
        status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
        if (not (proc / 'exe').samefile('/usr/bin/pkttyagent') or status['Uid'].split() != ['4001'] * 4
                or status['NoNewPrivs'].strip() != '0'
                or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))):
            raise RuntimeError('authentication agent principal or image differs')
        yield agent, master
    finally:
        try:
            if agent is not None:
                if agent.poll() is None:
                    os.killpg(agent.pid, signal.SIGTERM)
                    try:
                        agent.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(agent.pid, signal.SIGKILL)
                        agent.wait(timeout=5)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        os.killpg(agent.pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('owned authentication agent group did not retire')
                    time.sleep(0.02)
        finally:
            for fd in (master, slave, notify_read, notify_write):
                if fd is not None:
                    os.close(fd)


def authenticate(receiver, authority, requester, record, before, password_delay=0, incorrect_password=False,
                 action='com.carriez.RustDesk.set-unattended-password'):
    agent, terminal_fd = authority
    terminal = bytearray()
    chosen = sent = False
    deadline = time.monotonic() + 20
    completion = b'AUTHENTICATION FAILED' if incorrect_password else b'AUTHENTICATION COMPLETE'
    observation = {'requester_pid': requester[0], 'requester_start': requester[1], 'requester_uid': 4001,
                   'administrator_uid': 4003, 'agent_pid': agent.pid}
    with ExitStack() as retained:
        while completion not in terminal:
            if agent.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f'GUI administrator authorization did not complete: {terminal[-4096:]!r}')
            if select.select([terminal_fd], [], [], 0.1)[0]:
                data = os.read(terminal_fd, 4096)
                if not data or len(terminal) + len(data) > 32768:
                    raise RuntimeError('administrator terminal closed or exceeded its bound')
                terminal.extend(data)
            if not chosen and b'Choose identity to authenticate as' in terminal:
                matches = re.findall(rb'(?m)^\s*([1-9][0-9]*)\.\s+[^\r\n]*\brdreceiver4003\b[^\r\n]*', terminal)
                if len(matches) != 1:
                    raise RuntimeError('administrator identity menu differs')
                os.write(terminal_fd, matches[0] + b'\n')
                chosen = True
            if not sent and b'Password:' in terminal and not termios.tcgetattr(terminal_fd)[3] & termios.ECHO:
                if (action.encode() not in terminal
                        or b'rdreceiver4003' not in terminal or receiver.credential() != before
                        or receiver.child_record() != record):
                    raise RuntimeError('GUI authorization challenge or pre-approval state differs')
                if incorrect_password:
                    helper, helper_start = receiver.pending_admin_helper(*requester, record)
                    helper_fd = os.pidfd_open(int(helper.name))
                    retained.callback(os.close, helper_fd)
                    fields = (helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                    if (int(fields[19]) != helper_start or fields[0] in (b'Z', b'X')
                            or select.select([helper_fd], [], [], 0)[0]):
                        raise RuntimeError('GUI authorization helper changed before incorrect password submission')
                    observation.update(helper_pid=int(helper.name), helper_start=helper_start)
                # Model time spent answering the real prompt, without changing product deadlines.
                time.sleep(password_delay)
                password = receiver.INVALID_ADMIN_PASSWORD if incorrect_password else receiver.ADMIN_PASSWORD
                answered_at = time.monotonic()
                os.write(terminal_fd, (password + '\n').encode())
                sent = True
        other = b'AUTHENTICATION COMPLETE' if incorrect_password else b'AUTHENTICATION FAILED'
        if (not sent or terminal.count(completion) != 1 or other in terminal
                or terminal.count(b'Password:') != 1 or receiver.ADMIN_PASSWORD.encode() in terminal
                or receiver.INVALID_ADMIN_PASSWORD.encode() in terminal):
            raise RuntimeError('GUI administrator proof is incomplete or exposed its password')
        if incorrect_password:
            deadline = time.monotonic() + 5
            while True:
                exited = bool(select.select([helper_fd], [], [], 0.02)[0])
                try:
                    fields = (helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                    reaped = int(fields[19]) != helper_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
                if exited and reaped:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('failed GUI authorization did not retire its exact helper')
            if agent.poll() is not None or receiver.credential() != before or receiver.child_record() != record:
                raise RuntimeError('incorrect administrator password changed the credential, service or agent')
            observation.update(helper_exited=exited, helper_reaped=reaped, agent_alive=True,
                               seconds=time.monotonic() - answered_at, protected_unchanged=True)
    name = 'ADMIN_FAILURE' if incorrect_password else 'ADMIN'
    print('LINUX_INSTALLED_SETTINGS_' + name + '=' + json.dumps(
        {**observation, 'terminal': terminal.decode()}, sort_keys=True), flush=True)


def credential_network(receiver, record, probe_sha, phase, new=GUI_PASSWORD, old=BASELINE_PASSWORD):
    receiver.keyed(new, phase + '-new', record, probe_sha)
    directory = Path('/home/rdreceiver4001/.local/share/logs/RustDesk/server')
    path, baseline = owned_log(directory, record['pid'], 4001)
    before = receiver.credential()
    listener = receiver.direct_listener(record)
    result = receiver.run([*ordinary(4002), str(receiver.PROBE), '127.0.0.1:21118', '--password-stdin', 'fail'],
                          input=old + '\n', timeout=45)
    if result.stdout.splitlines() != ['probe_client: keying ok=false (expected=fail)', 'probe_client: PASS'] or result.stderr:
        raise RuntimeError('obsolete GUI credential was not refused')
    after_path, after = owned_log(directory, record['pid'], 4001)
    delta = after[len(baseline):].decode() if after.startswith(baseline) else ''
    failures = [line for line in delta.splitlines() if 'R-S10/R-T12 security summary' in line]
    if (after_path != path or len(failures) != 1 or not failures[0].endswith(
            'R-S10/R-T12 security summary (last 10s): shed=0 rate_limited=0 key_confirmation_failures=1 recent_src=Some(127.0.0.1)')
            or receiver.credential() != before or receiver.direct_listener(record) != listener
            or receiver.child_record() != record):
        raise RuntimeError(f'obsolete credential lacks exact child confirmation-mismatch evidence: {delta}')
    receiver.keyed(new, phase + '-recovery', record, probe_sha)
    print('LINUX_INSTALLED_SETTINGS_CREDENTIAL=' + json.dumps(
        {'phase': phase, **record, 'old': 'receiver-confirmed-refusal', 'new': 'mutual-cpace',
         'log': str(path), 'log_sha256': hashlib.sha256(after).hexdigest(), 'refusal': failures[0]}, sort_keys=True), flush=True)


def network_state():
    rows = set()
    for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
        with Path('/proc/net', protocol).open() as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise RuntimeError('guest socket inventory exceeds its bound')
        for line in data.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise RuntimeError('guest socket inventory is incomplete')
            rows.add((protocol, fields[1], fields[2], fields[3], fields[5].split(':')[0], fields[7], fields[9]))
    return rows


def wait_network_retirement(baseline):
    began = time.monotonic()
    reported = False
    while True:
        current = network_state()
        if current == baseline:
            print('LINUX_INSTALLED_SETTINGS_NETWORK=pass inventory=baseline '
                  f'wait_seconds={time.monotonic() - began:.3f}', flush=True)
            return
        residual = current - baseline
        if not reported:
            print('LINUX_INSTALLED_SETTINGS_NETWORK_PENDING=' + json.dumps(
                {'removed': sorted(baseline - current), 'added': sorted(residual)}), flush=True)
            reported = True
        # Only kernel TIME_WAIT records from the completed loopback probe may drain.
        # The outer inventory still requires exact equality; no socket is exempted.
        if (baseline - current or not residual or any(
                protocol != 'tcp' or state != '06' or timer != '03' or inode != '0'
                or not local.startswith('0100007F:') or not remote.startswith('0100007F:')
                or '0100007F:527E' not in (local, remote)
                for protocol, local, remote, state, timer, uid, inode in residual)
                or time.monotonic() - began >= 75):
            raise RuntimeError(f'guest network did not retire: {sorted(residual)}')
        time.sleep(0.1)


def user_credential():
    import tomllib  # This observation runs in the guest, not the older preparation image.

    path = Path('/home/rdreceiver4001/.config/rustdesk/RustDesk.toml')
    if not path.exists():
        values = {}
    else:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 4001
                or metadata.st_nlink != 1 or metadata.st_size > 65536):
            raise RuntimeError('ordinary-user credential file authority differs')
        values = tomllib.loads(path.read_text())
    fields = [values.get(key, '') for key in ('password', 'password_prs', 'salt')]
    if not all(isinstance(value, str) for value in fields):
        raise RuntimeError('ordinary-user credential fields differ')
    return hashlib.sha256(json.dumps(fields).encode()).hexdigest()


def recording_value():
    import tomllib

    path = Path('/root/.config/rustdesk/RustDesk2.toml')
    values = {}
    if path.exists():
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_nlink != 1 or metadata.st_size > 65536
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise RuntimeError('recording preference file authority differs')
        values = tomllib.loads(path.read_text()).get('options', {})
    value = values.get('allow-auto-record-incoming', '')
    if value not in ('Y', ''):
        raise RuntimeError('saved recording preference is not a canonical boolean')
    return value == 'Y'


def recording_option(expected):
    if recording_value() != expected:
        raise RuntimeError('recording checkbox disagrees with the saved preference')
    print(f'LINUX_INSTALLED_RECORDING_OPTION=pass enabled={str(expected).lower()} owner=0', flush=True)


def user_recording_options():
    path = Path('/home/rdreceiver4001/.config/rustdesk/RustDesk2.toml')
    if not path.exists():
        return None
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 4001
            or metadata.st_nlink != 1 or metadata.st_size > 65536):
        raise RuntimeError('user recording options identity differs')
    return digest(path)


def service_absent():
    properties = dict(line.split('=', 1) for line in run([
        '/usr/bin/systemctl', 'show', 'rustdesk.service',
        '--property=ActiveState,SubState,Result,MainPID,ExecMainStatus']).splitlines())
    expected = {'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success',
                'MainPID': '0', 'ExecMainStatus': '0'}
    paths = ['/sys/fs/cgroup/system.slice/rustdesk.service', '/run/rustdesk/service-child.record']
    remaining = [path for path in paths if os.path.lexists(path)]
    if properties != expected or remaining:
        raise RuntimeError(f'fixture service is not completely stopped: {properties}, remaining={remaining}')
    endpoints = []
    for suffix in ('_service', '_service_password', '_service_credential'):
        path = '/run/RustDesk-service/ipc' + suffix
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(1)
            try:
                peer.connect(path)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                    raise
                endpoints.append({'path': path, 'errno': error.errno,
                                  'filesystem_entry': os.path.lexists(path)})
            else:
                raise RuntimeError(f'stopped service endpoint still accepts connections: {path}')
    return {**properties, 'endpoint_observations': endpoints}


def stop_service(receiver, record):
    retained = []
    try:
        for pid in (record['supervisor'], record['pid']):
            retained.append(os.pidfd_open(pid))
        if receiver.child_record() != record or select.select(retained, [], [], 0)[0]:
            raise RuntimeError('service generation changed before the controlled stop')
        run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
        if len(select.select(retained, [], [], 2)[0]) != len(retained):
            raise RuntimeError('controlled service stop left an exact process alive')
        properties = service_absent()
        print('LINUX_INSTALLED_SETTINGS_STOPPED=' + json.dumps({**record, **properties,
              'processes': 'pidfd-exited', 'endpoints': 'unavailable'}, sort_keys=True), flush=True)
    finally:
        for fd in retained:
            os.close(fd)


def package_unit():
    unit = Path('/etc/systemd/system/rustdesk.service')
    if (os.path.lexists(unit)
            or digest('/usr/lib/systemd/system/rustdesk.service') != digest(MEDIA / 'repo/res/rustdesk.service')
            or run(['/usr/bin/dpkg-query', '--search', '/usr/lib/systemd/system/rustdesk.service']).strip()
            != 'rustdesk: /usr/lib/systemd/system/rustdesk.service'):
        raise RuntimeError('settings workflow requires the package-owned vendor unit')


def package_process(pid):
    product = Path('/proc') / str(pid)
    if (any(path in (product / 'maps').read_text() for path in
            (str(WORK / 'debian-x11'), '/usr/local/lib/rustdesk-settings-fixture'))
            or any(value.startswith((b'LD_LIBRARY_PATH=', b'LD_PRELOAD=', b'LIBGL_DRIVERS_PATH='))
                   for value in (product / 'environ').read_bytes().split(b'\0'))):
        raise RuntimeError('packaged product loaded or inherited a private fixture runtime')


def scenario(receiver, probe_sha, network_before):
    package_unit()
    process = None
    authorization = ExitStack()
    record = before = None
    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        record = receiver.ready()
        receiver.change(0, BASELINE_PASSWORD, True)
        before = receiver.credential()
        receiver.keyed(BASELINE_PASSWORD, 'gui-baseline', record, probe_sha)
        print('LINUX_INSTALLED_SETTINGS_BASELINE=pass service=actual credential=root-provisioned '
              'child=supervised desktop=pam-logind-x11', flush=True)
        process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S', str(SCRIPT), '--session'],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        requester = None
        committed = None
        authority = None
        recording_profile = None
        recording_enabled = False
        for index, stage in enumerate(STAGES):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('installed GUI stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'installed GUI ended before stage {stage}')
            event = json.loads(raw)
            expected = committed if committed is not None else before
            if stage == 'applied':
                committed = receiver.credential()
                if committed == before:
                    raise RuntimeError('GUI reported success without changing the protected credential')
                expected = committed
            if event.get('stage') != stage or receiver.credential() != expected or receiver.child_record() != record:
                raise RuntimeError(f'installed GUI stage or protected credential differs: {event}')
            identity = (event['pid'], int(Path(f'/proc/{event["pid"]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
            if requester is not None and requester != identity:
                raise RuntimeError('installed GUI requester generation changed')
            requester = identity
            for pid in (identity[0], record['supervisor'], record['pid']):
                package_process(pid)
            status = dict(line.split(':', 1) for line in Path(f'/proc/{identity[0]}/status').read_text().splitlines() if ':' in line)
            if (status['Uid'].split() != ['4001'] * 4 or status['NoNewPrivs'].strip() != '1'
                    or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                    or not Path(f'/proc/{identity[0]}/exe').samefile('/usr/share/rustdesk/rustdesk')):
                raise RuntimeError('GUI requester is not the ordinary installed image')
            if index == 8:
                service_refusals(record, *requester, 2)
            if index == 10:
                authority = authorization.enter_context(administrator(receiver, requester))
            if stage == 'submit-approved':
                authenticate(receiver, authority, requester, record, before)
            if stage == 'applied':
                authorization.close()
                print('LINUX_INSTALLED_SETTINGS_AGENT=pass lifetime=through-applied cleanup=joined', flush=True)
            if stage.startswith('recording-'):
                if stage == 'recording-open':
                    recording_profile = user_recording_options()
                if stage == 'recording-denied':
                    service_refusals(record, *requester, 1, action='com.carriez.RustDesk.set-incoming-recording')
                    authority = authorization.enter_context(administrator(receiver, requester))
                if stage.endswith('-submit'):
                    recording_option(recording_enabled)
                    authenticate(receiver, authority, requester, record, committed,
                                 password_delay=2,
                                 action='com.carriez.RustDesk.set-incoming-recording')
                elif stage in ('recording-enable', 'recording-disable'):
                    recording_enabled = stage == 'recording-enable'
                if not stage.endswith('-submit'):
                    recording_option(recording_enabled)
                if user_recording_options() != recording_profile:
                    raise RuntimeError('service recording change mutated the user profile')
            print('LINUX_INSTALLED_SETTINGS_OBSERVED=' + json.dumps({**event, 'index': index,
                  'credential': 'committed' if committed is not None else 'baseline',
                  'service_generation': record['generation']}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('installed GUI session did not retire successfully')
        authorization.close()
        refusals = service_refusals(record, *requester, 3)
        if committed is None or receiver.credential() != committed:
            raise RuntimeError('protected credential differs after the GUI workflow')
        print('LINUX_INSTALLED_SETTINGS_REFUSALS=' + json.dumps(refusals), flush=True)
        credential_network(receiver, record, probe_sha, 'gui-applied')
        run(['/usr/bin/systemctl', 'restart', 'rustdesk.service'], timeout=40)
        restarted = receiver.ready(record)
        record = restarted
        if receiver.credential() != committed:
            raise RuntimeError('GUI credential did not persist through service restart')
        recording_option(True)
        credential_network(receiver, restarted, probe_sha, 'gui-restarted')
        for pipe in (process.stdin, process.stdout):
            pipe.close()
        for path in (Path('/coord'), Path('/coord/output')):
            path.mkdir(mode=0o700)
            os.chown(path, 4001, 4001)
        process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S', str(SCRIPT), '--session-restart'],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stopped = False
        restarted_requester = None
        profile_before = None
        for stage in RESTART_STAGES:
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('restarted GUI stage timed out')
            event = json.loads(process.stdout.readline(4096))
            if (event.get('stage') != stage or event.get('pid') == requester[0]
                    or receiver.credential() != committed):
                raise RuntimeError('restarted GUI or protected credential differs')
            identity = (event['pid'], int(Path(f'/proc/{event["pid"]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
            if restarted_requester is not None and identity != restarted_requester:
                raise RuntimeError('GUI generation changed across the service outage')
            restarted_requester = identity
            package_process(identity[0])
            if not stopped:
                for pid in (restarted['supervisor'], restarted['pid']):
                    package_process(pid)
            if stopped:
                service_absent()
                if user_credential() != profile_before:
                    raise RuntimeError('unavailable installed service caused a user-profile credential write')
            elif receiver.child_record() != restarted:
                raise RuntimeError('service changed outside the controlled outage')
            print('LINUX_INSTALLED_SETTINGS_RESTART=' + json.dumps({**event, **restarted,
                  'gui_pid': event['pid'], 'credential': 'preserved',
                  'service': 'stopped' if stopped else 'running'}, sort_keys=True), flush=True)
            if stage == 'fill':
                profile_before = user_credential()
                stop_service(receiver, restarted)
                stopped = True
            elif stage == 'failed':
                run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
                restarted = receiver.ready(restarted)
                record = restarted
                stopped = False
            elif stage == 'denied':
                service_refusals(restarted, *restarted_requester, 1)
                if user_credential() != profile_before:
                    raise RuntimeError('service recovery changed the user-profile credential')
            elif stage == 'recording-restarted':
                recording_option(True)
                if user_recording_options() != recording_profile:
                    raise RuntimeError('restarted recording workflow changed the user profile')
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        viewer_identity = viewer_fd = None
        for stage in LIVE_RECORDING_STAGES:
            if not select.select([process.stdout], [], [], 60)[0]:
                raise RuntimeError('live recording stage timed out')
            event = json.loads(process.stdout.readline(4096))
            if (event.get('stage') != stage or event.get('pid') != restarted_requester[0]
                    or receiver.credential() != committed or receiver.child_record() != restarted):
                raise RuntimeError('live recording changed its GUI, credential or service generation')
            start = int(Path(f'/proc/{event["pid"]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19])
            if start != restarted_requester[1]:
                raise RuntimeError('live recording GUI generation changed')
            for pid in (event['pid'], restarted['supervisor'], restarted['pid']):
                package_process(pid)
            viewer_proc = Path(f'/proc/{event["viewer_pid"]}')
            if stage == 'recording-live-finished':
                if (event['viewer_pid'] != viewer_identity[0] or viewer_proc.exists()
                        or not select.select([viewer_fd], [], [], 0)[0]):
                    raise RuntimeError('live recording viewer did not exit and reap')
            else:
                if viewer_fd is None:
                    viewer_fd = os.pidfd_open(event['viewer_pid'])
                    authorization.callback(os.close, viewer_fd)
                fields = (viewer_proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                identity = (event['viewer_pid'], int(fields[19]))
                status = dict(line.split(':', 1) for line in (viewer_proc / 'status').read_text().splitlines() if ':' in line)
                if (select.select([viewer_fd], [], [], 0)[0] or int(fields[1]) != process.pid
                        or status['Uid'].split() != ['4001'] * 4 or status['NoNewPrivs'].strip() != '1'
                        or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                        or not (viewer_proc / 'exe').samefile('/usr/share/rustdesk/rustdesk')
                        or (viewer_proc / 'cmdline').read_bytes().split(b'\0') !=
                           [b'/usr/share/rustdesk/rustdesk', b'--connect', b'127.0.0.1', b'']
                        or (viewer_identity is not None and identity != viewer_identity)):
                    raise RuntimeError('live recording viewer principal or generation differs')
                viewer_identity = identity
                package_process(identity[0])
            if stage == 'recording-live':
                authority = authorization.enter_context(administrator(receiver, restarted_requester))
            elif stage == 'recording-live-disabled':
                recording_enabled = False
            elif stage == 'recording-live-enabled':
                recording_enabled = True
            recording_option(recording_enabled)
            if user_recording_options() != recording_profile:
                raise RuntimeError('live service recording change mutated the user profile')
            if stage.endswith('-submit'):
                authenticate(receiver, authority, restarted_requester, restarted, committed,
                             password_delay=2, action='com.carriez.RustDesk.set-incoming-recording')
            print('LINUX_INSTALLED_RECORDING_LIVE_OBSERVED=' + json.dumps({**event,
                  'viewer_start': viewer_identity[1], 'enabled_before_approval' if stage.endswith('-submit') else 'enabled':
                  recording_enabled, 'service_generation': restarted['generation']}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=100) != 0:
            raise RuntimeError('restarted GUI did not retire')
        authorization.close()
        credential_network(receiver, restarted, probe_sha, 'gui-service-recovered')
        print('LINUX_INSTALLED_SETTINGS_FAILURE=pass outcome=Failed service=absent '
              'protected=unchanged profile=unchanged recovery=same-gui-denied cleanup=joined', flush=True)
        print('LINUX_INSTALLED_RECORDING_SETTINGS=pass enabled=confirmed disabled=confirmed '
              'authorization=polkit-pam denial=no-agent pending=disabled persistence=root-service '
              'restart=service-and-gui profile=unchanged credential=unchanged ui=actual', flush=True)
    except Exception:
        if record is not None:
            try:
                path, data = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
                print('LINUX_INSTALLED_SETTINGS_FAILURE_STATE=' + json.dumps({
                    'credential_matches_baseline': receiver.credential() == before,
                    'child': receiver.child_record(), 'service_log': str(path),
                    'log_sha256': hashlib.sha256(data).hexdigest(),
                    'log_tail': data.decode().splitlines()[-20:]}, sort_keys=True), flush=True)
            except Exception as diagnostic_error:
                print(f'LINUX_INSTALLED_SETTINGS_FAILURE_OBSERVATION={diagnostic_error}', flush=True)
        raise
    finally:
        try:
            authorization.close()
        finally:
            try:
                if process is not None:
                    if process.poll() is None:
                        process.stdin.close()  # EOF makes the owning controller drain its actual children.
                        process.wait(timeout=50)
                    for pipe in (process.stdin, process.stdout):
                        if pipe is not None and not pipe.closed:
                            pipe.close()
            finally:
                run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
                if Path('/sys/fs/cgroup/system.slice/rustdesk.service').exists():
                    raise RuntimeError('installed service cgroup remains after stop')
                wait_network_retirement(network_before)


def pending_graphical_pam(agent_identity):
    # The pinned x86_64 helper has sent its PAM prompt before blocking in read(0).
    executable = Path('/usr/lib/polkit-1/polkit-agent-helper-1')
    expected = [os.fsencode(executable), b'rdreceiver4003', b'']
    deadline = time.monotonic() + 5
    while True:
        matches = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                fields = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                if int(fields[1]) == agent_identity[0] and (proc / 'cmdline').read_bytes().split(b'\0') == expected:
                    matches.append((proc, int(fields[19])))
            except FileNotFoundError:
                continue
        if len(matches) > 1:
            raise RuntimeError('graphical agent has duplicate PAM helpers')
        if matches:
            proc, start = matches[0]
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if (status['Uid'].split() != ['4001', '0', '0', '0']
                    or not (proc / 'exe').samefile(executable)
                    or int(Path(f'/proc/{agent_identity[0]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]) != agent_identity[1]):
                raise RuntimeError('graphical PAM helper identity differs')
            syscall = (proc / 'syscall').read_text().split()
            if len(syscall) >= 3 and syscall[0] == '0' and int(syscall[1], 0) == 0:
                return proc, start
        if time.monotonic() >= deadline:
            raise RuntimeError('graphical PAM helper did not wait for password input')
        time.sleep(0.01)


def recording_graphical_scenario(receiver, process, requester, record, agent_identity, session_cgroup):
    credential = receiver.credential()
    profile = user_recording_options()
    listener = receiver.direct_listener(record)
    action = 'com.carriez.RustDesk.set-incoming-recording'
    enabled = False
    submitted = cancelled = 0
    helper = helper_fd = pam_helper = pam_fd = cancelled_at = None
    helpers = []
    with ExitStack() as retained:
        for stage in RECORDING_GRAPHICAL_STAGES:
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('graphical recording stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'graphical recording ended before {stage}')
            event = json.loads(raw)
            if (event != {'stage': stage, 'pid': requester[0], 'agent_pid': agent_identity[0]}
                    or receiver.child_record() != record or receiver.direct_listener(record) != listener
                    or receiver.credential() != credential or user_recording_options() != profile):
                raise RuntimeError('graphical recording changed its owner, credential, profile or service')
            for identity, executable, nnp in ((requester, Path('/usr/share/rustdesk/rustdesk'), '1'),
                                               (agent_identity, GRAPHICAL_AGENT, '0')):
                proc = Path(f'/proc/{identity[0]}')
                fields = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                if (int(fields[19]) != identity[1] or fields[0] in (b'Z', b'X')
                        or not (proc / 'exe').samefile(executable)
                        or (proc / 'cgroup').read_text() != session_cgroup
                        or status['Uid'].split() != ['4001'] * 4 or status['NoNewPrivs'].strip() != nnp
                        or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))):
                    raise RuntimeError('graphical recording requester or agent identity differs')
            for pid in (requester[0], record['supervisor'], record['pid']):
                package_process(pid)
            if stage in ('recording-enable', 'recording-disable'):
                enabled = stage == 'recording-enable'
                if not select.select([helper_fd], [], [], 0)[0] or helper.exists():
                    raise RuntimeError('approved recording change did not reap its authorization helper')
            recording_option(enabled)
            command = b'continue\n'
            if stage.endswith('-submit'):
                submitted += 1
                helper, helper_start = receiver.pending_admin_helper(*requester, record, wait_seconds=5, action=action)
                helper_fd = os.pidfd_open(int(helper.name))
                retained.callback(os.close, helper_fd)
                identity = (int(helper.name), helper_start)
                if (identity in helpers or select.select([helper_fd], [], [], 0)[0]
                        or int((helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]) != helper_start):
                    raise RuntimeError('recording retry lacks a fresh live authorization helper')
                helpers.append(identity)
                if submitted == 1:
                    cancelled_at = time.monotonic()
                    command = b'cancel\n'
                elif submitted >= 3:
                    command = b'authenticate\n'
            elif stage == 'recording-agent-select':
                pam_helper, pam_start = pending_graphical_pam(agent_identity)
                pam_fd = os.pidfd_open(int(pam_helper.name))
                retained.callback(os.close, pam_fd)
                if (pending_graphical_pam(agent_identity) != (pam_helper, pam_start)
                        or select.select([pam_fd, helper_fd], [], [], 0)[0]):
                    raise RuntimeError('recording password entry lost its pending PAM helper')
            elif stage == 'recording-agent-password':
                if (pending_graphical_pam(agent_identity) != (pam_helper, pam_start)
                        or select.select([pam_fd, helper_fd], [], [], 0)[0]):
                    raise RuntimeError('partial recording password unexpectedly completed authentication')
                cancelled_at = time.monotonic()
            elif stage == 'recording-cancelled':
                cancelled += 1
                service_refusals(record, *requester, cancelled, exit_status=3, action=action)
                if (not select.select([helper_fd], [], [], 0)[0] or helper.exists()
                        or time.monotonic() - cancelled_at >= 10
                        or (pam_fd is not None and
                            (not select.select([pam_fd], [], [], 0)[0] or pam_helper.exists()))):
                    raise RuntimeError('cancelled recording authorization left a helper or exceeded its drain bound')
                print('LINUX_INSTALLED_RECORDING_GRAPHICAL_CANCEL=' + json.dumps({
                    'phase': 'password-entry' if pam_fd is not None else 'administrator-selection',
                    'requester': requester, 'agent': agent_identity, 'helper': helpers[-1],
                    'pam_helper': [int(pam_helper.name), pam_start] if pam_fd is not None else None,
                    'helpers_reaped': True, 'setting': False, 'credential_unchanged': True,
                    'profile_unchanged': True, 'seconds': time.monotonic() - cancelled_at}, sort_keys=True), flush=True)
            print('LINUX_INSTALLED_RECORDING_GRAPHICAL_STAGE=' + json.dumps({**event,
                  'requester_start': requester[1], 'agent_start': agent_identity[1],
                  'service_generation': record['generation'], 'enabled': enabled,
                  'credential_unchanged': True, 'profile_unchanged': True}, sort_keys=True), flush=True)
            process.stdin.write(command)
            process.stdin.flush()
    if submitted != 4 or cancelled != 2 or enabled:
        raise RuntimeError('graphical recording cancellation/retry coverage is incomplete')
    print('LINUX_INSTALLED_RECORDING_GRAPHICAL=pass cancellation=gtk-selection-and-password '
          'cancelled=2 fresh_authorizations=4 helpers=reaped protected=preserved profile=unchanged '
          'retry=same-gui-and-agent enabled=confirmed disabled=confirmed', flush=True)


def recording_concurrent_scenario(receiver, process, requester, record, agent_identity, session_cgroup):
    credential, profile = receiver.credential(), user_recording_options()
    listener = receiver.direct_listener(record)
    identities = {'primary': requester}
    helper = helper_fd = secondary_fd = owner = refused = None
    pam_helper = pam_fd = departed_at = None
    helpers = []
    departed_stages = ('depart-retired', 'recovery-submit', 'recovery-enabled',
                       'recovery-disable-submit', 'recovery-disabled', 'retired')

    def pending(wait_seconds=0):
        deadline = time.monotonic() + wait_seconds
        subjects = {f'{pid},{start},4001'.encode(): name for name, (pid, start) in identities.items()}
        prefix = [b'/usr/bin/pkcheck', b'--action-id', b'com.carriez.RustDesk.set-incoming-recording']
        while True:
            matches = []
            for proc in Path('/proc').iterdir():
                if not proc.name.isdecimal():
                    continue
                try:
                    fields = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                    if int(fields[1]) != record['supervisor']:
                        continue
                    argv = (proc / 'cmdline').read_bytes().split(b'\0')
                    if argv[:3] != prefix:
                        continue
                    if (len(argv) != 7 or argv[3] != b'--process' or argv[4] not in subjects
                            or argv[5:] != [b'--allow-user-interaction', b'']):
                        raise RuntimeError('concurrent recording helper has an unexpected subject or action')
                    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                    if status['Uid'].split() != ['0'] * 4 or not (proc / 'exe').samefile('/usr/bin/pkcheck'):
                        raise RuntimeError('concurrent recording helper has the wrong authority')
                    matches.append((int(proc.name), int(fields[19]), subjects[argv[4]]))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if len(matches) > 1:
                raise RuntimeError('concurrent recording admitted more than one authorization helper')
            if matches or time.monotonic() >= deadline:
                return matches
            time.sleep(0.01)

    with ExitStack() as retained:
        for stage in ('ready', 'submitted', 'contended', 'applied', 'retry-submitted', 'retry-applied',
                      'depart-submit', 'depart-password', *departed_stages):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('concurrent recording stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'concurrent recording ended before {stage}')
            event = json.loads(raw)
            if stage == 'ready':
                pid = event['secondary_pid']
                secondary_fd = os.pidfd_open(pid)
                retained.callback(os.close, secondary_fd)
                identities['secondary'] = (pid, int(Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
                if pid == requester[0]:
                    raise RuntimeError('concurrent recording did not launch a second GUI')
            expected = {'stage': stage, 'pid': requester[0], 'secondary_pid': identities['secondary'][0],
                        'agent_pid': agent_identity[0]}
            if stage == 'contended':
                refused = event.get('refused')
                if refused not in ('Denied', 'Failed'):
                    raise RuntimeError('competing recording request did not report an explicit refusal')
                expected.update(owner=owner, refused=refused)
            elif stage == 'depart-retired':
                if event.get('exit_status') not in (0, -signal.SIGTERM):
                    raise RuntimeError('recording requester did not exit normally or by its owned SIGTERM')
                expected['exit_status'] = event['exit_status']
            if (event != expected or receiver.child_record() != record or receiver.direct_listener(record) != listener
                    or receiver.credential() != credential or user_recording_options() != profile):
                raise RuntimeError('concurrent recording changed its owner, credential, profile or service')
            for name, identity in (*identities.items(), ('agent', agent_identity)):
                proc = Path(f'/proc/{identity[0]}')
                if name == 'secondary' and stage in departed_stages:
                    if not select.select([secondary_fd], [], [], 0)[0] or proc.exists():
                        raise RuntimeError('secondary recording GUI was not reaped')
                    continue
                fields = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                executable = GRAPHICAL_AGENT if name == 'agent' else Path('/usr/share/rustdesk/rustdesk')
                parent = Path(f'/proc/{requester[0]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[1]
                if (int(fields[19]) != identity[1] or fields[0] in (b'Z', b'X') or fields[1] != parent
                        or not (proc / 'exe').samefile(executable)
                        or (proc / 'cmdline').read_bytes().split(b'\0') != [os.fsencode(executable), b'']
                        or (proc / 'cgroup').read_text() != session_cgroup or status['Uid'].split() != ['4001'] * 4
                        or status['NoNewPrivs'].strip() != ('0' if name == 'agent' else '1')
                        or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))):
                    raise RuntimeError('concurrent recording requester or agent identity differs')
                if name != 'agent':
                    package_process(identity[0])
            for pid in (record['supervisor'], record['pid']):
                package_process(pid)
            enabled = stage in ('applied', 'retry-submitted', 'recovery-enabled', 'recovery-disable-submit')
            recording_option(enabled)
            command = b'continue\n'
            if stage in ('submitted', 'retry-submitted', 'depart-submit', 'recovery-submit', 'recovery-disable-submit'):
                matches = pending(5)
                if len(matches) != 1:
                    raise RuntimeError('recording submission has no pending authorization')
                helper = matches[0]
                if helper in helpers:
                    raise RuntimeError('recording retry reused its authorization helper')
                helper_fd = os.pidfd_open(helper[0])
                retained.callback(os.close, helper_fd)
                if pending() != [helper] or select.select([helper_fd], [], [], 0)[0]:
                    raise RuntimeError('recording submission lost its exact helper')
                helpers.append(helper)
                if stage == 'submitted':
                    owner = helper[2]
                    command = (owner + '\n').encode()
                elif stage == 'retry-submitted':
                    if helper[2] == owner:
                        raise RuntimeError('recording retry did not come from the previously refused GUI')
                    command = b'authenticate\n'
                elif stage == 'depart-submit':
                    if helper[2] != 'secondary':
                        raise RuntimeError('pending exit case does not belong to the secondary GUI')
                else:
                    if helper[2] != 'primary':
                        raise RuntimeError('post-exit recovery does not belong to the surviving GUI')
                    command = b'authenticate\n'
            elif stage in ('contended', 'depart-password'):
                if pending() != [helper] or select.select([helper_fd], [], [], 0)[0]:
                    raise RuntimeError('competing recording request displaced the original authorization')
                if stage == 'contended':
                    command = b'authenticate\n'
                else:
                    pam_helper, pam_start = pending_graphical_pam(agent_identity)
                    pam_fd = os.pidfd_open(int(pam_helper.name))
                    retained.callback(os.close, pam_fd)
                    if (pending_graphical_pam(agent_identity) != (pam_helper, pam_start)
                            or select.select([pam_fd, helper_fd, secondary_fd], [], [], 0)[0]):
                        raise RuntimeError('requester exit case has no live pending PAM conversation')
                    departed_at = time.monotonic()
                    command = b'depart\n'
            else:
                if pending():
                    raise RuntimeError('completed recording operation left a pending helper')
                if helper_fd is not None and (not select.select([helper_fd], [], [], 0)[0]
                                              or Path(f'/proc/{helper[0]}').exists()):
                    raise RuntimeError('completed recording operation did not reap its helper')
            if stage == 'depart-retired':
                seconds = time.monotonic() - departed_at
                if seconds >= 10 or not select.select([pam_fd], [], [], 0)[0] or pam_helper.exists():
                    raise RuntimeError('requester exit did not retire its PAM helper within ten seconds')
                print('LINUX_INSTALLED_RECORDING_REQUESTER_EXIT=' + json.dumps({
                    'requester': identities['secondary'], 'observer': requester, 'agent': agent_identity,
                    'helper': helper, 'pam_helper': [int(pam_helper.name), pam_start],
                    'exit_status': event['exit_status'], 'seconds': seconds,
                    'helpers_reaped': True, 'setting': False, 'credential_unchanged': True,
                    'profile_unchanged': True}, sort_keys=True), flush=True)
            exit_stage = stage.startswith(('depart-', 'recovery-'))
            prefix = 'LINUX_INSTALLED_RECORDING_REQUESTER_EXIT_STAGE=' if exit_stage else 'LINUX_INSTALLED_RECORDING_CONCURRENT_STAGE='
            print(prefix + json.dumps({**event,
                'identities': identities, 'agent': agent_identity, 'service_generation': record['generation'],
                'enabled': enabled, 'helper': helper, 'credential_unchanged': True,
                'profile_unchanged': True}, sort_keys=True), flush=True)
            process.stdin.write(command)
            process.stdin.flush()
    if (len(helpers) != 5 or helpers[0][2] == helpers[1][2] or refused is None
            or [helper[2] for helper in helpers[2:]] != ['secondary', 'primary', 'primary']):
        raise RuntimeError('recording concurrency coverage is incomplete')
    print('LINUX_INSTALLED_RECORDING_CONCURRENT=pass guis=2 pending=one competing=explicit-refusal '
          'authorization=preserved retry=other-gui enabled=confirmed disabled=confirmed '
          'helpers=reaped credential=unchanged profile=unchanged', flush=True)
    print('LINUX_INSTALLED_RECORDING_REQUESTER_EXIT_RECOVERY=pass requester=SIGTERM phase=partial-password '
          'dialog=retired helpers=reaped protected=preserved profile=unchanged '
          'retry=surviving-gui-and-agent enabled=confirmed disabled=confirmed', flush=True)


def recording_stop_scenario(receiver, process, requester, record, session_cgroup):
    credential, profile = receiver.credential(), user_recording_options()
    generations = [record['generation']]
    helper = helper_fd = agent = pam_helper = pam_fd = trace = None
    helpers = []
    with ExitStack() as retained, ExitStack() as barrier:
        def properties():
            return dict(line.split('=', 1) for line in run(['/usr/bin/systemctl', 'show', 'rustdesk.service',
                '--property=MainPID,ActiveState,SubState,Result,ExecMainStatus']).splitlines())

        def restart(current, committed):
            pidfds = [os.pidfd_open(pid) for pid in (current['supervisor'], current['pid'])]
            for fd in pidfds:
                retained.callback(os.close, fd)
            if receiver.child_record() != current or select.select(pidfds, [], [], 0)[0]:
                raise RuntimeError('recording stop lost its exact service generation')
            began = time.monotonic()
            run(['/usr/bin/systemctl', 'stop', '--no-block', 'rustdesk.service'])
            if committed:
                deadline = time.monotonic() + 3
                while True:
                    unit = properties()
                    _, log = owned_log(Path('/root/.local/share/logs/RustDesk/service'), current['supervisor'], 0)
                    if (unit['ActiveState'] == 'deactivating' and unit['MainPID'] == str(current['supervisor'])
                            and log.count(b'R-T9: graceful shutdown initiated') == 1):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('recording stop did not reach the actual supervisor drain')
                    time.sleep(0.02)
                for tid in trace.attached:
                    proc = Path(f'/proc/{current["pid"]}/task/{tid}')
                    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                    if ((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[0] != b't'
                            or int(status['TracerPid']) != os.getpid()):
                        raise RuntimeError('recording commit escaped the exact child stop barrier')
                recording_option(True)
                if receiver.child_record() != current or select.select(pidfds, [], [], 0)[0]:
                    raise RuntimeError('recording commit lost its owner before the stop barrier released')
                print('LINUX_INSTALLED_RECORDING_STOP_ADMITTED=' + json.dumps({**current,
                    'unit': unit, 'threads': sorted(trace.attached), 'enabled': True,
                    'credential_unchanged': receiver.credential() == credential}, sort_keys=True), flush=True)
                barrier.close()
            deadline = began + 10
            while properties()['ActiveState'] != 'inactive':
                if time.monotonic() >= deadline:
                    raise RuntimeError('recording stop exceeded ten seconds')
                time.sleep(0.02)
            stopped = service_absent()
            pending_helpers = [(helper, helper_fd)] + ([] if committed else [(pam_helper, pam_fd)])
            while any(not select.select([fd], [], [], 0)[0] or path.exists() for path, fd in pending_helpers):
                if time.monotonic() >= deadline:
                    raise RuntimeError('recording stop did not drain its authorization helpers within ten seconds')
                time.sleep(0.02)
            if (len(select.select(pidfds, [], [], 0)[0]) != 2
                    or any(Path(f'/proc/{pid}').exists() for pid in (current['supervisor'], current['pid']))
                    or not select.select([helper_fd], [], [], 0)[0] or helper.exists()
                    or (not committed and (not select.select([pam_fd], [], [], 0)[0] or pam_helper.exists()))
                    or receiver.credential() != credential or user_recording_options() != profile):
                raise RuntimeError('recording stop did not reap its owners or preserve protected state')
            recording_option(committed)
            print('LINUX_INSTALLED_RECORDING_SERVICE_STOPPED=' + json.dumps({**current,
                'committed': committed, 'seconds': time.monotonic() - began, 'unit': stopped,
                'helper': helpers[-1], 'pam_helper': None if committed else [int(pam_helper.name), pam_start],
                'helpers_reaped': True, 'credential_unchanged': True, 'profile_unchanged': True}, sort_keys=True), flush=True)
            run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
            fresh = receiver.ready(serving=True)
            if (fresh['generation'] in generations or fresh['supervisor'] == current['supervisor']
                    or fresh['pid'] == current['pid'] or receiver.credential() != credential):
                raise RuntimeError('recording restart did not establish a fresh generation with the same credential')
            generations.append(fresh['generation'])
            return fresh

        for stage in ('open', 'approval-submit', 'approval-password', 'approval-restarted',
                      'commit-submit', 'commit-authorized', 'commit-restarted', 'disable-submit', 'disabled'):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('recording shutdown GUI stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'recording shutdown ended before {stage}')
            event = json.loads(raw)
            if agent is None:
                agent = (event['agent_pid'], int(Path(f'/proc/{event["agent_pid"]}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
            expected = {'stage': stage, 'pid': requester[0], 'agent_pid': agent[0]}
            if stage.endswith('-restarted'):
                allowed = ('Applied', 'Uncertain') if stage == 'commit-restarted' else ('Denied', 'Uncertain')
                if event.get('outcome') not in allowed:
                    raise RuntimeError('recording restart reported an outcome inconsistent with the commit boundary')
                expected['outcome'] = event['outcome']
            if event != expected or receiver.child_record() != record:
                raise RuntimeError('recording shutdown changed its GUI or service owner')
            for identity, executable, nnp in ((requester, Path('/usr/share/rustdesk/rustdesk'), '1'),
                                               (agent, GRAPHICAL_AGENT, '0')):
                proc = Path(f'/proc/{identity[0]}')
                fields = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                if (int(fields[19]) != identity[1] or fields[0] in (b'Z', b'X')
                        or not (proc / 'exe').samefile(executable)
                        or (proc / 'cmdline').read_bytes().split(b'\0') != [os.fsencode(executable), b'']
                        or (proc / 'cgroup').read_text() != session_cgroup or status['Uid'].split() != ['4001'] * 4
                        or status['NoNewPrivs'].strip() != nnp
                        or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))):
                    raise RuntimeError('recording shutdown GUI or agent authority changed')
            command = b'continue\n'
            if stage in ('approval-submit', 'commit-submit', 'disable-submit'):
                helper, start = receiver.pending_admin_helper(*requester, record, wait_seconds=5,
                    action='com.carriez.RustDesk.set-incoming-recording')
                helper_fd = os.pidfd_open(int(helper.name))
                retained.callback(os.close, helper_fd)
                identity = (int(helper.name), start)
                if (identity in helpers or select.select([helper_fd], [], [], 0)[0]
                        or int((helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]) != start):
                    raise RuntimeError('recording shutdown lacks a fresh authorization helper')
                helpers.append(identity)
                if stage == 'commit-submit':
                    barrier.enter_context(stopped_child(receiver, record))
                    trace = receiver.TracedChildStop(record['pid'])
                    barrier.callback(trace.release)
                    child_fd = os.pidfd_open(record['pid'])
                    retained.callback(os.close, child_fd)
                    signal.pidfd_send_signal(child_fd, signal.SIGCONT)
                elif stage == 'disable-submit':
                    command = b'authenticate\n'
            elif stage == 'approval-password':
                pam_helper, pam_start = pending_graphical_pam(agent)
                pam_fd = os.pidfd_open(int(pam_helper.name))
                retained.callback(os.close, pam_fd)
                if pending_graphical_pam(agent) != (pam_helper, pam_start) or select.select([pam_fd, helper_fd], [], [], 0)[0]:
                    raise RuntimeError('recording service stop has no pending PAM conversation')
                record = restart(record, False)
            elif stage == 'commit-authorized':
                deadline = time.monotonic() + 5
                while not recording_value():
                    if time.monotonic() >= deadline or receiver.child_record() != record:
                        raise RuntimeError('approved recording change did not persist before shutdown')
                    time.sleep(0.01)
                record = restart(record, True)
            elif stage == 'disabled':
                if not select.select([helper_fd], [], [], 0)[0] or helper.exists():
                    raise RuntimeError('post-stop recording retry did not reap its helper')
            enabled = stage in ('commit-authorized', 'commit-restarted', 'disable-submit')
            recording_option(enabled)
            if receiver.credential() != credential or user_recording_options() != profile:
                raise RuntimeError('recording shutdown changed the credential or user profile')
            for pid in (requester[0], record['supervisor'], record['pid']):
                package_process(pid)
            print('LINUX_INSTALLED_RECORDING_STOP_STAGE=' + json.dumps({**event,
                'requester': requester, 'agent': agent, 'service_generation': record['generation'],
                'enabled': enabled, 'credential_unchanged': True, 'profile_unchanged': True}, sort_keys=True), flush=True)
            process.stdin.write(command)
            process.stdin.flush()
    if len(generations) != 3 or len(helpers) != 3:
        raise RuntimeError('recording shutdown coverage is incomplete')
    print('LINUX_INSTALLED_RECORDING_STOP=pass unapproved=preserved admitted=persisted '
          'outcomes=truthful generations=3 helpers=reaped credential=unchanged profile=unchanged '
          'retry=same-gui-and-agent disabled=confirmed', flush=True)
    return record


def admin_failure_scenario(receiver, probe_sha, network_before, graphical=None):
    package_unit()
    authorization = ExitStack()
    process = None
    requester = committed = profile_before = authority = None
    helper_fd = helper = helper_start = cancelled_at = agent_identity = None
    pam_fd = pam_helper = pam_start = None
    barrier = ExitStack()
    concurrent = first_committed = None
    retained_logs = []
    stages = GRAPHICAL_STAGES if graphical is not None else ADMIN_FAILURE_STAGES
    cancellations = 0
    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        receiver.change(0, BASELINE_PASSWORD, True)
        record = receiver.ready(serving=True)
        before = receiver.credential()
        receiver.keyed(BASELINE_PASSWORD, 'gui-admin-failure-baseline', record, probe_sha)
        listener = receiver.direct_listener(record)
        if listener is None:
            raise RuntimeError('administrator failure baseline has no ready listener')
        if graphical is None:
            process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S',
                                        str(SCRIPT), '--session-admin-failure'],
                                       env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        else:
            process, session_id, pam = graphical
            pam.properties({'process': process, 'session': session_id, 'uid': 4001, 'type': 'x11'}, 'active')
            session_cgroup = Path(f'/proc/{process.pid}/cgroup').read_text()
            if f'/session-{session_id}.scope\n' not in session_cgroup:
                raise RuntimeError('graphical workflow is outside its real logind session')
            process.stdin.write(b'application\n')
            process.stdin.flush()
        for index, stage in enumerate(stages):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('administrator failure GUI stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'administrator failure GUI ended before {stage}')
            event = json.loads(raw)
            proc = Path(f'/proc/{event["pid"]}')
            identity = (event['pid'], int((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            current_record = receiver.child_record()
            current_listener = receiver.direct_listener(record)
            if (event.get('stage') != stage or (requester is not None and requester != identity)
                    or status['Uid'].split() != ['4001'] * 4 or status['NoNewPrivs'].strip() != '1'
                    or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                    or not (proc / 'exe').samefile('/usr/share/rustdesk/rustdesk')
                    or current_record != record or current_listener != listener):
                raise RuntimeError('administrator failure lost the ordinary GUI or exact service generation: '
                                   + json.dumps({'event': event, 'requester': requester, 'identity': identity,
                                                 'status': status, 'expected_record': record,
                                                 'current_record': current_record, 'expected_listener': listener,
                                                 'current_listener': current_listener}, sort_keys=True))
            requester = identity
            for pid in (requester[0], record['supervisor'], record['pid']):
                package_process(pid)
            if graphical is not None:
                if (proc / 'cgroup').read_text() != session_cgroup:
                    raise RuntimeError('GUI left the native desktop session')
                if committed is None or stage == 'applied':
                    agent_proc = Path(f'/proc/{event["agent_pid"]}')
                    agent_start = int((agent_proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19])
                    current_agent = (event['agent_pid'], agent_start)
                    agent_status = dict(line.split(':', 1) for line in (agent_proc / 'status').read_text().splitlines() if ':' in line)
                    if ((agent_identity is not None and agent_identity != current_agent)
                            or not (agent_proc / 'exe').samefile(GRAPHICAL_AGENT)
                            or (agent_proc / 'cgroup').read_text() != session_cgroup
                            or agent_status['Uid'].split() != ['4001'] * 4
                            or agent_status['NoNewPrivs'].strip() != '0'
                            or any(int(agent_status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))):
                        raise RuntimeError('graphical agent identity or session changed')
                    agent_identity = current_agent
                elif event['agent_pid'] is not None or Path(f'/proc/{agent_identity[0]}').exists():
                    raise RuntimeError('graphical agent was not reaped before fresh no-agent refusal')
            if graphical is not None and stage == 'pending':
                deadline = time.monotonic() + 5
                while (first_committed := receiver.credential()) == before:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('concurrent GUI change did not reach durable commit')
                    time.sleep(0.01)
                committed = first_committed
            if stage == 'applied':
                if concurrent is not None:
                    stdout, stderr = concurrent.communicate(timeout=15)
                    if (concurrent.returncode != 0 or stdout.strip() != 'Done!'
                            or len(stdout) + len(stderr) > 131072):
                        raise RuntimeError('concurrent administrator CLI did not report Applied: '
                                           + repr((concurrent.returncode, stdout[-4096:], stderr[-4096:])))
                    print('LINUX_INSTALLED_SETTINGS_CONCURRENT_COMPLETE=' + json.dumps({
                        'cli_pid': concurrent.pid, 'exit': concurrent.returncode, 'stdout': stdout,
                        'stderr': stderr, 'gui_pid': requester[0], 'gui': 'Applied',
                        'seconds_after_resume': time.monotonic() - resumed_at,
                        'service_generation': record['generation']}, sort_keys=True), flush=True)
                committed = receiver.credential()
                if committed == before or (concurrent is not None and committed == first_committed):
                    raise RuntimeError('GUI reported authorized success without changing the credential')
            if receiver.credential() != (committed if committed is not None else before):
                raise RuntimeError('administrator failure changed the credential without authorized GUI success')
            if profile_before is not None and user_credential() != profile_before:
                raise RuntimeError('administrator failure or retry wrote a user-profile credential')
            command = b'continue\n'
            if index == 1:
                profile_before = user_credential()
                if graphical is None:
                    authority = authorization.enter_context(administrator(receiver, requester))
            elif index == 2 or (graphical is not None and index == 6):
                if graphical is None:
                    authenticate(receiver, authority, requester, record, before, incorrect_password=True)
                else:
                    if helper_fd is not None:
                        os.close(helper_fd)
                        helper_fd = None
                    helper, helper_start = receiver.pending_admin_helper(*requester, record, wait_seconds=5)
                    helper_fd = os.pidfd_open(int(helper.name))
                    if (int((helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]) != helper_start
                            or select.select([helper_fd], [], [], 0)[0]):
                        raise RuntimeError('graphical cancellation lost the pending authorization helper')
                    if index == 2:
                        cancelled_at = time.monotonic()
                        command = b'cancel\n'
            elif stage == 'agent-select':
                pam_helper, pam_start = pending_graphical_pam(agent_identity)
                pam_fd = os.pidfd_open(int(pam_helper.name))
                if (int((pam_helper / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]) != pam_start
                        or select.select([pam_fd, helper_fd], [], [], 0)[0]):
                    raise RuntimeError('password-entry fixture lost a pending authorization helper')
            elif stage == 'agent-password':
                if pending_graphical_pam(agent_identity) != (pam_helper, pam_start) or select.select([pam_fd, helper_fd], [], [], 0)[0]:
                    raise RuntimeError('partial password unexpectedly completed authentication')
                cancelled_at = time.monotonic()
            elif stage == 'denied' and committed is None:
                cancellations += 1
                service_refusals(record, *requester, cancellations, exit_status=3 if graphical is not None else 1)
                if graphical is not None:
                    if (not select.select([helper_fd], [], [], 0)[0] or helper.exists()
                            or time.monotonic() - cancelled_at >= 10):
                        raise RuntimeError('cancelled graphical authorization did not promptly reap its helper')
                    if pam_fd is not None and (not select.select([pam_fd], [], [], 0)[0] or pam_helper.exists()):
                        raise RuntimeError('cancelled password entry left its PAM helper')
                    print('LINUX_INSTALLED_SETTINGS_GRAPHICAL_CANCEL=' + json.dumps({
                        'requester': requester, 'agent': agent_identity, 'helper': [int(helper.name), helper_start],
                        'session': session_id, 'cgroup': session_cgroup, 'helper_reaped': True,
                        'phase': 'password-entry' if pam_fd is not None else 'administrator-selection',
                        'pam_helper': [int(pam_helper.name), pam_start] if pam_fd is not None else None,
                        'pam_helper_reaped': True if pam_fd is not None else None,
                        'protected_unchanged': True, 'seconds': time.monotonic() - cancelled_at}, sort_keys=True), flush=True)
                phase = 'gui-admin-failure-preserved' if cancellations == 1 else 'gui-password-cancel-preserved'
                receiver.keyed(BASELINE_PASSWORD, phase, record, probe_sha)
            elif stage == 'submit-approved':
                # Reuse the registered agent: this must produce a fresh actual PAM challenge.
                if graphical is None:
                    authenticate(receiver, authority, requester, record, before)
                else:
                    receiver.pending_admin_helper(*requester, record, wait_seconds=5)
                    for directory, pid, uid in (
                            ('/root/.local/share/logs/RustDesk/service', record['supervisor'], 0),
                            ('/home/rdreceiver4001/.local/share/logs/RustDesk/server', record['pid'], 4001)):
                        owned_log(Path(directory), pid, uid, retained=retained_logs)
                    threads = barrier.enter_context(stopped_child(receiver, record))
                    command = b'authenticate\n'
            elif stage == 'pending':
                # A second real administrator request overlaps the GUI's admitted commit.
                concurrent = subprocess.Popen([str(receiver.PRIMARY), '--password-stdin'], env=ENV,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                concurrent.stdin.write(CONCURRENT_PASSWORD + '\n')
                concurrent.stdin.close()
                concurrent.stdin = None
                started = time.monotonic()
                observed = [first_committed]
                while time.monotonic() - started < 2:
                    if (concurrent.poll() is not None or receiver.stopped_receiver_threads(record) != threads
                            or receiver.child_record() != record or user_credential() != profile_before):
                        raise RuntimeError('concurrent request completed or lost authority before child resume')
                    current = receiver.credential()
                    if current != observed[-1]:
                        observed.append(current)
                    if len(observed) != 1 or current == before:
                        raise RuntimeError('concurrent request persisted before the first runtime convergence')
                    time.sleep(0.02)
                cli_proc = Path(f'/proc/{concurrent.pid}')
                cli_status = dict(line.split(':', 1) for line in (cli_proc / 'status').read_text().splitlines() if ':' in line)
                if cli_status['Uid'].split() != ['0'] * 4 or not (cli_proc / 'exe').samefile(receiver.PRIMARY):
                    raise RuntimeError('concurrent administrator CLI identity differs')
                committed = receiver.credential()
                print('LINUX_INSTALLED_SETTINGS_CONCURRENT_PENDING=' + json.dumps({
                    **record, 'gui_pid': requester[0], 'cli_pid': concurrent.pid,
                    'cli_start': int((cli_proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]),
                    'child_threads': threads, 'seconds': time.monotonic() - started,
                    'durable_observations': observed, 'gui': 'pending', 'cli': 'pending',
                    'profile_unchanged': True}, sort_keys=True), flush=True)
                resumed_at = time.monotonic()
                barrier.close()
            elif stage == 'applied':
                authorization.close()
                if graphical is not None:
                    process.stdin.write(b'recording\n')
                    process.stdin.flush()
                    recording_graphical_scenario(receiver, process, requester, record, agent_identity, session_cgroup)
                    Path('/coord').mkdir(mode=0o700)
                    os.chown('/coord', 4001, 4001)
                    process.stdin.write(b'recording-concurrent\n')
                    process.stdin.flush()
                    recording_concurrent_scenario(receiver, process, requester, record, agent_identity, session_cgroup)
                    command = b'retire-agent\n'
            elif stage == 'denied':
                service_refusals(record, *requester, cancellations, exit_status=3 if graphical is not None else 1)
                service_refusals(record, *requester, 1)
            print('LINUX_INSTALLED_SETTINGS_ADMIN_STAGE=' + json.dumps({**event, 'index': index,
                  'requester_start': requester[1], 'service_generation': record['generation'],
                  'credential': 'committed' if committed is not None else 'baseline',
                  'profile_unchanged': user_credential() == profile_before if profile_before is not None else None},
                  sort_keys=True), flush=True)
            process.stdin.write(command)
            process.stdin.flush()
        if graphical is not None:
            process.stdin.write(b'recording-stop\n')
            process.stdin.flush()
            record = recording_stop_scenario(receiver, process, requester, record, session_cgroup)
            if pam.reply(process) != {'session': session_id, 'phase': 'application-closed'}:
                raise RuntimeError('PAM-owned graphical application did not retire')
        elif process.wait(timeout=15) != 0:
            raise RuntimeError('administrator failure GUI did not retire')
        if committed is None or receiver.credential() != committed:
            raise RuntimeError('administrator failure workflow did not retire with its committed credential')
        if graphical is not None:
            credential_network(receiver, record, probe_sha, 'gui-concurrent-final',
                               new=CONCURRENT_PASSWORD, old=GUI_PASSWORD)
        else:
            credential_network(receiver, record, probe_sha, 'gui-admin-failure-retry')
    except Exception as error:
        if graphical is not None and first_committed is not None:
            diagnostic = {'error': str(error), 'expected_service': record, 'logs': {}}
            for path, stream, uid in retained_logs:
                try:
                    before_log = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(before_log.st_mode) or before_log.st_uid != uid
                            or before_log.st_nlink != 1 or before_log.st_mode & 0o022
                            or before_log.st_size > 8 * 1024 * 1024):
                        raise RuntimeError('retained diagnostic log authority or bound changed')
                    data = os.pread(stream.fileno(), before_log.st_size, 0)
                    if len(data) != before_log.st_size or os.fstat(stream.fileno()).st_size < before_log.st_size:
                        raise RuntimeError('retained diagnostic log truncated during observation')
                    data = data[:data.rfind(b'\n') + 1]
                    diagnostic['logs'][str(path)] = {'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest(), 'tail': data[-16384:].decode('utf-8', errors='replace')}
                except (OSError, RuntimeError) as observation_error:
                    diagnostic['logs'][str(path)] = {'unavailable': str(observation_error)}
            print('LINUX_INSTALLED_SETTINGS_CONCURRENT_FAILURE=' + json.dumps(diagnostic, sort_keys=True), flush=True)
        raise
    finally:
        try:
            barrier.close()
            if concurrent is not None:
                if concurrent.poll() is None:
                    concurrent.terminate()
                stdout, stderr = concurrent.communicate(timeout=10)
                print('LINUX_INSTALLED_SETTINGS_CONCURRENT_RETIRED=' + json.dumps({
                    'pid': concurrent.pid, 'exit': concurrent.returncode,
                    'stdout': stdout[-4096:], 'stderr': stderr[-4096:]}, sort_keys=True), flush=True)
                for pipe in (concurrent.stdin, concurrent.stdout, concurrent.stderr):
                    if pipe is not None and not pipe.closed:
                        pipe.close()
            authorization.close()
            if helper_fd is not None:
                os.close(helper_fd)
            if pam_fd is not None:
                os.close(pam_fd)
            for _, stream, _ in retained_logs:
                stream.close()
        finally:
            try:
                if process is not None and graphical is None:
                    if process.poll() is None:
                        process.stdin.close()
                        process.wait(timeout=50)
                    for pipe in (process.stdin, process.stdout):
                        if not pipe.closed:
                            pipe.close()
            finally:
                run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
                if Path('/sys/fs/cgroup/system.slice/rustdesk.service').exists():
                    raise RuntimeError('administrator failure left the installed service cgroup')
                wait_network_retirement(network_before)


@contextmanager
def stopped_child(receiver, record):
    fd = os.pidfd_open(record['pid'])
    stopped = False
    try:
        if receiver.child_record() != record or select.select([fd], [], [], 0)[0]:
            raise RuntimeError('uncertainty fixture lost its exact service child')
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 3
        while (threads := receiver.stopped_receiver_threads(record)) is None:
            if time.monotonic() >= deadline:
                raise RuntimeError('uncertainty child never reached the kernel stop barrier')
            time.sleep(0.01)
        yield threads
    finally:
        try:
            if stopped and not select.select([fd], [], [], 0)[0]:
                signal.pidfd_send_signal(fd, signal.SIGCONT)
        finally:
            os.close(fd)


def uncertain_scenario(receiver, probe_sha, network_before):
    package_unit()
    authorization, barrier = ExitStack(), ExitStack()
    process = None
    record = committed = requester = profile_before = submitted_at = authority = None
    pending = 0
    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        record = receiver.ready()
        receiver.change(0, BASELINE_PASSWORD, True)
        before = receiver.credential()
        receiver.keyed(BASELINE_PASSWORD, 'gui-uncertain-baseline', record, probe_sha)
        process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S',
                                    str(SCRIPT), '--session-uncertain'],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for index, stage in enumerate(UNCERTAIN_STAGES):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('uncertainty GUI stage timed out')
            raw = process.stdout.readline(4096)
            if not raw or not raw.endswith(b'\n'):
                raise RuntimeError(f'uncertainty GUI ended before {stage}')
            event = json.loads(raw)
            proc = Path(f'/proc/{event["pid"]}')
            identity = (event['pid'], int((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19]))
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if (event.get('stage') != stage or (requester is not None and requester != identity)
                    or status['Uid'].split() != ['4001'] * 4 or status['NoNewPrivs'].strip() != '1'
                    or any(int(status[k], 16) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                    or not (proc / 'exe').samefile('/usr/share/rustdesk/rustdesk')
                    or receiver.child_record() != record
                    or receiver.credential() != (committed if committed is not None else before)):
                raise RuntimeError('uncertainty GUI, service generation or credential changed unexpectedly')
            for pid in (event['pid'], record['supervisor'], record['pid']):
                package_process(pid)
            requester = identity
            if stage == 'fill':
                profile_before = user_credential()
                threads = barrier.enter_context(stopped_child(receiver, record))
                authority = authorization.enter_context(administrator(receiver, requester))
                submitted_at = time.monotonic()
            elif stage == 'submit-approved':
                authenticate(receiver, authority, requester, record, before, password_delay=10)
                deadline = time.monotonic() + 5
                while (changed := receiver.credential()) == before:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('administrator-approved GUI mutation did not commit')
                    time.sleep(0.01)
                committed = changed
                if receiver.stopped_receiver_threads(record) != threads or user_credential() != profile_before:
                    raise RuntimeError('durable commit lost its stopped-child or user-profile boundary')
                print('LINUX_INSTALLED_SETTINGS_COMMITTED=' + json.dumps({**record,
                      'gui_pid': requester[0], 'child_threads': threads,
                      'seconds': time.monotonic() - submitted_at, 'protected_changed': True,
                      'profile_unchanged': True}, sort_keys=True), flush=True)
            elif stage == 'pending':
                pending += 1
                if receiver.stopped_receiver_threads(record) != threads or user_credential() != profile_before:
                    raise RuntimeError('pending GUI mutation escaped the controlled barrier')
                elapsed = time.monotonic() - submitted_at
                if elapsed >= 600 or (pending == 21 and elapsed < 595):
                    raise RuntimeError('pending GUI observation missed its pre-expiry window')
                print(f'LINUX_INSTALLED_SETTINGS_UNCERTAIN_WAIT index={pending} seconds={elapsed:.3f} '
                      'gui=pending child=kernel-stopped protected=committed', flush=True)
                target = submitted_at + (pending * 30 if pending < 20 else 596 if pending == 20 else 601)
                while time.monotonic() < target:
                    fields = Path(f'/proc/{record["pid"]}/stat').read_bytes().rsplit(b') ', 1)[1].split()
                    if (process.poll() is not None or fields[0] != b'T' or int(fields[19]) != record['start']
                            or receiver.credential() != committed):
                        raise RuntimeError('pending mutation lost its owner, held child or committed credential')
                    time.sleep(0.1)
            elif stage == 'uncertain':
                elapsed = time.monotonic() - submitted_at
                if not 600 <= elapsed <= 625 or pending != 21 or receiver.stopped_receiver_threads(record) != threads:
                    raise RuntimeError('uncertain GUI result lacks its real recovery-deadline boundary')
                print('LINUX_INSTALLED_SETTINGS_UNCERTAIN=' + json.dumps({**record,
                      'gui_pid': requester[0], 'seconds': elapsed, 'pending_checks': pending,
                      'protected_changed': receiver.credential() != before,
                      'profile_unchanged': user_credential() == profile_before,
                      'outcome': 'Uncertain'}, sort_keys=True), flush=True)
                barrier.close()
                authorization.close()
                # Allow the existing one-second replica retry; CPace below proves convergence.
                time.sleep(2)
                resumed_record = receiver.child_record()
                credential_preserved = receiver.credential() == committed
                if resumed_record != record or not credential_preserved:
                    diagnostic = {'expected': record, 'observed': resumed_record,
                                  'credential_preserved': credential_preserved,
                                  'seconds': time.monotonic() - submitted_at, 'logs': {}}
                    for label, directory, pid, uid in (
                            ('supervisor', '/root/.local/share/logs/RustDesk/service', record['supervisor'], 0),
                            ('original-child', '/home/rdreceiver4001/.local/share/logs/RustDesk/server', record['pid'], 4001),
                            ('current-child', '/home/rdreceiver4001/.local/share/logs/RustDesk/server', resumed_record['pid'], 4001)):
                        try:
                            path, data = owned_log(Path(directory), pid, uid)
                            diagnostic['logs'][label] = {'path': str(path), 'bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest(),
                                'tail': data[-8192:].decode('utf-8', errors='replace')}
                        except (OSError, RuntimeError) as error:
                            diagnostic['logs'][label] = {'unavailable': str(error)}
                    print('LINUX_INSTALLED_SETTINGS_RESUME_DIAGNOSTIC=' + json.dumps(diagnostic, sort_keys=True), flush=True)
                    raise RuntimeError('uncertain mutation changed its service child or protected credential after resume')
                credential_network(receiver, record, probe_sha, 'gui-uncertain-resumed')
            elif stage == 'denied':
                service_refusals(record, *requester, 1)
            print('LINUX_INSTALLED_SETTINGS_UNCERTAIN_STAGE=' + json.dumps({**event, 'index': index,
                  'credential': 'committed' if committed is not None else 'baseline',
                  'service_generation': record['generation']}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0 or receiver.credential() != committed or user_credential() != profile_before:
            raise RuntimeError('uncertainty GUI did not retire with the expected credential state')
        run(['/usr/bin/systemctl', 'restart', 'rustdesk.service'], timeout=40)
        restarted = receiver.ready(record)
        for pid in (restarted['supervisor'], restarted['pid']):
            package_process(pid)
        credential_network(receiver, restarted, probe_sha, 'gui-uncertain-restarted')
        if receiver.credential() != committed:
            raise RuntimeError('unconfirmed GUI mutation did not survive service restart')
    finally:
        try:
            barrier.close()
        finally:
            try:
                authorization.close()
            finally:
                try:
                    if process is not None:
                        if process.poll() is None:
                            process.stdin.close()
                            process.wait(timeout=50)
                        for pipe in (process.stdin, process.stdout):
                            if pipe is not None and not pipe.closed:
                                pipe.close()
                finally:
                    run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
                    service_absent()
                    wait_network_retirement(network_before)


def concurrent_stop_scenario(receiver, probe_sha, archive, network_before):
    package_unit()
    package_env = {**ENV, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'DEBIAN_FRONTEND': 'noninteractive'}
    clients, retained_logs, pidfds = [], [], {}
    trace = reference = replacement = None

    def payload_identity():
        return {str(path): {'device': path.stat().st_dev, 'inode': path.stat().st_ino}
                for path in (receiver.PRIMARY, receiver.CHILD, Path('/usr/share/rustdesk/lib/librustdesk.so'))}

    def properties():
        return dict(line.split('=', 1) for line in run([
            '/usr/bin/systemctl', 'show', 'rustdesk.service',
            '--property=MainPID,ActiveState,SubState,NRestarts,InvocationID,ExecMainCode,ExecMainStatus,Result,'
            'Type,KillMode,NotifyAccess,TimeoutStopUSec'
        ]).splitlines())

    def root_snapshot():
        path, stream, uid = retained_logs[0]
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_nlink != 1
                or metadata.st_mode & 0o022 or metadata.st_size > 8 * 1024 * 1024):
            raise RuntimeError('retained shutdown log authority or bound differs')
        data = os.pread(stream.fileno(), metadata.st_size, 0)
        if len(data) != metadata.st_size or os.fstat(stream.fileno()).st_size < metadata.st_size:
            raise RuntimeError('retained shutdown log truncated during observation')
        data = data[:data.rfind(b'\n') + 1]
        return data, {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                      'tail': data[-8192:].decode(errors='replace')}

    def launch(value):
        client = subprocess.Popen([str(receiver.PRIMARY), '--password-stdin'], env=ENV,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        clients.append(client)
        proc = Path(f'/proc/{client.pid}')
        deadline = time.monotonic() + 3
        while (proc / 'cmdline').read_bytes().split(b'\0') != [os.fsencode(receiver.PRIMARY), b'--password-stdin', b'']:
            if client.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('concurrent stop requester did not reach its exact installed role')
            time.sleep(0.005)
        status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
        if (status['Uid'].split() != ['0'] * 4 or not (proc / 'exe').samefile(receiver.PRIMARY)
                or (proc / 'cgroup').read_text() == Path(f'/proc/{record["supervisor"]}/cgroup').read_text()):
            raise RuntimeError('concurrent stop requester principal or image differs')
        identity = {'pid': client.pid, 'start': int((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19])}
        client.stdin.write(value + '\n')
        client.stdin.close()
        client.stdin = None
        return client, identity

    def held():
        if (any(client.poll() is not None for client in clients[:2])
                or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())
                or receiver.child_record() != record or receiver.credential() != first_value
                or user_credential() != profile):
            raise RuntimeError('queued changes lost pending ownership, durable ordering or profile isolation')
        if replacement is not None and (replacement.poll() is not None or payload_identity() != payload_before):
            raise RuntimeError('package replacement advanced before admitted credential changes drained')
        for tid in trace.attached:
            proc = Path(f'/proc/{record["pid"]}/task/{tid}')
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if ((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[0] != b't'
                    or int(status['TracerPid']) != os.getpid()):
                raise RuntimeError('concurrent stop child escaped the exact tracing barrier')

    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        receiver.change(0, BASELINE_PASSWORD, True)
        record = receiver.ready(serving=True)
        for pid in (record['supervisor'], record['pid']):
            package_process(pid)
        payload_before = payload_identity()
        baseline, profile = receiver.credential(), user_credential()
        receiver.keyed(BASELINE_PASSWORD, 'concurrent-stop-baseline', record, probe_sha)
        initial = properties()
        if (initial['ActiveState'] != 'active' or initial['MainPID'] != str(record['supervisor'])
                or any(initial[key] != value for key, value in
                       {'Type': 'notify', 'KillMode': 'mixed', 'NotifyAccess': 'main', 'TimeoutStopUSec': '30s'}.items())):
            raise RuntimeError('concurrent stop lacks the installed supervisor')
        reference = receiver.ServiceUnitResultReference()
        identities = {}
        for role, pid in (('supervisor', record['supervisor']), ('child', record['pid'])):
            pidfds[role] = os.pidfd_open(pid)
            identities[role] = {'pid': pid, 'start': int(Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()[19])}
        if identities['child']['start'] != record['start'] or receiver.child_record() != record:
            raise RuntimeError('concurrent stop service identity changed')
        owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0, retained=retained_logs)
        with stopped_child(receiver, record):
            trace = receiver.TracedChildStop(record['pid'])
            signal.pidfd_send_signal(pidfds['child'], signal.SIGCONT)
            first, first_identity = launch(GUI_PASSWORD)
            deadline = time.monotonic() + 5
            while (first_value := receiver.credential()) == baseline:
                if first.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('first concurrent stop request did not persist')
                time.sleep(0.01)
            second, second_identity = launch(CONCURRENT_PASSWORD)
            began = time.monotonic()
            while time.monotonic() - began < 2:
                held()
                time.sleep(0.02)
            # Dpkg's real prerm must wait for the service drain before unpacking.
            # Separate configuration exposes the stopped state without a fixture restart.
            replacement = subprocess.Popen(['/usr/bin/dpkg', '--unpack', str(archive)], env=package_env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True)
            stopping_at = time.monotonic()
            while True:
                held()
                current = properties()
                _, root_log = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
                if (current['ActiveState'] == 'deactivating' and current['SubState'] == 'stop-sigterm'
                        and root_log.count(b'R-T9: graceful shutdown initiated') == 1):
                    break
                if time.monotonic() - stopping_at > 3:
                    raise RuntimeError('package replacement did not initiate actual service shutdown')
                time.sleep(0.05)
            # A fresh caller must not enter the closed admission queue.
            late, late_identity = launch('Post-stop-must-not-apply-2026!')
            stdout, stderr = late.communicate(timeout=5)
            if late.returncode != 1 or stdout.strip() == 'Done!':
                raise RuntimeError('post-stop request did not report refusal')
            print('LINUX_INSTALLED_SETTINGS_STOP_REFUSAL=' + json.dumps({**late_identity,
                  'exit': late.returncode, 'stdout': stdout, 'stderr': stderr}, sort_keys=True), flush=True)
            # Cross the shipped 30-second stop deadline with both admitted owners held.
            while time.monotonic() - stopping_at < 35:
                held()
                time.sleep(0.05)
            current = properties()
            if (current['MainPID'] != initial['MainPID'] or current['InvocationID'] != initial['InvocationID']
                    or current['NRestarts'] != initial['NRestarts'] or current['ActiveState'] != 'deactivating'):
                raise RuntimeError('queued changes did not survive the original unit stop deadline')
            print('LINUX_INSTALLED_SETTINGS_STOP_PENDING=' + json.dumps({**record,
                  'requesters': [first_identity, second_identity], 'threads': sorted(trace.attached),
                  'seconds_after_stop': time.monotonic() - stopping_at, 'unit': current,
                  'durable': first_value, 'profile_unchanged': True,
                  'package': {'pid': replacement.pid, 'archive_sha256': digest(archive),
                              'payload_before': payload_before}}, sort_keys=True), flush=True)
            resumed_at = time.monotonic()
            trace.release()
            results = []
            for client, identity in ((first, first_identity), (second, second_identity)):
                stdout, stderr = client.communicate(timeout=10)
                if client.returncode != 0 or stdout != 'Done!\n' or stderr:
                    raise RuntimeError('admitted change lacked Applied after the shutdown barrier: '
                                       + repr((client.returncode, stdout[-4096:], stderr[-4096:])))
                results.append({**identity, 'exit': client.returncode, 'stdout': stdout})
        output, _ = replacement.communicate(timeout=20)
        if replacement.returncode != 0 or len(output) > 131072:
            raise RuntimeError('package unpack did not complete after credential drain: ' + output[-8192:])
        package_status = run(['/usr/bin/dpkg-query', '--show', '--showformat=${Status}', 'rustdesk'])
        payload_after = payload_identity()
        if package_status != 'install ok unpacked' or any(
                payload_after[path] == identity for path, identity in payload_before.items()):
            raise RuntimeError('package did not replace every executable payload after draining')
        print('LINUX_DEBIAN_STOP_UNPACK=' + json.dumps({
            'pid': replacement.pid, 'exit': replacement.returncode, 'output': output,
            'status': package_status, 'payload_before': payload_before, 'payload_after': payload_after,
        }, sort_keys=True), flush=True)
        deadline = resumed_at + 20
        while (any(not select.select([fd], [], [], 0)[0] for fd in pidfds.values())
               or Path('/sys/fs/cgroup/system.slice/rustdesk.service').exists()):
            if time.monotonic() >= deadline:
                raise RuntimeError('drained service did not retire its exact generation')
            time.sleep(0.02)
        for identity in identities.values():
            proc = Path(f'/proc/{identity["pid"]}/stat')
            if proc.exists() and int(proc.read_bytes().rsplit(b') ', 1)[1].split()[19]) == identity['start']:
                raise RuntimeError('drained service process was not reaped')
        service_absent()
        outcome = properties()
        final_value = receiver.credential()
        if (outcome['ExecMainCode'] != '1' or outcome['ExecMainStatus'] != '0' or outcome['Result'] != 'success'
                or outcome['NRestarts'] != initial['NRestarts']
                or final_value in (baseline, first_value) or user_credential() != profile):
            raise RuntimeError('concurrent drain lost its final credential or clean service outcome')
        root_log, log_snapshot = root_snapshot()
        if (not any(line.endswith(b'] Exit') for line in root_log.splitlines())
                or b' ERROR ' in root_log):
            raise RuntimeError('retained supervisor log lacks a clean final exit')
        print('LINUX_INSTALLED_SETTINGS_STOP_COMPLETE=' + json.dumps({**record, 'requesters': results,
              'seconds_after_resume': time.monotonic() - resumed_at, 'unit': outcome,
              'durable': final_value, 'processes_reaped': identities, 'profile_unchanged': True,
              'root_log': log_snapshot}, sort_keys=True), flush=True)
        reference.close()
        output = run(['/usr/bin/dpkg', '--configure', 'rustdesk'], env=package_env, timeout=45)
        print('LINUX_DEBIAN_STOP_CONFIGURE=' + json.dumps({'exit': 0, 'output': output}, sort_keys=True), flush=True)
        package_unit()
        if (run(['/usr/bin/dpkg-query', '--show', '--showformat=${Status}', 'rustdesk']) != 'install ok installed'
                or run(['/usr/bin/dpkg', '--verify', 'rustdesk'])):
            raise RuntimeError('drained package replacement is not configured and intact')
        recovered = receiver.ready(serving=True)
        for pid in (recovered['supervisor'], recovered['pid']):
            package_process(pid)
        if (recovered['generation'] == record['generation'] or receiver.credential() != final_value):
            raise RuntimeError('restart did not retain the final queued credential in a fresh generation')
        credential_network(receiver, recovered, probe_sha, 'concurrent-stop-restart',
                           new=CONCURRENT_PASSWORD, old=GUI_PASSWORD)
    except Exception as error:
        if retained_logs:
            _, snapshot = root_snapshot()
            print('LINUX_INSTALLED_SETTINGS_STOP_FAILURE=' + json.dumps(
                {'error': str(error), 'root_log': snapshot}, sort_keys=True), flush=True)
        raise
    finally:
        try:
            if trace is not None and trace.attached:
                if select.select([pidfds['child']], [], [], 0)[0]:
                    trace.reap_killed()
                else:
                    trace.release()
        finally:
            try:
                if replacement is not None:
                    replacement.communicate(timeout=45)
                    replacement.stdout.close()
                for client in clients:
                    if client.poll() is None:
                        client.kill()
                    client.communicate(timeout=5)
                    for pipe in (client.stdin, client.stdout, client.stderr):
                        if pipe is not None and not pipe.closed:
                            pipe.close()
                run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=40)
                service_absent()
                wait_network_retirement(network_before)
            finally:
                if reference is not None:
                    reference.close()
                for _, stream, _ in retained_logs:
                    stream.close()
                for fd in pidfds.values():
                    os.close(fd)


def main(arguments, uncertain=False, admin_failure=False, graphical=False, concurrent_stop=False, package=False,
         settings=False, upgrade=False, conffiles=False, camera=False, remote=False):
    guard()
    agent_archive_sha = None
    if graphical:
        arguments, agent_archive_sha = arguments[:-1], arguments[-1]
    package_install = not package
    (source, app_input, context, manifest_sha, commit, provider, image, client, sock, config,
     archive_sha, polkit_manifest, probe_commit, probe_manifest_sha, probe_sha, probe_size) = arguments
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
    prepared = prepare_runtime(source, execution, image, client, sock, config, graphical=graphical,
                               package_install=package_install, settings=settings or uncertain or admin_failure,
                               upgrade=upgrade, conffiles=conffiles, camera=camera, remote=remote)
    if not package:
        probe_manifest = MEDIA / 'settings-probe/peer-manifest.json'
        probe = MEDIA / 'settings-probe/probe_client'
        if (digest(probe_manifest) != probe_manifest_sha or digest(probe) != probe_sha
                or probe.stat().st_size != int(probe_size)):
            raise RuntimeError('retained CPace probe input identity differs')
        probe_record = json.loads(probe_manifest.read_text())
        if (probe_record['context']['source_commit'] != probe_commit
                or probe_record['files']['probe_client'] != {'bytes': int(probe_size), 'sha256': probe_sha}):
            raise RuntimeError('retained CPace probe provenance differs')
        install(probe, receiver.PROBE, 0o755)
    if package_install:
        subprocess.run(['/usr/bin/python3', '-B', '-I', '-S',
                        str(SCRIPT.with_name('test-linux-debian-install.py')),
                        '--run-remote-' + remote if remote in ('network', 'loss', 'congestion', 'backoff', 'input-recovery') else '--run-remote' if remote
                        else '--run-camera-busy' if camera == 'busy' else '--run-camera' if camera
                        else '--run-admin-failure' if admin_failure else '--run-concurrent-stop' if concurrent_stop
                        else '--run-conffiles' if conffiles
                        else '--run-upgrade' if upgrade else '--run-uncertain' if uncertain
                        else '--run-settings' if settings else '--run', str(source),
                        str(prepared), str(app_input), manifest_sha, commit, probe_sha,
                        *([agent_archive_sha] if graphical else [])],
                       env=ENV, check=True, timeout=840 if uncertain else 600)
        return
    if package:
        print(f'LINUX_DEBIAN_CANDIDATE_NATIVE=pass app_commit={commit} manifest_sha256={manifest_sha} '
              'packages=2 equality=bytes constructor=production archive=validated payloads=unchanged '
              'install=unexecuted app_build=absent cleanup=joined', flush=True)
        return


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare-package-remote']:
        prepare_package(single=True, remote=True)
    elif sys.argv[1:] == ['--prepare-package-camera']:
        prepare_package(single=True, camera=True)
    elif sys.argv[1:] == ['--prepare-package-graphical']:
        prepare_package(single=True, graphical=True)
    elif sys.argv[1:] == ['--prepare-package-settings']:
        prepare_package(single=True, settings=True)
    elif sys.argv[1:] == ['--prepare-package']:
        prepare_package()
    elif sys.argv[1:] == ['--prepare-package-install']:
        prepare_package(single=True)
    elif sys.argv[1:] == ['--prepare-package-upgrade']:
        prepare_package(single=True, upgrade=True)
    elif sys.argv[1:] == ['--prepare-package-conffiles']:
        prepare_package(single=True, conffiles=True)
    elif sys.argv[1:] == ['--session']:
        session()
    elif sys.argv[1:] == ['--session-restart']:
        session(restarted=True)
    elif sys.argv[1:] == ['--session-uncertain']:
        session(uncertain=True)
    elif sys.argv[1:] == ['--session-admin-failure']:
        session(admin_failure=True)
    elif sys.argv[1:] == ['--session-graphical']:
        session(admin_failure=True, graphical=True)
    elif len(sys.argv) == 19 and sys.argv[1] == '--run-graphical':
        main(sys.argv[2:], graphical=True)
    elif len(sys.argv) == 18 and sys.argv[1] in ('--run', '--run-uncertain', '--run-admin-failure', '--run-concurrent-stop', '--run-package', '--run-package-install', '--run-package-upgrade', '--run-package-conffiles', '--run-package-camera', '--run-package-camera-busy', '--run-package-remote', '--run-package-remote-network', '--run-package-remote-loss', '--run-package-remote-congestion', '--run-package-remote-backoff', '--run-package-remote-input-recovery'):
        main(sys.argv[2:], uncertain=sys.argv[1] == '--run-uncertain',
             admin_failure=sys.argv[1] == '--run-admin-failure', concurrent_stop=sys.argv[1] == '--run-concurrent-stop',
             package=sys.argv[1] == '--run-package',
             settings=sys.argv[1] == '--run', upgrade=sys.argv[1] == '--run-package-upgrade',
             conffiles=sys.argv[1] == '--run-package-conffiles',
             camera={'--run-package-camera': 'recovery', '--run-package-camera-busy': 'busy'}.get(sys.argv[1], False),
             remote={'--run-package-remote': 'suspend', '--run-package-remote-network': 'network',
                     '--run-package-remote-loss': 'loss', '--run-package-remote-congestion': 'congestion',
                     '--run-package-remote-backoff': 'backoff',
                     '--run-package-remote-input-recovery': 'input-recovery'}.get(sys.argv[1], False))
    else:
        raise SystemExit('closed installed-settings arguments required')

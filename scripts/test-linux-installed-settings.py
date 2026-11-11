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
import pwd
import re
import runpy
import select
import shutil
import signal
import socket
import stat
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
          'reopen', 'fill', 'submit-approved', 'applied', 'reopen', 'submit', 'denied')
RESTART_STAGES = ('open', 'fill', 'submit', 'failed', 'reopen', 'submit', 'denied')
UNCERTAIN_STAGES = (('open', 'fill', 'submit-approved') + ('pending',) * 21
                    + ('uncertain', 'uncertain-preserved', 'cancel', 'reopen', 'submit', 'denied'))
ADMIN_FAILURE_STAGES = ('open', 'fill', 'submit', 'denied', 'reopen', 'fill',
                        'submit-approved', 'applied', 'reopen', 'submit', 'denied')
GRAPHICAL_STAGES = ('open', 'fill', 'submit', 'denied', 'reopen', 'fill', 'submit',
                    'agent-select', 'agent-password', 'agent-cancel', 'denied',
                    'reopen', 'fill', 'submit-approved', 'pending', 'applied', 'reopen', 'submit', 'denied')


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


def prepare(graphical=False):
    if os.getuid() != 1000 or not Path('/.dockerenv').is_file():
        raise RuntimeError('settings runtime preparation requires the ordinary isolated container')
    print(run(['/usr/bin/python3', '-B', '-I', '-S', '/work/scripts/test-installed-settings-log.py']),
          end='', flush=True)
    for kind in ('xvfb', 'atspi'):
        print(run(['/bin/bash', f'/work/scripts/smoke-{kind}-prepare.sh'], timeout=60), end='', flush=True)
    flags = run(['/usr/bin/pkg-config', '--cflags', '--libs', 'x11', 'xtst', 'xi',
                 'atspi-2', 'gobject-2.0', 'gtk+-3.0']).split()
    for copy in ('first', 'second'):
        run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             '/work/scripts/linux-installed-settings-x11.c', *flags, '-o', f'/out/driver-{copy}'], timeout=60)
    if digest('/out/driver-first') != digest('/out/driver-second'):
        raise RuntimeError('repeated settings driver builds differ')
    if graphical:
        for copy in ('first', 'second'):
            run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                 '/work/scripts/linux-polkit-dialog-x11.c', *flags, '-o', f'/out/agent-driver-{copy}'], timeout=60)
        if digest('/out/agent-driver-first') != digest('/out/agent-driver-second'):
            raise RuntimeError('repeated graphical-agent driver builds differ')
    libraries = Path('/out/libraries')
    libraries.mkdir()
    roots = []
    for path in Path('/app/bundle').rglob('*'):
        if path.is_file():
            with path.open('rb') as stream:
                if stream.read(4) == b'\x7fELF':
                    roots.append(path)
    roots += [Path('/out/driver-first'), Path('/xvfb-root/usr/bin/Xvfb'),
              Path('/xvfb-root/usr/bin/xkbcomp'), Path('/usr/bin/dbus-daemon'), Path('/usr/bin/fc-match'),
              Path('/atspi-root/usr/libexec/at-spi-bus-launcher'),
              Path('/atspi-root/usr/libexec/at-spi2-registryd')]
    dynamic = [Path('/usr/lib/x86_64-linux-gnu') / name for name in
               ('dri/swrast_dri.so', 'libEGL_mesa.so.0', 'libGLX_mesa.so.0',
                'libEGL.so.1', 'libGLESv2.so.2', 'libGL.so.1', 'libGLX.so.0')]
    if graphical:
        # PNG is built into this GdkPixbuf; its GIO format detection needs the MIME database.
        shutil.copyfile('/usr/share/mime/mime.cache', '/out/mime.cache')
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
                         ('/usr/share/fonts/truetype/dejavu', 'fonts'), ('/etc/fonts', 'fontconfig')):
        shutil.copytree(source, '/out/' + name)
    shutil.copyfile('/usr/bin/fc-match', '/out/fc-match')
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


def prepare_package():
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
    archives = []
    for name in ('first', 'second'):
        stage = Path('/out') / (name + '-stage')
        archive = Path('/out') / (name + '.deb')
        module['package_flutter_deb'](version, bundle, stage, archive)
        print(run(['/usr/bin/python3', '-B', '-I', '-S',
                   '/work/scripts/verify-debian-package-authority.py', '--repo', '/work',
                   '--deb', str(archive)], timeout=60), end='', flush=True)
        extracted = Path('/out') / (name + '-extracted')
        run(['/usr/bin/dpkg-deb', '--extract', str(archive), str(extracted)], timeout=60)
        for relative, expected in original.items():
            if digest(extracted / 'usr/share/rustdesk' / relative) != expected:
                raise RuntimeError('candidate archive changed a retained application payload')
        child = extracted / 'usr/share/rustdesk/rustdesk-service-child'
        if digest(child) != original['rustdesk'] or stat.S_IMODE(child.stat().st_mode) != 0o711:
            raise RuntimeError('candidate service-child image differs')
        archives.append({'sha256': digest(archive), 'bytes': archive.stat().st_size})
        shutil.rmtree(stage)
        shutil.rmtree(extracted)
    if archives[0] != archives[1]:
        raise RuntimeError('independent packaging stages produced different archives')
    if original != {str(p.relative_to(bundle)): digest(p) for p in bundle.rglob('*') if p.is_file()}:
        raise RuntimeError('candidate packaging changed its retained application input')
    print('LINUX_DEBIAN_CANDIDATE_PACKAGE=' + json.dumps({
        'archive': archives[0], 'version': version, 'source_date_epoch': epoch,
        'application_files': len(original), 'packager_sha256': digest('/work/build.py'),
        'validator_sha256': digest('/work/scripts/verify-debian-package-authority.py'),
        'dpkg_deb_sha256': digest('/usr/bin/dpkg-deb'),
        'scope': 'retained-application-packaging-only', 'builds': 2,
    }, sort_keys=True), flush=True)
    records = {str(p.relative_to('/out')): {'sha256': digest(p), 'bytes': p.stat().st_size}
               for p in Path('/out').iterdir() if p.is_file()}
    if sum(r['bytes'] for r in records.values()) > 268435456:
        raise RuntimeError('candidate packages exceed 256 MiB')
    Path('/out/manifest.json').write_text(json.dumps(records, sort_keys=True))


def prepare_runtime(source, execution, image, client, sock, config, graphical=False, package=False):
    prepared = WORK / 'prepared'
    prepared.mkdir(mode=0o700)
    os.chown(prepared, 1000, 1000)
    mounts = [(str(source), '/work', True), (str(execution), '/app', True),
              (str(prepared), '/out', False)]
    for kind in (() if package else ('xvfb', 'atspi')):
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
             '--prepare-package' if package else '--prepare-graphical' if graphical else '--prepare']
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
    for name, destination in (('xkb', WORK / 'xkb'),
                              ('fonts', Path('/usr/share/fonts/truetype/dejavu')),
                              ('fontconfig', Path('/etc/fonts'))):
        for path in (prepared / name).rglob('*'):
            if path.is_file():
                install(path, destination / path.relative_to(prepared / name))
    install(prepared / 'fc-match', WORK / 'fc-match', 0o755)
    install(prepared / 'driver-first', WORK / 'settings-driver', 0o755)
    if (prepared / 'agent-driver-first').exists():
        install(prepared / 'agent-driver-first', WORK / 'agent-driver', 0o755)
    install(prepared / '50_mesa.json', '/usr/share/glvnd/egl_vendor.d/50_mesa.json')
    # Xvfb starts with the receiver's closed environment, before the GUI environment.
    install(prepared / 'libraries/swrast_dri.so', '/usr/lib/x86_64-linux-gnu/dri/swrast_dri.so')
    run(['/usr/sbin/ldconfig'])
    if (prepared / 'mime.cache').exists():
        install(prepared / 'mime.cache', '/usr/share/mime/mime.cache')
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
    extracted = WORK / 'graphical-agent-package'
    run(['/usr/bin/dpkg-deb', '--extract', str(path), str(extracted)])
    install(extracted / GRAPHICAL_AGENT.relative_to('/'), GRAPHICAL_AGENT, 0o755)
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
                   'LIBGL_ALWAYS_SOFTWARE': '1', 'LIBGL_DRIVERS_PATH': '/usr/local/lib/rustdesk-settings-fixture'}
    bus = app = agent = None
    try:
        font = run([str(WORK / 'fc-match'), '-f', '%{file}', 'sans-serif'], env=environment).strip()
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
                driver = [str(WORK / 'agent-driver'), str(agent.pid), action]
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
            if graphical and command in ('cancel\n', 'authenticate\n') and agent is not None:
                if agent.poll() is not None:
                    raise RuntimeError('graphical authentication agent exited before its dialog action')
                print(run([str(WORK / 'agent-driver'), str(agent.pid), command.strip()], env=environment,
                          timeout=40, output_limit=524288), end='', file=sys.stderr, flush=True)
            elif graphical and command == 'retire-agent\n' and agent is not None:
                agent.terminate()
                agent.wait(timeout=8)
                agent = None
            elif command != 'continue\n':
                raise RuntimeError('GUI scenario lost its owning controller')
    finally:
        for process in (app, agent, bus):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
        retire_children()


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


def service_refusals(record, requester, start, count, exit_status=2):
    path, data = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
    messages = data.decode().splitlines()
    prefix = ('polkit denied action=com.carriez.RustDesk.set-unattended-password, '
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


def authenticate(receiver, authority, requester, record, before, password_delay=0, incorrect_password=False):
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
                if (b'com.carriez.RustDesk.set-unattended-password' not in terminal
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


def scenario(receiver, probe_sha):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('installed settings require absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    process = None
    authorization = ExitStack()
    network_before = network_state()
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
            print('LINUX_INSTALLED_SETTINGS_OBSERVED=' + json.dumps({**event, 'index': index,
                  'credential': 'committed' if committed is not None else 'baseline',
                  'service_generation': record['generation']}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('installed GUI session did not retire successfully')
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
        credential_network(receiver, restarted, probe_sha, 'gui-restarted')
        for pipe in (process.stdin, process.stdout):
            pipe.close()
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
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('restarted GUI did not retire')
        credential_network(receiver, restarted, probe_sha, 'gui-service-recovered')
        print('LINUX_INSTALLED_SETTINGS_FAILURE=pass outcome=Failed service=absent '
              'protected=unchanged profile=unchanged recovery=same-gui-denied cleanup=joined', flush=True)
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


def admin_failure_scenario(receiver, probe_sha, graphical=None):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('administrator failure scenario requires absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    network_before = network_state()
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
        record = receiver.ready()
        receiver.change(0, BASELINE_PASSWORD, True)
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


def uncertain_scenario(receiver, probe_sha):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('uncertainty scenario requires absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    network_before = network_state()
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


def concurrent_stop_scenario(receiver, probe_sha):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('concurrent stop requires absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    network_before = network_state()
    clients, retained_logs, pidfds = [], [], {}
    trace = reference = None

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
        for tid in trace.attached:
            proc = Path(f'/proc/{record["pid"]}/task/{tid}')
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if ((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[0] != b't'
                    or int(status['TracerPid']) != os.getpid()):
                raise RuntimeError('concurrent stop child escaped the exact tracing barrier')

    try:
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        record = receiver.ready()
        receiver.change(0, BASELINE_PASSWORD, True)
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
            run(['/usr/bin/systemctl', 'stop', '--no-block', 'rustdesk.service'], timeout=5)
            stopping_at = time.monotonic()
            while True:
                held()
                current = properties()
                _, root_log = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
                if (current['ActiveState'] == 'deactivating' and current['SubState'] == 'stop-sigterm'
                        and root_log.count(b'R-T9: graceful shutdown initiated') == 1):
                    break
                if time.monotonic() - stopping_at > 3:
                    raise RuntimeError('normal stop did not initiate actual service shutdown')
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
                  'durable': first_value, 'profile_unchanged': True}, sort_keys=True), flush=True)
            resumed_at = time.monotonic()
            trace.release()
            results = []
            for client, identity in ((first, first_identity), (second, second_identity)):
                stdout, stderr = client.communicate(timeout=10)
                if client.returncode != 0 or stdout != 'Done!\n' or stderr:
                    raise RuntimeError('admitted change lacked Applied after the shutdown barrier: '
                                       + repr((client.returncode, stdout[-4096:], stderr[-4096:])))
                results.append({**identity, 'exit': client.returncode, 'stdout': stdout})
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
        if (outcome['ExecMainCode'] != '1' or outcome['NRestarts'] != initial['NRestarts']
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
        run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
        recovered = receiver.ready()
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


def main(arguments, uncertain=False, admin_failure=False, graphical=False, concurrent_stop=False, package=False):
    guard()
    if graphical:
        arguments, agent_archive_sha = arguments[:-1], arguments[-1]
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
    prepared = prepare_runtime(source, execution, image, client, sock, config, graphical=graphical, package=package)
    if package:
        print(f'LINUX_DEBIAN_CANDIDATE_NATIVE=pass app_commit={commit} manifest_sha256={manifest_sha} '
              'packages=2 equality=bytes constructor=production archive=validated payloads=unchanged '
              'install=unexecuted app_build=absent cleanup=joined', flush=True)
        return
    receiver.install_polkit(archive_sha, polkit_manifest)
    install_runtime(prepared)
    if graphical:
        install_graphical_agent(agent_archive_sha)
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
    try:
        pwd.getpwuid(4003)
    except KeyError:
        run(['/usr/sbin/useradd', '--uid', '4003', '--user-group', '--create-home',
             '--shell', '/usr/sbin/nologin', '--groups', 'sudo', 'rdreceiver4003'])
    else:
        raise RuntimeError('fixture administrator UID already exists')
    try:
        receiver.run(['/usr/sbin/chpasswd'], input=f'rdreceiver4003:{receiver.ADMIN_PASSWORD}\n')
        scenario_function = (concurrent_stop_scenario if concurrent_stop else admin_failure_scenario if admin_failure
                             else uncertain_scenario if uncertain else scenario)
        if graphical:
            receiver.installed_desktop(lambda actor, session, pam: admin_failure_scenario(
                receiver, probe_sha, graphical=(actor, session, pam)), settings=True, session_controller=True)
        else:
            receiver.installed_desktop(lambda: scenario_function(receiver, probe_sha), settings=True)
    finally:
        run(['/usr/sbin/userdel', 'rdreceiver4003'])
    for name, record in manifest['files'].items():
        if name.startswith('bundle/') and digest(bundle / name[len('bundle/'):]) != record['sha256']:
            raise RuntimeError('installed application changed during execution')
    if digest(receiver.PROBE) != probe_sha:
        raise RuntimeError('CPace probe changed during the installed workflow')
    if concurrent_stop:
        print(f'LINUX_INSTALLED_SETTINGS_CONCURRENT_STOP_NATIVE=pass cases=3 app_commit={commit} manifest_sha256={manifest_sha} '
              'clients=actual-root-cli service=actual queued=2 shutdown=systemctl barrier=ptrace '
              'stop_deadline=extended outcomes=Applied post_stop=refused restart=retained '
              'cpace=3 stale_refusals=1 cleanup=joined', flush=True)
    elif graphical:
        print(f'LINUX_INSTALLED_SETTINGS_GRAPHICAL_NATIVE=pass cases=5 app_commit={commit} manifest_sha256={manifest_sha} '
              'ui=actual service=actual cancellation=gtk-selection-and-password authorization=polkit-pam '
              'helper=reaped protected=preserved profile=unchanged retry=same-gui-and-agent '
              'concurrent=gui-and-cli cpace=5 stale_refusals=1 cleanup=joined', flush=True)
    elif admin_failure:
        print(f'LINUX_INSTALLED_SETTINGS_ADMIN_FAILURE_NATIVE=pass cases=3 app_commit={commit} manifest_sha256={manifest_sha} '
              'ui=actual service=actual denial=incorrect-admin-password authorization=polkit-pam '
              'helper=reaped protected=preserved profile=unchanged retry=same-gui-and-agent '
              'cpace=4 stale_refusals=1 cleanup=joined', flush=True)
    elif uncertain:
        print(f'LINUX_INSTALLED_SETTINGS_UNCERTAIN_NATIVE=pass cases=3 app_commit={commit} manifest_sha256={manifest_sha} '
              'ui=actual service=actual authorization=polkit-pam child=kernel-stopped deadline=600 '
              'outcome=Uncertain durable=committed recovery=same-generation cpace=5 stale_refusals=2 '
              'restart=service cleanup=joined', flush=True)
    else:
        print(f'LINUX_INSTALLED_SETTINGS_NATIVE=pass cases=8 app_commit={commit} manifest_sha256={manifest_sha} '
              'ui=actual service=actual cancellation=before-submit denial=no-agent authorization=polkit-pam '
              'cpace=7 stale_refusals=3 restart=service-and-gui failure=service-unavailable cleanup=joined', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']:
        prepare()
    elif sys.argv[1:] == ['--prepare-graphical']:
        prepare(graphical=True)
    elif sys.argv[1:] == ['--prepare-package']:
        prepare_package()
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
    elif len(sys.argv) == 18 and sys.argv[1] in ('--run', '--run-uncertain', '--run-admin-failure', '--run-concurrent-stop', '--run-package'):
        main(sys.argv[2:], uncertain=sys.argv[1] == '--run-uncertain',
             admin_failure=sys.argv[1] == '--run-admin-failure', concurrent_stop=sys.argv[1] == '--run-concurrent-stop',
             package=sys.argv[1] == '--run-package')
    else:
        raise SystemExit('closed installed-settings arguments required')

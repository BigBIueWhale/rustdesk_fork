#!/usr/bin/env python3
"""Real Flutter password controls with the installed service, in the owned VM only."""

import ctypes
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
import select
import shutil
import signal
import stat
import subprocess
import sys
import termios
import time

MEDIA = Path('/mnt/rustdesk-verifier-inputs')
SCRIPT = MEDIA / 'repo/scripts/test-linux-installed-settings.py'
WORK = Path('/var/tmp/rustdesk-linux-service-receiver')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
BASELINE_PASSWORD = 'Installed-baseline-2026!'
GUI_PASSWORD = 'InstalledGui2026'
STAGES = ('open', 'fill', 'cancel', 'reopen', 'submit', 'denied', 'reopen', 'submit', 'denied',
          'reopen', 'fill', 'submit-approved', 'applied', 'reopen', 'submit', 'denied')


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
              Path('/xvfb-root/usr/bin/xkbcomp'), Path('/usr/bin/dbus-daemon'), Path('/usr/bin/fc-match'),
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
    for name, destination in (('xkb', WORK / 'xkb'),
                              ('fonts', Path('/usr/share/fonts/truetype/dejavu')),
                              ('fontconfig', Path('/etc/fonts'))):
        for path in (prepared / name).rglob('*'):
            if path.is_file():
                install(path, destination / path.relative_to(prepared / name))
    install(prepared / 'fc-match', WORK / 'fc-match', 0o755)
    install(prepared / 'driver-first', WORK / 'settings-driver', 0o755)
    install(prepared / '50_mesa.json', '/usr/share/glvnd/egl_vendor.d/50_mesa.json')
    # Xvfb starts with the receiver's closed environment, before the GUI environment.
    install(prepared / 'libraries/swrast_dri.so', '/usr/lib/x86_64-linux-gnu/dri/swrast_dri.so')
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


def session(restarted=False):
    guard(4001)
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot retain GUI descendants')
    environment = {**ENV, 'HOME': '/home/rdreceiver4001', 'USER': 'rdreceiver4001',
                   'DISPLAY': ':77', 'XAUTHORITY': '/run/user/4001/gdm/Xauthority',
                   'XDG_RUNTIME_DIR': '/run/user/4001', 'XDG_SESSION_TYPE': 'x11',
                   'XDG_DATA_DIRS': '/usr/local/share:/usr/share', 'GDK_BACKEND': 'x11',
                   'LIBGL_ALWAYS_SOFTWARE': '1', 'LIBGL_DRIVERS_PATH': '/usr/local/lib/rustdesk-settings-fixture'}
    bus = app = None
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
        app = subprocess.Popen(['/usr/share/rustdesk/rustdesk'], env=environment,
                               stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
        stages = ('open', 'cancel') if restarted else STAGES
        for stage in stages:
            output = run([str(WORK / 'settings-driver'), str(app.pid), stage], env=environment,
                         timeout=40, output_limit=524288)
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


def owned_log(directory, pid, uid):
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
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(131073)
        after = os.fstat(stream.fileno())
    if (len(data) > 131072 or (before.st_dev, before.st_ino) not in held
            or before.st_size != after.st_size or len(data) != after.st_size):
        raise RuntimeError('service log exceeded its bound or changed during observation')
    return path, data


def service_refusals(record, requester, start, count):
    path, data = owned_log(Path('/root/.local/share/logs/RustDesk/service'), record['supervisor'], 0)
    messages = data.decode().splitlines()
    prefix = ('polkit denied action=com.carriez.RustDesk.set-unattended-password, '
              f'subject={requester},{start},4001, status=exit status: ')
    refusals = [line for line in messages if line.endswith(prefix + '2')]
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


def authenticate(receiver, authority, requester, record, before):
    agent, terminal_fd = authority
    terminal = bytearray()
    chosen = sent = False
    deadline = time.monotonic() + 20
    while b'AUTHENTICATION COMPLETE' not in terminal:
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
            os.write(terminal_fd, (receiver.ADMIN_PASSWORD + '\n').encode())
            sent = True
    if (not sent or terminal.count(b'AUTHENTICATION COMPLETE') != 1
            or receiver.ADMIN_PASSWORD.encode() in terminal):
        raise RuntimeError('GUI administrator proof is incomplete or exposed its password')
    print('LINUX_INSTALLED_SETTINGS_ADMIN=' + json.dumps(
        {'requester_pid': requester[0], 'requester_start': requester[1], 'requester_uid': 4001,
         'administrator_uid': 4003, 'agent_pid': agent.pid, 'terminal': terminal.decode()}, sort_keys=True), flush=True)


def credential_network(receiver, record, probe_sha, phase):
    receiver.keyed(GUI_PASSWORD, phase + '-new', record, probe_sha)
    directory = Path('/home/rdreceiver4001/.local/share/logs/RustDesk/server')
    path, baseline = owned_log(directory, record['pid'], 4001)
    before = receiver.credential()
    listener = receiver.direct_listener(record)
    result = receiver.run([*ordinary(4002), str(receiver.PROBE), '127.0.0.1:21118', '--password-stdin', 'fail'],
                          input=BASELINE_PASSWORD + '\n', timeout=45)
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
    receiver.keyed(GUI_PASSWORD, phase + '-recovery', record, probe_sha)
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


def scenario(receiver, probe_sha):
    unit = Path('/etc/systemd/system/rustdesk.service')
    if unit.exists():
        raise RuntimeError('installed settings require absent initial service state')
    install(MEDIA / 'repo/res/rustdesk.service', unit)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    process = None
    authorization = ExitStack()
    network_before = network_state()
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
                authorization.close()
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
        if receiver.credential() != committed:
            raise RuntimeError('GUI credential did not persist through service restart')
        credential_network(receiver, restarted, probe_sha, 'gui-restarted')
        for pipe in (process.stdin, process.stdout):
            pipe.close()
        process = subprocess.Popen([*ordinary(4001), '/usr/bin/python3', '-B', '-I', '-S', str(SCRIPT), '--session-restart'],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for stage in ('open', 'cancel'):
            if not select.select([process.stdout], [], [], 45)[0]:
                raise RuntimeError('restarted GUI stage timed out')
            event = json.loads(process.stdout.readline(4096))
            if (event.get('stage') != stage or event.get('pid') == requester[0]
                    or receiver.credential() != committed or receiver.child_record() != restarted):
                raise RuntimeError('restarted GUI or protected credential differs')
            print('LINUX_INSTALLED_SETTINGS_RESTART=' + json.dumps({**event, **restarted,
                  'gui_pid': event['pid'], 'credential': 'preserved'}, sort_keys=True), flush=True)
            process.stdin.write(b'continue\n')
            process.stdin.flush()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('restarted GUI did not retire')
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


def main(arguments):
    guard()
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
        receiver.installed_desktop(lambda: scenario(receiver, probe_sha), settings=True)
    finally:
        run(['/usr/sbin/userdel', 'rdreceiver4003'])
    for name, record in manifest['files'].items():
        if name.startswith('bundle/') and digest(bundle / name[len('bundle/'):]) != record['sha256']:
            raise RuntimeError('installed application changed during execution')
    if digest(receiver.PROBE) != probe_sha:
        raise RuntimeError('CPace probe changed during the installed workflow')
    print(f'LINUX_INSTALLED_SETTINGS_NATIVE=pass cases=6 app_commit={commit} manifest_sha256={manifest_sha} '
          'ui=actual service=actual cancellation=before-submit denial=no-agent authorization=polkit-pam '
          'cpace=5 stale_refusals=2 restart=service-and-gui cleanup=joined', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']:
        prepare()
    elif sys.argv[1:] == ['--session']:
        session()
    elif sys.argv[1:] == ['--session-restart']:
        session(restarted=True)
    elif len(sys.argv) == 18 and sys.argv[1] == '--run':
        main(sys.argv[2:])
    else:
        raise SystemExit('closed installed-settings arguments required')

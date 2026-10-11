#!/usr/bin/env python3
"""Compile the locked camera component in guest Docker and observe native handles."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import stat
import subprocess
import tarfile
import time


MEDIA = Path('/mnt/rustdesk-media')
STATE = Path('/var/tmp/rustdesk-verifier-authority')
AUTHORITY = Path('/run/rustdesk-verifier-vm')
SOCKET = AUTHORITY / 'docker.sock'
CONFIG = AUTHORITY / 'docker-config'
WORK = Path('/var/lib/rustdesk-media-tools')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
CLIENT_ENV = dict(ENV, DOCKER_HOST='unix://' + str(SOCKET), DOCKER_CONFIG=str(CONFIG))
NATIVE = WORK / 'native/camera-probe'
NOFILE = 524544


def require(condition, message):
    if not condition:
        raise ValueError(message)


def record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and 0 < info.st_size <= 1024 * 1024 * 1024, 'component file authority differs')
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'bytes': info.st_size, 'sha256': digest}


def root_command(argv, timeout=30):
    return subprocess.run(argv, env=ENV, check=True, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def nonroot(argv):
    return ['/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--clear-groups',
            '--no-new-privs', *argv]


def preflight():
    output = subprocess.check_output(nonroot([
        '/bin/bash', str(MEDIA / 'scripts/verify-vm-entry-preflight.sh')]),
        env=CLIENT_ENV, timeout=10)
    require(output == b'VERIFIER_VM_ENTRY_AUTHORITY=pass uid=1000 gid=1000 network=none '
            b'docker=27.5.1 channel=guest-unix peer=pid-bound config=root-readonly daemon=vm-root\n',
            'guest compiler entry authority differs')


def operation(argv, timeout=30):
    preflight()
    try:
        result = subprocess.run(nonroot(argv), env=CLIENT_ENV, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        preflight()
    require(len(result.stdout) <= 1048576 and len(result.stderr) <= 1048576,
            'compiler operation output exceeds bound')
    if result.returncode:
        print(result.stdout.decode(errors='replace'), flush=True)
        print(result.stderr.decode(errors='replace'), flush=True)
        raise ValueError('guest compiler operation failed: ' + str(result.returncode))
    if result.stderr:
        print(result.stderr.decode(errors='replace'), flush=True)
    return result


def docker(*args, timeout=30):
    return operation(['/usr/bin/docker', '--host', 'unix://' + str(SOCKET),
                      '--config', str(CONFIG), *args], timeout).stdout


def network():
    result = []
    for name in ('tcp', 'tcp6', 'udp', 'udp6'):
        for line in Path('/proc/net', name).read_text().splitlines()[1:]:
            fields = line.split()
            result.append([name, fields[1], fields[3]])
    return sorted(result)


def start_daemon(pins):
    require(not STATE.exists() and not AUTHORITY.exists() and not Path('/usr/bin/docker').exists(),
            'guest compiler authority destination occupied')
    resource.setrlimit(resource.RLIMIT_NOFILE, (NOFILE, NOFILE))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
            'guest compiler AppArmor is unavailable')
    STATE.mkdir(mode=0o755)
    AUTHORITY.mkdir(mode=0o755)
    os.chmod(STATE, 0o755)
    os.chmod(AUTHORITY, 0o755)
    binary = STATE / 'bin'
    binary.mkdir(mode=0o755)
    CONFIG.mkdir(mode=0o755)
    for name in ('data', 'exec'):
        (WORK / name).mkdir(mode=0o700)
    bundle = MEDIA / 'docker-27.5.1.tgz'
    require(record(bundle) == {'bytes': int(pins['SIZE_VERIFIER_VM_DOCKER_STATIC']),
                              'sha256': pins['SHA256_VERIFIER_VM_DOCKER_STATIC']},
            'guest Docker bundle pin differs')
    expected = ['docker/', 'docker/runc', 'docker/containerd', 'docker/docker-init',
                'docker/dockerd', 'docker/containerd-shim-runc-v2', 'docker/docker-proxy',
                'docker/docker', 'docker/ctr']
    with tarfile.open(bundle, 'r:gz') as archive:
        members = archive.getmembers()
        require([m.name.rstrip('/') + ('/' if m.isdir() else '') for m in members] == expected,
                'guest Docker bundle inventory differs')
        for member in members[1:]:
            require(member.isfile() and 0 < member.size <= 128 * 1024 * 1024,
                    'guest Docker executable type/bounds differ')
            destination = Path('/usr/bin/docker') if member.name == 'docker/docker' else binary / Path(member.name).name
            with archive.extractfile(member) as source, destination.open('xb') as output:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fchmod(output.fileno(), 0o555)
                os.fsync(output.fileno())
    os.chmod(binary, 0o555)
    (CONFIG / 'config.json').write_bytes(b'{}\n')
    os.chmod(CONFIG / 'config.json', 0o444)
    os.chmod(CONFIG, 0o555)
    (AUTHORITY / 'authority').write_text('rustdesk-verifier-vm-authority-v1 docker=27.5.1\n')
    os.chmod(AUTHORITY / 'authority', 0o444)
    log = (WORK / 'daemon.log').open('xb', buffering=0)
    daemon = subprocess.Popen([
        str(binary / 'dockerd'), '--host', 'unix://' + str(SOCKET),
        '--pidfile', str(AUTHORITY / 'docker.pid'), '--data-root', str(WORK / 'data'),
        '--exec-root', str(WORK / 'exec'), '--bridge', 'none', '--iptables=false',
        '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
        '--userland-proxy=false', '--group', 'root', '--log-level', 'error'],
        env=dict(ENV, PATH=str(binary) + ':' + ENV['PATH']),
        stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    log.close()
    try:
        deadline = time.monotonic() + 20
        while True:
            require(daemon.poll() is None and time.monotonic() < deadline,
                    'guest compiler daemon did not become ready')
            if SOCKET.exists() and (AUTHORITY / 'docker.pid').exists():
                ready = subprocess.run([
                    '/usr/bin/docker', '--host', 'unix://' + str(SOCKET), '--config', str(CONFIG),
                    'version', '--format', '{{.Server.Version}}'], env=CLIENT_ENV,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                if ready.returncode == 0 and ready.stdout == b'27.5.1\n':
                    break
            time.sleep(0.05)
        require(stat.S_ISSOCK(SOCKET.lstat().st_mode), 'guest Docker endpoint differs')
        os.chown(SOCKET, 0, 1000)
        os.chmod(SOCKET, 0o660)
        pidfile = AUTHORITY / 'docker.pid'
        require(pidfile.read_text().strip() == str(daemon.pid), 'guest Docker PID differs')
        os.chmod(pidfile, 0o444)
        proc = Path('/proc', str(daemon.pid))
        raw = (proc / 'stat').read_text()
        start = raw[raw.rfind(')') + 2:].split()[19]
        require((proc / 'exe').resolve() == binary / 'dockerd' and start.isdigit(),
                'guest Docker generation differs')
        identity = AUTHORITY / 'docker.identity'
        identity.write_text('pid=' + str(daemon.pid) + ' start=' + start
                            + ' daemon_sha256=' + record(binary / 'dockerd')['sha256']
                            + ' client_sha256=' + record(Path('/usr/bin/docker'))['sha256'] + '\n')
        os.chmod(identity, 0o444)
        preflight()
        return daemon
    except BaseException:
        if daemon.poll() is None:
            daemon.terminate()
        daemon.wait(timeout=30)
        raise


def load_image(pins):
    args = ['/usr/bin/python3', '-I', '-S', str(MEDIA / 'scripts/offline-image-provenance.py'),
            'verify-load', '--role', 'devcheck', '--archive', str(MEDIA / 'devcheck.docker.tar.gz'),
            '--base', 'rust:1.75-slim@' + pins['DEV_CHECK_BASE_IMAGE_ID']]
    for option, key in (
        ('archive-sha', 'SHA256_DEV_CHECK_IMAGE_ARCHIVE'), ('archive-size', 'SIZE_DEV_CHECK_IMAGE_ARCHIVE'),
        ('expected-id', 'DEV_CHECK_IMAGE_ID'), ('config-id', 'DEV_CHECK_IMAGE_CONFIG_ID'),
        ('manifest-id', 'DEV_CHECK_IMAGE_MANIFEST_ID'), ('dockerfile-sha', 'SHA256_DEV_CHECK_DOCKERFILE'),
        ('dpkg-sha', 'SHA256_DEV_CHECK_DPKG_MANIFEST'), ('cargo-sha', 'SHA256_DEV_CHECK_CARGO'),
        ('rustc-sha', 'SHA256_DEV_CHECK_RUSTC'), ('debian-snapshot', 'DEV_CHECK_DEBIAN_SNAPSHOT'),
        ('security-snapshot', 'DEV_CHECK_SECURITY_SNAPSHOT'), ('source-date-epoch', 'DEV_CHECK_SOURCE_DATE_EPOCH')):
        args += ['--' + option, pins[key]]
    require(operation(args, timeout=120).stdout.decode().strip()
            == 'loaded and verified devcheck ' + pins['DEV_CHECK_IMAGE_ID'],
            'guest compiler image provenance differs')


def compile_probe(pins):
    validator = ['/usr/bin/python3', '-I', '-S', str(MEDIA / 'scripts/online-input-provenance.py'),
                 'verify-subtree', '--tree', str(MEDIA / 'cargo-vendor'),
                 '--expected', pins['SHA256_CARGO_VENDOR_CLOSURE_V1']]
    expected = 'verified subtree ' + pins['SHA256_CARGO_VENDOR_CLOSURE_V1']
    require(operation(validator, timeout=60).stdout.decode().strip() == expected, 'Cargo vendor closure differs')
    build = WORK / 'build'
    build.mkdir(mode=0o700)
    os.chown(build, 1000, 1000)
    script = ('set -euo pipefail\n'
              'mkdir /tmp/home /tmp/cargo-home\n'
              'cp /config.toml /tmp/cargo-home/config.toml\n'
              'test "$(cargo --version)" = "cargo 1.75.0 (1d8b05cdd 2023-11-20)"\n'
              'test "$(rustc --version)" = "rustc 1.75.0 (82e1608df 2023-12-21)"\n'
              'cargo build --offline --locked --release --jobs 2 --target-dir /work/target\n')
    argv = ['create', '--pull=never', '--network=none', '--user=1000:1000',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--security-opt=apparmor=docker-default',
            '--pids-limit=128', '--memory=1073741824', '--memory-swap=1073741824', '--cpus=2',
            '--ipc=private', '--cgroupns=private', '--ulimit=nofile=4096:4096',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=268435456,mode=1777', '--workdir=/probe',
            '--env=HOME=/tmp/home', '--env=CARGO_HOME=/tmp/cargo-home', '--env=CARGO_NET_OFFLINE=true',
            '--env=CARGO_INCREMENTAL=0', '--env=SOURCE_DATE_EPOCH=' + pins['SOURCE_DATE_EPOCH_PIN'],
            '--env=PATH=/usr/local/cargo/bin:/usr/bin:/bin']
    mounts = [(MEDIA / 'probe', '/probe', True), (MEDIA / 'cargo-vendor', '/online/cargo-vendor', True),
              (MEDIA / 'cargo-vendor-config.toml', '/config.toml', True), (build, '/work', False)]
    for source, target, readonly in mounts:
        argv += ['--mount', 'type=bind,source=' + str(source) + ',target=' + target
                 + ',bind-recursive=disabled' + (',readonly' if readonly else '')]
    argv += ['--entrypoint=/bin/bash', pins['DEV_CHECK_IMAGE_CONFIG_ID'], '--noprofile', '--norc', '-c', script]
    identifier = docker(*argv).decode().strip()
    require(re.fullmatch('[0-9a-f]{64}', identifier), 'compiler container identity differs')
    try:
        configuration = json.loads(docker('inspect', identifier))[0]
        host = configuration['HostConfig']
        require(configuration['Image'] == pins['DEV_CHECK_IMAGE_CONFIG_ID']
                and configuration['Config']['User'] == '1000:1000'
                and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none'
                and not host['Privileged'] and not host['Devices'] and not host['PortBindings']
                and not host['PidMode'] and host['IpcMode'] == 'private'
                and host['CapDrop'] == ['ALL'] and not host['CapAdd']
                and 'no-new-privileges' in host['SecurityOpt']
                and host['PidsLimit'] == 128 and host['Memory'] == 1073741824
                and host['MemorySwap'] == 1073741824 and host['NanoCpus'] == 2000000000
                and host['CgroupnsMode'] == 'private'
                and configuration['AppArmorProfile'] == 'docker-default', 'compiler container authority differs')
        require(host['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,size=268435456,mode=1777'},
                'compiler temporary filesystem differs')
        require(all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp')
                    for m in configuration['Mounts']), 'compiler has an undeclared mount')
        actual = sorted((m['Source'], m['Destination'], m['RW']) for m in configuration['Mounts']
                        if m['Type'] == 'bind')
        require(actual == sorted((str(s), t, not ro) for s, t, ro in mounts), 'compiler mounts differ')
        compiled = operation(['/usr/bin/docker', '--host', 'unix://' + str(SOCKET),
                              '--config', str(CONFIG), 'start', '--attach', identifier], timeout=150)
        print(compiled.stdout.decode(errors='replace'), flush=True)
        require(b'CAMERA_NATIVE_COMPILE_NETWORK_CANARY=refused' in compiled.stderr,
                'native compiler network canary did not execute')
        final = json.loads(docker('inspect', identifier))[0]
        require(not final['State']['Running'] and final['State']['ExitCode'] == 0,
                'compiler container did not terminate successfully')
        source = build / 'target/release/rustdesk-camera-native-probe'
        artifact = record(source)
        require(source.read_bytes()[:4] == b'\x7fELF', 'native compiler did not produce an ELF')
        native_root = WORK / 'native'
        native_root.mkdir(mode=0o755)
        os.chmod(native_root, 0o755)
        with source.open('rb') as input_file, NATIVE.open('xb') as output_file:
            shutil.copyfileobj(input_file, output_file)
            output_file.flush()
            os.fchmod(output_file.fileno(), 0o555)
            os.fsync(output_file.fileno())
        require(record(NATIVE) == artifact, 'sealed native artifact differs')
        require(operation(validator, timeout=60).stdout.decode().strip() == expected, 'Cargo vendor changed after compile')
        return artifact
    finally:
        state = json.loads(docker('inspect', identifier))[0]['State']
        if state['Running']:
            docker('stop', '--time=5', identifier)
        docker('rm', identifier)


def native_argv(scenario):
    return ['/usr/bin/setpriv', '--reuid=4000', '--regid=4000', '--clear-groups',
            '--no-new-privs', str(NATIVE), scenario]


def move_node(source, destination):
    fd = os.open('/dev', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.stat(source, dir_fd=fd, follow_symlinks=False).st_mode),
                'owned fixture node type differs')
        result = ctypes.CDLL(None, use_errno=True).renameat2(fd, source.encode(), fd, destination.encode(), 1)
        require(result == 0, 'owned fixture node no-clobber rename failed')
    finally:
        os.close(fd)


def native_scenarios(artifact):
    results = []
    for prefix in ([], ['/usr/bin/setpriv', '--reuid=4001', '--regid=4001', '--clear-groups']):
        refused = subprocess.run(prefix + [str(NATIVE), '--capture'], env=ENV,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        require(refused.returncode == 1 and not refused.stdout
                and b'capture requires the exact unprivileged fixture principal' in refused.stderr,
                'native root/foreign principal refusal differs')
    for count in (1, 2):
        require(not list(Path('/dev').glob('video*')), 'native scenario starts with a camera')
        root_command(['/usr/sbin/modprobe', 'vivid', 'n_devs=' + str(count), 'node_types=1',
                      'vid_cap_nr=' + ('2' if count == 1 else '2,3'), 'num_inputs=1', 'input_types=0'])
        try:
            root_command(['/usr/bin/udevadm', 'settle', '--timeout=10'])
            expected = ['video2'] if count == 1 else ['video2', 'video3']
            require(sorted(p.name for p in Path('/dev').glob('video*')) == expected, 'native node inventory differs')
            for node in expected:
                p = Path('/dev', node)
                require(stat.S_ISCHR(p.lstat().st_mode) and os.major(p.lstat().st_rdev) == 81,
                        'guest fixture did not produce a native V4L2 node')
                os.chown(p, 4000, 4000)
                os.chmod(p, 0o600)
            require(record(NATIVE) == artifact, 'native executable changed')
            scenario = '--capture' if count == 1 else '--two-retained-baseline'
            run = subprocess.run(native_argv(scenario), env=ENV, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=10)
            require(len(run.stdout) <= 16384 and len(run.stderr) <= 16384, 'native result exceeds bound')
            if count == 1:
                require(run.returncode == 0 and not run.stderr, 'nokhwa native capture failed: ' + run.stderr.decode(errors='replace'))
                results.append(json.loads(run.stdout))
            else:
                require(run.returncode == -6 and b'Device list should not contain duplicate indexes' in run.stderr
                        and b'left: 0' in run.stderr and b'right: 2' in run.stderr,
                        'pinned two-retained-device failure differs: ' + run.stderr.decode(errors='replace'))
                result = json.loads(run.stdout)
                require(result['next_operation'] == 'open-native-three', 'second native open was not reached')
                result.update({'signal': 'SIGABRT', 'stderr': run.stderr.decode()})
                results.append(result)
                results.append(reuse_scenario())
        finally:
            root_command(['/usr/sbin/modprobe', '-r', 'vivid'])
            root_command(['/usr/bin/udevadm', 'settle', '--timeout=10'])
        require(not list(Path('/dev').glob('video*')) and not Path('/sys/module/vivid').exists(),
                'native fixture module/node retirement incomplete')
    require(record(NATIVE) == artifact, 'native executable changed after scenarios')
    return results


def reuse_scenario():
    process = subprocess.Popen(native_argv('--reuse-baseline'), env=ENV,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    moved_original = moved_replacement = False
    identities = {name: (Path('/dev', name).lstat().st_ino, Path('/dev', name).lstat().st_rdev)
                  for name in ('video2', 'video3')}
    try:
        deadline = time.monotonic() + 10
        first_line = bytearray()
        while not first_line.endswith(b'\n'):
            remaining = deadline - time.monotonic()
            require(remaining > 0 and len(first_line) < 16384, 'native reuse readiness deadline/bound exceeded')
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            require(ready, 'native reuse did not become ready')
            byte = os.read(process.stdout.fileno(), 1)
            require(byte, 'native reuse exited before readiness')
            first_line.extend(byte)
        first = json.loads(first_line)
        require(first['scenario'] == 'reuse-ready' and first['original_rdev'] == identities['video2'][1]
                and first['replacement_rdev'] == identities['video3'][1], 'native reuse identities differ')
        move_node('video2', 'rustdesk-retained-video2')
        moved_original = True
        move_node('video3', 'video2')
        moved_replacement = True
        output, error = process.communicate(b'reuse\n', timeout=10)
        require(process.returncode == 0 and not error and len(output) <= 16384,
                'native reuse failed: ' + error.decode(errors='replace'))
        result = json.loads(output)
        require(result['scenario'] == 'reuse-baseline' and result['retained_rdevs'] == [identities['video2'][1]]
                and result['current_node_rdev'] == identities['video3'][1], 'native cached-handle observation differs')
        return {'readiness': first, 'result': result, 'scope': 'guest-native-node-rename; physical-hotplug-unexecuted'}
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        if moved_replacement:
            require((Path('/dev/video2').lstat().st_ino, Path('/dev/video2').lstat().st_rdev) == identities['video3'],
                    'replacement node identity changed')
            move_node('video2', 'video3')
        if moved_original:
            p = Path('/dev/rustdesk-retained-video2')
            require((p.lstat().st_ino, p.lstat().st_rdev) == identities['video2'], 'retained node identity changed')
            move_node('rustdesk-retained-video2', 'video2')


def verify(pins):
    require(os.getuid() == 0 and os.getgid() == 0 and os.uname().release == '6.1.0-50-amd64'
            and 'rustdesk.verifier_vm=1' in Path('/proc/cmdline').read_text().split()
            and sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'],
            'native compiler requires the exact no-NIC media guest')
    require(root_command(['/usr/sbin/blockdev', '--getsize64', '/dev/disk/by-id/virtio-rd-media-tools']).strip()
            == b'17179869184', 'guest compiler scratch disk size differs')
    with Path('/dev/disk/by-id/virtio-rd-media-tools').open('rb') as blank:
        require(blank.read(8192) == bytes(8192), 'guest compiler scratch disk is not blank')
    WORK.mkdir(mode=0o755)
    root_command(['/usr/sbin/mkfs.ext4', '-q', '/dev/disk/by-id/virtio-rd-media-tools'], timeout=30)
    root_command(['/usr/bin/mount', '-o', 'nodev,nosuid', '/dev/disk/by-id/virtio-rd-media-tools', str(WORK)])
    os.chmod(WORK, 0o755)
    baseline = network()
    daemon = start_daemon(pins)
    try:
        require(network() == baseline, 'guest Docker added a network endpoint')
        print('media nokhwa: authenticated guest compiler image admission', flush=True)
        load_image(pins)
        print('media nokhwa: locked offline component compile', flush=True)
        artifact = compile_probe(pins)
        require(docker('ps', '-aq') == b'', 'compiler container remains')
    finally:
        if daemon.poll() is None:
            daemon.terminate()
        require(daemon.wait(timeout=30) in (0, -15), 'guest Docker daemon exit differs')
        require(not SOCKET.exists() and network() == baseline, 'guest Docker retirement differs')
        deadline = time.monotonic() + 10
        while True:
            owned = []
            for proc in Path('/proc').glob('[0-9]*'):
                try:
                    executable = (proc / 'exe').resolve(strict=True)
                except FileNotFoundError:
                    continue
                if executable.parent == STATE / 'bin':
                    owned.append(proc.name)
            if not owned:
                break
            require(time.monotonic() < deadline, 'owned guest Docker descendants remain: ' + str(owned))
            time.sleep(0.05)
    print('media nokhwa: native capture, retained-device failure and node reuse', flush=True)
    results = native_scenarios(artifact)
    return {'artifact': artifact, 'scenarios': results, 'root_foreign_probe_refused': True,
            'compiler_container_retired': True, 'daemon_joined': True,
            'compile_network_canary_refused': True,
            'compiler_image': pins['DEV_CHECK_IMAGE_CONFIG_ID'],
            'cargo_vendor_sha256': pins['SHA256_CARGO_VENDOR_CLOSURE_V1'],
            'supplier_executed': True, 'rustdesk_product_executed': False}

#!/usr/bin/env python3
"""Provision and exercise the fixed guest-only nonzero V4L2 fixture."""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / '.harness-state/verifier-vm'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
CONTROLS = [Path('/tmp/ralph_loop_prompt.md'), Path('/tmp/privilege_securiry_deep_audit.md'),
            Path('/home/user/.codex/attachments/7d861720-c713-4c42-9cb6-7498de976f37/pasted-text-1.txt')]
KEYS = ('DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD', 'SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE',
        'SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE', 'SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE',
        'VERIFIER_VM_KERNEL_RELEASE', 'VERIFIER_VM_ROOT_FILESYSTEM_UUID',
        'SIZE_VERIFIER_VM_KERNEL', 'SHA256_VERIFIER_VM_KERNEL',
        'SIZE_VERIFIER_VM_INITRD', 'SHA256_VERIFIER_VM_INITRD',
        'VERIFIER_MEDIA_KERNEL_RELEASE', 'VERIFIER_MEDIA_KERNEL_PACKAGE_VERSION',
        'SIZE_VERIFIER_MEDIA_KERNEL_PACKAGE', 'SHA256_VERIFIER_MEDIA_KERNEL_PACKAGE',
        'SIZE_VERIFIER_MEDIA_KERNEL', 'SHA256_VERIFIER_MEDIA_KERNEL',
        'SHA256_VERIFIER_MEDIA_KERNEL_CONFIG', 'SOURCE_DATE_EPOCH_PIN')
TOOLS = ('/usr/bin/git', '/usr/bin/qemu-img', '/usr/bin/qemu-system-x86_64',
         '/usr/bin/xorriso', '/usr/bin/ss', '/usr/bin/dd', '/usr/sbin/debugfs', '/usr/sbin/sgdisk')
STREAM_LIMIT = 16 * 1024 * 1024
CANCELLED = False


def cancel(signum, frame):
    global CANCELLED
    CANCELLED = True


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(argv, timeout=120, fds=()):
    require(not CANCELLED, 'media transaction cancelled')
    result = subprocess.run(argv, cwd=REPO, env=ENV, pass_fds=fds, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(len(result.stdout) <= 1048576 and len(result.stderr) <= 1048576,
            'orchestration command output exceeds bound')
    require(not CANCELLED, 'media transaction cancelled')
    return result.stdout


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def observe(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'frozen source/input is not a regular file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        require(metadata(info) == metadata(os.fstat(source.fileno())), 'frozen file identity changed')
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
        require(metadata(info) == metadata(os.fstat(source.fileno())), 'frozen file changed while read')
    require(metadata(info) == metadata(path.lstat()), 'frozen path identity changed')
    return {'metadata': metadata(info), 'sha256': digest}


def listeners():
    result = []
    for line in command(['/usr/bin/ss', '-H', '-lntu']).decode('ascii').splitlines():
        fields = line.split()
        require(len(fields) == 6 and fields[0] in ('tcp', 'udp'), 'listener inventory is ambiguous')
        result.append(fields[0] + ' ' + fields[4])
    return sorted(set(result))


def directory(path, mode):
    require(path.is_absolute() and path.resolve() == path, 'private directory ancestry is ambiguous')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (os.getuid(), os.getgid(), mode), 'private directory authority differs: ' + str(path))
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def admit(path, size, digest):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (info.st_uid, info.st_gid, info.st_size) == (os.getuid(), os.getgid(), size)
            and stat.S_IMODE(info.st_mode) in (0o400, 0o444), 'immutable input authority differs')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(os.dup(fd), 'rb') as source:
        require(metadata(info) == metadata(os.fstat(fd)), 'immutable input identity changed')
        require(hashlib.file_digest(source, 'sha256').hexdigest() == digest, 'immutable input pin differs')
    require(metadata(info) == metadata(path.lstat()) == metadata(os.fstat(fd)),
            'immutable input changed during admission')
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def exclusive(path, data, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())


class Transaction:
    def __init__(self, parent, baseline):
        self.parent = parent
        self.name = 'run.' + secrets.token_hex(5)
        os.mkdir(self.name, 0o700, dir_fd=parent)
        self.path = ROOT / self.name
        self.fd = directory(self.path, 0o700)
        self.identity = metadata(os.fstat(self.fd))[:2]
        self.baseline = baseline
        self.disposable = {}

    def remember(self, name):
        info = (self.path / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid) == (os.getuid(), os.getgid()), 'scratch authority differs')
        self.disposable[name] = metadata(info)[:2]

    def safe_listeners(self):
        require(metadata(ROOT.lstat())[:2] == metadata(os.fstat(self.parent))[:2]
                and metadata(self.path.lstat())[:2] == self.identity
                == metadata(os.fstat(self.fd))[:2], 'retained run/root identity changed')
        current = listeners()
        require(not set(current) - set(self.baseline), 'host listener endpoint added')
        return current

    def boot(self, phase, base, overlay, kernel, initrd, payload, pins):
        seed = self.path / (phase + '-seed')
        seed.mkdir(mode=0o700)
        user_data = ('#!/bin/sh\nset -eu\n'
                     'finish() { status=$?; trap - EXIT; echo MEDIA_CLOUD_EXIT=$status; '
                     'sync; systemctl poweroff --no-block || poweroff -f; exit "$status"; }\n'
                     'trap finish EXIT\n'
                     'mkdir -p /mnt/rustdesk-media\n'
                     'mount -L RD_MEDIA -o ro,nodev,nosuid,noexec /mnt/rustdesk-media\n'
                     '/usr/bin/python3 -I -S /mnt/rustdesk-media/guest.py --' + phase + '\n')
        exclusive(seed / 'user-data', user_data.encode())
        exclusive(seed / 'meta-data', ('instance-id: media-' + self.name + '-' + phase
                                      + '\nlocal-hostname: rustdesk-media\n').encode())
        exclusive(seed / 'network-config', b'version: 2\nethernets: {}\n')
        seed_iso = self.path / (phase + '-seed.iso')
        command(['/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-volid', 'CIDATA', '-joliet',
                 '-rock', '-output', str(seed_iso), str(seed)])
        os.chmod(seed_iso, 0o400)
        self.remember(seed_iso.name)
        seed_fd = os.open(seed_iso, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        serial = self.path / 'serial.sock'
        argv = ['/usr/bin/qemu-system-x86_64', '-name', 'rustdesk-media-fixture',
                '-machine', 'q35', '-accel', 'kvm', '-cpu', 'host', '-m', '2048', '-smp', '2',
                '-no-reboot', '-no-user-config', '-nodefaults', '-display', 'none',
                '-monitor', 'none', '-parallel', 'none', '-nic', 'none',
                '-kernel', '/proc/self/fd/' + str(kernel), '-initrd', '/proc/self/fd/' + str(initrd),
                '-append', 'root=UUID=' + pins['VERIFIER_VM_ROOT_FILESYSTEM_UUID']
                + ' rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.media_vm=1'
                + ' systemd.mask=systemd-networkd-wait-online.service'
                + ' systemd.mask=ssh.service systemd.mask=ssh.socket',
                '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                '-chardev', 'socket,id=serial0,path=' + str(serial) + ',server=on,wait=on',
                '-device', 'isa-serial,chardev=serial0']
        for node, driver, file_fd in (('base-file', 'file', base), ('disk-file', 'file', overlay)):
            argv += ['-blockdev', json.dumps({'driver': driver, 'node-name': node,
                      'filename': '/proc/self/fd/' + str(file_fd), 'read-only': node == 'base-file'})]
        argv += ['-blockdev', json.dumps({'driver': 'qcow2', 'node-name': 'base',
                                         'file': 'base-file', 'read-only': True}),
                 '-blockdev', json.dumps({'driver': 'qcow2', 'node-name': 'disk',
                                         'file': 'disk-file', 'backing': 'base'}),
                 '-device', 'virtio-blk-pci,drive=disk']
        for media_fd in (seed_fd, payload):
            argv += ['-drive', 'file=/proc/self/fd/' + str(media_fd)
                     + ',if=virtio,format=raw,media=cdrom,readonly=on']
        exclusive(self.path / (phase + '-command.json'), json.dumps(argv).encode() + b'\n')
        process = None
        stream = None
        socket_identity = None
        selector = selectors.DefaultSelector()
        outputs = {}
        counts = {}
        started = time.monotonic()
        try:
            for kind in ('serial', 'stderr'):
                path = self.path / (phase + '.' + kind + '.log')
                outputs[kind] = open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                             | os.O_NOFOLLOW, 0o600), 'wb', buffering=0)
                counts[kind] = 0
            process = subprocess.Popen(argv, cwd=REPO, env=ENV, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       pass_fds=(base, overlay, kernel, initrd, payload, seed_fd,
                                                 self.parent, self.fd))
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while not serial.exists():
                require(not CANCELLED and process.poll() is None and time.monotonic() - started < 10,
                        'QEMU did not create the serial endpoint')
                time.sleep(0.02)
            info = serial.lstat()
            require(stat.S_ISSOCK(info.st_mode) and (info.st_uid, info.st_gid)
                    == (os.getuid(), os.getgid()) and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                    'serial endpoint authority differs')
            socket_identity = metadata(info)[:2]
            process_stat = Path('/proc', str(process.pid), 'stat').read_text()
            suffix = process_stat[process_stat.rfind(')') + 2:].split()
            require(len(suffix) >= 20 and suffix[19].isdigit()
                    and Path('/proc', str(process.pid), 'exe').resolve()
                    == Path('/usr/bin/qemu-system-x86_64'), 'owned QEMU process identity differs')
            exclusive(self.path / (phase + '-process.json'), json.dumps({
                'pid': process.pid, 'start_time': suffix[19],
                'exe': '/usr/bin/qemu-system-x86_64'}).encode() + b'\n')
            stream = socket.socket(socket.AF_UNIX)
            stream.settimeout(5)
            stream.connect(str(serial))
            stream.setblocking(False)
            selector.register(stream, selectors.EVENT_READ, 'serial')
            next_inventory = 0
            while selector.get_map():
                require(not CANCELLED, 'media transaction cancelled')
                require(time.monotonic() - started < 240, 'guest phase exceeded 240-second deadline')
                if time.monotonic() >= next_inventory:
                    self.safe_listeners()
                    next_inventory = time.monotonic() + 1
                for key, _ in selector.select(0.1):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    kind = key.data
                    counts[kind] += len(data)
                    require(counts[kind] <= STREAM_LIMIT, 'guest output exceeded bounded channel')
                    outputs[kind].write(data)
            require(process.wait(timeout=10) == 0, 'QEMU failed')
        finally:
            # This direct child cannot be PID-reused before it is reaped. QEMU's
            # sandbox forbids spawning; no daemon, helper or detached timeout exists.
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stderr is not None:
                    while data := os.read(process.stderr.fileno(), 65536):
                        remaining = max(0, STREAM_LIMIT - counts['stderr'])
                        outputs['stderr'].write(data[:remaining])
                        counts['stderr'] += len(data)
                    process.stderr.close()
            selector.close()
            if stream is not None:
                stream.close()
            os.close(seed_fd)
            for output in outputs.values():
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o400)
                output.close()
            if serial.exists():
                current = serial.lstat()
                require(stat.S_ISSOCK(current.st_mode)
                        and metadata(current)[:2] == socket_identity
                        and (current.st_uid, current.st_gid) == (os.getuid(), os.getgid()),
                        'serial cleanup identity differs')
                serial.unlink()
            self.safe_listeners()
        raw = (self.path / (phase + '.serial.log')).read_bytes()
        records = re.findall(rb'(?:^|\n)MEDIA_GUEST_RESULT=(\{[^\r\n]+\})\r?\n', raw)
        require(len(records) == 1 and b'MEDIA_CLOUD_EXIT=0' in raw
                and b'MEDIA_GUEST_FAILURE=' not in raw, 'positive guest receipt absent or ambiguous')
        result = json.loads(records[0])
        require(result['phase'] == phase and result['nonce'] == self.name
                and result['source_commit'] == self.commit and result['interfaces'] == ['lo'],
                'guest source/phase/topology identity differs')
        print('media VM: ' + phase + ' passed in ' + str(round(time.monotonic() - started)) + 's', flush=True)
        return result

    def finish(self):
        require(metadata(self.path.lstat())[:2] == self.identity
                == metadata(os.fstat(self.fd))[:2], 'run identity changed')
        for name, identity in self.disposable.items():
            info = (self.path / name).lstat()
            require(metadata(info)[:2] == identity and stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1 and info.st_uid == os.getuid(), 'scratch cleanup identity differs')
            os.unlink(name, dir_fd=self.fd)
        os.fsync(self.fd)
        destination = 'media-v4l2-' + self.name
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.renameat2(self.parent, self.name.encode(), self.parent, destination.encode(), 1)
        require(result == 0, 'evidence no-clobber publication failed: ' + str(ctypes.get_errno()))
        os.fsync(self.parent)
        return ROOT / destination


def main():
    require(sys.argv[1:] == [], 'media harness has no argument/path/kernel/command selector')
    require(os.getuid() != 0 and os.getgid() != 0, 'host root UID/group forbidden')
    require(not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists(),
            'host container execution forbidden')
    os.umask(0o077)
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, cancel)
    require(command(['/usr/bin/git', 'branch', '--show-current']).strip() == b'master', 'master required')
    require(not command(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=normal']),
            'clean committed source required')
    commit = command(['/usr/bin/git', 'rev-parse', 'HEAD']).decode().strip()
    pins_text = (REPO / 'scripts/pins.env').read_text()
    pins = {}
    for key in KEYS:
        matches = re.findall(r'^' + key + r'="([A-Za-z0-9.+-]+)"(?:\s.*)?$', pins_text, re.M)
        require(len(matches) == 1, 'pin absent or ambiguous: ' + key)
        pins[key] = matches[0]
    require(pins['VERIFIER_MEDIA_KERNEL_RELEASE'] == '6.1.0-50-amd64'
            and pins['VERIFIER_MEDIA_KERNEL_PACKAGE_VERSION'] == '6.1.176-1', 'closed media tuple differs')
    tools = {}
    for path in map(Path, TOOLS):
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o755),
                'fixed orchestration tool authority differs')
        tools[str(path)] = observe(resolved)
    parent = directory(ROOT, 0o700)
    fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    acquisition = directory(ROOT / 'online-fetch-runs', 0o700)
    require(not any(n.startswith('run.') for n in os.listdir(parent) + os.listdir(acquisition)),
            'earlier unreconciled verifier/acquisition run remains')
    base_path = ROOT / ('debian-12-genericcloud-amd64-' + pins['DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD'] + '.qcow2')
    boot_root = ROOT / ('direct-boot-' + pins['VERIFIER_VM_KERNEL_RELEASE'])
    boot_dir = directory(boot_root, 0o500)
    candidate = REPO / 'online/candidates/verifier-media-kernel'
    candidate_dir = directory(candidate, 0o700)
    package_path = candidate / 'linux-image-6.1.0-50-amd64_6.1.176-1_amd64.deb'
    input_paths = [base_path, boot_root / 'vmlinuz', boot_root / 'initrd.img', package_path]
    fds = [admit(path, int(pins[size]), pins[digest]) for path, size, digest in zip(
        input_paths, ('SIZE_DEBIAN_SYSTEMD_SMOKE_IMAGE', 'SIZE_VERIFIER_VM_KERNEL',
                      'SIZE_VERIFIER_VM_INITRD', 'SIZE_VERIFIER_MEDIA_KERNEL_PACKAGE'),
        ('SHA256_DEBIAN_SYSTEMD_SMOKE_IMAGE', 'SHA256_VERIFIER_VM_KERNEL',
         'SHA256_VERIFIER_VM_INITRD', 'SHA256_VERIFIER_MEDIA_KERNEL_PACKAGE'))]
    base, kernel, initrd, package = fds
    with os.fdopen(os.dup(base), 'rb') as source:
        require(hashlib.file_digest(source, 'sha512').hexdigest()
                == pins['SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE'], 'publisher base SHA512 differs')
    base_info = json.loads(command(['/usr/bin/qemu-img', 'info', '--output=json',
                                   '/proc/self/fd/' + str(base)], fds=(base,)))
    require(base_info['format'] == 'qcow2' and base_info['virtual-size'] == 3221225472
            and 'backing-filename' not in base_info, 'base image topology differs')
    source_paths = [REPO / os.fsdecode(p) for p in command(['/usr/bin/git', 'ls-files', '-z']).split(b'\0') if p]
    frozen_paths = source_paths + CONTROLS + input_paths
    before = {str(p): observe(p) for p in frozen_paths}
    baseline = listeners()
    transaction = Transaction(parent, baseline)
    transaction.commit = commit
    run = transaction.path
    print('media VM: owned transaction ' + str(run) + ' source=' + commit, flush=True)
    exclusive(run / 'freeze.before.json', json.dumps(before, sort_keys=True).encode() + b'\n')
    exclusive(run / 'tools.json', json.dumps(tools, sort_keys=True).encode() + b'\n')
    exclusive(run / 'listeners.before.json', json.dumps(baseline).encode() + b'\n')
    media = run / 'media'
    media.mkdir(mode=0o700)
    guest = command(['/usr/bin/git', 'show', 'HEAD:scripts/verifier-media-guest.py'])
    exclusive(media / 'guest.py', guest)
    contract = {'source_commit': commit, 'nonce': transaction.name, 'pins': pins}
    exclusive(media / 'contract.json', json.dumps(contract, sort_keys=True).encode() + b'\n')
    # Copy only authenticated inert bytes to the read-only guest input ISO.
    os.lseek(package, 0, os.SEEK_SET)
    with os.fdopen(os.dup(package), 'rb') as source:
        exclusive(media / package_path.name, source.read(70305561))
    transaction.remember('media/' + package_path.name)
    payload_path = run / 'payload.iso'
    command(['/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-volid', 'RD_MEDIA', '-joliet',
             '-rock', '-output', str(payload_path), str(media)])
    os.chmod(payload_path, 0o400)
    transaction.remember('payload.iso')
    payload = os.open(payload_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    overlay_path = run / 'overlay.qcow2'
    command(['/usr/bin/qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b',
             '/proc/self/fd/' + str(base), str(overlay_path)], fds=(base,))
    transaction.remember('overlay.qcow2')
    overlay = os.open(overlay_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    provision = transaction.boot('provision', base, overlay, kernel, initrd, payload, pins)
    image_options = ('driver=qcow2,file.driver=file,file.filename=/proc/self/fd/' + str(overlay)
                     + ',backing.driver=qcow2,backing.file.driver=file,backing.file.filename=/proc/self/fd/' + str(base))
    raw = run / 'disk.raw'
    command(['/usr/bin/qemu-img', 'convert', '--image-opts', image_options, '-O', 'raw', str(raw)],
            fds=(base, overlay))
    transaction.remember('disk.raw')
    require(raw.stat().st_size == 3221225472, 'provisioned virtual disk size differs')
    gpt = command(['/usr/sbin/sgdisk', '-i', '1', str(raw)]).decode()
    require('First sector: 262144 ' in gpt and 'Partition size: 6027264 sectors ' in gpt
            and 'EDAB4CD7-721A-4D00-A97A-A319F170948F' in gpt, 'provisioned root layout differs')
    root_disk = run / 'root.ext4'
    command(['/usr/bin/dd', 'if=' + str(raw), 'of=' + str(root_disk), 'bs=65536',
             'skip=2048', 'count=47088', 'conv=sparse', 'status=none'])
    transaction.remember('root.ext4')
    require(root_disk.stat().st_size == 3085959168, 'root extent differs')
    stats = command(['/usr/sbin/debugfs', '-R', 'stats', str(root_disk)]).decode()
    require('Filesystem UUID:          ' + pins['VERIFIER_VM_ROOT_FILESYSTEM_UUID'] in stats
            and 'Filesystem state:         clean' in stats, 'provisioned filesystem identity/state differs')
    for name, guest_path, expected in (
        ('vmlinuz', '/boot/vmlinuz-6.1.0-50-amd64', provision['kernel']),
        ('initrd.img', '/boot/rustdesk-media-initrd-a', provision['initrd'])):
        require(0 < expected['bytes'] <= 134217728, 'produced boot asset bound differs')
        inode = command(['/usr/sbin/debugfs', '-R', 'stat ' + guest_path, str(root_disk)]).decode()
        require('Type: regular' in inode and re.search(r'\bSize:\s+' + str(expected['bytes']) + r'\b', inode)
                and re.search(r'\bLinks:\s+1\b', inode), 'boot output inode differs')
        command(['/usr/sbin/debugfs', '-R', 'dump ' + guest_path + ' ' + str(run / name), str(root_disk)])
        os.chmod(run / name, 0o400)
    require(provision['kernel'] == {'bytes': int(pins['SIZE_VERIFIER_MEDIA_KERNEL']),
                                    'sha256': pins['SHA256_VERIFIER_MEDIA_KERNEL']}
            and provision['same_guest_initrd_equality'] is True, 'boot producer identity/equality differs')
    media_kernel = admit(run / 'vmlinuz', provision['kernel']['bytes'], provision['kernel']['sha256'])
    media_initrd = admit(run / 'initrd.img', provision['initrd']['bytes'], provision['initrd']['sha256'])
    fixture = transaction.boot('fixture', base, overlay, media_kernel, media_initrd, payload, pins)
    require(len(fixture['captures']) == 2 and fixture['module_retired'] is True
            and fixture['root_foreign_probe_refused'] is True
            and fixture['product_executed'] is False, 'fixture lifecycle result differs')
    for capture in fixture['captures']:
        require(capture['principal'] == '4000:4000' and capture['node'] == '/dev/video2'
                and capture['driver'] == 'vivid' and capture['native_zero_errno'] == 2
                and capture['frame_bytes'] == 172800 and len(capture['frame_sha256']) == 4
                and len(set(capture['frame_sha256'])) >= 2, 'native capture result differs')
    after = {str(p): observe(p) for p in frozen_paths}
    exclusive(run / 'freeze.after.json', json.dumps(after, sort_keys=True).encode() + b'\n')
    require(before == after, 'source/control/input changed during media transaction')
    require(tools == {str(p): observe(Path(p).resolve()) for p in tools}, 'orchestration tool changed')
    exclusive(run / 'listeners.after.json', json.dumps(transaction.safe_listeners()).encode() + b'\n')
    receipt = {'format': 'rustdesk-verifier-media-v1', 'source_commit': commit,
               'source_tree': command(['/usr/bin/git', 'rev-parse', 'HEAD^{tree}']).decode().strip(),
               'provision': provision, 'fixture': fixture, 'source_input_freeze_equal': True,
               'host_listener_additions': [], 'guest_processes_joined': True}
    exclusive(run / 'receipt.json', json.dumps(receipt, sort_keys=True).encode() + b'\n')
    for fd in fds + [overlay, payload, media_kernel, media_initrd, candidate_dir, boot_dir, acquisition]:
        os.close(fd)
    evidence = transaction.finish()
    os.close(transaction.fd)
    os.close(parent)
    print('VERIFIER_MEDIA_VM=pass evidence=' + str(evidence), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('VERIFIER_MEDIA_VM=fail ' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)

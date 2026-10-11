#!/usr/bin/env python3
"""Fixed guest administrator recipe and unprivileged native V4L2 fixture."""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import stat
import struct
import subprocess
import sys
import time


MEDIA = Path('/mnt/rustdesk-media')
RELEASE = '6.1.0-50-amd64'
PACKAGE = 'linux-image-' + RELEASE + '_6.1.176-1_amd64.deb'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
LIMIT = 128 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(argv):
    subprocess.run(argv, env=ENV, check=True, timeout=120)


def file_record(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and 0 < info.st_size <= limit, 'guest file bounds/type differ: ' + str(path))
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'bytes': info.st_size, 'sha256': digest}


def topology():
    require(os.uname().machine == 'x86_64', 'guest architecture differs')
    require('rustdesk.media_vm=1' in Path('/proc/cmdline').read_text().split(),
            'guest-only marker absent')
    require(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'],
            'guest must have only loopback')
    require(not any(line.split()[2] in ('9p', 'virtiofs', 'nfs', 'cifs')
                    for line in Path('/proc/mounts').read_text().splitlines()),
            'guest filesystem share present')


def capture():
    require(os.getuid() == 4000 and os.getgid() == 4000 and not os.getgroups(),
            'capture requires the exact unprivileged fixture principal')
    topology()
    require(os.uname().release == RELEASE, 'capture kernel release differs')
    require(sorted(p.name for p in Path('/dev').glob('video*')) == ['video2'],
            'nonzero-only node inventory differs')
    try:
        fd = os.open('/dev/video0', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as error:
        require(error.errno == errno.ENOENT, 'native index zero failed for another reason')
    else:
        os.close(fd)
        raise ValueError('native index zero unexpectedly opened')
    fd = os.open('/dev/video2', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 81,
                'capture is not a native V4L2 character device')
        require(Path('/sys/class/video4linux/video2/name').read_text().strip()
                == 'vivid-000-vid-cap', 'sysfs driver identity differs')
        # Linux v6.1 UAPI videodev2.h and asm-generic/ioctl.h, x86_64 ABI:
        # capability is 104 bytes; format is 208 with its pointer-aligned union at 8.
        require(struct.calcsize('P') == 8 and sys.byteorder == 'little', 'V4L2 ABI differs')
        capability = bytearray(104)
        fcntl.ioctl(fd, (2 << 30) | (104 << 16) | (ord('V') << 8), capability, True)
        require(capability[:16].split(b'\0')[0] == b'vivid', 'QUERYCAP driver differs')
        caps, device_caps = struct.unpack_from('<II', capability, 84)
        effective = device_caps if caps & 0x80000000 else caps
        require(effective & 1 and effective & 0x01000000, 'capture/read capability absent')
        fmt = bytearray(208)
        rgb = int.from_bytes(b'RGB3', 'little')
        struct.pack_into('<I', fmt, 0, 1)
        struct.pack_into('<IIII', fmt, 8, 320, 180, rgb, 1)
        fcntl.ioctl(fd, (3 << 30) | (208 << 16) | (ord('V') << 8) | 5, fmt, True)
        width, height, pixel, field, stride, size = struct.unpack_from('<IIIIII', fmt, 8)
        require((width, height, pixel, field, stride, size)
                == (320, 180, rgb, 1, 960, 172800), 'native negotiated format differs')
        frames = []
        pixel_counts = []
        deadline = time.monotonic() + 5
        while len(frames) < 4:
            require(time.monotonic() < deadline, 'native frame deadline exceeded')
            try:
                frame = os.read(fd, size)
            except BlockingIOError:
                select.select([fd], [], [], min(0.1, max(0, deadline - time.monotonic())))
                continue
            require(len(frame) == size, 'native frame bytes differ: ' + str(len(frame)))
            colors = len({frame[offset:offset + 3] for offset in range(0, size, 3)})
            require(colors >= 8, 'native RGB colorbar count differs: ' + str(colors))
            pixel_counts.append(colors)
            frames.append(hashlib.sha256(frame).hexdigest())
        require(len(set(frames)) >= 2, 'native frame content did not advance')
        return {'principal': '4000:4000', 'node': '/dev/video2', 'driver': 'vivid',
                'rdev': [os.major(info.st_rdev), os.minor(info.st_rdev)],
                'native_zero_errno': errno.ENOENT, 'format': 'RGB3',
                'width': width, 'height': height, 'frame_bytes': size,
                'frame_sha256': frames, 'pixel_color_counts': pixel_counts}
    finally:
        os.close(fd)


def provision(pins):
    require(os.uname().release == pins['VERIFIER_VM_KERNEL_RELEASE'],
            'provisioning kernel release differs')
    lib = Path('/lib')
    require(lib.is_symlink() and os.readlink(lib) == 'usr/lib', 'base library ancestry differs')
    lib_identity = (lib.lstat().st_dev, lib.lstat().st_ino)
    stage = Path('/var/lib/rustdesk-media-package')
    stage.mkdir(mode=0o700)
    run(['/usr/bin/dpkg-deb', '--extract', str(MEDIA / PACKAGE), str(stage)])
    os.chmod(stage, 0o700)
    for prefix in ('vmlinuz-', 'config-', 'System.map-'):
        target = Path('/boot', prefix + RELEASE)
        require(not target.exists() and not target.is_symlink(), 'media boot destination occupied')
        source = stage / 'boot' / (prefix + RELEASE)
        file_record(source, LIMIT)
        with source.open('rb') as source_file, target.open('xb') as output:
            shutil.copyfileobj(source_file, output)
    target_modules = Path('/usr/lib/modules', RELEASE)
    require(not target_modules.exists() and not target_modules.is_symlink(),
            'media module destination occupied')
    os.rename(stage / 'lib/modules' / RELEASE, target_modules)
    require(lib.is_symlink() and os.readlink(lib) == 'usr/lib'
            and (lib.lstat().st_dev, lib.lstat().st_ino) == lib_identity,
            'provisioning changed base library ancestry')
    require(file_record(Path('/boot/vmlinuz-' + RELEASE), LIMIT)
            == {'bytes': int(pins['SIZE_VERIFIER_MEDIA_KERNEL']),
                'sha256': pins['SHA256_VERIFIER_MEDIA_KERNEL']}, 'extracted kernel differs')
    require(file_record(Path('/boot/config-' + RELEASE), 1048576)['sha256']
            == pins['SHA256_VERIFIER_MEDIA_KERNEL_CONFIG'], 'extracted config differs')
    modules = list(Path('/lib/modules', RELEASE).rglob('*.ko'))
    require(len(modules) == 4022 and all(p.is_file() and not p.is_symlink() for p in modules),
            'extracted module inventory differs')
    run(['/usr/sbin/depmod', RELEASE])
    # Explicit version avoids using the currently running cloud kernel. No apt,
    # package maintainer scripts, bootloader update or network acquisition occurs.
    build_env = dict(ENV, SOURCE_DATE_EPOCH=pins['SOURCE_DATE_EPOCH_PIN'])
    for suffix in ('a', 'b'):
        subprocess.run(['/usr/sbin/mkinitramfs', '-c', 'gzip', '-o',
                        '/boot/rustdesk-media-initrd-' + suffix, RELEASE],
                       env=build_env, check=True, timeout=120)
    first = file_record(Path('/boot/rustdesk-media-initrd-a'), LIMIT)
    require(first == file_record(Path('/boot/rustdesk-media-initrd-b'), LIMIT),
            'independent initramfs invocations differ')
    result = {'kernel': file_record(Path('/boot/vmlinuz-' + RELEASE), LIMIT),
              'initrd': first, 'kernel_release': RELEASE, 'module_count': len(modules),
              'same_guest_initrd_equality': True,
              'epoch': pins['SOURCE_DATE_EPOCH_PIN']}
    return result


def fixture(pins):
    require(os.uname().release == RELEASE, 'media boot kernel release differs')
    require(file_record(Path('/boot/config-' + RELEASE), 1048576)['sha256']
            == pins['SHA256_VERIFIER_MEDIA_KERNEL_CONFIG'], 'running media module config differs')
    probe = Path('/var/lib/rustdesk-media-probe.py')
    with (MEDIA / 'guest.py').open('rb') as source, probe.open('xb') as output:
        shutil.copyfileobj(source, output)
        output.flush()
        os.fchmod(output.fileno(), 0o444)
        os.fsync(output.fileno())
    require(file_record(probe, 1048576) == file_record(MEDIA / 'guest.py', 1048576),
            'unprivileged probe source copy differs')
    run(['/usr/sbin/groupadd', '--gid', '4000', 'media-fixture'])
    run(['/usr/sbin/useradd', '--uid', '4000', '--gid', '4000', '--no-create-home',
         '--shell', '/usr/sbin/nologin', 'media-fixture'])
    for prefix in ([], ['/usr/bin/setpriv', '--reuid=4001', '--regid=4001', '--clear-groups']):
        refused = subprocess.run(prefix + ['/usr/bin/python3', '-I', '-S',
                                 str(probe), '--probe'], env=ENV, timeout=10,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(refused.returncode == 1 and not refused.stdout
                and b'capture requires the exact unprivileged fixture principal' in refused.stderr,
                'root/foreign capture principal was not refused')
    captures = []
    for generation in range(2):
        require(not list(Path('/dev').glob('video*')), 'fixture starts with unexpected camera nodes')
        run(['/usr/sbin/modprobe', 'vivid', 'n_devs=1', 'node_types=1', 'vid_cap_nr=2',
             'num_inputs=1', 'input_types=0'])
        try:
            run(['/usr/bin/udevadm', 'settle', '--timeout=10'])
            node = Path('/dev/video2')
            require(stat.S_ISCHR(node.lstat().st_mode), 'vivid did not create the native node')
            os.chown(node, 4000, 4000)
            os.chmod(node, 0o600)
            output = subprocess.check_output([
                '/usr/bin/setpriv', '--reuid=4000', '--regid=4000', '--clear-groups',
                '--no-new-privs', '/usr/bin/python3', '-I', '-S', str(probe),
                '--probe'], env=ENV, timeout=10)
            require(len(output) <= 8192, 'capture result exceeds bound')
            captures.append(json.loads(output))
        finally:
            run(['/usr/sbin/modprobe', '-r', 'vivid'])
            run(['/usr/bin/udevadm', 'settle', '--timeout=10'])
        require(not list(Path('/dev').glob('video*'))
                and not Path('/sys/module/vivid').exists(), 'fixture retirement incomplete')
    return {'kernel_release': RELEASE, 'captures': captures,
            'module_retired': True, 'root_foreign_probe_refused': True, 'product_executed': False}


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['--probe']:
        print(json.dumps(capture(), sort_keys=True), flush=True)
        return
    require(sys.argv[1:] in (['--provision'], ['--fixture']), 'guest request differs')
    require(os.getuid() == 0 and os.getgid() == 0, 'guest provisioning requires guest root')
    topology()
    contract = json.loads((MEDIA / 'contract.json').read_text())
    pins = contract['pins']
    require(file_record(MEDIA / PACKAGE, 70305560)
            == {'bytes': int(pins['SIZE_VERIFIER_MEDIA_KERNEL_PACKAGE']),
                'sha256': pins['SHA256_VERIFIER_MEDIA_KERNEL_PACKAGE']}, 'media package pin differs')
    result = provision(pins) if sys.argv[1] == '--provision' else fixture(pins)
    result.update({'source_commit': contract['source_commit'], 'nonce': contract['nonce'],
                   'phase': sys.argv[1][2:], 'interfaces': ['lo']})
    print('\nMEDIA_GUEST_RESULT=' + json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('MEDIA_GUEST_FAILURE=' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)

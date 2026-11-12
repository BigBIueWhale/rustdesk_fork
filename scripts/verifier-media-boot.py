#!/usr/bin/env python3
"""Run the pinned media kernel fixture across one guest-local kexec handoff."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MEDIA = Path('/mnt/rustdesk-verifier-inputs/media')
STATE = Path('/var/lib/rustdesk-media-boot.json')
UNIT = Path('/etc/systemd/system/rustdesk-media-fixture.service')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def create(path, data):
    with path.open('xb') as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())


def application_request(argv, contract, release):
    require(len(argv) == 21 and argv[:4] == [
        'bash', '/mnt/rustdesk-verifier-inputs/guest.sh',
        '/mnt/rustdesk-verifier-inputs/docker.tgz',
        '/mnt/rustdesk-verifier-inputs/repo/scripts/verify-vm-entry-preflight.sh']
        and argv[7] == release
        and argv[8] == contract['pins']['VERIFIER_VM_ROOT_FILESYSTEM_UUID']
        and argv[9:11] == ['--linux-flutter-app-replay', '/mnt/rustdesk-verifier-inputs/source.tar']
        and argv[11] == contract['source_commit']
        and argv[20] in ('--camera-shared', '--camera-busy', '--installed-camera'),
        'closed application replay request differs')
    require(all(re.fullmatch('[0-9a-f]{40}', argv[i]) for i in (11, 12, 14, 15))
            and all(re.fullmatch('[0-9a-f]{64}', argv[i]) for i in (6, 13, 16, 17))
            and all(len(argv[i]) <= 16384 and isinstance(json.loads(argv[i]), dict)
                    for i in (18, 19)), 'application replay identities differ')


def application_fixture(guest, contract, previous):
    argv = previous['application_argv']
    application_request(argv, contract, contract['pins']['VERIFIER_VM_KERNEL_RELEASE'])
    argv[7] = guest.RELEASE
    require(not list(Path('/dev').glob('video*')), 'application starts with camera nodes')
    guest.run(['/usr/sbin/modprobe', 'vivid', 'n_devs=1', 'node_types=1', 'vid_cap_nr=2',
               'num_inputs=1', 'input_types=0'])
    try:
        guest.run(['/usr/bin/udevadm', 'settle', '--timeout=10'])
        node = Path('/dev/video2')
        require(sorted(p.name for p in Path('/dev').glob('video*')) == ['video2']
                and stat.S_ISCHR(node.lstat().st_mode)
                and Path('/sys/class/video4linux/video2/name').read_text().strip()
                == 'vivid-000-vid-cap', 'application native camera identity differs')
        uid = 4001 if argv[20] == '--installed-camera' else 1000
        os.chown(node, uid, uid)
        os.chmod(node, 0o600)
        # Common guest orchestration joins the app containers or installed
        # service before returning. The device is created only in this guest.
        subprocess.run(argv, check=True, timeout=840)
    finally:
        guest.run(['/usr/sbin/modprobe', '-r', 'vivid'])
        guest.run(['/usr/bin/udevadm', 'settle', '--timeout=10'])
    require(not list(Path('/dev').glob('video*')) and not Path('/sys/module/vivid').exists(),
            'application camera module retirement incomplete')
    population = 'viewers=2 generations=3' if argv[20] == '--camera-shared' else 'viewers=1 generations=2'
    if argv[20] == '--installed-camera':
        population = 'viewers=1 generations=1'
    print('MEDIA_APPLICATION_FIXTURE=pass source=' + contract['source_commit']
          + ' kernel=' + guest.RELEASE
          + ' native_node=2 ' + population + ' module=retired cleanup=joined', flush=True)
    print('VERIFIER_VM_CLOUD_INIT=pass', flush=True)


def main():
    os.umask(0o077)
    preparing_app = sys.argv[1:3] == ['--prepare', '--']
    require(preparing_app or sys.argv[1:] in (['--prepare'], ['--fixture']),
            'closed media boot request required')
    require(os.getuid() == 0 and os.getgid() == 0 and os.uname().machine == 'x86_64',
            'media boot requires the x86_64 guest administrator')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd'
            and sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
            and 'rustdesk.verifier_vm=1' in Path('/proc/cmdline').read_text().split(),
            'isolated verifier guest topology differs')
    require(not any(line.split()[2] in ('9p', 'virtiofs', 'nfs', 'cifs')
                    for line in Path('/proc/mounts').read_text().splitlines()),
            'media boot forbids filesystem shares')
    contract = json.loads((MEDIA / 'contract.json').read_text())
    require(type(contract['nokhwa']) is bool and type(contract['application']) is bool
            and not (contract['nokhwa'] and contract['application']), 'closed media workload required')
    if sys.argv[1] == '--prepare':
        require(preparing_app == contract['application'], 'media/application preparation differs')
        if preparing_app:
            application_request(sys.argv[3:], contract, contract['pins']['VERIFIER_VM_KERNEL_RELEASE'])
    require(re.fullmatch('[0-9a-f]{40}', contract['source_commit']) is not None,
            'media source commit differs')
    spec = importlib.util.spec_from_file_location('media_guest', MEDIA / 'guest.py')
    require(spec is not None and spec.loader is not None, 'media fixture loader absent')
    guest = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(guest)
    guest.MEDIA = MEDIA
    for name, expected in contract['sources'].items():
        require(guest.file_record(MEDIA / name, 1048576) == expected, 'media source differs: ' + name)
    pins = contract['pins']
    require(guest.file_record(MEDIA / guest.PACKAGE, 70305560)
            == {'bytes': int(pins['SIZE_VERIFIER_MEDIA_KERNEL_PACKAGE']),
                'sha256': pins['SHA256_VERIFIER_MEDIA_KERNEL_PACKAGE']}, 'media package differs')
    cmdline = ('root=UUID=' + pins['VERIFIER_VM_ROOT_FILESYSTEM_UUID']
               + ' rw rootfstype=ext4 rootwait console=ttyS0,115200n8 rustdesk.verifier_vm=1'
               + ' systemd.mask=systemd-networkd-wait-online.service'
               + ' systemd.mask=ssh.service systemd.mask=ssh.socket')
    media_cmdline = cmdline + ' rustdesk.media_vm=1 systemd.mask=serial-getty@ttyS0.service'
    for service in ('cloud-init-local', 'cloud-init', 'cloud-config', 'cloud-final'):
        media_cmdline += ' systemd.mask=' + service + '.service'
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    kernel = Path('/boot/vmlinuz-' + guest.RELEASE)
    initrd = Path('/boot/rustdesk-media-initrd-a')
    if sys.argv[1] == '--prepare':
        require(Path('/proc/cmdline').read_text().strip() == cmdline,
                'initial media boot command line differs')
        require(Path('/sys/kernel/kexec_loaded').read_text().strip() == '0',
                'another kexec image is already loaded')
        result = guest.provision(pins)
        result.update(source_commit=contract['source_commit'], boot_id=boot_id)
        if preparing_app:
            result['application_argv'] = sys.argv[3:]
        create(STATE, json.dumps(result, sort_keys=True).encode() + b'\n')
        start = '/usr/bin/python3 -I -S /mnt/rustdesk-verifier-inputs/media/boot.py --fixture'
        if preparing_app:
            start = ('/bin/bash -o pipefail -c "' + start + ' 2>&1 | /usr/bin/python3 -I -S '
                     '/mnt/rustdesk-verifier-inputs/repo/scripts/bounded-unix-stream-capture.py '
                     '--guest-output"')
        unit = ('[Unit]\nDescription=Disposable native media fixture\n'
                'After=local-fs.target\nConditionKernelCommandLine=rustdesk.media_vm=1\n'
                '[Service]\nType=oneshot\nTimeoutStartSec='
                + ('900' if preparing_app else '360' if contract['nokhwa'] else '60') + '\n'
                'ExecStartPre=/usr/bin/mount -L RD_VERIFIER_INPUTS -o ro,nodev,nosuid,noexec'
                ' /mnt/rustdesk-verifier-inputs\n'
                'ExecStart=' + start + '\n'
                'ExecStopPost=/usr/bin/systemctl --no-block poweroff\n'
                'StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n')
        create(UNIT, unit.encode())
        (UNIT.parent / 'multi-user.target.wants' / UNIT.name).symlink_to(UNIT)
        # Linux x86_64 SYS_kexec_file_load=320. The kernel consumes authenticated
        # descriptors; systemd 252 performs orderly shutdown before RB_KEXEC.
        command = media_cmdline.encode() + b'\0'
        with kernel.open('rb') as kernel_file, initrd.open('rb') as initrd_file:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
            status = libc.syscall(ctypes.c_long(320), ctypes.c_int(kernel_file.fileno()),
                                  ctypes.c_int(initrd_file.fileno()), ctypes.c_ulong(len(command)),
                                  ctypes.c_char_p(command), ctypes.c_ulong(0))
            if status != 0:
                raise OSError(ctypes.get_errno(), 'guest kexec_file_load failed')
        require(Path('/sys/kernel/kexec_loaded').read_text().strip() == '1',
                'media kernel was not loaded')
        print('\nMEDIA_BOOT_PREPARED=' + json.dumps(result, sort_keys=True), flush=True)
    else:
        require(Path('/proc/cmdline').read_text().strip() == media_cmdline,
                'media handoff command line differs')
        previous = json.loads(STATE.read_text())
        require(previous['boot_id'] != boot_id and previous['source_commit'] == contract['source_commit']
                and previous['kernel_release'] == os.uname().release == guest.RELEASE,
                'media kernel handoff identity differs')
        require(guest.file_record(kernel, guest.LIMIT) == previous['kernel']
                and guest.file_record(initrd, guest.LIMIT) == previous['initrd'],
                'media handoff assets changed')
        if contract['application']:
            application_fixture(guest, contract, previous)
            return
        result = guest.fixture(pins, contract) if contract['nokhwa'] else guest.capture_fixture(pins)
        result.update(source_commit=contract['source_commit'], boot_id=boot_id,
                      previous_boot_id=previous['boot_id'], sources=contract['sources'])
        print('MEDIA_KERNEL_RESULT=' + json.dumps(result, sort_keys=True), flush=True)
        print('MEDIA_KERNEL_FIXTURE=pass source=' + contract['source_commit']
              + ' generations=2 principal=4000:4000 root-foreign=refused'
              + ' module=retired product=unexecuted', flush=True)
        if contract['nokhwa']:
            print('MEDIA_NOKHWA_FIXTURE=pass source=' + contract['source_commit']
                  + ' capture=decoded two-retained=independent node-reuse=fresh-handle stream=exclusive-retry'
                  + ' supplier=executed product=unexecuted cleanup=joined', flush=True)
            print('MEDIA_CAMERA_MODULE=pass source=' + contract['source_commit']
                  + ' nonzero=decoded catalog=retained replacement=independent overlap=shared'
                  + ' application=unexecuted', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('MEDIA_KERNEL_FAILURE=' + str(error), file=sys.stderr, flush=True)
        print('VERIFIER_VM_CLOUD_INIT=fail status=1', file=sys.stderr, flush=True)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Run the pinned media kernel fixture across one guest-local kexec handoff."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
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


def main():
    os.umask(0o077)
    require(sys.argv[1:] in (['--prepare'], ['--fixture']), 'closed media boot request required')
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
        create(STATE, json.dumps(result, sort_keys=True).encode() + b'\n')
        unit = ('[Unit]\nDescription=Disposable native media fixture\n'
                'After=local-fs.target\nConditionKernelCommandLine=rustdesk.media_vm=1\n'
                '[Service]\nType=oneshot\nTimeoutStartSec=60\n'
                'ExecStartPre=/usr/bin/mount -L RD_VERIFIER_INPUTS -o ro,nodev,nosuid,noexec'
                ' /mnt/rustdesk-verifier-inputs\n'
                'ExecStart=/usr/bin/python3 -I -S /mnt/rustdesk-verifier-inputs/media/boot.py --fixture\n'
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
        result = guest.capture_fixture(pins)
        result.update(source_commit=contract['source_commit'], boot_id=boot_id,
                      previous_boot_id=previous['boot_id'], sources=contract['sources'])
        print('MEDIA_KERNEL_RESULT=' + json.dumps(result, sort_keys=True), flush=True)
        print('MEDIA_KERNEL_FIXTURE=pass source=' + contract['source_commit']
              + ' generations=2 principal=4000:4000 root-foreign=refused'
              + ' module=retired product=unexecuted', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('MEDIA_KERNEL_FAILURE=' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)

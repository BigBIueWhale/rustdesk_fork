#!/usr/bin/env python3
"""Run the offline verifier orchestration with no host IP socket authority."""
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import stat
import sys


BODY_MARKER = b'\n# VM_HOST_NETWORK_BODY\n'
ENTRY_PREFIX = (b'#!/usr/bin/env bash\n'
                b'exec /usr/bin/python3 -I -S "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/vm-host-network.py" "$@"\n')
AUDIT_ARCH_X86_64 = 0xc000003e
DENY_SYSCALLS = (101, 310, 311, 425, 426, 427, 438)
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


class Instruction(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('instructions', ctypes.POINTER(Instruction))]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def install_network_policy():
    require(os.geteuid() != 0 and os.getegid() != 0, 'host root is forbidden')
    require(os.uname().machine == 'x86_64', 'host network policy requires x86_64')
    require(len(os.listdir('/proc/self/task')) == 1, 'network policy requires a single-threaded entry')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    require(all(int(status[key], 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
            'host network entry has capabilities')
    allow, deny, kill = 0x7fff0000, 0x50000 | errno.EPERM, 0x80000000
    # seccomp_data: nr at 0, arch at 4, low words of args[0]/args[2] at 16/32.
    # Reject compat and x32 ABIs before interpreting any syscall or argument.
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, AUDIT_ARCH_X86_64), (0x06, 0, 0, kill),
                    (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, kill)]
    # No ring-based socket operations or foreign descriptor/process acquisition.
    for number in DENY_SYSCALLS:
        instructions.extend(((0x15, 0, 1, number), (0x06, 0, 0, deny)))
    instructions.extend((
        (0x15, 2, 0, 41), (0x15, 9, 0, 53), (0x06, 0, 0, allow),
        (0x20, 0, 0, 16), (0x15, 0, 1, socket.AF_UNIX), (0x06, 0, 0, allow),
        (0x15, 0, 3, socket.AF_NETLINK), (0x20, 0, 0, 32),
        (0x15, 0, 1, 4), (0x06, 0, 0, allow), (0x06, 0, 0, deny),
        (0x20, 0, 0, 16), (0x15, 0, 1, socket.AF_UNIX),
        (0x06, 0, 0, allow), (0x06, 0, 0, deny),
    ))
    array = (Instruction * len(instructions))(*(Instruction(*item) for item in instructions))
    program = Program(len(array), array)
    require(LIBC.prctl(38, 1, 0, 0, 0) == 0, 'cannot set no-new-privileges')
    require(LIBC.prctl(22, 2, ctypes.byref(program), 0, 0) == 0,
            f'cannot install host network filter: errno {ctypes.get_errno()}')
    require(LIBC.prctl(39, 0, 0, 0, 0) == 1 and LIBC.prctl(21, 0, 0, 0, 0) == 2,
            'host network filter readback differs')
    # An admission check creates no bound endpoint, even if the filter is wrong.
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            probe = socket.socket(family, socket.SOCK_DGRAM)
        except OSError as error:
            require(error.errno == errno.EPERM, 'host socket denial differs')
        else:
            probe.close()
            raise ValueError('host IP socket escaped the network filter')


def close_inherited_descriptors():
    # The sealed harness replaces stdin. Retain only non-IP stdout/stderr; no
    # inherited socket or io_uring capability may enter the process tree.
    for descriptor in (1, 2):
        metadata = os.fstat(descriptor)
        if stat.S_ISSOCK(metadata.st_mode):
            with socket.socket(fileno=os.dup(descriptor)) as channel:
                require(channel.getsockopt(socket.SOL_SOCKET, 39) == socket.AF_UNIX,
                        'IP standard-output descriptor is forbidden')
    for name in os.listdir('/proc/self/fd'):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                # listdir's temporary procfs descriptor is already closed.
                if error.errno != errno.EBADF:
                    raise


def main():
    require(os.geteuid() != 0 and os.getegid() != 0, 'host root is forbidden')
    root = Path(__file__).resolve().parent
    entry = root / 'smoke-verifier-vm-authority.sh'
    descriptor = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and metadata.st_nlink == 1 and not metadata.st_mode & 0o022
                and 0 < metadata.st_size <= 1048576, 'verifier entry authority differs')
        raw = source.read(1048577)
    prefix, marker, body = raw.partition(BODY_MARKER)
    require(prefix == ENTRY_PREFIX and marker and body,
            'verifier entry must use the fixed confined bootstrap')
    close_inherited_descriptors()
    install_network_policy()
    script = os.memfd_create('rustdesk-verifier-host-body', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(script), 'wb') as output:
            output.write(body)
        os.lseek(script, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        fcntl.fcntl(script, fcntl.F_ADD_SEALS, seals)
        require(fcntl.fcntl(script, fcntl.F_GET_SEALS) == seals, 'harness RAM seal differs')
        os.dup2(script, 0, inheritable=True)
        os.set_inheritable(0, True)
    finally:
        if script != 0:
            os.close(script)
    print('VERIFIER_VM_HOST_NETWORK=pass ip_sockets=denied unix=allowed netlink=socket-diag-only '
          'io_uring=denied foreign_process_access=denied inheritance=fork-exec '
          'entry=sealed-ram body_sha256=' + hashlib.sha256(body).hexdigest(), flush=True)
    os.execv('/bin/bash', ['/bin/bash', '--noprofile', '--norc', '-s', '--', str(root), *sys.argv[1:]])


if __name__ == '__main__':
    main()

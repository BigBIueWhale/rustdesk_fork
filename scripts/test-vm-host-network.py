#!/usr/bin/env python3
"""Guest-only native tests of the verifier's host socket restriction."""
import ctypes
import base64
import errno
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile


SOURCE = Path(__file__).with_name('vm-host-network.py')
OBSERVER = SOURCE.with_name('smoke-verifier-vm-authority.sh')
spec = importlib.util.spec_from_file_location('vm_host_network', SOURCE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
LIBC = policy.LIBC


def denied(number, *arguments):
    ctypes.set_errno(0)
    result = LIBC.syscall(number, *arguments)
    if result >= 0:
        if number in (41, 425, 438):
            os.close(result)
        raise AssertionError(f'syscall {number} escaped the policy')
    assert ctypes.get_errno() == errno.EPERM, (number, ctypes.get_errno())


def restriction_cases():
    status = Path('/proc/self/status').read_text()
    assert 'NoNewPrivs:\t1\n' in status and 'Seccomp:\t2\n' in status
    for family in range(49):
        if family not in (socket.AF_UNIX, socket.AF_NETLINK):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_RAW):
                denied(41, family, kind, 0)
        if family == socket.AF_UNIX:
            continue
        pair = (ctypes.c_int * 2)()
        denied(53, family, socket.SOCK_STREAM, 0, ctypes.byref(pair))
    for protocol in range(33):
        if protocol not in (0, 4):
            denied(41, socket.AF_NETLINK, socket.SOCK_RAW, protocol)
    # Socket arguments are kernel ints; nonzero upper words cannot select IP.
    denied(41, ctypes.c_ulonglong((1 << 32) | socket.AF_INET), socket.SOCK_DGRAM, 0)
    for number in policy.DENY_SYSCALLS:
        denied(number, -1, -1, 0, 0, 0, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:
        assert diag.family == socket.AF_NETLINK
    with tempfile.TemporaryDirectory() as root:
        name = root + '/control.sock'
        with socket.socket(socket.AF_UNIX) as listener, socket.socket(socket.AF_UNIX) as client:
            listener.bind(name)
            listener.listen(1)
            client.connect(name)
            with listener.accept()[0] as accepted:
                client.sendall(b'owned-unix-control')
                assert accepted.recv(64) == b'owned-unix-control'
                accepted.sendall(b'reply')
                assert client.recv(64) == b'reply'
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b'pair')
        assert right.recv(4) == b'pair'
    result = subprocess.run(['/usr/bin/ss', '-H', '-lntu'], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert not result.stderr, result.stderr
    assert all(len(fields := line.split()) == 6 and fields[0] in ('tcp', 'udp')
               for line in result.stdout.splitlines())


def worker():
    policy.install_network_policy()
    restriction_cases()
    child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(Path(__file__)), '--inherited'],
                           capture_output=True, text=True, timeout=5)
    assert (child.returncode, child.stdout, child.stderr) == (0, 'inherited restrictions passed\n', ''), \
        (child.returncode, child.stdout, child.stderr)
    child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(Path(__file__)), '--x32'],
                           capture_output=True, text=True, timeout=5)
    assert child.returncode == -signal.SIGSYS, (child.returncode, child.stdout, child.stderr)
    child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(Path(__file__)), '--i386'],
                           capture_output=True, text=True, timeout=5)
    assert child.returncode == -signal.SIGSYS, (child.returncode, child.stdout, child.stderr)
    print('native restrictions and fork-exec inheritance passed')


def main():
    assert 'rustdesk.verifier_vm=1' in Path('/proc/cmdline').read_text().split()
    assert os.geteuid() != 0 and os.getegid() != 0
    assert 'Seccomp:\t0\n' in Path('/proc/self/status').read_text()
    before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    observer = OBSERVER.read_bytes()
    observation_functions = b''
    for name in (b'capture_listeners', b'report_listener_delta'):
        opening = b'\n' + name + b'() {\n'
        assert observer.count(opening) == 1, name
        body = observer.split(opening, 1)[1].split(b'\n}\n', 1)
        assert len(body) == 2, name
        observation_functions += name + b'() {\n' + body[0] + b'\n}\n'
    # This exact guest kernel/principal can bind IP before the production filter.
    for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(family, kind) as control:
                control.bind((address, 0))
                assert control.getsockname()[1] > 0
                if kind == socket.SOCK_STREAM:
                    control.listen(1)
    child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(Path(__file__)), '--worker'],
                           capture_output=True, text=True, timeout=15)
    assert (child.returncode, child.stdout, child.stderr) == (
        0, 'native restrictions and fork-exec inheritance passed\n', ''), \
        (child.returncode, child.stdout, child.stderr)
    # Exercise the actual bootstrap, source bound and argument preserving, inside
    # guest scratch. An ambient environment variable cannot skip its filter.
    with tempfile.TemporaryDirectory() as root:
        helper = Path(root) / SOURCE.name
        helper.write_bytes(SOURCE.read_bytes())
        helper.chmod(0o400)
        entry = Path(root) / 'smoke-verifier-vm-authority.sh'
        entry.write_bytes(policy.ENTRY_PREFIX + policy.BODY_MARKER +
                          b'exec /usr/bin/python3 -B -I -S "$1/test-vm-host-network.py" --inherited "${@:2}"\n')
        entry.chmod(0o400)
        test = Path(root) / Path(__file__).name
        test.write_bytes(Path(__file__).read_bytes())
        test.chmod(0o400)
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent',
                       'VERIFIER_VM_HOST_NETWORK_CONFINE': 'forged'}
        startup = Path(root) / 'untrusted-bash-env'
        startup.write_text('echo untrusted-startup-ran\n')
        # The sealed-body shell must ignore startup files, too.
        environment['BASH_ENV'] = str(startup)
        child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), 'argument with spaces'],
                               env=environment, capture_output=True, text=True, timeout=10)
        assert child.returncode == 0 and not child.stderr and 'untrusted-startup-ran' not in child.stdout
        del environment['BASH_ENV']
        child = subprocess.run(['/bin/bash', str(entry), 'argument with spaces'], env=environment,
                               capture_output=True, text=True, timeout=10)
        assert child.returncode == 0 and not child.stderr, (child.returncode, child.stdout, child.stderr)
        lines = child.stdout.splitlines()
        assert len(lines) == 2 and lines[0].startswith('VERIFIER_VM_HOST_NETWORK=pass ')
        assert lines[1] == 'inherited restrictions passed'
        assert os.environ.get('VERIFIER_VM_HOST_NETWORK_CONFINE') is None
        # Inherited IP stdout must be refused before any harness body can run.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as inherited:
            child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper)],
                                   stdout=inherited, stderr=subprocess.PIPE, text=True, timeout=5)
        assert child.returncode == 1 and 'IP standard-output descriptor is forbidden' in child.stderr
        # A bound inherited IP socket is absent at the exact child descriptor.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as inherited:
            inherited.bind(('127.0.0.1', 0))
            child = subprocess.run(['/bin/bash', str(entry), 'argument with spaces',
                                    '--closed-fd', str(inherited.fileno())], env=environment,
                                   pass_fds=(inherited.fileno(),), capture_output=True, text=True, timeout=10)
        assert child.returncode == 0 and not child.stderr
        child = subprocess.run(['/bin/bash', str(entry), 'argument with spaces'], env=environment,
                               preexec_fn=lambda: os.close(0), capture_output=True, text=True, timeout=10)
        assert child.returncode == 0 and not child.stderr
        # A separate, unfiltered guest process creates an actual new endpoint.
        # The exact observer runs inside the confined bootstrap and retains that
        # delta without assigning ownership or vetoing an otherwise safe run.
        baseline_command = observation_functions + b'capture_listeners\n'
        baseline = subprocess.run(['/bin/bash', '-s'], input=baseline_command,
                                  env=environment, capture_output=True, timeout=5)
        assert baseline.returncode == 0 and not baseline.stderr
        run = Path(root) / 'run.native1234'
        run.mkdir(mode=0o700)
        (run / 'listeners.before').write_bytes(baseline.stdout)
        (run / 'listeners.before').chmod(0o600)
        entry.chmod(0o600)
        entry.write_bytes(policy.ENTRY_PREFIX + policy.BODY_MARKER +
                          b'set -euo pipefail\n' + observation_functions +
                          b'RUN_ROOT=$1; RUN="$1/run.native1234"; MODE=host-network-tests\n'
                          b'RUN_ID=$(/usr/bin/stat -c "%d:%i" "$RUN"); OUTER_SOURCE=$2\n'
                          b'LISTENER_OBSERVATION_NUMBER=0\n'
                          b'LISTENERS_BEFORE="$RUN/listeners.before"\n'
                          b'LISTENERS_DURING="$RUN/listeners.during"\n'
                          b'LISTENERS_AFTER="$RUN/listeners.after"\n'
                          b'umask 077\n'
                          b'report_listener_delta before ""\n'
                          b'capture_listeners >"$LISTENERS_DURING"\n'
                          b'/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_DURING" >"$RUN/added.listeners"\n'
                          b'report_listener_delta during "$RUN/added.listeners"\n'
                          b'capture_listeners >"$LISTENERS_AFTER"\n'
                          b'/usr/bin/comm -13 "$LISTENERS_BEFORE" "$LISTENERS_AFTER" >"$RUN/after-added.listeners"\n'
                          b'report_listener_delta after "$RUN/after-added.listeners"\n')
        entry.chmod(0o400)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as external:
            external.bind(('127.0.0.1', 0))
            endpoint = f'udp 127.0.0.1:{external.getsockname()[1]}\n'.encode()
            child = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), str(OBSERVER)],
                                   env=environment, capture_output=True, text=True, timeout=10)
            assert child.returncode == 0 and not child.stderr, (child.returncode, child.stdout, child.stderr)
            lines = child.stdout.splitlines()
            assert len(lines) == 6 and sum(line.startswith('VERIFIER_VM_HOST_LISTENER_EVIDENCE=retained ') for line in lines) == 3
            assert lines[3] == 'VERIFIER_VM_HOST_ENDPOINT_DELTA=unattributed phase=during added=1'
            assert lines[5] == 'VERIFIER_VM_HOST_ENDPOINT_DELTA=unattributed phase=after added=1'
            assert (run / 'added.listeners').read_bytes() == endpoint
            assert set(baseline.stdout.splitlines()) <= set(
                (run / 'listeners.during').read_bytes().splitlines())
            evidence = sorted(Path(root).glob('host-network-tests-run.native1234.listeners.*.json'))
            assert len(evidence) == 3
            pinned = {path.name: path.read_bytes() for path in evidence}
            # Occupied outputs refuse without changing existing evidence.
            repeated = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), str(OBSERVER)],
                                      env=environment, capture_output=True, text=True, timeout=10)
            assert repeated.returncode != 0 and 'FileExistsError' in repeated.stderr
            assert all(path.read_bytes() == pinned[path.name] for path in evidence)
            for path in run.iterdir():
                path.unlink()
            run.rmdir()
            for path in evidence:
                data = path.read_bytes()
                document = json.loads(data)
                assert document['entry_sha256'] == hashlib.sha256(observer).hexdigest()
                assert document['ownership'] == 'unattributed'
                assert base64.b64decode(document['baseline']['base64'], validate=True) == baseline.stdout
                added = base64.b64decode(document['added']['base64'], validate=True)
                assert added == (b'' if document['phase'] == 'before' else endpoint)
                assert base64.b64decode(document['removed']['base64'], validate=True) == b''
                for value in (document[key] for key in ('baseline', 'snapshot', 'added', 'removed')):
                    raw = base64.b64decode(value['base64'], validate=True)
                    assert value['bytes'] == len(raw) and value['sha256'] == hashlib.sha256(raw).hexdigest()
                assert path.stat().st_mode & 0o777 == 0o400 and path.stat().st_nlink == 1
            run.mkdir(mode=0o700)
            before_file = run / 'listeners.before'
            before_file.write_bytes(baseline.stdout)
            before_file.chmod(0o600)
            sentinel = Path(root) / 'sentinel'
            sentinel.write_bytes(b'preserve-owned-sentinel')
            evidence[0].unlink()
            evidence[0].symlink_to(sentinel)
            rejected = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), str(OBSERVER)],
                                      env=environment, capture_output=True, text=True, timeout=10)
            assert rejected.returncode != 0 and 'FileExistsError' in rejected.stderr
            assert evidence[0].is_symlink() and sentinel.read_bytes() == b'preserve-owned-sentinel'
            before_file.unlink()
            before_file.symlink_to(sentinel)
            rejected = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), str(OBSERVER)],
                                      env=environment, capture_output=True, text=True, timeout=10)
            assert rejected.returncode != 0 and 'Too many levels of symbolic links' in rejected.stderr
            assert sentinel.read_bytes() == b'preserve-owned-sentinel'
            before_file.unlink()
            before_file.write_bytes(b'x' * 1048577)
            before_file.chmod(0o600)
            rejected = subprocess.run(['/usr/bin/python3', '-B', '-I', '-S', str(helper), str(OBSERVER)],
                                      env=environment, capture_output=True, text=True, timeout=10)
            assert rejected.returncode != 0 and 'AssertionError' in rejected.stderr
            assert evidence[0].is_symlink() and sentinel.read_bytes() == b'preserve-owned-sentinel'
        retired = subprocess.run(['/bin/bash', '-s'], input=baseline_command,
                                 env=environment, capture_output=True, timeout=5)
        assert retired.returncode == 0 and not retired.stderr and retired.stdout == baseline.stdout
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == before
    assert OBSERVER.read_bytes() == observer
    print('VM_HOST_NETWORK_NATIVE=' + json.dumps({
        'ip_controls': 4, 'socket_denials': 141, 'socketpair_denials': 48,
        'netlink_protocol_denials': 31, 'upper_word_denials': 1,
        'blocked_syscalls': len(policy.DENY_SYSCALLS), 'inherited_worker': True,
        'x32': 'SIGSYS', 'i386': 'SIGSYS', 'unix_control': 'roundtrip', 'unix_socketpair': 'roundtrip',
        'ss': 'protocol-endpoint-only', 'bootstrap': 'sealed-body-executed',
        'extra_inherited_ip_fd': 'closed', 'ip_stdout': 'refused',
        'closed_stdin': 'sealed-body-executed',
        'bash_env': 'ignored',
        'external_listener_delta': 'retained-unattributed', 'external_listener_additions': 1,
        'listener_evidence': 'exact-bytes-retained-after-run-retirement',
        'listener_evidence_phases': 3, 'listener_evidence_occupied': 'preserved-refused',
        'listener_evidence_output_symlink': 'preserved-refused',
        'listener_evidence_input_symlink': 'refused', 'listener_evidence_oversize': 'refused',
        'observer_sha256': hashlib.sha256(observer).hexdigest(),
        'source_sha256': before, 'source_unchanged': True,
    }, sort_keys=True))
    print('VM_HOST_NETWORK_TESTS=pass controls=4 restrictions=native inheritance=fork-exec '
          'unix=roundtrip netlink=socket-diag ip=denied x32=SIGSYS descriptors=closed-or-refused')


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        worker()
    elif sys.argv[1:] == ['--x32']:
        LIBC.syscall(0x40000000 | 41, socket.AF_INET, socket.SOCK_DGRAM, 0)
        raise AssertionError('x32 syscall was not killed')
    elif sys.argv[1:] == ['--i386']:
        # int 0x80 socketcall(1, NULL): the compat ABI must die before argument lookup.
        with mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC) as code:
            code.write(bytes.fromhex('b866000000bb0100000031c9cd80c3'))
            address = ctypes.addressof(ctypes.c_char.from_buffer(code))
            ctypes.CFUNCTYPE(ctypes.c_long)(address)()
        raise AssertionError('i386 socketcall was not killed')
    elif len(sys.argv) >= 2 and sys.argv[1] == '--inherited':
        assert sys.argv[2:] in ([], ['argument with spaces']) or (
            len(sys.argv) == 5 and sys.argv[2:4] == ['argument with spaces', '--closed-fd'])
        if len(sys.argv) == 5:
            try:
                os.fstat(int(sys.argv[4]))
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                raise AssertionError('extra inherited socket descriptor remained open')
        restriction_cases()
        print('inherited restrictions passed')
    else:
        main()

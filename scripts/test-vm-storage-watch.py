#!/usr/bin/env python3
"""Exercise production watch with native filesystem faults inside the verifier VM."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace


def publish(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output)


def worker(helper, base, scenario):
    spec = importlib.util.spec_from_file_location('storage_watch_subject', helper)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    base = Path(base)
    run = base / 'run'
    target = run / ('blocked/diagnostic' if scenario == 'permission' else 'transient')
    original = Path.rglob
    samples = 0

    def enumerate_entries(path, pattern):
        nonlocal samples
        if path != run:
            yield from original(path, pattern)
            return
        samples += 1
        entries = list(original(path, pattern))
        if samples == 2:
            publish(base / 'second-sample', {'observed': True})
        for entry in entries:
            if samples == 1 and entry == target and scenario != 'headroom':
                # Schedule the real removal/access change after enumeration and
                # before production lstat. No stat result or exception is faked.
                if scenario == 'permission':
                    os.chmod(target.parent, 0)
                else:
                    target.unlink()
                publish(base / 'fault', {'scenario': scenario})
            yield entry

    Path.rglob = enumerate_entries
    # File-lifetime tests run in a 2-GiB guest. Control this separate observation;
    # production thresholds and the outer VM's real admission remain unchanged.
    subject.available_memory = lambda: subject.HEADROOM + (
        -1 if scenario == 'headroom' else 64 * 1024 ** 2)
    workspace = base / 'workspace'
    identity = workspace.stat()
    try:
        subject.watch(SimpleNamespace(
            memory_mib=2048, storage_profile='ledger-token-count',
            workspace=str(workspace), identity=f'{identity.st_dev}:{identity.st_ino}',
            parent=os.getppid(), run=str(run), ready=str(base / 'ready'),
            stop=str(run / 'stop'), receipt=str(base / 'receipt')))
    finally:
        Path.rglob = original


def wait_for(path, child):
    deadline = time.monotonic() + 3
    while not path.exists():
        if child.poll() is not None or time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def qmp_child(base, scenario):
    base = Path(base)

    def term(signum, frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        publish(base / 'term', {'signal': signum})
        if scenario == 'graceful':
            raise SystemExit(0)

    signal.signal(signal.SIGTERM, term)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.bind(str(base / 'run/qmp.sock'))
        channel.listen(1)
        connection, _ = channel.accept()
        with connection, connection.makefile('rb') as incoming:
            connection.sendall(b'{"QMP": {}}\n')
            for name in ('qmp_capabilities', 'query-status', 'cont'):
                request = json.loads(incoming.readline(4096))
                assert request == {'execute': name, 'id': name}
                result = {'status': 'prelaunch'} if name == 'query-status' else {}
                connection.sendall(json.dumps({'return': result, 'id': name}).encode() + b'\n')
    publish(base / 'running', {'pid': os.getpid()})
    if scenario == 'normal':
        deadline = time.monotonic() + 10
        while not (base / 'release').exists():
            assert time.monotonic() < deadline, 'normal child was not released'
            time.sleep(0.01)
    else:
        while True:
            signal.pause()


def supervisor_worker(helper, base, scenario):
    spec = importlib.util.spec_from_file_location('storage_supervisor_subject', helper)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    original = subprocess.Popen

    def launch(argv, **kwargs):
        assert argv == ['/usr/bin/qemu-system-x86_64', '-S']
        return original([sys.executable, '-B', '-I', '-S', __file__,
                         '--qmp-child', base, scenario], **kwargs)

    # Only executable selection is substituted. The production supervisor owns
    # the real child, pidfd, signals, prlimit, QMP exchange, wait and receipt.
    subject.subprocess.Popen = launch
    try:
        result = subject.run_qemu(SimpleNamespace(
            memory_mib=2048, storage_profile='ledger-token-count',
            run=str(Path(base) / 'run'), qmp=str(Path(base) / 'run/qmp.sock'),
            qemu=['/usr/bin/qemu-system-x86_64']))
        raise SystemExit(result if result >= 0 else 128 - result)
    finally:
        subject.subprocess.Popen = original


def run_supervisor_case(helper, scenario):
    child_identity = None
    supervisor = None
    with tempfile.TemporaryDirectory(prefix='storage-supervisor.', dir='/dev/shm') as name:
        base = Path(name)
        (base / 'run').mkdir(mode=0o700)
        try:
            supervisor = subprocess.Popen(
                [sys.executable, '-B', '-I', '-S', __file__, '--supervise',
                 helper, name, scenario], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                umask=0o077)
            assert wait_for(base / 'running', supervisor), 'native child did not start'
            child_pid = json.loads((base / 'running').read_bytes())['pid']
            child_identity = os.pidfd_open(child_pid)
            began = time.monotonic()
            if scenario == 'normal':
                publish(base / 'release', {'ready': True})
            else:
                supervisor.send_signal(signal.SIGTERM)
                assert wait_for(base / 'term', supervisor), 'supervisor did not forward TERM'
                if scenario == 'stubborn':
                    supervisor.send_signal(signal.SIGTERM)
            forced = False
            try:
                output, error = supervisor.communicate(timeout=7)
            except subprocess.TimeoutExpired:
                forced = True
                signal.pidfd_send_signal(child_identity, signal.SIGKILL)
                output, error = supervisor.communicate(timeout=3)
            elapsed = time.monotonic() - began
            assert len(output) + len(error) <= 8192, 'supervisor diagnostics exceed their bound'
            receipt = json.loads((base / 'run/storage.qemu-io').read_bytes())
            limit = json.loads((base / 'run/storage.limit').read_bytes())
            expected = -signal.SIGKILL if scenario == 'stubborn' else 0
            passed = (not forced and receipt['qemu_pid'] == child_pid
                      and receipt['returncode'] == expected
                      and not Path(f'/proc/{child_pid}').exists()
                      and limit['qemu_pid'] == child_pid
                      and limit['hard_file_limit_bytes'] == 1024 ** 3
                      and limit['limit_installed_before_guest_execution'] is True
                      and (supervisor.returncode == 0 if scenario == 'normal'
                           else supervisor.returncode in (0, 1)))
            return {'case': scenario, 'passed': passed,
                    'supervisor_exit': supervisor.returncode,
                    'elapsed_seconds': round(elapsed, 3), 'fixture_forced_cleanup': forced,
                    'receipt': receipt, 'limit': limit, 'child': 'native-python-qmp-surrogate',
                    'children': 'joined', 'qemu': 'not-started',
                    'stderr': error.decode(errors='replace')[-2048:]}
        finally:
            if child_identity is not None:
                try:
                    signal.pidfd_send_signal(child_identity, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(child_identity)
            if supervisor is not None and supervisor.poll() is None:
                supervisor.terminate()
                try:
                    supervisor.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    supervisor.kill()
                    supervisor.communicate(timeout=3)


def run_case(helper, scenario):
    terms = []
    previous = signal.signal(signal.SIGTERM, lambda signum, frame: terms.append(signum))
    child = None
    endpoint = None
    with tempfile.TemporaryDirectory(prefix='storage-watch.', dir='/dev/shm') as name:
        base = Path(name)
        run = base / 'run'
        run.mkdir(mode=0o700)
        (base / 'workspace').mkdir(mode=0o700)
        keep = run / 'keep'
        keep.write_bytes(b'x' * 4096)
        minimum_allocation = keep.stat().st_blocks * 512
        target = run / 'transient'
        if scenario == 'socket':
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            endpoint.bind(str(target))
        elif scenario == 'permission':
            (run / 'blocked').mkdir(mode=0o700)
            (run / 'blocked/diagnostic').write_bytes(b'private')
        else:
            target.write_bytes(b'transient')
        try:
            child = subprocess.Popen(
                [sys.executable, '-B', '-I', '-S', __file__, '--worker', helper,
                 str(base), scenario], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ready = wait_for(base / 'ready', child)
            second_sample = False
            if scenario in ('socket', 'regular'):
                second_sample = wait_for(base / 'second-sample', child)
                if second_sample:
                    # This tests receipt consumption, not a QEMU launch/wait.
                    fixture = {'qemu_pid': os.getpid(), 'returncode': 0, 'write_bytes': 0}
                    publish(run / 'storage.qemu-io', fixture)
                    publish(run / 'stop', {'fixture': True})
            output, error = child.communicate(timeout=3)
            assert len(output) + len(error) <= 8192, 'watch diagnostics exceed their bound'
            receipt = json.loads((base / 'receipt').read_bytes())
            fault = (base / 'fault').exists()
            if scenario in ('socket', 'regular'):
                passed = (ready and fault and second_sample and child.returncode == 0
                          and not terms and receipt['reason'] == 'completed'
                          and receipt['qemu_io'] == fixture
                          and receipt['qemu_io_source'] == 'supervisor-waited-child-rusage'
                          and receipt['durable_run_peak_allocated_bytes'] >= minimum_allocation)
            else:
                expected = 'PermissionError:' if scenario == 'permission' else 'memory-headroom'
                passed = (ready and child.returncode != 0 and terms == [signal.SIGTERM]
                          and receipt['reason'].startswith(expected)
                          and receipt['qemu_io'] is None
                          and (fault if scenario == 'permission' else not fault))
            return {'case': scenario, 'passed': passed, 'monitor_exit': child.returncode,
                    'signals': terms, 'fault_triggered': fault,
                    'second_sample': second_sample, 'reason': receipt['reason'],
                    'samples': receipt['samples'], 'receipt': receipt,
                    'stderr': error.decode(errors='replace')[-2048:],
                    'filesystem': 'native', 'schedule': 'controlled',
                    'memory_observer': 'fixed', 'qemu_receipt': 'fixture-only',
                    'children': 'joined'}
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate(timeout=3)
            if endpoint is not None:
                endpoint.close()
            if (run / 'blocked').exists():
                os.chmod(run / 'blocked', 0o700)
            signal.signal(signal.SIGTERM, previous)


def main():
    if os.geteuid() != 4000 or os.getegid() != 4000:
        raise SystemExit('storage-watch fixture requires verifier guest principal 4000')
    if len(sys.argv) == 5 and sys.argv[1] == '--worker':
        worker(*sys.argv[2:])
        return
    if len(sys.argv) == 5 and sys.argv[1] == '--supervise':
        supervisor_worker(*sys.argv[2:])
        return
    if len(sys.argv) == 4 and sys.argv[1] == '--qmp-child':
        qmp_child(*sys.argv[2:])
        return
    if len(sys.argv) != 2:
        raise SystemExit('expected one production storage helper')
    results = [run_case(sys.argv[1], case)
               for case in ('socket', 'regular', 'permission', 'headroom')]
    for result in results:
        print('VM_TRANSIENT_WATCH_CASE=' + json.dumps(result, sort_keys=True), flush=True)
    if not all(result['passed'] for result in results):
        raise SystemExit('production storage watch regression failed')
    print('VM_TRANSIENT_WATCH=pass cases=4 disappeared=2 refusals=2 filesystem=native '
          'schedule=controlled memory=fixed qemu=not-started children=joined')
    results = [run_supervisor_case(sys.argv[1], case)
               for case in ('normal', 'graceful', 'stubborn')]
    for result in results:
        print('VM_TRANSIENT_SUPERVISOR_CASE=' + json.dumps(result, sort_keys=True), flush=True)
    if not all(result['passed'] for result in results):
        raise SystemExit('production storage supervisor cancellation regression failed')
    print('VM_TRANSIENT_SUPERVISOR=pass cases=3 normal=joined graceful=joined stubborn=killed-joined '
          'signals=pidfd qmp=fixture qemu=not-started')


if __name__ == '__main__':
    main()

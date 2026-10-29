#!/usr/bin/env python3
"""Run extracted startup/transport code against real Unix listeners in the owned VM."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import tomllib

ROOT = Path('/var/tmp/rustdesk-verifier-authority')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build():
    require(os.getuid() == 1000 and Path('/.dockerenv').is_file(), 'confined builder required')
    repo = Path('/source')
    work = Path('/cargo-target/listener-component')
    work.mkdir()
    spec = importlib.util.spec_from_file_location('listener_parser', repo / 'scripts/verify-linux-service-password-ipc.py')
    parser = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = parser
    spec.loader.exec_module(parser)

    def parsed(path):
        return parser.RustSource.parse(str(path), path.read_text())

    def function(source, name, *, index=None, parent=None):
        starts = [i for i, t in enumerate(source.tokens[:-1]) if t.text == 'fn'
                  and source.tokens[i + 1].text == name and source.brace_parent[i] == parent]
        require(len(starts) == (2 if index is not None else 1), f'ambiguous function: {name}')
        chosen = 0 if index is None else index
        start = starts[chosen]
        if source.tokens[start - 1].text == 'async':
            start -= 1
        body = source.functions(name, parent=parent)[chosen]
        return 'pub(crate) ' + source.text[source.tokens[start].offset:source.tokens[body.end].offset + 1] + '\n'

    fs_source = parsed(repo / 'src/ipc/fs.rs')
    guard = fs_source.impl(('impl', 'Drop', 'for', 'FdGuard'), 'fd guard')
    filesystem = fs_source.text[fs_source.text.index('struct FdGuard(i32);'):fs_source.tokens[guard.end].offset + 1] + '\n'
    for name in ('open_ipc_parent_dir_fd', 'remove_parent_entry_via_fd', 'remove_ipc_socket_via_secure_parent_fd',
                 'probe_existing_listener', 'existing_listener_identity_is_acceptable', 'current_euid', 'check_existing_listener',
                 'expected_ipc_parent_mode', 'scrub_preexisting_ipc_parent_entries',
                 'recreate_foreign_service_ipc_parent_dir', 'should_recreate_foreign_service_ipc_parent',
                 'verify_linux_service_ipc_namespace', 'ensure_secure_ipc_parent_dir',
                 'scrub_secure_ipc_parent_dir', 'should_scrub_parent_entries_after_listener_check'):
        filesystem += function(fs_source, name)
    if fs_source.functions('connect_existing_listener'):
        filesystem += function(fs_source, 'connect_existing_listener')
    if fs_source.functions('prepare_ipc_listener_bind'):
        filesystem += function(fs_source, 'prepare_ipc_listener_bind')
    (work / 'filesystem.rs').write_text(filesystem)
    auth = parsed(repo / 'src/ipc/auth.rs')
    identity = ''.join(function(auth, name) for name in (
        'peer_cred_from_fd', 'peer_uid_from_fd', 'peer_pid_from_fd', 'current_exe_canonical_path',
        'executable_paths_match', 'peer_executable_is_current_by_pid', 'validate_linux_root_service_peer'))
    identity += function(auth, 'peer_exe_canonical_path_by_pid', index=0)
    # Root-level helpers have crate visibility rather than a parent module.
    (work / 'identity.rs').write_text(identity.replace('pub(crate) ', ''))
    ipc = parsed(repo / 'src/ipc.rs')
    transport = ''.join(function(ipc, name) for name in ('connect', 'connect_with_path', 'new_listener'))
    (work / 'transport.rs').write_text(transport.replace('pub(crate) ', ''))
    connection = ''
    for name in ('SERVICE_IPC_MAX_FRAME_BYTES', 'MAIN_IPC_MAX_FRAME_BYTES', 'SERVICE_IPC_REQUEST_TIMEOUT_MS'):
        start = ipc.all().require(('const', name), 'connection constant', unique=True)
        end = next(i for i in range(start, len(ipc.tokens)) if ipc.tokens[i].text == ';')
        connection += ipc.text[ipc.tokens[start].offset:ipc.tokens[end].offset + 1] + '\n'
    for kind, name in (('enum', 'ServiceIpcRequest'), ('enum', 'ServiceIpcResponse'), ('struct', 'ConnectionTmpl')):
        body = ipc.item(kind, name)
        start = ipc.all().require((kind, name), 'connection item', unique=True)
        offset = ipc.tokens[start].offset
        if kind == 'enum':
            offset = ipc.text.rindex('#[derive(', 0, offset)
        connection += ipc.text[offset:ipc.tokens[body.end].offset + 1] + '\n'
    methods = ipc.impl(('impl', '<', 'T', '>', 'ConnectionTmpl', '<', 'T', '>'), 'connection methods')
    connection += 'impl<T: AsyncRead + AsyncWrite + Unpin> ConnectionTmpl<T> {\n'
    for name in ('new', 'new_with_max_packet_length', 'new_protected_service', 'new_main',
                 'send_json', 'send_json_timeout', 'next_json', 'send_service_request_timeout',
                 'next_service_request_timeout', 'send_service_response_timeout',
                 'next_service_response_timeout', 'set_max_packet_length'):
        connection += function(ipc, name, parent=methods.start - 1)
    connection += '}\nimpl<T: AsyncRead + AsyncWrite + Unpin + AsRawFd> ConnectionTmpl<T> {\n'
    peers = auth.impl(('impl', '<', 'T', '>', 'ConnectionTmpl', '<', 'T', '>'), 'peer methods')
    connection += ''.join(function(auth, name, parent=peers.start - 1) for name in ('peer_uid', 'peer_pid'))
    connection += '}\n' + function(ipc, 'handle_service_request')
    (work / 'connection.rs').write_text(connection)
    shutil.copyfile(repo / 'libs/hbb_common/src/bytes_codec.rs', work / 'bytes_codec.rs')
    config = parsed(repo / 'libs/hbb_common/src/config.rs')
    (work / 'config.rs').write_text(''.join(function(config, name) for name in (
        'is_service_ipc_postfix', 'ipc_parent_dir_for_uid')))
    shutil.copyfile(repo / 'scripts/test-linux-ipc-listener.rs', work / 'main.rs')
    (work / 'Cargo.toml').write_text('''[package]
name = "ipc-listener-component"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "ipc-listener"
path = "main.rs"
[dependencies]
anyhow = "=1.0.103"
bytes = "=1.11.1"
futures-util = { version = "=0.3.31", features = ["sink"] }
libc = "=0.2.171"
log = "=0.4.22"
serde = { version = "=1.0.228", features = ["derive"] }
serde_json = "=1.0.118"
socket2 = "=0.5.10"
tokio = { version = "=1.44.2", features = ["rt", "net", "time", "io-util"] }
tokio-util = { version = "=0.7.15", features = ["codec"] }
parity-tokio-ipc = { git = "https://github.com/rustdesk-org/parity-tokio-ipc" }
[profile.dev]
debug = 0
incremental = false
''')
    shutil.copyfile(repo / 'Cargo.lock', work / 'Cargo.lock')
    env = dict(ENV, CARGO_HOME='/tmp/cargo-home', CARGO_TARGET_DIR=str(work / 'target'),
               RUSTC='/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/rustc')
    command = ['/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/cargo',
               'build', '--offline', '--manifest-path', str(work / 'Cargo.toml'), '--jobs', '1']
    subprocess.run(command, env=env, check=True, timeout=180)
    root_packages = tomllib.loads((repo / 'Cargo.lock').read_text())['package']
    for package in tomllib.loads((work / 'Cargo.lock').read_text())['package']:
        if package['name'] == 'ipc-listener-component':
            continue
        require(any(all(package.get(k) == p.get(k) for k in ('name', 'version', 'source', 'checksum'))
                    for p in root_packages), f'dependency escaped root lock: {package["name"]}')
    binary = Path('/cargo-target/ipc-listener')
    shutil.copyfile(work / 'target/debug/ipc-listener', binary)
    binary.chmod(0o555)
    require(binary.stat().st_size < 64 * 1024 * 1024, 'binary exceeds bound')
    barrier = Path('/cargo-target/ipc-listener-barrier.so')
    subprocess.run(['/usr/bin/cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    str(repo / 'scripts/test-linux-ipc-listener-barrier.c'), '-ldl', '-o', str(barrier)],
                   env=ENV, check=True, timeout=30)
    print(f'LINUX_IPC_LISTENER_BUILD=pass artifact_sha256={sha(binary)} '
          f'fs_fragment_sha256={hashlib.sha256(filesystem.encode()).hexdigest()} '
          f'barrier_sha256={sha(barrier)} '
          f'connection_fragment_sha256={hashlib.sha256(connection.encode()).hexdigest()} '
          f'codec_sha256={sha(work / "bytes_codec.rs")} '
          'transport=parity-tokio-ipc-root-locked framing=production', flush=True)


def native(expected_sha, barrier_sha):
    require(os.geteuid() == 0 and Path('/run/rustdesk-verifier-vm').stat().st_uid == 0
            and Path('/proc/1/comm').read_text().strip() == 'systemd'
            and sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
            and Path(__file__).resolve().parent.parent == ROOT / 'focused-rust-test-source',
            'owned zero-NIC VM required')
    artifact = ROOT / 'focused-rust-test-target/ipc-listener'
    metadata = artifact.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000 and metadata.st_nlink == 1
            and metadata.st_size < 64 * 1024 * 1024 and sha(artifact) == expected_sha,
            f'artifact differs: uid={metadata.st_uid} links={metadata.st_nlink} size={metadata.st_size}')
    work = ROOT / 'ipc-listener-native'
    work.mkdir(mode=0o755)
    work.chmod(0o755)
    probe = work / 'probe'
    shutil.copyfile(artifact, probe)
    probe.chmod(0o555)
    barrier_input = ROOT / 'focused-rust-test-target/ipc-listener-barrier.so'
    metadata = barrier_input.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000 and metadata.st_nlink == 1
            and metadata.st_size < 1048576 and sha(barrier_input) == barrier_sha, 'barrier differs')
    barrier = work / 'barrier.so'
    shutil.copyfile(barrier_input, barrier); barrier.chmod(0o555)
    parents = [Path('/run/RustDesk-service'), Path('/tmp/RustDesk-0'), Path('/tmp/RustDesk-4001')]
    for parent, uid in zip(parents, (0, 0, 4001)):
        require(not os.path.lexists(parent), 'fixture parent already exists')
        parent.mkdir(mode=0o711 if parent == parents[0] else 0o700)
        os.chown(parent, uid, uid)
    fd_before = len(list(Path('/proc/self/fd').iterdir()))
    failures, cases = [], []

    def path(postfix, uid=0):
        return (parents[0] if postfix.startswith('_service') else parents[2] if uid else parents[1]) / ('ipc' + postfix)

    def command(action, postfix, uid=0):
        return dict(args=[str(probe), action, postfix], env=ENV, user=uid, group=uid, extra_groups=[])

    def check(postfix, uid=0, action='try-start'):
        result = subprocess.run(**command(action, postfix, uid), capture_output=True, text=True, timeout=5)
        require(len(result.stdout) + len(result.stderr) < 65536, 'output exceeds bound')
        return result

    def record(name, passed, result):
        cases.append(name)
        if not passed:
            failures.append(name)
        print(f'LINUX_IPC_LISTENER_CASE={"pass" if passed else "fail"} name={name} '
              f'exit={result.returncode} stdout={result.stdout.strip()!r} stderr={result.stderr.strip()!r}', flush=True)

    for postfix in ('_password', '_service_password', '_service_credential', ''):
        uid = 4001 if postfix == '_password' else 0
        endpoint = path(postfix, uid)
        child = subprocess.Popen(**command('listen', postfix, uid), stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            require(select.select([child.stdout], [], [], 5)[0] and child.stdout.readline() == 'READY\n', 'listener failed')
            before = endpoint.lstat()
            result = check(postfix, uid)
            preserved = endpoint.exists() and endpoint.lstat().st_ino == before.st_ino
            record('active-' + (postfix or 'main'), result.returncode == 3 and preserved, result)
        finally:
            child.communicate('stop\n', timeout=5)
            require(child.returncode == 0, 'listener did not join')
            endpoint.unlink(missing_ok=True)

    for name, uid in (('backlog-full', 0), ('permission-denied', 4001)):
        endpoint = path('', uid)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint)); listener.listen(0)
            before = endpoint.lstat()
            filler = None
            try:
                if uid:
                    endpoint.chmod(0)
                else:
                    filler = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    filler.settimeout(2); filler.connect(str(endpoint))
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as extra:
                        extra.setblocking(False)
                        import errno
                        require(extra.connect_ex(str(endpoint)) == errno.EAGAIN, 'backlog is not full')
                result = check('', uid)
                record(name, result.returncode == 3 and endpoint.exists()
                       and endpoint.lstat().st_ino == before.st_ino, result)
            finally:
                if filler is not None:
                    filler.close()
                endpoint.unlink(missing_ok=True)

    endpoint = path('_service_password')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(str(endpoint))
    result = check('_service_password')
    record('stale-socket', result.returncode == 0 and result.stdout == 'OK started\n' and endpoint.is_socket(), result)
    endpoint.unlink(missing_ok=True)
    result = check('_service_password')
    record('missing-socket', result.returncode == 0 and result.stdout == 'OK started\n' and endpoint.is_socket(), result)
    endpoint.unlink(missing_ok=True)
    endpoint = path('')
    endpoint.mkdir(); (endpoint / 'keep').write_bytes(b'preserved')
    result = check('')
    record('cleanup-failure', result.returncode == 3 and (endpoint / 'keep').read_bytes() == b'preserved', result)
    (endpoint / 'keep').unlink(); endpoint.rmdir()

    endpoint = path('')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint)); listener.listen(8)
        before = endpoint.lstat()
        result = check('')
        record('foreign-image-live-preserved', result.returncode == 3 and endpoint.exists()
               and endpoint.lstat().st_ino == before.st_ino, result)
    endpoint.unlink(missing_ok=True)

    lock = path('_service_password').with_name('ipc_service_password.lock')
    lock.unlink(missing_ok=True)
    for kind in ('symlink', 'fifo', 'writable', 'foreign-owner', 'hardlink'):
        target = parents[0] / 'lock-target'
        if kind == 'symlink':
            target.write_bytes(b'keep'); lock.symlink_to(target)
        elif kind == 'fifo':
            os.mkfifo(lock, 0o600)
        else:
            lock.write_bytes(b'keep'); lock.chmod(0o600)
            if kind == 'writable':
                lock.chmod(0o666)
            elif kind == 'foreign-owner':
                os.chown(lock, 4001, 4001)
            else:
                os.link(lock, target)
        before = lock.lstat()
        result = check('_service_password')
        after = lock.lstat()
        record('unsafe-lock-' + kind, result.returncode == 3 and not path('_service_password').exists()
               and (before.st_ino, before.st_mode, before.st_uid, before.st_nlink)
               == (after.st_ino, after.st_mode, after.st_uid, after.st_nlink)
               and (kind == 'fifo' or lock.read_bytes() == b'keep'), result)
        lock.unlink(); target.unlink(missing_ok=True)

    # Pause before stale unlink (reservation held), or before reservation acquisition
    # (the asynchronous probe has finished). Each schedule uses real kernel operations.
    schedules = [(schedule, postfix, uid) for schedule in ('unlink', 'flock', 'crash')
                 for postfix, uid in (('_service_password', 0), ('_password', 4001))]
    for schedule, postfix, uid in schedules:
        endpoint = path(postfix, uid)
        label = postfix if schedule == 'unlink' else schedule + '-' + postfix
        other_postfix = '_service_credential' if uid == 0 else ''
        other_endpoint = path(other_postfix, uid)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            stale.bind(str(endpoint))
        endpoint.chmod(0o666)
        entered_r, entered_w = os.pipe()
        release_r, release_w = os.pipe()
        children = []
        try:
            launch = command('start', postfix, uid)
            launch['env'] = dict(ENV, LD_PRELOAD=str(barrier), IPC_BARRIER_ENTER=str(entered_w),
                                 IPC_BARRIER_RELEASE=str(release_r), IPC_BARRIER_ENTRY=endpoint.name,
                                 IPC_BARRIER_CALL='flock' if schedule == 'flock' else 'unlink')
            first = subprocess.Popen(**launch, pass_fds=(entered_w, release_r), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(first)
            os.close(entered_w); entered_w = None
            os.close(release_r); release_r = None
            require(select.select([entered_r], [], [], 5)[0] and os.read(entered_r, 1) == b'R', 'startup barrier not reached')
            if schedule == 'crash':
                lock = endpoint.with_name(endpoint.name + '.lock')
                lock_before = lock.lstat()
                first.kill(); first.communicate(timeout=5)
                require(first.returncode == -signal.SIGKILL, 'owned crash child did not join')
                children.remove(first)
                result = check(postfix, uid)
                record('crash-recovery-' + postfix, result.returncode == 0
                       and result.stdout == 'OK started\n' and endpoint.is_socket()
                       and lock.lstat().st_ino == lock_before.st_ino, result)
                continue
            second = subprocess.Popen(**command('start', postfix, uid), stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(second)
            require(select.select([second.stdout], [], [], 5)[0], 'competing startup did not finish')
            second_ready = second.stdout.readline() == 'READY\n'
            if not second_ready:
                second.wait(timeout=5)
            incumbent_inode = endpoint.lstat().st_ino if second_ready else None
            independent = subprocess.Popen(**command('start', other_postfix, uid), stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(independent)
            require(select.select([independent.stdout], [], [], 5)[0], 'independent startup did not finish')
            independent_ready = independent.stdout.readline() == 'READY\n'
            record('independent-start-' + label, independent_ready and other_endpoint.is_socket(),
                   subprocess.CompletedProcess([], 0 if independent_ready else 3, '', ''))
            os.write(release_w, b'G'); os.close(release_w); release_w = None
            require(select.select([first.stdout], [], [], 5)[0], 'first startup did not finish')
            first_ready = first.stdout.readline() == 'READY\n'
            if not first_ready:
                first.wait(timeout=5)
            owner, refused = (second, first) if schedule == 'flock' else (first, second)
            owner_ready, refused_ready = (second_ready, first_ready) if schedule == 'flock' else (first_ready, second_ready)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(2); peer.connect(str(endpoint))
                import struct
                connected_pid, connected_uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            result = subprocess.CompletedProcess([], refused.returncode if not refused_ready else 0,
                                                 f'first_ready={first_ready} second_ready={second_ready} connected_pid={connected_pid}', '')
            record('concurrent-start-' + label, owner_ready and not refused_ready and refused.returncode == 3
                   and connected_pid == owner.pid and connected_uid == uid
                   and (schedule != 'flock' or endpoint.lstat().st_ino == incumbent_inode), result)
        finally:
            if release_w is not None:
                try:
                    os.write(release_w, b'G')
                except BrokenPipeError:
                    pass
            for fd in (entered_r, entered_w, release_r, release_w):
                if fd is not None:
                    os.close(fd)
            cleanup_ok = True
            for child in children:
                try:
                    child.communicate('stop\n', timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.communicate(timeout=5)
                    cleanup_ok = False
                cleanup_ok = cleanup_ok and child.returncode in (0, 3)
            endpoint.unlink(missing_ok=True)
            other_endpoint.unlink(missing_ok=True)
            require(cleanup_ok, 'startup child did not join normally')
        result = check(postfix, uid)
        record('restart-after-contention-' + label, result.returncode == 0
               and result.stdout == 'OK started\n' and endpoint.is_socket(), result)
        endpoint.unlink(missing_ok=True)

    for kind in ('deleted', 'unreadable'):
        endpoint = path('_password', 4001)
        executable = work / 'unlinked-probe'
        launch = command('listen' if kind == 'deleted' else 'listen-unprovable', '_password', 4001)
        if kind == 'deleted':
            shutil.copyfile(probe, executable); executable.chmod(0o555)
            require(sha(executable) == expected_sha, 'identity fixture binary differs')
            launch['args'][0] = str(executable)
        child = subprocess.Popen(**launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            require(select.select([child.stdout], [], [], 5)[0] and child.stdout.readline() == 'READY\n',
                    'identity fixture listener failed')
            before = endpoint.lstat()
            if kind == 'deleted':
                executable.unlink()
                require(os.readlink(f'/proc/{child.pid}/exe').endswith(' (deleted)'), 'executable was not unlinked')
            passed = True
            for action in ('probe', 'try-start'):
                result = check('_password', 4001, action)
                expected = ('Failed to canonicalize peer executable path' if kind == 'deleted'
                            else 'Failed to read peer executable link')
                passed = passed and result.returncode == 3 and expected in result.stderr
                passed = passed and endpoint.exists() and endpoint.lstat().st_ino == before.st_ino
            record('identity-unavailable-' + kind, passed, result)
        finally:
            child.communicate('stop\n', timeout=5)
            require(child.returncode == 0, 'identity fixture child did not join')
            endpoint.unlink(missing_ok=True); executable.unlink(missing_ok=True)

    for scenario in ('valid', 'unknown-field', 'unknown-type', 'malformed',
                     'oversized', 'truncated', 'silent', 'disconnect'):
        endpoint = path('_service')
        child = subprocess.Popen(**command('service-' + scenario, '_service'),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            require(select.select([child.stdout], [], [], 5)[0] and child.stdout.readline() == 'READY\n',
                    'service listener failed')
            before = endpoint.lstat()
            passed = True
            elapsed = []
            for action in ('probe', 'try-start'):
                started = time.monotonic()
                result = check('_service', action=action)
                elapsed.append(time.monotonic() - started)
                require(select.select([child.stdout], [], [], 3)[0] and child.stdout.readline() == 'PROBE\n',
                        'typed liveness request was not received')
                preserved = endpoint.exists() and endpoint.lstat().st_ino == before.st_ino
                expected_exit = 0 if scenario == 'valid' and action == 'probe' else 3
                passed = passed and preserved and result.returncode == expected_exit
                if scenario == 'valid':
                    passed = passed and (result.stdout == 'OK alive\n' if action == 'probe'
                                         else 'ipc listener is active' in result.stderr)
                elif scenario in ('unknown-field', 'unknown-type', 'malformed'):
                    passed = passed and 'invalid liveness response' in result.stderr
                elif scenario == 'oversized':
                    passed = passed and 'Too big packet' in result.stderr
                elif scenario == 'truncated':
                    passed = passed and 'incomplete frame at end of stream' in result.stderr
                else:
                    passed = passed and 'liveness read failed' in result.stderr
                passed = passed and elapsed[-1] < 3.0
                if scenario == 'silent':
                    passed = passed and elapsed[-1] >= 0.75
            output, errors = child.communicate(timeout=5)
            passed = passed and child.returncode == 0 and not output and not errors
            record('service-liveness-' + scenario, passed,
                   subprocess.CompletedProcess([], child.returncode, f'seconds={elapsed}', errors))
        finally:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=5)
                raise RuntimeError('service fixture did not complete normally')
            endpoint.unlink(missing_ok=True)
    # Lock creation and recovery must not inherit missing owner access from umask.
    # Parents are already admitted; this tests the endpoint reservation itself.
    for postfix, uid in (('_service_password', 0), ('_password', 4001)):
        endpoint = path(postfix, uid)
        lock = endpoint.with_name(endpoint.name + '.lock')
        for mask in (0o200, 0o400, 0o600):
            for state in ('fresh', 'recovery'):
                lock.unlink(missing_ok=True)
                before = None
                if state == 'recovery':
                    lock.write_bytes(b'')
                    os.chown(lock, uid, uid)
                    lock.chmod(0o600 & ~mask)
                    before = lock.lstat()
                result = subprocess.run(**command('try-start', postfix, uid), umask=mask,
                                        capture_output=True, text=True, timeout=5)
                after = lock.lstat()
                record(f'lock-mask-{mask:03o}-{state}-{postfix}',
                       result.returncode == 0 and result.stdout == 'OK started\n'
                       and endpoint.is_socket() and stat.S_IMODE(after.st_mode) == 0o600
                       and after.st_uid == uid and after.st_nlink == 1
                       and (before is None or (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)), result)
                endpoint.unlink(missing_ok=True)
                lock.unlink()
    for parent in parents:
        for lock in parent.glob('ipc*.lock'):
            metadata = lock.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    and metadata.st_uid == parent.stat().st_uid and metadata.st_size == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o600, 'startup lock changed')
            lock.unlink()
        parent.rmdir()
    require(len(list(Path('/proc/self/fd').iterdir())) == fd_before, 'descriptor leaked')
    require(sha(probe) == expected_sha and sha(artifact) == expected_sha, 'artifact changed')
    require(sha(barrier) == barrier_sha, 'barrier changed')
    probe.unlink(); barrier.unlink(); work.rmdir()
    require(len(cases) == 51, 'case inventory differs')
    print(f'LINUX_IPC_LISTENER_NATIVE={"fail" if failures else "pass"} cases=51 failures={len(failures)} '
          f'artifact_sha256={expected_sha} cleanup=joined', flush=True)
    require(not failures, 'listener failures: ' + ','.join(failures))


if __name__ == '__main__':
    if sys.argv[1:] == ['build']:
        build()
    elif len(sys.argv) == 4 and sys.argv[1] == 'native':
        native(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('expected build or native ARTIFACT_SHA256 BARRIER_SHA256')

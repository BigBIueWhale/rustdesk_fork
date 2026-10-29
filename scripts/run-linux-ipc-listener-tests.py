#!/usr/bin/env python3
"""Run extracted startup/transport code against real Unix listeners in the owned VM."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import socket
import stat
import subprocess
import sys
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

    def function(source, name, *, index=None):
        starts = [i for i, t in enumerate(source.tokens[:-1]) if t.text == 'fn'
                  and source.tokens[i + 1].text == name and source.brace_parent[i] is None]
        require(len(starts) == (2 if index is not None else 1), f'ambiguous function: {name}')
        chosen = 0 if index is None else index
        start = starts[chosen]
        if source.tokens[start - 1].text == 'async':
            start -= 1
        body = source.functions(name)[chosen]
        return 'pub(crate) ' + source.text[source.tokens[start].offset:source.tokens[body.end].offset + 1] + '\n'

    fs_source = parsed(repo / 'src/ipc/fs.rs')
    guard = fs_source.impl(('impl', 'Drop', 'for', 'FdGuard'), 'fd guard')
    filesystem = fs_source.text[fs_source.text.index('struct FdGuard(i32);'):fs_source.tokens[guard.end].offset + 1] + '\n'
    for name in ('open_ipc_parent_dir_fd', 'remove_parent_entry_via_fd', 'remove_ipc_socket_via_secure_parent_fd',
                 'probe_existing_listener', 'existing_listener_identity_is_acceptable', 'current_euid', 'check_existing_listener'):
        filesystem += function(fs_source, name)
    if fs_source.functions('connect_existing_listener'):
        filesystem += function(fs_source, 'connect_existing_listener')
    (work / 'filesystem.rs').write_text(filesystem)
    auth = parsed(repo / 'src/ipc/auth.rs')
    identity = ''.join(function(auth, name) for name in (
        'peer_cred_from_fd', 'peer_uid_from_fd', 'peer_pid_from_fd', 'current_exe_canonical_path',
        'executable_paths_match', 'peer_executable_is_current_by_pid', 'validate_linux_root_service_peer'))
    identity += function(auth, 'peer_exe_canonical_path_by_pid', index=0)
    # Root-level helpers have crate visibility rather than a parent module.
    (work / 'identity.rs').write_text(identity.replace('pub(crate) ', ''))
    ipc = parsed(repo / 'src/ipc.rs')
    transport = ''.join(function(ipc, name) for name in ('connect', 'connect_with_path'))
    (work / 'transport.rs').write_text(transport.replace('pub(crate) ', ''))
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
libc = "=0.2.171"
log = "=0.4.22"
tokio = { version = "=1.44.2", features = ["full"] }
parity-tokio-ipc = { git = "https://github.com/rustdesk-org/parity-tokio-ipc" }
''')
    shutil.copyfile(repo / 'Cargo.lock', work / 'Cargo.lock')
    env = dict(ENV, CARGO_HOME='/tmp/cargo-home', CARGO_TARGET_DIR=str(work / 'target'),
               RUSTC='/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/rustc')
    command = ['/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/cargo',
               'build', '--offline', '--manifest-path', str(work / 'Cargo.toml'), '--jobs', '2']
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
    print(f'LINUX_IPC_LISTENER_BUILD=pass artifact_sha256={sha(binary)} '
          f'fs_fragment_sha256={hashlib.sha256(filesystem.encode()).hexdigest()} '
          'transport=parity-tokio-ipc-root-locked framing=unexecuted', flush=True)


def native(expected_sha):
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
    probe = work / 'probe'
    shutil.copyfile(artifact, probe)
    probe.chmod(0o555)
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

    def check(postfix, uid=0):
        result = subprocess.run(**command('check', postfix, uid), capture_output=True, text=True, timeout=5)
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
            record('active-' + (postfix or 'main'), result.returncode == 0 and result.stdout == 'OK true\n' and preserved, result)
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
    record('stale-socket', result.returncode == 0 and result.stdout == 'OK false\n' and not endpoint.exists(), result)
    endpoint.unlink(missing_ok=True)
    result = check('_service_password')
    record('missing-socket', result.returncode == 0 and result.stdout == 'OK false\n' and not endpoint.exists(), result)
    endpoint = path('')
    endpoint.mkdir(); (endpoint / 'keep').write_bytes(b'preserved')
    result = check('')
    record('cleanup-failure', result.returncode == 3 and (endpoint / 'keep').read_bytes() == b'preserved', result)
    (endpoint / 'keep').unlink(); endpoint.rmdir()
    for parent in parents:
        parent.rmdir()
    require(len(list(Path('/proc/self/fd').iterdir())) == fd_before, 'descriptor leaked')
    require(sha(probe) == expected_sha and sha(artifact) == expected_sha, 'artifact changed')
    probe.unlink(); work.rmdir()
    require(len(cases) == 9, 'case inventory differs')
    print(f'LINUX_IPC_LISTENER_NATIVE={"fail" if failures else "pass"} cases=9 failures={len(failures)} '
          f'artifact_sha256={expected_sha} cleanup=joined', flush=True)
    require(not failures, 'listener failures: ' + ','.join(failures))


if __name__ == '__main__':
    if sys.argv[1:] == ['build']:
        build()
    elif len(sys.argv) == 3 and sys.argv[1] == 'native':
        native(sys.argv[2])
    else:
        raise SystemExit('expected build or native ARTIFACT_SHA256')

#!/usr/bin/env python3
"""Compile exact IPC directory functions; exercise root/user authority only in the verifier VM."""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tomllib

VM_ROOT = Path('/var/tmp/rustdesk-verifier-authority')
WORK = VM_ROOT / 'ipc-parent-native'
FUNCTIONS = ('expected_ipc_parent_mode', 'open_ipc_parent_dir_fd',
             'remove_parent_entry_via_fd', 'scrub_preexisting_ipc_parent_entries',
             'recreate_foreign_service_ipc_parent_dir', 'should_recreate_foreign_service_ipc_parent',
             'verify_linux_service_ipc_namespace', 'ensure_secure_ipc_parent_dir', 'scrub_secure_ipc_parent_dir')
RUSTC = '/usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/rustc'
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp', 'RUSTC': RUSTC}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, *, uid=None, expected=0):
    options = {} if uid is None else {'user': uid, 'group': uid, 'extra_groups': []}
    result = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=30, **options)
    require(len(result.stdout) + len(result.stderr) < 65536, 'component output exceeded bound')
    require(result.returncode == expected, f'component command failed: {result.stdout} {result.stderr}')
    return result


def build():
    require(os.getuid() == 1000 and Path('/.dockerenv').is_file(), 'build requires confined non-root container')
    repo, target, dependency = Path('/source'), Path('/cargo-target'), Path('/ipc-libc')
    manifest = dependency / '.cargo-checksum.json'
    require(sha(manifest) == '5a88740676af47d478c6716f642ba0776016ef750a1dd3229654d38b0b297b6e',
            'libc manifest differs')
    checks = json.loads(manifest.read_bytes())
    locked = [p for p in tomllib.loads((repo / 'Cargo.lock').read_text())['package']
              if p['name'] == 'libc' and p['version'] == '0.2.171']
    require(len(locked) == 1 and checks['package'] == locked[0]['checksum'], 'libc root lock differs')
    require({str(p.relative_to(dependency)) for p in dependency.rglob('*') if p.is_file()}
            == set(checks['files']) | {'.cargo-checksum.json'}, 'libc file inventory differs')
    for name, digest in checks['files'].items():
        path = dependency / name
        require(not path.is_symlink() and sha(path) == digest, 'libc file identity differs')
    rustc = RUSTC
    require(run([rustc, '--version']).stdout.strip() == 'rustc 1.75.0 (82e1608df 2023-12-21)',
            'compiler differs')
    builder = target / 'libc-build'
    run([rustc, '--edition=2021', str(dependency / 'build.rs'), '-o', str(builder)])
    flags = [line.removeprefix('cargo:rustc-cfg=') for line in run([str(builder)]).stdout.splitlines()
             if line.startswith('cargo:rustc-cfg=')]
    require(flags == ['freebsd11', 'libc_const_extern_fn'], 'libc build configuration differs')
    library = target / 'liblibc.rlib'
    run([rustc, '--edition=2021', '--crate-name=libc', '--crate-type=rlib', '--cfg', 'feature="std"',
         *[arg for flag in flags for arg in ('--cfg', flag)], str(dependency / 'src/lib.rs'), '-o', str(library)])
    spec = importlib.util.spec_from_file_location('ipc_source', repo / 'scripts/verify-linux-service-password-ipc.py')
    parser = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = parser
    spec.loader.exec_module(parser)

    def function(parsed, name):
        body = parsed.function(name)
        starts = [t.offset for i, t in enumerate(parsed.tokens[:-1])
                  if t.text == 'fn' and parsed.tokens[i + 1].text == name
                  and parsed.brace_parent[i] is None]
        require(len(starts) == 1, 'production function is ambiguous')
        return parsed.text[starts[0]:parsed.tokens[body.end].offset + 1] + '\n'

    fs_path = repo / 'src/ipc/fs.rs'
    fs = parser.RustSource.parse(str(fs_path), fs_path.read_text())
    config_path = repo / 'libs/hbb_common/src/config.rs'
    config = parser.RustSource.parse(str(config_path), config_path.read_text())
    guard = fs.impl(('impl', 'Drop', 'for', 'FdGuard'), 'FdGuard destructor')
    start = fs.text.index('struct FdGuard(i32);')
    fragment = fs.text[start:fs.tokens[guard.end].offset + 1] + '\n'
    fragment += ''.join(function(fs, name) for name in FUNCTIONS)
    if fs.functions('ipc_descriptor_directory'):
        fragment += function(fs, 'ipc_descriptor_directory')
    generated = ('extern crate self as hbb_common;\npub extern crate libc;\n'
                 'type ResultType<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;\n'
                 'use std::{ffi::CString, io::{Error, ErrorKind}, os::unix::ffi::OsStrExt, path::Path};\n'
                 'mod config { static APP_NAME: std::sync::RwLock<&str> = std::sync::RwLock::new("RustDesk");\n'
                 'pub ' + function(config, 'is_service_ipc_postfix')
                 + 'pub ' + function(config, 'ipc_parent_dir_for_uid') + '}\n' + fragment
                 + (repo / 'scripts/test-linux-ipc-parent.rs').read_text())
    source = target / 'ipc-parent.rs'
    source.write_text(generated)
    binary = target / 'ipc-parent'
    run([rustc, '--edition=2021', '--extern', f'libc={library}', str(source), '-o', str(binary)])
    print(f'LINUX_IPC_PARENT_BUILD=pass artifact_sha256={sha(binary)} source_sha256={sha(fs_path)} '
          f'fragment_sha256={hashlib.sha256(fragment.encode()).hexdigest()} '
          f'config_sha256={sha(config_path)} libc=0.2.171 functions={len(FUNCTIONS) + bool(fs.functions("ipc_descriptor_directory"))} '
          'error_adapter=std-boxed name_adapter=RustDesk-rwlock', flush=True)


def native(expected_sha):
    require(os.geteuid() == 0 and Path('/run/rustdesk-verifier-vm').stat().st_uid == 0
            and Path('/proc/1/comm').read_text().strip() == 'systemd'
            and sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
            and Path(__file__).resolve().parent.parent == VM_ROOT / 'focused-rust-test-source',
            'native execution requires the owned zero-NIC verifier VM')
    artifact = VM_ROOT / 'focused-rust-test-target/ipc-parent'
    metadata = artifact.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_nlink == 1 and metadata.st_size < 16777216
            and sha(artifact) == expected_sha, 'built artifact differs')
    WORK.mkdir(mode=0o755)
    WORK.chmod(0o755)
    probe = WORK / 'probe'
    shutil.copyfile(artifact, probe)
    probe.chmod(0o555)
    require(sha(probe) == expected_sha and probe.stat().st_uid == 0, 'sealed probe differs')
    data = WORK / 'data'
    data.mkdir(mode=0o1777)
    data.chmod(0o1777)
    service = Path('/run/RustDesk-service')
    require(not os.path.lexists(service), 'service fixture already exists')
    fd_before = len(list(Path('/proc/self/fd').iterdir()))
    cases = []

    def actor(code, *args, uid=4001):
        return run(['/usr/bin/python3', '-I', '-S', '-c', code, *map(str, args)], uid=uid)

    def call(parent, postfix='_service', *, uid=0, action='ensure', refused=False):
        result = run([str(probe), action, str(parent / ('ipc' + postfix)), postfix],
                     uid=uid, expected=3 if refused else 0)
        if refused:
            require(not result.stdout and result.stderr.startswith('ERR '), 'refusal receipt differs')
            return None
        require(result.stdout in ('OK true\n', 'OK false\n') and not result.stderr, 'operation receipt differs')
        return result.stdout == 'OK true\n'

    def record(name):
        cases.append(name)
        print(f'LINUX_IPC_PARENT_CASE=pass name={name}', flush=True)

    def denied(code, *args):
        actor('import errno,os,pathlib,sys\ntry:\n ' + code + '\n'
              'except OSError as e:\n assert e.errno in (errno.EACCES,errno.EPERM)\n'
              'else:\n raise AssertionError("namespace mutation admitted")', *args)

    def identity(path):
        st = path.lstat()
        return st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode

    for postfix in ('_service', '_service_password', '_service_credential'):
        for uid in (0, 4001):
            result = run([str(probe), 'path', str(uid), postfix], uid=uid)
            require(result.stdout == str(service) + '\n' and not result.stderr, 'service route differs')
    for uid in (0, 4001):
        for postfix in ('', '_password'):
            result = run([str(probe), 'path', str(uid), postfix], uid=uid)
            require(result.stdout == f'/tmp/RustDesk-{uid}\n', 'user route changed')
    record('service-routing')

    import socket
    for postfix in ('_service', '_service_password', '_service_credential'):
        call(service, postfix)
        st = service.stat()
        require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o711, 'service mode/owner differs')
        require(call(service, postfix) is False, 'healthy parent requests scrub')
        endpoint = service / ('ipc' + postfix)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(5)
            listener.bind(str(endpoint))
            endpoint.chmod(0o666)
            listener.listen(1)
            result = actor('import os,socket,sys\nwith socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:\n'
                           ' s.settimeout(5);s.connect(sys.argv[1]);s.sendall(b"R");print(os.getpid())', endpoint)
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(5)
                pid, uid, gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require((pid, uid, gid) == (int(result.stdout.strip()), 4001, 4001)
                        and peer.recv(2) == b'R', 'ordinary client or kernel peer credentials differ')
        endpoint.unlink()
        service.rmdir()
    record('fresh-runtime-parent-and-local-socket-access')

    call(service, uid=4001, refused=True)
    require(not service.exists(), 'nonroot service created its parent')
    denied('pathlib.Path(sys.argv[1]).mkdir()', service)
    call(service)
    before = identity(service)
    denied('pathlib.Path(sys.argv[1]).rename(sys.argv[2])', service, '/run/RustDesk-service-moved')
    denied('pathlib.Path(sys.argv[1]).rmdir()', service)
    denied('os.open(sys.argv[1]+"/intrusion",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)', service)
    require(identity(service) == before and not list(service.iterdir()), 'foreign mutation changed service parent')
    service.rmdir()
    record('unprivileged-create-rename-and-remove-refused')

    # A root-created misconfiguration is refused without changing its owner, ACLs or contents.
    service.mkdir(mode=0o700)
    os.chown(service, 4001, 4001)
    actor('import os,pathlib,struct,sys\np=pathlib.Path(sys.argv[1])\n'
          'acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",*e) for e in '
          '[(1,7,0xffffffff),(2,7,4001),(4,0,0xffffffff),(16,7,0xffffffff),(32,0,0xffffffff)])\n'
          'os.setxattr(p,"system.posix_acl_access",acl);os.setxattr(p,"system.posix_acl_default",acl)\n'
          '(p/"ipc_service").write_bytes(b"keep");(p/"unrelated").write_bytes(b"untouched")', service)
    before = identity(service)
    attrs = {name: os.getxattr(service, name)
             for name in ('system.posix_acl_access', 'system.posix_acl_default')}
    call(service, refused=True)
    require(identity(service) == before and all(os.getxattr(service, k) == v for k, v in attrs.items())
            and (service / 'ipc_service').read_bytes() == b'keep'
            and (service / 'unrelated').read_bytes() == b'untouched', 'foreign parent was adopted or scrubbed')
    (service / 'ipc_service').unlink(); (service / 'unrelated').unlink(); service.rmdir()
    record('foreign-access-and-default-acl-refused')

    target = data / 'target'
    target.mkdir(mode=0o700)
    (target / 'keep').write_bytes(b'untouched')
    service.symlink_to(target, target_is_directory=True)
    before = identity(service)
    call(service, refused=True)
    require(identity(service) == before and (target / 'keep').read_bytes() == b'untouched', 'symlink target changed')
    service.unlink(); (target / 'keep').unlink(); target.rmdir()
    record('symlink-parent-refused')

    parent = data / 'user-owned'
    call(parent, '', uid=4001)
    before = identity(parent)
    require(before[2] == 4001 and stat.S_IMODE(before[4]) == 0o700, 'user-mode parent differs')
    call(parent, '', uid=4002, refused=True)
    call(parent, '', uid=0, refused=True)
    require(identity(parent) == before, 'wrong owner adopted user parent')
    actor('import pathlib,sys\npathlib.Path(sys.argv[1]).rmdir()', parent)
    record('user-owned-success-and-other-principal-refusal')

    service.mkdir(mode=0o777)
    service.chmod(0o777)
    sentinel = data / 'sentinel'
    sentinel.write_bytes(b'untouched')
    actor('import pathlib,sys\np=pathlib.Path(sys.argv[1]);(p/"ipc_service").symlink_to(sys.argv[2]);'
          '(p/"ipc_service.pid").write_bytes(b"stale");(p/"keep").write_bytes(b"unrelated")', service, sentinel)
    require(call(service) is True and (service / 'ipc_service').is_symlink()
            and (service / 'ipc_service.pid').read_bytes() == b'stale', 'mode repair scrubbed before liveness')
    call(service, action='scrub')
    require(stat.S_IMODE(service.stat().st_mode) == 0o711 and sentinel.read_bytes() == b'untouched'
            and [p.name for p in service.iterdir()] == ['keep'], 'scrub followed link or removed unrelated entry')
    denied('os.open(sys.argv[1]+"/intrusion",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)', service)
    (service / 'keep').unlink(); service.rmdir(); sentinel.unlink()
    record('mode-repair-and-exact-symlink-scrub')

    runtime = Path('/run')
    runtime_before = identity(runtime)
    for name in ('unsafe-run-mode-refused', 'foreign-run-owner-refused'):
        try:
            if name.startswith('unsafe'):
                runtime.chmod(0o777)
            else:
                os.chown(runtime, 4001, 4001)
            call(service, refused=True)
            require(not service.exists(), 'unsafe runtime namespace created a service parent')
        finally:
            os.chown(runtime, runtime_before[2], runtime_before[3])
            runtime.chmod(stat.S_IMODE(runtime_before[4]))
        require(identity(runtime) == runtime_before, 'runtime fixture was not restored')
        record(name)

    # Public namespaces are rejected before any cleanup, regardless of the replacement type.
    for replacement in ('file', 'symlink', 'missing', 'empty-directory', 'nonempty-directory'):
        parent = data / replacement
        actor('import pathlib,sys\np=pathlib.Path(sys.argv[1])\n'
              'if sys.argv[2]=="file":p.write_bytes(b"replacement")\n'
              'elif sys.argv[2]=="symlink":p.symlink_to("unresolved")\n'
              'elif sys.argv[2].endswith("directory"):\n'
              ' p.mkdir(mode=0o700)\n'
              ' if sys.argv[2]=="nonempty-directory":(p/"ipc_service").write_bytes(b"replacement")\n',
              parent, replacement)
        before = identity(parent) if os.path.lexists(parent) else None
        call(parent, refused=True)
        after = identity(parent) if os.path.lexists(parent) else None
        require(after == before, 'public-namespace refusal changed an entry')
        if replacement == 'file':
            require(parent.read_bytes() == b'replacement', 'public file changed')
        elif replacement == 'symlink':
            require(os.readlink(parent) == 'unresolved', 'public symlink changed')
        elif replacement == 'nonempty-directory':
            require((parent / 'ipc_service').read_bytes() == b'replacement', 'public directory was scrubbed')
            (parent / 'ipc_service').unlink()
        if after is not None:
            if stat.S_ISDIR(after[4]):
                parent.rmdir()
            else:
                parent.unlink()
        record('public-namespace-' + replacement + '-refused')

    require(not list(data.iterdir()) and not os.path.lexists(service)
            and len(list(Path('/proc/self/fd').iterdir())) == fd_before, 'fixture or descriptor leaked')
    require(sha(probe) == expected_sha and sha(artifact) == expected_sha, 'artifact changed during execution')
    data.rmdir(); probe.unlink(); WORK.rmdir()
    require(len(cases) == 14, 'native case inventory differs')
    print(f'LINUX_IPC_PARENT_NATIVE=pass cases=14 artifact_sha256={expected_sha} '
          'receiver_uid=0 actors=4001,4002 source=production-functions installed=unexecuted cleanup=joined', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['build']:
        build()
    elif len(sys.argv) == 3 and sys.argv[1] == 'native':
        native(sys.argv[2])
    else:
        raise SystemExit('expected build or native ARTIFACT_SHA256')

#!/usr/bin/env python3
"""Compile exact IPC directory functions; exercise root/user authority only in the verifier VM."""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
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
             'ensure_secure_ipc_parent_dir', 'scrub_secure_ipc_parent_dir')
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
    generated = ('extern crate self as hbb_common;\npub extern crate libc;\n'
                 'type ResultType<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;\n'
                 'use std::{ffi::CString, io::{Error, ErrorKind}, os::unix::ffi::OsStrExt, path::Path};\n'
                 'mod config { pub ' + function(config, 'is_service_ipc_postfix') + '}\n' + fragment
                 + (repo / 'scripts/test-linux-ipc-parent.rs').read_text())
    source = target / 'ipc-parent.rs'
    source.write_text(generated)
    binary = target / 'ipc-parent'
    run([rustc, '--edition=2021', '--extern', f'libc={library}', str(source), '-o', str(binary)])
    barrier = target / 'ipc-parent-barrier.so'
    run(['/usr/bin/cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
         str(repo / 'scripts/test-linux-ipc-parent-barrier.c'), '-ldl', '-o', str(barrier)])
    print(f'LINUX_IPC_PARENT_BARRIER=pass artifact_sha256={sha(barrier)} scheduling=real-openat', flush=True)
    print(f'LINUX_IPC_PARENT_BUILD=pass artifact_sha256={sha(binary)} source_sha256={sha(fs_path)} '
          f'fragment_sha256={hashlib.sha256(fragment.encode()).hexdigest()} '
          f'config_sha256={sha(config_path)} libc=0.2.171 functions=8 error_adapter=std-boxed', flush=True)


def native(expected_sha, barrier_sha):
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
    barrier_artifact = artifact.with_name('ipc-parent-barrier.so')
    metadata = barrier_artifact.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000 and metadata.st_nlink == 1
            and metadata.st_size < 1048576 and sha(barrier_artifact) == barrier_sha, 'barrier artifact differs')
    barrier = WORK / 'barrier.so'
    shutil.copyfile(barrier_artifact, barrier)
    barrier.chmod(0o555)
    require(sha(barrier) == barrier_sha and barrier.stat().st_uid == 0, 'sealed barrier differs')
    data = WORK / 'data'
    data.mkdir(mode=0o1777)
    data.chmod(0o1777)
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

    def denied_write(parent):
        actor('import errno,os,sys\ntry:\n fd=os.open(sys.argv[1]+"/intrusion",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\n'
              'except OSError as e:\n assert e.errno==errno.EACCES\n'
              'else:\n os.close(fd);raise AssertionError("foreign write admitted")', parent)
        require(not (parent / 'intrusion').exists(), 'foreign file appeared')

    # Real ordinary processes create the foreign inode and both ACL kinds.
    create_foreign = ('import os,pathlib,struct,sys\np=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700)\n'
                      'acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",*e) for e in '
                      '[(1,7,0xffffffff),(2,7,4001),(4,0,0xffffffff),(16,7,0xffffffff),(32,0,0xffffffff)])\n'
                      'os.setxattr(p,"system.posix_acl_access",acl);os.setxattr(p,"system.posix_acl_default",acl)\n'
                      '(p/"ipc_service").write_bytes(b"stale");(p/"ipc_service.pid").write_bytes(b"stale")\n')
    for postfix in ('_service', '_service_password', '_service_credential'):
        parent = data / ('fresh' + postfix)
        call(parent, postfix)
        st = parent.stat()
        require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o711, 'fresh service mode/owner differs')
        require(call(parent, postfix) is False, 'healthy parent requests scrub')
        denied_write(parent)
        parent.rmdir()
    record('fresh-service-parents-and-repeat')

    parent = data / 'foreign-service'
    actor(create_foreign, parent)
    old = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        old_identity = os.fstat(old)
        require(old_identity.st_uid == 4001, 'foreign actor did not own fixture')
        for attr in ('system.posix_acl_access', 'system.posix_acl_default'):
            require(os.getxattr(old, attr), 'foreign ACL missing')
        require(call(parent) is True, 'foreign replacement must request scrub')
        st = parent.stat()
        require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o711
                and st.st_ino != old_identity.st_ino and os.fstat(old).st_nlink == 0,
                'foreign inode was adopted or remained linked')
        for attr in ('system.posix_acl_access', 'system.posix_acl_default'):
            try:
                os.getxattr(parent, attr)
            except OSError as error:
                require(error.errno == errno.ENODATA, 'ACL inspection failed')
            else:
                raise RuntimeError('foreign ACL survived replacement')
        require(not list(parent.iterdir()), 'stale artifacts survived replacement')
        denied_write(parent)
    finally:
        os.close(old)
    parent.rmdir()
    record('foreign-access-and-default-acl-replacement')

    parent = data / 'nonempty-service'
    actor(create_foreign + '(p/"keep").write_bytes(b"untouched")\n', parent)
    before = parent.stat()
    call(parent, refused=True)
    after = parent.stat()
    require((before.st_dev, before.st_ino, before.st_uid) == (after.st_dev, after.st_ino, after.st_uid)
            and (parent / 'keep').read_bytes() == b'untouched', 'nonempty refusal changed foreign authority')
    actor('import pathlib,sys\np=pathlib.Path(sys.argv[1]);(p/"keep").unlink();p.rmdir()', parent)
    record('nonempty-foreign-refusal')

    target, link = data / 'target', data / 'link'
    target.mkdir(mode=0o700)
    (target / 'keep').write_bytes(b'untouched')
    link.symlink_to(target, target_is_directory=True)
    call(link, refused=True)
    require(link.is_symlink() and (target / 'keep').read_bytes() == b'untouched', 'symlink refusal changed target')
    link.unlink(); (target / 'keep').unlink(); target.rmdir()
    record('symlink-parent-refusal')

    parent = data / 'user-owned'
    call(parent, '', uid=4001)
    st = parent.stat()
    require(st.st_uid == 4001 and stat.S_IMODE(st.st_mode) == 0o700, 'user-mode parent differs')
    call(parent, '', uid=4002, refused=True)
    call(parent, '', uid=0, refused=True)
    require(parent.stat().st_ino == st.st_ino and parent.stat().st_uid == 4001, 'wrong owner adopted user parent')
    actor('import pathlib,sys\npathlib.Path(sys.argv[1]).rmdir()', parent)
    record('user-owned-success-and-other-principal-refusal')

    parent = data / 'repair'
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    sentinel = data / 'sentinel'
    sentinel.write_bytes(b'untouched')
    actor('import pathlib,sys\np=pathlib.Path(sys.argv[1]);(p/"ipc_service").symlink_to(sys.argv[2]);'
          '(p/"ipc_service.pid").write_bytes(b"stale");(p/"keep").write_bytes(b"unrelated")', parent, sentinel)
    require(call(parent) is True, 'unsafe mode did not request scrub')
    call(parent, action='scrub')
    require(stat.S_IMODE(parent.stat().st_mode) == 0o711 and sentinel.read_bytes() == b'untouched'
            and [p.name for p in parent.iterdir()] == ['keep'], 'scrub followed link or removed unrelated entry')
    denied_write(parent)
    (parent / 'keep').unlink(); parent.rmdir(); sentinel.unlink()
    record('mode-repair-and-exact-symlink-scrub')

    failures = []
    for phase in ('before-open', 'after-open'):
        for replacement in ('file', 'symlink', 'missing', 'empty-directory', 'nonempty-directory'):
            name = f'race-{phase}-{replacement}'
            parent, moved = data / name, data / (name + '-moved')
            sentinel = data / (name + '-target')
            sentinel.mkdir(mode=0o700)
            (sentinel / 'keep').write_bytes(b'untouched')
            actor('import pathlib,sys\npathlib.Path(sys.argv[1]).mkdir(mode=0o700)', parent)
            original = parent.stat()
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            process = None
            try:
                process = subprocess.Popen(
                    [str(probe), 'ensure', str(parent / 'ipc_service'), '_service'],
                    env={**ENV, 'LD_PRELOAD': str(barrier), 'IPC_PARENT_BARRIER_NAME': name,
                         'IPC_PARENT_BARRIER_PHASE': phase, 'IPC_PARENT_READY_FD': str(ready_write),
                         'IPC_PARENT_RELEASE_FD': str(release_read)},
                    pass_fds=(ready_write, release_read), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    user=0, group=0, extra_groups=[], text=True)
                os.close(ready_write); ready_write = -1
                os.close(release_read); release_read = -1
                require(select.select([ready_read], [], [], 10)[0] == [ready_read]
                        and os.read(ready_read, 1) == b'R', 'production openat barrier not reached')
                actor('import pathlib,sys\np=pathlib.Path(sys.argv[1]);p.rename(sys.argv[2])\n'
                      'if sys.argv[3]=="file": p.write_bytes(b"replacement")\n'
                      'elif sys.argv[3]=="symlink": p.symlink_to(sys.argv[4],target_is_directory=True)\n'
                      'elif sys.argv[3].endswith("directory"):\n'
                      ' p.mkdir(mode=0o700)\n'
                      ' if sys.argv[3]=="nonempty-directory":\n'
                      '  (p/"ipc_service").write_bytes(b"replacement content");(p/"keep").write_bytes(b"unrelated")\n',
                      parent, moved, replacement, sentinel)
                replacement_stat = parent.lstat() if replacement != 'missing' else None
                require(os.write(release_write, b'G') == 1, 'cannot release production openat')
                stdout, stderr = process.communicate(timeout=10)
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
                for fd in (ready_read, ready_write, release_read, release_write):
                    if fd >= 0:
                        os.close(fd)
            require(len(stdout) + len(stderr) < 65536, 'race output exceeded bound')
            require(moved.stat().st_ino == original.st_ino and moved.stat().st_uid == 4001
                    and not list(moved.iterdir()) and (sentinel / 'keep').read_bytes() == b'untouched',
                    'race changed moved directory or symlink target')
            current = parent.lstat() if os.path.lexists(parent) else None
            preserved = current is None if replacement_stat is None else (
                current is not None and (current.st_dev, current.st_ino, current.st_mode, current.st_uid)
                == (replacement_stat.st_dev, replacement_stat.st_ino, replacement_stat.st_mode, replacement_stat.st_uid))
            if preserved and replacement == 'file':
                preserved = parent.read_bytes() == b'replacement'
            if preserved and replacement == 'symlink':
                preserved = os.readlink(parent) == str(sentinel)
            if preserved and replacement == 'empty-directory':
                preserved = not list(parent.iterdir())
            if preserved and replacement == 'nonempty-directory':
                preserved = (sorted(p.name for p in parent.iterdir()) == ['ipc_service', 'keep']
                             and (parent / 'ipc_service').read_bytes() == b'replacement content'
                             and (parent / 'keep').read_bytes() == b'unrelated')
            passed = process.returncode == 3 and not stdout and stderr.startswith('ERR ') and preserved
            print(f'LINUX_IPC_PARENT_RACE={"pass" if passed else "fail"} name={name} '
                  f'exit={process.returncode} replacement_preserved={str(preserved).lower()} '
                  'actor_uid=4001 schedule=controlled-openat cleanup=joined', flush=True)
            if passed:
                record(name)
            else:
                failures.append(name)
            if current is not None:
                if stat.S_ISDIR(current.st_mode):
                    for child in ('ipc_service', 'keep'):
                        if (parent / child).exists():
                            (parent / child).unlink()
                    parent.rmdir()
                else:
                    parent.unlink()
            moved.rmdir(); (sentinel / 'keep').unlink(); sentinel.rmdir()

    require(not list(data.iterdir()) and len(list(Path('/proc/self/fd').iterdir())) == fd_before,
            'native fixture or descriptor leaked')
    require(sha(probe) == expected_sha and sha(artifact) == expected_sha
            and sha(barrier) == barrier_sha and sha(barrier_artifact) == barrier_sha,
            'artifact changed during execution')
    data.rmdir(); probe.unlink(); barrier.unlink(); WORK.rmdir()
    require(not failures, f'parent replacement races failed after joined cleanup: {failures}')
    require(len(cases) == 16, 'native case inventory differs')
    print(f'LINUX_IPC_PARENT_NATIVE=pass cases=16 artifact_sha256={expected_sha} '
          'receiver_uid=0 actors=4001,4002 source=production-functions installed=unexecuted cleanup=joined', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['build']:
        build()
    elif len(sys.argv) == 4 and sys.argv[1] == 'native':
        native(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('expected build or native ARTIFACT_SHA256 BARRIER_SHA256')

#!/usr/bin/env python3
"""Dependency-complete candidate package lifecycle in the owned no-NIC VM."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import tarfile

MEDIA = Path('/mnt/rustdesk-verifier-inputs')
SCRIPT = MEDIA / 'repo/scripts/test-linux-debian-install.py'
WORK = Path('/var/tmp/rustdesk-linux-service-receiver')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'DEBIAN_FRONTEND': 'noninteractive'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(arguments, phase, timeout=180):
    print('LINUX_DEBIAN_INSTALL_STAGE=' + phase, flush=True)
    result = subprocess.run(arguments, env=ENV, capture_output=True, timeout=timeout)
    output = result.stdout + result.stderr
    require(len(output) <= 1024 * 1024, 'package command exceeded its evidence bound')
    print('LINUX_DEBIAN_INSTALL_COMMAND=' + json.dumps({
        'phase': phase, 'exit': result.returncode, 'bytes': len(output),
        'sha256': hashlib.sha256(output).hexdigest(),
        'tail': output[-8192:].decode('utf-8', errors='replace'),
    }, sort_keys=True), flush=True)
    require(result.returncode == 0, f'package command failed: {phase}')
    return result.stdout.decode('utf-8')


def runtime_inputs(source):
    pins = dict(re.findall(r'^([A-Z0-9_]+)="([^"]*)"',
                           (source / 'scripts/pins.env').read_text(), re.M))
    archive = MEDIA / 'debian-runtime-candidate.tar.gz'
    require(archive.stat().st_size == int(pins['DEBIAN_RUNTIME_CANDIDATE_ARCHIVE_SIZE'])
            and digest(archive) == pins['DEBIAN_RUNTIME_CANDIDATE_ARCHIVE_SHA256'],
            'Debian runtime archive differs from its pin')
    destination = WORK / 'debian-runtime'
    destination.mkdir(mode=0o700)
    (destination / 'packages').mkdir(mode=0o700)
    metadata = {}
    records = {}
    plan = None
    seen = set()
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            require(member.name not in seen and len(seen) < 516 and member.isfile()
                    and (member.mode, member.uid, member.gid, member.uname, member.gname, member.mtime)
                    == (0o400, 0, 0, '', '', int(pins['DEV_CHECK_SOURCE_DATE_EPOCH']))
                    and 0 < member.size <= 64 * 1024 * 1024, 'runtime member authority differs')
            seen.add(member.name)
            payload = stream.extractfile(member)
            if member.name in ('contract', 'control', 'manifest.tsv', 'plan.json'):
                require(plan is None and member.size <= 1024 * 1024, 'runtime metadata order/size differs')
                data = payload.read()
                key = member.name.split('.')[0].upper()
                require(hashlib.sha256(data).hexdigest() == pins['DEBIAN_RUNTIME_CANDIDATE_' + key + '_SHA256'],
                        'runtime metadata differs from its pin')
                metadata[member.name] = data
                continue
            if plan is None:
                require(set(metadata) == {'contract', 'control', 'manifest.tsv', 'plan.json'},
                        'runtime metadata is incomplete')
                plan = json.loads(metadata['plan.json'])
                require(0 < len(plan) <= 512 and sum(r['bytes'] for r in plan.values()) <= 512 * 1024 * 1024,
                        'runtime closure exceeds its admission bound')
                for line in metadata['manifest.tsv'].decode().splitlines():
                    name, version, architecture, filename, size, sha = line.split('\t')
                    require(filename not in records and architecture in ('amd64', 'all'),
                            'runtime package metadata repeats or differs')
                    records[filename] = {'name': name, 'version': version, 'bytes': int(size), 'sha256': sha}
                require(set(plan) == set(records), 'runtime plan and inventory differ')
            require(re.fullmatch(r'packages/[A-Za-z0-9.+_:%~\-]+\.deb', member.name),
                    'runtime member pathname differs')
            name = member.name[9:]
            require(name in records and member.size == records[name]['bytes'] == plan[name]['bytes']
                    and records[name]['sha256'] == plan[name]['sha256'], 'runtime package plan differs')
            target = destination / member.name
            with target.open('xb') as output:
                shutil.copyfileobj(payload, output, 1024 * 1024)
            target.chmod(0o400)
            require(target.stat().st_size == member.size and digest(target) == records[name]['sha256'],
                    'runtime package content differs')
    require(plan is not None and seen == set(metadata) | {'packages/' + name for name in records},
            'runtime member inventory differs')
    contract = dict(line.split('=', 1) for line in metadata['contract'].decode().splitlines())
    require(contract['generator_sha256'] == digest(source / 'build.py'),
            'runtime dependency generator is stale')
    return destination, records, metadata['control']


def main(source, prepared, app_input, manifest_sha, commit):
    require(Path(__file__).resolve() == SCRIPT, 'package test entry differs')
    spec = importlib.util.spec_from_file_location('installed_settings', SCRIPT.with_name('test-linux-installed-settings.py'))
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)
    settings.guard()
    receiver = settings.receiver_module()
    receiver.guard()
    require(not any(os.path.lexists(p) for p in ('/usr/bin/rustdesk', '/usr/share/rustdesk',
            '/etc/systemd/system/rustdesk.service', '/usr/lib/systemd/system/rustdesk.service',
            '/root/.config/rustdesk', '/root/.config/RustDesk')), 'package fixture is not fresh')
    manifest_path = app_input / 'app-manifest.json'
    require(digest(manifest_path) == manifest_sha, 'application manifest differs')
    manifest = json.loads(manifest_path.read_text())
    archive = prepared / 'first.deb'
    prepared_manifest = json.loads((prepared / 'manifest.json').read_text())
    require(prepared_manifest['first.deb'] == {'bytes': archive.stat().st_size, 'sha256': digest(archive)},
            'prepared package differs')
    runtime, records, control = runtime_inputs(source)
    controls = WORK / 'debian-control'
    command(['/usr/bin/dpkg-deb', '--control', str(archive), str(controls)], 'control')
    require((controls / 'control').read_bytes() == control, 'package and resolved dependency metadata differ')
    version, = re.findall(r'^Version: (.+)$', control.decode(), re.M)
    cache = runtime / 'packages'
    cached_application = cache / f'rustdesk_{version}_amd64.deb'
    require(not cached_application.exists(), 'application cache slot is occupied')
    shutil.copyfile(archive, cached_application)
    cached_application.chmod(0o400)
    require(digest(cached_application) == digest(archive), 'cached application differs')
    sources = runtime / 'sources.list'
    sources.write_text('')
    for directory in ('sources.list.d', 'lists', 'lists/partial', 'packages/partial'):
        (runtime / directory).mkdir(mode=0o700)
    # --no-download consumes the archive cache without running file acquisition.
    # Supply the verified files there, as well as their package metadata arguments.
    apt = ['/usr/bin/apt-get', '-o', f'Dir::Etc::sourcelist={sources}',
           '-o', f'Dir::Etc::sourceparts={runtime}/sources.list.d',
           '-o', f'Dir::State::lists={runtime}/lists', '-o', f'Dir::Cache::archives={cache}',
           '--no-download', '--no-install-recommends', '--no-remove', '--yes']
    user_created = False
    pidfds = []
    try:
        command([*apt, 'install', *(str(runtime / 'packages' / name) for name in sorted(records)),
                 str(cached_application)], 'install', timeout=240)
        command([*apt, 'check'], 'dependencies')
        require(command(['/usr/bin/dpkg', '--audit'], 'dpkg-audit') == '', 'dpkg has incomplete packages')
        installed = command(['/usr/bin/dpkg-query', '--show',
            '--showformat=${Package}\t${Version}\t${db:Status-Abbrev}\n',
            *(record['name'] for record in records.values())], 'runtime-inventory')
        actual = {name: (ver, status) for name, ver, status in
                  (line.split('\t') for line in installed.splitlines())}
        require(actual == {r['name']: (r['version'], 'ii ') for r in records.values()},
                'installed dependency versions/status differ')

        def installed_state(phase):
            require(settings.run(['/usr/bin/dpkg-query', '--show', '--showformat=${Status}\t${Version}', 'rustdesk'])
                    == 'install ok installed\t' + version, 'application package is not configured')
            require(settings.run(['/usr/bin/dpkg', '--verify', 'rustdesk']) == '', 'installed payload verification failed')
            for name, record in manifest['files'].items():
                if name.startswith('bundle/'):
                    path = Path('/usr/share/rustdesk') / name[len('bundle/'):]
                    require(path.stat().st_size == record['bytes'] and digest(path) == record['sha256'],
                            'installed application differs from its retained input')
            require(os.readlink('/usr/bin/rustdesk') == '../share/rustdesk/rustdesk', 'installed command link differs')
            for path in ('/usr/bin/rustdesk', '/usr/lib/systemd/system/rustdesk.service'):
                require(settings.run(['/usr/bin/dpkg-query', '--search', path]).strip() == 'rustdesk: ' + path,
                        'installed package ownership differs')
            require(digest('/usr/lib/systemd/system/rustdesk.service') == digest(source / 'res/rustdesk.service')
                    and not os.path.lexists('/etc/systemd/system/rustdesk.service'), 'vendor unit authority differs')
            child = receiver.CHILD.lstat()
            require(digest(receiver.CHILD) == digest(receiver.PRIMARY) and stat.S_ISREG(child.st_mode)
                    and (child.st_uid, child.st_gid, stat.S_IMODE(child.st_mode), child.st_nlink) == (0, 0, 0o711, 1),
                    'installed child image differs')
            listing = settings.run(['/usr/bin/ldd', str(receiver.PRIMARY)])
            require('not found' not in listing, 'installed application has an unresolved library')
            props = dict(line.split('=', 1) for line in settings.run(['/usr/bin/systemctl', 'show', 'rustdesk.service',
                '--property=ActiveState,SubState,MainPID,FragmentPath,NRestarts']).splitlines())
            require(props['ActiveState'] == 'active' and props['SubState'] == 'running'
                    and props['FragmentPath'] == '/usr/lib/systemd/system/rustdesk.service'
                    and props['NRestarts'] == '0', 'package did not start the vendor service normally')
            pid = int(props['MainPID'])
            fd = os.pidfd_open(pid)
            pidfds.append(fd)
            require(pid > 1 and Path(f'/proc/{pid}/exe').samefile(receiver.PRIMARY)
                    and not select.select([fd], [], [], 0)[0], 'installed supervisor identity differs')
            print('LINUX_DEBIAN_INSTALL_STATE=' + json.dumps({'phase': phase, 'unit': props,
                  'archive_sha256': digest(archive), 'application_files': sum(n.startswith('bundle/') for n in manifest['files'])},
                  sort_keys=True), flush=True)
            return fd

        first = installed_state('installed')
        receiver.change(0, settings.BASELINE_PASSWORD, True)
        credential = receiver.credential()
        command(['/usr/sbin/useradd', '--uid', '4002', '--user-group', '--create-home',
                 '--shell', '/usr/sbin/nologin', 'rdreceiver4002'], 'ordinary-user')
        user_created = True
        receiver.change(4002, 'Unapproved-package-change-2026!', False)
        require(receiver.credential() == credential, 'refused operation changed the installed credential')
        command(['/usr/bin/dpkg', '--install', str(archive)], 'reinstall', timeout=90)
        second = installed_state('reinstalled')
        require(select.select([first], [], [], 2)[0] == [first] and receiver.credential() == credential,
                'reinstall failed to retire its old supervisor or preserve the credential')
        command(['/usr/bin/dpkg', '--remove', 'rustdesk'], 'remove', timeout=90)
        require(select.select([second], [], [], 2)[0] == [second] and receiver.credential() == credential,
                'remove failed to stop the supervisor or preserve the credential')
        settings.service_absent()
        require(not any(os.path.lexists(p) for p in ('/usr/bin/rustdesk', '/usr/share/rustdesk/rustdesk',
                    '/usr/lib/systemd/system/rustdesk.service')), 'remove retained package payload')
        command(['/usr/bin/dpkg', '--purge', 'rustdesk'], 'purge')
        require(not any(os.path.lexists(p) for p in ('/root/.config/rustdesk', '/root/.config/RustDesk',
                    '/etc/init.d/rustdesk')), 'purge retained package-owned state')
        command([*apt, 'check'], 'final-dependencies')
        require(command(['/usr/bin/dpkg', '--audit'], 'final-dpkg-audit') == '', 'final dpkg state is incomplete')
        require(digest(manifest_path) == manifest_sha, 'application input changed')
        print('LINUX_DEBIAN_INSTALL_CREDENTIAL=' + json.dumps({'sha256': credential,
              'administrator': 'Applied', 'ordinary_user': 'refused', 'reinstall': 'preserved',
              'remove': 'preserved', 'purge': 'absent'}, sort_keys=True), flush=True)
    except BaseException:
        print(settings.run(['/usr/bin/journalctl', '--unit=rustdesk.service', '--no-pager', '-n', '40']), flush=True)
        raise
    finally:
        try:
            if Path('/usr/lib/systemd/system/rustdesk.service').exists():
                settings.run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=45)
            else:
                require(all(select.select([fd], [], [], 0)[0] for fd in pidfds),
                        'removed unit left a retained supervisor alive')
        finally:
            for fd in pidfds:
                os.close(fd)
            if user_created:
                command(['/usr/sbin/userdel', 'rdreceiver4002'], 'retire-user')
    print(f'LINUX_DEBIAN_INSTALL_NATIVE=pass app_commit={commit} manifest_sha256={manifest_sha} '
          'dependencies=apt-checked install=dpkg reinstall=same-version service=actual credential=preserved '
          'remove=preserved purge=retired desktop=unexecuted cleanup=joined', flush=True)


if __name__ == '__main__':
    require(len(sys.argv) == 7 and sys.argv[1] == '--run', 'closed Debian installation arguments required')
    main(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5], sys.argv[6])

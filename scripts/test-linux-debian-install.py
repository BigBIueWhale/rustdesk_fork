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
import time

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


def desktop_runtime(settings, prepared):
    # Only X11 fixture processes see these libraries. The package keeps the
    # dependency set APT installed, with no loader configuration changes.
    fixture = WORK / 'debian-x11'
    fixture.mkdir(mode=0o755)
    fixture.chmod(0o755)
    for tool in ('Xvfb', 'xkbcomp'):
        settings.install(WORK / 'xvfb-root/usr/bin' / tool, fixture / tool, 0o755)
    libraries = fixture / 'lib'
    for path in (WORK / 'xvfb-root/usr/lib').rglob('*.so*'):
        if path.is_file():
            settings.install(path, libraries / path.name)
    for path in (prepared / 'xkb').rglob('*'):
        if path.is_file():
            settings.install(path, WORK / 'xkb' / path.relative_to(prepared / 'xkb'))
    for tool, wrapper in (('Xvfb', WORK / 'Xvfb'), ('xkbcomp', Path('/usr/bin/xkbcomp'))):
        require(not os.path.lexists(wrapper), 'desktop fixture command is already occupied')
        wrapper.write_text('#!/bin/sh\nexec /lib64/ld-linux-x86-64.so.2 --library-path '
                           + str(libraries) + ' ' + str(fixture / tool) + ' "$@"\n')
        wrapper.chmod(0o755)
        listing = settings.run(['/lib64/ld-linux-x86-64.so.2', '--library-path',
                                str(libraries), '--list', str(fixture / tool)])
        require('not found' not in listing, 'desktop fixture dependency is missing')
    print('LINUX_DEBIAN_DESKTOP_RUNTIME=private product_libraries=apt loader_configuration=unchanged', flush=True)


def administrator_units(source, archive, version, settings, receiver):
    primary = Path('/etc/systemd/system/rustdesk.service')
    drop_directory = Path('/etc/systemd/system/rustdesk.service.d')
    drop = drop_directory / '90-package-fixture.conf'
    vendor = Path('/usr/lib/systemd/system/rustdesk.service')
    linked = WORK / 'administrator-unit/rustdesk.service'
    linked.parent.mkdir(mode=0o755)
    linked.parent.chmod(0o755)

    def snapshot(path):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)),
                'administrator fixture authority differs')
        return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                'uid': info.st_uid, 'gid': info.st_gid, 'bytes': info.st_size,
                'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
                'target': os.readlink(path) if path.is_symlink() else None,
                'sha256': None if path.is_symlink() else digest(path)}

    def properties():
        return dict(line.split('=', 1) for line in settings.run([
            '/usr/bin/systemctl', 'show', 'rustdesk.service',
            '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,Environment,NRestarts'
        ]).splitlines())

    completed = []
    for kind in ('mask', 'linked', 'replacement', 'drop-in'):
        require(not any(os.path.lexists(p) for p in (primary, drop_directory, linked, vendor)),
                'administrator unit case is not fresh')
        settings.service_absent()
        environment = 'RUSTDESK_PACKAGE_ADMIN=' + kind
        addition = '\n[Service]\nEnvironment=' + environment + '\n'
        if kind == 'mask':
            primary.symlink_to('/dev/null')
            paths = [primary]
        elif kind == 'linked':
            linked.write_bytes((source / 'res/rustdesk.service').read_bytes() + addition.encode())
            linked.chmod(0o644)
            primary.symlink_to(linked)
            paths = [primary, linked]
        elif kind == 'replacement':
            primary.write_bytes((source / 'res/rustdesk.service').read_bytes() + addition.encode())
            primary.chmod(0o644)
            paths = [primary]
        else:
            drop_directory.mkdir(mode=0o755)
            drop_directory.chmod(0o755)
            drop.write_text(addition)
            drop.chmod(0o644)
            paths = [drop]
        original = {str(p): snapshot(p) for p in paths}
        settings.run(['/usr/bin/systemctl', 'daemon-reload'])
        pidfds = []
        phases = []
        try:
            for phase, action in (('install', '--install'), ('reinstall', '--install'),
                                  ('remove', '--remove'), ('purge', '--purge')):
                command(['/usr/bin/dpkg', action, str(archive) if action == '--install' else 'rustdesk'],
                        'admin-' + kind + '-' + phase, timeout=90)
                observed = {str(p): snapshot(p) for p in paths}
                require(observed == original, 'package changed administrator unit state')
                props = properties()
                if action == '--install':
                    require(settings.run(['/usr/bin/dpkg-query', '--show', '--showformat=${Status}\t${Version}',
                                          'rustdesk']) == 'install ok installed\t' + version,
                            'administrator-state package is not configured')
                    require(settings.run(['/usr/bin/dpkg', '--verify', 'rustdesk']) == ''
                            and digest(vendor) == digest(source / 'res/rustdesk.service')
                            and os.readlink('/usr/bin/rustdesk') == '../share/rustdesk/rustdesk',
                            'administrator-state package payload differs')
                    if kind == 'mask':
                        require(props['LoadState'] == 'masked' and props['ActiveState'] == 'inactive'
                                and props['MainPID'] == '0', 'installation bypassed the administrator mask')
                        settings.service_absent()
                    else:
                        fragment = linked if kind == 'linked' else primary if kind == 'replacement' else vendor
                        require(props['LoadState'] == 'loaded' and props['ActiveState'] == 'active'
                                and props['SubState'] == 'running' and props['NRestarts'] == '0'
                                and Path(props['FragmentPath']).samefile(fragment)
                                and props['DropInPaths'] == (str(drop) if kind == 'drop-in' else '')
                                and environment in props['Environment'].split(),
                                'administrator unit did not govern the installed service')
                        pid = int(props['MainPID'])
                        require(pid > 1, 'administrator unit has no supervisor')
                        fd = os.pidfd_open(pid)
                        pidfds.append(fd)
                        require(Path(f'/proc/{pid}/exe').samefile(receiver.PRIMARY)
                                and environment.encode() in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
                                and not select.select([fd], [], [], 0)[0]
                                and properties()['MainPID'] == str(pid),
                                'administrator-selected supervisor identity or environment differs')
                        require(all(select.select([old], [], [], 2)[0] for old in pidfds[:-1]),
                                'reinstall retained an old administrator-selected supervisor')
                else:
                    require(all(select.select([fd], [], [], 2)[0] for fd in pidfds),
                            'package removal retained an administrator-selected supervisor')
                    settings.service_absent()
                    require(not any(os.path.lexists(p) for p in
                            (vendor, Path('/usr/bin/rustdesk'), receiver.PRIMARY)),
                            'administrator-state removal retained package payload')
                    if phase == 'purge':
                        require(not any(os.path.lexists(p) for p in
                                ('/root/.config/rustdesk', '/root/.config/RustDesk', '/etc/init.d/rustdesk')),
                                'administrator-state purge retained package-owned state')
                phases.append(phase)
                print('LINUX_DEBIAN_ADMIN_UNIT=' + json.dumps({
                    'case': kind, 'phase': phase, 'files': observed, 'unit': props,
                    'retired_supervisors': len(pidfds) - (1 if action == '--install' and kind != 'mask' else 0),
                }, sort_keys=True), flush=True)
        finally:
            try:
                if vendor.exists() and kind != 'mask':
                    settings.run(['/usr/bin/systemctl', 'stop', 'rustdesk.service'], timeout=45)
                require(all(select.select([fd], [], [], 2)[0] for fd in pidfds),
                        'administrator-unit fixture did not retire its supervisors')
            finally:
                for fd in pidfds:
                    os.close(fd)
        require({str(p): snapshot(p) for p in paths} == original,
                'administrator unit changed before fixture retirement')
        for path in paths:
            path.unlink()
        if kind == 'drop-in':
            drop_directory.rmdir()
        settings.run(['/usr/bin/systemctl', 'daemon-reload'])
        settings.service_absent()
        completed.append({'case': kind, 'phases': phases})
    linked.parent.rmdir()
    print('LINUX_DEBIAN_ADMIN_UNITS=' + json.dumps(completed, sort_keys=True), flush=True)


def settings_workflow(source, prepared, settings, receiver, probe_sha, agent_archive_sha, network_before,
                      uncertain=False):
    desktop_runtime(settings, prepared)
    require(not Path('/etc/ld.so.conf.d/rustdesk-settings-fixture.conf').exists()
            and not Path('/usr/local/lib/rustdesk-settings-fixture').exists(),
            'package settings must use the ordinary installed libraries')
    packages = []
    for line in (source / 'scripts/smoke-atspi-packages.tsv').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        name, size, sha, _ = line.split('\t')
        path = WORK / 'atspi-debs' / (name + '.deb')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == int(size)
                and digest(path) == sha, 'desktop accessibility package differs from its pin')
        packages.append(str(path))
    require(len(packages) == 2, 'desktop accessibility package closure differs')
    command(['/usr/bin/dpkg', '--install', *packages], 'desktop-accessibility')
    versions = {'at-spi2-core': ('2.46.0-5', 'install ok installed'),
                'gsettings-desktop-schemas': ('43.0-1', 'install ok installed')}
    drivers = [('driver-first', 'settings-driver')]
    if agent_archive_sha is not None:
        settings.install_graphical_agent(agent_archive_sha)
        versions['policykit-1-gnome'] = ('0.105-8', 'install ok installed')
        drivers.append(('agent-driver-first', 'agent-driver'))
    installed = command(['/usr/bin/dpkg-query', '--show', '--showformat=${Package}\t${Version}\t${Status}\n',
                         *versions],
                        'desktop-runtime-inventory')
    require(dict((name, (version, status)) for name, version, status in
                 (line.split('\t') for line in installed.splitlines())) == versions,
            'desktop accessibility or agent package is not configured')
    for name, target in drivers:
        settings.install(prepared / name, WORK / target, 0o755)
        require('not found' not in settings.run(['/usr/bin/ldd', str(WORK / target)]),
                'package settings driver has an unresolved dependency')
    command(['/usr/sbin/useradd', '--uid', '4003', '--user-group', '--create-home',
             '--shell', '/usr/sbin/nologin', '--groups', 'sudo', 'rdreceiver4003'], 'desktop-administrator')
    try:
        receiver.run(['/usr/sbin/chpasswd'], input=f'rdreceiver4003:{receiver.ADMIN_PASSWORD}\n')
        if agent_archive_sha is not None:
            receiver.installed_desktop(lambda actor, session, pam: settings.admin_failure_scenario(
                receiver, probe_sha, graphical=(actor, session, pam), network_before=network_before),
                settings=True, session_controller=True)
        else:
            scenario = settings.uncertain_scenario if uncertain else settings.scenario
            receiver.installed_desktop(lambda: scenario(receiver, probe_sha, network_before), settings=True)
        settings.service_absent()
        require(settings.run(['/usr/bin/dpkg', '--verify', 'rustdesk']) == '',
                'settings workflow changed the installed package')
        label, cases = (('GRAPHICAL', 5) if agent_archive_sha is not None else
                        ('UNCERTAIN', 3) if uncertain else ('FAILURE', 8))
        print(f'LINUX_DEBIAN_{label}_WORKFLOW=pass cases={cases} libraries=apt policy=package '
              'unit=vendor authorization=polkit-pam profile=unchanged cleanup=joined', flush=True)
    finally:
        command(['/usr/sbin/userdel', 'rdreceiver4003'], 'retire-desktop-administrator')


def main(source, prepared, app_input, manifest_sha, commit, probe_sha, agent_archive_sha=None,
         settings_mode=None, upgrade=False):
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
    previous = settings.upgrade_manifest(source, MEDIA / 'debian-upgrade') if upgrade else None
    archive = prepared / 'first.deb'
    initial_archive = prepared / 'previous.deb' if upgrade else archive
    prepared_manifest = json.loads((prepared / 'manifest.json').read_text())
    for candidate in (archive, initial_archive):
        require(prepared_manifest[candidate.name] == {'bytes': candidate.stat().st_size, 'sha256': digest(candidate)},
                'prepared package differs')
    runtime, records, control = runtime_inputs(source)
    controls = WORK / 'debian-control'
    command(['/usr/bin/dpkg-deb', '--control', str(archive), str(controls)], 'control')
    require((controls / 'control').read_bytes() == control, 'package and resolved dependency metadata differ')
    if upgrade:
        previous_controls = WORK / 'previous-debian-control'
        command(['/usr/bin/dpkg-deb', '--control', str(initial_archive), str(previous_controls)], 'previous-control')
        require((previous_controls / 'control').read_bytes() == control
                and digest(initial_archive) != digest(archive), 'upgrade package identity or control differs')
    version, = re.findall(r'^Version: (.+)$', control.decode(), re.M)
    cache = runtime / 'packages'
    cached_application = cache / f'rustdesk_{version}_amd64.deb'
    require(not cached_application.exists(), 'application cache slot is occupied')
    shutil.copyfile(initial_archive, cached_application)
    cached_application.chmod(0o400)
    require(digest(cached_application) == digest(initial_archive), 'cached application differs')
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
    supervisors = []
    network_before = settings.network_state()

    def sessionless_snapshot(phase):
        pid = supervisors[-1]
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        record = Path('/run/rustdesk/service-child.record')
        sessions = settings.run(['/usr/bin/loginctl', 'list-sessions', '--no-legend', '--no-pager']).strip()
        observed = {'phase': phase, 'supervisor': pid, 'children': children,
                    'child_record_present': os.path.lexists(record), 'sessions': sessions,
                    'credential_file_sha256': digest('/root/.config/rustdesk/RustDesk.toml')
                    if Path('/root/.config/rustdesk/RustDesk.toml').exists() else None}
        print('LINUX_DEBIAN_INSTALL_SESSIONLESS=' + json.dumps(observed, sort_keys=True), flush=True)
        require(not children and not observed['child_record_present'] and not sessions,
                'sessionless package fixture has a session or child')

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

        def installed_state(phase, expected_manifest=manifest, expected_archive=archive):
            require(settings.run(['/usr/bin/dpkg-query', '--show', '--showformat=${Status}\t${Version}', 'rustdesk'])
                    == 'install ok installed\t' + version, 'application package is not configured')
            require(settings.run(['/usr/bin/dpkg', '--verify', 'rustdesk']) == '', 'installed payload verification failed')
            for name, record in expected_manifest['files'].items():
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
            print('LINUX_DEBIAN_INSTALL_UNIT=' + json.dumps({'phase': phase, **props}, sort_keys=True), flush=True)
            require(props['ActiveState'] == 'active' and props['SubState'] == 'running'
                    and props['FragmentPath'] in ('/usr/lib/systemd/system/rustdesk.service',
                                                 '/lib/systemd/system/rustdesk.service')
                    and Path(props['FragmentPath']).samefile('/usr/lib/systemd/system/rustdesk.service')
                    and props['NRestarts'] == '0', 'package did not start the vendor service normally')
            pid = int(props['MainPID'])
            supervisors.append(pid)
            fd = os.pidfd_open(pid)
            pidfds.append(fd)
            require(pid > 1 and Path(f'/proc/{pid}/exe').samefile(receiver.PRIMARY)
                    and not select.select([fd], [], [], 0)[0], 'installed supervisor identity differs')
            print('LINUX_DEBIAN_INSTALL_STATE=' + json.dumps({'phase': phase, 'unit': props,
                  'archive_sha256': digest(expected_archive),
                  'application_files': sum(n.startswith('bundle/') for n in expected_manifest['files'])},
                  sort_keys=True), flush=True)
            return fd

        def mapped_core(record, expected_manifest, phase):
            core = Path('/usr/share/rustdesk/lib/librustdesk.so')
            info = core.stat()
            expected = expected_manifest['files']['bundle/lib/librustdesk.so']
            require(core.stat().st_size == expected['bytes'] and digest(core) == expected['sha256'],
                    'installed core differs from the selected application')
            observations = []
            for pid in (record['supervisor'], record['pid']):
                settings.package_process(pid)
                mappings = [line.split(maxsplit=5) for line in Path(f'/proc/{pid}/maps').read_text().splitlines()
                            if 'librustdesk.so' in line]
                require(mappings and all(len(fields) == 6 and fields[5] == str(core)
                        and int(fields[4]) == info.st_ino
                        and tuple(int(v, 16) for v in fields[3].split(':')) == (os.major(info.st_dev), os.minor(info.st_dev))
                        for fields in mappings), 'service process is not executing the selected installed core')
                observations.append({'pid': pid, 'segments': len(mappings)})
            print('LINUX_DEBIAN_UPGRADE_CORE=' + json.dumps({
                'phase': phase, 'sha256': expected['sha256'], 'inode': info.st_ino,
                'processes': observations, **record}, sort_keys=True), flush=True)

        first = installed_state('installed', previous if upgrade else manifest, initial_archive)
        if agent_archive_sha is not None or settings_mode is not None:
            settings_workflow(source, prepared, settings, receiver, probe_sha, agent_archive_sha, network_before,
                              uncertain=settings_mode == 'uncertain')
            require(select.select([first], [], [], 0)[0] == [first],
                    'settings workflow did not retire the original package supervisor')
            credential = receiver.credential()
            settings.run(['/usr/bin/systemctl', 'start', 'rustdesk.service'])
            installed_state('after-settings' if settings_mode is not None else 'after-graphical')
            require(receiver.credential() == credential, 'settings credential did not survive service restart')
        else:
            sessionless_snapshot('before-password')
            credential = None
            if not upgrade:
                started = time.monotonic()
                receiver.change(0, settings.BASELINE_PASSWORD, True)
                print('LINUX_DEBIAN_INSTALL_PASSWORD_SECONDS=' + str(time.monotonic() - started), flush=True)
                sessionless_snapshot('after-password')
                credential = receiver.credential()
            require(digest(receiver.PROBE) == probe_sha, 'installed CPace probe differs')
            desktop_runtime(settings, prepared)

            def desktop_bootstrap(actor, session, pam):
                nonlocal credential
                record = receiver.ready()
                child_fd = os.pidfd_open(record['pid'])
                active_supervisor = first
                try:
                    if upgrade:
                        receiver.change(0, settings.BASELINE_PASSWORD, True)
                        credential = receiver.credential()
                        mapped_core(record, previous, 'before-upgrade')
                    require(receiver.child_record() == record and record['supervisor'] == supervisors[0]
                            and not select.select([first, child_fd], [], [], 0)[0]
                            and receiver.credential() == credential, 'desktop bootstrap changed its owner or credential')
                    for pid in (record['supervisor'], record['pid']):
                        proc = Path('/proc') / str(pid)
                        require(str(WORK / 'debian-x11') not in (proc / 'maps').read_text()
                                and not any(value.startswith((b'LD_LIBRARY_PATH=', b'LD_PRELOAD='))
                                            for value in (proc / 'environ').read_bytes().split(b'\0')),
                                'product loaded or inherited the private desktop runtime')
                    settings.credential_network(receiver, record, probe_sha, 'package-desktop-bootstrap',
                                                new=settings.BASELINE_PASSWORD, old='Wrong-bootstrap-password-2026!')
                    if upgrade:
                        old_record = record
                        profile = settings.user_credential()
                        command(['/usr/bin/dpkg', '--install', str(archive)], 'upgrade', timeout=90)
                        active_supervisor = installed_state('upgraded')
                        require(len(select.select([first, child_fd], [], [], 2)[0]) == 2,
                                'package upgrade retained an old supervisor or child')
                        record = receiver.ready(old_record)
                        require(record['supervisor'] == supervisors[-1]
                                and record['generation'] != old_record['generation']
                                and receiver.credential() == credential
                                and settings.user_credential() == profile,
                                'package upgrade did not preserve credential or replace its service generation')
                        next_child = os.pidfd_open(record['pid'])
                        os.close(child_fd)
                        child_fd = next_child
                        mapped_core(record, manifest, 'after-upgrade')
                        settings.credential_network(receiver, record, probe_sha, 'package-upgraded',
                                                    new=settings.BASELINE_PASSWORD, old='Wrong-upgrade-password-2026!')
                        require(settings.user_credential() == profile, 'upgraded authentication changed profile credentials')
                        print('LINUX_DEBIAN_UPGRADE=' + json.dumps({
                            'previous_app': previous['context']['source_commit'], 'current_app': commit,
                            'previous_package': digest(initial_archive), 'current_package': digest(archive),
                            'old': old_record, 'new': record, 'version': version, 'credential_sha256': credential,
                            'old_processes': 'pidfd-exited', 'profile': 'unchanged',
                        }, sort_keys=True), flush=True)
                    actor.stdin.write(b'close\n')
                    actor.stdin.flush()
                    require(pam.reply(actor) == {'session': session, 'phase': 'closed'},
                            'desktop did not close its actual PAM session')
                    require(select.select([child_fd], [], [], 25)[0] == [child_fd],
                            'service child survived desktop session closure')
                    deadline = time.monotonic() + 5
                    while (Path(f'/proc/{record["pid"]}').exists()
                           or os.path.lexists('/run/rustdesk/service-child.record')):
                        require(time.monotonic() < deadline, 'desktop child or record was not retired')
                        time.sleep(0.05)
                    require(not select.select([active_supervisor], [], [], 0)[0] and receiver.credential() == credential,
                            'desktop retirement changed the supervisor or credential')
                    print('LINUX_DEBIAN_DESKTOP_BOOTSTRAP=' + json.dumps({
                        **record, 'session': session, 'credential_sha256': credential,
                        'authentication': 'mutual-cpace', 'wrong_password': 'receiver-confirmed-refusal',
                        'child': 'exited-and-reaped',
                    }, sort_keys=True), flush=True)
                finally:
                    os.close(child_fd)

            receiver.installed_desktop(desktop_bootstrap, close_session=True)
            sessionless_snapshot('after-desktop')
            require(settings.run(['/usr/bin/systemctl', 'show', 'rustdesk.service',
                    '--property=MainPID', '--value']).strip() == str(supervisors[-1]),
                    'package supervisor changed during desktop lifecycle')
        require(digest(receiver.PROBE) == probe_sha, 'desktop workflow changed the CPace probe')
        command(['/usr/sbin/useradd', '--uid', '4002', '--user-group', '--create-home',
                 '--shell', '/usr/sbin/nologin', 'rdreceiver4002'], 'ordinary-user')
        user_created = True
        receiver.change(4002, 'Unapproved-package-change-2026!', False)
        require(receiver.credential() == credential, 'refused operation changed the installed credential')
        command(['/usr/bin/dpkg', '--install', str(archive)], 'reinstall', timeout=90)
        second = installed_state('reinstalled')
        require(all(select.select([fd], [], [], 2)[0] for fd in pidfds[:-1])
                and receiver.credential() == credential,
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
        if agent_archive_sha is None and settings_mode is None and not upgrade:
            administrator_units(source, archive, version, settings, receiver)
        command([*apt, 'check'], 'final-dependencies')
        require(command(['/usr/bin/dpkg', '--audit'], 'final-dpkg-audit') == '', 'final dpkg state is incomplete')
        require(digest(manifest_path) == manifest_sha, 'application input changed')
        print('LINUX_DEBIAN_INSTALL_CREDENTIAL=' + json.dumps({'sha256': credential,
              'administrator': 'Applied', 'ordinary_user': 'refused', 'reinstall': 'preserved',
              'remove': 'preserved', 'purge': 'absent'}, sort_keys=True), flush=True)
    except BaseException:
        if supervisors:
            try:
                sessionless_snapshot('failure')
                path, data = settings.owned_log(Path('/root/.local/share/logs/RustDesk/service'), supervisors[-1], 0)
                messages = [line.decode('utf-8', errors='replace') for line in data.splitlines()
                            if b'Retrying admitted password mutation after child identity failure' in line
                            or b'Linux durable credential changed but its runtime replica' in line]
                print('LINUX_DEBIAN_INSTALL_RECOVERY=' + json.dumps({
                    'path': str(path), 'messages': messages[-10:], 'count': len(messages)},
                    sort_keys=True), flush=True)
            except Exception as diagnostic_error:
                print('LINUX_DEBIAN_INSTALL_DIAGNOSTIC_ERROR=' + str(diagnostic_error), flush=True)
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
    settings.wait_network_retirement(network_before)
    if upgrade:
        print(f'LINUX_DEBIAN_UPGRADE_NATIVE=pass previous_app={previous["context"]["source_commit"]} '
              f'app_commit={commit} manifest_sha256={manifest_sha} dependencies=apt-checked '
              'upgrade=distinct-core-same-base service=actual old_processes=retired credential=preserved '
              'cpace=4 wrong_password=refused profile=unchanged reinstall=same-version remove=preserved '
              'purge=retired cleanup=joined', flush=True)
    elif settings_mode == 'uncertain':
        print(f'LINUX_DEBIAN_SETTINGS_UNCERTAIN_NATIVE=pass cases=3 app_commit={commit} manifest_sha256={manifest_sha} '
              'dependencies=apt-checked install=dpkg reinstall=same-version remove=preserved purge=retired '
              'ui=actual service=actual authorization=polkit-pam child=kernel-stopped deadline=600 '
              'outcome=Uncertain durable=committed recovery=same-generation cpace=5 stale_refusals=2 '
              'restart=service cleanup=joined', flush=True)
    elif settings_mode == 'failure':
        print(f'LINUX_DEBIAN_SETTINGS_FAILURE_NATIVE=pass cases=8 app_commit={commit} manifest_sha256={manifest_sha} '
              'dependencies=apt-checked install=dpkg reinstall=same-version remove=preserved purge=retired '
              'ui=actual service=actual cancellation=before-submit denial=no-agent authorization=polkit-pam '
              'cpace=7 stale_refusals=3 restart=service-and-gui failure=service-unavailable cleanup=joined', flush=True)
    elif agent_archive_sha is not None:
        print(f'LINUX_DEBIAN_SETTINGS_NATIVE=pass cases=5 app_commit={commit} manifest_sha256={manifest_sha} '
              'dependencies=apt-checked install=dpkg reinstall=same-version remove=preserved purge=retired '
              'ui=actual service=actual cancellation=gtk-selection-and-password authorization=polkit-pam '
              'helper=reaped protected=preserved profile=unchanged retry=same-gui-and-agent '
              'concurrent=gui-and-cli cpace=5 stale_refusals=1 cleanup=joined', flush=True)
    else:
        print(f'LINUX_DEBIAN_INSTALL_NATIVE=pass app_commit={commit} manifest_sha256={manifest_sha} '
              'dependencies=apt-checked install=dpkg reinstall=same-version service=actual credential=preserved '
              'remove=preserved purge=retired desktop=credential-bootstrap cpace=2 wrong_password=refused '
              'admin_units=4 cleanup=joined', flush=True)


if __name__ == '__main__':
    require((len(sys.argv) in (8, 9) and sys.argv[1] == '--run')
            or (len(sys.argv) == 8 and sys.argv[1] in ('--run-settings', '--run-uncertain', '--run-upgrade')),
            'closed Debian installation arguments required')
    require(len(sys.argv) == 8 or re.fullmatch('[0-9a-f]{64}', sys.argv[8]), 'graphical agent digest differs')
    main(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5], sys.argv[6], sys.argv[7],
         sys.argv[8] if len(sys.argv) == 9 else None,
         settings_mode={'--run-settings': 'failure', '--run-uncertain': 'uncertain'}.get(sys.argv[1]),
         upgrade=sys.argv[1] == '--run-upgrade')

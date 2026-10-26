#!/usr/bin/env python3
"""Execute production maintainer scripts with real dpkg in the disposable VM."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile


REPO = Path('/mnt/rustdesk-verifier-inputs/repo')
PACKAGE = 'rustdesk-maintainer-fixture'
UNIT = 'rustdesk.service'
INIT = Path('/etc/init.d/rustdesk')
UNIT_PATH = Path('/usr/lib/systemd/system/rustdesk.service')
BASELINE_SHA = '89a2f108215ea75de2cc61624fd37d46e7f05abf904475e62f56ddf6acd137a9'
RECEIPT = ('DEBIAN_MAINTAINER_NATIVE=pass baseline=disabled-state-lost '
           'candidate=disabled-state-preserved remove-purge=ok deconfigure=ok '
           'tools=actual package=fixture service=oneshot product=unexecuted')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root',
       'DEBIAN_FRONTEND': 'noninteractive', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, *, expected=0):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=ENV, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        raise RuntimeError(f'command timed out and was joined: {arguments!r}: {output[-4096:]!r}')
    require(len(output) <= 65536, f'command diagnostics exceeded bound: {arguments!r}')
    require(process.returncode == expected,
            f'command exit {process.returncode}, expected {expected}: {arguments!r}: {output!r}')
    return output.decode('utf-8', errors='strict')


def links():
    return {str(path): os.readlink(path) for path in Path('/etc').glob('rc?.d/*rustdesk')
            if path.is_symlink()}


def status():
    return run(['dpkg-query', '-W', '-f=${db:Status-Status}', PACKAGE]).strip()


def service_state():
    return run(['systemctl', 'show', '--property=ActiveState', '--value', UNIT]).strip()


def write(path, contents, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(contents)
    path.chmod(mode)


def package(work, version, sources, prerm):
    stage = work / version
    write(stage / 'DEBIAN/control', (
        f'Package: {PACKAGE}\nVersion: {version}\nArchitecture: all\n'
        'Maintainer: RustDesk isolated test <nobody@example.invalid>\n'
        'Description: disposable maintainer script fixture\n').encode())
    write(stage / 'DEBIAN/conffiles', b'/etc/init.d/rustdesk\n')
    for name in ('preinst', 'postinst', 'prerm', 'postrm'):
        write(stage / 'DEBIAN' / name, prerm if name == 'prerm' else sources[name], 0o755)
    write(stage / 'etc/init.d/rustdesk', sources['init'], 0o755)
    # The real scripts manage a harmless native systemd unit, not a RustDesk process.
    write(stage / 'usr/lib/systemd/system/rustdesk.service',
          b'[Unit]\nDescription=Disposable maintainer fixture\n'
          b'[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n'
          b'[Install]\nWantedBy=multi-user.target\n')
    for directory in [stage, *(p for p in stage.rglob('*') if p.is_dir())]:
        directory.chmod(0o755)
    output = work / f'{version}.deb'
    run(['dpkg-deb', '--root-owner-group', '--build', str(stage), str(output)])
    require(output.stat().st_size <= 65536, 'fixture package exceeds bound')
    return output


def main():
    require(os.geteuid() == os.getegid() == 0, 'requires disposable VM root')
    require(REPO.is_dir() and os.statvfs(REPO).f_flag & os.ST_RDONLY,
            'requires the read-only verifier input filesystem')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd'
            and Path('/run/systemd/system').is_dir(), 'requires real guest systemd')
    require('VERSION_CODENAME=bookworm' in Path('/etc/os-release').read_text(),
            'requires the pinned Debian bookworm guest')
    roots = [Path('/root/.config/RustDesk'), Path('/root/.config/rustdesk')]
    neighbor = Path('/etc/rc2.d/S98rustdesk-neighbor')
    for path in [INIT, UNIT_PATH, Path('/etc/systemd/system/rustdesk.service'),
                 Path('/usr/bin/rustdesk'), neighbor, *roots]:
        require(not os.path.lexists(path), f'fixture path already occupied: {path}')
    require(not links(), 'pre-existing RustDesk runlevel links')
    run(['dpkg-query', '-W', PACKAGE], expected=1)
    tools = {}
    for name in ('dpkg', 'dpkg-deb', 'dpkg-query', 'update-rc.d',
                 'deb-systemd-helper', 'deb-systemd-invoke', 'systemctl'):
        path = shutil.which(name, path=ENV['PATH'])
        require(path is not None, f'missing native tool: {name}')
        tools[name] = {'path': path, 'sha256': digest(Path(path).read_bytes())}
    tool_version = run(['dpkg-query', '-W', '-f=${Version}', 'init-system-helpers']).strip()
    sources = {name: (REPO / 'res/DEBIAN' / name).read_bytes()
               for name in ('preinst', 'postinst', 'prerm', 'postrm')}
    sources['init'] = (REPO / 'res/rustdesk.init').read_bytes()
    before = (REPO / 'res/DEBIAN/prerm-before').read_bytes()
    require(digest(before) == BASELINE_SHA, 'historical prerm identity differs')
    identities = {name: digest(value) for name, value in sources.items()}
    artifacts = {}
    with tempfile.TemporaryDirectory(prefix='rustdesk-maintainer-') as directory:
        work = Path(directory)
        baseline = package(work, '1.0', sources, before)
        candidate = package(work, '2.0', sources, sources['prerm'])
        artifacts = {p.name: digest(p.read_bytes()) for p in (baseline, candidate)}
        neighbor.symlink_to('../init.d/rustdesk-neighbor')
        run(['dpkg', '--install', str(baseline)])
        require(status() == 'installed' and INIT.is_file() and service_state() == 'active',
                'baseline package/service did not actually start')
        initial_links = links()
        require(initial_links, 'baseline install did not create actual SysV links')
        run(['update-rc.d', 'rustdesk', 'disable'])
        disabled_links = links()
        require(disabled_links and disabled_links != initial_links
                and all('/S' not in path for path in disabled_links),
                'native helper did not disable actual SysV start links')
        run(['dpkg', '--remove', PACKAGE])
        require(status() == 'config-files' and INIT.is_file() and not links(),
                'baseline did not expose premature loss of disabled SysV state')
        run(['dpkg', '--install', str(baseline)])
        require(links() == initial_links, 'baseline reinstall did not restore unwanted defaults')
        print('DEBIAN_MAINTAINER_BASELINE=' + json.dumps({
            'remove_exit': 0, 'prerm_sha256': BASELINE_SHA,
            'disabled_links': disabled_links, 'removed_links': {},
            'reinstalled_links': links(), 'disabled_state_lost': True}), flush=True)

        run(['dpkg', '--install', str(candidate)])
        require(status() == 'installed' and service_state() == 'active',
                'candidate upgrade did not restore the installed active fixture')
        installed = Path('/var/lib/dpkg/info')
        require((installed / f'{PACKAGE}.prerm').read_bytes() == sources['prerm'],
                'dpkg did not install the exact candidate prerm')
        run(['update-rc.d', 'rustdesk', 'disable'])
        candidate_links = links()
        require(candidate_links == disabled_links, 'candidate disabled state differs')
        run([str(installed / f'{PACKAGE}.prerm'), 'deconfigure'])
        require(INIT.is_file() and links() == candidate_links and service_state() == 'inactive',
                'deconfigure failed to stop the fixture while preserving init/link state')
        run([str(installed / f'{PACKAGE}.postinst'), 'configure'])
        require(service_state() == 'active', 'configure did not restart after deconfigure')

        run(['dpkg', '--remove', PACKAGE])
        require(status() == 'config-files' and INIT.is_file() and links() == candidate_links,
                'removal did not preserve conffile and runlevel links until purge')
        require(service_state() == 'inactive' and not UNIT_PATH.exists(),
                'package removal left the fixture unit active or installed')
        run(['dpkg', '--install', str(candidate)])
        require(status() == 'installed' and service_state() == 'active'
                and links() == disabled_links,
                'candidate reinstallation lost the administrator-disabled SysV state')
        run(['dpkg', '--remove', PACKAGE])
        require(status() == 'config-files' and links() == disabled_links,
                'repeated removal lost the retained disabled state')
        for root in roots:
            write(root / 'owned-fixture', b'purge only this disposable test configuration\n')
        run(['dpkg', '--purge', PACKAGE])
        require(not INIT.exists() and not links() and all(not root.exists() for root in roots),
                'purge did not retire the init script, links and owned configuration')
        remaining = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status}', PACKAGE],
                                   env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=5, check=False)
        require((remaining.returncode == 1 and not remaining.stdout)
                or (remaining.returncode == 0 and remaining.stdout == b'not-installed'),
                'purge left the fixture installed in the package database')
        require(neighbor.is_symlink() and os.readlink(neighbor) == '../init.d/rustdesk-neighbor',
                'purge changed the neighboring service link')
        neighbor.unlink()
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            require((REPO / 'res/DEBIAN' / name).read_bytes() == sources[name],
                    f'input changed: {name}')
        require((REPO / 'res/rustdesk.init').read_bytes() == sources['init'], 'init source changed')
    print('DEBIAN_MAINTAINER_ARTIFACTS=' + json.dumps({
        'sources': identities, 'packages': artifacts, 'tools': tools,
        'candidate_disabled_links': disabled_links, 'candidate_purged_links': {},
        'init_system_helpers': tool_version, 'baseline_commit':
        'a5d3fb539999e11bb2a15543fbc70366c1a3df41'}, sort_keys=True), flush=True)
    print(RECEIPT, flush=True)


if __name__ == '__main__':
    main()

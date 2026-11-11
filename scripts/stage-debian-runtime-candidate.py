#!/usr/bin/env python3
"""Acquire the generated Debian package's runtime closure in the acquisition VM."""

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import shlex
import stat
import subprocess
import sys

OUTPUT = Path('/outputs')
APT = Path('/tmp/debian-runtime-apt')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(APT), 'LC_ALL': 'C'}
MAX_BYTES = 512 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(arguments, timeout=180):
    result = subprocess.run(arguments, env=ENV, capture_output=True, text=True, timeout=timeout)
    require(len(result.stdout) + len(result.stderr) <= 1024 * 1024, 'APT output exceeds its bound')
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    require(result.returncode == 0, f'{arguments[0]} exited {result.returncode}')
    return result.stdout


def main():
    require(sys.argv[1:] == ['/outputs'] and Path('/.dockerenv').is_file(), 'closed acquisition arguments required')
    uid, gid = int(os.environ['RUNTIME_UID']), int(os.environ['RUNTIME_GID'])
    require(uid == os.getuid() != 0 and gid == os.getgid() != 0, 'runtime acquisition principal differs')
    info = OUTPUT.lstat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
            (uid, gid, 0o700) and not list(OUTPUT.iterdir()), 'runtime output authority differs')
    require(run(['/usr/bin/dpkg', '--print-architecture']).strip() == 'amd64', 'runtime architecture differs')
    snapshots = [os.environ['RUNTIME_DEBIAN_SNAPSHOT'], os.environ['RUNTIME_SECURITY_SNAPSHOT']]
    require(all(re.fullmatch('[0-9]{8}T[0-9]{6}Z', value) for value in snapshots), 'snapshot pins differ')
    base = os.environ['RUNTIME_BASE']
    require(re.fullmatch('sha256:[0-9a-f]{64}', base), 'base pin differs')
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    os.umask(0o077)
    for path in [APT, APT / 'lists', APT / 'lists/partial', APT / 'log',
                 OUTPUT / 'packages', OUTPUT / 'packages/partial']:
        path.mkdir(mode=0o700)
    status = APT / 'status'
    status.write_bytes(b'')
    sources = APT / 'snapshot.sources'
    sources.write_text(''.join(
        f'Types: deb\nURIs: https://snapshot.debian.org/archive/{archive}/{snapshot}/\n'
        f'Suites: {suites}\nComponents: main\n'
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\n'
        for archive, snapshot, suites in [('debian', snapshots[0], 'bookworm bookworm-updates'),
                                          ('debian-security', snapshots[1], 'bookworm-security')]))
    options = []
    for setting in [f'Dir::Etc::sourcelist={sources}', 'Dir::Etc::sourceparts=-',
                    f'Dir::State::lists={APT}/lists', f'Dir::State::status={status}',
                    'Dir::Cache::archives=/outputs/packages', f'Dir::Log={APT}/log',
                    f'Dir::State::extended_states={APT}/extended_states',
                    'APT::Sandbox::User=', 'Debug::NoLocking=1', 'Acquire::Retries=0',
                    'Acquire::https::Timeout=30', 'APT::Get::AllowUnauthenticated=false',
                    'Acquire::AllowInsecureRepositories=false', 'Acquire::ForceHash=SHA256']:
        options += ['-o', setting]
    os.chdir('/source')
    module = runpy.run_path('/source/build.py')
    control = OUTPUT / 'control'
    module['generate_control_file'](module['get_version'](), control)
    fields = dict(line.split(': ', 1) for line in control.read_text().splitlines() if ': ' in line)
    require(fields['Package'] == 'rustdesk' and fields['Architecture'] == 'amd64', 'generated package identity differs')
    dependencies = fields['Depends'] + ', ' + fields['Recommends']
    run(['/usr/bin/apt-get', *options, '-o', 'APT::Update::Error-Mode=any', 'update', '-qq'])
    command = ['/usr/bin/apt-get', *options, '--yes', '--download-only', '--no-install-recommends', '--no-remove']
    plan = run([*command, '--print-uris', 'satisfy', dependencies])
    expected = {}
    for line in plan.splitlines():
        if not line.startswith("'"):
            continue
        uri, filename, size, checksum = shlex.split(line)
        require(uri.startswith(tuple(f'https://snapshot.debian.org/archive/{archive}/{snapshot}/'
                                     for archive, snapshot in zip(('debian', 'debian-security'), snapshots))),
                'download plan leaves the authenticated snapshot')
        require(re.fullmatch(r'[A-Za-z0-9.+_:%~\-]+\.deb', filename) and filename not in expected,
                'download filename differs or repeats')
        require(re.fullmatch('SHA256:[0-9a-f]{64}', checksum) and 0 < int(size) <= MAX_FILE,
                'download size or SHA-256 is unavailable')
        expected[filename] = {'bytes': int(size), 'sha256': checksum[7:], 'uri': uri}
    require(0 < len(expected) <= 512 and sum(record['bytes'] for record in expected.values()) <= MAX_BYTES,
            'runtime closure exceeds its admission bound')
    print(f'DEBIAN_RUNTIME_PLAN=admitted packages={len(expected)} bytes={sum(r["bytes"] for r in expected.values())}', flush=True)
    run([*command, 'satisfy', dependencies])
    require(status.read_bytes() == b'', 'download-only acquisition modified the private dpkg database')
    packages = sorted((OUTPUT / 'packages').glob('*.deb'))
    require({p.name for p in packages} == set(expected), 'downloaded package inventory differs from the admitted plan')
    records = []
    for path in packages:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (info.st_uid, info.st_gid) == (uid, gid),
                'downloaded package authority differs')
        record = expected[path.name]
        require(info.st_size == record['bytes'] and digest(path) == record['sha256'], 'downloaded package bytes differ')
        metadata = subprocess.check_output(['/usr/bin/dpkg-deb', '--show',
                    '--showformat=${Package}\t${Version}\t${Architecture}', str(path)], env=ENV, text=True, timeout=10)
        name, version, architecture = metadata.split('\t')
        require(re.fullmatch('[a-z0-9][a-z0-9+.-]*', name) and re.fullmatch('[0-9A-Za-z.+:~\\-]+', version)
                and architecture in ('amd64', 'all'), 'downloaded package metadata differs')
        records.append('\t'.join([name, version, architecture, path.name, str(info.st_size), record['sha256']]))
        path.chmod(0o400)
    (OUTPUT / 'manifest.tsv').write_text('\n'.join(sorted(records)) + '\n')
    (OUTPUT / 'plan.json').write_text(json.dumps(expected, sort_keys=True, indent=2) + '\n')
    (OUTPUT / 'contract').write_text(
        f'base={base}\ndebian_snapshot={snapshots[0]}\nsecurity_snapshot={snapshots[1]}\n'
        f'generator_sha256={digest("/source/build.py")}\ncontrol_sha256={digest(control)}\n'
        'closure=empty-dpkg-status\nroots=production-Depends-and-Recommends\n'
        f'keyring_sha256={digest("/usr/share/keyrings/debian-archive-keyring.gpg")}\n')
    for name in ['control', 'manifest.tsv', 'plan.json', 'contract']:
        (OUTPUT / name).chmod(0o400)
    print(f'DEBIAN_RUNTIME_CANDIDATE=downloaded packages={len(records)} bytes={sum(r["bytes"] for r in expected.values())} '
          'authenticated=apt-signed-metadata hashes=sha256 installed=none', flush=True)


if __name__ == '__main__':
    main()

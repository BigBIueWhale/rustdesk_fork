#!/usr/bin/env python3
"""Acquire one review-only Debian camera-test kernel; never install or execute it."""
import email.utils
import hashlib
import json
import lzma
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request


ORIGIN = 'https://deb.debian.org/debian/'
RELEASE = '6.1.0-50-amd64'
PACKAGE = 'linux-image-' + RELEASE
VERSION = '6.1.176-1'
FILENAME = 'pool/main/l/linux-signed-amd64/' + PACKAGE + '_' + VERSION + '_amd64.deb'
# Independent publisher path: packages.debian.org/bookworm/amd64/
# linux-image-6.1.0-50-amd64/download. The signed archive must agree before fetch.
PACKAGE_SIZE = 70305560
PACKAGE_SHA256 = '7b5597492a0a65aee61985a492e6bcc3f2cde830072a0e3b3d8c7e1b90279bd3'
BOOKWORM_KEYS = {'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8',
                 '4D64FEC119C2029067D6E791F8D2585B8783D481'}
KEYRING = '/usr/share/keyrings/debian-archive-keyring.gpg'
INDEX_LIMIT = 16777216
EXPANDED_LIMIT = 100663296


def require(condition, message):
    if not condition:
        raise ValueError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise ValueError('archive redirect refused')


def seal_file(root, name, payload):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=root)
    with os.fdopen(fd, 'wb') as output:
        output.write(payload)
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())
    os.fsync(root)


def download(root, name, path, limit, expected=None):
    require(re.fullmatch(r'[A-Za-z0-9_./+-]+', path) is not None
            and not any(part in ('', '.', '..') for part in path.split('/')),
            'archive path differs')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(ORIGIN + path, headers={'Accept-Encoding': 'identity'})
    digest, size, started = hashlib.sha256(), 0, time.monotonic()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=root)
    with os.fdopen(fd, 'wb') as output, opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == ORIGIN + path,
                'archive response differs')
        require(response.headers.get('Content-Encoding', 'identity') == 'identity',
                'archive content encoding differs')
        declared = response.headers.get('Content-Length')
        if declared is not None:
            require(declared.isdecimal() and 0 < int(declared) <= limit,
                    'archive declared size exceeds bound')
        while True:
            require(time.monotonic() - started <= 180, 'archive transfer exceeded deadline')
            block = response.read(min(1048576, limit - size + 1))
            if not block:
                break
            size += len(block)
            require(size <= limit, 'archive bytes exceed bound')
            output.write(block)
            digest.update(block)
        require(size > 0 and (declared is None or size == int(declared)),
                'archive transfer size differs')
        record = {'file': name, 'bytes': size, 'sha256': digest.hexdigest(),
                  'url': ORIGIN + path}
        if expected is not None:
            require((size, record['sha256']) == expected, 'archive pinned bytes differ')
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())
    os.fsync(root)
    return record


def fields(paragraph):
    result, current = {}, None
    for line in paragraph.splitlines():
        if line.startswith((' ', '\t')):
            require(current is not None, 'orphan archive continuation')
            result[current] += '\n' + line[1:]
        else:
            key, separator, value = line.partition(':')
            require(separator and key not in result, 'duplicate or malformed archive field')
            result[key], current = value.lstrip(), key
    return result


def verify_signature(signature, release):
    return subprocess.run(['/usr/bin/gpgv', '--homedir', '/tmp', '--status-fd=1',
                           '--keyring', KEYRING, signature, release],
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=20, check=False)


def inspect_package(path):
    identity = subprocess.run(['/usr/bin/dpkg-deb', '--show',
                               '--showformat=${Package}\n${Version}\n${Architecture}\n', path],
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                              capture_output=True, timeout=20, check=True)
    require(identity.stdout.decode('ascii') == PACKAGE + '\n' + VERSION + '\namd64\n',
            'Debian package identity differs')
    config, modules, count, expanded, kernels = None, [], 0, 0, 0
    with tempfile.TemporaryFile() as error:
        with subprocess.Popen(['/usr/bin/dpkg-deb', '--fsys-tarfile', path],
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                              stdout=subprocess.PIPE, stderr=error) as process:
            try:
                with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                    for member in archive:
                        count += 1
                        expanded += member.size
                        require(count <= 20000 and expanded <= 536870912,
                                'kernel archive exceeds inspection bounds')
                        name = member.name.removeprefix('./')
                        if name == 'boot/vmlinuz-' + RELEASE:
                            require(member.isfile() and 1048576 <= member.size <= 67108864,
                                    'kernel image differs')
                            kernels += 1
                        if name == 'boot/config-' + RELEASE:
                            require(config is None and member.isfile()
                                    and 0 < member.size <= 1048576, 'kernel config differs')
                            with archive.extractfile(member) as source:
                                config = source.read(1048577)
                            require(len(config) == member.size, 'kernel config is short')
                        if name.startswith('lib/modules/' + RELEASE + '/') and name.endswith('.ko'):
                            require(member.isfile(), 'kernel module is not a regular file')
                            modules.append(name)
                require(process.wait(timeout=20) == 0, 'kernel archive inspection failed')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    require(config is not None and kernels == 1, 'one kernel image/configuration is required')
    settings = dict(line.split('=', 1) for line in config.decode('ascii').splitlines()
                    if line.startswith('CONFIG_') and '=' in line)
    require(settings.get('CONFIG_MEDIA_SUPPORT') in ('y', 'm')
            and settings.get('CONFIG_VIDEO_DEV') in ('y', 'm')
            and settings.get('CONFIG_VIDEO_VIVID') == 'm', 'kernel lacks V4L2/vivid support')
    require(any(name.endswith('/vivid.ko') for name in modules), 'vivid module is absent')
    require(any(name.endswith('/videodev.ko') for name in modules), 'V4L2 module is absent')
    return config, sorted(modules)


def main():
    require(len(sys.argv) == 2 and re.fullmatch('[0-9a-f]{40}', sys.argv[1]),
            'one exact source commit is required')
    require(os.getuid() != 0 and os.getgid() != 0, 'kernel acquisition refuses root')
    root = os.open('/output', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(root)
        require((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
                == (os.getuid(), os.getgid(), 0o700) and not os.listdir(root),
                'kernel candidate output is not private and empty')
        records = [download(root, 'Release', 'dists/bookworm/Release', 1048576),
                   download(root, 'Release.gpg', 'dists/bookworm/Release.gpg', 65536)]
        verified = verify_signature('/output/Release.gpg', '/output/Release')
        require(verified.returncode == 0, 'Debian archive signature failed')
        valid = [line.split() for line in verified.stdout.decode('ascii').splitlines()
                 if line.startswith('[GNUPG:] VALIDSIG ')]
        signers = {parts[-1] for parts in valid if len(parts) == 12}
        require(BOOKWORM_KEYS <= signers, 'both exact bookworm signing principals are required')
        seal_file(root, 'signature-status.txt', verified.stdout + verified.stderr)
        with open('/output/Release', 'rb') as source:
            release_bytes = source.read(1048577)
        with tempfile.NamedTemporaryFile(dir='/tmp') as tampered:
            tampered.write(bytes([release_bytes[0] ^ 1]) + release_bytes[1:])
            tampered.flush()
            negative = verify_signature('/output/Release.gpg', tampered.name)
            require(negative.returncode != 0, 'tampered Release unexpectedly authenticated')
        release = fields(release_bytes.decode('ascii'))
        require(release.get('Origin') == 'Debian' and release.get('Codename') == 'bookworm',
                'signed archive origin/codename differs')
        now = time.time()
        date = email.utils.parsedate_to_datetime(release['Date']).timestamp()
        require(date <= now + 86400, 'archive date is in the future')
        if 'Valid-Until' in release:
            require(now <= email.utils.parsedate_to_datetime(release['Valid-Until']).timestamp(),
                    'signed archive has expired')
        indexes = [line.split() for line in release['SHA256'].splitlines()
                   if line.split()[-1:] == ['main/binary-amd64/Packages.xz']]
        require(len(indexes) == 1 and len(indexes[0]) == 3, 'one signed package index is required')
        digest, size, _ = indexes[0]
        require(re.fullmatch('[0-9a-f]{64}', digest) and size.isdecimal()
                and 0 < int(size) <= INDEX_LIMIT, 'signed package index bounds differ')
        records.append(download(root, 'Packages.xz',
                                'dists/bookworm/main/binary-amd64/by-hash/SHA256/' + digest,
                                INDEX_LIMIT, (int(size), digest)))
        decoder = lzma.LZMADecompressor(memlimit=134217728)
        with open('/output/Packages.xz', 'rb') as source:
            text = decoder.decompress(source.read(INDEX_LIMIT + 1), max_length=EXPANDED_LIMIT + 1)
        require(decoder.eof and not decoder.unused_data and len(text) <= EXPANDED_LIMIT,
                'package index expansion differs or exceeds bound')
        matches = [fields(paragraph) for paragraph in text.decode('utf-8').strip().split('\n\n')
                   if paragraph.startswith('Package: ' + PACKAGE + '\n')]
        require(len(matches) == 1, 'one exact kernel package is required')
        entry = matches[0]
        require((entry['Version'], entry['Architecture'], entry['Filename'], entry['Size'],
                 entry['SHA256']) == (VERSION, 'amd64', FILENAME, str(PACKAGE_SIZE), PACKAGE_SHA256),
                'signed kernel metadata differs from independent publisher pin')
        records.append(download(root, FILENAME.rsplit('/', 1)[-1], FILENAME,
                                PACKAGE_SIZE, (PACKAGE_SIZE, PACKAGE_SHA256)))
        config, modules = inspect_package('/output/' + records[-1]['file'])
        seal_file(root, 'kernel.config', config)
        seal_file(root, 'modules.json', (json.dumps(modules, indent=2) + '\n').encode())
        with open(KEYRING, 'rb') as source:
            keyring_sha256 = hashlib.file_digest(source, 'sha256').hexdigest()
        manifest = {'format': 'rustdesk-verifier-media-kernel-candidate-v1',
                    'source_commit': sys.argv[1], 'kernel_release': RELEASE,
                    'package_version': VERSION, 'records': records,
                    'archive_signers': sorted(signers), 'keyring_sha256': keyring_sha256,
                    'publisher_metadata_url': 'https://packages.debian.org/bookworm/amd64/' + PACKAGE + '/download',
                    'config_sha256': hashlib.sha256(config).hexdigest(), 'module_count': len(modules),
                    'tampered_release_refused': True, 'package_installed': False,
                    'kernel_executed': False, 'boot_inputs_promoted': False}
        seal_file(root, 'manifest.json', (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        require(set(os.listdir(root)) == {'Release', 'Release.gpg', 'Packages.xz',
                'signature-status.txt', 'kernel.config', 'modules.json', 'manifest.json', records[-1]['file']},
                'candidate inventory differs')
        print('VERIFIER_MEDIA_KERNEL_CANDIDATE=pass sha256=' + PACKAGE_SHA256
              + ' signed=bookworm media=v4l2-vivid installed=no executed=no promoted=no')
    finally:
        os.close(root)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, UnicodeError, lzma.LZMAError,
            tarfile.TarError, subprocess.SubprocessError) as error:
        print('verifier media kernel acquisition: ' + str(error), file=sys.stderr)
        sys.exit(1)

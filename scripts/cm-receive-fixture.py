#!/usr/bin/env python3
"""Observe receive artifacts in the owned CM replay container, never on a host."""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, stat.S_IMODE(info.st_mode)) != (1000, 0o700):
        raise ValueError(f"Unexpected CM fixture directory: {path}")


def main():
    if (os.getuid(), os.getgid()) != (1000, 1000) or Path.cwd() != Path('/work'):
        raise ValueError('CM fixture requires its unprivileged guest container')
    if os.environ.get('HOME') != '/tmp/rd-cm-file-replay' or len(sys.argv) != 3:
        raise ValueError('CM fixture context differs')
    mode, leaf = sys.argv[1:]
    if mode not in ('path', 'staged', 'retired') or not re.fullmatch(r'[a-z-]+\.txt', leaf):
        raise ValueError('CM fixture operation differs')
    root = Path('/tmp/rd-cm-file-replay/allowed-after-login')
    private_directory(root)
    names = os.listdir(root)
    if len(names) > 128:
        raise ValueError('CM fixture inventory exceeds its bound')
    containers = [root / name for name in names if re.fullmatch(r'\.rustdesk-receive-[0-9a-f]{32}', name)]
    child = hashlib.sha256(b'rustdesk.receive.file.v1\0' + leaf.encode()).hexdigest()
    for container in containers:
        private_directory(container)
    paths = [container / child for container in containers]
    if mode == 'retired':
        if any(os.path.lexists(path) for path in paths):
            raise ValueError(f'CM receive still retains {leaf}')
        return
    if len(paths) != 1:
        raise ValueError('CM fixture needs one live receive namespace')
    path = paths[0]
    if mode == 'staged':
        private_directory(path)
        for name in ('payload.download', 'resume.digest', 'claim.download.lock'):
            info = (path / name).lstat()
            if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode)) != (1000, 1, 0o600):
                raise ValueError(f'CM receive artifact differs: {name}')
    print(path)


if __name__ == '__main__':
    main()

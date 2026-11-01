#!/usr/bin/env python3
"""Exercise each exact page restoration callback with controlled saved-address reads."""

import hashlib
import os
from pathlib import Path
import sys


def main():
    if (sys.argv[1:] not in (['prepare'], ['verify'])
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/project')):
        raise ValueError('address restore probe requires its isolated nonroot entry')
    repo, project = Path('/source/flutter'), Path('/work/project')
    methods = []
    for platform in ('desktop', 'mobile'):
        relative = f'lib/{platform}/pages/connection_page.dart'
        source = (repo / relative).read_bytes()
        if (project / relative).read_bytes() != source:
            raise ValueError(f'address page copy differs: {platform}')
        text = source.decode('utf-8')
        start = '    WidgetsBinding.instance.addPostFrameCallback((_) async {'
        if text.count(start) != 1:
            raise ValueError(f'address restore callback is ambiguous: {platform}')
        begin = text.index(start)
        end = text.index('\n    });', begin) + len('\n    });')
        callback = text[begin:end]
        methods.append(f'  void _restore_{platform}() {{\n{callback}\n  }}\n')
        print(f'ADDRESS_RESTORE_SOURCE={sys.argv[1]} platform={platform} '
              f'page={hashlib.sha256(source).hexdigest()} '
              f'callback={hashlib.sha256(callback.encode()).hexdigest()}', flush=True)
    relative = 'test_probes/address_restore_cases.dart.inc'
    cases = (repo / relative).read_bytes()
    if (project / relative).read_bytes() != cases:
        raise ValueError('address restore case copy differs')
    marker = '// EXACT_PAGE_RESTORATION_CALLBACKS'
    if cases.count(marker.encode()) != 1:
        raise ValueError('address restore insertion marker differs')
    generated = cases.replace(marker.encode(), ''.join(methods).encode())
    target = project / 'test_probes/address_restore_probe_test.dart'
    if sys.argv[1] == 'prepare':
        with target.open('xb') as stream:
            stream.write(generated)
        target.chmod(0o400)
    if target.read_bytes() != generated:
        raise ValueError('address restore executed source differs')
    print(f'ADDRESS_RESTORE_PROBE={sys.argv[1]} '
          f'sha256={hashlib.sha256(generated).hexdigest()} '
          'callbacks=exact controller=production reads=double feedback=double', flush=True)


if __name__ == '__main__':
    main()

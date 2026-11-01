#!/usr/bin/env python3
"""Mount the complete desktop connection page with controlled native reads."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = {
    'lib/models/native_model.dart': b'\nvoid installConnectionPageBinding(RustdeskImpl binding) {\n  PlatformFFI.instance._ffiBind = binding;\n}\n',
    'lib/common.dart': b'\nvoid installConnectionPageOwner(FFI owner) {\n  _globalFFI = owner;\n}\n',
}


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('connection page probe requires its isolated nonroot entry')
    repo, project = Path('/source/flutter'), Path('/work/source/flutter')
    prepare = sys.argv[1] == 'prepare'
    for source in sorted((repo / 'lib').rglob('*')):
        if not source.is_file():
            continue
        relative = source.relative_to(repo).as_posix()
        if relative in ('lib/generated_bridge.dart', 'lib/generated_bridge.freezed.dart'):
            continue
        original = source.read_bytes()
        target = project / relative
        suffix = SUPPORT.get(relative, b'')
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'connection page source differs: {relative}')
            if suffix:
                with target.open('ab') as stream:
                    stream.write(suffix)
        if target.read_bytes() != original + suffix:
            raise ValueError(f'connection page copy differs: {relative}')
    cases = (repo / 'test_probes/connection_page_cases.dart.inc').read_bytes()
    target = project / 'test_probes/connection_page_probe_test.dart'
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('connection page cases differ')
    widget = (repo / 'lib/desktop/pages/connection_page.dart').read_bytes()
    print(f'CONNECTION_PAGE_SOURCE={sys.argv[1]} '
          f'widget={hashlib.sha256(widget).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'page=exact toast=production native_reads=double translation=double', flush=True)


if __name__ == '__main__':
    main()

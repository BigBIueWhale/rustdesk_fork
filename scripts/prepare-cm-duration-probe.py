#!/usr/bin/env python3
"""Expose the unchanged CM header only in the isolated Flutter test copy."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = {
    'lib/models/native_model.dart': (
        '\nvoid installCmDurationProbeBinding(RustdeskImpl binding) {\n'
        '  PlatformFFI.instance._ffiBind = binding;\n}\n'),
    'lib/desktop/pages/server_page.dart': (
        '\nWidget buildCmDurationProbe(Client client) => _CmHeader(client: client);\n'),
}


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('CM duration probe requires its isolated nonroot entry')
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
        expected = original + SUPPORT.get(relative, '').encode('utf-8')
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'CM duration source differs: {relative}')
            if relative in SUPPORT:
                target.write_bytes(expected)
        if target.read_bytes() != expected:
            raise ValueError(f'CM duration copy differs: {relative}')
    source = repo / 'test_probes/cm_duration_cases.dart.inc'
    target = project / 'test_probes/cm_duration_probe_test.dart'
    cases = source.read_bytes()
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('CM duration cases differ')
    page = (repo / 'lib/desktop/pages/server_page.dart').read_bytes()
    model = (repo / 'lib/models/server_model.dart').read_bytes()
    print(f'CM_DURATION_SOURCE={sys.argv[1]} '
          f'page={hashlib.sha256(page).hexdigest()} '
          f'model={hashlib.sha256(model).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'source_copy=exact native_binding=double', flush=True)


if __name__ == '__main__':
    main()

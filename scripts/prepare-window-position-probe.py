#!/usr/bin/env python3
"""Bind window persistence to explicit native doubles in the isolated test copy."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = {
    'lib/models/native_model.dart': (
        '\nvoid installWindowPositionProbeBinding(RustdeskImpl binding) {\n'
        '  PlatformFFI.instance._ffiBind = binding;\n}\n'),
    'lib/common.dart': (
        '\nvoid resetWindowPositionProbe() {\n'
        '  _saveWindowDebounce.cancel();\n'
        '  _lastWindowPosition = null;\n}\n'),
}


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('window position probe requires its isolated nonroot entry')
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
        suffix = SUPPORT.get(relative, '').encode()
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'window position source differs: {relative}')
            if suffix:
                with target.open('ab') as stream:
                    stream.write(suffix)
        if target.read_bytes() != original + suffix:
            raise ValueError(f'window position copy differs: {relative}')
    cases = (repo / 'test_probes/window_position_cases.dart.inc').read_bytes()
    target = project / 'test_probes/window_position_probe_test.dart'
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('window position cases differ')
    common = (repo / 'lib/common.dart').read_bytes()
    print(f'WINDOW_POSITION_SOURCE={sys.argv[1]} '
          f'common={hashlib.sha256(common).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'source_copy=exact native_storage=double window_channel=double', flush=True)


if __name__ == '__main__':
    main()

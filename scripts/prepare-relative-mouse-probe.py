#!/usr/bin/env python3
"""Install explicit native doubles around the unchanged Dart mouse model in its VM."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = ('\nvoid installRelativeMouseProbeBinding(RustdeskImpl binding) {\n'
           '  PlatformFFI.instance._ffiBind = binding;\n}\n').encode()


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('relative mouse probe requires its isolated nonroot entry')
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
        suffix = SUPPORT if relative == 'lib/models/native_model.dart' else b''
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'relative mouse source differs: {relative}')
            if suffix:
                with target.open('ab') as stream:
                    stream.write(suffix)
        if target.read_bytes() != original + suffix:
            raise ValueError(f'relative mouse copy differs: {relative}')
    cases = (repo / 'test_probes/relative_mouse_enable_cases.dart.inc').read_bytes()
    target = project / 'test_probes/relative_mouse_enable_probe_test.dart'
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('relative mouse cases differ')
    model = (repo / 'lib/models/relative_mouse_model.dart').read_bytes()
    print(f'RELATIVE_MOUSE_SOURCE={sys.argv[1]} '
          f'model={hashlib.sha256(model).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'model_copy=exact native_binding=double window_channel=double', flush=True)


if __name__ == '__main__':
    main()

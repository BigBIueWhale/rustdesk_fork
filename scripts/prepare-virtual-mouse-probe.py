#!/usr/bin/env python3
"""Install native preference/input doubles in the isolated Flutter workload."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = ('\nvoid installVirtualMouseProbeBinding(RustdeskImpl binding) {\n'
           '  PlatformFFI.instance._ffiBind = binding;\n}\n').encode()


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('virtual mouse probe requires its isolated nonroot entry')
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
                raise ValueError(f'virtual mouse source differs: {relative}')
            if suffix:
                with target.open('ab') as stream:
                    stream.write(suffix)
        if target.read_bytes() != original + suffix:
            raise ValueError(f'virtual mouse copy differs: {relative}')
    cases = (repo / 'test_probes/virtual_mouse_button_cases.dart.inc').read_bytes()
    target = project / 'test_probes/virtual_mouse_button_probe_test.dart'
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('virtual mouse cases differ')
    for name in ('lib/mobile/widgets/floating_mouse_widgets.dart',
                 'lib/models/input_model.dart',
                 'lib/common/widgets/remote_input.dart'):
        print(f'VIRTUAL_MOUSE_SOURCE={sys.argv[1]} file={name} '
              f'sha256={hashlib.sha256((repo / name).read_bytes()).hexdigest()}', flush=True)
    print(f'VIRTUAL_MOUSE_TESTS={hashlib.sha256(cases).hexdigest()} '
          'source_copy=exact preferences_and_native_input=double', flush=True)


if __name__ == '__main__':
    main()

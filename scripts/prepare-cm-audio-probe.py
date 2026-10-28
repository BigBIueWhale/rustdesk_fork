#!/usr/bin/env python3
"""Expose the production CM panel and controlled bridge only inside its VM."""

import hashlib
import os
from pathlib import Path
import sys


SUFFIXES = {
    'lib/models/native_model.dart': (
        '\nvoid installCmAudioProbeBinding(RustdeskImpl binding) {\n'
        '  PlatformFFI.instance._ffiBind = binding;\n}\n').encode(),
    'lib/desktop/pages/server_page.dart': (
        '\nWidget buildCmAudioProbePanel(Client client) =>\n'
        '    _CmControlPanel(client: client);\n').encode(),
}


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('CM audio probe requires its isolated nonroot entry')
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
        suffix = SUFFIXES.get(relative, b'')
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'CM audio source differs: {relative}')
            if suffix:
                with target.open('ab') as stream:
                    stream.write(suffix)
        if target.read_bytes() != original + suffix:
            raise ValueError(f'CM audio copy differs: {relative}')
    cases = (repo / 'test_probes/cm_audio_cases.dart.inc').read_bytes()
    target = project / 'test_probes/cm_audio_probe_test.dart'
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('CM audio cases differ')
    panel = (repo / 'lib/desktop/pages/server_page.dart').read_bytes()
    print(f'CM_AUDIO_SOURCE={sys.argv[1]} '
          f'panel={hashlib.sha256(panel).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'panel_copy=exact native_binding=double', flush=True)


if __name__ == '__main__':
    main()

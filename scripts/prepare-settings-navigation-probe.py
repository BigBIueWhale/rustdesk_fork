#!/usr/bin/env python3
"""Bind the real settings page to explicit native doubles inside its VM test copy."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = {
    'lib/models/native_model.dart': (
        '\nvoid installSettingsProbeBinding(RustdeskImpl binding) {\n'
        '  PlatformFFI.instance._ffiBind = binding;\n}\n'),
    'lib/common.dart': (
        '\nvoid installSettingsProbeParent(FFI parent) {\n'
        '  _globalFFI = parent;\n}\n'),
}


def main():
    if (sys.argv[1:] not in [['prepare'], ['verify']]
            or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path('/work/source/flutter')):
        raise ValueError('settings probe requires its isolated nonroot test entry')
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
                raise ValueError(f'settings probe source differs: {relative}')
            if relative in SUPPORT:
                with target.open('ab') as stream:
                    stream.write(SUPPORT[relative].encode('utf-8'))
        if target.read_bytes() != expected:
            raise ValueError(f'settings probe copy differs: {relative}')
    source = repo / 'test_probes/settings_navigation_cases.dart.inc'
    target = project / 'test_probes/settings_navigation_probe_test.dart'
    cases = source.read_bytes()
    if prepare:
        with target.open('xb') as stream:
            stream.write(cases)
        target.chmod(0o400)
    if target.read_bytes() != cases:
        raise ValueError('settings probe cases differ')
    page = (repo / 'lib/desktop/pages/desktop_setting_page.dart').read_bytes()
    print(f'SETTINGS_NAVIGATION_SOURCE={sys.argv[1]} '
          f'page={hashlib.sha256(page).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'page_copy=exact native_binding=double parent=double', flush=True)


if __name__ == '__main__':
    main()

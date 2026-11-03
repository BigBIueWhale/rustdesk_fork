#!/usr/bin/env python3
"""Mount connection pages with explicit native and mobile-platform doubles."""

import hashlib
import os
from pathlib import Path
import sys


SUPPORT = {
    'lib/models/native_model.dart': b'\nvoid installConnectionPageBinding(RustdeskImpl binding) {\n  PlatformFFI.instance._ffiBind = binding;\n}\n',
    'lib/common.dart': b'\nvoid installConnectionPageOwner(FFI owner) {\n  _globalFFI = owner;\n}\n',
    'lib/native/common.dart': (
        b'\nbool _navigationProbeAndroid = false;\n'
        b'void installMobileNavigationPlatform() {\n'
        b'  _navigationProbeAndroid = true;\n}\n'),
}

PLATFORM_DOUBLES = {
    b'final isAndroid_ = Platform.isAndroid;':
        b'final isAndroid_ = _navigationProbeAndroid || Platform.isAndroid;',
    b'final isLinux_ = Platform.isLinux;':
        b'final isLinux_ = !_navigationProbeAndroid && Platform.isLinux;',
    b'final isDesktop_ = Platform.isWindows || Platform.isMacOS || Platform.isLinux;':
        b'final isDesktop_ = !_navigationProbeAndroid && '
        b'(Platform.isWindows || Platform.isMacOS || Platform.isLinux);',
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
        expected = original
        if relative == 'lib/native/common.dart':
            for before, after in PLATFORM_DOUBLES.items():
                if expected.count(before) != 1:
                    raise ValueError('mobile platform declaration differs')
                expected = expected.replace(before, after)
        expected += suffix
        if prepare:
            if target.read_bytes() != original:
                raise ValueError(f'connection page source differs: {relative}')
            if expected != original:
                target.write_bytes(expected)
        if target.read_bytes() != expected:
            raise ValueError(f'connection page copy differs: {relative}')
    for name in ('connection_page', 'mobile_navigation'):
        cases = (repo / f'test_probes/{name}_cases.dart.inc').read_bytes()
        target = project / f'test_probes/{name}_probe_test.dart'
        if prepare:
            with target.open('xb') as stream:
                stream.write(cases)
            target.chmod(0o400)
        if target.read_bytes() != cases:
            raise ValueError(f'{name} cases differ')
    cases = (repo / 'test_probes/connection_page_cases.dart.inc').read_bytes()
    widget = (repo / 'lib/desktop/pages/connection_page.dart').read_bytes()
    print(f'CONNECTION_PAGE_SOURCE={sys.argv[1]} '
          f'widget={hashlib.sha256(widget).hexdigest()} '
          f'tests={hashlib.sha256(cases).hexdigest()} '
          'page=exact toast=production native_reads=double translation=double', flush=True)
    mobile = (repo / 'test_probes/mobile_navigation_cases.dart.inc').read_bytes()
    print(f'MOBILE_NAVIGATION_SOURCE={sys.argv[1]} '
          f'tests={hashlib.sha256(mobile).hexdigest()} '
          'pages=exact ffi_navigation=exact dialogs=exact '
          'native_session=double platform=double', flush=True)


if __name__ == '__main__':
    main()

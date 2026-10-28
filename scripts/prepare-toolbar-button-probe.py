#!/usr/bin/env python3
"""Render exact toolbar button bodies with local palette/translation/session doubles."""

import hashlib
import os
from pathlib import Path
import re
import sys


def main():
    if sys.argv[1:] not in (['/source', '/work/project'], ['/source', '/work/project', 'verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('toolbar probe requires its isolated nonroot model-test entry')
    verify = sys.argv[-1] == 'verify'
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    names = ('flutter/lib/desktop/widgets/remote_toolbar.dart', 'flutter/lib/common.dart',
             'flutter/test_probes/toolbar_button_cases.dart.inc')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('toolbar project copy differs from source')
        print(f'TOOLBAR_BUTTON_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source = inputs[names[0]].decode('utf-8')
    parts = []
    for start, end in (
        ('class _ToolbarTheme {', 'typedef DismissFunc ='),
        ('class _IconMenuButton extends', 'class _SubmenuButton extends'),
        ('Widget _buildPointerTrackWidget(', 'class SessionScrollPreferences extends'),
    ):
        if source.count(start) != 1 or source.count(end) != 1:
            raise ValueError('toolbar source boundary is missing or ambiguous')
        parts.append(source[source.index(start):source.index(end)])
    constants = []
    common = inputs[names[1]].decode('utf-8')
    for name in ('accent', 'button', 'border'):
        matches = re.findall(r'  static const Color ' + name + r' = Color\(0x[0-9A-Fa-f]{8}\);', common)
        if len(matches) != 1:
            raise ValueError('toolbar theme constant is missing or ambiguous')
        constants.append(matches[0])
    support = '''
const isWindows = false;
String translate(String text) => text;
class FFI {
  dynamic get inputModel => throw StateError('session access outside this fixture');
}
class MyTheme {
''' + '\n'.join(constants) + '''
  static MyTheme color(BuildContext context) => MyTheme();
  Color? get border3 => border;
  Color? get divider => border;
}
'''
    tests = inputs[names[2]].decode('utf-8')
    text = tests + '\n' + support + '\n'.join(parts)
    path = project / 'test_probes/toolbar_button_probe_test.dart'
    if not verify:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        path.chmod(0o400)
    data = path.read_bytes()
    if data != text.encode('utf-8'):
        raise ValueError('toolbar probe publication differs')
    print(f'TOOLBAR_BUTTON_FIXTURE=observed verify={verify} bytes={len(data)} '
          f'sha256={hashlib.sha256(data).hexdigest()} widget=production '
          'translation=identity session=absent palette=fixture', flush=True)


if __name__ == '__main__':
    main()

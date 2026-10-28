#!/usr/bin/env python3
"""Render the exact password widget bodies without loading the native bridge."""

import hashlib
import os
from pathlib import Path
import sys


def main():
    if sys.argv[1:] not in (['prepare'], ['verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('password probe requires its isolated nonroot entry')
    repo, project = Path('/source'), Path('/work/project')
    names = ('flutter/lib/common/widgets/dialog.dart',
             'flutter/lib/common/widgets/password_text_field.dart',
             'flutter/test_probes/password_focus_cases.dart.inc')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('password project copy differs from source')
        print(f'PASSWORD_FOCUS_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source = inputs[names[0]].decode('utf-8')
    start, end = 'class DialogTextField extends', '// CPace credential replacement belongs'
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('password source boundary is missing or ambiguous')
    body = source[source.index(start):source.index(end)]
    support = '''
bool get isAndroid => defaultTargetPlatform == TargetPlatform.android;
String translate(String text) => text;
class MyTheme {
  static final lightTheme = ThemeData.light();
}
'''
    text = inputs[names[2]].decode('utf-8') + support + body
    path = project / 'test_probes/password_focus_probe_test.dart'
    if sys.argv[1] == 'prepare':
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        path.chmod(0o400)
    data = path.read_bytes()
    if data != text.encode('utf-8'):
        raise ValueError('password probe publication differs')
    print(f'PASSWORD_FOCUS_FIXTURE=observed mode={sys.argv[1]} bytes={len(data)} '
          f'sha256={hashlib.sha256(data).hexdigest()} widget=production '
          'translation=identity palette=fixture native=absent', flush=True)


if __name__ == '__main__':
    main()

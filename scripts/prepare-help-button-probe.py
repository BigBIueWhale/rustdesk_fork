#!/usr/bin/env python3
"""Render the production help-card button with an identity translation fixture."""

import hashlib
import os
from pathlib import Path
import re
import sys


def main():
    if sys.argv[1:] not in (['/source', '/work/project'], ['/source', '/work/project', 'verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('button probe requires its isolated nonroot model-test entry')
    verify = sys.argv[-1] == 'verify'
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    names = ('flutter/lib/desktop/widgets/button.dart', 'flutter/lib/common.dart',
             'flutter/test_probes/fixed_width_button_cases.dart.inc',
             'flutter/test_probes/fixed_width_button_layout_cases.dart.inc')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('button project copy differs from source')
        print(f'HELP_BUTTON_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source = inputs[names[0]].decode('utf-8')
    common = inputs[names[1]].decode('utf-8')
    marker = "import '../../common.dart';"
    if source.count(marker) != 1:
        raise ValueError('button common import is missing or ambiguous')
    constants = []
    for name in ('accent', 'button', 'hoverBorder', 'border'):
        matches = re.findall(r'  static const Color ' + name + r' = Color\(0x[0-9A-Fa-f]{8}\);', common)
        if len(matches) != 1:
            raise ValueError('button theme constant is missing or ambiguous')
        constants.append(matches[0])
    support = ('class MyTheme {\n' + '\n'.join(constants) +
               '\n}\nString translate(String text) => text;\n')
    body = source.replace(marker, '') + '\n' + support
    tests = inputs[names[2]].decode('utf-8')
    for name, text in (('fixed_width_button_probe.dart', body),
                       ('fixed_width_button_probe_test.dart', tests),
                       ('fixed_width_button_layout_test.dart', inputs[names[3]].decode('utf-8'))):
        path = project / 'test_probes' / name
        if not verify:
            with path.open('x', encoding='utf-8') as stream:
                stream.write(text)
            path.chmod(0o400)
        data = path.read_bytes()
        if data != text.encode('utf-8'):
            raise ValueError('button probe publication differs')
        print(f'HELP_BUTTON_FIXTURE=observed verify={verify} path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()} translation=identity '
              'widget=production theme=production', flush=True)


if __name__ == '__main__':
    main()

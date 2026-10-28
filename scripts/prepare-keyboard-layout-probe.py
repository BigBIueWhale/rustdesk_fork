#!/usr/bin/env python3
"""Render the production keyboard chooser with controlled save callbacks."""

import hashlib
import os
from pathlib import Path
import sys


def main():
    if sys.argv[1:] not in (['/source', '/work/project'], ['/source', '/work/project', 'verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('keyboard chooser probe requires its isolated nonroot entry')
    verify = sys.argv[-1] == 'verify'
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    names = ('flutter/lib/desktop/widgets/kb_layout_type_chooser.dart',
             'flutter/test_probes/keyboard_layout_cases.dart.inc',
             'flutter/assets/kb_layout_iso.svg',
             'flutter/assets/kb_layout_not_iso.svg')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('keyboard chooser project copy differs from source')
        print(f'KEYBOARD_LAYOUT_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source = inputs[names[0]].decode('utf-8')
    start = '/// Saves the type and publishes confirmed readback to the shared choice model.'
    end = "\nRxString KBLayoutType = ''.obs;"
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('keyboard chooser component boundary is ambiguous')
    body = ("import 'package:flutter/material.dart';\n"
            "import 'package:get/get.dart';\n"
            "import 'package:flutter_svg/flutter_svg.dart';\n\n" +
            source[source.index(start):source.index(end)] +
            '\nString translate(String text) => text;\n')
    for name, text in (
            ('keyboard_layout_probe.dart', body),
            ('keyboard_layout_probe_test.dart', inputs[names[1]].decode('utf-8'))):
        path = project / 'test_probes' / name
        if not verify:
            with path.open('x', encoding='utf-8') as stream:
                stream.write(text)
            path.chmod(0o400)
        data = path.read_bytes()
        if data != text.encode('utf-8'):
            raise ValueError('keyboard chooser probe publication differs')
        print(f'KEYBOARD_LAYOUT_FIXTURE=observed verify={verify} path={name} '
              f'bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} '
              'widget=production assets=production save=controlled', flush=True)


if __name__ == '__main__':
    main()

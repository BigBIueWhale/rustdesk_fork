#!/usr/bin/env python3
"""Render the exact connection-mode control with a connection callback double."""

import hashlib
import os
from pathlib import Path
import re
import sys


def main():
    if sys.argv[1:] not in (['/source', '/work/project'], ['/source', '/work/project', 'verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('connection-menu probe requires its isolated nonroot entry')
    verify = sys.argv[-1] == 'verify'
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    names = ('flutter/lib/desktop/pages/connection_page.dart',
             'flutter/lib/desktop/widgets/popup_menu.dart',
             'flutter/lib/common.dart', 'flutter/lib/consts.dart',
             'flutter/test_probes/connection_menu_cases.dart.inc')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('connection-menu project copy differs')
        print(f'CONNECTION_MENU_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source, menu, common, constants, tests = (
        inputs[name].decode('utf-8') for name in names)
    start = '                Container(\n                  height: 28.0,\n                  width: 28.0,'
    end = '\n              ]),'
    if source.count(start) != 1:
        raise ValueError('connection-menu boundary is missing or ambiguous')
    control = source[source.index(start):source.index(end, source.index(start))].strip()
    if not control.endswith('),'):
        raise ValueError('connection-menu expression is incomplete')
    control = control[:-1]
    if source.count('  final _menuOpen = false.obs;') != 1:
        raise ValueError('connection-menu state differs')
    accent = re.findall(r'  static const Color accent = Color\(0x[0-9A-Fa-f]{8}\);', common)
    padding = re.findall(r'^const kDesktopMenuPadding = .*;$', constants, re.M)
    if len(accent) != 1 or len(padding) != 1 or menu.count('class MenuConfig {') != 1:
        raise ValueError('connection-menu support is missing or ambiguous')
    support = '''
String translate(String text) => text;
class IconFont { static const more = Icons.expand_more; }
class MyTheme {
''' + accent[0] + '\n}\n' + padding[0] + '''
class _Probe extends StatefulWidget {
  const _Probe(this.selected);
  final ValueChanged<String> selected;
  @override
  State<_Probe> createState() => _ProbeState();
}
class _ProbeState extends State<_Probe> {
  final _menuOpen = false.obs;
  void onConnect({bool isFileTransfer = false, bool isViewCamera = false,
      bool isTerminal = false}) {
    widget.selected(isFileTransfer ? 'file' : isViewCamera ? 'camera' :
        isTerminal ? 'terminal' : 'remote');
  }
  @override
  Widget build(BuildContext context) =>
''' + control + ';\n}\n'
    text = tests + '\n' + support + menu[menu.index('class MenuConfig {'):]
    path = project / 'test_probes/connection_menu_probe_test.dart'
    if not verify:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        path.chmod(0o400)
    data = path.read_bytes()
    if data != text.encode('utf-8'):
        raise ValueError('connection-menu probe publication differs')
    print(f'CONNECTION_MENU_FIXTURE=observed verify={verify} bytes={len(data)} '
          f'sha256={hashlib.sha256(data).hexdigest()} control=production '
          'entries=production translation=identity icon=fixture connection=double', flush=True)


if __name__ == '__main__':
    main()

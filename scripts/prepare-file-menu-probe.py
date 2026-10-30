#!/usr/bin/env python3
"""Render the exact file-pane menu with file-operation callback doubles."""

import hashlib
import os
from pathlib import Path
import re
import sys


def main():
    if sys.argv[1:] not in (['/source', '/work/project'], ['/source', '/work/project', 'verify']) or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('file-menu probe requires its isolated nonroot entry')
    verify = sys.argv[-1] == 'verify'
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    names = ('flutter/lib/desktop/pages/file_manager_page.dart',
             'flutter/lib/desktop/widgets/popup_menu.dart',
             'flutter/lib/common.dart', 'flutter/lib/consts.dart',
             'flutter/test_probes/file_menu_cases.dart.inc',
             'flutter/lib/desktop/widgets/menu_button.dart')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('file-menu project copy differs')
        print(f'FILE_MENU_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    source, menu, common, constants, tests = (
        inputs[name].decode('utf-8') for name in names[:5])
    start = '  Widget menu({bool isLocal = false}) {'
    end = '\n  Widget _buildFileList('
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('file-menu method boundary is missing or ambiguous')
    method = source[source.index(start):source.index(end)]
    accent = re.findall(r'  static const Color accent = Color\(0x[0-9A-Fa-f]{8}\);', common)
    padding = re.findall(r'^const kDesktopMenuPadding = .*;$', constants, re.M)
    if len(accent) != 1 or len(padding) != 1 or menu.count('class MenuConfig {') != 1:
        raise ValueError('file-menu support is missing or ambiguous')
    support = '''
String translate(String text) => text;
ColorFilter svgColor(Color? color) => ColorFilter.mode(color ?? Colors.black, BlendMode.srcIn);
class SvgPicture {
  static Widget asset(String path, {ColorFilter? colorFilter}) =>
      const SizedBox(width: 16, height: 16, child: Icon(Icons.more_horiz, size: 16));
}
class MyTheme {
''' + accent[0] + '\n}\n' + padding[0] + '''
class _Options { bool showHidden = false; }
class _Directory { final entries = <String>['one', 'two']; }
class _Controller {
  _Controller(this.selected);
  final ValueChanged<String> selected;
  final options = _Options().obs;
  final directory = _Directory().obs;
  void toggleShowHidden({required int expectedSessionId}) {
    options.value.showHidden = !options.value.showHidden;
    selected('hidden');
  }
}
class _Selection {
  _Selection(this.selected);
  final ValueChanged<String> selected;
  void selectAll(List<String> entries) => selected('all');
  void clear() => selected('none');
}
class _Probe extends StatefulWidget {
  const _Probe(this.selected);
  final ValueChanged<String> selected;
  @override
  State<_Probe> createState() => _ProbeState();
}
class _ProbeState extends State<_Probe> {
  late final controller = _Controller((value) => widget.selected(value));
  late final selectedItems = _Selection((value) => widget.selected(value));
  final expectedSessionId = 7;
  bool get isCurrentSession => true;
  @override
  Widget build(BuildContext context) => menu();
''' + method + '\n}\n'
    text = tests + '\n' + support + menu[menu.index('class MenuConfig {'):]
    path = project / 'test_probes/file_menu_probe_test.dart'
    if not verify:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
        path.chmod(0o400)
    data = path.read_bytes()
    if data != text.encode('utf-8'):
        raise ValueError('file-menu probe publication differs')
    print(f'FILE_MENU_FIXTURE=observed verify={verify} bytes={len(data)} '
          f'sha256={hashlib.sha256(data).hexdigest()} method=production '
          'entries=production translation=identity icon=fixture operations=double', flush=True)


if __name__ == '__main__':
    main()

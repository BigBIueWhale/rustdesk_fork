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
             'flutter/test_probes/password_focus_cases.dart.inc',
             'flutter/lib/common.dart',
             'flutter/lib/common/widgets/connect_password_dialog.dart',
             'flutter/test/connect_password_dialog_lifecycle_test.dart')
    inputs = {name: (repo / name).read_bytes() for name in names}
    for name, data in inputs.items():
        if (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('password project copy differs from source')
        print(f'PASSWORD_FOCUS_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    def extract(source, start, end=None):
        if source.count(start) != 1 or (end is not None and source.count(end) != 1):
            raise ValueError('password source boundary is missing or ambiguous')
        return source[source.index(start):source.index(end) if end is not None else len(source)]

    body = extract(inputs[names[0]].decode('utf-8'),
                   'class DialogTextField extends', '// CPace credential replacement belongs')
    support = '''
bool get isAndroid => defaultTargetPlatform == TargetPlatform.android;
String translate(String text) => text;
class MyTheme {
  static final lightTheme = ThemeData.light();
}
'''
    common = inputs[names[3]].decode('utf-8')
    dialog_support = support.replace('  static final lightTheme', '''
  static const accent = Colors.blue;
  static EdgeInsets dialogTitlePadding() => const EdgeInsets.all(24);
  static EdgeInsets dialogContentPadding({bool actions = true}) => const EdgeInsets.all(24);
  static EdgeInsets dialogActionsPadding() => const EdgeInsets.all(24);
  static const dialogButtonPadding = EdgeInsets.only(left: 24);
  static final lightTheme''') + '''
typedef F = String Function(String);
const isWebDesktop = false;
bool get isDesktop => !isAndroid && defaultTargetPlatform != TargetPlatform.iOS;
final gFFI = _NativeDouble();
class _NativeDouble {
  Future<void> invokeMethod(String name, bool value) async {
    if (name != 'enable_soft_keyboard' || !value) {
      throw StateError('unexpected native request');
    }
  }
}
'''
    imports = '''import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/password_text_field.dart';
import 'package:get/get.dart';
'''
    dialog = imports + dialog_support + body + ''.join(
        extract(common, start, end) for start, end in (
            ('class DialogClose {', 'typedef DialogBuilder ='),
            ('class CustomAlertDialog extends', 'Widget createDialogContent('),
            ('Widget dialogButton(', 'int versionCmp('),
        )) + extract(inputs[names[4]].decode('utf-8'), 'class ConnectPasswordDialog extends')
    tests = inputs[names[5]].decode('utf-8')
    for old, new in (
        ("import 'package:flutter_hbb/common.dart' show CustomAlertDialog, DialogClose;",
         "import 'password_dialog_probe.dart';"),
        ("import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';", ''),
    ):
        if tests.count(old) != 1:
            raise ValueError('connection test import differs')
        tests = tests.replace(old, new)
    outputs = {
        'password_focus_probe_test.dart': inputs[names[2]].decode('utf-8') + support + body,
        'password_dialog_probe.dart': dialog,
        'connect_password_dialog_lifecycle_test.dart': tests,
    }
    for name, text in outputs.items():
        path = project / 'test_probes' / name
        if sys.argv[1] == 'prepare':
            with path.open('x', encoding='utf-8') as stream:
                stream.write(text)
            path.chmod(0o400)
        data = path.read_bytes()
        if data != text.encode('utf-8'):
            raise ValueError('password probe publication differs')
        print(f'PASSWORD_FOCUS_FIXTURE=observed mode={sys.argv[1]} path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()} widget=production '
              'translation=identity palette-and-insets=fixture native=double', flush=True)


if __name__ == '__main__':
    main()

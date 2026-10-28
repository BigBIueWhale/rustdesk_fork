import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/password_text_field.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

final _otherField = find.byKey(const ValueKey('other-field'));
Finder get _passwordField => find.descendant(
    of: find.byType(PasswordWidget), matching: find.byType(TextField));

Future<void> _show(WidgetTester tester, TextEditingController controller,
    FocusNode other, {bool showPassword = true, String? error}) async {
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(platform: TargetPlatform.linux, useMaterial3: false),
    home: Scaffold(
      body: Column(children: [
        if (showPassword)
          PasswordWidget(
            key: const ValueKey('password'),
            controller: controller,
            errorText: error,
            translateText: (text) => text,
          ),
        TextField(
          key: const ValueKey('other-field'),
          focusNode: other,
          autofocus: !showPassword,
        ),
      ]),
    ),
  ));
  await tester.pump();
}

void main() {
  late TextEditingController controller;
  late FocusNode other;
  setUp(() {
    controller = TextEditingController();
    other = FocusNode();
  });
  tearDown(() {
    controller.dispose();
    other.dispose();
  });

  testWidgets('password prompt autofocus opens the editor', (tester) async {
    await _show(tester, controller, other);
    expect(tester.widget<TextField>(_passwordField).focusNode!.hasPrimaryFocus,
        isTrue);
    await tester.pump(const Duration(milliseconds: 100));
    expect(tester.testTextInput.isVisible, isTrue);
    expect(tester.testTextInput.setClientArgs!['obscureText'], isTrue);
  });

  testWidgets('password prompt preserves immediate keyboard traversal',
      (tester) async {
    await _show(tester, controller, other);
    final password = tester.widget<TextField>(_passwordField).focusNode!;
    expect(password.hasPrimaryFocus, isTrue);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pump();
    final selected = FocusManager.instance.primaryFocus;
    expect(selected, isNotNull);
    expect(password.hasFocus, isFalse);
    await tester.pump(const Duration(milliseconds: 100));
    expect(FocusManager.instance.primaryFocus, same(selected));
    expect(password.hasFocus, isFalse);
  });

  testWidgets('password prompt preserves immediate pointer focus',
      (tester) async {
    await _show(tester, controller, other);
    await tester.tap(_otherField);
    await tester.pump();
    expect(other.hasPrimaryFocus, isTrue);
    await tester.pump(const Duration(milliseconds: 100));
    expect(other.hasPrimaryFocus, isTrue);
  });

  testWidgets('password prompt respects an already focused editor',
      (tester) async {
    await _show(tester, controller, other, showPassword: false);
    expect(other.hasPrimaryFocus, isTrue);
    await _show(tester, controller, other);
    expect(other.hasPrimaryFocus, isTrue);
    await tester.pump(const Duration(milliseconds: 100));
    expect(other.hasPrimaryFocus, isTrue);
  });

  testWidgets('password prompt rebuild preserves user focus', (tester) async {
    await _show(tester, controller, other);
    await tester.pump(const Duration(milliseconds: 100));
    await tester.tap(_otherField);
    await tester.pump();
    expect(other.hasPrimaryFocus, isTrue);
    await _show(tester, controller, other, error: 'Try again');
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Try again'), findsOneWidget);
    expect(other.hasPrimaryFocus, isTrue);
  });

  testWidgets('password prompt reveal preserves text and selection',
      (tester) async {
    await _show(tester, controller, other);
    await tester.enterText(_passwordField, ' Exact1x-\'" ');
    controller.selection = const TextSelection(baseOffset: 2, extentOffset: 7);
    for (final obscure in [false, true]) {
      await tester.tap(find.byType(IconButton));
      await tester.pump();
      expect(tester.widget<TextField>(_passwordField).obscureText, obscure);
      expect(controller.text, ' Exact1x-\'" ');
      expect(controller.selection,
          const TextSelection(baseOffset: 2, extentOffset: 7));
    }
    await tester.pump(const Duration(milliseconds: 100));
    expect(tester.takeException(), isNull);
  });

  testWidgets('password prompt removal retires its focus node', (tester) async {
    await _show(tester, controller, other);
    final password = tester.widget<TextField>(_passwordField).focusNode!;
    await _show(tester, controller, other, showPassword: false);
    await tester.tap(_otherField);
    await tester.pump(const Duration(milliseconds: 100));
    expect(other.hasPrimaryFocus, isTrue);
    expect(() => password.addListener(() {}), throwsFlutterError);
    expect(tester.takeException(), isNull);
  });
}

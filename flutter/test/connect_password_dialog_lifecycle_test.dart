import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show CustomAlertDialog;
import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> _show(
  WidgetTester tester, {
  String owner = 'prompt',
  required Future<bool?> Function() readRemember,
  bool Function(String, bool)? submitPassword,
  VoidCallback? close,
  VoidCallback? onCancel,
  VoidCallback? onAccepted,
}) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: ConnectPasswordDialog(
        key: ValueKey(owner),
        readRemember: readRemember,
        submitPassword: submitPassword ?? (_, __) => false,
        close: DialogClose(
          isCurrent: () => true,
          complete: (_) => close?.call(),
        ),
        onCancel: onCancel ?? () {},
        onAccepted: onAccepted ?? () {},
        translateText: (text) => text,
      ),
    ),
  ));
  await tester.pump(const Duration(milliseconds: 60));
}

Finder _button(String label) => find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    );

void main() {
  testWidgets('connect prompt is present before its saved preference resolves',
      (tester) async {
    final preference = Completer<bool?>();
    await _show(tester, readRemember: () => preference.future);
    expect(find.text('Password Required'), findsOneWidget);
    expect(find.byType(TextField), findsOneWidget);
    expect(tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNull);
    preference.complete(true);
    await tester.pump();
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        isTrue);
    expect(
        tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNotNull);

    await tester.enterText(find.byType(TextField), 'Exact1x-\'"');
    for (var reveal = 0; reveal < 2; reveal++) {
      await tester.tap(find.byType(IconButton));
      await tester.pump();
      final configuration = tester.testTextInput.setClientArgs!;
      expect(configuration['obscureText'], reveal == 1);
      expect(
          configuration['inputType'], TextInputType.visiblePassword.toJson());
      expect(configuration['autocorrect'], isFalse);
      expect(configuration['enableSuggestions'], isFalse);
      expect(configuration['enableIMEPersonalizedLearning'], isFalse);
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
          'Exact1x-\'"');
    }
  });

  testWidgets('retired connect preference cannot change its replacement',
      (tester) async {
    final oldPreference = Completer<bool?>();
    final newPreference = Completer<bool?>();
    var oldReads = 0;
    await _show(tester, owner: 'old', readRemember: () {
      oldReads++;
      return oldPreference.future;
    });
    final oldController =
        tester.widget<TextField>(find.byType(TextField)).controller!;
    await _show(tester, owner: 'new', readRemember: () => newPreference.future);
    oldPreference.complete(true);
    await tester.pump();
    expect(oldReads, 1);
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        isFalse);
    expect(tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNull);
    expect(() => oldController.addListener(() {}), throwsFlutterError);
    newPreference.complete(false);
    await tester.pump();
    expect(
        tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNotNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('explicit remember choice wins over delayed saved preference',
      (tester) async {
    final preference = Completer<bool?>();
    final writes = <bool>[];
    await _show(tester,
        readRemember: () => preference.future,
        submitPassword: (_, remember) {
          writes.add(remember);
          return false;
        });
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    preference.complete(true);
    await tester.pump();
    await tester.enterText(find.byType(TextField), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(writes, [false]);
  });

  testWidgets('connect submit admits one accepted replacement attempt',
      (tester) async {
    final events = <String>[];
    await _show(tester,
        readRemember: () async => false,
        submitPassword: (password, remember) {
          events.add('submit:$password:$remember');
          return true;
        },
        close: () => events.add('close'),
        onAccepted: () => events.add('accepted'));
    await tester.enterText(find.byType(TextField), ' Runtime1x ');
    final dialog =
        tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog));
    dialog.onSubmit!();
    dialog.onSubmit!();
    expect(events, ['submit:Runtime1x:false', 'close', 'accepted']);
  });

  testWidgets('rejected connect submission retains its prompt for retry',
      (tester) async {
    var attempts = 0;
    var accepted = 0;
    await _show(tester,
        readRemember: () async => true,
        submitPassword: (_, __) => ++attempts == 2,
        onAccepted: () => accepted++);
    await tester.enterText(find.byType(TextField), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(attempts, 1);
    expect(accepted, 0);
    expect(find.text('Prompt: Failed'), findsOneWidget);
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(attempts, 2);
    expect(accepted, 1);
  });

  testWidgets('cancel retires a pending connect preference and callbacks',
      (tester) async {
    final preference = Completer<bool?>();
    final events = <String>[];
    await _show(tester,
        readRemember: () => preference.future,
        close: () => events.add('close'),
        onCancel: () => events.add('cancel'));
    final dialog =
        tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog));
    dialog.onCancel!();
    dialog.onCancel!();
    preference.complete(true);
    await tester.pump();
    expect(events, ['close', 'cancel']);
    expect(tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('failed saved preference needs an explicit remember decision',
      (tester) async {
    for (final throws in [false, true]) {
      final preference = Completer<bool?>();
      await _show(tester,
          owner: 'failure:$throws', readRemember: () => preference.future);
      if (throws) {
        preference.completeError(StateError('private failure details'));
      } else {
        preference.complete(null);
      }
      await tester.pump();
      expect(find.text('Prompt: Failed'), findsOneWidget);
      expect(tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNull);
      await tester.tap(find.byType(CheckboxListTile));
      await tester.pump();
      expect(
          tester.widget<ButtonStyleButton>(_button('OK')).onPressed, isNotNull);
      expect(tester.takeException(), isNull);
    }
  });
}

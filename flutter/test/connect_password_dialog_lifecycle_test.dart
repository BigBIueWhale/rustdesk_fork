import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show CustomAlertDialog, DialogClose;
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
  bool Function()? isCurrent,
}) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: ConnectPasswordDialog(
        key: ValueKey(owner),
        readRemember: readRemember,
        submitPassword: submitPassword ?? (_, __) => false,
        close: DialogClose(
          isCurrent: isCurrent ?? () => true,
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
  for (final platform in [
    TargetPlatform.android,
    TargetPlatform.iOS,
    TargetPlatform.linux,
    TargetPlatform.windows,
    TargetPlatform.macOS,
  ]) {
    testWidgets('connect keyboard action submits once on ${platform.name}',
        (tester) async {
      debugDefaultTargetPlatformOverride = platform;
      try {
        final submitted = <String>[];
        var accepted = 0;
        await _show(tester,
            readRemember: () async => false,
            submitPassword: (password, remember) {
              expect(remember, isFalse);
              submitted.add(password);
              return true;
            },
            onAccepted: () => accepted++);
        await tester.enterText(find.byType(TextField), ' Runtime1x\u00a0');
        await tester.testTextInput.receiveAction(TextInputAction.done);
        await tester.pump();
        expect(submitted, [' Runtime1x\u00a0']);
        expect(accepted, 1);
        await tester.showKeyboard(find.byType(TextField));
        await tester.testTextInput.receiveAction(TextInputAction.done);
        await tester.pump();
        expect(submitted, [' Runtime1x\u00a0']);
        expect(accepted, 1);
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    });
  }

  testWidgets('connect keyboard action waits for preference and permits retry',
      (tester) async {
    final preference = Completer<bool?>();
    var attempts = 0;
    var accepted = 0;
    await _show(tester,
        readRemember: () => preference.future,
        submitPassword: (password, remember) {
          expect(password, ' Exact1x ');
          expect(remember, isFalse);
          return ++attempts == 2;
        },
        onAccepted: () => accepted++);
    await tester.enterText(find.byType(TextField), ' Exact1x ');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(attempts, 0);
    preference.complete(false);
    await tester.pump();
    await tester.showKeyboard(find.byType(TextField));
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(attempts, 1);
    expect(accepted, 0);
    expect(find.text('Prompt: Failed'), findsOneWidget);
    await tester.showKeyboard(find.byType(TextField));
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(attempts, 2);
    expect(accepted, 1);
  });

  testWidgets('connect keyboard action refuses a stale owner', (tester) async {
    var current = true;
    var submitted = 0;
    await _show(tester,
        readRemember: () async => false,
        isCurrent: () => current,
        submitPassword: (_, __) {
          submitted++;
          return true;
        });
    await tester.enterText(find.byType(TextField), 'Runtime1x');
    current = false;
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(submitted, 0);
  });

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
    const passwords = {
      'plain': 'Runtime1x',
      'leading': ' Runtime1x',
      'trailing': 'Runtime1x ',
      'both': ' Runtime1x ',
      'nonbreaking': '\u00a0Runtime1x\u00a0',
      'wide': '\u3000Runtime1x\u3000',
      'combining': ' Cafe\u0301-1x ',
      'spaces': '   ',
    };
    for (final button in [false, true]) {
      for (final entry in passwords.entries) {
        final events = <String>[];
        final submitted = <String>[];
        await _show(tester,
            owner: '$button:${entry.key}',
            readRemember: () async => false,
            submitPassword: (password, remember) {
              submitted.add(password);
              events.add('submit:$remember');
              return true;
            },
            close: () => events.add('close'),
            onAccepted: () => events.add('accepted'));
        final dialog =
            tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog));
        dialog.onSubmit!();
        await tester.tap(_button('OK'));
        expect(events, isEmpty);
        await tester.enterText(find.byType(TextField), entry.value);
        if (button) {
          await tester.tap(_button('OK'));
        } else {
          dialog.onSubmit!();
        }
        dialog.onSubmit!();
        final preserved =
            submitted.length == 1 && submitted.single == entry.value;
        debugPrint('CONNECT_PASSWORD_EXACT case=${entry.key} button=$button '
            'preserved=$preserved');
        expect(submitted, [entry.value], reason: '$button:${entry.key}');
        expect(events, ['submit:false', 'close', 'accepted']);
      }
    }
  });

  testWidgets('rejected connect submission retains its prompt for retry',
      (tester) async {
    var attempts = 0;
    var accepted = 0;
    final submitted = <String>[];
    await _show(tester,
        readRemember: () async => true,
        submitPassword: (password, _) {
          submitted.add(password);
          return ++attempts == 2;
        },
        onAccepted: () => accepted++);
    await tester.enterText(find.byType(TextField), ' Runtime1x\u00a0');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(attempts, 1);
    expect(accepted, 0);
    expect(find.text('Prompt: Failed'), findsOneWidget);
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(attempts, 2);
    expect(accepted, 1);
    expect(submitted, [' Runtime1x\u00a0', ' Runtime1x\u00a0']);
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

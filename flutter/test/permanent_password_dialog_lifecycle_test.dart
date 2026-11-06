import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/permanent_password_dialog.dart';
import 'package:flutter_hbb/generated_bridge.dart' show PasswordMutationOutcome;
import 'package:flutter_test/flutter_test.dart';

Widget _harness({
  required PermanentPasswordWriter writePassword,
  required PermanentPasswordMutationCoordinator mutationCoordinator,
  required VoidCallback close,
}) {
  return MaterialApp(
    home: Scaffold(
      body: PermanentPasswordDialog(
        passwordSet: false,
        maxLength: 128,
        writePassword: writePassword,
        mutationCoordinator: mutationCoordinator,
        close: close,
        translateText: (text) => text,
      ),
    ),
  );
}

Finder _button(String label) => find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    );

void main() {
  testWidgets('one submit owns every action until durable completion',
      (tester) async {
    final completion = Completer<PasswordMutationOutcome>();
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    final writes = <String>[];
    final events = <String>[];

    await tester.pumpWidget(_harness(
      writePassword: (password) {
        writes.add(password);
        return completion.future;
      },
      mutationCoordinator: mutationCoordinator,
      close: () => events.add('close'),
    ));

    final fields = find.byType(TextField);
    expect(fields, findsNWidgets(2));
    for (var field = 0; field < 2; field++) {
      await tester.showKeyboard(fields.at(field));
      final configuration = tester.testTextInput.setClientArgs!;
      expect(configuration['autocorrect'], isFalse);
      expect(configuration['enableSuggestions'], isFalse);
      expect(configuration['enableIMEPersonalizedLearning'], isFalse);
    }
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    expect(writes, ['Runtime1x']);
    expect(
      tester.widgetList<TextField>(fields).map((field) => field.enabled),
      everyElement(isFalse),
    );
    expect(
      tester.widget<ButtonStyleButton>(_button('OK')).onPressed,
      isNull,
    );
    expect(
      tester.widget<ButtonStyleButton>(_button('Cancel')).onPressed,
      isNull,
    );
    expect(
      find.byKey(const ValueKey('permanent-password-progress')),
      findsOneWidget,
    );

    await tester.tap(find.text('OK'), warnIfMissed: false);
    await tester.pump();
    expect(writes, ['Runtime1x']);

    completion.complete(PasswordMutationOutcome.Applied);
    await tester.pump();
    expect(events, ['close']);
  });

  testWidgets('failed mutation reopens the same dialog owner', (tester) async {
    var attempts = 0;
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    await tester.pumpWidget(_harness(
      writePassword: (password) async {
        attempts += 1;
        return PasswordMutationOutcome.Failed;
      },
      mutationCoordinator: mutationCoordinator,
      close: () => fail('failed persistence closed the dialog'),
    ));

    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    expect(attempts, 1);
    expect(find.text('Prompt: Failed'), findsOneWidget);
    expect(
      tester.widgetList<TextField>(fields).map((field) => field.enabled),
      everyElement(isTrue),
    );
    expect(
      find.byKey(const ValueKey('permanent-password-progress')),
      findsNothing,
    );
  });

  testWidgets('retired dialog ignores its outstanding completion',
      (tester) async {
    final completion = Completer<PasswordMutationOutcome>();
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    var closes = 0;
    await tester.pumpWidget(_harness(
      writePassword: (_) => completion.future,
      mutationCoordinator: mutationCoordinator,
      close: () => closes += 1,
    ));

    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    await tester.pumpWidget(const SizedBox.shrink());
    completion.complete(PasswordMutationOutcome.Applied);
    await tester.pump();

    expect(closes, 0);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
      'lost mutation result does not claim that the password stayed unchanged',
      (tester) async {
    final completion = Completer<PasswordMutationOutcome>();
    var writes = 0;
    var closes = 0;
    await tester.pumpWidget(_harness(
      writePassword: (_) {
        writes += 1;
        return completion.future;
      },
      mutationCoordinator: PermanentPasswordMutationCoordinator(),
      close: () => closes += 1,
    ));
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    completion.completeError(StateError('result channel closed'));
    await tester.pump();

    expect(writes, 1);
    expect(closes, 0);
    expect(
        find.textContaining(
            'The password change could not be confirmed. It may have been applied.'),
        findsOneWidget);
    expect(find.text('Prompt: Failed'), findsNothing);
    expect(find.byKey(const ValueKey('permanent-password-progress')), findsNothing);
    expect(tester.widget<ButtonStyleButton>(_button('Cancel')).onPressed, isNotNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('denied mutation permits an explicit authorized retry',
      (tester) async {
    var writes = 0;
    var closes = 0;
    await tester.pumpWidget(_harness(
      writePassword: (_) async => ++writes == 1
          ? PasswordMutationOutcome.Denied
          : PasswordMutationOutcome.Applied,
      mutationCoordinator: PermanentPasswordMutationCoordinator(),
      close: () => closes += 1,
    ));
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    expect(find.text('Prompt: Password change was denied.'), findsOneWidget);
    expect(find.text('Prompt: Failed'), findsNothing);
    expect(writes, 1);
    expect(closes, 0);
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(writes, 2);
    expect(closes, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('replacement dialog preserves an uncertain native outcome',
      (tester) async {
    final completion = Completer<PasswordMutationOutcome>();
    final coordinator = PermanentPasswordMutationCoordinator();
    var writes = 0;
    var retiredCloses = 0;
    var replacementCloses = 0;
    Future<PasswordMutationOutcome> writePassword(String _) {
      writes += 1;
      return completion.future;
    }

    await tester.pumpWidget(_harness(
      writePassword: writePassword,
      mutationCoordinator: coordinator,
      close: () => retiredCloses += 1,
    ));
    await tester.enterText(find.byType(TextField).at(0), 'Runtime1x');
    await tester.enterText(find.byType(TextField).at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpWidget(_harness(
      writePassword: writePassword,
      mutationCoordinator: coordinator,
      close: () => replacementCloses += 1,
    ));
    completion.complete(PasswordMutationOutcome.Uncertain);
    await tester.pump();

    expect(writes, 1);
    expect(retiredCloses, 0);
    expect(replacementCloses, 0);
    expect(
        find.textContaining(
            'The password change could not be confirmed. It may have been applied.'),
        findsOneWidget);
    expect(find.text('Prompt: Failed'), findsNothing);
    await tester.tap(find.text('Cancel'));
    await tester.pump();
    expect(replacementCloses, 1);
    expect(writes, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('replacement dialog takes over the same pending mutation',
      (tester) async {
    final completion = Completer<PasswordMutationOutcome>();
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    var writes = 0;
    var retiredCloses = 0;
    var replacementCloses = 0;

    Future<PasswordMutationOutcome> writePassword(String _) {
      writes += 1;
      return completion.future;
    }

    await tester.pumpWidget(_harness(
      writePassword: writePassword,
      mutationCoordinator: mutationCoordinator,
      close: () => retiredCloses += 1,
    ));
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(writes, 1);

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpWidget(_harness(
      writePassword: writePassword,
      mutationCoordinator: mutationCoordinator,
      close: () => replacementCloses += 1,
    ));
    await tester.pump();

    expect(writes, 1);
    expect(
      tester.widgetList<TextField>(find.byType(TextField)).map(
            (field) => field.enabled,
          ),
      everyElement(isFalse),
    );
    expect(
      find.byKey(const ValueKey('permanent-password-progress')),
      findsOneWidget,
    );

    completion.complete(PasswordMutationOutcome.Applied);
    await tester.pump();

    expect(writes, 1);
    expect(retiredCloses, 0);
    expect(replacementCloses, 1);
  });
}

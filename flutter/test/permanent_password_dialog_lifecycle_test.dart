import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/permanent_password_dialog.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _harness({
  required PermanentPasswordWriter writePassword,
  required PermanentPasswordMutationCoordinator mutationCoordinator,
  required VoidCallback close,
  PermanentPasswordContinuation? onNonEmptySaved,
}) {
  return MaterialApp(
    home: Scaffold(
      body: PermanentPasswordDialog(
        passwordSet: false,
        maxLength: 128,
        writePassword: writePassword,
        mutationCoordinator: mutationCoordinator,
        close: close,
        onNonEmptySaved: onNonEmptySaved,
        translateText: (text) => text,
      ),
    ),
  );
}

void main() {
  testWidgets('one submit owns every action until durable completion',
      (tester) async {
    final completion = Completer<bool>();
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
      onNonEmptySaved: () async => events.add('continue'),
    ));

    final fields = find.byType(TextField);
    expect(fields, findsNWidgets(2));
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
      tester
          .widget<ElevatedButton>(
            find.ancestor(
              of: find.text('OK'),
              matching: find.byType(ElevatedButton),
            ),
          )
          .onPressed,
      isNull,
    );
    expect(
      tester
          .widget<OutlinedButton>(
            find.ancestor(
              of: find.text('Cancel'),
              matching: find.byType(OutlinedButton),
            ),
          )
          .onPressed,
      isNull,
    );
    expect(
      find.byKey(const ValueKey('permanent-password-progress')),
      findsOneWidget,
    );

    await tester.tap(find.text('OK'), warnIfMissed: false);
    await tester.pump();
    expect(writes, ['Runtime1x']);

    completion.complete(true);
    await tester.pump();
    expect(events, ['close', 'continue']);
  });

  testWidgets('failed mutation reopens the same dialog owner', (tester) async {
    var attempts = 0;
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    await tester.pumpWidget(_harness(
      writePassword: (password) async {
        attempts += 1;
        return false;
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
    final completion = Completer<bool>();
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    var closes = 0;
    var continuations = 0;
    await tester.pumpWidget(_harness(
      writePassword: (_) => completion.future,
      mutationCoordinator: mutationCoordinator,
      close: () => closes += 1,
      onNonEmptySaved: () async => continuations += 1,
    ));

    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), 'Runtime1x');
    await tester.enterText(fields.at(1), 'Runtime1x');
    await tester.tap(find.text('OK'));
    await tester.pump();

    await tester.pumpWidget(const SizedBox.shrink());
    completion.complete(true);
    await tester.pump();

    expect(closes, 0);
    expect(continuations, 0);
    expect(tester.takeException(), isNull);
  });

  testWidgets('replacement dialog takes over the same pending mutation',
      (tester) async {
    final completion = Completer<bool>();
    final mutationCoordinator = PermanentPasswordMutationCoordinator();
    var writes = 0;
    var retiredCloses = 0;
    var replacementCloses = 0;
    var continuations = 0;

    Future<bool> writePassword(String _) {
      writes += 1;
      return completion.future;
    }

    await tester.pumpWidget(_harness(
      writePassword: writePassword,
      mutationCoordinator: mutationCoordinator,
      close: () => retiredCloses += 1,
      onNonEmptySaved: () async => continuations += 100,
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
      onNonEmptySaved: () async => continuations += 1,
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

    completion.complete(true);
    await tester.pump();

    expect(writes, 1);
    expect(retiredCloses, 0);
    expect(replacementCloses, 1);
    expect(continuations, 1);
  });
}

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/widgets/kb_layout_type_chooser.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _app(KBChosenCallback save, {double width = 360}) => MaterialApp(
      home: Scaffold(
        body: Center(
          child: KBLayoutTypeChooser(
            chosenType: KBLayoutType,
            width: width,
            height: 200,
            dividerWidth: 4,
            cb: save,
            failureText: 'Save failed',
          ),
        ),
      ),
    );

Future<void> _show(WidgetTester tester, KBChosenCallback save) async {
  await tester.pumpWidget(_app(save));
  await tester.pumpAndSettle();
}

VoidCallback _press(WidgetTester tester, String type) => tester
    .widget<TextButton>(find.ancestor(
      of: find.text(type),
      matching: find.byType(TextButton),
    ))
    .onPressed!;

void main() {
  late String original;
  setUp(() {
    original = KBLayoutType.value;
    KBLayoutType.value = 'ISO';
  });
  tearDown(() => KBLayoutType.value = original);

  testWidgets('keyboard chooser waits and blocks repeated choices',
      (tester) async {
    final completion = Completer<void>();
    final calls = <String>[];
    var stored = 'ISO';
    var reads = 0;
    await _show(tester, (value) => saveLocalKeyboardLayoutType(value,
        writeType: (value) async {
          calls.add(value);
          await completion.future;
          stored = value;
        },
        readType: () {
          reads++;
          return stored;
        }));
    final iso = _press(tester, 'ISO');
    final notIso = _press(tester, 'Not ISO');
    notIso();
    iso();
    notIso();
    await tester.pump();
    expect(calls, ['Not ISO']);
    expect(reads, 0);
    expect(KBLayoutType.value, 'ISO');
    expect(tester.widgetList<TextButton>(find.byType(TextButton))
        .every((button) => button.onPressed == null), isTrue);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    completion.complete();
    await tester.pumpAndSettle();
    expect(reads, 1);
    expect(KBLayoutType.value, 'Not ISO');
    expect(find.byType(LinearProgressIndicator), findsNothing);
  });

  testWidgets('keyboard chooser displays save errors and retries the same choice',
      (tester) async {
    var writes = 0;
    var stored = 'ISO';
    await _show(tester, (value) => saveLocalKeyboardLayoutType(value,
        writeType: (value) async {
          if (++writes == 1) throw StateError('denied');
          stored = value;
        }, readType: () => stored));
    _press(tester, 'Not ISO')();
    await tester.pumpAndSettle();
    expect(KBLayoutType.value, 'ISO');
    expect(find.text('Save failed'), findsOneWidget);
    expect(tester.takeException(), isNull);
    _press(tester, 'Not ISO')();
    await tester.pumpAndSettle();
    expect(writes, 2);
    expect(KBLayoutType.value, 'Not ISO');
    expect(find.text('Save failed'), findsNothing);
  });

  testWidgets('keyboard chooser exposes mismatched readback and permits retry',
      (tester) async {
    var writes = 0;
    var stored = 'ISO';
    await _show(tester, (value) => saveLocalKeyboardLayoutType(value,
        writeType: (value) async {
          if (++writes > 1) stored = value;
        }, readType: () => stored));
    _press(tester, 'Not ISO')();
    await tester.pumpAndSettle();
    expect(KBLayoutType.value, 'ISO');
    expect(find.text('Save failed'), findsOneWidget);
    _press(tester, 'Not ISO')();
    await tester.pumpAndSettle();
    expect(writes, 2);
    expect(KBLayoutType.value, 'Not ISO');
    expect(find.text('Save failed'), findsNothing);
  });

  testWidgets('keyboard chooser retains its admitted save through parent rebuild',
      (tester) async {
    final completion = Completer<void>();
    var firstWrites = 0;
    var replacementWrites = 0;
    var stored = 'ISO';
    await _show(tester, (value) => saveLocalKeyboardLayoutType(value,
        writeType: (value) async {
          firstWrites++;
          await completion.future;
          stored = value;
        }, readType: () => stored));
    final stale = _press(tester, 'Not ISO');
    stale();
    await tester.pump();
    await tester.pumpWidget(_app((value) => saveLocalKeyboardLayoutType(value,
        writeType: (value) async {
          replacementWrites++;
          stored = value;
        }, readType: () => stored), width: 380));
    stale();
    await tester.pump();
    expect(firstWrites, 1);
    expect(replacementWrites, 0);
    completion.complete();
    await tester.pumpAndSettle();
    expect(KBLayoutType.value, 'Not ISO');
    _press(tester, 'ISO')();
    await tester.pumpAndSettle();
    expect(replacementWrites, 1);
    expect(KBLayoutType.value, 'ISO');
  });

  testWidgets('keyboard chooser disposal retires callbacks while the save settles',
      (tester) async {
    for (final failSave in [false, true]) {
      KBLayoutType.value = 'ISO';
      final completion = Completer<void>();
      var writes = 0;
      var stored = 'ISO';
      await _show(tester, (value) => saveLocalKeyboardLayoutType(value,
          writeType: (value) async {
            writes++;
            await completion.future;
            stored = value;
          }, readType: () => stored));
      final stale = _press(tester, 'Not ISO');
      stale();
      await tester.pump();
      await tester.pumpWidget(const SizedBox.shrink());
      stale();
      expect(writes, 1);
      if (failSave) {
        completion.completeError(StateError('late failure'));
      } else {
        completion.complete();
      }
      await tester.pump();
      expect(KBLayoutType.value, failSave ? 'ISO' : 'Not ISO');
      expect(tester.takeException(), isNull);
    }
  });

  test('keyboard layout callback publishes only confirmed native readback',
      () async {
    final completion = Completer<void>();
    var reads = 0;
    final saved = saveLocalKeyboardLayoutType('Not ISO',
        writeType: (_) => completion.future, readType: () {
          reads++;
          return 'Not ISO';
        });
    expect(KBLayoutType.value, 'ISO');
    expect(reads, 0);
    completion.complete();
    expect(await saved, isTrue);
    expect(reads, 1);
    expect(KBLayoutType.value, 'Not ISO');
  });

  test('keyboard layout callback preserves its model after native failure',
      () async {
    var reads = 0;
    await expectLater(saveLocalKeyboardLayoutType('Not ISO',
        writeType: (_) => Future<void>.error(StateError('denied')),
        readType: () {
          reads++;
          return 'Not ISO';
        }), throwsStateError);
    expect(reads, 0);
    expect(KBLayoutType.value, 'ISO');
  });
}

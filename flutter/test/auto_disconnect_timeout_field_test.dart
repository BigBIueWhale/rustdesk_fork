import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/auto_disconnect_timeout_field.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> _mount(
  WidgetTester tester, {
  String value = '10',
  bool enabled = true,
  Key fieldKey = const ValueKey('timeout'),
  required Future<String> Function(String) save,
}) =>
    tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: AutoDisconnectTimeoutField(
          key: fieldKey,
          value: value,
          enabled: enabled,
          saveTimeout: save,
          translateText: (text) => text,
        ),
      ),
    ));

ElevatedButton _apply(WidgetTester tester) =>
    tester.widget<ElevatedButton>(find.byType(ElevatedButton));

TextEditingController _controller(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).controller!;

Future<void> _edit(WidgetTester tester, String value) async {
  await tester.enterText(find.byType(TextField), value);
  await tester.pump();
}

void main() {
  testWidgets('inline timeout keeps one save while a newer draft is edited',
      (tester) async {
    final first = Completer<String>();
    final calls = <String>[];
    await _mount(tester, save: (value) {
      calls.add(value);
      return calls.length == 1 ? first.future : Future.value(value);
    });
    await _edit(tester, '20');
    final savedCallback = _apply(tester).onPressed!;
    savedCallback();
    await tester.pump();
    await _edit(tester, '30');
    expect(_apply(tester).onPressed, isNull);
    savedCallback();
    await tester.pump();
    expect(calls, ['20']);
    first.complete('20');
    await tester.pump();
    expect(_controller(tester).text, '30');
    expect(_apply(tester).onPressed, isNotNull);
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(calls, ['20', '30']);
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('inline timeout retains its controller and draft across rebuilds',
      (tester) async {
    Future<String> save(String value) async => value;
    await _mount(tester, save: save);
    final controller = _controller(tester);
    await _edit(tester, '25');
    await _mount(tester, value: '18', save: save);
    expect(_controller(tester), same(controller));
    expect(controller.text, '25');
    expect(_apply(tester).onPressed, isNotNull);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(() => controller.addListener(() {}), throwsFlutterError);
  });

  testWidgets('inline timeout refreshes an unedited effective value',
      (tester) async {
    Future<String> save(String value) async => value;
    await _mount(tester, save: save);
    expect(_apply(tester).onPressed, isNull);
    await _mount(tester, value: '18', save: save);
    expect(_controller(tester).text, '18');
    expect(_apply(tester).onPressed, isNull);
    await _edit(tester, '25');
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(_apply(tester).onPressed, isNull);
    await _mount(tester, value: '31', save: save);
    expect(_controller(tester).text, '31');
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('inline timeout reports failure and permits the identical retry',
      (tester) async {
    final calls = <String>[];
    await _mount(tester, save: (value) {
      calls.add(value);
      if (calls.length == 1) throw StateError('dispatch failed');
      if (calls.length == 2) return Future.error(StateError('write failed'));
      return Future.value(value);
    });
    await _edit(tester, '25');
    for (var attempt = 0; attempt < 2; attempt++) {
      await tester.tap(find.text('Apply'));
      await tester.pump();
      expect(find.text('Failed'), findsOneWidget);
      expect(_controller(tester).text, '25');
      expect(_apply(tester).onPressed, isNotNull);
    }
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(calls, ['25', '25', '25']);
    expect(find.text('Failed'), findsNothing);
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('inline timeout refuses a mismatched effective value',
      (tester) async {
    var writes = 0;
    await _mount(tester, save: (value) async => ++writes == 1 ? '10' : value);
    await _edit(tester, '25');
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(find.text('Failed'), findsOneWidget);
    expect(_controller(tester).text, '25');
    expect(_apply(tester).onPressed, isNotNull);
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(writes, 2);
    expect(find.text('Failed'), findsNothing);
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('retired inline timeout cannot update its replacement',
      (tester) async {
    final pending = Completer<String>();
    var writes = 0;
    await _mount(tester, save: (_) {
      writes++;
      return pending.future;
    });
    await _edit(tester, '25');
    final oldSave = _apply(tester).onPressed!;
    oldSave();
    await tester.pump();
    await _mount(tester,
        value: '40',
        fieldKey: const ValueKey('replacement'),
        save: (value) async => value);
    oldSave();
    pending.completeError(StateError('retired write failed'));
    await tester.pump();
    expect(writes, 1);
    expect(tester.takeException(), isNull);
    expect(_controller(tester).text, '40');
    expect(find.text('Failed'), findsNothing);
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('disabled inline timeout cannot save or bypass a pending write',
      (tester) async {
    final pending = Completer<String>();
    var writes = 0;
    Future<String> save(String value) {
      writes++;
      return pending.future;
    }

    await _mount(tester, save: save);
    await _edit(tester, '25');
    final oldSave = _apply(tester).onPressed!;
    await _mount(tester, enabled: false, save: save);
    expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
    oldSave();
    expect(writes, 0);
    await _mount(tester, save: save);
    oldSave();
    await tester.pump();
    expect(writes, 1);
    await _mount(tester, enabled: false, save: save);
    await _mount(tester, save: save);
    expect(_apply(tester).onPressed, isNull);
    oldSave();
    expect(writes, 1);
    pending.complete('25');
    await tester.pump();
    expect(_apply(tester).onPressed, isNull);
  });

  testWidgets('inline timeout preserves valid input and the empty default',
      (tester) async {
    final calls = <String>[];
    await _mount(tester, save: (value) async {
      calls.add(value);
      return value;
    });
    await _edit(tester, '65535');
    for (final invalid in ['65536', '99999', '-1', '1.5', '01', 'abc']) {
      await _edit(tester, invalid);
      expect(_controller(tester).text, '65535');
    }
    await _edit(tester, '');
    await tester.tap(find.text('Apply'));
    await tester.pump();
    expect(calls, ['']);
    expect(_controller(tester).text, '');
    expect(_apply(tester).onPressed, isNull);
  });
}

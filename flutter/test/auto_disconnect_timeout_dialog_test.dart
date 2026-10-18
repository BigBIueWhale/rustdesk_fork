import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_test/flutter_test.dart';

Future<OverlayDialogManager> _manager(WidgetTester tester) async {
  final state = BlockableOverlayState();
  final manager = OverlayDialogManager(translateText: (text) => text);
  manager.setOverlayState(state);
  await tester.pumpWidget(MaterialApp(
    home: BlockableOverlay(
      state: state,
      underlying: const SizedBox.expand(),
    ),
  ));
  addTearDown(() async {
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
  });
  return manager;
}

Future<String> _open(
  OverlayDialogManager manager, {
  required Future<void> Function(String) write,
  required Future<String> Function() read,
}) =>
    changeAutoDisconnectTimeout(
      '10',
      dialogManager: manager,
      writeTimeout: write,
      readTimeout: read,
      translateText: (text) => text,
    );

VoidCallback _button(WidgetTester tester, String label) => tester
    .widget<ButtonStyleButton>(find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    ))
    .onPressed!;

void main() {
  testWidgets('cancel and escape preserve the stored timeout', (tester) async {
    final manager = await _manager(tester);
    var writes = 0;
    for (final escape in [false, true]) {
      final result = _open(manager, write: (_) async {
        writes++;
      }, read: () async => '10');
      await tester.pump();
      await tester.enterText(find.byType(TextField), '27');
      if (escape) {
        await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      } else {
        await tester.tap(find.text('Cancel'));
      }
      await tester.pump();
      expect(await result, '10');
      expect(writes, 0);
    }
  });

  testWidgets('successful save waits for readback', (tester) async {
    final manager = await _manager(tester);
    final write = Completer<void>();
    final read = Completer<String>();
    final events = <String>[];
    String? result;
    _open(manager, write: (value) {
      events.add('write:$value');
      return write.future;
    }, read: () {
      events.add('read');
      return read.future;
    }).then((value) => result = value);
    await tester.pump();
    await tester.enterText(find.byType(TextField), '27');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(events, ['write:27']);
    expect(result, isNull);
    write.complete();
    await tester.pump();
    expect(events, ['write:27', 'read']);
    expect(result, isNull);
    read.complete('27');
    await tester.pump();
    expect(result, '27');
    expect(find.byType(TextField), findsNothing);
  });

  testWidgets('unchanged readback keeps the dialog open for retry',
      (tester) async {
    final manager = await _manager(tester);
    var stored = '10';
    var writes = 0;
    String? result;
    _open(manager, write: (value) async {
      writes++;
      if (writes > 1) stored = value;
    }, read: () async => stored).then((value) => result = value);
    await tester.pump();
    await tester.enterText(find.byType(TextField), '27');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(result, isNull);
    expect(find.text('Failed to save'), findsOneWidget);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text, '27');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(writes, 2);
    expect(result, '27');
    expect(stored, '27');
  });

  testWidgets('pending save admits only one submission', (tester) async {
    final manager = await _manager(tester);
    final write = Completer<void>();
    var writes = 0;
    String? result;
    _open(manager, write: (_) {
      writes++;
      return write.future;
    }, read: () async => '27').then((value) => result = value);
    await tester.pump();
    await tester.enterText(find.byType(TextField), '27');
    final submit = _button(tester, 'OK');
    final cancel = _button(tester, 'Cancel');
    submit();
    submit();
    cancel();
    await tester.pump();
    expect(writes, 1);
    expect(result, isNull);
    expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
    write.complete();
    await tester.pump();
    expect(result, '27');
    expect(tester.takeException(), isNull);
  });

  testWidgets('dismissed dialog ignores its pending completion', (tester) async {
    final manager = await _manager(tester);
    final write = Completer<void>();
    var reads = 0;
    var writes = 0;
    final result = _open(manager, write: (_) {
      writes++;
      return write.future;
    }, read: () async {
      reads++;
      return '27';
    });
    await tester.pump();
    await tester.enterText(find.byType(TextField), '27');
    final submit = _button(tester, 'OK');
    submit();
    manager.dismissAll();
    final next = manager.show<void>((_, __, ___) => const Text('next dialog'));
    submit();
    await tester.pump();
    expect(await result, '10');
    expect(writes, 1);
    write.complete();
    await tester.pump();
    expect(reads, 0);
    expect(find.text('next dialog'), findsOneWidget);
    expect(tester.takeException(), isNull);
    manager.dismissAll();
    await next;
  });

  testWidgets('save and read errors leave an editable dialog', (tester) async {
    final manager = await _manager(tester);
    for (final failWrite in [true, false]) {
      var fail = true;
      String? result;
      _open(manager, write: (_) async {
        if (fail && failWrite) throw StateError('write failed');
      }, read: () async {
        if (fail) throw StateError('read failed');
        return '27';
      }).then((value) => result = value);
      await tester.pump();
      await tester.enterText(find.byType(TextField), '27');
      await tester.tap(find.text('OK'));
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(result, isNull);
      expect(find.text('Failed to save'), findsOneWidget);
      expect(tester.widget<TextField>(find.byType(TextField)).enabled, isTrue);
      fail = false;
      await tester.tap(find.text('OK'));
      await tester.pump();
      expect(result, '27');
    }
  });

  testWidgets('timeout field preserves its numeric limits and empty default',
      (tester) async {
    final manager = await _manager(tester);
    var stored = '10';
    final result = _open(manager, write: (value) async {
      stored = value;
    }, read: () async => stored);
    await tester.pump();
    final field = find.byType(TextField);
    await tester.enterText(field, '65535');
    expect(tester.widget<TextField>(field).controller!.text, '65535');
    await tester.enterText(field, '65536');
    expect(tester.widget<TextField>(field).controller!.text, '65535');
    await tester.tap(find.byIcon(Icons.clear));
    await tester.pump();
    expect(tester.widget<TextField>(field).controller!.text, '');
    await tester.tap(find.text('OK'));
    await tester.pump();
    expect(await result, '');
    expect(stored, '');
  });
}

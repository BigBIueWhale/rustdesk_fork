import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/common/widgets/trackpad_speed_dialog.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_test/flutter_test.dart';

class _UnusedOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw StateError('Controlled trackpad work must not access the session');
  }
}

Future<OverlayDialogManager> _manager(WidgetTester tester) async {
  final state = BlockableOverlayState();
  final manager = OverlayDialogManager(translateText: (text) => text);
  manager.setOverlayState(state);
  await tester.pumpWidget(MaterialApp(
    home: BlockableOverlay(state: state, underlying: const SizedBox.expand()),
  ));
  addTearDown(() async {
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
  });
  return manager;
}

Future<void> _open(OverlayDialogManager manager,
    Future<int?> Function(int) save) => manager.show<void>(
  (_, close, __) => TrackpadSpeedDialog(
    initialSpeed: 100, saveSpeed: save, close: close,
    translateText: (text) => text,
  ), tag: 'trackpad',
);

VoidCallback _button(WidgetTester tester, String label) => tester
    .widget<ButtonStyleButton>(find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    )).onPressed!;

void main() {
  testWidgets('trackpad dialog stages raw text until committed Close', (tester) async {
    final manager = await _manager(tester);
    final pending = Completer<int?>();
    final calls = <int>[];
    final result = _open(manager, (value) { calls.add(value); return pending.future; });
    await tester.pump();
    await tester.enterText(find.byType(TextField), '235');
    await tester.pump(const Duration(seconds: 2));
    expect(calls, isEmpty);
    await tester.tap(find.text('Close'));
    await tester.pump();
    expect(calls, [235]);
    expect(manager.existing('trackpad'), isTrue);
    pending.complete(235);
    await tester.pump();
    await result;
    expect(manager.existing('trackpad'), isFalse);
  });

  testWidgets('trackpad dialog retains failed saves for identical retry', (tester) async {
    final manager = await _manager(tester);
    for (final mode in ['throw', 'null', 'mismatch']) {
      final calls = <int>[];
      final result = _open(manager, (value) async {
        calls.add(value);
        if (calls.length > 1) return value;
        if (mode == 'throw') throw StateError('write denied');
        return mode == 'null' ? null : 100;
      });
      await tester.pump();
      await tester.enterText(find.byType(TextField), '235');
      await tester.tap(find.text('Close'));
      await tester.pump();
      expect(find.text('Failed'), findsOneWidget);
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text, '235');
      expect(tester.widget<TextField>(find.byType(TextField)).enabled, isTrue);
      await tester.tap(find.text('Retry'));
      await tester.pump();
      await result;
      expect(calls, [235, 235]);
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('trackpad dialog admits one save and blocks pending Escape', (tester) async {
    final manager = await _manager(tester);
    final pending = Completer<int?>();
    var writes = 0;
    final result = _open(manager, (_) { writes++; return pending.future; });
    await tester.pump();
    await tester.enterText(find.byType(TextField), '235');
    final submit = _button(tester, 'Close');
    final dialog = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog));
    submit(); submit(); dialog.onSubmit!(); dialog.onCancel!();
    await tester.pump();
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    expect(writes, 1);
    expect(manager.existing('trackpad'), isTrue);
    expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
    pending.complete(235);
    await tester.pump();
    await result;
  });

  testWidgets('trackpad dialog retirement cannot close a replacement', (tester) async {
    final manager = await _manager(tester);
    for (final failure in [false, true]) {
      final pending = Completer<int?>();
      var writes = 0;
      final result = _open(manager, (_) { writes++; return pending.future; });
      await tester.pump();
      await tester.enterText(find.byType(TextField), '235');
      final submit = _button(tester, 'Close');
      submit();
      manager.dismissByTag('trackpad');
      final next = manager.show<void>((_, __, ___) => const Text('replacement'), tag: 'trackpad');
      submit();
      await tester.pump();
      if (failure) { pending.completeError(StateError('late failure')); }
      else { pending.complete(235); }
      await tester.pump();
      await result;
      expect(writes, 1);
      expect(find.text('replacement'), findsOneWidget);
      expect(tester.takeException(), isNull);
      manager.dismissByTag('trackpad');
      await next;
    }
  });

  testWidgets('trackpad dialog Escape and unchanged Close perform no save', (tester) async {
    final manager = await _manager(tester);
    var writes = 0;
    var result = _open(manager, (value) async { writes++; return value; });
    await tester.pump();
    await tester.enterText(find.byType(TextField), '235');
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    await result;
    result = _open(manager, (value) async { writes++; return value; });
    await tester.pump();
    await tester.tap(find.text('Close'));
    await tester.pump();
    await result;
    expect(writes, 0);
  });

  testWidgets('trackpad dialog bounds raw Close and rejects empty input', (tester) async {
    final manager = await _manager(tester);
    final calls = <int>[];
    for (final value in ['0', '1001']) {
      final result = _open(manager, (value) async { calls.add(value); return value; });
      await tester.pump();
      await tester.enterText(find.byType(TextField), '');
      await tester.tap(find.text('Close'));
      await tester.pump();
      expect(find.text('Failed'), findsOneWidget);
      await tester.enterText(find.byType(TextField), value);
      await tester.tap(find.text('Retry'));
      await tester.pump();
      await result;
    }
    expect(calls, [10, 1000]);
  });

  testWidgets('trackpad dialog rebuild retains draft and uses current writer', (tester) async {
    final manager = await _manager(tester);
    late StateSetter rebuild;
    final calls = <String>[];
    var current = false;
    final result = manager.show<void>((setState, close, _) {
      rebuild = setState;
      final writer = current ? 'current' : 'old';
      return TrackpadSpeedDialog(initialSpeed: 100,
        saveSpeed: (value) async { calls.add('$writer:$value'); return value; },
        close: close, translateText: (text) => text);
    });
    await tester.pump();
    await tester.enterText(find.byType(TextField), '235');
    rebuild(() => current = true);
    await tester.pump();
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text, '235');
    await tester.tap(find.text('Close'));
    await tester.pump();
    await result;
    expect(calls, ['current:235']);
  });

  testWidgets('trackpad dialog fits narrow layout and stages slider input', (tester) async {
    tester.view.physicalSize = const Size(360, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final manager = await _manager(tester);
    final calls = <int>[];
    final result = _open(manager, (value) async { calls.add(value); return value; });
    await tester.pump();
    tester.widget<Slider>(find.byType(Slider)).onChanged!(245);
    await tester.pump();
    expect(calls, isEmpty);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text, '245');
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('Close'));
    await tester.pump();
    await result;
    expect(calls, [245]);
  });

  testWidgets('trackpad model admits one writer across dialogs and allows retry', (tester) async {
    final owner = _UnusedOwner();
    final model = InputModel(WeakReference(owner));
    addTearDown(model.relativeMouseMode.close);
    // The callback at 0b205551 applies each returned value without model admission.
    final oldReply = Completer<int>();
    final newReply = Completer<int>();
    Future<void> before(Future<int> reply) async {
      model.applyTrackpadSpeed(await reply);
    }
    final oldOperation = before(oldReply.future);
    final newOperation = before(newReply.future);
    newReply.complete(240);
    await newOperation;
    expect(model.trackpadSpeed, 240);
    oldReply.complete(235);
    await oldOperation;
    expect(model.trackpadSpeed, 235);
    model.applyTrackpadSpeed(100);

    final manager = await _manager(tester);
    final pending = Completer<int>();
    final calls = <int>[];
    Future<int?> save(int value) => model.saveTrackpadSpeed(value,
        writeSpeed: (value) {
          calls.add(value);
          return calls.length == 1 ? pending.future : Future.value(value);
        }, isCurrent: () => true);
    final first = _open(manager, save);
    await tester.pump();
    await tester.enterText(find.byType(TextField), '235');
    await tester.tap(find.text('Close'));
    manager.dismissByTag('trackpad');
    final second = _open(manager, save);
    await tester.pump();
    await tester.enterText(find.byType(TextField), '240');
    await tester.tap(find.text('Close'));
    await tester.pump();
    expect(calls, [235]);
    expect(find.text('Failed'), findsOneWidget);
    pending.complete(235);
    await tester.pump();
    await first;
    expect(model.trackpadSpeed, 235);
    expect(manager.existing('trackpad'), isTrue);
    await tester.tap(find.text('Retry'));
    await tester.pump();
    await second;
    expect(calls, [235, 240]);
    expect(model.trackpadSpeed, 240);
  });

  testWidgets('trackpad model retires failed writes and stale refreshes', (tester) async {
    final owner = _UnusedOwner();
    final model = InputModel(WeakReference(owner));
    addTearDown(model.relativeMouseMode.close);
    var current = true;
    bool isCurrent() => current;
    final old = Completer<int?>();
    final recent = Completer<int?>();
    final first = model.refreshTrackpadSpeed(readSpeed: () => old.future, isCurrent: isCurrent);
    final second = model.refreshTrackpadSpeed(readSpeed: () => recent.future, isCurrent: isCurrent);
    recent.complete(200);
    await second;
    old.complete(120);
    await first;
    expect(model.trackpadSpeed, 200);
    final stale = Completer<int?>();
    final reading = model.refreshTrackpadSpeed(readSpeed: () => stale.future, isCurrent: isCurrent);
    expect(await model.saveTrackpadSpeed(235, writeSpeed: (v) async => v, isCurrent: isCurrent), 235);
    stale.complete(100);
    await reading;
    expect(model.trackpadSpeed, 235);
    final retired = Completer<int>();
    final saving = model.saveTrackpadSpeed(240, writeSpeed: (_) => retired.future, isCurrent: isCurrent);
    current = false;
    retired.complete(240);
    expect(await saving, isNull);
    expect(model.trackpadSpeed, 235);
    var unwantedRead = false;
    await model.refreshTrackpadSpeed(readSpeed: () async { unwantedRead = true; return 100; }, isCurrent: isCurrent);
    expect(unwantedRead, isFalse);
    current = true;
    await expectLater(model.saveTrackpadSpeed(240,
        writeSpeed: (_) => Future.error(StateError('denied')), isCurrent: isCurrent), throwsStateError);
    expect(await model.saveTrackpadSpeed(240, writeSpeed: (_) async => 250, isCurrent: isCurrent), isNull);
    expect(model.trackpadSpeed, 235);
    expect(await model.saveTrackpadSpeed(240, writeSpeed: (v) async => v, isCurrent: isCurrent), 240);
    await expectLater(model.saveTrackpadSpeed(9, writeSpeed: (v) async => v, isCurrent: isCurrent), throwsRangeError);
    expect(model.trackpadSpeed, 240);
    await model.refreshTrackpadSpeed(readSpeed: () async => 1001, isCurrent: isCurrent);
    expect(model.trackpadSpeed, 100);
  });
}

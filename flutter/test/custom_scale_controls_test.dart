import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/common/widgets/custom_scale_base.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Preferences implements CanvasPreferences {
  int percent = 100;
  String style = kRemoteViewStyleCustom;
  String scroll = kRemoteScrollStyleAuto;
  int reads = 0;
  int styleReads = 0;
  Future<double> Function(int)? read;
  Future<String?> Function(int)? readStyle;

  @override
  Future<double> customScale(SessionID id) {
    reads++;
    return read?.call(reads) ?? Future.value(percent / 100.0);
  }

  @override
  Future<String?> viewStyle(SessionID id) {
    styleReads++;
    return readStyle?.call(styleReads) ?? Future.value(style);
  }
  @override
  Future<String?> scrollStyle(SessionID id) async => scroll;
  @override
  Future<int?> edgeThickness(SessionID id) async => 100;
}

class _Writer implements CanvasCustomScaleWriter {
  _Writer(this.preferences);
  final _Preferences preferences;
  final calls = <int>[];
  Future<int> Function(int)? write;
  int active = 0;
  int maximumActive = 0;

  @override
  Future<int> save(SessionID id, int percent) async {
    calls.add(percent);
    active++;
    if (active > maximumActive) maximumActive = active;
    try {
      final effective = await (write?.call(percent) ?? Future.value(percent));
      if (effective == percent) {
        preferences.percent = percent;
        preferences.style = kRemoteViewStyleCustom;
      }
      return effective;
    } finally {
      active--;
    }
  }
}

class _Topology implements FfiModel {
  _Topology(this.sessionId);
  final SessionID sessionId;
  @override
  final pi = PeerInfo()
    ..displays.add(Display()
      ..width = 2
      ..height = 2);
  @override
  ui.Rect get rect => const ui.Rect.fromLTWH(0, 0, 2, 2);
  @override
  bool isCurrentDisplayTopology(SessionID id, int revision) => id == sessionId && revision == 0;
  @override
  int? currentDisplayTopologyRevision(SessionID id) => id == sessionId ? 0 : null;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Input implements InputModel {
  int refreshes = 0;
  @override
  void refreshMousePos() => refreshes++;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Session implements FFI {
  final preferences = _Preferences();
  late final writer = _Writer(preferences);
  bool current = true;
  @override
  final SessionID sessionId = Uuid().v4obj();
  @override
  final SessionID clientOwnerId = Uuid().v4obj();
  @override
  late final _Topology ffiModel = _Topology(sessionId);
  @override
  late final ImageModel imageModel = ImageModel(WeakReference<FFI>(this));
  @override
  late final CanvasModel canvasModel = CanvasModel(WeakReference<FFI>(this),
      preferences: preferences, customScaleWriter: writer);
  @override
  late final CursorModel cursorModel = CursorModel(WeakReference<FFI>(this));
  @override
  final _Input inputModel = _Input();
  @override
  bool isCurrentSession(SessionID id) => current && id == sessionId;
  @override
  bool isCurrentSessionOwner(SessionID id, SessionID owner) =>
      isCurrentSession(id) && owner == clientOwnerId;

  void dispose() {
    canvasModel.dispose();
    imageModel.dispose();
    cursorModel.dispose();
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Controls extends StatefulWidget {
  const _Controls({super.key, required this.session, this.changed});
  final _Session session;
  final ValueChanged<int>? changed;
  @override
  State<_Controls> createState() => _ControlsState();
}

class _ControlsState extends CustomScaleControls<_Controls> {
  @override
  FFI get ffi => widget.session;
  @override
  ValueChanged<int>? get onScaleChanged => widget.changed;
  @override
  String get scaleFailureText => 'Failed';
  @override
  String get scaleRetryText => 'Retry';

  @override
  Widget build(BuildContext context) => Column(children: [
    Text('$scaleValue', key: const ValueKey('percent')),
    Slider(value: scalePos, onChanged: onSliderChanged),
    TextButton(key: const ValueKey('minus'), onPressed: nudgeScale(-1), child: const Text('-')),
    TextButton(key: const ValueKey('plus'), onPressed: nudgeScale(1), child: const Text('+')),
    buildScaleStatus(),
  ]);
}

Widget _root(_Session session, {Key key = const ValueKey('controls'), ValueChanged<int>? changed}) =>
    MaterialApp(home: Scaffold(body: SizedBox(width: 400,
      child: _Controls(key: key, session: session, changed: changed))));

String _percent(WidgetTester tester) => tester.widget<Text>(find.byKey(const ValueKey('percent'))).data!;
Future<void> _flush(WidgetTester tester) async { await tester.pump(); await tester.pump(); }
Future<void> _debounce(WidgetTester tester) async {
  await tester.pump(const Duration(milliseconds: 301));
  await _flush(tester);
}
Future<void> _finish(WidgetTester tester, List<_Session> sessions) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await _flush(tester);
  for (final session in sessions) { session.dispose(); }
}

List<Object> _canvasState(_Session session) => [session.canvasModel.x, session.canvasModel.y,
  session.canvasModel.scale, session.canvasModel.size, session.canvasModel.viewStyle,
  session.canvasModel.scrollX, session.canvasModel.scrollY, session.inputModel.refreshes];

void main() {
  testWidgets('custom scale initializes percentage and normalized position together', (tester) async {
    final session = _Session();
    final pending = Completer<double>();
    session.preferences.read = (_) => pending.future;
    await tester.pumpWidget(_root(session));
    expect(_percent(tester), '100');
    expect(tester.widget<Slider>(find.byType(Slider)).value, kScaleCustomPivotPos);
    pending.complete(1.5);
    await _flush(tester);
    expect(_percent(tester), '150');
    expect(tester.widget<Slider>(find.byType(Slider)).value, greaterThan(kScaleCustomPivotPos));
    expect(session.writer.calls, isEmpty);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale initial read cannot replace a newer saved draft', (tester) async {
    final session = _Session();
    final pending = Completer<double>();
    session.preferences.read = (call) => call == 1 ? pending.future : Future.value(session.preferences.percent / 100);
    await tester.pumpWidget(_root(session));
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(session.writer.calls, [101]);
    pending.complete(1.5);
    await _flush(tester);
    expect(_percent(tester), '101');
    expect(find.text('Retry'), findsNothing);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale rebuild preserves its draft and uses current callbacks', (tester) async {
    final session = _Session();
    final oldCalls = <int>[];
    final currentCalls = <int>[];
    await tester.pumpWidget(_root(session, changed: oldCalls.add));
    await _flush(tester);
    oldCalls.clear();
    await tester.tap(find.byKey(const ValueKey('plus')));
    await tester.pumpWidget(_root(session, changed: currentCalls.add));
    expect(_percent(tester), '101');
    await _debounce(tester);
    expect(oldCalls, [101]);
    expect(currentCalls, [101]);
    expect(session.writer.calls, [101]);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale serializes saves and retains only the latest draft', (tester) async {
    final session = _Session();
    final pending = Completer<int>();
    session.writer.write = (value) => session.writer.calls.length == 1 ? pending.future : Future.value(value);
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(session.writer.calls, [101]);
    expect(_percent(tester), '103');
    pending.complete(101);
    await _flush(tester);
    expect(session.writer.calls, [101, 103]);
    expect(session.writer.maximumActive, 1);
    expect(_percent(tester), '103');
    await _finish(tester, [session]);
  });

  testWidgets('custom scale failed save preserves canvas and retries the same draft', (tester) async {
    final session = _Session();
    final initialRead = Completer<double>();
    session.preferences.read = (call) => call == 1 ? initialRead.future
        : Future.value(session.preferences.percent / 100.0);
    session.writer.write = (value) => session.writer.calls.length == 1
        ? Future.error(StateError('store failed')) : Future.value(value);
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    session.canvasModel.update(31, 37, 1.75);
    final before = _canvasState(session);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(_percent(tester), '101');
    expect(_canvasState(session), before);
    expect(find.text('Retry'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('custom-scale-retry')));
    await _flush(tester);
    expect(session.writer.calls, [101, 101]);
    expect(find.text('Retry'), findsNothing);
    initialRead.complete(1.0);
    await _flush(tester);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale mismatched result remains visible and retryable', (tester) async {
    final session = _Session();
    session.writer.write = (value) async => session.writer.calls.length == 1 ? value + 1 : value;
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(_percent(tester), '101');
    expect(session.preferences.percent, 100);
    expect(find.text('Retry'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('custom-scale-retry')));
    await _flush(tester);
    expect(session.writer.calls, [101, 101]);
    expect(find.text('Retry'), findsNothing);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale failed loading retries a read without saving defaults', (tester) async {
    final session = _Session();
    session.preferences.percent = 150;
    session.preferences.read = (call) => call == 1
        ? Future.error(StateError('read failed')) : Future.value(1.5);
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    expect(find.text('Retry'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('custom-scale-retry')));
    await _flush(tester);
    expect(_percent(tester), '150');
    expect(session.preferences.reads, 2);
    expect(session.writer.calls, isEmpty);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale removal cancels queued and captured edit callbacks', (tester) async {
    final session = _Session();
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    final oldSlider = tester.widget<Slider>(find.byType(Slider)).onChanged!;
    final oldNudge = tester.widget<TextButton>(find.byKey(const ValueKey('plus'))).onPressed!;
    await tester.tap(find.byKey(const ValueKey('plus')));
    await tester.pumpWidget(const SizedBox.shrink());
    oldSlider(1.0);
    oldNudge();
    await _debounce(tester);
    expect(session.writer.calls, isEmpty);
    expect(tester.takeException(), isNull);
    session.dispose();
  });

  testWidgets('custom scale removed widget retires feedback while admitted canvas work settles', (tester) async {
    final session = _Session();
    final pending = Completer<int>();
    final calls = <int>[];
    session.writer.write = (_) => pending.future;
    await tester.pumpWidget(_root(session, changed: calls.add));
    await _flush(tester);
    calls.clear();
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    pending.complete(101);
    await _flush(tester);
    expect(calls, [101]);
    expect(session.preferences.percent, 101);
    expect(session.canvasModel.scale, closeTo(1.01 / ui.window.devicePixelRatio, 1e-9));
    expect(tester.takeException(), isNull);
    session.dispose();
  });

  testWidgets('custom scale retargeting invalidates old reads and captured handlers', (tester) async {
    final old = _Session();
    final current = _Session()..preferences.percent = 200;
    final pending = Completer<double>();
    old.preferences.read = (_) => pending.future;
    await tester.pumpWidget(_root(old));
    final oldSlider = tester.widget<Slider>(find.byType(Slider)).onChanged!;
    final oldNudge = tester.widget<TextButton>(find.byKey(const ValueKey('plus'))).onPressed!;
    await tester.pumpWidget(_root(current));
    oldSlider(1.0);
    oldNudge();
    expect(current.preferences.reads, 0);
    pending.complete(1.5);
    await _flush(tester);
    expect(_percent(tester), '200');
    expect(current.writer.calls, isEmpty);
    expect(old.writer.calls, isEmpty);
    await _finish(tester, [old, current]);
  });

  testWidgets('custom scale retired save error cannot replace a new session draft', (tester) async {
    final old = _Session();
    final current = _Session()..preferences.percent = 200;
    final pending = Completer<int>();
    old.writer.write = (_) => pending.future;
    await tester.pumpWidget(_root(old));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    await tester.pumpWidget(_root(current));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(current.writer.calls, isEmpty);
    pending.completeError(StateError('retired save failed'));
    await _flush(tester);
    expect(current.writer.calls, [201]);
    expect(_percent(tester), '201');
    expect(find.text('Retry'), findsNothing);
    await _finish(tester, [old, current]);
  });

  testWidgets('custom scale slider preserves limits and its hundred percent detent', (tester) async {
    final session = _Session()..preferences.percent = 5;
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('minus')));
    await _debounce(tester);
    expect(session.writer.calls, isEmpty);
    tester.widget<Slider>(find.byType(Slider)).onChanged!(1.0);
    await _debounce(tester);
    expect(_percent(tester), '1000');
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    tester.widget<Slider>(find.byType(Slider)).onChanged!(kScaleCustomPivotPos + 0.003);
    await _debounce(tester);
    expect(_percent(tester), '100');
    expect(session.writer.calls, [1000, 100]);
    await _finish(tester, [session]);
  });

  testWidgets('replacement custom scale controls wait for admission and retain retry', (tester) async {
    final session = _Session();
    final pending = Completer<int>();
    session.writer.write = (value) => session.writer.calls.length == 1 ? pending.future : Future.value(value);
    await tester.pumpWidget(_root(session));
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    await tester.pumpWidget(_root(session, key: const ValueKey('replacement')));
    await tester.tap(find.byKey(const ValueKey('plus')));
    await _debounce(tester);
    expect(session.writer.calls, [101]);
    expect(find.text('Retry'), findsOneWidget);
    pending.complete(101);
    await _flush(tester);
    await tester.tap(find.byKey(const ValueKey('custom-scale-retry')));
    await _flush(tester);
    expect(session.writer.calls, [101, 101]);
    expect(session.writer.maximumActive, 1);
    expect(find.text('Retry'), findsNothing);
    await _finish(tester, [session]);
  });

  testWidgets('custom scale removal cancels its deferred read subscription', (tester) async {
    final session = _Session();
    final native = Completer<int>();
    final calls = <int>[];
    session.writer.write = (_) => native.future;
    final saving = session.canvasModel.applyCustomScalePercent(150,
        owner: session.canvasModel.captureUpdateOwner());
    await tester.pumpWidget(_root(session, changed: calls.add));
    await _flush(tester);
    expect(session.preferences.reads, 0);
    await tester.pumpWidget(const SizedBox.shrink());
    native.complete(150);
    await _flush(tester);
    expect(await saving, 150);
    expect(session.preferences.reads, 1);
    expect(calls, isEmpty);
    expect(tester.takeException(), isNull);
    session.dispose();
  });

  testWidgets('canvas custom scale admission is shared through publication', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final native = Completer<int>();
      final scaleRead = Completer<double>();
      session.writer.write = (_) => native.future;
      session.preferences.read = (call) => call == 1 ? scaleRead.future
          : Future.value(session.preferences.percent / 100.0);
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final saving = canvas.applyCustomScalePercent(125, owner: owner);
      await expectLater(canvas.applyCustomScalePercent(150, owner: owner), throwsStateError);
      native.complete(125);
      await Future<void>.delayed(Duration.zero);
      expect(session.preferences.reads, 1);
      await expectLater(canvas.applyCustomScalePercent(175, owner: owner), throwsStateError);
      await expectLater(canvas.readCustomScalePercent(owner: owner), throwsStateError);
      expect(session.preferences.reads, 1);
      scaleRead.complete(1.25);
      expect(await saving, 125);
      expect(await canvas.readCustomScalePercent(owner: owner), 125);
      expect(session.writer.calls, [125]);
      expect(session.canvasModel.scale, closeTo(1.25 / ui.window.devicePixelRatio, 1e-9));
      session.dispose();
    });
  });

  testWidgets('canvas scale owner retirement preserves state while accepted work settles', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final native = Completer<int>();
      session.writer.write = (value) => session.writer.calls.length == 1 ? native.future : Future.value(value);
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final saving = canvas.applyCustomScalePercent(125, owner: owner);
      session.imageModel.retirePresentation();
      canvas.update(31, 37, 1.75);
      final before = _canvasState(session);
      native.complete(125);
      expect(await saving, 125);
      expect(_canvasState(session), before);
      await expectLater(canvas.applyCustomScalePercent(200, owner: owner), throwsStateError);
      final fresh = canvas.captureUpdateOwner();
      expect(await canvas.readCustomScalePercent(owner: fresh), 125);
      expect(await canvas.applyCustomScalePercent(200, owner: fresh), 200);
      expect(session.writer.calls, [125, 200]);
      session.dispose();
    });
  });

  testWidgets('canvas clear retains accepted scale admission until completion', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final native = Completer<int>();
      session.writer.write = (value) => session.writer.calls.length == 1 ? native.future : Future.value(value);
      final canvas = session.canvasModel;
      final saving = canvas.applyCustomScalePercent(125, owner: canvas.captureUpdateOwner());
      canvas.clear();
      final fresh = canvas.captureUpdateOwner();
      await expectLater(canvas.applyCustomScalePercent(200, owner: fresh), throwsStateError);
      native.complete(125);
      expect(await saving, 125);
      expect(await canvas.readCustomScalePercent(owner: fresh), 125);
      expect(await canvas.applyCustomScalePercent(200, owner: fresh), 200);
      expect(session.writer.calls, [125, 200]);
      session.dispose();
    });
  });

  testWidgets('canvas scale read failure preserves geometry and permits retry', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      canvas.update(31, 37, 1.75);
      final before = _canvasState(session);
      session.preferences.read = (_) => Future.error(StateError('read failed'));
      expect(await canvas.updateViewStyle(owner: owner), isFalse);
      expect(_canvasState(session), before);
      for (final scale in [double.nan, double.infinity, 0.0, -1.0, 10.01]) {
        session.preferences.read = (_) async => scale;
        expect(await canvas.updateViewStyle(owner: owner), isFalse);
        expect(_canvasState(session), before);
      }
      session.preferences.read = (_) async => 2.25;
      expect(await canvas.updateViewStyle(owner: owner), isTrue);
      expect(canvas.scale, closeTo(2.25 / ui.window.devicePixelRatio, 1e-9));
      expect(session.inputModel.refreshes, 1);
      session.dispose();
    });
  });

  testWidgets('canvas scale getter refuses invalid values and unavailable owners', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      for (final scale in [double.nan, double.infinity, 0.0, -1.0, 10.01, 0.0501]) {
        session.preferences.read = (_) async => scale;
        await expectLater(canvas.readCustomScalePercent(owner: owner), throwsStateError);
      }
      final reads = session.preferences.reads;
      await expectLater(canvas.readCustomScalePercent(owner: null), throwsStateError);
      for (final percent in [4, 1001]) {
        await expectLater(canvas.applyCustomScalePercent(percent, owner: owner), throwsArgumentError);
      }
      session.current = false;
      await expectLater(canvas.readCustomScalePercent(owner: owner), throwsStateError);
      await expectLater(canvas.applyCustomScalePercent(100, owner: owner), throwsStateError);
      expect(session.preferences.reads, reads);
      expect(session.writer.calls, isEmpty);
      session.current = true;
      session.preferences.read = (_) async => 2.5;
      expect(await canvas.readCustomScalePercent(owner: canvas.captureUpdateOwner()), 250);
      session.dispose();
    });
  });

  testWidgets('canvas scale commit retires an older pending preference update', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final olderRead = Completer<double>();
      session.preferences.read = (call) => call == 1 ? olderRead.future
          : Future.value(session.preferences.percent / 100.0);
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final older = canvas.updateViewStyle(owner: owner);
      await Future<void>.delayed(Duration.zero);
      expect(session.preferences.reads, 1);
      expect(await canvas.applyCustomScalePercent(225, owner: owner), 225);
      final before = _canvasState(session);
      olderRead.complete(1.0);
      expect(await older, isFalse);
      expect(_canvasState(session), before);
      expect(canvas.scale, closeTo(2.25 / ui.window.devicePixelRatio, 1e-9));
      session.dispose();
    });
  });

  testWidgets('canvas style change retires an older custom scale read', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final olderRead = Completer<double>();
      session.preferences.read = (_) => olderRead.future;
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final older = canvas.updateViewStyle(owner: owner);
      session.preferences.style = kRemoteViewStyleOriginal;
      expect(await canvas.updateViewStyle(owner: owner), isTrue);
      final before = _canvasState(session);
      olderRead.complete(2.25);
      expect(await older, isFalse);
      expect(_canvasState(session), before);
      session.dispose();
    });
  });

  testWidgets('canvas ready initializers remain useful without a preference commit', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final first = Completer<double>();
      final second = Completer<double>();
      session.preferences.read = (call) => call == 1 ? first.future : second.future;
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final earlier = canvas.updateViewStyle(owner: owner);
      final later = canvas.updateViewStyle(owner: owner);
      second.complete(1.5);
      expect(await later, isTrue);
      first.complete(1.5);
      expect(await earlier, isTrue);
      expect(session.inputModel.refreshes, 2);
      expect(session.writer.calls, isEmpty);
      session.dispose();
    });
  });

  testWidgets('canvas asynchronous view read leaves event handling available', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final held = Completer<String?>();
      session.preferences.readStyle = (_) => held.future;
      final canvas = session.canvasModel;
      canvas.update(31, 37, 1.75);
      final before = _canvasState(session);
      var finished = false;
      final pending = canvas.updateViewStyle(owner: canvas.captureUpdateOwner())
          .then((value) { finished = true; return value; });
      var eventRan = false;
      await Future<void>(() { eventRan = true; });
      expect(eventRan, isTrue);
      expect(finished, isFalse);
      expect(_canvasState(session), before);
      held.complete(kRemoteViewStyleOriginal);
      expect(await pending, isTrue);
      expect(canvas.viewStyle.style, kRemoteViewStyleOriginal);
      session.dispose();
    });
  });

  testWidgets('canvas view read errors and invalid styles preserve geometry and retry', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      canvas.update(31, 37, 1.75);
      final before = _canvasState(session);
      for (final value in [null, '', 'bad']) {
        session.preferences.readStyle = (_) async => value;
        expect(await canvas.updateViewStyle(owner: owner), isFalse);
        expect(_canvasState(session), before);
      }
      session.preferences.readStyle = (_) => throw StateError('sync read failure');
      expect(await canvas.updateViewStyle(owner: owner), isFalse);
      session.preferences.readStyle = (_) => Future.error(StateError('async read failure'));
      expect(await canvas.updateViewStyle(owner: owner), isFalse);
      expect(_canvasState(session), before);
      expect(session.preferences.reads, 0);
      session.preferences.readStyle = (_) async => kRemoteViewStyleAdaptive;
      expect(await canvas.updateViewStyle(owner: owner), isTrue);
      expect(canvas.viewStyle.style, kRemoteViewStyleAdaptive);
      session.dispose();
    });
  });

  testWidgets('canvas retired first view read cannot start its scale query', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final held = Completer<String?>();
      session.preferences.readStyle = (_) => held.future;
      final canvas = session.canvasModel;
      final pending = canvas.updateViewStyle(owner: canvas.captureUpdateOwner());
      session.imageModel.retirePresentation();
      final before = _canvasState(session);
      held.complete(kRemoteViewStyleCustom);
      expect(await pending, isFalse);
      expect(_canvasState(session), before);
      expect(session.preferences.reads, 0);
      session.dispose();
    });
  });

  testWidgets('canvas delayed original read cannot replace applied adaptive style', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final held = Completer<String?>();
      session.preferences.readStyle = (call) => call == 1
          ? held.future : Future.value(kRemoteViewStyleAdaptive);
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final pending = canvas.updateViewStyle(owner: owner);
      expect(await canvas.updateViewStyle(owner: owner), isTrue);
      final before = _canvasState(session);
      held.complete(kRemoteViewStyleOriginal);
      expect(await pending, isFalse);
      expect(_canvasState(session), before);
      expect(canvas.viewStyle.style, kRemoteViewStyleAdaptive);
      session.dispose();
    });
  });

  testWidgets('canvas retirement during final style read prevents publication', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final held = Completer<String?>();
      final started = Completer<void>();
      session.preferences.readStyle = (call) {
        if (call == 1) return Future.value(kRemoteViewStyleCustom);
        started.complete();
        return held.future;
      };
      final canvas = session.canvasModel;
      final pending = canvas.updateViewStyle(owner: canvas.captureUpdateOwner());
      await started.future;
      canvas.clear();
      final before = _canvasState(session);
      held.complete(kRemoteViewStyleCustom);
      expect(await pending, isFalse);
      expect(_canvasState(session), before);
      expect(session.inputModel.refreshes, 0);
      session.dispose();
    });
  });

  testWidgets('canvas pending scale uses current geometry after its reads', (tester) async {
    tester.view.physicalSize = const Size(800, 600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.runAsync(() async {
      final session = _Session();
      final held = Completer<double>();
      final started = Completer<void>();
      session.preferences.read = (_) { started.complete(); return held.future; };
      final canvas = session.canvasModel;
      final pending = canvas.updateViewStyle(owner: canvas.captureUpdateOwner());
      await started.future;
      tester.view.physicalSize = const Size(1200, 800);
      final expected = canvas.getSize();
      held.complete(2.25);
      expect(await pending, isTrue);
      expect(canvas.size, expected);
      expect(canvas.viewStyle.width, expected.width);
      expect(canvas.viewStyle.height, expected.height);
      session.dispose();
    });
  });

  testWidgets('canvas scrolling read failure and retired style cannot reset geometry', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      session.preferences.scroll = kRemoteScrollStyleEdge;
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      await canvas.updateScrollStyle(owner: owner);
      canvas.setScrollPercent(0.6, 0.7);
      session.preferences.readStyle = (_) => Future.error(StateError('style unavailable'));
      expect(await canvas.tryUpdateScrollStyle(Duration.zero, null, owner: owner), isFalse);
      expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
      final held = Completer<String?>();
      session.preferences.readStyle = (call) => call == 2
          ? held.future : Future.value(kRemoteViewStyleAdaptive);
      final pending = canvas.tryUpdateScrollStyle(const Duration(seconds: 30), null, owner: owner);
      expect(await canvas.updateViewStyle(owner: owner), isTrue);
      canvas.setScrollPercent(0.4, 0.5);
      held.complete(kRemoteViewStyleOriginal);
      expect(await pending, isFalse);
      expect([canvas.scrollX, canvas.scrollY], [0.4, 0.5]);
      session.dispose();
    });
  });

  testWidgets('canvas changed scroll mode retires a pending view style read', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      session.preferences.scroll = kRemoteScrollStyleEdge;
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      await canvas.updateScrollStyle(owner: owner);
      final held = Completer<String?>();
      session.preferences.readStyle = (_) => held.future;
      final pending = canvas.tryUpdateScrollStyle(
          const Duration(seconds: 30), null, owner: owner);
      session.preferences.scroll = kRemoteScrollStyleAuto;
      await canvas.updateScrollStyle(owner: owner);
      session.preferences.scroll = kRemoteScrollStyleEdge;
      await canvas.updateScrollStyle(owner: owner);
      canvas.setScrollPercent(0.6, 0.7);
      held.complete(kRemoteViewStyleOriginal);
      expect(await pending, isFalse);
      expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
      session.dispose();
    });
  });

  testWidgets('canvas scroll mode change cancels and joins its queued timer', (tester) async {
    final session = _Session();
    final canvas = session.canvasModel;
    Future<bool>? pending;
    try {
      session.preferences.scroll = kRemoteScrollStyleEdge;
      final owner = canvas.captureUpdateOwner();
      await tester.runAsync(() => canvas.updateScrollStyle(owner: owner));
      bool? result;
      pending = canvas.tryUpdateScrollStyle(
          const Duration(seconds: 30), kRemoteViewStyleOriginal, owner: owner)
          .then((value) { result = value; return value; });
      canvas.setScrollPercent(0.6, 0.7);
      session.preferences.scroll = kRemoteScrollStyleAuto;
      await tester.runAsync(() => canvas.updateScrollStyle(owner: owner));
      await tester.pump();
      expect(result, isFalse);
      expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
      await tester.pump(const Duration(seconds: 30));
      expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
      expect(tester.takeException(), isNull);
    } finally {
      session.dispose();
      if (pending != null) await pending;
    }
  });

  testWidgets('canvas scale mutation failure releases admission for retry', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      session.writer.write = (value) {
        if (session.writer.calls.length == 1) return Future.error(StateError('store failed'));
        return Future.value(session.writer.calls.length == 2 ? value + 1 : value);
      };
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      canvas.update(31, 37, 1.75);
      final before = _canvasState(session);
      await expectLater(canvas.applyCustomScalePercent(125, owner: owner), throwsStateError);
      await expectLater(canvas.applyCustomScalePercent(125, owner: owner), throwsStateError);
      expect(_canvasState(session), before);
      expect(await canvas.applyCustomScalePercent(125, owner: owner), 125);
      expect(session.writer.calls, [125, 125, 125]);
      expect(session.writer.maximumActive, 1);
      session.dispose();
    });
  });

  testWidgets('canvas scale getter reports a superseded pre-commit read', (tester) async {
    await tester.runAsync(() async {
      final session = _Session();
      final olderRead = Completer<double>();
      session.preferences.read = (call) => call == 1 ? olderRead.future
          : Future.value(session.preferences.percent / 100.0);
      final canvas = session.canvasModel;
      final owner = canvas.captureUpdateOwner();
      final older = canvas.readCustomScalePercent(owner: owner);
      final refused = expectLater(older, throwsStateError);
      expect(await canvas.applyCustomScalePercent(225, owner: owner), 225);
      olderRead.complete(1.0);
      await refused;
      expect(await canvas.readCustomScalePercent(owner: owner), 225);
      session.dispose();
    });
  });
}

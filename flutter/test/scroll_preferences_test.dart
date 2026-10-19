import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/remote_toolbar.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Preferences implements CanvasPreferences {
  String? style = kRemoteScrollStyleAuto;
  int? thickness = 100;
  int styleReads = 0;
  int thicknessReads = 0;
  Future<String?> Function(int)? readStyle;
  Future<int?> Function(int)? readThickness;
  @override
  String? viewStyle(SessionID id) => kRemoteViewStyleOriginal;
  @override
  Future<double> customScale(SessionID id) async => 1.0;
  @override
  Future<String?> scrollStyle(SessionID id) {
    styleReads++;
    return readStyle?.call(styleReads) ?? Future.value(style);
  }
  @override
  Future<int?> edgeThickness(SessionID id) {
    thicknessReads++;
    return readThickness?.call(thicknessReads) ?? Future.value(thickness);
  }
}

class _Writer implements CanvasScrollPreferenceWriter {
  _Writer(this.preferences);
  final _Preferences preferences;
  final calls = <(String, Object)>[];
  Future<String> Function(String)? style;
  Future<int> Function(int)? thickness;
  @override
  Future<String> saveStyle(SessionID id, String value) async {
    calls.add(('style', value));
    final effective = await (style?.call(value) ?? Future.value(value));
    if (effective == value) preferences.style = value;
    return effective;
  }
  @override
  Future<int> saveThickness(SessionID id, int value) async {
    calls.add(('thickness', value));
    final effective = await (thickness?.call(value) ?? Future.value(value));
    if (effective == value) preferences.thickness = value;
    return effective;
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
  @override
  void refreshMousePos() {}
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
      preferences: preferences, scrollPreferenceWriter: writer);
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

Future<void> _controls(WidgetTester tester, {int value = 100,
    Future<int?> Function(int)? save, Key key = const ValueKey('thickness')}) =>
  tester.pumpWidget(MaterialApp(home: Scaffold(body: SizedBox(width: 360,
    child: EdgeThicknessControl(key: key, value: value, saveThickness: save,
      translateText: (text) => text)))));
Slider _slider(WidgetTester tester) => tester.widget<Slider>(find.byType(Slider));
Future<void> _flush(WidgetTester tester) async { await tester.pump(); await tester.pump(); }
Future<void> _debounce(WidgetTester tester) async {
  await tester.pump(const Duration(milliseconds: 301));
  await _flush(tester);
}
List<Object> _state(_Session s) => [s.canvasModel.scrollStyle,
  s.canvasModel.edgeScrollEdgeThickness, s.canvasModel.x, s.canvasModel.y,
  s.canvasModel.scale, s.canvasModel.scrollX, s.canvasModel.scrollY];

void main() {
  testWidgets('edge thickness owns a bounded draft without initial writes', (tester) async {
    final calls = <int>[];
    await _controls(tester, value: 999, save: (v) async { calls.add(v); return v; });
    expect(_slider(tester).value, 100);
    _slider(tester).onChanged!(double.nan);
    await _debounce(tester);
    expect(calls, isEmpty);
    _slider(tester).onChanged!(0);
    await _debounce(tester);
    _slider(tester).onChanged!(999);
    await _debounce(tester);
    expect(calls, [20, 150]);
    expect(_slider(tester).value, 150);
    await _controls(tester, value: 80);
    expect(_slider(tester).onChanged, isNull);
    expect(_slider(tester).value, 80);
  });

  testWidgets('edge thickness rebuild retains its draft and latest writer', (tester) async {
    final old = <int>[];
    final current = <int>[];
    await _controls(tester, save: (v) async { old.add(v); return v; });
    _slider(tester).onChanged!(80);
    await _controls(tester, save: (v) async { current.add(v); return v; });
    expect(_slider(tester).value, 80);
    await _debounce(tester);
    expect(old, isEmpty);
    expect(current, [80]);
    await _controls(tester, save: (v) async { current.add(v); return v; });
    expect(_slider(tester).value, 80);
    await _debounce(tester);
    expect(current, [80]);
  });

  testWidgets('edge thickness serializes writes and keeps only latest intent', (tester) async {
    final first = Completer<int?>();
    final calls = <int>[];
    Future<int?> save(int v) { calls.add(v); return calls.length == 1 ? first.future : Future.value(v); }
    await _controls(tester, save: save);
    _slider(tester).onChanged!(80);
    await _debounce(tester);
    _slider(tester).onChanged!(90);
    _slider(tester).onChanged!(100);
    await _debounce(tester);
    expect(calls, [80]);
    first.complete(80);
    await _flush(tester);
    expect(calls, [80, 100]);
    expect(_slider(tester).value, 100);
    expect(find.text('Retry'), findsNothing);
  });

  testWidgets('edge thickness refusal mismatch and null results retain retry', (tester) async {
    var calls = 0;
    await _controls(tester, save: (v) async {
      calls++;
      if (calls == 1) throw StateError('store failed');
      if (calls == 2) return v + 1;
      return calls == 3 ? null : v;
    });
    _slider(tester).onChanged!(80);
    await _debounce(tester);
    for (var i = 0; i < 3; i++) {
      expect(_slider(tester).value, 80);
      expect(find.text('Retry'), findsOneWidget);
      await tester.tap(find.byKey(const ValueKey('edge-thickness-retry')));
      await _flush(tester);
    }
    expect(calls, 4);
    expect(find.text('Retry'), findsNothing);
  });

  testWidgets('edge thickness removal cancels queued and captured edits', (tester) async {
    final calls = <int>[];
    await _controls(tester, save: (v) async { calls.add(v); return v; });
    final captured = _slider(tester).onChanged!;
    captured(80);
    await tester.pumpWidget(const SizedBox.shrink());
    captured(90);
    await _debounce(tester);
    expect(calls, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('edge thickness removed admitted work retires feedback', (tester) async {
    final pending = Completer<int?>();
    await _controls(tester, save: (_) => pending.future);
    _slider(tester).onChanged!(80);
    await _debounce(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    pending.completeError(StateError('retired storage failure'));
    await _flush(tester);
    expect(tester.takeException(), isNull);
  });

  testWidgets('edge thickness disable and reenable retire old callbacks', (tester) async {
    final pending = Completer<int?>();
    final calls = <int>[];
    await _controls(tester, save: (_) => pending.future);
    final captured = _slider(tester).onChanged!;
    captured(80);
    await _debounce(tester);
    await _controls(tester, value: 90);
    await _controls(tester, value: 90, save: (v) async { calls.add(v); return v; });
    captured(70);
    _slider(tester).onChanged!(110);
    await _debounce(tester);
    expect(calls, isEmpty);
    pending.completeError(StateError('old write failed'));
    await _flush(tester);
    expect(calls, [110]);
    expect(_slider(tester).value, 110);
    expect(find.text('Retry'), findsNothing);
  });

  testWidgets('edge thickness replacement owner cannot receive old completion', (tester) async {
    final pending = Completer<int?>();
    await _controls(tester, save: (_) => pending.future);
    _slider(tester).onChanged!(80);
    await _debounce(tester);
    final calls = <int>[];
    await _controls(tester, key: const ValueKey('new-owner'), value: 120,
        save: (v) async { calls.add(v); return v; });
    pending.complete(80);
    await _flush(tester);
    expect(_slider(tester).value, 120);
    expect(calls, isEmpty);
  });

  testWidgets('edge thickness external values do not replace pending edits', (tester) async {
    final pending = Completer<int?>();
    final calls = <int>[];
    Future<int?> save(int v) { calls.add(v); return calls.length == 1 ? pending.future : Future.value(v); }
    await _controls(tester, save: save);
    _slider(tester).onChanged!(80);
    await _debounce(tester);
    _slider(tester).onChanged!(90);
    await _controls(tester, value: 70, save: save);
    expect(_slider(tester).value, 90);
    await _debounce(tester);
    pending.complete(80);
    await _flush(tester);
    expect(calls, [80, 90]);
    await _controls(tester, value: 60, save: save);
    expect(_slider(tester).value, 60);
  });

  test('scroll style selection joins the checked canvas operation', () async {
    final pending = Completer<String>();
    var finished = false;
    final calls = <String>[];
    final choosing = selectSessionScrollStyle(kRemoteScrollStyleEdge,
        applyStyle: (v) { calls.add(v); return pending.future; }, isCurrent: () => true,
        showFailure: () => fail('valid scroll choice failed'))
        .then((value) { finished = true; return value; });
    await Future<void>.delayed(Duration.zero);
    expect(calls, [kRemoteScrollStyleEdge]);
    expect(finished, isFalse);
    pending.complete(kRemoteScrollStyleEdge);
    expect(await choosing, isTrue);
  });

  test('scroll style refusal mismatch and invalid choices remain explicit', () async {
    var calls = 0;
    var failures = 0;
    Future<bool> choose(String? value) => selectSessionScrollStyle(value,
        applyStyle: (v) async {
          calls++;
          if (calls == 1) throw StateError('save failed');
          return calls == 2 ? kRemoteScrollStyleAuto : v;
        }, isCurrent: () => true, showFailure: () => failures++);
    expect(await choose(kRemoteScrollStyleEdge), isFalse);
    expect(await choose(kRemoteScrollStyleEdge), isFalse);
    expect(await choose(kRemoteScrollStyleEdge), isTrue);
    for (final value in ['', 'bad', kRemoteViewStyleOriginal]) {
      expect(await choose(value), isFalse);
    }
    expect(await choose(null), isFalse);
    expect(calls, 3);
    expect(failures, 5);
  });

  test('scroll style retirement blocks admission and late feedback', () async {
    var current = false;
    var calls = 0;
    var failures = 0;
    final pending = Completer<String>();
    Future<bool> choose() => selectSessionScrollStyle(kRemoteScrollStyleBar,
        applyStyle: (_) { calls++; return pending.future; }, isCurrent: () => current,
        showFailure: () => failures++);
    expect(await choose(), isFalse);
    current = true;
    final choosing = choose();
    current = false;
    pending.completeError(StateError('retired result'));
    expect(await choosing, isFalse);
    expect(calls, 1);
    expect(failures, 0);
  });

  testWidgets('canvas scrolling saves share admission through publication', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final read = Completer<String?>();
      s.preferences.readStyle = (_) => read.future;
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final saving = c.applyScrollStyle(kRemoteScrollStyleBar, owner: owner);
      await Future<void>.delayed(Duration.zero);
      expect(c.scrollPreferenceSavePending, isTrue);
      await expectLater(c.applyEdgeScrollEdgeThickness(80, owner: owner), throwsStateError);
      await expectLater(c.applyScrollStyle(kRemoteScrollStyleEdge, owner: owner), throwsStateError);
      expect(s.writer.calls, [('style', kRemoteScrollStyleBar)]);
      read.complete(kRemoteScrollStyleBar);
      expect(await saving, kRemoteScrollStyleBar);
      expect(c.scrollStyle, ScrollStyle.scrollbar);
      expect(await c.applyEdgeScrollEdgeThickness(80, owner: owner), 80);
      expect(c.edgeScrollEdgeThickness, 80);
      expect(c.scrollPreferenceSavePending, isFalse);
      s.dispose();
    });
  });

  testWidgets('canvas scrolling failed saves preserve state and permit retry', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final before = _state(s);
      await expectLater(c.applyScrollStyle('bad', owner: owner), throwsArgumentError);
      await expectLater(c.applyEdgeScrollEdgeThickness(19, owner: owner), throwsArgumentError);
      await expectLater(c.applyEdgeScrollEdgeThickness(151, owner: owner), throwsArgumentError);
      await expectLater(c.applyScrollStyle(kRemoteScrollStyleBar, owner: null), throwsStateError);
      expect(s.writer.calls, isEmpty);
      s.writer.style = (_) => Future.error(StateError('denied'));
      s.writer.thickness = (_) async => 81;
      await expectLater(c.applyScrollStyle(kRemoteScrollStyleBar, owner: owner), throwsStateError);
      await expectLater(c.applyEdgeScrollEdgeThickness(80, owner: owner), throwsStateError);
      expect(_state(s), before);
      s.writer.style = null;
      s.writer.thickness = null;
      expect(await c.applyScrollStyle(kRemoteScrollStyleBar, owner: owner), kRemoteScrollStyleBar);
      expect(await c.applyEdgeScrollEdgeThickness(80, owner: owner), 80);
      s.dispose();
    });
  });

  testWidgets('canvas retired scroll owner suppresses viewport effects', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final pending = Completer<int>();
      s.writer.thickness = (_) => pending.future;
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final saving = c.applyEdgeScrollEdgeThickness(80, owner: owner);
      s.imageModel.retirePresentation();
      final before = _state(s);
      pending.complete(80);
      expect(await saving, 80);
      expect(_state(s), before);
      expect(s.preferences.thickness, 80);
      await expectLater(c.applyScrollStyle(kRemoteScrollStyleBar, owner: owner), throwsStateError);
      expect((await c.readScrollPreferences(owner: c.captureUpdateOwner())).thickness, 80);
      s.dispose();
    });
  });

  testWidgets('canvas clear keeps admitted scrolling work owned until completion', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final pending = Completer<String>();
      s.writer.style = (_) => pending.future;
      final c = s.canvasModel;
      final saving = c.applyScrollStyle(kRemoteScrollStyleBar, owner: c.captureUpdateOwner());
      c.clear();
      final owner = c.captureUpdateOwner();
      await expectLater(c.applyEdgeScrollEdgeThickness(80, owner: owner), throwsStateError);
      pending.complete(kRemoteScrollStyleBar);
      expect(await saving, kRemoteScrollStyleBar);
      expect(c.scrollStyle, ScrollStyle.scrollauto);
      expect(await c.applyEdgeScrollEdgeThickness(80, owner: owner), 80);
      s.dispose();
    });
  });

  testWidgets('canvas disposal joins accepted scroll save without notification', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final pending = Completer<int>();
      s.writer.thickness = (_) => pending.future;
      final c = s.canvasModel;
      var notifications = 0;
      c.addListener(() => notifications++);
      final saving = c.applyEdgeScrollEdgeThickness(80, owner: c.captureUpdateOwner());
      c.dispose();
      pending.complete(80);
      expect(await saving, 80);
      expect(notifications, 0);
      expect(c.scrollPreferenceSavePending, isFalse);
      s.imageModel.dispose();
      s.cursorModel.dispose();
    });
  });

  testWidgets('canvas scroll commit retires older style initialization', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final old = Completer<String?>();
      s.preferences.readStyle = (call) => call == 1 ? old.future : Future.value(s.preferences.style);
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final initializing = c.updateScrollStyle(owner: owner);
      expect(await c.applyScrollStyle(kRemoteScrollStyleBar, owner: owner), kRemoteScrollStyleBar);
      old.complete(kRemoteScrollStyleAuto);
      expect(await initializing, isFalse);
      expect(c.scrollStyle, ScrollStyle.scrollbar);
      s.dispose();
    });
  });

  testWidgets('canvas thickness commit retires older thickness initialization', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final old = Completer<int?>();
      s.preferences.readThickness = (_) => old.future;
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final initializing = c.initializeEdgeScrollEdgeThickness(owner: owner);
      expect(await c.applyEdgeScrollEdgeThickness(80, owner: owner), 80);
      old.complete(100);
      expect(await initializing, isFalse);
      expect(c.edgeScrollEdgeThickness, 80);
      s.dispose();
    });
  });

  testWidgets('canvas ready scroll initializers remain useful without commits', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final first = Completer<String?>();
      final second = Completer<String?>();
      s.preferences.readStyle = (call) => call == 1 ? first.future : second.future;
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final earlier = c.updateScrollStyle(owner: owner);
      final later = c.updateScrollStyle(owner: owner);
      second.complete(kRemoteScrollStyleBar);
      expect(await later, isTrue);
      first.complete(kRemoteScrollStyleBar);
      expect(await earlier, isTrue);
      expect(s.writer.calls, isEmpty);
      s.dispose();
    });
  });

  testWidgets('canvas scroll reads reject invalid values and retired snapshots', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final before = _state(s);
      final valid = await c.readScrollPreferences(owner: owner);
      expect(valid, (style: kRemoteScrollStyleAuto, thickness: 100));
      for (final value in [null, '', 'bad']) {
        s.preferences.style = value;
        await expectLater(c.readScrollPreferences(owner: owner),
            value == null ? throwsStateError : throwsArgumentError);
      }
      s.preferences.style = kRemoteScrollStyleAuto;
      for (final value in [null, 19, 151]) {
        s.preferences.thickness = value;
        expect(await c.initializeEdgeScrollEdgeThickness(owner: owner), isFalse);
        await expectLater(c.readScrollPreferences(owner: owner), throwsStateError);
      }
      expect(_state(s), before);
      final old = Completer<String?>();
      s.preferences.readStyle = (_) => old.future;
      final reading = c.readScrollPreferences(owner: owner);
      final refusal = expectLater(reading, throwsStateError);
      final reads = s.preferences.thicknessReads;
      s.current = false;
      old.complete(kRemoteScrollStyleAuto);
      await refusal;
      expect(s.preferences.thicknessReads, reads);
      s.dispose();
    });
  });

  testWidgets('canvas scroll snapshot is retired by a committed thickness change', (tester) async {
    await tester.runAsync(() async {
      final s = _Session();
      final old = Completer<int?>();
      s.preferences.readThickness = (_) => old.future;
      final c = s.canvasModel;
      final owner = c.captureUpdateOwner();
      final reading = c.readScrollPreferences(owner: owner);
      final refusal = expectLater(reading, throwsStateError);
      await Future<void>.delayed(Duration.zero);
      expect(s.preferences.thicknessReads, 1);
      expect(await c.applyEdgeScrollEdgeThickness(80, owner: owner), 80);
      old.complete(100);
      await refusal;
      expect(c.edgeScrollEdgeThickness, 80);
      s.dispose();
    });
  });
}

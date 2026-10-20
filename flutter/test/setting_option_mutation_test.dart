import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/audio_input.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, Object> _audioDevices(String current,
        {List<String> devices = const ['Mic A', 'Mic B', 'Mic C']}) =>
    {'devices': devices, 'current': current};

Widget _audioControls(AudioInputDeviceLoader load,
        {AudioInputDeviceWriter? write,
        bool isCm = false,
        double width = 360,
        ValueChanged<AudioINputSetDevice>? capture}) =>
    MaterialApp(
      home: Scaffold(
        body: SizedBox(
          width: width,
          child: AudioInput(
            isCm: isCm,
            isVoiceCall: true,
            loadDevicesInfo: load,
            writeDevice: write,
            failureText: 'Audio load failed',
            retryText: 'Retry',
            builder: (devices, current, select) {
              capture?.call(select);
              return Column(mainAxisSize: MainAxisSize.min, children: [
                Text('device:$current'),
                TextButton(
                    onPressed: () => select('Mic B'),
                    child: const Text('Choose Mic B')),
              ]);
            },
          ),
        ),
      ),
    );

Future<void> _trackpad(WidgetTester tester, {
  int value = 100,
  SimpleWrapper<int>? draft,
  bool enabled = true,
  Key fieldKey = const ValueKey('trackpad'),
  required Future<int?> Function(int)? save,
}) => tester.pumpWidget(MaterialApp(
  home: Scaffold(body: SizedBox(width: 360, child: TrackpadSpeedWidget(
    key: fieldKey,
    value: draft ?? SimpleWrapper(value),
    enabled: enabled,
    translateText: (text) => text,
    saveSpeed: enabled ? save : null,
  ))),
));

TextEditingController _trackpadController(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).controller!;

Future<void> _slideTrackpad(WidgetTester tester, int value) async {
  tester.widget<Slider>(find.byType(Slider)).onChanged!(value.toDouble());
  await tester.pump();
}

Future<void> _qualityEditor(WidgetTester tester, {
  double quality = 50,
  double fps = 30,
  Future<double?> Function(double)? saveQuality,
  Future<double?> Function(double)? saveFps,
  bool showFps = true,
  bool mobile = false,
  Key editorKey = const ValueKey('quality'),
  VoidCallback? onClose,
}) => tester.pumpWidget(MaterialApp(
  home: Scaffold(body: SizedBox(width: 360, child: CustomImageQualityWidget(
    key: editorKey,
    initQuality: quality, initFps: fps,
    saveQuality: saveQuality, saveFps: saveFps,
    showFps: showFps, showMoreQuality: true,
    translateText: (text) => text, mobileLayout: mobile, onClose: onClose,
  ))),
));

Slider _qualitySlider(WidgetTester tester, int index) =>
    tester.widget<Slider>(find.byType(Slider).at(index));

Future<void> _slideQuality(WidgetTester tester, int index, double value) async {
  _qualitySlider(tester, index).onChanged!(value);
  await tester.pump();
}

Widget _combo(Map<String, String> options, String selected,
        ValueChanged<String> onChanged, {bool enabled = true}) =>
    ComboBox(keys: options.keys.toList(), values: options.values.toList(),
        initialKey: selected, onChanged: onChanged, enabled: enabled);

Widget _comboPage(Map<String, String> options, String selected,
        ValueChanged<String> onChanged, {bool enabled = true}) =>
    MaterialApp(theme: MyTheme.lightTheme, home: Scaffold(body: SizedBox(width: 320,
        child: _combo(options, selected, onChanged, enabled: enabled))));

DropdownButton<String> _comboButton(WidgetTester tester) =>
    tester.widget<DropdownButton<String>>(find.byType(DropdownButton<String>));

void main() {
  testWidgets('combo uses keys independently of display labels', (tester) async {
    final requests = <String>[];
    await tester.pumpWidget(_comboPage(
        {'a': 'First label', 'b': 'Second label'}, 'a', requests.add));
    expect(_comboButton(tester).value, 'a');
    expect(_comboButton(tester).items!.map((item) => item.value), ['a', 'b']);
    await tester.tap(find.byType(DropdownButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.byWidgetPredicate(
        (widget) => widget is DropdownMenuItem<String> && widget.value == 'b').last);
    await tester.pumpAndSettle();
    expect(requests, ['b']);
    expect(_comboButton(tester).value, 'a');
  });

  testWidgets('combo duplicate labels preserve distinct selection identities', (tester) async {
    final requests = <String>[];
    await tester.pumpWidget(_comboPage(
        {'a': 'Shared label', 'b': 'Shared label'}, 'a', requests.add));
    expect(tester.takeException(), isNull);
    await tester.tap(find.byType(DropdownButton<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.byWidgetPredicate(
        (widget) => widget is DropdownMenuItem<String> && widget.value == 'b').last);
    await tester.pumpAndSettle();
    expect(requests, ['b']);
    expect(_comboButton(tester).value, 'a');
  });

  testWidgets('combo pending and failed changes retain the confirmed selection', (tester) async {
    var selected = 'A';
    var failures = 0;
    final requests = <String>[];
    var completion = Completer<String>();
    Future<void>? pending;
    await tester.pumpWidget(MaterialApp(theme: MyTheme.lightTheme, home: Scaffold(body: SizedBox(width: 320,
        child: StatefulBuilder(builder: (context, update) {
          return _combo({'A': 'A', 'B': 'B'}, selected, (requested) {
            requests.add(requested);
            pending = completion.future.then<void>((effective) {
              update(() => selected = effective);
            }, onError: (Object error, StackTrace stack) {
              failures++;
            });
          });
        })))));
    _comboButton(tester).onChanged!('B');
    await tester.pump();
    final whilePending = _comboButton(tester).value;
    completion.completeError(StateError('store refused'));
    await pending;
    await tester.pump();
    final afterFailure = _comboButton(tester).value;
    completion = Completer<String>();
    _comboButton(tester).onChanged!('B');
    await tester.pump();
    final duringRetry = _comboButton(tester).value;
    completion.complete('B');
    await pending;
    await tester.pump();
    expect(requests, ['B', 'B']);
    expect(failures, 1);
    expect([whilePending, afterFailure, duringRetry], ['A', 'A', 'A']);
    expect(_comboButton(tester).value, 'B');
  });

  testWidgets('combo refreshed confirmed value replaces the displayed selection', (tester) async {
    final requests = <String>[];
    const options = {'A': 'A', 'B': 'B', 'C': 'C'};
    await tester.pumpWidget(_comboPage(options, 'A', requests.add));
    await tester.pumpWidget(_comboPage(options, 'C', requests.add));
    expect(_comboButton(tester).value, 'C');
    expect(requests, isEmpty);
  });

  testWidgets('combo empty options disable selection without inventing a value', (tester) async {
    final requests = <String>[];
    await tester.pumpWidget(_comboPage({}, '', requests.add));
    expect(tester.takeException(), isNull);
    expect(_comboButton(tester).value, isNull);
    expect(_comboButton(tester).items, isEmpty);
    expect(_comboButton(tester).onChanged, isNull);
    expect(requests, isEmpty);
  });

  testWidgets('combo unavailable selection stays visible without choosing another key', (tester) async {
    final requests = <String>[];
    await tester.pumpWidget(_comboPage(
        {'A': 'Available A', 'B': 'Available B'}, 'Unplugged microphone', requests.add));
    expect(_comboButton(tester).value, isNull);
    expect(find.text('Unplugged microphone'), findsOneWidget);
    expect(requests, isEmpty);
  });

  testWidgets('combo disabled and unchanged choices dispatch nothing', (tester) async {
    final requests = <String>[];
    const options = {'A': 'A', 'B': 'B'};
    await tester.pumpWidget(_comboPage(options, 'A', requests.add, enabled: false));
    expect(_comboButton(tester).onChanged, isNull);
    await tester.pumpWidget(_comboPage(options, 'A', requests.add));
    _comboButton(tester).onChanged!(null);
    _comboButton(tester).onChanged!('A');
    await tester.pump();
    expect(requests, isEmpty);
    expect(_comboButton(tester).value, 'A');
  });

  testWidgets('combo label refresh preserves its selected identity', (tester) async {
    final requests = <String>[];
    await tester.pumpWidget(_comboPage({'a': 'English label'}, 'a', requests.add));
    await tester.pumpWidget(_comboPage({'a': 'Translated label'}, 'a', requests.add));
    expect(_comboButton(tester).value, 'a');
    expect(find.text('Translated label'), findsOneWidget);
    expect(requests, isEmpty);
  });
  test('view style choice joins persistence before canvas publication', () async {
    final pending = Completer<String>();
    final canvas = Completer<bool>();
    final writes = <String>[];
    var updates = 0;
    var finished = false;
    final choosing = selectSessionViewStyle('adaptive',
        saveStyle: (value) { writes.add(value); return pending.future; },
        updateCanvas: () { updates++; return canvas.future; }, isCurrent: () => true,
        showFailure: () => fail('successful view style reported failure'))
        .then((result) { finished = true; return result; });
    await Future<void>.delayed(Duration.zero);
    expect(writes, ['adaptive']);
    expect(updates, 0);
    expect(finished, isFalse);
    pending.complete('adaptive');
    await Future<void>.delayed(Duration.zero);
    expect(updates, 1);
    expect(finished, isFalse);
    canvas.complete(true);
    expect(await choosing, isTrue);
  });

  test('view style refusal and mismatch leave the canvas and preserve retry', () async {
    for (final synchronous in [false, true]) {
      var calls = 0;
      var updates = 0;
      var failures = 0;
      Future<String> write(String value) {
        calls++;
        if (calls == 1) {
          if (synchronous) throw StateError('store failed');
          return Future.error(StateError('store failed'));
        }
        return Future.value(calls == 2 ? 'original' : value);
      }
      Future<bool> choose() => selectSessionViewStyle('custom',
          saveStyle: write, updateCanvas: () async { updates++; return true; },
          isCurrent: () => true, showFailure: () => failures++);
      expect(await choose(), isFalse);
      expect(await choose(), isFalse);
      expect(updates, 0);
      expect(await choose(), isTrue);
      expect(updates, 1);
      expect(failures, 2);
    }
  });

  test('view style canvas refusal and failure remain visible and retryable', () async {
    var updates = 0;
    var failures = 0;
    Future<bool> choose() => selectSessionViewStyle('original',
        saveStyle: (value) async => value,
        updateCanvas: () async {
          updates++;
          if (updates == 1) return false;
          if (updates == 2) throw StateError('canvas failed');
          return true;
        }, isCurrent: () => true, showFailure: () => failures++);
    expect(await choose(), isFalse);
    expect(await choose(), isFalse);
    expect(await choose(), isTrue);
    expect(updates, 3);
    expect(failures, 2);
  });

  test('view style owner retirement blocks writes and late canvas effects', () async {
    var current = false;
    var writes = 0;
    var updates = 0;
    var failures = 0;
    final pending = Completer<String>();
    Future<bool> choose() => selectSessionViewStyle('adaptive',
        saveStyle: (_) { writes++; return pending.future; },
        updateCanvas: () async { updates++; return true; },
        isCurrent: () => current, showFailure: () => failures++);
    expect(await choose(), isFalse);
    expect(writes, 0);
    current = true;
    final admitted = choose();
    current = false;
    pending.complete('adaptive');
    expect(await admitted, isFalse);
    expect(writes, 1);
    expect(updates, 0);
    expect(failures, 0);
  });

  test('view style retired canvas completion cannot publish failure feedback', () async {
    var current = true;
    var failures = 0;
    final pending = Completer<bool>();
    final choosing = selectSessionViewStyle('custom',
        saveStyle: (value) async => value, updateCanvas: () => pending.future,
        isCurrent: () => current, showFailure: () => failures++);
    await Future<void>.delayed(Duration.zero);
    current = false;
    pending.completeError(StateError('retired canvas failed'));
    expect(await choosing, isFalse);
    expect(failures, 0);
  });

  test('view style selection admits only the three named styles', () async {
    final writes = <String>[];
    var failures = 0;
    Future<bool> choose(String? value) => selectSessionViewStyle(value,
        saveStyle: (value) async { writes.add(value); return value; },
        updateCanvas: () async => true, isCurrent: () => true,
        showFailure: () => failures++);
    for (final value in ['original', 'adaptive', 'custom']) {
      expect(await choose(value), isTrue);
    }
    expect(await choose(null), isFalse);
    expect(await choose('unknown'), isFalse);
    expect(writes, ['original', 'adaptive', 'custom']);
    expect(failures, 1);
  });

  test('image preset choice awaits the effective native acknowledgement', () async {
    final pending = Completer<String>();
    final writes = <String>[];
    var custom = 0;
    var finished = false;
    final choosing = selectSessionImageQuality('best',
        savePreset: (value) { writes.add(value); return pending.future; },
        editCustom: () async { custom++; }, isCurrent: () => true,
        showFailure: () => fail('successful preset reported failure'))
        .then((result) { finished = true; return result; });
    await Future<void>.delayed(Duration.zero);
    expect(writes, ['best']);
    expect(finished, isFalse);
    expect(custom, 0);
    pending.complete('best');
    expect(await choosing, isTrue);
  });

  test('image Custom choice stages its editor without a preset write', () async {
    final pending = Completer<void>();
    var edits = 0;
    var writes = 0;
    var finished = false;
    final choosing = selectSessionImageQuality('custom',
        savePreset: (value) async { writes++; return value; },
        editCustom: () { edits++; return pending.future; }, isCurrent: () => true,
        showFailure: () => fail('successful custom editor reported failure'))
        .then((result) { finished = true; return result; });
    await Future<void>.delayed(Duration.zero);
    expect(edits, 1);
    expect(writes, 0);
    expect(finished, isFalse);
    pending.complete();
    expect(await choosing, isTrue);
    expect(writes, 0);
  });

  test('image preset errors and mismatched replies preserve retry', () async {
    for (final synchronous in [false, true]) {
      var calls = 0;
      var failures = 0;
      Future<String> write(String value) {
        calls++;
        if (calls == 1) {
          if (synchronous) throw StateError('store failed');
          return Future.error(StateError('store failed'));
        }
        return Future.value(calls == 2 ? 'low' : value);
      }
      Future<bool> choose() => selectSessionImageQuality('best',
          savePreset: write, editCustom: () async => fail('unexpected editor'),
          isCurrent: () => true, showFailure: () => failures++);
      expect(await choose(), isFalse);
      expect(await choose(), isFalse);
      expect(await choose(), isTrue);
      expect(calls, 3);
      expect(failures, 2);
    }
  });

  test('image choice retirement blocks admission and late feedback', () async {
    var current = false;
    var writes = 0;
    var edits = 0;
    var failures = 0;
    final pending = Completer<String>();
    Future<bool> choose(String value) => selectSessionImageQuality(value,
        savePreset: (_) { writes++; return pending.future; },
        editCustom: () async { edits++; }, isCurrent: () => current,
        showFailure: () => failures++);
    expect(await choose('best'), isFalse);
    expect(await choose('custom'), isFalse);
    expect(writes, 0);
    expect(edits, 0);
    current = true;
    final admitted = choose('best');
    current = false;
    pending.completeError(StateError('late store failed'));
    expect(await admitted, isFalse);
    expect(writes, 1);
    expect(failures, 0);
    expect(await choose('best'), isFalse);
    expect(writes, 1);
  });

  test('image Custom errors and retirement never write a marker', () async {
    var current = true;
    var writes = 0;
    var failures = 0;
    final pending = Completer<void>();
    Future<bool> choose(Future<void> Function() edit) => selectSessionImageQuality('custom',
        savePreset: (value) async { writes++; return value; }, editCustom: edit,
        isCurrent: () => current, showFailure: () => failures++);
    expect(await choose(() => throw StateError('editor failed')), isFalse);
    expect(failures, 1);
    final retired = choose(() => pending.future);
    current = false;
    pending.completeError(StateError('retired editor failed'));
    expect(await retired, isFalse);
    expect(failures, 1);
    expect(writes, 0);
  });

  test('image preset selection admits only the three named presets', () async {
    final writes = <String>[];
    var failures = 0;
    Future<bool> choose(String? value) => selectSessionImageQuality(value,
        savePreset: (value) async { writes.add(value); return value; },
        editCustom: () async => fail('unexpected custom editor'),
        isCurrent: () => true, showFailure: () => failures++);
    for (final value in ['low', 'balanced', 'best']) {
      expect(await choose(value), isTrue);
    }
    expect(await choose(null), isFalse);
    expect(await choose('unknown'), isFalse);
    expect(writes, ['low', 'balanced', 'best']);
    expect(failures, 1);
  });

  testWidgets('quality editor Close waits for an admitted hidden FPS save', (tester) async {
    final pending = Completer<double?>();
    var closes = 0;
    Future<double?> saveFps(double value) => pending.future;
    await _qualityEditor(tester,
      saveQuality: (v) async => v, saveFps: saveFps, onClose: () { closes++; });
    await _slideQuality(tester, 1, 40);
    await tester.pump(const Duration(seconds: 1));
    await _qualityEditor(tester, showFps: false,
      saveQuality: (v) async => v, saveFps: saveFps, onClose: () { closes++; });
    await tester.tap(find.text('Close'));
    await tester.pump();
    expect(closes, 0);
    pending.complete(40);
    await tester.pump();
    expect(closes, 1);
  });

  testWidgets('quality dialog editing initializes its counterpart without losing a draft', (tester) async {
    for (final editFps in [false, true]) {
      final quality = <double>[];
      final fps = <double>[];
      await _qualityEditor(tester,
        editorKey: ValueKey(editFps),
        saveQuality: (v) async { quality.add(v); return v; },
        saveFps: (v) async { fps.add(v); return v; }, onClose: () {});
      await _slideQuality(tester, 0, 80);
      if (editFps) await _slideQuality(tester, 1, 40);
      await tester.pump(const Duration(seconds: 1));
      expect(quality, [80]);
      expect(fps, [editFps ? 40 : 30]);
      await _slideQuality(tester, 0, 90);
      await tester.pump(const Duration(seconds: 1));
      expect(quality, [80, 90]);
      expect(fps, [editFps ? 40 : 30]);
    }
  });

  testWidgets('quality editor Close flushes latest edits and waits for both fields', (tester) async {
    final pending = Completer<double?>();
    final quality = <double>[];
    final fps = <double>[];
    var closes = 0;
    await _qualityEditor(tester,
      saveQuality: (v) { quality.add(v); return quality.length == 1 ? pending.future : Future.value(v); },
      saveFps: (v) async { fps.add(v); return v; },
      onClose: () { closes++; });
    await _slideQuality(tester, 0, 80);
    await tester.pump(const Duration(seconds: 1));
    await _slideQuality(tester, 0, 90);
    final close = tester.widget<TextButton>(find.widgetWithText(TextButton, 'Close')).onPressed!;
    close(); close();
    await tester.pump();
    expect(quality, [80]);
    expect(fps, [30]);
    expect(closes, 0);
    expect(_qualitySlider(tester, 0).onChanged, isNull);
    pending.complete(80);
    await tester.pump();
    expect(quality, [80, 90]);
    expect(closes, 1);
  });

  testWidgets('quality editor Close failure stays open for explicit retry', (tester) async {
    var writes = 0;
    var closes = 0;
    await _qualityEditor(tester,
      saveQuality: (v) async => ++writes == 1 ? null : v,
      saveFps: (v) async => v, onClose: () { closes++; });
    await tester.tap(find.text('Close'));
    await tester.pump();
    expect(closes, 0);
    expect(find.text('Failed'), findsOneWidget);
    await tester.tap(find.text('Retry'));
    await tester.pump();
    expect(find.text('Failed'), findsNothing);
    await tester.tap(find.text('Close'));
    await tester.pump();
    expect(writes, 2);
    expect(closes, 1);
  });

  testWidgets('quality editor retired Close cannot close a replacement', (tester) async {
    final quality = Completer<double?>();
    final fps = Completer<double?>();
    var closes = 0;
    await _qualityEditor(tester,
      saveQuality: (_) => quality.future, saveFps: (_) => fps.future,
      onClose: () { closes++; });
    await tester.tap(find.text('Close'));
    await tester.pump();
    await _qualityEditor(tester, quality: 60, fps: 40,
      editorKey: const ValueKey('replacement'), saveQuality: (v) async => v);
    quality.completeError(StateError('retired quality close'));
    fps.completeError(StateError('retired FPS close'));
    await tester.pump();
    expect(closes, 0);
    expect(_qualitySlider(tester, 0).value, 60);
    expect(tester.takeException(), isNull);
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('quality editor refuses nonfinite and out of range effective values', (tester) async {
    var qualityWrites = 0;
    var fpsWrites = 0;
    await _qualityEditor(tester,
      saveQuality: (v) async => ++qualityWrites == 1 ? double.nan : v,
      saveFps: (v) async => ++fpsWrites == 1 ? 1000.0 : v);
    await _slideQuality(tester, 0, 80);
    await _slideQuality(tester, 1, 40);
    await tester.pump(const Duration(seconds: 1));
    expect(find.text('Failed'), findsNWidgets(2));
    await tester.tap(find.text('Retry').first);
    await tester.pump();
    await tester.tap(find.text('Retry'));
    await tester.pump();
    expect(find.text('Failed'), findsNothing);
    expect(qualityWrites, 2);
    expect(fpsWrites, 2);
  });

  testWidgets('quality editor retains drafts and current writers across rebuild', (tester) async {
    final oldCalls = <double>[];
    final newCalls = <double>[];
    await _qualityEditor(tester,
      saveQuality: (v) async { oldCalls.add(v); return v; },
      saveFps: (v) async { oldCalls.add(v); return v; });
    await _slideQuality(tester, 0, 80);
    await _slideQuality(tester, 1, 40);
    await tester.pump(const Duration(milliseconds: 500));
    await _qualityEditor(tester,
      saveQuality: (v) async { newCalls.add(v); return v; },
      saveFps: (v) async { newCalls.add(v); return v; });
    expect(_qualitySlider(tester, 0).value, 80);
    expect(_qualitySlider(tester, 1).value, 40);
    await tester.pump(const Duration(milliseconds: 500));
    expect(oldCalls, isEmpty);
    expect(newCalls, [80, 40]);
  });

  testWidgets('quality editor removal retires timers and captured edits', (tester) async {
    final calls = <double>[];
    Future<double?> save(double v) async { calls.add(v); return v; }
    await _qualityEditor(tester, saveQuality: save, saveFps: save);
    final quality = _qualitySlider(tester, 0).onChanged!;
    final fps = _qualitySlider(tester, 1).onChanged!;
    final more = tester.widget<Checkbox>(find.byType(Checkbox)).onChanged!;
    await _slideQuality(tester, 0, 80);
    await _slideQuality(tester, 1, 40);
    await tester.pumpWidget(const SizedBox.shrink());
    quality(90); fps(50); more(true);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('quality editor serializes a field and preserves independent FPS', (tester) async {
    final pending = Completer<double?>();
    final quality = <double>[];
    final fps = <double>[];
    await _qualityEditor(tester,
      saveQuality: (v) { quality.add(v); return quality.length == 1 ? pending.future : Future.value(v); },
      saveFps: (v) async { fps.add(v); return v; });
    await _slideQuality(tester, 0, 80);
    await tester.pump(const Duration(seconds: 1));
    await _slideQuality(tester, 0, 90);
    await _slideQuality(tester, 1, 40);
    await tester.pump(const Duration(milliseconds: 500));
    await _slideQuality(tester, 0, 100);
    await tester.pump(const Duration(seconds: 1));
    expect(quality, [80]);
    expect(fps, [40]);
    pending.complete(80);
    await tester.pump();
    expect(quality, [80, 100]);
    expect(_qualitySlider(tester, 0).value, 100);
  });

  testWidgets('quality editor failures stay visible and permit identical retry', (tester) async {
    final calls = <double>[];
    await _qualityEditor(tester, saveQuality: (v) {
      calls.add(v);
      switch (calls.length) {
        case 1: throw StateError('sync quality failure');
        case 2: return Future.error(StateError('async quality failure'));
        case 3: return Future.value(null);
        default: return Future.value(v);
      }
    });
    await _slideQuality(tester, 0, 80);
    await tester.pump(const Duration(seconds: 1));
    for (var i = 0; i < 3; i++) {
      expect(find.text('Failed'), findsOneWidget);
      expect(_qualitySlider(tester, 0).value, 80);
      await tester.tap(find.text('Retry'));
      await tester.pump();
    }
    expect(calls, [80, 80, 80, 80]);
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('quality editor uses confirmed effective quality and FPS', (tester) async {
    await _qualityEditor(tester,
      saveQuality: (_) async => 75, saveFps: (_) async => 45);
    await _slideQuality(tester, 0, 80);
    await _slideQuality(tester, 1, 50);
    await tester.pump(const Duration(seconds: 1));
    expect(_qualitySlider(tester, 0).value, 75);
    expect(_qualitySlider(tester, 1).value, 45);
  });

  testWidgets('quality editor fixed quality disables its More control', (tester) async {
    await _qualityEditor(tester, saveFps: (v) async => v);
    expect(_qualitySlider(tester, 0).onChanged, isNull);
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).onChanged, isNull);
    expect(_qualitySlider(tester, 1).onChanged, isNotNull);
  });

  testWidgets('quality editor hiding FPS cancels its queued save', (tester) async {
    final calls = <double>[];
    Future<double?> save(double v) async { calls.add(v); return v; }
    await _qualityEditor(tester, saveQuality: save, saveFps: save);
    await _slideQuality(tester, 1, 40);
    await _qualityEditor(tester, showFps: false, saveQuality: save, saveFps: save);
    await tester.pump(const Duration(seconds: 1));
    expect(find.byType(Slider), findsOneWidget);
    expect(calls, isEmpty);
  });

  testWidgets('quality editor replacement ignores retired callbacks and errors', (tester) async {
    final pending = Completer<double?>();
    final calls = <double>[];
    await _qualityEditor(tester, saveQuality: (v) { calls.add(v); return pending.future; });
    final oldEdit = _qualitySlider(tester, 0).onChanged!;
    await _slideQuality(tester, 0, 80);
    await tester.pump(const Duration(seconds: 1));
    await _qualityEditor(tester, quality: 60,
      editorKey: const ValueKey('replacement'), saveQuality: (v) async => v);
    oldEdit(100);
    pending.completeError(StateError('retired quality failure'));
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [80]);
    expect(_qualitySlider(tester, 0).value, 60);
    expect(tester.takeException(), isNull);
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('quality editor clean values follow external refresh', (tester) async {
    Future<double?> save(double v) async => v;
    await _qualityEditor(tester, saveQuality: save, saveFps: save);
    await _qualityEditor(tester, quality: 70, fps: 50, saveQuality: save, saveFps: save);
    expect(_qualitySlider(tester, 0).value, 70);
    expect(_qualitySlider(tester, 1).value, 50);
  });

  testWidgets('quality editor leaving More saves its bounded current value', (tester) async {
    final calls = <double>[];
    await _qualityEditor(tester, quality: 500, saveQuality: (v) async { calls.add(v); return v; });
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, isTrue);
    await tester.tap(find.byType(Checkbox));
    await tester.pump();
    expect(_qualitySlider(tester, 0).value, 100);
    expect(_qualitySlider(tester, 0).max, 100);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [100]);
  });

  testWidgets('quality editor preserves narrow mobile layout and hidden FPS', (tester) async {
    await _qualityEditor(tester, mobile: true, showFps: false, saveQuality: (v) async => v);
    expect(find.byType(Slider), findsOneWidget);
    expect(find.byType(Checkbox), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('trackpad draft survives rebuild and uses the current save callback',
      (tester) async {
    final firstCalls = <int>[];
    final currentCalls = <int>[];
    await _trackpad(tester, save: (value) async {
      firstCalls.add(value);
      return value;
    });
    final controller = _trackpadController(tester);
    await _slideTrackpad(tester, 250);
    await tester.pump(const Duration(milliseconds: 500));
    await _trackpad(tester, save: (value) async {
      currentCalls.add(value);
      return value;
    });
    expect(_trackpadController(tester), same(controller));
    expect(controller.text, '250');
    expect(tester.widget<Slider>(find.byType(Slider)).value, 250);
    await tester.pump(const Duration(milliseconds: 500));
    expect(firstCalls, isEmpty);
    expect(currentCalls, [250]);
  });

  testWidgets('trackpad removal cancels debounce and disposes its controller',
      (tester) async {
    final calls = <int>[];
    await _trackpad(tester, save: (value) async {
      calls.add(value);
      return value;
    });
    final controller = _trackpadController(tester);
    await _slideTrackpad(tester, 200);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 1));
    expect(calls, isEmpty);
    expect(() => controller.addListener(() {}), throwsFlutterError);
  });

  testWidgets('trackpad retired edit callbacks cannot dispatch work',
      (tester) async {
    final calls = <int>[];
    await _trackpad(tester, save: (value) async {
      calls.add(value);
      return value;
    });
    final slider = tester.widget<Slider>(find.byType(Slider)).onChanged!;
    final submit = tester.widget<TextField>(find.byType(TextField)).onSubmitted!;
    await tester.pumpWidget(const SizedBox.shrink());
    slider(200);
    submit('300');
    await tester.pump(const Duration(seconds: 1));
    expect(calls, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('trackpad serializes saves and retains only the latest newer draft',
      (tester) async {
    final first = Completer<int?>();
    final calls = <int>[];
    await _trackpad(tester, save: (value) {
      calls.add(value);
      return calls.length == 1 ? first.future : Future.value(value);
    });
    await _slideTrackpad(tester, 200);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [200]);
    await _slideTrackpad(tester, 300);
    await tester.pump(const Duration(milliseconds: 500));
    await _slideTrackpad(tester, 400);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [200]);
    first.complete(200);
    await tester.pump();
    expect(calls, [200, 400]);
    expect(_trackpadController(tester).text, '400');
  });

  testWidgets('trackpad failed saves retain the draft and permit identical retry',
      (tester) async {
    final calls = <int>[];
    await _trackpad(tester, save: (value) {
      calls.add(value);
      switch (calls.length) {
        case 1: throw StateError('sync save failure');
        case 2: return Future.error(StateError('async save failure'));
        case 3: return Future.value(null);
        default: return Future.value(value);
      }
    });
    await _slideTrackpad(tester, 250);
    await tester.pump(const Duration(seconds: 1));
    for (var retry = 0; retry < 3; retry++) {
      expect(find.text('Failed'), findsOneWidget);
      expect(_trackpadController(tester).text, '250');
      await tester.tap(find.text('Retry'));
      await tester.pump();
    }
    expect(calls, [250, 250, 250, 250]);
    expect(find.text('Failed'), findsNothing);
    expect(find.text('Retry'), findsNothing);
  });

  testWidgets('trackpad success publishes its confirmed effective value',
      (tester) async {
    final completion = Completer<int?>();
    await _trackpad(tester, save: (_) => completion.future);
    await _slideTrackpad(tester, 250);
    await tester.pump(const Duration(seconds: 1));
    expect(_trackpadController(tester).text, '250');
    completion.complete(240);
    await tester.pump();
    expect(_trackpadController(tester).text, '240');
    expect(tester.widget<Slider>(find.byType(Slider)).value, 240);
  });

  testWidgets('trackpad clean refresh preserves unsubmitted text on rebuild',
      (tester) async {
    final calls = <int>[];
    Future<int?> save(int value) async { calls.add(value); return value; }
    await _trackpad(tester, save: save);
    await _trackpad(tester, value: 180, save: save);
    expect(_trackpadController(tester).text, '180');
    await tester.enterText(find.byType(TextField), '275');
    await _trackpad(tester, value: 220, save: save);
    expect(_trackpadController(tester).text, '275');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [275]);
  });

  testWidgets('trackpad replacement retires old edits and pending completion',
      (tester) async {
    final pending = Completer<int?>();
    final calls = <int>[];
    await _trackpad(tester, save: (value) { calls.add(value); return pending.future; });
    final oldSlider = tester.widget<Slider>(find.byType(Slider)).onChanged!;
    await _slideTrackpad(tester, 200);
    await tester.pump(const Duration(seconds: 1));
    await _trackpad(tester, value: 400,
        fieldKey: const ValueKey('replacement'), save: (value) async => value);
    oldSlider(300);
    pending.complete(200);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [200]);
    expect(_trackpadController(tester).text, '400');
    expect(tester.widget<Slider>(find.byType(Slider)).value, 400);
    expect(tester.takeException(), isNull);
  });

  testWidgets('trackpad disabling retires queued work without bypassing a pending save',
      (tester) async {
    final pending = Completer<int?>();
    final calls = <int>[];
    Future<int?> save(int value) {
      calls.add(value);
      return calls.length == 1 ? pending.future : Future.value(value);
    }
    await _trackpad(tester, save: save);
    final oldSlider = tester.widget<Slider>(find.byType(Slider)).onChanged!;
    final oldSubmit = tester.widget<TextField>(find.byType(TextField)).onSubmitted!;
    await _slideTrackpad(tester, 200);
    await tester.pump(const Duration(seconds: 1));
    await _slideTrackpad(tester, 300);
    await _trackpad(tester, enabled: false, save: save);
    oldSlider(500);
    oldSubmit('600');
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [200]);
    expect(tester.widget<Slider>(find.byType(Slider)).onChanged, isNull);
    expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
    expect(_trackpadController(tester).text, '100');
    await _trackpad(tester, save: save);
    await _slideTrackpad(tester, 400);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [200]);
    pending.complete(200);
    await tester.pump();
    expect(calls, [200, 400]);
    expect(_trackpadController(tester).text, '400');
  });

  testWidgets('trackpad retired save errors cannot affect a replacement',
      (tester) async {
    final pending = Completer<int?>();
    await _trackpad(tester, save: (_) => pending.future);
    await _slideTrackpad(tester, 200);
    await tester.pump(const Duration(seconds: 1));
    await _trackpad(tester, value: 400,
        fieldKey: const ValueKey('replacement'), save: (value) async => value);
    pending.completeError(StateError('retired save failure'));
    await tester.pump();
    expect(tester.takeException(), isNull);
    expect(_trackpadController(tester).text, '400');
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('trackpad dialog staging keeps bounded local values without saves',
      (tester) async {
    final draft = SimpleWrapper(100);
    await _trackpad(tester, draft: draft, save: null);
    await _slideTrackpad(tester, 250);
    expect(draft.value, 250);
    await tester.enterText(find.byType(TextField), '2000');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(draft.value, 1000);
    await tester.enterText(find.byType(TextField), '0');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(draft.value, 10);
    expect(_trackpadController(tester).text, '10');
    await tester.enterText(find.byType(TextField), '10x');
    expect(_trackpadController(tester).text, '10');
    await tester.enterText(find.byType(TextField), '');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    expect(_trackpadController(tester).text, '10');
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 1));
  });

  test('default option save waits and returns the effective native value', () async {
    final completion = Completer<String>();
    String? result;
    final save = saveUserDefaultOption('custom-fps', '25.0',
        writeOption: (key, value) {
          expect(key, 'custom-fps');
          expect(value, '25.0');
          return completion.future;
        }, showFailure: () => fail('successful default save reported failure'))
        .then((value) => result = value);
    await Future<void>.delayed(Duration.zero);
    expect(result, isNull);
    completion.complete('25');
    await save;
    expect(result, '25');
  });

  test('default option failure is visible and the identical retry stays usable', () async {
    for (final synchronous in [false, true]) {
      var calls = 0;
      var failures = 0;
      Future<String> write(String key, String value) {
        expect(key, 'view-style');
        expect(value, 'adaptive');
        if (++calls == 1) {
          if (synchronous) throw StateError('default save failed');
          return Future.error(StateError('default save failed'));
        }
        return Future.value('adaptive');
      }
      expect(await saveUserDefaultOption('view-style', 'adaptive',
          writeOption: write, showFailure: () => failures++), isNull);
      expect(failures, 1);
      expect(await saveUserDefaultOption('view-style', 'adaptive',
          writeOption: write, showFailure: () => failures++), 'adaptive');
      expect(calls, 2);
      expect(failures, 1);
    }
  });

  test('default option empty effective value is distinct from failure', () async {
    var failures = 0;
    expect(await saveUserDefaultOption('default-test', '',
        writeOption: (key, value) async => '',
        showFailure: () => failures++), '');
    expect(failures, 0);
  });

  testWidgets('audio load failure stays visible and retries in a narrow view',
      (tester) async {
    for (final synchronous in [false, true]) {
      var calls = 0;
      Future<Map<String, Object>> load(bool cm, bool voice) {
        if (++calls == 1) {
          if (synchronous) throw StateError('read failed');
          return Future.error(StateError('read failed'));
        }
        return Future.value(_audioDevices('Mic A'));
      }
      await tester.pumpWidget(_audioControls(load, width: 150));
      await tester.pumpAndSettle();
      expect(find.text('Audio load failed'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.tap(find.text('Retry'));
      await tester.pumpAndSettle();
      expect(calls, 2);
      expect(find.text('device:Mic A'), findsOneWidget);
      expect(find.text('Audio load failed'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('audio parent rebuild retains its pending read and later refreshes',
      (tester) async {
    final completion = Completer<Map<String, Object>>();
    var calls = 0;
    Future<Map<String, Object>> load(bool cm, bool voice) {
      calls++;
      return completion.future;
    }
    await tester.pumpWidget(_audioControls(load));
    await tester.pumpWidget(_audioControls(load, width: 380));
    final pendingCalls = calls;
    completion.complete(_audioDevices('Mic A'));
    await tester.pumpAndSettle();
    expect(pendingCalls, 1);
    await tester.pumpWidget(_audioControls(load, width: 400));
    await tester.pumpAndSettle();
    expect(calls, 2);
    expect(find.text('device:Mic A'), findsOneWidget);
  });

  testWidgets('audio stale retry cannot start duplicate pending reads',
      (tester) async {
    final completion = Completer<Map<String, Object>>();
    var calls = 0;
    Future<Map<String, Object>> load(bool cm, bool voice) => ++calls == 1
        ? Future.error(StateError('first read failed'))
        : completion.future;
    await tester.pumpWidget(_audioControls(load));
    await tester.pumpAndSettle();
    final retry = tester.widget<TextButton>(find.widgetWithText(TextButton, 'Retry')).onPressed!;
    retry();
    retry();
    await tester.pumpWidget(_audioControls(load, width: 380));
    retry();
    final pendingCalls = calls;
    completion.complete(_audioDevices('Mic B'));
    await tester.pumpAndSettle();
    expect(pendingCalls, 2);
    expect(find.text('device:Mic B'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('audio role replacement ignores old data and error completion',
      (tester) async {
    for (final failOld in [false, true]) {
      final old = Completer<Map<String, Object>>();
      final current = Completer<Map<String, Object>>();
      final roles = <bool>[];
      Future<Map<String, Object>> load(bool cm, bool voice) {
        roles.add(cm);
        expect(voice, isTrue);
        return cm ? current.future : old.future;
      }
      await tester.pumpWidget(_audioControls(load));
      await tester.pumpWidget(_audioControls(load, isCm: true));
      if (failOld) {
        old.completeError(StateError('retired read failed'));
      } else {
        old.complete(_audioDevices('Mic A'));
      }
      await tester.pump();
      await tester.pumpWidget(_audioControls(load, isCm: true, width: 380));
      final pendingRoles = roles.toList();
      current.complete(_audioDevices('Mic C'));
      await tester.pumpAndSettle();
      expect(pendingRoles, [false, true]);
      expect(find.text('device:Mic C'), findsOneWidget);
      expect(find.text('device:Mic A'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('audio retired retry cannot read after replacement or disposal',
      (tester) async {
    for (final dispose in [false, true]) {
      var oldReads = 0;
      var newReads = 0;
      Future<Map<String, Object>> old(bool cm, bool voice) {
        oldReads++;
        return Future.error(StateError('read failed'));
      }
      Future<Map<String, Object>> replacement(bool cm, bool voice) async {
        newReads++;
        return _audioDevices('Mic B');
      }
      await tester.pumpWidget(_audioControls(old));
      await tester.pumpAndSettle();
      final retry = tester.widget<TextButton>(find.widgetWithText(TextButton, 'Retry')).onPressed!;
      await tester.pumpWidget(dispose
          ? const SizedBox.shrink()
          : _audioControls(replacement, isCm: true));
      await tester.pumpAndSettle();
      retry();
      await tester.pumpAndSettle();
      expect(oldReads, 1);
      expect(newReads, dispose ? 0 : 1);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('audio empty default and absent devices remain valid load outcomes',
      (tester) async {
    await tester.pumpWidget(_audioControls(
        (cm, voice) async => _audioDevices('', devices: [''])));
    await tester.pumpAndSettle();
    expect(find.text('device:'), findsOneWidget);
    expect(find.text('Audio load failed'), findsNothing);
    await tester.pumpWidget(_audioControls(
        (cm, voice) async => _audioDevices('', devices: [])));
    await tester.pumpAndSettle();
    expect(find.text('Choose Mic B'), findsNothing);
    expect(find.text('Audio load failed'), findsNothing);
  });

  testWidgets('audio admitted write drains while retired callbacks cannot dispatch',
      (tester) async {
    for (final dispose in [false, true]) {
      final completion = Completer<void>();
      final values = {false: 'Mic A', true: 'Mic C'};
      final writes = <String>[];
      AudioINputSetDevice? select;
      Future<Map<String, Object>> load(bool cm, bool voice) async =>
          _audioDevices(values[cm]!);
      Future<void> write(String device, bool cm, bool voice) async {
        writes.add('$cm:$voice:$device');
        await completion.future;
        values[cm] = device;
      }
      await tester.pumpWidget(_audioControls(load, write: write,
          capture: (value) => select = value));
      await tester.pumpAndSettle();
      final retired = select!;
      final admitted = retired('Mic B');
      await tester.pumpWidget(dispose
          ? const SizedBox.shrink()
          : _audioControls(load, write: write, isCm: true));
      await tester.pump();
      final late = retired('Mic A');
      completion.complete();
      await Future.wait([admitted, late]);
      await tester.pumpAndSettle();
      expect(writes, ['false:true:Mic B']);
      expect(values[false], 'Mic B');
      expect(values[true], 'Mic C');
      if (!dispose) expect(find.text('device:Mic C'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('audio live write waits then publishes confirmed readback',
      (tester) async {
    final completion = Completer<void>();
    final readback = Completer<Map<String, Object>>();
    var reads = 0;
    AudioINputSetDevice? select;
    Future<Map<String, Object>> load(bool cm, bool voice) => ++reads == 1
        ? Future.value(_audioDevices('Mic A')) : readback.future;
    await tester.pumpWidget(_audioControls(load,
        write: (device, cm, voice) => completion.future,
        capture: (value) => select = value));
    await tester.pumpAndSettle();
    final save = select!('Mic B');
    await tester.pump();
    expect(reads, 1);
    expect(find.text('device:Mic A'), findsOneWidget);
    completion.complete();
    await save;
    await tester.pump();
    final loading = find.byType(LinearProgressIndicator).evaluate().length;
    readback.complete(_audioDevices('Mic C'));
    await tester.pumpAndSettle();
    expect(reads, 2);
    expect(loading, 1);
    expect(find.text('device:Mic C'), findsOneWidget);
  });

  testWidgets('audio pending write refuses duplicate and rebuilt selections',
      (tester) async {
    final completion = Completer<void>();
    final writes = <String>[];
    var current = 'Mic A';
    var reads = 0;
    AudioINputSetDevice? select;
    Future<Map<String, Object>> load(bool cm, bool voice) async {
      reads++;
      return _audioDevices(current);
    }
    Future<void> write(String device, bool cm, bool voice) async {
      writes.add(device);
      await completion.future;
      current = device;
    }
    await tester.pumpWidget(_audioControls(load, write: write,
        capture: (value) => select = value));
    await tester.pumpAndSettle();
    final first = select!('Mic B');
    final duplicate = select!('Mic C');
    await tester.pumpWidget(_audioControls(load, write: write, width: 380,
        capture: (value) => select = value));
    await tester.pump();
    final rebuilt = select!('Mic C');
    final pendingWrites = writes.toList();
    final pendingReads = reads;
    final busy = find.byType(LinearProgressIndicator).evaluate().length;
    completion.complete();
    await Future.wait([first, duplicate, rebuilt]);
    await tester.pumpAndSettle();
    expect(pendingWrites, ['Mic B']);
    expect(pendingReads, 1);
    expect(busy, 1);
    expect(writes, ['Mic B']);
    expect(reads, 2);
    expect(find.text('device:Mic B'), findsOneWidget);
    await tester.tap(find.text('Choose Mic B'));
    await tester.pumpAndSettle();
    expect(writes, ['Mic B', 'Mic B']);
  });

  testWidgets('audio replacement retains admission until the old write settles',
      (tester) async {
    final completion = Completer<void>();
    final writes = <String>[];
    var oldReads = 0;
    var newReads = 0;
    var current = 'Mic C';
    AudioINputSetDevice? select;
    Future<Map<String, Object>> oldLoad(bool cm, bool voice) async {
      oldReads++;
      return _audioDevices('Mic A');
    }
    Future<Map<String, Object>> newLoad(bool cm, bool voice) async {
      newReads++;
      return _audioDevices(current);
    }
    Future<void> oldWrite(String device, bool cm, bool voice) async {
      writes.add('old:$device');
      await completion.future;
    }
    Future<void> newWrite(String device, bool cm, bool voice) async {
      writes.add('new:$device');
      current = device;
    }
    await tester.pumpWidget(_audioControls(oldLoad, write: oldWrite,
        capture: (value) => select = value));
    await tester.pumpAndSettle();
    final retired = select!;
    final admitted = retired('Mic B');
    await tester.pumpWidget(_audioControls(newLoad, write: newWrite, isCm: true,
        capture: (value) => select = value));
    await tester.pump();
    final replacement = select!('Mic B');
    final stale = retired('Mic C');
    final pendingWrites = writes.toList();
    completion.complete();
    await Future.wait([admitted, replacement, stale]);
    await tester.pumpAndSettle();
    expect(pendingWrites, ['old:Mic B']);
    expect(oldReads, 1);
    expect(newReads, 1);
    expect(find.text('device:Mic C'), findsOneWidget);
    await select!('Mic B');
    await tester.pumpAndSettle();
    expect(writes, ['old:Mic B', 'new:Mic B']);
    expect(newReads, 2);
    expect(find.text('device:Mic B'), findsOneWidget);
  });

  testWidgets('audio failed write releases admission for an identical retry',
      (tester) async {
    for (final synchronous in [false, true]) {
      final completion = Completer<void>();
      var writes = 0;
      var reads = 0;
      var current = 'Mic A';
      AudioINputSetDevice? select;
      Future<Map<String, Object>> load(bool cm, bool voice) async {
        reads++;
        return _audioDevices(current);
      }
      Future<void> write(String device, bool cm, bool voice) {
        if (++writes == 1) {
          if (synchronous) throw StateError('device write failed');
          return completion.future;
        }
        current = device;
        return Future.value();
      }
      await tester.pumpWidget(_audioControls(load, write: write,
          capture: (value) => select = value));
      await tester.pumpAndSettle();
      final failure = expectLater(select!('Mic B'), throwsStateError);
      if (!synchronous) completion.completeError(StateError('device write failed'));
      await failure;
      await tester.pumpAndSettle();
      expect(reads, 2);
      expect(find.text('device:Mic A'), findsOneWidget);
      await select!('Mic B');
      await tester.pumpAndSettle();
      expect(writes, 2);
      expect(reads, 3);
      expect(find.text('device:Mic B'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  test('Flutter UI preference save waits and returns effective readback', () async {
    final completion = Completer<void>();
    var reads = 0;
    String? result;
    final save = saveLocalFlutterOption('peer-view', 'requested',
        writeOption: (key, value) {
          expect(key, 'peer-view');
          expect(value, 'requested');
          return completion.future;
        }, readOption: (key) {
          expect(key, 'peer-view');
          reads++;
          return 'effective';
        }, showFailure: () => fail('successful preference save reported failure'))
        .then((value) => result = value);
    await Future<void>.delayed(Duration.zero);
    expect(reads, 0);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, 'effective');
    expect(reads, 1);
  });

  test('Flutter UI preference failure preserves readback and permits retry', () async {
    var writes = 0;
    var reads = 0;
    var failures = 0;
    Future<void> write(String key, String value) async {
      expect(key, 'peer-view');
      expect(value, '');
      if (++writes == 1) throw StateError('save failed');
    }
    String read(String key) {
      reads++;
      return '';
    }
    expect(await saveLocalFlutterOption('peer-view', '', writeOption: write,
        readOption: read, showFailure: () => failures++), isNull);
    expect(reads, 0);
    expect(await saveLocalFlutterOption('peer-view', '', writeOption: write,
        readOption: read, showFailure: () => failures++), '');
    expect(writes, 2);
    expect(reads, 1);
    expect(failures, 1);
  });

  test('Flutter UI preference readback failure reports uncertainty and permits retry', () async {
    var writes = 0;
    var reads = 0;
    var failures = 0;
    Future<void> write(String key, String value) async { writes++; }
    String read(String key) {
      if (++reads == 1) throw StateError('readback failed');
      return 'confirmed';
    }
    expect(await saveLocalFlutterOption('peer-view', 'requested', writeOption: write,
        readOption: read, showFailure: () => failures++), isNull);
    expect(writes, 1);
    expect(await saveLocalFlutterOption('peer-view', 'requested', writeOption: write,
        readOption: read, showFailure: () => failures++), 'confirmed');
    expect(writes, 2);
    expect(reads, 2);
    expect(failures, 1);
  });

  test('local option save waits before publishing dependent effects', () async {
    final completion = Completer<void>();
    final calls = <String>[];
    var effect = false;
    final save = mainSetLocalOption('theme', 'dark',
        writeOption: (key, value) {
          calls.add('$key=$value');
          return completion.future;
        }, showFailure: () => fail('successful local save reported failure'))
        .then((saved) { if (saved) effect = true; });
    await Future<void>.delayed(Duration.zero);
    expect(calls, ['theme=dark']);
    expect(effect, isFalse);
    completion.complete();
    await save;
    expect(effect, isTrue);
  });

  test('local option failures report feedback and stop dependent effects',
      () async {
    for (final synchronous in [false, true]) {
      var failures = 0;
      var effect = false;
      final saved = await mainSetLocalOption('theme', 'dark',
          writeOption: (_, __) {
            if (synchronous) throw StateError('dispatch failure');
            return Future<void>.error(StateError('native save failure'));
          }, showFailure: () => failures++);
      if (saved) effect = true;
      expect(effect, isFalse);
      expect(saved, isFalse);
      expect(failures, 1);
    }
  });

  test('local option failure permits the identical retry', () async {
    final calls = <String>[];
    var failures = 0;
    Future<void> write(String key, String value) async {
      calls.add('$key=$value');
      if (calls.length == 1) throw StateError('first local save failed');
    }
    expect(await mainSetLocalOption('theme', 'dark',
        writeOption: write, showFailure: () => failures++), isFalse);
    expect(await mainSetLocalOption('theme', 'dark',
        writeOption: write, showFailure: () => failures++), isTrue);
    expect(calls, ['theme=dark', 'theme=dark']);
    expect(failures, 1);
  });

  test('favorite save owns its submitted IDs and waits for completion', () async {
    final completion = Completer<void>();
    final ids = ['first'];
    List<String>? submitted;
    bool? result;
    final save = mainSetFavorites(ids, true, writeFavorites: (values, favorite) {
      submitted = values;
      expect(favorite, isTrue);
      return completion.future;
    }, showFailure: () => fail('successful favorite save reported failure'))
        .then((value) => result = value);
    ids.add('later');
    await Future<void>.delayed(Duration.zero);
    expect(submitted, ['first']);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, isTrue);
  });

  test('failed favorite membership change reports failure and permits retry',
      () async {
    var calls = 0;
    var failures = 0;
    Future<void> write(List<String> ids, bool favorite) async {
      expect(ids, ['first', 'second']);
      expect(favorite, isFalse);
      if (++calls == 1) throw StateError('favorite save failed');
    }
    final first = await mainSetFavorites(['first', 'second'], false,
        writeFavorites: write, showFailure: () => failures++);
    final retry = await mainSetFavorites(['first', 'second'], false,
        writeFavorites: write, showFailure: () => failures++);
    expect(first, isFalse);
    expect(retry, isTrue);
    expect(calls, 2);
    expect(failures, 1);
  });

  test('option save waits for its native completion', () async {
    final completion = Completer<void>();
    final calls = <String>[];
    bool? result;
    final save = mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (key, value) {
        calls.add('$key=$value');
        return completion.future;
      },
      showFailure: () => fail('successful save reported failure'),
    ).then((value) => result = value);
    await Future<void>.delayed(Duration.zero);
    expect(calls, ['enable-abr=Y']);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, isTrue);
  });

  test('native option failure reports feedback without success', () async {
    var failures = 0;
    final saved = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (_, __) => Future<void>.error(StateError('native failure')),
      showFailure: () => failures++,
    );
    expect(saved, isFalse);
    expect(failures, 1);
  });

  test('synchronous option dispatch failure is reported', () async {
    var failures = 0;
    final saved = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (_, __) => throw StateError('dispatch failure'),
      showFailure: () => failures++,
    );
    expect(saved, isFalse);
    expect(failures, 1);
  });

  test('failed option save permits the identical retry', () async {
    final calls = <String>[];
    var failures = 0;
    Future<void> write(String key, String value) async {
      calls.add('$key=$value');
      if (calls.length == 1) throw StateError('first write failed');
    }

    final first = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: write,
      showFailure: () => failures++,
    );
    final retry = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: write,
      showFailure: () => failures++,
    );
    expect(first, isFalse);
    expect(retry, isTrue);
    expect(calls, ['enable-abr=Y', 'enable-abr=Y']);
    expect(failures, 1);
  });
}

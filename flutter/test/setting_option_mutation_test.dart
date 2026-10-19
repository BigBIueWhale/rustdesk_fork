import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/audio_input.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
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

void main() {
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
      await tester.pumpAndSettle();
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

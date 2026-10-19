import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/audio_input.dart';
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

void main() {
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

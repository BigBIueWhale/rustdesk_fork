import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/audio_input.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_test/flutter_test.dart';

final _duplicates = [
  SoundInput(id: 'source-a', label: 'Microphone'),
  SoundInput(id: 'source-b', label: 'Microphone'),
];

Widget _picker(AudioInputDeviceLoader load, AudioInputDeviceWriter write) =>
    MaterialApp(home: Scaffold(body: SizedBox(
      width: 360,
      child: AudioInput(
        isCm: false,
        isVoiceCall: true,
        loadDevicesInfo: load,
        writeDevice: write,
        failureText: 'Failed',
        retryText: 'Retry',
        builder: (devices, current, select) => ComboBox(
          options: devices,
          selectedKey: current,
          onChanged: select,
        ),
      ),
    )));

void main() {
  test('audio choices retain distinct identifiers for duplicate labels', () {
    final data = AudioInputDevices.fromInputs(_duplicates, 'source-b');
    expect(data.devices, {
      'source-a': 'Microphone (source-a)',
      'source-b': 'Microphone (source-b)',
    });
    expect(data.current, 'source-b');
  });

  test('audio choices separate translated system sound from device identity', () {
    final data = AudioInputDevices.fromInputs([
      SoundInput(id: 'System Sound', label: 'Systemton'),
    ], 'System Sound', systemSoundLabel: 'Systemton');
    expect(data.devices, {
      '': 'Systemton',
      'System Sound': 'Systemton (System Sound)',
    });
    expect(data.current, 'System Sound');
  });

  test('audio choices preserve current identity across labels and ordering', () {
    final data = AudioInputDevices.fromInputs([
      SoundInput(id: 'source-b', label: 'Renamed microphone'),
      SoundInput(id: 'source-a', label: ''),
    ], 'source-b');
    expect(data.current, 'source-b');
    expect(data.devices, {
      'source-b': 'Renamed microphone',
      'source-a': 'source-a',
    });
  });

  testWidgets('audio dropdown selects each duplicate device by identifier',
      (tester) async {
    var current = 'source-a';
    final writes = <String>[];
    await tester.pumpWidget(_picker(
      (cm, voice) async => AudioInputDevices.fromInputs(_duplicates, current),
      (device, cm, voice) async {
        expect(cm, isFalse);
        expect(voice, isTrue);
        writes.add(device);
        current = device;
      },
    ));
    await tester.pumpAndSettle();
    for (final id in ['source-b', 'source-a']) {
      final label = 'Microphone ($id)';
      await tester.tap(find.byType(DropdownButton<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text(label).last);
      await tester.pumpAndSettle();
      expect(tester.widget<DropdownButton<String>>(
          find.byType(DropdownButton<String>)).value, id);
    }
    expect(writes, ['source-b', 'source-a']);
    expect(tester.takeException(), isNull);
  });

  testWidgets('audio dropdown retains unavailable selection without a default write',
      (tester) async {
    final writes = <String>[];
    await tester.pumpWidget(_picker(
      (cm, voice) async => AudioInputDevices.fromInputs(
          _duplicates, 'removed-source', systemSoundLabel: 'System Sound'),
      (device, cm, voice) async => writes.add(device),
    ));
    await tester.pumpAndSettle();
    final dropdown = tester.widget<DropdownButton<String>>(
        find.byType(DropdownButton<String>));
    expect(dropdown.value, isNull);
    expect(find.text('removed-source'), findsOneWidget);
    expect(writes, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('audio dropdown sends the empty system identifier and preserves named devices',
      (tester) async {
    var current = 'System Sound';
    final writes = <String>[];
    final inputs = [SoundInput(id: 'System Sound', label: 'Systemton')];
    await tester.pumpWidget(_picker(
      (cm, voice) async => AudioInputDevices.fromInputs(
          inputs, current, systemSoundLabel: 'Systemton'),
      (device, cm, voice) async {
        writes.add(device);
        current = device;
      },
    ));
    await tester.pumpAndSettle();
    for (final label in ['Systemton', 'Systemton (System Sound)']) {
      await tester.tap(find.byType(DropdownButton<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text(label).last);
      await tester.pumpAndSettle();
    }
    expect(writes, ['', 'System Sound']);
    expect(tester.takeException(), isNull);
  });
}


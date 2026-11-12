import 'dart:convert';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/incoming_recording_status.dart';
import 'package:flutter_hbb/models/incoming_recording_status.dart';
import 'package:flutter_hbb/models/incoming_recording_setting.dart';
import 'package:flutter_hbb/common/widgets/incoming_recording_setting.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> showStatus(WidgetTester tester, IncomingRecordingStatus? status) =>
    tester.pumpWidget(MaterialApp(home: Scaffold(body: IncomingRecordingStatusView(
      status: status, translate: (value) => value,
    ))));

void main() {
  Future<void> showSetting(WidgetTester tester, IncomingRecordingSettingModel model) =>
      tester.pumpWidget(MaterialApp(home: Scaffold(body: IncomingRecordingSettingView(
        model: model, translate: (value) => value, fixed: false,
      ))));

  testWidgets('incoming recording setting waits for receiver and excludes duplicate changes', (tester) async {
    final reply = Completer<IncomingRecordingChange>();
    final requests = <bool>[];
    final model = IncomingRecordingSettingModel((enabled) {
      requests.add(enabled);
      return reply.future;
    });
    await showSetting(tester, model);
    expect(find.text('Recording setting unavailable'), findsOneWidget);
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).onChanged, isNull);
    model.update(const IncomingRecordingSetting(false, false));
    await tester.pump();
    await tester.tap(find.byType(Checkbox));
    await tester.pump();
    expect(requests, [true]);
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, false);
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).onChanged, isNull);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    await model.change(false);
    expect(requests, [true]);
    // The receiver's effective value, not the requested value, is authoritative.
    reply.complete(const IncomingRecordingChange(IncomingRecordingChangeOutcome.applied, false));
    await tester.pump();
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, false);
    expect(find.byType(LinearProgressIndicator), findsNothing);
  });

  testWidgets('incoming recording setting distinguishes denied failed and uncertain outcomes', (tester) async {
    var next = IncomingRecordingChangeOutcome.denied;
    final model = IncomingRecordingSettingModel((_) async => IncomingRecordingChange(next, null));
    model.update(const IncomingRecordingSetting(false, false));
    await showSetting(tester, model);
    for (final entry in {
      IncomingRecordingChangeOutcome.denied: 'Denied',
      IncomingRecordingChangeOutcome.failed: 'Failed',
      IncomingRecordingChangeOutcome.uncertain: 'Recording change is unconfirmed',
    }.entries) {
      next = entry.key;
      await tester.tap(find.byType(Checkbox));
      await tester.pump();
      expect(find.text(entry.value), findsOneWidget);
      expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, false);
    }
    // Reading the current value does not prove the outcome of the previous change.
    model.update(const IncomingRecordingSetting(true, false));
    await tester.pump();
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, true);
    expect(find.text('Recording change is unconfirmed'), findsOneWidget);
  });

  testWidgets('incoming recording setting preserves native pending and refuses false success', (tester) async {
    var calls = 0;
    final model = IncomingRecordingSettingModel((_) async {
      calls += 1;
      if (calls == 1) return const IncomingRecordingChange(IncomingRecordingChangeOutcome.applied, null);
      throw StateError('reply lost');
    });
    model.update(const IncomingRecordingSetting(false, true));
    await showSetting(tester, model);
    expect(tester.widget<Checkbox>(find.byType(Checkbox)).onChanged, isNull);
    await model.change(true);
    expect(calls, 0);
    model.update(const IncomingRecordingSetting(false, false));
    for (var attempt = 0; attempt < 2; attempt += 1) {
      await model.change(true);
      await tester.pump();
      expect(find.text('Recording change is unconfirmed'), findsOneWidget);
      expect(tester.widget<Checkbox>(find.byType(Checkbox)).value, false);
    }
  });

  test('incoming recording setting validates availability and pending snapshots', () {
    expect(IncomingRecordingSetting.decode('{"enabled":null,"pending":true}').pending, true);
    expect(IncomingRecordingSetting.decode('{"enabled":false,"pending":false}').enabled, false);
    for (final invalid in ['null', '{}', '{"enabled":false}', '{"enabled":"Y","pending":false}',
      '{"enabled":true,"pending":null}', '{"enabled":false,"pending":false,"extra":true}']) {
      expect(() => IncomingRecordingSetting.decode(invalid), throwsFormatException);
    }
  });

  testWidgets('incoming recording unavailable is distinct from stopped', (tester) async {
    await showStatus(tester, IncomingRecordingStatus.decode('null'));
    expect(find.text('Recording status unavailable'), findsOneWidget);
    expect(find.text('Not recording'), findsNothing);
    await showStatus(tester, const IncomingRecordingStatus(0, 0, 0, null));
    expect(find.text('Not recording'), findsOneWidget);
    expect(find.text('Recording status unavailable'), findsNothing);
  });

  testWidgets('incoming recording finishing is not reported as complete', (tester) async {
    await showStatus(tester, const IncomingRecordingStatus(1, 2, 3, null));
    expect(find.text('Starting: 1'), findsOneWidget);
    expect(find.text('Recording: 2'), findsOneWidget);
    expect(find.text('Finishing: 3'), findsOneWidget);
    expect(find.text('Not recording'), findsNothing);
    await showStatus(tester, const IncomingRecordingStatus(0, 0, 1, null));
    expect(find.text('Finishing: 1'), findsOneWidget);
    expect(find.text('Not recording'), findsNothing);
  });

  testWidgets('incoming recording historical failure survives healthy retry', (tester) async {
    final encoded = jsonEncode({
      'starting': 0, 'active': 0, 'finishing': 0,
      'last_failure': {'display': 3, 'camera': true, 'stage': 'finish'},
    });
    final status = IncomingRecordingStatus.decode(encoded)!;
    await showStatus(tester, status);
    expect(find.text('Not recording'), findsOneWidget);
    expect(find.text('Last recording failure: View camera 4 (Finishing)'), findsOneWidget);
    await showStatus(tester, IncomingRecordingStatus(0, 1, 0, status.lastFailure));
    expect(find.text('Recording: 1'), findsOneWidget);
    expect(find.text('Last recording failure: View camera 4 (Finishing)'), findsOneWidget);
    await showStatus(tester, IncomingRecordingStatus.decode(encoded));
    expect(find.text('Last recording failure: View camera 4 (Finishing)'), findsOneWidget);
  });

  test('incoming recording malformed or excessive status is refused', () {
    final valid = <String, Object?>{
      'starting': 32, 'active': 31, 'finishing': 1, 'last_failure': null,
    };
    expect(IncomingRecordingStatus.decode(jsonEncode(valid))!.finishing, 1);
    for (final invalid in [
      {...valid, 'starting': 33}, {...valid, 'active': -1}, {...valid, 'active': '1'},
      {...valid, 'extra': true}, {...valid}..remove('last_failure'),
      {...valid, 'last_failure': {'display': 0, 'camera': false, 'stage': 'unknown'}},
      {...valid, 'last_failure': {'display': -1, 'camera': false, 'stage': 'write'}},
      {...valid, 'last_failure': {'display': 0, 'camera': false, 'stage': 'write', 'extra': true}},
    ]) {
      expect(() => IncomingRecordingStatus.decode(jsonEncode(invalid)), throwsFormatException);
    }
  });
}

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/incoming_recording_status.dart';
import 'package:flutter_hbb/models/incoming_recording_status.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> showStatus(WidgetTester tester, IncomingRecordingStatus? status) =>
    tester.pumpWidget(MaterialApp(home: Scaffold(body: IncomingRecordingStatusView(
      status: status, translate: (value) => value,
    ))));

void main() {
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

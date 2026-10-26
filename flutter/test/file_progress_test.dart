import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:percent_indicator/percent_indicator.dart';
import 'package:uuid/uuid.dart';

class _ProgressHarness {
  final session = const Uuid().v4obj();
  late final controller = JobController(() => session, () => null,
      isCurrentSession: (actual) => actual == session, nextJobId: () => 7);

  _ProgressHarness() {
    controller.addTransferJob(Entry()..path = '/source/file', true, session);
    job.fileNum = 2;
    job.speed = 10;
    job.finishedSize = 20;
  }

  JobProgress get job => controller.jobTable.single;
  List<Object> get snapshot =>
      [job.fileNum, job.speed, job.finishedSize, job.recvJobRes];

  Map<String, dynamic> event() =>
      {'id': '7', 'file_num': '3', 'speed': '12.5', 'finished_size': '40'};
}

void main() {
  test('file progress accepts zero fractional speed and large byte counts', () {
    final h = _ProgressHarness();
    for (final size in ['0', '4294967296', '9007199254740992']) {
      h.controller.tryUpdateJobProgress(
          h.event()..['finished_size'] = size, h.session);
      expect(h.snapshot, [3, 12.5, int.parse(size), true]);
    }
    h.controller.tryUpdateJobProgress(h.event()..['speed'] = '0', h.session);
    expect(h.snapshot, [3, 0.0, 40, true]);
  });

  test('file progress refuses invalid speeds without partial mutation', () {
    final changed = <int>[];
    final values = <Object?>[
      null, 12, true, [], {}, 'bad', 'NaN', 'Infinity', '-Infinity', '-1', '1e999'
    ];
    for (var i = 0; i < values.length; i++) {
      final h = _ProgressHarness();
      h.controller.tryUpdateJobProgress(
          h.event()..['speed'] = values[i], h.session);
      if (!listEquals(h.snapshot, [2, 10.0, 20, false])) changed.add(i);
      h.controller.tryUpdateJobProgress(h.event(), h.session);
      expect(h.snapshot, [3, 12.5, 40, true]);
    }
    expect(changed, isEmpty);
  });

  test('file progress refuses invalid byte counts without partial mutation', () {
    final changed = <int>[];
    final values = <Object?>[
      null, 12, true, [], {}, 'bad', '-1', '1.5', '9223372036854775808',
      '0x10', '01', '+1', ' 1 '
    ];
    for (var i = 0; i < values.length; i++) {
      final h = _ProgressHarness();
      h.controller.tryUpdateJobProgress(
          h.event()..['finished_size'] = values[i], h.session);
      if (!listEquals(h.snapshot, [2, 10.0, 20, false])) changed.add(i);
      h.controller.tryUpdateJobProgress(h.event(), h.session);
      expect(h.snapshot, [3, 12.5, 40, true]);
    }
    expect(changed, isEmpty);
  });

  test('file progress refuses invalid action and file identities', () {
    final h = _ProgressHarness();
    for (final key in ['id', 'file_num']) {
      for (final value in <Object?>[
        null, 7, key == 'id' ? '-1' : '-2', '-01', ' -1', '-1.0',
        '01', '2147483648', 'bad'
      ]) {
        h.controller.tryUpdateJobProgress(
            h.event()..[key] = value, h.session);
        expect(h.snapshot, [2, 10.0, 20, false]);
      }
    }
    h.controller.tryUpdateJobProgress(h.event()..['id'] = '0', h.session);
    expect(h.snapshot, [2, 10.0, 20, false]);
  });

  test('file progress preserves current jobs on stale or unknown events', () {
    final h = _ProgressHarness();
    h.controller.tryUpdateJobProgress(h.event(), const Uuid().v4obj());
    expect(h.snapshot, [2, 10.0, 20, false]);
    h.controller.tryUpdateJobProgress(h.event()..['id'] = '8', h.session);
    expect(h.snapshot, [2, 10.0, 20, false]);
    h.controller.tryUpdateJobProgress(h.event(), h.session);
    expect(h.snapshot, [3, 12.5, 40, true]);
  });

  test('file progress diagnostics do not disclose rejected event contents', () {
    final h = _ProgressHarness();
    final messages = <String>[];
    final original = debugPrint;
    debugPrint = (message, {wrapWidth}) => messages.add(message ?? '');
    try {
      h.controller.tryUpdateJobProgress(
          h.event()..['finished_size'] = 'private-event-marker', h.session);
    } finally {
      debugPrint = original;
    }
    expect(messages.join('\n'), isNot(contains('private-event-marker')));
    expect(messages.join('\n'), isNot(contains('finished_size')));
  });

  for (final download in [false, true]) {
    final direction = download ? 'download' : 'upload';
    testWidgets('first file $direction progress renders before file completion',
        (tester) async {
      final h = _ProgressHarness();
      h.job
        ..fileNum = 0
        ..finishedSize = 0
        ..totalSize = 100
        ..fileCount = 2
        ..isRemoteToLocal = download;
      Future<void> render() => tester.pumpWidget(MaterialApp(
            home: Scaffold(
              body: Column(children: [
                Text(h.job.getStatus()),
                LinearPercentIndicator(
                  animateFromLastPercent: true,
                  center: Text(h.job.percentText),
                  percent: h.job.percent,
                ),
              ]),
            ),
          ));

      await render();
      expect(find.text('0%'), findsOneWidget);
      h.controller.tryUpdateJobProgress(
          h.event()..['file_num'] = '-1', h.session);
      await render();
      expect(find.text('40%'), findsOneWidget);
      expect(h.job.getStatus(), startsWith('0/2 files'));
      expect(h.snapshot, [-1, 12.5, 40, true]);
      expect(h.job.state, JobState.inProgress);
      expect(tester.takeException(), isNull);

      h.controller.tryUpdateJobProgress(
          h.event()
            ..['file_num'] = '0'
            ..['finished_size'] = '60',
          h.session);
      await render();
      expect(find.text('60%'), findsOneWidget);
      expect(h.job.getStatus(), startsWith('1/2 files'));
      expect(h.snapshot, [0, 12.5, 60, true]);
      expect(tester.takeException(), isNull);
    });
  }

  test('before-first progress index cannot complete a file command', () async {
    final h = _ProgressHarness();
    final listener = h.controller.jobResultListener;
    final result = listener.dispatchAndWait(
        expectedSessionId: h.session,
        actionId: 7,
        fileNum: 0,
        dispatch: () async {});
    try {
      final beforeFirst = h.event()..['file_num'] = '-1';
      expect(await h.controller.jobDone(beforeFirst, h.session), isFalse);
      expect(h.job.state, JobState.inProgress);
      expect(listener.tryComplete(h.session, beforeFirst), isFalse);
      expect(listener.tryCompleteError(
          h.session, {...beforeFirst, 'err': 'unowned'}), isFalse);
      expect(listener.tryComplete(
          h.session, h.event()..['file_num'] = '0'), isTrue);
      expect((await result)['file_num'], '0');
    } finally {
      listener.clear();
    }
  });
}

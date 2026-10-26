import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/mobile/widgets/file_job_status.dart';
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

class _ResumeHarness {
  final session = const Uuid().v4obj();
  late var currentSession = session;
  final calls = <List<Object>>[];
  final replies = <Completer<void>>[];
  late final controller = JobController(() => currentSession, () => null,
      isCurrentSession: (actual) => actual == currentSession,
      nextJobId: () => 7,
      requests: JobControllerRequests(
        cancelJob: (_, __) async {},
        addJob: (_, __, ___, ____, _____, ______, _______) async {},
        resumeJob: (sessionId, actionId, isRemote) {
          calls.add([sessionId, actionId, isRemote]);
          final reply = Completer<void>();
          replies.add(reply);
          return reply.future;
        },
      ));

  _ResumeHarness() {
    controller.addTransferJob(Entry()..path = '/source/file', true, session);
    job.state = JobState.paused;
  }

  JobProgress get job => controller.jobTable.single;
  Future<bool> resume() =>
      controller.resumeJob(7, expectedSessionId: session);
}


class _StatusJob extends JobProgress {
  @override
  String display() => 'Rendered status';
}

class _StatusHarness {
  final session = const Uuid().v4obj();
  late var currentSession = session;
  var nextId = 1;
  final calls = <List<Object>>[];
  final replies = <Completer<void>>[];
  late final controller = JobController(() => currentSession, () => null,
      isCurrentSession: (actual) => actual == currentSession,
      requests: JobControllerRequests(
        cancelJob: (sessionId, actionId) {
          calls.add([sessionId, actionId]);
          final reply = Completer<void>();
          replies.add(reply);
          return reply.future;
        },
        addJob: (_, __, ___, ____, _____, ______, _______) async {},
        resumeJob: (_, __, ___) async {},
      ));

  JobProgress add({JobState state = JobState.inProgress}) {
    final job = _StatusJob()
      ..id = nextId++
      ..type = JobType.transfer
      ..state = state;
    controller.jobTable.add(job);
    return job;
  }

  List<int> get ids => controller.jobTable.map((job) => job.id).toList();

  Future<void> render(WidgetTester tester) => tester.pumpWidget(MaterialApp(
        home: Scaffold(
          bottomSheet: FileJobStatus(controller: controller,
              sessionId: session, translateText: (text) => text),
        ),
      ));

  VoidCallback action(WidgetTester tester) =>
      tester.widget<IconButton>(
          find.widgetWithIcon(IconButton, Icons.cancel_outlined)).onPressed!;
}


void main() {

  testWidgets('mobile cancel preserves other jobs and result waiters',
      (tester) async {
    final h = _StatusHarness();
    final first = h.add();
    final second = h.add();
    final outcomes = <Object>[];
    final waiter = h.controller.jobResultListener.dispatchAndWait(
        expectedSessionId: h.session, actionId: second.id, fileNum: 0,
        dispatch: () async {}).then<void>(
            (value) => outcomes.add(value),
            onError: (Object error) { outcomes.add(error); });
    addTearDown(h.controller.jobResultListener.clear);
    await h.render(tester);
    await tester.tap(find.byIcon(Icons.cancel_outlined));
    expect(h.calls, [[h.session, first.id]]);
    expect(h.ids, [first.id, second.id]);
    final third = h.add();
    h.replies.single.complete();
    await tester.pump();
    expect(h.ids, [second.id, third.id]);
    expect(outcomes, isEmpty);
    expect(find.byIcon(Icons.cancel_outlined), findsOneWidget);
    expect(h.controller.jobResultListener.tryComplete(h.session,
        {'id': second.id.toString(), 'file_num': '0'}), isTrue);
    await waiter;
    expect(outcomes.single, isA<Map<String, dynamic>>());
    await tester.tap(find.byIcon(Icons.cancel_outlined));
    expect(h.calls.last, [h.session, second.id]);
    h.replies.last.complete();
    await tester.pump();
    expect(h.ids, [third.id]);
  });

  testWidgets('mobile late cancel cannot remove replacement or cleared jobs',
      (tester) async {
    for (final replace in [false, true]) {
      final h = _StatusHarness();
      final first = h.add();
      final second = h.add();
      await h.render(tester);
      await tester.tap(find.byIcon(Icons.cancel_outlined));
      h.controller.removeJob(h.session, first.id);
      JobProgress? replacement;
      if (replace) {
        replacement = h.add()..id = first.id;
      }
      h.replies.single.complete();
      await tester.pump();
      expect(h.ids, [second.id, if (replace) first.id]);
      if (replacement != null) {
        expect(identical(h.controller.jobTable.last, replacement), isTrue);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('mobile stale status callback cannot act on replacement jobs',
      (tester) async {
    for (final state in [JobState.inProgress, JobState.done, JobState.error]) {
      final h = _StatusHarness();
      final first = h.add(state: state);
      await h.render(tester);
      final callback = h.action(tester);
      h.controller.removeJob(h.session, first.id);
      final replacement = h.add()..id = first.id;
      final result = (callback as dynamic)();
      if (result is Future) {
        if (h.replies.isNotEmpty) h.replies.single.complete();
        await result;
      }
      expect(h.calls, isEmpty);
      expect(h.ids, [first.id]);
      expect(identical(h.controller.jobTable.single, replacement), isTrue);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('mobile completed status dismisses only displayed job',
      (tester) async {
    for (final state in [JobState.done, JobState.error]) {
      final h = _StatusHarness();
      final first = h.add(state: JobState.error);
      final second = h.add(state: state);
      await h.render(tester);
      expect(find.text(state == JobState.done ? 'Successful!' : 'Error!'),
          findsOneWidget);
      await tester.tap(find.byIcon(Icons.cancel_outlined));
      await tester.pump();
      expect(h.ids, [first.id]);
      expect(h.calls, isEmpty);
      expect(find.text('Error!'), findsOneWidget);
      expect(second.state, state);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('mobile cancel failure preserves jobs and permits retry',
      (tester) async {
    final h = _StatusHarness();
    final first = h.add();
    final second = h.add();
    await h.render(tester);
    final failed = (h.action(tester) as dynamic)() as Future<void>;
    final observed = expectLater(failed, throwsA(isA<StateError>()));
    h.replies.single.completeError(StateError('bridge refused'));
    await observed;
    await tester.pump();
    expect(h.ids, [first.id, second.id]);
    await tester.tap(find.byIcon(Icons.cancel_outlined));
    expect(h.calls, [[h.session, first.id], [h.session, first.id]]);
    h.replies.last.complete();
    await tester.pump();
    expect(h.ids, [second.id]);
  });

  testWidgets('mobile cancel obeys session ownership before and after dispatch',
      (tester) async {
    final h = _StatusHarness();
    final first = h.add();
    await h.render(tester);
    final callback = h.action(tester);
    h.currentSession = const Uuid().v4obj();
    await (callback as dynamic)();
    expect(h.calls, isEmpty);
    expect(h.ids, [first.id]);
    h.currentSession = h.session;
    final pending = (callback as dynamic)() as Future<void>;
    expect(h.calls, [[h.session, first.id]]);
    h.currentSession = const Uuid().v4obj();
    h.controller.clear();
    final replacement = h.add();
    h.replies.single.complete();
    await pending;
    expect(h.ids, [replacement.id]);
  });

  testWidgets('mobile status hides after its only job is cancelled',
      (tester) async {
    final h = _StatusHarness();
    await h.render(tester);
    expect(find.byIcon(Icons.cancel_outlined), findsNothing);
    final job = h.add();
    await tester.pump();
    await tester.tap(find.byIcon(Icons.cancel_outlined));
    expect(h.calls, [[h.session, job.id]]);
    expect(h.ids, [job.id]);
    h.replies.single.complete();
    await tester.pump();
    expect(h.ids, isEmpty);
    expect(find.byIcon(Icons.cancel_outlined), findsNothing);
  });


  for (final outcome in ['done', 'error', 'skipped']) {
    test('resume reply preserves earlier $outcome event', () async {
      for (final download in [false, true]) {
        final h = _ResumeHarness();
        h.job.isRemoteToLocal = download;
        h.job.totalSize = 100;
        final resumed = h.resume();
        expect(h.calls, [[h.session, 7, download]]);
        final event = {'id': '7', 'file_num': '0'};
        if (outcome == 'done') {
          expect(await h.controller.jobDone(event, h.session), isTrue);
        } else {
          h.controller.jobError(
              {...event, 'err': outcome}, h.session);
        }
        final expected = outcome == 'error' ? JobState.error : JobState.done;
        expect(h.job.state, expected);
        final before = [h.job.err, h.job.fileNum, h.job.finishedSize];
        h.replies.single.complete();
        expect(await resumed, isTrue);
        expect(h.job.state, expected);
        expect([h.job.err, h.job.fileNum, h.job.finishedSize], before);
      }
    });
  }

  test('resume reply cannot mutate a removed or replacement job', () async {
    for (final replace in [false, true]) {
      final h = _ResumeHarness();
      final original = h.job;
      final resumed = h.resume();
      expect(h.controller.removeJob(h.session, 7), isTrue);
      if (replace) {
        h.controller.addTransferJob(
            Entry()..path = '/source/replacement', false, h.session);
        h.job.state = JobState.paused;
      }
      h.replies.single.complete();
      expect(await resumed, isFalse);
      expect(original.state, JobState.paused);
      if (replace) expect(h.job.state, JobState.paused);
    }
  });

  test('resume accepts current paused jobs and refuses stale sessions', () async {
    for (final download in [false, true]) {
      final h = _ResumeHarness();
      h.job.isRemoteToLocal = download;
      final resumed = h.resume();
      expect(h.calls, [[h.session, 7, download]]);
      expect(h.job.state, JobState.paused);
      h.replies.single.complete();
      expect(await resumed, isTrue);
      expect(h.job.state, JobState.inProgress);
    }
    final h = _ResumeHarness();
    final resumed = h.resume();
    h.currentSession = const Uuid().v4obj();
    h.replies.single.complete();
    expect(await resumed, isFalse);
    expect(h.job.state, JobState.paused);
    expect(await h.resume(), isFalse);
    expect(await h.controller.resumeJob(8), isFalse);
    expect(h.calls, hasLength(1));
  });

  test('resume bridge failure preserves the job and permits retry', () async {
    final h = _ResumeHarness();
    final failed = expectLater(h.resume(), throwsA(isA<StateError>()));
    h.replies.single.completeError(StateError('bridge failed'));
    await failed;
    expect(h.job.state, JobState.paused);
    final retried = h.resume();
    h.replies.last.complete();
    expect(await retried, isTrue);
    expect(h.job.state, JobState.inProgress);
    expect(h.calls, hasLength(2));
  });

  test('resume refuses nonpaused and nontransfer jobs before dispatch', () async {
    final h = _ResumeHarness();
    for (final state in JobState.values.where((s) => s != JobState.paused)) {
      h.job.state = state;
      final resumed = h.resume();
      if (h.replies.isNotEmpty) {
        h.replies.removeLast().complete();
      }
      expect(await resumed, isFalse);
      expect(h.job.state, state);
    }
    h.job.state = JobState.paused;
    for (final type in JobType.values.where((t) => t != JobType.transfer)) {
      h.job.type = type;
      final resumed = h.resume();
      if (h.replies.isNotEmpty) {
        h.replies.removeLast().complete();
      }
      expect(await resumed, isFalse);
      expect(h.job.state, JobState.paused);
    }
    expect(h.calls, isEmpty);
  });

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

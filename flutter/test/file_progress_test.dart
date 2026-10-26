import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
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
      for (final value in <Object?>[null, 7, '-1', '01', '2147483648', 'bad']) {
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
}

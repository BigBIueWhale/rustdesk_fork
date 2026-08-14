import 'dart:async';

import 'package:flutter_hbb/models/session_event_queue.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('runs bounded session-state work in native stream order', () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = SessionEventQueue('session-a');

    Future<void> operation(String value) async {
      executed.add('$value-enter');
      if (value == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
      executed.add('$value-exit');
    }

    final first = queue.submit('session-a', () => operation('first'));
    await firstEntered.future;
    final second = queue.submit('session-a', () => operation('second'));
    final checkpoint = queue.checkpoint('session-a');

    expect(executed, ['first-enter']);
    releaseFirst.complete();
    expect(await first, SessionEventDisposition.completed);
    expect(await second, SessionEventDisposition.completed);
    expect(await checkpoint.done, SessionEventDisposition.completed);
    expect(queue.isCurrent(checkpoint), isTrue);
    expect(executed, [
      'first-enter',
      'first-exit',
      'second-enter',
      'second-exit',
    ]);
  });

  test('media checkpoints neither consume capacity nor survive later state',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final queue = SessionEventQueue('session-a', maxPending: 2);

    final first = queue.submit('session-a', () async {
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    final second = queue.submit('session-a', () async {});
    final checkpoints = List.generate(
        128, (_) => queue.checkpoint('session-a'),
        growable: false);
    final third = queue.submit('session-a', () async {});

    for (final checkpoint in checkpoints) {
      expect(queue.isCurrent(checkpoint), isFalse);
    }
    releaseFirst.complete();
    expect(await first, SessionEventDisposition.completed);
    expect(await second, SessionEventDisposition.completed);
    expect(await third, SessionEventDisposition.completed);
    for (final checkpoint in checkpoints) {
      expect(await checkpoint.done, SessionEventDisposition.completed);
      expect(queue.isCurrent(checkpoint), isFalse);
    }

    final current = queue.checkpoint('session-a');
    expect(await current.done, SessionEventDisposition.completed);
    expect(queue.isCurrent(current), isTrue);
  });

  test('capacity failure retires running and queued session-state work',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = SessionEventQueue('session-a', maxPending: 2);

    final first = queue.submit('session-a', () async {
      executed.add('first');
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    final second = queue.submit('session-a', () async {
      executed.add('second');
    });
    final third = queue.submit('session-a', () async {
      executed.add('third');
    });
    final overflow = queue.submit('session-a', () async {
      executed.add('overflow');
    });

    await expectLater(overflow, throwsStateError);
    expect(await first, SessionEventDisposition.retired);
    expect(await second, SessionEventDisposition.retired);
    expect(await third, SessionEventDisposition.retired);
    expect(
        await queue.submit('session-a', () async {
          executed.add('late');
        }),
        SessionEventDisposition.retired);
    expect(executed, ['first']);

    releaseFirst.complete();
    await Future<void>.delayed(Duration.zero);
    expect(executed, ['first']);
  });

  test('task failure is terminal and does not run retained successors',
      () async {
    final executed = <String>[];
    final queue = SessionEventQueue('session-a');

    final failed = queue.submit('session-a', () async {
      executed.add('failed');
      throw StateError('expected failure');
    });
    final successor = queue.submit('session-a', () async {
      executed.add('successor');
    });

    await expectLater(failed, throwsStateError);
    expect(await successor, SessionEventDisposition.retired);
    expect(executed, ['failed']);
  });

  test('mismatched owners are refused before invocation', () async {
    final queue = SessionEventQueue('session-a');
    var invoked = false;

    expect(
        await queue.submit('session-b', () async {
          invoked = true;
        }),
        SessionEventDisposition.retired);
    final mismatchedCheckpoint = queue.checkpoint('session-b');
    expect(await mismatchedCheckpoint.done, SessionEventDisposition.retired);
    expect(queue.isCurrent(mismatchedCheckpoint), isFalse);
    expect(queue.retire('session-b'), isFalse);
    expect(invoked, isFalse);

    expect(await queue.submit('session-a', () async {}),
        SessionEventDisposition.completed);
  });

  test('exact retirement cannot block a replacement session', () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final executed = <String>[];
    final oldQueue = SessionEventQueue('session-a');

    final oldRunning = oldQueue.submit('session-a', () async {
      executed.add('old-running');
      oldEntered.complete();
      await releaseOld.future;
    });
    await oldEntered.future;
    final oldPending = oldQueue.submit('session-a', () async {
      executed.add('old-pending');
    });

    expect(oldQueue.retire('session-b'), isFalse);
    expect(oldQueue.retire('session-a'), isTrue);
    expect(await oldRunning, SessionEventDisposition.retired);
    expect(await oldPending, SessionEventDisposition.retired);
    final retiredCheckpoint = oldQueue.checkpoint('session-a');
    expect(await retiredCheckpoint.done, SessionEventDisposition.retired);
    expect(oldQueue.isCurrent(retiredCheckpoint), isFalse);

    final replacement = SessionEventQueue('session-b');
    expect(
        await replacement.submit('session-b', () async {
          executed.add('replacement');
        }),
        SessionEventDisposition.completed);
    expect(executed, ['old-running', 'replacement']);

    releaseOld.complete();
    await Future<void>.delayed(Duration.zero);
    expect(oldQueue.retire('session-a'), isTrue);
    expect(executed, ['old-running', 'replacement']);
  });
}

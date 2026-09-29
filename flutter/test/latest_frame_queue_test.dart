import 'dart:async';

import 'package:flutter_hbb/models/latest_frame_queue.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('retains one running frame and only the latest successor per display',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final presented = <String>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    Future<void> present(String frame) async {
      presented.add(frame);
      if (frame == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
    }

    final first = queue.submit('session-a', 0, 'first', present);
    await firstEntered.future;
    final second = queue.submit('session-a', 0, 'second', present);
    final third = queue.submit('session-a', 0, 'third', present);

    expect(await second, LatestFrameDisposition.superseded);
    expect(presented, ['first']);
    releaseFirst.complete();
    expect(await first, LatestFrameDisposition.presented);
    expect(await third, LatestFrameDisposition.presented);
    expect(presented, ['first', 'third']);
  });

  test('different displays drain independently', () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final presented = <String>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    final first = queue.submit('session-a', 0, 'display-0', (frame) async {
      presented.add(frame);
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    final other = queue.submit('session-a', 1, 'display-1', (frame) async {
      presented.add(frame);
    });

    expect(await other, LatestFrameDisposition.presented);
    expect(presented, ['display-0', 'display-1']);
    releaseFirst.complete();
    expect(await first, LatestFrameDisposition.presented);
  });

  test('bounded parallel lane overtakes one stalled presentation', () async {
    final firstEntered = Completer<void>();
    final secondEntered = Completer<void>();
    final fourthEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final releaseSecond = Completer<void>();
    final releaseFourth = Completer<void>();
    final presented = <String>[];
    var running = 0;
    var peakRunning = 0;
    final queue = LatestFrameQueue<String, int, String>('session-a',
        maxConcurrentDrainsPerKey: 3, maxCurrentDrainsPerKey: 2);

    Future<void> present(String frame) async {
      presented.add(frame);
      running += 1;
      peakRunning = running > peakRunning ? running : peakRunning;
      try {
        if (frame == 'first') {
          firstEntered.complete();
          await releaseFirst.future;
        } else if (frame == 'second') {
          secondEntered.complete();
          await releaseSecond.future;
        } else if (frame == 'fourth') {
          fourthEntered.complete();
          await releaseFourth.future;
        }
      } finally {
        running -= 1;
      }
    }

    final first = queue.submit('session-a', 0, 'first', present);
    await firstEntered.future;
    final second = queue.submit('session-a', 0, 'second', present);
    await secondEntered.future;
    final third = queue.submit('session-a', 0, 'third', present);
    final fourth = queue.submit('session-a', 0, 'fourth', present);

    expect(await third, LatestFrameDisposition.superseded);
    expect(presented, ['first', 'second']);
    releaseSecond.complete();
    expect(await second, LatestFrameDisposition.presented);
    await fourthEntered.future;
    expect(presented, ['first', 'second', 'fourth']);
    expect(peakRunning, 2);

    releaseFourth.complete();
    expect(await fourth, LatestFrameDisposition.presented);
    releaseFirst.complete();
    expect(await first, LatestFrameDisposition.presented);
  });

  test('parallel recovery remains inside the total drain bound', () async {
    final firstEntered = Completer<void>();
    final secondEntered = Completer<void>();
    final replacementEntered = Completer<void>();
    final successorEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final releaseSecond = Completer<void>();
    final releaseReplacement = Completer<void>();
    final queue = LatestFrameQueue<String, int, String>('session-a',
        maxConcurrentDrainsPerKey: 3, maxCurrentDrainsPerKey: 2);

    final first = queue.submit('session-a', 0, 'first', (_) async {
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    final second = queue.submit('session-a', 0, 'second', (_) async {
      secondEntered.complete();
      await releaseSecond.future;
    });
    await secondEntered.future;

    expect(queue.suspend('session-a'), isTrue);
    expect(await first, LatestFrameDisposition.retired);
    expect(await second, LatestFrameDisposition.retired);
    expect(queue.recover('session-a'), isTrue);

    final replacement = queue.submit('session-a', 0, 'replacement', (_) async {
      replacementEntered.complete();
      await releaseReplacement.future;
    });
    await replacementEntered.future;
    final successor = queue.submit('session-a', 0, 'successor', (_) async {
      successorEntered.complete();
    });

    // Both detached drains plus the replacement consume the hard total. The
    // latest successor stays bounded until one of those operations finishes.
    expect(successorEntered.isCompleted, isFalse);
    releaseFirst.complete();
    await successorEntered.future;
    expect(await successor, LatestFrameDisposition.presented);

    releaseReplacement.complete();
    expect(await replacement, LatestFrameDisposition.presented);
    releaseSecond.complete();
    await Future<void>.delayed(Duration.zero);
  });

  test('parallel limit cannot exceed the total drain bound', () {
    expect(
        () => LatestFrameQueue<String, int, String>('session-a',
            maxConcurrentDrainsPerKey: 1, maxCurrentDrainsPerKey: 2),
        throwsArgumentError);
  });

  test('shared drain pool survives queue replacement without minting capacity',
      () async {
    final pool = LatestFrameDrainPool(
        maxConcurrentDrains: 3, maxWaitingDrains: 8);
    final releaseOldFirst = Completer<void>();
    final releaseOldSecond = Completer<void>();
    final releaseReplacement = Completer<void>();
    final oldFirstEntered = Completer<void>();
    final oldSecondEntered = Completer<void>();
    final replacementEntered = Completer<void>();
    final newestEntered = Completer<void>();
    var running = 0;
    var observedPeak = 0;

    Future<void> hold(Completer<void> entered, Completer<void> release) async {
      running += 1;
      observedPeak = running > observedPeak ? running : observedPeak;
      entered.complete();
      try {
        await release.future;
      } finally {
        running -= 1;
      }
    }

    final old = LatestFrameQueue<String, int, String>('old',
        maxConcurrentDrainsPerKey: 3,
        maxCurrentDrainsPerKey: 2,
        drainPool: pool);
    final oldFirst = old.submit(
        'old', 0, 'old-first', (_) => hold(oldFirstEntered, releaseOldFirst));
    await oldFirstEntered.future;
    final oldSecond = old.submit('old', 0, 'old-second',
        (_) => hold(oldSecondEntered, releaseOldSecond));
    await oldSecondEntered.future;
    expect(old.retire('old'), isTrue);
    expect(await oldFirst, LatestFrameDisposition.retired);
    expect(await oldSecond, LatestFrameDisposition.retired);

    final replacement = LatestFrameQueue<String, int, String>('replacement',
        maxConcurrentDrainsPerKey: 3,
        maxCurrentDrainsPerKey: 2,
        drainPool: pool);
    final replacementRunning = replacement.submit(
        'replacement',
        0,
        'replacement-running',
        (_) => hold(replacementEntered, releaseReplacement));
    await replacementEntered.future;
    final replacementWaiting = replacement.submit(
        'replacement', 0, 'replacement-waiting', (_) async {
      fail('retired queued conversion must not start');
    });
    expect(pool.activeDrains, 3);
    expect(pool.waitingDrains, 1);

    expect(replacement.retire('replacement'), isTrue);
    expect(await replacementRunning, LatestFrameDisposition.retired);
    expect(await replacementWaiting, LatestFrameDisposition.retired);
    expect(pool.waitingDrains, 0);

    final newest = LatestFrameQueue<String, int, String>('newest',
        maxConcurrentDrainsPerKey: 3,
        maxCurrentDrainsPerKey: 2,
        drainPool: pool);
    final newestFrame = newest.submit('newest', 0, 'newest', (_) async {
      running += 1;
      observedPeak = running > observedPeak ? running : observedPeak;
      newestEntered.complete();
      running -= 1;
    });
    expect(newestEntered.isCompleted, isFalse);
    expect(pool.activeDrains, 3);
    expect(pool.waitingDrains, 1);

    releaseOldFirst.complete();
    await newestEntered.future;
    expect(await newestFrame, LatestFrameDisposition.presented);
    expect(observedPeak, 3);
    expect(pool.peakActiveDrains, 3);

    releaseOldSecond.complete();
    releaseReplacement.complete();
    await Future<void>.delayed(Duration.zero);
    expect(pool.activeDrains, 0);
    expect(pool.waitingDrains, 0);
  });

  test('shared drain pool retains only the latest waiting frame', () async {
    final pool = LatestFrameDrainPool(
        maxConcurrentDrains: 1, maxWaitingDrains: 4);
    final blockerEntered = Completer<void>();
    final releaseBlocker = Completer<void>();
    final presented = <String>[];
    final blocker = LatestFrameQueue<String, int, String>('blocker',
        drainPool: pool);
    final blocked = blocker.submit('blocker', 0, 'blocked', (_) async {
      blockerEntered.complete();
      await releaseBlocker.future;
    });
    await blockerEntered.future;

    final waiting = LatestFrameQueue<String, int, String>('waiting',
        drainPool: pool);
    final first = waiting.submit('waiting', 0, 'first', (frame) async {
      presented.add(frame);
    });
    final second = waiting.submit('waiting', 0, 'second', (frame) async {
      presented.add(frame);
    });
    final latest = waiting.submit('waiting', 0, 'latest', (frame) async {
      presented.add(frame);
    });

    expect(await first, LatestFrameDisposition.superseded);
    expect(await second, LatestFrameDisposition.superseded);
    expect(pool.waitingDrains, 1);
    expect(presented, isEmpty);

    releaseBlocker.complete();
    expect(await blocked, LatestFrameDisposition.presented);
    expect(await latest, LatestFrameDisposition.presented);
    expect(presented, ['latest']);
    expect(pool.activeDrains, 0);
    expect(pool.waitingDrains, 0);
  });

  test('shared drain pool starts live waiting lanes in FIFO order', () async {
    final pool = LatestFrameDrainPool(
        maxConcurrentDrains: 1, maxWaitingDrains: 4);
    final blockerEntered = Completer<void>();
    final releaseBlocker = Completer<void>();
    final blocker = LatestFrameQueue<String, int, String>('blocker',
        drainPool: pool);
    final blocked = blocker.submit('blocker', 0, 'blocked', (_) async {
      blockerEntered.complete();
      await releaseBlocker.future;
    });
    await blockerEntered.future;

    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final firstWaiting = LatestFrameQueue<String, int, String>('first',
        drainPool: pool);
    final first = firstWaiting.submit('first', 0, 'first', (_) async {
      firstEntered.complete();
      await releaseFirst.future;
    });
    final secondEntered = Completer<void>();
    final secondWaiting = LatestFrameQueue<String, int, String>('second',
        drainPool: pool);
    final second = secondWaiting.submit('second', 0, 'second', (_) async {
      secondEntered.complete();
    });
    expect(pool.waitingDrains, 2);

    releaseBlocker.complete();
    expect(await blocked, LatestFrameDisposition.presented);
    await firstEntered.future;
    expect(secondEntered.isCompleted, isFalse);
    expect(pool.activeDrains, 1);
    expect(pool.waitingDrains, 1);

    releaseFirst.complete();
    expect(await first, LatestFrameDisposition.presented);
    await secondEntered.future;
    expect(await second, LatestFrameDisposition.presented);
    expect(pool.activeDrains, 0);
    expect(pool.waitingDrains, 0);
  });

  test('shared drain pool refuses excess waiting lanes visibly', () async {
    final pool = LatestFrameDrainPool(
        maxConcurrentDrains: 1, maxWaitingDrains: 1);
    final blockerEntered = Completer<void>();
    final releaseBlocker = Completer<void>();
    final blocker = LatestFrameQueue<String, int, String>('blocker',
        drainPool: pool);
    final blocked = blocker.submit('blocker', 0, 'blocked', (_) async {
      blockerEntered.complete();
      await releaseBlocker.future;
    });
    await blockerEntered.future;

    final firstWaiting = LatestFrameQueue<String, int, String>('first-waiting',
        drainPool: pool);
    final firstStarted = Completer<void>();
    final first = firstWaiting.submit('first-waiting', 0, 'first', (_) async {
      firstStarted.complete();
    });
    expect(pool.waitingDrains, 1);

    final refused = LatestFrameQueue<String, int, String>('refused',
        drainPool: pool);
    var refusedStarted = false;
    await expectLater(
        refused.submit('refused', 0, 'refused', (_) async {
          refusedStarted = true;
        }),
        throwsStateError);
    expect(refusedStarted, isFalse);
    expect(pool.activeDrains, 1);
    expect(pool.waitingDrains, 1);
    expect(await refused.submit('refused', 0, 'later', (_) async {}),
        LatestFrameDisposition.retired);

    releaseBlocker.complete();
    expect(await blocked, LatestFrameDisposition.presented);
    await firstStarted.future;
    expect(await first, LatestFrameDisposition.presented);
    expect(pool.activeDrains, 0);
    expect(pool.waitingDrains, 0);
  });

  test('parallel failure retires its peer and retained successor', () async {
    final failedEntered = Completer<void>();
    final peerEntered = Completer<void>();
    final releaseFailed = Completer<void>();
    final releasePeer = Completer<void>();
    final presented = <String>[];
    final queue = LatestFrameQueue<String, int, String>('session-a',
        maxConcurrentDrainsPerKey: 3, maxCurrentDrainsPerKey: 2);

    final failed = queue.submit('session-a', 0, 'failed', (frame) async {
      presented.add(frame);
      failedEntered.complete();
      await releaseFailed.future;
      throw StateError('expected failure');
    });
    await failedEntered.future;
    final peer = queue.submit('session-a', 0, 'peer', (frame) async {
      presented.add(frame);
      peerEntered.complete();
      await releasePeer.future;
    });
    await peerEntered.future;
    final successor = queue.submit('session-a', 0, 'successor', (frame) async {
      presented.add(frame);
    });

    releaseFailed.complete();
    await expectLater(failed, throwsStateError);
    expect(await peer, LatestFrameDisposition.retired);
    expect(await successor, LatestFrameDisposition.retired);
    expect(presented, ['failed', 'peer']);
    expect(await queue.submit('session-a', 0, 'later', (_) async {}),
        LatestFrameDisposition.retired);

    releasePeer.complete();
    await Future<void>.delayed(Duration.zero);
  });

  test('observed submissions retain only running and latest without futures',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final thirdPresented = Completer<void>();
    final presented = <String>[];
    final failures = <Object>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    Future<void> present(String frame) async {
      presented.add(frame);
      if (frame == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      } else if (frame == 'third') {
        thirdPresented.complete();
      }
    }

    expect(
        queue.submitObserved('session-a', 0, 'first', present,
            onError: (error, stackTrace) => failures.add(error)),
        isTrue);
    await firstEntered.future;
    expect(
        queue.submitObserved('session-a', 0, 'second', present,
            onError: (error, stackTrace) => failures.add(error)),
        isTrue);
    expect(
        queue.submitObserved('session-a', 0, 'third', present,
            onError: (error, stackTrace) => failures.add(error)),
        isTrue);

    releaseFirst.complete();
    await thirdPresented.future;
    expect(presented, ['first', 'third']);
    expect(failures, isEmpty);
  });

  test('observed failure is visible and retires its exact queue', () async {
    final failure = Completer<Object>();
    final queue = LatestFrameQueue<String, int, String>('session-a');

    expect(
        queue.submitObserved('session-a', 0, 'failed', (_) async {
          throw StateError('expected failure');
        }, onError: (error, stackTrace) => failure.complete(error)),
        isTrue);
    expect(await failure.future, isA<StateError>());
    expect(
        queue.submitObserved('session-a', 0, 'retired', (_) async {},
            onError: (error, stackTrace) => fail('unexpected error: $error')),
        isFalse);
  });

  test('a failed frame retires its retained successor', () async {
    final failedEntered = Completer<void>();
    final releaseFailed = Completer<void>();
    final presented = <String>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    final failed = queue.submit('session-a', 0, 'failed', (frame) async {
      presented.add(frame);
      failedEntered.complete();
      await releaseFailed.future;
      throw StateError('expected failure');
    });
    await failedEntered.future;
    final successor = queue.submit('session-a', 0, 'successor', (frame) async {
      presented.add(frame);
    });

    releaseFailed.complete();
    await expectLater(failed, throwsStateError);
    expect(await successor, LatestFrameDisposition.retired);
    expect(presented, ['failed']);
  });

  test('owner mismatch and display overflow refuse frames before invocation',
      () async {
    var invoked = false;
    final queue =
        LatestFrameQueue<String, int, String>('session-a', maxKeys: 1);

    expect(
        await queue.submit('session-b', 0, 'stale', (_) async {
          invoked = true;
        }),
        LatestFrameDisposition.retired);
    final held = Completer<void>();
    final first = queue.submit('session-a', 0, 'first', (_) => held.future);
    await expectLater(
        queue.submit('session-a', 1, 'overflow', (_) async {
          invoked = true;
        }),
        throwsStateError);
    expect(invoked, isFalse);
    held.complete();
    expect(await first, LatestFrameDisposition.retired);
  });

  test('exact retirement releases retained frames and cannot block replacement',
      () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final presented = <String>[];
    final oldQueue = LatestFrameQueue<String, int, String>('session-a');

    final oldRunning =
        oldQueue.submit('session-a', 0, 'old-running', (frame) async {
      presented.add(frame);
      oldEntered.complete();
      await releaseOld.future;
    });
    await oldEntered.future;
    final oldPending =
        oldQueue.submit('session-a', 0, 'old-pending', (frame) async {
      presented.add(frame);
    });

    expect(oldQueue.retire('session-b'), isFalse);
    expect(oldQueue.retire('session-a'), isTrue);
    expect(await oldRunning, LatestFrameDisposition.retired);
    expect(await oldPending, LatestFrameDisposition.retired);

    final replacement = LatestFrameQueue<String, int, String>('session-b');
    expect(
        await replacement.submit('session-b', 0, 'replacement', (frame) async {
          presented.add(frame);
        }),
        LatestFrameDisposition.presented);
    expect(presented, ['old-running', 'replacement']);

    releaseOld.complete();
    await Future<void>.delayed(Duration.zero);
    expect(oldQueue.retire('session-a'), isTrue);
    expect(presented, ['old-running', 'replacement']);
  });

  test('recovery bypasses a detached asynchronous presentation', () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final presented = <String>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    final old = queue.submit('session-a', 0, 'old', (frame) async {
      presented.add(frame);
      oldEntered.complete();
      await releaseOld.future;
    });
    await oldEntered.future;
    final pending = queue.submit('session-a', 0, 'pending', (frame) async {
      presented.add(frame);
    });

    expect(queue.suspend('session-b'), isFalse);
    expect(queue.recover('session-b'), isFalse);
    expect(queue.suspend('session-a'), isTrue);
    expect(await old, LatestFrameDisposition.retired);
    expect(await pending, LatestFrameDisposition.retired);
    expect(
        await queue.submit('session-a', 0, 'while-suspended', (frame) async {
          presented.add(frame);
        }),
        LatestFrameDisposition.retired);

    expect(queue.recover('session-a'), isTrue);
    expect(
        await queue.submit('session-a', 0, 'replacement', (frame) async {
          presented.add(frame);
        }),
        LatestFrameDisposition.presented);
    expect(presented, ['old', 'replacement']);

    releaseOld.complete();
    await Future<void>.delayed(Duration.zero);
    expect(presented, ['old', 'replacement']);
  });

  test('a detached failure cannot retire its recovered generation', () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final replacementPresented = Completer<void>();
    final failures = <Object>[];
    final queue = LatestFrameQueue<String, int, String>('session-a');

    expect(
        queue.submitObserved('session-a', 0, 'old', (_) async {
          oldEntered.complete();
          await releaseOld.future;
          throw StateError('detached failure');
        }, onError: (error, stackTrace) => failures.add(error)),
        isTrue);
    await oldEntered.future;

    expect(queue.suspend('session-a'), isTrue);
    expect(queue.recover('session-a'), isTrue);
    expect(
        queue.submitObserved('session-a', 0, 'replacement', (_) async {
          replacementPresented.complete();
        }, onError: (error, stackTrace) => failures.add(error)),
        isTrue);
    await replacementPresented.future;

    releaseOld.complete();
    await Future<void>.delayed(Duration.zero);
    expect(failures, isEmpty);
    expect(await queue.submit('session-a', 0, 'successor', (_) async {}),
        LatestFrameDisposition.presented);
  });

  test('recovery fails visibly at the per-display drain bound', () async {
    final firstEntered = Completer<void>();
    final secondEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final releaseSecond = Completer<void>();
    final queue = LatestFrameQueue<String, int, String>('session-a',
        maxConcurrentDrainsPerKey: 2);

    final first = queue.submit('session-a', 0, 'first', (_) async {
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    expect(queue.suspend('session-a'), isTrue);
    expect(await first, LatestFrameDisposition.retired);
    expect(queue.recover('session-a'), isTrue);

    final second = queue.submit('session-a', 0, 'second', (_) async {
      secondEntered.complete();
      await releaseSecond.future;
    });
    await secondEntered.future;
    expect(queue.suspend('session-a'), isTrue);
    expect(await second, LatestFrameDisposition.retired);
    expect(queue.recover('session-a'), isTrue);

    await expectLater(queue.submit('session-a', 0, 'overflow', (_) async {}),
        throwsStateError);
    expect(queue.recover('session-a'), isFalse);

    releaseFirst.complete();
    releaseSecond.complete();
    await Future<void>.delayed(Duration.zero);
  });

  test('detached displays remain inside the queue-wide key bound', () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final queue =
        LatestFrameQueue<String, int, String>('session-a', maxKeys: 1);

    final first = queue.submit('session-a', 0, 'first', (_) async {
      firstEntered.complete();
      await releaseFirst.future;
    });
    await firstEntered.future;
    expect(queue.suspend('session-a'), isTrue);
    expect(await first, LatestFrameDisposition.retired);
    expect(queue.recover('session-a'), isTrue);

    await expectLater(
        queue.submit('session-a', 1, 'other-display', (_) async {}),
        throwsStateError);

    releaseFirst.complete();
    await Future<void>.delayed(Duration.zero);
  });
}

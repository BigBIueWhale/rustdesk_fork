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

    final oldRunning = oldQueue.submit('session-a', 0, 'old-running',
        (frame) async {
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
}

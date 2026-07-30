import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/models/mobile_session_start_queue.dart';

void main() {
  test('retains one running request and only the latest pending request',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = MobileSessionStartQueue<String>((request) async {
      executed.add(request);
      if (request == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
    });

    final first = queue.submit('first');
    await firstEntered.future;
    final second = queue.submit('second');
    final third = queue.submit('third');

    expect(
      await second,
      MobileSessionStartDisposition.superseded,
    );
    expect(executed, ['first']);

    releaseFirst.complete();
    expect(await first, MobileSessionStartDisposition.completed);
    expect(await third, MobileSessionStartDisposition.completed);
    expect(executed, ['first', 'third']);
  });

  test('cancels the exact pending request without interrupting finality',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = MobileSessionStartQueue<String>((request) async {
      executed.add(request);
      if (request == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
    });

    final first = queue.submit('first');
    await firstEntered.future;
    final second = queue.submit('second');

    expect(queue.cancelPendingOrGetRunning((request) => request == 'other'),
        isNull);
    expect(
      await queue.cancelPendingOrGetRunning((request) => request == 'second')!,
      MobileSessionStartDisposition.cancelled,
    );
    expect(await second, MobileSessionStartDisposition.cancelled);

    releaseFirst.complete();
    expect(await first, MobileSessionStartDisposition.completed);
    expect(executed, ['first']);
  });

  test('closing the running request waits while a newer request is pending',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = MobileSessionStartQueue<String>((request) async {
      executed.add(request);
      if (request == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
    });

    final first = queue.submit('first');
    await firstEntered.future;
    final second = queue.submit('second');
    final firstFinality =
        queue.cancelPendingOrGetRunning((request) => request == 'first');

    expect(firstFinality, isNotNull);
    var firstFinalityCompleted = false;
    unawaited(firstFinality!.then((_) => firstFinalityCompleted = true));
    await Future<void>.delayed(Duration.zero);
    expect(firstFinalityCompleted, isFalse);
    expect(executed, ['first']);

    releaseFirst.complete();
    expect(await firstFinality, MobileSessionStartDisposition.completed);
    expect(await first, MobileSessionStartDisposition.completed);
    expect(await second, MobileSessionStartDisposition.completed);
    expect(executed, ['first', 'second']);
  });

  test('a failed running request does not wedge the bounded successor',
      () async {
    final executed = <String>[];
    final queue = MobileSessionStartQueue<String>((request) async {
      executed.add(request);
      if (request == 'first') {
        throw StateError('expected failure');
      }
    });

    final first = queue.submit('first');
    final second = queue.submit('second');

    await expectLater(first, throwsStateError);
    expect(await second, MobileSessionStartDisposition.completed);
    expect(executed, ['first', 'second']);
  });
}

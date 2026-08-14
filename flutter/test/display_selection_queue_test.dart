import 'dart:async';

import 'package:flutter_hbb/models/display_selection_queue.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('keeps one running display selection and only the latest successor',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = DisplaySelectionQueue('session-a');

    Future<bool> operation(String value) async {
      executed.add(value);
      if (value == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
      return true;
    }

    final first = queue.submit('session-a', () => operation('first'));
    await firstEntered.future;
    final second = queue.submit('session-a', () => operation('second'));
    final third = queue.submit('session-a', () => operation('third'));

    expect(await second, isFalse);
    expect(executed, ['first']);

    releaseFirst.complete();
    expect(await first, isTrue);
    expect(await third, isTrue);
    expect(executed, ['first', 'third']);
  });

  test('a refused display selection does not wedge its bounded successor',
      () async {
    final executed = <String>[];
    final queue = DisplaySelectionQueue('session-a');

    final first = queue.submit('session-a', () async {
      executed.add('first');
      return false;
    });
    final second = queue.submit('session-a', () async {
      executed.add('second');
      return true;
    });

    expect(await first, isFalse);
    expect(await second, isTrue);
    expect(executed, ['first', 'second']);
  });

  test('a failed display selection does not wedge its bounded successor',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = DisplaySelectionQueue('session-a');

    final first = queue.submit('session-a', () async {
      executed.add('first');
      firstEntered.complete();
      await releaseFirst.future;
      throw StateError('expected failure');
    });
    await firstEntered.future;
    final second = queue.submit('session-a', () async {
      executed.add('second');
      return true;
    });

    releaseFirst.complete();
    await expectLater(first, throwsStateError);
    expect(await second, isTrue);
    expect(executed, ['first', 'second']);
  });

  test('a stale owner cannot enter the display selection sequencer', () async {
    var executed = false;
    final queue = DisplaySelectionQueue('session-a');

    final admitted = await queue.submit('session-b', () async {
      executed = true;
      return true;
    });

    expect(admitted, isFalse);
    expect(executed, isFalse);
  });

  test('a retired session cannot block its replacement session', () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final oldFinished = Completer<void>();
    final executed = <String>[];
    final oldQueue = DisplaySelectionQueue('session-a');

    final oldRunning = oldQueue.submit('session-a', () async {
      executed.add('old-running');
      oldEntered.complete();
      await releaseOld.future;
      oldFinished.complete();
      return true;
    });
    await oldEntered.future;
    final oldPending = oldQueue.submit('session-a', () async {
      executed.add('old-pending');
      return true;
    });

    expect(oldQueue.retire('session-b'), isFalse);
    expect(oldQueue.retire('session-a'), isTrue);
    expect(await oldRunning, isFalse);
    expect(await oldPending, isFalse);
    expect(await oldQueue.submit('session-a', () async => true), isFalse);

    final replacementQueue = DisplaySelectionQueue('session-b');
    expect(
        await replacementQueue.submit('session-b', () async {
          executed.add('replacement');
          return true;
        }),
        isTrue);
    expect(executed, ['old-running', 'replacement']);

    releaseOld.complete();
    await oldFinished.future;
    expect(oldQueue.retire('session-a'), isTrue);
    expect(executed, ['old-running', 'replacement']);
  });
}

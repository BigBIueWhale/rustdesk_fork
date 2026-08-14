import 'dart:async';

import 'package:flutter_hbb/models/display_selection_queue.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('keeps one running display selection and only the latest successor',
      () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final executed = <String>[];
    final queue = DisplaySelectionQueue();

    Future<bool> operation(String value) async {
      executed.add(value);
      if (value == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
      return true;
    }

    final first = queue.submit(() => operation('first'));
    await firstEntered.future;
    final second = queue.submit(() => operation('second'));
    final third = queue.submit(() => operation('third'));

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
    final queue = DisplaySelectionQueue();

    final first = queue.submit(() async {
      executed.add('first');
      return false;
    });
    final second = queue.submit(() async {
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
    final queue = DisplaySelectionQueue();

    final first = queue.submit(() async {
      executed.add('first');
      firstEntered.complete();
      await releaseFirst.future;
      throw StateError('expected failure');
    });
    await firstEntered.future;
    final second = queue.submit(() async {
      executed.add('second');
      return true;
    });

    releaseFirst.complete();
    await expectLater(first, throwsStateError);
    expect(await second, isTrue);
    expect(executed, ['first', 'second']);
  });
}

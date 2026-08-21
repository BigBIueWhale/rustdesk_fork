import 'dart:async';

import 'package:flutter_hbb/models/server_status_refresh_loop.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const interval = Duration(milliseconds: 500);

  testWidgets('never overlaps a slow refresh and waits a full interval',
      (tester) async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    var turns = 0;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
        if (turns == 1) {
          firstEntered.complete();
          await releaseFirst.future;
        }
      },
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );

    loop.start();
    await tester.pump();
    await firstEntered.future;
    await tester.pump(const Duration(seconds: 5));
    expect(turns, 1);

    releaseFirst.complete();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 499));
    expect(turns, 1);
    await tester.pump(const Duration(milliseconds: 1));
    expect(turns, 2);
    await loop.close();
  });

  testWidgets('initial readiness is checked once before periodic refresh',
      (tester) async {
    var readinessChecks = 0;
    var turns = 0;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
      },
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );

    loop.start(initialReady: () async {
      readinessChecks += 1;
      return false;
    });
    await tester.pump();
    await tester.pump();
    expect(readinessChecks, 1);
    expect(turns, 0);

    await tester.pump(interval);
    expect(readinessChecks, 1);
    expect(turns, 1);
    await loop.close();
  });

  testWidgets('a failed turn is visible and does not wedge later turns',
      (tester) async {
    final errors = <Object>[];
    var turns = 0;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
        if (turns == 1) {
          throw StateError('expected failure');
        }
      },
      onError: (error, stackTrace) => errors.add(error),
    );

    loop.start();
    await tester.pump();
    await tester.pump();
    expect(turns, 1);
    expect(errors, hasLength(1));
    expect(errors.single, isA<StateError>());

    await tester.pump(interval);
    expect(turns, 2);
    await loop.close();
  });

  testWidgets('close drains the active turn and prevents rearming',
      (tester) async {
    final entered = Completer<void>();
    final release = Completer<void>();
    var turns = 0;
    var closeCompleted = false;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
        entered.complete();
        await release.future;
      },
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );

    loop.start();
    await tester.pump();
    await entered.future;
    final close = loop.close();
    unawaited(close.then((_) => closeCompleted = true));
    await tester.pump();
    expect(closeCompleted, isFalse);

    release.complete();
    await tester.pump();
    await close;
    expect(closeCompleted, isTrue);
    await tester.pump(const Duration(seconds: 5));
    expect(turns, 1);
  });

  testWidgets('refuses duplicate start and restart after close',
      (tester) async {
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {},
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );

    loop.start();
    expect(loop.start, throwsStateError);
    await tester.pump();
    await loop.close();
    expect(loop.start, throwsStateError);
  });
}

import 'dart:async';

import 'package:flutter_hbb/models/server_status_refresh_loop.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const interval = Duration(milliseconds: 500);

  testWidgets('close waits for readiness without admitting a refresh',
      (tester) async {
    final ready = Completer<bool>();
    var turns = 0;
    var closed = false;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
      },
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );
    loop.start(initialReady: () => ready.future);
    await tester.pump(Duration.zero);
    final closing = loop.close().then((_) => closed = true);
    await tester.pump();
    final closedWhilePending = closed;
    ready.complete(true);
    await tester.pump();
    await closing;
    await tester.pump(const Duration(seconds: 5));
    expect(closedWhilePending, isFalse);
    expect(closed, isTrue);
    expect(turns, 0);
  });

  for (final phase in ['readiness', 'refresh']) {
    testWidgets('reentrant close drains the accepted $phase turn',
        (tester) async {
      final release = Completer<void>();
      var closed = false;
      Future<void>? closing;
      late ServerStatusRefreshLoop loop;
      Future<void> retire() async {
        closing = loop.close().then((_) => closed = true);
        await release.future;
      }

      loop = ServerStatusRefreshLoop(
        interval: interval,
        refresh: phase == 'refresh' ? retire : () async {},
        onError: (error, stackTrace) => fail('unexpected error: $error'),
      );
      loop.start(
        initialReady: phase == 'readiness'
            ? () async {
                await retire();
                return true;
              }
            : null,
      );
      await tester.pump(Duration.zero);
      final closedWhilePending = closed;
      release.complete();
      await tester.pump();
      await closing;
      await tester.pump(const Duration(seconds: 5));
      expect(closing, isNotNull);
      expect(closedWhilePending, isFalse);
      expect(closed, isTrue);
    });
  }

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
    await tester.pump(Duration.zero);
    expect(firstEntered.isCompleted, isTrue);
    await tester.pump(const Duration(seconds: 5));
    expect(turns, 1);

    releaseFirst.complete();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 499));
    expect(turns, 1);
    await tester.pump(const Duration(milliseconds: 1));
    expect(turns, 2);
    await tester.pump();
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
    await tester.pump(Duration.zero);
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
    await tester.pump(Duration.zero);
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
    await tester.pump(Duration.zero);
    expect(entered.isCompleted, isTrue);
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

  testWidgets('close cancels the deferred first turn before it begins',
      (tester) async {
    var turns = 0;
    final loop = ServerStatusRefreshLoop(
      interval: interval,
      refresh: () async {
        turns += 1;
      },
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );

    loop.start();
    await loop.close();
    await tester.pump(Duration.zero);
    expect(turns, 0);
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
    await tester.pump(Duration.zero);
    await tester.pump();
    await loop.close();
    expect(loop.start, throwsStateError);
  });
}

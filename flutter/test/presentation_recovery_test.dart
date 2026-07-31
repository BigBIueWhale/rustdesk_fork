import 'dart:async';

import 'package:flutter_hbb/models/presentation_recovery.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('initial and duplicate resume notifications do not request a refresh',
      () async {
    final recovery = PresentationRecovery();
    var refreshes = 0;

    Future<void> resume() => recovery.resume(
          selected: true,
          refresh: () async => refreshes += 1,
          onError: (error, stackTrace) => fail('unexpected refresh failure'),
        );

    await resume();
    await resume();

    expect(refreshes, 0);
  });

  test('one suspended presentation produces one refresh', () async {
    final recovery = PresentationRecovery();
    var refreshes = 0;

    recovery.suspend();
    await recovery.resume(
      selected: true,
      refresh: () async => refreshes += 1,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    await recovery.resume(
      selected: true,
      refresh: () async => refreshes += 1,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );

    expect(refreshes, 1);
  });

  test('a hidden desktop tab retains recovery until it is selected', () async {
    final recovery = PresentationRecovery();
    var refreshes = 0;

    recovery.suspend();
    await recovery.resume(
      selected: false,
      refresh: () async => refreshes += 1,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    expect(refreshes, 0);

    await recovery.resume(
      selected: true,
      refresh: () async => refreshes += 1,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    expect(refreshes, 1);
  });

  test('a failed refresh is rearmed for a later resume transition', () async {
    final recovery = PresentationRecovery();
    var attempts = 0;
    final errors = <Object>[];

    recovery.suspend();
    await recovery.resume(
      selected: true,
      refresh: () async {
        attempts += 1;
        throw StateError('expected');
      },
      onError: (error, stackTrace) => errors.add(error),
    );
    expect(attempts, 1);
    expect(errors, hasLength(1));

    await recovery.resume(
      selected: true,
      refresh: () async => attempts += 1,
      onError: (error, stackTrace) => fail('unexpected second failure'),
    );
    expect(attempts, 2);
  });

  test('suspend and resume during a request preserve one follow-up refresh',
      () async {
    final recovery = PresentationRecovery();
    final firstRefresh = Completer<void>();
    var refreshes = 0;

    Future<void> refresh() async {
      refreshes += 1;
      if (refreshes == 1) {
        await firstRefresh.future;
      }
    }

    recovery.suspend();
    final firstResume = recovery.resume(
      selected: true,
      refresh: refresh,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    expect(refreshes, 1);

    recovery.suspend();
    await recovery.resume(
      selected: true,
      refresh: refresh,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    expect(refreshes, 1);

    firstRefresh.complete();
    await firstResume;
    expect(refreshes, 2);
  });

  test('retirement cancels pending and in-flight follow-up recovery', () async {
    final recovery = PresentationRecovery();
    final firstRefresh = Completer<void>();
    var refreshes = 0;

    recovery.suspend();
    final firstResume = recovery.resume(
      selected: true,
      refresh: () async {
        refreshes += 1;
        await firstRefresh.future;
      },
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );
    recovery.suspend();
    recovery.retire();
    firstRefresh.complete();
    await firstResume;
    await recovery.resume(
      selected: true,
      refresh: () async => refreshes += 1,
      onError: (error, stackTrace) => fail('unexpected refresh failure'),
    );

    expect(refreshes, 1);
  });

  test('retirement still reports an in-flight refresh failure', () async {
    final recovery = PresentationRecovery();
    final firstRefresh = Completer<void>();
    final errors = <Object>[];

    recovery.suspend();
    final resume = recovery.resume(
      selected: true,
      refresh: () => firstRefresh.future,
      onError: (error, stackTrace) => errors.add(error),
    );
    recovery.retire();
    firstRefresh.completeError(StateError('expected'));
    await resume;

    expect(errors, hasLength(1));
  });
}

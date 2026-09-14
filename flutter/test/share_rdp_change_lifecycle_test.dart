import 'dart:async';

import 'package:flutter_hbb/models/share_rdp_change_lifecycle.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('r_s11ir duplicate UI actions share one synchronous request latch',
      () async {
    final release = Completer<void>();
    final applied = <bool>[];
    final states = <bool>[];
    final lifecycle = ShareRdpChangeLifecycle();

    Future<void> apply(bool enabled) async {
      applied.add(enabled);
      await release.future;
    }

    final first = lifecycle.request(
      enabled: true,
      apply: apply,
      isMounted: () => true,
      notifyChanged: () => states.add(lifecycle.pending),
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );
    expect(lifecycle.pending, isTrue);

    await lifecycle.request(
      enabled: false,
      apply: apply,
      isMounted: () => true,
      notifyChanged: () => states.add(lifecycle.pending),
      onError: (error, stackTrace) => fail('unexpected error: $error'),
    );
    expect(applied, [true]);
    expect(states, [true]);

    release.complete();
    await first;
    expect(lifecycle.pending, isFalse);
    expect(states, [true, false]);
  });

  test('r_s11ir failure is visible before the mounted latch is released',
      () async {
    final events = <String>[];
    final lifecycle = ShareRdpChangeLifecycle();

    await lifecycle.request(
      enabled: true,
      apply: (_) async => throw StateError('expected failure'),
      isMounted: () => true,
      notifyChanged: () => events.add(lifecycle.pending ? 'pending' : 'idle'),
      onError: (error, stackTrace) {
        expect(lifecycle.pending, isTrue);
        expect(error, isA<StateError>());
        events.add('error');
      },
    );

    expect(lifecycle.pending, isFalse);
    expect(events, ['pending', 'error', 'idle']);
  });

  test('r_s11ir an unmounted owner receives no late UI callback', () async {
    final release = Completer<void>();
    var mounted = true;
    var notifications = 0;
    var errors = 0;
    final lifecycle = ShareRdpChangeLifecycle();

    final request = lifecycle.request(
      enabled: true,
      apply: (_) async {
        await release.future;
        throw StateError('expected after unmount');
      },
      isMounted: () => mounted,
      notifyChanged: () => notifications += 1,
      onError: (error, stackTrace) => errors += 1,
    );
    expect(lifecycle.pending, isTrue);
    expect(notifications, 1);

    mounted = false;
    release.complete();
    await request;
    expect(notifications, 1);
    expect(errors, 0);
  });
}

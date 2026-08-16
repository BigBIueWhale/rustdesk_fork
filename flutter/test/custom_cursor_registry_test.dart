import 'dart:async';

import 'package:flutter_hbb/models/custom_cursor_registry.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('activation queue preserves issue order across asynchronous turns',
      () async {
    final queue = CustomCursorActivationQueue();
    final firstMayFinish = Completer<void>();
    final order = <String>[];
    final first = queue.schedule(() async {
      order.add('first-start');
      await firstMayFinish.future;
      order.add('first-finish');
    });
    final second = queue.schedule(() async {
      order.add('second');
    });

    await Future<void>.delayed(Duration.zero);
    expect(order, ['first-start']);
    firstMayFinish.complete();
    await Future.wait([first, second]);
    expect(order, ['first-start', 'first-finish', 'second']);
  });

  test('replacement owns display before old lease deletion', () async {
    final queue = CustomCursorActivationQueue();
    final coordinator =
        CustomCursorPresentationCoordinator(activations: queue);
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);
    final order = <String>[];

    CustomCursorHandle add(String owner) => registry.ensure(
      owner: owner,
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async => order.add('delete-$owner'),
    )!;

    CustomCursorPresentationToken token(String name) =>
        CustomCursorPresentationToken(
          coordinator: coordinator,
          fallback: () async => order.add('fallback-$name'),
          onError: (_, __) => fail('presentation unexpectedly failed'),
        );

    final first = token('first');
    final firstLease = add('first').acquire()!;
    expect(
      await first.activate(
        firstLease,
        () => true,
        (_) async => order.add('present-first'),
      ),
      isTrue,
    );
    registry.retireOwner('first');

    final second = token('second');
    final secondLease = add('second').acquire()!;
    expect(
      await second.activate(
        secondLease,
        () => true,
        (_) async => order.add('present-second'),
      ),
      isTrue,
    );
    await Future<void>.delayed(Duration.zero);
    expect(order, ['present-first', 'present-second', 'delete-first']);

    // Disposing the stale session must not reset the newer displayed cursor.
    await first.retire();
    expect(order, ['present-first', 'present-second', 'delete-first']);

    registry.retireOwner('second');
    await second.retire();
    await Future<void>.delayed(Duration.zero);
    expect(order, [
      'present-first',
      'present-second',
      'delete-first',
      'fallback-second',
      'delete-second',
    ]);
  });

  test('slow obsolete registration cannot block a newer activation',
      () async {
    final coordinator = CustomCursorPresentationCoordinator(
        activations: CustomCursorActivationQueue());
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);
    final slowRegistration = Completer<bool>();
    final presented = <String>[];
    final slowHandle = registry.ensure(
      owner: 'slow',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) => slowRegistration.future,
      delete: (_) async {},
    )!;
    final currentHandle = registry.ensure(
      owner: 'current',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async {},
    )!;
    CustomCursorPresentationToken token() => CustomCursorPresentationToken(
          coordinator: coordinator,
          fallback: () async {},
          onError: (_, __) => fail('presentation unexpectedly failed'),
        );
    final slow = token();
    final current = token();
    final slowActivation = slow.activate(
      slowHandle.acquire()!,
      () => true,
      (_) async => presented.add('slow'),
    );

    expect(
      await current.activate(
        currentHandle.acquire()!,
        () => true,
        (_) async => presented.add('current'),
      ),
      isTrue,
    );
    expect(presented, ['current']);
    slowRegistration.complete(true);
    expect(await slowActivation, isFalse);
    expect(presented, ['current']);

    registry.retireOwner('slow');
    registry.retireOwner('current');
    await slow.retire();
    await current.retire();
  });

  test('failed desired registration falls back before old lease deletion',
      () async {
    final order = <String>[];
    final coordinator = CustomCursorPresentationCoordinator(
        activations: CustomCursorActivationQueue());
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);
    final currentHandle = registry.ensure(
      owner: 'current',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async => order.add('delete-current'),
    )!;
    final failedHandle = registry.ensure(
      owner: 'failed',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => false,
      delete: (_) async => order.add('delete-failed'),
    )!;
    final current = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async => order.add('fallback-current'),
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    final failed = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async => order.add('fallback-failed'),
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    expect(
      await current.activate(
        currentHandle.acquire()!,
        () => true,
        (_) async => order.add('present-current'),
      ),
      isTrue,
    );
    registry.retireOwner('current');
    expect(
      await failed.activate(
        failedHandle.acquire()!,
        () => true,
        (_) async => order.add('present-failed'),
      ),
      isFalse,
    );
    await Future<void>.delayed(Duration.zero);
    expect(order, [
      'present-current',
      'fallback-failed',
      'delete-current',
    ]);
    expect(registry.ownerEntryCount('failed'), 0);
    await current.retire();
    await failed.retire();
  });

  test('failed fallback retains the possibly displayed lease', () async {
    final errors = <Object>[];
    final deleted = <String>[];
    final coordinator = CustomCursorPresentationCoordinator(
        activations: CustomCursorActivationQueue());
    final registry = CustomCursorRegistry(maxEntries: 1, maxRgbaBytes: 4);
    final handle = registry.ensure(
      owner: 'owner',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (key) async => deleted.add(key),
    )!;
    final current = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async {},
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    expect(
      await current.activate(handle.acquire()!, () => true, (_) async {}),
      isTrue,
    );
    registry.retireOwner('owner');

    final failing = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async => throw StateError('reset failed'),
      onError: (error, _) => errors.add(error),
    );
    await failing.activateFallback(() => true);
    await Future<void>.delayed(Duration.zero);
    expect(errors.single, isA<StateError>());
    expect(deleted, isEmpty);

    final succeeding = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async {},
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    await succeeding.activateFallback(() => true);
    await Future<void>.delayed(Duration.zero);
    expect(deleted, hasLength(1));
    await current.retire();
    await failing.retire();
    await succeeding.retire();
  });

  test('partial presentation failure retains both possible displays',
      () async {
    final errors = <Object>[];
    final deleted = <String>[];
    final coordinator = CustomCursorPresentationCoordinator(
        activations: CustomCursorActivationQueue());
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);

    CustomCursorHandle add(String owner) => registry.ensure(
          owner: owner,
          logicalKey: 'cursor',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (key) async => deleted.add(key),
        )!;

    final current = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async {},
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    expect(
      await current.activate(add('current').acquire()!, () => true, (_) async {}),
      isTrue,
    );
    registry.retireOwner('current');

    final uncertain = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async => throw StateError('reset failed'),
      onError: (error, _) => errors.add(error),
    );
    expect(
      await uncertain.activate(
        add('uncertain').acquire()!,
        () => true,
        (_) async => throw StateError('presentation outcome unknown'),
      ),
      isTrue,
    );
    registry.retireOwner('uncertain');
    expect(errors, hasLength(2));
    expect(deleted, isEmpty);

    final reset = CustomCursorPresentationToken(
      coordinator: coordinator,
      fallback: () async {},
      onError: (_, __) => fail('presentation unexpectedly failed'),
    );
    await reset.activateFallback(() => true);
    await Future<void>.delayed(Duration.zero);
    expect(deleted, hasLength(2));
    await current.retire();
    await uncertain.retire();
    await reset.retire();
  });

  test('bounds count and bytes with deterministic inactive LRU eviction',
      () async {
    final registered = <String>[];
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);

    CustomCursorHandle? add(String key, int bytes) => registry.ensure(
          owner: 'owner',
          logicalKey: key,
          rgbaBytes: bytes,
          register: (platformKey) async {
            registered.add(platformKey);
            return true;
          },
          delete: (platformKey) async {
            deleted.add(platformKey);
          },
        );

    final first = add('first', 4)!;
    add('second', 4)!;
    expect(registry.ownerEntryCount('owner'), 2);
    expect(registry.ownerRgbaBytes('owner'), 8);
    expect(registry.entryCount, 2);
    expect(registry.rgbaBytes, 8);

    // Touch first; second is now the least-recently-used inactive entry.
    final touch = first.acquire();
    expect(touch, isNotNull);
    touch!.release();
    add('third', 4)!;
    await Future<void>.delayed(Duration.zero);
    expect(registry.ownerEntryCount('owner'), 2);
    expect(registry.ownerRgbaBytes('owner'), 8);
    expect(registered, hasLength(3));
    expect(deleted.single, contains('_second_'));
  });

  test('entry and byte limits are global across UI owners', () async {
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);

    CustomCursorHandle add(String owner) => registry.ensure(
          owner: owner,
          logicalKey: 'cursor',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (key) async => deleted.add(key),
        )!;

    final first = add('first');
    add('second');
    final touch = first.acquire()!;
    touch.release();
    add('third');
    await Future<void>.delayed(Duration.zero);
    expect(registry.entryCount, 2);
    expect(registry.rgbaBytes, 8);
    expect(registry.ownerCount, 2);
    expect(registry.ownerEntryCount('first'), 1);
    expect(registry.ownerEntryCount('second'), 0);
    expect(registry.ownerEntryCount('third'), 1);
    expect(deleted.single, contains('second'));
  });

  test('never evicts an active platform cursor and refuses excess capacity',
      () async {
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 1, maxRgbaBytes: 4);
    final handle = registry.ensure(
      owner: 'owner',
      logicalKey: 'active',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (key) async => deleted.add(key),
    )!;
    final lease = handle.acquire()!;
    for (var i = 0; i < 32; i += 1) {
      expect(
        registry.ensure(
          owner: 'refused-$i',
          logicalKey: 'refused',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (_) async {},
        ),
        isNull,
      );
    }
    expect(registry.ownerCount, 1);
    expect(deleted, isEmpty);
    lease.release();
    expect(
        registry.ensure(
          owner: 'owner',
          logicalKey: 'replacement',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (key) async => deleted.add(key),
        ),
        isNotNull);
    await Future<void>.delayed(Duration.zero);
    expect(deleted, hasLength(1));
  });

  test('pending registration remains globally accounted until finality',
      () async {
    final registration = Completer<bool>();
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 1, maxRgbaBytes: 4);
    registry.ensure(
      owner: 'pending',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) => registration.future,
      delete: (key) async => deleted.add(key),
    );
    registry.retireOwner('pending');

    for (var i = 0; i < 32; i += 1) {
      expect(
        registry.ensure(
          owner: 'refused-$i',
          logicalKey: 'cursor',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (_) async {},
        ),
        isNull,
      );
    }
    expect(registry.entryCount, 1);
    expect(registry.rgbaBytes, 4);
    expect(registry.ownerCount, 1);
    expect(deleted, isEmpty);

    registration.complete(true);
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(registry.entryCount, 0);
    expect(registry.rgbaBytes, 0);
    expect(registry.ownerCount, 0);
    expect(deleted, hasLength(1));
  });

  test('retirement waits for registration and the final exact lease', () async {
    final registration = Completer<bool>();
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 2, maxRgbaBytes: 8);
    final handle = registry.ensure(
      owner: 'owner',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) => registration.future,
      delete: (key) async => deleted.add(key),
    )!;
    final lease = handle.acquire()!;
    registry.retireOwner('owner');
    expect(registry.ownerEntryCount('owner'), 1);
    expect(handle.acquire(), isNull);
    registration.complete(true);
    await Future<void>.delayed(Duration.zero);
    expect(deleted, isEmpty);
    lease.release();
    await Future<void>.delayed(Duration.zero);
    expect(registry.ownerEntryCount('owner'), 0);
    expect(deleted, hasLength(1));
  });

  test('failed registration releases capacity without invoking delete',
      () async {
    final deleted = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 1, maxRgbaBytes: 4);
    final failed = registry.ensure(
      owner: 'owner',
      logicalKey: 'failed',
      rgbaBytes: 4,
      register: (_) async => false,
      delete: (key) async => deleted.add(key),
    )!;
    final lease = failed.acquire()!;
    expect(await lease.ready, isFalse);
    lease.release();
    await Future<void>.delayed(Duration.zero);
    expect(registry.ownerEntryCount('owner'), 0);
    expect(deleted, isEmpty);
  });

  test('uncertain registration attempts exact cleanup and fails closed',
      () async {
    final errors = <String>[];
    final deleted = <String>[];
    final registry = CustomCursorRegistry(
      maxEntries: 1,
      maxRgbaBytes: 4,
      onError: (operation, _, __) => errors.add(operation),
    );
    final handle = registry.ensure(
      owner: 'owner',
      logicalKey: 'cursor',
      rgbaBytes: 4,
      register: (_) async => throw StateError('registration uncertain'),
      delete: (key) async => deleted.add(key),
    )!;
    final lease = handle.acquire()!;
    expect(await lease.ready, isFalse);
    lease.release();
    await Future<void>.delayed(Duration.zero);
    expect(errors.single, contains('register'));
    expect(deleted, [handle.platformKey]);
    expect(
      registry.ensure(
        owner: 'later',
        logicalKey: 'cursor',
        rgbaBytes: 4,
        register: (_) async => true,
        delete: (_) async {},
      ),
      isNull,
    );
  });

  test('replacement registration waits for exact eviction deletion',
      () async {
    final deletionStarted = Completer<void>();
    final allowDeletion = Completer<void>();
    final registered = <String>[];
    final registry = CustomCursorRegistry(maxEntries: 1, maxRgbaBytes: 4);

    CustomCursorHandle add(String logicalKey) => registry.ensure(
          owner: 'owner',
          logicalKey: logicalKey,
          rgbaBytes: 4,
          register: (platformKey) async {
            registered.add(platformKey);
            return true;
          },
          delete: (_) async {
            deletionStarted.complete();
            await allowDeletion.future;
          },
        )!;

    final first = add('first');
    final firstLease = first.acquire()!;
    expect(await firstLease.ready, isTrue);
    firstLease.release();
    final replacement = add('replacement');
    await deletionStarted.future;
    expect(registered, hasLength(1));
    allowDeletion.complete();
    final lease = replacement.acquire()!;
    expect(await lease.ready, isTrue);
    expect(registered, hasLength(2));
    lease.release();
  });

  test('uncertain deletion fails closed for all later registrations',
      () async {
    final errors = <String>[];
    final registry = CustomCursorRegistry(
      maxEntries: 1,
      maxRgbaBytes: 4,
      onError: (operation, _, __) => errors.add(operation),
    );
    final first = registry.ensure(
      owner: 'owner',
      logicalKey: 'first',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async => throw StateError('deletion uncertain'),
    )!;
    final firstLease = first.acquire()!;
    expect(await firstLease.ready, isTrue);
    firstLease.release();

    final replacement = registry.ensure(
      owner: 'owner',
      logicalKey: 'replacement',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async {},
    )!;
    final replacementLease = replacement.acquire()!;
    expect(await replacementLease.ready, isFalse);
    replacementLease.release();
    expect(errors.single, contains('delete'));
    expect(
        registry.ensure(
          owner: 'other-owner',
          logicalKey: 'later',
          rgbaBytes: 4,
          register: (_) async => true,
          delete: (_) async {},
        ),
        isNull);
  });

  test('throwing presentation diagnostics cannot interrupt fallback finality',
      () async {
    final registry = CustomCursorRegistry();
    final handle = registry.ensure(
      owner: 'presentation-reporting',
      logicalKey: 'shape',
      rgbaBytes: 4,
      register: (_) async => true,
      delete: (_) async {},
    )!;
    final lease = handle.acquire()!;
    final coordinator = CustomCursorPresentationCoordinator(
      activations: CustomCursorActivationQueue(),
    );
    final errors = <Object>[];

    await (runZonedGuarded<Future<void>>(() async {
          final presented = await coordinator.activate(
            presenter: Object(),
            lease: lease,
            mayPresent: () => true,
            present: (_) async => throw StateError('presentation failed'),
            fallback: () async {},
            onError: (_, __) => throw StateError('reporting failed'),
          );
          expect(presented, isFalse);
          await Future<void>.delayed(Duration.zero);
        }, (error, _) => errors.add(error)) ??
        Future<void>.value());

    expect(errors, hasLength(1));
    registry.retireOwner('presentation-reporting');
    await Future<void>.delayed(Duration.zero);
    expect(registry.entryCount, 0);
  });

  test('throwing registry diagnostics cannot strand registration finality',
      () async {
    final registry = CustomCursorRegistry(
      onError: (_, __, ___) => throw StateError('reporting failed'),
    );
    final errors = <Object>[];

    await (runZonedGuarded<Future<void>>(() async {
          final handle = registry.ensure(
            owner: 'registration-reporting',
            logicalKey: 'shape',
            rgbaBytes: 4,
            register: (_) async => throw StateError('registration failed'),
            delete: (_) async {},
          )!;
          final lease = handle.acquire()!;
          expect(await lease.ready, isFalse);
          lease.release();
          registry.retireOwner('registration-reporting');
          await Future<void>.delayed(Duration.zero);
        }, (error, _) => errors.add(error)) ??
        Future<void>.value());

    expect(errors, hasLength(1));
    expect(registry.entryCount, 0);
  });
}

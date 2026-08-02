import 'dart:async';

import 'package:flutter_hbb/models/desktop_texture_lifecycle.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeTexture implements RetirableDesktopTexture {
  _FakeTexture({
    this.activationBarrier,
    this.retirementBarrier,
    this.activationResult = true,
  });

  final Completer<bool>? activationBarrier;
  final Completer<void>? retirementBarrier;
  final bool activationResult;
  int activateCalls = 0;
  int retireCalls = 0;

  @override
  Future<bool> activate() async {
    activateCalls += 1;
    if (activationBarrier != null) {
      return activationBarrier!.future;
    }
    return activationResult;
  }

  @override
  Future<void> retire() async {
    retireCalls += 1;
    if (retirementBarrier != null) {
      await retirementBarrier!.future;
    }
  }
}

void main() {
  test('retirement before initialization completes prevents late publication',
      () async {
    final initialized = Completer<bool>();
    final events = <String>[];
    final errors = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () => initialized.future,
      publish: () => events.add('publish'),
      unpublish: () => events.add('unpublish'),
      release: () async => events.add('release'),
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    final activation = lifecycle.activate();
    final retirement = lifecycle.retire();
    initialized.complete(true);
    await retirement;

    expect(await activation, isFalse);
    expect(events, ['release']);
    expect(errors, isEmpty);
  });

  test('published texture is unpublished before one exact release', () async {
    final events = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () async {
        events.add('initialize');
        return true;
      },
      publish: () => events.add('publish'),
      unpublish: () => events.add('unpublish'),
      release: () async => events.add('release'),
      onError: (operation, error, stackTrace) =>
          fail('unexpected $operation error: $error'),
    );

    expect(await lifecycle.activate(), isTrue);
    final first = lifecycle.retire();
    final second = lifecycle.retire();

    expect(identical(first, second), isTrue);
    await first;
    expect(events, ['initialize', 'publish', 'unpublish', 'release']);
  });

  test('initialization failure is reported and the allocation is released',
      () async {
    final events = <String>[];
    final errors = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () async => throw StateError('expected'),
      publish: () => events.add('publish'),
      unpublish: () => events.add('unpublish'),
      release: () async => events.add('release'),
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    expect(await lifecycle.activate(), isFalse);
    await lifecycle.retire();

    expect(errors, ['initialize']);
    expect(events, ['release']);
  });

  test('rejected initialization is reported and the allocation is released',
      () async {
    final events = <String>[];
    final errors = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () async => false,
      publish: () => events.add('publish'),
      unpublish: () => events.add('unpublish'),
      release: () async => events.add('release'),
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    expect(await lifecycle.activate(), isFalse);
    await lifecycle.retire();

    expect(errors, ['initialize']);
    expect(events, ['release']);
  });

  test('failed publication is unpublished and released immediately', () async {
    final events = <String>[];
    final errors = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () async => true,
      publish: () {
        events.add('publish');
        throw StateError('expected');
      },
      unpublish: () => events.add('unpublish'),
      release: () async => events.add('release'),
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    expect(await lifecycle.activate(), isFalse);
    await lifecycle.retire();

    expect(errors, ['publish']);
    expect(events, ['publish', 'unpublish', 'release']);
  });

  test('unpublication failure cannot prevent exact release', () async {
    final events = <String>[];
    final errors = <String>[];
    final lifecycle = DesktopTextureLifecycle(
      initialize: () async => true,
      publish: () => events.add('publish'),
      unpublish: () {
        events.add('unpublish');
        throw StateError('expected unpublish failure');
      },
      release: () async {
        events.add('release');
        throw StateError('expected release failure');
      },
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    expect(await lifecycle.activate(), isTrue);
    await lifecycle.retire();
    await lifecycle.retire();

    expect(errors, ['unpublish', 'release']);
    expect(events, ['publish', 'unpublish', 'release']);
  });

  test('failed slot creation is bounded and a later demand can retry',
      () async {
    final created = <_FakeTexture>[];
    final errors = <String>[];
    var attempts = 0;
    final slot = LatestDesktopTextureSlot<_FakeTexture>(
      create: () {
        attempts += 1;
        if (attempts == 1) {
          throw StateError('expected');
        }
        final texture = _FakeTexture();
        created.add(texture);
        return texture;
      },
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    slot.setWanted(true);
    await slot.drain();
    expect(attempts, 1);
    expect(created, isEmpty);
    expect(errors, ['create']);

    slot.setWanted(false);
    await slot.drain();
    slot.setWanted(true);
    await slot.drain();
    expect(attempts, 2);
    expect(created, hasLength(1));

    await slot.dispose();
    expect(created.single.retireCalls, 1);
  });

  test('failed asynchronous activation is retired and retry is bounded',
      () async {
    final created = <_FakeTexture>[];
    final errors = <String>[];
    final slot = LatestDesktopTextureSlot<_FakeTexture>(
      create: () {
        final texture = _FakeTexture(
          activationResult: created.isNotEmpty,
        );
        created.add(texture);
        return texture;
      },
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    slot.setWanted(true);
    await slot.drain();
    expect(created, hasLength(1));
    expect(created.single.activateCalls, 1);
    expect(created.single.retireCalls, 1);
    expect(slot.hasCurrent, isFalse);
    expect(slot.wanted, isTrue);

    // Draining the same failed demand must not become a retry loop.
    await slot.drain();
    expect(created, hasLength(1));

    slot.setWanted(false);
    await slot.drain();
    slot.setWanted(true);
    await slot.drain();
    expect(created, hasLength(2));
    expect(created.last.activateCalls, 1);
    expect(created.last.retireCalls, 0);
    expect(slot.hasCurrent, isTrue);
    expect(errors, isEmpty);

    await slot.dispose();
    expect(created.last.retireCalls, 1);
  });

  test('new demand during failed activation receives a fresh exact attempt',
      () async {
    final firstActivation = Completer<bool>();
    final created = <_FakeTexture>[];
    final errors = <String>[];
    final slot = LatestDesktopTextureSlot<_FakeTexture>(
      create: () {
        final texture = _FakeTexture(
          activationBarrier: created.isEmpty ? firstActivation : null,
        );
        created.add(texture);
        return texture;
      },
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    slot.setWanted(true);
    await Future<void>.delayed(Duration.zero);
    expect(created, hasLength(1));
    expect(created.single.activateCalls, 1);

    slot.setWanted(false);
    slot.setWanted(true);
    firstActivation.complete(false);
    await slot.drain();

    expect(created, hasLength(2));
    expect(created.first.retireCalls, 1);
    expect(created.last.activateCalls, 1);
    expect(created.last.retireCalls, 0);
    expect(slot.hasCurrent, isTrue);
    expect(errors, isEmpty);

    await slot.dispose();
    expect(created.last.retireCalls, 1);
  });

  test('replacement waits for exact predecessor retirement', () async {
    final predecessorBarrier = Completer<void>();
    final created = <_FakeTexture>[];
    final errors = <String>[];
    final slot = LatestDesktopTextureSlot<_FakeTexture>(
      create: () {
        final Completer<void> barrier;
        if (created.isEmpty) {
          barrier = predecessorBarrier;
        } else {
          barrier = Completer<void>()..complete();
        }
        final texture = _FakeTexture(retirementBarrier: barrier);
        created.add(texture);
        return texture;
      },
      onError: (operation, error, stackTrace) => errors.add(operation),
    );

    slot.setWanted(true);
    await slot.drain();
    expect(created, hasLength(1));

    slot.setWanted(false);
    slot.setWanted(true);
    await Future<void>.delayed(Duration.zero);
    expect(created, hasLength(1));
    expect(created.single.retireCalls, 1);

    predecessorBarrier.complete();
    await slot.drain();
    expect(created, hasLength(2));
    expect(slot.hasCurrent, isTrue);
    expect(errors, isEmpty);

    await slot.dispose();
    expect(created.last.retireCalls, 1);
    expect(slot.hasCurrent, isFalse);
  });
}

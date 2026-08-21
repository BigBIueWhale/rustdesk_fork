import 'dart:async';

import 'package:flutter_hbb/models/global_event_dispatcher.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('runs admitted events in FIFO order without handler overlap', () async {
    final firstEntered = Completer<void>();
    final releaseFirst = Completer<void>();
    final order = <String>[];
    var active = 0;
    var maximumActive = 0;
    final diagnostics = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => diagnostics.add(error),
    );
    dispatcher.replaceFallback((event) async {
      active += 1;
      maximumActive = active > maximumActive ? active : maximumActive;
      final value = event['value'] as String;
      order.add('$value-enter');
      if (value == 'first') {
        firstEntered.complete();
        await releaseFirst.future;
      }
      order.add('$value-exit');
      active -= 1;
    }, onFailure: (error, stackTrace) => fail('unexpected failure: $error'));

    expect(dispatcher.dispatch('{"value":"first"}'), isTrue);
    expect(dispatcher.dispatch('{"value":"second"}'), isTrue);
    await firstEntered.future;
    expect(order, ['first-enter']);
    expect(dispatcher.pendingCount, 1);

    releaseFirst.complete();
    await dispatcher.idle();
    expect(order,
        ['first-enter', 'first-exit', 'second-enter', 'second-exit']);
    expect(maximumActive, 1);
    expect(dispatcher.hasRunning, isFalse);
    expect(dispatcher.retainedBytes, 0);
    expect(diagnostics, isEmpty);
  });

  test('replacement retires old pending work without migrating its event',
      () async {
    final oldEvents = <String>[];
    final newEvents = <String>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    final oldGeneration = dispatcher.replaceFallback((event) async {
      oldEvents.add(event['value'] as String);
    }, onFailure: (error, stackTrace) => fail('unexpected old failure'));

    expect(dispatcher.dispatch('{"value":"stale"}'), isTrue);
    final newGeneration = dispatcher.replaceFallback((event) async {
      newEvents.add(event['value'] as String);
    }, onFailure: (error, stackTrace) => fail('unexpected new failure'));
    expect(newGeneration, greaterThan(oldGeneration));
    expect(dispatcher.dispatch('{"value":"current"}'), isTrue);

    await dispatcher.idle();
    expect(oldEvents, isEmpty);
    expect(newEvents, ['current']);
    expect(dispatcher.retainedBytes, 0);
    expect(dispatcher.retireFallback(oldGeneration), isFalse);
    expect(dispatcher.retireFallback(newGeneration), isTrue);
  });

  test('active old work settles before replacement work and never overlaps',
      () async {
    final oldEntered = Completer<void>();
    final releaseOld = Completer<void>();
    final order = <String>[];
    final diagnostics = <Object>[];
    final replacementFailures = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => diagnostics.add(error),
    );
    dispatcher.replaceFallback((event) async {
      order.add('old-enter');
      oldEntered.complete();
      await releaseOld.future;
      order.add('old-exit');
      throw StateError('expected retired-owner failure');
    }, onFailure: (error, stackTrace) => fail('unexpected old failure'));
    dispatcher.dispatch('{"value":"old"}');
    await oldEntered.future;

    dispatcher.replaceFallback((event) async {
      order.add('new');
    }, onFailure: (error, stackTrace) => replacementFailures.add(error));
    dispatcher.dispatch('{"value":"new"}');
    expect(order, ['old-enter']);

    releaseOld.complete();
    await dispatcher.idle();
    expect(order, ['old-enter', 'old-exit', 'new']);
    expect(diagnostics, hasLength(1));
    expect(diagnostics.single, isA<StateError>());
    expect(replacementFailures, isEmpty);
  });

  test('fallback overflow fails once, retires pending work, and recovers',
      () async {
    final entered = Completer<void>();
    final release = Completer<void>();
    final failures = <Object>[];
    final events = <String>[];
    final dispatcher = GlobalEventDispatcher(
      maxPending: 1,
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    dispatcher.replaceFallback((event) async {
      events.add(event['value'] as String);
      entered.complete();
      await release.future;
    }, onFailure: (error, stackTrace) => failures.add(error));
    dispatcher.dispatch('{"value":"running"}');
    await entered.future;
    expect(dispatcher.dispatch('{"value":"pending"}'), isTrue);
    expect(dispatcher.dispatch('{"value":"overflow"}'), isFalse);
    expect(failures, hasLength(1));
    expect(dispatcher.pendingCount, 0);
    expect(dispatcher.dispatch('{"value":"retired"}'), isFalse);

    dispatcher.replaceFallback((event) async {
      events.add(event['value'] as String);
    }, onFailure: (error, stackTrace) => fail('unexpected recovery failure'));
    expect(dispatcher.dispatch('{"value":"replacement"}'), isTrue);
    release.complete();
    await dispatcher.idle();
    expect(events, ['running', 'replacement']);
    expect(failures, hasLength(1));
    expect(dispatcher.retainedBytes, 0);
  });

  test('byte and message bounds fail the exact fallback visibly', () async {
    final failures = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      maxMessageCodeUnits: 32,
      maxRetainedBytes: 512,
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    dispatcher.replaceFallback((event) async {},
        onFailure: (error, stackTrace) => failures.add(error));

    final oversized = ''.padRight(40, 'x');
    expect(dispatcher.dispatch('{"value":"$oversized"}'), isFalse);
    expect(failures, hasLength(1));
    expect(dispatcher.retainedBytes, 0);

    final entered = Completer<void>();
    final release = Completer<void>();
    final byteFailures = <Object>[];
    final byteDispatcher = GlobalEventDispatcher(
      maxMessageCodeUnits: 1024,
      maxRetainedBytes: 550,
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    byteDispatcher.replaceFallback((event) async {
      entered.complete();
      await release.future;
    }, onFailure: (error, stackTrace) => byteFailures.add(error));
    expect(byteDispatcher.dispatch('{"value":"running"}'), isTrue);
    await entered.future;
    expect(byteDispatcher.dispatch('{"value":"pending"}'), isFalse);
    expect(byteFailures, hasLength(1));
    expect(byteDispatcher.pendingCount, 0);
    release.complete();
    await byteDispatcher.idle();
    expect(byteDispatcher.retainedBytes, 0);
  });

  test('registered handler inventory is finite and reusable after retirement',
      () async {
    final diagnostics = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      maxRegisteredHandlers: 1,
      onDiagnostic: (error, stackTrace) => diagnostics.add(error),
    );
    expect(dispatcher.registerHandler('one', 'owner', (event) async {}),
        isTrue);
    expect(dispatcher.registerHandler('two', 'owner', (event) async {}),
        isFalse);
    expect(diagnostics, hasLength(1));
    expect(diagnostics.single, isA<StateError>());
    dispatcher.unregisterHandler('one', 'owner');
    expect(dispatcher.registerHandler('two', 'owner', (event) async {}),
        isTrue);
  });

  test('registered handlers are captured and retired by exact registration',
      () async {
    final blockerEntered = Completer<void>();
    final releaseBlocker = Completer<void>();
    final events = <String>[];
    final diagnostics = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => diagnostics.add(error),
    );
    dispatcher.replaceFallback((event) async {
      blockerEntered.complete();
      await releaseBlocker.future;
    }, onFailure: (error, stackTrace) => fail('unexpected fallback failure'));
    dispatcher.registerHandler('registered', 'owner', (event) async {
      events.add('old');
    });
    dispatcher.dispatch('{"value":"blocker"}', allowRegistered: false);
    await blockerEntered.future;
    expect(dispatcher.dispatch('{"name":"registered"}'), isTrue);
    dispatcher.unregisterHandler('registered', 'owner');
    expect(
        dispatcher.registerHandler('registered', 'owner', (event) async {
          events.add('new');
        }),
        isTrue);
    expect(dispatcher.dispatch('{"name":"registered"}'), isTrue);

    releaseBlocker.complete();
    await dispatcher.idle();
    expect(events, ['new']);
    expect(diagnostics, isEmpty);
  });

  test('registered-only routing never falls through to session fallback',
      () async {
    final registered = <String>[];
    final fallback = <String>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    dispatcher.registerHandler('theme', 'theme', (event) async {
      registered.add(event['name'] as String);
    });
    dispatcher.replaceFallback((event) async {
      fallback.add(event['name'] as String);
    }, onFailure: (error, stackTrace) => fail('unexpected fallback failure'));

    dispatcher.dispatch('{"name":"theme"}', allowFallback: false);
    dispatcher.dispatch('{"name":"theme"}', allowRegistered: false);
    await dispatcher.idle();
    expect(registered, ['theme']);
    expect(fallback, ['theme']);
  });

  test('configured latest-state events hand off synchronously outside FIFO',
      () async {
    final controlEntered = Completer<void>();
    final releaseControl = Completer<void>();
    final cursorValues = <String>[];
    final failures = <Object>[];
    final dispatcher = GlobalEventDispatcher(
      synchronousFallbackEvents: const {'cursor_position'},
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    dispatcher.replaceFallback((event) {
      if (event['name'] == 'cursor_position') {
        cursorValues.add(event['value'] as String);
        return null;
      }
      controlEntered.complete();
      return releaseControl.future;
    }, onFailure: (error, stackTrace) => failures.add(error));

    expect(dispatcher.dispatch('{"name":"control"}'), isTrue);
    await controlEntered.future;
    expect(dispatcher.dispatch(
        '{"name":"cursor_position","value":"one"}'), isTrue);
    expect(dispatcher.dispatch(
        '{"name":"cursor_position","value":"two"}'), isTrue);
    expect(cursorValues, ['one', 'two']);
    expect(dispatcher.pendingCount, 0);

    releaseControl.complete();
    await dispatcher.idle();
    expect(failures, isEmpty);
    expect(dispatcher.retainedBytes, 0);
  });

  test('configured synchronous handoff fails closed on an async callback',
      () async {
    final failures = <Object>[];
    final release = Completer<void>();
    final dispatcher = GlobalEventDispatcher(
      synchronousFallbackEvents: const {'cursor_position'},
      onDiagnostic: (error, stackTrace) => fail('unexpected error: $error'),
    );
    dispatcher.replaceFallback((event) async {
      await release.future;
    }, onFailure: (error, stackTrace) => failures.add(error));

    expect(dispatcher.dispatch('{"name":"cursor_position"}'), isFalse);
    expect(failures, hasLength(1));
    expect(dispatcher.dispatch('{"name":"cursor_position"}'), isFalse);
    release.complete();
    await Future<void>.delayed(Duration.zero);
  });

  test('handler and malformed-input failures remain visible and drainable',
      () async {
    final diagnostics = <Object>[];
    final fallbackFailures = <Object>[];
    final events = <String>[];
    final dispatcher = GlobalEventDispatcher(
      onDiagnostic: (error, stackTrace) => diagnostics.add(error),
    );
    dispatcher.registerHandler('registered', 'owner', (event) async {
      throw StateError('expected registered failure');
    });
    dispatcher.registerHandler('later', 'owner', (event) async {
      events.add('later');
    });
    dispatcher.replaceFallback((event) async {
      events.add('fallback');
    }, onFailure: (error, stackTrace) => fallbackFailures.add(error));

    dispatcher.dispatch('{"name":"registered"}');
    dispatcher.dispatch('{"name":"later"}');
    await dispatcher.idle();
    expect(diagnostics, hasLength(1));
    expect(diagnostics.single, isA<StateError>());
    expect(dispatcher.dispatch('not-json'), isFalse);
    expect(fallbackFailures, hasLength(1));
    expect(events, ['later']);
    expect(dispatcher.retainedBytes, 0);
  });
}

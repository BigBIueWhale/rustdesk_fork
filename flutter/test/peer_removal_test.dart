import 'dart:async';

import 'package:flutter_hbb/common.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('peer deletion owns its IDs and waits for each deletion and refresh',
      () async {
    final first = Completer<void>();
    final second = Completer<void>();
    final refresh = Completer<void>();
    final ids = ['first', 'second'];
    final events = <String>[];
    bool? result;
    final pending = mainRemovePeers(ids, removePeer: (id) {
      events.add('remove:$id');
      return id == 'first' ? first.future : second.future;
    }, reloadRecentPeers: () {
      events.add('refresh');
      return refresh.future;
    }, showFailure: () => fail('successful deletion reported failure'))
        .then((value) => result = value);
    ids.add('later');
    expect(events, ['remove:first']);
    expect(result, isNull);
    first.complete();
    await Future<void>.delayed(Duration.zero);
    expect(events, ['remove:first', 'remove:second']);
    expect(result, isNull);
    second.complete();
    await Future<void>.delayed(Duration.zero);
    expect(events, ['remove:first', 'remove:second', 'refresh']);
    expect(result, isNull);
    refresh.complete();
    await pending;
    expect(result, isTrue);
  });

  test('peer deletion reports a single failure and permits an identical retry',
      () async {
    var calls = 0;
    var refreshes = 0;
    var failures = 0;
    Future<void> remove(String id) async {
      expect(id, 'selected');
      if (++calls == 1) throw StateError('delete refused');
    }

    Future<void> refresh() async {
      refreshes++;
    }
    expect(
        await mainRemovePeers(['selected'],
            removePeer: remove,
            reloadRecentPeers: refresh,
            showFailure: () => failures++),
        isFalse);
    expect(
        await mainRemovePeers(['selected'],
            removePeer: remove,
            reloadRecentPeers: refresh,
            showFailure: () => failures++),
        isTrue);
    expect(calls, 2);
    expect(refreshes, 2);
    expect(failures, 1);
  });

  test('peer deletion completes the submitted batch after a partial failure',
      () async {
    final events = <String>[];
    var failures = 0;
    final result = await mainRemovePeers(['first', 'second', 'third'],
        removePeer: (id) async {
      events.add('remove:$id');
      if (id == 'second') throw StateError('delete refused');
    }, reloadRecentPeers: () async {
      events.add('refresh');
    }, showFailure: () => failures++);
    expect(result, isFalse);
    expect(events,
        ['remove:first', 'remove:second', 'remove:third', 'refresh']);
    expect(failures, 1);
  });

  test('peer deletion reports a refresh failure after completed deletion',
      () async {
    var removed = 0;
    var failures = 0;
    final result = await mainRemovePeers(['selected'], removePeer: (_) async {
      removed++;
    }, reloadRecentPeers: () async {
      throw StateError('refresh refused');
    }, showFailure: () => failures++);
    expect(result, isFalse);
    expect(removed, 1);
    expect(failures, 1);
  });

  test('peer deletion preserves a synchronous native failure as a failed result',
      () async {
    var refreshes = 0;
    var failures = 0;
    final result = await mainRemovePeers(['selected'], removePeer: (_) {
      throw StateError('native dispatch refused');
    }, reloadRecentPeers: () async {
      refreshes++;
    }, showFailure: () => failures++);
    expect(result, isFalse);
    expect(refreshes, 1);
    expect(failures, 1);
  });
}

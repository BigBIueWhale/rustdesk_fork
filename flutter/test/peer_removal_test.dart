import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _DeleteCall {
  final result = Completer<void>();
  bool? currentAtCompletion;
}

class _DeleteHarness {
  final manager = OverlayDialogManager(translateText: (text) => text);
  final calls = <_DeleteCall>[];
  final openings = <Future<void>>[];
  final submissions = <Future<Object?>>[];

  Future<void> mount(WidgetTester tester) async {
    final overlay = BlockableOverlayState();
    manager.setOverlayState(overlay);
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
    ));
    await open(tester, 'Delete original');
  }

  Future<void> open(WidgetTester tester, String title) async {
    openings.add(deleteConfirmDialog((isCurrent) async {
      final call = _DeleteCall();
      calls.add(call);
      await call.result.future;
      call.currentAtCompletion = isCurrent();
    }, title, dialogManager: manager, translateText: (text) => text));
    await tester.pumpAndSettle();
  }

  Future<Object?> submit(Function() callback) {
    final observed = Future<void>.sync(() => callback()).then<Object?>(
        (_) => null, onError: (Object error, StackTrace _) => error);
    submissions.add(observed);
    return observed;
  }

  Future<void> drain(WidgetTester tester) async {
    manager.dismissAll();
    for (final call in calls) {
      if (!call.result.isCompleted) call.result.complete();
    }
    await Future.wait(submissions);
    await Future.wait(openings);
    await tester.pumpWidget(const SizedBox.shrink());
  }
}

class _UnusedOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('peer selection must not call its native owner');
}

PeerTabModel _selectedModel(FFI owner) {
  final model = PeerTabModel(WeakReference<FFI>(owner),
      readLocalOption: (_) => '');
  model.setMultiSelectionMode(true);
  model.select(Peer.fromJson({'id': 'first'}));
  return model;
}

class _PeerRenameCall {
  _PeerRenameCall(this.name);
  final String name;
  final result = Completer<bool>();
  bool? currentAtCompletion;
}

class _PeerRenameHarness {
  final manager = OverlayDialogManager(translateText: (text) => text);
  final calls = <_PeerRenameCall>[];
  final openings = <Future<void>>[];
  final submissions = <Future<Object?>>[];

  Future<void> mount(WidgetTester tester) async {
    final overlay = BlockableOverlayState();
    manager.setOverlayState(overlay);
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
    ));
    await open(tester, 'original');
  }

  Future<void> open(WidgetTester tester, String name) async {
    openings.add(renameDialog(oldName: name, onSubmit: (name, isCurrent) async {
      final call = _PeerRenameCall(name);
      calls.add(call);
      final saved = await call.result.future;
      call.currentAtCompletion = isCurrent();
      return saved;
    }, dialogManager: manager, translateText: (text) => text));
    await tester.pumpAndSettle();
  }

  Future<Object?> submit(Function() callback) {
    final observed = Future<void>.sync(() => callback()).then<Object?>(
        (_) => null, onError: (Object error, StackTrace _) => error);
    submissions.add(observed);
    return observed;
  }

  Future<void> drain(WidgetTester tester) async {
    manager.dismissAll();
    for (final call in calls) {
      if (!call.result.isCompleted) call.result.complete(false);
    }
    await Future.wait(submissions);
    await Future.wait(openings);
    await tester.pumpWidget(const SizedBox.shrink());
  }
}

void main() {
  test('peer option workflow waits for write and refresh with exact arguments',
      () async {
    final write = Completer<void>();
    final refresh = Completer<void>();
    final events = <String>[];
    bool? result;
    final pending = mainSetPeerOption('peer', 'alias', 'selected',
        writeOption: (id, key, value) {
      events.add('$id:$key:$value');
      return write.future;
    }, reloadPeers: () {
      events.add('refresh');
      return refresh.future;
    }, showFailure: () => fail('successful option save reported failure'))
        .then((value) => result = value);
    expect(events, ['peer:alias:selected']);
    expect(result, isNull);
    write.complete();
    await Future<void>.delayed(Duration.zero);
    expect(events, ['peer:alias:selected', 'refresh']);
    expect(result, isNull);
    refresh.complete();
    await pending;
    expect(result, isTrue);
  });

  test('peer option workflow reports write or refresh failure and retries',
      () async {
    for (final kind in ['sync', 'async', 'refresh']) {
      var calls = 0;
      var refreshes = 0;
      var failures = 0;
      Future<void> write(String id, String key, String value) {
        expect([id, key, value], ['peer', 'alias', 'selected']);
        if (++calls == 1) {
          if (kind == 'sync') throw StateError('write refused');
          if (kind == 'async') return Future.error(StateError('write refused'));
        }
        return Future.value();
      }
      Future<void> reload() async {
        if (++refreshes == 1 && kind == 'refresh') {
          throw StateError('refresh refused');
        }
      }
      expect(await mainSetPeerOption('peer', 'alias', 'selected',
          writeOption: write, reloadPeers: reload,
          showFailure: () => failures++), isFalse);
      expect(await mainSetPeerOption('peer', 'alias', 'selected',
          writeOption: write, reloadPeers: reload,
          showFailure: () => failures++), isTrue);
      expect(calls, 2);
      expect(failures, 1);
      expect(refreshes, kind == 'refresh' ? 2 : 1);
    }
  });

  testWidgets('peer rename owns one pending save until success', (tester) async {
    final harness = _PeerRenameHarness();
    await harness.mount(tester);
    try {
      await tester.enterText(find.byType(TextField), ' renamed ');
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      final duplicate = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(1));
      expect(harness.calls.single.name, 'renamed');
      expect(find.byType(CustomAlertDialog), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
      expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
      harness.calls.single.result.complete(true);
      expect(await first, isNull);
      expect(await duplicate, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('retired peer rename callbacks cannot save a replacement',
      (tester) async {
    final harness = _PeerRenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await harness.open(tester, 'replacement');
      expect(await harness.submit(submit), isNull);
      expect(harness.calls, isEmpty);
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
          'replacement');
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('peer rename failure stays visible and permits a changed retry',
      (tester) async {
    final harness = _PeerRenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      await tester.pump();
      harness.calls.single.result.complete(false);
      expect(await first, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsNothing);
      await tester.enterText(find.byType(TextField), 'retry');
      final retry = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(2));
      expect(harness.calls.last.name, 'retry');
      harness.calls.last.result.complete(true);
      expect(await retry, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('admitted peer rename drains without closing its replacement',
      (tester) async {
    final harness = _PeerRenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final pending = harness.submit(submit);
      await tester.pump();
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await harness.open(tester, 'replacement');
      harness.calls.single.result.complete(true);
      expect(await pending, isNull);
      await tester.pumpAndSettle();
      expect(harness.calls.single.currentAtCompletion, isFalse);
      expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
          'replacement');
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('peer rename disposes its editor while admitted failure drains',
      (tester) async {
    final harness = _PeerRenameHarness();
    await harness.mount(tester);
    try {
      final controller =
          tester.widget<TextField>(find.byType(TextField)).controller!;
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final pending = harness.submit(submit);
      await tester.pump();
      harness.manager.dismissAll();
      await tester.pumpAndSettle();
      expect(() => controller.addListener(() {}), throwsFlutterError);
      harness.calls.single.result.complete(false);
      expect(await pending, isNull);
      expect(await harness.submit(submit), isNull);
      expect(harness.calls, hasLength(1));
      expect(harness.calls.single.currentAtCompletion, isFalse);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  test('peer credential removal waits for the exact submitted operation', () async {
    final dispatch = Completer<void>();
    final ids = <String>[];
    bool? result;
    final pending = mainForgetPassword('selected', forgetPassword: (id) {
      ids.add(id);
      return dispatch.future;
    }, showFailure: () => fail('successful credential removal reported failure'))
        .then((value) => result = value);
    expect(ids, ['selected']);
    expect(result, isNull);
    dispatch.complete();
    await pending;
    expect(result, isTrue);
  });

  test('peer credential removal reports failure and retries the same peer',
      () async {
    var calls = 0;
    var failures = 0;
    Future<void> forget(String id) async {
      expect(id, 'selected');
      if (++calls == 1) throw StateError('credential removal refused');
    }
    expect(await mainForgetPassword('selected', forgetPassword: forget,
        showFailure: () => failures++), isFalse);
    expect(await mainForgetPassword('selected', forgetPassword: forget,
        showFailure: () => failures++), isTrue);
    expect(calls, 2);
    expect(failures, 1);
  });

  test('peer credential removal preserves a synchronous bridge failure', () async {
    var failures = 0;
    expect(await mainForgetPassword('selected', forgetPassword: (_) {
      throw StateError('credential removal refused');
    }, showFailure: () => failures++), isFalse);
    expect(failures, 1);
  });

  testWidgets('peer delete confirmation admits one pending submission',
      (tester) async {
    final harness = _DeleteHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      final duplicate = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(1));
      harness.calls.single.result.complete();
      expect(await first, isNull);
      expect(await duplicate, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('retired peer delete callback cannot submit into a replacement',
      (tester) async {
    final harness = _DeleteHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await harness.open(tester, 'Delete replacement');
      final stale = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, isEmpty);
      expect(await stale, isNull);
      expect(find.text('Delete replacement'), findsOneWidget);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('admitted peer deletion drains without closing a replacement',
      (tester) async {
    final harness = _DeleteHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final pending = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(1));
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await harness.open(tester, 'Delete replacement');
      harness.calls.single.result.complete();
      expect(await pending, isNull);
      await tester.pumpAndSettle();
      expect(harness.calls.single.currentAtCompletion, isFalse);
      expect(find.text('Delete replacement'), findsOneWidget);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('peer delete submission failure stays visible and retries',
      (tester) async {
    final harness = _DeleteHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      await tester.pump();
      harness.calls.single.result.completeError(StateError('delete refused'));
      expect(await first, isA<StateError>());
      await tester.pumpAndSettle();
      expect(find.text('Delete original'), findsOneWidget);
      final retry = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(2));
      harness.calls.last.result.complete();
      expect(await retry, isNull);
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  test('peer deletion captures immutable IDs without exposing mutable selection',
      () {
    final owner = _UnusedOwner();
    final model = _selectedModel(owner);
    try {
      final selection = model.captureSelection();
      model.select(Peer.fromJson({'id': 'second'}));
      expect(selection.ids, ['first']);
      expect(() => selection.ids.add('foreign'), throwsUnsupportedError);
      expect(() => model.selectedPeers.clear(), throwsUnsupportedError);
      expect(model.selectedPeers.map((peer) => peer.id), ['first', 'second']);
      expect(selection.isCurrent, isFalse);
    } finally {
      model.dispose();
    }
  });

  test('peer deletion cannot clear a replaced selection or tab round trip', () {
    final owner = _UnusedOwner();
    final model = _selectedModel(owner);
    try {
      final original = model.captureSelection();
      model.setMultiSelectionMode(false);
      model.setMultiSelectionMode(true);
      model.select(Peer.fromJson({'id': 'first'}));
      expect(original.retire(), isFalse);
      expect(model.selectedPeers.single.id, 'first');
      final next = model.captureSelection();
      model.setCurrentTab(1);
      model.setCurrentTab(0);
      expect(next.retire(), isFalse);
      expect(model.selectedPeers.single.id, 'first');
      expect(model.multiSelectionMode, isTrue);
    } finally {
      model.dispose();
    }
  });

  test('peer deletion retires its unchanged selection exactly once', () {
    final owner = _UnusedOwner();
    final model = _selectedModel(owner);
    try {
      final selection = model.captureSelection();
      expect(selection.ids, ['first']);
      expect(selection.tab, 0);
      expect(selection.isCurrent, isTrue);
      expect(selection.retire(), isTrue);
      expect(model.selectedPeers, isEmpty);
      expect(model.multiSelectionMode, isFalse);
      expect(selection.retire(), isFalse);
    } finally {
      model.dispose();
    }
  });

  test('peer deletion cannot notify a disposed selection owner', () {
    final owner = _UnusedOwner();
    final model = _selectedModel(owner);
    final selection = model.captureSelection();
    model.dispose();
    expect(selection.isCurrent, isFalse);
    expect(selection.retire(), isFalse);
  });

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

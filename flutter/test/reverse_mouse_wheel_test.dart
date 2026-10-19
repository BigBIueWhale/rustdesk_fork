import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' as common;
import 'package:flutter_hbb/common/widgets/reverse_mouse_wheel.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/reverse_mouse_wheel.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Store implements ReverseMouseWheelStore {
  final reads = <(common.SessionID, common.SessionID)>[];
  final writes = <(common.SessionID, common.SessionID, bool)>[];
  Future<bool> Function()? onRead;
  Future<bool> Function(bool)? onWrite;
  bool value = false;
  @override
  Future<bool> read(common.SessionID id, common.SessionID owner) {
    reads.add((id, owner));
    return onRead?.call() ?? Future.value(value);
  }
  @override
  Future<bool> write(common.SessionID id, common.SessionID owner, bool requested) async {
    writes.add((id, owner, requested));
    final effective = await (onWrite?.call(requested) ?? Future.value(requested));
    if (effective == requested) value = effective;
    return effective;
  }
}

class _Input implements InputModel {
  _Input(this.reverseMouseWheel);
  @override
  final ReverseMouseWheelPreferences reverseMouseWheel;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Session implements FFI {
  final store = _Store();
  bool current = true;
  @override
  common.SessionID sessionId = Uuid().v4obj();
  @override
  common.SessionID clientOwnerId = Uuid().v4obj();
  @override
  late final _Input inputModel = _Input(ReverseMouseWheelPreferences(
      WeakReference<FFI>(this), store: store));
  ReverseMouseWheelPreferences get preferences => inputModel.reverseMouseWheel;
  @override
  bool isCurrentSessionOwner(common.SessionID id, common.SessionID owner) =>
      current && sessionId == id && clientOwnerId == owner;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<void> _show(WidgetTester tester, _Session session, {bool enabled = true,
    bool pair = false}) async {
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: SizedBox(width: 600,
    child: Column(children: [
      ReverseMouseWheelControl(key: const ValueKey('one'), ffi: session,
          enabled: enabled, translateText: (s) => s),
      if (pair) ReverseMouseWheelControl(key: const ValueKey('two'), ffi: session,
          enabled: enabled, translateText: (s) => s),
    ])))));
  await tester.pump();
  await tester.pump();
}
CheckboxMenuButton _box(WidgetTester tester) =>
    tester.widget<CheckboxMenuButton>(find.byType(CheckboxMenuButton).first);
Future<void> _flush(WidgetTester tester) async { await tester.pump(); await tester.pump(); }
TextButton _retry(WidgetTester tester) => tester.widget<TextButton>(
    find.byKey(const ValueKey('reverse-mouse-wheel-retry')).first);

void main() {
  test('reverse wheel reads and writes capture both owner identifiers', () async {
    final session = _Session();
    expect(await session.preferences.read(), false);
    expect(await session.preferences.save(true), true);
    expect(session.store.reads, [(session.sessionId, session.clientOwnerId)]);
    expect(session.store.writes, [(session.sessionId, session.clientOwnerId, true)]);
    expect(session.preferences.value, true);
    session.preferences.dispose();
  });
  test('reverse wheel bounds admission before native dispatch', () async {
    final session = _Session();
    final read = Completer<bool>();
    final write = Completer<bool>();
    session.store.onRead = () => read.future;
    session.store.onWrite = (_) => write.future;
    final reading = session.preferences.read();
    await expectLater(session.preferences.read(), throwsStateError);
    final saving = session.preferences.save(true);
    await expectLater(session.preferences.save(false), throwsStateError);
    await expectLater(session.preferences.read(), throwsStateError);
    expect(session.store.reads.length, 1);
    expect(session.store.writes.length, 1);
    write.complete(true);
    expect(await saving, true);
    read.complete(false);
    expect(await reading, true);
    expect(session.preferences.value, true);
    session.preferences.dispose();
  });
  test('reverse wheel write failure and mismatch preserve the confirmed value', () async {
    final session = _Session();
    await session.preferences.read();
    session.store.onWrite = (_) => Future.error(StateError('denied'));
    await expectLater(session.preferences.save(true), throwsStateError);
    expect(session.preferences.value, false);
    session.store.onWrite = (_) async => false;
    await expectLater(session.preferences.save(true), throwsStateError);
    expect(session.preferences.value, false);
    expect(session.preferences.saving, false);
    session.store.onWrite = null;
    expect(await session.preferences.save(true), true);
    session.preferences.dispose();
  });
  test('reverse wheel retired read cannot publish into replacement owner', () async {
    final session = _Session();
    final read = Completer<bool>();
    session.store.onRead = () => read.future;
    final reading = session.preferences.read();
    final failure = expectLater(reading, throwsStateError);
    session.clientOwnerId = Uuid().v4obj();
    read.complete(true);
    await failure;
    expect(session.preferences.value, null);
    session.store.onRead = null;
    expect(await session.preferences.read(), false);
    session.preferences.dispose();
  });
  test('reverse wheel admitted write remains owned after owner retirement', () async {
    final session = _Session();
    await session.preferences.read();
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    final saving = session.preferences.save(true);
    session.clientOwnerId = Uuid().v4obj();
    expect(session.preferences.saving, true);
    expect(session.preferences.value, null);
    await expectLater(session.preferences.save(false), throwsStateError);
    write.complete(true);
    expect(await saving, true);
    expect(session.preferences.value, null);
    expect(session.preferences.saving, false);
    session.preferences.dispose();
  });
  test('reverse wheel disposal retains pending capacity without late notification', () async {
    final session = _Session();
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    var notifications = 0;
    session.preferences.addListener(() => notifications++);
    final saving = session.preferences.save(false);
    expect(notifications, 1);
    session.preferences.dispose();
    expect(session.preferences.saving, true);
    await expectLater(session.preferences.save(true), throwsStateError);
    write.complete(false);
    expect(await saving, false);
    expect(notifications, 1);
    expect(session.preferences.saving, false);
  });
  testWidgets('reverse wheel initial read is singular through rebuilds', (tester) async {
    final session = _Session();
    final read = Completer<bool>();
    session.store.onRead = () => read.future;
    await _show(tester, session);
    await _show(tester, session);
    expect(session.store.reads.length, 1);
    expect(find.byType(CheckboxMenuButton), findsNothing);
    expect(session.store.writes, isEmpty);
    read.complete(true);
    await _flush(tester);
    expect(_box(tester).value, true);
  });
  testWidgets('reverse wheel failed read stays unknown and retries explicitly', (tester) async {
    final session = _Session();
    session.store.onRead = () => Future.error(StateError('read denied'));
    await _show(tester, session);
    expect(find.byType(CheckboxMenuButton), findsNothing);
    expect(find.text('Failed'), findsOneWidget);
    expect(session.store.writes, isEmpty);
    session.store.onRead = null;
    _retry(tester).onPressed!();
    await _flush(tester);
    expect(_box(tester).value, false);
    expect(find.text('Failed'), findsNothing);
    expect(session.store.reads.length, 2);
  });
  testWidgets('reverse wheel visual value waits for acknowledged write', (tester) async {
    final session = _Session();
    await _show(tester, session);
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    _box(tester).onChanged!(true);
    await _flush(tester);
    expect(_box(tester).value, false);
    expect(_box(tester).onChanged, null);
    write.complete(true);
    await _flush(tester);
    expect(_box(tester).value, true);
    expect(_box(tester).onChanged, isNotNull);
  });
  for (final requested in [true, false]) {
    testWidgets('reverse wheel failed write retries requested $requested', (tester) async {
      final session = _Session();
      session.store.value = !requested;
      await _show(tester, session);
      session.store.onWrite = (_) => Future.error(StateError('write denied'));
      _box(tester).onChanged!(requested);
      await _flush(tester);
      expect(_box(tester).value, !requested);
      expect(find.text('Failed'), findsOneWidget);
      session.store.onWrite = null;
      _retry(tester).onPressed!();
      await _flush(tester);
      expect(_box(tester).value, requested);
      expect(session.store.writes.map((e) => e.$3).toList(), [requested, requested]);
      expect(find.text('Failed'), findsNothing);
    });
  }
  testWidgets('reverse wheel mismatched acknowledgement is visible and retryable', (tester) async {
    final session = _Session();
    await _show(tester, session);
    session.store.onWrite = (_) async => false;
    _box(tester).onChanged!(true);
    await _flush(tester);
    expect(_box(tester).value, false);
    expect(find.text('Failed'), findsOneWidget);
    session.store.onWrite = null;
    _retry(tester).onPressed!();
    await _flush(tester);
    expect(_box(tester).value, true);
  });
  testWidgets('reverse wheel shared controls observe one write and confirmed value', (tester) async {
    final session = _Session();
    await _show(tester, session, pair: true);
    await _flush(tester);
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    final callbacks = tester.widgetList<CheckboxMenuButton>(find.byType(CheckboxMenuButton))
        .map((box) => box.onChanged!).toList();
    callbacks[0](true);
    callbacks[1](true);
    await _flush(tester);
    expect(session.store.writes.length, 1);
    expect(tester.widgetList<CheckboxMenuButton>(find.byType(CheckboxMenuButton))
        .every((box) => box.value == false && box.onChanged == null), true);
    write.complete(true);
    await _flush(tester);
    expect(tester.widgetList<CheckboxMenuButton>(find.byType(CheckboxMenuButton))
        .every((box) => box.value == true), true);
  });
  testWidgets('reverse wheel retarget rejects captured callbacks and old completion', (tester) async {
    final old = _Session();
    await _show(tester, old);
    final callback = _box(tester).onChanged!;
    final write = Completer<bool>();
    old.store.onWrite = (_) => write.future;
    callback(true);
    final replacement = _Session();
    await _show(tester, replacement);
    callback(true);
    write.complete(true);
    await _flush(tester);
    expect(_box(tester).value, false);
    expect(replacement.store.writes, isEmpty);
    expect(old.store.writes.length, 1);
  });
  testWidgets('reverse wheel disable and reenable retire old callbacks', (tester) async {
    final session = _Session();
    await _show(tester, session);
    final callback = _box(tester).onChanged!;
    await _show(tester, session, enabled: false);
    callback(true);
    expect(_box(tester).onChanged, null);
    await _show(tester, session);
    callback(true);
    expect(session.store.writes, isEmpty);
    _box(tester).onChanged!(true);
    await _flush(tester);
    expect(_box(tester).value, true);
  });
  testWidgets('reverse wheel replacement reads while old control read is pending', (tester) async {
    final old = _Session();
    final read = Completer<bool>();
    old.store.onRead = () => read.future;
    await _show(tester, old);
    final replacement = _Session();
    await _show(tester, replacement);
    expect(replacement.store.reads.length, 1);
    expect(_box(tester).value, false);
    read.complete(true);
    await _flush(tester);
    expect(_box(tester).value, false);
  });
  testWidgets('reverse wheel disposed deferred listener cannot start another read', (tester) async {
    final session = _Session();
    final read = Completer<bool>();
    session.store.onRead = () => read.future;
    await _show(tester, session, pair: true);
    expect(session.store.reads.length, 1);
    await tester.pumpWidget(const SizedBox());
    read.complete(false);
    await _flush(tester);
    expect(session.store.reads.length, 1);
    expect(tester.takeException(), null);
  });
  testWidgets('reverse wheel stale retry cannot target replacement session', (tester) async {
    final old = _Session();
    old.store.onRead = () => Future.error(StateError('denied'));
    await _show(tester, old);
    final retry = _retry(tester).onPressed!;
    final replacement = _Session();
    await _show(tester, replacement);
    retry();
    await _flush(tester);
    expect(replacement.store.reads.length, 1);
    expect(replacement.store.writes, isEmpty);
  });
  testWidgets('reverse wheel mobile control uses the same confirmed state', (tester) async {
    final before = common.isMobile;
    common.isMobile = true;
    try {
      final session = _Session();
      await _show(tester, session);
      var box = tester.widget<CheckboxListTile>(find.byType(CheckboxListTile));
      expect(box.value, false);
      box.onChanged!(true);
      await _flush(tester);
      box = tester.widget<CheckboxListTile>(find.byType(CheckboxListTile));
      expect(box.value, true);
    } finally {
      common.isMobile = before;
    }
  });
}

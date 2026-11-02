import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/common/widgets/audio_mute.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/session_audio_mute.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Store implements SessionAudioMuteStore {
  final reads = <(SessionID, SessionID)>[];
  final writes = <(SessionID, SessionID, bool)>[];
  Future<bool> Function()? onRead;
  Future<bool> Function(bool)? onWrite;
  bool value = false;

  @override
  Future<bool> read(SessionID session, SessionID owner) {
    reads.add((session, owner));
    return onRead?.call() ?? Future.value(value);
  }

  @override
  Future<bool> write(SessionID session, SessionID owner, bool muted) async {
    writes.add((session, owner, muted));
    final effective = await (onWrite?.call(muted) ?? Future.value(muted));
    if (effective == muted) value = effective;
    return effective;
  }
}

class _Session implements FFI {
  final store = _Store();
  bool current = true;
  @override
  SessionID sessionId = Uuid().v4obj();
  @override
  SessionID clientOwnerId = Uuid().v4obj();
  @override
  late final audioMute = SessionAudioMute(WeakReference<FFI>(this), store: store);
  @override
  bool isCurrentSessionOwner(SessionID session, SessionID owner) =>
      current && session == sessionId && owner == clientOwnerId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<void> _show(WidgetTester tester, _Session session, {VoidCallback? failure}) async {
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: AudioMuteControl(
      ffi: session, translateText: (s) => s, showFailure: failure ?? () {}))));
  await tester.pump();
  await tester.pump();
}

CheckboxMenuButton _box(WidgetTester tester) =>
    tester.widget<CheckboxMenuButton>(find.byType(CheckboxMenuButton));

void main() {
  test('mute reads and explicit writes retain both owner identifiers', () async {
    final session = _Session();
    await session.audioMute.refresh();
    await session.audioMute.save(true);
    await session.audioMute.save(true);
    expect(session.store.reads, [(session.sessionId, session.clientOwnerId)]);
    expect(session.store.writes, List.filled(2, (session.sessionId, session.clientOwnerId, true)));
    expect(session.audioMute.value, true);
  });

  test('mute failure and mismatched confirmation preserve the prior value', () async {
    final session = _Session();
    await session.audioMute.refresh();
    session.store.onWrite = (_) => Future.error(StateError('denied'));
    await expectLater(session.audioMute.save(true), throwsStateError);
    expect(session.audioMute.value, false);
    expect(session.audioMute.failed, true);
    expect(session.audioMute.retryValue, true);
    session.store.onWrite = (_) async => false;
    await expectLater(session.audioMute.save(true), throwsStateError);
    expect(session.audioMute.value, false);
    session.store.onWrite = null;
    await session.audioMute.save(true);
    expect(session.audioMute.value, true);
    expect(session.audioMute.failed, false);
  });

  test('mute coalesces pending reads and refuses overlapping writes', () async {
    final session = _Session();
    final read = Completer<bool>();
    session.store.onRead = () => read.future;
    final first = session.audioMute.refresh();
    final second = session.audioMute.refresh();
    await expectLater(session.audioMute.save(true), throwsStateError);
    expect(session.store.reads.length, 1);
    expect(session.store.writes, isEmpty);
    read.complete(false);
    await Future.wait([first, second]);
    expect(session.audioMute.value, false);
    expect(session.audioMute.busy, false);
  });

  test('mute retired read cannot publish into a replacement owner', () async {
    final session = _Session();
    final read = Completer<bool>();
    session.store.onRead = () => read.future;
    final old = session.audioMute.refresh();
    session.clientOwnerId = Uuid().v4obj();
    session.store.onRead = null;
    final replacement = session.audioMute.refresh();
    read.complete(true);
    await Future.wait([old, replacement]);
    expect(session.audioMute.value, false);
    expect(session.store.reads.length, 2);
    expect(session.store.reads.last.$2, session.clientOwnerId);
  });

  test('mute admitted save retains capacity through owner retirement', () async {
    final session = _Session();
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    final oldOwner = session.clientOwnerId;
    final saving = session.audioMute.save(true);
    session.clientOwnerId = Uuid().v4obj();
    await expectLater(session.audioMute.save(false), throwsStateError);
    expect(session.audioMute.busy, true);
    write.complete(true);
    await saving;
    expect(session.audioMute.value, isNull);
    expect(session.store.writes.single.$2, oldOwner);
    await session.audioMute.refresh();
    expect(session.audioMute.value, true);
  });

  test('mute disposal retains pending ownership without late notifications', () async {
    final session = _Session();
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    var notifications = 0;
    session.audioMute.addListener(() => notifications++);
    final saving = session.audioMute.save(true);
    session.audioMute.dispose();
    final before = notifications;
    expect(session.audioMute.busy, true);
    await expectLater(session.audioMute.save(false), throwsStateError);
    write.complete(true);
    await saving;
    expect(session.audioMute.value, isNull);
    expect(session.audioMute.busy, false);
    expect(notifications, before);
  });

  testWidgets('mute checkbox waits for confirmation and rejects stale callbacks', (tester) async {
    final session = _Session();
    await _show(tester, session);
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    final oldCallback = _box(tester).onChanged!;
    oldCallback(true);
    oldCallback(true);
    await tester.pump();
    expect(_box(tester).value, false);
    expect(_box(tester).onChanged, isNull);
    expect(session.store.writes.length, 1);
    write.complete(true);
    await tester.pump();
    await tester.pump();
    expect(_box(tester).value, true);
    oldCallback(false);
    expect(session.store.writes.length, 1);
  });

  testWidgets('mute failure survives menu dismissal and retries the same intent', (tester) async {
    final session = _Session();
    var failures = 0;
    final menu = MenuController();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: MenuAnchor(
        controller: menu,
        menuChildren: [AudioMuteControl(ffi: session, translateText: (s) => s,
            showFailure: () => failures++)],
        builder: (context, controller, child) => TextButton(
            onPressed: controller.open, child: const Text('Display settings'))))));
    menu.open();
    await tester.pumpAndSettle();
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    await tester.tap(find.text('Mute'));
    await tester.pumpAndSettle();
    expect(menu.isOpen, false);
    expect(find.byType(AudioMuteControl), findsNothing);
    expect(session.store.writes.length, 1);
    expect(session.audioMute.busy, true);
    write.completeError(StateError('denied'));
    await tester.pump();
    expect(failures, 1);
    expect(session.audioMute.failed, true);
    menu.open();
    await tester.pumpAndSettle();
    expect(_box(tester).value, false);
    expect(find.text('Failed'), findsOneWidget);
    session.store.onWrite = null;
    await tester.tap(find.text('Retry'));
    await tester.pump();
    await tester.pump();
    expect(_box(tester).value, true);
    expect(find.text('Failed'), findsNothing);
    expect(session.store.writes.map((e) => e.$3), [true, true]);
  });

  testWidgets('mute replacement retires old callbacks and late failure presentation', (tester) async {
    final session = _Session();
    var failures = 0;
    await _show(tester, session, failure: () => failures++);
    final oldCallback = _box(tester).onChanged!;
    final write = Completer<bool>();
    session.store.onWrite = (_) => write.future;
    oldCallback(true);
    session.current = false;
    final replacement = _Session();
    await _show(tester, replacement);
    oldCallback(false);
    write.completeError(StateError('retired'));
    await tester.pump();
    expect(failures, 0);
    expect(replacement.store.writes, isEmpty);
    expect(_box(tester).value, false);
  });

  testWidgets('mute failed initial read retries without writing a default', (tester) async {
    final session = _Session();
    session.store.onRead = () => Future.error(StateError('unavailable'));
    await _show(tester, session);
    expect(find.byType(CheckboxMenuButton), findsNothing);
    expect(find.text('Failed'), findsOneWidget);
    expect(session.store.writes, isEmpty);
    session.store.onRead = null;
    await tester.tap(find.text('Retry'));
    await tester.pump();
    await tester.pump();
    expect(_box(tester).value, false);
    expect(session.store.writes, isEmpty);
  });
}

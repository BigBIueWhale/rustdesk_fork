import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show SessionID, isMobile;
import 'package:flutter_hbb/common/widgets/view_mode.dart';
import 'package:flutter_hbb/generated_bridge.dart' show ViewModeState;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/session_view_mode.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

ViewModeState _state(bool view, bool cursor, int revision) =>
    ViewModeState(viewOnly: view, showMyCursor: cursor, revision: revision);

class _Store implements SessionViewModeStore {
  final reads = <(SessionID, SessionID)>[];
  final writes = <(SessionID, SessionID, ViewModeSetting, bool)>[];
  Future<ViewModeState> Function()? onRead;
  Future<ViewModeState> Function(ViewModeSetting, bool)? onWrite;
  ViewModeState value = _state(false, false, 0);

  @override
  Future<ViewModeState> read(SessionID session, SessionID owner) {
    reads.add((session, owner));
    return onRead?.call() ?? Future.value(value);
  }

  @override
  Future<ViewModeState> write(SessionID session, SessionID owner,
      ViewModeSetting setting, bool enabled) async {
    writes.add((session, owner, setting, enabled));
    return value = await (onWrite?.call(setting, enabled) ?? Future.value(
        setting == ViewModeSetting.viewOnly
            ? _state(enabled, enabled && value.showMyCursor, value.revision + 1)
            : _state(enabled || value.viewOnly, enabled, value.revision + 1)));
  }
}

class _Model implements FfiModel {
  final published = <(bool, bool)>[];
  @override
  void setViewMode(String id, bool view, bool cursor) => published.add((view, cursor));
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Session implements FFI {
  final store = _Store();
  bool current = true;
  @override
  String id = 'peer';
  @override
  SessionID sessionId = Uuid().v4obj();
  @override
  SessionID clientOwnerId = Uuid().v4obj();
  @override
  final ffiModel = _Model();
  @override
  late final viewMode = SessionViewMode(WeakReference<FFI>(this), store: store);
  @override
  bool isCurrentSessionOwner(SessionID session, SessionID owner) =>
      current && session == sessionId && owner == clientOwnerId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<void> _show(WidgetTester tester, _Session session, {VoidCallback? failure}) async {
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: ViewModeControl(
      ffi: session, translateText: (s) => s, showFailure: failure ?? () {}))));
  await tester.pump();
  await tester.pump();
}

CheckboxMenuButton _box(WidgetTester tester) =>
    tester.widget<CheckboxMenuButton>(find.byType(CheckboxMenuButton));

void main() {
  test('view mode reads and explicit coupled choices retain exact owners', () async {
    final session = _Session();
    await session.viewMode.refresh();
    await session.viewMode.save(ViewModeSetting.showMyCursor, true);
    expect(session.ffiModel.published.last, (true, true));
    await session.viewMode.save(ViewModeSetting.viewOnly, false);
    expect(session.ffiModel.published.last, (false, false));
    await session.viewMode.save(ViewModeSetting.viewOnly, false);
    expect(session.store.reads, [(session.sessionId, session.clientOwnerId)]);
    expect(session.store.writes, [
      (session.sessionId, session.clientOwnerId, ViewModeSetting.showMyCursor, true),
      (session.sessionId, session.clientOwnerId, ViewModeSetting.viewOnly, false),
      (session.sessionId, session.clientOwnerId, ViewModeSetting.viewOnly, false),
    ]);
  });

  test('view mode failed save preserves both values and retries exact intent', () async {
    final session = _Session();
    session.store.value = _state(true, true, 2);
    await session.viewMode.refresh();
    session.store.onWrite = (_, __) => Future.error(StateError('denied'));
    await expectLater(session.viewMode.save(ViewModeSetting.viewOnly, false), throwsStateError);
    expect(session.ffiModel.published, [(true, true)]);
    expect(session.viewMode.failed, true);
    expect(session.viewMode.retryValue, (ViewModeSetting.viewOnly, false));
    await session.viewMode.refresh();
    expect(session.viewMode.failed, true);
    session.store.onWrite = null;
    await session.viewMode.save(ViewModeSetting.viewOnly, false);
    expect(session.ffiModel.published.last, (false, false));
    expect(session.viewMode.failed, false);
  });

  test('view mode rejects mismatched and inconsistent confirmations', () async {
    final session = _Session();
    await session.viewMode.refresh();
    session.store.onWrite = (_, __) async => _state(false, false, 1);
    await expectLater(session.viewMode.save(ViewModeSetting.viewOnly, true), throwsStateError);
    session.store.onWrite = (_, __) async => _state(false, true, 2);
    await expectLater(session.viewMode.save(ViewModeSetting.showMyCursor, true), throwsStateError);
    expect(session.ffiModel.published, [(false, false)]);
  });

  test('view mode coalesces reads and bounds coupled writes', () async {
    final session = _Session();
    final read = Completer<ViewModeState>();
    session.store.onRead = () => read.future;
    final first = session.viewMode.refresh();
    final second = session.viewMode.refresh();
    await expectLater(session.viewMode.save(ViewModeSetting.showMyCursor, true), throwsStateError);
    expect(session.store.reads.length, 1);
    expect(session.store.writes, isEmpty);
    read.complete(_state(false, false, 0));
    await Future.wait([first, second]);
    expect(session.viewMode.busy, false);
  });

  test('view mode newer peer event survives delayed replies and old events', () async {
    final session = _Session();
    await session.viewMode.refresh();
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    final saving = session.viewMode.save(ViewModeSetting.showMyCursor, true);
    session.viewMode.synchronize(_state(false, false, 2));
    write.complete(_state(true, true, 1));
    await saving;
    session.viewMode.synchronize(_state(true, true, 1));
    expect(session.viewMode.value!.revision, 2);
    expect(session.ffiModel.published.last, (false, false));
    expect(session.ffiModel.published, everyElement((false, false)));
  });

  test('view mode retired read cannot publish into replacement owner', () async {
    final session = _Session();
    final read = Completer<ViewModeState>();
    session.store.onRead = () => read.future;
    final old = session.viewMode.refresh();
    session.clientOwnerId = Uuid().v4obj();
    session.store.onRead = null;
    final replacement = session.viewMode.refresh();
    read.complete(_state(true, true, 10));
    await Future.wait([old, replacement]);
    expect(session.ffiModel.published, [(false, false)]);
    expect(session.store.reads.last.$2, session.clientOwnerId);
  });

  test('view mode admitted save retains capacity through owner retirement', () async {
    final session = _Session();
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    final owner = session.clientOwnerId;
    final saving = session.viewMode.save(ViewModeSetting.showMyCursor, true);
    session.clientOwnerId = Uuid().v4obj();
    await expectLater(session.viewMode.save(ViewModeSetting.viewOnly, false), throwsStateError);
    write.complete(_state(true, true, 1));
    await saving;
    expect(session.viewMode.value, isNull);
    expect(session.ffiModel.published, isEmpty);
    expect(session.store.writes.single.$2, owner);
    await session.viewMode.refresh();
    expect(session.ffiModel.published, [(true, true)]);
  });

  testWidgets('view mode checkbox waits and rejects stale callbacks', (tester) async {
    final session = _Session();
    await _show(tester, session);
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    final old = _box(tester).onChanged!;
    old(true);
    old(true);
    await tester.pump();
    expect(_box(tester).value, false);
    expect(_box(tester).onChanged, isNull);
    expect(session.store.writes.length, 1);
    write.complete(_state(true, false, 1));
    await tester.pump();
    expect(_box(tester).value, true);
    old(false);
    expect(session.store.writes.length, 1);
  });

  testWidgets('view mode failed selection survives menu closure and retries', (tester) async {
    final session = _Session();
    session.store.value = _state(true, true, 1);
    var failures = 0;
    final menu = MenuController();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: MenuAnchor(
        controller: menu,
        menuChildren: [ViewModeControl(ffi: session, translateText: (s) => s,
            showFailure: () => failures++)],
        builder: (context, controller, child) => TextButton(
            onPressed: controller.open, child: const Text('Keyboard settings'))))));
    menu.open();
    await tester.pumpAndSettle();
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    await tester.tap(find.text('View Mode'));
    await tester.pumpAndSettle();
    expect(menu.isOpen, false);
    expect(find.byType(ViewModeControl), findsNothing);
    expect(session.store.writes.length, 1);
    write.completeError(StateError('denied'));
    await tester.pump();
    expect(failures, 1);
    menu.open();
    await tester.pumpAndSettle();
    expect(_box(tester).value, true);
    expect(find.text('Failed'), findsOneWidget);
    session.store.onWrite = null;
    await tester.tap(find.text('Retry'));
    await tester.pump();
    expect(_box(tester).value, false);
    expect(find.text('Failed'), findsNothing);
    expect(session.store.writes.map((e) => e.$4), [false, false]);
  });

  testWidgets('view mode cursor choice updates both shared controls', (tester) async {
    final session = _Session();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: Column(children: [
      ViewModeControl(ffi: session, translateText: (s) => s),
      ViewModeControl(ffi: session, setting: ViewModeSetting.showMyCursor, translateText: (s) => s),
    ]))));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Show my cursor'));
    await tester.pump();
    expect(tester.widgetList<CheckboxMenuButton>(find.byType(CheckboxMenuButton))
        .map((b) => b.value), [true, true]);
    expect(session.store.writes.length, 1);
  });

  testWidgets('view mode replacement rejects late failure and old selection', (tester) async {
    final session = _Session();
    var failures = 0;
    await _show(tester, session, failure: () => failures++);
    final old = _box(tester).onChanged!;
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    old(true);
    session.current = false;
    final replacement = _Session();
    await _show(tester, replacement);
    old(false);
    write.completeError(StateError('retired'));
    await tester.pump();
    expect(failures, 0);
    expect(replacement.store.writes, isEmpty);
    expect(_box(tester).value, false);
  });

  testWidgets('view mode failed read retries without writing a default', (tester) async {
    final session = _Session();
    session.store.onRead = () => Future.error(StateError('unavailable'));
    await _show(tester, session);
    expect(find.byType(CheckboxMenuButton), findsNothing);
    expect(find.text('Failed'), findsOneWidget);
    expect(session.store.writes, isEmpty);
    session.store.onRead = null;
    await tester.tap(find.text('Retry'));
    await tester.pump();
    expect(_box(tester).value, false);
    expect(session.store.writes, isEmpty);
  });

  testWidgets('view mode mobile value also waits for confirmed persistence', (tester) async {
    final previous = isMobile;
    isMobile = true;
    addTearDown(() { isMobile = previous; });
    final session = _Session();
    await _show(tester, session);
    final write = Completer<ViewModeState>();
    session.store.onWrite = (_, __) => write.future;
    await tester.tap(find.text('View Mode'));
    await tester.pump();
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value, false);
    write.complete(_state(true, false, 1));
    await tester.pump();
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value, true);
  });
}

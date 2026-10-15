import 'dart:convert';

import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/terminal_connection_pool.dart';
import 'package:flutter_hbb/models/terminal_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _EqualTerminalOwner {
  @override
  bool operator ==(Object other) => other is _EqualTerminalOwner;

  @override
  int get hashCode => 0;
}

class _TerminalParent implements FFI {
  @override
  String get id => '192.0.2.7';

  @override
  final terminalModels = <int, TerminalModel>{};
  final unexpectedAccess = <Invocation>[];

  @override
  dynamic noSuchMethod(Invocation invocation) {
    unexpectedAccess.add(invocation);
    throw UnsupportedError(
        'Unexpected parent access: ${invocation.memberName}');
  }
}

TerminalModel _install(_TerminalParent parent,
    {Future<void> Function(String data)? sendInput}) {
  final model = TerminalModel(parent, 7, sendInput: sendInput);
  parent.terminalModels[7] = model;
  return model;
}

void _open(TerminalModel model, {bool replay = false}) =>
    model.handleTerminalResponse({
      'type': 'opened',
      'terminal_id': 7,
      'success': true,
      'persistent_sessions': <int>[],
      'replay_terminal_output': replay,
    });

void _data(TerminalModel model, String text) => model.handleTerminalResponse({
      'type': 'data',
      'terminal_id': 7,
      'data': base64Encode(utf8.encode(text)),
    });

void _close(TerminalModel model) => model.handleTerminalResponse({
      'type': 'closed',
      'terminal_id': 7,
      'exit_code': 0,
    });

void main() {
  for (final viewReady in [false, true]) {
    testWidgets('terminal CSI parser resets across reopen ready=$viewReady',
        (tester) async {
      final parent = _TerminalParent();
      final sent = <String>[];
      final model = _install(parent, sendInput: (data) async => sent.add(data));
      addTearDown(model.dispose);
      _open(model);
      if (viewReady) await tester.pump();
      _data(model, '\x1b[5');
      _open(model);
      _data(model, 'n');
      await tester.pump();
      expect(sent, isEmpty);
      _data(model, '\x1b[5n');
      expect(sent, ['\x1b[0n']);
      expect(parent.unexpectedAccess, isEmpty);
    });

    testWidgets('terminal OSC parser resets across reopen ready=$viewReady',
        (tester) async {
      final parent = _TerminalParent();
      final sent = <String>[];
      final titles = <String>[];
      final model = _install(parent, sendInput: (data) async => sent.add(data));
      addTearDown(model.dispose);
      model.terminal.onTitleChange = titles.add;
      _open(model);
      if (viewReady) await tester.pump();
      _data(model, '\x1b]2;old title');
      _open(model);
      _data(model, '\x07');
      await tester.pump();
      expect(titles, isEmpty);
      _data(model, '\x1b]2;current title\x07');
      expect(titles, ['current title']);
      _data(model, '\x1b[5n');
      expect(sent, ['\x1b[0n']);
      expect(parent.unexpectedAccess, isEmpty);
    });
  }

  testWidgets('terminal parser preserves current splits and presented state',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final titles = <String>[];
    final model = _install(parent, sendInput: (data) async => sent.add(data));
    addTearDown(model.dispose);
    final terminal = model.terminal;
    final screen = terminal.buffer;
    terminal.onTitleChange = titles.add;
    _open(model);
    _data(model, 'visible text');
    _data(model, '\x1b[5');
    _data(model, 'n');
    _data(model, '\x1b]2;current');
    _data(model, ' title\x07');
    await tester.pump();
    expect(sent, ['\x1b[0n']);
    expect(titles, ['current title']);
    final cursorX = screen.cursorX;
    final cursorY = screen.cursorY;
    _open(model);
    expect(model.terminal, same(terminal));
    expect(terminal.buffer, same(screen));
    expect(screen.cursorX, cursorX);
    expect(screen.cursorY, cursorY);
    _data(model, '\x1b[5n');
    expect(sent, ['\x1b[0n', '\x1b[0n']);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('reopened terminal cannot answer a queued predecessor query',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final model = _install(parent, sendInput: (data) async => sent.add(data));
    addTearDown(model.dispose);
    _open(model);
    _data(model, '\x1b[5n');
    _open(model);
    await tester.pump();
    expect(sent, isEmpty);
    await model.sendVirtualKey('current input');
    expect(sent, ['current input']);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('closed terminal cannot buffer an old query reply for reopen',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final model = _install(parent, sendInput: (data) async => sent.add(data));
    addTearDown(model.dispose);
    _open(model);
    _data(model, '\x1b[5n');
    _close(model);
    await tester.pump();
    expect(sent, isEmpty);
    _open(model);
    await tester.pump();
    expect(sent, isEmpty);
    await model.sendVirtualKey('current input');
    expect(sent, ['current input']);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('queued terminal queries retain their exact open owner',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final model = _install(parent, sendInput: (data) async => sent.add(data));
    addTearDown(model.dispose);
    _open(model);
    _data(model, '\x1b[5n');
    _close(model);
    _open(model);
    _data(model, '\x1b[6n');
    await tester.pump();
    expect(sent, [matches(r'^\x1b\[[0-9]+;[0-9]+R$')]);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('current terminal query replies preserve replay suppression',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final model = _install(parent, sendInput: (data) async => sent.add(data));
    addTearDown(model.dispose);
    _open(model, replay: true);
    _data(model, '\x1b[5n');
    _data(model, '\x1b[6n');
    await tester.pump();
    expect(sent, [matches(r'^\x1b\[[0-9]+;[0-9]+R$')]);
    _data(model, '\x1b[5n');
    expect(sent, hasLength(2));
    expect(sent.last, '\x1b[0n');
    expect(parent.unexpectedAccess, isEmpty);
  });

  test('terminal pool retains one owner until its last release', () {
    final pool = TerminalConnectionPool<Object>();
    final owner = Object();
    pool.install('peer', owner);
    expect(pool.retain('peer', owner), isTrue);
    expect(pool.referenceCount('peer'), 2);
    expect(pool.release('peer', owner), isNull);
    expect(pool['peer'], same(owner));
    expect(pool.referenceCount('peer'), 1);
    expect(pool.release('peer', owner), same(owner));
    expect(pool['peer'], isNull);
    expect(pool.referenceCount('peer'), 0);
    expect(pool.length, 0);
  });

  test('terminal pool refuses an unowned retain or release', () {
    final pool = TerminalConnectionPool<Object>();
    final owner = Object();
    final foreign = Object();
    pool.install('peer', owner);
    expect(pool.retain('peer', foreign), isFalse);
    expect(pool.release('peer', foreign), isNull);
    expect(pool['peer'], same(owner));
    expect(pool.referenceCount('peer'), 1);
    expect(pool.length, 1);
  });

  test('terminal pool replacement survives old page releases', () {
    final pool = TerminalConnectionPool<Object>();
    final oldOwner = Object();
    final newOwner = Object();
    pool.install('peer', oldOwner);
    expect(pool.retain('peer', oldOwner), isTrue);
    pool.install('peer', newOwner);
    expect(pool.release('peer', oldOwner), isNull);
    expect(pool.release('peer', oldOwner), isNull);
    expect(pool['peer'], same(newOwner));
    expect(pool.referenceCount('peer'), 1);
    expect(pool.release('peer', newOwner), same(newOwner));
  });

  test('terminal pool authority uses identity rather than equality', () {
    final pool = TerminalConnectionPool<_EqualTerminalOwner>();
    final owner = _EqualTerminalOwner();
    final equalOwner = _EqualTerminalOwner();
    expect(owner, equalOwner);
    pool.install('peer', owner);
    expect(pool.retain('peer', equalOwner), isFalse);
    expect(pool.release('peer', equalOwner), isNull);
    expect(pool['peer'], same(owner));
    expect(pool.referenceCount('peer'), 1);
    pool.install('peer', equalOwner);
    expect(pool.release('peer', owner), isNull);
    expect(pool['peer'], same(equalOwner));
    expect(pool.referenceCount('peer'), 1);
  });

  test('terminal pool retires its slot before external cleanup', () {
    final pool = TerminalConnectionPool<Object>();
    final owner = Object();
    final successor = Object();
    final independent = Object();
    pool.install('peer', owner);
    pool.install('other', independent);
    final retired = pool.release('peer', owner);
    expect(retired, same(owner));
    expect(pool['peer'], isNull);
    pool.install('peer', successor);
    expect(pool.release('peer', retired!), isNull);
    expect(pool['peer'], same(successor));
    expect(pool['other'], same(independent));
    expect(pool.length, 2);
  });

  test('terminal pool cannot reset a live owner reference count', () {
    final pool = TerminalConnectionPool<Object>();
    final owner = Object();
    pool.install('peer', owner);
    expect(pool.retain('peer', owner), isTrue);
    expect(() => pool.install('peer', owner), throwsStateError);
    expect(pool.referenceCount('peer'), 2);
    expect(pool['peer'], same(owner));
  });

  testWidgets('current terminal open completion notifies once', (tester) async {
    final parent = _TerminalParent();
    final model = _install(parent);
    var notifications = 0;
    model.addListener(() => notifications++);
    _open(model);
    expect(notifications, 0);
    await tester.pump();
    expect(notifications, 1);
    expect(model.terminalOpened, isTrue);
    expect(parent.unexpectedAccess, isEmpty);
    model.dispose();
  });

  testWidgets('disposed terminal ignores delayed open completion',
      (tester) async {
    final parent = _TerminalParent();
    final model = _install(parent);
    _open(model);
    model.dispose();
    await tester.pump();
    expect(tester.takeException(), isNull);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('replacement terminal retires predecessor open notification',
      (tester) async {
    final parent = _TerminalParent();
    final predecessor = _install(parent);
    var oldNotifications = 0;
    predecessor.addListener(() => oldNotifications++);
    _open(predecessor);
    final successor = _install(parent);
    await tester.pump();
    expect(oldNotifications, 0);
    expect(successor.terminalOpened, isFalse);
    expect(parent.unexpectedAccess, isEmpty);
    predecessor.dispose();
    successor.dispose();
  });

  testWidgets('terminal close retires its pending open notification',
      (tester) async {
    final parent = _TerminalParent();
    final model = _install(parent);
    var notifications = 0;
    model.addListener(() => notifications++);
    _open(model);
    model.handleTerminalResponse({
      'type': 'closed',
      'terminal_id': 7,
      'exit_code': 0,
    });
    expect(notifications, 1);
    await tester.pump();
    expect(notifications, 1);
    expect(model.terminalOpened, isFalse);
    expect(parent.unexpectedAccess, isEmpty);
    model.dispose();
  });

  testWidgets('terminal reopen retires the previous open completion',
      (tester) async {
    final parent = _TerminalParent();
    final model = _install(parent);
    var notifications = 0;
    model.addListener(() => notifications++);
    _open(model);
    _open(model);
    await tester.pump();
    expect(notifications, 1);
    expect(model.terminalOpened, isTrue);
    expect(parent.unexpectedAccess, isEmpty);
    model.dispose();
  });
}

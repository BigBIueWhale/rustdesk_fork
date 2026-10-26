import 'dart:async';
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
  testWidgets('terminal live input follows the complete pre-open buffer',
      (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final firstSent = Completer<void>();
    final model = _install(parent, sendInput: (data) async {
      sent.add(data);
      if (data == 'first') await firstSent.future;
    });
    addTearDown(model.dispose);
    await model.sendVirtualKey('first');
    await model.sendVirtualKey('second');
    _open(model);
    final live = model.sendVirtualKey('third');
    final whilePending = List<String>.of(sent);
    firstSent.complete();
    await tester.pump();
    await live;
    expect(whilePending, ['first']);
    expect(sent, ['first', 'second', 'third']);
    expect(parent.unexpectedAccess, isEmpty);
  });

  testWidgets('terminal live input has one ordered sender', (tester) async {
    final parent = _TerminalParent();
    final sent = <String>[];
    final firstSent = Completer<void>();
    var active = 0;
    var peak = 0;
    final model = _install(parent, sendInput: (data) async {
      active++;
      if (active > peak) peak = active;
      sent.add(data);
      if (sent.length == 1) await firstSent.future;
      active--;
    });
    addTearDown(model.dispose);
    _open(model);
    await tester.pump();
    final first = model.sendVirtualKey('echo π');
    final second = model.sendVirtualKey('\r');
    final third = model.sendVirtualKey('next\nline');
    final whilePending = List<String>.of(sent);
    firstSent.complete();
    await tester.pump();
    await Future.wait([first, second, third]);
    expect(whilePending, ['echo π']);
    expect(sent, ['echo π', '\r', 'next\nline']);
    expect(peak, 1);
    expect(active, 0);
    await model.sendVirtualKey('later');
    expect(sent.last, 'later');
    expect(parent.unexpectedAccess, isEmpty);
  });

  for (final retirement in ['close', 'reopen', 'replace', 'dispose']) {
    testWidgets('terminal pending input retires on $retirement', (tester) async {
      final parent = _TerminalParent();
      final sent = <String>[];
      final firstSent = Completer<void>();
      Future<void> send(String data) async {
        sent.add(data);
        if (data == 'old first') await firstSent.future;
      }

      final model = _install(parent, sendInput: send);
      addTearDown(model.dispose);
      _open(model);
      await tester.pump();
      final first = model.sendVirtualKey('old first');
      final second = model.sendVirtualKey('old second');
      if (retirement == 'close') {
        _close(model);
        await model.sendVirtualKey('current');
        firstSent.complete();
        await tester.pump();
        _open(model);
      } else if (retirement == 'reopen') {
        _open(model);
        await model.sendVirtualKey('current');
      } else {
        if (retirement == 'dispose') model.dispose();
        final successor = _install(parent, sendInput: send);
        addTearDown(successor.dispose);
        _open(successor);
        await successor.sendVirtualKey('current');
      }
      if (!firstSent.isCompleted) firstSent.complete();
      await tester.pump();
      await Future.wait([first, second]);
      expect(sent, ['old first', 'current']);
      expect(parent.unexpectedAccess, isEmpty);
    });
  }

  for (final synchronous in [false, true]) {
    testWidgets('terminal input recovers after send failure sync=$synchronous',
        (tester) async {
      final parent = _TerminalParent();
      final sent = <String>[];
      final model = _install(parent, sendInput: (data) {
        sent.add(data);
        if (data == 'refused') {
          if (synchronous) throw StateError('controlled send refusal');
          return Future<void>.error(StateError('controlled send refusal'));
        }
        return Future<void>.value();
      });
      addTearDown(model.dispose);
      await model.sendVirtualKey('refused');
      await model.sendVirtualKey('buffered');
      _open(model);
      final current = model.sendVirtualKey('current');
      await tester.pump();
      await current;
      expect(sent, ['refused', 'buffered', 'current']);
      await model.sendVirtualKey('retry');
      expect(sent.last, 'retry');
      expect(tester.takeException(), isNull);
      expect(parent.unexpectedAccess, isEmpty);
    });
  }

  testWidgets('terminal input stalls only its own model', (tester) async {
    final firstParent = _TerminalParent();
    final secondParent = _TerminalParent();
    final firstSent = Completer<void>();
    final sent = <String>[];
    final first = _install(firstParent, sendInput: (_) => firstSent.future);
    final second =
        _install(secondParent, sendInput: (data) async => sent.add(data));
    addTearDown(first.dispose);
    addTearDown(second.dispose);
    _open(first);
    _open(second);
    await tester.pump();
    final pending = first.sendVirtualKey('stalled');
    await second.sendVirtualKey('independent');
    expect(sent, ['independent']);
    firstSent.complete();
    await tester.pump();
    await pending;
    expect(firstParent.unexpectedAccess, isEmpty);
    expect(secondParent.unexpectedAccess, isEmpty);
  });

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

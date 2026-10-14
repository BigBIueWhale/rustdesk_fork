import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/terminal_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _TerminalParent implements FFI {
  @override
  String get id => '192.0.2.7';

  @override
  final terminalModels = <int, TerminalModel>{};
  final unexpectedAccess = <Invocation>[];

  @override
  dynamic noSuchMethod(Invocation invocation) {
    unexpectedAccess.add(invocation);
    throw UnsupportedError('Unexpected parent access: ${invocation.memberName}');
  }
}

TerminalModel _install(_TerminalParent parent) {
  final model = TerminalModel(parent, 7);
  parent.terminalModels[7] = model;
  return model;
}

void _open(TerminalModel model) => model.handleTerminalResponse({
      'type': 'opened',
      'terminal_id': 7,
      'success': true,
      'persistent_sessions': <int>[],
    });

void main() {
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

  testWidgets('disposed terminal ignores delayed open completion', (tester) async {
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

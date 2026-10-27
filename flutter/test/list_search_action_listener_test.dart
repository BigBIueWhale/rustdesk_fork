import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/desktop/widgets/list_search_action_listener.dart';
import 'package:flutter_test/flutter_test.dart';

class _Subject {
  final left = FocusNode();
  final right = FocusNode();
  final other = FocusNode();
  final row = FocusNode();
  final leftBuffer = TimeoutStringBuffer();
  final rightBuffer = TimeoutStringBuffer();
  final events = <String>[];
  final shortcuts = <ShortcutActivator, VoidCallback>{};
  var leftResult = '';
  var rightResult = '';

  Widget build() => MaterialApp(
        home: Scaffold(
          body: StatefulBuilder(builder: (context, setState) {
            void report(String pane, String action, String value) {
              final result = '$pane:$action:$value';
              events.add(result);
              setState(() {
                if (pane == 'left') {
                  leftResult = result;
                } else {
                  rightResult = result;
                }
              });
            }

            return CallbackShortcuts(bindings: shortcuts, child: Column(children: [
              ListSearchActionListener(
                node: left,
                buffer: leftBuffer,
                onSearch: (value) => report('left', 'search', value),
                onNext: (value) => report('left', 'next', value),
                child: Focus(focusNode: row, child: Text(leftResult)),
              ),
              ListSearchActionListener(
                node: right,
                buffer: rightBuffer,
                onSearch: (value) => report('right', 'search', value),
                onNext: (value) => report('right', 'next', value),
                child: Text(rightResult),
              ),
              TextField(focusNode: other),
            ]));
          }),
        ),
      );

  Future<void> show(WidgetTester tester) async {
    addTearDown(() => dispose(tester));
    await tester.pumpWidget(build());
    await focus(tester, left);
  }

  Future<void> focus(WidgetTester tester, FocusNode node) async {
    node.requestFocus();
    await tester.pump();
    expect(node.hasPrimaryFocus, isTrue);
  }

  Future<void> dispose(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    left.dispose();
    right.dispose();
    other.dispose();
    row.dispose();
  }
}

Future<void> _type(WidgetTester tester, LogicalKeyboardKey key,
    String character) async {
  await tester.sendKeyEvent(key, character: character);
  await tester.pump();
}

void main() {
  late int originalTimeout;
  setUp(() {
    originalTimeout = TimeoutStringBuffer.timeoutMilliSec;
    // Focus retirement must work without relying on elapsed-time expiry.
    TimeoutStringBuffer.timeoutMilliSec = 60000;
  });
  tearDown(() => TimeoutStringBuffer.timeoutMilliSec = originalTimeout);

  for (final modifier in [
    LogicalKeyboardKey.controlLeft,
    LogicalKeyboardKey.controlRight,
    LogicalKeyboardKey.metaLeft,
    LogicalKeyboardKey.metaRight,
  ]) {
    testWidgets('list search ignores ${modifier.keyLabel} shortcuts',
        (tester) async {
      final subject = _Subject();
      var commands = 0;
      final control = modifier == LogicalKeyboardKey.controlLeft ||
          modifier == LogicalKeyboardKey.controlRight;
      for (final shift in [false, true]) {
        subject.shortcuts[SingleActivator(LogicalKeyboardKey.keyC,
            control: control, meta: !control, shift: shift)] = () => commands++;
      }
      await subject.show(tester);
      for (final shift in [false, true]) {
        subject.leftBuffer.clear();
        subject.events.clear();
        commands = 0;
        await _type(tester, LogicalKeyboardKey.keyA, 'a');
        await tester.sendKeyDownEvent(modifier);
        if (shift) await tester.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
        await tester.sendKeyDownEvent(LogicalKeyboardKey.keyC,
            character: shift ? 'C' : 'c');
        await tester.sendKeyRepeatEvent(LogicalKeyboardKey.keyC,
            character: shift ? 'C' : 'c');
        await tester.sendKeyUpEvent(LogicalKeyboardKey.keyC);
        if (shift) await tester.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
        await tester.sendKeyUpEvent(modifier);
        await tester.pump();
        expect(commands, 2, reason: 'shortcut propagation, shift=$shift');
        expect(subject.events, ['left:search:a'], reason: 'shift=$shift');
        expect(subject.leftBuffer.buffer, 'a');
        expect(find.text('left:search:a'), findsOneWidget);
        await _type(tester, LogicalKeyboardKey.keyB, 'b');
        expect(subject.events, ['left:search:a', 'left:search:ab']);
      }
    });
  }

  testWidgets('list search preserves shifted Option and AltGr characters',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    for (final (modifiers, character) in [
      (<LogicalKeyboardKey>[], 'é'),
      (<LogicalKeyboardKey>[], '😀'),
      ([LogicalKeyboardKey.shiftLeft], 'A'),
      ([LogicalKeyboardKey.altLeft], 'ß'),
      ([LogicalKeyboardKey.altRight], '@'),
      ([LogicalKeyboardKey.controlLeft, LogicalKeyboardKey.altRight], '@'),
      ([LogicalKeyboardKey.controlLeft, LogicalKeyboardKey.altLeft], '€'),
      ([LogicalKeyboardKey.controlRight, LogicalKeyboardKey.altRight,
        LogicalKeyboardKey.shiftRight], 'É'),
    ]) {
      subject.leftBuffer.clear();
      subject.events.clear();
      for (final modifier in modifiers) {
        await tester.sendKeyDownEvent(modifier);
      }
      await tester.sendKeyDownEvent(LogicalKeyboardKey.keyQ, character: character);
      await tester.sendKeyRepeatEvent(LogicalKeyboardKey.keyQ, character: character);
      await tester.sendKeyUpEvent(LogicalKeyboardKey.keyQ);
      for (final modifier in modifiers.reversed) {
        await tester.sendKeyUpEvent(modifier);
      }
      await tester.pump();
      final query = character.toLowerCase();
      expect(subject.events, ['left:search:$query', 'left:next:$query']);
      expect(subject.leftBuffer.buffer, query);
      expect(find.text('left:next:$query'), findsOneWidget);
    }
  });

  testWidgets('list search accumulates and cycles while focus stays inside',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'A');
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await _type(tester, LogicalKeyboardKey.keyB, 'b');
    expect(subject.events,
        ['left:search:a', 'left:next:a', 'left:search:ab']);
    expect(find.text('left:search:ab'), findsOneWidget);
  });

  testWidgets('list search starts fresh after focus returns from another control',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await subject.focus(tester, subject.other);
    await tester.enterText(find.byType(TextField), 'location');
    expect(subject.events, ['left:search:a']);
    await subject.focus(tester, subject.left);
    await _type(tester, LogicalKeyboardKey.keyB, 'b');
    expect(subject.events, ['left:search:a', 'left:search:b']);
    expect(find.text('left:search:b'), findsOneWidget);
  });

  testWidgets('list search keeps pane histories separate after switching back',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await subject.focus(tester, subject.right);
    await _type(tester, LogicalKeyboardKey.keyB, 'b');
    await subject.focus(tester, subject.left);
    await _type(tester, LogicalKeyboardKey.keyC, 'c');
    await subject.focus(tester, subject.right);
    await _type(tester, LogicalKeyboardKey.keyD, 'd');
    expect(subject.events, [
      'left:search:a', 'right:search:b', 'left:search:c', 'right:search:d'
    ]);
    expect(find.text('left:search:c'), findsOneWidget);
    expect(find.text('right:search:d'), findsOneWidget);
  });

  testWidgets('list search preserves a prefix when a descendant takes focus',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await subject.focus(tester, subject.row);
    expect(subject.left.hasFocus, isTrue);
    await _type(tester, LogicalKeyboardKey.keyB, 'b');
    await subject.focus(tester, subject.left);
    await _type(tester, LogicalKeyboardKey.keyC, 'c');
    expect(subject.events,
        ['left:search:a', 'left:search:ab', 'left:search:abc']);
    expect(find.text('left:search:abc'), findsOneWidget);
  });

  testWidgets('list search preserves a prefix across a parent rebuild',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await tester.pumpWidget(subject.build());
    expect(subject.left.hasPrimaryFocus, isTrue);
    await _type(tester, LogicalKeyboardKey.keyB, 'b');
    expect(subject.events, ['left:search:a', 'left:search:ab']);
    expect(find.text('left:search:ab'), findsOneWidget);
  });

  testWidgets('list search resets repeated character cycling after focus leaves',
      (tester) async {
    final subject = _Subject();
    await subject.show(tester);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    await subject.focus(tester, subject.other);
    await subject.focus(tester, subject.left);
    await _type(tester, LogicalKeyboardKey.keyA, 'a');
    expect(subject.events,
        ['left:search:a', 'left:next:a', 'left:search:a']);
    expect(find.text('left:search:a'), findsOneWidget);
  });
}

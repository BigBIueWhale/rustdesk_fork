import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart' as overlay;
import 'package:flutter_test/flutter_test.dart';

const _keys = [
  overlay.DraggablePositions.kChatWindow,
  overlay.DraggablePositions.kMobileActions,
  overlay.DraggablePositions.kIOSDraggable,
];

overlay.DraggableKeyPosition _load(String value, [String? key]) {
  final expectedKey = key ?? _keys.first;
  final position = overlay.DraggableKeyPosition(expectedKey, readOption: (key) {
    expect(key, expectedKey);
    return value;
  });
  position.load();
  return position;
}

class _MemoryPosition extends overlay.DraggableKeyPosition {
  _MemoryPosition(this.pos) : super('keyboard-position');

  @override
  Offset pos;
  final updates = <Offset>[];

  @override
  void update(Offset value) {
    pos = value;
    updates.add(value);
  }

  // These cases start inside the screen and isolate keyboard layout from storage.
  @override
  void tryAdjust(double w, double h, double scale) {}
}

Future<void> _keyboardPanel(WidgetTester tester, _MemoryPosition position,
    String kind, double inset, {double height = 80}) async {
  await tester.pumpWidget(MaterialApp(
    home: MediaQuery(
      data: MediaQueryData(size: const Size(800, 600),
          viewInsets: EdgeInsets.only(bottom: inset)),
      child: kind == 'ios'
          ? overlay.IOSDraggable(position: position, width: 120, height: height,
              builder: (_) => const SizedBox.expand(key: ValueKey('panel')))
          : overlay.Draggable(position: position, width: 120, height: height,
              checkKeyboard: true,
              builder: (_, __) => const SizedBox.expand(key: ValueKey('panel'))),
    ),
  ));
}

void _expectPanel(WidgetTester tester, _MemoryPosition position, double y) {
  final panel = find.ancestor(of: find.byKey(const ValueKey('panel')),
      matching: find.byType(Positioned));
  expect(tester.getTopLeft(panel), Offset(40, y));
  expect(position.pos, Offset(40, y));
  expect(tester.takeException(), isNull);
}

void main() {
  for (final kind in ['standard', 'ios']) {
    testWidgets('floating $kind panel avoids the first keyboard inset and restores',
        (tester) async {
      final position = _MemoryPosition(const Offset(40, 450));
      await _keyboardPanel(tester, position, kind, 0);
      _expectPanel(tester, position, 450);
      await _keyboardPanel(tester, position, kind, 300);
      _expectPanel(tester, position, 220);
      await _keyboardPanel(tester, position, kind, 350);
      _expectPanel(tester, position, 170);
      await _keyboardPanel(tester, position, kind, 0);
      _expectPanel(tester, position, 450);
      await _keyboardPanel(tester, position, kind, 200);
      _expectPanel(tester, position, 320);
      await _keyboardPanel(tester, position, kind, 0);
      _expectPanel(tester, position, 450);
    });

    testWidgets('floating $kind panel opens above an already visible keyboard',
        (tester) async {
      final position = _MemoryPosition(const Offset(40, 450));
      await _keyboardPanel(tester, position, kind, 300);
      _expectPanel(tester, position, 220);
      await _keyboardPanel(tester, position, kind, 0);
      _expectPanel(tester, position, 450);
    });

    testWidgets('floating $kind panel keeps its top reachable in a short viewport',
        (tester) async {
      final position = _MemoryPosition(const Offset(40, 150));
      await _keyboardPanel(tester, position, kind, 250, height: 400);
      await _keyboardPanel(tester, position, kind, 300, height: 400);
      _expectPanel(tester, position, 0);
      await _keyboardPanel(tester, position, kind, 0, height: 400);
      _expectPanel(tester, position, 150);
    });

    testWidgets('floating $kind panel preserves an unobscured position',
        (tester) async {
      final position = _MemoryPosition(const Offset(40, 40));
      await _keyboardPanel(tester, position, kind, 0);
      await _keyboardPanel(tester, position, kind, 300);
      _expectPanel(tester, position, 40);
      expect(position.updates, isEmpty);
      await _keyboardPanel(tester, position, kind, 0);
      _expectPanel(tester, position, 40);
    });
  }

  test('floating position preserves finite saved coordinates', () {
    const values = {
      '0,0': Offset.zero,
      '12.5,34.75': Offset(12.5, 34.75),
      '-10,-20': Offset(-10, -20),
      ' 1.5 , 2.5 ': Offset(1.5, 2.5),
      '1e2,-2e1': Offset(100, -20),
      '1e100,-1e100': Offset(1e100, -1e100),
    };
    for (final key in _keys) {
      for (final entry in values.entries) {
        final position = _load(entry.key, key);
        expect(position.pos, entry.value, reason: '$key: ${entry.key}');
        expect(position.isInvalid(), isFalse);
      }
    }
  });

  test('floating position treats absent or wrong arity as unset', () {
    for (final value in ['', '12', '12,34,56', ',,', '12;34']) {
      expect(_load(value).isInvalid(), isTrue, reason: value);
    }
    expect(_load('-999999,-999999').isInvalid(), isTrue);
  });

  test('floating position rejects malformed coordinates without throwing', () {
    final outcomes = <String, Object>{};
    for (final value in [
      ',', ',2', '1,', 'word,2', '1,word', ' , ', '0x10,2', '1,2px'
    ]) {
      try {
        outcomes[value] = _load(value).isInvalid();
      } catch (error) {
        outcomes[value] = error.runtimeType.toString();
      }
    }
    debugPrint('FLOATING_POSITION malformed=$outcomes');
    expect(outcomes.values, everyElement(isTrue));
  });

  test('floating position rejects nonfinite coordinates', () {
    final outcomes = <String, bool>{};
    for (final value in [
      'NaN,2', '1,NaN', '-NaN,2', 'Infinity,2', '1,Infinity',
      '-Infinity,2', '1,-Infinity', '1e999,2', '1,-1e999'
    ]) {
      outcomes[value] = _load(value).isInvalid();
    }
    debugPrint('FLOATING_POSITION nonfinite=$outcomes');
    expect(outcomes.values, everyElement(isTrue));
  });

  test('floating position reload discards an invalid saved checkpoint', () {
    var stored = '12,34';
    final position = overlay.DraggableKeyPosition(_keys.first,
        readOption: (_) => stored);
    position.load();
    expect(position.pos, const Offset(12, 34));
    stored = 'NaN,34';
    position.load();
    expect(position.isInvalid(), isTrue);
    stored = '56,78';
    position.load();
    expect(position.pos, const Offset(56, 78));
  });

  test('floating position invalid data leaves other positions loadable', () {
    final saved = {
      _keys[0]: 'broken,34',
      _keys[1]: '56,78',
      _keys[2]: '90,12',
    };
    final reads = <String>[];
    final positions = [
      for (final key in _keys)
        overlay.DraggableKeyPosition(key, readOption: (key) {
          reads.add(key);
          return saved[key]!;
        }),
    ];
    for (final position in positions) {
      position.load();
    }
    expect(reads, _keys);
    expect(positions[0].isInvalid(), isTrue);
    expect(positions[1].pos, const Offset(56, 78));
    expect(positions[2].pos, const Offset(90, 12));
    expect(saved[_keys.first], 'broken,34');
  });

  testWidgets('floating position places the actual draggable at saved coordinates',
      (tester) async {
    final position = _load('40.5,60.25');
    const target = ValueKey('floating-content');
    await tester.pumpWidget(MaterialApp(
      home: overlay.Draggable(
        position: position,
        width: 120,
        height: 80,
        builder: (_, __) => const SizedBox.expand(key: target),
      ),
    ));
    expect(tester.getTopLeft(find.byKey(target)), const Offset(40.5, 60.25));
    expect(tester.getSize(find.byKey(target)), const Size(120, 80));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  test('floating position preserves storage read errors', () {
    final error = StateError('read failed');
    final position = overlay.DraggableKeyPosition(_keys.first,
        readOption: (_) => throw error);
    expect(position.load, throwsA(same(error)));
    expect(position.isInvalid(), isTrue);
  });
}

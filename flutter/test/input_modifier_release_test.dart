import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart' show KeyEventResult;
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;

const modifierKeys = [
  LogicalKeyboardKey.altLeft,
  LogicalKeyboardKey.altRight,
  LogicalKeyboardKey.controlLeft,
  LogicalKeyboardKey.controlRight,
  LogicalKeyboardKey.shiftLeft,
  LogicalKeyboardKey.shiftRight,
  LogicalKeyboardKey.metaLeft,
  LogicalKeyboardKey.metaRight,
  LogicalKeyboardKey.superKey,
];

class _UnusedOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw StateError('Modifier bookkeeping must not access the session');
  }
}

RawKeyEvent rawEvent(LogicalKeyboardKey key,
    {required bool down, int modifiers = 0}) {
  final data = RawKeyEventDataLinux(
    keyHelper: GtkKeyHelper(),
    scanCode: modifierKeys.indexOf(key) + 200,
    modifiers: modifiers,
    specifiedLogicalKey: key.keyId,
    isDown: down,
  );
  return down ? RawKeyDownEvent(data: data) : RawKeyUpEvent(data: data);
}

void seedRaw(ToReleaseRawKeys keys, LogicalKeyboardKey key) {
  final event = rawEvent(key, down: true);
  switch (key) {
    case LogicalKeyboardKey.altLeft:
      keys.lastLAltKeyEvent = event;
    case LogicalKeyboardKey.altRight:
      keys.lastRAltKeyEvent = event;
    case LogicalKeyboardKey.controlLeft:
      keys.lastLCtrlKeyEvent = event;
    case LogicalKeyboardKey.controlRight:
      keys.lastRCtrlKeyEvent = event;
    case LogicalKeyboardKey.shiftLeft:
      keys.lastLShiftKeyEvent = event;
    case LogicalKeyboardKey.shiftRight:
      keys.lastRShiftKeyEvent = event;
    case LogicalKeyboardKey.metaLeft:
      keys.lastLCommandKeyEvent = event;
    case LogicalKeyboardKey.metaRight:
      keys.lastRCommandKeyEvent = event;
    case LogicalKeyboardKey.superKey:
      keys.lastSuperKeyEvent = event;
  }
}

KeyEvent keyEvent(LogicalKeyboardKey key, {required bool down}) {
  // The bookkeeping retains the supplied physical identity unchanged.
  final physical = PhysicalKeyboardKey(key.keyId);
  return down
      ? KeyDownEvent(
          logicalKey: key, physicalKey: physical, timeStamp: Duration.zero)
      : KeyUpEvent(
          logicalKey: key, physicalKey: physical, timeStamp: Duration.zero);
}

List<LogicalKeyboardKey> pendingRaw(ToReleaseRawKeys keys) {
  final events = <LogicalKeyboardKey>[];
  keys.release((event) {
    events.add(event.logicalKey);
    return KeyEventResult.handled;
  });
  return events;
}

List<KeyEvent> pendingKeys(ToReleaseKeys keys) {
  final events = <KeyEvent>[];
  keys.release((event) {
    events.add(event);
    return KeyEventResult.handled;
  });
  return events;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _UnusedOwner owner;
  late InputModel model;
  setUp(() {
    owner = _UnusedOwner();
    model = InputModel(WeakReference(owner));
  });
  tearDown(() {
    // No relative mouse operation or native session is started by these tests.
    model.relativeMouseMode.close();
    RawKeyboard.instance.clearKeysPressed();
  });

  test('right Alt retains its own release identity', () {
    model.handleKeyDownEventModifiers(
        keyEvent(LogicalKeyboardKey.altRight, down: true));
    expect(model.toReleaseKeys.lastLAltKeyEvent, isNull);
    expect(model.toReleaseKeys.lastRAltKeyEvent?.logicalKey,
        LogicalKeyboardKey.altRight);
  });

  test('modern modifier release preserves the other held side', () {
    for (var i = 0; i < 8; i += 2) {
      final left = modifierKeys[i];
      final right = modifierKeys[i + 1];
      model.handleKeyDownEventModifiers(keyEvent(left, down: true));
      model.handleKeyDownEventModifiers(keyEvent(right, down: true));
      model.handleKeyUpEventModifiers(keyEvent(left, down: false));
      final pending = pendingKeys(model.toReleaseKeys);
      expect(pending.map((e) => e.logicalKey), [right]);
      final flags = model.modify(<String, dynamic>{});
      final flag = ['alt', 'ctrl', 'shift', 'command'][i ~/ 2];
      expect(flags[flag], 'true', reason: right.keyLabel);
      model.handleKeyUpEventModifiers(keyEvent(right, down: false));
      expect(model.modify(<String, dynamic>{}), isEmpty);
      expect(pendingKeys(model.toReleaseKeys), isEmpty);
    }
  });

  test('modern focus cleanup emits every held modifier once', () {
    for (final key in modifierKeys) {
      model.handleKeyDownEventModifiers(keyEvent(key, down: true));
    }
    final released = <LogicalKeyboardKey>[];
    model.toReleaseKeys.release((event) {
      expect(event, isA<KeyUpEvent>());
      released.add(event.logicalKey);
      model.handleKeyUpEventModifiers(event);
      return KeyEventResult.handled;
    });
    expect(released, unorderedEquals(modifierKeys));
    expect(pendingKeys(model.toReleaseKeys), isEmpty);
    expect(model.modify(<String, dynamic>{}), isEmpty);
  });

  test('modern reset removes pending modifier releases', () {
    for (final key in modifierKeys) {
      model.handleKeyDownEventModifiers(keyEvent(key, down: true));
    }
    model.toReleaseKeys.reset();
    model.resetModifiers();
    expect(pendingKeys(model.toReleaseKeys), isEmpty);
    expect(model.modify(<String, dynamic>{}), isEmpty);
  });

  test('raw tracking uses the changed key without aggregate state', () {
    final keys = ToReleaseRawKeys();
    for (final key in modifierKeys) {
      final event = rawEvent(key, down: true) as RawKeyDownEvent;
      keys.updateKeyDown(event.logicalKey, event);
    }
    expect(pendingRaw(keys), unorderedEquals(modifierKeys));
  });

  test('raw chord retains every changed modifier', () async {
    final keys = ToReleaseRawKeys();
    const modifiers = GtkKeyHelper.modifierMod1 |
        GtkKeyHelper.modifierControl |
        GtkKeyHelper.modifierShift |
        GtkKeyHelper.modifierMeta;
    for (final key in modifierKeys.take(8)) {
      final event =
          rawEvent(key, down: true, modifiers: modifiers) as RawKeyDownEvent;
      await RawKeyboard.instance.handleRawKeyEvent(event);
      keys.updateKeyDown(event.logicalKey, event);
    }
    expect(pendingRaw(keys), unorderedEquals(modifierKeys.take(8)));
  });

  test('raw key up retires its key after aggregate state is clear', () {
    final keys = ToReleaseRawKeys();
    for (final key in modifierKeys) {
      final up = rawEvent(key, down: false) as RawKeyUpEvent;
      // Seed an admitted press, independently of the defect in updateKeyDown.
      seedRaw(keys, key);
      keys.updateKeyUp(key, up);
      expect(pendingRaw(keys), isEmpty, reason: key.keyLabel);
      keys.reset();
    }
  });

  test('raw key up preserves a different held modifier', () {
    final keys = ToReleaseRawKeys();
    final left = rawEvent(LogicalKeyboardKey.altLeft, down: true);
    final right = rawEvent(LogicalKeyboardKey.altRight, down: true);
    keys.lastLAltKeyEvent = left;
    keys.lastRAltKeyEvent = right;
    keys.updateKeyUp(LogicalKeyboardKey.altLeft,
        rawEvent(LogicalKeyboardKey.altLeft, down: false) as RawKeyUpEvent);
    expect(pendingRaw(keys), [LogicalKeyboardKey.altRight]);
  });

  test('raw focus cleanup retires each exact pending release', () {
    final keys = ToReleaseRawKeys();
    seedRaw(keys, LogicalKeyboardKey.shiftLeft);
    seedRaw(keys, LogicalKeyboardKey.controlRight);
    final released = <LogicalKeyboardKey>[];
    keys.release((event) {
      expect(event, isA<RawKeyUpEvent>());
      released.add(event.logicalKey);
      keys.updateKeyUp(event.logicalKey, event as RawKeyUpEvent);
      return KeyEventResult.handled;
    });
    expect(released,
        [LogicalKeyboardKey.shiftLeft, LogicalKeyboardKey.controlRight]);
    expect(pendingRaw(keys), isEmpty);
  });

  test('ordinary raw keys and reset cannot retain modifier ownership', () {
    final keys = ToReleaseRawKeys();
    final event = rawEvent(LogicalKeyboardKey.keyA, down: true);
    keys.updateKeyDown(event.logicalKey, event as RawKeyDownEvent);
    expect(pendingRaw(keys), isEmpty);
    keys.lastLAltKeyEvent = rawEvent(LogicalKeyboardKey.altLeft, down: true);
    keys.reset();
    expect(pendingRaw(keys), isEmpty);
  });
}

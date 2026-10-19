import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart' show KeyEventResult;
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/common.dart' as common;
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/models/flutter_keyboard_input.dart';
import 'package:flutter_hbb/models/model.dart' show FFI, FfiModel, ConnType;
import 'package:flutter_hbb/consts.dart';
import 'package:uuid/uuid.dart';

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

class _Backend implements FlutterKeyboardInputBackend {
  @override
  bool useFlutterInput = true;
  String round = 'first-round';
  Future<String> Function()? onRead;
  Future<void> Function()? onSend;
  final sends = <(FlutterKeyboardTarget, int, int?, FlutterKeyStroke)>[];
  final releases = <(FlutterKeyboardTarget, int, int?)>[];
  final boundaries = <bool>[];
  @override
  Future<String> readRound(common.SessionID session, common.SessionID client) =>
      onRead?.call() ?? Future.value(round);
  @override
  Future<void> send(FlutterKeyboardTarget target, int sequence, int? slot, FlutterKeyStroke stroke) {
    sends.add((target, sequence, slot, stroke));
    return onSend?.call() ?? Future.value();
  }
  @override
  Future<void> release(FlutterKeyboardTarget target, int sequence, int? slot) async {
    releases.add((target, sequence, slot));
  }
  @override
  void enterOrLeave(common.SessionID session, bool enter) => boundaries.add(enter);
}

class _Session implements FFI {
  _Session(this.backend) {
    ffiModel = FfiModel(WeakReference<FFI>(this));
    ffiModel.pi.version = '1.4.7';
    ffiModel.pi.platform = 'Linux';
    inputModel = InputModel(WeakReference<FFI>(this), keyboardBackend: backend);
  }
  final _Backend backend;
  @override
  common.SessionID sessionId = const Uuid().v4obj();
  @override
  common.SessionID clientOwnerId = const Uuid().v4obj();
  @override
  final String id = 'modifier-ui-test';
  @override
  final connType = ConnType.defaultConn;
  @override
  late final FfiModel ffiModel;
  @override
  late final InputModel inputModel;
  bool current = true;
  @override
  bool isCurrentSessionOwner(common.SessionID session, common.SessionID client) =>
      current && session == sessionId && client == clientOwnerId;
  @override
  bool isCurrentSession(common.SessionID session) => current && session == sessionId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
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
    expect(event, isA<RawKeyUpEvent>());
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

  test('modern release callback visits and clears every modifier slot', () {
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

  test('ordinary raw keys and reset cannot retain modifier ownership', () {
    final keys = ToReleaseRawKeys();
    final event = rawEvent(LogicalKeyboardKey.keyA, down: true);
    keys.updateKeyDown(event.logicalKey, event as RawKeyDownEvent);
    expect(pendingRaw(keys), isEmpty);
    keys.lastLAltKeyEvent = rawEvent(LogicalKeyboardKey.altLeft, down: true);
    keys.reset();
    expect(pendingRaw(keys), isEmpty);
  });

  group('owned modifier dispatch', () {
    late _Backend backend;
    late _Session session;
    late InputModel input;
    setUp(() async {
      backend = _Backend();
      session = _Session(backend);
      input = session.inputModel;
      KeyboardEnabledState.init(session.id);
      await input.resumeKeyboardInput();
    });
    tearDown(() {
      input.suspendKeyboardInput();
      input.relativeMouseMode.close();
      session.ffiModel.dispose();
      KeyboardEnabledState.delete(session.id);
    });

    test('focus leave releases the captured owner in one batch', () {
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.controlLeft, down: true));
      final admitted = backend.sends.single.$1;
      session.sessionId = const Uuid().v4obj();
      session.clientOwnerId = const Uuid().v4obj();
      input.enterOrLeave(false);
      expect(backend.releases.single.$1.sessionId, admitted.sessionId);
      expect(backend.releases.single.$1.clientOwnerId, admitted.clientOwnerId);
      expect(backend.releases.single.$1.epoch, admitted.epoch);
      expect(backend.releases.single.$3, isNull);
      expect(backend.boundaries, [false]);
      expect(pendingKeys(input.toReleaseKeys), isEmpty);
      expect(input.modify(<String, dynamic>{}), isEmpty);
    });

    test('modern key up bypasses changed input source and keyboard mode', () {
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.altRight, down: true));
      final admitted = backend.sends.single;
      backend.useFlutterInput = false;
      input.keyboardMode = kKeyLegacyMode;
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.altRight, down: false));
      expect(backend.sends.length, 1);
      expect(backend.releases.single.$2, admitted.$2);
      expect(backend.releases.single.$3, 5);
      expect(input.alt, isFalse);
    });

    test('raw key up bypasses changed input source and clears its slot', () {
      input.handleRawKeyEvent(rawEvent(LogicalKeyboardKey.shiftRight, down: true));
      final admitted = backend.sends.single;
      backend.useFlutterInput = false;
      input.handleRawKeyEvent(rawEvent(LogicalKeyboardKey.shiftRight, down: false));
      expect(backend.releases.single.$2, admitted.$2);
      expect(backend.releases.single.$3, 1);
      expect(pendingRaw(input.toReleaseRawKeys), isEmpty);
    });

    test('permission revocation retires modifiers before blocking new input', () {
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.controlRight, down: true));
      session.ffiModel.updatePermission({'name': 'permission', 'keyboard': 'false'}, session.id);
      expect(backend.releases.single.$3, isNull);
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.controlRight, down: false));
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.keyA, down: true));
      expect(backend.sends.length, 1);
      expect(input.ctrl, isFalse);
    });

    test('view only retires modifiers and refuses later new input', () {
      input.handleRawKeyEvent(rawEvent(LogicalKeyboardKey.altRight, down: true));
      session.ffiModel.setViewOnly(session.id, true);
      expect(backend.releases.single.$3, isNull);
      input.handleRawKeyEvent(rawEvent(LogicalKeyboardKey.altRight, down: false));
      input.inputKey('a');
      expect(backend.sends.length, 1);
      expect(input.alt, isFalse);
    });

    test('focus cleanup fences a down whose bridge completion is pending', () async {
      final pending = Completer<void>();
      backend.onSend = () => pending.future;
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.shiftLeft, down: true));
      final first = backend.sends.single.$1;
      input.enterOrLeave(false);
      input.enterOrLeave(true);
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.shiftLeft, down: true));
      expect(backend.releases.first.$1.epoch, first.epoch);
      expect(backend.sends.last.$1.epoch, greaterThan(first.epoch));
      pending.complete();
      await pending.future;
      expect(backend.releases.length, 2);
    });

    test('modifier repeats share a sequence and a later press gets a new one', () {
      final down = keyEvent(LogicalKeyboardKey.shiftLeft, down: true);
      input.handleKeyEvent(down);
      input.handleKeyEvent(down);
      expect(backend.sends[0].$2, backend.sends[1].$2);
      input.handleKeyEvent(keyEvent(LogicalKeyboardKey.shiftLeft, down: false));
      input.handleKeyEvent(down);
      expect(backend.sends.last.$2, greaterThan(backend.releases.single.$2));
    });

    test('connection suspension refuses input until a new round is installed', () async {
      input.inputKey('Control_L', down: true, press: false, modifierSlot: 2);
      final old = backend.sends.single.$1;
      input.suspendKeyboardInput();
      input.inputKey('a');
      expect(backend.sends.length, 1);
      backend.round = 'replacement-round';
      await input.resumeKeyboardInput();
      input.inputKey('b');
      expect(backend.sends.last.$1.round, 'replacement-round');
      expect(backend.sends.last.$1.epoch, greaterThan(old.epoch));
    });

    test('retired owner cannot install a late keyboard round', () async {
      final read = Completer<String>();
      backend.onRead = () => read.future;
      final resuming = input.resumeKeyboardInput();
      input.suspendKeyboardInput();
      session.current = false;
      read.complete('late-round');
      await resuming;
      input.inputKey('a');
      expect(backend.sends, isEmpty);
    });

    test('changing the owner during a round read refuses later dispatch', () async {
      final read = Completer<String>();
      backend.onRead = () => read.future;
      final resuming = input.resumeKeyboardInput();
      session.clientOwnerId = const Uuid().v4obj();
      read.complete('late-round');
      await resuming;
      input.inputKey('a');
      expect(backend.sends, isEmpty);
    });
  });
}

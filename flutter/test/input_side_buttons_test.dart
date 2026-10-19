import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/models/flutter_keyboard_input.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Keys implements FlutterKeyboardInputBackend {
  @override
  void enterOrLeave(SessionID session, bool enter) {}
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Side-button tests must not emit keyboard input');
}

class _Owner implements FFI {
  @override
  SessionID sessionId = const Uuid().v4obj();
  @override
  final clientOwnerId = const Uuid().v4obj();
  bool current = true;
  @override
  bool isCurrentSessionOwner(SessionID session, SessionID client) =>
      current && session == sessionId && client == clientOwnerId;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected side-button owner access: ${invocation.memberName}');
}

class _Input extends InputModel {
  _Input(this.owner) : super(WeakReference<FFI>(owner), keyboardBackend: _Keys());
  final _Owner owner;
  final events = <(SessionID, String, MouseButtons)>[];
  Future<void> Function()? onSend;
  bool allowed = true;
  bool viewOnly = false;
  bool cursor = false;
  bool camera = false;
  @override
  String get id => '';
  @override
  bool get keyboardPerm => allowed;
  @override
  bool get isViewOnly => viewOnly;
  @override
  bool get showMyCursor => cursor;
  @override
  bool get isViewCamera => camera;

  // Only the final native bridge send is observed. Method-channel decoding,
  // admission, retained presses, pointer entry and disposal are production code.
  @override
  Future<void> sendSideMouseButton(String type, MouseButtons button,
      {required SessionID expectedSessionId}) {
    events.add((expectedSessionId, type, button));
    return onSend?.call() ?? Future.value();
  }

  void close() {
    disposeSideButtonTracking();
    relativeMouseMode.close();
    isPhysicalMouse.close();
  }
}

Future<void> _message(Object? arguments, {String method = 'onSideMouseButton'}) async {
  const codec = StandardMethodCodec();
  final result = await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .handlePlatformMessage('org.rustdesk.rustdesk/side_buttons',
          codec.encodeMethodCall(MethodCall(method, arguments)), null);
  expect(result, isNotNull);
  expect(codec.decodeEnvelope(result!), isNull);
}

Future<void> _button(String type, [String button = 'back']) =>
    _message({'button': button, 'type': type});

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Owner owner;
  late _Input input;
  final extra = <_Input>[];
  setUp(() {
    owner = _Owner();
    input = _Input(owner);
    input.enterOrLeave(true);
  });
  tearDown(() async {
    input.close();
    for (final model in extra) { model.close(); }
    extra.clear();
    await Future<void>.value();
  });

  test('side button duplicate down preserves one accepted press', () async {
    final session = owner.sessionId;
    await _button('down');
    await _button('down');
    await _button('up');
    expect(input.events, [(session, 'down', MouseButtons.back),
      (session, 'up', MouseButtons.back)]);
  });

  test('side button duplicate down cannot transfer a press to another model', () async {
    final second = _Input(_Owner());
    extra.add(second);
    await _button('down');
    input.enterOrLeave(false);
    second.enterOrLeave(true);
    await _button('down');
    await _button('up');
    expect(second.events, isEmpty);
    expect(input.events.map((e) => e.$2), ['down', 'up']);
    await _button('down');
    await _button('up');
    expect(second.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button up retains the session selected by down', () async {
    final selected = owner.sessionId;
    await _button('down');
    owner.sessionId = const Uuid().v4obj();
    await _button('up');
    expect(input.events, [(selected, 'down', MouseButtons.back),
      (selected, 'up', MouseButtons.back)]);
  });

  test('side button stale disposal preserves a newer press and active model', () async {
    final retired = owner.sessionId;
    owner.sessionId = const Uuid().v4obj();
    final selected = owner.sessionId;
    await _button('down');
    input.disposeSideButtonTracking(expectedSessionId: retired);
    expect(input.events, [(selected, 'down', MouseButtons.back)]);
    await _button('up');
    await _button('down');
    await _button('up');
    expect(input.events, [(selected, 'down', MouseButtons.back),
      (selected, 'up', MouseButtons.back), (selected, 'down', MouseButtons.back),
      (selected, 'up', MouseButtons.back)]);
  });

  test('side button separate buttons retain independent models', () async {
    final second = _Input(_Owner());
    extra.add(second);
    await _button('down');
    input.enterOrLeave(false);
    second.enterOrLeave(true);
    await _button('down', 'forward');
    await _button('up');
    await _button('up', 'forward');
    expect(input.events, [(owner.sessionId, 'down', MouseButtons.back),
      (owner.sessionId, 'up', MouseButtons.back)]);
    expect(second.events, [(second.sessionId, 'down', MouseButtons.forward),
      (second.sessionId, 'up', MouseButtons.forward)]);
  });

  test('side button view only refuses presses with either cursor setting', () async {
    input.viewOnly = true;
    for (final cursor in [false, true]) {
      input.cursor = cursor;
      await _button('down');
      await _button('up');
    }
    expect(input.events, isEmpty);
    input.viewOnly = false;
    await _button('down');
    await _button('up');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button unknown names cannot release a held button', () async {
    await _button('down', 'forward');
    await _button('up', 'unknown');
    await _button('cancel', 'forward');
    await _button('down', 'middle');
    await _message({'button': 'forward', 'type': 'up'}, method: 'other');
    expect(input.events.map((e) => e.$2), ['down']);
    await _button('up', 'forward');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button malformed messages preserve the held press', () async {
    await _button('down');
    for (final message in [null, <Object?>[], {'button': 'back'},
      {'button': 8, 'type': 'up'}, {'button': 'back', 'type': 1}]) {
      await _message(message);
    }
    expect(input.events.map((e) => e.$2), ['down']);
    await _button('up');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button retired owner cannot admit a new press', () async {
    owner.current = false;
    await _button('down');
    await _button('up');
    expect(input.events, isEmpty);
    owner.current = true;
    await _button('down');
    await _button('up');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button release survives permission and camera changes', () async {
    await _button('down');
    input.allowed = false;
    input.camera = true;
    await _button('up');
    await _button('down');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
  });

  test('side button disposal releases each accepted press once', () async {
    await _button('down');
    await _button('down', 'forward');
    input.disposeSideButtonTracking(expectedSessionId: owner.sessionId);
    input.disposeSideButtonTracking(expectedSessionId: owner.sessionId);
    await _button('up');
    await _button('up', 'forward');
    expect(input.events, [(owner.sessionId, 'down', MouseButtons.back),
      (owner.sessionId, 'down', MouseButtons.forward),
      (owner.sessionId, 'up', MouseButtons.back),
      (owner.sessionId, 'up', MouseButtons.forward)]);
  });

  test('side button pending and failed sends do not block the channel', () async {
    final pending = Completer<void>();
    input.onSend = () => pending.future;
    await _button('down');
    await _button('up');
    expect(input.events.map((e) => e.$2), ['down', 'up']);
    pending.completeError(StateError('controlled bridge refusal'));
    await Future<void>.value();
    input.onSend = null;
    await _button('down');
    await _button('up');
    expect(input.events.map((e) => e.$2), ['down', 'up', 'down', 'up']);
  });
}

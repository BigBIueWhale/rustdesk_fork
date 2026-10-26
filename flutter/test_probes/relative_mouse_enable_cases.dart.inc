import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/main.dart' show kWindowId;
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/relative_mouse_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';

class _NativeMouse implements RustdeskImpl {
  final messages = <(SessionID, Map<String, dynamic>)>[];
  final cursor = <(int, int)>[];
  final unexpected = <Symbol>[];

  @override
  dynamic noSuchMethod(Invocation call) {
    switch (call.memberName) {
      case #translate:
        return call.namedArguments[#name];
      case #mainCurrentIsWayland:
        return false;
      case #versionToNumber:
        return 1;
      case #sessionSendMouse:
        messages.add((call.namedArguments[#sessionId] as SessionID,
            jsonDecode(call.namedArguments[#msg] as String) as Map<String, dynamic>));
        return Future<void>.value();
      case #mainSetCursorPosition:
        cursor.add((call.namedArguments[#x] as int, call.namedArguments[#y] as int));
        return true;
    }
    unexpected.add(call.memberName);
    throw UnsupportedError('Unexpected relative mouse call: ${call.memberName}');
  }

  List<SessionID> get enables => messages
      .where((entry) => entry.$2['relative_mouse_mode'] == '1')
      .map((entry) => entry.$1).toList();
}

void main() {
  const channel = MethodChannel('mixin.one/flutter_multi_window');
  late _NativeMouse native;
  late RelativeMouseModel model;
  late RxBool enabled;
  late SessionID session;
  late List<Completer<Object?>> frames;
  var inside = false;
  var allowed = true;
  var camera = false;
  int? oldWindow;

  setUp(() {
    oldWindow = kWindowId;
    kWindowId = 42;
    native = _NativeMouse();
    installRelativeMouseProbeBinding(native);
    frames = [];
    inside = false;
    allowed = true;
    camera = false;
    session = const Uuid().v4obj();
    enabled = false.obs;
    model = RelativeMouseModel(
      getSessionId: () => session, enabled: enabled,
      keyboardPerm: () => allowed, isViewCamera: () => camera,
      peerVersion: () => '1.4.7', peerPlatform: () => 'Windows',
      modify: (message) => message,
      getPointerInsideImage: () => inside,
      setPointerInsideImage: (value) => inside = value,
    )..updateImageWidgetSize(const Size(800, 600));
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) {
      expect(call.method, 'getFrame');
      expect(call.arguments, {'windowId': 42});
      final frame = Completer<Object?>();
      frames.add(frame);
      return frame.future;
    });
  });

  tearDown(() {
    model.dispose();
    enabled.close();
    expect(frames.every((frame) => frame.isCompleted), isTrue);
    expect(native.unexpected, isEmpty);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    kWindowId = oldWindow;
  });

  Future<void> begin(WidgetTester tester) async {
    expect(model.setRelativeMouseMode(true), isTrue);
    await tester.pump();
  }

  void reply(int index, {double x = 100, double width = 800, double height = 600}) {
    frames[index].complete({'x': x, 'y': 200.0, 'width': width, 'height': height});
  }

  testWidgets('relative mouse current geometry enables once and disables', (tester) async {
    await begin(tester);
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    reply(0);
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
    expect(model.setRelativeMouseMode(false), isTrue);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.messages.last.$2, {'relative_mouse_mode': '0'});
  });

  testWidgets('relative mouse disable retires a delayed enable', (tester) async {
    await begin(tester);
    model.setRelativeMouseMode(false);
    reply(0);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    await begin(tester);
    reply(1);
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
  });

  testWidgets('relative mouse old geometry cannot warp a replacement mode', (tester) async {
    await begin(tester);
    model.setRelativeMouseMode(false);
    await begin(tester);
    reply(1);
    await tester.pump();
    inside = true;
    reply(0, x: 900);
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
    expect(native.cursor, isEmpty);
  });

  testWidgets('relative mouse disposal closes pending and future admission', (tester) async {
    await begin(tester);
    model.dispose();
    reply(0);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    model.updateImageWidgetSize(const Size(800, 600));
    expect(model.setRelativeMouseMode(true), isFalse);
    await tester.pump();
    expect(frames, hasLength(1));
  });

  testWidgets('relative mouse invalid geometry stays disabled and permits retry', (tester) async {
    for (final width in [0.0, -1.0, double.nan, double.infinity]) {
      await begin(tester);
      reply(frames.length - 1, width: width);
      await tester.pump();
      expect(enabled.value, isFalse, reason: 'width=$width');
      expect(native.enables, isEmpty);
    }
    await begin(tester);
    reply(frames.length - 1);
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
  });

  testWidgets('relative mouse missing window and failed geometry do not enable', (tester) async {
    kWindowId = null;
    await begin(tester);
    expect(enabled.value, isFalse);
    expect(frames, isEmpty);
    kWindowId = 42;
    await begin(tester);
    frames.single.completeError(PlatformException(code: 'window-gone'));
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    await begin(tester);
    reply(1);
    await tester.pump();
    expect(enabled.value, isTrue);
  });

  testWidgets('relative mouse session reset retires the old geometry request', (tester) async {
    final previous = session;
    await begin(tester);
    model.resetForSession(previous);
    session = const Uuid().v4obj();
    reply(0);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    model.updateImageWidgetSize(const Size(800, 600));
    await begin(tester);
    reply(1);
    await tester.pump();
    expect(native.enables, [session]);
  });

  testWidgets('relative mouse enable rechecks permission and camera admission', (tester) async {
    await begin(tester);
    allowed = false;
    reply(0);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    allowed = true;
    await begin(tester);
    camera = true;
    reply(1);
    await tester.pump();
    expect(enabled.value, isFalse);
    expect(native.enables, isEmpty);
    camera = false;
    await begin(tester);
    reply(2);
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
  });

  testWidgets('relative mouse stale geometry error preserves the current mode', (tester) async {
    await begin(tester);
    await begin(tester);
    reply(1);
    await tester.pump();
    expect(enabled.value, isTrue);
    frames[0].completeError(PlatformException(code: 'old-window-gone'));
    await tester.pump();
    expect(enabled.value, isTrue);
    expect(native.enables, [session]);
  });
}

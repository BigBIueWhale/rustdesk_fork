import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/mobile/widgets/floating_mouse_widgets.dart';
import 'package:flutter_hbb/models/flutter_keyboard_input.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Binding implements RustdeskImpl {
  final saved = <String, String>{};
  final events = <(SessionID, String, String)>[];
  Future<void> Function(String type)? send;

  @override
  String getLocalFlutterOption({required String k, dynamic hint}) => saved[k] ?? '';
  @override
  Future<void> setLocalFlutterOption(
      {required String k, required String v, dynamic hint}) async {
    saved[k] = v;
  }
  @override
  Future<void> sessionSendMouse(
      {required SessionID sessionId, required String msg, dynamic hint}) {
    final event = jsonDecode(msg) as Map<String, dynamic>;
    if (event.containsKey('relative_mouse_mode')) {
      expect(event, {'relative_mouse_mode': '0'});
      return Future.value();
    }
    events.add((sessionId, event['type'] as String, event['buttons'] as String));
    return send?.call(event['type'] as String) ?? Future.value();
  }
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected native call: ${invocation.memberName}');
}

class _Keys implements FlutterKeyboardInputBackend {
  @override
  void enterOrLeave(SessionID session, bool enter) {}
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Virtual mouse tests must not emit keyboard input');
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
      throw StateError('Unexpected owner call: ${invocation.memberName}');
}

class _Input extends InputModel {
  _Input(_Owner owner) : super(WeakReference<FFI>(owner), keyboardBackend: _Keys());
  @override
  String get id => '';
  @override
  bool get keyboardPerm => true;
  @override
  bool get isViewOnly => false;
  @override
  bool get isViewCamera => false;
}

class _Cursor implements CursorModel {
  @override
  bool blockEvents = false;
  final rects = <Rect>{};
  Future<void> Function()? sync;
  @override
  void addBlockedRect(Rect rect) => rects.add(rect);
  @override
  void removeBlockedRect(Rect rect) => rects.remove(rect);
  @override
  Future<void> syncCursorPosition() => sync?.call() ?? Future.value();
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected cursor call: ${invocation.memberName}');
}

class _Buttons {
  final binding = _Binding();
  final owner = _Owner();
  final cursor = _Cursor();
  late final input = _Input(owner);
  SessionID get session => owner.sessionId;

  Future<void> mount(WidgetTester tester) async {
    installVirtualMouseProbeBinding(binding);
    await tester.pumpWidget(MaterialApp(home: Stack(children: [
      for (final left in [true, false])
        FloatingLeftRightButton(
          key: ValueKey(left), isLeft: left, inputModel: input, cursorModel: cursor),
    ])));
    await tester.pump();
    addTearDown(() async {
      await tester.pumpWidget(const SizedBox.shrink());
      input.disposeRelativeMouseMode();
      input.relativeMouseMode.close();
      input.isPhysicalMouse.close();
    });
  }

  Future<TestGesture> down(WidgetTester tester, bool left, {int? pointer}) =>
      tester.startGesture(tester.getCenter(find.byKey(ValueKey(left))), pointer: pointer);

  Future<void> settle(WidgetTester tester) async {
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 60));
    expect(tester.takeException(), isNull);
  }
}

void main() {
  for (final left in [true, false]) {
    final button = left ? 'left' : 'right';

    testWidgets('virtual $button button quick tap releases once', (tester) async {
      final f = _Buttons();
      await f.mount(tester);
      final gesture = await f.down(tester, left);
      await tester.pump(const Duration(milliseconds: 60));
      await gesture.up();
      await f.settle(tester);
      expect(f.binding.events, [(f.session, 'down', button), (f.session, 'up', button)]);
    });

    testWidgets('virtual $button button early cancellation emits nothing', (tester) async {
      final f = _Buttons();
      await f.mount(tester);
      final gesture = await f.down(tester, left);
      await tester.pump(const Duration(milliseconds: 60));
      await gesture.cancel();
      await tester.pump(const Duration(milliseconds: 300));
      expect(f.binding.events, isEmpty);
    });

    for (final ending in ['release', 'cancel', 'removal', 'replacement']) {
      testWidgets('virtual $button button $ending retires pending cursor sync', (tester) async {
        final f = _Buttons();
        await f.mount(tester);
        final sync = Completer<void>();
        f.cursor.sync = () => sync.future;
        final gesture = await f.down(tester, left);
        await tester.pump(const Duration(milliseconds: 210));
        expect(f.binding.events, isEmpty);
        if (ending == 'removal') {
          await tester.pumpWidget(const SizedBox.shrink());
          await gesture.cancel();
        } else if (ending == 'replacement') {
          f.input.resetForSession(f.session);
          f.owner.sessionId = const Uuid().v4obj();
          await gesture.up();
        } else if (ending == 'cancel') {
          await gesture.cancel();
        } else {
          await gesture.up();
        }
        sync.complete();
        await f.settle(tester);
        expect(f.binding.events, isEmpty);
      });
    }

    testWidgets('virtual $button button release waits for admitted down', (tester) async {
      final f = _Buttons();
      await f.mount(tester);
      final down = Completer<void>();
      f.binding.send = (type) => type == 'down' ? down.future : Future.value();
      final gesture = await f.down(tester, left);
      await tester.pump(const Duration(milliseconds: 210));
      expect(f.binding.events, [(f.session, 'down', button)]);
      await gesture.up();
      final beforeCompletion = f.binding.events.toList();
      down.complete();
      await f.settle(tester);
      expect(beforeCompletion, [(f.session, 'down', button)]);
      expect(f.binding.events, [(f.session, 'down', button), (f.session, 'up', button)]);
    });

    testWidgets('virtual $button button removal releases an admitted hold', (tester) async {
      final f = _Buttons();
      await f.mount(tester);
      final gesture = await f.down(tester, left);
      await tester.pump(const Duration(milliseconds: 210));
      expect(f.binding.events, [(f.session, 'down', button)]);
      await tester.pumpWidget(const SizedBox.shrink());
      await gesture.cancel();
      await f.settle(tester);
      expect(f.binding.events, [(f.session, 'down', button), (f.session, 'up', button)]);
    });
  }

  testWidgets('virtual buttons release their own simultaneous holds', (tester) async {
    final f = _Buttons();
    await f.mount(tester);
    final left = await f.down(tester, true, pointer: 1);
    await tester.pump(const Duration(milliseconds: 210));
    final right = await f.down(tester, false, pointer: 2);
    await tester.pump(const Duration(milliseconds: 210));
    await right.up();
    await left.up();
    await f.settle(tester);
    expect(f.binding.events, [
      (f.session, 'down', 'left'), (f.session, 'down', 'right'),
      (f.session, 'up', 'right'), (f.session, 'up', 'left'),
    ]);
  });
}

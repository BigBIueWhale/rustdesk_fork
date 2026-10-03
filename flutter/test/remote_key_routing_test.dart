import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/remote_key_routing.dart';

const androidBack = PhysicalKeyboardKey(LogicalKeyboardKey.androidPlane | 4);

List<KeyEvent> keyEdges(
    PhysicalKeyboardKey physical, LogicalKeyboardKey logical) {
  return [
    KeyDownEvent(
        physicalKey: physical, logicalKey: logical, timeStamp: Duration.zero),
    KeyRepeatEvent(
        physicalKey: physical, logicalKey: logical, timeStamp: Duration.zero),
    KeyUpEvent(
        physicalKey: physical, logicalKey: logical, timeStamp: Duration.zero),
  ];
}

Future<bool> sendAndroidBack(WidgetTester tester,
    {required bool down, int scanCode = 0}) async {
  tester.binding.keyEventManager.handleKeyData(ui.KeyData(
    type: down ? ui.KeyEventType.down : ui.KeyEventType.up,
    physical: LogicalKeyboardKey.androidPlane | (scanCode == 0 ? 4 : scanCode),
    logical: LogicalKeyboardKey.goBack.keyId,
    timeStamp: Duration.zero,
    synthesized: false,
  ));
  final handled = Completer<bool>();
  await tester.binding.defaultBinaryMessenger.handlePlatformMessage(
    SystemChannels.keyEvent.name,
    SystemChannels.keyEvent.codec.encodeMessage({
      'type': down ? 'keydown' : 'keyup',
      'keymap': 'android',
      'keyCode': 4,
      'scanCode': scanCode,
      'metaState': 0,
    }),
    (data) {
      expect(data, isNotNull);
      final reply = SystemChannels.keyEvent.codec.decodeMessage(data!);
      handled.complete((reply as Map)['handled'] as bool);
    },
  );
  return handled.future;
}

Widget keyTree(
  KeyEventResult Function(KeyEvent) forward,
  List<KeyEvent> parentEvents,
) {
  return Directionality(
    textDirection: TextDirection.ltr,
    child: Focus(
      onKeyEvent: (node, event) {
        parentEvents.add(event);
        return KeyEventResult.ignored;
      },
      child: Focus(
        autofocus: true,
        onKeyEvent: (node, event) => routeRemoteKeyEvent(
          event,
          isAndroid: true,
          forward: forward,
        ),
        child: const SizedBox(width: 20, height: 20),
      ),
    ),
  );
}

void main() {
  test('Android navigation Back never enters the remote handler', () {
    for (final event in keyEdges(androidBack, LogicalKeyboardKey.goBack)) {
      expect(
        routeRemoteKeyEvent(event, isAndroid: true, forward: (_) {
          fail('local navigation entered the remote handler');
        }),
        KeyEventResult.ignored,
      );
    }
  });

  test('Flutter key-state synchronization also preserves local Back ownership',
      () {
    const event = KeyUpEvent(
      physicalKey: androidBack,
      logicalKey: LogicalKeyboardKey.goBack,
      timeStamp: Duration.zero,
      synthesized: true,
    );
    expect(
      routeRemoteKeyEvent(event, isAndroid: true, forward: (_) {
        fail('synchronized local navigation entered the remote handler');
      }),
      KeyEventResult.ignored,
    );
  });

  test('physical Back with the Android logical key still forwards both edges',
      () {
    for (final physical in [
      PhysicalKeyboardKey.browserBack,
      const PhysicalKeyboardKey(LogicalKeyboardKey.androidPlane | 158),
    ]) {
      for (final event in keyEdges(physical, LogicalKeyboardKey.goBack)) {
        var calls = 0;
        expect(
          routeRemoteKeyEvent(event, isAndroid: true, forward: (received) {
            expect(received, same(event));
            calls++;
            return KeyEventResult.handled;
          }),
          KeyEventResult.handled,
        );
        expect(calls, 1);
      }
    }
  });

  test('physical browser Back keeps its distinct remote logical identity', () {
    for (final event in keyEdges(
        PhysicalKeyboardKey.browserBack, LogicalKeyboardKey.browserBack)) {
      var calls = 0;
      expect(
        routeRemoteKeyEvent(event, isAndroid: true, forward: (received) {
          expect(received, same(event));
          calls++;
          return KeyEventResult.handled;
        }),
        KeyEventResult.handled,
      );
      expect(calls, 1);
    }
  });

  test('a physical-ID collision alone cannot suppress another logical key', () {
    for (final event in keyEdges(androidBack, LogicalKeyboardKey.keyA)) {
      var calls = 0;
      expect(
        routeRemoteKeyEvent(event, isAndroid: true, forward: (received) {
          expect(received, same(event));
          calls++;
          return KeyEventResult.handled;
        }),
        KeyEventResult.handled,
      );
      expect(calls, 1);
    }
  });

  test('non-Android routing preserves the exact event and handler result', () {
    for (final result in KeyEventResult.values) {
      for (final event in keyEdges(androidBack, LogicalKeyboardKey.goBack)) {
        var calls = 0;
        expect(
          routeRemoteKeyEvent(event, isAndroid: false, forward: (received) {
            expect(received, same(event));
            calls++;
            return result;
          }),
          result,
        );
        expect(calls, 1);
      }
    }
  });

  testWidgets('focused Android Back reaches ancestors without remote input',
      (tester) async {
    final parentEvents = <KeyEvent>[];
    await tester.pumpWidget(keyTree((_) {
      fail('focused local navigation entered the remote handler');
    }, parentEvents));
    await tester.pump();
    expect(await sendAndroidBack(tester, down: true), isFalse);
    expect(await sendAndroidBack(tester, down: false), isFalse);
    expect(parentEvents, hasLength(2));
    expect(parentEvents.first, isA<KeyDownEvent>());
    expect(parentEvents.last, isA<KeyUpEvent>());
  });

  testWidgets('focused physical Android Back remains remote input',
      (tester) async {
    final parentEvents = <KeyEvent>[];
    final forwarded = <KeyEvent>[];
    await tester.pumpWidget(keyTree((event) {
      forwarded.add(event);
      return KeyEventResult.handled;
    }, parentEvents));
    await tester.pump();
    expect(await sendAndroidBack(tester, down: true, scanCode: 158), isTrue);
    expect(await sendAndroidBack(tester, down: false, scanCode: 158), isTrue);
    expect(parentEvents, isEmpty);
    expect(forwarded, hasLength(2));
    expect(forwarded.first, isA<KeyDownEvent>());
    expect(forwarded.last, isA<KeyUpEvent>());
  });
}

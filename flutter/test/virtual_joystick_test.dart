import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/mobile/widgets/floating_mouse_widgets.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

class _Input implements InputModel {
  _Input(bool relative) : relativeMouseMode = relative.obs;
  @override
  final RxBool relativeMouseMode;
  final movements = <Offset>[];

  @override
  Future<void> sendMobileRelativeMouseMove(double dx, double dy) async {
    movements.add(Offset(dx, dy));
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected input call: ${invocation.memberName}');
}

class _Cursor implements CursorModel {
  @override
  bool blockEvents = false;
  final movements = <Offset>[];

  @override
  Future<void> updatePan(Offset delta, Offset localPosition, bool touchMode) async {
    expect(localPosition, Offset.zero);
    expect(touchMode, isFalse);
    movements.add(delta);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected cursor call: ${invocation.memberName}');
}

class _Joystick {
  _Joystick(this.relative) : input = _Input(relative);
  final bool relative;
  final _Input input;
  final cursor = _Cursor();
  List<Offset> get movements => relative ? input.movements : cursor.movements;

  Future<void> mount(WidgetTester tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Stack(children: [
        VirtualJoystick(cursorModel: cursor, inputModel: input),
      ]),
    ));
    await tester.pump();
    addTearDown(() => tester.pumpWidget(const SizedBox.shrink()));
  }

  Future<TestGesture> drag(WidgetTester tester) async {
    final center = tester.getCenter(find.byType(VirtualJoystick));
    final gesture = await tester.startGesture(center);
    await gesture.moveBy(const Offset(40, 0));
    await tester.pump();
    expect(cursor.blockEvents, isTrue);
    expect(movements, isNotEmpty);
    expect(movements.last.dx, greaterThan(0));
    return gesture;
  }

  Future<void> expectStopped(WidgetTester tester) async {
    final count = movements.length;
    await tester.pump(const Duration(seconds: 1));
    expect(movements.length, count);
    expect(cursor.blockEvents, isFalse);
    expect(relative ? cursor.movements : input.movements, isEmpty);
    expect(tester.takeException(), isNull);
  }
}

void main() {
  for (final relative in [false, true]) {
    final mode = relative ? 'relative' : 'absolute';

    testWidgets('virtual joystick $mode drag and cancellation stop movement',
        (tester) async {
      final joystick = _Joystick(relative);
      await joystick.mount(tester);
      final gesture = await joystick.drag(tester);
      final initial = joystick.movements.length;
      await tester.pump(const Duration(milliseconds: 200));
      expect(joystick.movements.length, greaterThan(initial));
      await gesture.cancel();
      await joystick.expectStopped(tester);
      final retry = await joystick.drag(tester);
      await tester.pump(const Duration(milliseconds: 200));
      await retry.up();
      await joystick.expectStopped(tester);
    });

    testWidgets('virtual joystick $mode early cancellation prevents movement',
        (tester) async {
      final joystick = _Joystick(relative);
      await joystick.mount(tester);
      final gesture = await joystick.drag(tester);
      await tester.pump(const Duration(milliseconds: 60));
      await gesture.cancel();
      await joystick.expectStopped(tester);
    });

    testWidgets('virtual joystick $mode removal stops queued movement',
        (tester) async {
      final joystick = _Joystick(relative);
      await joystick.mount(tester);
      final queued = <void Function()>[];
      // Hold ready zero-delay callbacks until the widget has been removed.
      // The gesture recognizer, hold timer and periodic timers still execute.
      final gesture = await runZoned(() => joystick.drag(tester),
          zoneSpecification: ZoneSpecification(
        createTimer: (self, parent, zone, duration, callback) {
          if (duration == Duration.zero) {
            return parent.createTimer(zone, duration, () => queued.add(callback));
          }
          return parent.createTimer(zone, duration, callback);
        },
      ));
      await tester.pump(const Duration(milliseconds: 140));
      final beforeRemoval = joystick.movements.length;
      expect(beforeRemoval, greaterThan(0));
      await tester.pumpWidget(const SizedBox.shrink());
      for (final callback in queued) {
        callback();
      }
      await tester.pump();
      expect(joystick.movements.length, beforeRemoval);
      await gesture.cancel();
      await joystick.expectStopped(tester);
    });

    testWidgets('virtual joystick $mode removal before hold prevents movement',
        (tester) async {
      final joystick = _Joystick(relative);
      await joystick.mount(tester);
      final gesture = await joystick.drag(tester);
      await tester.pump(const Duration(milliseconds: 60));
      await tester.pumpWidget(const SizedBox.shrink());
      await gesture.cancel();
      await joystick.expectStopped(tester);
    });
  }
}

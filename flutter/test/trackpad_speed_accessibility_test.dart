import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> _show(WidgetTester tester, {
  int speed = 100,
  bool enabled = true,
  Key? fieldKey,
  Future<int?> Function(int)? save,
}) => tester.pumpWidget(MaterialApp(
  home: Scaffold(body: SizedBox(width: 360, child: TrackpadSpeedWidget(
    key: fieldKey ?? ValueKey((speed, enabled)),
    value: SimpleWrapper(speed),
    enabled: enabled,
    saveSpeed: save,
    translateText: (text) => text,
  ))),
));

String _displayedSpeed(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).controller!.text;

void main() {
  testWidgets('trackpad announces speed across its enabled and disabled range', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      for (final enabled in [true, false]) {
        for (final speed in [10, 11, 20, 99, 100, 101, 235, 250, 500, 990, 999, 1000]) {
          await _show(tester, speed: speed, enabled: enabled);
          final data = tester.getSemantics(find.byType(Slider)).getSemanticsData();
          expect(data.value, '$speed%', reason: 'speed=$speed enabled=$enabled');
          expect(_displayedSpeed(tester), '$speed');
        }
      }
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('trackpad accessibility predictions match adjusted and saved speed', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      for (final increase in [true, false]) {
        final calls = <int>[];
        await _show(tester, save: (value) async { calls.add(value); return value; });
        final node = tester.getSemantics(find.byType(Slider));
        final before = node.getSemanticsData();
        final predicted = increase ? before.increasedValue : before.decreasedValue;
        tester.binding.pipelineOwner.semanticsOwner!.performAction(node.id,
            increase ? ui.SemanticsAction.increase : ui.SemanticsAction.decrease);
        await tester.pump();
        await tester.pump(const Duration(seconds: 1));
        final expected = increase ? 101 : 99;
        expect(calls, [expected]);
        expect(_displayedSpeed(tester), '$expected');
        expect(predicted, '$expected%');
        expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '$expected%');
        await tester.pumpWidget(const SizedBox.shrink());
      }
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('trackpad keyboard changes retain confirmed backend values', (tester) async {
    final pending = Completer<int?>();
    final calls = <int>[];
    await _show(tester, save: (value) { calls.add(value); return pending.future; });
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pump();
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
    await tester.pump(const Duration(seconds: 1));
    expect(calls, [101]);
    expect(_displayedSpeed(tester), '101');
    pending.complete(240);
    await tester.pump();
    expect(_displayedSpeed(tester), '240');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('trackpad submitted integer speed survives rebuild and reload', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      const fieldKey = ValueKey('retained-trackpad');
      final calls = <int>[];
      Future<int?> save(int value) async { calls.add(value); return value; }
      await _show(tester, fieldKey: fieldKey, save: save);
      final state = tester.state(find.byType(TrackpadSpeedWidget));
      await tester.enterText(find.byType(TextField), '235');
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      expect(calls, [235]);
      expect(_displayedSpeed(tester), '235');
      expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '235%');
      for (final speed in [235, 101, 999]) {
        await _show(tester, speed: speed, fieldKey: fieldKey, save: save);
        expect(tester.state(find.byType(TrackpadSpeedWidget)), same(state));
        expect(_displayedSpeed(tester), '$speed');
        expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '$speed%');
        expect(calls, [235]);
      }
      await tester.pumpWidget(const SizedBox.shrink());
      await _show(tester, speed: 235, save: save);
      expect(_displayedSpeed(tester), '235');
      expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '235%');
      expect(calls, [235]);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      semantics.dispose();
    }
  });

  testWidgets('trackpad accessibility clamps one point adjustments at both bounds', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      for (final speed in [10, 1000]) {
        for (final increase in [true, false]) {
          final calls = <int>[];
          await _show(tester, speed: speed,
              save: (value) async { calls.add(value); return value; });
          final node = tester.getSemantics(find.byType(Slider));
          final before = node.getSemanticsData();
          final predicted = increase ? before.increasedValue : before.decreasedValue;
          final expected = (speed + (increase ? 1 : -1)).clamp(10, 1000);
          tester.binding.pipelineOwner.semanticsOwner!.performAction(node.id,
              increase ? ui.SemanticsAction.increase : ui.SemanticsAction.decrease);
          await tester.pump();
          await tester.pump(const Duration(seconds: 1));
          expect(_displayedSpeed(tester), '$expected');
          expect(predicted, '$expected%');
          expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '$expected%');
          expect(calls, expected == speed ? isEmpty : [expected]);
          await tester.pumpWidget(const SizedBox.shrink());
        }
      }
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      semantics.dispose();
    }
  });

  testWidgets('trackpad disabled accessibility cannot adjust or save speed', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      final calls = <int>[];
      await _show(tester, enabled: false,
          save: (value) async { calls.add(value); return value; });
      final node = tester.getSemantics(find.byType(Slider));
      final data = node.getSemanticsData();
      expect(data.hasAction(ui.SemanticsAction.increase), isFalse);
      expect(data.hasAction(ui.SemanticsAction.decrease), isFalse);
      for (final action in [ui.SemanticsAction.increase, ui.SemanticsAction.decrease]) {
        tester.binding.pipelineOwner.semanticsOwner!.performAction(node.id, action);
      }
      await tester.pump(const Duration(seconds: 2));
      expect(calls, isEmpty);
      expect(_displayedSpeed(tester), '100');
    } finally {
      semantics.dispose();
    }
  });
}

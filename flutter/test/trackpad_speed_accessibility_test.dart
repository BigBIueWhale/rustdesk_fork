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
  Future<int?> Function(int)? save,
}) => tester.pumpWidget(MaterialApp(
  home: Scaffold(body: SizedBox(width: 360, child: TrackpadSpeedWidget(
    key: ValueKey((speed, enabled)),
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
    addTearDown(semantics.dispose);
    for (final enabled in [true, false]) {
      for (final speed in [10, 20, 100, 250, 500, 990, 1000]) {
        await _show(tester, speed: speed, enabled: enabled);
        final data = tester.getSemantics(find.byType(Slider)).getSemanticsData();
        expect(data.value, '$speed%', reason: 'speed=$speed enabled=$enabled');
        expect(_displayedSpeed(tester), '$speed');
      }
    }
  });

  testWidgets('trackpad accessibility predictions match adjusted and saved speed', (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
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
      final expected = increase ? 110 : 90;
      expect(calls, [expected]);
      expect(_displayedSpeed(tester), '$expected');
      expect(predicted, '$expected%');
      expect(tester.getSemantics(find.byType(Slider)).getSemanticsData().value, '$expected%');
      await tester.pumpWidget(const SizedBox.shrink());
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
    expect(calls, [110]);
    expect(_displayedSpeed(tester), '110');
    pending.complete(240);
    await tester.pump();
    expect(_displayedSpeed(tester), '240');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('trackpad disabled accessibility cannot adjust or save speed', (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
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
  });
}

import 'dart:async';
import 'dart:ui' show SemanticsAction;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/setting_checkbox.dart';
import 'package:flutter_test/flutter_test.dart';

const _label = 'Show quality monitor';

Widget _subject(Future<bool?> Function(bool) save,
    {bool value = false, bool enabled = true}) => MaterialApp(
      home: Scaffold(
        body: SettingCheckbox(
          label: _label,
          value: value,
          enabled: enabled,
          saveValue: save,
          failureText: 'Save failed',
        ),
      ),
    );

void _expectState(WidgetTester tester,
    {required bool checked, required bool enabled}) {
  expect(tester.getSemantics(find.text(_label)), containsSemantics(
    label: _label,
    hasCheckedState: true,
    isChecked: checked,
    hasEnabledState: true,
    isEnabled: enabled,
    hasTapAction: enabled,
  ));
}

void _activate(WidgetTester tester) {
  final node = tester.getSemantics(find.text(_label));
  tester.binding.pipelineOwner.semanticsOwner!
      .performAction(node.id, SemanticsAction.tap);
}

void main() {
  for (final checked in [false, true]) {
    for (final enabled in [false, true]) {
      testWidgets('checkbox label exposes checked=$checked enabled=$enabled',
          (tester) async {
        var writes = 0;
        await tester.pumpWidget(_subject((next) async {
          writes++;
          return next;
        }, value: checked, enabled: enabled));
        _expectState(tester, checked: checked, enabled: enabled);
        if (!enabled) {
          _activate(tester);
          await tester.tap(find.text(_label));
          await tester.pump();
          expect(writes, 0);
        }
      }, semanticsEnabled: true);
    }
  }

  testWidgets('checkbox semantic action waits for one acknowledged write',
      (tester) async {
    final write = Completer<bool?>();
    final requested = <bool>[];
    await tester.pumpWidget(_subject((next) {
      requested.add(next);
      return write.future;
    }));
    _activate(tester);
    await tester.pump();
    expect(requested, [true]);
    _expectState(tester, checked: false, enabled: false);
    _activate(tester);
    await tester.tap(find.text(_label));
    await tester.pump();
    expect(requested, [true]);
    write.complete(true);
    await tester.pumpAndSettle();
    _expectState(tester, checked: true, enabled: true);
  }, semanticsEnabled: true);

  testWidgets('checkbox failed semantic write stays unchecked and can retry',
      (tester) async {
    var writes = 0;
    await tester.pumpWidget(_subject((next) async {
      writes++;
      return writes == 1 ? null : next;
    }));
    _activate(tester);
    await tester.pumpAndSettle();
    expect(writes, 1);
    expect(find.text('Save failed'), findsOneWidget);
    _expectState(tester, checked: false, enabled: true);
    _activate(tester);
    await tester.pumpAndSettle();
    expect(writes, 2);
    expect(find.text('Save failed'), findsNothing);
    _expectState(tester, checked: true, enabled: true);
  }, semanticsEnabled: true);

  testWidgets('checkbox and label pointer actions each write exactly once',
      (tester) async {
    final requested = <bool>[];
    await tester.pumpWidget(_subject((next) async {
      requested.add(next);
      return next;
    }));
    await tester.tap(find.text(_label));
    await tester.pumpAndSettle();
    expect(requested, [true]);
    await tester.tap(find.byType(Checkbox));
    await tester.pumpAndSettle();
    expect(requested, [true, false]);
  });

  testWidgets('checkbox keyboard focus retains one toggle per Space',
      (tester) async {
    final requested = <bool>[];
    await tester.pumpWidget(_subject((next) async {
      requested.add(next);
      return next;
    }));
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.space);
    await tester.pumpAndSettle();
    expect(requested, [true]);
    await tester.sendKeyEvent(LogicalKeyboardKey.space);
    await tester.pumpAndSettle();
    expect(requested, [true, false]);
  });
}

import 'dart:async';
import 'dart:ui' show SemanticsAction, SemanticsFlag;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

import 'keyboard_layout_probe.dart';

Widget app(RxString selected, KBChosenCallback save) => MaterialApp(
      home: Scaffold(
        body: Column(children: [
          KBLayoutTypeChooser(
            chosenType: selected,
            width: 360,
            height: 200,
            dividerWidth: 4,
            cb: save,
            failureText: 'Save failed',
          ),
          TextButton(onPressed: () {}, child: const Text('After chooser')),
        ]),
      ),
    );

List<SemanticsNode> nodes(WidgetTester tester) {
  final result = <SemanticsNode>[];
  void visit(SemanticsNode node) {
    result.add(node);
    node.visitChildren((child) {
      visit(child);
      return true;
    });
  }
  visit(tester.binding.pipelineOwner.semanticsOwner!.rootSemanticsNode!);
  return result;
}

SemanticsNode choice(WidgetTester tester, String label) => nodes(tester)
    .singleWhere((node) => node.getSemanticsData().label == label &&
        node.hasFlag(SemanticsFlag.hasCheckedState));

void activate(WidgetTester tester, SemanticsNode node) => tester.binding
    .pipelineOwner.semanticsOwner!.performAction(node.id, SemanticsAction.tap);

void main() {
  testWidgets('keyboard choice exposes one labelled radio per option',
      (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
    final selected = 'ISO'.obs;
    await tester.pumpWidget(app(selected, (_) async => true));
    await tester.pumpAndSettle();
    for (final label in ['ISO', 'Not ISO']) {
      final node = choice(tester, label);
      expect(node.hasFlag(SemanticsFlag.isInMutuallyExclusiveGroup), isTrue);
      expect(node.hasFlag(SemanticsFlag.isChecked), label == 'ISO');
      expect(node.hasFlag(SemanticsFlag.isEnabled), isTrue);
      expect(node.getSemanticsData().hasAction(SemanticsAction.tap), isTrue);
    }
    final actions = nodes(tester).where((node) =>
        node.getSemanticsData().hasAction(SemanticsAction.tap)).toList();
    expect(actions.map((node) => node.getSemanticsData().label).toList(),
        ['ISO', 'Not ISO', 'After chooser']);
  });

  testWidgets('keyboard choice tabs once per option and activates with Space',
      (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
    final selected = 'ISO'.obs;
    final writes = <String>[];
    await tester.pumpWidget(app(selected, (value) async {
      writes.add(value);
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(choice(tester, 'ISO').hasFlag(SemanticsFlag.isFocused), isTrue);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(choice(tester, 'Not ISO').hasFlag(SemanticsFlag.isFocused), isTrue);
    await tester.sendKeyEvent(LogicalKeyboardKey.space);
    await tester.pumpAndSettle();
    expect(writes, ['Not ISO']);
    expect(selected.value, 'Not ISO');
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(tester.getSemantics(find.text('After chooser'))
        .hasFlag(SemanticsFlag.isFocused), isTrue);
  });

  testWidgets('keyboard choice semantics waits for confirmed save',
      (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
    final selected = 'ISO'.obs;
    final completion = Completer<void>();
    var writes = 0;
    await tester.pumpWidget(app(selected, (value) async {
      writes++;
      await completion.future;
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    activate(tester, choice(tester, 'Not ISO'));
    await tester.pump();
    expect(writes, 1);
    expect(selected.value, 'ISO');
    for (final label in ['ISO', 'Not ISO']) {
      final node = choice(tester, label);
      expect(node.hasFlag(SemanticsFlag.isEnabled), isFalse);
      expect(node.getSemanticsData().hasAction(SemanticsAction.tap), isFalse);
      activate(tester, node);
    }
    await tester.pump();
    expect(writes, 1);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    completion.complete();
    await tester.pumpAndSettle();
    expect(choice(tester, 'Not ISO').hasFlag(SemanticsFlag.isChecked), isTrue);
    expect(find.byType(LinearProgressIndicator), findsNothing);
  });

  testWidgets('keyboard choice semantic failure preserves selection and retries',
      (tester) async {
    final semantics = tester.ensureSemantics();
    addTearDown(semantics.dispose);
    final selected = 'ISO'.obs;
    var writes = 0;
    await tester.pumpWidget(app(selected, (value) async {
      if (++writes == 1) return false;
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    activate(tester, choice(tester, 'Not ISO'));
    await tester.pumpAndSettle();
    expect(find.text('Save failed'), findsOneWidget);
    expect(choice(tester, 'ISO').hasFlag(SemanticsFlag.isChecked), isTrue);
    activate(tester, choice(tester, 'Not ISO'));
    await tester.pumpAndSettle();
    expect(writes, 2);
    expect(choice(tester, 'Not ISO').hasFlag(SemanticsFlag.isChecked), isTrue);
    expect(find.text('Save failed'), findsNothing);
  });

  testWidgets('keyboard choice keeps both diagram pointer targets',
      (tester) async {
    final selected = 'ISO'.obs;
    final writes = <String>[];
    await tester.pumpWidget(app(selected, (value) async {
      writes.add(value);
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(SvgPicture).at(1));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(SvgPicture).at(0));
    await tester.pumpAndSettle();
    expect(writes, ['Not ISO', 'ISO']);
    expect(tester.takeException(), isNull);
  });

  testWidgets('keyboard choice label and radio each submit once',
      (tester) async {
    final selected = 'ISO'.obs;
    final writes = <String>[];
    await tester.pumpWidget(app(selected, (value) async {
      writes.add(value);
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Not ISO'));
    await tester.pumpAndSettle();
    await tester.tap(find.byWidgetPredicate((widget) =>
        widget is Radio<String> && widget.value == 'ISO'));
    await tester.pumpAndSettle();
    expect(writes, ['Not ISO', 'ISO']);
  });

  testWidgets('keyboard choice removal refuses captured actions during save',
      (tester) async {
    final selected = 'ISO'.obs;
    final completion = Completer<void>();
    var writes = 0;
    await tester.pumpWidget(app(selected, (value) async {
      writes++;
      await completion.future;
      selected.value = value;
      return true;
    }));
    await tester.pumpAndSettle();
    final captured = tester.widget<Radio<String>>(find.byWidgetPredicate(
        (widget) => widget is Radio<String> && widget.value == 'Not ISO'))
        .onChanged!;
    captured('Not ISO');
    await tester.pump();
    await tester.pumpWidget(const SizedBox.shrink());
    captured('Not ISO');
    expect(writes, 1);
    completion.complete();
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}

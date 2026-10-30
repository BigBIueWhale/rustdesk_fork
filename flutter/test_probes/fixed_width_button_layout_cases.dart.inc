import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fixed_width_button_probe.dart';

Widget _subject(bool outline, String label, double scale,
        TextDirection direction, VoidCallback onPressed) =>
    MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(
          textScaler: TextScaler.linear(scale),
        ),
        child: Directionality(textDirection: direction, child: child!),
      ),
      home: Scaffold(
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              FixedWidthButton(
                width: 150,
                padding: 8,
                textSize: 20,
                isOutline: outline,
                text: label,
                onTap: onPressed,
              ),
            ],
          ),
        ),
      ),
    );

void _expectCompleteLabel(WidgetTester tester, String label) {
  final button = find.byType(FixedWidthButton);
  final paragraph = tester.renderObject<RenderParagraph>(find.descendant(
    of: button,
    matching: find.byType(RichText),
  ));
  expect(paragraph.text.toPlainText(), label);
  expect(paragraph.didExceedMaxLines, isFalse);
  final bounds = tester.getRect(button);
  expect(bounds.width, 150);
  final boxes = paragraph.getBoxesForSelection(
      TextSelection(baseOffset: 0, extentOffset: label.length));
  expect(boxes, isNotEmpty);
  for (final box in boxes) {
    final start = paragraph.localToGlobal(Offset(box.left, box.top));
    final end = paragraph.localToGlobal(Offset(box.right, box.bottom));
    expect(start.dx, greaterThanOrEqualTo(bounds.left - 0.01));
    expect(end.dx, lessThanOrEqualTo(bounds.right + 0.01));
    expect(start.dy, greaterThanOrEqualTo(bounds.top - 0.01));
    expect(end.dy, lessThanOrEqualTo(bounds.bottom + 0.01));
  }
  expect(tester.takeException(), isNull);
}

void main() {
  for (final outline in [false, true]) {
    final variant = outline ? 'outline' : 'filled';
    testWidgets('help button $variant fits a long translated label',
        (tester) async {
      const label = 'Berechtigungen konfigurieren';
      var calls = 0;
      await tester.pumpWidget(_subject(
          outline, label, 1, TextDirection.ltr, () => calls++));
      _expectCompleteLabel(tester, label);
      await tester.tap(find.byType(FixedWidthButton));
      expect(calls, 1);
    });

    testWidgets('help button $variant fits enlarged text in both directions',
        (tester) async {
      for (final direction in TextDirection.values) {
        final label = direction == TextDirection.ltr ? 'Configure' : 'הגדרה';
        for (final scale in [1.0, 2.0, 3.0]) {
          var calls = 0;
          await tester.pumpWidget(
              _subject(outline, label, scale, direction, () => calls++));
          _expectCompleteLabel(tester, label);
          await tester.tap(find.byType(FixedWidthButton));
          expect(calls, 1);
        }
      }
    });
  }
}

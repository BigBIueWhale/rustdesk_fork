import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _page({
  required Map<String, String> options,
  required String selected,
  required ValueChanged<String> onChanged,
  double scale = 1,
  TextDirection direction = TextDirection.ltr,
}) => MaterialApp(
  theme: MyTheme.lightTheme,
  builder: (context, child) => MediaQuery(
    data: MediaQuery.of(context).copyWith(textScaler: TextScaler.linear(scale)),
    child: Directionality(textDirection: direction, child: child!),
  ),
  home: Scaffold(body: Center(child: SizedBox(
    width: 180,
    child: ComboBox(options: options, selectedKey: selected,
        onChanged: onChanged),
  ))),
);

void _expectTextFits(WidgetTester tester, Finder text, Rect bounds) {
  final paragraph = tester.renderObject<RenderParagraph>(text);
  final boxes = paragraph.getBoxesForSelection(TextSelection(
    baseOffset: 0, extentOffset: paragraph.text.toPlainText().length,
  ));
  expect(boxes, isNotEmpty);
  for (final box in boxes) {
    final top = paragraph.localToGlobal(Offset(0, box.top)).dy;
    final bottom = paragraph.localToGlobal(Offset(0, box.bottom)).dy;
    expect(top, greaterThanOrEqualTo(bounds.top - 0.01));
    expect(bottom, lessThanOrEqualTo(bounds.bottom + 0.01));
  }
}

void main() {
  testWidgets('combo selected label fits enlarged text in both directions',
      (tester) async {
    for (final direction in TextDirection.values) {
      for (final scale in [1.0, 2.0, 3.0, 4.0]) {
        await tester.pumpWidget(_page(options: const {'en': 'English'},
            selected: 'en', onChanged: (_) => fail('Unexpected selection'),
            scale: scale, direction: direction));
        await tester.pumpAndSettle();
        _expectTextFits(tester, find.text('English'),
            tester.getRect(find.byType(DropdownButton<String>)));
        expect(tester.takeException(), isNull);
      }
    }
  });

  testWidgets('combo unavailable label fits enlarged text without a selection',
      (tester) async {
    for (final direction in TextDirection.values) {
      await tester.pumpWidget(_page(options: const {'en': 'English'},
          selected: 'Other', onChanged: (_) => fail('Unexpected selection'),
          scale: 4, direction: direction));
      await tester.pumpAndSettle();
      expect(tester.widget<DropdownButton<String>>(
          find.byType(DropdownButton<String>)).value, isNull);
      _expectTextFits(tester, find.text('Other'),
          tester.getRect(find.byType(DropdownButton<String>)));
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('combo menu items fit enlarged text and select the original key',
      (tester) async {
    final changes = <String>[];
    for (final direction in TextDirection.values) {
      await tester.pumpWidget(_page(options: const {'en': 'English', 'he': 'עברית'},
          selected: 'en', onChanged: changes.add, scale: 4, direction: direction));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(DropdownButton<String>));
      await tester.pumpAndSettle();
      final label = find.text('עברית').last;
      final item = find.ancestor(of: label,
          matching: find.byType(DropdownMenuItem<String>)).first;
      _expectTextFits(tester, label, tester.getRect(item));
      await tester.tap(label);
      await tester.pumpAndSettle();
      expect(changes.last, 'he');
      expect(tester.takeException(), isNull);
    }
    expect(changes, ['he', 'he']);
  });

  testWidgets('combo long labels remain selectable in a narrow view',
      (tester) async {
    const labels = {
      'de': 'Deutsch mit einer sehr langen Anzeigebezeichnung',
      'he': 'עברית עם שם תצוגה ארוך במיוחד לבחירה',
    };
    final changes = <String>[];
    for (final direction in TextDirection.values) {
      await tester.pumpWidget(_page(options: labels, selected: 'de',
          onChanged: changes.add, direction: direction));
      await tester.pumpAndSettle();
      expect(tester.getSize(find.byType(DropdownButton<String>)).width,
          lessThanOrEqualTo(180));
      expect(tester.takeException(), isNull);
      await tester.tap(find.byType(DropdownButton<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text(labels['he']!).last);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    }
    expect(changes, ['he', 'he']);
  });
}

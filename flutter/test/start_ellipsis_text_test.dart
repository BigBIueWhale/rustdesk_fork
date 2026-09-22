import 'package:characters/characters.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/start_ellipsis_text.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const style = TextStyle(fontFamily: 'Ahem', fontSize: 10);

  Widget subject(String text, double width) => MaterialApp(
        home: Material(
          child: Align(
            alignment: Alignment.topLeft,
            child: SizedBox(
              width: width,
              child: StartEllipsisText(text, style: style),
            ),
          ),
        ),
      );

  testWidgets('leaves fitting text unchanged', (tester) async {
    const original = 'report.txt';
    await tester.pumpWidget(subject(original, 400));

    expect(tester.widget<Text>(find.byType(Text)).data, original);
  });

  testWidgets('retains the longest fitting suffix', (tester) async {
    const original = 'a-very-long-report.txt';
    await tester.pumpWidget(subject(original, 80));

    final visible = tester.widget<Text>(find.byType(Text)).data!;
    expect(visible, startsWith('…'));
    expect(visible.length, lessThan(original.length));
    expect(original, endsWith(visible.substring(1)));
  });

  testWidgets('never cuts a grapheme cluster', (tester) async {
    const original = 'prefix-👩‍👩‍👧‍👦-suffix.txt';
    await tester.pumpWidget(subject(original, 90));

    final visible = tester.widget<Text>(find.byType(Text)).data!;
    final visibleSuffix = visible.characters.skip(1).join();
    final clusters = original.characters.toList();
    final completeSuffixes = <String>{
      for (var i = 0; i <= clusters.length; i++) clusters.skip(i).join(),
    };
    expect(visible, startsWith('…'));
    expect(completeSuffixes, contains(visibleSuffix));
  });

  testWidgets('exposes the complete text to assistive technology',
      (tester) async {
    const original = 'a-very-long-accessible-report.txt';
    await tester.pumpWidget(subject(original, 70));

    expect(
      tester.getSemantics(find.byType(Text)),
      containsSemantics(label: original),
    );
  }, semanticsEnabled: true);
}

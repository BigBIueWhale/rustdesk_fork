import 'dart:io';
import 'dart:typed_data';

import 'package:characters/characters.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/start_ellipsis_text.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    final root = Platform.environment['FLUTTER_ROOT'];
    if (root == null) throw StateError('Flutter SDK font location is missing');
    final loader = FontLoader('PathLabelTest');
    for (final weight in ['Regular', 'Bold']) {
      loader.addFont(File('$root/bin/cache/artifacts/material_fonts/'
              'Roboto-$weight.ttf')
          .readAsBytes()
          .then(ByteData.sublistView));
    }
    await loader.load();
  });

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

  for (final separator in {
    'LF': '\n',
    'CRLF': '\r\n',
    'line separator': '\u2028',
    'paragraph separator': '\u2029',
  }.entries) {
    for (final bounded in [true, false]) {
      final layout = bounded ? 'bounded' : 'unbounded';
      testWidgets('keeps filename end after ${separator.key} in $layout width',
          (tester) async {
        final original = 'prefix${separator.value}report.exe';
        final label = StartEllipsisText(original,
            style: style.copyWith(letterSpacing: 0));
        await tester.pumpWidget(MaterialApp(
          home: Material(
            child: Align(
              alignment: Alignment.topLeft,
              child: bounded
                  ? SizedBox(width: 400, child: label)
                  : Row(mainAxisSize: MainAxisSize.min, children: [label]),
            ),
          ),
        ));

        final visible = tester.widget<Text>(find.byType(Text)).data!;
        expect(visible, '…report.exe');
        expect(tester.getSemantics(find.byType(Text)),
            containsSemantics(label: original));
        final paragraph =
            tester.renderObject<RenderParagraph>(find.byType(RichText));
        final boxes = paragraph.getBoxesForSelection(TextSelection(
            baseOffset: visible.length - 4, extentOffset: visible.length));
        expect(boxes, isNotEmpty,
            reason: 'The actual filename extension must be laid out');
        for (final box in boxes) {
          expect(box.left, greaterThanOrEqualTo(0));
          expect(box.right, lessThanOrEqualTo(paragraph.size.width + 0.01));
        }
        expect(tester.takeException(), isNull);
      }, semanticsEnabled: true);
    }
  }

  for (final inherited in [true, false]) {
    for (final overflowing in [false, true]) {
      final styleName = inherited ? 'inherited' : 'explicit';
      final sizeName = overflowing ? 'truncated' : 'fitting';
      testWidgets(
          'bold accessibility preserves $sizeName filename end with $styleName style',
          (tester) async {
        const original = 'reports/iiiiiiiiiiiiiiiiiiii.txt';
        const font = TextStyle(
            inherit: false, fontFamily: 'PathLabelTest', fontSize: 24,
            fontWeight: FontWeight.normal, color: Colors.black);
        final sample = overflowing ? '…iiiiiiii.txt' : original;
        double width(FontWeight weight) {
          final painter = TextPainter(
              text: TextSpan(text: sample, style: font.copyWith(fontWeight: weight)),
              textDirection: TextDirection.ltr)..layout();
          try {
            return painter.width;
          } finally {
            painter.dispose();
          }
        }
        final regular = width(FontWeight.normal);
        final bold = width(FontWeight.bold);
        expect(bold, greaterThan(regular + 1), reason: 'Real font metrics must differ');
        final available = (regular + bold) / 2;
        final label = StartEllipsisText(original, style: inherited ? null : font);

        Future<String> render(bool boldText) async {
          await tester.pumpWidget(Directionality(
              textDirection: TextDirection.ltr,
              child: MediaQuery(
                  data: MediaQueryData(boldText: boldText),
                  child: DefaultTextStyle(
                      style: font,
                      child: Align(
                          alignment: Alignment.topLeft,
                          child: SizedBox(width: available, child: label))))));
          final text = tester.widget<Text>(find.byType(Text));
          final visible = text.data!;
          expect(text.semanticsLabel, original);
          expect(visible, endsWith('.txt'));
          final paragraph = tester.renderObject<RenderParagraph>(find.byType(RichText));
          final boxes = paragraph.getBoxesForSelection(TextSelection(
              baseOffset: visible.length - 4, extentOffset: visible.length));
          expect(boxes, isNotEmpty);
          for (final box in boxes) {
            expect(box.left, greaterThanOrEqualTo(0));
            expect(box.right, lessThanOrEqualTo(paragraph.size.width + 0.01),
                reason: 'The rendered filename extension must remain inside the label');
          }
          return visible;
        }

        final normalText = await render(false);
        expect(normalText, overflowing ? startsWith('…') : original);
        final boldText = await render(true);
        expect(boldText, startsWith('…'));
        expect(boldText.length, lessThan(normalText.length));
        expect(await render(false), normalText);
      });
    }
  }
}

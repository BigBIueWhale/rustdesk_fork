import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/popup_menu_position.dart';
import 'package:flutter_hbb/desktop/widgets/material_mod_popup_menu.dart'
    as mod_menu;
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

Widget _subject(TextDirection direction, String layout,
    ValueChanged<String> selected) {
  Widget page() => Scaffold(
        body: Padding(
          padding: EdgeInsets.only(
              left: direction == TextDirection.rtl ? 360 : 180, top: 120),
          child: Align(alignment: Alignment.topLeft, child: _Probe(selected)),
        ),
      );
  return MaterialApp(
    theme: ThemeData(useMaterial3: false, platform: TargetPlatform.linux),
    builder: (context, child) =>
        Directionality(textDirection: direction, child: child!),
    home: layout == 'root'
        ? page()
        : Align(
            alignment: Alignment.topLeft,
            child: Padding(
              padding: const EdgeInsets.only(left: 60, top: 70),
              child: Transform.scale(
                scale: layout == 'scaled' ? 1.2 : 1.0,
                alignment: Alignment.topLeft,
                child: SizedBox(
                  width: 500,
                  height: 400,
                  child: Navigator(
                    onGenerateRoute: (_) =>
                        MaterialPageRoute<void>(builder: (_) => page()),
                  ),
                ),
              ),
            ),
          ),
  );
}

final _entries = find.byWidgetPredicate((w) => w is mod_menu.PopupMenuItem);

Future<void> _closeMenu(WidgetTester tester) async {
  if (_entries.evaluate().isNotEmpty) {
    final context = tester.element(find.byIcon(IconFont.more));
    Navigator.of(context).pop();
    await tester.pumpAndSettle();
  }
}

void main() {
  for (final direction in TextDirection.values) {
    for (final layout in ['root', 'offset', 'scaled']) {
      testWidgets('connection menu keyboard anchor ${direction.name} $layout',
          (tester) async {
        final selected = <String>[];
        await tester.pumpWidget(_subject(direction, layout, selected.add));
        await tester.pumpAndSettle();
        final scale = layout == 'scaled' ? 1.2 : 1.0;
        for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
          final icon = find.byIcon(IconFont.more);
          Focus.of(tester.element(icon)).requestFocus();
          await tester.pump();
          final button = tester.getRect(find.byType(InkWell).first);
          await tester.sendKeyEvent(key);
          await tester.pumpAndSettle();
          try {
            expect(_entries, findsNWidgets(3));
            final bounds = tester.getRect(_entries.first);
            expect(direction == TextDirection.ltr ? bounds.left : bounds.right,
                closeTo(direction == TextDirection.ltr ? button.left : button.right,
                    0.01));
            expect(bounds.top, closeTo(button.bottom + 8 * scale, 0.01));
            expect(tester.state<_ProbeState>(find.byType(_Probe))._menuOpen.value,
                isTrue);
            await tester.sendKeyEvent(LogicalKeyboardKey.escape);
            await tester.pumpAndSettle();
            expect(_entries, findsNothing);
            expect(tester.state<_ProbeState>(find.byType(_Probe))._menuOpen.value,
                isFalse);
          } finally {
            await _closeMenu(tester);
          }
        }
        expect(selected, isEmpty);
        expect(tester.takeException(), isNull);
      });
    }
  }

  for (final item in [('Transfer file', 'file'), ('View camera', 'camera'),
      ('Terminal (beta)', 'terminal')]) {
    testWidgets('connection menu selects ${item.$2}', (tester) async {
      final selected = <String>[];
      await tester.pumpWidget(_subject(TextDirection.ltr, 'root', selected.add));
      await tester.tap(find.byIcon(IconFont.more));
      await tester.pumpAndSettle();
      try {
        await tester.tap(find.text(item.$1));
        await tester.pumpAndSettle();
        expect(selected, [item.$2]);
        expect(_entries, findsNothing);
        expect(tester.state<_ProbeState>(find.byType(_Probe))._menuOpen.value,
            isFalse);
      } finally {
        await _closeMenu(tester);
      }
      expect(tester.takeException(), isNull);
    });
  }
}

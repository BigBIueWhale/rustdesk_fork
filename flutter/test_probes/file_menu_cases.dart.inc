import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart' hide MenuButton;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/popup_menu_position.dart';
import 'package:flutter_hbb/desktop/widgets/material_mod_popup_menu.dart'
    as mod_menu;
import 'package:flutter_hbb/desktop/widgets/menu_button.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

Widget _subject(TextDirection direction, String layout,
    ValueChanged<String> selected, {ValueListenable<double> movement = const AlwaysStoppedAnimation(0)}) {
  Widget page() => Scaffold(
        body: ValueListenableBuilder<double>(valueListenable: movement,
          builder: (context, offset, _) => Padding(
          padding: EdgeInsets.only(
              left: (direction == TextDirection.rtl ? 360 : 80) + offset,
              top: 120 + offset),
          child: Align(alignment: Alignment.topLeft, child: _Probe(selected)),
        )),
      );
  return MaterialApp(
    theme: ThemeData(useMaterial3: false, platform: TargetPlatform.linux,
        fontFamily: 'FileMenuTest'),
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
    Navigator.of(tester.element(find.byIcon(Icons.more_horiz))).pop();
    await tester.pumpAndSettle();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    final root = Platform.environment['FLUTTER_ROOT'];
    if (root == null) throw StateError('Flutter SDK font location is missing');
    final loader = FontLoader('FileMenuTest')..addFont(
        File('$root/bin/cache/artifacts/material_fonts/Roboto-Regular.ttf')
            .readAsBytes().then(ByteData.sublistView));
    await loader.load();
  });

  for (final direction in TextDirection.values) {
    for (final layout in ['root', 'offset', 'scaled']) {
      testWidgets('file menu keyboard anchor ${direction.name} $layout',
          (tester) async {
        final selected = <String>[];
        final scale = layout == 'scaled' ? 1.2 : 1.0;
        final movement = ValueNotifier(0.0);
        addTearDown(movement.dispose);
        await tester.pumpWidget(_subject(direction, layout, selected.add,
            movement: movement));
        Rect? previousButton;
        for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
          await tester.pumpAndSettle();
          final icon = find.byIcon(Icons.more_horiz);
          Focus.of(tester.element(icon)).requestFocus();
          await tester.pump();
          final button = tester.getRect(find.byType(_Probe));
          if (previousButton != null) {
            final delta = button.topLeft - previousButton.topLeft;
            expect(delta.dx, closeTo(10 * scale, 0.01));
            expect(delta.dy, closeTo(10 * scale, 0.01));
          }
          previousButton = button;
          await tester.sendKeyEvent(key);
          await tester.pumpAndSettle();
          try {
            expect(_entries, findsNWidgets(3));
            final bounds = tester.getRect(_entries.first);
            expect(direction == TextDirection.ltr ? bounds.left : bounds.right,
                closeTo(direction == TextDirection.ltr ? button.left : button.right,
                    0.01));
            expect(bounds.top, closeTo(button.bottom + 8 * scale, 0.01));
            await tester.sendKeyEvent(LogicalKeyboardKey.escape);
            await tester.pumpAndSettle();
            expect(_entries, findsNothing);
          } finally {
            await _closeMenu(tester);
          }
          movement.value += 10;
        }
        expect(selected, isEmpty);
        expect(tester.takeException(), isNull);
      });
    }
  }

  for (final item in [('Show Hidden Files', 'hidden'), ('Select All', 'all'),
      ('Unselect All', 'none')]) {
    testWidgets('file menu selects ${item.$2}', (tester) async {
      final selected = <String>[];
      await tester.pumpWidget(_subject(TextDirection.ltr, 'root', selected.add));
      await tester.tap(find.byIcon(Icons.more_horiz));
      await tester.pumpAndSettle();
      try {
        await tester.tap(find.text(item.$1));
        await tester.pumpAndSettle();
        expect(selected, [item.$2]);
        expect(_entries, findsNothing);
      } finally {
        await _closeMenu(tester);
      }
      expect(tester.takeException(), isNull);
    });
  }
}

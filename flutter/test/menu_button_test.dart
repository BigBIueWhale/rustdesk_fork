import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart' hide MenuButton;
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/desktop/widgets/menu_button.dart';
import 'package:flutter_test/flutter_test.dart';

const _surface = ValueKey('button-surface');
const _normal = Color(0xffffffff);
const _hover = Color(0xff00ff00);
const _focus = Color(0xffff0000);

Widget _subject(VoidCallback? pressed) => MaterialApp(
      theme: ThemeData(platform: TargetPlatform.linux, focusColor: _focus),
      home: Scaffold(
        body: Center(
          child: RepaintBoundary(
            key: _surface,
            child: MenuButton(
              onPressed: pressed,
              color: _normal,
              hoverColor: _hover,
              padding: EdgeInsets.zero,
              tooltip: 'More actions',
              child: const SizedBox(
                width: 100,
                height: 60,
                child: Center(child: Text('Action')),
              ),
            ),
          ),
        ),
      ),
    );

Future<Color> _background(WidgetTester tester) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(_surface));
  final color = await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1);
    try {
      final bytes = (await image.toByteData(format: ui.ImageByteFormat.rawRgba))!;
      final offset = (30 * image.width + 10) * 4;
      return Color.fromARGB(bytes.getUint8(offset + 3), bytes.getUint8(offset),
          bytes.getUint8(offset + 1), bytes.getUint8(offset + 2));
    } finally {
      image.dispose();
    }
  });
  return color!;
}

void main() {
  testWidgets('menu button exposes its enabled role and action', (tester) async {
    await tester.pumpWidget(_subject(() {}));
    expect(
      tester.getSemantics(find.byType(MenuButton)),
      containsSemantics(
        label: 'Action',
        isButton: true,
        hasEnabledState: true,
        isEnabled: true,
        hasTapAction: true,
      ),
    );
  }, semanticsEnabled: true);

  testWidgets('menu button exposes disabled state without an action',
      (tester) async {
    await tester.pumpWidget(_subject(null));
    expect(
      tester.getSemantics(find.byType(MenuButton)),
      containsSemantics(
        label: 'Action',
        isButton: true,
        hasEnabledState: true,
        isEnabled: false,
        hasTapAction: false,
      ),
    );
  }, semanticsEnabled: true);

  testWidgets('menu button paints keyboard focus above its background',
      (tester) async {
    await tester.pumpWidget(_subject(() {}));
    expect(await _background(tester), _normal);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(await _background(tester), _focus);
    FocusManager.instance.primaryFocus!.unfocus();
    await tester.pumpAndSettle();
    expect(await _background(tester), _normal);
  });

  testWidgets('menu button retains pointer hover and exit painting',
      (tester) async {
    await tester.pumpWidget(_subject(() {}));
    final pointer = await tester.createGesture(kind: PointerDeviceKind.mouse);
    await pointer.addPointer(location: Offset.zero);
    await pointer.moveTo(tester.getCenter(find.byType(MenuButton)));
    await tester.pumpAndSettle();
    expect(await _background(tester), _hover);
    await pointer.moveTo(Offset.zero);
    await tester.pumpAndSettle();
    expect(await _background(tester), _normal);
    await pointer.removePointer();
  });

  testWidgets('menu button activates once per keyboard or pointer action',
      (tester) async {
    var calls = 0;
    await tester.pumpWidget(_subject(() => calls++));
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(calls, 1);
    await tester.sendKeyEvent(LogicalKeyboardKey.space);
    await tester.pumpAndSettle();
    expect(calls, 2);
    await tester.tap(find.byType(MenuButton));
    await tester.pumpAndSettle();
    expect(calls, 3);
  });

  testWidgets('menu button disabled rebuild refuses activation and can recover',
      (tester) async {
    var calls = 0;
    await tester.pumpWidget(_subject(() => calls++));
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.pumpWidget(_subject(null));
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyEvent(LogicalKeyboardKey.space);
    await tester.tap(find.byType(MenuButton));
    await tester.pumpAndSettle();
    expect(calls, 0);
    await tester.pumpWidget(_subject(() => calls++));
    await tester.tap(find.byType(MenuButton));
    await tester.pumpAndSettle();
    expect(calls, 1);
  });
}

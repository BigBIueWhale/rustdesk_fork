import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fixed_width_button_probe.dart';

const _surface = ValueKey('help-button-surface');
const _focus = Color(0xffff0000);

Widget _subject(bool outline, VoidCallback pressed) => MaterialApp(
  theme: ThemeData(
    platform: TargetPlatform.linux,
    focusColor: _focus,
    hoverColor: Colors.transparent,
    highlightColor: Colors.transparent,
    splashColor: Colors.transparent,
  ),
  home: Scaffold(
    backgroundColor: Colors.white,
    body: Center(
      child: RepaintBoundary(
        key: _surface,
        child: FixedWidthButton(
          width: 150,
          padding: 8,
          radius: 10,
          isOutline: outline,
          borderColor: Colors.green,
          text: 'Configure',
          textSize: 20,
          onTap: pressed,
        ),
      ),
    ),
  ),
);

Future<Color> _background(WidgetTester tester) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(_surface));
  final result = await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1);
    try {
      final bytes = (await image.toByteData(format: ui.ImageByteFormat.rawRgba))!;
      final offset = (4 * image.width + image.width ~/ 2) * 4;
      return Color.fromARGB(bytes.getUint8(offset + 3), bytes.getUint8(offset),
          bytes.getUint8(offset + 1), bytes.getUint8(offset + 2));
    } finally {
      image.dispose();
    }
  });
  return result!;
}

void main() {
  for (final outline in [false, true]) {
    final variant = outline ? 'outline' : 'filled';
    testWidgets('help button $variant exposes its role and action', (tester) async {
      await tester.pumpWidget(_subject(outline, () {}));
      expect(tester.getSemantics(find.text('Configure')), containsSemantics(
        label: 'Configure',
        isButton: true,
        hasEnabledState: true,
        isEnabled: true,
        hasTapAction: true,
      ));
    }, semanticsEnabled: true);

    testWidgets('help button $variant paints keyboard focus', (tester) async {
      await tester.pumpWidget(_subject(outline, () {}));
      final unfocused = await _background(tester);
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(await _background(tester), _focus);
      FocusManager.instance.primaryFocus!.unfocus();
      await tester.pumpAndSettle();
      expect(await _background(tester), unfocused);
    });

    testWidgets('help button $variant activates once per keyboard or pointer action',
        (tester) async {
      var calls = 0;
      await tester.pumpWidget(_subject(outline, () => calls++));
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(calls, 1);
      await tester.sendKeyEvent(LogicalKeyboardKey.space);
      await tester.pumpAndSettle();
      expect(calls, 2);
      await tester.tap(find.byType(FixedWidthButton));
      await tester.pumpAndSettle();
      expect(calls, 3);
    });

    testWidgets('help button $variant preserves geometry and retires cancelled presses',
        (tester) async {
      var calls = 0;
      await tester.pumpWidget(_subject(outline, () => calls++));
      final size = tester.getSize(find.byType(FixedWidthButton));
      expect(size.width, 150);
      final normal = await _background(tester);
      final pointer = await tester.startGesture(
          tester.getCenter(find.byType(FixedWidthButton)),
          kind: PointerDeviceKind.mouse);
      await tester.pump(const Duration(milliseconds: 150));
      expect(await _background(tester), MyTheme.accent);
      await pointer.cancel();
      await pointer.removePointer();
      await tester.pumpAndSettle();
      expect(calls, 0);
      expect(await _background(tester), normal);
      expect(tester.getSize(find.byType(FixedWidthButton)), size);
      await tester.tap(find.byType(FixedWidthButton));
      await tester.pumpAndSettle();
      expect(calls, 1);
    });
  }
}

import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

const _surface = ValueKey('toolbar-button-surface');
const _icon = ValueKey('toolbar-button-icon');
const _normal = Color(0xff123456);
const _highlight = Color(0xff00dd00);

Widget _subject(bool submenu, VoidCallback? pressed) => MaterialApp(
  theme: ThemeData(platform: TargetPlatform.linux),
  home: Scaffold(body: Center(child: Column(
    mainAxisSize: MainAxisSize.min,
    children: [
      RepaintBoundary(key: _surface, child: submenu
        ? _IconSubmenuButton(
            tooltip: 'Tools', color: _normal, hoverColor: _highlight,
            icon: const SizedBox(key: _icon, width: 32, height: 32),
            menuChildrenGetter: (_) => pressed == null ? [] : [
              MenuItemButton(onPressed: pressed, child: const Text('Run action')),
            ])
        : _IconMenuButton(
            tooltip: 'Tools', color: _normal, hoverColor: _highlight,
            topLevel: false,
            icon: const SizedBox(key: _icon, width: 32, height: 32),
            onPressed: pressed)),
      TextButton(onPressed: () {}, child: const Text('Outside')),
    ],
  ))),
);

Future<Color> _background(WidgetTester tester) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(_surface));
  final point = boundary.globalToLocal(tester.getCenter(find.byKey(_icon)));
  final result = await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1);
    try {
      final bytes = (await image.toByteData(format: ui.ImageByteFormat.rawRgba))!;
      final offset = (point.dy.floor() * image.width + point.dx.floor()) * 4;
      return Color.fromARGB(bytes.getUint8(offset + 3), bytes.getUint8(offset),
          bytes.getUint8(offset + 1), bytes.getUint8(offset + 2));
    } finally {
      image.dispose();
    }
  });
  return result!;
}

Finder _button() => find.ancestor(
    of: find.byKey(_icon), matching: find.byType(TextButton)).first;

Future<void> _focusButton(WidgetTester tester) async {
  final node = tester.widget<TextButton>(_button()).focusNode!;
  node.requestFocus();
  await tester.pumpAndSettle();
  expect(node.hasPrimaryFocus, isTrue);
}

Future<void> _focusOutside(WidgetTester tester) async {
  Focus.of(tester.element(find.text('Outside'))).requestFocus();
  await tester.pumpAndSettle();
}

Future<void> _openSubmenu(WidgetTester tester, bool submenu) async {
  if (submenu) {
    await tester.tap(_button());
    await tester.pumpAndSettle();
    expect(find.text('Run action'), findsOneWidget);
  }
}

void main() {
  for (final submenu in [false, true]) {
    final variant = submenu ? 'submenu' : 'action';
    testWidgets('toolbar $variant paints and retires keyboard focus', (tester) async {
      await tester.pumpWidget(_subject(submenu, () {}));
      expect(await _background(tester), _normal);
      await _openSubmenu(tester, submenu);
      await _focusButton(tester);
      expect(tester.getSemantics(find.byKey(_icon)), containsSemantics(isFocused: true));
      expect(await _background(tester), _highlight);
      await _focusOutside(tester);
      expect(tester.getSemantics(find.text('Outside')), containsSemantics(isFocused: true));
      expect(await _background(tester), _normal);
    }, semanticsEnabled: true);

    testWidgets('toolbar $variant retains pointer hover and exit', (tester) async {
      await tester.pumpWidget(_subject(submenu, () {}));
      final pointer = await tester.createGesture(kind: PointerDeviceKind.mouse);
      await pointer.addPointer(location: Offset.zero);
      await pointer.moveTo(tester.getCenter(find.byKey(_icon)));
      await tester.pumpAndSettle();
      expect(await _background(tester), _highlight);
      await pointer.moveTo(Offset.zero);
      await _focusOutside(tester);
      await tester.pumpAndSettle();
      expect(await _background(tester), _normal);
      await pointer.removePointer();
    });

    testWidgets('toolbar $variant activates by keyboard and pointer', (tester) async {
      var calls = 0;
      await tester.pumpWidget(_subject(submenu, () => calls++));
      for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
        await _openSubmenu(tester, submenu);
        await _focusButton(tester);
        await tester.sendKeyEvent(key);
        await tester.pumpAndSettle();
        if (submenu) {
          expect(find.text('Run action'), findsNothing);
          await _openSubmenu(tester, submenu);
          await tester.tap(find.text('Run action'));
          await tester.pumpAndSettle();
        }
        expect(calls, key == LogicalKeyboardKey.enter ? 1 : 2);
      }
      await tester.tap(_button());
      await tester.pumpAndSettle();
      if (submenu) {
        await tester.tap(find.text('Run action'));
        await tester.pumpAndSettle();
      }
      expect(calls, 3);
    });

    testWidgets('toolbar $variant disabling clears focus and permits reuse', (tester) async {
      var calls = 0;
      await tester.pumpWidget(_subject(submenu, () => calls++));
      await _openSubmenu(tester, submenu);
      await _focusButton(tester);
      await tester.pumpWidget(_subject(submenu, null));
      await tester.pumpAndSettle();
      expect(await _background(tester), _normal);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.tap(_button());
      await tester.pumpAndSettle();
      expect(calls, 0);
      expect(find.text('Run action'), findsNothing);
      await tester.pumpWidget(_subject(submenu, () => calls++));
      await tester.pumpAndSettle();
      expect(await _background(tester), _normal);
      await _openSubmenu(tester, submenu);
      await _focusButton(tester);
      expect(tester.getSemantics(find.byKey(_icon)), containsSemantics(isFocused: true));
      expect(await _background(tester), _highlight);
    }, semanticsEnabled: true);
  }
}

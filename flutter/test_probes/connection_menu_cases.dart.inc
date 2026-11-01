import 'dart:math';
import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/popup_menu_position.dart';
import 'package:flutter_hbb/desktop/widgets/material_mod_popup_menu.dart'
    as mod_menu;
import 'package:flutter_hbb/desktop/widgets/menu_button.dart' as menu_button;
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

final _entries = find.byWidgetPredicate((w) =>
    w is mod_menu.PopupMenuEntry && w is! mod_menu.PopupMenuDivider);

Future<BuildContext> _openButtonEntry(WidgetTester tester, RxBool enabled,
    bool dismiss, List<String> events, {VoidCallback? action}) async {
  late BuildContext page;
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(useMaterial3: false, platform: TargetPlatform.linux),
    home: Builder(builder: (context) {
      page = context;
      return const Scaffold(body: Text('Underlying page'));
    }),
  ));
  mod_menu.showMenu<String>(
    context: page,
    position: const RelativeRect.fromLTRB(40, 40, 400, 400),
    items: MenuEntryButton<String>(
      childBuilder: (style) => Text('Entry action', style: style),
      proc: () {
        events.add('action');
        action?.call();
      },
      enabled: enabled,
      dismissOnClicked: dismiss,
      dismissCallback: () => events.add('dismiss'),
    ).build(page, const MenuConfig(commonColor: Colors.blue, boxWidth: 180)),
  ).then((_) => events.add('closed'));
  await tester.pumpAndSettle();
  return page;
}

Future<void> _activateEntry(WidgetTester tester, String method) async {
  if (method == 'pointer') {
    await tester.tap(find.text('Entry action'));
  } else if (method == 'semantics') {
    final node = tester.getSemantics(find.text('Entry action'));
    tester.binding.pipelineOwner.semanticsOwner!
        .performAction(node.id, ui.SemanticsAction.tap);
  } else {
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
  }
  await tester.pumpAndSettle();
}

Future<void> _closeMenu(WidgetTester tester) async {
  if (_entries.evaluate().isNotEmpty) {
    final context = tester.element(find.byIcon(IconFont.more));
    Navigator.of(context).pop();
    await tester.pumpAndSettle();
  }
}

void main() {
  for (final method in ['pointer', 'semantics', 'keyboard']) {
    for (final dismiss in [false, true]) {
      testWidgets('menu entry $method dismiss=$dismiss invokes once',
          (tester) async {
        final events = <String>[];
        await _openButtonEntry(tester, true.obs, dismiss, events);
        try {
          await _activateEntry(tester, method);
          expect(events.where((event) => event == 'action'), hasLength(1));
          expect(events.where((event) => event == 'dismiss'),
              hasLength(dismiss ? 1 : 0));
          expect(events.where((event) => event == 'closed'),
              hasLength(dismiss ? 1 : 0));
          expect(find.text('Entry action'),
              dismiss ? findsNothing : findsOneWidget);
          if (dismiss) expect(events.indexOf('dismiss'), lessThan(events.indexOf('action')));
        } finally {
          await tester.pumpWidget(const SizedBox.shrink());
          await tester.pumpAndSettle();
        }
        expect(tester.takeException(), isNull);
      }, semanticsEnabled: true);
    }
  }

  testWidgets('menu entry live disabled state refuses actions and recovers',
      (tester) async {
    final enabled = true.obs;
    final events = <String>[];
    await _openButtonEntry(tester, enabled, false, events);
    try {
      enabled.value = false;
      await tester.pumpAndSettle();
      expect(tester.getSemantics(find.text('Entry action')), containsSemantics(
        label: 'Entry action', isButton: true, hasEnabledState: true,
        isEnabled: false, hasTapAction: false,
      ));
      await _activateEntry(tester, 'pointer');
      await _activateEntry(tester, 'semantics');
      await _activateEntry(tester, 'keyboard');
      expect(events, isEmpty);
      expect(find.text('Entry action'), findsOneWidget);
      enabled.value = true;
      await tester.pumpAndSettle();
      expect(tester.getSemantics(find.text('Entry action')), containsSemantics(
        label: 'Entry action', isButton: true, hasEnabledState: true,
        isEnabled: true, hasTapAction: true,
      ));
      await _activateEntry(tester, 'semantics');
      expect(events, ['action']);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pumpAndSettle();
    }
    expect(tester.takeException(), isNull);
  }, semanticsEnabled: true);

  testWidgets('menu entry closes only its menu before opening a dialog',
      (tester) async {
    final events = <String>[];
    late BuildContext page;
    page = await _openButtonEntry(tester, true.obs, true, events, action: () {
      showDialog<void>(context: page, builder: (_) =>
          const AlertDialog(content: Text('New dialog')));
    });
    try {
      await _activateEntry(tester, 'semantics');
      expect(events, ['dismiss', 'action', 'closed']);
      expect(find.text('Entry action'), findsNothing);
      expect(find.text('New dialog'), findsOneWidget);
      Navigator.of(page).pop();
      await tester.pumpAndSettle();
      expect(find.text('Underlying page'), findsOneWidget);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pumpAndSettle();
    }
    expect(tester.takeException(), isNull);
  }, semanticsEnabled: true);

  testWidgets('connection menu exposes its description and button action',
      (tester) async {
    final selected = <String>[];
    await tester.pumpWidget(_subject(TextDirection.ltr, 'root', selected.add));
    final node = tester.getSemantics(find.byIcon(IconFont.more));
    expect(node, containsSemantics(
      tooltip: 'More',
      isButton: true,
      hasEnabledState: true,
      isEnabled: true,
      isFocusable: true,
      hasTapAction: true,
    ));
    tester.binding.pipelineOwner.semanticsOwner!
        .performAction(node.id, ui.SemanticsAction.tap);
    await tester.pumpAndSettle();
    try {
      expect(_entries, findsNWidgets(3));
      await tester.tap(find.text('Transfer file'));
      await tester.pumpAndSettle();
      expect(selected, ['file']);
      expect(_entries, findsNothing);
    } finally {
      await _closeMenu(tester);
    }
    expect(tester.takeException(), isNull);
  }, semanticsEnabled: true);

  testWidgets('connection menu responds across the outlined button interior',
      (tester) async {
    final selected = <String>[];
    await tester.pumpWidget(_subject(TextDirection.ltr, 'root', selected.add));
    final bounds = tester.getRect(find.byType(_Probe));
    expect(bounds.size, const Size(28, 28));
    for (final point in [
      Offset(bounds.left + 3, bounds.center.dy),
      Offset(bounds.right - 3, bounds.center.dy),
      Offset(bounds.center.dx, bounds.top + 3),
      Offset(bounds.center.dx, bounds.bottom - 3),
    ]) {
      await tester.tapAt(point);
      await tester.pumpAndSettle();
      try {
        expect(_entries, findsNWidgets(3));
      } finally {
        await _closeMenu(tester);
      }
    }
    expect(selected, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('connection menu shows its description on hover', (tester) async {
    await tester.pumpWidget(_subject(TextDirection.ltr, 'root', (_) {}));
    final pointer = await tester.createGesture(kind: PointerDeviceKind.mouse);
    await pointer.addPointer(location: Offset.zero);
    try {
      await pointer.moveTo(tester.getCenter(find.byIcon(IconFont.more)));
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
      expect(find.text('More'), findsOneWidget);
      expect(_entries, findsNothing);
    } finally {
      await pointer.removePointer();
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
    }
    expect(tester.takeException(), isNull);
  });

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

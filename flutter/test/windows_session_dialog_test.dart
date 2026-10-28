import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_test/flutter_test.dart';

Future<OverlayDialogManager> _manager(WidgetTester tester) async {
  final state = BlockableOverlayState();
  final manager = OverlayDialogManager(translateText: (text) => text);
  manager.setOverlayState(state);
  await tester.pumpWidget(MaterialApp(
    home: BlockableOverlay(
      state: state,
      underlying: const SizedBox.expand(),
    ),
  ));
  return manager;
}

void _open(OverlayDialogManager manager, ValueChanged<String> onSelected,
    {String title = 'Choose Windows session'}) {
  showWindowsSessionsDialog(
    '',
    title,
    'Choose a session',
    manager,
    '[{"sid":"11","name":"Console"},{"sid":"22","name":"Remote"}]',
    onSelected: onSelected,
    translateText: (text) => text,
  );
}

Finder get _connect => find.ancestor(
      of: find.text('Connect'),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    );

VoidCallback _submit(WidgetTester tester) =>
    tester.widget<ButtonStyleButton>(_connect).onPressed!;

Future<void> _dispose(WidgetTester tester, OverlayDialogManager manager) async {
  manager.dismissAll();
  await tester.pumpWidget(const SizedBox.shrink());
}

void main() {
  testWidgets('Windows chooser connects the first advertised session',
      (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    try {
      _open(manager, selected.add);
      await tester.pumpAndSettle();
      await tester.tap(_connect);
      await tester.pumpAndSettle();
      expect(selected, ['11']);
      expect(find.byType(CustomAlertDialog), findsNothing);
    } finally {
      await _dispose(tester, manager);
    }
  });

  testWidgets('Windows chooser connects the changed selection', (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    try {
      _open(manager, selected.add);
      await tester.pumpAndSettle();
      await tester.tap(find.byType(DropdownButton<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Remote').last);
      await tester.pumpAndSettle();
      await tester.tap(_connect);
      await tester.pumpAndSettle();
      expect(selected, ['22']);
      expect(find.byType(CustomAlertDialog), findsNothing);
    } finally {
      await _dispose(tester, manager);
    }
  });

  testWidgets('Windows chooser submits only once before unmount', (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    try {
      _open(manager, selected.add);
      await tester.pumpAndSettle();
      final element = tester.element(find.byType(CustomAlertDialog));
      final submit = _submit(tester);
      submit();
      expect(element.mounted, isTrue);
      submit();
      submit();
      expect(selected, ['11']);
    } finally {
      await _dispose(tester, manager);
    }
  });

  testWidgets('Windows chooser dismissed callbacks have no selection authority',
      (tester) async {
    for (final unmount in [false, true]) {
      final manager = await _manager(tester);
      final selected = <String>[];
      try {
        _open(manager, selected.add);
        await tester.pumpAndSettle();
        final element = tester.element(find.byType(CustomAlertDialog));
        final submit = _submit(tester);
        manager.dismissAll();
        if (unmount) await tester.pump();
        expect(element.mounted, !unmount);
        submit();
        expect(selected, isEmpty);
      } finally {
        await _dispose(tester, manager);
      }
    }
  });

  testWidgets('Windows chooser replacement retires the prior submit',
      (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    try {
      _open(manager, (sid) => selected.add('old:$sid'));
      await tester.pumpAndSettle();
      final element = tester.element(find.byType(CustomAlertDialog));
      final submit = _submit(tester);
      _open(manager, (sid) => selected.add('new:$sid'), title: 'Replacement');
      expect(element.mounted, isTrue);
      submit();
      expect(selected, isEmpty);
      await tester.pumpAndSettle();
      expect(find.text('Replacement'), findsOneWidget);
      await tester.tap(_connect);
      expect(selected, ['new:11']);
    } finally {
      await _dispose(tester, manager);
    }
  });

  testWidgets('Windows chooser retires before reentrant selection dispatch',
      (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    late VoidCallback submit;
    try {
      _open(manager, (sid) {
        selected.add(sid);
        if (selected.length == 1) submit();
      });
      await tester.pumpAndSettle();
      submit = _submit(tester);
      submit();
      expect(selected, ['11']);
    } finally {
      await _dispose(tester, manager);
    }
  });

  for (final key in {
    'Enter': LogicalKeyboardKey.enter,
    'numpad Enter': LogicalKeyboardKey.numpadEnter,
  }.entries) {
    testWidgets('Windows chooser ${key.key} submits its current selection',
        (tester) async {
      final manager = await _manager(tester);
      final selected = <String>[];
      try {
        _open(manager, selected.add);
        await tester.pumpAndSettle();
        expect(FocusManager.instance.primaryFocus, isNotNull);
        await tester.sendKeyEvent(key.value);
        await tester.pumpAndSettle();
        expect(selected, ['11']);
        expect(find.byType(CustomAlertDialog), findsNothing);
      } finally {
        await _dispose(tester, manager);
      }
    });
  }

  testWidgets('Windows chooser retired dropdown cannot update disposed state',
      (tester) async {
    final manager = await _manager(tester);
    final selected = <String>[];
    try {
      _open(manager, selected.add);
      await tester.pumpAndSettle();
      final change = tester
          .widget<DropdownButton<String>>(find.byType(DropdownButton<String>))
          .onChanged!;
      manager.dismissAll();
      await tester.pumpAndSettle();
      expect(() => change('22'), returnsNormally);
      expect(selected, isEmpty);
      expect(tester.takeException(), isNull);
    } finally {
      await _dispose(tester, manager);
    }
  });
}

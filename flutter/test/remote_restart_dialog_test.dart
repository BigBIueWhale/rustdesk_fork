import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/common/widgets/remote_restart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';

Future<OverlayDialogManager> manager(WidgetTester tester) async {
  final overlay = BlockableOverlayState();
  final manager = OverlayDialogManager(translateText: (text) => text);
  manager.setOverlayState(overlay);
  await tester.pumpWidget(MaterialApp(
    theme: MyTheme.lightTheme,
    home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
  ));
  return manager;
}

Future<void> open(OverlayDialogManager manager, Future<void> Function() request) =>
    manager.show<void>((_, close, __) => RemoteRestartDialog(
      target: 'operator@desktop(192.0.2.1)',
      requestRestart: request,
      close: close,
      translateText: (text) => text,
    ), tag: 'restart');

Finder button(String text) => find.ancestor(
  of: find.text(text),
  matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
);

Future<void> dispose(WidgetTester tester, OverlayDialogManager manager) async {
  manager.dismissAll();
  await tester.pumpWidget(const SizedBox.shrink());
}

void main() {
  testWidgets('restart waits for admission and submits once', (tester) async {
    final dialogs = await manager(tester);
    final result = Completer<void>();
    var requests = 0;
    open(dialogs, () { requests++; return result.future; });
    await tester.pumpAndSettle();
    final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog)).onSubmit!;
    submit();
    submit();
    await tester.pump();
    expect(requests, 1);
    expect(find.byType(RemoteRestartDialog), findsOneWidget);
    expect(tester.widget<ButtonStyleButton>(button('OK')).onPressed, isNull);
    expect(tester.widget<ButtonStyleButton>(button('Cancel')).onPressed, isNull);
    result.complete();
    await tester.pumpAndSettle();
    expect(find.byType(RemoteRestartDialog), findsNothing);
    submit();
    expect(requests, 1);
    await dispose(tester, dialogs);
  });

  testWidgets('restart failure stays visible and permits retry', (tester) async {
    final dialogs = await manager(tester);
    var requests = 0;
    open(dialogs, () async {
      requests++;
      if (requests == 1) throw StateError('round closed');
    });
    await tester.pumpAndSettle();
    await tester.tap(button('OK'));
    await tester.pumpAndSettle();
    expect(find.text('Failed'), findsOneWidget);
    expect(find.byType(RemoteRestartDialog), findsOneWidget);
    await tester.tap(button('Retry'));
    await tester.pumpAndSettle();
    expect(requests, 2);
    expect(find.byType(RemoteRestartDialog), findsNothing);
    await dispose(tester, dialogs);
  });

  testWidgets('restart cancellation sends no command', (tester) async {
    final dialogs = await manager(tester);
    var requests = 0;
    open(dialogs, () async { requests++; });
    await tester.pumpAndSettle();
    final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog)).onSubmit!;
    await tester.tap(button('Cancel'));
    submit();
    await tester.pumpAndSettle();
    expect(requests, 0);
    expect(find.byType(RemoteRestartDialog), findsNothing);
    await dispose(tester, dialogs);
  });

  testWidgets('restart Enter confirms the displayed target', (tester) async {
    final dialogs = await manager(tester);
    var requests = 0;
    open(dialogs, () async { requests++; });
    await tester.pumpAndSettle();
    expect(find.textContaining('operator@desktop(192.0.2.1)'), findsOneWidget);
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(requests, 1);
    expect(find.byType(RemoteRestartDialog), findsNothing);
    await dispose(tester, dialogs);
  });

  testWidgets('restart dismissed callbacks cannot submit before unmount', (tester) async {
    final dialogs = await manager(tester);
    var requests = 0;
    open(dialogs, () async { requests++; });
    await tester.pumpAndSettle();
    final element = tester.element(find.byType(RemoteRestartDialog));
    final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog)).onSubmit!;
    dialogs.dismissAll();
    expect(element.mounted, isTrue);
    submit();
    expect(requests, 0);
    await dispose(tester, dialogs);
    submit();
    expect(requests, 0);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restart old completion preserves a replacement dialog', (tester) async {
    for (final fail in [false, true]) {
      final dialogs = await manager(tester);
      final pending = Completer<void>();
      var replacements = 0;
      open(dialogs, () => pending.future);
      await tester.pumpAndSettle();
      await tester.tap(button('OK'));
      await tester.pump();
      open(dialogs, () async { replacements++; });
      await tester.pumpAndSettle();
      if (fail) { pending.completeError(StateError('old failure')); }
      else { pending.complete(); }
      await tester.pumpAndSettle();
      expect(find.byType(RemoteRestartDialog), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
      expect(replacements, 0);
      await tester.tap(button('OK'));
      await tester.pumpAndSettle();
      expect(replacements, 1);
      expect(tester.takeException(), isNull);
      await dispose(tester, dialogs);
    }
  });

  testWidgets('restart synchronous refusal is visible and retryable', (tester) async {
    final dialogs = await manager(tester);
    var requests = 0;
    open(dialogs, () {
      requests++;
      if (requests == 1) throw StateError('retired owner');
      return Future<void>.value();
    });
    await tester.pumpAndSettle();
    await tester.tap(button('OK'));
    await tester.pumpAndSettle();
    expect(find.text('Failed'), findsOneWidget);
    await tester.tap(button('Retry'));
    await tester.pumpAndSettle();
    expect(requests, 2);
    expect(find.byType(RemoteRestartDialog), findsNothing);
    await dispose(tester, dialogs);
  });

  testWidgets('restart admission closes only its own dialog', (tester) async {
    final dialogs = await manager(tester);
    final pending = Completer<void>();
    open(dialogs, () => pending.future);
    await tester.pumpAndSettle();
    await tester.tap(button('OK'));
    await tester.pump();
    dialogs.show<void>((_, __, ___) => const Text('unrelated'), tag: 'other');
    pending.complete();
    await tester.pumpAndSettle();
    expect(find.byType(RemoteRestartDialog), findsNothing);
    expect(find.text('unrelated'), findsOneWidget);
    await dispose(tester, dialogs);
  });

  testWidgets('restart pending Escape cannot imply cancellation', (tester) async {
    final dialogs = await manager(tester);
    final pending = Completer<void>();
    open(dialogs, () => pending.future);
    await tester.pumpAndSettle();
    await tester.tap(button('OK'));
    await tester.pump();
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    expect(find.byType(RemoteRestartDialog), findsOneWidget);
    pending.completeError(StateError('refused'));
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pumpAndSettle();
    expect(find.byType(RemoteRestartDialog), findsNothing);
    await dispose(tester, dialogs);
  });
}

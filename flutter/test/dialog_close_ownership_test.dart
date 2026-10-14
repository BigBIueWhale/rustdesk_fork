import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';
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

void main() {
  testWidgets('dialog close grants only its exact current entry', (tester) async {
    final manager = await _manager(tester);
    try {
      late DialogClose originalClose;
      late DialogClose replacementClose;
      final original = manager.show<String>((_, close, __) {
        originalClose = close;
        return const Text('original');
      }, tag: 'same-tag');
      await tester.pump();
      expect(originalClose.isCurrent, isTrue);
      final replacement = manager.show<String>((_, close, __) {
        replacementClose = close;
        return const Text('replacement');
      }, tag: 'same-tag');
      expect(originalClose.isCurrent, isFalse);
      expect(originalClose('stale result'), isFalse);
      await tester.pump();
      expect(await original, isNull);
      expect(find.text('replacement'), findsOneWidget);
      expect(replacementClose('current result'), isTrue);
      expect(replacementClose('duplicate result'), isFalse);
      expect(await replacement, 'current result');
      expect(manager.existing('same-tag'), isFalse);
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('loading cancel retires only its own entry and dispatches once',
      (tester) async {
    final manager = await _manager(tester);
    final events = <String>[];
    try {
      manager.showLoading('loading',
          tag: 'loading', onCancel: () => events.add('cancel'));
      await tester.pump();
      final cancel = tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onCancel!;
      final unrelated = manager.show<void>(
          (_, __, ___) => const Text('unrelated'),
          tag: 'unrelated');
      cancel();
      cancel();
      await tester.pump();
      expect(events, ['cancel']);
      expect(manager.existing('loading'), isFalse);
      expect(manager.existing('unrelated'), isTrue);
      expect(find.text('unrelated'), findsOneWidget);
      manager.dismissByTag('unrelated');
      await unrelated;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('superseded loading cancel has no authority before unmount',
      (tester) async {
    final manager = await _manager(tester);
    var cancels = 0;
    try {
      manager.showLoading('old loading',
          tag: 'state', onCancel: () => cancels++);
      await tester.pump();
      final oldElement = tester.element(find.byType(CustomAlertDialog));
      final cancel = tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onCancel!;
      final replacement = manager.show<void>(
          (_, __, ___) => const Text('replacement'),
          tag: 'state');
      expect(oldElement.mounted, isTrue);
      cancel();
      expect(cancels, 0);
      await tester.pump();
      expect(manager.existing('state'), isTrue);
      expect(find.text('replacement'), findsOneWidget);
      manager.dismissByTag('state');
      await replacement;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('superseded connect callbacks cannot act before unmount',
      (tester) async {
    for (final submit in [false, true]) {
      final manager = await _manager(tester);
      final events = <String>[];
      try {
        final oldPrompt = manager.show<void>((_, close, __) {
          return ConnectPasswordDialog(
            readRemember: () async => false,
            submitPassword: (_, __) {
              events.add('submit');
              return true;
            },
            close: close,
            onCancel: () => events.add('cancel'),
            onAccepted: () => events.add('accepted'),
            translateText: (text) => text,
          );
        }, tag: 'state');
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 60));
        await tester.enterText(find.byType(TextField), 'Runtime1x');
        final oldElement = tester.element(find.byType(ConnectPasswordDialog));
        final dialog =
            tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog));
        final action = submit ? dialog.onSubmit! : dialog.onCancel!;
        final replacement = manager.show<void>(
            (_, __, ___) => const Text('replacement'),
            tag: 'state');
        expect(oldElement.mounted, isTrue);
        action();
        expect(events, isEmpty);
        await tester.pump();
        expect(await oldPrompt, isNull);
        expect(manager.existing('state'), isTrue);
        expect(find.text('replacement'), findsOneWidget);
        manager.dismissByTag('state');
        await replacement;
      } finally {
        manager.dismissAll();
        await tester.pumpWidget(const SizedBox.shrink());
      }
    }
  });
}

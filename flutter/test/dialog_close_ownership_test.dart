import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/connect_password_dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';

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

VoidCallback _messageButton(WidgetTester tester, String label) => tester
    .widget<ButtonStyleButton>(find.ancestor(
      of: find.text(label),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    ))
    .onPressed!;

void main() {
  testWidgets('unbound message cannot close the active desktop tab',
      (tester) async {
    final manager = await _manager(tester);
    final controller = DesktopTabController(
      tabType: DesktopTabType.remoteScreen,
    );
    final removed = <String>[];
    controller.onRemoved = (_, key) => removed.add(key);
    controller.state.value.tabs.addAll([
      TabInfo(key: 'origin', label: 'origin', page: const SizedBox.shrink()),
      TabInfo(key: 'active', label: 'active', page: const SizedBox.shrink()),
    ]);
    controller.state.value.selected = 1;
    controller.state.value.scrollController.itemCount = 2;
    expect(Get.isRegistered<DesktopTabController>(), isFalse);
    Get.put<DesktopTabController>(controller);
    try {
      msgBox(const Uuid().v4obj(), 'error', 'notice', 'error detail', '', manager);
      await tester.pump();
      final submit = _messageButton(tester, 'OK');
      final unrelated = manager.show<void>(
          (_, __, ___) => const Text('unrelated'),
          tag: 'unrelated');
      submit();
      submit();
      await tester.pump();
      expect(removed, isEmpty);
      expect(controller.state.value.tabs.map((tab) => tab.key),
          ['origin', 'active']);
      expect(controller.state.value.selected, 1);
      expect(find.text('notice'), findsNothing);
      expect(manager.existing('unrelated'), isTrue);
      manager.dismissByTag('unrelated');
      await unrelated;
    } finally {
      manager.dismissAll();
      await Get.delete<DesktopTabController>();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('image wait cancel retires its entry and dispatches once',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    var cancels = 0;
    late final String tag;
    try {
      tag = manager.showWaitingForImage(session, 'success', 'waiting', 'image',
          onCancel: () {
        expect(manager.existing(tag), isFalse);
        cancels++;
      });
      await tester.pump();
      final escape = tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onCancel!;
      final button = _messageButton(tester, 'Cancel');
      final unrelated = manager.show<void>(
          (_, __, ___) => const Text('unrelated'),
          tag: 'unrelated');
      button();
      escape();
      button();
      expect(cancels, 1);
      await tester.pump();
      expect(find.text('waiting'), findsNothing);
      expect(manager.existing('unrelated'), isTrue);
      expect(find.text('unrelated'), findsOneWidget);
      manager.dismissByTag('unrelated');
      await unrelated;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('superseded image wait cancel cannot act before unmount',
      (tester) async {
    for (final useButton in [false, true]) {
      final manager = await _manager(tester);
      final session = const Uuid().v4obj();
      var cancels = 0;
      try {
        manager.showWaitingForImage(session, 'success', 'old wait', 'image',
            onCancel: () => cancels++);
        await tester.pump();
        final oldElement = tester.element(find.byType(CustomAlertDialog));
        final cancel = useButton
            ? _messageButton(tester, 'Cancel')
            : tester
                .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
                .onCancel!;
        final tag = manager.showWaitingForImage(
            session, 'success', 'new wait', 'image',
            onCancel: () => cancels += 10);
        expect(oldElement.mounted, isTrue);
        cancel();
        expect(cancels, 0);
        expect(manager.existing(tag), isTrue);
        await tester.pump();
        expect(find.text('new wait'), findsOneWidget);
        _messageButton(tester, 'Cancel')();
        expect(cancels, 10);
      } finally {
        manager.dismissAll();
        await tester.pumpWidget(const SizedBox.shrink());
      }
    }
  });

  testWidgets('dismissed image wait cancel cannot act before unmount',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    var cancels = 0;
    try {
      final tag = manager.showWaitingForImage(
          session, 'success', 'old wait', 'image',
          onCancel: () => cancels++);
      await tester.pump();
      final oldElement = tester.element(find.byType(CustomAlertDialog));
      final cancel = _messageButton(tester, 'Cancel');
      manager.dismissByTag(tag);
      final presented = manager.show<void>(
          (_, __, ___) => const Text('image presented'),
          tag: 'presented');
      expect(oldElement.mounted, isTrue);
      cancel();
      expect(cancels, 0);
      await tester.pump();
      expect(find.text('old wait'), findsNothing);
      expect(manager.existing('presented'), isTrue);
      expect(find.text('image presented'), findsOneWidget);
      manager.dismissByTag('presented');
      await presented;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('message submit retires only its entry and dispatches once',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    var submits = 0;
    try {
      msgBox(session, 'custom', 'request', 'confirm', '', manager,
          onSubmit: () => submits++);
      await tester.pump();
      final submit = tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final unrelated = manager.show<void>(
          (_, __, ___) => const Text('unrelated'),
          tag: 'unrelated');
      submit();
      submit();
      await tester.pump();
      expect(submits, 1);
      expect(find.text('request'), findsNothing);
      expect(manager.existing('unrelated'), isTrue);
      expect(find.text('unrelated'), findsOneWidget);
      manager.dismissByTag('unrelated');
      await unrelated;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('retired message submit cannot act before unmount', (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    final events = <String>[];
    try {
      msgBox(session, 'custom', 'old request', 'confirm', '', manager,
          onSubmit: () => events.add('old'));
      await tester.pump();
      final oldElement = tester.element(find.byType(CustomAlertDialog));
      final submit = tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      msgBox(session, 'custom', 'new request', 'confirm', '', manager,
          onSubmit: () => events.add('new'));
      expect(oldElement.mounted, isTrue);
      submit();
      expect(events, isEmpty);
      await tester.pump();
      expect(find.text('new request'), findsOneWidget);
      tester
          .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!();
      expect(events, ['new']);
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('retired message cancel and close cannot dismiss a replacement',
      (tester) async {
    for (final cancel in [true, false]) {
      final manager = await _manager(tester);
      final session = const Uuid().v4obj();
      try {
        msgBox(session, 'custom-hasclose', 'old request', 'confirm', '', manager);
        await tester.pump();
        final oldElement = tester.element(find.byType(CustomAlertDialog));
        final action = cancel
            ? tester
                .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
                .onCancel!
            : _messageButton(tester, 'Close');
        msgBox(session, 'custom-hasclose', 'new request', 'confirm', '', manager);
        expect(oldElement.mounted, isTrue);
        action();
        await tester.pump();
        expect(find.text('new request'), findsOneWidget);
        final currentAction = cancel
            ? tester
                .widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
                .onCancel!
            : _messageButton(tester, 'Close');
        final unrelated = manager.show<void>(
            (_, __, ___) => const Text('unrelated'),
            tag: 'unrelated');
        currentAction();
        currentAction();
        await tester.pump();
        expect(find.text('new request'), findsNothing);
        expect(manager.existing('unrelated'), isTrue);
        expect(find.text('unrelated'), findsOneWidget);
        manager.dismissByTag('unrelated');
        await unrelated;
      } finally {
        manager.dismissAll();
        await tester.pumpWidget(const SizedBox.shrink());
      }
    }
  });

  testWidgets('message reconnect countdown never submits an action',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    final events = <String>[];
    try {
      msgBox(session, 'error', 'Connection Error', 'retry', '', manager,
          onSubmit: () => events.add('submit'),
          reconnect: (_, __) => events.add('reconnect'),
          reconnectTimeout: 3);
      await tester.pump();
      await tester.pump(const Duration(seconds: 4));
      expect(events, isEmpty);
      expect(find.text('Reconnect (0s)'), findsOneWidget);
      _messageButton(tester, 'Reconnect (0s)')();
      expect(events, ['reconnect']);
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('retired message reconnect cannot act before unmount',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    var reconnects = 0;
    try {
      msgBox(session, 'error', 'Connection Error', 'retry', '', manager,
          reconnect: (_, __) => reconnects++, reconnectTimeout: 3);
      await tester.pump();
      final oldElement = tester.element(find.byType(CustomAlertDialog));
      final reconnect = _messageButton(tester, 'Reconnect (3s)');
      msgBox(session, 'custom', 'new request', 'confirm', '', manager);
      expect(oldElement.mounted, isTrue);
      reconnect();
      expect(reconnects, 0);
      await tester.pump();
      expect(find.text('new request'), findsOneWidget);
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('message reconnect retires its entry and dispatches once',
      (tester) async {
    final manager = await _manager(tester);
    final session = const Uuid().v4obj();
    var reconnects = 0;
    try {
      msgBox(session, 'error', 'Connection Error', 'retry', '', manager,
          reconnect: (actualManager, actualSession) {
        expect(identical(actualManager, manager), isTrue);
        expect(actualSession, session);
        reconnects++;
      }, reconnectTimeout: 3);
      await tester.pump();
      final reconnect = _messageButton(tester, 'Reconnect (3s)');
      final unrelated = manager.show<void>(
          (_, __, ___) => const Text('unrelated'),
          tag: 'unrelated');
      reconnect();
      reconnect();
      await tester.pump();
      expect(reconnects, 1);
      expect(manager.existing('unrelated'), isTrue);
      expect(find.text('unrelated'), findsOneWidget);
      manager.dismissByTag('unrelated');
      await unrelated;
    } finally {
      manager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

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

import 'dart:async';

import 'package:back_button_interceptor/back_button_interceptor.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/mobile_connection_navigation.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_test/flutter_test.dart';

class _TestDialog extends StatelessWidget {
  const _TestDialog(this.label);

  final String label;

  @override
  Widget build(BuildContext context) => Text(label);
}

Future<void> _closeWhilePlatformReplyIsPending(WidgetTester tester,
    {required bool failReply, required bool ownedRoute}) async {
  final navigatorKey = GlobalKey<NavigatorState>();
  final reply = Completer<void>();
  var requests = 0;
  final messenger = tester.binding.defaultBinaryMessenger;
  messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
    if (call.method == 'SystemChrome.setEnabledSystemUIOverlays') {
      requests++;
      expect(
        call.arguments,
        SystemUiOverlay.values.map((overlay) => overlay.toString()).toList(),
      );
      await reply.future;
    }
    return null;
  });
  addTearDown(() {
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
  });
  try {
    await tester.pumpWidget(MaterialApp(
      navigatorKey: navigatorKey,
      home: const Text('home'),
    ));
    final navigator = navigatorKey.currentState!;
    final oldRoute = MaterialPageRoute<void>(
      builder: (_) => const Text('old connection'),
    );
    unawaited(navigator.push(oldRoute));
    await tester.pumpAndSettle();
    expect(find.text('old connection'), findsOneWidget);

    if (ownedRoute) {
      final view = MobileConnectionView();
      expect(
          view.bind(oldRoute,
              isCurrentSession: () => true, onClosed: (_) {}),
          isNotNull);
      view.closeCallback()();
    } else {
      closeMobileConnectionRoute(navigator);
    }
    await tester.pumpAndSettle();
    expect(requests, 1);
    expect(reply.isCompleted, isFalse);
    expect(find.text('old connection'), findsNothing);
    expect(find.text('home'), findsOneWidget);

    final replacement = MaterialPageRoute<void>(
      builder: (_) => const Text('replacement connection'),
    );
    unawaited(navigator.push(replacement));
    await tester.pumpAndSettle();
    if (failReply) {
      reply.completeError(PlatformException(code: 'restoration-refused'));
    } else {
      reply.complete();
    }
    await tester.pumpAndSettle();
    expect(replacement.isCurrent, isTrue);
    expect(find.text('replacement connection'), findsOneWidget);
    expect(tester.takeException(), isNull);
  } finally {
    if (!reply.isCompleted) reply.complete();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();
  }
}

Future<NavigatorState> _mobileNavigator(WidgetTester tester) async {
  final key = GlobalKey<NavigatorState>();
  final messenger = tester.binding.defaultBinaryMessenger;
  messenger.setMockMethodCallHandler(SystemChannels.platform, (_) async => null);
  addTearDown(() {
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
  });
  await tester.pumpWidget(MaterialApp(
    navigatorKey: key,
    home: const Text('home'),
  ));
  return key.currentState!;
}

Future<MaterialPageRoute<void>> _pushMobileRoute(
    WidgetTester tester, NavigatorState navigator, String label) async {
  final route = MaterialPageRoute<void>(builder: (_) => Text(label));
  unawaited(navigator.push(route));
  await tester.pumpAndSettle();
  return route;
}

void main() {
  testWidgets('mobile close precedes a held system UI reply', (tester) async {
    for (final owned in [false, true]) {
      await _closeWhilePlatformReplyIsPending(tester,
          failReply: false, ownedRoute: owned);
    }
  });

  testWidgets('failed system UI reply cannot close a replacement route',
      (tester) async {
    for (final owned in [false, true]) {
      await _closeWhilePlatformReplyIsPending(tester,
          failReply: true, ownedRoute: owned);
    }
  });

  testWidgets('mobile terminal close owns one route and completes once',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    await _pushMobileRoute(tester, navigator, 'previous page');
    final route = await _pushMobileRoute(tester, navigator, 'terminal');
    final view = MobileConnectionView();
    final closed = <bool>[];
    final owner = view.bind(route,
        isCurrentSession: () => true, onClosed: closed.add)!;
    var completed = false;
    unawaited(route.popped.then<void>((_) {
      completed = true;
    }));
    final close = view.closeCallback();
    close();
    close();
    expect(owner.isCurrent, isFalse);
    await tester.pumpAndSettle();
    expect(completed, isTrue);
    expect(closed, [false]);
    expect(find.text('previous page'), findsOneWidget);
    expect(find.text('terminal'), findsNothing);
  });

  testWidgets('retired mobile terminal callback cannot close a replacement route',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    final oldRoute = await _pushMobileRoute(tester, navigator, 'old terminal');
    final oldElement = tester.element(find.text('old terminal'));
    final view = MobileConnectionView();
    final oldOwner = view.bind(oldRoute,
        isCurrentSession: () => true, onClosed: (_) {})!;
    final oldClose = view.closeCallback();
    final replacement = MaterialPageRoute<void>(
        builder: (_) => const Text('replacement terminal'));
    unawaited(navigator.pushReplacement(replacement));
    final current = view.bind(replacement,
        isCurrentSession: () => true, onClosed: (_) {})!;
    expect(oldElement.mounted, isTrue);
    oldClose();
    view.unbind(oldOwner);
    expect(current.isCurrent, isTrue);
    await tester.pumpAndSettle();
    expect(find.text('replacement terminal'), findsOneWidget);
    view.closeCallback()();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('hidden mobile terminal callback cannot pop a different route',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    final route = await _pushMobileRoute(tester, navigator, 'terminal');
    final view = MobileConnectionView();
    view.bind(route, isCurrentSession: () => true, onClosed: (_) {});
    final close = view.closeCallback();
    final different = await _pushMobileRoute(tester, navigator, 'different');
    close();
    expect(different.isCurrent, isTrue);
    await tester.pumpAndSettle();
    expect(find.text('different'), findsOneWidget);
    navigator.pop();
    await tester.pumpAndSettle();
    close();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('mobile terminal session replacement revokes captured close',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    final route = await _pushMobileRoute(tester, navigator, 'terminal');
    final view = MobileConnectionView();
    var session = Object();
    final oldSession = session;
    view.bind(route,
        isCurrentSession: () => identical(session, oldSession),
        onClosed: (_) {});
    final oldClose = view.closeCallback();
    session = Object();
    oldClose();
    expect(route.isCurrent, isTrue);
    final currentSession = session;
    view.bind(route,
        isCurrentSession: () => identical(session, currentSession),
        onClosed: (_) {});
    oldClose();
    expect(route.isCurrent, isTrue);
    view.closeCallback()();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('mobile terminal route rejects foreign and unbound callbacks',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    final route = await _pushMobileRoute(tester, navigator, 'terminal');
    final view = MobileConnectionView();
    final unbound = view.closeCallback();
    final other = MobileConnectionView();
    final foreign = other.bind(route,
        isCurrentSession: () => true, onClosed: (_) {})!;
    view.closeCallback(route: foreign)();
    view.unbind(foreign);
    expect(foreign.isCurrent, isTrue);
    other.unbind(foreign);
    view.bind(route, isCurrentSession: () => true, onClosed: (_) {});
    unbound();
    expect(route.isCurrent, isTrue);
    view.closeCallback()();
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('mobile terminal close drains local route history only',
      (tester) async {
    final navigator = await _mobileNavigator(tester);
    final route = await _pushMobileRoute(tester, navigator, 'terminal');
    final removed = <int>[];
    route.addLocalHistoryEntry(LocalHistoryEntry(onRemove: () => removed.add(1)));
    route.addLocalHistoryEntry(LocalHistoryEntry(onRemove: () => removed.add(2)));
    final view = MobileConnectionView();
    final closed = <bool>[];
    view.bind(route, isCurrentSession: () => true, onClosed: closed.add);
    view.closeCallback()();
    await tester.pumpAndSettle();
    expect(removed, [2, 1]);
    expect(closed, [true]);
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets(
      'blockable overlay keeps one mounted owner and rebuilds its underlying route',
      (tester) async {
    final overlayState = BlockableOverlayState();
    final routeKey = GlobalKey<ScaffoldState>();
    late StateSetter rebuild;
    var label = 'first';
    var expandedLayout = false;
    var routeTaps = 0;
    var blockerTaps = 0;
    overlayState.onMiddleBlockedClick = () {
      blockerTaps++;
      overlayState.setMiddleBlocked(false);
    };

    await tester.pumpWidget(MaterialApp(
      home: StatefulBuilder(builder: (context, setState) {
        rebuild = setState;
        final overlay = BlockableOverlay(
          state: overlayState,
          underlying: Scaffold(
            key: routeKey,
            body: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: () => routeTaps++,
              child: Center(child: Text(label)),
            ),
            bottomNavigationBar: const SizedBox(
              key: ValueKey('bottom-bar'),
              height: 56,
            ),
          ),
        );
        return expandedLayout
            ? SizedBox.expand(child: overlay)
            : Center(child: overlay);
      }),
    ));

    final firstOwner = overlayState.key!.currentState;
    final firstRoute = routeKey.currentState;
    expect(firstOwner, isNotNull);
    expect(firstRoute, isNotNull);
    expect(find.text('first'), findsOneWidget);
    expect(tester.getSize(find.byKey(const ValueKey('bottom-bar'))).height, 56);

    final inserted = OverlayEntry(
      builder: (_) => const Positioned(
        left: 8,
        top: 8,
        child: Text('inserted'),
      ),
    );
    firstOwner!.insert(inserted);
    await tester.pump();
    expect(find.text('inserted'), findsOneWidget);

    rebuild(() => label = 'second');
    await tester.pump();

    expect(overlayState.key!.currentState, same(firstOwner));
    expect(find.text('first'), findsNothing);
    expect(find.text('second'), findsOneWidget);
    expect(find.text('inserted'), findsOneWidget);
    expect(tester.getSize(find.byKey(const ValueKey('bottom-bar'))).height, 56);

    for (var move = 1; move <= 6; move++) {
      rebuild(() {
        expandedLayout = !expandedLayout;
        label = 'route $move';
      });
      await tester.pump();

      expect(tester.takeException(), isNull);
      expect(overlayState.key!.currentState, same(firstOwner));
      expect(routeKey.currentState, same(firstRoute));
      expect(find.text(label), findsOneWidget);
      expect(find.text('inserted'), findsOneWidget);
      expect(inserted.mounted, isTrue);
      expect(
          tester.getSize(find.byKey(const ValueKey('bottom-bar'))).height, 56);

      overlayState.setMiddleBlocked(true);
      await tester.pump();
      await tester.tap(find.text(label));
      await tester.pump();
      expect(blockerTaps, move);
      expect(routeTaps, move - 1);

      await tester.tap(find.text(label));
      await tester.pump();
      expect(routeTaps, move);
    }

    inserted
      ..remove()
      ..dispose();
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
    expect(firstOwner!.mounted, isFalse);
    expect(firstRoute!.mounted, isFalse);
    expect(inserted.mounted, isFalse);
    expect(overlayState.key!.currentState, isNull);
  });

  testWidgets('middle blocker owns the tap before revealing the route',
      (tester) async {
    final overlayState = BlockableOverlayState();
    var routeTaps = 0;
    var blockerTaps = 0;
    overlayState.onMiddleBlockedClick = () {
      blockerTaps++;
      overlayState.setMiddleBlocked(false);
    };

    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(
        state: overlayState,
        underlying: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: () => routeTaps++,
          child: const SizedBox.expand(),
        ),
      ),
    ));

    overlayState.setMiddleBlocked(true);
    await tester.pump();
    await tester.tapAt(const Offset(200, 200));
    await tester.pump();

    expect(blockerTaps, 1);
    expect(routeTaps, 0);
    expect(overlayState.middleBlocked.value, isFalse);

    await tester.tapAt(const Offset(200, 200));
    await tester.pump();
    expect(blockerTaps, 1);
    expect(routeTaps, 1);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('one explicit dialog tag owns one disposable overlay entry',
      (tester) async {
    final overlayState = BlockableOverlayState();
    final manager = OverlayDialogManager();
    manager.setOverlayState(overlayState);
    late DialogClose closeFirst;
    final originalPopRoute = BackButtonInterceptor.handlePopRouteFunction;
    var defaultBackEvents = 0;
    BackButtonInterceptor.handlePopRouteFunction = () async {
      defaultBackEvents++;
    };
    addTearDown(() {
      BackButtonInterceptor.handlePopRouteFunction = originalPopRoute;
    });

    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(
        state: overlayState,
        underlying: const SizedBox.expand(),
      ),
    ));

    final first = manager.show<String>(
      (_, close, ___) {
        closeFirst = close;
        return const _TestDialog('first dialog');
      },
      tag: 'connection-state',
    );
    await tester.pump();
    expect(find.text('first dialog'), findsOneWidget);
    expect(closeFirst.isCurrent, isTrue);

    final replacement = manager.show<String>(
      (_, __, ___) => const _TestDialog('replacement dialog'),
      tag: 'connection-state',
    );
    expect(closeFirst.isCurrent, isFalse);
    expect(closeFirst('stale completion'), isFalse);
    await tester.pump();

    expect(await first, isNull);
    expect(find.text('first dialog'), findsNothing);
    expect(find.text('replacement dialog'), findsOneWidget);

    expect(closeFirst('stale completion'), isFalse);
    await tester.pump();
    final replacementStillOwned = manager.existing('connection-state');

    manager.dismissByTag('connection-state');
    await tester.pump();
    final replacementRemoved =
        find.text('replacement dialog').evaluate().isEmpty;

    final otherManager = OverlayDialogManager();
    otherManager.setOverlayState(overlayState);
    final local = manager.show<String>(
      (_, __, ___) => const _TestDialog('local dialog'),
      tag: 'shared-tag',
      backDismiss: true,
    );
    final independent = otherManager.show<String>(
      (_, __, ___) => const _TestDialog('independent dialog'),
      tag: 'shared-tag',
      backDismiss: true,
    );
    await tester.pump();
    manager.dismissAll();
    await tester.pump();
    expect(await local, isNull);
    expect(find.text('independent dialog'), findsOneWidget);

    await BackButtonInterceptor.popRoute();
    await tester.pump();
    final independentBackDismissed = !otherManager.existing('shared-tag') &&
        find.text('independent dialog').evaluate().isEmpty;
    otherManager.dismissAll();
    await tester.pump();
    expect(await independent, isNull);

    manager.dismissByTag('connection-state');
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
    expect(
      <String, Object>{
        'replacement still owned after stale close': replacementStillOwned,
        'replacement removed by its owner': replacementRemoved,
        'independent back handler survived': independentBackDismissed,
        'default back events': defaultBackEvents,
      },
      <String, Object>{
        'replacement still owned after stale close': true,
        'replacement removed by its owner': true,
        'independent back handler survived': true,
        'default back events': 0,
      },
    );
    expect(await replacement, isNull);
  });
}

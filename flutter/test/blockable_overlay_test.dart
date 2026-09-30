import 'package:flutter_hbb/common.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_test/flutter_test.dart';

class _TestDialog extends StatelessWidget {
  const _TestDialog(this.label);

  final String label;

  @override
  Widget build(BuildContext context) => Text(label);
}

void main() {
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

    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(
        state: overlayState,
        underlying: const SizedBox.expand(),
      ),
    ));

    final first = manager.show<String>(
      (_, __, ___) => const _TestDialog('first dialog'),
      tag: 'connection-state',
    );
    await tester.pump();
    expect(find.text('first dialog'), findsOneWidget);

    final replacement = manager.show<String>(
      (_, __, ___) => const _TestDialog('replacement dialog'),
      tag: 'connection-state',
    );
    await tester.pump();

    expect(await first, isNull);
    expect(find.text('first dialog'), findsNothing);
    expect(find.text('replacement dialog'), findsOneWidget);

    manager.dismissByTag('connection-state');
    await tester.pump();
    expect(await replacement, isNull);
    expect(find.text('replacement dialog'), findsNothing);

    manager.dismissByTag('connection-state');
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
  });
}

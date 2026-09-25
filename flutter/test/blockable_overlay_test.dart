import 'package:flutter_hbb/common.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets(
      'blockable overlay keeps one mounted owner and rebuilds its underlying route',
      (tester) async {
    final overlayState = BlockableOverlayState();
    late StateSetter rebuild;
    var label = 'first';

    await tester.pumpWidget(MaterialApp(
      home: StatefulBuilder(builder: (context, setState) {
        rebuild = setState;
        return BlockableOverlay(
          state: overlayState,
          underlying: Scaffold(
            body: Center(child: Text(label)),
            bottomNavigationBar: const SizedBox(
              key: ValueKey('bottom-bar'),
              height: 56,
            ),
          ),
        );
      }),
    ));

    final firstOwner = overlayState.key!.currentState;
    expect(firstOwner, isNotNull);
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

    inserted
      ..remove()
      ..dispose();
    await tester.pumpWidget(const SizedBox.shrink());
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
      (_, __, ___) => const CustomAlertDialog(
        content: Text('first dialog'),
      ),
      tag: 'connection-state',
    );
    await tester.pump();
    expect(find.text('first dialog'), findsOneWidget);

    final replacement = manager.show<String>(
      (_, __, ___) => const CustomAlertDialog(
        content: Text('replacement dialog'),
      ),
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

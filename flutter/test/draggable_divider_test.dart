import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/widgets/dragable_divider.dart';
import 'package:flutter_test/flutter_test.dart';

const _divider = ValueKey('divider');
const _pane = ValueKey('pane');

Widget _subject(ValueChanged<double>? onMove,
    {Axis axis = Axis.vertical, VoidCallback? onHover}) {
  var extent = 100.0;
  return MaterialApp(
    home: Scaffold(
      body: Center(
        child: StatefulBuilder(builder: (context, setState) {
          return SizedBox(
            width: 400,
            height: 400,
            child: Flex(
              direction: axis == Axis.vertical ? Axis.horizontal : Axis.vertical,
              children: [
                SizedBox(key: _pane, width: extent, height: extent),
                DraggableDivider(
                  key: _divider,
                  axis: axis,
                  thickness: 2,
                  padding: const EdgeInsets.all(8),
                  onHover: onHover,
                  onPointerMove: onMove == null
                      ? null
                      : (delta) {
                          setState(() => extent += delta);
                          onMove(delta);
                        },
                ),
                const Expanded(child: SizedBox()),
              ],
            ),
          );
        }),
      ),
    ),
  );
}

void main() {
  testWidgets('divider primary mouse drag resizes columns by exact distance',
      (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    final pointer = await tester.startGesture(
      tester.getCenter(find.byKey(_divider)),
      kind: PointerDeviceKind.mouse,
    );
    await pointer.moveBy(const Offset(24, 9));
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).width, 124);
    await pointer.moveBy(const Offset(-7, -5));
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).width, 117);
    expect(moves.fold(0.0, (sum, delta) => sum + delta), 17);
    await pointer.up();
    await pointer.removePointer();
  });

  testWidgets('divider secondary and middle drags leave columns unchanged',
      (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    for (final buttons in [
      kSecondaryMouseButton,
      kMiddleMouseButton,
      kPrimaryMouseButton | kSecondaryMouseButton,
    ]) {
      final pointer = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)),
        kind: PointerDeviceKind.mouse,
        buttons: buttons,
      );
      await pointer.moveBy(const Offset(30, 0));
      await pointer.up();
      await pointer.removePointer();
      await tester.pump();
      expect(moves, isEmpty, reason: 'buttons=$buttons');
      expect(tester.getSize(find.byKey(_pane)).width, 100);
    }
  });

  testWidgets('divider touch drag preserves axis distance', (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add, axis: Axis.horizontal));
    final pointer = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await pointer.moveBy(const Offset(11, 30));
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).height, 130);
    await pointer.moveBy(const Offset(-8, -10));
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).height, 120);
    expect(moves.fold(0.0, (sum, delta) => sum + delta), 20);
    await pointer.up();
  });

  testWidgets('divider hover chooses axis cursor without resizing',
      (tester) async {
    final moves = <double>[];
    var hovers = 0;
    final pointer = await tester.createGesture(
        kind: PointerDeviceKind.mouse);
    await pointer.addPointer(location: Offset.zero);
    for (final axis in Axis.values) {
      await tester.pumpWidget(
          _subject(moves.add, axis: axis, onHover: () => hovers++));
      await pointer.moveTo(tester.getCenter(find.byKey(_divider)));
      await tester.pump();
      expect(tester.binding.mouseTracker.debugDeviceActiveCursor(1),
          axis == Axis.vertical
              ? SystemMouseCursors.resizeLeftRight
              : SystemMouseCursors.resizeUpDown);
      await pointer.moveTo(Offset.zero);
    }
    expect(hovers, greaterThanOrEqualTo(2));
    expect(moves, isEmpty);
    await pointer.removePointer();
  });

  testWidgets('divider disabled state neither resizes nor advertises resizing',
      (tester) async {
    await tester.pumpWidget(_subject(null));
    final pointer = await tester.createGesture(
        kind: PointerDeviceKind.mouse);
    await pointer.addPointer(location: tester.getCenter(find.byKey(_divider)));
    await tester.pump();
    expect(tester.binding.mouseTracker.debugDeviceActiveCursor(1),
        SystemMouseCursors.basic);
    await pointer.down(tester.getCenter(find.byKey(_divider)));
    await pointer.moveBy(const Offset(30, 0));
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).width, 100);
    await pointer.up();
    await pointer.removePointer();
  });

  testWidgets('divider disabling an active drag requires a fresh pointer',
      (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    final pointer = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await pointer.moveBy(const Offset(30, 0));
    await tester.pump();
    expect(moves, isNotEmpty);
    await tester.pumpWidget(_subject(null));
    await pointer.moveBy(const Offset(30, 0));
    await tester.pumpWidget(_subject(moves.add));
    moves.clear();
    await pointer.moveBy(const Offset(30, 0));
    await tester.pump();
    expect(moves, isEmpty);
    await pointer.up();
    final fresh = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await fresh.moveBy(const Offset(30, 0));
    await fresh.up();
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).width, 130);
  });

  testWidgets('divider cancelled drag releases input for the next drag',
      (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    final pointer = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await pointer.moveBy(const Offset(30, 0));
    await tester.pump();
    await pointer.cancel();
    final fresh = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await fresh.moveBy(const Offset(-20, 0));
    await fresh.up();
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).width, 110);
    expect(moves.fold(0.0, (sum, delta) => sum + delta), 10);
  });

  testWidgets('divider trackpad scrolling leaves columns unchanged',
      (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    final start = tester.getCenter(find.byKey(_divider));
    final pointer = await tester.startGesture(start,
        kind: PointerDeviceKind.trackpad);
    await pointer.panZoomUpdate(start, pan: const Offset(30, 0));
    await pointer.panZoomEnd();
    await tester.pump();
    expect(moves, isEmpty);
    expect(tester.getSize(find.byKey(_pane)).width, 100);
  });

  testWidgets('divider axis change retires an active drag', (tester) async {
    final moves = <double>[];
    await tester.pumpWidget(_subject(moves.add));
    final pointer = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await pointer.moveBy(const Offset(30, 0));
    await tester.pump();
    await tester.pumpWidget(_subject(moves.add, axis: Axis.horizontal));
    moves.clear();
    await pointer.moveBy(const Offset(0, 30));
    await tester.pump();
    expect(moves, isEmpty);
    await pointer.up();
    final fresh = await tester.startGesture(
        tester.getCenter(find.byKey(_divider)));
    await fresh.moveBy(const Offset(0, 30));
    await fresh.up();
    await tester.pump();
    expect(tester.getSize(find.byKey(_pane)).height, 130);
  });
}

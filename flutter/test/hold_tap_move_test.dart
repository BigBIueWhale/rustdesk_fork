import 'package:flutter/gestures.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common/widgets/gestures.dart';
import 'package:flutter_test/flutter_test.dart';

class _OtherRecognizer implements GestureArenaMember {
  int accepted = 0;
  int rejected = 0;
  @override
  void acceptGesture(int pointer) { accepted++; }
  @override
  void rejectGesture(int pointer) { rejected++; }
}

class _Fixture {
  _Fixture({this.withDoubleTap = false, this.withEnd = true});
  final bool withDoubleTap;
  final bool withEnd;
  final starts = <DragStartDetails>[];
  final downs = <DragDownDetails>[];
  final updates = <DragUpdateDetails>[];
  final ends = <DragEndDetails>[];
  final events = <String>[];
  final live = <TestGesture>{};
  final competitors = <_OtherRecognizer>[];
  final entries = <int, List<GestureArenaEntry>>{};
  int cancellations = 0;
  int doubleTaps = 0;

  int get fallbackAccepts => competitors.fold(0, (n, r) => n + r.accepted);
  int get fallbackRejects => competitors.fold(0, (n, r) => n + r.rejected);

  Future<void> mount(WidgetTester tester, Offset offset) =>
      tester.pumpWidget(Directionality(
    textDirection: TextDirection.ltr,
    child: Transform.translate(
      offset: offset,
      child: Listener(
        onPointerDown: (event) {
          entries[event.pointer] = List.generate(2, (_) {
            final other = _OtherRecognizer();
            competitors.add(other);
            return GestureBinding.instance.gestureArena.add(event.pointer, other);
          });
        },
        child: RawGestureDetector(
          behavior: HitTestBehavior.opaque,
          gestures: {
            if (withDoubleTap)
              DoubleTapGestureRecognizer: GestureRecognizerFactoryWithHandlers<
                  DoubleTapGestureRecognizer>(
                () => DoubleTapGestureRecognizer(
                    supportedDevices: {PointerDeviceKind.touch}),
                (instance) { instance.onDoubleTap = () { doubleTaps++; }; },
              ),
            HoldTapMoveGestureRecognizer: GestureRecognizerFactoryWithHandlers<
                HoldTapMoveGestureRecognizer>(
              () => HoldTapMoveGestureRecognizer(
                  supportedDevices: {PointerDeviceKind.touch}),
              (instance) {
                instance
                  ..onHoldDragDown = (d) { downs.add(d); events.add('down'); }
                  ..onHoldDragStart = (d) { starts.add(d); events.add('start'); }
                  ..onHoldDragUpdate = (d) { updates.add(d); events.add('update'); }
                  ..onHoldDragCancel = () { cancellations++; events.add('cancel'); }
                  ..onHoldDragEnd = withEnd
                      ? (d) { ends.add(d); events.add('end'); } : null;
              },
            ),
          },
          child: const SizedBox.expand(),
        ),
      ),
    ),
  ));

  Future<TestGesture> down(WidgetTester tester, int pointer,
      [Offset position = const Offset(80, 80)]) async {
    final gesture = await tester.startGesture(position,
        pointer: pointer, kind: PointerDeviceKind.touch);
    live.add(gesture);
    return gesture;
  }

  Future<void> up(TestGesture gesture) async {
    await gesture.up();
    live.remove(gesture);
  }

  Future<void> cancel(TestGesture gesture) async {
    await gesture.cancel();
    live.remove(gesture);
  }

  Future<TestGesture> second(WidgetTester tester, int pointer) async {
    final first = await down(tester, pointer);
    await up(first);
    await tester.pump(kDoubleTapMinTime + const Duration(milliseconds: 1));
    return down(tester, pointer + 1);
  }

  Future<TestGesture> activate(WidgetTester tester, int pointer) async {
    final gesture = await second(tester, pointer);
    await tester.pump(kDoubleTapTimeout);
    return gesture;
  }

  Future<void> complete(WidgetTester tester, int pointer) async {
    final gesture = await activate(tester, pointer);
    await up(gesture);
  }

  Future<void> close(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    for (final gesture in live.toList()) { await up(gesture); }
    // Retire only the fixture's participants after recording product behavior.
    for (final item in entries.entries) {
      for (final entry in item.value) { entry.resolve(GestureDisposition.rejected); }
      GestureBinding.instance.gestureArena.release(item.key);
    }
    await tester.pump(const Duration(seconds: 1));
  }
}

Future<void> _run(WidgetTester tester,
    Future<void> Function(_Fixture) body, {
      bool withDoubleTap = false, bool withEnd = true,
      Offset offset = Offset.zero,
    }) async {
  final fixture = _Fixture(withDoubleTap: withDoubleTap, withEnd: withEnd);
  await fixture.mount(tester, offset);
  try { await body(fixture); }
  finally { await fixture.close(tester); }
}

void main() {
  testWidgets('hold drag accepts tap hold movement and release',
      (tester) => _run(tester, (f) async {
    final gesture = await f.activate(tester, 1);
    await gesture.moveBy(const Offset(30, 0));
    await f.up(gesture);
    expect(f.starts, hasLength(1));
    expect(f.updates, hasLength(1));
    expect(f.ends, hasLength(1));
    expect(f.events.take(4), ['down', 'start', 'update', 'end']);
  }));

  testWidgets('hold drag quick second release cannot end or start a drag',
      (tester) => _run(tester, (f) async {
    final gesture = await f.second(tester, 1);
    await f.up(gesture);
    await tester.pump(kDoubleTapTimeout);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
    expect(f.fallbackAccepts, 2);
  }));

  testWidgets('hold drag movement admission resolves both exact arenas',
      (tester) => _run(tester, (f) async {
    final gesture = await f.second(tester, 1);
    await gesture.moveBy(const Offset(40, 0));
    expect(f.starts, hasLength(1));
    expect(f.fallbackRejects, 4);
    expect(f.fallbackAccepts, 0);
    await f.up(gesture);
    expect(f.ends, hasLength(1));
  }));

  testWidgets('hold drag repeated completion leaves no earlier arena owners',
      (tester) => _run(tester, (f) async {
    for (var i = 0; i < 20; i++) { await f.complete(tester, 1 + i * 2); }
    expect(f.starts, hasLength(20));
    expect(f.ends, hasLength(20));
    expect(f.fallbackRejects, 80);
    expect(f.fallbackAccepts, 0);
  }));

  testWidgets('hold drag active movement can return inside initial tolerance',
      (tester) => _run(tester, (f) async {
    final gesture = await f.second(tester, 1);
    await gesture.moveTo(const Offset(120, 80));
    await gesture.moveTo(const Offset(90, 80));
    await gesture.moveTo(const Offset(80, 80));
    expect(f.starts, hasLength(1));
    expect(f.updates, hasLength(3));
    expect(f.updates.last.delta, const Offset(-10, 0));
    await f.up(gesture);
  }));

  testWidgets('hold drag active cancellation ends once and permits retry',
      (tester) => _run(tester, (f) async {
    final gesture = await f.activate(tester, 1);
    await f.cancel(gesture);
    expect(f.ends, hasLength(1));
    await f.complete(tester, 3);
    expect(f.starts, hasLength(2));
    expect(f.ends, hasLength(2));
  }));

  testWidgets('hold drag active disposal ends once without late start',
      (tester) => _run(tester, (f) async {
    final gesture = await f.activate(tester, 1);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(f.ends, hasLength(1));
    await tester.pump(kDoubleTapTimeout);
    expect(f.starts, hasLength(1));
    expect(f.ends, hasLength(1));
    await f.up(gesture);
  }));

  testWidgets('hold drag pending cancellation releases the first tap hold',
      (tester) => _run(tester, (f) async {
    final gesture = await f.second(tester, 1);
    await f.cancel(gesture);
    await tester.pump(kDoubleTapTimeout);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
    expect(f.cancellations, 1);
    // PointerCancel has no automatic arena sweep; the first tap's Up does.
    expect(f.fallbackAccepts, 1);
  }));

  testWidgets('hold drag state retires when the end callback is absent',
      (tester) => _run(tester, (f) async {
    await f.complete(tester, 1);
    await f.complete(tester, 3);
    expect(f.starts, hasLength(2));
    expect(f.fallbackRejects, 8);
  }, withEnd: false));

  testWidgets('hold drag refuses a first tap that moved beyond tolerance',
      (tester) => _run(tester, (f) async {
    final first = await f.down(tester, 1);
    await first.moveBy(const Offset(200, 0));
    await f.up(first);
    await tester.pump(kDoubleTapMinTime + const Duration(milliseconds: 1));
    final second = await f.down(tester, 2);
    await tester.pump(kDoubleTapTimeout);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
    await f.up(second);
    await tester.pump(kDoubleTapTimeout);
    await f.complete(tester, 3);
    expect(f.starts, hasLength(1));
    expect(f.ends, hasLength(1));
  }));

  testWidgets('hold drag preserves the real quick double tap recognizer',
      (tester) => _run(tester, (f) async {
    final gesture = await f.second(tester, 1);
    await f.up(gesture);
    await tester.pump(kDoubleTapTimeout);
    expect(f.doubleTaps, 1);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
  }, withDoubleTap: true));

  testWidgets('hold drag extra pointer retires the pending sequence',
      (tester) => _run(tester, (f) async {
    final second = await f.second(tester, 1);
    final third = await f.down(tester, 3);
    await f.up(second);
    await f.up(third);
    await tester.pump(kDoubleTapTimeout);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
    expect(f.fallbackAccepts, 3);
    await f.complete(tester, 4);
    expect(f.starts, hasLength(1));
    expect(f.ends, hasLength(1));
  }));

  testWidgets('hold drag start retains device and transformed coordinates',
      (tester) => _run(tester, (f) async {
    final gesture = await f.activate(tester, 1);
    expect(f.starts, hasLength(1));
    expect(f.starts.single.kind, PointerDeviceKind.touch);
    expect(f.starts.single.globalPosition, const Offset(80, 80));
    expect(f.starts.single.localPosition, const Offset(50, 60));
    await f.up(gesture);
  }, offset: const Offset(30, 20)));

  testWidgets('hold drag first tap timeout releases fallback and permits retry',
      (tester) => _run(tester, (f) async {
    final first = await f.down(tester, 1);
    await f.up(first);
    await tester.pump(kDoubleTapTimeout);
    expect(f.fallbackAccepts, 1);
    expect(f.starts, isEmpty);
    expect(f.ends, isEmpty);
    await f.complete(tester, 2);
    expect(f.starts, hasLength(1));
    expect(f.ends, hasLength(1));
  }));
}

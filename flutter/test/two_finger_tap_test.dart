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
  late DoubleFinerTapGestureRecognizer recognizer;
  final taps = <TapDownDetails>[];
  final downs = <TapDownDetails>[];
  int cancellations = 0;
  final competitors = <_OtherRecognizer>[];
  final entries = <int, List<GestureArenaEntry>>{};

  int get fallbackAccepts => competitors.fold(0, (n, r) => n + r.accepted);

  Future<void> mount(WidgetTester tester) => tester.pumpWidget(Directionality(
    textDirection: TextDirection.ltr,
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
          DoubleFinerTapGestureRecognizer: GestureRecognizerFactoryWithHandlers<
              DoubleFinerTapGestureRecognizer>(
            () => DoubleFinerTapGestureRecognizer(
                supportedDevices: {PointerDeviceKind.touch}),
            (instance) {
              recognizer = instance;
              instance
                ..onDoubleFinerTap = taps.add
                ..onDoubleFinerTapDown = downs.add
                ..onDoubleFinerTapCancel = () { cancellations++; };
            },
          ),
        },
        child: const SizedBox.expand(),
      ),
    ),
  ));

  Future<TestGesture> down(WidgetTester tester, int pointer,
      [Offset position = const Offset(40, 40)]) => tester.startGesture(
        position, pointer: pointer, kind: PointerDeviceKind.touch);

  Future<void> pair(WidgetTester tester, int first) async {
    final a = await down(tester, first);
    final b = await down(tester, first + 1, const Offset(80, 40));
    await a.up();
    await b.up();
    await tester.pump(kDoubleTapTimeout);
  }

  Future<void> close(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    // Retire the test's exact arena participants even when the old product leaks a hold.
    for (final item in entries.entries) {
      for (final entry in item.value) { entry.resolve(GestureDisposition.rejected); }
      GestureBinding.instance.gestureArena.release(item.key);
    }
    await tester.pump(const Duration(seconds: 1));
  }
}

Future<void> _run(WidgetTester tester,
    Future<void> Function(_Fixture) body) async {
  final fixture = _Fixture();
  await fixture.mount(tester);
  try { await body(fixture); }
  finally { await fixture.close(tester); }
}

void main() {
  testWidgets('two finger tap accepts one complete overlapping pair', (tester) =>
    _run(tester, (f) async {
      await f.pair(tester, 1);
      expect(f.downs, hasLength(1));
      expect(f.downs.single.localPosition, const Offset(80, 40));
      expect(f.taps, hasLength(1));
      expect(f.taps.single.kind, PointerDeviceKind.touch);
      expect(f.cancellations, 0);
      expect(f.fallbackAccepts, 0);
    }));

  testWidgets('two finger tap supports repeated completed sequences', (tester) =>
    _run(tester, (f) async {
      for (var i = 0; i < 20; i++) { await f.pair(tester, 1 + i * 2); }
      expect(f.taps, hasLength(20));
      expect(f.downs, hasLength(20));
      expect(f.cancellations, 0);
      expect(f.fallbackAccepts, 0);
    }));

  testWidgets('two finger tap cancellation retires the old deadline before retry', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      final b = await f.down(tester, 2);
      await a.up();
      await b.cancel();
      await f.pair(tester, 3);
      expect(f.taps, hasLength(1));
      expect(f.cancellations, 1);
      expect(f.fallbackAccepts, 2);
    }));

  testWidgets('two finger tap arena rejection cancels the complete sequence', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      final b = await f.down(tester, 2);
      f.entries[1]!.first.resolve(GestureDisposition.accepted);
      await a.up();
      await b.up();
      await f.pair(tester, 3);
      expect(f.taps, hasLength(1));
      expect(f.cancellations, 1);
      expect(f.fallbackAccepts, 2);
    }));

  testWidgets('two finger tap single pointer timeout releases arena sweep', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      await a.up();
      await tester.pump(kDoubleTapTimeout);
      expect(f.taps, isEmpty);
      expect(f.fallbackAccepts, 1);
      await f.pair(tester, 2);
      expect(f.taps, hasLength(1));
    }));

  testWidgets('two finger tap disposal releases both exact arena holds', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      final b = await f.down(tester, 2);
      await tester.pumpWidget(const SizedBox.shrink());
      await a.up();
      await b.up();
      await tester.pump(kDoubleTapTimeout);
      expect(f.taps, isEmpty);
      expect(f.cancellations, 0);
      expect(f.fallbackAccepts, 2);
    }));

  testWidgets('two finger tap refuses a third held pointer', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      final b = await f.down(tester, 2);
      final c = await f.down(tester, 3);
      await a.up();
      await b.up();
      await tester.pump(kDoubleTapTimeout);
      final tapsWhileThirdIsHeld = f.taps.length;
      await c.up();
      expect(tapsWhileThirdIsHeld, 0);
      expect(f.cancellations, 1);
      expect(f.fallbackAccepts, 3);
    }));

  testWidgets('two finger tap refuses nonoverlapping single taps', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      await a.up();
      final b = await f.down(tester, 2);
      await b.up();
      await tester.pump(kDoubleTapTimeout);
      expect(f.taps, isEmpty);
      expect(f.downs, isEmpty);
      expect(f.fallbackAccepts, 2);
    }));

  testWidgets('two finger tap movement refusal permits a fresh complete pair', (tester) =>
    _run(tester, (f) async {
      final a = await f.down(tester, 1);
      final b = await f.down(tester, 2);
      await b.moveTo(const Offset(400, 250));
      await a.up();
      await b.up();
      await f.pair(tester, 3);
      expect(f.taps, hasLength(1));
      expect(f.cancellations, 1);
      expect(f.fallbackAccepts, 2);
    }));
}

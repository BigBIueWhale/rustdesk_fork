import 'package:flutter/gestures.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common/widgets/gestures.dart';
import 'package:flutter_test/flutter_test.dart';

class _Winner implements GestureArenaMember {
  int accepted = 0;
  @override
  void acceptGesture(int pointer) { accepted++; }
  @override
  void rejectGesture(int pointer) {}
}

class _Fixture {
  final events = <String>[];
  final violations = <String>[];
  final oneStarts = <DragStartDetails>[];
  final twoStarts = <ScaleStartDetails>[];
  final threeStarts = <DragStartDetails>[];
  final live = <TestGesture>{};
  final winner = _Winner();
  int? rejectPointer;
  String? active;

  void start(String kind) {
    if (active != null) { violations.add('$kind started while $active active'); }
    active = kind;
    events.add('$kind:start');
  }

  void update(String kind) {
    if (active != kind) { violations.add('$kind update while $active active'); }
    events.add('$kind:update');
  }

  void end(String kind) {
    if (active != kind) { violations.add('$kind end while $active active'); }
    active = null;
    events.add('$kind:end');
  }

  Future<void> mount(WidgetTester tester,
      [Offset offset = Offset.zero]) => tester.pumpWidget(Directionality(
    textDirection: TextDirection.ltr,
    child: Transform.translate(
      offset: offset,
      child: Listener(
        onPointerDown: (event) {
          if (event.pointer == rejectPointer) {
            GestureBinding.instance.gestureArena.add(event.pointer, winner)
                .resolve(GestureDisposition.accepted);
          }
        },
        child: RawGestureDetector(
          behavior: HitTestBehavior.opaque,
          gestures: {
            CustomTouchGestureRecognizer: GestureRecognizerFactoryWithHandlers<
                CustomTouchGestureRecognizer>(
              () => CustomTouchGestureRecognizer(
                  supportedDevices: {PointerDeviceKind.touch}),
              (instance) {
                instance
                  ..onOneFingerPanStart = (d) { oneStarts.add(d); start('one'); }
                  ..onOneFingerPanUpdate = (_) { update('one'); }
                  ..onOneFingerPanEnd = (_) { end('one'); }
                  ..onTwoFingerScaleStart = (d) { twoStarts.add(d); start('two'); }
                  ..onTwoFingerScaleUpdate = (_) { update('two'); }
                  ..onTwoFingerScaleEnd = (_) { end('two'); }
                  ..onThreeFingerVerticalDragStart = (d) {
                    threeStarts.add(d); start('three');
                  }
                  ..onThreeFingerVerticalDragUpdate = (_) { update('three'); }
                  ..onThreeFingerVerticalDragEnd = (_) { end('three'); };
              },
            ),
          },
          child: const SizedBox.expand(),
        ),
      ),
    ),
  ));

  Future<TestGesture> down(WidgetTester tester, int pointer,
      [Offset position = const Offset(100, 100)]) async {
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

  Future<void> pan(WidgetTester tester, int pointer) async {
    final a = await down(tester, pointer);
    await a.moveBy(const Offset(40, 15));
    await up(a);
  }

  Future<void> close(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    for (final gesture in live.toList()) { await up(gesture); }
    await tester.pump(const Duration(seconds: 1));
  }
}

Future<void> _run(WidgetTester tester,
    Future<void> Function(_Fixture) body, {Offset offset = Offset.zero}) async {
  final fixture = _Fixture();
  await fixture.mount(tester, offset);
  try { await body(fixture); }
  finally { await fixture.close(tester); }
}

void main() {
  testWidgets('custom touch one finger starts before updates and ends once',
      (tester) => _run(tester, (f) async {
    await f.pan(tester, 1);
    expect(f.oneStarts, hasLength(1));
    expect(f.events.first, 'one:start');
    expect(f.events.last, 'one:end');
    expect(f.events.where((e) => e == 'one:update'), isNotEmpty);
    expect(f.violations, isEmpty);
    expect(f.active, isNull);
  }));

  testWidgets('custom touch rapid successive pans each own a start',
      (tester) => _run(tester, (f) async {
    for (var i = 0; i < 20; i++) { await f.pan(tester, i + 1); }
    expect(f.oneStarts, hasLength(20));
    expect(f.events.where((e) => e == 'one:end'), hasLength(20));
    expect(f.violations, isEmpty);
  }));

  testWidgets('custom touch replacement scale pointers start a fresh phase',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    await a.moveBy(const Offset(40, 15));
    await f.up(b);
    final c = await f.down(tester, 3, const Offset(160, 100));
    await a.moveBy(const Offset(20, 10));
    await f.up(c);
    await f.up(a);
    expect(f.twoStarts, hasLength(2));
    expect(f.events.where((e) => e == 'two:end'), hasLength(2));
    expect(f.violations, isEmpty);
  }));

  testWidgets('custom touch scale to pan survives continuous movement',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    await a.moveBy(const Offset(40, 15));
    await f.up(b);
    for (var i = 0; i < 16; i++) {
      await a.moveBy(const Offset(2, 1));
      await tester.pump(const Duration(milliseconds: 16));
    }
    expect(f.oneStarts, hasLength(1));
    expect(f.active, 'one');
    expect(f.violations, isEmpty);
    await f.up(a);
  }));

  testWidgets('custom touch three to two survives continuous movement',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    final c = await f.down(tester, 3, const Offset(220, 100));
    await a.moveBy(const Offset(40, 15));
    await f.up(c);
    for (var i = 0; i < 16; i++) {
      await a.moveBy(const Offset(2, 1));
      await tester.pump(const Duration(milliseconds: 16));
    }
    expect(f.twoStarts, hasLength(1));
    expect(f.active, 'two');
    expect(f.violations, isEmpty);
    await f.up(b);
    await f.up(a);
  }));

  testWidgets('custom touch fourth pointer pauses recognized updates',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    final c = await f.down(tester, 3, const Offset(220, 100));
    await a.moveBy(const Offset(40, 15));
    final d = await f.down(tester, 4, const Offset(280, 100));
    final updates = f.events.where((e) => e.endsWith(':update')).length;
    await a.moveBy(const Offset(20, 10));
    expect(f.events.where((e) => e.endsWith(':update')), hasLength(updates));
    expect(f.active, isNull);
    await f.up(d);
    await a.moveBy(const Offset(20, 10));
    expect(f.active, 'three');
    expect(f.threeStarts, hasLength(2));
    expect(f.violations, isEmpty);
    await f.up(c);
    await f.up(b);
    await f.up(a);
  }));

  testWidgets('custom touch disposal cannot publish a deferred start',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    await a.moveBy(const Offset(40, 15));
    await f.up(b);
    await a.moveBy(const Offset(20, 10));
    await tester.pumpWidget(const SizedBox.shrink());
    final retiredEvents = f.events.length;
    await tester.pump(const Duration(milliseconds: 300));
    expect(f.events, hasLength(retiredEvents));
    expect(f.active, isNull);
    await f.up(a);
  }));

  testWidgets('custom touch cancellation permits an immediate fresh pan',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    await a.moveBy(const Offset(40, 15));
    await f.cancel(a);
    await f.pan(tester, 2);
    expect(f.oneStarts, hasLength(2));
    expect(f.events.where((e) => e == 'one:end'), hasLength(2));
    expect(f.violations, isEmpty);
  }));

  testWidgets('custom touch rejected extra pointer leaves a balanced usable pan',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    await a.moveBy(const Offset(40, 15));
    f.rejectPointer = 2;
    final b = await f.down(tester, 2, const Offset(160, 100));
    await a.moveBy(const Offset(20, 10));
    expect(f.winner.accepted, 1);
    expect(f.oneStarts, hasLength(2));
    expect(f.events.where((e) => e == 'one:end'), hasLength(1));
    expect(f.active, 'one');
    expect(f.violations, isEmpty);
    await f.up(b);
    await f.up(a);
    expect(f.events.where((e) => e == 'one:end'), hasLength(2));
  }));

  testWidgets('custom touch three finger start retains transformed coordinates',
      (tester) => _run(tester, (f) async {
    final a = await f.down(tester, 1);
    final b = await f.down(tester, 2, const Offset(160, 100));
    final c = await f.down(tester, 3, const Offset(220, 100));
    await a.moveBy(const Offset(40, 15));
    expect(f.threeStarts, hasLength(1));
    final start = f.threeStarts.single;
    expect(start.globalPosition - start.localPosition, const Offset(30, 20));
    await f.up(c);
    await f.up(b);
    await f.up(a);
  }, offset: const Offset(30, 20)));
}

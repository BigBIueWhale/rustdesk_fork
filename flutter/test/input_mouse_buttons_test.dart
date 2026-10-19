import 'dart:math';
import 'dart:ui' show Color, Rect;

import 'package:flutter/gestures.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common.dart' show mouseButtonsToPeer;
import 'package:flutter_hbb/common/widgets/remote_input.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI, FfiModel, CanvasModel, CursorModel;
import 'package:flutter_test/flutter_test.dart';

class _Owner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Button conversion must not access native session state');
}

class _Input extends InputModel {
  _Input(this.owner) : super(WeakReference<FFI>(owner)) {
    isPhysicalMouse.value = true;
  }
  final _Owner owner;
  final events = <({String type, int buttons, Offset position})>[];
  @override
  String get id => '';
  @override
  bool get isViewOnly => false;
  @override
  bool get showMyCursor => false;
  @override
  bool get isViewCamera => false;
  @override
  bool get useEdgeScroll => false;

  @override
  Map<String, dynamic>? handleMouse(Map<String, dynamic> event, Offset position,
      {bool onExit = false, bool moveCanvas = true, bool edgeScroll = false}) {
    events.add((type: event['type'] as String,
        buttons: event['buttons'] as int, position: position));
    return event;
  }

  List<(String, String)> get buttons => events
      .where((e) => e.type != 'mousemove')
      .map((e) => (e.type, mouseButtonsToPeer(e.buttons))).toList();

  void move(int buttons, {Offset position = const Offset(80, 80)}) =>
      onPointMoveImage(PointerMoveEvent(kind: PointerDeviceKind.mouse,
          buttons: buttons, position: position));

  void up([int buttons = 0]) => onPointUpImage(PointerUpEvent(
      kind: PointerDeviceKind.mouse, buttons: buttons,
      position: const Offset(80, 80)));

  void close() {
    // No native mode was enabled; close only these fixture-owned observables.
    relativeMouseMode.close();
    isPhysicalMouse.close();
  }
}

class _DisplayModel extends FfiModel {
  _DisplayModel(super.parent) : super(compareVersion: (_, __) => 1);
  @override
  Rect get rect => const Rect.fromLTWH(0, 0, 100, 100);
}

class _CoordinateOwner extends _Owner {
  _CoordinateOwner(String platform) {
    final parent = WeakReference<FFI>(this);
    ffiModel = _DisplayModel(parent)..pi.platform = platform;
    canvasModel = CanvasModel(parent);
    cursorModel = CursorModel(parent);
  }
  @override
  late final FfiModel ffiModel;
  @override
  late final CanvasModel canvasModel;
  @override
  late final CursorModel cursorModel;
}

class _CoordinateInput extends _Input {
  _CoordinateInput(_CoordinateOwner super.owner);
  final messages = <Map<String, dynamic>>[];

  @override
  Map<String, dynamic>? handleMouse(Map<String, dynamic> event, Offset position,
      {bool onExit = false, bool moveCanvas = true, bool edgeScroll = false}) {
    // Observe after the production control, canvas, bounds and button conversion.
    // The final native send is the only replaced part of this path.
    final message = processEventToPeer(Map.of(event), position,
        onExit: onExit, moveCanvas: false, edgeScroll: false);
    if (message != null) messages.add(Map.of(message));
    return message;
  }

  List<(String, String)> get peerButtons => messages
      .where((e) => e['type'] != kMouseEventTypeDefault)
      .map((e) => (e['type'] as String, e['buttons'] as String)).toList();

  @override
  void close() {
    super.close();
    final coordinates = owner as _CoordinateOwner;
    coordinates.canvasModel.dispose();
    coordinates.cursorModel.dispose();
    coordinates.ffiModel.dispose();
  }
}

class _MouseRegionFixture {
  _MouseRegionFixture(this.tester, {this.buttons = kPrimaryMouseButton});
  final WidgetTester tester;
  final int buttons;
  final model = _CoordinateInput(_CoordinateOwner(kPeerPlatformLinux));
  final callerEvents = <String>[];
  TestPointer? _pointer;
  TestPointer? _touch;
  int _nextPointer = 1;

  Future<void> mount() async {
    await tester.pumpWidget(Directionality(textDirection: TextDirection.ltr,
      child: Align(alignment: Alignment.topLeft,
        child: SizedBox(width: 120, height: 120,
          child: RawPointerMouseRegion(inputModel: model,
            onPointerDown: (_) => callerEvents.add('down'),
            onPointerUp: (_) => callerEvents.add('up'),
            child: const ColoredBox(color: Color(0xff000000)),
          ),
        ),
      ),
    ));
    await tester.sendEventToBinding(const PointerAddedEvent(
        kind: PointerDeviceKind.mouse, device: 1, position: Offset(80, 80)));
  }

  Listener get listener => tester.widget<Listener>(find.descendant(
      of: find.byType(RawPointerMouseRegion), matching: find.byType(Listener)));

  Future<void> down() async {
    final pointer = TestPointer(_nextPointer++, PointerDeviceKind.mouse, 1, buttons);
    _pointer = pointer;
    await tester.sendEventToBinding(pointer.down(const Offset(80, 80)));
  }

  Future<PointerCancelEvent> cancel({Offset? position}) async {
    final pointer = _pointer!;
    final normal = pointer.cancel();
    final event = position == null ? normal : PointerCancelEvent(
        kind: pointer.kind, device: pointer.device, pointer: pointer.pointer,
        position: position);
    await tester.sendEventToBinding(event);
    return event;
  }

  Future<void> up() => tester.sendEventToBinding(_pointer!.up());

  Future<void> touchDown() async {
    final touch = TestPointer(100, PointerDeviceKind.touch);
    _touch = touch;
    await tester.sendEventToBinding(touch.down(const Offset(80, 80)));
  }

  Future<void> close() async {
    if (_touch?.isDown == true) await tester.sendEventToBinding(_touch!.up());
    if (_pointer?.isDown == true) await cancel();
    await tester.sendEventToBinding(const PointerRemovedEvent(
        kind: PointerDeviceKind.mouse, device: 1));
    await tester.pumpWidget(const SizedBox.shrink());
    model.close();
  }
}

Future<void> _withMouseRegion(WidgetTester tester,
    Future<void> Function(_MouseRegionFixture) body,
    {int buttons = kPrimaryMouseButton}) async {
  final fixture = _MouseRegionFixture(tester, buttons: buttons);
  try {
    await fixture.mount();
    await body(fixture);
  } finally { await fixture.close(); }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Input input;
  setUp(() { input = _Input(_Owner()); });
  tearDown(() { input.close(); });

  test('physical mouse single primary press and release remain paired', () {
    input.onPointDownImage(const PointerDownEvent(
        kind: PointerDeviceKind.mouse, buttons: kPrimaryMouseButton,
        position: Offset(80, 80)));
    input.up();
    expect(input.buttons, [('mousedown', 'left'), ('mouseup', 'left')]);
  });

  test('physical mouse right to left releases right before pressing left', () {
    input.move(2);
    input.move(1, position: const Offset(90, 100));
    expect(input.buttons, [
      ('mousedown', 'right'), ('mouseup', 'right'), ('mousedown', 'left')]);
    expect(input.events.where((e) => e.type == 'mousemove').last.position,
        const Offset(90, 100));
  });

  test('physical mouse left to right releases left before pressing right', () {
    input.move(1);
    input.move(2);
    expect(input.buttons, [
      ('mousedown', 'left'), ('mouseup', 'left'), ('mousedown', 'right')]);
  });

  test('physical mouse mixed replacement releases every previous button', () {
    input.move(6);
    input.events.clear();
    input.move(1);
    expect(input.buttons, [
      ('mouseup', 'right'), ('mouseup', 'wheel'), ('mousedown', 'left')]);
  });

  test('physical mouse first down decomposes the five supported buttons', () {
    input.onPointDownImage(const PointerDownEvent(
        kind: PointerDeviceKind.mouse, buttons: 31,
        position: Offset(80, 80)));
    expect(input.buttons, [('mousedown', 'left'), ('mousedown', 'right'),
      ('mousedown', 'wheel'), ('mousedown', 'back'), ('mousedown', 'forward')]);
    input.up();
    expect(input.buttons.skip(5), [('mouseup', 'left'), ('mouseup', 'right'),
      ('mouseup', 'wheel'), ('mouseup', 'back'), ('mouseup', 'forward')]);
  });

  test('physical mouse coalesced presses keep individual peer identities', () {
    input.move(1);
    input.events.clear();
    input.move(31);
    expect(input.buttons, [('mousedown', 'right'), ('mousedown', 'wheel'),
      ('mousedown', 'back'), ('mousedown', 'forward')]);
  });

  test('physical mouse partial chord release preserves the held primary', () {
    input.move(7);
    input.events.clear();
    input.move(1);
    expect(input.buttons, [('mouseup', 'right'), ('mouseup', 'wheel')]);
    input.up();
    expect(input.buttons.last, ('mouseup', 'left'));
  });

  test('physical mouse final up retires stale chord button flags', () {
    input.move(7);
    input.events.clear();
    input.up(7);
    input.up();
    expect(input.buttons, [('mouseup', 'left'), ('mouseup', 'right'),
      ('mouseup', 'wheel')]);
  });

  test('physical mouse unchanged chord emits movement without button repeats', () {
    input.move(3);
    input.events.clear();
    input.move(3, position: const Offset(110, 120));
    expect(input.buttons, isEmpty);
    expect(input.events.single.type, 'mousemove');
    expect(input.events.single.position, const Offset(110, 120));
  });

  test('physical mouse hover retires missing releases before a fresh press', () {
    input.move(3);
    input.events.clear();
    input.onPointHoverImage(const PointerHoverEvent(
        kind: PointerDeviceKind.mouse, position: Offset(90, 100)));
    input.move(2);
    expect(input.buttons, [('mouseup', 'left'), ('mouseup', 'right'),
      ('mousedown', 'right')]);
  });

  test('physical mouse unsupported bits cannot become empty peer buttons', () {
    input.move(32);
    expect(input.buttons, isEmpty);
    input.move(33);
    input.move(32);
    expect(input.buttons, [('mousedown', 'left'), ('mouseup', 'left')]);
  });

  test('physical mouse secondary release preserves a held primary', () {
    input.move(1);
    input.move(3);
    input.move(1);
    input.up();
    expect(input.buttons, [('mousedown', 'left'), ('mousedown', 'right'),
      ('mouseup', 'right'), ('mouseup', 'left')]);
  });

  test('physical mouse independent models retain separate button history', () {
    final other = _Input(_Owner());
    try {
      input.move(1);
      other.move(2);
      input.up();
      other.up();
      expect(input.buttons, [('mousedown', 'left'), ('mouseup', 'left')]);
      expect(other.buttons, [('mousedown', 'right'), ('mouseup', 'right')]);
    } finally { other.close(); }
  });

  test('physical mouse nonmouse movement cannot replace mouse button history', () {
    input.move(1);
    input.onPointMoveImage(const PointerMoveEvent(
        kind: PointerDeviceKind.touch, buttons: 2));
    input.up();
    expect(input.buttons, [('mousedown', 'left'), ('mouseup', 'left')]);
  });

  const peers = [kPeerPlatformLinux, kPeerPlatformWindows, kPeerPlatformMacOS];
  const outside = [Offset(-40, 80), Offset(180, 80),
    Offset(80, -40), Offset(80, 180)];
  const namedButtons = [(1, 'left'), (2, 'right'), (4, 'wheel'),
    (8, 'back'), (16, 'forward')];
  for (final (button, name) in namedButtons) {
    test('physical mouse outside release preserves $name', () {
      for (final platform in peers) {
        for (final position in outside) {
          final model = _CoordinateInput(_CoordinateOwner(platform));
          try {
            model.onPointDownImage(PointerDownEvent(
                kind: PointerDeviceKind.mouse, buttons: button,
                position: const Offset(80, 80)));
            model.onPointUpImage(PointerUpEvent(
                kind: PointerDeviceKind.mouse, position: position));
            model.onPointUpImage(PointerUpEvent(
                kind: PointerDeviceKind.mouse, position: position));
            expect(model.peerButtons, [('down', name), ('up', name)],
                reason: '$platform release at $position');
          } finally { model.close(); }
        }
      }
    });
  }

  test('physical mouse outside chord release retires every button once', () {
    final model = _CoordinateInput(_CoordinateOwner(kPeerPlatformLinux));
    try {
      model.onPointDownImage(const PointerDownEvent(
          kind: PointerDeviceKind.mouse, buttons: 31, position: Offset(80, 80)));
      model.onPointUpImage(const PointerUpEvent(
          kind: PointerDeviceKind.mouse, position: Offset(180, 180)));
      model.up();
      expect(model.peerButtons, [
        for (final (_, name) in namedButtons) ('down', name),
        for (final (_, name) in namedButtons) ('up', name),
      ]);
    } finally { model.close(); }
  });

  test('physical mouse outside presses and movement remain rejected', () {
    for (final platform in peers) {
      for (final position in outside) {
        for (final type in [kMouseEventTypeDown, kMouseEventTypeDefault]) {
          expect(InputModel.getPointInRemoteRect(true, platform,
              kPointerEventKindMouse, type, position.dx, position.dy,
              const Rect.fromLTWH(0, 0, 100, 100)), isNull);
        }
      }
    }
  });

  test('physical mouse bounds retain snapping tolerance and mobile clamping', () {
    const rect = Rect.fromLTWH(0, 0, 100, 100);
    Point<double>? point(bool desktop, String peer, double x, double y) =>
        InputModel.getPointInRemoteRect(desktop, peer, kPointerEventKindMouse,
            kMouseEventTypeDefault, x, y, rect);
    expect(point(true, kPeerPlatformWindows, 100, 100), const Point(100.0, 100.0));
    expect(point(true, kPeerPlatformLinux, 104, 104), const Point(99.0, 99.0));
    expect(point(true, kPeerPlatformLinux, 105, 105), isNull);
    expect(point(true, kPeerPlatformLinux, -5, 50), const Point(0.0, 50.0));
    expect(point(true, kPeerPlatformLinux, -6, 50), isNull);
    expect(point(false, kPeerPlatformLinux, -40, 50), const Point(0.0, 50.0));
    expect(point(false, kPeerPlatformLinux, -40, -40), isNull);
  });

  testWidgets('physical mouse widget cancellation releases the primary button',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.cancel();
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
      expect(f.callerEvents, ['down']);
    });
  });

  testWidgets('physical mouse widget outside cancellation releases a chord',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.cancel(position: const Offset(180, 180));
      expect(f.model.peerButtons, [
        for (final (_, name) in namedButtons) ('down', name),
        for (final (_, name) in namedButtons) ('up', name),
      ]);
    }, buttons: 31);
  });

  testWidgets('physical mouse widget cancellation permits a fresh matching press',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.cancel();
      await f.down();
      await f.cancel();
      expect(f.model.peerButtons, [
        ('down', 'left'), ('up', 'left'), ('down', 'left'), ('up', 'left')]);
    });
  });

  testWidgets('physical mouse widget repeated cancellation releases once',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      final event = await f.cancel();
      f.listener.onPointerCancel?.call(event);
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
    });
  });

  testWidgets('physical mouse widget touch cancellation preserves a mouse press',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      f.listener.onPointerCancel?.call(const PointerCancelEvent(
          kind: PointerDeviceKind.touch, position: Offset(80, 80)));
      expect(f.model.peerButtons, [('down', 'left')]);
      await f.up();
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
    });
  });

  testWidgets('physical mouse widget cancellation without a press emits nothing',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      f.listener.onPointerCancel?.call(const PointerCancelEvent(
          kind: PointerDeviceKind.mouse, position: Offset(80, 80)));
      expect(f.model.peerButtons, isEmpty);
    });
  });

  testWidgets('physical mouse widget ordinary up retains caller callbacks',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.up();
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
      expect(f.callerEvents, ['down', 'up']);
    });
  });

  testWidgets('physical mouse widget mouse cancellation survives a touch pointer',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.touchDown();
      expect(f.model.isPhysicalMouse.value, false);
      await f.cancel();
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
    });
  });

  testWidgets('physical mouse widget mouse up survives a touch pointer',
      (tester) async {
    await _withMouseRegion(tester, (f) async {
      await f.down();
      await f.touchDown();
      expect(f.model.isPhysicalMouse.value, false);
      await f.up();
      expect(f.model.peerButtons, [('down', 'left'), ('up', 'left')]);
    });
  });
}

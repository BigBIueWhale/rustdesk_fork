import 'package:flutter/gestures.dart';
import 'package:flutter_hbb/common.dart' show mouseButtonsToPeer;
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
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
}

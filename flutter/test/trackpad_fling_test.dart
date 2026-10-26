import 'dart:async';

import 'package:fake_async/fake_async.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/flutter_keyboard_input.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI, FfiModel;
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Keys implements FlutterKeyboardInputBackend {
  @override
  bool useFlutterInput = true;
  @override
  Future<String> readRound(SessionID session, SessionID client) =>
      throw StateError('Trackpad tests must not read a keyboard round');
  @override
  Future<void> send(FlutterKeyboardTarget target, int sequence, int? slot,
          FlutterKeyStroke stroke) =>
      throw StateError('Trackpad tests must not send keys');
  @override
  Future<void> release(FlutterKeyboardTarget target, int sequence, int? slot) =>
      throw StateError('Trackpad tests must not release keys');
  @override
  void enterOrLeave(SessionID session, bool enter) {}
}

class _Owner implements FFI {
  _Owner() {
    final parent = WeakReference<FFI>(this);
    ffiModel = FfiModel(parent, compareVersion: (_, __) => 1)
      ..pi.platform = 'Linux';
    inputModel = _Input(this);
  }
  @override
  SessionID sessionId = const Uuid().v4obj();
  @override
  SessionID clientOwnerId = const Uuid().v4obj();
  @override
  final String id = '';
  @override
  late final FfiModel ffiModel;
  @override
  late final _Input inputModel;
  bool current = true;
  @override
  bool isCurrentSessionOwner(SessionID session, SessionID client) =>
      current && session == sessionId && client == clientOwnerId;
  @override
  bool isCurrentSession(SessionID session) => current && session == sessionId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Input extends InputModel {
  _Input(this.owner)
      : super(WeakReference<FFI>(owner), keyboardBackend: _Keys());
  final _Owner owner;
  final scrolls = <({SessionID session, int x, int y})>[];
  final wheels = <({SessionID session, int x, int y})>[];
  final scales = <int>[];
  final scaleTargets = <SessionID>[];
  final pointers = <({SessionID session, String type})>[];
  Future<void> Function()? onScroll;
  bool viewOnly = false;
  bool viewCamera = false;
  bool keyboardAllowed = true;
  @override
  String get id => '';
  @override
  bool get isViewOnly => viewOnly;
  @override
  bool get isViewCamera => viewCamera;
  @override
  bool get keyboardPerm => keyboardAllowed;
  @override
  bool get showMyCursor => false;
  @override
  bool get useEdgeScroll => false;

  // Observe only final native output; gesture processing and timers are real.
  @override
  Future<void> sendWheelScroll(int x, int y,
      {required SessionID expectedSessionId}) {
    wheels.add((session: expectedSessionId, x: x, y: y));
    return Future.value();
  }

  @override
  Future<void> sendTrackpadScale(int scale,
      {SessionID? expectedSessionId}) {
    scales.add(scale);
    scaleTargets.add(expectedSessionId ?? sessionId);
    return Future.value();
  }

  @override
  Future<void> sendTrackpadScroll(int x, int y,
      {SessionID? expectedSessionId}) {
    scrolls.add((session: expectedSessionId ?? sessionId, x: x, y: y));
    return onScroll?.call() ?? Future.value();
  }

  @override
  Map<String, dynamic>? handleMouse(Map<String, dynamic> event, Offset position,
          {bool onExit = false, bool moveCanvas = true, bool edgeScroll = false}) =>
      event;

  // Android routing is observed before coordinate/control and native dispatch.
  @override
  void handlePointerEvent(String kind, String type, Offset offset,
      {SessionID? expectedSessionId}) {
    expect(kind, 'touch');
    pointers.add((session: expectedSessionId ?? sessionId, type: type));
  }

  void begin({int pointer = 0, int device = 0, int view = 0}) =>
      onPointerPanZoomStart(PointerPanZoomStartEvent(
          pointer: pointer, device: device, viewId: view));

  void update(double y,
          {double scale = 1, int pointer = 0, int device = 0, int view = 0}) =>
      onPointerPanZoomUpdate(PointerPanZoomUpdateEvent(
          pan: Offset(0, y), panDelta: Offset(0, y), scale: scale,
          pointer: pointer, device: device, viewId: view));

  void end({int pointer = 0, int device = 0, int view = 0}) =>
      onPointerPanZoomEnd(PointerPanZoomEndEvent(
          pointer: pointer, device: device, viewId: view));

  void clearOutput() {
    scrolls.clear();
    scales.clear();
    scaleTargets.clear();
    pointers.clear();
  }

  void startCoast([double y = 100]) {
    onPointerPanZoomStart(const PointerPanZoomStartEvent());
    onPointerPanZoomUpdate(PointerPanZoomUpdateEvent(
        pan: Offset(0, y), panDelta: Offset(0, y)));
    onPointerPanZoomEnd(const PointerPanZoomEndEvent());
  }

  void close() {
    resetForSession(sessionId);
    relativeMouseMode.close();
    isPhysicalMouse.close();
    owner.ffiModel.dispose();
  }
}

void _run(void Function(FakeAsync, _Owner, _Input) body) {
  fakeAsync((clock) {
    final owner = _Owner();
    try {
      body(clock, owner, owner.inputModel);
    } finally {
      owner.inputModel.close();
      clock.flushMicrotasks();
    }
  });
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('wheel ordinary directions retain session and dominant axis', () {
    _run((clock, owner, input) {
      for (final delta in [const Offset(20, 0), const Offset(-20, 0),
          const Offset(0, 20), const Offset(0, -20), const Offset(40, 20),
          const Offset(20, -40), const Offset(20, 20)]) {
        input.onPointerSignalImage(PointerScrollEvent(scrollDelta: delta));
      }
      expect(input.wheels.map((event) => (event.x, event.y)),
          [(-1, 0), (1, 0), (0, -1), (0, 1), (-1, 0), (0, 1), (0, -1)]);
      expect(input.wheels.every((event) => event.session == owner.sessionId),
          isTrue);
    });
  });

  test('wheel inactive owner refuses dispatch and permits fresh input', () {
    _run((clock, owner, input) {
      owner.current = false;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, isEmpty);
      owner.sessionId = const Uuid().v4obj();
      owner.clientOwnerId = const Uuid().v4obj();
      owner.current = true;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, [(session: owner.sessionId, x: 0, y: -1)]);
    });
  });

  test('wheel disposed model refuses retained callbacks', () {
    _run((clock, owner, input) {
      final callback = input.onPointerSignalImage;
      input.disposeRelativeMouseMode(expectedSessionId: owner.sessionId);
      callback(const PointerScrollEvent(scrollDelta: Offset(0, 20)));
      expect(input.wheels, isEmpty);
      final replacement = _Owner();
      try {
        replacement.inputModel.onPointerSignalImage(const PointerScrollEvent(
            scrollDelta: Offset(0, 20)));
        expect(replacement.inputModel.wheels,
            [(session: replacement.sessionId, x: 0, y: -1)]);
      } finally {
        replacement.inputModel.close();
      }
    });
  });

  test('wheel permission refusal permits an authorized retry', () {
    _run((clock, owner, input) {
      input.keyboardAllowed = false;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, isEmpty);
      input.keyboardAllowed = true;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, [(session: owner.sessionId, x: 0, y: -1)]);
    });
  });

  test('wheel view-only and camera refusals retain normal control', () {
    _run((clock, owner, input) {
      input.viewOnly = true;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, isEmpty);
      input.viewOnly = false;
      input.viewCamera = true;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, isEmpty);
      input.viewCamera = false;
      input.onPointerSignalImage(const PointerScrollEvent(
          scrollDelta: Offset(0, 20)));
      expect(input.wheels, [(session: owner.sessionId, x: 0, y: -1)]);
    });
  });

  test('trackpad gesture orphan update and end emit nothing', () {
    _run((clock, owner, input) {
      input.update(100);
      input.end();
      clock.elapse(const Duration(milliseconds: 60));
      expect(input.scrolls, isEmpty);
      expect(input.scales, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  for (final identity in ['session', 'client']) {
    test('trackpad gesture changed $identity cannot inherit pan or fling', () {
      _run((clock, owner, input) {
        input.begin();
        input.update(100);
        input.clearOutput();
        if (identity == 'session') {
          owner.sessionId = const Uuid().v4obj();
        } else {
          owner.clientOwnerId = const Uuid().v4obj();
        }
        input.update(100, scale: 1.5);
        input.end();
        clock.elapse(const Duration(milliseconds: 60));
        expect(input.scrolls, isEmpty);
        expect(input.scales, isEmpty);
        expect(clock.nonPeriodicTimerCount, 0);
        input.startCoast();
        clock.elapse(const Duration(milliseconds: 30));
        expect(input.scrolls, hasLength(2));
        expect(input.scrolls.every((e) => e.session == owner.sessionId), isTrue);
      });
    });
  }

  for (final field in ['pointer', 'device', 'view']) {
    test('trackpad gesture wrong $field preserves the active sequence', () {
      _run((clock, owner, input) {
        input.begin(pointer: 10, device: 7, view: 2);
        input.update(100, pointer: 10, device: 7, view: 2);
        input.clearOutput();
        final pointer = field == 'pointer' ? 11 : 10;
        final device = field == 'device' ? 8 : 7;
        final view = field == 'view' ? 3 : 2;
        input.update(400, scale: 1.5,
            pointer: pointer, device: device, view: view);
        input.end(pointer: pointer, device: device, view: view);
        expect(input.scrolls, isEmpty);
        expect(input.scales, isEmpty);
        expect(clock.nonPeriodicTimerCount, 0);
        input.end(pointer: 10, device: 7, view: 2);
        clock.elapse(const Duration(milliseconds: 30));
        expect(input.scales, [0]);
        expect(input.scrolls.map((e) => e.y), [5]);
      });
    });
  }

  test('trackpad gesture late end preserves a replacement pointer', () {
    _run((clock, owner, input) {
      input.begin(pointer: 1);
      input.update(100, pointer: 1);
      input.begin(pointer: 2);
      input.update(200, pointer: 2);
      input.clearOutput();
      input.end(pointer: 1);
      expect(input.scales, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
      input.end(pointer: 2);
      clock.elapse(const Duration(milliseconds: 30));
      expect(input.scales, [0]);
      expect(input.scrolls.map((e) => e.y), [11]);
    });
  });

  test('trackpad gesture duplicate end preserves its running coast', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.clearOutput();
      input.end();
      expect(input.scales, isEmpty);
      expect(clock.nonPeriodicTimerCount, 1);
      clock.elapse(const Duration(milliseconds: 30));
      expect(input.scrolls.map((e) => e.y), [5]);
    });
  });

  test('trackpad gesture matching pan and scale retain their target', () {
    _run((clock, owner, input) {
      input.begin(pointer: 7, device: 4, view: 3);
      input.update(100, pointer: 7, device: 4, view: 3);
      input.update(0, scale: 1.5, pointer: 7, device: 4, view: 3);
      input.end(pointer: 7, device: 4, view: 3);
      clock.elapse(const Duration(milliseconds: 30));
      expect(input.scales, [500, 0]);
      expect(input.scaleTargets, [owner.sessionId, owner.sessionId]);
      expect(input.scrolls.map((e) => e.y), [6, 5]);
      expect(input.scrolls.every((e) => e.session == owner.sessionId), isTrue);
    });
  });

  test('trackpad gesture same owner retains fractional scrolling', () {
    _run((clock, owner, input) {
      for (var index = 0; index < 3; index++) {
        input.begin();
        input.update(8);
        input.end();
      }
      expect(input.scrolls.map((e) => e.y), [1]);
    });
  });

  for (final direction in [1, -1]) {
    test('trackpad slow pinch ${direction > 0 ? "in" : "out"} retains cumulative zoom', () {
      _run((clock, owner, input) {
        input.begin();
        for (var step = 1; step <= 2048; step++) {
          input.update(0, scale: 1 + direction * step / 4096);
        }
        expect(input.scales.fold<int>(0, (sum, value) => sum + value),
            direction * 500);
        expect(input.scales.every((value) => value == direction), isTrue);
        expect(input.scaleTargets.every((target) => target == owner.sessionId),
            isTrue);
        expect(input.scrolls, isEmpty);
        input.end();
        expect(input.scales.last, 0);
        expect(clock.nonPeriodicTimerCount, 0);
      });
    });
  }

  test('trackpad pinch total is independent of event subdivision', () {
    _run((clock, owner, input) {
      input.begin();
      input.update(0, scale: 1 + 100 / 512);
      final coarse = input.scales.single;
      expect(coarse, 195);
      input.end();
      input.clearOutput();
      input.begin();
      for (var step = 1; step <= 100; step++) {
        input.update(0, scale: 1 + step / 512);
      }
      expect(input.scales.fold<int>(0, (sum, value) => sum + value), coarse);
      expect(input.scrolls, isEmpty);
    });
  });

  test('trackpad pinch reversal preserves zoom within one wire unit', () {
    _run((clock, owner, input) {
      input.begin();
      for (final step in [1, 2, 3, 2, 1, 0, -1, -2, -3, -2, -1, 0]) {
        input.update(0, scale: 1 + step / 512);
        final total = input.scales.fold<int>(0, (sum, value) => sum + value);
        expect((total - step * 1000 / 512).abs(), lessThan(1));
        final count = input.scales.length;
        input.update(0, scale: 1 + step / 512);
        expect(input.scales.length, count);
      }
      expect(input.scales.fold<int>(0, (sum, value) => sum + value), 0);
      expect(input.scrolls, isEmpty);
    });
  });

  test('trackpad pinch remainder retires with its gesture', () {
    _run((clock, owner, input) {
      for (final pointer in [1, 2, 3]) {
        input.begin(pointer: pointer);
        input.update(0, scale: 1 + 3 / 4096, pointer: pointer);
        input.end(pointer: pointer);
      }
      expect(input.scales, [0, 0, 0]);
      input.begin(pointer: 4);
      input.update(0, scale: 1.5, pointer: 4);
      expect(input.scales, [0, 0, 0, 500]);
      expect(input.scrolls, isEmpty);
    });
  });

  test('trackpad gesture fractional remainder belongs to its exact owner', () {
    for (final identity in ['session', 'client']) {
      _run((clock, owner, input) {
        for (var index = 0; index < 2; index++) {
          input.begin();
          input.update(8);
          input.end();
        }
        input.clearOutput();
        if (identity == 'session') {
          owner.sessionId = const Uuid().v4obj();
        } else {
          owner.clientOwnerId = const Uuid().v4obj();
        }
        input.begin();
        input.update(8);
        expect(input.scrolls, isEmpty);
      });
    }
  });

  test('trackpad gesture reset refuses late update and end', () {
    _run((clock, owner, input) {
      input.begin();
      input.update(100);
      input.resetForSession(owner.sessionId);
      input.clearOutput();
      input.update(100);
      input.end();
      clock.elapse(const Duration(milliseconds: 60));
      expect(input.scrolls, isEmpty);
      expect(input.scales, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  test('trackpad gesture Android matching sequence retains all phases', () {
    _run((clock, owner, input) {
      owner.ffiModel.pi.platform = kPeerPlatformAndroid;
      input.begin();
      input.update(100);
      input.end();
      expect(input.pointers.map((e) => e.type),
          [kMouseEventTypePanStart, kMouseEventTypePanUpdate, kMouseEventTypePanEnd]);
      expect(input.pointers.every((e) => e.session == owner.sessionId), isTrue);
      expect(input.scales, isEmpty);
      expect(input.scrolls, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  test('trackpad gesture Android orphan callbacks emit no phases', () {
    _run((clock, owner, input) {
      owner.ffiModel.pi.platform = kPeerPlatformAndroid;
      input.update(100);
      input.end();
      expect(input.pointers, isEmpty);
    });
  });

  test('trackpad gesture Android replacement cannot inherit old phases', () {
    _run((clock, owner, input) {
      owner.ffiModel.pi.platform = kPeerPlatformAndroid;
      input.begin();
      input.clearOutput();
      owner.sessionId = const Uuid().v4obj();
      input.update(100);
      input.end();
      expect(input.pointers, isEmpty);
      input.begin();
      input.update(100);
      input.end();
      expect(input.pointers.map((e) => e.type),
          [kMouseEventTypePanStart, kMouseEventTypePanUpdate, kMouseEventTypePanEnd]);
      expect(input.pointers.every((e) => e.session == owner.sessionId), isTrue);
    });
  });

  test('trackpad fling retains Linux scaling decay and finite completion', () {
    _run((clock, owner, input) {
      input.startCoast();
      expect(clock.nonPeriodicTimerCount, 1);
      clock.elapse(const Duration(milliseconds: 60));
      expect(input.scrolls.map((e) => (e.x, e.y)), [(0, 6), (0, 5), (0, 5)]);
      expect(input.scales, [0]);
      clock.elapse(const Duration(seconds: 5));
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  final interrupts = <String, void Function(_Input)>{
    'new pan': (input) =>
        input.onPointerPanZoomStart(const PointerPanZoomStartEvent()),
    'pointer down': (input) => input.onPointDownImage(const PointerDownEvent(
        kind: PointerDeviceKind.mouse, buttons: kPrimaryMouseButton)),
    'hover': (input) => input.onPointHoverImage(
        const PointerHoverEvent(kind: PointerDeviceKind.mouse)),
    'window blur': (input) => input.onWindowBlur(),
  };
  for (final entry in interrupts.entries) {
    test('trackpad fling ${entry.key} cancels the pending timer immediately', () {
      _run((clock, owner, input) {
        input.startCoast();
        input.scrolls.clear();
        entry.value(input);
        expect(clock.nonPeriodicTimerCount, 0);
        clock.elapse(const Duration(milliseconds: 120));
        expect(input.scrolls, isEmpty);
      });
    });
  }

  test('trackpad fling disposal retires pending coast work', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.scrolls.clear();
      input.disposeRelativeMouseMode(expectedSessionId: owner.sessionId);
      expect(clock.nonPeriodicTimerCount, 0);
      clock.elapse(const Duration(milliseconds: 120));
      expect(input.scrolls, isEmpty);
    });
  });

  test('trackpad fling disposed model refuses later pan callbacks', () {
    _run((clock, owner, input) {
      input.disposeRelativeMouseMode(expectedSessionId: owner.sessionId);
      input.startCoast();
      clock.elapse(const Duration(milliseconds: 120));
      expect(input.scrolls, isEmpty);
      expect(input.scales, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  test('trackpad fling reset retires old work and permits a fresh coast', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.resetForSession(owner.sessionId);
      expect(clock.nonPeriodicTimerCount, 0);
      owner.sessionId = const Uuid().v4obj();
      input.scrolls.clear();
      input.startCoast();
      clock.elapse(const Duration(milliseconds: 30));
      expect(input.scrolls, hasLength(2));
      expect(input.scrolls.every((e) => e.session == owner.sessionId), isTrue);
    });
  });

  for (final identity in ['session', 'client']) {
    test('trackpad fling changed $identity retires the captured coast', () {
      _run((clock, owner, input) {
        input.startCoast();
        input.scrolls.clear();
        if (identity == 'session') {
          owner.sessionId = const Uuid().v4obj();
        } else {
          owner.clientOwnerId = const Uuid().v4obj();
        }
        clock.elapse(const Duration(milliseconds: 30));
        expect(input.scrolls, isEmpty);
        expect(clock.nonPeriodicTimerCount, 0);
      });
    });
  }

  test('trackpad fling models retain independent timer ownership', () {
    _run((clock, owner, input) {
      final second = _Owner().inputModel;
      try {
        input.startCoast();
        second.startCoast();
        expect(clock.nonPeriodicTimerCount, 2);
        input.onPointerPanZoomStart(const PointerPanZoomStartEvent());
        expect(clock.nonPeriodicTimerCount, 1);
        clock.elapse(const Duration(milliseconds: 30));
        expect(second.scrolls, hasLength(2));
      } finally {
        second.close();
      }
    });
  });

  test('trackpad fling waits for its admitted send before another timer', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.scrolls.clear();
      final held = Completer<void>();
      input.onScroll = () => held.future;
      try {
        clock.elapse(const Duration(milliseconds: 120));
        expect(input.scrolls, hasLength(1));
        expect(clock.nonPeriodicTimerCount, 0);
      } finally {
        held.complete();
        clock.flushMicrotasks();
      }
    });
  });

  test('trackpad fling late send completion cannot restart disposed work', () {
    _run((clock, owner, input) {
      input.startCoast();
      final held = Completer<void>();
      input.onScroll = () => held.future;
      clock.elapse(const Duration(milliseconds: 30));
      input.disposeRelativeMouseMode(expectedSessionId: owner.sessionId);
      input.scrolls.clear();
      held.complete();
      clock.flushMicrotasks();
      clock.elapse(const Duration(milliseconds: 120));
      expect(input.scrolls, isEmpty);
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  test('trackpad fling reentrant stop cannot create another timer', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.onScroll = () {
        input.onPointerPanZoomStart(const PointerPanZoomStartEvent());
        return Future.value();
      };
      clock.elapse(const Duration(milliseconds: 30));
      expect(clock.nonPeriodicTimerCount, 0);
    });
  });

  test('trackpad fling reentrant replacement retains one timer', () {
    _run((clock, owner, input) {
      input.startCoast();
      input.onScroll = () {
        input.onScroll = null;
        input.startCoast(200);
        return Future.value();
      };
      clock.elapse(const Duration(milliseconds: 30));
      expect(clock.nonPeriodicTimerCount, 1);
      input.scrolls.clear();
      clock.elapse(const Duration(milliseconds: 30));
      expect(input.scrolls.map((e) => e.y), [11]);
    });
  });

  test('trackpad fling dispatch failure retires its own timer', () {
    for (final synchronous in [true, false]) {
      _run((clock, owner, input) {
        input.startCoast();
        input.onScroll = () {
          if (synchronous) throw StateError('controlled trackpad send failure');
          return Future.error(StateError('controlled trackpad send failure'));
        };
        clock.elapse(const Duration(milliseconds: 30));
        clock.flushMicrotasks();
        expect(clock.nonPeriodicTimerCount, 0);
      });
    }
  });
}

import 'dart:async';

import 'package:fake_async/fake_async.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
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
  final scales = <int>[];
  Future<void> Function()? onScroll;
  @override
  String get id => '';
  @override
  bool get isViewOnly => false;
  @override
  bool get isViewCamera => false;
  @override
  bool get keyboardPerm => true;
  @override
  bool get showMyCursor => false;
  @override
  bool get useEdgeScroll => false;

  // Observe only final native output; gesture processing and timers are real.
  @override
  Future<void> sendTrackpadScale(int scale) {
    scales.add(scale);
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

import 'dart:async';
import 'package:flutter/gestures.dart';

enum GestureState {
  none,
  oneFingerPan,
  twoFingerScale,
  threeFingerVerticalDrag
}

class CustomTouchGestureRecognizer extends ScaleGestureRecognizer {
  CustomTouchGestureRecognizer({
    Object? debugOwner,
    Set<PointerDeviceKind>? supportedDevices,
  }) : super(
          debugOwner: debugOwner,
          supportedDevices: supportedDevices,
        ) {
    _init();
  }

  // oneFingerPan
  GestureDragStartCallback? onOneFingerPanStart;
  GestureDragUpdateCallback? onOneFingerPanUpdate;
  GestureDragEndCallback? onOneFingerPanEnd;

  // twoFingerScale : scale + pan event
  GestureScaleStartCallback? onTwoFingerScaleStart;
  GestureScaleUpdateCallback? onTwoFingerScaleUpdate;
  GestureScaleEndCallback? onTwoFingerScaleEnd;

  // threeFingerVerticalDrag
  GestureDragStartCallback? onThreeFingerVerticalDragStart;
  GestureDragUpdateCallback? onThreeFingerVerticalDragUpdate;
  GestureDragEndCallback? onThreeFingerVerticalDragEnd;

  var _currentState = GestureState.none;
  bool _disposed = false;

  void _init() {
    onUpdate = (d) {
      if (_disposed) return;
      if (_currentState == GestureState.none) {
        _startPhase(d);
      }
      if (_disposed) return;
      switch (_currentState) {
        case GestureState.oneFingerPan:
          onOneFingerPanUpdate?.call(_getDragUpdateDetails(d));
          break;
        case GestureState.twoFingerScale:
          onTwoFingerScaleUpdate?.call(d);
          break;
        case GestureState.threeFingerVerticalDrag:
          onThreeFingerVerticalDragUpdate?.call(_getDragUpdateDetails(d));
          break;
        case GestureState.none:
          break;
      }
    };
    onEnd = _endPhase;
  }

  void _startPhase(ScaleUpdateDetails d) {
    switch (d.pointerCount) {
      case 1:
        _currentState = GestureState.oneFingerPan;
        onOneFingerPanStart?.call(_getDragStartDetails(d));
        break;
      case 2:
        _currentState = GestureState.twoFingerScale;
        onTwoFingerScaleStart?.call(ScaleStartDetails(
            localFocalPoint: d.localFocalPoint,
            focalPoint: d.focalPoint,
            pointerCount: d.pointerCount,
            sourceTimeStamp: d.sourceTimeStamp));
        break;
      case 3:
        _currentState = GestureState.threeFingerVerticalDrag;
        onThreeFingerVerticalDragStart?.call(_getDragStartDetails(d));
        break;
    }
  }

  void _endPhase(ScaleEndDetails d) {
    final state = _currentState;
    _currentState = GestureState.none;
    switch (state) {
      case GestureState.oneFingerPan:
        final panEnd = onOneFingerPanEnd;
        if (panEnd != null) {
          invokeCallback<void>('onOneFingerPanEnd',
              () => panEnd(_getDragEndDetails(d)));
        }
        break;
      case GestureState.twoFingerScale:
        final scaleEnd = onTwoFingerScaleEnd;
        if (scaleEnd != null) {
          invokeCallback<void>('onTwoFingerScaleEnd', () => scaleEnd(d));
        }
        break;
      case GestureState.threeFingerVerticalDrag:
        final dragEnd = onThreeFingerVerticalDragEnd;
        if (dragEnd != null) {
          invokeCallback<void>('onThreeFingerVerticalDragEnd',
              () => dragEnd(_getDragEndDetails(d)));
        }
        break;
      case GestureState.none:
        break;
    }
  }

  DragStartDetails _getDragStartDetails(ScaleUpdateDetails d) => DragStartDetails(
      globalPosition: d.focalPoint,
      localPosition: d.localFocalPoint,
      sourceTimeStamp: d.sourceTimeStamp);

  DragUpdateDetails _getDragUpdateDetails(ScaleUpdateDetails d) =>
      DragUpdateDetails(
          globalPosition: d.focalPoint,
          localPosition: d.localFocalPoint,
          delta: d.focalPointDelta);

  DragEndDetails _getDragEndDetails(ScaleEndDetails d) =>
      DragEndDetails(velocity: d.velocity);

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _endPhase(ScaleEndDetails());
    super.dispose();
  }
}

enum _HoldDragPhase { firstDown, waitingForSecond, secondDown, resolving, dragging }

class _HoldDragPointer {
  _HoldDragPointer(this.down, this.entry);

  final PointerDownEvent down;
  final GestureArenaEntry entry;
  bool tracking = true;
  bool held = false;
  bool resolved = false;
}

class _HoldDragSequence {
  _HoldDragSequence(this.first);

  final _HoldDragPointer first;
  _HoldDragPointer? second;
  _HoldDragPhase phase = _HoldDragPhase.firstDown;
  Timer? minimumTimer;
  Timer? deadline;
  bool minimumElapsed = false;

  List<_HoldDragPointer> get pointers => [first, if (second != null) second!];

  void cancelTimers() {
    minimumTimer?.cancel();
    minimumTimer = null;
    deadline?.cancel();
    deadline = null;
  }
}

class HoldTapMoveGestureRecognizer extends GestureRecognizer {
  HoldTapMoveGestureRecognizer({
    Object? debugOwner,
    Set<PointerDeviceKind>? supportedDevices,
  }) : super(
          debugOwner: debugOwner,
          supportedDevices: supportedDevices,
        );

  GestureDragStartCallback? onHoldDragStart;
  GestureDragUpdateCallback? onHoldDragUpdate;
  GestureDragDownCallback? onHoldDragDown;
  GestureDragCancelCallback? onHoldDragCancel;
  GestureDragEndCallback? onHoldDragEnd;

  _HoldDragSequence? _sequence;
  bool _disposed = false;
  bool _finishing = false;

  @override
  bool isPointerAllowed(PointerDownEvent event) =>
      !_disposed && !_finishing && event.buttons == kPrimaryButton &&
      (onHoldDragStart != null || onHoldDragUpdate != null ||
          onHoldDragDown != null || onHoldDragCancel != null ||
          onHoldDragEnd != null) &&
      super.isPointerAllowed(event);

  @override
  void addAllowedPointer(PointerDownEvent event) {
    if (_disposed || _finishing) return;
    final sequence = _sequence;
    if (sequence == null) {
      _startFirstTap(event);
      return;
    }
    if (sequence.phase != _HoldDragPhase.waitingForSecond) {
      _finish(sequence);
      return;
    }
    if ((event.position - sequence.first.down.position).distance > kDoubleTapSlop) {
      return;
    }
    if (!sequence.minimumElapsed || event.kind != sequence.first.down.kind) {
      _finish(sequence);
      if (!_disposed && !_finishing && _sequence == null) _startFirstTap(event);
      return;
    }

    sequence.deadline?.cancel();
    final second = _track(event);
    sequence.second = second;
    sequence.phase = _HoldDragPhase.secondDown;
    _hold(second);
    sequence.deadline = Timer(kDoubleTapTimeout, () => _activate(sequence));
    final down = onHoldDragDown;
    if (down != null) {
      invokeCallback<void>('onHoldDragDown', () => down(DragDownDetails(
          globalPosition: event.position, localPosition: event.localPosition)));
    }
  }

  _HoldDragPointer _track(PointerDownEvent event) {
    final pointer = _HoldDragPointer(event,
        GestureBinding.instance.gestureArena.add(event.pointer, this));
    GestureBinding.instance.pointerRouter.addRoute(
        event.pointer, _handleEvent, event.transform);
    return pointer;
  }

  void _startFirstTap(PointerDownEvent event) {
    final sequence = _HoldDragSequence(_track(event));
    _sequence = sequence;
    sequence.minimumTimer = Timer(kDoubleTapMinTime, () {
      if (!identical(_sequence, sequence)) return;
      sequence.minimumTimer = null;
      sequence.minimumElapsed = true;
    });
  }

  void _hold(_HoldDragPointer pointer) {
    pointer.held = true;
    GestureBinding.instance.gestureArena.hold(pointer.down.pointer);
  }

  void _release(_HoldDragPointer pointer) {
    if (!pointer.held) return;
    pointer.held = false;
    GestureBinding.instance.gestureArena.release(pointer.down.pointer);
  }

  void _stopTracking(_HoldDragPointer pointer) {
    if (!pointer.tracking) return;
    pointer.tracking = false;
    GestureBinding.instance.pointerRouter.removeRoute(
        pointer.down.pointer, _handleEvent);
  }

  _HoldDragPointer? _find(_HoldDragSequence sequence, int pointer) {
    for (final candidate in sequence.pointers) {
      if (candidate.down.pointer == pointer) return candidate;
    }
    return null;
  }

  void _handleEvent(PointerEvent event) {
    final sequence = _sequence;
    if (sequence == null) return;
    final pointer = _find(sequence, event.pointer);
    if (pointer == null || !pointer.tracking) return;
    if (event is PointerCancelEvent) {
      _finish(sequence);
    } else if (event is PointerUpEvent) {
      if (sequence.phase == _HoldDragPhase.firstDown) {
        _hold(pointer);
        _stopTracking(pointer);
        sequence.phase = _HoldDragPhase.waitingForSecond;
        sequence.deadline = Timer(kDoubleTapTimeout, () => _finish(sequence));
      } else {
        _finish(sequence);
      }
    } else if (event is PointerMoveEvent) {
      if (event.buttons != pointer.down.buttons) {
        _finish(sequence);
        return;
      }
      final moved =
          (event.position - pointer.down.position).distance > kDoubleTapTouchSlop;
      if (sequence.phase == _HoldDragPhase.firstDown) {
        if (moved) _finish(sequence);
        return;
      }
      if (sequence.phase == _HoldDragPhase.secondDown && moved) {
        _activate(sequence);
      }
      if (!identical(_sequence, sequence) ||
          sequence.phase != _HoldDragPhase.dragging) return;
      final update = onHoldDragUpdate;
      if (update != null) {
        invokeCallback<void>('onHoldDragUpdate', () => update(DragUpdateDetails(
            sourceTimeStamp: event.timeStamp,
            globalPosition: event.position,
            localPosition: event.localPosition,
            delta: event.delta)));
      }
    }
  }

  void _activate(_HoldDragSequence sequence) {
    if (!identical(_sequence, sequence) ||
        sequence.phase != _HoldDragPhase.secondDown) return;
    sequence.cancelTimers();
    sequence.phase = _HoldDragPhase.resolving;
    for (final pointer in sequence.pointers) {
      if (!pointer.resolved) {
        pointer.resolved = true;
        pointer.entry.resolve(GestureDisposition.accepted);
      }
      if (!identical(_sequence, sequence)) return;
    }
    for (final pointer in sequence.pointers) {
      _release(pointer);
      if (!identical(_sequence, sequence)) return;
    }
    sequence.phase = _HoldDragPhase.dragging;
    final start = onHoldDragStart;
    if (start != null) {
      final down = sequence.second!.down;
      invokeCallback<void>('onHoldDragStart', () => start(DragStartDetails(
          sourceTimeStamp: down.timeStamp,
          kind: down.kind,
          globalPosition: down.position,
          localPosition: down.localPosition)));
    }
  }

  @override
  void acceptGesture(int pointer) {
    final sequence = _sequence;
    if (sequence != null) _find(sequence, pointer)?.resolved = true;
  }

  @override
  void rejectGesture(int pointer) {
    final sequence = _sequence;
    if (sequence == null) return;
    final rejected = _find(sequence, pointer);
    if (rejected == null) return;
    rejected.resolved = true;
    _finish(sequence);
  }

  void _finish(_HoldDragSequence sequence) {
    if (!identical(_sequence, sequence)) return;
    final dragging = sequence.phase == _HoldDragPhase.dragging;
    final pendingSecond = sequence.second != null;
    _finishing = true;
    _sequence = null;
    sequence.cancelTimers();
    final pointers = sequence.pointers;
    for (final pointer in pointers) {
      _stopTracking(pointer);
    }
    try {
      for (final pointer in pointers) {
        if (!pointer.resolved) {
          pointer.resolved = true;
          pointer.entry.resolve(GestureDisposition.rejected);
        }
      }
    } finally {
      for (final pointer in pointers) {
        _release(pointer);
      }
      _finishing = false;
    }
    if (dragging) {
      final end = onHoldDragEnd;
      if (end != null) {
        invokeCallback<void>('onHoldDragEnd', () => end(DragEndDetails()));
      }
    } else if (pendingSecond) {
      final cancel = onHoldDragCancel;
      if (cancel != null) invokeCallback<void>('onHoldDragCancel', cancel);
    }
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    final sequence = _sequence;
    if (sequence != null) _finish(sequence);
    super.dispose();
  }

  @override
  String get debugDescription => 'hold drag';
}

class DoubleFinerTapGestureRecognizer extends GestureRecognizer {
  DoubleFinerTapGestureRecognizer({
    Object? debugOwner,
    Set<PointerDeviceKind>? supportedDevices,
  }) : super(
          debugOwner: debugOwner,
          supportedDevices: supportedDevices,
        );

  GestureTapDownCallback? onDoubleFinerTapDown;
  GestureTapDownCallback? onDoubleFinerTap;
  GestureTapCancelCallback? onDoubleFinerTapCancel;

  Timer? _firstTapTimer;
  TapDownDetails? _pairDetails;
  final Set<int> _upTap = {};
  final Map<int, ({PointerDownEvent down, GestureArenaEntry entry})> _trackers = {};
  bool _finishing = false;
  bool _disposed = false;

  @override
  bool isPointerAllowed(PointerDownEvent event) =>
      !_disposed && event.buttons == kPrimaryButton &&
      (onDoubleFinerTapDown != null || onDoubleFinerTap != null ||
          onDoubleFinerTapCancel != null) &&
      super.isPointerAllowed(event);

  @override
  void addAllowedPointer(PointerDownEvent event) {
    if (_disposed || _finishing) return;
    if (_trackers.length == 2 ||
        (_trackers.isNotEmpty && _trackers.values.first.down.kind != event.kind)) {
      _finish(false);
      return;
    }
    if (_upTap.isNotEmpty) _finish(false);
    if (_disposed || _finishing) return;

    _trackers[event.pointer] = (
      down: event,
      entry: GestureBinding.instance.gestureArena.add(event.pointer, this),
    );
    GestureBinding.instance.gestureArena.hold(event.pointer);
    GestureBinding.instance.pointerRouter.addRoute(
        event.pointer, _handleEvent, event.transform);
    if (_trackers.length == 1) {
      _firstTapTimer = Timer(kDoubleTapTimeout, _timeoutCheck);
    } else {
      final details = TapDownDetails(
        globalPosition: event.position,
        localPosition: event.localPosition,
        kind: event.kind,
      );
      _pairDetails = details;
      final down = onDoubleFinerTapDown;
      if (down != null) {
        invokeCallback<void>('onDoubleFinerTapDown', () => down(details));
      }
    }
  }

  void _handleEvent(PointerEvent event) {
    final tracker = _trackers[event.pointer];
    if (tracker == null) return;
    if (event is PointerUpEvent) {
      GestureBinding.instance.pointerRouter.removeRoute(event.pointer, _handleEvent);
      _upTap.add(event.pointer);
      if (_trackers.length == 2 && _upTap.length == 2) _finish(true);
    } else if (event is PointerCancelEvent ||
        (event is PointerMoveEvent &&
            (event.position - tracker.down.position).distance > kDoubleTapTouchSlop)) {
      _finish(false);
    }
  }

  @override
  void acceptGesture(int pointer) {}

  @override
  void rejectGesture(int pointer) {
    if (_trackers.containsKey(pointer)) _finish(false);
  }

  void _timeoutCheck() {
    _finish(false);
  }

  void _finish(bool accepted) {
    if (_trackers.isEmpty) return;
    _finishing = true;
    final trackers = _trackers.values.toList(growable: false);
    final details = _pairDetails;
    _firstTapTimer?.cancel();
    _firstTapTimer = null;
    for (final tracker in trackers) {
      if (!_upTap.contains(tracker.down.pointer)) {
        GestureBinding.instance.pointerRouter.removeRoute(
            tracker.down.pointer, _handleEvent);
      }
    }
    _trackers.clear();
    _upTap.clear();
    _pairDetails = null;
    try {
      for (final tracker in trackers) {
        tracker.entry.resolve(accepted
            ? GestureDisposition.accepted : GestureDisposition.rejected);
      }
    } finally {
      for (final tracker in trackers) {
        GestureBinding.instance.gestureArena.release(tracker.down.pointer);
      }
      _finishing = false;
    }
    if (_disposed || details == null) return;
    final tap = onDoubleFinerTap;
    final cancel = onDoubleFinerTapCancel;
    if (accepted) {
      if (tap != null) invokeCallback<void>('onDoubleFinerTap', () => tap(details));
    } else if (cancel != null) {
      invokeCallback<void>('onDoubleFinerTapCancel', cancel);
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _finish(false);
    super.dispose();
  }

  @override
  String get debugDescription => 'two finger tap';
}

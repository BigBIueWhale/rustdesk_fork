import 'dart:async';
import 'package:flutter/gestures.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common/widgets/remote_input.dart';

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
  GestureDragCancelCallback? onOneFingerPanCancel;

  // twoFingerScale : scale + pan event
  GestureScaleStartCallback? onTwoFingerScaleStart;
  GestureScaleUpdateCallback? onTwoFingerScaleUpdate;
  GestureScaleEndCallback? onTwoFingerScaleEnd;

  // threeFingerVerticalDrag
  GestureDragStartCallback? onThreeFingerVerticalDragStart;
  GestureDragUpdateCallback? onThreeFingerVerticalDragUpdate;
  GestureDragEndCallback? onThreeFingerVerticalDragEnd;

  var _currentState = GestureState.none;
  Timer? _debounceTimer;

  void _init() {
    debugPrint("CustomTouchGestureRecognizer init");
    // onStart = (d) {};
    onUpdate = (d) {
      _debounceTimer?.cancel();
      if (d.pointerCount == 1 && _currentState != GestureState.oneFingerPan) {
        onOneFingerStartDebounce(d);
      } else if (d.pointerCount == 2 &&
          _currentState != GestureState.twoFingerScale) {
        onTwoFingerStartDebounce(d);
      } else if (d.pointerCount == 3 &&
          _currentState != GestureState.threeFingerVerticalDrag) {
        _currentState = GestureState.threeFingerVerticalDrag;
        if (onThreeFingerVerticalDragStart != null) {
          onThreeFingerVerticalDragStart!(
              DragStartDetails(globalPosition: d.localFocalPoint));
        }
        debugPrint("start threeFingerScale");
      }
      if (_currentState != GestureState.none) {
        switch (_currentState) {
          case GestureState.oneFingerPan:
            if (onOneFingerPanUpdate != null) {
              onOneFingerPanUpdate!(_getDragUpdateDetails(d));
            }
            break;
          case GestureState.twoFingerScale:
            if (onTwoFingerScaleUpdate != null) {
              onTwoFingerScaleUpdate!(d);
            }
            break;
          case GestureState.threeFingerVerticalDrag:
            if (onThreeFingerVerticalDragUpdate != null) {
              onThreeFingerVerticalDragUpdate!(_getDragUpdateDetails(d));
            }
            break;
          default:
            break;
        }
        return;
      }
    };
    onEnd = (d) {
      debugPrint("ScaleGestureRecognizer onEnd");
      _debounceTimer?.cancel();
      // end
      switch (_currentState) {
        case GestureState.oneFingerPan:
          debugPrint("OneFingerState.pan onEnd");
          if (onOneFingerPanEnd != null) {
            onOneFingerPanEnd!(_getDragEndDetails(d));
          }
          break;
        case GestureState.twoFingerScale:
          debugPrint("TwoFingerState.scale onEnd");
          if (onTwoFingerScaleEnd != null) {
            onTwoFingerScaleEnd!(d);
          }
          if (isSpecialHoldDragActive) {
            // If we are in special drag mode, we need to reset the state.
            // Otherwise, the next `onTwoFingerScaleUpdate()` will handle a wrong `focalPoint`.
            _currentState = GestureState.none;
            return;
          }
          break;
        case GestureState.threeFingerVerticalDrag:
          debugPrint("ThreeFingerState.vertical onEnd");
          if (onThreeFingerVerticalDragEnd != null) {
            onThreeFingerVerticalDragEnd!(_getDragEndDetails(d));
          }
          break;
        default:
          break;
      }
      _debounceTimer = Timer(Duration(milliseconds: 200), () {
        _currentState = GestureState.none;
      });
    };
  }

  // FIXME: This debounce logic is not working properly.
  // If we move our finger very fast, we won't be able to detect the "oneFingerPan" event sometimes.
  void onOneFingerStartDebounce(ScaleUpdateDetails d) {
    start(ScaleUpdateDetails d) {
      _currentState = GestureState.oneFingerPan;
      if (onOneFingerPanStart != null) {
        onOneFingerPanStart!(DragStartDetails(
            localPosition: d.localFocalPoint, globalPosition: d.focalPoint));
      }
    }

    if (_currentState != GestureState.none) {
      _debounceTimer = Timer(Duration(milliseconds: 200), () {
        start(d);
        debugPrint("debounce start oneFingerPan");
      });
    } else {
      start(d);
      debugPrint("start oneFingerPan");
    }
  }

  void onTwoFingerStartDebounce(ScaleUpdateDetails d) {
    start(ScaleUpdateDetails d) {
      _currentState = GestureState.twoFingerScale;
      if (onTwoFingerScaleStart != null) {
        onTwoFingerScaleStart!(ScaleStartDetails(
            localFocalPoint: d.localFocalPoint, focalPoint: d.focalPoint));
      }
    }

    if (_currentState == GestureState.threeFingerVerticalDrag) {
      _debounceTimer = Timer(Duration(milliseconds: 200), () {
        start(d);
        debugPrint("debounce start twoFingerScale");
      });
    } else {
      start(d);
      debugPrint("start twoFingerScale");
    }
  }

  DragUpdateDetails _getDragUpdateDetails(ScaleUpdateDetails d) =>
      DragUpdateDetails(
          globalPosition: d.focalPoint,
          localPosition: d.localFocalPoint,
          delta: d.focalPointDelta);

  DragEndDetails _getDragEndDetails(ScaleEndDetails d) =>
      DragEndDetails(velocity: d.velocity);

  @override
  void rejectGesture(int pointer) {
    super.rejectGesture(pointer);
    switch (_currentState) {
      case GestureState.oneFingerPan:
        if (onOneFingerPanCancel != null) {
          onOneFingerPanCancel!();
        }
        break;
      case GestureState.twoFingerScale:
        // Reset scale state if needed, currently self-contained
        break;
      case GestureState.threeFingerVerticalDrag:
        // Reset drag state if needed, currently self-contained
        break;
      default:
        break;
    }
    _currentState = GestureState.none;
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

  bool _isStart = false;

  Timer? _firstTapUpTimer;
  Timer? _secondTapDownTimer;
  _TapTracker? _firstTap;
  _TapTracker? _secondTap;

  PointerDownEvent? _lastPointerDownEvent;

  final Map<int, _TapTracker> _trackers = <int, _TapTracker>{};

  @override
  bool isPointerAllowed(PointerDownEvent event) {
    if (_firstTap == null) {
      switch (event.buttons) {
        case kPrimaryButton:
          if (onHoldDragStart == null &&
              onHoldDragUpdate == null &&
              onHoldDragCancel == null &&
              onHoldDragEnd == null) {
            return false;
          }
          break;
        default:
          return false;
      }
    }
    return super.isPointerAllowed(event);
  }

  @override
  void addAllowedPointer(PointerDownEvent event) {
    if (_firstTap != null) {
      if (!_firstTap!.isWithinGlobalTolerance(event, kDoubleTapSlop)) {
        // Ignore out-of-bounds second taps.
        return;
      } else if (!_firstTap!.hasElapsedMinTime() ||
          !_firstTap!.hasSameButton(event)) {
        // Restart when the second tap is too close to the first (touch screens
        // often detect touches intermittently), or when buttons mismatch.
        _reset();
        return _trackTap(event);
      } else if (onHoldDragDown != null) {
        invokeCallback<void>(
            'onHoldDragDown',
            () => onHoldDragDown!(DragDownDetails(
                globalPosition: event.position,
                localPosition: event.localPosition)));
      }
    }
    _trackTap(event);
  }

  void _trackTap(PointerDownEvent event) {
    _stopFirstTapUpTimer();
    _stopSecondTapDownTimer();
    final _TapTracker tracker = _TapTracker(
      event: event,
      entry: GestureBinding.instance.gestureArena.add(event.pointer, this),
      doubleTapMinTime: kDoubleTapMinTime,
      gestureSettings: gestureSettings,
    );
    _trackers[event.pointer] = tracker;
    _lastPointerDownEvent = event;
    tracker.startTrackingPointer(_handleEvent, event.transform);
  }

  void _handleEvent(PointerEvent event) {
    final _TapTracker tracker = _trackers[event.pointer]!;
    if (event is PointerUpEvent) {
      if (_firstTap == null && _secondTap == null) {
        _registerFirstTap(tracker);
      } else if (_secondTap != null) {
        if (event.pointer == _secondTap!.pointer) {
          if (onHoldDragEnd != null) {
            onHoldDragEnd!(DragEndDetails());
            _secondTap = null;
            _isStart = false;
          }
        }
      } else {
        _reject(tracker);
      }
    } else if (event is PointerDownEvent) {
      if (_firstTap != null && _secondTap == null) {
        _registerSecondTap(tracker);
      }
    } else if (event is PointerMoveEvent) {
      if (!tracker.isWithinGlobalTolerance(event, kDoubleTapTouchSlop)) {
        if (_firstTap != null && _firstTap!.pointer == event.pointer) {
          // first tap move
          _reject(tracker);
        } else if (_secondTap != null && _secondTap!.pointer == event.pointer) {
          // debugPrint("_secondTap move");
          // second tap move
          if (!_isStart) {
            _resolve();
          }
          if (onHoldDragUpdate != null) {
            onHoldDragUpdate!(DragUpdateDetails(
                globalPosition: event.position,
                localPosition: event.localPosition,
                delta: event.delta));
          }
        }
      }
    } else if (event is PointerCancelEvent) {
      _reject(tracker);
    }
  }

  @override
  void acceptGesture(int pointer) {}

  @override
  void rejectGesture(int pointer) {
    _TapTracker? tracker = _trackers[pointer];
    // If tracker isn't in the list, check if this is the first tap tracker
    if (tracker == null && _firstTap != null && _firstTap!.pointer == pointer) {
      tracker = _firstTap;
    }
    // If tracker is still null, we rejected ourselves already
    if (tracker != null) {
      _reject(tracker);
    }
  }

  void _resolve() {
    _stopSecondTapDownTimer();
    _firstTap?.entry.resolve(GestureDisposition.accepted);
    _secondTap?.entry.resolve(GestureDisposition.accepted);
    _isStart = true;
    // TODO start details
    if (onHoldDragStart != null) {
      onHoldDragStart!(DragStartDetails(
        kind: _lastPointerDownEvent?.kind,
      ));
    }
  }

  void _reject(_TapTracker tracker) {
    try {
      _checkCancel();
      _isStart = false;
      _trackers.remove(tracker.pointer);
      tracker.entry.resolve(GestureDisposition.rejected);
      _freezeTracker(tracker);
      _reset();
    } catch (e) {
      debugPrint("Failed to _reject:$e");
    }
  }

  @override
  void dispose() {
    _reset();
    super.dispose();
  }

  void _reset() {
    _isStart = false;
    // debugPrint("reset");
    _stopFirstTapUpTimer();
    _stopSecondTapDownTimer();
    if (_firstTap != null) {
      if (_trackers.isNotEmpty) {
        _checkCancel();
      }
      // Note, order is important below in order for the resolve -> reject logic
      // to work properly.
      final _TapTracker tracker = _firstTap!;
      _firstTap = null;
      _reject(tracker);
      GestureBinding.instance.gestureArena.release(tracker.pointer);

      if (_secondTap != null) {
        final _TapTracker tracker = _secondTap!;
        _secondTap = null;
        _reject(tracker);
        GestureBinding.instance.gestureArena.release(tracker.pointer);
      }
    }
    _firstTap = null;
    _secondTap = null;
    _clearTrackers();
  }

  void _registerFirstTap(_TapTracker tracker) {
    _startFirstTapUpTimer();
    GestureBinding.instance.gestureArena.hold(tracker.pointer);
    // Note, order is important below in order for the clear -> reject logic to
    // work properly.
    _freezeTracker(tracker);
    _trackers.remove(tracker.pointer);
    _firstTap = tracker;
  }

  void _registerSecondTap(_TapTracker tracker) {
    if (_firstTap != null) {
      _stopFirstTapUpTimer();
      _freezeTracker(_firstTap!);
      _firstTap = null;
    }

    _startSecondTapDownTimer();
    GestureBinding.instance.gestureArena.hold(tracker.pointer);

    _secondTap = tracker;

    // TODO
  }

  void _clearTrackers() {
    _trackers.values.toList().forEach(_reject);
    assert(_trackers.isEmpty);
  }

  void _freezeTracker(_TapTracker tracker) {
    tracker.stopTrackingPointer(_handleEvent);
  }

  void _startFirstTapUpTimer() {
    _firstTapUpTimer ??= Timer(kDoubleTapTimeout, _reset);
  }

  void _startSecondTapDownTimer() {
    _secondTapDownTimer ??= Timer(kDoubleTapTimeout, _resolve);
  }

  void _stopFirstTapUpTimer() {
    if (_firstTapUpTimer != null) {
      _firstTapUpTimer!.cancel();
      _firstTapUpTimer = null;
    }
  }

  void _stopSecondTapDownTimer() {
    if (_secondTapDownTimer != null) {
      _secondTapDownTimer!.cancel();
      _secondTapDownTimer = null;
    }
  }

  void _checkCancel() {
    if (onHoldDragCancel != null) {
      invokeCallback<void>('onHoldDragCancel', onHoldDragCancel!);
    }
  }

  @override
  String get debugDescription => 'double tap';
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
    _finish(_trackers.length == 2 && _upTap.length == 2);
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

/// TapTracker helps track individual tap sequences as part of a
/// larger gesture.
class _TapTracker {
  _TapTracker({
    required PointerDownEvent event,
    required this.entry,
    required Duration doubleTapMinTime,
    required this.gestureSettings,
  })  : pointer = event.pointer,
        _initialGlobalPosition = event.position,
        initialButtons = event.buttons,
        _doubleTapMinTimeCountdown =
            _CountdownZoned(duration: doubleTapMinTime);

  final DeviceGestureSettings? gestureSettings;
  final int pointer;
  final GestureArenaEntry entry;
  final Offset _initialGlobalPosition;
  final int initialButtons;
  final _CountdownZoned _doubleTapMinTimeCountdown;

  bool _isTrackingPointer = false;

  void startTrackingPointer(PointerRoute route, Matrix4? transform) {
    if (!_isTrackingPointer) {
      _isTrackingPointer = true;
      GestureBinding.instance.pointerRouter.addRoute(pointer, route, transform);
    }
  }

  void stopTrackingPointer(PointerRoute route) {
    if (_isTrackingPointer) {
      _isTrackingPointer = false;
      GestureBinding.instance.pointerRouter.removeRoute(pointer, route);
    }
  }

  bool isWithinGlobalTolerance(PointerEvent event, double tolerance) {
    final Offset offset = event.position - _initialGlobalPosition;
    return offset.distance <= tolerance;
  }

  bool hasElapsedMinTime() {
    return _doubleTapMinTimeCountdown.timeout;
  }

  bool hasSameButton(PointerDownEvent event) {
    return event.buttons == initialButtons;
  }
}

/// CountdownZoned tracks whether the specified duration has elapsed since
/// creation, honoring [Zone].
class _CountdownZoned {
  _CountdownZoned({required Duration duration}) {
    Timer(duration, _onTimeout);
  }

  bool _timeout = false;

  bool get timeout => _timeout;

  void _onTimeout() {
    _timeout = true;
  }
}

RawGestureDetector getMixinGestureDetector({
  Widget? child,
  GestureTapUpCallback? onTapUp,
  GestureTapDownCallback? onDoubleTapDown,
  GestureDoubleTapCallback? onDoubleTap,
  GestureLongPressDownCallback? onLongPressDown,
  GestureLongPressCallback? onLongPress,
  GestureDragStartCallback? onHoldDragStart,
  GestureDragUpdateCallback? onHoldDragUpdate,
  GestureDragCancelCallback? onHoldDragCancel,
  GestureDragEndCallback? onHoldDragEnd,
  GestureTapDownCallback? onDoubleFinerTap,
  GestureDragStartCallback? onOneFingerPanStart,
  GestureDragUpdateCallback? onOneFingerPanUpdate,
  GestureDragEndCallback? onOneFingerPanEnd,
  GestureDragCancelCallback? onOneFingerPanCancel,
  GestureScaleUpdateCallback? onTwoFingerScaleUpdate,
  GestureScaleEndCallback? onTwoFingerScaleEnd,
  GestureDragUpdateCallback? onThreeFingerVerticalDragUpdate,
}) {
  return RawGestureDetector(
      child: child,
      gestures: <Type, GestureRecognizerFactory>{
        // Official
        TapGestureRecognizer:
            GestureRecognizerFactoryWithHandlers<TapGestureRecognizer>(
                () => TapGestureRecognizer(), (instance) {
          instance.onTapUp = onTapUp;
        }),
        DoubleTapGestureRecognizer:
            GestureRecognizerFactoryWithHandlers<DoubleTapGestureRecognizer>(
                () => DoubleTapGestureRecognizer(), (instance) {
          instance
            ..onDoubleTapDown = onDoubleTapDown
            ..onDoubleTap = onDoubleTap;
        }),
        LongPressGestureRecognizer:
            GestureRecognizerFactoryWithHandlers<LongPressGestureRecognizer>(
                () => LongPressGestureRecognizer(), (instance) {
          instance
            ..onLongPressDown = onLongPressDown
            ..onLongPress = onLongPress;
        }),
        // Customized
        HoldTapMoveGestureRecognizer:
            GestureRecognizerFactoryWithHandlers<HoldTapMoveGestureRecognizer>(
                () => HoldTapMoveGestureRecognizer(),
                (instance) => instance
                  ..onHoldDragStart = onHoldDragStart
                  ..onHoldDragUpdate = onHoldDragUpdate
                  ..onHoldDragCancel = onHoldDragCancel
                  ..onHoldDragEnd = onHoldDragEnd),
        DoubleFinerTapGestureRecognizer: GestureRecognizerFactoryWithHandlers<
                DoubleFinerTapGestureRecognizer>(
            () => DoubleFinerTapGestureRecognizer(), (instance) {
          instance.onDoubleFinerTap = onDoubleFinerTap;
        }),
        CustomTouchGestureRecognizer:
            GestureRecognizerFactoryWithHandlers<CustomTouchGestureRecognizer>(
                () => CustomTouchGestureRecognizer(), (instance) {
          instance
            ..onOneFingerPanStart = onOneFingerPanStart
            ..onOneFingerPanUpdate = onOneFingerPanUpdate
            ..onOneFingerPanEnd = onOneFingerPanEnd
            ..onOneFingerPanCancel = onOneFingerPanCancel
            ..onTwoFingerScaleUpdate = onTwoFingerScaleUpdate
            ..onTwoFingerScaleEnd = onTwoFingerScaleEnd
            ..onThreeFingerVerticalDragUpdate = onThreeFingerVerticalDragUpdate;
        }),
      });
}

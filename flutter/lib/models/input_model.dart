import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'dart:ui' as ui;

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/main.dart';
import 'package:flutter_hbb/utils/multi_window_manager.dart';
import 'package:get/get.dart';

import '../../models/model.dart';
import '../../models/platform_model.dart';
import '../../models/state_model.dart';
import 'input_modifier_utils.dart';
import 'flutter_keyboard_input.dart';
import 'relative_mouse_model.dart';
import 'reverse_mouse_wheel.dart';
import '../common.dart';
import '../consts.dart';

/// Mouse button enum.
enum MouseButtons { left, right, wheel, back, forward }

const _kMouseEventDown = 'mousedown';
const _kMouseEventUp = 'mouseup';
const _kMouseEventMove = 'mousemove';

class CanvasCoords {
  double x = 0;
  double y = 0;
  double scale = 1.0;
  double scrollX = 0;
  double scrollY = 0;
  ScrollStyle scrollStyle = ScrollStyle.scrollauto;
  Size size = Size.zero;

  CanvasCoords();

  Map<String, dynamic> toJson() {
    return {
      'x': x,
      'y': y,
      'scale': scale,
      'scrollX': scrollX,
      'scrollY': scrollY,
      'scrollStyle': scrollStyle.toJson(),
      'size': {
        'w': size.width,
        'h': size.height,
      }
    };
  }

  static CanvasCoords fromJson(Map<String, dynamic> json) {
    final model = CanvasCoords();
    model.x = json['x'];
    model.y = json['y'];
    model.scale = json['scale'];
    model.scrollX = json['scrollX'];
    model.scrollY = json['scrollY'];
    model.scrollStyle =
        ScrollStyle.fromJson(json['scrollStyle'], ScrollStyle.scrollauto);
    model.size = Size(json['size']['w'], json['size']['h']);
    return model;
  }

  static CanvasCoords fromCanvasModel(CanvasModel model) {
    final coords = CanvasCoords();
    coords.x = model.x;
    coords.y = model.y;
    coords.scale = model.scale;
    coords.scrollX = model.scrollX;
    coords.scrollY = model.scrollY;
    coords.scrollStyle = model.scrollStyle;
    coords.size = model.size;
    return coords;
  }
}

class CursorCoords {
  Offset offset = Offset.zero;

  CursorCoords();

  Map<String, dynamic> toJson() {
    return {
      'offset_x': offset.dx,
      'offset_y': offset.dy,
    };
  }

  static CursorCoords fromJson(Map<String, dynamic> json) {
    final model = CursorCoords();
    model.offset = Offset(json['offset_x'], json['offset_y']);
    return model;
  }

  static CursorCoords fromCursorModel(CursorModel model) {
    final coords = CursorCoords();
    coords.offset = model.offset;
    return coords;
  }
}

class RemoteWindowCoords {
  RemoteWindowCoords(
      this.windowRect, this.canvas, this.cursor, this.remoteRect);
  Rect windowRect;
  CanvasCoords canvas;
  CursorCoords cursor;
  Rect remoteRect;
  Offset relativeOffset = Offset.zero;

  Map<String, dynamic> toJson() {
    return {
      'canvas': canvas.toJson(),
      'cursor': cursor.toJson(),
      'windowRect': rectToJson(windowRect),
      'remoteRect': rectToJson(remoteRect),
    };
  }

  static Map<String, dynamic> rectToJson(Rect r) {
    return {
      'l': r.left,
      't': r.top,
      'w': r.width,
      'h': r.height,
    };
  }

  static Rect rectFromJson(Map<String, dynamic> json) {
    return Rect.fromLTWH(
      json['l'],
      json['t'],
      json['w'],
      json['h'],
    );
  }

  RemoteWindowCoords.fromJson(Map<String, dynamic> json)
      : windowRect = rectFromJson(json['windowRect']),
        canvas = CanvasCoords.fromJson(json['canvas']),
        cursor = CursorCoords.fromJson(json['cursor']),
        remoteRect = rectFromJson(json['remoteRect']);
}

extension ToString on MouseButtons {
  String get value {
    switch (this) {
      case MouseButtons.left:
        return 'left';
      case MouseButtons.right:
        return 'right';
      case MouseButtons.wheel:
        return 'wheel';
      case MouseButtons.back:
        return 'back';
      case MouseButtons.forward:
        return 'forward';
    }
  }
}

class PointerEventToRust {
  final String kind;
  final String type;
  final dynamic value;

  PointerEventToRust(this.kind, this.type, this.value);

  Map<String, dynamic> toJson() {
    return {
      'k': kind,
      'v': {
        't': type,
        'v': value,
      }
    };
  }
}

class ToReleaseRawKeys {
  RawKeyEvent? lastLShiftKeyEvent;
  RawKeyEvent? lastRShiftKeyEvent;
  RawKeyEvent? lastLCtrlKeyEvent;
  RawKeyEvent? lastRCtrlKeyEvent;
  RawKeyEvent? lastLAltKeyEvent;
  RawKeyEvent? lastRAltKeyEvent;
  RawKeyEvent? lastLCommandKeyEvent;
  RawKeyEvent? lastRCommandKeyEvent;
  RawKeyEvent? lastSuperKeyEvent;

  reset() {
    lastLShiftKeyEvent = null;
    lastRShiftKeyEvent = null;
    lastLCtrlKeyEvent = null;
    lastRCtrlKeyEvent = null;
    lastLAltKeyEvent = null;
    lastRAltKeyEvent = null;
    lastLCommandKeyEvent = null;
    lastRCommandKeyEvent = null;
    lastSuperKeyEvent = null;
  }

  updateKeyDown(LogicalKeyboardKey logicKey, RawKeyDownEvent e) {
    if (logicKey == LogicalKeyboardKey.altLeft) {
      lastLAltKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.altRight) {
      lastRAltKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.controlLeft) {
      lastLCtrlKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.controlRight) {
      lastRCtrlKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.shiftLeft) {
      lastLShiftKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.shiftRight) {
      lastRShiftKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.metaLeft) {
      lastLCommandKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.metaRight) {
      lastRCommandKeyEvent = e;
    } else if (logicKey == LogicalKeyboardKey.superKey) {
      lastSuperKeyEvent = e;
    }
  }

  updateKeyUp(LogicalKeyboardKey logicKey, RawKeyUpEvent e) {
    if (logicKey == LogicalKeyboardKey.altLeft) {
      lastLAltKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.altRight) {
      lastRAltKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.controlLeft) {
      lastLCtrlKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.controlRight) {
      lastRCtrlKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.shiftLeft) {
      lastLShiftKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.shiftRight) {
      lastRShiftKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.metaLeft) {
      lastLCommandKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.metaRight) {
      lastRCommandKeyEvent = null;
    } else if (logicKey == LogicalKeyboardKey.superKey) {
      lastSuperKeyEvent = null;
    }
  }

  release(KeyEventResult Function(RawKeyEvent e) handleRawKeyEvent) {
    for (final key in [
      lastLShiftKeyEvent,
      lastRShiftKeyEvent,
      lastLCtrlKeyEvent,
      lastRCtrlKeyEvent,
      lastLAltKeyEvent,
      lastRAltKeyEvent,
      lastLCommandKeyEvent,
      lastRCommandKeyEvent,
      lastSuperKeyEvent,
    ]) {
      if (key != null) {
        handleRawKeyEvent(RawKeyUpEvent(
          data: key.data,
          character: key.character,
        ));
      }
    }
  }
}

class ToReleaseKeys {
  KeyEvent? lastLShiftKeyEvent;
  KeyEvent? lastRShiftKeyEvent;
  KeyEvent? lastLCtrlKeyEvent;
  KeyEvent? lastRCtrlKeyEvent;
  KeyEvent? lastLAltKeyEvent;
  KeyEvent? lastRAltKeyEvent;
  KeyEvent? lastLCommandKeyEvent;
  KeyEvent? lastRCommandKeyEvent;
  KeyEvent? lastSuperKeyEvent;

  reset() {
    lastLShiftKeyEvent = null;
    lastRShiftKeyEvent = null;
    lastLCtrlKeyEvent = null;
    lastRCtrlKeyEvent = null;
    lastLAltKeyEvent = null;
    lastRAltKeyEvent = null;
    lastLCommandKeyEvent = null;
    lastRCommandKeyEvent = null;
    lastSuperKeyEvent = null;
  }

  release(KeyEventResult Function(KeyEvent e) handleKeyEvent) {
    for (final key in [
      lastLShiftKeyEvent,
      lastRShiftKeyEvent,
      lastLCtrlKeyEvent,
      lastRCtrlKeyEvent,
      lastLAltKeyEvent,
      lastRAltKeyEvent,
      lastLCommandKeyEvent,
      lastRCommandKeyEvent,
      lastSuperKeyEvent,
    ]) {
      if (key != null) {
        handleKeyEvent(key);
      }
    }
  }
}

class _TrackpadGesture {
  _TrackpadGesture(this.sessionId, this.clientOwnerId, PointerPanZoomStartEvent e)
      : pointer = e.pointer,
        device = e.device,
        viewId = e.viewId;

  final SessionID sessionId;
  final SessionID clientOwnerId;
  final int pointer;
  final int device;
  final int viewId;
  double scale = 1.0;
  Offset lastDelta = Offset.zero;

  bool matches(PointerEvent e) =>
      pointer == e.pointer && device == e.device && viewId == e.viewId;
}

class _TrackpadFling {
  _TrackpadFling(this.sessionId, this.clientOwnerId, this.x, this.y);

  final SessionID sessionId;
  final SessionID clientOwnerId;
  double x;
  double y;
  Timer? timer;
}

class InputModel {
  late final reverseMouseWheel = ReverseMouseWheelPreferences(parent);

  // Side mouse button support for Linux.
  // Flutter's Linux embedder drops X11 button 8/9 events, so we capture them
  // natively via GDK and forward through the platform channel.
  static InputModel? _activeSideButtonModel;
  // Tracks per-button which model received a side button down event, so the
  // matching up event is routed there even if the pointer has left the view
  // or a different button was pressed in between.
  static final Map<MouseButtons, InputModel> _sideButtonDownModels = {};
  static bool _sideButtonChannelInitialized = false;

  /// Each Flutter engine (main window + sub-windows from desktop_multi_window)
  /// runs its own Dart isolate with its own statics. Called from initEnv()
  /// which runs per-engine, so each isolate registers its own handler tied
  /// to its own set of InputModels.
  static void initSideButtonChannel() {
    if (!isLinux) return;
    if (_sideButtonChannelInitialized) return;
    _sideButtonChannelInitialized = true;

    const channel = MethodChannel('org.rustdesk.rustdesk/side_buttons');
    channel.setMethodCallHandler((call) async {
      if (call.method == 'onSideMouseButton') {
        final args = call.arguments as Map<dynamic, dynamic>;
        final button = args['button'] as String;
        final type = args['type'] as String;
        final mb = button == 'back' ? MouseButtons.back : MouseButtons.forward;

        if (type == 'down') {
          final model = _activeSideButtonModel;
          if (model != null &&
              !(model.isViewOnly && !model.showMyCursor) &&
              model.keyboardPerm &&
              !model.isViewCamera) {
            _sideButtonDownModels[mb] = model;
            // Fire-and-forget to avoid blocking the platform channel handler.
            unawaited(
                model.sendSideMouseButton(type, mb,
                    expectedSessionId: model.sessionId).catchError((Object e) {
              debugPrint(
                  '[InputModel] failed to send side button $type for $mb: $e');
            }));
          }
        } else {
          // Only route 'up' when we recorded the matching 'down';
          // dropping avoids sending unpaired 'up' to an unrelated session.
          // Use _sendMouseUnchecked to bypass permission checks so the
          // release always goes through even if permissions changed.
          final model = _sideButtonDownModels.remove(mb);
          if (model != null) {
            unawaited(
                model.sendSideMouseButton(type, mb,
                    expectedSessionId: model.sessionId).catchError((Object e) {
              debugPrint(
                  '[InputModel] failed to send side button $type for $mb: $e');
            }));
          }
        }
      }
      return null;
    });
  }

  /// Clear any static references to this model (prevents stale routing).
  /// Releases any held side buttons on the peer so closing a session
  /// mid-press does not leave a stuck button.
  void disposeSideButtonTracking({SessionID? expectedSessionId}) {
    if (_activeSideButtonModel == this) _activeSideButtonModel = null;
    final held = _sideButtonDownModels.entries
        .where((e) => e.value == this)
        .map((e) => e.key)
        .toList();
    for (final mb in held) {
      _sideButtonDownModels.remove(mb);
      // Best-effort release; session may already be tearing down.
      unawaited(
          sendSideMouseButton('up', mb,
              expectedSessionId: expectedSessionId ?? sessionId)
              .catchError((Object e) {
        debugPrint('[InputModel] failed to release side button $mb: $e');
      }));
    }
  }

  final WeakReference<FFI> parent;
  late final FlutterKeyboardInput _keyboardInput;
  String keyboardMode = '';
  int _keyboardModeReadGeneration = 0;

  // keyboard
  var shift = false;
  var ctrl = false;
  var alt = false;
  var command = false;

  final ToReleaseRawKeys toReleaseRawKeys = ToReleaseRawKeys();
  final ToReleaseKeys toReleaseKeys = ToReleaseKeys();

  // trackpad
  _TrackpadGesture? _trackpadGesture;
  _TrackpadFling? _trackpadFling;
  bool _trackpadDisposed = false;
  bool _flingSendPending = false;
  final _flingBaseDelay = 30;
  final _trackpadAdjustPeerLinux = 0.06;
  // This is an experience value.
  final _trackpadAdjustMacToWin = 2.50;
  // Ignore directional locking for very small deltas on both axes (including
  // tiny single-axis movement) to avoid over-filtering near zero.
  static const double _trackpadAxisNoiseThreshold = 0.2;
  // Lock to dominant axis only when one axis is clearly stronger.
  // 1.6 means the dominant axis must be >= 60% larger than the other.
  static const double _trackpadAxisLockRatio = 1.6;
  int _trackpadSpeed = kDefaultTrackpadSpeed;
  double _trackpadSpeedInner = kDefaultTrackpadSpeed / 100.0;
  bool _savingTrackpadSpeed = false;
  int _trackpadSpeedRevision = 0;
  int _trackpadReadGeneration = 0;
  var _trackpadScrollUnsent = Offset.zero;
  ({SessionID sessionId, SessionID clientOwnerId})? _trackpadScrollOwner;

  // Mobile relative mouse delta accumulators (for slow/fine movements).
  double _mobileDeltaRemainderX = 0.0;
  double _mobileDeltaRemainderY = 0.0;

  bool _pointerMovedAfterEnter = false;
  bool _pointerInsideImage = false;

  // mouse
  final isPhysicalMouse = false.obs;
  int _lastButtons = 0;
  Offset lastMousePos = Offset.zero;
  int _lastWheelTsUs = 0;

  // Wheel acceleration thresholds.
  static const int _wheelAccelFastThresholdUs = 40000; // 40ms
  static const int _wheelAccelMediumThresholdUs = 80000; // 80ms
  static const double _wheelBurstVelocityThreshold =
      0.002; // delta units per microsecond
  // Wheel burst acceleration (empirical tuning).
  // Applies only to fast, non-smooth bursts to preserve single-step scrolling.
  // Flutter uses microseconds for dt, so velocity is in delta/us.

  // Relative mouse mode (for games/3D apps).
  final relativeMouseMode = false.obs;
  late final RelativeMouseModel _relativeMouse;
  // Callback to cancel external throttle timer when relative mouse mode is disabled.
  VoidCallback? onRelativeMouseModeDisabled;
  // Disposer for the relativeMouseMode observer (to prevent memory leaks).
  Worker? _relativeMouseModeDisposer;

  bool _queryOtherWindowCoords = false;
  Rect? _windowRect;
  List<RemoteWindowCoords> _remoteWindowCoords = [];

  SessionID get sessionId => parent.target!.sessionId;

  // Local gate for clipboard-assisted input flows on mobile Wayland dialogs.
  // It should not block physical keyboard events.
  bool keyboardInputAllowed = true;

  bool get keyboardPerm => parent.target!.ffiModel.keyboard;
  String get id => parent.target?.id ?? '';
  String? get peerPlatform => parent.target?.ffiModel.pi.platform;
  String get peerVersion => parent.target?.ffiModel.pi.version ?? '';
  bool get isViewOnly => parent.target!.ffiModel.viewOnly;
  bool get showMyCursor => parent.target!.ffiModel.showMyCursor;
  double get devicePixelRatio => parent.target!.canvasModel.devicePixelRatio;
  bool get isViewCamera => parent.target!.connType == ConnType.viewCamera;
  int get trackpadSpeed => _trackpadSpeed;
  bool get useEdgeScroll =>
      parent.target!.canvasModel.scrollStyle == ScrollStyle.scrolledge;

  /// Check if the connected server supports relative mouse mode.
  bool get isRelativeMouseModeSupported => _relativeMouse.isSupported;

  InputModel(this.parent, {FlutterKeyboardInputBackend? keyboardBackend}) {
    _keyboardInput = FlutterKeyboardInput(
        parent, keyboardBackend ?? const NativeFlutterKeyboardInputBackend());
    initSideButtonChannel();
    _relativeMouse = RelativeMouseModel(
      getSessionId: () => sessionId,
      enabled: relativeMouseMode,
      keyboardPerm: () => keyboardPerm,
      isViewCamera: () => isViewCamera,
      peerVersion: () => peerVersion,
      peerPlatform: () => peerPlatform,
      modify: (msg) => modify(msg),
      getPointerInsideImage: () => _pointerInsideImage,
      setPointerInsideImage: (inside) => _pointerInsideImage = inside,
    );
    _relativeMouse.onDisabled = () => onRelativeMouseModeDisabled?.call();

    // Sync relative mouse mode state to global state for UI components (e.g., tab bar hint).
    _relativeMouseModeDisposer = ever(relativeMouseMode, (bool value) {
      final peerId = id;
      if (peerId.isNotEmpty) {
        stateGlobal.relativeMouseModeState[peerId] = value;
      }
    });
  }

  // https://github.com/flutter/flutter/issues/157241
  // Infer CapsLock state from the character output.
  // This is needed because Flutter's HardwareKeyboard.lockModesEnabled may report
  // incorrect CapsLock state on iOS.
  bool _getIosCapsFromCharacter(KeyEvent e) {
    if (!isIOS) return false;
    final ch = e.character;
    return _getIosCapsFromCharacterImpl(
        ch, HardwareKeyboard.instance.isShiftPressed);
  }

  // RawKeyEvent version of _getIosCapsFromCharacter.
  bool _getIosCapsFromRawCharacter(RawKeyEvent e) {
    if (!isIOS) return false;
    final ch = e.character;
    return _getIosCapsFromCharacterImpl(ch, e.isShiftPressed);
  }

  // Shared implementation for inferring CapsLock state from character.
  // Uses Unicode-aware case detection to support non-ASCII letters (e.g., ü/Ü, é/É).
  //
  // Limitations:
  // 1. This inference assumes the client and server use the same keyboard layout.
  //    If layouts differ (e.g., client uses EN, server uses DE), the character output
  //    may not match expectations. For example, ';' on EN layout maps to 'ö' on DE
  //    layout, making it impossible to correctly infer CapsLock state from the
  //    character alone.
  // 2. On iOS, CapsLock+Shift produces uppercase letters (unlike desktop where it
  //    produces lowercase). This method cannot handle that case correctly.
  bool _getIosCapsFromCharacterImpl(String? ch, bool shiftPressed) {
    if (ch == null || ch.length != 1) return false;
    // Use Dart's built-in Unicode-aware case detection
    final upper = ch.toUpperCase();
    final lower = ch.toLowerCase();
    final isUpper = upper == ch && lower != ch;
    final isLower = lower == ch && upper != ch;
    // Skip non-letter characters (e.g., numbers, symbols, CJK characters without case)
    if (!isUpper && !isLower) return false;
    return isUpper != shiftPressed;
  }

  int _buildLockModes(bool iosCapsLock) {
    const capslock = 1;
    const numlock = 2;
    const scrolllock = 3;
    int lockModes = 0;
    if (isIOS) {
      if (iosCapsLock) {
        lockModes |= (1 << capslock);
      }
      // Ignore "NumLock/ScrollLock" on iOS for now.
    } else {
      if (HardwareKeyboard.instance.lockModesEnabled
          .contains(KeyboardLockMode.capsLock)) {
        lockModes |= (1 << capslock);
      }
      if (HardwareKeyboard.instance.lockModesEnabled
          .contains(KeyboardLockMode.numLock)) {
        lockModes |= (1 << numlock);
      }
      if (HardwareKeyboard.instance.lockModesEnabled
          .contains(KeyboardLockMode.scrollLock)) {
        lockModes |= (1 << scrolllock);
      }
    }
    return lockModes;
  }

  // This function must be called after the peer info is received.
  // Because `sessionGetKeyboardMode` relies on the peer version.
  Future<bool> updateKeyboardMode() async {
    if (!isDesktop && !isWebDesktop) return false;
    final owner = parent.target;
    if (owner == null) return false;
    final expectedSession = owner.sessionId;
    final expectedClient = owner.clientOwnerId;
    return refreshKeyboardMode(
      readMode: () => bind.sessionGetKeyboardMode(sessionId: expectedSession),
      supportsMode: (mode) => bind.sessionIsKeyboardModeSupported(
          sessionId: expectedSession, mode: mode),
      useFlutterInput: () => isDesktop && isInputSourceFlutter,
      isCurrent: () => owner.isCurrentSessionOwner(expectedSession, expectedClient),
    );
  }

  Future<bool> refreshKeyboardMode({
    required Future<String?> Function() readMode,
    required bool Function(String) supportsMode,
    required bool Function() useFlutterInput,
    required bool Function() isCurrent,
  }) async {
    if (!isCurrent()) return false;
    final generation = ++_keyboardModeReadGeneration;
    try {
      final flutterInput = useFlutterInput();
      final mode = flutterInput
          ? [kKeyMapMode, kKeyLegacyMode].firstWhere(supportsMode,
              orElse: () => kKeyLegacyMode)
          : await readMode() ?? kKeyLegacyMode;
      if (!isCurrent() || generation != _keyboardModeReadGeneration ||
          flutterInput != useFlutterInput()) return false;
      if (![kKeyLegacyMode, kKeyMapMode, kKeyTranslateMode, 'auto']
          .contains(mode)) throw StateError('Invalid keyboard mode readback');
      keyboardMode = mode;
      return true;
    } catch (error) {
      debugPrint('Failed to refresh keyboard mode: $error');
      return false;
    }
  }

  void retireKeyboardMode() {
    _keyboardModeReadGeneration++;
    keyboardMode = '';
  }

  /// Updates the trackpad speed based on the session value.
  ///
  /// The retrieved value is an integer percentage.
  /// If unavailable or out of bounds (less than `kMinTrackpadSpeed` or greater
  /// than `kMaxTrackpadSpeed`), the trackpad speed is reset to the default
  /// value (`kDefaultTrackpadSpeed`).
  ///
  /// Bounds:
  /// - Minimum: `kMinTrackpadSpeed`
  /// - Maximum: `kMaxTrackpadSpeed`
  /// - Default: `kDefaultTrackpadSpeed`
  Future<void> updateTrackpadSpeed() async {
    final owner = parent.target;
    if (owner == null) return;
    final expectedSession = owner.sessionId;
    final expectedClient = owner.clientOwnerId;
    await refreshTrackpadSpeed(
        readSpeed: () => bind.sessionGetTrackpadSpeed(sessionId: expectedSession),
        isCurrent: () => owner.isCurrentSessionOwner(expectedSession, expectedClient));
  }

  Future<void> refreshTrackpadSpeed({
    required Future<int?> Function() readSpeed,
    required bool Function() isCurrent,
  }) async {
    if (!isCurrent()) return;
    final generation = ++_trackpadReadGeneration;
    final revision = _trackpadSpeedRevision;
    final speed =
        (await readSpeed() ?? kDefaultTrackpadSpeed);
    if (!isCurrent() || generation != _trackpadReadGeneration ||
        revision != _trackpadSpeedRevision) return;
    applyTrackpadSpeed(speed >= kMinTrackpadSpeed && speed <= kMaxTrackpadSpeed
        ? speed : kDefaultTrackpadSpeed);
  }

  void applyTrackpadSpeed(int speed) {
    RangeError.checkValueInInterval(speed, kMinTrackpadSpeed, kMaxTrackpadSpeed);
    _trackpadSpeedRevision++;
    _trackpadSpeed = speed;
    _trackpadSpeedInner = _trackpadSpeed / 100.0;
  }

  Future<int?> saveTrackpadSpeed(int speed, {
    required Future<int> Function(int) writeSpeed,
    required bool Function() isCurrent,
  }) async {
    if (_savingTrackpadSpeed || !isCurrent()) return null;
    RangeError.checkValueInInterval(speed, kMinTrackpadSpeed, kMaxTrackpadSpeed);
    _savingTrackpadSpeed = true;
    try {
      final effective = await writeSpeed(speed);
      if (!isCurrent() || effective != speed) return null;
      applyTrackpadSpeed(effective);
      return effective;
    } finally {
      _savingTrackpadSpeed = false;
    }
  }

  void handleKeyDownEventModifiers(KeyEvent e) {
    KeyUpEvent upEvent(e) => KeyUpEvent(
          physicalKey: e.physicalKey,
          logicalKey: e.logicalKey,
          timeStamp: e.timeStamp,
        );
    if (e.logicalKey == LogicalKeyboardKey.altLeft) {
      if (!alt) {
        alt = true;
      }
      toReleaseKeys.lastLAltKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.altRight) {
      if (!alt) {
        alt = true;
      }
      toReleaseKeys.lastRAltKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.controlLeft) {
      if (!ctrl) {
        ctrl = true;
      }
      toReleaseKeys.lastLCtrlKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.controlRight) {
      if (!ctrl) {
        ctrl = true;
      }
      toReleaseKeys.lastRCtrlKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.shiftLeft) {
      if (!shift) {
        shift = true;
      }
      toReleaseKeys.lastLShiftKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.shiftRight) {
      if (!shift) {
        shift = true;
      }
      toReleaseKeys.lastRShiftKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.metaLeft) {
      if (!command) {
        command = true;
      }
      toReleaseKeys.lastLCommandKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.metaRight) {
      if (!command) {
        command = true;
      }
      toReleaseKeys.lastRCommandKeyEvent = upEvent(e);
    } else if (e.logicalKey == LogicalKeyboardKey.superKey) {
      if (!command) {
        command = true;
      }
      toReleaseKeys.lastSuperKeyEvent = upEvent(e);
    }
  }

  void handleKeyUpEventModifiers(KeyEvent e) {
    if (e.logicalKey == LogicalKeyboardKey.altLeft) {
      alt = toReleaseKeys.lastRAltKeyEvent != null;
      toReleaseKeys.lastLAltKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.altRight) {
      alt = toReleaseKeys.lastLAltKeyEvent != null;
      toReleaseKeys.lastRAltKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.controlLeft) {
      ctrl = toReleaseKeys.lastRCtrlKeyEvent != null;
      toReleaseKeys.lastLCtrlKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.controlRight) {
      ctrl = toReleaseKeys.lastLCtrlKeyEvent != null;
      toReleaseKeys.lastRCtrlKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.shiftLeft) {
      shift = toReleaseKeys.lastRShiftKeyEvent != null;
      toReleaseKeys.lastLShiftKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.shiftRight) {
      shift = toReleaseKeys.lastLShiftKeyEvent != null;
      toReleaseKeys.lastRShiftKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.metaLeft) {
      command = toReleaseKeys.lastRCommandKeyEvent != null ||
          toReleaseKeys.lastSuperKeyEvent != null;
      toReleaseKeys.lastLCommandKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.metaRight) {
      command = toReleaseKeys.lastLCommandKeyEvent != null ||
          toReleaseKeys.lastSuperKeyEvent != null;
      toReleaseKeys.lastRCommandKeyEvent = null;
    } else if (e.logicalKey == LogicalKeyboardKey.superKey) {
      command = toReleaseKeys.lastLCommandKeyEvent != null ||
          toReleaseKeys.lastRCommandKeyEvent != null;
      toReleaseKeys.lastSuperKeyEvent = null;
    }
  }

  // Safe: this only re-dispatches synthesized Shift key-up events.
  // The key-up path clears the tracked Shift state so this does not loop.
  void _releaseTrackedShiftKeyEventIfNeeded() {
    final leftShift = toReleaseKeys.lastLShiftKeyEvent;
    final rightShift = toReleaseKeys.lastRShiftKeyEvent;
    if (leftShift != null) {
      handleKeyEvent(leftShift);
    }
    if (rightShift != null) {
      handleKeyEvent(rightShift);
    }
  }

  // Safe: this only re-dispatches synthesized Shift key-up events.
  // The raw key-up path clears the tracked Shift state so this does not loop.
  void _releaseTrackedRawShiftKeyEventIfNeeded() {
    final leftShift = toReleaseRawKeys.lastLShiftKeyEvent;
    final rightShift = toReleaseRawKeys.lastRShiftKeyEvent;
    if (leftShift != null) {
      handleRawKeyEvent(RawKeyUpEvent(
        data: leftShift.data,
        character: leftShift.character,
      ));
    }
    if (rightShift != null) {
      handleRawKeyEvent(RawKeyUpEvent(
        data: rightShift.data,
        character: rightShift.character,
      ));
    }
  }

  KeyEventResult handleRawKeyEvent(RawKeyEvent e) {
    final modifierSlot = flutterModifierSlot(e.logicalKey);
    if (e is RawKeyUpEvent && modifierSlot != null) {
      _clearTrackedModifier(modifierSlot);
      _keyboardInput.releaseSlot(modifierSlot);
      return KeyEventResult.handled;
    }
    if (!keyboardPerm || isViewOnly || !_keyboardInput.backend.useFlutterInput) {
      releaseHeldModifiers();
    }
    if (!keyboardPerm || !_keyboardInput.ready) return KeyEventResult.handled;
    if (isViewOnly) return KeyEventResult.handled;
    if (isViewCamera) return KeyEventResult.handled;
    if (!_keyboardInput.backend.useFlutterInput) {
      if (isDesktop) {
        return KeyEventResult.handled;
      } else if (isWeb) {
        return KeyEventResult.ignored;
      }
    }

    if (_relativeMouse.handleRawKeyEvent(e)) {
      return KeyEventResult.handled;
    }

    bool iosCapsLock = false;
    if (isIOS && e is RawKeyDownEvent) {
      iosCapsLock = _getIosCapsFromRawCharacter(e);
    }

    final key = e.logicalKey;
    if (e is RawKeyDownEvent) {
      if (!e.repeat) {
        if (e.isAltPressed && !alt) {
          alt = true;
        }
        if (e.isControlPressed && !ctrl) {
          ctrl = true;
        }
        if (e.isShiftPressed && !shift) {
          shift = true;
        }
        if ((e.isMetaPressed || key == LogicalKeyboardKey.superKey) &&
            !command) {
          command = true;
        }
      }
      toReleaseRawKeys.updateKeyDown(key, e);
    }
    if (e is RawKeyUpEvent) {
      toReleaseRawKeys.updateKeyUp(key, e);
      if (key == LogicalKeyboardKey.altLeft ||
          key == LogicalKeyboardKey.altRight) {
        alt = toReleaseRawKeys.lastLAltKeyEvent != null ||
            toReleaseRawKeys.lastRAltKeyEvent != null;
      } else if (key == LogicalKeyboardKey.controlLeft ||
          key == LogicalKeyboardKey.controlRight) {
        ctrl = toReleaseRawKeys.lastLCtrlKeyEvent != null ||
            toReleaseRawKeys.lastRCtrlKeyEvent != null;
      } else if (key == LogicalKeyboardKey.shiftRight ||
          key == LogicalKeyboardKey.shiftLeft) {
        shift = toReleaseRawKeys.lastLShiftKeyEvent != null ||
            toReleaseRawKeys.lastRShiftKeyEvent != null;
      } else if (key == LogicalKeyboardKey.metaLeft ||
          key == LogicalKeyboardKey.metaRight ||
          key == LogicalKeyboardKey.superKey) {
        command = toReleaseRawKeys.lastLCommandKeyEvent != null ||
            toReleaseRawKeys.lastRCommandKeyEvent != null ||
            toReleaseRawKeys.lastSuperKeyEvent != null;
      }
    }

    // On some mobile soft-keyboard paths, Flutter may leave cached Shift state
    // set even though the current raw key event is not shifted anymore.
    if (e is RawKeyDownEvent &&
        shouldReleaseStaleMobileShift(
          isMobile: isMobile,
          cachedShiftPressed: shift,
          actualShiftPressed: e.isShiftPressed,
          logicalKey: e.logicalKey,
          hasTrackedShiftKeyDown: toReleaseRawKeys.lastLShiftKeyEvent != null ||
              toReleaseRawKeys.lastRShiftKeyEvent != null,
        )) {
      if (kDebugMode) {
        debugPrint(
          'input: releasing stale mobile Shift before replaying tracked raw '
          'key-up (logicalKey=${e.logicalKey.keyLabel}, '
          'actualShiftPressed=${e.isShiftPressed}, cachedShiftPressed=$shift)',
        );
      }
      _releaseTrackedRawShiftKeyEventIfNeeded();
    }

    // * Currently mobile does not enable map mode
    if ((isDesktop || isWebDesktop) && keyboardMode == kKeyMapMode) {
      mapKeyboardModeRaw(e, iosCapsLock);
    } else {
      legacyKeyboardModeRaw(e);
    }

    return KeyEventResult.handled;
  }

  KeyEventResult handleKeyEvent(KeyEvent e) {
    final modifierSlot = flutterModifierSlot(e.logicalKey);
    if (e is KeyUpEvent && modifierSlot != null) {
      _clearTrackedModifier(modifierSlot);
      _keyboardInput.releaseSlot(modifierSlot);
      return KeyEventResult.handled;
    }
    if (!keyboardPerm || isViewOnly || !_keyboardInput.backend.useFlutterInput) {
      releaseHeldModifiers();
    }
    if (!keyboardPerm || !_keyboardInput.ready) return KeyEventResult.handled;
    if (isViewOnly) return KeyEventResult.handled;
    if (isViewCamera) return KeyEventResult.handled;
    if (!_keyboardInput.backend.useFlutterInput) {
      if (isDesktop) {
        return KeyEventResult.handled;
      } else if (isWeb) {
        return KeyEventResult.ignored;
      }
    }
    if (isWindows || isLinux) {
      // Ignore meta keys. Because flutter window will loose focus if meta key is pressed.
      if (e.physicalKey == PhysicalKeyboardKey.metaLeft ||
          e.physicalKey == PhysicalKeyboardKey.metaRight) {
        return KeyEventResult.handled;
      }
    }

    if (_relativeMouse.handleKeyEvent(
      e,
      ctrlPressed: ctrl,
      shiftPressed: shift,
      altPressed: alt,
      commandPressed: command,
    )) {
      return KeyEventResult.handled;
    }

    bool iosCapsLock = false;
    if (isIOS && (e is KeyDownEvent || e is KeyRepeatEvent)) {
      iosCapsLock = _getIosCapsFromCharacter(e);
    }

    // Update cached modifier state before sending the event. The stale mobile
    // Shift release check below relies on this cached state.
    if (e is KeyUpEvent) {
      handleKeyUpEventModifiers(e);
    } else if (e is KeyDownEvent) {
      handleKeyDownEventModifiers(e);
    }

    bool isMobileAndMapMode = false;
    if (isMobile) {
      // Do not use map mode if mobile -> Android. Android does not support map mode for now.
      // Because simulating the physical key events(uhid) which requires root permission is not supported.
      if (peerPlatform != kPeerPlatformAndroid) {
        if (isIOS) {
          isMobileAndMapMode = true;
        } else {
          // The physicalKey.usbHidUsage may be not correct for soft keyboard on Android.
          // iOS does not have this issue.
          // 1. Open the soft keyboard on Android
          // 2. Switch to input method like zh/ko/ja
          // 3. Click Backspace and Enter on the soft keyboard or physical keyboard
          // 4. The physicalKey.usbHidUsage is not correct.
          // PhysicalKeyboardKey#8ac83(usbHidUsage: "0x1100000042", debugName: "Key with ID 0x1100000042")
          // LogicalKeyboardKey#2604c(keyId: "0x10000000d", keyLabel: "Enter", debugName: "Enter")
          //
          // The correct PhysicalKeyboardKey should be
          // PhysicalKeyboardKey#e14a9(usbHidUsage: "0x00070028", debugName: "Enter")
          // https://github.com/flutter/flutter/issues/157771
          // We cannot use the debugName to determine the key is correct or not, because it's null in release mode.
          // The normal `usbHidUsage` for keyboard shoud be between [0x00000010, 0x000c029f]
          // https://github.com/flutter/flutter/blob/c051b69e2a2224300e20d93dbd15f4b91e8844d1/packages/flutter/lib/src/services/keyboard_key.g.dart#L5332 - 5600
          final isNormalHsbHidUsage = (e.physicalKey.usbHidUsage >> 20) == 0;
          isMobileAndMapMode = isNormalHsbHidUsage &&
              // No need to check `!['Backspace', 'Enter'].contains(e.logicalKey.keyLabel)`
              // But we still add it for more reliability.
              !['Backspace', 'Enter'].contains(e.logicalKey.keyLabel);
        }
      }
    }

    // On some mobile soft-keyboard paths, Flutter may leave cached Shift state
    // set even though the current key event is not shifted anymore.
    if (e is KeyDownEvent &&
        shouldReleaseStaleMobileShift(
          isMobile: isMobile,
          cachedShiftPressed: shift,
          actualShiftPressed: HardwareKeyboard.instance.isShiftPressed,
          logicalKey: e.logicalKey,
          hasTrackedShiftKeyDown: toReleaseKeys.lastLShiftKeyEvent != null ||
              toReleaseKeys.lastRShiftKeyEvent != null,
        )) {
      _releaseTrackedShiftKeyEventIfNeeded();
    }

    final isDesktopAndMapMode =
        isDesktop || (isWebDesktop && keyboardMode == kKeyMapMode);
    if (isMobileAndMapMode || isDesktopAndMapMode) {
      // FIXME: e.character is wrong for dead keys, eg: ^ in de
      newKeyboardMode(
          e.character ?? '',
          e.physicalKey.usbHidUsage & 0xFFFF,
          // Show repeat event be converted to "release+press" events?
          e is KeyDownEvent || e is KeyRepeatEvent,
          iosCapsLock, modifierSlot: modifierSlot);
    } else {
      legacyKeyboardMode(e);
    }

    return KeyEventResult.handled;
  }

  /// Send Key Event
  void newKeyboardMode(
      String character, int usbHid, bool down, bool iosCapsLock,
      {SessionID? expectedSessionId, int? modifierSlot}) {
    if (!keyboardPerm || isViewOnly || isViewCamera) return;
    final lockModes = _buildLockModes(iosCapsLock);
    _keyboardInput.send(FlutterKeyStroke.key(character, usbHid, lockModes, down),
        slot: modifierSlot, expectedSessionId: expectedSessionId);
  }

  void mapKeyboardModeRaw(RawKeyEvent e, bool iosCapsLock) {
    int positionCode = -1;
    int platformCode = -1;
    bool down;

    if (e.data is RawKeyEventDataMacOs) {
      RawKeyEventDataMacOs newData = e.data as RawKeyEventDataMacOs;
      positionCode = newData.keyCode;
      platformCode = newData.keyCode;
    } else if (e.data is RawKeyEventDataWindows) {
      RawKeyEventDataWindows newData = e.data as RawKeyEventDataWindows;
      positionCode = newData.scanCode;
      platformCode = newData.keyCode;
    } else if (e.data is RawKeyEventDataLinux) {
      RawKeyEventDataLinux newData = e.data as RawKeyEventDataLinux;
      // scanCode and keyCode of RawKeyEventDataLinux are incorrect.
      // 1. scanCode means keycode
      // 2. keyCode means keysym
      positionCode = newData.scanCode;
      platformCode = newData.keyCode;
    } else if (e.data is RawKeyEventDataAndroid) {
      RawKeyEventDataAndroid newData = e.data as RawKeyEventDataAndroid;
      positionCode = newData.scanCode + 8;
      platformCode = newData.keyCode;
    } else {}

    if (e is RawKeyDownEvent) {
      down = true;
    } else {
      down = false;
    }
    inputRawKey(
        e.character ?? '', platformCode, positionCode, down, iosCapsLock,
        modifierSlot: flutterModifierSlot(e.logicalKey));
  }

  /// Send raw Key Event
  void inputRawKey(String name, int platformCode, int positionCode, bool down,
      bool iosCapsLock, {int? modifierSlot}) {
    if (!keyboardPerm || isViewOnly || isViewCamera) return;
    final lockModes = _buildLockModes(iosCapsLock);
    _keyboardInput.send(
        FlutterKeyStroke.raw(name, platformCode, positionCode, lockModes, down),
        slot: modifierSlot);
  }

  void legacyKeyboardModeRaw(RawKeyEvent e) {
    if (e is RawKeyDownEvent) {
      if (e.repeat) {
        sendRawKey(e, press: true);
      } else {
        sendRawKey(e, down: true);
      }
    }
    if (e is RawKeyUpEvent) {
      sendRawKey(e);
    }
  }

  void sendRawKey(RawKeyEvent e, {bool? down, bool? press}) {
    // for maximum compatibility
    final label = physicalKeyMap[e.physicalKey.usbHidUsage] ??
        logicalKeyMap[e.logicalKey.keyId] ??
        e.logicalKey.keyLabel;
    inputKey(label, down: down, press: press ?? false,
        modifierSlot: flutterModifierSlot(e.logicalKey));
  }

  void legacyKeyboardMode(KeyEvent e) {
    if (e is KeyDownEvent) {
      sendKey(e, down: true);
    } else if (e is KeyRepeatEvent) {
      sendKey(e, press: true);
    } else if (e is KeyUpEvent) {
      sendKey(e);
    }
  }

  void sendKey(KeyEvent e, {bool? down, bool? press}) {
    // for maximum compatibility
    final label = physicalKeyMap[e.physicalKey.usbHidUsage] ??
        logicalKeyMap[e.logicalKey.keyId] ??
        e.logicalKey.keyLabel;
    inputKey(label, down: down, press: press ?? false,
        modifierSlot: flutterModifierSlot(e.logicalKey));
  }

  /// Send key stroke event.
  /// [down] indicates the key's state(down or up).
  /// [press] indicates a click event(down and up).
  void inputKey(String name, {bool? down, bool? press, int? modifierSlot}) {
    if (!keyboardPerm) return;
    if (isViewOnly) return;
    if (isViewCamera) return;
    _keyboardInput.send(FlutterKeyStroke.legacy(name, down ?? false,
        press ?? true, alt, ctrl, shift, command), slot: modifierSlot);
  }

  static Map<String, dynamic> getMouseEventMove() => {
        'type': _kMouseEventMove,
        'buttons': 0,
      };

  List<Map<String, dynamic>> _getMouseButtonEvents(PointerEvent evt, String type) {
    const buttons = [kPrimaryMouseButton, kSecondaryMouseButton,
      kMiddleMouseButton, kBackMouseButton, kForwardMouseButton];
    const supportedMask = kPrimaryMouseButton | kSecondaryMouseButton |
        kMiddleMouseButton | kBackMouseButton | kForwardMouseButton;
    final current = type == _kMouseEventUp ? 0 : (evt.buttons & supportedMask);
    final released = _lastButtons & ~current;
    final pressed = current & ~_lastButtons;
    _lastButtons = current;
    if (released == 0 && pressed == 0) return const [];

    // A peer message names one button. Retire the old chord before new presses.
    return [
      for (final button in buttons)
        if ((released & button) != 0) {'type': _kMouseEventUp, 'buttons': button},
      for (final button in buttons)
        if ((pressed & button) != 0) {'type': _kMouseEventDown, 'buttons': button},
    ];
  }

  void _handleMouseEvent(PointerEvent evt, String type,
      {bool edgeScroll = false}) {
    final changes = _getMouseButtonEvents(evt, type);
    final relative = _relativeMouse.enabled.value;
    if (type == _kMouseEventMove) {
      if (relative) {
        _relativeMouse.handleRelativeMouseMove(evt.localPosition);
      } else {
        handleMouse(getMouseEventMove(), evt.position, edgeScroll: edgeScroll);
      }
    }
    for (final change in changes) {
      if (relative) {
        unawaited(_relativeMouse.sendRelativeMouseButton(change));
      } else {
        handleMouse(change, evt.position);
      }
    }
  }

  /// Send a mouse tap event(down and up).
  Future<void> tap(MouseButtons button) =>
      _sendMousePair(button, Duration.zero);

  Future<void> _sendMousePair(MouseButtons button, Duration hold) async {
    if (!keyboardPerm || isViewCamera) return;
    final expectedSessionId = sessionId;
    await _sendMouseUnchecked('down', button,
        expectedSessionId: expectedSessionId);
    if (hold > Duration.zero) {
      await Future.delayed(hold);
    }
    await _sendMouseUnchecked('up', button,
        expectedSessionId: expectedSessionId);
  }

  Future<void> tapDown(MouseButtons button) async {
    await sendMouse('down', button);
  }

  Future<void> tapUp(MouseButtons button) async {
    await sendMouse('up', button);
  }

  /// Send scroll event with scroll distance [y].
  Future<void> scroll(int y) async {
    if (isViewCamera) return;
    await bind.sessionSendMouse(
        sessionId: sessionId,
        msg: json
            .encode(modify({'id': id, 'type': 'wheel', 'y': y.toString()})));
  }

  /// Reset key modifiers to false, including [shift], [ctrl], [alt] and [command].
  void resetModifiers() {
    shift = ctrl = alt = command = false;
  }

  /// Modify the given modifier map [evt] based on current modifier key status.
  Map<String, dynamic> modify(Map<String, dynamic> evt) {
    if (ctrl) evt['ctrl'] = 'true';
    if (shift) evt['shift'] = 'true';
    if (alt) evt['alt'] = 'true';
    if (command) evt['command'] = 'true';
    return evt;
  }

  /// Send mouse event unconditionally (no permission checks).
  /// Used for side button releases that must go through even if permissions
  /// changed after the matching down was sent.
  Future<void> _sendMouseUnchecked(String type, MouseButtons button,
      {SessionID? expectedSessionId}) async {
    await bind.sessionSendMouse(
        sessionId: expectedSessionId ?? sessionId,
        msg: json.encode(modify({'type': type, 'buttons': button.value})));
  }

  Future<void> sendSideMouseButton(String type, MouseButtons button,
      {required SessionID expectedSessionId}) =>
      _sendMouseUnchecked(type, button, expectedSessionId: expectedSessionId);

  /// Send mouse press event.
  Future<void> sendMouse(String type, MouseButtons button) async {
    if (!keyboardPerm) return;
    if (isViewCamera) return;
    await _sendMouseUnchecked(type, button);
  }

  void enterOrLeave(bool enter) {
    _stopTrackpadFling();
    releaseHeldModifiers();
    _pointerMovedAfterEnter = false;
    _pointerInsideImage = enter;
    _lastWheelTsUs = 0;

    // Track active model for side button events (Linux).
    if (enter) {
      _activeSideButtonModel = this;
    } else if (_activeSideButtonModel == this) {
      _activeSideButtonModel = null;
    }

    // Fix status
    if (!enter) {
      resetModifiers();
    }
    _relativeMouse.onEnterOrLeaveImage(enter);
    _keyboardInput.backend.enterOrLeave(sessionId, enter);
  }

  /// Send mouse movement event with distance in [x] and [y].
  Future<void> moveMouse(double x, double y) async {
    if (!keyboardPerm) return;
    if (isViewCamera) return;
    var x2 = x.toInt();
    var y2 = y.toInt();
    await bind.sessionSendMouse(
        sessionId: sessionId,
        msg: json.encode(modify({'x': '$x2', 'y': '$y2'})));
  }

  /// Send relative mouse movement for mobile clients (virtual joystick).
  /// This method is for touch-based controls that want to send delta values.
  /// Uses the 'move_relative' type which bypasses absolute position tracking.
  ///
  /// Accumulates fractional deltas to avoid losing slow/fine movements.
  /// Only sends events when relative mouse mode is enabled and supported.
  Future<void> sendMobileRelativeMouseMove(double dx, double dy) async {
    if (!keyboardPerm) return;
    if (isViewCamera) return;
    // Only send relative mouse events when relative mode is enabled and supported.
    if (!isRelativeMouseModeSupported || !relativeMouseMode.value) return;
    _mobileDeltaRemainderX += dx;
    _mobileDeltaRemainderY += dy;
    final x = _mobileDeltaRemainderX.truncate();
    final y = _mobileDeltaRemainderY.truncate();
    _mobileDeltaRemainderX -= x;
    _mobileDeltaRemainderY -= y;
    if (x == 0 && y == 0) return;
    await bind.sessionSendMouse(
        sessionId: sessionId,
        msg: json.encode(modify({
          'type': 'move_relative',
          'x': '$x',
          'y': '$y',
        })));
  }

  /// Update the pointer lock center position based on current window frame.
  Future<void> updatePointerLockCenter({Offset? localCenter}) {
    return _relativeMouse.updatePointerLockCenter(localCenter: localCenter);
  }

  /// Get the current image widget size (for comparison to avoid unnecessary updates).
  Size? get imageWidgetSize => _relativeMouse.imageWidgetSize;

  /// Update the image widget size for center calculation.
  void updateImageWidgetSize(Size size) {
    _relativeMouse.updateImageWidgetSize(size);
  }

  void toggleRelativeMouseMode() {
    _relativeMouse.toggleRelativeMouseMode();
  }

  bool setRelativeMouseMode(bool enabled) {
    return _relativeMouse.setRelativeMouseMode(enabled);
  }

  Future<void> resumeKeyboardInput() => _keyboardInput.resume();

  void releaseHeldModifiers() {
    _keyboardInput.releaseAll();
    toReleaseKeys.reset();
    toReleaseRawKeys.reset();
    resetModifiers();
  }

  void suspendKeyboardInput() {
    _keyboardInput.suspend();
    toReleaseKeys.reset();
    toReleaseRawKeys.reset();
    resetModifiers();
  }

  void _refreshModifierFlags() {
    shift = toReleaseKeys.lastLShiftKeyEvent != null ||
        toReleaseKeys.lastRShiftKeyEvent != null ||
        toReleaseRawKeys.lastLShiftKeyEvent != null ||
        toReleaseRawKeys.lastRShiftKeyEvent != null;
    ctrl = toReleaseKeys.lastLCtrlKeyEvent != null ||
        toReleaseKeys.lastRCtrlKeyEvent != null ||
        toReleaseRawKeys.lastLCtrlKeyEvent != null ||
        toReleaseRawKeys.lastRCtrlKeyEvent != null;
    alt = toReleaseKeys.lastLAltKeyEvent != null ||
        toReleaseKeys.lastRAltKeyEvent != null ||
        toReleaseRawKeys.lastLAltKeyEvent != null ||
        toReleaseRawKeys.lastRAltKeyEvent != null;
    command = toReleaseKeys.lastLCommandKeyEvent != null ||
        toReleaseKeys.lastRCommandKeyEvent != null ||
        toReleaseKeys.lastSuperKeyEvent != null ||
        toReleaseRawKeys.lastLCommandKeyEvent != null ||
        toReleaseRawKeys.lastRCommandKeyEvent != null ||
        toReleaseRawKeys.lastSuperKeyEvent != null;
  }

  void _clearTrackedModifier(int slot) {
    switch (slot) {
      case 0:
        toReleaseKeys.lastLShiftKeyEvent = null;
        toReleaseRawKeys.lastLShiftKeyEvent = null;
      case 1:
        toReleaseKeys.lastRShiftKeyEvent = null;
        toReleaseRawKeys.lastRShiftKeyEvent = null;
      case 2:
        toReleaseKeys.lastLCtrlKeyEvent = null;
        toReleaseRawKeys.lastLCtrlKeyEvent = null;
      case 3:
        toReleaseKeys.lastRCtrlKeyEvent = null;
        toReleaseRawKeys.lastRCtrlKeyEvent = null;
      case 4:
        toReleaseKeys.lastLAltKeyEvent = null;
        toReleaseRawKeys.lastLAltKeyEvent = null;
      case 5:
        toReleaseKeys.lastRAltKeyEvent = null;
        toReleaseRawKeys.lastRAltKeyEvent = null;
      case 6:
        toReleaseKeys.lastLCommandKeyEvent = null;
        toReleaseRawKeys.lastLCommandKeyEvent = null;
      case 7:
        toReleaseKeys.lastRCommandKeyEvent = null;
        toReleaseRawKeys.lastRCommandKeyEvent = null;
      case 8:
        toReleaseKeys.lastSuperKeyEvent = null;
        toReleaseRawKeys.lastSuperKeyEvent = null;
    }
    _refreshModifierFlags();
  }

  /// Exit the relative-mouse shortcut using the exact accepted modifier presses.
  void exitRelativeMouseModeWithKeyRelease() {
    if (!_relativeMouse.enabled.value) return;
    releaseHeldModifiers();
    _relativeMouse.setRelativeMouseMode(false);
  }

  void resetForSession(SessionID expectedSessionId) {
    _trackpadGesture = null;
    _stopTrackpadFling();
    suspendKeyboardInput();
    retireKeyboardMode();
    disposeSideButtonTracking(expectedSessionId: expectedSessionId);
    _relativeMouse.resetForSession(expectedSessionId);
    onRelativeMouseModeDisabled = null;
    _trackpadScrollUnsent = Offset.zero;
    _trackpadScrollOwner = null;
    _mobileDeltaRemainderX = 0;
    _mobileDeltaRemainderY = 0;
    _pointerMovedAfterEnter = false;
    _pointerInsideImage = false;
    _lastButtons = 0;
    lastMousePos = Offset.zero;
    _lastWheelTsUs = 0;
    _queryOtherWindowCoords = false;
    _windowRect = null;
    _remoteWindowCoords.clear();
    toReleaseKeys.reset();
    toReleaseRawKeys.reset();
    resetModifiers();
    keyboardInputAllowed = true;
    final peerId = id;
    if (peerId.isNotEmpty) {
      stateGlobal.relativeMouseModeState.remove(peerId);
    }
  }

  void disposeRelativeMouseMode({SessionID? expectedSessionId}) {
    _trackpadDisposed = true;
    _trackpadGesture = null;
    _trackpadScrollOwner = null;
    _trackpadScrollUnsent = Offset.zero;
    _stopTrackpadFling();
    suspendKeyboardInput();
    _relativeMouse.dispose(expectedSessionId: expectedSessionId);
    onRelativeMouseModeDisabled = null;
    // Cancel the relative mouse mode observer and clean up global state.
    _relativeMouseModeDisposer?.dispose();
    _relativeMouseModeDisposer = null;
    final peerId = id;
    if (peerId.isNotEmpty) {
      stateGlobal.relativeMouseModeState.remove(peerId);
    }
  }

  void onWindowBlur() {
    _stopTrackpadFling();
    _relativeMouse.onWindowBlur();
  }

  void onWindowFocus() {
    _relativeMouse.onWindowFocus();
  }

  void onPointHoverImage(PointerHoverEvent e) {
    _stopTrackpadFling();
    if (isViewOnly && !showMyCursor) return;
    if (e.kind != ui.PointerDeviceKind.mouse) return;

    // May fix https://github.com/rustdesk/rustdesk/issues/13009
    if (isIOS && e.synthesized && e.position == Offset.zero && e.buttons == 0) {
      // iOS may emit a synthesized hover event at (0,0) when the mouse is disconnected.
      // Ignore this event to prevent cursor jumping.
      debugPrint('Ignored synthesized hover at (0,0) on iOS');
      return;
    }

    // Only update pointer region when relative mouse mode is enabled.
    // This avoids unnecessary tracking when not in relative mode.
    if (_relativeMouse.enabled.value) {
      _relativeMouse.updatePointerRegionTopLeftGlobal(e);
    }

    if (!isPhysicalMouse.value) {
      isPhysicalMouse.value = true;
    }
    if (isPhysicalMouse.value) {
      _handleMouseEvent(e, _kMouseEventMove, edgeScroll: useEdgeScroll);
    }
  }

  void onPointerPanZoomStart(PointerPanZoomStartEvent e) {
    _stopTrackpadFling();
    _trackpadGesture = null;
    if (_trackpadDisposed) return;
    final owner = parent.target;
    if (owner == null ||
        !owner.isCurrentSessionOwner(owner.sessionId, owner.clientOwnerId)) {
      return;
    }
    if (isViewOnly) return;
    if (isViewCamera) return;
    final scrollOwner =
        (sessionId: owner.sessionId, clientOwnerId: owner.clientOwnerId);
    if (_trackpadScrollOwner != scrollOwner) {
      _trackpadScrollUnsent = Offset.zero;
      _trackpadScrollOwner = scrollOwner;
    }
    final gesture = _TrackpadGesture(owner.sessionId, owner.clientOwnerId, e);
    _trackpadGesture = gesture;
    if (peerPlatform == kPeerPlatformAndroid) {
      handlePointerEvent('touch', kMouseEventTypePanStart, e.position,
          expectedSessionId: gesture.sessionId);
    }
  }

  _TrackpadGesture? _currentTrackpadGesture(PointerEvent e) {
    final gesture = _trackpadGesture;
    if (gesture == null) return null;
    final owner = parent.target;
    if (_trackpadDisposed ||
        owner == null ||
        !owner.isCurrentSessionOwner(gesture.sessionId, gesture.clientOwnerId)) {
      _trackpadGesture = null;
      _stopTrackpadFling();
      return null;
    }
    return gesture.matches(e) ? gesture : null;
  }

  // https://docs.flutter.dev/release/breaking-changes/trackpad-gestures
  void onPointerPanZoomUpdate(PointerPanZoomUpdateEvent e) {
    final gesture = _currentTrackpadGesture(e);
    if (gesture == null) return;
    if (isViewOnly) return;
    if (isViewCamera) return;
    if (peerPlatform != kPeerPlatformAndroid) {
      final scale = ((e.scale - gesture.scale) * 1000).toInt();
      gesture.scale = e.scale;

      if (scale != 0) {
        sendTrackpadScale(scale, expectedSessionId: gesture.sessionId);
        return;
      }
    }

    var delta = e.panDelta * _trackpadSpeedInner;
    if (isMacOS && peerPlatform == kPeerPlatformWindows) {
      delta *= _trackpadAdjustMacToWin;
    }
    delta = _filterTrackpadDeltaAxis(delta);
    gesture.lastDelta = delta;

    var x = delta.dx.toInt();
    var y = delta.dy.toInt();
    if (peerPlatform == kPeerPlatformLinux) {
      _trackpadScrollUnsent += (delta * _trackpadAdjustPeerLinux);
      x = _trackpadScrollUnsent.dx.truncate();
      y = _trackpadScrollUnsent.dy.truncate();
      _trackpadScrollUnsent -= Offset(x.toDouble(), y.toDouble());
    } else {
      if (x == 0 && y == 0) {
        final thr = 0.1;
        if (delta.dx.abs() > delta.dy.abs()) {
          x = delta.dx > thr ? 1 : (delta.dx < -thr ? -1 : 0);
        } else {
          y = delta.dy > thr ? 1 : (delta.dy < -thr ? -1 : 0);
        }
      }
    }
    if (x != 0 || y != 0) {
      if (peerPlatform == kPeerPlatformAndroid) {
        handlePointerEvent('touch', kMouseEventTypePanUpdate,
            Offset(x.toDouble(), y.toDouble()),
            expectedSessionId: gesture.sessionId);
      } else {
        if (isViewCamera) return;
        sendTrackpadScroll(x, y, expectedSessionId: gesture.sessionId);
      }
    }
  }

  Offset _filterTrackpadDeltaAxis(Offset delta) {
    final absDx = delta.dx.abs();
    final absDy = delta.dy.abs();
    // Keep diagonal intent when movement is tiny on both axes.
    if (absDx < _trackpadAxisNoiseThreshold &&
        absDy < _trackpadAxisNoiseThreshold) {
      return delta;
    }
    // Dominant-axis lock to reduce accidental cross-axis scrolling noise.
    if (absDy >= absDx * _trackpadAxisLockRatio) {
      return Offset(0, delta.dy);
    }
    if (absDx >= absDy * _trackpadAxisLockRatio) {
      return Offset(delta.dx, 0);
    }
    return delta;
  }

  Future<void> sendTrackpadScale(int scale,
      {SessionID? expectedSessionId}) => bind.sessionSendPointer(
      sessionId: expectedSessionId ?? sessionId,
      msg: json.encode(
          PointerEventToRust(kPointerEventKindTouch, 'scale', scale).toJson()));

  Future<void> sendTrackpadScroll(int x, int y,
      {SessionID? expectedSessionId}) => bind.sessionSendMouse(
      sessionId: expectedSessionId ?? sessionId,
      msg: '{"type": "trackpad", "x": "$x", "y": "$y"}');

  void _stopTrackpadFling() {
    final fling = _trackpadFling;
    _trackpadFling = null;
    fling?.timer?.cancel();
    // Preserve the active pan identity for its matching terminal event.
    _trackpadGesture?.lastDelta = Offset.zero;
  }

  bool _isCurrentTrackpadFling(_TrackpadFling fling) {
    final owner = parent.target;
    return identical(_trackpadFling, fling) &&
        !_trackpadDisposed &&
        owner != null &&
        owner.isCurrentSessionOwner(fling.sessionId, fling.clientOwnerId) &&
        !isViewOnly &&
        !isViewCamera &&
        keyboardPerm;
  }

  void _resumeTrackpadFling() {
    final fling = _trackpadFling;
    if (fling == null) return;
    if (!_isCurrentTrackpadFling(fling)) {
      _stopTrackpadFling();
      return;
    }
    if (_flingSendPending || fling.timer != null) return;

    fling.timer = Timer(Duration(milliseconds: _flingBaseDelay), () {
      fling.timer = null;
      if (!_isCurrentTrackpadFling(fling)) {
        if (identical(_trackpadFling, fling)) _stopTrackpadFling();
        return;
      }
      fling.x *= 0.97;
      fling.y *= 0.97;
      var dx = fling.x.toInt();
      var dy = fling.y.toInt();
      if (peerPlatform == kPeerPlatformLinux) {
        dx = (fling.x * _trackpadAdjustPeerLinux).toInt();
        dy = (fling.y * _trackpadAdjustPeerLinux).toInt();
      }
      if (dx == 0 && dy == 0) {
        _stopTrackpadFling();
        return;
      }

      // Keep one admitted send until it settles, even across reset/replacement.
      _flingSendPending = true;
      unawaited(_sendTrackpadFling(fling, dx, dy));
    });
  }

  Future<void> _sendTrackpadFling(_TrackpadFling fling, int x, int y) async {
    try {
      await sendTrackpadScroll(x, y, expectedSessionId: fling.sessionId);
    } catch (error) {
      if (identical(_trackpadFling, fling)) _stopTrackpadFling();
      debugPrint('[InputModel] trackpad fling send failed: ${error.runtimeType}');
    } finally {
      _flingSendPending = false;
      _resumeTrackpadFling();
    }
  }

  void onPointerPanZoomEnd(PointerPanZoomEndEvent e) {
    final gesture = _currentTrackpadGesture(e);
    if (gesture == null) return;
    final delta = gesture.lastDelta;
    _trackpadGesture = null;
    _stopTrackpadFling();
    if (_trackpadDisposed || isViewOnly) return;
    if (isViewCamera) return;
    if (peerPlatform == kPeerPlatformAndroid) {
      handlePointerEvent('touch', kMouseEventTypePanEnd, e.position,
          expectedSessionId: gesture.sessionId);
      return;
    }

    // 2.0 is an experience value
    double minFlingValue = 2.0 * _trackpadSpeedInner;
    if (isMacOS && peerPlatform == kPeerPlatformWindows) {
      minFlingValue *= _trackpadAdjustMacToWin;
    }
    if (delta.dx.abs() > minFlingValue || delta.dy.abs() > minFlingValue) {
      _trackpadFling = _TrackpadFling(
          gesture.sessionId, gesture.clientOwnerId, delta.dx, delta.dy);
    }
    sendTrackpadScale(0, expectedSessionId: gesture.sessionId);
    _resumeTrackpadFling();
  }

  // iOS Magic Mouse duplicate event detection.
  // When using Magic Mouse on iPad, iOS may emit both mouse and touch events
  // for the same click in certain areas (like top-left corner).
  int _lastMouseDownTimeMs = 0;
  ui.Offset _lastMouseDownPos = ui.Offset.zero;

  /// Check if a touch tap event should be ignored because it's a duplicate
  /// of a recent mouse event (iOS Magic Mouse issue).
  bool shouldIgnoreTouchTap(ui.Offset pos) {
    if (!isIOS) return false;
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final dt = nowMs - _lastMouseDownTimeMs;
    final distance = (_lastMouseDownPos - pos).distance;
    // If touch tap is within 2000ms and 80px of the last mouse down,
    // it's likely a duplicate event from the same Magic Mouse click.
    if (dt >= 0 && dt < 2000 && distance < 80.0) {
      debugPrint("shouldIgnoreTouchTap: IGNORED (dt=$dt, dist=$distance)");
      return true;
    }
    return false;
  }

  /// iOS may emit a synthesized touch event after a real mouse click.
  /// This helper ignores touch-down events that arrive shortly after a mouse down,
  /// even when the position is far (e.g., near the top edge).
  bool _shouldIgnoreTouchAfterMouse(int nowMs) {
    if (!isIOS) return false;
    const int kTouchAfterMouseWindowMs = 700;
    final dt = nowMs - _lastMouseDownTimeMs;
    return dt >= 0 && dt < kTouchAfterMouseWindowMs;
  }

  void onPointDownImage(PointerDownEvent e) {
    debugPrint("onPointDownImage ${e.kind}");
    _stopTrackpadFling();
    if (isDesktop) _queryOtherWindowCoords = true;
    _remoteWindowCoords = [];
    _windowRect = null;
    if (isViewOnly && !showMyCursor) return;
    if (isViewCamera) return;

    // Track mouse down events for duplicate detection on iOS.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if (e.kind == ui.PointerDeviceKind.mouse) {
      if (!isPhysicalMouse.value) {
        isPhysicalMouse.value = true;
      }
      _lastMouseDownTimeMs = nowMs;
      _lastMouseDownPos = e.position;
    }

    if (_relativeMouse.enabled.value) {
      _relativeMouse.updatePointerRegionTopLeftGlobal(e);
    }

    if (e.kind != ui.PointerDeviceKind.mouse) {
      // Ignore duplicate touch events that follow a recent mouse click (iOS Magic Mouse issue).
      if (isPhysicalMouse.value && _shouldIgnoreTouchAfterMouse(nowMs)) {
        return;
      }
      if (isPhysicalMouse.value) {
        isPhysicalMouse.value = false;
      }
    }
    if (isPhysicalMouse.value) {
      _handleMouseEvent(e, _kMouseEventDown);
    }
  }

  void onPointUpImage(PointerUpEvent e) => _endPhysicalMouseImage(e);

  void onPointCancelImage(PointerCancelEvent e) => _endPhysicalMouseImage(e);

  void _endPhysicalMouseImage(PointerEvent e) {
    if (isDesktop) _queryOtherWindowCoords = false;
    if (isViewOnly && !showMyCursor) return;
    if (isViewCamera) return;

    if (_relativeMouse.enabled.value) {
      _relativeMouse.updatePointerRegionTopLeftGlobal(e);
    }

    if (e.kind != ui.PointerDeviceKind.mouse) return;
    // Retire the tracked chord even when a touch contact selected touch input.
    _handleMouseEvent(e, _kMouseEventUp);
  }

  void onPointMoveImage(PointerMoveEvent e) {
    if (isViewOnly && !showMyCursor) return;
    if (isViewCamera) return;
    if (e.kind != ui.PointerDeviceKind.mouse) return;

    if (_relativeMouse.enabled.value) {
      _relativeMouse.updatePointerRegionTopLeftGlobal(e);
    }

    if (_queryOtherWindowCoords) {
      final expectedSessionId = sessionId;
      Future.delayed(Duration.zero, () async {
        final remoteWindowCoords = <RemoteWindowCoords>[];
        final windowRect =
            await fillRemoteCoordsAndGetCurFrame(remoteWindowCoords);
        if (parent.target?.isCurrentSession(expectedSessionId) != true) return;
        _remoteWindowCoords = remoteWindowCoords;
        _windowRect = windowRect;
      });
      _queryOtherWindowCoords = false;
    }
    if (isPhysicalMouse.value) {
      _handleMouseEvent(e, _kMouseEventMove, edgeScroll: useEdgeScroll);
    }
  }

  static Future<Rect?> fillRemoteCoordsAndGetCurFrame(
      List<RemoteWindowCoords> remoteWindowCoords) async {
    final coords =
        await rustDeskWinManager.getOtherRemoteWindowCoordsFromMain();
    final wc = WindowController.fromWindowId(kWindowId!);
    try {
      final frame = await wc.getFrame();
      for (final c in coords) {
        c.relativeOffset = Offset(
            c.windowRect.left - frame.left, c.windowRect.top - frame.top);
        remoteWindowCoords.add(c);
      }
      return frame;
    } catch (e) {
      // Unreachable code
      debugPrint("Failed to get frame of window $kWindowId, it may be hidden");
    }
    return null;
  }

  /// Handle scroll/wheel events.
  /// Note: Scroll events intentionally use absolute positioning even in relative mouse mode.
  /// This is because scroll events don't need relative positioning - they represent
  /// scroll deltas that are independent of cursor position. Games and 3D applications
  /// handle scroll events the same way regardless of mouse mode.
  void onPointerSignalImage(PointerSignalEvent e) {
    if (isViewOnly) return;
    if (isViewCamera) return;
    if (e is PointerScrollEvent) {
      final rawDx = e.scrollDelta.dx;
      final rawDy = e.scrollDelta.dy;
      final dominantDelta =
          rawDx.abs() > rawDy.abs() ? rawDx.abs() : rawDy.abs();
      final isSmooth = dominantDelta < 1;
      final nowUs = DateTime.now().microsecondsSinceEpoch;
      final dtUs = _lastWheelTsUs == 0 ? 0 : nowUs - _lastWheelTsUs;
      _lastWheelTsUs = nowUs;
      int accel = 1;
      if (!isSmooth &&
          dtUs > 0 &&
          dtUs <= _wheelAccelMediumThresholdUs &&
          (isWindows || isLinux) &&
          peerPlatform == kPeerPlatformMacOS) {
        final velocity = dominantDelta / dtUs;
        if (velocity >= _wheelBurstVelocityThreshold) {
          if (dtUs < _wheelAccelFastThresholdUs) {
            accel = 3;
          } else {
            accel = 2;
          }
        }
      }
      var dx = rawDx.toInt();
      var dy = rawDy.toInt();
      if (rawDx.abs() > rawDy.abs()) {
        dy = 0;
      } else {
        dx = 0;
      }
      if (dx > 0) {
        dx = -accel;
      } else if (dx < 0) {
        dx = accel;
      }
      if (dy > 0) {
        dy = -accel;
      } else if (dy < 0) {
        dy = accel;
      }
      bind.sessionSendMouse(
          sessionId: sessionId,
          msg: '{"type": "wheel", "x": "$dx", "y": "$dy"}');
    }
  }

  void refreshMousePos() => handleMouse({
        'buttons': 0,
        'type': _kMouseEventMove,
      }, lastMousePos, edgeScroll: useEdgeScroll);

  void tryMoveEdgeOnExit(Offset pos) => handleMouse(
        {
          'buttons': 0,
          'type': _kMouseEventMove,
        },
        pos,
        onExit: true,
      );

  static double tryGetNearestRange(double v, double min, double max, double n) {
    if (v < min && v >= min - n) {
      v = min;
    }
    if (v > max && v <= max + n) {
      v = max;
    }
    return v;
  }

  Offset setNearestEdge(double x, double y, Rect rect) {
    double left = x - rect.left;
    double right = rect.right - 1 - x;
    double top = y - rect.top;
    double bottom = rect.bottom - 1 - y;
    if (left < right && left < top && left < bottom) {
      x = rect.left;
    }
    if (right < left && right < top && right < bottom) {
      x = rect.right - 1;
    }
    if (top < left && top < right && top < bottom) {
      y = rect.top;
    }
    if (bottom < left && bottom < right && bottom < top) {
      y = rect.bottom - 1;
    }
    return Offset(x, y);
  }

  void handlePointerEvent(String kind, String type, Offset offset,
      {SessionID? expectedSessionId}) {
    double x = offset.dx;
    double y = offset.dy;
    if (_checkPeerControlProtected(x, y)) {
      return;
    }
    // Only touch events are handled for now. So we can just ignore buttons.
    // to-do: handle mouse events

    late final dynamic evtValue;
    if (type == kMouseEventTypePanUpdate) {
      evtValue = {
        'x': x.toInt(),
        'y': y.toInt(),
      };
    } else {
      final isMoveTypes = [kMouseEventTypePanStart, kMouseEventTypePanEnd];
      final pos = handlePointerDevicePos(
        kPointerEventKindTouch,
        x,
        y,
        isMoveTypes.contains(type),
        type,
      );
      if (pos == null) {
        return;
      }
      evtValue = {
        'x': pos.x.toInt(),
        'y': pos.y.toInt(),
      };
    }

    final evt = PointerEventToRust(kind, type, evtValue).toJson();
    if (isViewCamera) return;
    bind.sessionSendPointer(
        sessionId: expectedSessionId ?? sessionId, msg: json.encode(modify(evt)));
  }

  bool _checkPeerControlProtected(double x, double y) {
    final cursorModel = parent.target!.cursorModel;
    if (cursorModel.isPeerControlProtected) {
      lastMousePos = ui.Offset(x, y);
      return true;
    }

    if (!cursorModel.gotMouseControl) {
      bool selfGetControl =
          (x - lastMousePos.dx).abs() > kMouseControlDistance ||
              (y - lastMousePos.dy).abs() > kMouseControlDistance;
      if (selfGetControl) {
        cursorModel.gotMouseControl = true;
      } else {
        lastMousePos = ui.Offset(x, y);
        return true;
      }
    }
    lastMousePos = ui.Offset(x, y);
    return false;
  }

  Map<String, dynamic>? processEventToPeer(
    Map<String, dynamic> evt,
    Offset offset, {
    bool onExit = false,
    bool moveCanvas = true,
    bool edgeScroll = false,
  }) {
    if (isViewCamera) return null;
    double x = offset.dx;
    double y = max(0.0, offset.dy);
    if (_checkPeerControlProtected(x, y)) {
      return null;
    }

    var type = kMouseEventTypeDefault;
    var isMove = false;
    switch (evt['type']) {
      case _kMouseEventDown:
        type = kMouseEventTypeDown;
        break;
      case _kMouseEventUp:
        type = kMouseEventTypeUp;
        break;
      case _kMouseEventMove:
        _pointerMovedAfterEnter = true;
        isMove = true;
        break;
      default:
        return null;
    }
    evt['type'] = type;

    if (type == kMouseEventTypeDown && !_pointerMovedAfterEnter) {
      // Move mouse to the position of the down event first.
      lastMousePos = ui.Offset(x, y);
      refreshMousePos();
    }

    final pos = handlePointerDevicePos(
      kPointerEventKindMouse,
      x,
      y,
      isMove,
      type,
      onExit: onExit,
      moveCanvas: moveCanvas,
      edgeScroll: edgeScroll,
    );
    if (pos == null) {
      return null;
    }
    if (type != '') {
      evt['x'] = '0';
      evt['y'] = '0';
    } else {
      evt['x'] = '${pos.x.toInt()}';
      evt['y'] = '${pos.y.toInt()}';
    }

    final buttons = evt['buttons'];
    if (buttons is int) {
      evt['buttons'] = mouseButtonsToPeer(buttons);
    } else {
      // Log warning if buttons exists but is not an int (unexpected caller).
      // Keep empty string fallback for missing buttons to preserve move/hover behavior.
      if (buttons != null) {
        debugPrint(
            '[InputModel] processEventToPeer: unexpected buttons type: ${buttons.runtimeType}, value: $buttons');
      }
      evt['buttons'] = '';
    }
    return evt;
  }

  Map<String, dynamic>? handleMouse(
    Map<String, dynamic> evt,
    Offset offset, {
    bool onExit = false,
    bool moveCanvas = true,
    bool edgeScroll = false,
  }) {
    final evtToPeer = processEventToPeer(evt, offset,
        onExit: onExit, moveCanvas: moveCanvas, edgeScroll: edgeScroll);
    if (evtToPeer != null) {
      bind.sessionSendMouse(
          sessionId: sessionId, msg: json.encode(modify(evtToPeer)));
    }
    return evtToPeer;
  }

  Point? handlePointerDevicePos(
    String kind,
    double x,
    double y,
    bool isMove,
    String evtType, {
    bool onExit = false,
    bool moveCanvas = true,
    bool edgeScroll = false,
  }) {
    final ffiModel = parent.target!.ffiModel;
    CanvasCoords canvas =
        CanvasCoords.fromCanvasModel(parent.target!.canvasModel);
    Rect? rect = ffiModel.rect;

    if (isMove) {
      if (_remoteWindowCoords.isNotEmpty &&
          _windowRect != null &&
          !_isInCurrentWindow(x, y)) {
        final coords =
            findRemoteCoords(x, y, _remoteWindowCoords, devicePixelRatio);
        if (coords != null) {
          isMove = false;
          canvas = coords.canvas;
          rect = coords.remoteRect;
          x -= isWindows
              ? coords.relativeOffset.dx / devicePixelRatio
              : coords.relativeOffset.dx;
          y -= isWindows
              ? coords.relativeOffset.dy / devicePixelRatio
              : coords.relativeOffset.dy;
        }
      }
    }

    y -= CanvasModel.topToEdge;
    x -= CanvasModel.leftToEdge;
    if (isMove) {
      final canvasModel = parent.target!.canvasModel;

      if (edgeScroll) {
        canvasModel.edgeScrollMouse(x, y);
      } else if (moveCanvas) {
        canvasModel.moveDesktopMouse(x, y);
      }

      canvasModel.updateLocalCursor(x, y);
    }

    return _handlePointerDevicePos(
      kind,
      x,
      y,
      isMove,
      canvas,
      rect,
      evtType,
      onExit: onExit,
    );
  }

  bool _isInCurrentWindow(double x, double y) {
    var w = _windowRect!.width;
    var h = _windowRect!.height;
    if (isWindows) {
      w /= devicePixelRatio;
      h /= devicePixelRatio;
    }
    return x >= 0 && y >= 0 && x <= w && y <= h;
  }

  static RemoteWindowCoords? findRemoteCoords(double x, double y,
      List<RemoteWindowCoords> remoteWindowCoords, double devicePixelRatio) {
    if (isWindows) {
      x *= devicePixelRatio;
      y *= devicePixelRatio;
    }
    for (final c in remoteWindowCoords) {
      if (x >= c.relativeOffset.dx &&
          y >= c.relativeOffset.dy &&
          x <= c.relativeOffset.dx + c.windowRect.width &&
          y <= c.relativeOffset.dy + c.windowRect.height) {
        return c;
      }
    }
    return null;
  }

  Point? _handlePointerDevicePos(
    String kind,
    double x,
    double y,
    bool moveInCanvas,
    CanvasCoords canvas,
    Rect? rect,
    String evtType, {
    bool onExit = false,
  }) {
    if (rect == null) {
      return null;
    }

    final nearThr = 3;
    var nearRight = (canvas.size.width - x) < nearThr;
    var nearBottom = (canvas.size.height - y) < nearThr;
    final imageWidth = rect.width * canvas.scale;
    final imageHeight = rect.height * canvas.scale;
    if (canvas.scrollStyle != ScrollStyle.scrollauto) {
      x += imageWidth * canvas.scrollX;
      y += imageHeight * canvas.scrollY;

      // boxed size is a center widget
      if (canvas.size.width > imageWidth) {
        x -= ((canvas.size.width - imageWidth) / 2);
      }
      if (canvas.size.height > imageHeight) {
        y -= ((canvas.size.height - imageHeight) / 2);
      }
    } else {
      x -= canvas.x;
      y -= canvas.y;
    }

    x /= canvas.scale;
    y /= canvas.scale;
    if (canvas.scale > 0 && canvas.scale < 1) {
      final step = 1.0 / canvas.scale - 1;
      if (nearRight) {
        x += step;
      }
      if (nearBottom) {
        y += step;
      }
    }
    x += rect.left;
    y += rect.top;

    if (onExit) {
      final pos = setNearestEdge(x, y, rect);
      x = pos.dx;
      y = pos.dy;
    }

    return InputModel.getPointInRemoteRect(
        true, peerPlatform, kind, evtType, x, y, rect);
  }

  static Point<double>? getPointInRemoteRect(
      bool isLocalDesktop,
      String? peerPlatform,
      String kind,
      String evtType,
      double evtX,
      double evtY,
      Rect rect) {
    double minX = rect.left;
    // https://github.com/rustdesk/rustdesk/issues/6678
    // For Windows, [0,maxX], [0,maxY] should be set to enable window snapping.
    double maxX = (rect.left + rect.width) -
        (peerPlatform == kPeerPlatformWindows ? 0 : 1);
    double minY = rect.top;
    double maxY = (rect.top + rect.height) -
        (peerPlatform == kPeerPlatformWindows ? 0 : 1);
    evtX = InputModel.tryGetNearestRange(evtX, minX, maxX, 5);
    evtY = InputModel.tryGetNearestRange(evtY, minY, maxY, 5);
    if (isLocalDesktop) {
      // A release retires a held button even after the pointer leaves the image.
      if (kind == kPointerEventKindMouse && evtType != kMouseEventTypeUp &&
          (evtX < minX || evtY < minY || evtX > maxX || evtY > maxY)) {
        return null;
      }
    } else {
      bool evtXInRange = evtX >= minX && evtX <= maxX;
      bool evtYInRange = evtY >= minY && evtY <= maxY;
      if (!(evtXInRange || evtYInRange)) {
        return null;
      }
      if (evtX < minX) {
        evtX = minX;
      } else if (evtX > maxX) {
        evtX = maxX;
      }
      if (evtY < minY) {
        evtY = minY;
      } else if (evtY > maxY) {
        evtY = maxY;
      }
    }

    return Point(evtX, evtY);
  }

  /// Web only
  void listenToMouse(bool yesOrNo) {
    if (yesOrNo) {
      platformFFI.startDesktopWebListener();
    } else {
      platformFFI.stopDesktopWebListener();
    }
  }

  void onMobileBack() {
    final minBackButtonVersion = "1.3.8";
    final peerVersion =
        parent.target?.ffiModel.pi.version ?? minBackButtonVersion;
    var btn = MouseButtons.back;
    // For compatibility with old versions
    if (versionCmp(peerVersion, minBackButtonVersion) < 0) {
      btn = MouseButtons.right;
    }
    tap(btn);
  }

  void onMobileHome() => tap(MouseButtons.wheel);
  Future<void> onMobileApps() =>
      _sendMousePair(MouseButtons.wheel, const Duration(milliseconds: 500));

  // Simulate a key press event.
  // `usbHidUsage` is the USB HID usage code of the key.
  Future<void> tapHidKey(int usbHidUsage) async {
    final expectedSessionId = sessionId;
    newKeyboardMode(kKeyFlutterKey, usbHidUsage, true, false,
        expectedSessionId: expectedSessionId);
    await Future.delayed(Duration(milliseconds: 100));
    newKeyboardMode(kKeyFlutterKey, usbHidUsage, false, false,
        expectedSessionId: expectedSessionId);
  }

  Future<void> onMobileVolumeUp() async =>
      await tapHidKey(PhysicalKeyboardKey.audioVolumeUp.usbHidUsage & 0xFFFF);
  Future<void> onMobileVolumeDown() async =>
      await tapHidKey(PhysicalKeyboardKey.audioVolumeDown.usbHidUsage & 0xFFFF);
  Future<void> onMobilePower() async =>
      await tapHidKey(PhysicalKeyboardKey.power.usbHidUsage & 0xFFFF);
}

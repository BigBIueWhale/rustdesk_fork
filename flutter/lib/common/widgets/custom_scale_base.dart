import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/utils/scale.dart';
import 'package:flutter_hbb/common.dart';

/// Base class providing shared custom scale control logic for both mobile and desktop widgets.
/// Implementations must provide [ffi] and [onScaleChanged] getters.
abstract class CustomScaleControls<T extends StatefulWidget> extends State<T> {
  /// FFI instance for session interaction
  FFI get ffi;

  /// Callback invoked when scale value changes
  ValueChanged<int>? get onScaleChanged;

  late int _scaleValue;
  Timer? _scaleTimer;
  CanvasModel? _deferredReadCanvas;
  VoidCallback? _deferredReadListener;
  bool _saving = false;
  bool _loading = false;
  bool _dirty = false;
  bool _failed = false;
  int _generation = 0;
  int _revision = 0;
  late FFI _ownerFfi;
  late SessionID _sessionId;
  late SessionID _clientOwnerId;
  // Normalized slider position in [0, 1]. We map it nonlinearly to percent.
  double _scalePos = 0.0;

  int get scaleValue => _scaleValue;
  double get scalePos => _scalePos;
  bool get _operationPending => _saving || (_loading && !_dirty);

  @protected
  String get scaleFailureText => translate('Failed');

  @protected
  String get scaleRetryText => translate('Retry');

  int mapPosToPercent(double p) => _mapPosToPercent(p);

  static const int minPercent = kScaleCustomMinPercent;
  static const int pivotPercent = kScaleCustomPivotPercent; // 100% should be at 1/3 of track
  static const int maxPercent = kScaleCustomMaxPercent;
  static const double pivotPos = kScaleCustomPivotPos; // first 1/3 → up to 100%
  static const double detentEpsilon = kScaleCustomDetentEpsilon; // snap range around pivot (~0.6%)

  // Clamp helper for local use
  int _clampScale(int v) => clampCustomScalePercent(v);

  // Map normalized position [0,1] → percent [5,1000] with 100 at 1/3 width.
  int _mapPosToPercent(double p) {
    if (p <= 0.0) return minPercent;
    if (p >= 1.0) return maxPercent;
    if (p <= pivotPos) {
      final q = p / pivotPos; // 0..1
      final v = minPercent + q * (pivotPercent - minPercent);
      return _clampScale(v.round());
    } else {
      final q = (p - pivotPos) / (1.0 - pivotPos); // 0..1
      final v = pivotPercent + q * (maxPercent - pivotPercent);
      return _clampScale(v.round());
    }
  }

  // Map percent [5,1000] → normalized position [0,1]
  double _mapPercentToPos(int percent) {
    final p = _clampScale(percent);
    if (p <= pivotPercent) {
      final q = (p - minPercent) / (pivotPercent - minPercent);
      return q * pivotPos;
    } else {
      final q = (p - pivotPercent) / (maxPercent - pivotPercent);
      return pivotPos + q * (1.0 - pivotPos);
    }
  }

  // Snap normalized position to the pivot when close to it
  double _snapNormalizedPos(double p) {
    if ((p - pivotPos).abs() <= detentEpsilon) return pivotPos;
    if (p < 0.0) return 0.0;
    if (p > 1.0) return 1.0;
    return p;
  }

  @override
  void initState() {
    super.initState();
    _scaleValue = 100;
    _scalePos = _mapPercentToPos(_scaleValue);
    _captureSession();
    final generation = _generation;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_current(generation)) _loadScale();
    });
  }

  void _captureSession() {
    _ownerFfi = ffi;
    _sessionId = ffi.sessionId;
    _clientOwnerId = ffi.clientOwnerId;
  }

  bool _current(int generation) => mounted && generation == _generation &&
      identical(_ownerFfi, ffi) &&
      ffi.isCurrentSessionOwner(_sessionId, _clientOwnerId);

  @override
  void didUpdateWidget(covariant T oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(_ownerFfi, ffi) || _sessionId != ffi.sessionId ||
        _clientOwnerId != ffi.clientOwnerId) {
      _generation++;
      _revision++;
      _cancelDeferredRead();
      _scaleTimer?.cancel();
      _scaleTimer = null;
      _dirty = false;
      _failed = false;
      _scaleValue = 100;
      _scalePos = _mapPercentToPos(_scaleValue);
      _captureSession();
      final generation = _generation;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_current(generation)) _loadScale();
      });
    }
  }

  Future<void> _loadScale() async {
    if (_loading || !_current(_generation)) return;
    final generation = _generation;
    final revision = _revision;
    final canvas = ffi.canvasModel;
    final owner = canvas.captureUpdateOwner();
    if (owner == null) {
      setState(() => _failed = true);
      return;
    }
    if (canvas.customScaleSavePending) {
      _deferRead(canvas, generation);
      return;
    }
    setState(() => _loading = true);
    try {
      final value = await canvas.readCustomScalePercent(owner: owner);
      if (!_current(generation) || !owner.isCurrent ||
          revision != _revision || _dirty) return;
      if (value < minPercent || value > maxPercent) {
        throw StateError('Invalid custom scale');
      }
      setState(() {
        _scaleValue = value;
        _scalePos = _mapPercentToPos(value);
        _failed = false;
      });
      onScaleChanged?.call(value);
    } catch (error, stack) {
      debugPrint('[CustomScale] Read failed: $error');
      debugPrintStack(stackTrace: stack);
      if (_current(generation) && owner.isCurrent &&
          revision == _revision && !_dirty) setState(() => _failed = true);
    } finally {
      _loading = false;
      if (mounted) {
        setState(() {});
        if (generation != _generation && !_dirty) _loadScale();
      }
    }
  }

  void _cancelDeferredRead() {
    final listener = _deferredReadListener;
    if (listener != null) _deferredReadCanvas?.removeListener(listener);
    _deferredReadCanvas = null;
    _deferredReadListener = null;
  }

  void _deferRead(CanvasModel canvas, int generation) {
    _cancelDeferredRead();
    void ready() {
      if (!_current(generation)) {
        _cancelDeferredRead();
      } else if (!canvas.customScaleSavePending) {
        _cancelDeferredRead();
        if (!_dirty) _loadScale();
      }
    }
    _deferredReadCanvas = canvas;
    _deferredReadListener = ready;
    canvas.addListener(ready);
  }

  Future<void> _saveScale() async {
    if (_saving || !_dirty || !_current(_generation)) return;
    final canvas = ffi.canvasModel;
    final owner = canvas.captureUpdateOwner();
    if (owner == null) {
      setState(() => _failed = true);
      return;
    }
    final generation = _generation;
    final revision = _revision;
    final submitted = _scaleValue;
    _saving = true;
    setState(() {});
    try {
      final effective = await canvas.applyCustomScalePercent(submitted, owner: owner);
      if (!_current(generation) || !owner.isCurrent) return;
      if (effective != submitted || effective < minPercent || effective > maxPercent) {
        throw StateError('Custom scale was not applied');
      }
      if (revision == _revision) {
        setState(() {
          _scaleValue = effective;
          _scalePos = _mapPercentToPos(effective);
          _dirty = false;
          _failed = false;
        });
        if (isMobile) HapticFeedback.selectionClick();
        onScaleChanged?.call(effective);
      }
    } catch (error, stack) {
      debugPrint('[CustomScale] Save failed: $error');
      debugPrintStack(stackTrace: stack);
      if (_current(generation) && owner.isCurrent && revision == _revision) {
        setState(() => _failed = true);
      }
    } finally {
      _saving = false;
      if (mounted) {
        setState(() {});
        if (_dirty && _scaleTimer == null &&
            (generation != _generation || revision != _revision)) _saveScale();
      }
    }
  }

  void _editScale(int next, double position) {
    if (!_current(_generation)) return;
    if (next == _scaleValue && position == _scalePos && !_failed) return;
    _cancelDeferredRead();
    _revision++;
    setState(() {
      _scaleValue = next;
      _scalePos = position;
      _dirty = true;
      _failed = false;
    });
    _scaleTimer?.cancel();
    _scaleTimer = Timer(kDebounceCustomScaleDuration, () {
      _scaleTimer = null;
      _saveScale();
    });
    onScaleChanged?.call(next);
  }

  VoidCallback nudgeScale(int delta) {
    final generation = _generation;
    return () {
      if (!_current(generation)) return;
      final next = _clampScale(_scaleValue + delta);
      _editScale(next, _mapPercentToPos(next));
    };
  }

  ValueChanged<double> get onSliderChanged {
    final generation = _generation;
    return (value) {
      if (!_current(generation) || !value.isFinite) return;
      final position = _snapNormalizedPos(value);
      _editScale(_mapPosToPercent(position), position);
    };
  }

  VoidCallback get retryScale {
    final generation = _generation;
    return () {
      if (!_current(generation) || _operationPending) return;
      if (_dirty) {
        _scaleTimer?.cancel();
        _scaleTimer = null;
        _saveScale();
      } else {
        _loadScale();
      }
    };
  }

  Widget buildScaleStatus() => !_failed ? const SizedBox.shrink() : Row(
    mainAxisSize: MainAxisSize.min,
    children: [Text(scaleFailureText), TextButton(
      key: const ValueKey('custom-scale-retry'),
      onPressed: _operationPending ? null : retryScale,
      child: Text(scaleRetryText))]);

  @override
  void dispose() {
    _generation++;
    _cancelDeferredRead();
    _scaleTimer?.cancel();
    _scaleTimer = null;
    super.dispose();
  }
}

import 'package:flutter/material.dart';
import 'package:flutter_gpu_texture_renderer/flutter_gpu_texture_renderer.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:get/get.dart';

import '../../common.dart';
import './desktop_texture_lifecycle.dart';
import './platform_model.dart';

import 'package:texture_rgba_renderer/texture_rgba_renderer.dart'
    if (dart.library.html) 'package:flutter_hbb/web/texture_rgba_renderer.dart';

void _reportTextureLifecycleError(
  String kind,
  int display,
  String operation,
  Object error,
  StackTrace stackTrace,
) {
  debugPrint(
      '$kind texture $operation failed for display $display: ${error.runtimeType}');
  debugPrintStack(stackTrace: stackTrace);
}

class _PixelbufferTexture implements RetirableDesktopTexture {
  _PixelbufferTexture(
      this._display, this._sessionId, this._clientOwnerId, this._ffi)
      : _textureKey = bind.getNextTextureKey() {
    _lifecycle = DesktopTextureLifecycle(
      initialize: _initialize,
      publish: _publish,
      unpublish: _unpublish,
      release: _release,
      onError: (operation, error, stackTrace) => _reportTextureLifecycleError(
          'pixelbuffer', _display, operation, error, stackTrace),
    );
  }

  final int _textureKey;
  final int _display;
  final SessionID _sessionId;
  final SessionID _clientOwnerId;
  final FFI _ffi;
  int? _id;
  final textureRenderer = TextureRgbaRenderer();
  late final DesktopTextureLifecycle _lifecycle;
  int? _ptr;

  void start() {
    _lifecycle.start();
  }

  Future<bool> _initialize() async {
    final id = await textureRenderer.createTexture(_textureKey);
    _id = id;
    if (id == -1) {
      return false;
    }
    final ptr = await textureRenderer.getTexturePtr(_textureKey);
    _ptr = ptr;
    return ptr != 0;
  }

  void _publish() {
    final id = _id;
    final ptr = _ptr;
    if (id == null || id == -1 || ptr == null || ptr == 0) {
      return;
    }
    _ffi.textureModel.setRgbaTextureId(display: _display, id: id);
    platformFFI.registerPixelbufferTexture(
        _sessionId, _clientOwnerId, _display, ptr);
    debugPrint(
        "create pixelbuffer texture: peerId: ${_ffi.id} display:$_display, textureId:$id, texturePtr:$ptr");
  }

  void _unpublish() {
    try {
      platformFFI.registerPixelbufferTexture(
          _sessionId, _clientOwnerId, _display, 0);
    } finally {
      final id = _id;
      if (id != null && id != -1) {
        _ffi.textureModel.clearRgbaTextureId(display: _display, id: id);
      }
    }
  }

  Future<void> _release() async {
    final id = _id;
    if (id == null || id == -1) {
      return;
    }
    final closed = await textureRenderer.closeTexture(_textureKey);
    if (!closed) {
      debugPrint(
          'Failed to close pixelbuffer texture key $_textureKey for display $_display');
    }
    debugPrint(
        "destroy pixelbuffer texture: peerId: ${_ffi.id} display:$_display, textureId:$id");
  }

  @override
  Future<void> retire() => _lifecycle.retire();
}

class _GpuTexture implements RetirableDesktopTexture {
  _GpuTexture(this._display, this._sessionId, this._clientOwnerId, this._ffi)
      : support = bind.mainHasGpuTextureRender() {
    if (support) {
      _lifecycle = DesktopTextureLifecycle(
        initialize: _initialize,
        publish: _publish,
        unpublish: _unpublish,
        release: _release,
        onError: (operation, error, stackTrace) => _reportTextureLifecycleError(
            'GPU', _display, operation, error, stackTrace),
      );
    }
  }

  final int _display;
  final SessionID _sessionId;
  final SessionID _clientOwnerId;
  final FFI _ffi;
  final bool support;
  int? _id;
  int? _output;
  final gpuTextureRenderer = FlutterGpuTextureRenderer();
  DesktopTextureLifecycle? _lifecycle;

  void start() {
    _lifecycle?.start();
  }

  Future<bool> _initialize() async {
    final id = await gpuTextureRenderer.registerTexture();
    _id = id;
    if (id == null) {
      return false;
    }
    final output = await gpuTextureRenderer.output(id);
    _output = output;
    return output != null && output != 0;
  }

  void _publish() {
    final id = _id;
    final output = _output;
    if (id == null || output == null || output == 0) {
      return;
    }
    _ffi.textureModel.setGpuTextureId(display: _display, id: id);
    platformFFI.registerGpuTexture(
        _sessionId, _clientOwnerId, _display, output);
    debugPrint(
        "create gpu texture: peerId: ${_ffi.id} display:$_display, textureId:$id, output:$output");
  }

  void _unpublish() {
    try {
      platformFFI.registerGpuTexture(_sessionId, _clientOwnerId, _display, 0);
    } finally {
      final id = _id;
      if (id != null) {
        _ffi.textureModel.clearGpuTextureId(display: _display, id: id);
      }
    }
  }

  Future<void> _release() async {
    final id = _id;
    if (id == null) {
      return;
    }
    await gpuTextureRenderer.unregisterTexture(id);
    debugPrint(
        "destroy gpu texture: peerId: ${_ffi.id} display:$_display, textureId:$id, output:$_output");
  }

  @override
  Future<void> retire() => _lifecycle?.retire() ?? Future<void>.value();
}

class _DisplayTextures implements RetirableDesktopTexture {
  _DisplayTextures(int display, FFI ffi)
      : _pixelbuffer =
            _PixelbufferTexture(display, ffi.sessionId, ffi.clientOwnerId, ffi),
        _gpu = _GpuTexture(display, ffi.sessionId, ffi.clientOwnerId, ffi) {
    // Do not start either allocation until both exact owners exist. A
    // synchronous constructor failure therefore cannot strand its sibling.
    _pixelbuffer.start();
    _gpu.start();
  }

  final _PixelbufferTexture _pixelbuffer;
  final _GpuTexture _gpu;

  @override
  Future<void> retire() async {
    await Future.wait<void>([_pixelbuffer.retire(), _gpu.retire()]);
  }
}

class _Control {
  RxInt textureID = (-1).obs;

  int _rgbaTextureId = -1;
  int get rgbaTextureId => _rgbaTextureId;
  int _gpuTextureId = -1;
  int get gpuTextureId => _gpuTextureId;
  bool _isGpuTexture = false;
  bool get isGpuTexture => _isGpuTexture;

  setTextureType({bool gpuTexture = false}) {
    _isGpuTexture = gpuTexture;
    textureID.value = _isGpuTexture ? gpuTextureId : rgbaTextureId;
  }

  setRgbaTextureId(int id) {
    _rgbaTextureId = id;
    textureID.value = _isGpuTexture ? gpuTextureId : rgbaTextureId;
  }

  setGpuTextureId(int id) {
    _gpuTextureId = id;
    textureID.value = _isGpuTexture ? gpuTextureId : rgbaTextureId;
  }
}

class TextureModel {
  final WeakReference<FFI> parent;
  final Map<int, _Control> _control = {};
  final Map<int, LatestDesktopTextureSlot<_DisplayTextures>> _textureSlots = {};
  bool _disposed = false;
  Future<void>? _disposeFuture;

  TextureModel(this.parent);

  setTextureType({required int display, required bool gpuTexture}) {
    if (_disposed) return;
    debugPrint("setTextureType: display=$display, isGpuTexture=$gpuTexture");
    ensureControl(display);
    _control[display]?.setTextureType(gpuTexture: gpuTexture);
    // For versions that do not support multiple displays, the display parameter is always 0, need set type of current display
    final ffi = parent.target;
    if (ffi == null) return;
    if (!ffi.ffiModel.pi.isSupportMultiDisplay) {
      final currentDisplay = CurrentDisplayState.find(ffi.id).value;
      if (currentDisplay != display) {
        debugPrint(
            "setTextureType: currentDisplay=$currentDisplay, isGpuTexture=$gpuTexture");
        ensureControl(currentDisplay);
        _control[currentDisplay]?.setTextureType(gpuTexture: gpuTexture);
      }
    }
  }

  setRgbaTextureId({required int display, required int id}) {
    if (_disposed) return;
    ensureControl(display);
    _control[display]?.setRgbaTextureId(id);
  }

  setGpuTextureId({required int display, required int id}) {
    if (_disposed) return;
    ensureControl(display);
    _control[display]?.setGpuTextureId(id);
  }

  clearRgbaTextureId({required int display, required int id}) {
    if (_disposed) return;
    final control = _control[display];
    if (control?.rgbaTextureId == id) {
      control!.setRgbaTextureId(-1);
    }
  }

  clearGpuTextureId({required int display, required int id}) {
    if (_disposed) return;
    final control = _control[display];
    if (control?.gpuTextureId == id) {
      control!.setGpuTextureId(-1);
    }
  }

  RxInt getTextureId(int display) {
    ensureControl(display);
    return _control[display]!.textureID;
  }

  updateCurrentDisplay(int curDisplay) {
    if (isWeb || _disposed) return;
    final ffi = parent.target;
    if (ffi == null) return;
    final desired = <int>{};
    if (curDisplay == kAllDisplayValue) {
      final displays = ffi.ffiModel.pi.getCurDisplays();
      for (var i = 0; i < displays.length; i++) {
        desired.add(i);
      }
    } else {
      desired.add(curDisplay);
    }

    for (final display in desired) {
      final slot = _textureSlots.putIfAbsent(
        display,
        () => LatestDesktopTextureSlot<_DisplayTextures>(
          create: () => _DisplayTextures(display, ffi),
          onError: (operation, error, stackTrace) =>
              _reportTextureLifecycleError(
                  'display', display, operation, error, stackTrace),
        ),
      );
      slot.setWanted(true);
    }
    for (final entry in _textureSlots.entries.toList()) {
      if (!desired.contains(entry.key)) {
        _control.remove(entry.key);
        entry.value.setWanted(false);
      }
    }
  }

  Future<void> dispose() {
    _disposed = true;
    return _disposeFuture ??= _dispose();
  }

  Future<void> _dispose() async {
    await Future.wait<void>(_textureSlots.values.map((slot) => slot.dispose()));
    _textureSlots.clear();
    _control.clear();
  }

  ensureControl(int display) {
    var ctl = _control[display];
    if (ctl == null) {
      ctl = _Control();
      _control[display] = ctl;
    }
  }
}

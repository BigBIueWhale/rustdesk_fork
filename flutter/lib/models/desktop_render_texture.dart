import 'package:flutter/material.dart';
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
    _lifecycle.start();
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
    _ffi.textureModel.setTextureId(display: _display, id: id);
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
        _ffi.textureModel.clearTextureId(display: _display, id: id);
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

class _Control {
  RxInt textureID = (-1).obs;

  int _nativeTextureId = -1;
  int get nativeTextureId => _nativeTextureId;

  setTextureId(int id) {
    _nativeTextureId = id;
    textureID.value = id;
  }
}

class TextureModel {
  final WeakReference<FFI> parent;
  final Map<int, _Control> _control = {};
  final Map<int, LatestDesktopTextureSlot<_PixelbufferTexture>> _textureSlots =
      {};
  bool _disposed = false;
  Future<void>? _disposeFuture;

  TextureModel(this.parent);

  setTextureId({required int display, required int id}) {
    if (_disposed) return;
    ensureControl(display);
    _control[display]?.setTextureId(id);
  }

  clearTextureId({required int display, required int id}) {
    if (_disposed) return;
    final control = _control[display];
    if (control?.nativeTextureId == id) {
      control!.setTextureId(-1);
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
        () => LatestDesktopTextureSlot<_PixelbufferTexture>(
          create: () => _PixelbufferTexture(
              display, ffi.sessionId, ffi.clientOwnerId, ffi),
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

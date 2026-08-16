import 'dart:async';
import 'dart:convert';
import 'dart:js' as js;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'package:flutter_hbb/models/custom_cursor_registry.dart';
import 'package:flutter_hbb/models/model.dart' as model;

class CursorData {
  const CursorData({
    required this.key,
    required this.url,
    required this.hotX,
    required this.hotY,
  });

  final String key;
  final String url;
  final double hotX;
  final double hotY;
}

class CursorManager {
  CursorManager._();

  static final CursorManager instance = CursorManager._();

  final Map<String, CursorData> _cursors = <String, CursorData>{};
  String _latestKey = '';

  Future<String> registerCursor(CursorData data) async {
    _cursors[data.key] = data;
    return data.key;
  }

  Future<void> deleteCursor(String key) async {
    _cursors.remove(key);
  }

  Future<void> setSystemCursor(String key) async {
    if (_latestKey == key) {
      return;
    }
    final cursorData = _cursors[key];
    if (cursorData == null) {
      throw StateError('custom cursor is not registered');
    }
    js.context.callMethod('setByName', [
      'cursor',
      jsonEncode({
        'url': cursorData.url,
        'hotx': cursorData.hotX.toInt(),
        'hoty': cursorData.hotY.toInt(),
      })
    ]);
    _latestKey = key;
  }

  Future<void> resetSystemCursor() async {
    js.context.callMethod('setByName', ['cursor', 'auto']);
    _latestKey = '';
  }
}

final _customCursors = CustomCursorRegistry(
  onError: (operation, error, _) => debugPrint(
      'Custom cursor $operation failed: ${error.runtimeType}'),
);
final _cursorActivations = CustomCursorActivationQueue();
final _cursorPresentations = CustomCursorPresentationCoordinator(
  activations: _cursorActivations,
);
final _cursorPresentationFinalizer =
    Finalizer<CustomCursorPresentationToken>((presentation) {
  unawaited(presentation.retire());
});

Future<void> _activateSystemFallback() =>
    CursorManager.instance.resetSystemCursor();

void retireCustomCursorOwner(String owner) =>
    _customCursors.retireOwner(owner);

MouseCursor buildCursorOfCache(
    model.CursorModel cursor, double scale, model.CursorData? cache) {
  if (cache == null) {
    return MouseCursor.defer;
  }
  final target = cache.scaleTarget(scale);
  if (target == null) {
    return MouseCursor.defer;
  }
  final handle = _customCursors.ensure(
    owner: cursor.customCursorOwner,
    logicalKey: target.logicalKey,
    rgbaBytes: target.rgbaBytes,
    register: (platformKey) async {
      final data = cache.dataForTarget(target);
      if (data == null) {
        return false;
      }
      final registered = await CursorManager.instance.registerCursor(CursorData(
        key: platformKey,
        url: 'data:image/png;base64,${base64Encode(data)}',
        hotX: target.hotx,
        hotY: target.hoty,
      ));
      if (registered == platformKey) {
        return true;
      }
      if (registered.isNotEmpty) {
        await CursorManager.instance.deleteCursor(registered);
      }
      return false;
    },
    delete: CursorManager.instance.deleteCursor,
  );
  return handle == null
      ? MouseCursor.defer
      : _RegisteredMemoryCursor(handle);
}

class _RegisteredMemoryCursor extends MouseCursor {
  const _RegisteredMemoryCursor(this.handle);

  final CustomCursorHandle handle;

  @override
  MouseCursorSession createSession(int device) =>
      _RegisteredMemoryCursorSession(this, device);

  @override
  String get debugDescription =>
      objectRuntimeType(this, 'RegisteredMemoryCursor');

  @override
  bool operator ==(Object other) =>
      other is _RegisteredMemoryCursor &&
      other.handle.platformKey == handle.platformKey;

  @override
  int get hashCode => handle.platformKey.hashCode;
}

class _RegisteredMemoryCursorSession extends MouseCursorSession {
  _RegisteredMemoryCursorSession(_RegisteredMemoryCursor cursor, int device)
      : super(cursor, device) {
    _presentation = CustomCursorPresentationToken(
      coordinator: _cursorPresentations,
      fallback: _activateSystemFallback,
      onError: (error, _) => debugPrint(
          'Custom cursor presentation failed: ${error.runtimeType}'),
    );
    _cursorPresentationFinalizer.attach(this, _presentation, detach: this);
  }

  late final CustomCursorPresentationToken _presentation;
  bool _activationStarted = false;
  bool _disposed = false;

  @override
  _RegisteredMemoryCursor get cursor =>
      super.cursor as _RegisteredMemoryCursor;

  @override
  Future<void> activate() async {
    if (_disposed || _activationStarted) {
      return;
    }
    _activationStarted = true;
    final lease = cursor.handle.acquire();
    if (lease == null) {
      await _presentation.activateFallback(() => !_disposed);
      return;
    }
    await _presentation.activate(
      lease,
      () => !_disposed,
      CursorManager.instance.setSystemCursor,
    );
  }

  @override
  void dispose() {
    _disposed = true;
    _cursorPresentationFinalizer.detach(this);
    unawaited(_presentation.retire());
  }
}

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_custom_cursor/cursor_manager.dart'
    as custom_cursor_manager;

import 'package:flutter_hbb/models/custom_cursor_registry.dart';
import 'package:flutter_hbb/models/model.dart';

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

Future<void> _activateSystemFallback(int device) =>
    SystemMouseCursors.basic.createSession(device).activate();

void retireCustomCursorOwner(String owner) =>
    _customCursors.retireOwner(owner);

MouseCursor buildCursorOfCache(
    CursorModel cursor, double scale, CursorData? cache) {
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
      final registered =
          await custom_cursor_manager.CursorManager.instance.registerCursor(
        custom_cursor_manager.CursorData()
          ..name = platformKey
          ..buffer = data
          ..width = target.width
          ..height = target.height
          ..hotX = target.hotx
          ..hotY = target.hoty,
      );
      if (registered == platformKey) {
        return true;
      }
      if (registered.isNotEmpty) {
        await custom_cursor_manager.CursorManager.instance
            .deleteCursor(registered);
      }
      return false;
    },
    delete: custom_cursor_manager.CursorManager.instance.deleteCursor,
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
    final pointerDevice = device;
    _presentation = CustomCursorPresentationToken(
      coordinator: _cursorPresentations,
      fallback: () => _activateSystemFallback(pointerDevice),
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
      custom_cursor_manager.CursorManager.instance.setSystemCursor,
    );
  }

  @override
  void dispose() {
    _disposed = true;
    _cursorPresentationFinalizer.detach(this);
    unawaited(_presentation.retire());
  }
}

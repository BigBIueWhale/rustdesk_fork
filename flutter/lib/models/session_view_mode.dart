import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/generated_bridge.dart' show ViewModeState;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/platform_model.dart';

enum ViewModeSetting { viewOnly, showMyCursor }

abstract class SessionViewModeStore {
  Future<ViewModeState> read(SessionID session, SessionID owner);
  Future<ViewModeState> write(SessionID session, SessionID owner,
      ViewModeSetting setting, bool enabled);
}

class _NativeViewModeStore implements SessionViewModeStore {
  const _NativeViewModeStore();

  @override
  Future<ViewModeState> read(SessionID session, SessionID owner) =>
      bind.sessionGetViewMode(sessionId: session, clientOwnerId: owner);

  @override
  Future<ViewModeState> write(SessionID session, SessionID owner,
      ViewModeSetting setting, bool enabled) => setting == ViewModeSetting.viewOnly
      ? bind.sessionSetViewOnly(sessionId: session, clientOwnerId: owner, enabled: enabled)
      : bind.sessionSetShowMyCursor(sessionId: session, clientOwnerId: owner, enabled: enabled);
}

class SessionViewMode extends ChangeNotifier {
  SessionViewMode(this.parent, {SessionViewModeStore? store})
      : _store = store ?? const _NativeViewModeStore();

  final WeakReference<FFI> parent;
  final SessionViewModeStore _store;
  (SessionID, SessionID)? _owner;
  ViewModeState? _value;
  bool _failed = false;
  (ViewModeSetting, bool)? _retry;
  bool _disposed = false;
  Future<void>? _pending;
  int _revision = 0;

  bool get busy => _pending != null;
  int get revision => _revision;
  ViewModeState? get value => _current(_owner) ? _value : null;
  bool get failed => _current(_owner) && _failed;
  (ViewModeSetting, bool)? get retryValue => _current(_owner) ? _retry : null;

  bool _current((SessionID, SessionID)? owner) => !_disposed && owner != null &&
      parent.target?.isCurrentSessionOwner(owner.$1, owner.$2) == true;

  (SessionID, SessionID) _capture() {
    final ffi = parent.target;
    if (ffi == null || _disposed) throw StateError('Session owner is unavailable');
    final owner = (ffi.sessionId, ffi.clientOwnerId);
    if (!_current(owner)) throw StateError('Session owner is unavailable');
    return owner;
  }

  void _adopt((SessionID, SessionID) owner) {
    if (_owner == owner) return;
    _owner = owner;
    _value = null;
    _failed = false;
    _retry = null;
  }

  void _publish(ViewModeState state) {
    if (state.showMyCursor && !state.viewOnly) {
      throw StateError('Invalid View mode confirmation');
    }
    if (_value != null && state.revision < _value!.revision) return;
    _value = state;
    final ffi = parent.target!;
    ffi.ffiModel.setViewMode(ffi.id, state.viewOnly, state.showMyCursor);
  }

  void synchronize(ViewModeState state) {
    final owner = _capture();
    _adopt(owner);
    _publish(state);
    _revision++;
    notifyListeners();
  }

  Future<void> refresh() async {
    final owner = _capture();
    final pending = _pending;
    if (pending != null) {
      await pending;
      if (!_current(owner) || (_owner == owner && (value != null || failed))) return;
      if (_pending != null) return refresh();
    }
    await _run(null);
  }

  Future<void> save(ViewModeSetting setting, bool enabled) => _run((setting, enabled));

  Future<void> _run((ViewModeSetting, bool)? requested) async {
    final owner = _capture();
    if (busy) throw StateError('View mode operation is pending');
    final completion = Completer<void>();
    _pending = completion.future;
    _revision++;
    _adopt(owner);
    try {
      notifyListeners();
      final effective = requested == null
          ? await _store.read(owner.$1, owner.$2)
          : await _store.write(owner.$1, owner.$2, requested.$1, requested.$2);
      if (requested != null && (requested.$1 == ViewModeSetting.viewOnly
          ? effective.viewOnly : effective.showMyCursor) != requested.$2) {
        throw StateError('View mode preference was not confirmed');
      }
      if (!_current(owner)) return;
      _publish(effective);
      if (requested != null || _retry == null) {
        _failed = false;
        _retry = null;
      }
    } catch (error) {
      if (_current(owner)) {
        _failed = true;
        _retry = requested ?? _retry;
      }
      rethrow;
    } finally {
      _pending = null;
      completion.complete();
      if (!_disposed) notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _value = null;
    _owner = null;
    super.dispose();
  }
}

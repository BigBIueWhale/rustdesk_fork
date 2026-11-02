import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/platform_model.dart';

abstract class SessionAudioMuteStore {
  Future<bool> read(SessionID session, SessionID owner);
  Future<bool> write(SessionID session, SessionID owner, bool muted);
}

class _NativeAudioMuteStore implements SessionAudioMuteStore {
  const _NativeAudioMuteStore();

  @override
  Future<bool> read(SessionID session, SessionID owner) =>
      bind.sessionGetAudioMuted(sessionId: session, clientOwnerId: owner);

  @override
  Future<bool> write(SessionID session, SessionID owner, bool muted) =>
      bind.sessionSetAudioMuted(
          sessionId: session, clientOwnerId: owner, muted: muted);
}

class SessionAudioMute extends ChangeNotifier {
  SessionAudioMute(this.parent, {SessionAudioMuteStore? store})
      : _store = store ?? const _NativeAudioMuteStore();

  final WeakReference<FFI> parent;
  final SessionAudioMuteStore _store;
  (SessionID, SessionID)? _owner;
  bool? _value;
  bool _failed = false;
  bool? _retry;
  bool _disposed = false;
  Future<void>? _pending;
  int _revision = 0;

  bool get busy => _pending != null;
  int get revision => _revision;
  bool? get value => _current(_owner) ? _value : null;
  bool get failed => _current(_owner) && _failed;
  bool? get retryValue => _current(_owner) ? _retry : null;

  bool _current((SessionID, SessionID)? owner) => !_disposed && owner != null &&
      parent.target?.isCurrentSessionOwner(owner.$1, owner.$2) == true;

  (SessionID, SessionID) _capture() {
    final ffi = parent.target;
    if (ffi == null || _disposed) throw StateError('Session owner is unavailable');
    final owner = (ffi.sessionId, ffi.clientOwnerId);
    if (!_current(owner)) throw StateError('Session owner is unavailable');
    return owner;
  }

  void _notify() {
    if (!_disposed) notifyListeners();
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

  Future<void> save(bool muted) => _run(muted);

  Future<void> _run(bool? requested) async {
    final owner = _capture();
    if (busy) throw StateError('Mute operation is pending');
    final completion = Completer<void>();
    _pending = completion.future;
    _revision++;
    if (_owner != owner) {
      _owner = owner;
      _value = null;
      _failed = false;
      _retry = null;
    }
    try {
      _notify();
      final effective = requested == null
          ? await _store.read(owner.$1, owner.$2)
          : await _store.write(owner.$1, owner.$2, requested);
      if (requested != null && effective != requested) {
        throw StateError('Mute preference was not confirmed');
      }
      if (!_current(owner)) return;
      _value = effective;
      if (requested != null || _retry == null) {
        _failed = false;
        _retry = null;
      }
    } catch (error) {
      if (_current(owner)) {
        _failed = true;
        _retry = requested;
      }
      rethrow;
    } finally {
      _pending = null;
      completion.complete();
      _notify();
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

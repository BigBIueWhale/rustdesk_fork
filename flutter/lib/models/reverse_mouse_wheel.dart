import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/platform_model.dart';

abstract class ReverseMouseWheelStore {
  Future<bool> read(SessionID sessionId, SessionID clientOwnerId);
  Future<bool> write(SessionID sessionId, SessionID clientOwnerId, bool value);
}

class _NativeReverseMouseWheelStore implements ReverseMouseWheelStore {
  const _NativeReverseMouseWheelStore();

  @override
  Future<bool> read(SessionID sessionId, SessionID clientOwnerId) =>
      bind.sessionGetReverseMouseWheel(
          sessionId: sessionId, clientOwnerId: clientOwnerId);

  @override
  Future<bool> write(SessionID sessionId, SessionID clientOwnerId, bool value) =>
      bind.sessionSetReverseMouseWheel(
          sessionId: sessionId, clientOwnerId: clientOwnerId, value: value);
}

class _ReverseWheelOwner {
  _ReverseWheelOwner(this.model, this.ffi)
      : sessionId = ffi.sessionId, clientOwnerId = ffi.clientOwnerId;

  final ReverseMouseWheelPreferences model;
  final FFI ffi;
  final SessionID sessionId;
  final SessionID clientOwnerId;

  bool get isCurrent => !model._disposed && identical(model.parent.target, ffi) &&
      ffi.isCurrentSessionOwner(sessionId, clientOwnerId);
}

class ReverseMouseWheelPreferences extends ChangeNotifier {
  ReverseMouseWheelPreferences(this.parent, {ReverseMouseWheelStore? store})
      : _store = store ?? const _NativeReverseMouseWheelStore();

  final WeakReference<FFI> parent;
  final ReverseMouseWheelStore _store;
  bool _disposed = false;
  bool _reading = false;
  bool _saving = false;
  int _commitRevision = 0;
  bool? _value;
  _ReverseWheelOwner? _valueOwner;

  bool get reading => _reading;
  bool get saving => _saving;
  bool? get value => _valueOwner?.isCurrent == true ? _value : null;

  _ReverseWheelOwner _captureOwner() {
    final ffi = parent.target;
    if (ffi == null || _disposed) throw StateError('Session owner is unavailable');
    final owner = _ReverseWheelOwner(this, ffi);
    if (!owner.isCurrent) throw StateError('Session owner is unavailable');
    return owner;
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  Future<bool> read() async {
    final owner = _captureOwner();
    if (_reading || _saving) throw StateError('Reverse mouse wheel operation is pending');
    final revision = _commitRevision;
    _reading = true;
    try {
      _notify();
      final effective = await _store.read(owner.sessionId, owner.clientOwnerId);
      if (!owner.isCurrent) throw StateError('Session owner was retired');
      if (revision != _commitRevision) {
        final current = value;
        if (current == null) throw StateError('Reverse mouse wheel read was superseded');
        return current;
      }
      _value = effective;
      _valueOwner = owner;
      return effective;
    } finally {
      _reading = false;
      _notify();
    }
  }

  Future<bool> save(bool requested) async {
    final owner = _captureOwner();
    if (_saving) throw StateError('Reverse mouse wheel save is pending');
    _saving = true;
    try {
      _notify();
      final effective = await _store.write(owner.sessionId, owner.clientOwnerId, requested);
      if (effective != requested) throw StateError('Reverse mouse wheel was not applied');
      if (owner.isCurrent) {
        _commitRevision++;
        _value = effective;
        _valueOwner = owner;
      }
      return effective;
    } finally {
      _saving = false;
      _notify();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _value = null;
    _valueOwner = null;
    super.dispose();
  }
}

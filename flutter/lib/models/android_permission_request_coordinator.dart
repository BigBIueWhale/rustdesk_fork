import 'dart:async';

class AndroidPermissionRequest {
  AndroidPermissionRequest({required this.type, required this.id});

  final String type;
  final String id;
  final Completer<bool> _result = Completer<bool>();

  Future<bool> get result => _result.future;

  void _complete(bool granted) => _result.complete(granted);
}

class AndroidPermissionRequestCoordinator {
  AndroidPermissionRequest? _pending;

  AndroidPermissionRequest? begin({
    required String type,
    required String id,
  }) {
    if (_pending != null || type.isEmpty || id.isEmpty) {
      return null;
    }
    return _pending = AndroidPermissionRequest(type: type, id: id);
  }

  String? pendingId(String type) {
    final pending = _pending;
    return pending?.type == type ? pending?.id : null;
  }

  bool complete({
    required String type,
    required String id,
    required bool granted,
  }) {
    final pending = _pending;
    if (pending == null || pending.type != type || pending.id != id) {
      return false;
    }
    _pending = null;
    pending._complete(granted);
    return true;
  }
}

import 'dart:async';

/// Serializes normal-worker FFI display admissions for one exact owner without
/// retaining an unbounded backlog. One operation may run and only the latest
/// successor is retained; superseded or retired callers complete `false` and
/// must not commit UI state.
class DisplaySelectionQueue<Owner> {
  DisplaySelectionQueue(this.owner);

  final Owner owner;
  _DisplaySelectionEntry? _running;
  _DisplaySelectionEntry? _pending;
  bool _retired = false;

  Future<bool> submit(Owner expectedOwner, Future<bool> Function() operation) {
    if (_retired || expectedOwner != owner) {
      return Future.value(false);
    }
    final entry = _DisplaySelectionEntry(operation);
    if (_running == null) {
      _running = entry;
      unawaited(_drain());
    } else {
      _pending?.complete(false);
      _pending = entry;
    }
    return entry.done.future;
  }

  bool retire(Owner expectedOwner) {
    if (expectedOwner != owner) {
      return false;
    }
    if (_retired) {
      return true;
    }
    _retired = true;
    _running?.complete(false);
    _pending?.complete(false);
    _pending = null;
    return true;
  }

  Future<void> _drain() async {
    while (true) {
      final entry = _running;
      if (entry == null) {
        return;
      }
      try {
        final admitted = await entry.operation();
        entry.complete(_retired ? false : admitted);
      } catch (error, stackTrace) {
        if (_retired) {
          entry.complete(false);
        } else {
          entry.completeError(error, stackTrace);
        }
      }
      if (_retired) {
        _running = null;
        return;
      }
      _running = _pending;
      _pending = null;
    }
  }
}

class _DisplaySelectionEntry {
  _DisplaySelectionEntry(this.operation);

  final Future<bool> Function() operation;
  final done = Completer<bool>();

  void complete(bool admitted) {
    if (!done.isCompleted) {
      done.complete(admitted);
    }
  }

  void completeError(Object error, StackTrace stackTrace) {
    if (!done.isCompleted) {
      done.completeError(error, stackTrace);
    }
  }
}

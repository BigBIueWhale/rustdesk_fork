import 'dart:async';

/// Serializes normal-worker FFI display admissions without retaining an
/// unbounded backlog. One operation may run and only the latest successor is
/// retained; a superseded caller completes `false` and must not commit UI state.
class DisplaySelectionQueue {
  _DisplaySelectionEntry? _running;
  _DisplaySelectionEntry? _pending;

  Future<bool> submit(Future<bool> Function() operation) {
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

  Future<void> _drain() async {
    while (true) {
      final entry = _running;
      if (entry == null) {
        return;
      }
      try {
        entry.complete(await entry.operation());
      } catch (error, stackTrace) {
        entry.completeError(error, stackTrace);
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

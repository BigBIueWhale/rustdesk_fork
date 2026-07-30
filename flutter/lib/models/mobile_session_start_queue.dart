import 'dart:async';

enum MobileSessionStartDisposition {
  completed,
  superseded,
  cancelled,
}

class MobileSessionStartQueue<T> {
  MobileSessionStartQueue(this._run);

  final Future<void> Function(T request) _run;
  _MobileSessionStartEntry<T>? _running;
  _MobileSessionStartEntry<T>? _pending;

  Future<MobileSessionStartDisposition> submit(T request) {
    final entry = _MobileSessionStartEntry(request);
    final running = _running;
    if (running == null) {
      _running = entry;
      unawaited(_drain());
    } else {
      _pending?.complete(MobileSessionStartDisposition.superseded);
      _pending = entry;
    }
    return entry.done.future;
  }

  Future<MobileSessionStartDisposition>? cancelPendingOrGetRunning(
      bool Function(T request) matches) {
    final pending = _pending;
    if (pending != null && matches(pending.request)) {
      _pending = null;
      pending.complete(MobileSessionStartDisposition.cancelled);
      return pending.done.future;
    }
    final running = _running;
    if (running != null && matches(running.request)) {
      return running.done.future;
    }
    return null;
  }

  Future<void> _drain() async {
    while (true) {
      final entry = _running;
      if (entry == null) {
        return;
      }
      try {
        await _run(entry.request);
        entry.complete(MobileSessionStartDisposition.completed);
      } catch (error, stackTrace) {
        entry.completeError(error, stackTrace);
      }
      _running = _pending;
      _pending = null;
    }
  }
}

class _MobileSessionStartEntry<T> {
  _MobileSessionStartEntry(this.request);

  final T request;
  final done = Completer<MobileSessionStartDisposition>();

  void complete(MobileSessionStartDisposition disposition) {
    if (!done.isCompleted) {
      done.complete(disposition);
    }
  }

  void completeError(Object error, StackTrace stackTrace) {
    if (!done.isCompleted) {
      done.completeError(error, stackTrace);
    }
  }
}

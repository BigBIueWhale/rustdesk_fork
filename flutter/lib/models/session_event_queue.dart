import 'dart:async';
import 'dart:collection';

enum SessionEventDisposition {
  completed,
  retired,
}

class SessionEventCheckpoint<Owner> {
  const SessionEventCheckpoint._(this.owner, this.generation, this.done);

  final Owner owner;
  final int generation;
  final Future<SessionEventDisposition> done;
}

/// Preserves native stream order for the bounded, low-rate session-state lane.
///
/// Media decode is deliberately not run inside this queue. A media event may
/// instead submit a no-op checkpoint so that state events already observed on
/// the native stream finish before that media event reads their state.
class SessionEventQueue<Owner> {
  SessionEventQueue(this.owner, {this.maxPending = 32}) {
    if (maxPending < 1) {
      throw ArgumentError.value(maxPending, 'maxPending');
    }
  }

  final Owner owner;
  final int maxPending;
  final Queue<_SessionEventEntry> _pending = Queue<_SessionEventEntry>();
  _SessionEventEntry? _running;
  bool _retired = false;
  int _acceptedGeneration = 0;
  int _completedGeneration = 0;

  Future<SessionEventDisposition> submit(
      Owner expectedOwner, Future<void> Function() operation) {
    if (_retired || expectedOwner != owner) {
      return Future.value(SessionEventDisposition.retired);
    }
    if (_pending.length >= maxPending) {
      _retireCurrentAndPending();
      return Future.error(StateError('session event queue capacity exhausted'));
    }

    final entry = _SessionEventEntry(++_acceptedGeneration, operation);
    if (_running == null) {
      _running = entry;
      unawaited(_drain());
    } else {
      _pending.addLast(entry);
    }
    return entry.done.future;
  }

  /// Captures completion of all state work observed before a media event.
  ///
  /// Checkpoints do not enter the queue, so arbitrarily many media events
  /// cannot consume the bounded state-event capacity. [isCurrent] additionally
  /// rejects the checkpoint if a later state event was accepted before the
  /// media continuation resumed.
  SessionEventCheckpoint<Owner> checkpoint(Owner expectedOwner) {
    if (_retired || expectedOwner != owner) {
      return SessionEventCheckpoint._(expectedOwner, _acceptedGeneration,
          Future.value(SessionEventDisposition.retired));
    }
    final tail = _pending.isEmpty ? _running : _pending.last;
    return SessionEventCheckpoint._(
        owner,
        _acceptedGeneration,
        tail?.done.future ?? Future.value(SessionEventDisposition.completed));
  }

  bool isCurrent(SessionEventCheckpoint<Owner> checkpoint) =>
      !_retired &&
      checkpoint.owner == owner &&
      checkpoint.generation == _acceptedGeneration &&
      _completedGeneration >= checkpoint.generation;

  bool retire(Owner expectedOwner) {
    if (expectedOwner != owner) {
      return false;
    }
    if (_retired) {
      return true;
    }
    _retireCurrentAndPending();
    return true;
  }

  void _retireCurrentAndPending() {
    _retired = true;
    _running?.complete(SessionEventDisposition.retired);
    while (_pending.isNotEmpty) {
      _pending.removeFirst().complete(SessionEventDisposition.retired);
    }
  }

  Future<void> _drain() async {
    while (true) {
      final entry = _running;
      if (entry == null) {
        return;
      }
      try {
        await entry.operation();
        if (_retired) {
          entry.complete(SessionEventDisposition.retired);
        } else {
          _completedGeneration = entry.generation;
          entry.complete(SessionEventDisposition.completed);
        }
      } catch (error, stackTrace) {
        if (_retired) {
          entry.complete(SessionEventDisposition.retired);
        } else {
          entry.completeError(error, stackTrace);
          _retireCurrentAndPending();
        }
      }
      if (_retired) {
        _running = null;
        return;
      }
      _running = _pending.isEmpty ? null : _pending.removeFirst();
    }
  }
}

class _SessionEventEntry {
  _SessionEventEntry(this.generation, this.operation);

  final int generation;
  final Future<void> Function() operation;
  final done = Completer<SessionEventDisposition>();

  void complete(SessionEventDisposition disposition) {
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

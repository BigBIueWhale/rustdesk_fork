import 'dart:async';

enum LatestFrameDisposition {
  presented,
  superseded,
  retired,
}

/// Bounds asynchronous frame presentation for one exact owner.
///
/// Each current display generation retains a fixed number of running frames
/// and only its latest successor. Software image conversion uses two running
/// slots so a newer frame can overtake one slow, uncancellable engine future;
/// other callers retain the default single running slot. Recovery may leave
/// uncancellable predecessor drains, but their completions are powerless and
/// the per-key and queue-wide limits still bound them. Different displays
/// drain independently.
class LatestFrameQueue<Owner, Key, Frame> {
  LatestFrameQueue(
    this.owner, {
    this.maxKeys = 32,
    this.maxConcurrentDrainsPerKey = 2,
    this.maxCurrentDrainsPerKey = 1,
  }) {
    if (maxKeys < 1) {
      throw ArgumentError.value(maxKeys, 'maxKeys');
    }
    if (maxConcurrentDrainsPerKey < 1) {
      throw ArgumentError.value(
          maxConcurrentDrainsPerKey, 'maxConcurrentDrainsPerKey');
    }
    if (maxCurrentDrainsPerKey < 1 ||
        maxCurrentDrainsPerKey > maxConcurrentDrainsPerKey) {
      throw ArgumentError.value(
          maxCurrentDrainsPerKey, 'maxCurrentDrainsPerKey');
    }
  }

  final Owner owner;
  final int maxKeys;
  final int maxConcurrentDrainsPerKey;
  final int maxCurrentDrainsPerKey;
  final Map<Key, _LatestFrameLane<Frame>> _lanes = {};
  final Map<Key, int> _activeDrains = {};
  bool _retired = false;
  bool _suspended = false;

  Future<LatestFrameDisposition> submit(
    Owner expectedOwner,
    Key key,
    Frame frame,
    Future<void> Function(Frame frame) present,
  ) {
    final entry = _LatestFrameEntry(frame, present);
    final admission = _admit(expectedOwner, key, entry);
    if (admission == _LatestFrameAdmission.retired) {
      entry.complete(LatestFrameDisposition.retired);
    } else if (admission == _LatestFrameAdmission.exhausted) {
      entry.completeError(StateError('frame presentation capacity exhausted'),
          StackTrace.current);
    }
    return entry.done!.future;
  }

  /// Hands work to the same bounded lane without allocating a completion
  /// future for a high-rate callback that has no completion consumer.
  bool submitObserved(
    Owner expectedOwner,
    Key key,
    Frame frame,
    Future<void> Function(Frame frame) present, {
    required void Function(Object error, StackTrace stackTrace) onError,
  }) {
    final entry = _LatestFrameEntry.observed(frame, present, onError);
    final admission = _admit(expectedOwner, key, entry);
    if (admission == _LatestFrameAdmission.retired) {
      entry.complete(LatestFrameDisposition.retired);
      return false;
    }
    if (admission == _LatestFrameAdmission.exhausted) {
      entry.completeError(StateError('frame presentation capacity exhausted'),
          StackTrace.current);
      return false;
    }
    return true;
  }

  _LatestFrameAdmission _admit(
      Owner expectedOwner, Key key, _LatestFrameEntry<Frame> entry) {
    if (_retired || _suspended || expectedOwner != owner) {
      return _LatestFrameAdmission.retired;
    }

    var lane = _lanes[key];
    if (lane == null) {
      final activeDrains = _activeDrains[key] ?? 0;
      if (activeDrains == 0 && _activeDrains.length >= maxKeys) {
        _retireAll();
        return _LatestFrameAdmission.exhausted;
      }
      // A recovered generation must not wait forever behind a full set of
      // detached engine futures. Refuse visibly before retaining its frame.
      if (activeDrains >= maxConcurrentDrainsPerKey) {
        _retireAll();
        return _LatestFrameAdmission.exhausted;
      }
      lane = _LatestFrameLane<Frame>();
      _lanes[key] = lane;
    }

    if (lane.running.length < maxCurrentDrainsPerKey &&
        (_activeDrains[key] ?? 0) < maxConcurrentDrainsPerKey) {
      _startDrain(key, lane, entry);
    } else {
      lane.pending?.complete(LatestFrameDisposition.superseded);
      lane.pending = entry;
    }
    return _LatestFrameAdmission.accepted;
  }

  /// Stops new work and detaches the exact in-flight generation.
  ///
  /// Asynchronous engine operations cannot be cancelled, so the bounded
  /// current drains may still finish. Their entries are already retired and
  /// they cannot consume successors or report a failure into the replacement
  /// generation.
  bool suspend(Owner expectedOwner) {
    if (_retired || expectedOwner != owner) {
      return false;
    }
    if (_suspended) {
      return true;
    }
    _suspended = true;
    _detachLanes();
    return true;
  }

  /// Starts a fresh generation without waiting for a detached engine future.
  ///
  /// At most [maxConcurrentDrainsPerKey] operations may execute concurrently
  /// for one key across current and detached generations. Exhausting that hard
  /// bound retires the queue visibly instead of leaking uncancellable work
  /// across lifecycle transitions.
  bool recover(Owner expectedOwner) {
    if (_retired || expectedOwner != owner) {
      return false;
    }
    _detachLanes();
    _suspended = false;
    return true;
  }

  bool retire(Owner expectedOwner) {
    if (expectedOwner != owner) {
      return false;
    }
    if (_retired) {
      return true;
    }
    _retireAll();
    return true;
  }

  void _startDrain(Key key, _LatestFrameLane<Frame> lane,
      _LatestFrameEntry<Frame> entry) {
    final drain = _LatestFrameDrain(entry);
    lane.running.add(drain);
    _activeDrains[key] = (_activeDrains[key] ?? 0) + 1;
    unawaited(_drain(key, lane, drain));
  }

  void _startPendingIfPossible(Key key) {
    if (_retired || _suspended) return;
    final lane = _lanes[key];
    if (lane == null ||
        lane.pending == null ||
        lane.running.length >= maxCurrentDrainsPerKey ||
        (_activeDrains[key] ?? 0) >= maxConcurrentDrainsPerKey) {
      return;
    }
    final pending = lane.pending!;
    lane.pending = null;
    _startDrain(key, lane, pending);
  }

  Future<void> _drain(Key key, _LatestFrameLane<Frame> lane,
      _LatestFrameDrain<Frame> drain) async {
    try {
      final entry = drain.entry;
      try {
        await entry.present(entry.frame);
        entry.complete(_retired || drain.detached
            ? LatestFrameDisposition.retired
            : LatestFrameDisposition.presented);
      } catch (error, stackTrace) {
        if (_retired || drain.detached) {
          entry.complete(LatestFrameDisposition.retired);
        } else {
          entry.completeError(error, stackTrace);
          _retireAll();
        }
      }
    } finally {
      if (!drain.detached && identical(_lanes[key], lane)) {
        lane.running.remove(drain);
      }
      final remaining = (_activeDrains[key] ?? 1) - 1;
      if (remaining == 0) {
        _activeDrains.remove(key);
      } else {
        _activeDrains[key] = remaining;
      }
      _startPendingIfPossible(key);
      final current = _lanes[key];
      if (current != null &&
          current.running.isEmpty &&
          current.pending == null) {
        _lanes.remove(key);
      }
    }
  }

  void _detachLanes() {
    for (final lane in _lanes.values) {
      for (final drain in lane.running) {
        drain.detached = true;
        drain.entry.complete(LatestFrameDisposition.retired);
      }
      lane.pending?.complete(LatestFrameDisposition.retired);
      lane.pending = null;
    }
    _lanes.clear();
  }

  void _retireAll() {
    _retired = true;
    _suspended = true;
    _detachLanes();
  }
}

class _LatestFrameLane<Frame> {
  final Set<_LatestFrameDrain<Frame>> running = {};
  _LatestFrameEntry<Frame>? pending;
}

class _LatestFrameDrain<Frame> {
  _LatestFrameDrain(this.entry);

  final _LatestFrameEntry<Frame> entry;
  bool detached = false;
}

enum _LatestFrameAdmission {
  accepted,
  retired,
  exhausted,
}

class _LatestFrameEntry<Frame> {
  _LatestFrameEntry(this.frame, this.present)
      : done = Completer<LatestFrameDisposition>(),
        _onError = null;

  _LatestFrameEntry.observed(this.frame, this.present, this._onError)
      : done = null;

  final Frame frame;
  final Future<void> Function(Frame frame) present;
  final Completer<LatestFrameDisposition>? done;
  final void Function(Object error, StackTrace stackTrace)? _onError;
  bool _completed = false;

  void complete(LatestFrameDisposition disposition) {
    if (_completed) return;
    _completed = true;
    done?.complete(disposition);
  }

  void completeError(Object error, StackTrace stackTrace) {
    if (_completed) return;
    _completed = true;
    final completion = done;
    if (completion != null) {
      completion.completeError(error, stackTrace);
      return;
    }
    try {
      _onError!(error, stackTrace);
    } catch (reportError, reportStackTrace) {
      Zone.current.scheduleMicrotask(() {
        Zone.current.handleUncaughtError(reportError, reportStackTrace);
      });
    }
  }
}

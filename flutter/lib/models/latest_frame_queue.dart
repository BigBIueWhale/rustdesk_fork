import 'dart:async';

enum LatestFrameDisposition {
  presented,
  superseded,
  retired,
}

/// Bounds asynchronous frame presentation for one exact owner.
///
/// Each display may retain one running frame and only its latest successor.
/// Different displays drain independently so one slow decode cannot block an
/// unrelated display.
class LatestFrameQueue<Owner, Key, Frame> {
  LatestFrameQueue(this.owner, {this.maxKeys = 32}) {
    if (maxKeys < 1) {
      throw ArgumentError.value(maxKeys, 'maxKeys');
    }
  }

  final Owner owner;
  final int maxKeys;
  final Map<Key, _LatestFrameLane<Frame>> _lanes = {};
  bool _retired = false;

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
      entry.completeError(
          StateError('frame display capacity exhausted'), StackTrace.current);
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
      entry.completeError(
          StateError('frame display capacity exhausted'), StackTrace.current);
      return false;
    }
    return true;
  }

  _LatestFrameAdmission _admit(Owner expectedOwner, Key key,
      _LatestFrameEntry<Frame> entry) {
    if (_retired || expectedOwner != owner) {
      return _LatestFrameAdmission.retired;
    }

    var lane = _lanes[key];
    if (lane == null) {
      if (_lanes.length >= maxKeys) {
        _retireAll();
        return _LatestFrameAdmission.exhausted;
      }
      lane = _LatestFrameLane<Frame>();
      _lanes[key] = lane;
    }

    if (lane.running == null) {
      lane.running = entry;
      unawaited(_drain(key, lane));
    } else {
      lane.pending?.complete(LatestFrameDisposition.superseded);
      lane.pending = entry;
    }
    return _LatestFrameAdmission.accepted;
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

  Future<void> _drain(Key key, _LatestFrameLane<Frame> lane) async {
    while (true) {
      final entry = lane.running;
      if (entry == null) {
        return;
      }
      try {
        await entry.present(entry.frame);
        entry.complete(_retired
            ? LatestFrameDisposition.retired
            : LatestFrameDisposition.presented);
      } catch (error, stackTrace) {
        if (_retired) {
          entry.complete(LatestFrameDisposition.retired);
        } else {
          entry.completeError(error, stackTrace);
          _retireAll();
        }
      }
      if (_retired) {
        lane.running = null;
        return;
      }
      lane.running = lane.pending;
      lane.pending = null;
      if (lane.running == null) {
        if (identical(_lanes[key], lane)) {
          _lanes.remove(key);
        }
        return;
      }
    }
  }

  void _retireAll() {
    _retired = true;
    for (final lane in _lanes.values) {
      lane.running?.complete(LatestFrameDisposition.retired);
      lane.pending?.complete(LatestFrameDisposition.retired);
      lane.pending = null;
    }
    _lanes.clear();
  }
}

class _LatestFrameLane<Frame> {
  _LatestFrameEntry<Frame>? running;
  _LatestFrameEntry<Frame>? pending;
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

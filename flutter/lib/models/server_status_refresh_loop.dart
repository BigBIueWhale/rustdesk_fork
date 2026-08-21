import 'dart:async';

/// Owns the process-lifetime controlled-side status refresh schedule.
///
/// A refresh turn is never overlapped by a timer tick: the next one-shot timer
/// is armed only after the complete current turn has settled. [close] cancels a
/// pending timer and waits for an in-flight turn, which gives tests and any
/// future process-owner retirement an exact finality boundary.
class ServerStatusRefreshLoop {
  ServerStatusRefreshLoop({
    required Duration interval,
    required Future<void> Function() refresh,
    required void Function(Object error, StackTrace stackTrace) onError,
  })  : _interval = interval,
        _refresh = refresh,
        _onError = onError;

  final Duration _interval;
  final Future<void> Function() _refresh;
  final void Function(Object error, StackTrace stackTrace) _onError;

  Timer? _timer;
  Future<void>? _activeTurn;
  bool _started = false;
  bool _closed = false;

  void start({Future<bool> Function()? initialReady}) {
    if (_started) {
      throw StateError('server status refresh loop is already started');
    }
    if (_closed) {
      throw StateError('server status refresh loop is closed');
    }
    _started = true;
    _arm(Duration.zero, initialReady);
  }

  Future<void> close() async {
    _closed = true;
    _timer?.cancel();
    _timer = null;
    final activeTurn = _activeTurn;
    if (activeTurn != null) {
      await activeTurn;
    }
  }

  void _arm(Duration delay, Future<bool> Function()? initialReady) {
    if (_closed) return;
    if (_timer != null || _activeTurn != null) {
      throw StateError('server status refresh loop already owns scheduled work');
    }
    _timer = Timer(delay, () {
      _timer = null;
      _beginTurn(initialReady);
    });
  }

  void _beginTurn(Future<bool> Function()? initialReady) {
    final turn = _runTurn(initialReady);
    _activeTurn = turn;
    unawaited(turn.whenComplete(() {
      if (identical(_activeTurn, turn)) {
        _activeTurn = null;
      }
      if (!_closed) {
        _arm(_interval, null);
      }
    }));
  }

  Future<void> _runTurn(Future<bool> Function()? initialReady) async {
    try {
      if (initialReady == null || await initialReady()) {
        await _refresh();
      }
    } catch (error, stackTrace) {
      _onError(error, stackTrace);
    }
  }
}

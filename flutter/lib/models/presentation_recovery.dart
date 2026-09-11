typedef PresentationRefreshError = void Function(
    Object error, StackTrace stackTrace);

/// Owns one exact-session readiness callback and rejects stale retirement.
///
/// Mobile reuses one process-wide model while route cleanup is asynchronous.
/// The registration generation prevents an old route from clearing a newer
/// callback even if a session identity is ever reused.
class ExactPresentationReadyCallback<T> {
  int _generation = 0;
  T? _owner;
  void Function()? _callback;

  int register(T owner, void Function() callback) {
    final generation = ++_generation;
    _owner = owner;
    _callback = callback;
    return generation;
  }

  bool unregister(T owner, int generation) {
    if (_owner != owner || _generation != generation) {
      return false;
    }
    clear();
    return true;
  }

  bool notify(T owner) {
    if (_owner != owner) {
      return false;
    }
    final callback = _callback;
    if (callback == null) {
      return false;
    }
    callback();
    return true;
  }

  void clear() {
    _generation += 1;
    _owner = null;
    _callback = null;
  }
}

/// Coalesces presentation recovery across background/focus/visibility events.
///
/// A suspended presentation needs one fresh independently decodable frame when
/// it next becomes visible. Duplicate resume notifications do not create
/// duplicate requests. If another suspend/resume pair occurs while a request is
/// running, one follow-up request is preserved. A failed request remains pending
/// while visible, and an exact connection-readiness notification may retry it
/// without relying on another OS lifecycle event.
class PresentationRecovery {
  bool _refreshPending = false;
  bool _visible = false;
  bool _refreshInFlight = false;
  bool _retired = false;
  int _retryGeneration = 0;

  void suspend() {
    if (_retired) return;
    _refreshPending = true;
    _visible = false;
    _retryGeneration += 1;
  }

  Future<void> resume({
    required bool selected,
    required Future<void> Function() refresh,
    required PresentationRefreshError onError,
  }) async {
    if (_retired || !selected) return;

    _visible = true;
    await _drain(refresh: refresh, onError: onError);
  }

  /// Retries an already-pending visible recovery after the exact viewer round
  /// has established its peer/display authority. Readiness alone never creates
  /// a refresh demand.
  Future<void> readinessChanged({
    required Future<void> Function() refresh,
    required PresentationRefreshError onError,
  }) async {
    if (_retired) return;

    _retryGeneration += 1;
    await _drain(refresh: refresh, onError: onError);
  }

  Future<void> _drain({
    required Future<void> Function() refresh,
    required PresentationRefreshError onError,
  }) async {
    if (_refreshInFlight) return;

    _refreshInFlight = true;
    try {
      while (!_retired && _refreshPending && _visible) {
        _refreshPending = false;
        final attemptGeneration = _retryGeneration;
        try {
          await refresh();
        } catch (error, stackTrace) {
          if (!_retired) {
            _refreshPending = true;
          }
          onError(error, stackTrace);
          if (_retired || !_visible || attemptGeneration == _retryGeneration) {
            return;
          }
        }
      }
    } finally {
      _refreshInFlight = false;
    }
  }

  void retire() {
    _retired = true;
    _refreshPending = false;
    _visible = false;
  }
}

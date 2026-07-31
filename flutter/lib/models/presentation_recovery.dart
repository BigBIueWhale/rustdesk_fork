typedef PresentationRefreshError = void Function(
    Object error, StackTrace stackTrace);

/// Coalesces presentation recovery across background/focus/visibility events.
///
/// A suspended presentation needs one fresh independently decodable frame when
/// it next becomes visible. Duplicate resume notifications do not create
/// duplicate requests. If another suspend/resume pair occurs while a request is
/// running, one follow-up request is preserved.
class PresentationRecovery {
  bool _refreshPending = false;
  bool _resumeDemanded = false;
  bool _refreshInFlight = false;
  bool _retired = false;

  void suspend() {
    if (_retired) return;
    _refreshPending = true;
    _resumeDemanded = false;
  }

  Future<void> resume({
    required bool selected,
    required Future<void> Function() refresh,
    required PresentationRefreshError onError,
  }) async {
    if (_retired || !selected) return;

    _resumeDemanded = true;
    if (_refreshInFlight) return;

    _refreshInFlight = true;
    try {
      while (!_retired && _refreshPending && _resumeDemanded) {
        _refreshPending = false;
        _resumeDemanded = false;
        try {
          await refresh();
        } catch (error, stackTrace) {
          final followUpDemanded = _refreshPending && _resumeDemanded;
          if (!_retired) {
            _refreshPending = true;
            _resumeDemanded = followUpDemanded;
          }
          onError(error, stackTrace);
          if (!followUpDemanded) return;
        }
      }
    } finally {
      _refreshInFlight = false;
    }
  }

  void retire() {
    _retired = true;
    _refreshPending = false;
    _resumeDemanded = false;
  }
}

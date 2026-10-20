typedef ShareRdpChangeError = void Function(
    Object error, StackTrace stackTrace);

/// Owns one settings-page request to change the service-owned Windows RDP
/// sharing policy.
///
/// Admission closes synchronously before the first await so the checkbox and
/// its row cannot submit overlapping requests. The mounted view owns error
/// presentation and the final state refresh; an unmounted view is never called
/// back after the native transaction settles.
class ShareRdpChangeLifecycle {
  bool _pending = false;

  bool get pending => _pending;

  Future<void> request({
    required bool enabled,
    required Future<void> Function(bool enabled) apply,
    required bool Function() isMounted,
    required void Function() notifyChanged,
    required ShareRdpChangeError onError,
  }) async {
    if (_pending) return;
    _pending = true;
    notifyChanged();
    try {
      await apply(enabled);
    } catch (error, stackTrace) {
      if (isMounted()) {
        onError(error, stackTrace);
      }
    } finally {
      if (isMounted()) {
        _pending = false;
        notifyChanged();
      }
    }
  }
}

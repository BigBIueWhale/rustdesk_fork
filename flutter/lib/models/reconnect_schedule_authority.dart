/// Owns admission for generic reconnect callbacks within one viewer session.
///
/// Timer cancellation alone is not an ownership boundary: a callback may already
/// be queued when it is cancelled. A generation makes every replaced callback
/// stale, while [claim] ensures the dialog button and timer cannot both reconnect.
class ReconnectScheduleAuthority {
  int _generation = 0;
  bool _credentialRecoveryActive = false;

  /// Replace any prior generic retry and return the new callback generation.
  ///
  /// Credential recovery deliberately refuses generic retries until the native
  /// connection reports that replacement keying succeeded.
  int? replaceAutomaticRetry({required bool requested}) {
    final generation = ++_generation;
    if (!requested || _credentialRecoveryActive) {
      return null;
    }
    return generation;
  }

  /// Claim a retry exactly once.
  bool claim(int generation) {
    if (_credentialRecoveryActive || generation != _generation) {
      return false;
    }
    ++_generation;
    return true;
  }

  /// Rejected or absent keying material requires an explicit replacement.
  void requireCredentialReplacement() {
    _credentialRecoveryActive = true;
    ++_generation;
  }

  /// Native keying admitted a connection, so ordinary reconnect policy resumes.
  void acceptConnected() {
    _credentialRecoveryActive = false;
    ++_generation;
  }

  /// Retire this UI owner's callbacks and return to the initial state.
  void reset() {
    _credentialRecoveryActive = false;
    ++_generation;
  }
}

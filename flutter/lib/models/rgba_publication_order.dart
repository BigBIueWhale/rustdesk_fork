class RgbaPublicationAdmission<Session extends Object> {
  const RgbaPublicationAdmission._(
      this.session, this.display, this.publication, this.generation);

  final Session session;
  final int display;
  final int publication;
  final int generation;
}

/// Owns commit order for concurrent software-RGBA conversion.
///
/// Rust publication numbers increase within one native session handler. A new
/// session owns a new counter, so it may begin below its predecessor.
/// Admission rejects duplicate native work but does not invalidate an older
/// conversion merely because a newer conversion started. Conversion and UI
/// setup remain provisional; commit must immediately precede synchronous image
/// replacement. Once a higher publication commits, every lower late result is
/// permanently stale, including work still awaiting UI setup.
class ExactRgbaPublicationOrder<Session extends Object> {
  Session? _session;
  int _generation = 0;
  int _highestAdmittedPublication = 0;
  int _committedPublication = 0;

  RgbaPublicationAdmission<Session>? admit(
      Session session, int display, int publication) {
    if (publication <= 0) {
      return null;
    }
    if (_session != session) {
      _generation += 1;
      _session = session;
      _highestAdmittedPublication = 0;
      _committedPublication = 0;
    }
    if (publication <= _highestAdmittedPublication) {
      return null;
    }
    _highestAdmittedPublication = publication;
    return RgbaPublicationAdmission._(
        session, display, publication, _generation);
  }

  bool canComplete(RgbaPublicationAdmission<Session> admission) =>
      admission.generation == _generation &&
      admission.session == _session &&
      admission.publication <= _highestAdmittedPublication &&
      admission.publication > _committedPublication;

  bool commit(RgbaPublicationAdmission<Session> admission) {
    if (!canComplete(admission)) {
      return false;
    }
    _committedPublication = admission.publication;
    return true;
  }

  void retire() {
    _generation += 1;
    _session = null;
    _highestAdmittedPublication = 0;
    _committedPublication = 0;
  }
}

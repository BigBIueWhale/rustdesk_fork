class RgbaPublicationAdmission<Session extends Object> {
  const RgbaPublicationAdmission._(
      this.session, this.display, this.publication, this.generation);

  final Session session;
  final int display;
  final int publication;
  final int generation;
}

class RgbaPublicationCommit<Session extends Object> {
  const RgbaPublicationCommit._(this.session, this.display, this.publication,
      this.generation, this.revision);

  final Session session;
  final int display;
  final int publication;
  final int generation;
  final int revision;
}

/// Owns commit order for concurrent software-RGBA conversion.
///
/// Rust publication numbers increase within one native session handler. A new
/// session owns a new counter, so it may begin below its predecessor.
/// Admission rejects duplicate native work but does not invalidate an older
/// conversion merely because a newer conversion started. The highest frame to
/// *complete* wins: once a higher publication commits, every lower late result
/// is permanently stale. A later completion also rotates the commit revision,
/// preventing an earlier result that is still in asynchronous UI setup from
/// publishing after it.
class ExactRgbaPublicationOrder<Session extends Object> {
  Session? _session;
  int _generation = 0;
  int _highestAdmittedPublication = 0;
  int _committedPublication = 0;
  int _committedDisplay = 0;
  int _commitRevision = 0;

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
      _committedDisplay = 0;
      _commitRevision += 1;
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
      admission.publication <= _highestAdmittedPublication;

  RgbaPublicationCommit<Session>? commit(
      RgbaPublicationAdmission<Session> admission) {
    if (!canComplete(admission) ||
        admission.publication <= _committedPublication) {
      return null;
    }
    _committedPublication = admission.publication;
    _committedDisplay = admission.display;
    _commitRevision += 1;
    return RgbaPublicationCommit._(
      admission.session,
      admission.display,
      admission.publication,
      admission.generation,
      _commitRevision,
    );
  }

  bool isCurrent(RgbaPublicationCommit<Session> commit) =>
      commit.generation == _generation &&
      commit.session == _session &&
      commit.display == _committedDisplay &&
      commit.publication == _committedPublication &&
      commit.revision == _commitRevision;

  void retire() {
    _generation += 1;
    _session = null;
    _highestAdmittedPublication = 0;
    _committedPublication = 0;
    _committedDisplay = 0;
    _commitRevision += 1;
  }
}

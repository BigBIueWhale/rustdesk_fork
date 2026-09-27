class RgbaPublicationAdmission<Session extends Object> {
  const RgbaPublicationAdmission._(
      this.session, this.display, this.publication, this.revision);

  final Session session;
  final int display;
  final int publication;
  final int revision;
}

/// Owns commit order for asynchronous software-RGBA decoding.
///
/// Rust publication numbers increase within one native session handler. A new
/// session owns a new counter, so it may begin below its predecessor. The exact
/// current-session check remains the authority for admitting that replacement.
class ExactRgbaPublicationOrder<Session extends Object> {
  Session? _session;
  int _display = 0;
  int _publication = 0;
  int _revision = 0;

  RgbaPublicationAdmission<Session>? admit(
      Session session, int display, int publication) {
    if (publication <= 0 ||
        (_session == session && publication <= _publication)) {
      return null;
    }
    _session = session;
    _display = display;
    _publication = publication;
    _revision += 1;
    return RgbaPublicationAdmission._(session, display, publication, _revision);
  }

  bool isCurrent(RgbaPublicationAdmission<Session> admission) =>
      admission.revision == _revision &&
      admission.session == _session &&
      admission.display == _display &&
      admission.publication == _publication;

  void retire() {
    _revision += 1;
    _session = null;
    _display = 0;
    _publication = 0;
  }
}

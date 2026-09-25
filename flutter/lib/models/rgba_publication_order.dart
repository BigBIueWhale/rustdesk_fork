import 'dart:async';

enum RgbaPresentationDisposition { painted, retired }

/// Completes when one software-RGBA image reaches its paint sink or is retired.
///
/// Decoding and assigning an image to a model does not mean Flutter consumed it.
/// The native producer may promote its latest pending frame only after this
/// receipt reaches a terminal disposition.
class RgbaPresentationReceipt {
  final Completer<RgbaPresentationDisposition> _completion =
      Completer<RgbaPresentationDisposition>();

  Future<RgbaPresentationDisposition> get done => _completion.future;

  bool get isCompleted => _completion.isCompleted;

  void painted() => _complete(RgbaPresentationDisposition.painted);

  void retire() => _complete(RgbaPresentationDisposition.retired);

  void _complete(RgbaPresentationDisposition disposition) {
    if (!_completion.isCompleted) {
      _completion.complete(disposition);
    }
  }
}

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

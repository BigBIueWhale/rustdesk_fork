import 'package:flutter/foundation.dart';

final peerCredentialChanges = PeerCredentialChanges();

class PeerCredentialChanges extends ChangeNotifier {
  String? _forgottenPeerId;

  // Present only during synchronous notification, including nested notifications.
  String? get forgottenPeerId => _forgottenPeerId;

  void passwordForgotten(String peerId) {
    final previous = _forgottenPeerId;
    _forgottenPeerId = peerId;
    try {
      notifyListeners();
    } finally {
      _forgottenPeerId = previous;
    }
  }
}

enum AndroidScreenSharingCommand {
  requestMediaProjection,
  stopMainService,
}

class AndroidServiceUiState {
  bool _observedRunning = false;
  bool _commandInFlight = false;

  bool get observedRunning => _observedRunning;

  bool get commandInFlight => _commandInFlight;

  bool observeRunning(bool running) {
    if (_observedRunning == running) {
      return false;
    }
    _observedRunning = running;
    return true;
  }

  AndroidScreenSharingCommand screenSharingCommand({
    required bool mediaProjectionReady,
  }) {
    // MainService intentionally survives without an active MediaProjection. Its
    // lifetime therefore cannot decide whether the next screen-sharing action
    // must request capture or stop an already-active capture.
    return mediaProjectionReady
        ? AndroidScreenSharingCommand.stopMainService
        : AndroidScreenSharingCommand.requestMediaProjection;
  }

  Future<bool> runCommand(Future<void> Function() command) async {
    if (_commandInFlight) {
      return false;
    }
    _commandInFlight = true;
    try {
      await command();
      return true;
    } finally {
      _commandInFlight = false;
    }
  }
}

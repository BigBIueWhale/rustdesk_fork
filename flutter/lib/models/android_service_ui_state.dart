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

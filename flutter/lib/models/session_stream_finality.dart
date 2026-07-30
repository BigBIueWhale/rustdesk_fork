class SessionStreamFinality {
  bool _expectedCloseReceived = false;
  bool _unexpectedTerminationReported = false;

  void acceptExpectedClose() {
    _expectedCloseReceived = true;
  }

  bool acceptUnexpectedTermination() {
    if (_expectedCloseReceived || _unexpectedTerminationReported) {
      return false;
    }
    _unexpectedTerminationReported = true;
    return true;
  }
}

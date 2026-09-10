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

class SessionStreamBinding<Owner> {
  const SessionStreamBinding._(this.owner, this.generation);

  final Owner owner;
  final int generation;
}

class SessionStreamGeneration<Owner> {
  int _generation = 0;
  SessionStreamBinding<Owner>? _current;

  SessionStreamBinding<Owner> reserve(Owner owner) {
    final binding = SessionStreamBinding<Owner>._(owner, ++_generation);
    _current = binding;
    return binding;
  }

  bool isCurrent(SessionStreamBinding<Owner> binding) =>
      identical(_current, binding);

  bool retireOwner(Owner owner) {
    final current = _current;
    if (current != null && current.owner != owner) {
      return false;
    }
    _current = null;
    return true;
  }
}

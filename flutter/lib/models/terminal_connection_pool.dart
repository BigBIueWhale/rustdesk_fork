class TerminalConnectionPool<T extends Object> {
  final _entries = <String, _TerminalConnectionEntry<T>>{};

  T? operator [](String peerId) => _entries[peerId]?.owner;

  int get length => _entries.length;

  int referenceCount(String peerId) => _entries[peerId]?.references ?? 0;

  void install(String peerId, T owner) {
    if (identical(_entries[peerId]?.owner, owner)) {
      throw StateError('Terminal connection is already installed');
    }
    _entries[peerId] = _TerminalConnectionEntry(owner);
  }

  bool retain(String peerId, T owner) {
    final entry = _entries[peerId];
    if (entry == null || !identical(entry.owner, owner)) return false;
    entry.references++;
    return true;
  }

  T? release(String peerId, T owner) {
    final entry = _entries[peerId];
    if (entry == null || !identical(entry.owner, owner)) return null;
    if (entry.references > 1) {
      entry.references--;
      return null;
    }
    _entries.remove(peerId);
    return entry.owner;
  }
}

class _TerminalConnectionEntry<T extends Object> {
  _TerminalConnectionEntry(this.owner);

  final T owner;
  int references = 1;
}

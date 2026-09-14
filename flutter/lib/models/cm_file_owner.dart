class CmFileOwner {
  final int connectionId;
  final int registryGeneration;

  const CmFileOwner(this.connectionId, this.registryGeneration);

  bool get isValid => connectionId > 0 && registryGeneration > 0;

  @override
  bool operator ==(Object other) =>
      other is CmFileOwner &&
      other.connectionId == connectionId &&
      other.registryGeneration == registryGeneration;

  @override
  int get hashCode => Object.hash(connectionId, registryGeneration);
}

class CmFileLogEnvelope {
  static const _actions = <String>{
    'transfer',
    'remove',
    'create_dir',
    'rename',
  };

  final CmFileOwner owner;
  final String action;
  final String log;

  const CmFileLogEnvelope(this.owner, this.action, this.log);

  static CmFileLogEnvelope? tryParse(Map<String, dynamic> event) {
    final idValue = event['id'];
    final generationValue = event['registry_generation'];
    final action = event['action'];
    final log = event['log'];
    if (idValue is! String ||
        generationValue is! String ||
        action is! String ||
        log is! String ||
        !_actions.contains(action)) {
      return null;
    }
    final id = int.tryParse(idValue);
    final generation = int.tryParse(generationValue);
    if (id == null || generation == null) {
      return null;
    }
    final owner = CmFileOwner(id, generation);
    return owner.isValid ? CmFileLogEnvelope(owner, action, log) : null;
  }
}

class CmFileOwnerTables<T> {
  final T Function() _createTable;
  final Map<CmFileOwner, T> _tables = <CmFileOwner, T>{};
  CmFileOwner? _selectedOwner;
  CmFileOwner? _pendingOwner;
  int _selectionGeneration = 0;

  CmFileOwnerTables(this._createTable);

  bool reconcile(Iterable<CmFileOwner> activeOwners) {
    final active = activeOwners.where((owner) => owner.isValid).toSet();
    _tables.removeWhere((owner, _) => !active.contains(owner));
    for (final owner in active) {
      _tables.putIfAbsent(owner, _createTable);
    }

    if (_pendingOwner != null && !active.contains(_pendingOwner)) {
      _pendingOwner = null;
      _selectionGeneration += 1;
    }
    final selectedRetired =
        _selectedOwner != null && !active.contains(_selectedOwner);
    if (selectedRetired) {
      _selectedOwner = null;
    }
    return selectedRetired;
  }

  T? tableForPayload(CmFileOwner owner, int payloadConnectionId) =>
      owner.connectionId == payloadConnectionId ? _tables[owner] : null;

  T? tableFor(CmFileOwner owner) => _tables[owner];

  int? reserveSelection(CmFileOwner owner) {
    _selectionGeneration += 1;
    if (!_tables.containsKey(owner)) {
      _pendingOwner = null;
      return null;
    }
    _pendingOwner = owner;
    return _selectionGeneration;
  }

  T? commitSelection(CmFileOwner owner, int selectionGeneration) {
    if (_selectionGeneration != selectionGeneration ||
        _pendingOwner != owner) {
      return null;
    }
    final table = _tables[owner];
    _pendingOwner = null;
    if (table == null) {
      return null;
    }
    _selectedOwner = owner;
    return table;
  }

  void cancelSelection(CmFileOwner owner, int selectionGeneration) {
    if (_selectionGeneration == selectionGeneration &&
        _pendingOwner == owner) {
      _pendingOwner = null;
      _selectionGeneration += 1;
    }
  }

  bool isSelected(CmFileOwner owner) => _selectedOwner == owner;
}

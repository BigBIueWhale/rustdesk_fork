import 'dart:async';
import 'dart:collection';

typedef RegisterCustomCursor = Future<bool> Function(String platformKey);
typedef DeleteCustomCursor = Future<void> Function(String platformKey);
typedef CustomCursorRegistryError = void Function(
    String operation, Object error, StackTrace stackTrace);

void _reportCustomCursorError(
  void Function(Object error, StackTrace stackTrace) report,
  Object error,
  StackTrace stackTrace,
) {
  try {
    report(error, stackTrace);
  } catch (reportError, reportStackTrace) {
    Zone.current.scheduleMicrotask(() {
      Zone.current.handleUncaughtError(reportError, reportStackTrace);
    });
  }
}

/// Serializes platform cursor changes that Flutter intentionally starts without
/// awaiting the previous [MouseCursorSession] activation.
class CustomCursorActivationQueue {
  Future<void> _tail = Future<void>.value();

  Future<void> schedule(Future<void> Function() operation) {
    final predecessor = _tail;
    final turnComplete = Completer<void>();
    _tail = turnComplete.future;
    return _run(predecessor, turnComplete, operation);
  }

  static Future<void> _run(
    Future<void> predecessor,
    Completer<void> turnComplete,
    Future<void> Function() operation,
  ) async {
    await predecessor;
    try {
      await operation();
    } finally {
      turnComplete.complete();
    }
  }
}

/// Owns the one custom cursor that the platform can actually be displaying.
///
/// Flutter may start a replacement activation before the preceding activation
/// has completed, and it does not dispose a session for [PointerRemovedEvent].
/// Keeping presentation ownership here makes those framework details harmless:
/// successful replacement releases the former lease, stale disposal cannot
/// reset a newer cursor, and undisposed or outcome-uncertain registrations stay
/// inside the process-global registry bound until conclusively displaced.
class CustomCursorPresentationCoordinator {
  CustomCursorPresentationCoordinator({
    required CustomCursorActivationQueue activations,
  }) : _activations = activations;

  final CustomCursorActivationQueue _activations;
  Object? _desiredRequest;
  Object? _desiredPresenter;
  Object? _presenter;
  CustomCursorLease? _lease;
  final Map<Object, CustomCursorLease> _uncertainLeases = HashMap.identity();

  void _claimReplacement({required Object presenter}) {
    _desiredRequest = Object();
    _desiredPresenter = presenter;
  }

  Future<bool> activate({
    required Object presenter,
    required CustomCursorLease lease,
    required bool Function() mayPresent,
    required Future<void> Function(String platformKey) present,
    required Future<void> Function() fallback,
    required void Function(Object error, StackTrace stackTrace) onError,
  }) async {
    final request = Object();
    _desiredRequest = request;
    _desiredPresenter = presenter;
    final ready = await lease.ready;
    var presented = false;
    await _activations.schedule(() async {
      if (!identical(_desiredRequest, request) || !mayPresent()) {
        return;
      }
      if (!ready) {
        await _fallback(fallback, onError);
        return;
      }
      try {
        await present(lease.platformKey);
      } catch (error, stackTrace) {
        _reportCustomCursorError(onError, error, stackTrace);
        if (!await _fallback(fallback, onError)) {
          _uncertainLeases[presenter] = lease;
          presented = true;
        }
        return;
      }
      final previous = _lease;
      _presenter = presenter;
      _lease = lease;
      presented = true;
      previous?.release();
      _releaseUncertainLeases(except: lease);
    });
    if (!presented) {
      lease.release();
    }
    return presented;
  }

  Future<void> activateFallback({
    required Object presenter,
    required bool Function() mayPresent,
    required Future<void> Function() fallback,
    required void Function(Object error, StackTrace stackTrace) onError,
  }) {
    final request = Object();
    _desiredRequest = request;
    _desiredPresenter = presenter;
    return _activations.schedule(() async {
      if (identical(_desiredRequest, request) && mayPresent()) {
        await _fallback(fallback, onError);
      }
    });
  }

  Future<void> retire({
    required Object presenter,
    required Future<void> Function() fallback,
    required void Function(Object error, StackTrace stackTrace) onError,
  }) {
    final wasDesired = identical(_desiredPresenter, presenter);
    final handedOff = _desiredPresenter != null && !wasDesired;
    if (wasDesired) {
      _desiredRequest = null;
      _desiredPresenter = null;
    }
    return _activations.schedule(() async {
      // A successor observed at retirement permanently owns display finality.
      // If it is retired before this turn, its own later turn performs the
      // fallback; the predecessor must not take that responsibility back.
      if (handedOff) {
        return;
      }
      final successor = _desiredPresenter;
      if (successor != null && !identical(successor, presenter)) {
        return;
      }
      if (!wasDesired &&
          !identical(_presenter, presenter) &&
          !_uncertainLeases.containsKey(presenter)) {
        return;
      }
      await _fallback(fallback, onError);
    });
  }

  Future<bool> _fallback(
    Future<void> Function() fallback,
    void Function(Object error, StackTrace stackTrace) onError,
  ) async {
    try {
      await fallback();
    } catch (error, stackTrace) {
      // The old custom cursor may still be displayed. Keep its lease until a
      // later successful replacement proves that the platform stopped using it.
      _reportCustomCursorError(onError, error, stackTrace);
      return false;
    }
    final previous = _lease;
    _presenter = null;
    _lease = null;
    previous?.release();
    _releaseUncertainLeases();
    return true;
  }

  void _releaseUncertainLeases({CustomCursorLease? except}) {
    final retained = HashMap<Object, CustomCursorLease>.identity();
    for (final entry in _uncertainLeases.entries) {
      if (identical(entry.value, except)) {
        retained[entry.key] = entry.value;
      } else {
        entry.value.release();
      }
    }
    _uncertainLeases
      ..clear()
      ..addAll(retained);
  }
}

/// A finalizer-safe token for one [MouseCursorSession]. It contains no reference
/// to the session itself.
class CustomCursorPresentationToken {
  CustomCursorPresentationToken({
    required CustomCursorPresentationCoordinator coordinator,
    required Future<void> Function() fallback,
    required void Function(Object error, StackTrace stackTrace) onError,
  })  : _coordinator = coordinator,
        _fallback = fallback,
        _onError = onError;

  final CustomCursorPresentationCoordinator _coordinator;
  final Future<void> Function() _fallback;
  final void Function(Object error, StackTrace stackTrace) _onError;
  final Object _identity = Object();
  bool _activationStarted = false;
  bool _replacementClaimed = false;
  bool _retired = false;
  Future<void>? _retirement;

  void _claimReplacementOf(CustomCursorPresentationToken previous) {
    if (_retired ||
        _activationStarted ||
        _replacementClaimed ||
        identical(this, previous) ||
        !identical(_coordinator, previous._coordinator)) {
      throw StateError('invalid custom cursor presentation replacement');
    }
    _replacementClaimed = true;
    _coordinator._claimReplacement(presenter: _identity);
  }

  Future<bool> activate(
    CustomCursorLease lease,
    bool Function() mayPresent,
    Future<void> Function(String platformKey) present,
  ) {
    if (_retired || _activationStarted) {
      lease.release();
      return Future.value(false);
    }
    _activationStarted = true;
    return _coordinator.activate(
      presenter: _identity,
      lease: lease,
      mayPresent: () => !_retired && mayPresent(),
      present: present,
      fallback: _fallback,
      onError: _onError,
    );
  }

  Future<void> activateFallback(bool Function() mayPresent) {
    if (_retired || _activationStarted) {
      return Future.value();
    }
    _activationStarted = true;
    return _coordinator.activateFallback(
      presenter: _identity,
      mayPresent: () => !_retired && mayPresent(),
      fallback: _fallback,
      onError: _onError,
    );
  }

  Future<void> retire() {
    final retirement = _retirement;
    if (retirement != null) {
      return retirement;
    }
    _retired = true;
    final started = _coordinator.retire(
      presenter: _identity,
      fallback: _fallback,
      onError: _onError,
    );
    _retirement = started;
    return started;
  }
}

/// Owns every live custom-cursor presentation by its exact UI owner and
/// pointing device.
///
/// Flutter 3.24.5 forgets a `MouseCursorSession` on pointer-device removal
/// without calling its disposal hook. Platform adapters therefore route that
/// removal here. Revocation becomes synchronous before its asynchronous
/// fallback/deletion work begins, and a late stale disposal can retire only its
/// own session object.
class CustomCursorPresentationSessions {
  final Map<int, CustomCursorPresentationSession> _devices = {};

  CustomCursorPresentationSession bind({
    required String owner,
    required int device,
    required CustomCursorPresentationToken presentation,
  }) {
    final session = CustomCursorPresentationSession._(
      sessions: this,
      owner: owner,
      device: device,
      presentation: presentation,
    );
    _claim(session);
    return session;
  }

  Future<void> retireDevice(int device) {
    final session = _devices.remove(device);
    return session?._retireFromSessions() ?? Future<void>.value();
  }

  Future<void> retireOwner(String owner) {
    final owned = _devices.values
        .where((session) => session.owner == owner)
        .toList(growable: false);
    for (final session in owned) {
      if (identical(_devices[session.device], session)) {
        _devices.remove(session.device);
      }
    }
    return Future.wait<void>(
        owned.map((session) => session._retireFromSessions()));
  }

  void _claim(CustomCursorPresentationSession session) {
    final previous = _devices[session.device];
    if (previous != null && !identical(previous, session)) {
      session._presentation._claimReplacementOf(previous._presentation);
    }
    _devices[session.device] = session;
    if (previous != null && !identical(previous, session)) {
      unawaited(previous._retireFromSessions());
    }
  }

  void _retireExact(CustomCursorPresentationSession session) {
    if (identical(_devices[session.device], session)) {
      _devices.remove(session.device);
    }
  }
}

/// A finalizer-safe exact presentation owner. It deliberately contains no
/// reference to the `MouseCursorSession` that uses it.
class CustomCursorPresentationSession {
  CustomCursorPresentationSession._({
    required CustomCursorPresentationSessions sessions,
    required this.owner,
    required this.device,
    required CustomCursorPresentationToken presentation,
  })  : _sessions = sessions,
        _presentation = presentation;

  final CustomCursorPresentationSessions _sessions;
  final CustomCursorPresentationToken _presentation;
  final String owner;
  final int device;
  bool _retired = false;
  Future<void>? _retirement;

  bool get mayPresent => !_retired;

  Future<void> retire() {
    _sessions._retireExact(this);
    return _retireFromSessions();
  }

  Future<void> _retireFromSessions() {
    final retirement = _retirement;
    if (retirement != null) {
      return retirement;
    }
    _retired = true;
    final started = _presentation.retire();
    _retirement = started;
    return started;
  }
}

/// A process-bounded registry for platform cursor objects grouped by UI owner.
///
/// Registration may complete asynchronously, while Flutter's MouseCursorSession
/// disposal callback is synchronous. Entries therefore stay identity-bound until
/// registration and every active lease finish. Capacity eviction removes only an
/// inactive entry; it never asks the platform to delete a cursor that a live
/// pointing-device session may still be displaying.
class CustomCursorRegistry {
  CustomCursorRegistry({
    this.maxEntries = 64,
    this.maxRgbaBytes = 16 * 1024 * 1024,
    this.onError,
  }) {
    if (maxEntries < 1 || maxRgbaBytes < 1) {
      throw ArgumentError('custom cursor registry limits must be positive');
    }
  }

  static const int _maxGeneration = 0x1fffffffffffff;
  static const int _maxOwnerLength = 128;
  static const int _maxLogicalKeyLength = 256;

  final int maxEntries;
  final int maxRgbaBytes;
  final CustomCursorRegistryError? onError;
  final Map<String, _CustomCursorOwner> _owners = {};
  int _generation = 0;
  int _useCounter = 0;
  int _entryCount = 0;
  int _rgbaBytes = 0;
  bool _resourceStateUncertain = false;

  CustomCursorHandle? ensure({
    required String owner,
    required String logicalKey,
    required int rgbaBytes,
    required RegisterCustomCursor register,
    required DeleteCustomCursor delete,
  }) {
    if (_resourceStateUncertain ||
        owner.isEmpty ||
        owner.length > _maxOwnerLength ||
        logicalKey.isEmpty ||
        logicalKey.length > _maxLogicalKeyLength ||
        rgbaBytes < 1 ||
        rgbaBytes > maxRgbaBytes) {
      return null;
    }
    final ownerState = _owners.putIfAbsent(owner, _CustomCursorOwner.new);
    if (ownerState.retired) {
      return null;
    }
    final existing = ownerState.entries.remove(logicalKey);
    if (existing != null) {
      ownerState.entries[logicalKey] = existing;
      _touch(existing);
      return CustomCursorHandle._(this, existing);
    }

    final retiredResources = <Future<bool>>[];
    while (_entryCount >= maxEntries || _rgbaBytes + rgbaBytes > maxRgbaBytes) {
      final victim = _oldestInactiveEntry();
      if (victim == null) {
        _discardEmptyOwner(owner, ownerState);
        return null;
      }
      final victimOwner = _owners[victim.owner];
      if (victimOwner == null) {
        _discardEmptyOwner(owner, ownerState);
        return null;
      }
      retiredResources.add(_remove(victim.owner, victimOwner, victim));
    }

    if (_generation >= _maxGeneration) {
      _discardEmptyOwner(owner, ownerState);
      return null;
    }
    _generation += 1;
    final platformKey = '${owner}_${logicalKey}_g$_generation';
    final entry = _CustomCursorEntry(
      owner: owner,
      logicalKey: logicalKey,
      platformKey: platformKey,
      rgbaBytes: rgbaBytes,
      delete: delete,
    );
    _touch(entry);
    ownerState.entries[logicalKey] = entry;
    ownerState.rgbaBytes += rgbaBytes;
    _entryCount += 1;
    _rgbaBytes += rgbaBytes;
    _owners[owner] = ownerState;
    final ready = Completer<bool>();
    entry.ready = ready.future;
    unawaited(_initializeEntry(ownerState, entry, retiredResources, register)
        .then<void>((value) {
      entry.registrationFinished = true;
      ready.complete(value);
      _registrationFinished(owner, ownerState, entry);
    }, onError: (Object error, StackTrace stack) {
      _reportError('initialize $platformKey', error, stack);
      _registrationFailed(entry);
      entry.registrationFinished = true;
      ready.complete(false);
      _registrationFinished(owner, ownerState, entry);
    }));
    return CustomCursorHandle._(this, entry);
  }

  Future<bool> _initializeEntry(
    _CustomCursorOwner ownerState,
    _CustomCursorEntry entry,
    List<Future<bool>> retiredResources,
    RegisterCustomCursor register,
  ) async {
    for (final retired in retiredResources) {
      if (!await retired) {
        _registrationFailed(entry);
        return false;
      }
    }
    if (_resourceStateUncertain ||
        ownerState.retired ||
        !_owns(ownerState, entry)) {
      _registrationFailed(entry);
      return false;
    }
    bool registered;
    try {
      registered = await register(entry.platformKey);
    } catch (error, stackTrace) {
      _resourceStateUncertain = true;
      entry.registrationUncertain = true;
      _reportError('register ${entry.platformKey}', error, stackTrace);
      registered = false;
    }
    if (!registered) {
      _registrationFailed(entry);
    }
    return registered;
  }

  void retireOwner(String owner) {
    final ownerState = _owners[owner];
    if (ownerState == null || ownerState.retired) {
      return;
    }
    ownerState.retired = true;
    final inactive = ownerState.entries.values
        .where(
            (entry) => entry.activeSessions == 0 && entry.registrationFinished)
        .toList(growable: false);
    for (final entry in inactive) {
      unawaited(_remove(owner, ownerState, entry));
    }
    if (ownerState.entries.isEmpty) {
      _owners.remove(owner);
    }
  }

  int ownerEntryCount(String owner) => _owners[owner]?.entries.length ?? 0;

  int ownerRgbaBytes(String owner) => _owners[owner]?.rgbaBytes ?? 0;

  int get entryCount => _entryCount;

  int get rgbaBytes => _rgbaBytes;

  int get ownerCount => _owners.length;

  CustomCursorLease? _acquire(_CustomCursorEntry entry) {
    final ownerState = _owners[entry.owner];
    if (ownerState == null ||
        ownerState.retired ||
        entry.retired ||
        !identical(ownerState.entries[entry.logicalKey], entry) ||
        entry.activeSessions >= _maxGeneration) {
      return null;
    }
    entry.activeSessions += 1;
    ownerState.entries.remove(entry.logicalKey);
    ownerState.entries[entry.logicalKey] = entry;
    _touch(entry);
    return CustomCursorLease._(this, entry);
  }

  void _release(_CustomCursorEntry entry) {
    if (entry.activeSessions == 0) {
      return;
    }
    entry.activeSessions -= 1;
    final ownerState = _owners[entry.owner];
    if (entry.activeSessions == 0 &&
        entry.registrationFinished &&
        (entry.retired || ownerState == null || ownerState.retired)) {
      if (ownerState != null) {
        unawaited(_remove(entry.owner, ownerState, entry));
      }
    }
  }

  void _registrationFailed(_CustomCursorEntry entry) {
    entry.retired = true;
  }

  void _registrationFinished(
      String owner, _CustomCursorOwner ownerState, _CustomCursorEntry entry) {
    if (entry.activeSessions == 0 &&
        (entry.retired || ownerState.retired) &&
        _owns(ownerState, entry)) {
      unawaited(_remove(owner, ownerState, entry));
    }
  }

  bool _owns(_CustomCursorOwner ownerState, _CustomCursorEntry entry) =>
      identical(ownerState.entries[entry.logicalKey], entry);

  void _discardEmptyOwner(String owner, _CustomCursorOwner ownerState) {
    if (ownerState.entries.isEmpty && identical(_owners[owner], ownerState)) {
      _owners.remove(owner);
    }
  }

  _CustomCursorEntry? _oldestInactiveEntry() {
    _CustomCursorEntry? oldest;
    for (final owner in _owners.values) {
      for (final entry in owner.entries.values) {
        if (entry.activeSessions == 0 &&
            entry.registrationFinished &&
            (oldest == null || entry.lastUsed < oldest.lastUsed)) {
          oldest = entry;
        }
      }
    }
    return oldest;
  }

  void _touch(_CustomCursorEntry entry) {
    if (_useCounter >= _maxGeneration) {
      final entries = _owners.values
          .expand((owner) => owner.entries.values)
          .toList(growable: false)
        ..sort((left, right) => left.lastUsed.compareTo(right.lastUsed));
      _useCounter = 0;
      for (final retained in entries) {
        _useCounter += 1;
        retained.lastUsed = _useCounter;
      }
    }
    _useCounter += 1;
    entry.lastUsed = _useCounter;
  }

  Future<bool> _remove(
      String owner, _CustomCursorOwner ownerState, _CustomCursorEntry entry) {
    if (!_owns(ownerState, entry) ||
        !entry.registrationFinished ||
        entry.activeSessions != 0) {
      return Future.value(false);
    }
    ownerState.entries.remove(entry.logicalKey);
    ownerState.rgbaBytes -= entry.rgbaBytes;
    _entryCount -= 1;
    _rgbaBytes -= entry.rgbaBytes;
    entry.retired = true;
    final retired = entry.ready.then<bool>((registered) async {
      if (!registered && !entry.registrationUncertain) {
        return true;
      }
      try {
        await entry.delete(entry.platformKey);
        return true;
      } catch (error, stackTrace) {
        _resourceStateUncertain = true;
        _reportError('delete ${entry.platformKey}', error, stackTrace);
        return false;
      }
    });
    _discardEmptyOwner(owner, ownerState);
    return retired;
  }

  void _reportError(String operation, Object error, StackTrace stackTrace) {
    final report = onError;
    if (report != null) {
      _reportCustomCursorError(
        (reportedError, reportedStackTrace) =>
            report(operation, reportedError, reportedStackTrace),
        error,
        stackTrace,
      );
    } else {
      Zone.current.scheduleMicrotask(() {
        Zone.current.handleUncaughtError(error, stackTrace);
      });
    }
  }
}

class CustomCursorHandle {
  CustomCursorHandle._(this._registry, this._entry);

  final CustomCursorRegistry _registry;
  final _CustomCursorEntry _entry;

  String get platformKey => _entry.platformKey;

  CustomCursorLease? acquire() => _registry._acquire(_entry);
}

class CustomCursorLease {
  CustomCursorLease._(this._registry, this._entry);

  final CustomCursorRegistry _registry;
  final _CustomCursorEntry _entry;
  bool _released = false;

  String get platformKey => _entry.platformKey;
  Future<bool> get ready => _entry.ready;

  void release() {
    if (_released) {
      return;
    }
    _released = true;
    _registry._release(_entry);
  }
}

class _CustomCursorOwner {
  final LinkedHashMap<String, _CustomCursorEntry> entries = LinkedHashMap();
  int rgbaBytes = 0;
  bool retired = false;
}

class _CustomCursorEntry {
  _CustomCursorEntry({
    required this.owner,
    required this.logicalKey,
    required this.platformKey,
    required this.rgbaBytes,
    required this.delete,
  });

  final String owner;
  final String logicalKey;
  final String platformKey;
  final int rgbaBytes;
  late final Future<bool> ready;
  final DeleteCustomCursor delete;
  int activeSessions = 0;
  int lastUsed = 0;
  bool registrationFinished = false;
  bool registrationUncertain = false;
  bool retired = false;
}

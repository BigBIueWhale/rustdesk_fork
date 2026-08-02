typedef DesktopTextureLifecycleError = void Function(
    String operation, Object error, StackTrace stackTrace);

abstract class RetirableDesktopTexture {
  Future<bool> activate();
  Future<void> retire();
}

/// Owns one asynchronous texture from initialization through native publication
/// and final release.
///
/// Retirement is visible before the first await. A late initialization may
/// finish and is still released, but it can no longer publish itself.
class DesktopTextureLifecycle implements RetirableDesktopTexture {
  DesktopTextureLifecycle({
    required Future<bool> Function() initialize,
    required void Function() publish,
    required void Function() unpublish,
    required Future<void> Function() release,
    required DesktopTextureLifecycleError onError,
  })  : _initialize = initialize,
        _publish = publish,
        _unpublish = unpublish,
        _release = release,
        _onError = onError;

  final Future<bool> Function() _initialize;
  final void Function() _publish;
  final void Function() _unpublish;
  final Future<void> Function() _release;
  final DesktopTextureLifecycleError _onError;

  bool _started = false;
  bool _retireRequested = false;
  bool _publicationAttempted = false;
  bool _unpublicationAttempted = false;
  late Future<bool> _activationFuture;
  Future<void>? _retireFuture;
  Future<void>? _releaseFuture;

  @override
  Future<bool> activate() {
    if (!_started) {
      _started = true;
      _activationFuture = _initializeAndPublish();
    }
    return _activationFuture;
  }

  Future<bool> _initializeAndPublish() async {
    bool ready;
    try {
      ready = await _initialize();
    } catch (error, stackTrace) {
      _onError('initialize', error, stackTrace);
      await _releaseOnce();
      return false;
    }
    if (!ready) {
      _onError(
        'initialize',
        StateError('Desktop texture initialization was rejected'),
        StackTrace.current,
      );
      await _releaseOnce();
      return false;
    }
    if (_retireRequested) {
      return false;
    }

    // Treat a throwing publication as potentially visible. Finalization will
    // attempt the matching unpublication before releasing the resource.
    _publicationAttempted = true;
    try {
      _publish();
      return true;
    } catch (error, stackTrace) {
      _onError('publish', error, stackTrace);
      _unpublishOnce();
      await _releaseOnce();
      return false;
    }
  }

  @override
  Future<void> retire() {
    _retireRequested = true;
    activate();
    return _retireFuture ??= _retire();
  }

  Future<void> _retire() async {
    await _activationFuture;
    _unpublishOnce();
    await _releaseOnce();
  }

  void _unpublishOnce() {
    if (!_publicationAttempted || _unpublicationAttempted) {
      return;
    }
    _unpublicationAttempted = true;
    try {
      _unpublish();
    } catch (error, stackTrace) {
      _onError('unpublish', error, stackTrace);
    }
  }

  Future<void> _releaseOnce() => _releaseFuture ??= _releaseAndReportFailure();

  Future<void> _releaseAndReportFailure() async {
    try {
      await _release();
    } catch (error, stackTrace) {
      _onError('release', error, stackTrace);
    }
  }
}

/// Keeps at most one exact texture owner live. If demand returns while the old
/// owner is retiring, replacement waits for that retirement to finish.
class LatestDesktopTextureSlot<T extends RetirableDesktopTexture> {
  LatestDesktopTextureSlot({
    required T Function() create,
    required DesktopTextureLifecycleError onError,
  })  : _create = create,
        _onError = onError;

  final T Function() _create;
  final DesktopTextureLifecycleError _onError;

  bool _wanted = false;
  bool _disposed = false;
  bool _creationFailed = false;
  int _demandRevision = 0;
  T? _current;
  Future<void>? _reconcileFuture;

  bool get wanted => _wanted;
  bool get hasCurrent => _current != null;

  void setWanted(bool wanted) {
    if (_disposed && wanted) {
      return;
    }
    if (_wanted == wanted) {
      return;
    }
    _wanted = wanted;
    _creationFailed = false;
    _demandRevision += 1;
    _ensureReconcile();
  }

  void _ensureReconcile() {
    if (_reconcileFuture != null) {
      return;
    }
    final future = _reconcile();
    _reconcileFuture = future;
    future.then<void>(
      (_) => _finishReconcile(future),
      onError: (Object error, StackTrace stackTrace) {
        _onError('reconcile', error, stackTrace);
        _finishReconcile(future);
      },
    );
  }

  void _finishReconcile(Future<void> completed) {
    if (!identical(_reconcileFuture, completed)) {
      return;
    }
    _reconcileFuture = null;
    if (!_isSettled) {
      _ensureReconcile();
    }
  }

  bool get _isSettled =>
      _wanted ? _current != null || _creationFailed : _current == null;

  Future<void> _reconcile() async {
    while (!_isSettled) {
      if (_wanted) {
        final demandRevision = _demandRevision;
        late final T candidate;
        try {
          candidate = _create();
        } catch (error, stackTrace) {
          // One failed demand transition is terminal until demand changes.
          // This prevents an immediate retry loop while still allowing a
          // later display switch to retry.
          _creationFailed = true;
          _onError('create', error, stackTrace);
          continue;
        }

        _current = candidate;
        var activated = false;
        try {
          activated = await candidate.activate();
        } catch (error, stackTrace) {
          _onError('activate', error, stackTrace);
        }
        if (!activated) {
          await candidate.retire();
          if (identical(_current, candidate)) {
            _current = null;
          }
          // A stable failed demand is terminal until demand changes. If the
          // display was independently removed and wanted again while this
          // activation was pending, that newer demand owns a fresh attempt.
          if (_wanted && _demandRevision == demandRevision) {
            _creationFailed = true;
          }
        }
        continue;
      }

      final retiring = _current;
      if (retiring == null) {
        continue;
      }
      await retiring.retire();
      if (identical(_current, retiring)) {
        _current = null;
      }
    }
  }

  Future<void> drain() async {
    while (true) {
      if (!_isSettled) {
        _ensureReconcile();
      }
      final pending = _reconcileFuture;
      if (pending != null) {
        await pending;
        continue;
      }
      if (_isSettled) {
        return;
      }
    }
  }

  Future<void> dispose() {
    _disposed = true;
    if (_wanted) {
      _wanted = false;
      _demandRevision += 1;
    }
    _creationFailed = false;
    _ensureReconcile();
    return drain();
  }
}

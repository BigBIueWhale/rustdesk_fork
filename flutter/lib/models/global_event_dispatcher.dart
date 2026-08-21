import 'dart:async';
import 'dart:collection';
import 'dart:convert';

typedef GlobalEventHandler = Future<void>? Function(
    Map<String, dynamic> event);
typedef GlobalEventFailureHandler = void Function(
    Object error, StackTrace stackTrace);

/// Owns the process-global JSON event handoff from Rust/JavaScript to Dart.
///
/// Admission captures an exact registered-handler or fallback generation before
/// any asynchronous work starts. One running entry and a bounded FIFO preserve
/// source order without allowing slow handlers to overlap or accumulate an
/// unbounded number of retained JSON strings. Replacing or retiring an owner
/// removes only that owner's pending work; an already invoked handler is allowed
/// to settle, but can never be redirected to the replacement owner.
class GlobalEventDispatcher {
  GlobalEventDispatcher({
    required GlobalEventFailureHandler onDiagnostic,
    this.maxPending = 64,
    this.maxMessageCodeUnits = 16 * 1024 * 1024,
    this.maxRetainedBytes = 64 * 1024 * 1024,
    this.maxRegisteredHandlers = 256,
    Set<String> synchronousFallbackEvents = const <String>{},
  })  : _onDiagnostic = onDiagnostic,
        _synchronousFallbackEvents =
            Set<String>.unmodifiable(synchronousFallbackEvents) {
    if (maxPending < 1) {
      throw ArgumentError.value(maxPending, 'maxPending');
    }
    if (maxMessageCodeUnits < 1) {
      throw ArgumentError.value(maxMessageCodeUnits, 'maxMessageCodeUnits');
    }
    if (maxRetainedBytes < _entryOverheadBytes + 2) {
      throw ArgumentError.value(maxRetainedBytes, 'maxRetainedBytes');
    }
    if (maxRegisteredHandlers < 1) {
      throw ArgumentError.value(maxRegisteredHandlers, 'maxRegisteredHandlers');
    }
  }

  static const int _entryOverheadBytes = 256;
  static const int _handlerReferenceBytes = 16;

  final int maxPending;
  final int maxMessageCodeUnits;
  final int maxRetainedBytes;
  final int maxRegisteredHandlers;
  final GlobalEventFailureHandler _onDiagnostic;
  final Set<String> _synchronousFallbackEvents;

  final Map<String, Map<String, _RegisteredHandlerBinding>> _handlers = {};
  final Queue<_GlobalEventEntry> _pending = Queue<_GlobalEventEntry>();
  _GlobalEventEntry? _running;
  _FallbackBinding? _fallback;
  Future<void>? _drainFuture;
  int _fallbackGeneration = 0;
  int _registeredHandlerCount = 0;
  int _retainedBytes = 0;

  int get pendingCount => _pending.length;
  bool get hasRunning => _running != null;
  int get retainedBytes => _retainedBytes;

  bool registerHandler(String eventName, String handlerName,
      GlobalEventHandler handler,
      {bool replace = false}) {
    final eventHandlers = _handlers[eventName];
    final existing = eventHandlers?[handlerName];
    if (existing != null) {
      if (!replace) {
        return false;
      }
      existing.retired = true;
      _retirePendingRegisteredHandler(existing);
      eventHandlers![handlerName] = _RegisteredHandlerBinding(handler);
      return true;
    }
    if (_registeredHandlerCount >= maxRegisteredHandlers) {
      _diagnose(StateError('global event handler capacity exhausted'),
          StackTrace.current);
      return false;
    }
    final destination = eventHandlers ??
        _handlers.putIfAbsent(eventName,
            () => <String, _RegisteredHandlerBinding>{});
    destination[handlerName] = _RegisteredHandlerBinding(handler);
    _registeredHandlerCount += 1;
    return true;
  }

  void unregisterHandler(String eventName, String handlerName) {
    final eventHandlers = _handlers[eventName];
    final binding = eventHandlers?.remove(handlerName);
    if (binding == null) {
      return;
    }
    binding.retired = true;
    _registeredHandlerCount -= 1;
    _retirePendingRegisteredHandler(binding);
    if (eventHandlers!.isEmpty) {
      _handlers.remove(eventName);
    }
  }

  /// Installs a new fallback owner and retires pending work for its predecessor.
  ///
  /// The returned generation is the capability required by [retireFallback].
  int replaceFallback(GlobalEventHandler handler,
      {required GlobalEventFailureHandler onFailure}) {
    final previous = _fallback;
    if (previous != null) {
      _retireFallback(previous);
    }
    final binding =
        _FallbackBinding(++_fallbackGeneration, handler, onFailure);
    _fallback = binding;
    return binding.generation;
  }

  /// Retires only the exact fallback generation named by [generation].
  bool retireFallback(int generation) {
    final binding = _fallback;
    if (binding == null || binding.generation != generation) {
      return false;
    }
    _fallback = null;
    _retireFallback(binding);
    return true;
  }

  /// Admits one immutable JSON message to the shared serial handoff.
  ///
  /// Native callers allow both routes. Web's registered-event and global-event
  /// JavaScript callbacks use disjoint routes to preserve their existing ABI.
  bool dispatch(
    String message, {
    bool allowRegistered = true,
    bool allowFallback = true,
  }) {
    final fallback = allowFallback ? _currentFallback() : null;
    if (message.length > maxMessageCodeUnits) {
      _reject(fallback, StateError('global event message is too large'));
      return false;
    }

    late final Map<String, dynamic> event;
    try {
      final decoded = jsonDecode(message);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('global event is not a JSON object');
      }
      event = decoded;
    } catch (error, stackTrace) {
      _reject(fallback, error, stackTrace);
      return false;
    }

    final eventName = event['name'];
    List<_RegisteredHandlerBinding>? registered;
    if (allowRegistered) {
      final eventHandlers =
          eventName is String ? _handlers[eventName] : null;
      if (eventHandlers != null && eventHandlers.isNotEmpty) {
        registered = eventHandlers.values
            .where((binding) => !binding.retired)
            .toList(growable: true);
      }
    }

    final ownsRegisteredRoute = registered != null && registered.isNotEmpty;
    final owner = ownsRegisteredRoute ? null : fallback;
    if (!ownsRegisteredRoute && owner == null) {
      return false;
    }
    if (owner != null &&
        eventName is String &&
        _synchronousFallbackEvents.contains(eventName)) {
      try {
        final completion = owner.handler(event);
        if (completion != null) {
          _failFallback(
              owner,
              StateError('synchronous global event handoff returned a future'),
              StackTrace.current);
          return false;
        }
      } catch (error, stackTrace) {
        _failFallback(owner, error, stackTrace);
        return false;
      }
      return true;
    }
    final handlerCount = registered?.length ?? 0;
    final weight = _entryOverheadBytes +
        message.length * 2 +
        handlerCount * _handlerReferenceBytes;
    if ((_running != null && _pending.length >= maxPending) ||
        weight > maxRetainedBytes ||
        _retainedBytes > maxRetainedBytes - weight) {
      final error = StateError('global event dispatcher capacity exhausted');
      if (owner != null) {
        _failFallback(owner, error, StackTrace.current);
      } else {
        _diagnose(error, StackTrace.current);
      }
      return false;
    }

    final entry = _GlobalEventEntry(message, weight, registered, owner);
    _retainedBytes += weight;
    if (_running == null) {
      _running = entry;
      _startDrain();
    } else {
      _pending.addLast(entry);
    }
    return true;
  }

  /// Makes native stream failure terminal for the exact current fallback owner.
  void failCurrent(Object error, StackTrace stackTrace) {
    final fallback = _currentFallback();
    if (fallback == null) {
      _diagnose(error, stackTrace);
      return;
    }
    _failFallback(fallback, error, stackTrace);
  }

  /// Test/finality hook: waits until the single running owner and FIFO are empty.
  Future<void> idle() async {
    while (_running != null || _drainFuture != null) {
      final drain = _drainFuture;
      if (drain == null) {
        await Future<void>.delayed(Duration.zero);
      } else {
        await drain;
      }
    }
  }

  _FallbackBinding? _currentFallback() {
    final fallback = _fallback;
    return fallback == null || fallback.retired ? null : fallback;
  }

  void _startDrain() {
    if (_drainFuture != null) {
      return;
    }
    final drain = Future<void>.microtask(_drain);
    _drainFuture = drain;
    unawaited(drain.whenComplete(() {
      if (identical(_drainFuture, drain)) {
        _drainFuture = null;
      }
      if (_running != null) {
        _startDrain();
      }
    }));
  }

  Future<void> _drain() async {
    while (true) {
      final entry = _running;
      if (entry == null) {
        return;
      }
      try {
        if (!_entryRetired(entry)) {
          final decoded = jsonDecode(entry.message);
          if (decoded is! Map<String, dynamic>) {
            throw const FormatException('global event is not a JSON object');
          }
          if (entry.registeredHandlers != null) {
            final handlers = List<_RegisteredHandlerBinding>.of(
                entry.registeredHandlers!,
                growable: false);
            for (final binding in handlers) {
              if (!binding.retired) {
                await binding.handler(decoded);
              }
            }
          } else {
            final fallback = entry.fallback;
            if (fallback != null && !fallback.retired) {
              await fallback.handler(decoded);
            }
          }
        }
      } catch (error, stackTrace) {
        final fallback = entry.fallback;
        if (fallback == null || fallback.retired) {
          _diagnose(error, stackTrace);
        } else {
          _failFallback(fallback, error, stackTrace);
        }
      } finally {
        _release(entry);
        _running = _pending.isEmpty ? null : _pending.removeFirst();
      }
    }
  }

  bool _entryRetired(_GlobalEventEntry entry) {
    final fallback = entry.fallback;
    if (fallback != null) {
      return fallback.retired;
    }
    final handlers = entry.registeredHandlers;
    return handlers == null || handlers.every((binding) => binding.retired);
  }

  void _reject(_FallbackBinding? fallback, Object error,
      [StackTrace? stackTrace]) {
    final stack = stackTrace ?? StackTrace.current;
    if (fallback == null) {
      _diagnose(error, stack);
    } else {
      _failFallback(fallback, error, stack);
    }
  }

  void _failFallback(
      _FallbackBinding binding, Object error, StackTrace stackTrace) {
    if (binding.retired) {
      _diagnose(error, stackTrace);
      return;
    }
    if (identical(_fallback, binding)) {
      _fallback = null;
    }
    _retireFallback(binding);
    try {
      binding.onFailure(error, stackTrace);
    } catch (failure, failureStackTrace) {
      _diagnose(failure, failureStackTrace);
    }
  }

  void _retireFallback(_FallbackBinding binding) {
    if (binding.retired) {
      return;
    }
    binding.retired = true;
    _removePending((entry) => identical(entry.fallback, binding));
  }

  void _retirePendingRegisteredHandler(_RegisteredHandlerBinding binding) {
    final kept = Queue<_GlobalEventEntry>();
    while (_pending.isNotEmpty) {
      final entry = _pending.removeFirst();
      final handlers = entry.registeredHandlers;
      if (handlers != null) {
        handlers.removeWhere((candidate) => identical(candidate, binding));
      }
      if (handlers != null && handlers.isEmpty) {
        _release(entry);
      } else {
        kept.addLast(entry);
      }
    }
    _pending.addAll(kept);
  }

  void _removePending(bool Function(_GlobalEventEntry entry) remove) {
    final kept = Queue<_GlobalEventEntry>();
    while (_pending.isNotEmpty) {
      final entry = _pending.removeFirst();
      if (remove(entry)) {
        _release(entry);
      } else {
        kept.addLast(entry);
      }
    }
    _pending.addAll(kept);
  }

  void _release(_GlobalEventEntry entry) {
    if (entry.released) {
      return;
    }
    entry.released = true;
    _retainedBytes -= entry.weight;
  }

  void _diagnose(Object error, StackTrace stackTrace) {
    try {
      _onDiagnostic(error, stackTrace);
    } catch (failure, failureStackTrace) {
      // A diagnostic callback cannot safely be routed into itself. Preserve
      // visibility through the current zone without changing queue ownership.
      Zone.current.handleUncaughtError(failure, failureStackTrace);
    }
  }
}

class _RegisteredHandlerBinding {
  _RegisteredHandlerBinding(this.handler);

  final GlobalEventHandler handler;
  bool retired = false;
}

class _FallbackBinding {
  _FallbackBinding(this.generation, this.handler, this.onFailure);

  final int generation;
  final GlobalEventHandler handler;
  final GlobalEventFailureHandler onFailure;
  bool retired = false;
}

class _GlobalEventEntry {
  _GlobalEventEntry(this.message, this.weight, this.registeredHandlers,
      this.fallback);

  final String message;
  final int weight;
  final List<_RegisteredHandlerBinding>? registeredHandlers;
  final _FallbackBinding? fallback;
  bool released = false;
}

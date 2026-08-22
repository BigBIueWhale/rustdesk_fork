import 'dart:async';
import 'dart:collection';

import 'package:flutter/foundation.dart';

typedef EventCallback<Data> = Future<void> Function(Data data);

abstract class BaseEvent<EventType, Data> {
  final EventType type;
  final Data data;

  BaseEvent(this.type, this.data);

  @visibleForTesting
  Future<void> consume() async {
    final callback = findCallback(type);
    if (callback == null) {
      throw StateError('No callback owns the admitted event');
    }
    await callback(data);
  }

  EventCallback<Data>? findCallback(EventType type);
}

abstract class BaseEventLoop<EventType, Data> {
  BaseEventLoop({required this.maxOwnedEvents}) {
    if (maxOwnedEvents <= 0) {
      throw ArgumentError.value(
          maxOwnedEvents, 'maxOwnedEvents', 'must be positive');
    }
  }

  final int maxOwnedEvents;
  final Queue<BaseEvent<EventType, Data>> _events = Queue();
  var _generation = 0;
  var _closed = true;
  var _draining = false;
  var _eventRunning = false;
  int? _scheduledGeneration;

  @visibleForTesting
  int get ownedEventCount => _events.length + (_eventRunning ? 1 : 0);

  @visibleForTesting
  bool get isClosed => _closed;

  Future<void> onReady() async {
    _generation += 1;
    _closed = false;
    _scheduleDrain(_generation);
  }

  Future<void> onPreConsume(BaseEvent<EventType, Data> event) async {}

  Future<void> onPostConsume(BaseEvent<EventType, Data> event) async {}

  Future<void> onEventsClear() async {}

  void onEventsRetired() {}

  void onTerminalError(BaseEvent<EventType, Data>? event, Object error,
      StackTrace stackTrace) {
    FlutterError.reportError(FlutterErrorDetails(
      exception: error,
      stack: stackTrace,
      library: 'flutter_hbb event loop',
      context: ErrorDescription('while consuming a bounded event'),
    ));
  }

  bool _isCurrent(int generation) =>
      !_closed && generation == _generation;

  void _scheduleDrain(int generation) {
    if (!_isCurrent(generation) ||
        _draining ||
        _events.isEmpty ||
        _scheduledGeneration == generation) {
      return;
    }
    _scheduledGeneration = generation;
    scheduleMicrotask(() {
      if (_scheduledGeneration == generation) {
        _scheduledGeneration = null;
      }
      if (!_isCurrent(generation)) {
        if (!_closed && _events.isNotEmpty) {
          _scheduleDrain(_generation);
        }
        return;
      }
      unawaited(_drain(generation));
    });
  }

  Future<void> _drain(int generation) async {
    if (_draining || !_isCurrent(generation)) return;
    _draining = true;
    BaseEvent<EventType, Data>? currentEvent;
    try {
      while (_events.isNotEmpty) {
        currentEvent = _events.removeFirst();
        _eventRunning = true;
        try {
          await onPreConsume(currentEvent);
          if (!_isCurrent(generation)) return;
          await currentEvent.consume();
          if (!_isCurrent(generation)) return;
          await onPostConsume(currentEvent);
          if (!_isCurrent(generation)) return;
        } finally {
          _eventRunning = false;
        }
        currentEvent = null;
      }
      await onEventsClear();
    } catch (error, stackTrace) {
      if (_isCurrent(generation)) {
        _closed = true;
        _generation += 1;
        _scheduledGeneration = null;
        _events.clear();
        onEventsRetired();
        onTerminalError(currentEvent, error, stackTrace);
      } else {
        FlutterError.reportError(FlutterErrorDetails(
          exception: error,
          stack: stackTrace,
          library: 'flutter_hbb event loop',
          context: ErrorDescription('after an event generation was retired'),
        ));
      }
    } finally {
      _eventRunning = false;
      _draining = false;
      if (!_closed && _events.isNotEmpty) {
        _scheduleDrain(_generation);
      }
    }
  }

  Future<void> close() async {
    _closed = true;
    _generation += 1;
    _scheduledGeneration = null;
    _events.clear();
    onEventsRetired();
  }

  bool pushEvent(BaseEvent<EventType, Data> event) {
    if (_closed || ownedEventCount >= maxOwnedEvents) {
      return false;
    }
    _events.addLast(event);
    _scheduleDrain(_generation);
    return true;
  }
}

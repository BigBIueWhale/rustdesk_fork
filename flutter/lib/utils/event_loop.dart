import 'dart:async';

import 'package:flutter/foundation.dart';

typedef EventCallback<Data> = Future<dynamic> Function(Data data);

abstract class BaseEvent<EventType, Data> {
  EventType type;
  Data data;

  /// Constructor.
  BaseEvent(this.type, this.data);

  /// Consume this event.
  @visibleForTesting
  Future<dynamic> consume() async {
    final cb = findCallback(type);
    if (cb == null) {
      return null;
    } else {
      return cb(data);
    }
  }

  EventCallback<Data>? findCallback(EventType type);
}

abstract class BaseEventLoop<EventType, Data> {
  final List<BaseEvent<EventType, Data>> _evts = [];
  Timer? _timer;
  var _generation = 0;
  var _closed = true;

  List<BaseEvent<EventType, Data>> get evts => _evts;

  Future<void> onReady() async {
    _generation += 1;
    final generation = _generation;
    _closed = false;
    _timer?.cancel();
    // Poll every 100ms.
    _timer = Timer.periodic(Duration(milliseconds: 100),
        (timer) => _handleTimer(timer, generation));
  }

  /// An Event is about to be consumed.
  Future<void> onPreConsume(BaseEvent<EventType, Data> evt) async {}

  /// An Event was consumed.
  Future<void> onPostConsume(BaseEvent<EventType, Data> evt) async {}

  /// Events are all handled and cleared.
  Future<void> onEventsClear() async {}

  /// Events start to consume.
  Future<void> onEventsStartConsuming() async {}

  bool _isCurrent(int generation) => !_closed && generation == _generation;

  Future<void> _handleTimer(Timer timer, int generation) async {
    if (!_isCurrent(generation)) {
      timer.cancel();
      return;
    }
    if (_evts.isEmpty) {
      return;
    }
    timer.cancel();
    _timer = null;
    // Handle the logic.
    await onEventsStartConsuming();
    if (!_isCurrent(generation)) return;
    while (_evts.isNotEmpty) {
      final evt = _evts.removeAt(0);
      await onPreConsume(evt);
      if (!_isCurrent(generation)) return;
      await evt.consume();
      if (!_isCurrent(generation)) return;
      await onPostConsume(evt);
      if (!_isCurrent(generation)) return;
    }
    await onEventsClear();
    if (!_isCurrent(generation)) return;
    // Now events are all processed.
    _timer = Timer.periodic(Duration(milliseconds: 100),
        (timer) => _handleTimer(timer, generation));
  }

  Future<void> close() async {
    _closed = true;
    _generation += 1;
    _timer?.cancel();
    _timer = null;
  }

  void pushEvent(BaseEvent<EventType, Data> evt) {
    _evts.add(evt);
  }

  void clear() {
    _evts.clear();
  }
}

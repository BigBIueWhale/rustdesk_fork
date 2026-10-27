import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Session implements FFI {
  @override
  final sessionId = const Uuid().v4obj();
  @override
  final clientOwnerId = const Uuid().v4obj();
  @override
  final connType = ConnType.portForward;
  bool current = true;
  late final model = FfiModel(WeakReference<FFI>(this));

  @override
  bool isCurrentSession(SessionID id) => current && id == sessionId;

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected session action: ${invocation.memberName}');
}

class _ScheduledRetry {
  _ScheduledRetry(this.duration, this.callback, this.timer);
  final Duration duration;
  final void Function() callback;
  final Timer timer;
}

class _Fixture {
  final session = _Session();
  final manager = OverlayDialogManager(translateText: (text) => text);

  Future<void> mount(WidgetTester tester) async {
    final state = BlockableOverlayState();
    manager.setOverlayState(state);
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(
        state: state,
        underlying: const SizedBox.expand(),
      ),
    ));
  }

  List<_ScheduledRetry> show({bool retry = true}) {
    final timers = <_ScheduledRetry>[];
    runZoned(() {
      session.model.showMsgBox(session.sessionId, 'error', 'Connection Error',
          'Timeout', '', retry, manager);
    }, zoneSpecification: ZoneSpecification(
      createTimer: (self, parent, zone, duration, callback) {
        final timer = parent.createTimer(zone, duration, callback);
        timers.add(_ScheduledRetry(duration, callback, timer));
        return timer;
      },
    ));
    return timers;
  }

  Future<void> close(WidgetTester tester) async {
    session.model.clear();
    session.model.dispose();
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
  }
}

void main() {
  testWidgets('reconnect timer backoff stays bounded through repeated failures',
      (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      final retries = <_ScheduledRetry>[];
      for (var attempt = 0; attempt < 128; attempt++) {
        final retry = fixture.show().single;
        retries.add(retry);
        expect(retry.duration.inSeconds,
            attempt < 5 ? [1, 2, 4, 8, 16][attempt] : 30,
            reason: 'retry ${attempt + 1}');
        expect(retries.where((entry) => entry.timer.isActive), [retry]);
      }
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect countdown agrees with the capped timer', (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      for (final seconds in [1, 2, 4, 8, 16, 30, 30]) {
        final retry = fixture.show().single;
        await tester.pump();
        expect(find.text('Reconnect (${seconds}s)'), findsOneWidget);
        expect(retry.duration, Duration(seconds: seconds));
      }
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect nonretry message cancels and resets the delay',
      (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      fixture.show();
      final previous = fixture.show().single;
      expect(fixture.show(retry: false), isEmpty);
      expect(previous.timer.isActive, isFalse);
      previous.callback();
      expect(fixture.show().single.duration, const Duration(seconds: 1));
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect model reset retires callbacks and resets the delay',
      (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      fixture.show();
      final previous = fixture.show().single;
      fixture.session.model.clear();
      expect(previous.timer.isActive, isFalse);
      previous.callback();
      expect(fixture.show().single.duration, const Duration(seconds: 1));
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect replacement rejects an already queued callback',
      (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      final previous = fixture.show().single;
      final current = fixture.show().single;
      expect(previous.timer.isActive, isFalse);
      previous.callback();
      expect(current.timer.isActive, isTrue);
      await tester.pump();
      expect(find.text('Reconnect (2s)'), findsOneWidget);
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect retired session refuses scheduling and timer actions',
      (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      final pending = fixture.show().single;
      fixture.session.current = false;
      expect(fixture.show(), isEmpty);
      await tester.pump(const Duration(seconds: 2));
      expect(pending.timer.isActive, isFalse);
      expect(tester.takeException(), isNull);
    } finally {
      await fixture.close(tester);
    }
  });

  testWidgets('reconnect keyed event cancels and resets the delay', (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    try {
      fixture.show();
      final previous = fixture.show().single;
      final event = fixture.session.model
          .startEventListener(fixture.session.sessionId, 'reconnect-test');
      await event({'name': 'connection_ready', 'stream_type': 'tcp'});
      expect(previous.timer.isActive, isFalse);
      previous.callback();
      expect(fixture.show().single.duration, const Duration(seconds: 1));
    } finally {
      await fixture.close(tester);
    }
  });
}

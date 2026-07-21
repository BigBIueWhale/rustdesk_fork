import 'package:flutter_hbb/desktop/remote_frame_watchdog.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('reconnects when a focus refresh produces no frame',
      (tester) async {
    var connected = true;
    var refreshes = 0;
    var reconnects = 0;
    final watchdog = RemoteFrameWatchdog(
      isConnected: () => connected,
      refresh: () => refreshes++,
      reconnect: () => reconnects++,
      awayThreshold: const Duration(seconds: 10),
      refreshGrace: const Duration(seconds: 2),
    );
    final blurredAt = DateTime(2026, 1, 1);

    watchdog.onBlur(now: blurredAt);
    watchdog.onFocus(now: blurredAt.add(const Duration(seconds: 11)));
    expect(refreshes, 1);

    await tester.pump(const Duration(seconds: 2));
    expect(reconnects, 1);
    watchdog.dispose();
  });

  testWidgets('a refreshed frame prevents reconnect', (tester) async {
    var reconnects = 0;
    final watchdog = RemoteFrameWatchdog(
      isConnected: () => true,
      refresh: () {},
      reconnect: () => reconnects++,
      awayThreshold: Duration.zero,
      refreshGrace: const Duration(seconds: 2),
    );
    final blurredAt = DateTime(2026, 1, 1);

    watchdog.onBlur(now: blurredAt);
    watchdog.onFocus(now: blurredAt);
    watchdog.onFrame();
    await tester.pump(const Duration(seconds: 2));

    expect(reconnects, 0);
    watchdog.dispose();
  });

  testWidgets('short focus changes do not probe or reconnect', (tester) async {
    var refreshes = 0;
    var reconnects = 0;
    final watchdog = RemoteFrameWatchdog(
      isConnected: () => true,
      refresh: () => refreshes++,
      reconnect: () => reconnects++,
      awayThreshold: const Duration(seconds: 10),
      refreshGrace: const Duration(seconds: 2),
    );
    final blurredAt = DateTime(2026, 1, 1);

    watchdog.onBlur(now: blurredAt);
    watchdog.onFocus(now: blurredAt.add(const Duration(seconds: 9)));
    await tester.pump(const Duration(seconds: 3));

    expect(refreshes, 0);
    expect(reconnects, 0);
    watchdog.dispose();
  });

  testWidgets('disconnected sessions are not reconnected by the watchdog',
      (tester) async {
    var connected = true;
    var reconnects = 0;
    final watchdog = RemoteFrameWatchdog(
      isConnected: () => connected,
      refresh: () {},
      reconnect: () => reconnects++,
      awayThreshold: Duration.zero,
      refreshGrace: const Duration(seconds: 2),
    );
    final blurredAt = DateTime(2026, 1, 1);

    watchdog.onBlur(now: blurredAt);
    watchdog.onFocus(now: blurredAt);
    connected = false;
    await tester.pump(const Duration(seconds: 2));

    expect(reconnects, 0);
    watchdog.dispose();
  });
}

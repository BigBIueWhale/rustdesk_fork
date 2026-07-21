import 'dart:async';

/// Verifies that a remote session can still produce a frame after its window
/// returns from the background.
///
/// A static remote desktop may legitimately send no frames for a long time, so
/// elapsed time alone is not evidence of a dead connection. On focus we first
/// request a refresh; reconnect is only requested if that refresh produces no
/// frame within [refreshGrace].
class RemoteFrameWatchdog {
  RemoteFrameWatchdog({
    required this.isConnected,
    required this.refresh,
    required this.reconnect,
    this.awayThreshold = const Duration(seconds: 15),
    this.refreshGrace = const Duration(seconds: 5),
  });

  final bool Function() isConnected;
  final void Function() refresh;
  final void Function() reconnect;
  final Duration awayThreshold;
  final Duration refreshGrace;

  DateTime? _blurredAt;
  Timer? _refreshTimer;
  int _frameGeneration = 0;

  void onFrame() {
    _frameGeneration++;
    _refreshTimer?.cancel();
    _refreshTimer = null;
  }

  void onBlur({DateTime? now}) {
    _blurredAt = now ?? DateTime.now();
    _refreshTimer?.cancel();
    _refreshTimer = null;
  }

  void onFocus({DateTime? now}) {
    final blurredAt = _blurredAt;
    _blurredAt = null;
    if (blurredAt == null || !isConnected()) {
      return;
    }

    final focusedAt = now ?? DateTime.now();
    if (focusedAt.difference(blurredAt) < awayThreshold) {
      return;
    }

    final generationBeforeRefresh = _frameGeneration;
    refresh();
    _refreshTimer?.cancel();
    _refreshTimer = Timer(refreshGrace, () {
      _refreshTimer = null;
      if (isConnected() && _frameGeneration == generationBeforeRefresh) {
        reconnect();
      }
    });
  }

  void dispose() {
    _refreshTimer?.cancel();
    _refreshTimer = null;
  }
}

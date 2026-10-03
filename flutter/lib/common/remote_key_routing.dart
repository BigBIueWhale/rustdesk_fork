import 'package:flutter/services.dart';

KeyEventResult routeRemoteKeyEvent(
  KeyEvent event, {
  required bool isAndroid,
  required KeyEventResult Function(KeyEvent) forward,
}) {
  // Flutter encodes scan-code-zero KEYCODE_BACK in the Android plane.
  // Leave both edges to local navigation, not the remote keyboard; physical
  // browser-Back keys have their own physical identity and still forward.
  if (isAndroid &&
      event.logicalKey == LogicalKeyboardKey.goBack &&
      event.physicalKey.usbHidUsage == (LogicalKeyboardKey.androidPlane | 4)) {
    return KeyEventResult.ignored;
  }
  return forward(event);
}

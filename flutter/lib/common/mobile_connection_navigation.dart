import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

void closeMobileConnectionRoute(NavigatorState navigator) {
  unawaited(SystemChrome.setEnabledSystemUIMode(SystemUiMode.manual,
          overlays: SystemUiOverlay.values)
      .catchError((Object error, StackTrace _) {
    debugPrint('System UI restoration failed: ${error.runtimeType}');
  }));
  navigator.popUntil(ModalRoute.withName('/'));
}

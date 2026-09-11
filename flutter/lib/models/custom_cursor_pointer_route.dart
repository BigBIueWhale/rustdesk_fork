import 'dart:async';

import 'package:flutter/gestures.dart';

import 'package:flutter_hbb/models/custom_cursor_registry.dart';

/// Routes Flutter pointer-device removal into exact custom-cursor retirement.
class CustomCursorPointerRetirementRoute {
  CustomCursorPointerRetirementRoute(this._sessions);

  final CustomCursorPresentationSessions _sessions;
  late final PointerRoute _route = _handleEvent;
  PointerRouter? _router;

  void install(PointerRouter router) {
    final installed = _router;
    if (installed != null) {
      if (!identical(installed, router)) {
        throw StateError('custom cursor pointer route changed');
      }
      return;
    }
    _router = router;
    router.addGlobalRoute(_route);
  }

  void dispose() {
    final installed = _router;
    if (installed == null) {
      return;
    }
    _router = null;
    installed.removeGlobalRoute(_route);
  }

  void _handleEvent(PointerEvent event) {
    if (event is PointerRemovedEvent) {
      unawaited(_sessions.retireDevice(event.device));
    }
  }
}

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

void closeMobileConnectionRoute(NavigatorState navigator) {
  _restoreSystemUi();
  navigator.popUntil(ModalRoute.withName('/'));
}

void _restoreSystemUi() {
  unawaited(SystemChrome.setEnabledSystemUIMode(SystemUiMode.manual,
          overlays: SystemUiOverlay.values)
      .catchError((Object error, StackTrace _) {
    debugPrint('System UI restoration failed: ${error.runtimeType}');
  }));
}

class MobileConnectionView {
  MobileConnectionRoute? _current;

  MobileConnectionRoute? bind(ModalRoute<dynamic> route,
      {required bool Function() isCurrentSession,
      required void Function(bool atRoot) onClosed}) {
    if (route.navigator == null ||
        !route.isCurrent ||
        route.isFirst ||
        !isCurrentSession()) return null;
    final current = _current;
    if (current != null && current.matchesRoute(route) && current.isCurrent) {
      return current;
    }
    current?._retired = true;
    late final MobileConnectionRoute owner;
    owner = MobileConnectionRoute._(route,
        isCurrentOwner: () => identical(_current, owner) && isCurrentSession(),
        onClosed: onClosed);
    _current = owner;
    return owner;
  }

  void unbind(MobileConnectionRoute owner) {
    if (!identical(_current, owner)) return;
    owner._retired = true;
    _current = null;
  }

  VoidCallback closeCallback({MobileConnectionRoute? route}) {
    final owner = route ?? _current;
    return () {
      if (identical(_current, owner)) owner?.close();
    };
  }
}

class MobileConnectionRoute {
  MobileConnectionRoute._(this._route,
      {required bool Function() isCurrentOwner,
      required void Function(bool atRoot) onClosed})
      : _isCurrentOwner = isCurrentOwner,
        _onClosed = onClosed;

  final ModalRoute<dynamic> _route;
  final bool Function() _isCurrentOwner;
  final void Function(bool atRoot) _onClosed;
  bool _retired = false;

  bool matchesRoute(ModalRoute<dynamic> route) => identical(_route, route);

  bool get isCurrent => !_retired && _isCurrentOwner() && _route.isCurrent;

  bool close() {
    final navigator = _route.navigator;
    if (!isCurrent ||
        navigator == null ||
        !navigator.mounted ||
        _route.isFirst) {
      return false;
    }
    _retired = true;
    _restoreSystemUi();
    navigator.popUntil((route) {
      if (identical(route, _route)) return false;
      _onClosed(route.isFirst);
      return true;
    });
    return true;
  }
}

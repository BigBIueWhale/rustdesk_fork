// ignore_for_file: avoid_web_libraries_in_flutter

import 'dart:js_interop';
import 'dart:typed_data';
import 'dart:js';
import 'dart:html';
import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/state_model.dart';

import 'package:flutter_hbb/web/bridge.dart';
import 'package:flutter_hbb/common.dart';
import 'package:uuid/uuid.dart';
import 'global_event_dispatcher.dart';

final List<StreamSubscription<MouseEvent>> mouseListeners = [];
final List<StreamSubscription<KeyboardEvent>> keyListeners = [];

class PlatformFFI {
  final _eventDispatcher = GlobalEventDispatcher(
    onDiagnostic: (error, stackTrace) =>
        debugPrint('Global event dispatch failed: ${error.runtimeType}'),
    synchronousFallbackEvents: const {
      'cursor_position',
      'cursor_data',
      'cursor_id',
    },
  );
  final RustdeskImpl _ffiBind = RustdeskImpl();

  static String getByName(String name, [String arg = '']) {
    return context.callMethod('getByName', [name, arg]);
  }

  static void setByName(String name, [String value = '']) {
    context.callMethod('setByName', [name, value]);
  }

  PlatformFFI._() {
    window.document.addEventListener(
        'visibilitychange',
        (event) => {
              stateGlobal.isWebVisible =
                  window.document.visibilityState == 'visible'
            });
  }

  static final PlatformFFI instance = PlatformFFI._();

  static get localeName => window.navigator.language;
  RustdeskImpl get ffiBind => _ffiBind;

  static Future<String> getVersion() async {
    throw UnimplementedError();
  }

  bool registerEventHandler(
      String eventName, String handlerName, GlobalEventHandler handler,
      {bool replace = false}) {
    debugPrint('registerEventHandler $eventName $handlerName');
    return _eventDispatcher.registerHandler(eventName, handlerName, handler,
        replace: replace);
  }

  void unregisterEventHandler(String eventName, String handlerName) {
    debugPrint('unregisterEventHandler $eventName $handlerName');
    _eventDispatcher.unregisterHandler(eventName, handlerName);
  }

  String translate(String name, String locale) =>
      _ffiBind.translate(name: name, locale: locale);

  Uint8List? copyRgba(SessionID sessionId, int display, int publication) {
    throw UnimplementedError();
  }

  void nextRgba(SessionID sessionId, int display, int publication) =>
      _ffiBind.sessionNextRgba(
          sessionId: sessionId, display: display, publication: publication);
  bool takeCursorPosition(SessionID sessionId, SessionID clientOwnerId, int x,
          int y, int publication) =>
      _ffiBind.sessionTakeCursorPosition(
          sessionId: sessionId,
          clientOwnerId: clientOwnerId,
          x: x,
          y: y,
          publication: publication);
  bool takeCursorShape(SessionID sessionId, SessionID clientOwnerId, String id,
          int revision, int publication, bool accepted) =>
      _ffiBind.sessionTakeCursorShape(
          sessionId: sessionId,
          clientOwnerId: clientOwnerId,
          id: id,
          revision: revision,
          publication: publication,
          accepted: accepted);
  void registerPixelbufferTexture(
          SessionID sessionId, SessionID clientOwnerId, int display, int ptr) =>
      _ffiBind.sessionRegisterPixelbufferTexture(
          sessionId: sessionId,
          clientOwnerId: clientOwnerId,
          display: display,
          ptr: ptr);

  Future<void> init(String appType) async {
    Completer completer = Completer();
    context["onInitFinished"] = () {
      completer.complete();
    };
    context['dialog'] = (type, title, text) {
      final uuid = Uuid();
      msgBox(SessionID(uuid.v4()), type, title, text, '', gFFI.dialogManager);
    };
    context['closeConnection'] = () {
      gFFI.dialogManager.dismissAll();
      closeConnection();
    };
    context.callMethod('init');
    version = getByName('version');
    window.onContextMenu.listen((event) {
      event.preventDefault();
    });

    context['onRegisteredEvent'] = (String message) {
      _eventDispatcher.dispatch(message, allowFallback: false);
    };
    return completer.future;
  }

  int setEventCallback(GlobalEventHandler fun,
      {required GlobalEventFailureHandler onFailure}) {
    context["onGlobalEvent"] = (String message) {
      _eventDispatcher.dispatch(message, allowRegistered: false);
    };
    return _eventDispatcher.replaceFallback(fun, onFailure: onFailure);
  }

  bool clearEventCallback(int generation) =>
      _eventDispatcher.retireFallback(generation);

  void setRgbaCallback(void Function(int, Uint8List) fun) {
    context["onRgba"] = (int display, Uint8List? rgba) {
      if (rgba != null) {
        fun(display, rgba);
      }
    };
  }

  void startDesktopWebListener() {
    mouseListeners.add(
        window.document.onContextMenu.listen((evt) => evt.preventDefault()));
  }

  void stopDesktopWebListener() {
    for (var ml in mouseListeners) {
      ml.cancel();
    }
    mouseListeners.clear();
    for (var kl in keyListeners) {
      kl.cancel();
    }
    keyListeners.clear();
  }

  void setMethodCallHandler(FMethod callback) {}

  invokeMethod(String method, [dynamic arguments]) async {
    return true;
  }

  // just for compilation
  void syncAndroidServiceAppDirConfigPath() {}

  void setFullscreenCallback(void Function(bool) fun) {
    context["onFullscreenChanged"] = (bool v) {
      fun(v);
    };
  }
}

// ignore_for_file: avoid_web_libraries_in_flutter

import 'dart:convert';
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

final List<StreamSubscription<MouseEvent>> mouseListeners = [];
final List<StreamSubscription<KeyboardEvent>> keyListeners = [];

typedef HandleEvent = Future<void> Function(Map<String, dynamic> evt);

class PlatformFFI {
  final _eventHandlers = <String, Map<String, HandleEvent>>{};
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
      String eventName, String handlerName, HandleEvent handler,
      {bool replace = false}) {
    debugPrint('registerEventHandler $eventName $handlerName');
    var handlers = _eventHandlers[eventName];
    if (handlers == null) {
      _eventHandlers[eventName] = {handlerName: handler};
      return true;
    } else {
      if (!replace && handlers.containsKey(handlerName)) {
        return false;
      } else {
        handlers[handlerName] = handler;
        return true;
      }
    }
  }

  void unregisterEventHandler(String eventName, String handlerName) {
    debugPrint('unregisterEventHandler $eventName $handlerName');
    var handlers = _eventHandlers[eventName];
    if (handlers != null) {
      handlers.remove(handlerName);
    }
  }

  Future<bool> tryHandle(Map<String, dynamic> evt) async {
    final name = evt['name'];
    if (name != null) {
      final handlers = _eventHandlers[name];
      if (handlers != null) {
        if (handlers.isNotEmpty) {
          for (var handler in handlers.values) {
            await handler(evt);
          }
          return true;
        }
      }
    }
    return false;
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
      try {
        Map<String, dynamic> event = json.decode(message);
        tryHandle(event);
      } catch (e) {
        print('json.decode fail(): $e');
      }
    };
    return completer.future;
  }

  void setEventCallback(void Function(Map<String, dynamic>) fun) {
    context["onGlobalEvent"] = (String message) {
      try {
        Map<String, dynamic> event = json.decode(message);
        fun(event);
      } catch (e) {
        print('json.decode fail(): $e');
      }
    };
  }

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

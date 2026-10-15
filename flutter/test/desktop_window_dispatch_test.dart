import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:desktop_multi_window/src/channels.dart' show windowEventChannel;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _password = 'SyntheticPassword1';
const _token = 'SyntheticToken2';

Future<ByteData?> _dispatch(String method, dynamic envelope) async {
  final reply = Completer<ByteData?>();
  await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .handlePlatformMessage(
    windowEventChannel.name,
    windowEventChannel.codec.encodeMethodCall(MethodCall(method, envelope)),
    reply.complete,
  );
  return reply.future;
}

Map<String, dynamic> _envelope(dynamic arguments) => {
      'fromWindowId': 7,
      'arguments': arguments,
    };

void _expectFailure(ByteData? reply, List<String> messages) {
  expect(reply, isNotNull);
  PlatformException? failure;
  try {
    windowEventChannel.codec.decodeEnvelope(reply!);
  } on PlatformException catch (error) {
    failure = error;
  }
  expect(failure, isNotNull);
  expect(failure.toString(), isNot(contains(_password)));
  expect(failure.toString(), isNot(contains(_token)));
  expect(failure!.code, 'window_request_failed');
  expect(failure.message, 'Desktop window request failed');
  expect(failure.details, isNull);
  final text = messages.join('\n');
  expect(text, isNot(contains(_password)));
  expect(text, isNot(contains(_token)));
}

class _Listener extends MultiWindowListener {
  _Listener({this.failure});

  final Object? failure;
  final events = <String>[];

  @override
  void onWindowEvent(String eventName) {
    events.add(eventName);
    final error = failure;
    if (error != null) throw error;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late DebugPrintCallback previousDebugPrint;
  late List<String> messages;

  setUp(() {
    messages = [];
    previousDebugPrint = debugPrint;
    debugPrint = (String? message, {int? wrapWidth}) {
      messages.add(message ?? '');
    };
  });

  tearDown(() {
    DesktopMultiWindow.setMethodHandler(null);
    debugPrint = previousDebugPrint;
  });

  test('window dispatch preserves valid payload and sender', () async {
    var calls = 0;
    final payload = {'password': _password, 'connToken': _token};
    DesktopMultiWindow.setMethodHandler((call, sender) async {
      calls++;
      expect(sender, 7);
      expect(call.method, 'new_file_transfer');
      expect(call.arguments, payload);
      return {'accepted': true};
    });
    final reply = await _dispatch('new_file_transfer', _envelope(payload));
    expect(windowEventChannel.codec.decodeEnvelope(reply!), {'accepted': true});
    expect(calls, 1);
    expect(messages, isEmpty);
  });

  test('window dispatch preserves null and successful event replies', () async {
    var calls = 0;
    DesktopMultiWindow.setMethodHandler((call, sender) async {
      calls++;
      return null;
    });
    final reply = await _dispatch('query', _envelope(null));
    expect(reply, isNotNull);
    expect(windowEventChannel.codec.decodeEnvelope(reply!), isNull);
    final listener = _Listener();
    DesktopMultiWindow.addListener(listener);
    try {
      final eventReply = await _dispatch(
          'onEvent', _envelope({'eventName': 'focus', 'windowId': 4}));
      expect(windowEventChannel.codec.decodeEnvelope(eventReply!), isNull);
      expect(listener.events, ['focus']);
      expect(calls, 1);
      expect(messages, isEmpty);
    } finally {
      DesktopMultiWindow.removeListener(listener);
    }
  });

  test('window dispatch removes its registered handler', () async {
    var calls = 0;
    DesktopMultiWindow.setMethodHandler((call, sender) async => calls++);
    DesktopMultiWindow.setMethodHandler(null);
    expect(await _dispatch('query', _envelope(_password)), isNull);
    expect(calls, 0);
    expect(messages, isEmpty);
  });

  test('window dispatch redacts synchronous handler failure', () async {
    DesktopMultiWindow.setMethodHandler((call, sender) {
      throw StateError(_password + _token);
    });
    _expectFailure(await _dispatch('query', _envelope(null)), messages);
  });

  test('window dispatch redacts asynchronous JSON failure', () async {
    DesktopMultiWindow.setMethodHandler((call, sender) async {
      await Future<void>.value();
      return jsonDecode(call.arguments as String);
    });
    _expectFailure(
        await _dispatch('new_file_transfer',
            _envelope('{"password":"' + _password + _token)),
        messages);
  });

  test('window dispatch redacts platform error fields', () async {
    DesktopMultiWindow.setMethodHandler((call, sender) async {
      throw PlatformException(
        code: _password,
        message: _token,
        details: {'password': _password},
      );
    });
    _expectFailure(await _dispatch('query', _envelope(null)), messages);
  });

  test('window dispatch refuses a malformed sender envelope', () async {
    var calls = 0;
    DesktopMultiWindow.setMethodHandler((call, sender) async => calls++);
    _expectFailure(
        await _dispatch('query', {
          'fromWindowId': _password,
          'arguments': {'connToken': _token},
        }),
        messages);
    expect(calls, 0);
  });

  test('window dispatch joins event failure before replying', () async {
    final uncaught = <Object>[];
    final listener = _Listener(failure: StateError(_password + _token));
    DesktopMultiWindow.addListener(listener);
    DesktopMultiWindow.setMethodHandler((call, sender) async => true);
    ByteData? reply;
    try {
      await runZonedGuarded<Future<void>>(() async {
        reply = await _dispatch(
            'onEvent', _envelope({'eventName': 'focus', 'windowId': 4}));
      }, (error, stack) => uncaught.add(error));
      expect(uncaught, isEmpty);
      _expectFailure(reply, messages);
      expect(listener.events, ['focus']);
    } finally {
      DesktopMultiWindow.removeListener(listener);
    }
  });
}

import 'dart:async';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/utils/event_loop.dart';
import 'package:flutter_test/flutter_test.dart';

enum _EventType { value }

class _TestEvent extends BaseEvent<_EventType, int> {
  _TestEvent(int value, this.callback) : super(_EventType.value, value);

  final EventCallback<int> callback;

  @override
  EventCallback<int>? findCallback(_EventType type) => callback;
}

class _TestEventLoop extends BaseEventLoop<_EventType, int> {
  _TestEventLoop({required super.maxOwnedEvents});

  final List<Object> terminalErrors = [];

  @override
  void onTerminalError(BaseEvent<_EventType, int>? event, Object error,
      StackTrace stackTrace) {
    terminalErrors.add(error);
  }
}

Future<void> _flushEventLoop() =>
    Future<void>.delayed(const Duration(milliseconds: 1));

Map<String, dynamic> _confirmationEvent({
  Object? id = '1',
  Object? fileNum = '0',
  Object? readPath = '/tmp/file',
  Object? isUpload = 'true',
  Object? isIdentical = 'false',
}) =>
    {
      'name': 'override_file_confirm',
      'id': id,
      'file_num': fileNum,
      'read_path': readPath,
      'is_upload': isUpload,
      'is_identical': isIdentical,
    };

void main() {
  test('bounded event loop consumes admitted work in FIFO order', () async {
    final loop = _TestEventLoop(maxOwnedEvents: 3);
    final consumed = <int>[];
    await loop.onReady();

    for (var value = 1; value <= 3; value++) {
      expect(
          loop.pushEvent(_TestEvent(value, (current) async {
            consumed.add(current);
          })),
          isTrue);
    }

    await _flushEventLoop();
    expect(consumed, [1, 2, 3]);
    expect(loop.ownedEventCount, 0);
  });

  test('capacity counts running and pending events', () async {
    final loop = _TestEventLoop(maxOwnedEvents: 2);
    final running = Completer<void>();
    final release = Completer<void>();
    await loop.onReady();

    expect(
        loop.pushEvent(_TestEvent(1, (_) async {
          running.complete();
          await release.future;
        })),
        isTrue);
    await running.future;
    expect(loop.pushEvent(_TestEvent(2, (_) async {})), isTrue);
    expect(loop.pushEvent(_TestEvent(3, (_) async {})), isFalse);
    expect(loop.ownedEventCount, 2);

    release.complete();
    await _flushEventLoop();
    expect(loop.ownedEventCount, 0);
  });

  test('close retires pending work and rejects admission while closed',
      () async {
    final loop = _TestEventLoop(maxOwnedEvents: 2);
    final running = Completer<void>();
    final release = Completer<void>();
    final consumed = <int>[];
    await loop.onReady();

    expect(
        loop.pushEvent(_TestEvent(1, (value) async {
          consumed.add(value);
          running.complete();
          await release.future;
        })),
        isTrue);
    await running.future;
    expect(
        loop.pushEvent(_TestEvent(2, (value) async {
          consumed.add(value);
        })),
        isTrue);

    await loop.close();
    expect(loop.isClosed, isTrue);
    expect(loop.pushEvent(_TestEvent(3, (_) async {})), isFalse);
    release.complete();
    await _flushEventLoop();
    expect(consumed, [1]);
    expect(loop.ownedEventCount, 0);
  });

  test('retired callback cannot consume replacement-generation work',
      () async {
    final loop = _TestEventLoop(maxOwnedEvents: 2);
    final running = Completer<void>();
    final release = Completer<void>();
    final consumed = <String>[];
    await loop.onReady();

    expect(
        loop.pushEvent(_TestEvent(1, (_) async {
          consumed.add('retired-start');
          running.complete();
          await release.future;
          consumed.add('retired-finish');
        })),
        isTrue);
    await running.future;
    await loop.close();
    await loop.onReady();
    expect(
        loop.pushEvent(_TestEvent(2, (_) async {
          consumed.add('replacement');
        })),
        isTrue);
    await _flushEventLoop();
    expect(consumed, ['retired-start']);

    release.complete();
    await _flushEventLoop();
    expect(consumed, ['retired-start', 'retired-finish', 'replacement']);
  });

  test('callback failure is terminal and clears successors', () async {
    final loop = _TestEventLoop(maxOwnedEvents: 2);
    var successorRan = false;
    await loop.onReady();

    expect(
        loop.pushEvent(_TestEvent(1, (_) async {
          throw StateError('failed callback');
        })),
        isTrue);
    expect(
        loop.pushEvent(_TestEvent(2, (_) async {
          successorRan = true;
        })),
        isTrue);

    await _flushEventLoop();
    expect(loop.isClosed, isTrue);
    expect(loop.ownedEventCount, 0);
    expect(successorRan, isFalse);
    expect(loop.terminalErrors, hasLength(1));
    expect(loop.pushEvent(_TestEvent(3, (_) async {})), isFalse);
  });

  test('file confirmation parser owns one exact bounded typed payload', () {
    final parsed = FileOverrideConfirmation.tryParse(_confirmationEvent());
    expect(parsed, isNotNull);
    expect(parsed!.jobId, 1);
    expect(parsed.fileNum, 0);
    expect(parsed.readPath, '/tmp/file');
    expect(parsed.isUpload, isTrue);
    expect(parsed.isIdentical, isFalse);
  });

  test('file confirmation parser rejects malformed scalar authority', () {
    expect(FileOverrideConfirmation.tryParse(_confirmationEvent(id: 1)),
        isNull);
    expect(FileOverrideConfirmation.tryParse(_confirmationEvent(id: '0')),
        isNull);
    expect(FileOverrideConfirmation.tryParse(_confirmationEvent(id: '01')),
        isNull);
    expect(
        FileOverrideConfirmation.tryParse(_confirmationEvent(fileNum: '-1')),
        isNull);
    expect(
        FileOverrideConfirmation.tryParse(_confirmationEvent(fileNum: '01')),
        isNull);
    expect(
        FileOverrideConfirmation.tryParse(_confirmationEvent(isUpload: true)),
        isNull);
    expect(
        FileOverrideConfirmation.tryParse(
            _confirmationEvent(isIdentical: 'TRUE')),
        isNull);
  });

  test('file confirmation parser rejects unowned path storage', () {
    expect(
        FileOverrideConfirmation.tryParse(_confirmationEvent(readPath: '')),
        isNull);
    expect(
        FileOverrideConfirmation.tryParse(
            _confirmationEvent(readPath: 'bad\u0000path')),
        isNull);
    final overlong = List<String>.filled(
            FileOverrideConfirmation.maxReadPathCodeUnits + 1, 'a')
        .join();
    expect(
        FileOverrideConfirmation.tryParse(
            _confirmationEvent(readPath: overlong)),
        isNull);
  });
}

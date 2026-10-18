import 'dart:async';

import 'package:flutter_hbb/common.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Flutter UI preference save waits and returns effective readback', () async {
    final completion = Completer<void>();
    var reads = 0;
    String? result;
    final save = saveLocalFlutterOption('peer-view', 'requested',
        writeOption: (key, value) {
          expect(key, 'peer-view');
          expect(value, 'requested');
          return completion.future;
        }, readOption: (key) {
          expect(key, 'peer-view');
          reads++;
          return 'effective';
        }, showFailure: () => fail('successful preference save reported failure'))
        .then((value) => result = value);
    await Future<void>.delayed(Duration.zero);
    expect(reads, 0);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, 'effective');
    expect(reads, 1);
  });

  test('Flutter UI preference failure preserves readback and permits retry', () async {
    var writes = 0;
    var reads = 0;
    var failures = 0;
    Future<void> write(String key, String value) async {
      expect(key, 'peer-view');
      expect(value, '');
      if (++writes == 1) throw StateError('save failed');
    }
    String read(String key) {
      reads++;
      return '';
    }
    expect(await saveLocalFlutterOption('peer-view', '', writeOption: write,
        readOption: read, showFailure: () => failures++), isNull);
    expect(reads, 0);
    expect(await saveLocalFlutterOption('peer-view', '', writeOption: write,
        readOption: read, showFailure: () => failures++), '');
    expect(writes, 2);
    expect(reads, 1);
    expect(failures, 1);
  });

  test('Flutter UI preference readback failure reports uncertainty and permits retry', () async {
    var writes = 0;
    var reads = 0;
    var failures = 0;
    Future<void> write(String key, String value) async { writes++; }
    String read(String key) {
      if (++reads == 1) throw StateError('readback failed');
      return 'confirmed';
    }
    expect(await saveLocalFlutterOption('peer-view', 'requested', writeOption: write,
        readOption: read, showFailure: () => failures++), isNull);
    expect(writes, 1);
    expect(await saveLocalFlutterOption('peer-view', 'requested', writeOption: write,
        readOption: read, showFailure: () => failures++), 'confirmed');
    expect(writes, 2);
    expect(reads, 2);
    expect(failures, 1);
  });

  test('local option save waits before publishing dependent effects', () async {
    final completion = Completer<void>();
    final calls = <String>[];
    var effect = false;
    final save = mainSetLocalOption('theme', 'dark',
        writeOption: (key, value) {
          calls.add('$key=$value');
          return completion.future;
        }, showFailure: () => fail('successful local save reported failure'))
        .then((saved) { if (saved) effect = true; });
    await Future<void>.delayed(Duration.zero);
    expect(calls, ['theme=dark']);
    expect(effect, isFalse);
    completion.complete();
    await save;
    expect(effect, isTrue);
  });

  test('local option failures report feedback and stop dependent effects',
      () async {
    for (final synchronous in [false, true]) {
      var failures = 0;
      var effect = false;
      final saved = await mainSetLocalOption('theme', 'dark',
          writeOption: (_, __) {
            if (synchronous) throw StateError('dispatch failure');
            return Future<void>.error(StateError('native save failure'));
          }, showFailure: () => failures++);
      if (saved) effect = true;
      expect(effect, isFalse);
      expect(saved, isFalse);
      expect(failures, 1);
    }
  });

  test('local option failure permits the identical retry', () async {
    final calls = <String>[];
    var failures = 0;
    Future<void> write(String key, String value) async {
      calls.add('$key=$value');
      if (calls.length == 1) throw StateError('first local save failed');
    }
    expect(await mainSetLocalOption('theme', 'dark',
        writeOption: write, showFailure: () => failures++), isFalse);
    expect(await mainSetLocalOption('theme', 'dark',
        writeOption: write, showFailure: () => failures++), isTrue);
    expect(calls, ['theme=dark', 'theme=dark']);
    expect(failures, 1);
  });

  test('favorite save owns its submitted IDs and waits for completion', () async {
    final completion = Completer<void>();
    final ids = ['first'];
    List<String>? submitted;
    bool? result;
    final save = mainSetFavorites(ids, true, writeFavorites: (values, favorite) {
      submitted = values;
      expect(favorite, isTrue);
      return completion.future;
    }, showFailure: () => fail('successful favorite save reported failure'))
        .then((value) => result = value);
    ids.add('later');
    await Future<void>.delayed(Duration.zero);
    expect(submitted, ['first']);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, isTrue);
  });

  test('failed favorite membership change reports failure and permits retry',
      () async {
    var calls = 0;
    var failures = 0;
    Future<void> write(List<String> ids, bool favorite) async {
      expect(ids, ['first', 'second']);
      expect(favorite, isFalse);
      if (++calls == 1) throw StateError('favorite save failed');
    }
    final first = await mainSetFavorites(['first', 'second'], false,
        writeFavorites: write, showFailure: () => failures++);
    final retry = await mainSetFavorites(['first', 'second'], false,
        writeFavorites: write, showFailure: () => failures++);
    expect(first, isFalse);
    expect(retry, isTrue);
    expect(calls, 2);
    expect(failures, 1);
  });

  test('option save waits for its native completion', () async {
    final completion = Completer<void>();
    final calls = <String>[];
    bool? result;
    final save = mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (key, value) {
        calls.add('$key=$value');
        return completion.future;
      },
      showFailure: () => fail('successful save reported failure'),
    ).then((value) => result = value);
    await Future<void>.delayed(Duration.zero);
    expect(calls, ['enable-abr=Y']);
    expect(result, isNull);
    completion.complete();
    await save;
    expect(result, isTrue);
  });

  test('native option failure reports feedback without success', () async {
    var failures = 0;
    final saved = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (_, __) => Future<void>.error(StateError('native failure')),
      showFailure: () => failures++,
    );
    expect(saved, isFalse);
    expect(failures, 1);
  });

  test('synchronous option dispatch failure is reported', () async {
    var failures = 0;
    final saved = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: (_, __) => throw StateError('dispatch failure'),
      showFailure: () => failures++,
    );
    expect(saved, isFalse);
    expect(failures, 1);
  });

  test('failed option save permits the identical retry', () async {
    final calls = <String>[];
    var failures = 0;
    Future<void> write(String key, String value) async {
      calls.add('$key=$value');
      if (calls.length == 1) throw StateError('first write failed');
    }

    final first = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: write,
      showFailure: () => failures++,
    );
    final retry = await mainSetOption(
      'enable-abr',
      'Y',
      writeOption: write,
      showFailure: () => failures++,
    );
    expect(first, isFalse);
    expect(retry, isTrue);
    expect(calls, ['enable-abr=Y', 'enable-abr=Y']);
    expect(failures, 1);
  });
}

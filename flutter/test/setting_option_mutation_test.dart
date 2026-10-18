import 'dart:async';

import 'package:flutter_hbb/common.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
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

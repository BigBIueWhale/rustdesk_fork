import 'dart:async';

import 'package:flutter_hbb/common.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
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

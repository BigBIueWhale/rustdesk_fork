import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

void main() {
  test('retired file timeout cannot remove a replacement task', () async {
    final fetcher = FileFetcher(() => const Uuid().v4obj());
    const path = '/same-remote-directory';

    final retired = fetcher.registerReadTask(false, path);
    final retiredResult = expectLater(
      retired,
      throwsA('Superseded file-transfer session'),
    );
    fetcher.cancelPending();
    await retiredResult;

    await Future<void>.delayed(const Duration(milliseconds: 400));
    final replacement = fetcher.registerReadTask(false, path);

    // The retired task's two-second timeout fires first. It must compare the
    // exact completer before removing a same-path task registered by the next
    // mobile connection.
    await Future<void>.delayed(const Duration(milliseconds: 1800));
    fetcher.tryCompleteTask(
      jsonEncode({'id': 0, 'path': path, 'entries': <Object>[]}),
      'false',
    );

    final directory =
        await replacement.timeout(const Duration(milliseconds: 150));
    expect(directory.path, path);
  });
}

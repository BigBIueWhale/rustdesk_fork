import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

FileFetcherRequests requests({
  ReadRemoteDirectory? readDirectory,
  ReadRemoteDirectory? readEmptyDirectories,
  ReadRemoteDirectoryTree? readDirectoryTree,
}) {
  return FileFetcherRequests(
    readDirectory: readDirectory ??
        (sessionId, path, showHidden) => Future<void>.value(),
    readEmptyDirectories: readEmptyDirectories ??
        (sessionId, path, showHidden) => Future<void>.value(),
    readDirectoryTree: readDirectoryTree ??
        (sessionId, actionId, path, isRemote, showHidden) =>
            Future<void>.value(),
  );
}

String directoryResponse(String path, {int id = 0}) =>
    jsonEncode({'id': id, 'path': path, 'entries': <Object>[]});

void main() {
  test('directory response owner exists before bridge dispatch settles',
      () async {
    final session = const Uuid().v4obj();
    final dispatchEntered = Completer<void>();
    final releaseDispatch = Completer<void>();
    final fetcher = FileFetcher(
      () => session,
      maxPending: 1,
      requests: requests(readDirectory: (actualSession, path, hidden) async {
        expect(actualSession, session);
        expect(path, '/fast-remote-directory');
        dispatchEntered.complete();
        await releaseDispatch.future;
      }),
    );

    final result = fetcher.fetchDirectory(
        '/fast-remote-directory', false, false,
        expectedSessionId: session);
    await dispatchEntered.future;

    expect(
        fetcher.tryCompleteTask(session,
            directoryResponse('/fast-remote-directory'), 'false'),
        isTrue);
    final directory = await result.timeout(const Duration(milliseconds: 50));
    expect(directory.path, '/fast-remote-directory');

    // Until dispatch itself settles, the exact owner still occupies the key
    // and total-capacity slot even though the response reached the caller.
    await expectLater(
        fetcher.fetchDirectory('/fast-remote-directory', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>()));
    await expectLater(
        fetcher.fetchDirectory('/different-path', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>().having((error) => error.message, 'message',
            'File request capacity exhausted')));
    releaseDispatch.complete();
    await Future<void>.delayed(Duration.zero);
  });

  test('empty and recursive response owners exist before dispatch settles',
      () async {
    final session = const Uuid().v4obj();
    final emptyDispatchEntered = Completer<void>();
    final recursiveDispatchEntered = Completer<void>();
    final releaseEmptyDispatch = Completer<void>();
    final releaseRecursiveDispatch = Completer<void>();
    final fetcher = FileFetcher(
      () => session,
      maxPending: 2,
      requests: requests(
        readEmptyDirectories: (actualSession, path, hidden) async {
          expect(actualSession, session);
          expect(path, '/empty-tree');
          emptyDispatchEntered.complete();
          await releaseEmptyDispatch.future;
        },
        readDirectoryTree:
            (actualSession, actionId, path, isRemote, hidden) async {
          expect(actualSession, session);
          expect(actionId, 7);
          expect(path, '/recursive-tree');
          expect(isRemote, isFalse);
          recursiveDispatchEntered.complete();
          await releaseRecursiveDispatch.future;
        },
      ),
    );

    final empty = fetcher.readEmptyDirs('/empty-tree', false, false,
        expectedSessionId: session);
    await emptyDispatchEntered.future;
    expect(
        fetcher.tryCompleteEmptyDirsTask(
            session,
            jsonEncode({'path': '/empty-tree', 'empty_dirs': <Object>[]}),
            'false'),
        isTrue);
    expect(await empty, isEmpty);

    final recursive = fetcher.fetchDirectoryRecursiveToRemove(
        7, '/recursive-tree', true, false,
        expectedSessionId: session);
    await recursiveDispatchEntered.future;
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/recursive-tree', id: 7), 'true'),
        isTrue);
    expect((await recursive).path, '/recursive-tree');

    await expectLater(
        fetcher.fetchDirectory('/capacity-still-owned', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>().having((error) => error.message, 'message',
            'File request capacity exhausted')));
    releaseEmptyDispatch.complete();
    releaseRecursiveDispatch.complete();
    await Future<void>.delayed(Duration.zero);

    final afterSettlement = fetcher.fetchDirectory(
        '/after-dispatch-settlement', false, false,
        expectedSessionId: session);
    expect(
        fetcher.tryCompleteTask(session,
            directoryResponse('/after-dispatch-settlement'), 'false'),
        isTrue);
    expect((await afterSettlement).path, '/after-dispatch-settlement');
  });

  test('recursive requests require a positive signed-32-bit action ID',
      () async {
    final session = const Uuid().v4obj();
    var dispatches = 0;
    final fetcher = FileFetcher(
      () => session,
      maxPending: 1,
      requests: requests(readDirectoryTree:
          (actualSession, actionId, path, isRemote, hidden) async {
        dispatches++;
      }),
    );

    for (final invalidId in <int>[-1, 0, 0x80000000]) {
      await expectLater(
          fetcher.fetchDirectoryRecursiveToRemove(
              invalidId, '/invalid', false, false,
              expectedSessionId: session),
          throwsA(isA<ArgumentError>()));
    }
    expect(dispatches, 0);

    final valid = fetcher.fetchDirectoryRecursiveToRemove(
        1, '/valid', false, false,
        expectedSessionId: session);
    expect(dispatches, 1);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/valid', id: 1), 'false'),
        isTrue);
    expect((await valid).path, '/valid');
  });

  test('recursive errors require an exact canonical event owner', () async {
    final session = const Uuid().v4obj();
    final otherSession = const Uuid().v4obj();
    final fetcher = FileFetcher(() => session, requests: requests());
    final result = fetcher.fetchDirectoryRecursiveToRemove(
        7, '/recursive-error', false, false,
        expectedSessionId: session);

    for (final invalidId in <Object?>[
      7,
      null,
      '',
      '+7',
      '07',
      ' 7',
      '-1',
      '0',
      '2147483648'
    ]) {
      expect(
          fetcher.tryCompleteRecursiveTaskWithError(
              session, {'id': invalidId, 'err': 'recursive failure'}),
          isFalse);
    }
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            session, {'id': '7', 'err': 7}),
        isFalse);
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            otherSession, {'id': '7', 'err': 'recursive failure'}),
        isFalse);
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            session, {'id': '8', 'err': 'recursive failure'}),
        isFalse);
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            session, {'id': '7', 'err': 'recursive failure'}),
        isTrue);
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            session, {'id': '7', 'err': 'duplicate failure'}),
        isFalse);
    await expectLater(
        result,
        throwsA(isA<StateError>().having((error) => error.message, 'message',
            'recursive failure')));
  });

  test('response must match session, locality, operation, and key', () async {
    final session = const Uuid().v4obj();
    final otherSession = const Uuid().v4obj();
    final fetcher = FileFetcher(() => session, requests: requests());
    final result = fetcher.fetchDirectory('/owned', false, false,
        expectedSessionId: session);

    expect(
        fetcher.tryCompleteTask(
            otherSession, directoryResponse('/owned'), 'false'),
        isFalse);
    expect(
        fetcher.tryCompleteTask(session, directoryResponse('/owned'), 'true'),
        isFalse);
    expect(
        fetcher.tryCompleteEmptyDirsTask(
            session,
            jsonEncode({'path': '/owned', 'empty_dirs': <Object>[]}),
            'false'),
        isFalse);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/different'), 'false'),
        isFalse);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/owned', id: -1), 'false'),
        isFalse);
    expect(fetcher.tryCompleteTask(session, 7, 'false'), isFalse);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/owned'), true),
        isFalse);
    expect(
        fetcher.tryCompleteRecursiveTaskWithError(
            session, {'id': '0', 'err': 'anonymous error'}),
        isFalse);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/owned'), 'false'),
        isTrue);
    expect((await result).path, '/owned');
  });

  test('retirement cancels an in-flight dispatch and permits replacement',
      () async {
    final retiredSession = const Uuid().v4obj();
    final replacementSession = const Uuid().v4obj();
    var currentSession = retiredSession;
    final firstDispatchEntered = Completer<void>();
    final releaseFirstDispatch = Completer<void>();
    var dispatches = 0;
    final fetcher = FileFetcher(
      () => currentSession,
      requestTimeout: const Duration(milliseconds: 200),
      requests: requests(readDirectory: (actualSession, path, hidden) async {
        dispatches++;
        if (dispatches == 1) {
          firstDispatchEntered.complete();
          await releaseFirstDispatch.future;
        }
      }),
    );

    final retired = fetcher.fetchDirectory('/same-path', false, false,
        expectedSessionId: retiredSession);
    final retiredResult = expectLater(
        retired,
        throwsA(isA<StateError>().having(
            (error) => error.message,
            'message',
            'Superseded file-transfer session')));
    await firstDispatchEntered.future;
    fetcher.cancelPending();
    await retiredResult;

    currentSession = replacementSession;
    final replacement = fetcher.fetchDirectory('/same-path', false, false,
        expectedSessionId: replacementSession);
    releaseFirstDispatch.complete();
    await Future<void>.delayed(Duration.zero);
    expect(
        fetcher.tryCompleteTask(
            retiredSession, directoryResponse('/same-path'), 'false'),
        isFalse);
    expect(
        fetcher.tryCompleteTask(
            replacementSession, directoryResponse('/same-path'), 'false'),
        isTrue);
    expect((await replacement).path, '/same-path');
    expect(dispatches, 2);
  });

  test('dispatch failure removes its exact reservation', () async {
    final session = const Uuid().v4obj();
    var dispatches = 0;
    final fetcher = FileFetcher(
      () => session,
      requests: requests(readDirectory: (actualSession, path, hidden) async {
        dispatches++;
        if (dispatches == 1) {
          throw StateError('bridge dispatch failed');
        }
      }),
    );

    await expectLater(
        fetcher.fetchDirectory('/retry', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>().having(
            (error) => error.message, 'message', 'bridge dispatch failed')));

    final retry = fetcher.fetchDirectory('/retry', false, false,
        expectedSessionId: session);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/retry'), 'false'),
        isTrue);
    expect((await retry).path, '/retry');
    expect(dispatches, 2);
  });

  test('one total capacity bounds all response maps', () async {
    final session = const Uuid().v4obj();
    final fetcher = FileFetcher(
      () => session,
      maxPending: 2,
      requests: requests(),
    );

    final directory = fetcher.fetchDirectory('/one', false, false,
        expectedSessionId: session);
    final emptyDirectories = fetcher.readEmptyDirs('/two', false, false,
        expectedSessionId: session);
    final directoryResult =
        expectLater(directory, throwsA(isA<StateError>()));
    final emptyDirectoriesResult =
        expectLater(emptyDirectories, throwsA(isA<StateError>()));

    await expectLater(
        fetcher.fetchDirectoryRecursiveToRemove(
            7, '/three', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>().having((error) => error.message, 'message',
            'File request capacity exhausted')));

    fetcher.cancelPending();
    await directoryResult;
    await emptyDirectoriesResult;
  });

  test('timeout quarantines its key until the late response is consumed',
      () async {
    final session = const Uuid().v4obj();
    final dispatchEntered = Completer<void>();
    final releaseDispatch = Completer<void>();
    final fetcher = FileFetcher(
      () => session,
      requestTimeout: const Duration(milliseconds: 50),
      requests: requests(readDirectory: (actualSession, path, hidden) async {
        if (!dispatchEntered.isCompleted) dispatchEntered.complete();
        await releaseDispatch.future;
      }),
    );

    final timedOut = fetcher.fetchDirectory('/timeout', false, false,
        expectedSessionId: session);
    await dispatchEntered.future;
    await expectLater(timedOut, throwsA(isA<TimeoutException>()));

    // A timeout cannot prove that the peer will not answer later. Reusing this
    // path now would let the stale answer complete the replacement request.
    await expectLater(
        fetcher.fetchDirectory('/timeout', false, false,
            expectedSessionId: session),
        throwsA(isA<StateError>()));
    releaseDispatch.complete();
    await Future<void>.delayed(Duration.zero);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/timeout'), 'false'),
        isFalse);

    final replacement = fetcher.fetchDirectory('/timeout', false, false,
        expectedSessionId: session);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/timeout'), 'false'),
        isTrue);
    expect((await replacement).path, '/timeout');

    // A completed request cancels its timer, so it cannot affect a later slot.
    await Future<void>.delayed(const Duration(milliseconds: 60));
    final later = fetcher.fetchDirectory('/timeout', false, false,
        expectedSessionId: session);
    expect(
        fetcher.tryCompleteTask(
            session, directoryResponse('/timeout'), 'false'),
        isTrue);
    expect((await later).path, '/timeout');
  });
}

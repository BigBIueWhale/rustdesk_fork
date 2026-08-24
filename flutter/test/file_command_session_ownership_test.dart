import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

FileFetcherRequests _fetcherRequests() => FileFetcherRequests(
      readDirectory: (sessionId, path, showHidden) => Future<void>.value(),
      readEmptyDirectories: (sessionId, path, showHidden) =>
          Future<void>.value(),
      readDirectoryTree:
          (sessionId, actionId, path, isRemote, showHidden) =>
              Future<void>.value(),
    );

JobControllerRequests _jobRequests({
  CancelJobRequest? cancelJob,
  AddJobRequest? addJob,
  ResumeJobRequest? resumeJob,
}) =>
    JobControllerRequests(
      cancelJob: cancelJob ??
          (sessionId, actionId) => Future<void>.value(),
      addJob: addJob ??
          (sessionId, isRemote, includeHidden, actionId, path, to, fileNum) =>
              Future<void>.value(),
      resumeJob: resumeJob ??
          (sessionId, actionId, isRemote) => Future<void>.value(),
    );

FileControllerRequests _controllerRequests({
  SendFilesRequest? sendFiles,
}) =>
    FileControllerRequests(
      sendFiles: sendFiles ??
          (sessionId, actionId, path, to, fileNum, includeHidden, isRemote,
                  isDirectory) =>
              Future<void>.value(),
      removeFile: (sessionId, actionId, path, isRemote, fileNum) =>
          Future<void>.value(),
      removeEmptyDirectories: (sessionId, actionId, path, isRemote) =>
          Future<void>.value(),
      createDirectory: (sessionId, actionId, path, isRemote) =>
          Future<void>.value(),
      renameFile: (sessionId, actionId, path, newName, isRemote) =>
          Future<void>.value(),
    );

Entry _file(String name, String path) => Entry()
  ..entryType = 4
  ..name = name
  ..path = path
  ..size = 1;

void main() {
  test('retired send continuation cannot target replacement session',
      () async {
    final retiredSession = const Uuid().v4obj();
    final replacementSession = const Uuid().v4obj();
    var currentSession = retiredSession;
    var nextJobId = 0;
    final entered = Completer<void>();
    final release = Completer<void>();
    final calls = <Map<String, Object>>[];
    final jobController = JobController(() => currentSession, () => null,
        isCurrentSession: (sessionId) => sessionId == currentSession,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId);
    final fileFetcher =
        FileFetcher(() => currentSession, requests: _fetcherRequests());
    late final FileController controller;
    controller = FileController(
      isLocal: true,
      getSessionID: () => currentSession,
      getDialogManager: () => null,
      isCurrentSession: (sessionId) => sessionId == currentSession,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      requests: _controllerRequests(sendFiles: (sessionId, actionId, path,
          to, fileNum, includeHidden, isRemote, isDirectory) async {
        calls.add({
          'session': sessionId,
          'path': path,
          'to': to,
        });
        if (!entered.isCompleted) {
          entered.complete();
          await release.future;
        }
      }),
    );
    final selected = SelectedItems(isLocal: true)
      ..add(_file('one', '/source/one'))
      ..add(_file('two', '/source/two'));
    final destination = FileDirectory()..path = '/destination';

    final send = controller.sendFiles(selected,
        DirectoryData(destination, DirectoryOptions(isWindows: false)));
    await entered.future;
    currentSession = replacementSession;
    jobController.clear();
    release.complete();
    await send;
    await controller.sendFiles(selected,
        DirectoryData(destination, DirectoryOptions(isWindows: false)),
        expectedSessionId: retiredSession);

    expect(calls, hasLength(1));
    expect(calls.single['session'], retiredSession);
    expect(jobController.jobTable, isEmpty);
  });

  test('send operation snapshots entries and directory arguments at admission',
      () async {
    final session = const Uuid().v4obj();
    var nextJobId = 0;
    final entered = Completer<void>();
    final release = Completer<void>();
    final calls = <Map<String, Object>>[];
    final jobController = JobController(() => session, () => null,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId);
    final fileFetcher =
        FileFetcher(() => session, requests: _fetcherRequests());
    final controller = FileController(
      isLocal: true,
      getSessionID: () => session,
      getDialogManager: () => null,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      requests: _controllerRequests(sendFiles: (actualSession, actionId, path,
          to, fileNum, includeHidden, isRemote, isDirectory) async {
        calls.add({'session': actualSession, 'path': path, 'to': to});
        if (calls.length == 1) {
          entered.complete();
          await release.future;
        }
      }),
    );
    final second = _file('two', '/source/two');
    final selected = SelectedItems(isLocal: true)
      ..add(_file('one', '/source/one'))
      ..add(second);
    final destination = FileDirectory()..path = '/destination';
    final options = DirectoryOptions(isWindows: false);

    final send = controller.sendFiles(
        selected, DirectoryData(destination, options));
    await entered.future;
    second
      ..name = 'mutated'
      ..path = '/mutated';
    selected.clear();
    destination.path = '/replacement';
    options.isWindows = true;
    release.complete();
    await send;

    expect(calls, hasLength(2));
    expect(calls[1], {
      'session': session,
      'path': '/source/two',
      'to': '/destination/two',
    });
  });

  test('job result requires exact session action and file before completion',
      () async {
    final session = const Uuid().v4obj();
    final otherSession = const Uuid().v4obj();
    final entered = Completer<void>();
    final release = Completer<void>();
    final listener = JobResultListener(
        maxPending: 2, requestTimeout: const Duration(milliseconds: 200));
    final result = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 7,
        fileNum: 3,
        dispatch: () async {
          entered.complete();
          await release.future;
        });
    var resultCompleted = false;
    unawaited(result.then((_) {
      resultCompleted = true;
    }));
    await entered.future;

    expect(listener.tryComplete(otherSession,
        {'id': '7', 'file_num': '3', 'err': 'wrong session'}), isFalse);
    expect(listener.tryComplete(session,
        {'id': '8', 'file_num': '3', 'err': 'wrong action'}), isFalse);
    expect(listener.tryComplete(session,
        {'id': '7', 'file_num': '4', 'err': 'wrong file'}), isFalse);
    expect(listener.tryComplete(session,
        {'id': 7, 'file_num': '3', 'err': 'wrong type'}), isFalse);
    expect(listener.tryComplete(
        session, {'id': '7', 'file_num': '3', 'speed': '0'}), isTrue);
    await Future<void>.delayed(Duration.zero);
    expect(resultCompleted, isFalse);

    await expectLater(
        listener.dispatchAndWait(
            expectedSessionId: session,
            actionId: 7,
            fileNum: 3,
            dispatch: () => Future<void>.value()),
        throwsA(isA<StateError>()));
    release.complete();
    expect((await result)['id'], '7');
    expect(resultCompleted, isTrue);
  });

  test('retirement completes an exact pending job result with an error',
      () async {
    final session = const Uuid().v4obj();
    final release = Completer<void>();
    final listener = JobResultListener(
        requestTimeout: const Duration(milliseconds: 200));
    final result = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 11,
        fileNum: 0,
        dispatch: () => release.future);
    final retired = expectLater(
        result,
        throwsA(isA<StateError>().having((error) => error.message, 'message',
            'Superseded file-transfer session')));
    listener.clear();
    await retired;
    release.complete();
  });

  test('exact job error is caller-visible instead of successful completion',
      () async {
    final session = const Uuid().v4obj();
    final listener = JobResultListener(
        requestTimeout: const Duration(milliseconds: 200));
    final result = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 13,
        fileNum: 2,
        dispatch: () => Future<void>.value());
    final failed = expectLater(
        result,
        throwsA(isA<StateError>()
            .having((error) => error.message, 'message', 'permission denied')));
    expect(
        listener.tryCompleteError(session,
            {'id': '13', 'file_num': '2', 'err': 'permission denied'}),
        isTrue);
    await failed;
  });

  test('dispatch failure wins over an early matching success response',
      () async {
    final session = const Uuid().v4obj();
    final dispatch = Completer<void>();
    final listener = JobResultListener(
        requestTimeout: const Duration(milliseconds: 200));
    final result = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 17,
        fileNum: 4,
        dispatch: () => dispatch.future);
    final failed = expectLater(
        result,
        throwsA(isA<StateError>()
            .having((error) => error.message, 'message', 'dispatch failed')));

    expect(
        listener.tryComplete(
            session, {'id': '17', 'file_num': '4', 'speed': '0'}),
        isTrue);
    dispatch.completeError(StateError('dispatch failed'));
    await failed;
  });

  test('timed-out late result remains owned until dispatch settles', () async {
    final session = const Uuid().v4obj();
    final dispatch = Completer<void>();
    final listener = JobResultListener(
        maxPending: 1, requestTimeout: const Duration(milliseconds: 20));
    final timedOut = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 18,
        fileNum: 5,
        dispatch: () => dispatch.future);

    await expectLater(timedOut, throwsA(isA<TimeoutException>()));
    expect(
        listener.tryComplete(
            session, {'id': '18', 'file_num': '5', 'speed': '0'}),
        isFalse);
    await expectLater(
        listener.dispatchAndWait(
            expectedSessionId: session,
            actionId: 18,
            fileNum: 5,
            dispatch: () => Future<void>.value()),
        throwsA(isA<StateError>()));

    dispatch.complete();
    await Future<void>.delayed(Duration.zero);
    final replacement = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: 18,
        fileNum: 5,
        dispatch: () => Future<void>.value());
    expect(
        listener.tryComplete(
            session, {'id': '18', 'file_num': '5', 'speed': '0'}),
        isTrue);
    expect((await replacement)['file_num'], '5');
  });

  test('load-last-job cannot resume after its session is replaced', () async {
    final retiredSession = const Uuid().v4obj();
    final replacementSession = const Uuid().v4obj();
    var currentSession = retiredSession;
    final addEntered = Completer<void>();
    final releaseAdd = Completer<void>();
    var resumeCalls = 0;
    final controller = JobController(() => currentSession, () => null,
        isCurrentSession: (sessionId) => sessionId == currentSession,
        requests: _jobRequests(
          addJob: (sessionId, isRemote, includeHidden, actionId, path, to,
              fileNum) async {
            expect(sessionId, retiredSession);
            addEntered.complete();
            await releaseAdd.future;
          },
          resumeJob: (sessionId, actionId, isRemote) async {
            resumeCalls++;
          },
        ),
        nextJobId: () => 99);
    final event = {
      'value': jsonEncode({
        'remote': '/remote/file',
        'to': '/local/file',
        'show_hidden': false,
        'file_num': 0,
        'is_remote': true,
        'auto_start': true,
        'id': 19,
      })
    };

    final load = controller.loadLastJob(event, retiredSession);
    await addEntered.future;
    currentSession = replacementSession;
    controller.clear();
    releaseAdd.complete();
    await load;

    expect(resumeCalls, 0);
    expect(controller.jobTable, isEmpty);
  });
}

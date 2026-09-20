import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

String _identityTranslate(String text) => text;

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
  RemoveFileRequest? removeFile,
  RemoveEmptyDirectoriesRequest? removeEmptyDirectories,
  CreateDirectoryRequest? createDirectory,
  RenameFileRequest? renameFile,
}) =>
    FileControllerRequests(
      sendFiles: sendFiles ??
          (sessionId, actionId, path, to, fileNum, includeHidden, isRemote,
                  isDirectory) =>
              Future<void>.value(),
      removeFile: removeFile ??
          (sessionId, actionId, path, isRemote, fileNum) =>
              Future<void>.value(),
      removeEmptyDirectories: removeEmptyDirectories ??
          (sessionId, actionId, path, isRemote) => Future<void>.value(),
      createDirectory: createDirectory ??
          (sessionId, actionId, path, isRemote) => Future<void>.value(),
      renameFile: renameFile ??
          (sessionId, actionId, path, newName, isRemote) =>
              Future<void>.value(),
    );

class _DialogHarness extends OverlayDialogManager {
  _DialogHarness(this.context);

  final BuildContext context;
  final opened = Completer<void>();
  late CustomAlertDialog dialog;

  @override
  String showLoading(String text,
          {bool clickMaskDismiss = false,
          bool showCancel = true,
          VoidCallback? onCancel,
          String? tag}) =>
      'loading';

  @override
  void dismissAll() {}

  @override
  Future<T?> show<T>(DialogBuilder builder,
      {bool clickMaskDismiss = false,
      bool backDismiss = false,
      String? tag,
      bool useAnimation = true,
      bool forceGlobal = false}) {
    final result = Completer<T?>();
    dialog = builder((callback) => callback(), ([dynamic value]) {
      if (!result.isCompleted) result.complete(value as T?);
    }, context);
    opened.complete();
    return result.future;
  }
}

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
      translateText: _identityTranslate,
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
      translateText: _identityTranslate,
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

  testWidgets('rename snapshots directory policy before the dialog await',
      (tester) async {
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (value) {
      context = value;
      return const SizedBox.shrink();
    })));
    final session = const Uuid().v4obj();
    final manager = _DialogHarness(context);
    var nextJobId = 0;
    final calls = <Map<String, Object>>[];
    final jobController = JobController(() => session, () => manager,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId);
    final fileFetcher =
        FileFetcher(() => session, requests: _fetcherRequests());
    final controller = FileController(
      isLocal: true,
      getSessionID: () => session,
      getDialogManager: () => manager,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(
          renameFile: (actualSession, actionId, path, newName, isRemote) async {
        calls.add({
          'session': actualSession,
          'path': path,
          'newName': newName,
          'isRemote': isRemote,
        });
        await jobController.jobDone({
          'id': actionId.toString(),
          'file_num': '0',
          'speed': '0',
        }, actualSession);
      }),
    );
    final original = _file('old', '/source/old');
    controller.directory.value
      ..path = '/source'
      ..entries = [original];
    controller.options.value.isWindows = false;

    final rename = controller.renameAction(original, true);
    await manager.opened.future;
    controller.directory.value.entries.add(_file('new:name', '/source/new'));
    controller.options.value.isWindows = true;
    final content = manager.dialog.content as Column;
    final field = content.children.single as DialogTextField;
    field.controller.text = 'new:name';
    await manager.dialog.onSubmit!.call();
    await rename;

    expect(calls, [
      {
        'session': session,
        'path': '/source/old',
        'newName': 'new:name',
        'isRemote': false,
      }
    ]);
  });

  test('create waits for its exact result and exposes an exact error', () async {
    final session = const Uuid().v4obj();
    final dispatchEntered = Completer<void>();
    final releaseDispatch = Completer<void>();
    var nextJobId = 70;
    late JobController jobController;
    final fileFetcher =
        FileFetcher(() => session, requests: _fetcherRequests());
    late FileController controller;
    jobController = JobController(() => session, () => null,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId,
        resultTimeout: const Duration(seconds: 2));
    controller = FileController(
      isLocal: false,
      getSessionID: () => session,
      getDialogManager: () => null,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(
          createDirectory: (actualSession, actionId, path, isRemote) async {
        expect(actionId, 71);
        dispatchEntered.complete();
        await releaseDispatch.future;
      }),
    );

    final create = controller.createDirWithRemote('/remote/new', true);
    await dispatchEntered.future;
    var completed = false;
    unawaited(create.then<void>((_) {
      completed = true;
    }, onError: (Object _, StackTrace __) {
      completed = true;
    }));
    jobController.jobError(
        {'id': '72', 'file_num': '0', 'err': 'unowned'}, session);
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);
    jobController.jobError(
        {'id': '71', 'file_num': '0', 'err': 'mkdir denied'}, session);
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);

    releaseDispatch.complete();
    await expectLater(
        create,
        throwsA(isA<StateError>()
            .having((error) => error.message, 'message', 'mkdir denied')));
  });

  testWidgets(
      'remote empty-directory deletion uses a fresh exact result owner',
      (tester) async {
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (value) {
      context = value;
      return const SizedBox.shrink();
    })));
    final session = const Uuid().v4obj();
    final manager = _DialogHarness(context);
    var nextJobId = 0;
    final removeEntered = Completer<void>();
    final releaseRemove = Completer<void>();
    final removeCalls = <Map<String, Object>>[];
    final jobController = JobController(() => session, () => manager,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId,
        resultTimeout: const Duration(seconds: 2));
    late FileFetcher fileFetcher;
    fileFetcher = FileFetcher(() => session,
        requestTimeout: const Duration(seconds: 2),
        requests: FileFetcherRequests(
          readDirectory: (actualSession, path, showHidden) async {
            expect(
                fileFetcher.tryCompleteTask(
                    actualSession,
                    jsonEncode({'id': 0, 'path': path, 'entries': []}),
                    'false'),
                isTrue);
          },
          readEmptyDirectories: (actualSession, path, showHidden) async {},
          readDirectoryTree:
              (actualSession, actionId, path, isRemote, showHidden) async {
            expect(
                fileFetcher.tryCompleteTask(
                    actualSession,
                    jsonEncode(
                        {'id': actionId, 'path': path, 'entries': []}),
                    'false'),
                isTrue);
          },
        ));
    final controller = FileController(
      isLocal: false,
      getSessionID: () => session,
      getDialogManager: () => manager,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(removeEmptyDirectories:
          (actualSession, actionId, path, isRemote) async {
        removeCalls.add({
          'session': actualSession,
          'actionId': actionId,
          'path': path,
          'isRemote': isRemote,
        });
        removeEntered.complete();
        await releaseRemove.future;
      }),
    );
    controller.directory.value.path = '/remote';
    controller.history.addAll([
      '/remote/empty',
      '/remote/empty/child',
      '/remote/empty-sibling',
      '/else/remote/empty',
    ]);
    final directory = Entry()
      ..entryType = 0
      ..name = 'empty'
      ..path = '/remote/empty';
    final selected = SelectedItems(isLocal: false)..add(directory);

    final removal = controller.removeAction(selected);
    await manager.opened.future;
    await manager.dialog.onSubmit!.call();
    await removeEntered.future;
    expect(jobController.jobTable, hasLength(1));
    final displayJob = jobController.jobTable.single;
    expect(displayJob.id, 2);
    expect(removeCalls.single['actionId'], 3);
    expect(removeCalls.single['actionId'], isNot(displayJob.id));

    expect(
        await jobController.jobDone(
            {'id': '2', 'file_num': '0', 'speed': '0'}, session),
        isFalse);
    expect(displayJob.state, JobState.none);
    expect(
        await jobController.jobDone(
            {'id': '3', 'file_num': '0', 'speed': '0'}, session),
        isFalse);
    await tester.pump();
    expect(displayJob.state, JobState.none);

    releaseRemove.complete();
    await removal;
    expect(displayJob.state, JobState.done);
    expect(controller.history,
        ['/remote/empty-sibling', '/else/remote/empty']);
    expect(removeCalls, [
      {
        'session': session,
        'actionId': 3,
        'path': '/remote/empty',
        'isRemote': true,
      }
    ]);
  });

  testWidgets('directory-link deletion is one leaf command', (tester) async {
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (value) {
      context = value;
      return const SizedBox.shrink();
    })));
    final session = const Uuid().v4obj();
    final manager = _DialogHarness(context);
    var nextJobId = 0;
    var recursiveReads = 0;
    var directoryRemovals = 0;
    final fileRemovals = <Map<String, Object>>[];
    late FileFetcher fileFetcher;
    late JobController jobController;
    fileFetcher = FileFetcher(() => session,
        requestTimeout: const Duration(seconds: 2),
        requests: FileFetcherRequests(
          readDirectory: (actualSession, path, showHidden) async {
            expect(
                fileFetcher.tryCompleteTask(
                    actualSession,
                    jsonEncode({'id': 0, 'path': path, 'entries': []}),
                    'false'),
                isTrue);
          },
          readEmptyDirectories: (actualSession, path, showHidden) async {},
          readDirectoryTree:
              (actualSession, actionId, path, isRemote, showHidden) async {
            recursiveReads++;
          },
        ));
    jobController = JobController(() => session, () => manager,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId,
        resultTimeout: const Duration(seconds: 2));
    final controller = FileController(
      isLocal: false,
      getSessionID: () => session,
      getDialogManager: () => manager,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      getPeerVersion: () => '1.4.0',
      jobController: jobController,
      fileFetcher: fileFetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(
        removeFile: (actualSession, actionId, path, isRemote, fileNum) async {
          fileRemovals.add({
            'session': actualSession,
            'actionId': actionId,
            'path': path,
            'isRemote': isRemote,
            'fileNum': fileNum,
          });
          await jobController.jobDone({
            'id': actionId.toString(),
            'file_num': fileNum.toString(),
            'speed': '0',
          }, actualSession);
        },
        removeEmptyDirectories:
            (actualSession, actionId, path, isRemote) async {
          directoryRemovals++;
        },
      ),
    );
    controller.directory.value.path = '/remote';
    final directoryLink = Entry()
      ..entryType = 2
      ..name = 'link'
      ..path = '/remote/link';
    final selected = SelectedItems(isLocal: false)..add(directoryLink);

    final removal = controller.removeAction(selected);
    await manager.opened.future;
    await manager.dialog.onSubmit!.call();
    await removal;

    expect(recursiveReads, 0);
    expect(directoryRemovals, 0);
    expect(fileRemovals, [
      {
        'session': session,
        'actionId': 1,
        'path': '/remote/link',
        'isRemote': true,
        'fileNum': 0,
      }
    ]);
  });

  test('deleted-subtree matching is component exact for both path styles', () {
    expect(PathUtil.isSameOrDescendant('/root/leaf', '/root/leaf', false),
        isTrue);
    expect(
        PathUtil.isSameOrDescendant('/root/leaf/child', '/root/leaf', false),
        isTrue);
    expect(PathUtil.isSameOrDescendant('/root/leafish', '/root/leaf', false),
        isFalse);
    expect(
        PathUtil.isSameOrDescendant(
            r'C:\ROOT\Leaf\child', r'c:\root\leaf', true),
        isTrue);
    expect(
        PathUtil.isSameOrDescendant(
            r'C:\root\leafish', r'C:\root\leaf', true),
        isFalse);
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

  test('delete state changes only after exact result and dispatch finality',
      () async {
    final session = const Uuid().v4obj();
    final dispatch = Completer<void>();
    var nextJobId = 40;
    final controller = JobController(() => session, () => null,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: () => ++nextJobId,
        resultTimeout: const Duration(milliseconds: 200));
    final actionId = controller.addDeleteFileJob(
        _file('owned', '/source/owned'), true, session);
    expect(actionId, 41);
    final ownedActionId = actionId!;
    await expectLater(
        controller.dispatchDeleteFileAndWait(
            expectedSessionId: session,
            actionId: ownedActionId,
            fileNum: 1,
            dispatch: () => Future<void>.value()),
        throwsA(isA<StateError>()));
    final result = controller.dispatchDeleteFileAndWait(
        expectedSessionId: session,
        actionId: ownedActionId,
        fileNum: 0,
        dispatch: () => dispatch.future);
    final job = controller.jobTable.single;

    expect(
        await controller.jobDone(
            {'id': '41', 'file_num': '1', 'speed': '0'}, session),
        isFalse);
    controller.jobError(
        {'id': '41', 'file_num': '1', 'err': 'unowned'}, session);
    expect(job.state, JobState.none);
    expect(job.err, isEmpty);

    expect(
        await controller.jobDone(
            {'id': '41', 'file_num': '0', 'speed': '0'}, session),
        isFalse);
    await Future<void>.delayed(Duration.zero);
    expect(job.state, JobState.none);

    dispatch.complete();
    expect((await result)['file_num'], '0');
    expect(job.state, JobState.done);
    expect(job.fileNum, 0);
  });

  test('invalid or unowned cancel IDs never reach the native request surface',
      () async {
    final session = const Uuid().v4obj();
    final calls = <int>[];
    final controller = JobController(() => session, () => null,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(cancelJob: (actual, actionId) async {
          calls.add(actionId);
        }));

    expect(await controller.cancelJob(0), isFalse);
    expect(await controller.cancelJob(-1), isFalse);
    expect(await controller.cancelJob(0x80000000), isFalse);
    expect(await controller.cancelJob(17), isFalse);
    expect(calls, isEmpty);
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

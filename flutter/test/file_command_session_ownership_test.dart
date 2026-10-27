import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
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
    dialog = builder(
      (callback) => callback(),
      DialogClose(
        isCurrent: () => !result.isCompleted,
        complete: (value) => result.complete(value as T?),
      ),
      context,
    ) as CustomAlertDialog;
    opened.complete();
    return result.future;
  }
}

Entry _file(String name, String path) => Entry()
  ..entryType = 4
  ..name = name
  ..path = path
  ..size = 1;

class _ResultHarness {
  _ResultHarness({int capacity = 1,
      Duration timeout = const Duration(milliseconds: 200)})
      : listener = JobResultListener(maxPending: capacity, requestTimeout: timeout);

  final JobResultListener listener;
  var session = const Uuid().v4obj();
  var dispatches = 0;
  final completions = <Completer<void>>[];
  final results = <Future<Object>>[];

  Future<Object> start({int actionId = 7, Future<void> Function()? dispatch}) {
    final result = listener.dispatchAndWait(
        expectedSessionId: session,
        actionId: actionId,
        fileNum: 3,
        dispatch: () {
          dispatches++;
          if (dispatch != null) return dispatch();
          final completion = Completer<void>();
          completions.add(completion);
          return completion.future;
        });
    final observed = result.then<Object>((value) => value,
        onError: (Object error, StackTrace _) => error).timeout(
            const Duration(milliseconds: 500),
            onTimeout: () => TimeoutException('File-job test caller did not settle'));
    results.add(observed);
    return observed;
  }

  bool reply({int actionId = 7, String? error}) {
    final event = {'id': '$actionId', 'file_num': '3', 'speed': '0'};
    if (error != null) {
      event['err'] = error;
      return listener.tryCompleteError(session, event);
    }
    return listener.tryComplete(session, event);
  }

  Future<void> drain() async {
    listener.clear();
    for (final completion in completions) {
      if (!completion.isCompleted) completion.complete();
    }
    await Future.wait(results);
    await Future<void>.delayed(Duration.zero);
  }
}

Matcher get _capacityError => isA<StateError>().having(
    (error) => error.message, 'message', 'File-job result capacity exhausted');

Matcher get _retiredError => isA<StateError>().having(
    (error) => error.message, 'message', 'Superseded file-transfer session');

class _DeleteHarness {
  _DeleteHarness({this.isLocal = false});

  final bool isLocal;
  final session = const Uuid().v4obj();
  late var currentSession = session;
  final manager = OverlayDialogManager(translateText: _identityTranslate);
  final calls = <List<Object>>[];
  final dispatches = <Completer<void>>[];
  final results = <Future<Object?>>[];
  var nextId = 0;
  var failAllocation = false;
  var failListing = false;
  var refreshes = 0;
  final recursiveEntries = <Map<String, Object>>[];
  late JobController jobs;
  late FileFetcher fetcher;
  late FileController controller;

  Future<void> mount(WidgetTester tester) async {
    final overlay = BlockableOverlayState();
    manager.setOverlayState(overlay);
    jobs = JobController(() => currentSession, () => manager,
        isCurrentSession: (actual) => actual == currentSession,
        nextJobId: () {
          if (failAllocation) throw StateError('allocation failed');
          return ++nextId;
        });
    String listing(String path, int id) => jsonEncode({
      'id': id, 'path': path, 'entries': id == 0 ? [] : recursiveEntries,
    });
    fetcher = FileFetcher(() => currentSession,
        requests: FileFetcherRequests(
          readDirectory: (actual, path, hidden) async {
            refreshes++;
            fetcher.tryCompleteTask(actual, listing(path, 0), 'false');
          },
          readLocalDirectory: (actual, path, hidden) async {
            refreshes++;
            return listing(path, 0);
          },
          readEmptyDirectories: (_, __, ___) async {},
          readDirectoryTree: (actual, id, path, remote, hidden) async {
            if (failListing) throw StateError('listing denied');
            fetcher.tryCompleteTask(actual, listing(path, id), '${!remote}');
          },
        ));
    Future<void> dispatch(int id, String path, bool remote, int fileNum) {
      calls.add([id, path, remote, fileNum]);
      final pending = Completer<void>();
      dispatches.add(pending);
      return pending.future;
    }
    controller = FileController(
      isLocal: isLocal,
      getSessionID: () => currentSession,
      getDialogManager: () => manager,
      isCurrentSession: (actual) => actual == currentSession,
      getPeerPlatform: () => 'Linux',
      comparePeerVersion: (_) => 1,
      jobController: jobs,
      fileFetcher: fetcher,
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(
        removeFile: (actual, id, path, remote, num) =>
            dispatch(id, path, remote, num),
        removeEmptyDirectories: (actual, id, path, remote) =>
            dispatch(id, path, remote, 0),
      ),
    );
    controller.directory.value.path = '/files';
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
    ));
  }

  Future<Object?> start({bool directory = false}) {
    final entry = _file('first', '/files/first');
    if (directory) entry.entryType = 0;
    final selected = controller.selectedItems;
    selected.clear();
    selected.add(entry);
    selected.add(_file('successor', '/files/successor'));
    controller.directory.value.entries = [
      ...selected.items, _file('untouched', '/files/untouched'),
    ];
    final Future<dynamic> operation = controller.removeAction(selected);
    final result = operation.then<Object?>((value) => value,
        onError: (Object error, StackTrace _) => error);
    results.add(result);
    return result;
  }

  Future<void> confirm(WidgetTester tester) async {
    await tester.pumpAndSettle();
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle();
  }

  void fail({bool directory = false}) {
    final call = calls.last;
    if (directory && isLocal) {
      dispatches.last.completeError(StateError('delete denied'));
    } else {
      jobs.jobError({
        'id': '${call[0]}', 'file_num': '${call[3]}', 'err': 'delete denied',
      }, session);
      dispatches.last.complete();
    }
  }

  Future<void> replySuccess(int index, {bool localDirectory = false}) async {
    if (localDirectory) return;
    final call = calls[index];
    await jobs.jobDone({'id': '${call[0]}', 'file_num': '${call[3]}'}, session);
  }

  Future<void> drain(WidgetTester tester) async {
    currentSession = const Uuid().v4obj();
    manager.dismissAll();
    jobs.clear();
    for (final dispatch in dispatches) {
      if (!dispatch.isCompleted) dispatch.complete();
    }
    await Future.wait(results);
    await tester.pumpWidget(const SizedBox.shrink());
  }
}

void main() {
  for (final local in [false, true]) {
    for (final directory in [false, true]) {
      testWidgets('confirmed ${local ? "local" : "remote"} ${directory ? "directory" : "file"} leaves the listing before a later failure',
          (tester) async {
        final h = _DeleteHarness(isLocal: local);
        await h.mount(tester);
        try {
          final result = h.start(directory: directory);
          final listing = h.controller.directory.value;
          final first = listing.entries.first;
          final remaining = listing.entries.skip(1).toList();
          await h.confirm(tester);
          await h.replySuccess(0, localDirectory: local && directory);
          await tester.pump();
          expect(listing.entries.first, same(first));
          expect(h.controller.selectedItems.items, hasLength(2));
          h.dispatches.first.complete();
          await tester.pumpAndSettle();
          expect(listing.entries, remaining);
          expect(h.controller.selectedItems.items, [remaining.first]);
          expect(h.refreshes, 0);
          await h.confirm(tester);
          h.fail();
          await tester.pumpAndSettle();
          expect(await result, isFalse);
          expect(listing.entries, remaining);
          expect(h.controller.selectedItems.items, [remaining.first]);
          expect(h.jobs.jobTable.map((job) => job.state),
              [JobState.done, JobState.error]);
          expect(h.calls, hasLength(2));
        } finally {
          await h.drain(tester);
        }
      });
    }
  }

  testWidgets('delete result preserves replacement listings and changed entry paths',
      (tester) async {
    for (final replacement in ['listing', 'entry', 'path', 'session']) {
      final h = _DeleteHarness();
      await h.mount(tester);
      try {
        final result = h.start();
        final listing = h.controller.directory.value;
        final original = listing.entries.first;
        await h.confirm(tester);
        final fresh = _file('first', '/files/first');
        if (replacement == 'listing' || replacement == 'session') {
          h.controller.directory.value = FileDirectory()
            ..path = '/files'
            ..entries = [fresh];
        } else if (replacement == 'entry') {
          listing.entries = [fresh];
        } else {
          original.path = '/files/renamed';
          listing.entries = [original];
        }
        final current = h.controller.directory.value;
        final preserved = current.entries.single;
        h.controller.selectedItems.selectAll([preserved]);
        if (replacement == 'session') {
          h.currentSession = const Uuid().v4obj();
          h.jobs.clear();
        } else {
          await h.replySuccess(0);
        }
        h.dispatches.first.complete();
        await tester.pumpAndSettle();
        expect(h.controller.directory.value, same(current));
        expect(current.entries, [preserved]);
        expect(h.controller.selectedItems.items, [preserved]);
        if (replacement != 'session') {
          await h.confirm(tester);
          h.fail();
          await tester.pumpAndSettle();
        }
        expect(await result, isFalse);
        expect(current.entries, [preserved]);
        expect(h.controller.selectedItems.items, [preserved]);
      } finally {
        await h.drain(tester);
      }
    }
  });

  testWidgets('recursive deletion keeps its row until directory cleanup settles',
      (tester) async {
    for (final local in [false, true]) {
      final h = _DeleteHarness(isLocal: local);
      h.recursiveEntries.add({'name': 'child', 'entry_type': 4,
          'modified_time': 0, 'size': 1});
      await h.mount(tester);
      try {
        final result = h.start(directory: true);
        final listing = h.controller.directory.value;
        final original = listing.entries.first;
        final remaining = listing.entries.skip(1).toList();
        await h.confirm(tester);
        await h.replySuccess(0);
        h.dispatches.first.complete();
        await tester.pumpAndSettle();
        expect(h.calls, hasLength(2));
        expect(listing.entries.first, same(original));
        await h.replySuccess(1, localDirectory: local);
        await tester.pump();
        expect(listing.entries.first, same(original));
        h.dispatches[1].complete();
        await tester.pumpAndSettle();
        expect(listing.entries, remaining);
        expect(h.controller.selectedItems.items, [remaining.first]);
        await h.confirm(tester);
        h.fail();
        await tester.pumpAndSettle();
        expect(await result, isFalse);
        expect(listing.entries, remaining);
      } finally {
        await h.drain(tester);
      }
    }
  });

  testWidgets('failed recursive cleanup preserves the directory row and selection',
      (tester) async {
    final h = _DeleteHarness();
    h.recursiveEntries.add({'name': 'child', 'entry_type': 4,
        'modified_time': 0, 'size': 1});
    await h.mount(tester);
    try {
      final result = h.start(directory: true);
      final listing = h.controller.directory.value;
      final before = listing.entries.toList();
      await h.confirm(tester);
      await h.replySuccess(0);
      h.dispatches.first.complete();
      await tester.pumpAndSettle();
      h.fail(directory: true);
      await tester.pumpAndSettle();
      expect(await result, isFalse);
      expect(listing.entries, before);
      expect(h.controller.selectedItems.items, before.take(2));
      expect(h.jobs.jobTable.single.state, JobState.error);
    } finally {
      await h.drain(tester);
    }
  });

  testWidgets('skipping a deletion preserves its row through a later failure',
      (tester) async {
    final h = _DeleteHarness();
    await h.mount(tester);
    try {
      final result = h.start();
      final listing = h.controller.directory.value;
      final before = listing.entries.toList();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await h.confirm(tester);
      h.fail();
      await tester.pumpAndSettle();
      expect(await result, isFalse);
      expect(listing.entries, before);
      expect(h.controller.selectedItems.items, before.take(2));
      expect(h.calls.single[1], '/files/successor');
    } finally {
      await h.drain(tester);
    }
  });

  for (final local in [false, true]) {
    for (final directory in [false, true]) {
      testWidgets('delete ${local ? "local" : "remote"} ${directory ? "directory" : "file"} failure is visible and stops the batch',
          (tester) async {
        final h = _DeleteHarness(isLocal: local);
        await h.mount(tester);
        try {
          final result = h.start(directory: directory);
          await h.confirm(tester);
          expect(h.calls, hasLength(1));
          h.fail(directory: directory);
          await tester.pumpAndSettle();
          expect(await result, isFalse);
          expect(find.textContaining('delete denied', findRichText: true), findsWidgets);
          expect(h.jobs.jobTable.single.state, JobState.error);
          expect(h.calls, hasLength(1));
          expect(h.refreshes, 0);
          expect(h.controller.selectedItems.items, hasLength(2));
        } finally {
          await h.drain(tester);
        }
      });
    }
  }

  testWidgets('delete listing failure stops before the next selected entry',
      (tester) async {
    final h = _DeleteHarness()..failListing = true;
    await h.mount(tester);
    try {
      final result = h.start(directory: true);
      await tester.pumpAndSettle();
      expect(find.text('This is irreversible!'), findsNothing);
      expect(await result, isFalse);
      expect(find.textContaining('listing denied', findRichText: true), findsWidgets);
      expect(h.calls, isEmpty);
      expect(h.refreshes, 0);
    } finally {
      await h.drain(tester);
    }
  });

  testWidgets('delete allocation failure is visible and permits a fresh retry',
      (tester) async {
    final h = _DeleteHarness()..failAllocation = true;
    await h.mount(tester);
    try {
      final failed = h.start();
      await tester.pumpAndSettle();
      expect(await failed, isFalse);
      expect(find.textContaining('allocation failed', findRichText: true), findsWidgets);
      expect(h.calls, isEmpty);
      h.manager.dismissAll();
      h.failAllocation = false;
      final retry = h.start();
      await h.confirm(tester);
      await h.jobs.jobDone({'id': '1', 'file_num': '0'}, h.session);
      h.dispatches.single.complete();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(await retry, isTrue);
      expect(h.jobs.jobTable.first.state, JobState.done);
      expect(h.calls, hasLength(1));
      expect(h.refreshes, 1);
    } finally {
      await h.drain(tester);
    }
  });

  testWidgets('delete retired failure cannot replace the current dialog',
      (tester) async {
    final h = _DeleteHarness();
    await h.mount(tester);
    try {
      final result = h.start(directory: true);
      await h.confirm(tester);
      h.currentSession = const Uuid().v4obj();
      h.jobs.clear();
      msgBox(h.currentSession, 'custom-error', 'Error', 'Current dialog', '', h.manager);
      h.dispatches.single.completeError(StateError('retired failure'));
      await tester.pumpAndSettle();
      expect(await result, isFalse);
      expect(find.textContaining('Current dialog', findRichText: true), findsWidgets);
      expect(find.textContaining('retired failure', findRichText: true), findsNothing);
      expect(h.calls, hasLength(1));
    } finally {
      await h.drain(tester);
    }
  });

  test('native file-job allocation failures cannot dispatch fallback IDs',
      () async {
    final session = const Uuid().v4obj();
    var allocations = 0;
    final ids = JobID(nativeNext: () {
      allocations++;
      if (allocations == 2) throw StateError('bridge unavailable');
      if (allocations == 3) throw StateError('file-job ID space is exhausted');
      if (allocations == 4) return 0;
      if (allocations == 5) return 2147483648;
      return allocations == 1 ? 31 : 32;
    });
    final dispatched = <int>[];
    final jobController = JobController(() => session, () => null,
        isCurrentSession: (actual) => actual == session,
        requests: _jobRequests(),
        nextJobId: ids.next);
    final controller = FileController(
      isLocal: true,
      getSessionID: () => session,
      getDialogManager: () => null,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      comparePeerVersion: (_) => 1,
      jobController: jobController,
      fileFetcher: FileFetcher(() => session, requests: _fetcherRequests()),
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: _identityTranslate,
      requests: _controllerRequests(sendFiles: (actualSession, actionId,
          path, to, fileNum, includeHidden, isRemote, isDirectory) async {
        expect(actualSession, session);
        dispatched.add(actionId);
      }),
    );
    final selected = SelectedItems(isLocal: true)
      ..add(_file('one', '/source/one'));
    final destination = DirectoryData(
        FileDirectory()..path = '/destination',
        DirectoryOptions(isWindows: false));

    await controller.sendFiles(selected, destination);
    expect(dispatched, [31]);
    for (final failure in <Matcher>[
      isA<StateError>(),
      isA<StateError>(),
      isA<StateError>(),
      isA<StateError>(),
    ]) {
      await expectLater(
          controller.sendFiles(selected, destination), throwsA(failure));
      expect(dispatched, [31]);
      expect(jobController.jobTable.map((job) => job.id), [31]);
      expect(selected.items, hasLength(1));
    }

    await controller.sendFiles(selected, destination);
    expect(dispatched, [31, 32]);
    expect(jobController.jobTable.map((job) => job.id), [31, 32]);
  });

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
      comparePeerVersion: (_) => 1,
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
      comparePeerVersion: (_) => 1,
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
      comparePeerVersion: (_) => 1,
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
      comparePeerVersion: (_) => 1,
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
      comparePeerVersion: (_) => 1,
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
      comparePeerVersion: (_) => 1,
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

  test('cleared file jobs retain dispatch capacity until actual completion',
      () async {
    final harness = _ResultHarness();
    addTearDown(harness.drain);
    final old = harness.start();
    harness.listener.clear();
    expect(await old, _retiredError);
    harness.session = const Uuid().v4obj();
    harness.listener.clear();
    expect(await harness.start(actionId: 8), _capacityError);
    expect(harness.dispatches, 1);
    harness.completions.single.complete();
    await Future<void>.delayed(Duration.zero);
    final replacement = harness.start(actionId: 8);
    expect(harness.reply(actionId: 8), isTrue);
    harness.completions.last.complete();
    expect(await replacement, containsPair('id', '8'));
    expect(harness.dispatches, 2);
  });

  test('cleared file jobs retain capacity after early success and error',
      () async {
    for (final error in <String?>[null, 'early peer failure']) {
      final harness = _ResultHarness();
      addTearDown(harness.drain);
      final old = harness.start();
      expect(harness.reply(error: error), isTrue);
      harness.listener.clear();
      expect(await old, _retiredError);
      harness.session = const Uuid().v4obj();
      expect(await harness.start(actionId: 8), _capacityError);
      expect(harness.dispatches, 1);
      harness.completions.single.complete();
      await Future<void>.delayed(Duration.zero);
      final replacement = harness.start();
      expect(harness.reply(), isTrue);
      harness.completions.last.complete();
      expect(await replacement, containsPair('id', '7'));
    }
  });

  test('timed out file jobs retain dispatch capacity across clear', () async {
    final harness = _ResultHarness(timeout: const Duration(milliseconds: 20));
    addTearDown(harness.drain);
    expect(await harness.start(), isA<TimeoutException>());
    harness.listener.clear();
    harness.session = const Uuid().v4obj();
    expect(await harness.start(actionId: 8), _capacityError);
    expect(harness.dispatches, 1);
    harness.completions.single.completeError(StateError('late dispatch failure'));
    await Future<void>.delayed(Duration.zero);
    final replacement = harness.start();
    expect(harness.reply(), isTrue);
    harness.completions.last.complete();
    expect(await replacement, containsPair('id', '7'));
  });

  test('retired file job failure cannot release replacement ownership', () async {
    final harness = _ResultHarness(capacity: 2);
    addTearDown(harness.drain);
    final old = harness.start();
    harness.listener.clear();
    expect(await old, _retiredError);
    final replacement = harness.start();
    expect(await harness.start(actionId: 8), _capacityError);
    expect(harness.dispatches, 2);
    harness.completions.first.completeError(StateError('retired dispatch failed'));
    await Future<void>.delayed(Duration.zero);
    final other = harness.start(actionId: 8);
    expect(harness.reply(actionId: 8, error: 'current job denied'), isTrue);
    harness.completions.last.complete();
    expect(await other, isA<StateError>().having(
        (error) => error.message, 'message', 'current job denied'));
    expect(harness.reply(), isTrue);
    harness.completions[1].complete();
    expect(await replacement, containsPair('id', '7'));
    expect(harness.dispatches, 3);
  });

  test('settled file dispatches release cancelled response waiters', () async {
    final harness = _ResultHarness();
    addTearDown(harness.drain);
    final old = harness.start();
    harness.completions.single.complete();
    await Future<void>.delayed(Duration.zero);
    harness.listener.clear();
    expect(await old, _retiredError);
    final replacement = harness.start(actionId: 8);
    expect(harness.reply(actionId: 8), isTrue);
    harness.completions.last.complete();
    expect(await replacement, containsPair('id', '8'));
    final immediate = StateError('synchronous dispatch failure');
    expect(await harness.start(dispatch: () => throw immediate), same(immediate));
    final recovered = harness.start();
    expect(harness.reply(), isTrue);
    harness.completions.last.complete();
    expect(await recovered, containsPair('id', '7'));
  });

  test('inline file job completion and reentrant clear cannot retain slots',
      () async {
    final harness = _ResultHarness(capacity: 2);
    addTearDown(harness.drain);
    Future<void> inlineSuccess() {
      expect(harness.reply(), isTrue);
      return SynchronousFuture<void>(null);
    }
    for (var i = 0; i < 3; i++) {
      expect(await harness.start(dispatch: inlineSuccess), containsPair('id', '7'));
    }
    expect(await harness.start(dispatch: () {
      harness.listener.clear();
      return SynchronousFuture<void>(null);
    }), _retiredError);
    expect(await harness.start(dispatch: () {
      harness.listener.clear();
      throw StateError('dispatch refused after reentrant clear');
    }), _retiredError);
    Future<Object>? replacement;
    expect(await harness.start(dispatch: () {
      harness.listener.clear();
      replacement = harness.start();
      throw StateError('old dispatch refused after replacement');
    }), _retiredError);
    expect(harness.reply(), isTrue);
    harness.completions.last.complete();
    expect(await replacement!, containsPair('id', '7'));
    expect(await harness.start(dispatch: inlineSuccess), containsPair('id', '7'));
  });

  test('new file job owners share admission with listing owners', () async {
    final owners = <_ResultHarness>[];
    final session = const Uuid().v4obj();
    final nativeListing = Completer<String>();
    var listingDispatches = 0;
    final listing = FileFetcher(() => session,
        requestTimeout: const Duration(milliseconds: 20),
        requests: FileFetcherRequests(
          readDirectory: (_, __, ___) async {},
          readEmptyDirectories: (_, __, ___) async {},
          readDirectoryTree: (_, __, ___, ____, _____) async {},
          readLocalDirectory: (_, __, ___) {
            listingDispatches++;
            return nativeListing.future;
          },
        ));
    Future<Object> read() => listing.fetchDirectory('/local', true, false)
        .then<Object>((value) => value,
            onError: (Object error, StackTrace _) => error);
    addTearDown(() async {
      listing.cancelPending();
      if (!nativeListing.isCompleted) {
        nativeListing.complete(jsonEncode({'id': 0, 'path': '/local', 'entries': []}));
      }
      await Future.wait(owners.map((owner) => owner.drain()));
      await Future<void>.delayed(Duration.zero);
    });
    for (var i = 0; i < 64; i++) {
      final owner = _ResultHarness(timeout: const Duration(seconds: 2));
      owners.add(owner);
      final result = owner.start();
      owner.listener.clear();
      expect(await result, _retiredError);
    }
    final capacity = isA<StateError>().having(
        (error) => error.message, 'message', 'File request capacity exhausted');
    expect(await read(), capacity);
    expect(listingDispatches, 0);
    owners.first.completions.single.completeError(StateError('retired job'));
    await Future<void>.delayed(Duration.zero);
    final currentOwner = _ResultHarness();
    owners.add(currentOwner);
    final current = currentOwner.start();
    expect(currentOwner.reply(), isTrue);
    owners.first.listener.clear();
    expect(await read(), capacity);
    expect(listingDispatches, 0);
    currentOwner.completions.single.complete();
    expect(await current, containsPair('id', '7'));
    nativeListing.complete(jsonEncode({'id': 0, 'path': '/local', 'entries': []}));
    expect((await read() as FileDirectory).path, '/local');
  });
}

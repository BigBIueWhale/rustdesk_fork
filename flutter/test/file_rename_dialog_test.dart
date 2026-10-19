import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _RenameCall {
  _RenameCall(this.session, this.id, this.path, this.name, this.isRemote);

  final SessionID session;
  final int id;
  final String path;
  final String name;
  final bool isRemote;
  final dispatch = Completer<void>();
}

class _RenameHarness {
  final session = const Uuid().v4obj();
  final manager = OverlayDialogManager(translateText: (text) => text);
  final calls = <_RenameCall>[];
  final submissions = <Future<Object?>>[];
  late final JobController jobs;
  late final FileController controller;
  late Future<void> opening;

  Future<void> mount(WidgetTester tester) async {
    final overlay = BlockableOverlayState();
    manager.setOverlayState(overlay);
    var nextId = 0;
    jobs = JobController(() => session, () => manager,
        isCurrentSession: (actual) => actual == session,
        nextJobId: () => ++nextId,
        resultTimeout: const Duration(seconds: 2));
    controller = FileController(
      isLocal: true,
      getSessionID: () => session,
      getDialogManager: () => manager,
      isCurrentSession: (actual) => actual == session,
      getPeerPlatform: () => 'Linux',
      comparePeerVersion: (_) => 1,
      jobController: jobs,
      fileFetcher: FileFetcher(() => session),
      getOtherSideDirectoryData: () =>
          DirectoryData(FileDirectory(), DirectoryOptions()),
      translateText: (text) => text,
      requests: FileControllerRequests(
        sendFiles: (_, __, ___, ____, _____, ______, _______, ________) async {},
        removeFile: (_, __, ___, ____, _____) async {},
        removeEmptyDirectories: (_, __, ___, ____) async {},
        createDirectory: (_, __, ___, ____) async {},
        renameFile: (session, id, path, name, isRemote) {
          final call = _RenameCall(session, id, path, name, isRemote);
          calls.add(call);
          return call.dispatch.future;
        },
      ),
    );
    controller.options.value.isWindows = false;
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
    ));
    final entry = Entry()
      ..entryType = 4
      ..name = 'old.txt'
      ..path = '/source/old.txt';
    controller.directory.value
      ..path = '/source'
      ..entries = [entry];
    opening = controller.renameAction(entry, true);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'new.txt');
    await tester.pump();
  }

  Future<Object?> submit(Function() callback) {
    final observed = Future<void>.sync(() => callback()).then<Object?>(
        (_) => null, onError: (Object error, StackTrace _) => error);
    submissions.add(observed);
    return observed;
  }

  Future<void> finish(int index, {String? error}) async {
    final call = calls[index];
    if (call.dispatch.isCompleted) return;
    final event = {'id': '${call.id}', 'file_num': '0', 'speed': '0'};
    if (error == null) {
      await jobs.jobDone(event, call.session);
    } else {
      jobs.jobError({...event, 'err': error}, call.session);
    }
    call.dispatch.complete();
  }

  Future<void> drain(WidgetTester tester) async {
    manager.dismissAll();
    for (var index = 0; index < calls.length; index++) {
      await finish(index);
    }
    await Future.wait(submissions);
    await opening;
    jobs.clear();
    await tester.pumpWidget(const SizedBox.shrink());
  }
}

void main() {
  testWidgets('rename admits one request until its exact result settles',
      (tester) async {
    final harness = _RenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      final duplicate = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(1));
      expect(harness.calls.single.session, harness.session);
      expect(harness.calls.single.path, '/source/old.txt');
      expect(harness.calls.single.name, 'new.txt');
      expect(harness.calls.single.isRemote, isFalse);
      expect(find.byType(CustomAlertDialog), findsOneWidget);
      await harness.finish(0);
      expect(await first, isNull);
      expect(await duplicate, isNull);
      await harness.opening;
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('retired rename callbacks cannot admit a file operation',
      (tester) async {
    final harness = _RenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      await harness.opening;
      final stale = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, isEmpty);
      expect(await stale, isNull);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('rename failure after dismissal leaves the retired widget alone',
      (tester) async {
    final harness = _RenameHarness();
    await harness.mount(tester);
    try {
      final submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final pending = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(1));
      harness.manager.dismissAll();
      await tester.pumpAndSettle();
      await harness.opening;
      await harness.finish(0, error: 'rename denied');
      expect(await pending, isNull);
      await tester.pump();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });

  testWidgets('rename failure stays visible and permits an explicit retry',
      (tester) async {
    final harness = _RenameHarness();
    await harness.mount(tester);
    try {
      var submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final first = harness.submit(submit);
      await tester.pump();
      await harness.finish(0, error: 'rename denied');
      expect(await first, isNull);
      await tester.pumpAndSettle();
      expect(find.textContaining('rename denied'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'retry.txt');
      await tester.pumpAndSettle();
      expect(find.textContaining('rename denied'), findsNothing);
      submit = tester.widget<CustomAlertDialog>(find.byType(CustomAlertDialog))
          .onSubmit!;
      final retry = harness.submit(submit);
      await tester.pump();
      expect(harness.calls, hasLength(2));
      expect(harness.calls[1].id, isNot(harness.calls[0].id));
      expect(harness.calls[1].name, 'retry.txt');
      await harness.finish(1);
      expect(await retry, isNull);
      await harness.opening;
      await tester.pumpAndSettle();
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await harness.drain(tester);
    }
  });
}

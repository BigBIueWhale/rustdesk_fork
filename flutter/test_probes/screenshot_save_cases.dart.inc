import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Binding implements RustdeskImpl {
  final calls = <List<Object>>[];
  Future<String> Function() complete = () async => '';
  @override
  dynamic noSuchMethod(Invocation invocation) {
    switch (invocation.memberName) {
      case #translate:
        return invocation.namedArguments[#name] as String;
      case #sessionHandleScreenshot:
        calls.add([
          invocation.namedArguments[#sessionId] as SessionID,
          invocation.namedArguments[#screenshotId] as String,
          invocation.namedArguments[#action] as String,
        ]);
        return complete();
      default:
        throw StateError('Unexpected native call: ${invocation.memberName}');
    }
  }
}

class _Picker extends FilePicker {
  final requests = <Map<String, Object?>>[];
  int get calls => requests.length;
  Future<String?> Function() choose = () async => '/selected/screen:one.png';
  @override
  Future<String?> saveFile({String? dialogTitle, String? fileName,
      String? initialDirectory, FileType type = FileType.any,
      List<String>? allowedExtensions, bool lockParentWindow = false}) {
    requests.add({'title': dialogTitle, 'name': fileName,
        'type': type, 'extensions': allowedExtensions});
    return choose();
  }
}

class _Session implements FFI {
  @override
  final SessionID sessionId = const Uuid().v4obj();
  @override
  final SessionID clientOwnerId = const Uuid().v4obj();
  @override
  final dialogManager = OverlayDialogManager(translateText: (text) => text);
  @override
  late final ffiModel = FfiModel(WeakReference<FFI>(this));
  bool current = true;
  @override
  bool isCurrentSession(SessionID id) => current && id == sessionId;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected session access: ${invocation.memberName}');
}

class _Fixture {
  final binding = _Binding();
  final picker = _Picker();
  final session = _Session();
  late VoidCallback save;

  Future<void> open(WidgetTester tester) async {
    installScreenshotSaveProbeBinding(binding);
    final previousPicker = FilePicker.platform;
    FilePicker.platform = picker;
    addTearDown(() => FilePicker.platform = previousPicker);
    final overlay = BlockableOverlayState();
    session.dialogManager.setOverlayState(overlay);
    await tester.pumpWidget(MaterialApp(
      home: BlockableOverlay(state: overlay, underlying: const SizedBox.expand()),
    ));
    await session.ffiModel.startEventListener(session.sessionId, 'screenshot-peer')({
      'name': 'screenshot', 'msg': '', 'screenshot_id': 'request-17',
    });
    await tester.pump();
    save = tester.widget<ButtonStyleButton>(find.ancestor(
      of: find.text('Save as...'),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    )).onPressed!;
    addTearDown(() async {
      session.current = false;
      session.ffiModel.clear();
      session.dialogManager.dismissAll();
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  Future<void> press(WidgetTester tester) async {
    save();
    expect(session.dialogManager.existing('screenshot-actions'), isFalse);
    await tester.pumpAndSettle();
    expect(picker.requests, hasLength(1));
    final request = picker.requests.single;
    expect(request['title'], 'Save as...');
    expect(request['name'], matches(r'^screenshot_\d+\.png$'));
    expect(request['type'], FileType.custom);
    expect(request['extensions'], ['png']);
  }

  void expectCall(String action) => expect(binding.calls,
      [[session.sessionId, 'request-17', action]]);

  void expectFailure(WidgetTester tester, String detail) {
    expect(find.text('Take screenshot'), findsOneWidget);
    expect(find.textContaining(detail), findsOneWidget);
    expect(tester.takeException(), isNull);
  }
}

void main() {
  testWidgets('screenshot save preserves selected path and exact request', (tester) async {
    final f = _Fixture();
    await f.open(tester);
    await f.press(tester);
    f.expectCall('0:/selected/screen:one.png');
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('screenshot picker cancellation discards its exact request', (tester) async {
    final f = _Fixture();
    f.picker.choose = () async => null;
    await f.open(tester);
    await f.press(tester);
    f.expectCall('2');
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('screenshot save returned error is visible', (tester) async {
    final f = _Fixture();
    f.binding.complete = () async => 'native save refused';
    await f.open(tester);
    await f.press(tester);
    f.expectCall('0:/selected/screen:one.png');
    f.expectFailure(tester, 'native save refused');
  });

  for (final stage in ['picker', 'save']) {
    for (final timing in ['synchronous', 'asynchronous']) {
      testWidgets('screenshot $stage $timing exception is visible', (tester) async {
        final f = _Fixture();
        Future<String> fail() {
          if (timing == 'synchronous') throw StateError('$stage failure');
          return Future<String>.error(StateError('$stage failure'));
        }
        if (stage == 'picker') {
          f.picker.choose = fail;
        } else {
          f.binding.complete = fail;
        }
        await f.open(tester);
        await f.press(tester);
        expect(f.picker.calls, 1);
        if (stage == 'picker') {
          expect(f.binding.calls, isEmpty);
        } else {
          f.expectCall('0:/selected/screen:one.png');
        }
        f.expectFailure(tester, '$stage failure');
      });
    }
  }

  testWidgets('screenshot retired before deferred picker cannot start it', (tester) async {
    final f = _Fixture();
    await f.open(tester);
    f.save();
    f.session.current = false;
    await tester.pumpAndSettle();
    expect(f.picker.calls, 0);
    expect(f.binding.calls, isEmpty);
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  for (final outcome in ['completion', 'exception']) {
    testWidgets(outcome == 'completion'
        ? 'screenshot retired picker completion cannot save'
        : 'screenshot retired picker exception stays silent', (tester) async {
      final f = _Fixture();
      final pending = Completer<String?>();
      f.picker.choose = () => pending.future;
      await f.open(tester);
      await f.press(tester);
      expect(f.picker.calls, 1);
      f.session.current = false;
      if (outcome == 'completion') {
        pending.complete('/selected/late.png');
      } else {
        pending.completeError(StateError('late picker failure'));
      }
      await tester.pumpAndSettle();
      expect(f.binding.calls, isEmpty);
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  for (final outcome in ['exception', 'returned error']) {
    testWidgets('screenshot retired save $outcome stays silent', (tester) async {
      final f = _Fixture();
      final pending = Completer<String>();
      f.binding.complete = () => pending.future;
      await f.open(tester);
      await f.press(tester);
      f.expectCall('0:/selected/screen:one.png');
      f.session.current = false;
      if (outcome == 'exception') {
        pending.completeError(StateError('late save failure'));
      } else {
        pending.complete('late save refused');
      }
      await tester.pumpAndSettle();
      f.expectCall('0:/selected/screen:one.png');
      expect(find.byType(CustomAlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }
}

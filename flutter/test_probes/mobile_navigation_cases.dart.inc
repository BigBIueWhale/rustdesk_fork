import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/mobile/pages/remote_page.dart' as remote;
import 'package:flutter_hbb/mobile/pages/view_camera_page.dart' as camera;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/native/common.dart';
import 'package:flutter_keyboard_visibility/flutter_keyboard_visibility.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:uuid/uuid.dart';

class _Binding implements RustdeskImpl {
  @override
  String getLocalFlutterOption({required String k, dynamic hint}) => '';
  @override
  String mainGetLocalOption({required String key, dynamic hint}) => 'N';
  @override
  String translate({required String name, required String locale, dynamic hint}) => name;
  @override
  bool isIncomingOnly({dynamic hint}) => false;
  @override
  bool isOutgoingOnly({dynamic hint}) => false;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected navigation native call: ${invocation.memberName}');
}

// Only native session admission/retirement is replaced. Navigation, dialog,
// model construction and page lifecycle methods remain the product code.
class _Owner extends FFI {
  _Owner() : super(null);
  final closes = <SessionID>[];

  @override
  SessionID start(String id, {
    bool isFileTransfer = false, bool isViewCamera = false,
    bool isPortForward = false, bool isRdp = false, bool isTerminal = false,
    String? password, String? connToken, int? tabWindowId, int? display,
    List<int>? displays, SessionID? moveFromSessionId,
    SessionID? moveFromClientOwnerId,
  }) {
    this.id = id;
    sessionId = const Uuid().v4obj();
    connType = isViewCamera ? ConnType.viewCamera : ConnType.defaultConn;
    closed = false;
    return sessionId;
  }

  @override
  Future<void> close({bool closeSession = true, SessionID? expectedSessionId}) async {
    final closing = expectedSessionId ?? sessionId;
    closes.add(closing);
    if (closing == sessionId) closed = true;
  }
}

Future<void> _frames(WidgetTester tester) async {
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 450));
  await tester.pump(const Duration(milliseconds: 450));
  expect(tester.takeException(), isNull);
}

class _Harness {
  late final _Owner owner;
  final String kind;
  _Harness(this.kind);

  Future<void> mount(WidgetTester tester) async {
    isTest = true;
    Get.testMode = true;
    installConnectionPageBinding(_Binding());
    owner = _Owner();
    installConnectionPageOwner(owner);
    final messenger = tester.binding.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (_) async => null);
    messenger.setMockMethodCallHandler(const MethodChannel('mChannel'), (_) async => true);
    messenger.setMockMethodCallHandler(
        const MethodChannel('flutter_keyboard_visibility'), (_) async => null);
    await tester.binding.setSurfaceSize(const Size(400, 800));
    await tester.pumpWidget(MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: owner.ffiModel),
        ChangeNotifierProvider.value(value: owner.imageModel),
        ChangeNotifierProvider.value(value: owner.cursorModel),
        ChangeNotifierProvider.value(value: owner.canvasModel),
      ],
      child: MaterialApp(navigatorKey: globalKey, theme: MyTheme.lightTheme,
          home: const Scaffold(body: Text('home'))),
    ));
    await tester.pump();
  }

  Future<MaterialPageRoute<void>> page(WidgetTester tester,
      {bool replacement = false}) async {
    final route = MaterialPageRoute<void>(builder: (_) => kind == 'Remote'
        ? remote.RemotePage(id: '127.0.0.1')
        : camera.ViewCameraPage(id: '127.0.0.1'));
    if (replacement) {
      unawaited(globalKey.currentState!.pushReplacement(route));
    } else {
      unawaited(globalKey.currentState!.push(route));
    }
    await _frames(tester);
    expect(find.text('Connecting...'), findsOneWidget);
    return route;
  }

  VoidCallback loadingCancel(WidgetTester tester) =>
      tester.widget<TextButton>(find.widgetWithText(TextButton, 'Cancel')).onPressed!;

  Future<MaterialPageRoute<void>> other(WidgetTester tester) async {
    final route = MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('other page')));
    unawaited(globalKey.currentState!.push(route));
    await _frames(tester);
    return route;
  }

  Future<void> dispose(WidgetTester tester) async {
    owner.dialogManager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
    await _frames(tester);
    owner.recentPeersModel.dispose();
    owner.favoritePeersModel.dispose();
    owner.peerTabModel.dispose();
    owner.chatModel.dispose();
    final messenger = tester.binding.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
    messenger.setMockMethodCallHandler(const MethodChannel('mChannel'), null);
    messenger.setMockMethodCallHandler(const MethodChannel('flutter_keyboard_visibility'), null);
    await tester.binding.setSurfaceSize(null);
    Get.reset();
    isTest = false;
  }
}

void main() {
  installMobileNavigationPlatform();
  KeyboardVisibilityTesting.setVisibilityForTesting(false);
  for (final kind in ['Remote', 'Camera']) {
    testWidgets('mobile $kind loading Cancel closes its current page', (tester) async {
      final h = _Harness(kind);
      await h.mount(tester);
      try {
        final route = await h.page(tester);
        final session = h.owner.sessionId;
        h.loadingCancel(tester)();
        await _frames(tester);
        expect(route.isActive, isFalse);
        expect(find.text('home'), findsOneWidget);
        expect(h.owner.closes, [session]);
      } finally { await h.dispose(tester); }
    });

    testWidgets('mobile $kind loading Cancel preserves the preceding page', (tester) async {
      final h = _Harness(kind);
      await h.mount(tester);
      try {
        final previous = await h.other(tester);
        await h.page(tester);
        h.loadingCancel(tester)();
        await _frames(tester);
        expect(previous.isCurrent, isTrue);
        expect(find.text('other page'), findsOneWidget);
      } finally { await h.dispose(tester); }
    });

    testWidgets('mobile $kind hidden loading Cancel preserves the covering page', (tester) async {
      final h = _Harness(kind);
      await h.mount(tester);
      try {
        final route = await h.page(tester);
        final cancel = h.loadingCancel(tester);
        final covering = await h.other(tester);
        cancel();
        await _frames(tester);
        expect(covering.isCurrent, isTrue);
        expect(route.isActive, isTrue);
        expect(h.owner.closes, isEmpty);
      } finally { await h.dispose(tester); }
    });

    testWidgets('mobile $kind retired loading Cancel preserves a replacement session', (tester) async {
      final h = _Harness(kind);
      await h.mount(tester);
      try {
        await h.page(tester);
        final oldSession = h.owner.sessionId;
        final cancel = h.loadingCancel(tester);
        final current = await h.page(tester, replacement: true);
        final currentSession = h.owner.sessionId;
        expect(currentSession, isNot(oldSession));
        cancel();
        await _frames(tester);
        expect(current.isCurrent, isTrue);
        expect(h.owner.isCurrentSession(currentSession), isTrue);
        expect(h.owner.closes, [oldSession]);
      } finally { await h.dispose(tester); }
    });

    testWidgets('mobile $kind Back can close an ended session view', (tester) async {
      final h = _Harness(kind);
      await h.mount(tester);
      try {
        final route = await h.page(tester);
        h.owner.dialogManager.dismissAll();
        h.owner.closed = true;
        await _frames(tester);
        expect(await globalKey.currentState!.maybePop(), isTrue);
        await _frames(tester);
        expect(find.text('Are you sure to close the connection?'), findsOneWidget);
        await tester.tap(find.widgetWithText(TextButton, 'OK'));
        await _frames(tester);
        expect(route.isActive, isFalse);
        expect(find.text('home'), findsOneWidget);
      } finally { await h.dispose(tester); }
    });
  }
}

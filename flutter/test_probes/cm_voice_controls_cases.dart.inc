import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart'
    show MyTheme, OverlayDialogManager, globalKey, isTest;
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/mobile/pages/server_page.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

class _Binding implements RustdeskImpl {
  final responses = <(int, int, int, bool)>[];
  bool admitted = true;

  @override
  Future<bool> cmHandleIncomingVoiceCall({required int id,
      required int registryGeneration, required int callId,
      required bool accept, dynamic hint}) async {
    responses.add((id, registryGeneration, callId, accept));
    return admitted;
  }

  @override
  String translate({required String name, required String locale, dynamic hint}) => name;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Owner implements FFI {
  @override
  final dialogManager = OverlayDialogManager();

  @override
  late final serverModel = ServerModel(WeakReference<FFI>(this));

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Harness {
  final binding = _Binding();
  final owner = _Owner();
  final client = Client(7, true, false, false, 'Peer', '192.0.2.10', true, true, true)
    ..registryGeneration = 19
    ..voiceCallId = 23
    ..incomingVoiceCall = true;
  late StateSetter rebuild;
  bool previousIsTest = false;

  Future<void> mount(WidgetTester tester) async {
    previousIsTest = isTest;
    isTest = true;
    installCmAudioProbeBinding(binding);
    owner.serverModel.clients.add(client);
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: Center(child: SizedBox(width: 360,
        child: ChangeNotifierProvider<ServerModel>.value(value: owner.serverModel,
          child: StatefulBuilder(builder: (context, setState) {
            rebuild = setState;
            return ConnectionManager();
          }),
        ),
      ))),
    ));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  }

  Future<void> popup(WidgetTester tester) async {
    owner.serverModel.showVoiceCallDialog(client);
    await tester.pumpAndSettle();
    expect(find.text('Voice call'), findsOneWidget);
  }

  Finder pageAction(String label) => find.descendant(
      of: find.byType(ConnectionManager), matching: find.text(label));

  Future<void> tapPage(WidgetTester tester, String label) async {
    expect(pageAction(label), findsOneWidget);
    await tester.tap(pageAction(label));
    await tester.pumpAndSettle();
  }

  Future<void> finish(WidgetTester tester) async {
    owner.dialogManager.dismissAll();
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();
    owner.serverModel.serverPasswd.dispose();
    owner.serverModel.tabController.state.value.pageController.dispose();
    owner.serverModel.tabController.state.value.scrollController.dispose();
    owner.serverModel.controller.dispose();
    owner.serverModel.dispose();
    isTest = previousIsTest;
  }
}

void main() {
  for (final accept in [true, false]) {
    testWidgets('mobile voice popup ${accept ? 'accepts' : 'dismisses'} its exact call',
        (tester) async {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.popup(tester);
        await tester.tap(find.text(accept ? 'Accept' : 'Dismiss').last);
        await tester.pumpAndSettle();
        expect(find.text('Voice call'), findsNothing);
        expect(h.binding.responses, [(7, 19, 23, accept)]);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    });
  }

  testWidgets('mobile voice remains acceptable after closing its popup', (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.popup(tester);
      await tester.tap(find.widgetWithIcon(IconButton, Icons.close));
      await tester.pumpAndSettle();
      expect(find.text('Voice call'), findsNothing);
      expect(h.binding.responses, isEmpty);
      await h.tapPage(tester, 'Accept');
      expect(h.binding.responses, [(7, 19, 23, true)]);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  for (final accept in [true, false]) {
    testWidgets('mobile voice page ${accept ? 'accepts' : 'dismisses'} its exact call',
        (tester) async {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.tapPage(tester, accept ? 'Accept' : 'Dismiss');
        expect(h.binding.responses, [(7, 19, 23, accept)]);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    });
  }

  testWidgets('mobile voice page accepts with Enter and Space', (tester) async {
    for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        final label = h.pageAction('Accept');
        expect(label, findsOneWidget);
        var focused = false;
        for (var step = 0; step < 12; step++) {
          if (Focus.of(tester.element(label)).hasFocus) { focused = true; break; }
          await tester.sendKeyEvent(LogicalKeyboardKey.tab);
          await tester.pump();
        }
        expect(focused, isTrue);
        await tester.sendKeyEvent(key);
        await tester.pumpAndSettle();
        expect(h.binding.responses, [(7, 19, 23, true)]);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('mobile voice page retains the displayed call identity', (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      final button = tester.widget<TextButton>(find.ancestor(
          of: h.pageAction('Accept'), matching: find.byType(TextButton)));
      h.client.voiceCallId = 24;
      button.onPressed!();
      await tester.pumpAndSettle();
      expect(h.binding.responses, [(7, 19, 23, true)]);
      h.rebuild(() {});
      await tester.pumpAndSettle();
      await h.tapPage(tester, 'Accept');
      expect(h.binding.responses, [(7, 19, 23, true), (7, 19, 24, true)]);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('mobile voice page offers responses only while incoming', (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      for (final active in [false, true]) {
        h.rebuild(() {
          h.client.incomingVoiceCall = false;
          h.client.inVoiceCall = active;
          h.client.voiceCallId = active ? 23 : 0;
        });
        await tester.pumpAndSettle();
        expect(h.pageAction('Accept'), findsNothing);
        expect(h.pageAction('Dismiss'), findsNothing);
        expect(h.pageAction('Disconnect'), findsOneWidget);
      }
      expect(h.binding.responses, isEmpty);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('mobile voice page reports refusal and permits retry', (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      h.binding.admitted = false;
      await h.tapPage(tester, 'Accept');
      expect(find.text('Failed'), findsOneWidget);
      expect(h.binding.responses, [(7, 19, 23, true)]);
      await tester.pump(const Duration(seconds: 4));
      h.binding.admitted = true;
      await h.tapPage(tester, 'Accept');
      expect(h.binding.responses, [(7, 19, 23, true), (7, 19, 23, true)]);
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });
}

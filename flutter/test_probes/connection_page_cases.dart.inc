import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';
import 'package:flutter_hbb/common/widgets/peer_card.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/pages/connection_page.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';

class _Owner implements FFI {
  bool disposed = false;
  @override
  late final peerTabModel = PeerTabModel(WeakReference<FFI>(this), readLocalOption: (_) => '');
  @override
  final recentPeersModel = Peers(name: 'page-recent', loadEvent: LoadEvent.recent);
  @override
  final favoritePeersModel = Peers(name: 'page-favorite', loadEvent: LoadEvent.favorite);

  void dispose() {
    disposed = true;
    peerTabModel.dispose();
    recentPeersModel.dispose();
    favoritePeersModel.dispose();
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Binding implements RustdeskImpl {
  _Binding(this.owner);
  final _Owner owner;
  final address = Completer<String>();
  bool synchronousFailure = false;
  int addressReads = 0;

  @override
  Future<String> mainGetLastRemoteId({dynamic hint}) {
    addressReads++;
    if (synchronousFailure) throw StateError('private saved-address error');
    return address.future;
  }

  @override
  Future<String> mainGetCommon({required String key, dynamic hint}) async {
    expect(key, 'direct-listener-bound');
    return 'true';
  }

  @override
  Future<void> mainLoadRecentPeers({dynamic hint}) async {
    await Future<void>.value();
    if (!owner.disposed) owner.recentPeersModel.updatePeers({'peers': '[]', 'ids': ''});
  }

  @override
  Future<void> mainLoadFavPeers({dynamic hint}) async {}
  @override
  bool mainIsOptionFixed({required String key, dynamic hint}) => false;
  @override
  String getLocalFlutterOption({required String k, dynamic hint}) =>
      k == kOptionPeerSorting ? PeerSortType.remoteId : '';
  @override
  String translate({required String name, required String locale, dynamic hint}) => name;
  @override
  bool isIncomingOnly({dynamic hint}) => false;
  @override
  bool isOutgoingOnly({dynamic hint}) => false;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Harness {
  final owner = _Owner();
  late _Binding binding = _Binding(owner);
  final bindings = <_Binding>[];
  late StateSetter rebuild;
  bool visible = true;
  int generation = 0;

  Future<void> mount(WidgetTester tester) async {
    Get.testMode = true;
    desktopType = DesktopType.main;
    stateGlobal.isPortrait.value = false;
    peerCardUiType.value = PeerUiType.grid;
    peerSearchTextController.clear();
    peerSearchText.value = '';
    installConnectionPageOwner(owner);
    installConnectionPageBinding(binding);
    bindings.add(binding);
    await tester.binding.setSurfaceSize(const Size(1400, 800));
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: ChangeNotifierProvider<PeerTabModel>.value(
        value: owner.peerTabModel,
        child: StatefulBuilder(builder: (context, update) {
          rebuild = update;
          return visible ? ConnectionPage(key: ValueKey(generation))
              : const Text('Replacement page');
        }),
      )),
    ));
    await tester.pump();
    expect(find.byType(ConnectionPage), findsOneWidget);
    expect(binding.addressReads, 1);
  }

  Future<void> replace(WidgetTester tester) async {
    binding = _Binding(owner);
    bindings.add(binding);
    installConnectionPageBinding(binding);
    rebuild(() => generation++);
    await tester.pump();
    await tester.pump();
    expect(binding.addressReads, 1);
  }

  Future<void> close(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    for (final item in bindings) {
      if (!item.address.isCompleted) item.address.complete('');
    }
    await tester.pump(const Duration(seconds: 4));
    owner.dispose();
    await Get.reset();
    await tester.binding.setSurfaceSize(null);
  }
}

Finder get _field => find.byWidgetPredicate((widget) =>
    widget is TextField && widget.controller is DirectAddressTextEditingController);

void main() {
  testWidgets('connection page restores the saved address visibly', (tester) async {
    final harness = _Harness();
    try {
      await harness.mount(tester);
      harness.binding.address.complete('  saved.example:21118  ');
      await tester.pump();
      expect(find.text('saved.example:21118'), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
    } finally { await harness.close(tester); }
  });

  testWidgets('connection page preserves a typed address during restoration', (tester) async {
    final harness = _Harness();
    try {
      await harness.mount(tester);
      await tester.enterText(_field, 'typed.example:443');
      harness.binding.address.complete('saved.example:21118');
      await tester.pump();
      expect(find.text('typed.example:443'), findsOneWidget);
    } finally { await harness.close(tester); }
  });

  for (final synchronous in [false, true]) {
    testWidgets('connection page shows lookup failure synchronous=$synchronous', (tester) async {
      final harness = _Harness();
      harness.binding.synchronousFailure = synchronous;
      try {
        await harness.mount(tester);
        if (!synchronous) {
          await tester.enterText(_field, 'typed.example:443');
          harness.binding.address.completeError(StateError('private saved-address error'));
        }
        await tester.pump();
        expect(find.text('Failed'), findsOneWidget);
        expect(find.textContaining('private saved-address error'), findsNothing);
        if (!synchronous) expect(find.text('typed.example:443'), findsOneWidget);
        await tester.enterText(_field, 'retry.example:21118');
        expect(find.text('retry.example:21118'), findsOneWidget);
        await tester.pump(const Duration(seconds: 4));
        expect(find.text('Failed'), findsNothing);
        expect(harness.binding.addressReads, 1);
        expect(tester.takeException(), isNull);
      } finally { await harness.close(tester); }
    });
  }

  testWidgets('connection page suppresses a late failure after removal', (tester) async {
    final harness = _Harness();
    try {
      await harness.mount(tester);
      harness.rebuild(() => harness.visible = false);
      await tester.pump();
      harness.binding.address.completeError(StateError('retired saved-address error'));
      await tester.pump();
      expect(find.text('Replacement page'), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally { await harness.close(tester); }
  });

  testWidgets('connection page isolates replacement from the prior lookup', (tester) async {
    final harness = _Harness();
    try {
      await harness.mount(tester);
      final old = harness.binding;
      await harness.replace(tester);
      old.address.completeError(StateError('replaced saved-address error'));
      harness.binding.address.complete('replacement.example:21118');
      await tester.pump();
      expect(find.text('replacement.example:21118'), findsOneWidget);
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally { await harness.close(tester); }
  });

  for (final keyboard in [false, true]) {
    testWidgets('connection page rejects an invalid target keyboard=$keyboard', (tester) async {
      final harness = _Harness();
      try {
        await harness.mount(tester);
        harness.binding.address.complete('');
        await tester.pump();
        await tester.enterText(_field, ' 123 456 789 ');
        if (keyboard) {
          await tester.testTextInput.receiveAction(TextInputAction.done);
        } else {
          await tester.tap(find.widgetWithText(ElevatedButton, 'Connect'));
        }
        await tester.pump();
        expect(find.text('Direct address required (IP or host:port)'), findsOneWidget);
        expect(find.text('123 456 789'), findsOneWidget);
        expect(find.byType(ConnectionPage), findsOneWidget);
        expect(tester.takeException(), isNull);
      } finally { await harness.close(tester); }
    });
  }
}

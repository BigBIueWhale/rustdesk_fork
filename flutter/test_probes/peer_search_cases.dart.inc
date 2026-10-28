import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart'
    show MyTheme, globalKey, installPeerSearchProbeOwner;
import 'package:flutter_hbb/common/widgets/peer_card.dart';
import 'package:flutter_hbb/common/widgets/peer_tab_page.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

class _FavoriteCall {
  _FavoriteCall(List<String> ids, this.favorite) : ids = List.of(ids);
  final List<String> ids;
  final bool favorite;
  final result = Completer<void>();
}

class _Binding implements RustdeskImpl {
  String layout = '';
  Object? readError;
  final reads = <String>[];
  final writes = <String>[];
  Future<String> Function(String)? save;
  bool fixed = false;
  final favoriteCalls = <_FavoriteCall>[];
  bool failFavoriteSynchronously = false;

  @override
  Future<void> mainSetFavorites(
      {required List<String> ids, required bool favorite, dynamic hint}) {
    if (failFavoriteSynchronously) throw StateError('favorite request refused');
    final call = _FavoriteCall(ids, favorite);
    favoriteCalls.add(call);
    return call.result.future;
  }

  @override
  Future<void> mainLoadRecentPeers({dynamic hint}) async {}

  @override
  Future<void> mainLoadFavPeers({dynamic hint}) async {}

  @override
  bool mainIsOptionFixed({required String key, dynamic hint}) => fixed;

  @override
  Future<void> setLocalFlutterOption(
      {required String k, required String v, dynamic hint}) async {
    expect(k, kOptionPeerCardUiType);
    writes.add(v);
    layout = await save?.call(v) ?? v;
  }

  @override
  String getLocalFlutterOption({required String k, dynamic hint}) {
    if (k == kOptionPeerSorting) return PeerSortType.remoteId;
    expect(k, kOptionPeerCardUiType);
    reads.add(k);
    if (readError != null) throw readError!;
    return layout;
  }

  @override
  String translate({required String name, required String locale, dynamic hint}) =>
      name;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _PeerOwner implements FFI {
  @override
  late final PeerTabModel peerTabModel =
      PeerTabModel(WeakReference<FFI>(this), readLocalOption: (_) => '');
  @override
  final recentPeersModel = Peers(
      name: 'search-test-recent', loadEvent: LoadEvent.recent, getInitPeers: null);
  @override
  final favoritePeersModel = Peers(
      name: 'search-test-favorite', loadEvent: LoadEvent.favorite, getInitPeers: null);

  Peers peers(PeerTabIndex tab) =>
      tab == PeerTabIndex.recent ? recentPeersModel : favoritePeersModel;

  void dispose() {
    peerTabModel.dispose();
    recentPeersModel.dispose();
    favoritePeersModel.dispose();
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('peer search must not call its native owner');
}

class _PeerView extends BasePeersView {
  _PeerView(PeerTabIndex tab, List<String> activated)
      : super(
          peerTabIndex: tab,
          peerCardBuilder: (peer) => TextButton(
            onPressed: () => activated.add(peer.id), child: Text(peer.id)),
        );
}

final _searchPeers = [
  Peer.fromJson({'id': '192.0.2.10', 'hostname': 'Office'}),
  Peer.fromJson({'id': '192.0.2.20', 'username': 'Alice'}),
  Peer.fromJson({'id': '192.0.2.30', 'alias': 'Travel'}),
];

Future<void> _withPeers(WidgetTester tester, PeerTabIndex tab,
    Future<void> Function(_PeerOwner owner, List<String> activated) body) async {
  final owner = _PeerOwner();
  final activated = <String>[];
  installPeerSearchProbeOwner(owner);
  owner.peerTabModel.setCurrentTab(tab.index);
  owner.peers(tab).peers = _searchPeers.toList();
  peerCardUiType.value = PeerUiType.list;
  try {
    await tester.pumpWidget(MaterialApp(
      theme: MyTheme.lightTheme,
      home: Scaffold(body: _PeerView(tab, activated)),
    ));
    await body(owner, activated);
  } finally {
    await tester.pumpWidget(const SizedBox.shrink());
    owner.dispose();
  }
}

class _BulkFavoriteHarness {
  _BulkFavoriteHarness(this.binding);
  final _Binding binding;
  final owner = _PeerOwner();
  final submissions = <Future<void>>[];
  late StateSetter rebuild;
  bool visible = true;

  void select(String id) {
    owner.peerTabModel.setMultiSelectionMode(false);
    owner.peerTabModel.setMultiSelectionMode(true);
    owner.peerTabModel.select(Peer.fromJson({'id': id}));
  }

  Future<void> mount(WidgetTester tester) async {
    installPeerSearchProbeOwner(owner);
    select('192.0.2.10');
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: StatefulBuilder(builder: (context, setState) {
        rebuild = setState;
        return visible
            ? ChangeNotifierProvider<PeerTabModel>.value(
                value: owner.peerTabModel, child: const PeerTabPage())
            : const Text('Replacement page');
      })),
    ));
    await tester.pumpAndSettle();
  }

  VoidCallback action(WidgetTester tester) => tester.widget<InkWell>(
      find.descendant(of: find.byTooltip('Add to Favorites'),
          matching: find.byType(InkWell))).onTap!;

  Future<void> submit(VoidCallback callback) {
    final result = Future<void>.sync(() => (callback as dynamic)());
    submissions.add(result);
    return result;
  }

  Future<void> drain(WidgetTester tester) async {
    for (final call in binding.favoriteCalls) {
      if (!call.result.isCompleted) call.result.complete();
    }
    await Future.wait(submissions);
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpWidget(const SizedBox.shrink());
    owner.dispose();
  }
}

class _Harness {
  final other = FocusNode();
  late StateSetter rebuild;
  double width = 400;

  Widget app() => MaterialApp(
        home: Scaffold(
          body: StatefulBuilder(builder: (context, setState) {
            rebuild = setState;
            return SizedBox(
              width: width,
              child: Row(children: [
                PeerSearchBar(),
                TextButton(
                  focusNode: other,
                  onPressed: () {},
                  child: const Text('Other'),
                ),
              ]),
            );
          }),
        ),
      );

  Future<void> show(WidgetTester tester) async {
    addTearDown(other.dispose);
    await tester.pumpWidget(app());
    await tester.tap(find.byIcon(Icons.search_rounded));
    await tester.pumpAndSettle();
  }

  Future<void> resize(WidgetTester tester) async {
    rebuild(() => width += 20);
    await tester.pumpAndSettle();
  }
}

FocusNode _fieldFocus(WidgetTester tester) =>
    tester.widget<EditableText>(find.byType(EditableText)).focusNode;

class _LayoutHarness {
  late StateSetter rebuild;
  bool visible = true;

  Future<void> mount(WidgetTester tester) async {
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: StatefulBuilder(builder: (context, setState) {
        rebuild = setState;
        return Row(children: [
          if (visible) const PeerViewDropdown(),
          TextButton(onPressed: () => showDialog<void>(
            context: context,
            builder: (_) => const AlertDialog(content: Text('Other dialog')),
          ), child: const Text('Open other dialog')),
        ]);
      })),
    ));
    addTearDown(() async {
      await tester.pump(const Duration(seconds: 4));
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  Future<void> open(WidgetTester tester) async {
    await tester.tap(find.byTooltip('Change view'));
    await pump(tester);
  }

  Future<void> choose(WidgetTester tester, [String choice = 'Small tiles']) async {
    if (find.byTooltip(choice).evaluate().isEmpty) await open(tester);
    if (find.byTooltip(choice).evaluate().isNotEmpty) {
      await tester.tap(find.byTooltip(choice));
    }
    await pump(tester);
  }

  Future<void> pump(WidgetTester tester) async {
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pump();
  }

  Future<void> dismiss(WidgetTester tester) async {
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await pump(tester);
  }
}

void main() {
  late _Binding binding;
  setUp(() {
    binding = _Binding();
    installPeerSearchProbeBinding(binding);
    peerCardUiType.value = PeerUiType.grid;
    peerSearchTextController.clear();
    peerSearchText.value = '';
    stateGlobal.isPortrait.value = false;
  });


  testWidgets('bulk favorite pending save admits once and retires its selection',
      (tester) async {
    final harness = _BulkFavoriteHarness(binding);
    try {
      await harness.mount(tester);
      final original = harness.owner.peerTabModel.captureSelection();
      final callback = harness.action(tester);
      final pending = harness.submit(callback);
      await tester.pump();
      harness.rebuild(() {});
      await tester.pump();
      final duplicate = harness.submit(callback);
      await tester.pump();
      expect(binding.favoriteCalls, hasLength(1));
      expect(binding.favoriteCalls.single.ids, ['192.0.2.10']);
      expect(binding.favoriteCalls.single.favorite, isTrue);
      expect(original.isCurrent, isTrue);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(tester.widget<InkWell>(find.descendant(
          of: find.byTooltip('Add to Favorites'),
          matching: find.byType(InkWell))).onTap, isNull);
      binding.favoriteCalls.single.result.complete();
      await Future.wait([pending, duplicate]);
      await tester.pump();
      expect(harness.owner.peerTabModel.multiSelectionMode, isFalse);
      expect(harness.owner.peerTabModel.selectedPeers, isEmpty);
      expect(find.text('Successful'), findsOneWidget);
    } finally {
      await harness.drain(tester);
    }
  });

  for (final replacement in ['new-selection', 'tab-round-trip']) {
    testWidgets('bulk favorite $replacement completion preserves replacement',
        (tester) async {
      final harness = _BulkFavoriteHarness(binding);
      try {
        await harness.mount(tester);
        final pending = harness.submit(harness.action(tester));
        if (replacement == 'tab-round-trip') {
          harness.owner.peerTabModel.setCurrentTab(PeerTabIndex.fav.index);
          harness.owner.peerTabModel.setCurrentTab(PeerTabIndex.recent.index);
        }
        harness.select('192.0.2.20');
        await tester.pump();
        binding.favoriteCalls.single.result.complete();
        await pending;
        await tester.pump();
        expect(binding.favoriteCalls.single.ids, ['192.0.2.10']);
        expect(harness.owner.peerTabModel.selectedPeers.map((peer) => peer.id),
            ['192.0.2.20']);
        expect(harness.owner.peerTabModel.multiSelectionMode, isTrue);
        expect(find.text('Successful'), findsNothing);
        final next = harness.submit(harness.action(tester));
        expect(binding.favoriteCalls, hasLength(2));
        expect(binding.favoriteCalls.last.ids, ['192.0.2.20']);
        binding.favoriteCalls.last.result.complete();
        await next;
        await tester.pump();
        expect(harness.owner.peerTabModel.selectedPeers, isEmpty);
      } finally {
        await harness.drain(tester);
      }
    });
  }

  for (final failure in ['sync', 'async']) {
    testWidgets('bulk favorite $failure failure preserves selection and retries',
        (tester) async {
      final harness = _BulkFavoriteHarness(binding);
      try {
        await harness.mount(tester);
        binding.failFavoriteSynchronously = failure == 'sync';
        final failed = harness.submit(harness.action(tester));
        if (failure == 'async') {
          binding.favoriteCalls.single.result.completeError(StateError('save refused'));
        }
        await failed;
        await tester.pump();
        expect(harness.owner.peerTabModel.selectedPeers.single.id, '192.0.2.10');
        expect(harness.owner.peerTabModel.multiSelectionMode, isTrue);
        expect(find.text('Failed'), findsOneWidget);
        expect(find.byType(CircularProgressIndicator), findsNothing);
        await tester.pump(const Duration(seconds: 4));
        binding.failFavoriteSynchronously = false;
        final retried = harness.submit(harness.action(tester));
        expect(binding.favoriteCalls.last.ids, ['192.0.2.10']);
        binding.favoriteCalls.last.result.complete();
        await retried;
        await tester.pump();
        expect(harness.owner.peerTabModel.selectedPeers, isEmpty);
        expect(find.text('Successful'), findsOneWidget);
      } finally {
        await harness.drain(tester);
      }
    });
  }

  for (final retirement in ['page', 'selection']) {
    testWidgets('bulk favorite $retirement-retired callback refuses dispatch',
        (tester) async {
      final harness = _BulkFavoriteHarness(binding);
      try {
        await harness.mount(tester);
        final callback = harness.action(tester);
        if (retirement == 'page') {
          harness.rebuild(() => harness.visible = false);
        } else {
          harness.select('192.0.2.20');
        }
        await tester.pump();
        final late = harness.submit(callback);
        await tester.pump();
        expect(binding.favoriteCalls, isEmpty);
        await late;
      } finally {
        await harness.drain(tester);
      }
    });
  }

  for (final outcome in ['success', 'failure']) {
    testWidgets('bulk favorite $outcome after page retirement has no feedback',
        (tester) async {
      final harness = _BulkFavoriteHarness(binding);
      try {
        await harness.mount(tester);
        final pending = harness.submit(harness.action(tester));
        harness.rebuild(() => harness.visible = false);
        await tester.pump();
        harness.select('192.0.2.20');
        final call = binding.favoriteCalls.single;
        if (outcome == 'success') {
          call.result.complete();
        } else {
          call.result.completeError(StateError('late save refusal'));
        }
        await pending;
        await tester.pump();
        expect(call.ids, ['192.0.2.10']);
        expect(harness.owner.peerTabModel.selectedPeers.single.id, '192.0.2.20');
        expect(find.text('Replacement page'), findsOneWidget);
        expect(find.text('Successful'), findsNothing);
        expect(find.text('Failed'), findsNothing);
        expect(tester.takeException(), isNull);
      } finally {
        await harness.drain(tester);
      }
    });
  }

  for (final tab in PeerTabIndex.values) {
    testWidgets('peer ${tab.name} initial filtering renders without a waiting frame',
        (tester) async {
      peerSearchText.value = '  OFFICE  ';
      await _withPeers(tester, tab, (owner, activated) async {
        expect(find.text('192.0.2.10'), findsOneWidget);
        expect(find.text('192.0.2.20'), findsNothing);
        expect(find.byType(CircularProgressIndicator), findsNothing);
      });
    });

    testWidgets('peer ${tab.name} query changes retire old row actions in one frame',
        (tester) async {
      await _withPeers(tester, tab, (owner, activated) async {
        await tester.pumpAndSettle();
        peerSearchText.value = 'travel';
        await tester.pump();
        expect(find.text('192.0.2.10'), findsNothing);
        expect(find.text('192.0.2.20'), findsNothing);
        await tester.tap(find.text('192.0.2.30'));
        expect(activated, ['192.0.2.30']);
        peerSearchText.value = 'missing';
        await tester.pump();
        expect(find.byType(TextButton), findsNothing);
        peerSearchText.value = '';
        await tester.pump();
        expect(find.byType(TextButton), findsNWidgets(3));
      });
    });

    testWidgets('peer ${tab.name} list updates retire replaced row actions in one frame',
        (tester) async {
      peerSearchText.value = 'office';
      await _withPeers(tester, tab, (owner, activated) async {
        await tester.pumpAndSettle();
        owner.peers(tab).updatePeers({
          'peers': '[{"id":"192.0.2.99","hostname":"Office"}]',
        });
        await tester.pump();
        expect(find.text('192.0.2.10'), findsNothing);
        await tester.tap(find.text('192.0.2.99'));
        expect(activated, ['192.0.2.99']);
      });
    });

    testWidgets('peer ${tab.name} search matches all local fields and clears',
        (tester) async {
      await _withPeers(tester, tab, (owner, activated) async {
        await tester.pumpAndSettle();
        for (final query in ['2.10', ' office ', 'ALICE', 'TrAvEl', '[.*]', ' ']) {
          peerSearchText.value = query;
          await tester.pumpAndSettle();
          final expected = query == '2.10' || query == ' office '
              ? ['192.0.2.10']
              : query == 'ALICE' ? ['192.0.2.20']
              : query == 'TrAvEl' ? ['192.0.2.30']
              : query == '[.*]' ? <String>[]
              : _searchPeers.map((peer) => peer.id).toList();
          expect(tester.widgetList<Text>(find.descendant(
            of: find.byType(TextButton), matching: find.byType(Text)))
              .map((text) => text.data).toList(), expected);
          await tester.pump(const Duration(milliseconds: 1));
          expect(owner.peerTabModel.currentTabCachedPeers.map((peer) => peer.id),
              expected);
        }
      });
    });
  }

  testWidgets('peer layout selection owns one save through rebuild', (tester) async {
    final pending = Completer<String>();
    binding.save = (_) => pending.future;
    final harness = _LayoutHarness();
    await harness.mount(tester);
    await harness.choose(tester);
    final menuClosed = find.byTooltip('Small tiles').evaluate().isEmpty;
    final before = peerCardUiType.value;
    harness.rebuild(() {});
    await harness.pump(tester);
    await harness.choose(tester, 'List');
    final pendingWrites = binding.writes.toList();
    pending.complete('1');
    await harness.pump(tester);
    expect(menuClosed, isTrue);
    expect(before, PeerUiType.grid);
    expect(pendingWrites, ['1']);
    expect(peerCardUiType.value, PeerUiType.tile);
    expect(tester.takeException(), isNull);
  });

  testWidgets('peer layout save cannot close a later dialog', (tester) async {
    final pending = Completer<String>();
    binding.save = (_) => pending.future;
    final harness = _LayoutHarness();
    await harness.mount(tester);
    await harness.choose(tester);
    await harness.dismiss(tester);
    await tester.tap(find.text('Open other dialog'));
    await harness.pump(tester);
    expect(find.text('Other dialog'), findsOneWidget);
    pending.complete('1');
    await harness.pump(tester);
    await tester.pumpAndSettle();
    expect(find.text('Other dialog').hitTestable(), findsOneWidget);
    expect(globalKey.currentState!.canPop(), isTrue);
    expect(peerCardUiType.value, PeerUiType.tile);
    expect(binding.writes, ['1']);
  });

  testWidgets('peer layout retired menu cannot start a save', (tester) async {
    final harness = _LayoutHarness();
    await harness.mount(tester);
    await harness.open(tester);
    harness.rebuild(() => harness.visible = false);
    await harness.pump(tester);
    await harness.choose(tester);
    expect(binding.writes, isEmpty);
    expect(peerCardUiType.value, PeerUiType.grid);
    expect(tester.takeException(), isNull);
  });

  testWidgets('peer layout retired save drains without late error feedback',
      (tester) async {
    final pending = Completer<String>();
    binding.save = (_) => pending.future;
    final harness = _LayoutHarness();
    await harness.mount(tester);
    await harness.choose(tester);
    await harness.dismiss(tester);
    harness.rebuild(() => harness.visible = false);
    await harness.pump(tester);
    pending.completeError(StateError('save refused after close'));
    await harness.pump(tester);
    expect(binding.writes, ['1']);
    expect(binding.reads, isEmpty);
    expect(peerCardUiType.value, PeerUiType.grid);
    expect(find.text('Failed'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  for (final failure in ['write', 'readback', 'invalid', 'mismatch']) {
    testWidgets('peer layout $failure failure reports and permits retry',
        (tester) async {
      binding.save = (value) async {
        if (failure == 'write') throw StateError('save refused');
        if (failure == 'readback') binding.readError = StateError('read refused');
        return failure == 'invalid' ? 'broken' : failure == 'mismatch' ? '2' : value;
      };
      final harness = _LayoutHarness();
      await harness.mount(tester);
      await harness.choose(tester);
      expect(find.text('Failed'), findsOneWidget);
      expect(peerCardUiType.value,
          failure == 'mismatch' ? PeerUiType.list : PeerUiType.grid);
      await tester.pump(const Duration(seconds: 4));
      binding.readError = null;
      binding.save = null;
      await harness.choose(tester);
      expect(binding.writes, ['1', '1']);
      expect(binding.layout, '1');
      expect(peerCardUiType.value, PeerUiType.tile);
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('peer layout cancellation and newly fixed policy refuse writes',
      (tester) async {
    final harness = _LayoutHarness();
    await harness.mount(tester);
    await harness.open(tester);
    await harness.dismiss(tester);
    expect(binding.writes, isEmpty);
    await harness.open(tester);
    binding.fixed = true;
    await harness.choose(tester);
    expect(binding.writes, isEmpty);
    expect(peerCardUiType.value, PeerUiType.grid);
  });

  testWidgets('peer layout loads all supported saved choices', (tester) async {
    for (final entry in {
      '0': PeerUiType.grid,
      '1': PeerUiType.tile,
      '2': PeerUiType.list,
      '+1': PeerUiType.tile,
      '01': PeerUiType.tile,
      ' 2 ': PeerUiType.list,
      '0x2': PeerUiType.list,
    }.entries) {
      binding.layout = entry.key;
      binding.reads.clear();
      const PeerTabPage().createState();
      expect(peerCardUiType.value, entry.value, reason: entry.key);
      expect(binding.reads, [kOptionPeerCardUiType]);
      expect(binding.layout, entry.key);
    }
  });

  testWidgets('peer layout rejects invalid saved choices without throwing',
      (tester) async {
    final outcomes = <String, String>{};
    for (final value in [
      '', ' ', 'broken', '1.0', 'NaN', '-1', '3', '2147483647',
      '99999999999999999999999999999999999999',
    ]) {
      binding.layout = value;
      peerCardUiType.value = PeerUiType.list;
      try {
        const PeerTabPage().createState();
        outcomes[value] = peerCardUiType.value.name;
      } catch (error) {
        outcomes[value] = error.runtimeType.toString();
      }
      expect(binding.layout, value);
    }
    debugPrint('PEER_LAYOUT_INVALID=$outcomes');
    expect(outcomes.values, everyElement('grid'));
  });

  testWidgets('peer layout reload replaces a previous choice and recovers',
      (tester) async {
    final observed = <PeerUiType>[];
    for (final value in ['2', '', '1', '-1', '2']) {
      binding.layout = value;
      const PeerTabPage().createState();
      observed.add(peerCardUiType.value);
    }
    expect(observed, [PeerUiType.list, PeerUiType.grid, PeerUiType.tile,
      PeerUiType.grid, PeerUiType.list]);
  });

  testWidgets('peer layout preserves storage errors and current state',
      (tester) async {
    final failure = StateError('storage unavailable');
    binding.readError = failure;
    peerCardUiType.value = PeerUiType.tile;
    expect(() => const PeerTabPage().createState(), throwsA(same(failure)));
    expect(peerCardUiType.value, PeerUiType.tile);
    expect(binding.reads, [kOptionPeerCardUiType]);
  });

  testWidgets('peer search opens focused and publishes typed text', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    await tester.enterText(find.byType(TextField), 'office');
    expect(peerSearchText.value, 'office');
    expect(peerSearchTextController.text, 'office');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search keeps focus and caret through parent rebuilds', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    peerSearchTextController.selection = const TextSelection.collapsed(offset: 2);
    for (var i = 0; i < 3; i++) {
      await harness.resize(tester);
      expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
      expect(peerSearchTextController.selection,
          const TextSelection.collapsed(offset: 2));
      expect(peerSearchText.value, 'office');
    }
    tester.testTextInput.updateEditingValue(const TextEditingValue(
      text: 'ofXfice', selection: TextSelection.collapsed(offset: 3)));
    await tester.pump();
    expect(peerSearchText.value, 'ofXfice');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search does not change selection when focus leaves', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    peerSearchTextController.selection =
        const TextSelection(baseOffset: 1, extentOffset: 3);
    harness.other.requestFocus();
    await tester.pumpAndSettle();
    expect(harness.other.hasPrimaryFocus, isTrue);
    expect(peerSearchTextController.selection,
        const TextSelection(baseOffset: 1, extentOffset: 3));
    await harness.resize(tester);
    expect(harness.other.hasPrimaryFocus, isTrue);
    expect(peerSearchText.value, 'office');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search selects the query when focus returns', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    harness.other.requestFocus();
    await tester.pumpAndSettle();
    _fieldFocus(tester).requestFocus();
    await tester.pumpAndSettle();
    expect(peerSearchTextController.selection,
        const TextSelection(baseOffset: 0, extentOffset: 6));
    expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search close clears the query and reopening accepts input', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    for (var i = 0; i < 3; i++) {
      await tester.enterText(find.byType(TextField), 'query$i');
      expect(peerSearchText.value, 'query$i');
      await tester.tap(find.byIcon(Icons.close));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNothing);
      expect(peerSearchText.value, isEmpty);
      expect(peerSearchTextController.text, isEmpty);
      await tester.tap(find.byIcon(Icons.search_rounded));
      await tester.pumpAndSettle();
      expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    }
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search disposes its focus node when removed', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    final focus = _fieldFocus(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(focus.parent, isNull);
    expect(() => focus.addListener(() {}), throwsFlutterError);
    expect(tester.takeException(), isNull);
  });
}

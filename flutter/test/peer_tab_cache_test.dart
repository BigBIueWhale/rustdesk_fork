import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/peer_tab_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _UnusedOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('peer cache must not call its native owner');
}

Peer _peer(String id) => Peer.fromJson({'id': id});

PeerTabModel _model(FFI owner) =>
    PeerTabModel(WeakReference<FFI>(owner), readLocalOption: (_) => '');

void main() {
  testWidgets('peer cache publishes current rows and preserves select all',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    addTearDown(model.dispose);
    var notifications = 0;
    model.addListener(() => notifications++);
    final peer = _peer('192.0.2.1');

    model.setCurrentTabCachedPeers([peer]);
    expect(model.currentTabCachedPeers, isEmpty);
    await tester.pump(const Duration(milliseconds: 1));
    expect(model.currentTabCachedPeers, [peer]);
    expect(notifications, 1);

    model.setCurrentTab(model.currentTab);
    model.setMultiSelectionMode(true);
    model.selectAll();
    expect(model.captureSelection().ids, ['192.0.2.1']);
    expect(model.captureSelection().isCurrent, isTrue);

    final before = notifications;
    model.setCurrentTabCachedPeers([peer, _peer('192.0.2.2')]);
    await tester.pump(const Duration(milliseconds: 1));
    expect(notifications, before);
    expect(model.currentTabCachedPeers, hasLength(2));
  });

  testWidgets(
      'peer cache owns its submitted list and refuses external mutation',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    addTearDown(model.dispose);
    final peer = _peer('192.0.2.1');
    final input = [peer];
    model.setCurrentTabCachedPeers(input);
    input.clear();
    await tester.pump(const Duration(milliseconds: 1));
    expect(model.currentTabCachedPeers, [peer]);
    expect(() => model.currentTabCachedPeers.clear(), throwsUnsupportedError);
    expect(() => model.currentTabCachedPeers[0] = _peer('192.0.2.9'),
        throwsUnsupportedError);
    expect(model.currentTabCachedPeers, [peer]);
  });

  testWidgets('peer cache clears immediately when the current tab changes',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    addTearDown(model.dispose);
    model.setCurrentTabCachedPeers([_peer('192.0.2.1')]);
    await tester.pump(const Duration(milliseconds: 1));
    model.setCurrentTab(PeerTabIndex.fav.index);
    expect(model.currentTabCachedPeers, isEmpty);
    model.setMultiSelectionMode(true);
    model.selectAll();
    expect(model.selectedPeers, isEmpty);

    final favorite = _peer('192.0.2.2');
    model.setCurrentTabCachedPeers([favorite]);
    await tester.pump(const Duration(milliseconds: 1));
    model.selectAll();
    expect(model.selectedPeers, [favorite]);
  });

  testWidgets('peer cache retires queued rows across a tab round trip',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    addTearDown(model.dispose);
    model.setCurrentTabCachedPeers([_peer('192.0.2.1')]);
    model.setCurrentTab(PeerTabIndex.fav.index);
    model.setCurrentTab(PeerTabIndex.recent.index);
    await tester.pump(const Duration(milliseconds: 1));
    expect(model.currentTabCachedPeers, isEmpty);

    final current = _peer('192.0.2.3');
    model.setCurrentTabCachedPeers([current]);
    model.setCurrentTab(PeerTabIndex.recent.index);
    await tester.pump(const Duration(milliseconds: 1));
    expect(model.currentTabCachedPeers, [current]);
  });

  testWidgets('peer cache coalesces pending updates to the latest list',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    addTearDown(model.dispose);
    final publications = <List<String>>[];
    model.addListener(() => publications
        .add(model.currentTabCachedPeers.map((peer) => peer.id).toList()));
    model.setCurrentTabCachedPeers([_peer('192.0.2.1')]);
    model.setCurrentTabCachedPeers([]);
    model.setCurrentTabCachedPeers([_peer('192.0.2.2')]);
    await tester.pump(const Duration(milliseconds: 1));
    expect(publications, [
      ['192.0.2.2']
    ]);
  });

  testWidgets(
      'peer cache disposal cancels pending and refuses later publication',
      (tester) async {
    final owner = _UnusedOwner();
    final model = _model(owner);
    model.setCurrentTabCachedPeers([_peer('192.0.2.1')]);
    model.dispose();
    await tester.pump(const Duration(milliseconds: 1));
    expect(tester.takeException(), isNull);
    expect(model.currentTabCachedPeers, isEmpty);
    model.setCurrentTabCachedPeers([_peer('192.0.2.2')]);
    await tester.pump(const Duration(milliseconds: 1));
    expect(tester.takeException(), isNull);
    expect(model.currentTabCachedPeers, isEmpty);
  });
}

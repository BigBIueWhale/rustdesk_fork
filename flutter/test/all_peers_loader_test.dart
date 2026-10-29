import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/common/widgets/autocomplete.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _LoaderHarness {
  final source = Peers(name: 'loader-test', loadEvent: 'loader-test-event');
  final requests = <Completer<void>>[];
  late final loader = AllPeersLoader(recentPeers: source, requestLoad: () {
    final reply = Completer<void>();
    requests.add(reply);
    // Keep a failed request observed even when the old loader ignores it.
    unawaited(reply.future.then<void>((_) {}, onError: (Object _) {}));
    return reply.future;
  });
  var publications = 0;

  _LoaderHarness() {
    loader.init((update) {
      publications++;
      update();
    });
    addTearDown(() {
      loader.clear();
      source.dispose();
      for (final request in requests) {
        if (!request.isCompleted) request.complete();
      }
    });
  }

  void publish(List<Map<String, String>> peers, {String? ids}) {
    source.updatePeers({'peers': jsonEncode(peers), if (ids != null) 'ids': ids});
  }
}

void main() {
  test('peer loader ignores refused snapshots before and after valid data',
      () async {
    final h = _LoaderHarness();
    final request = h.loader.getAllPeers();
    h.requests.single.complete();
    await request;
    final pendingPublications = h.publications;
    h.source.updatePeers({'peers': '[invalid'});
    expect(h.loader.isPeersLoaded, isFalse);
    expect(h.loader.isPeersLoading, isTrue);
    expect(h.publications, pendingPublications);
    h.publish([
      {'id': '192.0.2.1', 'alias': 'Current'}
    ], ids: '192.0.2.2, 192.0.2.3');
    expect(h.loader.peers.map((peer) => peer.id),
        ['192.0.2.1', '192.0.2.2', '192.0.2.3']);
    expect(h.loader.isPeersLoaded, isTrue);
    expect(h.loader.isPeersLoading, isFalse);
    final current = h.loader.peers;
    final publications = h.publications;
    h.source.updatePeers({'peers': '[]', 'ids': 7});
    expect(h.loader.peers, same(current));
    expect(h.publications, publications);
    h.publish([]);
    expect(h.loader.peers, isEmpty);
    expect(h.loader.isPeersLoaded, isTrue);
    expect(h.publications, publications + 1);
  });

  test('peer loader waits for data beyond the request receipt', () async {
    final h = _LoaderHarness();
    final request = h.loader.getAllPeers();
    expect(h.requests, hasLength(1));
    h.requests.single.complete();
    await request;
    expect(h.loader.isPeersLoaded, isFalse);
    expect(h.loader.isPeersLoading, isTrue);
    expect(h.loader.peers, isEmpty);
    h.publish([{'id': '192.0.2.1', 'alias': 'Current'}]);
    expect(h.loader.isPeersLoaded, isTrue);
    expect(h.loader.isPeersLoading, isFalse);
    expect(h.loader.peers.single.alias, 'Current');
  });

  test('peer loader accepts an empty published result', () async {
    final h = _LoaderHarness();
    final request = h.loader.getAllPeers();
    h.publish([]);
    h.requests.single.complete();
    await request;
    expect(h.loader.isPeersLoaded, isTrue);
    expect(h.loader.isPeersLoading, isFalse);
    expect(h.loader.needLoad, isFalse);
    expect(h.loader.peers, isEmpty);
  });

  test('peer loader retains cached metadata and unique remaining addresses',
      () async {
    final h = _LoaderHarness();
    h.source.peers = [
      Peer.fromJson({'id': '192.0.2.1', 'alias': 'First'}),
      Peer.fromJson({'id': '192.0.2.1', 'alias': 'Duplicate'})
    ];
    h.source.restPeerIds = ['192.0.2.1', '192.0.2.2', '192.0.2.2'];
    await h.loader.getAllPeers();
    expect(h.requests, isEmpty);
    expect(h.loader.peers.map((peer) => peer.id), ['192.0.2.1', '192.0.2.2']);
    expect(h.loader.peers.first, same(h.source.peers.first));
    expect(h.loader.isPeersLoaded, isTrue);
  });

  test('peer loader does not dispatch overlapping requests', () async {
    final h = _LoaderHarness();
    final first = h.loader.getAllPeers();
    final second = h.loader.getAllPeers();
    expect(h.requests, hasLength(1));
    h.publish([{'id': '192.0.2.1'}]);
    h.requests.single.complete();
    await Future.wait([first, second]);
    await h.loader.getAllPeers();
    expect(h.requests, hasLength(1));
    h.publish([{'id': '192.0.2.2'}]);
    expect(h.loader.peers.single.id, '192.0.2.2');
  });

  test('peer loader request failure remains retryable and not loaded', () async {
    final h = _LoaderHarness();
    final failure = StateError('request failed');
    final request = h.loader.getAllPeers();
    final failed = expectLater(request, throwsA(same(failure)));
    h.requests.single.completeError(failure);
    await failed;
    expect(h.loader.isPeersLoading, isFalse);
    expect(h.loader.isPeersLoaded, isFalse);
    expect(h.loader.needLoad, isTrue);
    final retry = h.loader.getAllPeers();
    expect(h.requests, hasLength(2));
    h.publish([{'id': '192.0.2.3'}]);
    h.requests.last.complete();
    await retry;
    expect(h.loader.peers.single.id, '192.0.2.3');
  });

  test('peer loader clear refuses later loading and model publication', () async {
    final h = _LoaderHarness();
    h.loader.clear();
    await h.loader.getAllPeers();
    h.publish([{'id': '192.0.2.9'}]);
    expect(h.requests, isEmpty);
    expect(h.publications, 0);
    expect(h.loader.peers, isEmpty);
    expect(h.loader.needLoad, isFalse);
  });

  test('peer loader clear retires a pending request and its failure', () async {
    final h = _LoaderHarness();
    final request = h.loader.getAllPeers();
    final failure = StateError('late failure');
    final failed = expectLater(request, throwsA(same(failure)));
    h.loader.clear();
    final publications = h.publications;
    h.publish([{'id': '192.0.2.9'}]);
    h.requests.single.completeError(failure);
    await failed;
    expect(h.publications, publications);
    expect(h.loader.peers, isEmpty);
    expect(h.loader.isPeersLoading, isFalse);
    expect(h.loader.needLoad, isFalse);
  });
}

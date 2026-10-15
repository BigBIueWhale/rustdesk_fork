import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Peers peers;
  late DebugPrintCallback previousDebugPrint;
  final diagnostics = <String?>[];
  var notifications = 0;

  setUp(() {
    peers = Peers(
      name: 'peer-decode-test',
      getInitPeers: null,
      loadEvent: 'test-peer-decode',
    );
    diagnostics.clear();
    notifications = 0;
    peers.addListener(() => notifications += 1);
    previousDebugPrint = debugPrint;
    debugPrint = (message, {wrapWidth}) => diagnostics.add(message);
  });

  tearDown(() {
    debugPrint = previousDebugPrint;
    peers.dispose();
  });

  test('peer decode redacts malformed JSON exception content', () {
    const secret = 'SyntheticPrivatePeerNote';
    const malformed = '[{"note":"$secret"';
    expect(
      () => jsonDecode(malformed),
      throwsA(isA<FormatException>().having(
        (error) => error.toString(),
        'rendered exception',
        contains(secret),
      )),
    );

    peers.updatePeers({'peers': malformed});

    expect(peers.peers, isEmpty);
    expect(notifications, 1);
    expect(diagnostics, ['peers(): invalid peer data']);
    expect(diagnostics.join(), isNot(contains(secret)));
  });

  test('peer decode redacts invalid shapes and field values', () {
    const secret = 'SyntheticPrivatePeerValue';
    final invalid = <Object>[
      {'note': secret},
      [secret],
      [
        {'id': '192.0.2.7:21118', 'username': [secret]}
      ],
      [
        {'id': '192.0.2.7:21118', 'tags': secret}
      ],
    ];
    for (final value in invalid) {
      peers.updatePeers({'peers': jsonEncode(value)});
      expect(peers.peers, isEmpty);
    }

    expect(notifications, invalid.length);
    expect(diagnostics,
        List.filled(invalid.length, 'peers(): invalid peer data'));
    expect(diagnostics.join(), isNot(contains(secret)));
  });

  test('peer decode preserves valid metadata and recovers after refusal', () {
    const metadata = {
      'id': '192.0.2.7:21118',
      'username': 'local-user',
      'hostname': 'local-host',
      'platform': 'Linux',
      'alias': 'Local peer',
      'tags': ['local'],
      'rdpPort': '3389',
      'rdpUsername': 'rdp-user',
      'loginName': 'login-user',
      'note': 'SyntheticPrivatePeerNote',
    };
    final valid = jsonEncode([metadata]);
    peers.updatePeers({'peers': valid, 'ids': 'next,other'});
    expect(peers.restPeerIds, ['next', 'other']);
    expect(diagnostics, isEmpty);

    peers.updatePeers({'peers': '[invalid'});
    expect(peers.peers, isEmpty);
    expect(peers.restPeerIds, isEmpty);

    peers.updatePeers({'peers': valid});
    final peer = peers.peers.single;
    expect(peer.id, metadata['id']);
    expect(peer.username, metadata['username']);
    expect(peer.hostname, metadata['hostname']);
    expect(peer.platform, metadata['platform']);
    expect(peer.alias, metadata['alias']);
    expect(peer.tags, metadata['tags']);
    expect(peer.rdpPort, metadata['rdpPort']);
    expect(peer.rdpUsername, metadata['rdpUsername']);
    expect(peer.loginName, metadata['loginName']);
    expect(peer.note, metadata['note']);
    expect(notifications, 3);
    expect(diagnostics, ['peers(): invalid peer data']);
  });

  test('peer decode accepts empty input without a diagnostic', () {
    peers.updatePeers({'peers': ''});
    expect(peers.peers, isEmpty);
    expect(peers.restPeerIds, isEmpty);
    expect(notifications, 1);
    expect(diagnostics, isEmpty);
  });
}

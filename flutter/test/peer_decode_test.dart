import 'dart:convert';

import 'package:dash_chat_2/dash_chat_2.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _UnusedChatOwner implements FFI {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Chat history must not access its session');
}

ChatModel _chatModel() {
  final model = ChatModel(WeakReference<FFI>(_UnusedChatOwner()));
  addTearDown(() {
    model.inputNode.dispose();
    model.dispose();
  });
  return model;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
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

  test('chat reset clears outgoing bodies and preserves incoming history', () {
    final model = _chatModel();
    final keys = [
      MessageKey('same-peer', 7),
      MessageKey('other-incoming-peer', 8),
      MessageKey('same-peer', ChatModel.clientModeID),
      MessageKey('other-outgoing-peer', ChatModel.clientModeID),
    ];
    final messages = <ChatMessage>[];
    for (final key in keys) {
      final message = ChatMessage(
        user: ChatUser(id: key.peerId, firstName: 'Retained name'),
        text: 'Prior session ${key.connId}',
        createdAt: DateTime.utc(2026),
      );
      messages.add(message);
      model.insertMessage(key, message);
    }
    final bodies = keys.map((key) => model.messages[key]!).toList();
    final lists = bodies.map((body) => body.chatMessages).toList();
    expect(model.currentKey, same(keys.first));

    model.resetClientMode();

    expect(model.messages.keys, orderedEquals(keys));
    expect(model.currentKey, same(keys.first));
    for (var i = 0; i < keys.length; i++) {
      expect(model.messages[keys[i]], same(bodies[i]));
      expect(bodies[i].chatMessages, same(lists[i]));
      expect(bodies[i].chatUser, same(messages[i].user));
      expect(bodies[i].chatUser.firstName, 'Retained name');
      if (!keys[i].isOut) {
        expect(lists[i], [messages[i]]);
      }
    }
    expect(lists[2], isEmpty);
    expect(lists[3], isEmpty);
  });

  test('chat reset supports empty repeated and reused session histories', () {
    final model = _chatModel();
    final invalidSelection = model.currentKey;
    model.resetClientMode();
    expect(model.messages, isEmpty);
    expect(model.currentKey, same(invalidSelection));

    final outgoing = MessageKey('same-peer', ChatModel.clientModeID);
    final incoming = MessageKey('same-peer', 7);
    final received = ChatMessage(
      user: ChatUser(id: 'same-peer'),
      text: 'Incoming retained across reconnect',
      createdAt: DateTime.utc(2026),
    );
    model.insertMessage(incoming, received);
    final incomingBody = model.messages[incoming]!;
    for (var cycle = 0; cycle < 3; cycle++) {
      final sent = ChatMessage(
        user: ChatUser(id: 'local'),
        text: 'Outgoing session $cycle',
        createdAt: DateTime.utc(2026),
      );
      model.insertMessage(outgoing, sent);
      expect(model.messages[outgoing]!.chatMessages, [sent]);
      model.resetClientMode();
      model.resetClientMode();
      expect(model.messages[outgoing]!.chatMessages, isEmpty);
      expect(model.messages[incoming], same(incomingBody));
      expect(incomingBody.chatMessages, [received]);
    }
    final reconnected = MessageKey('same-peer', 19);
    model.updateConnIdOfKey(reconnected);
    expect(model.messages[reconnected], same(incomingBody));
    expect(model.messages.keys.where((key) => !key.isOut).single,
        same(reconnected));
    model.resetClientMode();
    expect(incomingBody.chatMessages, [received]);
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
        {
          'id': '192.0.2.7:21118',
          'username': [secret]
        }
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
    expect(
        diagnostics, List.filled(invalid.length, 'peers(): invalid peer data'));
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

  test('cached peer decode refuses data without payload diagnostics', () {
    const secret = 'SyntheticPrivateCachedPeer';
    const malformed = '{"peerInfo":{"username":"$secret"';
    expect(
      () => jsonDecode(malformed),
      throwsA(isA<FormatException>().having(
        (error) => error.toString(),
        'rendered exception',
        contains(secret),
      )),
    );
    final invalid = [
      malformed,
      '[]',
      jsonEncode({
        'updatePrivacyMode': <String, dynamic>{},
        'peerInfo': {'username': secret},
        'permissions': {'keyboard': secret},
        'streamType': 'TCP',
      }),
    ];
    for (final input in invalid) {
      expect(CachedPeerData.fromString(input), isNull);
    }
    expect(diagnostics,
        List.filled(invalid.length, 'Failed to parse CachedPeerData'));
    expect(diagnostics.join(), isNot(contains(secret)));
  });

  test('cached peer decode preserves snapshots and recovers after refusal', () {
    final data = CachedPeerData()
      ..updatePrivacyMode = {'state': 'off'}
      ..peerInfo = {
        'username': 'SyntheticPrivateCachedPeer',
        'hostname': 'local-host',
        'displays': '[]',
      }
      ..permissions = {'keyboard': true, 'clipboard': false}
      ..streamType = 'TCP';
    final encoded = data.toString();
    final decoded = CachedPeerData.fromString(encoded);
    expect(decoded, isNotNull);
    expect(decoded!.updatePrivacyMode, data.updatePrivacyMode);
    expect(decoded.peerInfo, data.peerInfo);
    expect(decoded.permissions, data.permissions);
    expect(decoded.streamType, data.streamType);
    expect(jsonDecode(decoded.toString()), jsonDecode(encoded));
    expect(diagnostics, isEmpty);

    expect(CachedPeerData.fromString(''), isNull);
    expect(CachedPeerData.fromString(encoded)!.peerInfo, data.peerInfo);
    expect(diagnostics, ['Failed to parse CachedPeerData']);
  });

  test('platform metadata refuses input without payload diagnostics', () {
    const secret = 'SyntheticPrivatePlatform';
    const malformed = '{"private":"$secret"';
    expect(
      () => jsonDecode(malformed),
      throwsA(isA<FormatException>().having(
        (error) => error.toString(),
        'rendered exception',
        contains(secret),
      )),
    );
    final info = PeerInfo()..platformAdditions = {'previous': secret};
    final previous = info.platformAdditions;
    final invalid = [malformed, '[]', '1', 7, jsonEncode(secret)];
    for (final input in invalid) {
      info.setPlatformAdditions(input);
      expect(identical(info.platformAdditions, previous), isTrue);
    }
    expect(diagnostics,
        List.filled(invalid.length, 'Failed to decode platformAdditions'));
    expect(diagnostics.join(), isNot(contains(secret)));
  });

  test('platform metadata preserves snapshots and quiet empty input', () {
    final info = PeerInfo();
    final fields = {
      'private': 'SyntheticPrivatePlatform',
      'installed': true,
      'display': {'width': 1920, 'height': 1080},
    };
    info.setPlatformAdditions(jsonEncode(fields));
    expect(info.platformAdditions, fields);
    final previous = info.platformAdditions;
    info.setPlatformAdditions(null);
    info.setPlatformAdditions('');
    expect(identical(info.platformAdditions, previous), isTrue);
    expect(diagnostics, isEmpty);

    info.setPlatformAdditions('{');
    expect(identical(info.platformAdditions, previous), isTrue);
    diagnostics.clear();
    info.setPlatformAdditions('{"replacement":2}');
    expect(info.platformAdditions, {'replacement': 2});
    expect(diagnostics, isEmpty);
  });

  test('resolution metadata refuses partial and private input', () {
    const secret = 'SyntheticPrivateResolution';
    const malformed = '[{"private":"$secret"';
    expect(
      () => jsonDecode(malformed),
      throwsA(isA<FormatException>().having(
        (error) => error.toString(),
        'rendered exception',
        contains(secret),
      )),
    );
    final info = PeerInfo()..resolutions = [Resolution(640, 480)];
    final previous = info.resolutions;
    final invalid = [
      malformed,
      jsonEncode({'missing': secret}),
      jsonEncode([
        {'width': 1920, 'height': 1080},
        secret,
      ]),
      7,
    ];
    for (final input in invalid) {
      info.setResolutions(input);
      expect(identical(info.resolutions, previous), isTrue);
    }
    expect(diagnostics,
        List.filled(invalid.length, 'Failed to parse resolutions'));
    expect(diagnostics.join(), isNot(contains(secret)));
  });

  test('resolution metadata preserves both formats and recovery', () {
    final info = PeerInfo();
    final values = [
      {'width': 1024, 'height': 768},
      {'width': 0, 'height': 720},
      {'width': 1920, 'height': 1080},
      {'width': 1920, 'height': 1200},
      {'width': -1, 'height': 720},
      {'width': 'SyntheticPrivateResolution', 'height': 720},
    ];
    for (final input in [
      values,
      {'resolutions': values}
    ]) {
      info.setResolutions(jsonEncode(input));
      expect(
        info.resolutions.map((value) => [value.width, value.height]).toList(),
        [
          [1920, 1200],
          [1920, 1080],
          [1024, 768],
        ],
      );
    }
    expect(diagnostics, isEmpty);
    final previous = info.resolutions;
    info.setResolutions('{');
    expect(identical(info.resolutions, previous), isTrue);
    diagnostics.clear();
    info.setResolutions('[]');
    expect(info.resolutions, isEmpty);
    expect(diagnostics, isEmpty);
  });
}

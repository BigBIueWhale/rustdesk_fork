import 'dart:async';
import 'dart:convert';

import 'package:dash_chat_2/dash_chat_2.dart';
import 'package:desktop_multi_window/src/channels.dart' show miltiWindowChannel;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart' show desktopType, DesktopType;
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';

class _ChatPeer implements FfiModel {
  @override
  final pi = PeerInfo()..username = 'Outgoing peer';

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Unexpected peer access');
}

Client _incomingClient(int generation) => Client(
    7, true, false, false, 'Incoming peer', 'incoming-peer', true, true, true)
  ..registryGeneration = generation;

class _ChatServer implements ServerModel {
  @override
  final clients = [_incomingClient(19)];
  @override
  final tabController = DesktopTabController(tabType: DesktopTabType.cm);
  var jumps = 0;

  _ChatServer() {
    final tab = TabInfo(key: '7', label: 'Incoming', page: const SizedBox());
    tabController.state.value.tabs.add(tab);
  }

  @override
  void jumpTo(int id) => jumps += 1;

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Unexpected server access');
}

class _ChatOwner implements FFI {
  @override
  var id = 'outgoing-peer';
  @override
  var sessionId = Uuid().v4obj();
  @override
  var clientOwnerId = Uuid().v4obj();
  @override
  var closed = false;
  @override
  final ffiModel = _ChatPeer();
  @override
  final _ChatServer serverModel = _ChatServer();

  @override
  bool isCurrentSessionOwner(UuidValue session, UuidValue owner) =>
      !closed && sessionId == session && clientOwnerId == owner;

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Unexpected session access');
}

class _HeldChat extends ChatModel {
  _HeldChat(_ChatOwner owner) : super(WeakReference<FFI>(owner));

  Completer<void>? page;
  final shown = <MessageKey>[];

  @override
  Future<void> showChatPage(MessageKey key) {
    shown.add(key);
    return page?.future ?? Future<void>.value();
  }
}

class _ChatDelivery {
  final owner = _ChatOwner();
  late final model = _HeldChat(owner);
  final windowCalls = <String>[];
  var notifications = 0;

  _ChatDelivery() {
    model.addListener(() => notifications += 1);
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const windowChannel = MethodChannel('window_manager');
    messenger.setMockMethodCallHandler(windowChannel, (call) async {
      windowCalls.add(call.method);
      return call.method == 'isMinimized' ? false : null;
    });
    messenger.setMockMethodCallHandler(miltiWindowChannel, (call) async {
      windowCalls.add('multi.${call.method}');
      return call.method == 'isMinimized' ? false : null;
    });
    addTearDown(() async {
      await Future<void>.delayed(Duration.zero);
      messenger.setMockMethodCallHandler(windowChannel, null);
      messenger.setMockMethodCallHandler(miltiWindowChannel, null);
      model.inputNode.dispose();
      model.dispose();
      owner.serverModel.tabController.state.value.pageController.dispose();
    });
  }

  void expectRetired() {
    expect(model.messages, isEmpty);
    expect(model.currentKey.peerId, isEmpty);
    expect(model.latestReceivedKey, isNull);
    expect(notifications, 0);
    expect(owner.serverModel.jumps, 0);
  }
}

class _PanelChat extends ChatModel {
  _PanelChat(_ChatOwner owner) : super(WeakReference<FFI>(owner));

  var focusRequests = 0;

  @override
  void requestChatInputFocus() => focusRequests += 1;
}

class _ChatPanel {
  final owner = _ChatOwner();
  late final model = _PanelChat(owner);
  final calls = <MethodCall>[];
  var notifications = 0;
  String? failAt;
  String? holdAt;
  final started = Completer<void>();
  final released = Completer<void>();

  String stage(MethodCall call) => call.method == 'setBounds'
      ? (call.arguments.containsKey('width') ? 'resize' : 'position')
      : call.method;

  _ChatPanel() {
    model.addListener(() => notifications += 1);
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const window = MethodChannel('window_manager');
    const screen = MethodChannel('screen_retriever');
    messenger.setMockMethodCallHandler(window, (call) async {
      calls.add(call);
      final currentStage = stage(call);
      if (currentStage == failAt) {
        failAt = null;
        throw PlatformException(code: 'panel-window-fault');
      }
      if (currentStage == holdAt) {
        holdAt = null;
        started.complete();
        await released.future;
      }
      if (call.method == 'isMinimized') return false;
      if (call.method == 'show' || call.method == 'setBounds') return null;
      throw StateError('Unexpected panel window call: ${call.method}');
    });
    messenger.setMockMethodCallHandler(screen, (call) async {
      const display = {
        'id': 1,
        'size': {'width': 1920.0, 'height': 1080.0},
        'visiblePosition': {'x': 0.0, 'y': 0.0},
      };
      switch (call.method) {
        case 'getPrimaryDisplay':
          return display;
        case 'getAllDisplays':
          return {'displays': [display]};
        case 'getCursorScreenPoint':
          return {'x': 100.0, 'y': 100.0};
        default:
          throw StateError('Unexpected panel screen call: ${call.method}');
      }
    });
    addTearDown(() {
      if (!released.isCompleted) released.complete();
      messenger.setMockMethodCallHandler(window, null);
      messenger.setMockMethodCallHandler(screen, null);
      model.inputNode.dispose();
      model.dispose();
      owner.serverModel.tabController.state.value.pageController.dispose();
    });
  }

  void clearObservations() {
    calls.clear();
    notifications = 0;
    model.focusRequests = 0;
  }

  void expectLayout(bool open, {int start = 0}) {
    final completed = calls.skip(start).toList();
    expect(completed.map(stage), ['isMinimized', 'show', 'resize', 'position']);
    expect(completed[2].arguments['width'], open ? 700.0 : 300.0);
    expect(completed[2].arguments['height'], 490.0);
    expect(completed[3].arguments['x'], open ? 1220.0 : 1620.0);
    expect(completed[3].arguments['y'], 0.0);
  }
}

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

  test('chat panel completes repeated open and close transitions', () async {
    final panel = _ChatPanel();
    for (var cycle = 0; cycle < 3; cycle++) {
      for (final open in [true, false]) {
        panel.clearObservations();
        panel.owner.serverModel.clients.single.unreadChatMessageCount.value = 9;
        await panel.model.toggleCMSidePage();
        expect(panel.model.isShowCMSidePage, open);
        expect(panel.notifications, 1);
        expect(panel.model.focusRequests, open ? 1 : 0);
        expect(panel.owner.serverModel.clients.single.unreadChatMessageCount.value,
            open ? 0 : 9);
        panel.expectLayout(open);
      }
    }
  });

  for (final wasOpen in [false, true]) {
    final priorState = wasOpen ? 'open' : 'closed';
    for (final failure in ['show', 'resize', 'position']) {
      test('chat panel preserves $priorState state and retries $failure failure',
          () async {
        final panel = _ChatPanel();
        if (wasOpen) await panel.model.toggleCMSidePage();
        panel.clearObservations();
        final client = panel.owner.serverModel.clients.single;
        client.unreadChatMessageCount.value = 9;
        panel.failAt = failure;

        final errorMatcher = isA<PlatformException>().having(
            (error) => error.code, 'code', 'panel-window-fault');
        await expectLater(panel.model.toggleCMSidePage(), throwsA(errorMatcher));
        final stateAfterFailure = panel.model.isShowCMSidePage;
        final unreadAfterFailure = client.unreadChatMessageCount.value;
        final focusAfterFailure = panel.model.focusRequests;
        final notificationsAfterFailure = panel.notifications;
        final failedCalls = panel.calls.length;
        await panel.model.toggleCMSidePage();

        expect(stateAfterFailure, wasOpen);
        expect(unreadAfterFailure, 9);
        expect(focusAfterFailure, 0);
        expect(notificationsAfterFailure, 0);
        expect(panel.model.isShowCMSidePage, !wasOpen);
        expect(client.unreadChatMessageCount.value, wasOpen ? 9 : 0);
        expect(panel.model.focusRequests, wasOpen ? 0 : 1);
        expect(panel.notifications, 1);
        panel.expectLayout(!wasOpen, start: failedCalls);
      });
    }

    test('chat panel serializes $priorState transition until native completion',
        () async {
      final panel = _ChatPanel();
      if (wasOpen) await panel.model.toggleCMSidePage();
      panel.clearObservations();
      panel.owner.serverModel.clients.single.unreadChatMessageCount.value = 9;
      panel.holdAt = 'resize';
      final first = panel.model.toggleCMSidePage();
      await panel.started.future.timeout(const Duration(seconds: 2));
      final pendingState = panel.model.isShowCMSidePage;
      final pendingUnread =
          panel.owner.serverModel.clients.single.unreadChatMessageCount.value;
      final pendingNotifications = panel.notifications;
      final pendingFocus = panel.model.focusRequests;
      final pendingCalls = panel.calls.length;
      try {
        await panel.model.toggleCMSidePage();
        expect(panel.calls.length, pendingCalls);
      } finally {
        panel.released.complete();
        await first;
      }

      expect(pendingState, wasOpen);
      expect(pendingUnread, 9);
      expect(pendingNotifications, 0);
      expect(pendingFocus, 0);
      expect(panel.model.isShowCMSidePage, !wasOpen);
      expect(panel.notifications, 1);
      expect(panel.model.focusRequests, wasOpen ? 0 : 1);
      panel.expectLayout(!wasOpen);
    });
  }

  test('chat delivery keeps a live outgoing owner', () async {
    final delivery = _ChatDelivery();
    delivery.model.page = Completer<void>();
    final task = delivery.model.receive(ChatModel.clientModeID, 'Outgoing');
    expect(delivery.model.shown.single.peerId, delivery.owner.id);
    expect(delivery.model.messages, isEmpty);
    delivery.model.page!.complete();
    await task;

    final key = delivery.model.messages.keys.single;
    expect(key.isOut, isTrue);
    expect(key.peerId, delivery.owner.id);
    expect(delivery.model.messages[key]!.chatMessages.single.text, 'Outgoing');
    expect(delivery.model.messages[key]!.chatUser.firstName, 'Outgoing peer');
    expect(delivery.model.latestReceivedKey, key);
    expect(delivery.notifications, 1);
    expect(delivery.windowCalls, isEmpty);
  });

  for (final retirement in ['close', 'session', 'ui']) {
    test('chat delivery refuses outgoing $retirement after page wait',
        () async {
      final delivery = _ChatDelivery();
      delivery.model.page = Completer<void>();
      final task = delivery.model.receive(ChatModel.clientModeID, 'Retired');
      expect(delivery.model.shown, hasLength(1));
      if (retirement == 'close') {
        delivery.owner.closed = true;
      } else if (retirement == 'session') {
        delivery.owner.sessionId = Uuid().v4obj();
        delivery.owner.id = 'replacement-peer';
      } else {
        delivery.owner.clientOwnerId = Uuid().v4obj();
      }
      delivery.model.page!.complete();
      await task;

      delivery.expectRetired();
      expect(delivery.windowCalls, isEmpty);
    });
  }

  test('chat delivery refuses retired outgoing owner after window wait',
      () async {
    final delivery = _ChatDelivery();
    final tabs = DesktopTabController(tabType: DesktopTabType.remoteScreen);
    tabs.state.value.tabs.addAll([
      TabInfo(key: delivery.owner.id, label: 'Peer', page: const SizedBox()),
      TabInfo(key: 'selected', label: 'Other', page: const SizedBox()),
    ]);
    tabs.state.value.selected = 1;
    Get.put<DesktopTabController>(tabs);
    UnreadChatCountState.init(delivery.owner.id);
    addTearDown(() {
      UnreadChatCountState.delete(delivery.owner.id);
      Get.delete<DesktopTabController>();
      tabs.state.value.pageController.dispose();
    });
    final started = Completer<void>();
    final minimized = Completer<bool>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(miltiWindowChannel, (call) async {
      expect(call.method, 'isMinimized');
      started.complete();
      return minimized.future;
    });

    final task = delivery.model.receive(ChatModel.clientModeID, 'Retired');
    await started.future;
    delivery.owner.closed = true;
    minimized.complete(false);
    await task;

    delivery.expectRetired();
    expect(UnreadChatCountState.find(delivery.owner.id).value, 0);
    expect(delivery.windowCalls, isEmpty);
  });

  test('chat delivery keeps a live incoming generation', () async {
    final delivery = _ChatDelivery();
    delivery.model.page = Completer<void>();
    final task = delivery.model.receive(7, 'Incoming');
    expect(delivery.model.shown.single.peerId, 'incoming-peer');
    delivery.owner.sessionId = Uuid().v4obj();
    delivery.model.page!.complete();
    await task;
    await Future<void>.delayed(Duration.zero);

    final key = delivery.model.messages.keys.single;
    expect(key.isOut, isFalse);
    expect(key.peerId, 'incoming-peer');
    expect(delivery.model.messages[key]!.chatMessages.single.text, 'Incoming');
    expect(delivery.model.messages[key]!.chatUser.firstName, 'Incoming peer');
    expect(delivery.model.latestReceivedKey, key);
    expect(delivery.notifications, 1);
    expect(delivery.owner.serverModel.jumps, 1);
    expect(delivery.windowCalls, ['isMinimized', 'show', 'focus']);
  });

  test('chat delivery refuses replaced incoming generation after page wait',
      () async {
    final delivery = _ChatDelivery();
    delivery.model.page = Completer<void>();
    final task = delivery.model.receive(7, 'Retired');
    expect(delivery.model.shown, hasLength(1));
    delivery.owner.serverModel.clients[0] = _incomingClient(20);
    delivery.model.page!.complete();
    await task;
    await Future<void>.delayed(Duration.zero);

    delivery.expectRetired();
    expect(delivery.windowCalls, isEmpty);
  });

  test('chat delivery refuses replaced incoming generation after CM wait',
      () async {
    final delivery = _ChatDelivery();
    final previousType = desktopType;
    desktopType = DesktopType.cm;
    addTearDown(() => desktopType = previousType);
    final task = delivery.model.receive(7, 'Retired');
    expect(delivery.model.shown, isEmpty);
    delivery.owner.serverModel.clients[0] = _incomingClient(20);
    await task;
    await Future<void>.delayed(Duration.zero);

    delivery.expectRetired();
    expect(delivery.model.shown, isEmpty);
    expect(delivery.windowCalls, isEmpty);
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

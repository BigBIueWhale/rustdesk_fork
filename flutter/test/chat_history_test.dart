import 'package:dash_chat_2/dash_chat_2.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _HistoryServer implements ServerModel {
  @override
  final clients = <Client>[];

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Unexpected history server access');
}

class _HistoryOwner implements FFI {
  @override
  final serverModel = _HistoryServer();

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('Unexpected history session access');
}

ChatModel _historyModel() {
  final model = ChatModel(WeakReference<FFI>(_HistoryOwner()));
  addTearDown(() {
    model.inputNode.dispose();
    model.dispose();
  });
  return model;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('chat history retains the newest 256 messages', () {
    final model = _historyModel();
    final key = MessageKey('peer', 7);
    for (var i = 0; i < 300; i++) {
      model.insertMessage(key, ChatMessage(user: ChatUser(id: 'peer'),
          text: 'message $i', createdAt: DateTime.utc(2026)));
    }
    final messages = model.messages[key]!.chatMessages;
    expect(messages.length, 256);
    expect(messages.first.text, 'message 299');
    expect(messages.last.text, 'message 44');
  });

  test('chat history bounds retained text independently of message count', () {
    final model = _historyModel();
    final key = MessageKey('peer', 7);
    for (var i = 0; i < 128; i++) {
      model.insertMessage(key, ChatMessage(user: ChatUser(id: 'peer'),
          text: '${i.toString().padLeft(4, '0')}${'x' * 4092}',
          createdAt: DateTime.utc(2026)));
    }
    final messages = model.messages[key]!.chatMessages;
    expect(messages.length, 64);
    expect(messages.fold<int>(0, (sum, m) => sum + m.text.length), 256 * 1024);
    expect(messages.first.text.startsWith('0127'), isTrue);
    expect(messages.last.text.startsWith('0064'), isTrue);
  });

  test('chat oversized history copy preserves submitted text and Unicode', () {
    final model = _historyModel();
    final key = MessageKey('peer', 7);
    final text = '${'x' * (256 * 1024 - 2)}\u{1f642}ending';
    final message = ChatMessage(user: ChatUser(id: 'local'), text: text,
        createdAt: DateTime.utc(2026));
    model.insertMessage(key, message);
    final stored = model.messages[key]!.chatMessages.single;
    expect(stored.text.length, lessThanOrEqualTo(256 * 1024));
    expect(stored.text.endsWith('…'), isTrue);
    expect(stored.text.runes.any((r) => r >= 0xd800 && r <= 0xdfff), isFalse);
    expect(message.text, text);
    expect(stored.user, same(message.user));
    expect(stored.createdAt, message.createdAt);
  });

  test('chat conversation retention protects selection and newest histories', () {
    final model = _historyModel();
    for (var i = 0; i < 80; i++) {
      final key = MessageKey('peer-$i', i + 1);
      model.insertMessage(key, ChatMessage(user: ChatUser(id: key.peerId),
          text: 'message $i', createdAt: DateTime.utc(2026)));
    }
    expect(model.messages.length, 64);
    expect(model.currentKey.peerId, 'peer-0');
    expect(model.messages[model.currentKey]!.chatMessages.single.text, 'message 0');
    expect(model.messages.keys.map((k) => k.peerId),
        ['peer-0', for (var i = 17; i < 80; i++) 'peer-$i']);
  });

  test('chat recently updated history survives conversation eviction', () {
    final model = _historyModel();
    for (var i = 0; i < 64; i++) {
      final key = MessageKey('peer-$i', i + 1);
      model.insertMessage(key, ChatMessage(user: ChatUser(id: key.peerId),
          text: 'message $i', createdAt: DateTime.utc(2026)));
    }
    final refreshed = MessageKey('peer-1', 100);
    model.insertMessage(refreshed, ChatMessage(user: ChatUser(id: 'peer-1'),
        text: 'new message', createdAt: DateTime.utc(2026)));
    model.insertMessage(MessageKey('peer-new', 101), ChatMessage(
        user: ChatUser(id: 'peer-new'), text: 'new peer',
        createdAt: DateTime.utc(2026)));
    expect(model.messages.length, 64);
    expect(model.messages[refreshed]!.chatMessages.map((m) => m.text),
        ['new message', 'message 1']);
    expect(model.messages.containsKey(MessageKey('peer-2', 3)), isFalse);
  });

  test('chat empty selected conversations share the retention ceiling', () {
    final model = _historyModel();
    for (var i = 0; i < 80; i++) {
      model.changeCurrentKey(MessageKey('peer-$i', i + 1));
    }
    expect(model.messages.length, 64);
    expect(model.currentKey.peerId, 'peer-79');
    expect(model.messages[model.currentKey]!.chatMessages,
        isEmpty);
    expect(model.messages.containsKey(MessageKey('peer-0', 1)), isFalse);
  });

  test('chat retained collection views cannot bypass admission', () {
    final model = _historyModel();
    final key = MessageKey('peer', 7);
    final message = ChatMessage(user: ChatUser(id: 'peer'), text: 'retained',
        createdAt: DateTime.utc(2026));
    model.insertMessage(key, message);
    expect(() => model.messages.clear(), throwsUnsupportedError);
    expect(() => model.messages[key]!.chatMessages.add(message),
        throwsUnsupportedError);
    expect(model.messages[key]!.chatMessages.single.text, 'retained');
  });

  test('chat clearing history releases its text capacity for reuse', () {
    final model = _historyModel();
    final key = MessageKey('peer', ChatModel.clientModeID);
    model.insertMessage(key, ChatMessage(user: ChatUser(id: 'peer'),
        text: 'x' * (256 * 1024), createdAt: DateTime.utc(2026)));
    model.resetClientMode();
    final body = model.messages[key]!;
    final retainedList = body.chatMessages;
    for (var i = 0; i < 3; i++) {
      model.insertMessage(key, ChatMessage(user: ChatUser(id: 'peer'),
          text: 'new $i', createdAt: DateTime.utc(2026)));
    }
    expect(model.messages[key], same(body));
    expect(body.chatMessages, same(retainedList));
    expect(body.chatMessages.map((m) => m.text), ['new 2', 'new 1', 'new 0']);
  });
}

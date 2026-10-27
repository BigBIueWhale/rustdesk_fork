import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Binding implements RustdeskImpl {
  final sent = <List<Object>>[];
  @override
  dynamic noSuchMethod(Invocation invocation) {
    switch (invocation.memberName) {
      case #translate:
        return invocation.namedArguments[#name] as String;
      case #sessionGetCommonSync:
        return 'false';
      case #sessionInputString:
        sent.add([
          invocation.namedArguments[#sessionId] as SessionID,
          invocation.namedArguments[#value] as String,
        ]);
        return Future<void>.value();
      default:
        throw StateError('Unexpected native operation: ${invocation.memberName}');
    }
  }
}

class _Model implements FfiModel {
  @override
  final pi = PeerInfo()..platform = kPeerPlatformLinux;
  @override
  final permissions = <String, bool>{'keyboard': true, 'restart': false};
  @override
  bool viewOnly = false;
  @override
  bool get keyboard => permissions['keyboard'] != false;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected model access: ${invocation.memberName}');
}

class _Session implements FFI {
  @override
  SessionID sessionId = const Uuid().v4obj();
  @override
  SessionID clientOwnerId = const Uuid().v4obj();
  @override
  ConnType connType = ConnType.defaultConn;
  @override
  final ffiModel = _Model();
  bool current = true;
  @override
  bool isCurrentSession(SessionID id) => current && id == sessionId;
  @override
  bool isCurrentSessionOwner(SessionID id, SessionID owner) =>
      isCurrentSession(id) && owner == clientOwnerId;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected session access: ${invocation.memberName}');
}

class _Fixture {
  final binding = _Binding();
  final session = _Session();
  int reads = 0;
  Future<Map<String, dynamic>?> Function() read =
      () async => {'text': 'héllo 👩‍💻\nnext line'};
  TTextMenu? paste;

  Future<void> mount(WidgetTester tester) async {
    installClipboardKeystrokesProbeBinding(binding);
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform, (call) async {
        if (call.method != 'Clipboard.getData') return null;
        expect(call.arguments, Clipboard.kTextPlain);
        reads++;
        return read();
      });
    addTearDown(() {
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform, null);
    });
    await tester.pumpWidget(MaterialApp(home: Builder(builder: (context) {
      final matches = toolbarControls(context, 'peer', session).where(
          (menu) => menu.child is Text &&
              (menu.child as Text).data == 'Send clipboard keystrokes');
      paste = matches.isEmpty ? null : matches.single;
      return const SizedBox.shrink();
    })));
  }

  Future<void> press() async {
    final dynamic callback = paste!.onPressed!;
    await callback();
  }

  Future<void> delayed(WidgetTester tester, VoidCallback change) async {
    await mount(tester);
    final pending = Completer<Map<String, dynamic>?>();
    read = () => pending.future;
    final action = press();
    await tester.pump();
    expect(reads, 1);
    expect(binding.sent, isEmpty);
    change();
    pending.complete({'text': 'held clipboard text'});
    await tester.pump();
    await action;
  }
}

void main() {
  testWidgets('clipboard keystrokes send current Unicode text unchanged', (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    expect(fixture.paste, isNotNull);
    await fixture.press();
    expect(fixture.reads, 1);
    expect(fixture.binding.sent,
        [[fixture.session.sessionId, 'héllo 👩‍💻\nnext line']]);
  });

  testWidgets('clipboard keystrokes ignore an unavailable clipboard', (tester) async {
    final fixture = _Fixture()..read = () async => null;
    await fixture.mount(tester);
    await fixture.press();
    expect(fixture.reads, 1);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes are absent in view only mode', (tester) async {
    final fixture = _Fixture();
    fixture.session.ffiModel.viewOnly = true;
    await fixture.mount(tester);
    expect(fixture.paste, isNull);
    expect(fixture.reads, 0);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes preserve role and keyboard restrictions', (tester) async {
    final fixture = _Fixture();
    for (final type in ConnType.values.where((type) => type != ConnType.defaultConn)) {
      fixture.session.connType = type;
      await fixture.mount(tester);
      expect(fixture.paste, isNull);
    }
    fixture.session.connType = ConnType.defaultConn;
    fixture.session.ffiModel.pi.platform = kPeerPlatformAndroid;
    await fixture.mount(tester);
    expect(fixture.paste, isNull);
    fixture.session.ffiModel.pi.platform = kPeerPlatformLinux;
    fixture.session.ffiModel.permissions['keyboard'] = false;
    await fixture.mount(tester);
    expect(fixture.paste, isNull);
    expect(fixture.reads, 0);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes stale callback refuses clipboard access', (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    fixture.session.current = false;
    await fixture.press();
    expect(fixture.reads, 0);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes replaced owner refuses clipboard access', (tester) async {
    final fixture = _Fixture();
    await fixture.mount(tester);
    fixture.session.clientOwnerId = const Uuid().v4obj();
    await fixture.press();
    expect(fixture.reads, 0);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes close during read prevents input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester, () => fixture.session.current = false);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes session replacement during read prevents input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester,
        () => fixture.session.sessionId = const Uuid().v4obj());
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes owner replacement during read prevents input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester,
        () => fixture.session.clientOwnerId = const Uuid().v4obj());
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes permission loss during read prevents input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester,
        () => fixture.session.ffiModel.permissions['keyboard'] = false);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes view only change during read prevents input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester,
        () => fixture.session.ffiModel.viewOnly = true);
    expect(fixture.binding.sent, isEmpty);
  });

  testWidgets('clipboard keystrokes unrelated metadata change preserves input', (tester) async {
    final fixture = _Fixture();
    await fixture.delayed(tester, () => fixture.session.ffiModel.pi.version = '1.4.7');
    expect(fixture.binding.sent,
        [[fixture.session.sessionId, 'held clipboard text']]);
  });
}

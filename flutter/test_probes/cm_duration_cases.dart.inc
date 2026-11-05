import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/pages/server_page.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _Binding implements RustdeskImpl {
  @override
  dynamic noSuchMethod(Invocation call) {
    if (call.memberName == #translate) return call.namedArguments[#name];
    if (call.memberName == #mainGetLocalOption) return '';
    throw UnsupportedError('Unexpected CM duration call: ${call.memberName}');
  }
}

Map<String, dynamic> _sample(int elapsed,
        {int generation = 19, bool authorized = true, bool disconnected = false}) =>
    {
      'id': 7,
      'registry_generation': generation,
      'authorized': authorized,
      'disconnected': disconnected,
      'elapsed_seconds': elapsed,
      'is_file_transfer': false,
      'is_view_camera': false,
      'is_terminal': true,
      'port_forward': '',
      'name': 'Duration fixture',
      'peer_id': '127.0.0.1',
      'keyboard': true,
      'clipboard': true,
      'audio': true,
      'file': true,
      'in_voice_call': false,
      'incoming_voice_call': false,
      'voice_call_id': 0,
    };

Future<void> _show(WidgetTester tester, Client client) async {
  addTearDown(() async => tester.pumpWidget(const SizedBox.shrink()));
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(body: buildCmDurationProbe(client)),
  ));
  await tester.pump();
  expect(find.text('Duration fixture'), findsOneWidget);
  expect(tester.takeException(), isNull);
}

Client _refresh(Client current, Map<String, dynamic> snapshot) =>
    reconcileCmClientState([current], jsonEncode([snapshot])).clients.single;

void main() {
  setUp(() {
    isTest = true;
    installCmDurationProbeBinding(_Binding());
  });

  testWidgets('CM duration starts at zero for a fresh connection', (tester) async {
    await _show(tester, Client.fromJson(_sample(0)));
    expect(find.text('Connected'), findsOneWidget);
    expect(find.text('00:00:00'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration is absent before authorization', (tester) async {
    await _show(tester, Client.fromJson(_sample(0, authorized: false)));
    await tester.pump(const Duration(seconds: 3));
    expect(find.textContaining(RegExp(r'^\d+:\d{2}:\d{2}$')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration renders an existing connection on first mount', (tester) async {
    await _show(tester, Client.fromJson(_sample(3661)));
    expect(find.text('01:01:01'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration catches up from the latest snapshot after delayed repaint', (tester) async {
    final client = Client.fromJson(_sample(0));
    await _show(tester, client);
    await tester.pump(const Duration(seconds: 5));
    final refreshed = _refresh(client, _sample(125));
    expect(identical(refreshed, client), isTrue);
    await tester.pump();
    expect(find.text('00:02:05'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration survives header recreation for the same owner', (tester) async {
    final client = Client.fromJson(_sample(0));
    await _show(tester, client);
    await tester.pump(const Duration(seconds: 42));
    await _show(tester, _refresh(client, _sample(42)));
    expect(find.text('00:00:42'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
    await _show(tester, client);
    expect(find.text('00:00:42'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration retains the final disconnected sample', (tester) async {
    final client = Client.fromJson(_sample(0));
    await _show(tester, client);
    final retired = _refresh(client, _sample(67, disconnected: true));
    expect(identical(retired, client), isTrue);
    await _show(tester, retired);
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('Disconnected'), findsOneWidget);
    expect(find.text('00:01:07'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration replacement uses the new owner sample', (tester) async {
    final client = Client.fromJson(_sample(600));
    await _show(tester, client);
    await tester.pump(const Duration(seconds: 5));
    final replacement = _refresh(client, _sample(0, generation: 20));
    expect(identical(replacement, client), isFalse);
    await _show(tester, replacement);
    expect(find.text('00:00:00'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration keeps hours beyond one day', (tester) async {
    await _show(tester, Client.fromJson(_sample(90061, disconnected: true)));
    expect(find.text('25:01:01'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('CM duration reports an unavailable clock without inventing elapsed time', (tester) async {
    final client = Client.fromJson(_sample(0)..['elapsed_seconds'] = null);
    await _show(tester, client);
    expect(find.text('Connected'), findsOneWidget);
    expect(find.text('--:--:--'), findsOneWidget);
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('--:--:--'), findsOneWidget);
    _refresh(client, _sample(7));
    await tester.pump();
    expect(find.text('00:00:07'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}

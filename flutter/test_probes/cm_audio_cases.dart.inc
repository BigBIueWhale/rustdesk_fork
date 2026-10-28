import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show MyTheme, globalKey;
import 'package:flutter_hbb/desktop/pages/server_page.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

final _inputs = [
  SoundInput(id: 'mic-a', label: 'Microphone A'),
  SoundInput(id: 'mic-b', label: 'Microphone B'),
];

class _Write {
  _Write(this.device);
  final String device;
  final result = Completer<void>();
}

class _Binding implements RustdeskImpl {
  final reads = <Completer<List<SoundInput>>>[];
  final writes = <_Write>[];
  String current = 'mic-a';

  @override
  Future<List<SoundInput>> mainGetSoundInputs({dynamic hint}) {
    final read = Completer<List<SoundInput>>();
    reads.add(read);
    return read.future;
  }

  @override
  Future<String> getVoiceCallInputDevice({required bool isCm, dynamic hint}) async {
    expect(isCm, isTrue);
    return current;
  }

  @override
  Future<void> setVoiceCallInputDevice(
      {required bool isCm, required String device, dynamic hint}) async {
    expect(isCm, isTrue);
    final write = _Write(device);
    writes.add(write);
    await write.result.future;
    current = device;
  }

  @override
  bool mainAudioSupportLoopback({dynamic hint}) => true;

  @override
  String translate({required String name, required String locale, dynamic hint}) =>
      name;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Client _client() =>
    Client(1, true, false, false, 'Peer', '192.0.2.10', true, true, true)
      ..registryGeneration = 2
      ..voiceCallId = 3
      ..inVoiceCall = true;

class _Registry extends ChangeNotifier implements ServerModel {
  @override
  final clients = <Client>[];

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Harness {
  final binding = _Binding();
  final registry = _Registry();
  Client client = _client();
  bool visible = true;
  late StateSetter rebuild;

  Future<void> mount(WidgetTester tester) async {
    installCmAudioProbeBinding(binding);
    registry.clients.add(client);
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: Center(child: SizedBox(width: 600,
        child: ChangeNotifierProvider<ServerModel>.value(value: registry,
          child: StatefulBuilder(builder: (context, setState) {
            rebuild = setState;
            return visible ? buildCmAudioProbePanel(client)
                : const Text('Replacement panel');
          }),
        ),
      ))),
    ));
    await tester.pumpAndSettle();
  }

  GestureTapDownCallback opener(WidgetTester tester) =>
      tester.widget<InkWell>(find.ancestor(
          of: find.text('Audio input'), matching: find.byType(InkWell))).onTapDown!;

  Future<void> open(WidgetTester tester) async {
    await tester.tap(find.text('Audio input'));
    await tester.pump();
  }

  Future<void> menu(WidgetTester tester) async {
    await open(tester);
    binding.reads.last.complete(_inputs);
    await tester.pumpAndSettle();
    expect(find.text('Microphone B'), findsOneWidget);
  }

  Future<void> retire(WidgetTester tester, String kind) async {
    rebuild(() {
      switch (kind) {
        case 'call':
          client.inVoiceCall = false;
          client.voiceCallId++;
          client.inVoiceCall = true;
          break;
        case 'registry': client.registryGeneration++; break;
        case 'client-id': client.id++; break;
        case 'client':
          client = _client();
          registry.clients..clear()..add(client);
          break;
        case 'page': visible = false; break;
        case 'ended': client.inVoiceCall = false; client.voiceCallId = 0; break;
      }
    });
    await tester.pump();
  }

  Future<void> finish(WidgetTester tester) async {
    for (final read in binding.reads) {
      if (!read.isCompleted) read.complete(_inputs);
    }
    for (final write in binding.writes) {
      if (!write.result.isCompleted) write.result.complete();
    }
    await tester.pumpAndSettle();
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();
    registry.dispose();
  }
}

const _retirements = ['call', 'registry', 'client-id', 'client', 'page', 'ended'];

void main() {
  testWidgets('audio CM picker writes the selected device for its current call',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.menu(tester);
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      expect(h.binding.writes.map((w) => w.device), ['mic-b']);
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker refuses retired opener callbacks', (tester) async {
    for (final kind in _retirements) {
      final h = _Harness();
      try {
        await h.mount(tester);
        final open = h.opener(tester);
        await h.retire(tester, kind);
        open(TapDownDetails(globalPosition: const Offset(100, 100)));
        await tester.pump();
        expect(h.binding.reads, isEmpty, reason: kind);
        expect(h.binding.writes, isEmpty);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker drops device results for a replaced call',
      (tester) async {
    for (final kind in _retirements) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.open(tester);
        await h.retire(tester, kind);
        h.binding.reads.single.complete(_inputs);
        await tester.pumpAndSettle();
        expect(find.text('Microphone B'), findsNothing, reason: kind);
        expect(h.binding.writes, isEmpty);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker refuses menu selections for a replaced call',
      (tester) async {
    for (final kind in _retirements) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.menu(tester);
        await h.retire(tester, kind);
        await tester.tap(find.text('Microphone B'));
        await tester.pumpAndSettle();
        expect(h.binding.writes, isEmpty, reason: kind);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker allows a fresh menu after call replacement',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.open(tester);
      await h.retire(tester, 'call');
      h.binding.reads.single.complete(_inputs);
      await tester.pumpAndSettle();
      expect(find.text('Microphone B'), findsNothing);
      await h.menu(tester);
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      expect(h.binding.writes.map((w) => w.device), ['mic-b']);
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker reports current read errors and suppresses retired errors',
      (tester) async {
    for (final replace in [false, true]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.open(tester);
        if (replace) await h.retire(tester, 'call');
        h.binding.reads.single.completeError(StateError('device read failed'));
        await tester.pumpAndSettle();
        expect(find.text('Failed'), replace ? findsNothing : findsOneWidget);
        expect(h.binding.writes, isEmpty);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker reports current write failure and allows retry',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.menu(tester);
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      h.binding.writes.single.result.completeError(StateError('device write failed'));
      await tester.pumpAndSettle();
      expect(find.text('Failed'), findsOneWidget);
      expect(h.binding.current, 'mic-a');
      await tester.pump(const Duration(seconds: 4));
      await h.menu(tester);
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      expect(h.binding.writes.map((w) => w.device), ['mic-b', 'mic-b']);
      h.binding.writes.last.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(find.text('Failed'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker drains old write failures without replacement feedback',
      (tester) async {
    for (final kind in _retirements) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.menu(tester);
        await tester.tap(find.text('Microphone B'));
        await tester.pump();
        await h.retire(tester, kind);
        h.binding.writes.single.result.completeError(StateError('old write failed'));
        await tester.pumpAndSettle();
        expect(h.binding.writes.map((w) => w.device), ['mic-b']);
        expect(find.text('Failed'), findsNothing, reason: kind);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker refuses missing call authority', (tester) async {
    for (final field in ['id', 'registry', 'call', 'negative-call', 'incoming']) {
      final h = _Harness();
      if (field == 'id') h.client.id = 0;
      if (field == 'registry') h.client.registryGeneration = 0;
      if (field == 'call') h.client.voiceCallId = 0;
      if (field == 'negative-call') h.client.voiceCallId = -1;
      if (field == 'incoming') h.client.incomingVoiceCall = true;
      try {
        await h.mount(tester);
        await h.open(tester);
        expect(h.binding.reads, isEmpty, reason: field);
        expect(h.binding.writes, isEmpty);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker checks registry replacement before the next frame',
      (tester) async {
    for (final stage in ['opener', 'read', 'selection', 'failure']) {
      final h = _Harness();
      try {
        await h.mount(tester);
        final open = h.opener(tester);
        if (stage == 'read') await h.open(tester);
        if (stage == 'selection' || stage == 'failure') await h.menu(tester);
        if (stage == 'failure') {
          await tester.tap(find.text('Microphone B'));
          await tester.pump();
        }
        h.registry.clients..clear()..add(_client()..registryGeneration = 99);
        if (stage == 'opener') {
          open(TapDownDetails(globalPosition: const Offset(100, 100)));
          expect(h.binding.reads, isEmpty);
        } else if (stage == 'read') {
          h.binding.reads.single.complete(_inputs);
          await tester.pumpAndSettle();
          expect(find.text('Microphone B'), findsNothing);
        } else if (stage == 'selection') {
          await tester.tap(find.text('Microphone B'));
        } else {
          h.binding.writes.single.result.completeError(StateError('retired owner'));
        }
        await tester.pumpAndSettle();
        expect(h.binding.writes, hasLength(stage == 'failure' ? 1 : 0));
        expect(find.text('Failed'), findsNothing);
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });
}

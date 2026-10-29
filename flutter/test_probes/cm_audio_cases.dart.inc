import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
    expectSync(isCm, isTrue);
    return current;
  }

  @override
  Future<void> setVoiceCallInputDevice(
      {required bool isCm, required String device, dynamic hint}) async {
    expectSync(isCm, isTrue);
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
  _Harness({this.otherClient});

  final binding = _Binding();
  final registry = _Registry();
  final Client? otherClient;
  Client client = _client();
  bool visible = true;
  late StateSetter rebuild;

  Future<void> mount(WidgetTester tester) async {
    installCmAudioProbeBinding(binding);
    registry.clients.add(client);
    if (otherClient != null) registry.clients.add(otherClient!);
    await tester.pumpWidget(MaterialApp(
      navigatorKey: globalKey,
      theme: MyTheme.lightTheme,
      home: Scaffold(body: Center(child: SizedBox(width: 600,
        child: ChangeNotifierProvider<ServerModel>.value(value: registry,
          child: StatefulBuilder(builder: (context, setState) {
            rebuild = setState;
            if (!visible) return const Text('Replacement panel');
            final panel = buildCmAudioProbePanel(client);
            return otherClient == null ? panel : Column(
              mainAxisSize: MainAxisSize.min,
              children: [panel, buildCmAudioProbePanel(otherClient!)],
            );
          }),
        ),
      ))),
    ));
    await tester.pumpAndSettle();
  }

  VoidCallback opener(WidgetTester tester, [int index = 0]) {
    final button = tester.widget<InkWell>(find.ancestor(
        of: find.text('Audio input').at(index), matching: find.byType(InkWell)));
    return () {
      button.onTapDown?.call(
          TapDownDetails(globalPosition: const Offset(100, 100)));
      button.onTap?.call();
    };
  }

  Future<void> tabTo(WidgetTester tester, String label) async {
    for (var step = 0; step < 12; step++) {
      if (Focus.of(tester.element(find.text(label))).hasFocus) return;
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pump();
    }
    fail('Keyboard traversal did not reach $label');
  }

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
    while (globalKey.currentState?.canPop() ?? false) {
      globalKey.currentState!.pop();
      await tester.pumpAndSettle();
    }
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();
    registry.dispose();
  }
}

const _retirements = ['call', 'registry', 'client-id', 'client', 'page', 'ended'];

void main() {
  testWidgets('audio CM picker retains pending reads after panel disposal',
      (tester) async {
    for (final failRead in [false, true]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.open(tester);
        final retired = h.opener(tester);
        await h.retire(tester, 'page');
        h.rebuild(() => h.visible = true);
        await tester.pumpAndSettle();
        h.opener(tester)();
        retired();
        await tester.pump();
        expect(h.binding.reads, hasLength(1));
        if (failRead) {
          h.binding.reads.single.completeError(StateError('retired read failed'));
        } else {
          h.binding.reads.single.complete(_inputs);
        }
        await tester.pumpAndSettle();
        expect(find.text('Microphone B'), findsNothing);
        expect(find.text('Failed'), findsNothing);
        await h.menu(tester);
        expect(h.binding.reads, hasLength(2));
        await tester.tap(find.text('Microphone B'));
        await tester.pumpAndSettle();
        expect(h.binding.writes, hasLength(1));
        h.binding.writes.single.result.complete();
        await tester.pumpAndSettle();
        expect(h.binding.current, 'mic-b');
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker retains pending writes after panel disposal',
      (tester) async {
    for (final failWrite in [false, true]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.menu(tester);
        await tester.tap(find.text('Microphone B'));
        await tester.pumpAndSettle();
        expect(h.binding.writes, hasLength(1));
        await h.retire(tester, 'page');
        h.rebuild(() => h.visible = true);
        await tester.pumpAndSettle();
        h.opener(tester)();
        await tester.pump();
        expect(h.binding.reads, hasLength(1), reason: 'old write still owns input');
        if (failWrite) {
          h.binding.writes.single.result.completeError(StateError('retired write failed'));
        } else {
          h.binding.writes.single.result.complete();
        }
        await tester.pumpAndSettle();
        expect(find.text('Failed'), findsNothing);
        await h.menu(tester);
        expect(h.binding.reads, hasLength(2));
        await tester.tap(find.text('Microphone A'));
        await tester.pumpAndSettle();
        expect(h.binding.writes.map((w) => w.device), ['mic-b', 'mic-a']);
        h.binding.writes.last.result.complete();
        await tester.pumpAndSettle();
        expect(h.binding.current, 'mic-a');
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM panels share input selection admission', (tester) async {
    final h = _Harness(otherClient: _client()
      ..id = 4
      ..registryGeneration = 5
      ..voiceCallId = 6);
    try {
      await h.mount(tester);
      final first = h.opener(tester, 0);
      final second = h.opener(tester, 1);
      first();
      second();
      await tester.pump();
      expect(h.binding.reads, hasLength(1));
      h.binding.reads.single.complete(_inputs);
      await tester.pumpAndSettle();
      expect(find.text('Microphone B'), findsOneWidget);
      second();
      await tester.pump();
      expect(h.binding.reads, hasLength(1), reason: 'menu owns input');
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Audio input').at(1));
      await tester.pump();
      expect(h.binding.reads, hasLength(2));
      h.binding.reads.last.complete(_inputs);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Microphone B'));
      await tester.pumpAndSettle();
      first();
      await tester.pump();
      expect(h.binding.reads, hasLength(2), reason: 'write owns input');
      expect(h.binding.writes, hasLength(1));
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Audio input').first);
      await tester.pump();
      expect(h.binding.reads, hasLength(3));
      h.binding.reads.last.complete(_inputs);
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker supports keyboard open select and dismissal',
      (tester) async {
    for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.tabTo(tester, 'Audio input');
        await tester.sendKeyEvent(key);
        await tester.pump();
        expect(h.binding.reads, hasLength(1), reason: key.keyLabel);
        h.binding.reads.single.complete(_inputs);
        await tester.pumpAndSettle();
        await h.tabTo(tester, 'Microphone B');
        await tester.sendKeyEvent(key);
        await tester.pumpAndSettle();
        expect(h.binding.writes.map((w) => w.device), ['mic-b']);
        h.binding.writes.single.result.complete();
        await tester.pumpAndSettle();
        expect(h.binding.current, 'mic-b');
        await h.tabTo(tester, 'Audio input');
        await tester.sendKeyEvent(key);
        await tester.pump();
        expect(h.binding.reads, hasLength(2));
        h.binding.reads.last.complete(_inputs);
        await tester.pumpAndSettle();
        await tester.sendKeyEvent(LogicalKeyboardKey.escape);
        await tester.pumpAndSettle();
        expect(find.text('Microphone B'), findsNothing);
        expect(h.binding.writes, hasLength(1));
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker keyboard entry retains pending and call ownership',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.tabTo(tester, 'Audio input');
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pump();
      expect(h.binding.reads, hasLength(1));
      await tester.sendKeyEvent(LogicalKeyboardKey.space);
      await tester.pump();
      expect(h.binding.reads, hasLength(1));
      await h.retire(tester, 'call');
      h.binding.reads.single.complete(_inputs);
      await tester.pumpAndSettle();
      expect(find.text('Microphone B'), findsNothing);
      expect(h.binding.writes, isEmpty);
      await h.tabTo(tester, 'Audio input');
      await tester.sendKeyEvent(LogicalKeyboardKey.space);
      await tester.pump();
      expect(h.binding.reads, hasLength(2));
      h.binding.reads.last.complete(_inputs);
      await tester.pumpAndSettle();
      await h.tabTo(tester, 'Microphone B');
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(h.binding.writes, hasLength(1));
      await h.tabTo(tester, 'Audio input');
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pump();
      expect(h.binding.reads, hasLength(2), reason: 'write remains pending');
      h.binding.writes.single.result.completeError(StateError('device write failed'));
      await tester.pumpAndSettle();
      expect(find.text('Failed'), findsOneWidget);
      await tester.pump(const Duration(seconds: 4));
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pump();
      expect(h.binding.reads, hasLength(3), reason: 'retry after failure');
      h.binding.reads.last.complete(_inputs);
      await tester.pumpAndSettle();
      await h.tabTo(tester, 'Microphone B');
      await tester.sendKeyEvent(LogicalKeyboardKey.space);
      await tester.pump();
      expect(h.binding.writes.map((w) => w.device), ['mic-b', 'mic-b']);
      h.binding.writes.last.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker ignores cancelled pointer presses', (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      final gesture = await tester.startGesture(tester.getCenter(find.text('Audio input')));
      await tester.pump(const Duration(milliseconds: 200));
      await gesture.cancel();
      await tester.pumpAndSettle();
      expect(h.binding.reads, isEmpty);
      expect(h.binding.writes, isEmpty);
      await h.menu(tester);
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      expect(h.binding.reads, hasLength(1));
      expect(h.binding.writes, isEmpty);
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker serializes device reads across rebuilds',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      final original = h.opener(tester);
      await h.open(tester);
      h.rebuild(() {});
      await tester.pump();
      original();
      h.opener(tester)();
      await tester.pump();
      expect(h.binding.reads, hasLength(1));
      h.binding.reads.single.complete(_inputs);
      await tester.pumpAndSettle();
      expect(find.text('Microphone B'), findsOneWidget);
      original();
      h.opener(tester)();
      await tester.pump();
      expect(h.binding.reads, hasLength(1), reason: 'menu remains open');
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      expect(h.binding.writes, hasLength(1));
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker serializes writes across rebuild and call replacement',
      (tester) async {
    for (final replace in [false, true]) {
      final h = _Harness();
      try {
        await h.mount(tester);
        await h.menu(tester);
        await tester.tap(find.text('Microphone B'));
        await tester.pumpAndSettle();
        expect(h.binding.writes, hasLength(1));
        if (replace) {
          await h.retire(tester, 'call');
        } else {
          h.rebuild(() {});
          await tester.pump();
        }
        h.opener(tester)();
        await tester.pump();
        expect(h.binding.reads, hasLength(1), reason: 'replace=$replace');
        expect(h.binding.writes, hasLength(1));
        h.binding.writes.single.result.complete();
        await tester.pumpAndSettle();
        await h.menu(tester);
        await tester.tap(find.text('Microphone A'));
        await tester.pump();
        expect(h.binding.writes.map((w) => w.device), ['mic-b', 'mic-a']);
        h.binding.writes.last.result.complete();
        await tester.pumpAndSettle();
        expect(h.binding.current, 'mic-a');
        expect(tester.takeException(), isNull);
      } finally { await h.finish(tester); }
    }
  });

  testWidgets('audio CM picker releases dismissal and selects system sound',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.menu(tester);
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      expect(h.binding.writes, isEmpty);
      expect(find.text('Microphone B'), findsNothing);
      await h.menu(tester);
      await tester.tap(find.text('System Sound'));
      await tester.pump();
      expect(h.binding.writes.map((w) => w.device), ['']);
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, '');
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

  testWidgets('audio CM picker retries after device enumeration fails',
      (tester) async {
    final h = _Harness();
    try {
      await h.mount(tester);
      await h.open(tester);
      h.binding.reads.single.completeError(StateError('device read failed'));
      await tester.pumpAndSettle();
      expect(find.text('Failed'), findsOneWidget);
      await tester.pump(const Duration(seconds: 4));
      await h.menu(tester);
      await tester.tap(find.text('Microphone B'));
      await tester.pump();
      expect(h.binding.writes, hasLength(1));
      h.binding.writes.single.result.complete();
      await tester.pumpAndSettle();
      expect(h.binding.current, 'mic-b');
      expect(tester.takeException(), isNull);
    } finally { await h.finish(tester); }
  });

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
        open();
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
          open();
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

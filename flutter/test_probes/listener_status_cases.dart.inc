import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/pages/connection_page.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_test/flutter_test.dart';

const _reachable = 'Reachable on :21118';
const _stopped = 'Not reachable — the service is not running';
const _unconfigured =
    'Not reachable — set a permanent password to open the port';
const _green = Color.fromARGB(255, 50, 190, 166);

Color? _indicatorColor(WidgetTester tester) {
  final indicator = tester.widget<Container>(find.byWidgetPredicate((widget) =>
      widget is Container && widget.decoration is BoxDecoration &&
      (widget.decoration as BoxDecoration).shape == BoxShape.circle));
  return (indicator.decoration as BoxDecoration).color;
}

class _Binding implements RustdeskImpl {
  final keys = <String>[];
  final replies = <Completer<String>>[];

  @override
  String translate({required String name, required String locale, dynamic hint}) =>
      name;

  @override
  bool isIncomingOnly({dynamic hint}) => false;

  @override
  Future<String> mainGetCommon({required String key, dynamic hint}) {
    keys.add(key);
    final reply = Completer<String>();
    replies.add(reply);
    return reply.future;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);

  Future<void> show(WidgetTester tester, {Key? key}) async {
    installListenerStatusProbeBinding(this);
    await tester.binding.setSurfaceSize(const Size(1400, 800));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: DirectListenerStatusWidget(key: key)),
    ));
    await tester.pump(Duration.zero);
  }

  Future<void> reply(WidgetTester tester, int index, String value) async {
    replies[index].complete(value);
    await tester.pump();
    await tester.pump();
  }

  Future<void> fail(WidgetTester tester, int index) async {
    replies[index].completeError(StateError('status read failed'));
    await tester.pump();
    await tester.pump();
  }

  Future<void> drain(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    for (var index = 0; index < replies.length; index++) {
      if (!replies[index].isCompleted) await reply(tester, index, 'false');
    }
    await tester.pump(const Duration(seconds: 3));
  }
}

void main() {
  testWidgets('listener waits for its first status before reporting configuration',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      expect(find.text('Loading...'), findsOneWidget);
      expect(find.text(_unconfigured), findsNothing);
      expect(find.text(_stopped), findsNothing);
      expect(find.text(_reachable), findsNothing);
      expect(_indicatorColor(tester), isNot(_green));
      await binding.reply(tester, 0, 'false');
      expect(find.text('Loading...'), findsOneWidget);
      await binding.reply(tester, 1, 'true');
      expect(find.text(_stopped), findsOneWidget);
    } finally {
      await binding.drain(tester);
    }
  });

  testWidgets('listener clears reachable status before its explanation arrives',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await binding.reply(tester, 0, 'true');
      expect(_indicatorColor(tester), _green);
      await tester.pump(const Duration(seconds: 1));
      await binding.reply(tester, 1, 'false');
      expect(find.text(_reachable), findsNothing);
      expect(_indicatorColor(tester), isNot(_green));
      expect(find.text('Loading...'), findsOneWidget);
      await binding.reply(tester, 2, 'true');
      expect(find.text(_stopped), findsOneWidget);
    } finally {
      await binding.drain(tester);
    }
  });

  for (final explanation in [false, true]) {
    testWidgets('listener handles read failure at explanation $explanation',
        (tester) async {
      final binding = _Binding();
      try {
        await binding.show(tester);
        await binding.reply(tester, 0, explanation ? 'false' : 'true');
        if (!explanation) await tester.pump(const Duration(seconds: 1));
        await binding.fail(tester, 1);
        expect(find.text('Failed'), findsOneWidget);
        expect(find.text(_reachable), findsNothing);
        expect(find.text(_unconfigured), findsNothing);
        expect(_indicatorColor(tester), isNot(_green));
        expect(tester.takeException(), isNull);
        await tester.pump(const Duration(seconds: 1));
        expect(binding.keys, hasLength(3));
        await binding.reply(tester, 2, 'true');
        expect(find.text(_reachable), findsOneWidget);
        expect(find.text('Failed'), findsNothing);
        expect(_indicatorColor(tester), _green);
      } finally {
        await binding.drain(tester);
      }
    });

    testWidgets('retired listener handles late read failure at explanation $explanation',
        (tester) async {
      final binding = _Binding();
      try {
        await binding.show(tester);
        if (explanation) await binding.reply(tester, 0, 'false');
        final reads = binding.keys.length;
        await tester.pumpWidget(const SizedBox.shrink());
        await binding.fail(tester, reads - 1);
        await tester.pump(const Duration(seconds: 3));
        expect(binding.keys, hasLength(reads));
        expect(tester.takeException(), isNull);
      } finally {
        await binding.drain(tester);
      }
    });
  }

  testWidgets('listener rejects invalid status replies and recovers',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await binding.reply(tester, 0, '');
      expect(find.text('Failed'), findsOneWidget);
      expect(binding.keys, ['direct-listener-bound']);
      await tester.pump(const Duration(seconds: 1));
      await binding.reply(tester, 1, 'false');
      await binding.reply(tester, 2, 'unknown');
      expect(find.text('Failed'), findsOneWidget);
      expect(find.text(_unconfigured), findsNothing);
      expect(_indicatorColor(tester), isNot(_green));
      await tester.pump(const Duration(seconds: 1));
      await binding.reply(tester, 3, 'true');
      expect(find.text(_reachable), findsOneWidget);
      expect(tester.takeException(), isNull);
    } finally {
      await binding.drain(tester);
    }
  });

  testWidgets('reachable listener publishes without a password read',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await binding.reply(tester, 0, 'true');
      expect(find.text(_reachable), findsOneWidget);
      expect(binding.keys, ['direct-listener-bound']);
      await tester.pump(const Duration(seconds: 1));
      expect(binding.keys, ['direct-listener-bound', 'direct-listener-bound']);
      await binding.reply(tester, 1, 'true');
      expect(find.text(_reachable), findsOneWidget);
    } finally {
      await binding.drain(tester);
    }
  });

  for (final configured in [false, true]) {
    testWidgets('unreachable listener reports configured password $configured',
        (tester) async {
      final binding = _Binding();
      try {
        await binding.show(tester);
        await binding.reply(tester, 0, 'false');
        expect(binding.keys, ['direct-listener-bound', 'permanent-password-set']);
        await binding.reply(tester, 1, '$configured');
        expect(find.text(configured ? _stopped : _unconfigured), findsOneWidget);
        expect(find.text(_reachable), findsNothing);
      } finally {
        await binding.drain(tester);
      }
    });
  }

  testWidgets('listener polling never overlaps either pending read',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await tester.pump(const Duration(seconds: 3));
      expect(binding.keys, ['direct-listener-bound']);
      await binding.reply(tester, 0, 'false');
      await tester.pump(const Duration(seconds: 3));
      expect(binding.keys, ['direct-listener-bound', 'permanent-password-set']);
      await binding.reply(tester, 1, 'true');
      expect(find.text(_stopped), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      expect(binding.keys.last, 'direct-listener-bound');
      expect(binding.keys, hasLength(3));
    } finally {
      await binding.drain(tester);
    }
  });

  testWidgets('retired listener refuses a follow-up password read',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await tester.pumpWidget(const SizedBox.shrink());
      await binding.reply(tester, 0, 'false');
      await tester.pump(const Duration(seconds: 3));
      expect(binding.keys, ['direct-listener-bound']);
      expect(tester.takeException(), isNull);
    } finally {
      await binding.drain(tester);
    }
  });

  testWidgets('retired password read cannot update a replacement listener',
      (tester) async {
    final old = _Binding();
    final replacement = _Binding();
    try {
      await old.show(tester, key: const ValueKey('old'));
      await old.reply(tester, 0, 'false');
      await replacement.show(tester, key: const ValueKey('new'));
      await old.reply(tester, 1, 'true');
      expect(find.text(_stopped), findsNothing);
      expect(replacement.keys, ['direct-listener-bound']);
      expect(old.keys, ['direct-listener-bound', 'permanent-password-set']);
      expect(tester.takeException(), isNull);
    } finally {
      await old.drain(tester);
      await replacement.drain(tester);
    }
  });

  testWidgets('a stopped listener reads a fresh password explanation',
      (tester) async {
    final binding = _Binding();
    try {
      await binding.show(tester);
      await binding.reply(tester, 0, 'true');
      expect(find.text(_reachable), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      await binding.reply(tester, 1, 'false');
      expect(binding.keys, [
        'direct-listener-bound', 'direct-listener-bound', 'permanent-password-set',
      ]);
      await binding.reply(tester, 2, 'true');
      expect(find.text(_stopped), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      await binding.reply(tester, 3, 'false');
      await binding.reply(tester, 4, 'false');
      expect(find.text(_unconfigured), findsOneWidget);
    } finally {
      await binding.drain(tester);
    }
  });
}

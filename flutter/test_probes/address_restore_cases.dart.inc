import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';
import 'package:flutter_test/flutter_test.dart';

class _Binding {
  final reply = Completer<String>();
  final notices = <String>[];
  bool throwSynchronously = false;
  int reads = 0;

  Future<String> mainGetLastRemoteId() {
    reads++;
    if (throwSynchronously) throw StateError('private saved address failure');
    return reply.future;
  }
}

class _Probe extends StatefulWidget {
  const _Probe(this.platform, this.binding, {super.key});
  final String platform;
  final _Binding binding;

  @override
  State<_Probe> createState() => _ProbeState();
}

class _ProbeState extends State<_Probe> {
  final _addressController = DirectAddressTextEditingController();
  _Binding get bind => widget.binding;
  String translate(String value) => value;
  void showToast(String value) => bind.notices.add(value);

  @override
  void initState() {
    super.initState();
    if (widget.platform == 'desktop') {
      _restore_desktop();
    } else {
      _restore_mobile();
    }
  }

  // EXACT_PAGE_RESTORATION_CALLBACKS

  @override
  Widget build(BuildContext context) => TextField(controller: _addressController);

  @override
  void dispose() {
    _addressController.dispose();
    super.dispose();
  }
}

Future<void> _show(WidgetTester tester, String platform, _Binding binding) =>
    tester.pumpWidget(MaterialApp(
      home: Scaffold(body: _Probe(platform, binding, key: ObjectKey(binding))),
    ));

void main() {
  for (final platform in ['desktop', 'mobile']) {
    testWidgets('$platform address startup restores the saved target', (tester) async {
      final binding = _Binding();
      await _show(tester, platform, binding);
      expect(binding.reads, 1);
      binding.reply.complete('  saved.example:21118  ');
      await tester.pump();
      expect(find.text('saved.example:21118'), findsOneWidget);
      expect(binding.notices, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('$platform address startup preserves a newer typed target', (tester) async {
      final binding = _Binding();
      await _show(tester, platform, binding);
      await tester.enterText(find.byType(TextField), 'typed.example:443');
      binding.reply.complete('saved.example:21118');
      await tester.pump();
      expect(find.text('typed.example:443'), findsOneWidget);
      expect(binding.notices, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    for (final synchronous in [false, true]) {
      testWidgets('$platform address startup handles failure synchronous=$synchronous', (tester) async {
        final binding = _Binding()..throwSynchronously = synchronous;
        await _show(tester, platform, binding);
        if (!synchronous) {
          await tester.enterText(find.byType(TextField), 'typed.example:443');
          binding.reply.completeError(StateError('private saved address failure'));
        }
        await tester.pump();
        expect(binding.notices, ['Failed']);
        expect(tester.takeException(), isNull);
        if (!synchronous) expect(find.text('typed.example:443'), findsOneWidget);
        await tester.enterText(find.byType(TextField), 'retry.example:21118');
        await tester.pump(const Duration(seconds: 3));
        expect(find.text('retry.example:21118'), findsOneWidget);
        expect(binding.reads, 1);
        expect(binding.notices, ['Failed']);
        await tester.pumpWidget(const SizedBox.shrink());
      });
    }

    testWidgets('$platform address startup handles failure after removal', (tester) async {
      final binding = _Binding();
      await _show(tester, platform, binding);
      await tester.pumpWidget(const SizedBox.shrink());
      binding.reply.completeError(StateError('retired saved address failure'));
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(binding.notices, isEmpty);
      expect(binding.reads, 1);
    });

    testWidgets('$platform address startup isolates a replacement from late failure', (tester) async {
      final old = _Binding();
      final replacement = _Binding();
      await _show(tester, platform, old);
      await _show(tester, platform, replacement);
      old.reply.completeError(StateError('replaced saved address failure'));
      replacement.reply.complete('replacement.example:21118');
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(find.text('replacement.example:21118'), findsOneWidget);
      expect(old.notices, isEmpty);
      expect(replacement.notices, isEmpty);
      expect(old.reads, 1);
      expect(replacement.reads, 1);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }
}

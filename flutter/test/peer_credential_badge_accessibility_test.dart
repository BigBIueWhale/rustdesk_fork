import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/peer_credential_badge.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_test/flutter_test.dart';

const _surface = ValueKey('badge-surface');
const _focus = Color(0xffff0000);

class _Harness {
  final reads = <Completer<PeerCredentialStatus>>[];

  Future<void> showError(WidgetTester tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(platform: TargetPlatform.linux, focusColor: _focus),
      home: Scaffold(body: Center(child: RepaintBoundary(
        key: _surface,
        child: PeerCredentialBadge(
          peerId: 'selected',
          retryLabel: 'Retry',
          size: 24,
          readStatus: (id) {
            expect(id, 'selected');
            final result = Completer<PeerCredentialStatus>();
            reads.add(result);
            return result.future;
          },
        ),
      ))),
    ));
    reads.single.completeError(StateError('read denied'));
    await tester.pumpAndSettle();
  }

  Future<void> finishRetry(WidgetTester tester) async {
    expect(reads, hasLength(2));
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.error_outline), findsNothing);
    reads.last.complete(
        const PeerCredentialStatus(hasSavedPrs: true, canForget: true));
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsOneWidget);
    expect(tester.takeException(), isNull);
  }
}

Future<Color> _background(WidgetTester tester) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(find.byKey(_surface));
  final color = await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1);
    try {
      final bytes = (await image.toByteData(format: ui.ImageByteFormat.rawRgba))!;
      return Color.fromARGB(bytes.getUint8(3), bytes.getUint8(0),
          bytes.getUint8(1), bytes.getUint8(2));
    } finally {
      image.dispose();
    }
  });
  return color!;
}

void main() {
  testWidgets('credential retry exposes a labelled enabled button action',
      (tester) async {
    final harness = _Harness();
    await harness.showError(tester);
    final semantics = tester.getSemantics(find.byIcon(Icons.error_outline));
    expect(semantics, containsSemantics(
      label: 'Bad state: read denied\nRetry',
      isButton: true,
      hasEnabledState: true,
      isEnabled: true,
      isFocusable: true,
      hasTapAction: true,
    ));
    tester.binding.pipelineOwner.semanticsOwner!
        .performAction(semantics.id, ui.SemanticsAction.tap);
    await harness.finishRetry(tester);
  }, semanticsEnabled: true);

  for (final (key, label) in [
    (LogicalKeyboardKey.enter, 'Enter'),
    (LogicalKeyboardKey.space, 'Space'),
  ]) {
    testWidgets('credential retry activates once with $label',
        (tester) async {
      final harness = _Harness();
      await harness.showError(tester);
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(key);
      await tester.sendKeyEvent(key);
      await harness.finishRetry(tester);
    });
  }

  testWidgets('credential retry paints keyboard focus', (tester) async {
    final harness = _Harness();
    await harness.showError(tester);
    expect(await _background(tester), isNot(_focus));
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(await _background(tester), _focus);
    FocusManager.instance.primaryFocus!.unfocus();
    await tester.pumpAndSettle();
    expect(await _background(tester), isNot(_focus));
    expect(harness.reads, hasLength(1));
  });

  testWidgets('credential retry pointer activation admits one pending read',
      (tester) async {
    final harness = _Harness();
    await harness.showError(tester);
    await tester.tap(find.byIcon(Icons.error_outline));
    await tester.tap(find.byIcon(Icons.error_outline));
    await harness.finishRetry(tester);
  });
}

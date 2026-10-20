import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart' show mainForgetPassword;
import 'package:flutter_hbb/common/widgets/peer_credential_badge.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_test/flutter_test.dart';

class _Read {
  _Read(this.id);
  final String id;
  final result = Completer<PeerCredentialStatus>();
}

class _Harness {
  final calls = <_Read>[];

  Future<PeerCredentialStatus> read(String id) {
    final call = _Read(id);
    calls.add(call);
    return call.result.future;
  }

  Widget view(String id) => MaterialApp(
        home: PeerCredentialBadge(
          peerId: id,
          retryLabel: 'Retry',
          readStatus: read,
        ),
      );

  Widget peers(List<String> ids) => MaterialApp(
        home: Column(
          children: [
            for (final id in ids)
              PeerCredentialBadge(
                peerId: id,
                retryLabel: 'Retry',
                readStatus: read,
              ),
          ],
        ),
      );
}

const _saved = PeerCredentialStatus(hasSavedPrs: true, canForget: true);
const _retired = PeerCredentialStatus(hasSavedPrs: false, canForget: true);
const _empty = PeerCredentialStatus(hasSavedPrs: false, canForget: false);

void main() {
  testWidgets('confirmed forget clears matching badges without another read',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.peers(['selected', 'selected', 'other']));
    for (final call in harness.calls) {
      call.result.complete(_saved);
    }
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNWidgets(3));
    final commit = Completer<void>();
    final pending = mainForgetPassword('selected', forgetPassword: (id) {
      expect(id, 'selected');
      return commit.future;
    }, showFailure: () => fail('successful forget reported failure'));
    await tester.pump();
    expect(find.byIcon(Icons.key), findsNWidgets(3));
    commit.complete();
    expect(await pending, isTrue);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsOneWidget);
    expect(harness.calls, hasLength(3));
    expect(tester.takeException(), isNull);
  });

  testWidgets('failed forget preserves the badge and the same peer can retry',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('selected'));
    harness.calls.single.result.complete(_saved);
    await tester.pumpAndSettle();
    var failures = 0;
    expect(
        await mainForgetPassword('selected', forgetPassword: (_) async {
          throw StateError('forget denied');
        }, showFailure: () => failures++),
        isFalse);
    await tester.pumpAndSettle();
    expect(failures, 1);
    expect(find.byIcon(Icons.key), findsOneWidget);
    expect(
        await mainForgetPassword('selected', forgetPassword: (_) async {}),
        isTrue);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNothing);
    expect(harness.calls, hasLength(1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('confirmed forget retires an older credential read',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('selected'));
    expect(
        await mainForgetPassword('selected', forgetPassword: (_) async {}),
        isTrue);
    await tester.pumpAndSettle();
    harness.calls.single.result.complete(_saved);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNothing);
    expect(harness.calls, hasLength(1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('confirmed forget retires an older error and retry callback',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('selected'));
    harness.calls.single.result.completeError(StateError('read denied'));
    await tester.pumpAndSettle();
    final retry = tester
        .widget<GestureDetector>(find.ancestor(
            of: find.byIcon(Icons.error_outline),
            matching: find.byType(GestureDetector)).first)
        .onTap!;
    expect(
        await mainForgetPassword('selected', forgetPassword: (_) async {}),
        isTrue);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.error_outline), findsNothing);
    retry();
    expect(harness.calls, hasLength(1));
    await tester.pumpWidget(const SizedBox.shrink());
    retry();
    expect(harness.calls, hasLength(1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('peer credential badge renders only saved PRS and reads once',
      (tester) async {
    final harness = _Harness();
    for (final status in [_empty, _retired, _saved]) {
      final id = 'peer-${harness.calls.length}';
      final before = harness.calls.length;
      await tester.pumpWidget(harness.view(id));
      expect(harness.calls.length, before + 1);
      expect(harness.calls.last.id, id);
      expect(find.byIcon(Icons.key), findsNothing);
      harness.calls.last.result.complete(status);
      await tester.pumpAndSettle();
      expect(find.byIcon(Icons.key),
          status.hasSavedPrs ? findsOneWidget : findsNothing);
      await tester.pumpWidget(harness.view(id));
      expect(harness.calls.length, before + 1);
    }
  });

  testWidgets('peer credential badge reports errors and admits one retry',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('selected'));
    harness.calls.single.result.completeError(StateError('read denied'));
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNothing);
    expect(find.byIcon(Icons.error_outline), findsOneWidget);
    expect(tester.widget<Tooltip>(find.byType(Tooltip)).message,
        contains('read denied'));
    final retry = tester
        .widget<GestureDetector>(find.ancestor(
            of: find.byIcon(Icons.error_outline),
            matching: find.byType(GestureDetector)).first)
        .onTap!;
    retry();
    retry();
    expect(harness.calls.length, 2);
    expect(harness.calls.last.id, 'selected');
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.error_outline), findsNothing);
    harness.calls.last.result.complete(_saved);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('peer credential badge retires old reads and old display data',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('old'));
    final old = harness.calls.single;
    await tester.pumpWidget(harness.view('current'));
    old.result.complete(_saved);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNothing);
    harness.calls.last.result.complete(_saved);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsOneWidget);
    await tester.pumpWidget(harness.view('replacement'));
    expect(find.byIcon(Icons.key), findsNothing);
    harness.calls.last.result.complete(_retired);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.key), findsNothing);
    expect(harness.calls.map((call) => call.id),
        ['old', 'current', 'replacement']);
  });

  testWidgets('peer credential badge rejects a retired retry callback',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('old'));
    harness.calls.single.result.completeError(StateError('read denied'));
    await tester.pumpAndSettle();
    final retry = tester
        .widget<GestureDetector>(find.ancestor(
            of: find.byIcon(Icons.error_outline),
            matching: find.byType(GestureDetector)).first)
        .onTap!;
    await tester.pumpWidget(harness.view('replacement'));
    retry();
    expect(harness.calls.length, 2);
    harness.calls.last.result.complete(_empty);
    await tester.pumpAndSettle();
    retry();
    expect(harness.calls.length, 2);
    await tester.pumpWidget(const SizedBox.shrink());
    retry();
    expect(harness.calls.length, 2);
    expect(tester.takeException(), isNull);
  });

  testWidgets('peer credential badge drains a failed read after disposal',
      (tester) async {
    final harness = _Harness();
    await tester.pumpWidget(harness.view('retiring'));
    await tester.pumpWidget(const SizedBox.shrink());
    harness.calls.single.result.completeError(StateError('late failure'));
    await tester.pumpAndSettle();
    expect(harness.calls.length, 1);
    expect(tester.takeException(), isNull);
  });
}

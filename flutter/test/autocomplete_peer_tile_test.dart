import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';
import 'package:flutter_hbb/common/widgets/autocomplete.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> _checkTile(WidgetTester tester,
    {required double width,
    required String address,
    required String alias,
    required bool truncated}) async {
  expect(isDirectAddress(address), isTrue);
  final peer = Peer.fromJson({
    'id': address,
    'alias': alias,
    'username': 'user',
    'hostname': 'host',
  });
  final selected = <String>[];
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: Align(
        alignment: Alignment.topLeft,
        child: SizedBox(
          width: width,
          child: AutocompletePeerTile(
            peer: peer,
            onSelect: () => selected.add(peer.id),
          ),
        ),
      ),
    ),
  ));
  expect(tester.takeException(), isNull);

  final tile = find.byType(AutocompletePeerTile);
  final label = find.text(alias.isEmpty ? address : '($address)');
  expect(label, findsOneWidget);
  if (alias.isNotEmpty) expect(find.text(alias), findsOneWidget);
  final tileRect = tester.getRect(tile);
  final labelRect = tester.getRect(label);
  expect(labelRect.width, greaterThan(0));
  expect(labelRect.left, greaterThanOrEqualTo(tileRect.left));
  expect(labelRect.right, lessThanOrEqualTo(tileRect.right));
  final paragraph = tester.renderObject<RenderParagraph>(label);
  expect(paragraph.didExceedMaxLines, truncated);

  await tester.tap(tile);
  await tester.pump();
  expect(selected, [address]);
  expect(peer.id, address);
  expect(tester.takeException(), isNull);
  await tester.pumpWidget(const SizedBox.shrink());
}

void main() {
  final label = List.filled(63, 'a').join();
  final tail = List.filled(61, 'b').join();
  final longAddress = '$label.$label.$label.$tail:21118';

  for (final width in [220, 320]) {
    testWidgets('autocomplete aliased long address fits $width pixels',
        (tester) async {
      await _checkTile(tester,
          width: width.toDouble(),
          address: longAddress,
          alias: 'Office',
          truncated: true);
    });

    testWidgets('autocomplete plain long address fits $width pixels',
        (tester) async {
      await _checkTile(tester,
          width: width.toDouble(),
          address: longAddress,
          alias: '',
          truncated: true);
    });
  }

  testWidgets('autocomplete short alias and address remain fully visible',
      (tester) async {
    await _checkTile(tester,
        width: 320, address: '192.0.2.7', alias: 'Office', truncated: false);
  });
}

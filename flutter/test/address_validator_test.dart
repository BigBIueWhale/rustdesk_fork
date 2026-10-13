import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';

Widget _addressField(DirectAddressTextEditingController controller) =>
    MaterialApp(
      home: Scaffold(body: TextField(controller: controller)),
    );

void main() {
  group('direct-address normalization (R-G2/R-SV5)', () {
    test('trims only surrounding whitespace', () {
      expect(normalizeDirectAddress('  192.168.1.10:21118  '),
          '192.168.1.10:21118');
      expect(normalizeDirectAddress('  host.example.com:21118\n'),
          'host.example.com:21118');
    });

    test('preserves malformed interior whitespace for fail-closed validation',
        () {
      const malformedIpv4 = '192. 168.1.10';
      const groupedNumericId = '123 456 789';
      expect(normalizeDirectAddress(malformedIpv4), malformedIpv4);
      expect(normalizeDirectAddress(groupedNumericId), groupedNumericId);
      expect(isDirectAddress(normalizeDirectAddress(malformedIpv4)), isFalse);
      expect(
          isDirectAddress(normalizeDirectAddress(groupedNumericId)), isFalse);
    });

    test('controller exposes address semantics without rewriting the target',
        () {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);

      controller.address = '  host.example.com:21118  ';
      expect(controller.address, 'host.example.com:21118');
      expect(controller.text, 'host.example.com:21118');

      controller.address = 'host. example.com:21118';
      expect(controller.address, 'host. example.com:21118');
      expect(isDirectAddress(controller.address), isFalse);
    });
  });

  group('initial address restoration', () {
    testWidgets('restores untouched text after a selection-only change',
        (tester) async {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);
      final savedAddress = Completer<String>();
      await tester.pumpWidget(_addressField(controller));
      final restoration =
          controller.restoreInitialAddress(() => savedAddress.future);

      await tester.tap(find.byType(TextField));
      await tester.pump();
      savedAddress.complete('  saved.example:21118  ');
      await tester.pump();

      expect(await restoration, isTrue);
      expect(controller.address, 'saved.example:21118');
      expect(find.text('saved.example:21118'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('a typed target wins over a delayed saved address',
        (tester) async {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);
      final savedAddress = Completer<String>();
      await tester.pumpWidget(_addressField(controller));
      final restoration =
          controller.restoreInitialAddress(() => savedAddress.future);

      await tester.enterText(find.byType(TextField), 'typed.example:21118');
      savedAddress.complete('saved.example:21118');
      await tester.pump();

      expect(await restoration, isFalse);
      expect(controller.address, 'typed.example:21118');
      expect(find.text('typed.example:21118'), findsOneWidget);
      expect(find.text('saved.example:21118'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('cleared text stays empty when the saved address arrives',
        (tester) async {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);
      final savedAddress = Completer<String>();
      await tester.pumpWidget(_addressField(controller));
      final restoration =
          controller.restoreInitialAddress(() => savedAddress.future);

      await tester.enterText(find.byType(TextField), 'typed.example:21118');
      await tester.enterText(find.byType(TextField), '');
      savedAddress.complete('saved.example:21118');
      await tester.pump();

      expect(await restoration, isFalse);
      expect(controller.text, isEmpty);
      expect(find.text('saved.example:21118'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    test('existing text or an earlier edit prevents the lookup', () async {
      final existing =
          DirectAddressTextEditingController(text: 'initial.example:21118');
      final edited = DirectAddressTextEditingController();
      addTearDown(existing.dispose);
      addTearDown(edited.dispose);
      edited.address = 'typed.example:21118';
      edited.clear();
      for (final controller in [existing, edited]) {
        expect(
            await controller.restoreInitialAddress(() {
              fail('an initialized address must not trigger a saved lookup');
            }),
            isFalse);
      }
      expect(existing.address, 'initial.example:21118');
      expect(edited.text, isEmpty);

      final unchangedEdits =
          <String, void Function(DirectAddressTextEditingController)>{
        'empty address write': (controller) {
          controller.address = '';
        },
        'whitespace address write': (controller) {
          controller.address = ' \t ';
        },
        'clear while empty': (controller) {
          controller.clear();
        },
      };
      for (final edit in unchangedEdits.entries) {
        final earlierEdit = DirectAddressTextEditingController();
        addTearDown(earlierEdit.dispose);
        edit.value(earlierEdit);
        expect(
            await earlierEdit.restoreInitialAddress(() {
              fail('an explicit edit must not trigger a saved lookup');
            }),
            isFalse,
            reason: edit.key);

        final pending = DirectAddressTextEditingController();
        addTearDown(pending.dispose);
        final savedAddress = Completer<String>();
        final restoration =
            pending.restoreInitialAddress(() => savedAddress.future);
        edit.value(pending);
        savedAddress.complete('saved.example:21118');
        expect(await restoration, isFalse, reason: edit.key);
        expect(pending.text, isEmpty, reason: edit.key);
      }
    });

    test('one controller admits only one initial lookup', () async {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);
      final savedAddress = Completer<String>();
      final restoration =
          controller.restoreInitialAddress(() => savedAddress.future);

      Future<String> unexpectedRead() {
        fail('duplicate initial lookup');
      }

      expect(await controller.restoreInitialAddress(unexpectedRead), isFalse);
      savedAddress.complete('saved.example:21118');
      expect(await restoration, isTrue);
      controller.clear();
      expect(await controller.restoreInitialAddress(unexpectedRead), isFalse);
      expect(controller.text, isEmpty);
    });

    test('disposal retires a pending lookup and prevents another read', () async {
      final controller = DirectAddressTextEditingController();
      final savedAddress = Completer<String>();
      final restoration =
          controller.restoreInitialAddress(() => savedAddress.future);
      controller.dispose();

      savedAddress.complete('saved.example:21118');
      expect(await restoration, isFalse);
      expect(
          await controller.restoreInitialAddress(() {
            fail('disposed controller must not trigger a saved lookup');
          }),
          isFalse);
    });

    test('lookup errors propagate and retire the initial attempt', () async {
      final controller = DirectAddressTextEditingController();
      addTearDown(controller.dispose);
      final failure = StateError('saved lookup failed');
      await expectLater(
          controller.restoreInitialAddress(() async => throw failure),
          throwsA(same(failure)));
      expect(controller.text, isEmpty);
      expect(
          await controller.restoreInitialAddress(() {
            fail('failed initial lookup must not be retried automatically');
          }),
          isFalse);
    });
  });

  group('isDirectAddress (R-G2/R-SV10 bare-ID rejection)', () {
    test('rejects a bare numeric RustDesk ID', () {
      expect(isDirectAddress('123456789'), isFalse);
      expect(isDirectAddress('123 456 789'), isFalse);
      expect(isDirectAddress('123456789/r'), isFalse);
      expect(isDirectAddress('123456789/r@relay.example.com'), isFalse);
      expect(isDirectAddress('1234567890'), isFalse);
    });
    test('rejects inherited relay-route syntax on otherwise direct targets',
        () {
      expect(hasRelayRouteSyntax('192.168.1.10/r'), isTrue);
      expect(hasRelayRouteSyntax('192.168.1.10/r@relay.example.com'), isTrue);
      expect(isDirectAddress('192.168.1.10/r'), isFalse);
      expect(isDirectAddress('192.168.1.10/r@relay.example.com'), isFalse);
      expect(isDirectAddress('host.example.com:21118/r'), isFalse);
    });
    test('accepts an IPv4, with or without a port', () {
      expect(isDirectAddress('192.168.1.10'), isTrue);
      expect(isDirectAddress('192.168.1.10:21118'), isTrue);
      expect(isDirectAddress('10.0.0.1'), isTrue);
    });
    test('accepts domain:port, rejects a bare hostname', () {
      expect(isDirectAddress('host.example.com:21118'), isTrue);
      expect(isDirectAddress('host.example.com'),
          isFalse); // port is required for a domain
    });
    test('rejects IPv6 direct targets', () {
      expect(isDirectAddress('fe80::1'), isFalse);
      expect(isDirectAddress('[fe80::1]:21118'), isFalse);
      expect(isDirectAddress('2001:db8::ff00:42:8329'), isFalse);
    });
    test('requires supplied ports in the nonzero 16-bit range', () {
      for (final host in ['127.0.0.1', 'host.example.com']) {
        expect(isDirectAddress('$host:1'), isTrue);
        expect(isDirectAddress('$host:65535'), isTrue);
        for (final port in ['0', '65536', '+1', '-1', '١', '000001']) {
          expect(isDirectAddress('$host:$port'), isFalse);
        }
      }
    });
    test('rejects empty / whitespace / junk', () {
      expect(isDirectAddress(''), isFalse);
      expect(isDirectAddress('   '), isFalse);
      expect(isDirectAddress('notanaddress'), isFalse);
      expect(
          isDirectAddress('999.999.999.999:1'), isFalse); // out-of-range octets
    });
  });

  test('shared Rust/Dart direct-address vectors', () {
    final vectors =
        jsonDecode(File('test/fixtures/direct_address.json').readAsStringSync())
            as Map;
    for (final group in ['accepted', 'rejected']) {
      for (final address in vectors[group] as List) {
        expect(isDirectAddress(address as String), group == 'accepted',
            reason: address);
      }
    }
  });

  test('hostname label and complete name bounds', () {
    final label = List.filled(63, 'a').join();
    final name = '$label.$label.$label.${List.filled(61, 'a').join()}';
    expect(name.length, 253);
    expect(isDirectAddress('$name:65535'), isTrue);
    expect(isDirectAddress('$name.:65535'), isTrue);
    expect(isDirectAddress('${name}a:65535'), isFalse);
    expect(
        isDirectAddress('${List.filled(64, 'a').join()}.example:1'), isFalse);
  });
}

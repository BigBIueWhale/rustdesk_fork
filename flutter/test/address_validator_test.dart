import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';
import 'package:flutter_hbb/common/formatter/port_number.dart';
import 'package:flutter_hbb/common/widgets/rdp_port_field.dart';

Widget _addressField(DirectAddressTextEditingController controller) =>
    MaterialApp(
      home: Scaffold(body: TextField(controller: controller)),
    );

void main() {
  group('RDP port editing', () {
    Future<TextEditingController> showField(
      WidgetTester tester, {
      String initialPort = '3390',
      bool enabled = true,
      Key? key,
      ValueChanged<String>? onChanged,
    }) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: RdpPortField(
            key: key,
            initialPort: initialPort,
            enabled: enabled,
            onChanged: onChanged ?? (_) {},
            labelText: 'Port',
          ),
        ),
      ));
      return tester.widget<EditableText>(find.byType(EditableText)).controller;
    }

    testWidgets('shows the saved port without publishing an edit',
        (tester) async {
      final edits = <String>[];
      final controller = await showField(tester, onChanged: edits.add);
      expect(controller.text, '3390');
      expect(find.text('Port'), findsOneWidget);
      expect(tester.widget<TextField>(find.byType(TextField)).decoration!.hintText,
          '3389');
      expect(edits, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('can clear the saved port and enter a replacement',
        (tester) async {
      final edits = <String>[];
      final controller = await showField(tester, onChanged: edits.add);
      await tester.enterText(find.byType(TextField), '');
      expect(controller.text, isEmpty);
      expect(edits, ['']);
      await tester.enterText(find.byType(TextField), '443');
      expect(controller.text, '443');
      expect(edits, ['', '443']);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('invalid edits retain the selected port and do not publish',
        (tester) async {
      final edits = <String>[];
      final controller = await showField(tester, onChanged: edits.add);
      await tester.showKeyboard(find.byType(TextField));
      const previous = TextEditingValue(
        text: '3390',
        selection: TextSelection(baseOffset: 1, extentOffset: 3),
      );
      for (final text in ['65536', '3x90', '-1', '+1', '01', '3390\n', '٣٣٩٠']) {
        controller.value = previous;
        tester.testTextInput.updateEditingValue(TextEditingValue(
          text: text,
          selection: TextSelection.collapsed(offset: text.length),
        ));
        await tester.pump();
        expect(controller.value, previous, reason: text);
        expect(edits, isEmpty, reason: text);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('accepts canonical ports with their editing selection',
        (tester) async {
      final edits = <String>[];
      final controller = await showField(tester, onChanged: edits.add);
      await tester.showKeyboard(find.byType(TextField));
      for (final text in ['0', '1', '9', '10', '443', '3389', '65535']) {
        final value = TextEditingValue(
          text: text,
          selection: TextSelection.collapsed(offset: text.length),
        );
        tester.testTextInput.updateEditingValue(value);
        await tester.pump();
        expect(controller.value, value);
        expect(edits.last, text);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('rebuild retains the current draft and controller',
        (tester) async {
      final controller = await showField(tester);
      await tester.enterText(find.byType(TextField), '443');
      controller.selection = const TextSelection(baseOffset: 0, extentOffset: 2);
      final before = controller.value;
      final rebuilt = await showField(tester);
      expect(rebuilt, same(controller));
      expect(rebuilt.value, before);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('pending save disables editing without losing the draft',
        (tester) async {
      final edits = <String>[];
      final controller = await showField(tester, onChanged: edits.add);
      await tester.enterText(find.byType(TextField), '443');
      final disabled = await showField(tester,
          initialPort: '443', enabled: false, onChanged: edits.add);
      expect(disabled, same(controller));
      expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
      await tester.tap(find.byType(TextField));
      await tester.pump();
      expect(tester.widget<EditableText>(find.byType(EditableText)).readOnly,
          isTrue);
      expect(controller.text, '443');
      expect(edits, ['443']);
      await showField(tester, initialPort: '443', onChanged: edits.add);
      await tester.enterText(find.byType(TextField), '3391');
      expect(edits, ['443', '3391']);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('removal disposes its text controller', (tester) async {
      final controller = await showField(tester);
      await tester.pumpWidget(const SizedBox.shrink());
      expect(() => controller.addListener(() {}), throwsFlutterError);
      expect(tester.takeException(), isNull);
    });

    testWidgets('replacement owns a fresh editor and retires the old one',
        (tester) async {
      final old = await showField(tester, key: const ValueKey('old'));
      await tester.enterText(find.byType(TextField), '443');
      final next = await showField(tester,
          key: const ValueKey('next'), initialPort: '3392');
      expect(next, isNot(same(old)));
      expect(next.text, '3392');
      expect(() => old.addListener(() {}), throwsFlutterError);
      await tester.pumpWidget(const SizedBox.shrink());
      expect(() => next.addListener(() {}), throwsFlutterError);
      expect(tester.takeException(), isNull);
    });
  });

  group('tunnel port editing', () {
    const previous = TextEditingValue(
      text: '21118',
      selection: TextSelection(baseOffset: 1, extentOffset: 4),
    );

    test('accepts empty and canonical 16-bit numeric drafts', () {
      for (final text in [
        '',
        '0',
        '1',
        '9',
        '10',
        '99',
        '100',
        '999',
        '1000',
        '9999',
        '10000',
        '59999',
        '60000',
        '64999',
        '65000',
        '65499',
        '65500',
        '65529',
        '65530',
        '65535'
      ]) {
        final edit = TextEditingValue(
          text: text,
          selection: TextSelection.collapsed(offset: text.length),
        );
        expect(portNumberInputFormatter.formatEditUpdate(previous, edit), edit,
            reason: text);
      }
    });

    test('rejects the whole invalid edit without changing the draft', () {
      for (final text in [
        '65536',
        '99999',
        '123456',
        '-1',
        '+1',
        '01',
        '00000',
        '21x18',
        ' 21118',
        '21118 ',
        '21118\n',
        '٢١',
        '🙂'
      ]) {
        final edit = TextEditingValue(
          text: text,
          selection: TextSelection.collapsed(offset: text.length),
        );
        expect(
            portNumberInputFormatter.formatEditUpdate(previous, edit), previous,
            reason: text);
      }
    });

    test('preserves selection and composition of accepted text', () {
      const edit = TextEditingValue(
        text: '12345',
        selection: TextSelection(baseOffset: 4, extentOffset: 1),
        composing: TextRange(start: 1, end: 4),
      );
      expect(portNumberInputFormatter.formatEditUpdate(previous, edit), edit);
    });

    Future<TextEditingController> showField(
        WidgetTester tester, String text) async {
      final controller = TextEditingController(text: text);
      addTearDown(controller.dispose);
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
            body: TextField(
          controller: controller,
          inputFormatters: [portNumberInputFormatter],
        )),
      ));
      await tester.showKeyboard(find.byType(TextField));
      return controller;
    }

    testWidgets('an out-of-range digit preserves the visible port',
        (tester) async {
      final controller = await showField(tester, '6553');
      await tester.enterText(find.byType(TextField), '65536');
      expect(controller.text, '6553');
      expect(find.text('6553'), findsOneWidget);
      await tester.enterText(find.byType(TextField), '65535');
      expect(controller.text, '65535');
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('invalid paste preserves the selected port and cursor',
        (tester) async {
      final controller = await showField(tester, previous.text);
      controller.value = previous;
      tester.testTextInput.updateEditingValue(const TextEditingValue(
        text: '2invalid8',
        selection: TextSelection.collapsed(offset: 8),
      ));
      await tester.pump();
      expect(controller.value, previous);
      expect(find.text(previous.text), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('clearing and replacing a port still works', (tester) async {
      final controller = await showField(tester, '21118');
      await tester.enterText(find.byType(TextField), '');
      expect(controller.text, isEmpty);
      await tester.enterText(find.byType(TextField), '443');
      expect(controller.text, '443');
      expect(find.text('443'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  });

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

    test('disposal retires a pending lookup and prevents another read',
        () async {
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

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/formatter/direct_address.dart';

void main() {
  group('direct-address normalization (R-G2/R-SV5)', () {
    test('trims only surrounding whitespace', () {
      expect(normalizeDirectAddress('  192.168.1.10:21118  '), '192.168.1.10:21118');
      expect(normalizeDirectAddress('  host.example.com:21118\n'),
          'host.example.com:21118');
    });

    test('preserves malformed interior whitespace for fail-closed validation', () {
      const malformedIpv4 = '192. 168.1.10';
      const groupedNumericId = '123 456 789';
      expect(normalizeDirectAddress(malformedIpv4), malformedIpv4);
      expect(normalizeDirectAddress(groupedNumericId), groupedNumericId);
      expect(isDirectAddress(normalizeDirectAddress(malformedIpv4)), isFalse);
      expect(isDirectAddress(normalizeDirectAddress(groupedNumericId)), isFalse);
    });

    test('controller exposes address semantics without rewriting the target', () {
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

  group('isDirectAddress (R-G2/R-SV10 bare-ID rejection)', () {
    test('rejects a bare numeric RustDesk ID', () {
      expect(isDirectAddress('123456789'), isFalse);
      expect(isDirectAddress('123 456 789'), isFalse);
      expect(isDirectAddress('123456789/r'), isFalse);
      expect(isDirectAddress('123456789/r@relay.example.com'), isFalse);
      expect(isDirectAddress('1234567890'), isFalse);
    });
    test('rejects inherited relay-route syntax on otherwise direct targets', () {
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
      expect(isDirectAddress('host.example.com'), isFalse); // port is required for a domain
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
      expect(isDirectAddress('999.999.999.999:1'), isFalse); // out-of-range octets
    });
  });

  test('shared Rust/Dart direct-address vectors', () {
    final vectors = jsonDecode(
        File('test/fixtures/direct_address.json').readAsStringSync()) as Map;
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
    expect(isDirectAddress('${List.filled(64, 'a').join()}.example:1'), isFalse);
  });
}

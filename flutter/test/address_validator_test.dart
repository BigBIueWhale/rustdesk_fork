// R-SV10 (requirements.html:693): "a test MUST prove a bare-ID input is rejected." R-G2: the
// direct-IP-only fork accepts only <ipv4>[:port] / <ipv6> / [<ipv6>]:port / <domain>:port at the
// connect box, never a bare numeric RustDesk ID. This unit-tests `isDirectAddress` — the validator
// the connect choke point (common.dart connect()) uses to fail closed on a non-address — so a
// regression that re-admitted bare IDs (and thus a rendezvous lookup) would turn this gate red.
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/common/formatter/id_formatter.dart';

void main() {
  group('isDirectAddress (R-G2/R-SV10 bare-ID rejection)', () {
    test('rejects a bare numeric RustDesk ID', () {
      expect(isDirectAddress('123456789'), isFalse);
      expect(isDirectAddress('123 456 789'), isFalse); // the space-grouped display form
      expect(isDirectAddress('123456789/r'), isFalse); // a relay-suffixed ID
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
    test('accepts IPv6 (bare and bracketed:port)', () {
      expect(isDirectAddress('fe80::1'), isTrue);
      expect(isDirectAddress('[fe80::1]:21118'), isTrue);
      expect(isDirectAddress('2001:db8::ff00:42:8329'), isTrue);
    });
    test('rejects empty / whitespace / junk', () {
      expect(isDirectAddress(''), isFalse);
      expect(isDirectAddress('   '), isFalse);
      expect(isDirectAddress('notanaddress'), isFalse);
      expect(isDirectAddress('999.999.999.999:1'), isFalse); // out-of-range octets
    });
  });
}

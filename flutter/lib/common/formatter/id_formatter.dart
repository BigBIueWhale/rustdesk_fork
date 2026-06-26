import 'package:flutter/material.dart';

class IDTextEditingController extends TextEditingController {
  IDTextEditingController({String? text}) : super(text: text);

  String get id => trimID(value.text);

  // R-G2: a direct-address fork does not space-group numeric IDs — just strip spaces (no formatID).
  set id(String newID) => text = trimID(newID);
}

String formatID(String id) {
  String id2 = id.replaceAll(' ', '');
  if (int.tryParse(id2) == null) return id;
  String newID = '';
  if (id2.length <= 3) {
    newID = id2;
  } else {
    var n = id2.length;
    var a = n % 3 != 0 ? n % 3 : 3;
    newID = id2.substring(0, a);
    for (var i = a; i < n; i += 3) {
      newID += " ${id2.substring(i, i + 3)}";
    }
  }
  return newID;
}

String trimID(String id) {
  return id.replaceAll(' ', '');
}

/// R-SV4/R-X6/R-G6: the inherited relay route suffix (`/r` or `/r@server`) is not
/// a direct address modifier in this fork. It must be rejected, never stripped.
bool hasRelayRouteSyntax(String s) {
  final t = trimID(s);
  return t.endsWith(r'\r') || t.endsWith('/r') || t.contains('/r@');
}

// R-G2/R-SV10: the fork is direct-IP-only. These mirror hbb_common's accept-set VERBATIM
// (`is_ipv4_str` / `is_ipv6_str` / `is_domain_port_str`, libs/hbb_common/src/lib.rs:403/414/430),
// which the Rust choke point enforces (src/client.rs:315/331, bailing on anything else at :353). A
// bare numeric RustDesk ID — the relay/rendezvous addressing the fork deleted — matches none.
final _ipv4Re = RegExp(
    r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d+)?$');
final _ipv6Re = RegExp(
    r'^((([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4})|(\[([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4}\]:\d+))$');
final _domainPortRe = RegExp(
    r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z-]{0,61}[a-z]:\d{1,5}$',
    caseSensitive: false);

/// R-G2/R-SV10: true iff [s] is a DIRECT address the fork can connect to — `<ipv4>[:port]`,
/// `<ipv6>` / `[<ipv6>]:port`, or `<domain>:port`. A bare numeric RustDesk ID is REJECTED (returns
/// false). Mirrors `hbb_common::is_ip_str || is_domain_port_str` so the connect UI and the
/// `client.rs` choke point agree on exactly one accept-set.
bool isDirectAddress(String s) {
  final t = s.trim();
  if (t.isEmpty) return false;
  if (hasRelayRouteSyntax(t)) return false;
  return _ipv4Re.hasMatch(t) || _ipv6Re.hasMatch(t) || _domainPortRe.hasMatch(t);
}

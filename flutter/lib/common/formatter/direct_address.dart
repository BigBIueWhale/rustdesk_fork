import 'package:flutter/material.dart';

/// Text controller for the direct address used by the viewer connection UI.
///
/// Only surrounding whitespace is presentation noise. Interior whitespace is
/// preserved so validation rejects the malformed address instead of silently
/// changing it into a different target.
class DirectAddressTextEditingController extends TextEditingController {
  DirectAddressTextEditingController({String? text}) : super(text: text);

  String get address => normalizeDirectAddress(value.text);

  set address(String newAddress) => text = normalizeDirectAddress(newAddress);
}

String normalizeDirectAddress(String address) => address.trim();

/// R-SV4/R-X6/R-G6: the inherited relay route suffix (`/r` or `/r@server`) is not
/// a direct address modifier in this fork. It must be rejected, never stripped.
bool hasRelayRouteSyntax(String address) {
  final normalized = normalizeDirectAddress(address);
  return normalized.endsWith(r'\r') ||
      normalized.endsWith('/r') ||
      normalized.contains('/r@');
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

/// R-G2/R-SV10: true iff [address] is a DIRECT address the fork can connect to —
/// `<ipv4>[:port]`, `<ipv6>` / `[<ipv6>]:port`, or `<domain>:port`. A bare numeric RustDesk ID is
/// REJECTED (returns false). Mirrors `hbb_common::is_ip_str || is_domain_port_str` so the connect UI
/// and the `client.rs` choke point agree on exactly one accept-set.
bool isDirectAddress(String address) {
  final normalized = normalizeDirectAddress(address);
  if (normalized.isEmpty) return false;
  if (hasRelayRouteSyntax(normalized)) return false;
  return _ipv4Re.hasMatch(normalized) ||
      _ipv6Re.hasMatch(normalized) ||
      _domainPortRe.hasMatch(normalized);
}

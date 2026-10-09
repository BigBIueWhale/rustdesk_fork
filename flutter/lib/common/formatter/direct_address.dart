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

/// R-G2/R-SV10: IPv4 with an optional port, or a qualified ASCII hostname with
/// a required port. Shared vectors exercise this and Rust's direct-peer predicate.
bool isDirectAddress(String address) {
  final normalized = normalizeDirectAddress(address);
  if (normalized.isEmpty || normalized.length > 260) return false;
  if (hasRelayRouteSyntax(normalized)) return false;
  final parts = normalized.split(':');
  if (parts.length == 1) return _isIpv4Host(parts[0]);
  if (parts.length != 2 || !_isDirectPort(parts[1])) return false;
  return _isIpv4Host(parts[0]) || _isDomainHost(parts[0]);
}

bool _isAsciiDigit(int value) => value >= 48 && value <= 57;

bool _isAsciiLetter(int value) =>
    (value >= 65 && value <= 90) || (value >= 97 && value <= 122);

bool _isAsciiAlphanumeric(int value) =>
    _isAsciiDigit(value) || _isAsciiLetter(value);

bool _isDirectPort(String port) {
  if (port.isEmpty || port.length > 5 || !port.codeUnits.every(_isAsciiDigit)) {
    return false;
  }
  final value = int.tryParse(port);
  return value != null && value >= 1 && value <= 65535;
}

bool _isIpv4Host(String host) {
  final octets = host.split('.');
  return octets.length == 4 &&
      octets.every((octet) =>
          octet.isNotEmpty &&
          octet.length <= 3 &&
          (octet.length == 1 || !octet.startsWith('0')) &&
          octet.codeUnits.every(_isAsciiDigit) &&
          int.parse(octet) <= 255);
}

bool _isDomainHost(String host) {
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  if (name.length > 253) return false;
  final labels = name.split('.');
  return labels.length >= 2 &&
      labels.last.codeUnits.any(_isAsciiLetter) &&
      labels.every((label) =>
          label.isNotEmpty &&
          label.length <= 63 &&
          _isAsciiAlphanumeric(label.codeUnitAt(0)) &&
          _isAsciiAlphanumeric(label.codeUnitAt(label.length - 1)) &&
          label.codeUnits
              .every((value) => _isAsciiAlphanumeric(value) || value == 45));
}

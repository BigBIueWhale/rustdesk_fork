import 'package:flutter/services.dart';

final _portNumber = RegExp(r'^(0|[1-9][0-9]{0,4})$');

final portNumberInputFormatter =
    TextInputFormatter.withFunction((oldValue, newValue) {
  final text = newValue.text;
  if (text.isEmpty) return newValue;
  final match = _portNumber.matchAsPrefix(text);
  return match != null && match.end == text.length && int.parse(text) <= 65535
      ? newValue
      : oldValue;
});

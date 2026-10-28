import 'package:flutter/material.dart';
import '../formatter/port_number.dart';

class RdpPortField extends StatelessWidget {
  const RdpPortField({
    super.key,
    required this.initialPort,
    required this.enabled,
    required this.onChanged,
    this.labelText,
  });

  final String initialPort;
  final bool enabled;
  final ValueChanged<String> onChanged;
  final String? labelText;

  @override
  Widget build(BuildContext context) => TextFormField(
        initialValue: initialPort,
        enabled: enabled,
        inputFormatters: [portNumberInputFormatter],
        decoration: InputDecoration(labelText: labelText, hintText: '3389'),
        onChanged: onChanged,
        autofocus: true,
      );
}

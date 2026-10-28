import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class RdpPortField extends StatefulWidget {
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
  State<RdpPortField> createState() => _RdpPortFieldState();
}

class _RdpPortFieldState extends State<RdpPortField> {
  late final _controller = TextEditingController(text: widget.initialPort);

  @override
  Widget build(BuildContext context) => TextField(
        enabled: widget.enabled,
        inputFormatters: [
          FilteringTextInputFormatter.allow(RegExp(
              r'^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$'))
        ],
        decoration:
            InputDecoration(labelText: widget.labelText, hintText: '3389'),
        controller: _controller,
        onChanged: widget.onChanged,
        autofocus: true,
      );
}

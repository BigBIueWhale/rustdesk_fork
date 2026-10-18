import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class AutoDisconnectTimeoutField extends StatefulWidget {
  const AutoDisconnectTimeoutField({
    super.key,
    required this.value,
    required this.enabled,
    required this.saveTimeout,
    required this.translateText,
  });

  final String value;
  final bool enabled;
  final Future<String> Function(String value) saveTimeout;
  final String Function(String text) translateText;

  @override
  State<AutoDisconnectTimeoutField> createState() =>
      _AutoDisconnectTimeoutFieldState();
}

class _AutoDisconnectTimeoutFieldState
    extends State<AutoDisconnectTimeoutField> {
  late final _controller = TextEditingController(text: widget.value);
  late String _savedValue = widget.value;
  bool _saving = false;
  bool _failed = false;
  static final _timeoutPattern = RegExp(
      r'^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$');

  bool get _canSave =>
      widget.enabled &&
      !_saving &&
      (_failed || _controller.text != _savedValue);

  @override
  void didUpdateWidget(covariant AutoDisconnectTimeoutField oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.value != oldWidget.value) {
      final replaceDraft = !_saving && !_failed &&
          _controller.text == _savedValue;
      _savedValue = widget.value;
      if (replaceDraft) _controller.text = widget.value;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!mounted || !_canSave) return;
    final requested = _controller.text;
    setState(() {
      _saving = true;
      _failed = false;
    });
    String? effective;
    try {
      effective = await widget.saveTimeout(requested);
    } catch (error) {
      debugPrint('Failed to save auto-disconnect timeout: $error');
    }
    if (!mounted) return;
    setState(() {
      _saving = false;
      _failed = effective != requested;
      if (effective != null) _savedValue = effective!;
    });
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText;
    return Row(children: [
      SizedBox(
        width: 95,
        child: Padding(
          padding: const EdgeInsets.only(right: 15),
          child: TextField(
            controller: _controller,
            enabled: widget.enabled,
            keyboardType: TextInputType.number,
            onChanged: (_) => setState(() => _failed = false),
            inputFormatters: [
              TextInputFormatter.withFunction((oldValue, newValue) {
                return newValue.text.isEmpty ||
                        _timeoutPattern.hasMatch(newValue.text)
                    ? newValue
                    : oldValue;
              }),
            ],
            decoration: InputDecoration(
              hintText: '10',
              errorText: _failed ? text('Failed') : null,
              contentPadding:
                  const EdgeInsets.symmetric(vertical: 12, horizontal: 12),
            ),
          ),
        ),
      ),
      ElevatedButton(
        onPressed: _canSave ? _save : null,
        child: Text(text('Apply')),
      ),
    ]);
  }
}

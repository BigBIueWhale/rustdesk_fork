import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';

class AutoDisconnectTimeoutDialog extends StatefulWidget {
  const AutoDisconnectTimeoutDialog({
    super.key,
    required this.initialValue,
    required this.saveTimeout,
    required this.close,
    required this.translateText,
  });

  final String initialValue;
  final Future<String> Function(String value) saveTimeout;
  final DialogClose close;
  final String Function(String text) translateText;

  @override
  State<AutoDisconnectTimeoutDialog> createState() =>
      _AutoDisconnectTimeoutDialogState();
}

class _AutoDisconnectTimeoutDialogState
    extends State<AutoDisconnectTimeoutDialog> {
  late final _controller = TextEditingController(text: widget.initialValue);
  bool _saving = false;
  bool _failed = false;
  static final _timeoutPattern = RegExp(r'^(0|[1-9][0-9]{0,4})

  bool get _current => mounted && widget.close.isCurrent;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _cancel() {
    if (_current && !_saving) widget.close();
  }

  Future<void> _save() async {
    if (!_current || _saving) return;
    final requested = _controller.text;
    setState(() {
      _saving = true;
      _failed = false;
    });
    try {
      final effective = await widget.saveTimeout(requested);
      if (!_current) return;
      if (effective == requested) {
        widget.close(effective);
        return;
      }
    } catch (error) {
      debugPrint('Failed to save auto-disconnect timeout: $error');
    }
    if (!_current) return;
    setState(() {
      _saving = false;
      _failed = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText;
    return CustomAlertDialog(
      title: Text(text('Timeout in minutes')),
      content: Padding(
        padding: const EdgeInsets.only(top: 8),
        child: TextField(
          controller: _controller,
          enabled: !_saving,
          autofocus: true,
          maxLines: null,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(
            hintText: '10',
            isCollapsed: true,
            errorText: _failed ? text('Failed') : null,
            suffix: IconButton(
              padding: EdgeInsets.zero,
              icon: const Icon(Icons.clear, size: 16),
              onPressed: _saving ? null : _controller.clear,
            ),
          ),
          inputFormatters: [
            TextInputFormatter.withFunction((oldValue, newValue) {
              final value = newValue.text;
              return value.isEmpty ||
                      (_timeoutPattern.hasMatch(value) &&
                          (int.tryParse(value) ?? 65536) <= 65535)
                  ? newValue
                  : oldValue;
            }),
          ],
        ),
      ),
      actions: [
        dialogButton('Cancel',
            onPressed: _saving ? null : _cancel,
            isOutline: true,
            translateText: text),
        dialogButton('OK',
            onPressed: _saving ? null : _save, translateText: text),
      ],
      onSubmit: _save,
      onCancel: _cancel,
    );
  }
}
);

  bool get _current => mounted && widget.close.isCurrent;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _cancel() {
    if (_current && !_saving) widget.close();
  }

  Future<void> _save() async {
    if (!_current || _saving) return;
    final requested = _controller.text;
    setState(() {
      _saving = true;
      _failed = false;
    });
    try {
      final effective = await widget.saveTimeout(requested);
      if (!_current) return;
      if (effective == requested) {
        widget.close(effective);
        return;
      }
    } catch (error) {
      debugPrint('Failed to save auto-disconnect timeout: $error');
    }
    if (!_current) return;
    setState(() {
      _saving = false;
      _failed = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText;
    return CustomAlertDialog(
      title: Text(text('Timeout in minutes')),
      content: Padding(
        padding: const EdgeInsets.only(top: 8),
        child: TextField(
          controller: _controller,
          enabled: !_saving,
          autofocus: true,
          maxLines: null,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(
            hintText: '10',
            isCollapsed: true,
            errorText: _failed ? text('Failed') : null,
            suffix: IconButton(
              padding: EdgeInsets.zero,
              icon: const Icon(Icons.clear, size: 16),
              onPressed: _saving ? null : _controller.clear,
            ),
          ),
          inputFormatters: [
            FilteringTextInputFormatter.allow(RegExp(
                r'^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$')),
          ],
        ),
      ),
      actions: [
        dialogButton('Cancel',
            onPressed: _saving ? null : _cancel,
            isOutline: true,
            translateText: text),
        dialogButton('OK',
            onPressed: _saving ? null : _save, translateText: text),
      ],
      onSubmit: _save,
      onCancel: _cancel,
    );
  }
}

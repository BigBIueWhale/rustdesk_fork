import 'package:flutter/material.dart';

class SettingCheckbox extends StatefulWidget {
  const SettingCheckbox({
    super.key,
    required this.label,
    required this.value,
    required this.enabled,
    required this.saveValue,
    required this.failureText,
    this.onChanged,
    this.checkedIcon,
    this.labelStyle,
  });

  final String label;
  final bool value;
  final bool enabled;
  final Future<bool?> Function(bool) saveValue;
  final String failureText;
  final ValueChanged<bool>? onChanged;
  final Icon? checkedIcon;
  final TextStyle? labelStyle;

  @override
  State<SettingCheckbox> createState() => _SettingCheckboxState();
}

class _SettingCheckboxState extends State<SettingCheckbox> {
  late bool _value = widget.value;
  bool _saving = false;
  bool _failed = false;

  @override
  void didUpdateWidget(covariant SettingCheckbox oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.value != oldWidget.value) {
      _value = widget.value;
      _failed = false;
    }
  }

  Future<void> _change(bool? next) async {
    if (!mounted || !widget.enabled || _saving ||
        next == null || next == _value) return;
    final write = widget.saveValue;
    setState(() { _saving = true; _failed = false; });
    bool? effective;
    try {
      effective = await write(next);
    } catch (error) {
      debugPrint('Failed to save checkbox setting: $error');
    }
    if (!mounted) return;
    final acknowledged = effective;
    setState(() {
      _saving = false;
      _failed = acknowledged != next;
      if (acknowledged != null) _value = acknowledged;
    });
    if (acknowledged != null) widget.onChanged?.call(acknowledged);
  }

  @override
  Widget build(BuildContext context) {
    final enabled = widget.enabled && !_saving;
    return Column(mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start, children: [
      GestureDetector(
        onTap: enabled ? () => _change(!_value) : null,
        child: Row(children: [
          Padding(
            padding: const EdgeInsets.only(right: 5),
            child: Checkbox(value: _value, onChanged: enabled ? _change : null),
          ),
          Offstage(
            offstage: !_value || widget.checkedIcon == null,
            child: widget.checkedIcon == null ? null : Padding(
              padding: const EdgeInsets.only(right: 5), child: widget.checkedIcon),
          ),
          Expanded(child: Text(widget.label, style: widget.labelStyle)),
        ]),
      ),
      if (_saving) const SizedBox(height: 2, child: LinearProgressIndicator()),
      if (_failed) Text(widget.failureText),
    ]);
  }
}

import 'package:flutter/material.dart';

typedef SettingBooleanBuilder = Widget Function(
    bool value, ValueChanged<bool?>? change, bool saving, bool failed);

class SettingBooleanControl extends StatefulWidget {
  const SettingBooleanControl({
    super.key,
    required this.value,
    required this.enabled,
    required this.saveValue,
    required this.builder,
    this.onChanged,
  });

  final bool value;
  final bool enabled;
  final Future<bool?> Function(bool) saveValue;
  final SettingBooleanBuilder builder;
  final ValueChanged<bool>? onChanged;

  @override
  State<SettingBooleanControl> createState() => _SettingBooleanControlState();
}

class _SettingBooleanControlState extends State<SettingBooleanControl> {
  late bool _value = widget.value;
  bool _saving = false;
  bool _failed = false;

  @override
  void didUpdateWidget(covariant SettingBooleanControl oldWidget) {
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
      debugPrint('Failed to save setting: $error');
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
  Widget build(BuildContext context) => widget.builder(
      _value, widget.enabled && !_saving ? _change : null, _saving, _failed);
}

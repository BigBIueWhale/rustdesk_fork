import 'package:flutter/material.dart';
import 'package:get/get.dart';

class SettingCheckbox extends StatelessWidget {
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
  Widget build(BuildContext context) {
    final ref = value.obs;
    change(bool? next) async {
      if (next == null) return;
      final effective = await saveValue(next);
      if (effective == null || !context.mounted) return;
      ref.value = effective;
      onChanged?.call(effective);
    }

    return GestureDetector(
      onTap: enabled ? () => change(!ref.value) : null,
      child: Obx(() => Row(children: [
        Padding(
          padding: const EdgeInsets.only(right: 5),
          child: Checkbox(value: ref.value, onChanged: enabled ? change : null),
        ),
        Offstage(
          offstage: !ref.value || checkedIcon == null,
          child: checkedIcon == null ? null : Padding(
            padding: const EdgeInsets.only(right: 5), child: checkedIcon),
        ),
        Expanded(child: Text(label, style: labelStyle)),
      ])),
    );
  }
}

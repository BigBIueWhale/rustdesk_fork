import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/setting_boolean.dart';

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
  Widget build(BuildContext context) => SettingBooleanControl(
    value: value,
    enabled: enabled,
    saveValue: saveValue,
    onChanged: onChanged,
    builder: (current, change, saving, failed) => Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start, children: [
      GestureDetector(
        onTap: change != null ? () => change(!current) : null,
        child: Row(children: [
          Padding(
            padding: const EdgeInsets.only(right: 5),
            child: Checkbox(value: current, onChanged: change),
          ),
          Offstage(
            offstage: !current || checkedIcon == null,
            child: checkedIcon == null ? null : Padding(
              padding: const EdgeInsets.only(right: 5), child: checkedIcon),
          ),
          Expanded(child: Text(label, style: labelStyle)),
        ]),
      ),
      if (saving) const SizedBox(height: 2, child: LinearProgressIndicator()),
      if (failed) Text(failureText),
    ]),
  );
}

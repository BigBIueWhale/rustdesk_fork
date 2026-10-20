import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/setting_boolean.dart';
import 'package:settings_ui/settings_ui.dart';

class DefaultOptionSwitch extends StatelessWidget {
  const DefaultOptionSwitch({
    super.key,
    required this.optionKey,
    required this.label,
    required this.value,
    required this.falseValue,
    required this.enabled,
    required this.saveOption,
    required this.failureText,
  });

  final String optionKey;
  final String label;
  final String value;
  final String falseValue;
  final bool enabled;
  final Future<String?> Function(String, String) saveOption;
  final String failureText;

  @override
  Widget build(BuildContext context) {
    return SettingBooleanControl(
      key: ValueKey(('user-default', optionKey)),
      value: value == 'Y',
      enabled: enabled,
      saveValue: (next) async {
        final effective = await saveOption(optionKey, next ? 'Y' : falseValue);
        return effective == null ? null : effective == 'Y';
      },
      builder: (current, change, saving, failed) => SettingsTile.switchTile(
        initialValue: current,
        enabled: change != null,
        onToggle: change == null ? null : (next) => change(next),
        title: Column(mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label),
          if (saving) const LinearProgressIndicator(minHeight: 2),
          if (failed) Text(failureText),
        ]),
      ),
    );
  }
}

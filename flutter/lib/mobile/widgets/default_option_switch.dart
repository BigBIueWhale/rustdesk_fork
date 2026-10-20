import 'package:flutter/material.dart';
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
    return SettingsTile.switchTile(
      initialValue: value == 'Y',
      title: Text(label),
      onToggle: enabled ? (next) async {
        await saveOption(optionKey, next ? 'Y' : falseValue);
      } : null,
    );
  }
}

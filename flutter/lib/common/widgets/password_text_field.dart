import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Password input keeps its keyboard policy when the text is revealed.
class PasswordTextField extends StatelessWidget {
  const PasswordTextField({
    super.key,
    required this.controller,
    this.focusNode,
    this.decoration = const InputDecoration(),
    this.autofocus = false,
    this.obscureText = true,
    this.enabled,
    this.onChanged,
    this.inputFormatters,
    this.maxLength,
  });

  final TextEditingController controller;
  final FocusNode? focusNode;
  final InputDecoration decoration;
  final bool autofocus;
  final bool obscureText;
  final bool? enabled;
  final ValueChanged<String>? onChanged;
  final List<TextInputFormatter>? inputFormatters;
  final int? maxLength;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      focusNode: focusNode,
      decoration: decoration,
      autofocus: autofocus,
      obscureText: obscureText,
      enabled: enabled,
      onChanged: onChanged,
      inputFormatters: inputFormatters,
      maxLength: maxLength,
      keyboardType: TextInputType.visiblePassword,
      autocorrect: false,
      enableSuggestions: false,
      enableIMEPersonalizedLearning: false,
      smartDashesType: SmartDashesType.disabled,
      smartQuotesType: SmartQuotesType.disabled,
      spellCheckConfiguration: const SpellCheckConfiguration.disabled(),
    );
  }
}

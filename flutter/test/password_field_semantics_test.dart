import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('obscured dialog field exposes enabled focused semantics',
      (tester) async {
    final controller = TextEditingController();
    final focusNode = FocusNode();
    addTearDown(controller.dispose);
    addTearDown(focusNode.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: Material(
          child: DialogTextField(
            title: 'Password',
            obscureText: true,
            controller: controller,
            focusNode: focusNode,
          ),
        ),
      ),
    );
    focusNode.requestFocus();
    await tester.pump();

    expect(
      tester.getSemantics(find.byType(EditableText)),
      containsSemantics(
        isTextField: true,
        isObscured: true,
        hasEnabledState: true,
        isEnabled: true,
        isFocusable: true,
        isFocused: true,
      ),
    );
  }, semanticsEnabled: true);
}

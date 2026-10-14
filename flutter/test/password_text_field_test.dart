import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/password_text_field.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  for (final platform in [TargetPlatform.android, TargetPlatform.iOS]) {
    testWidgets('password keyboard policy survives reveal on ${platform.name}',
        (tester) async {
      final controller = TextEditingController();
      final focusNode = FocusNode();
      addTearDown(controller.dispose);
      addTearDown(focusNode.dispose);

      debugDefaultTargetPlatformOverride = platform;
      try {
        for (final obscured in [true, false, true]) {
          await tester.pumpWidget(MaterialApp(
            home: Material(
              child: PasswordTextField(
                controller: controller,
                focusNode: focusNode,
                obscureText: obscured,
              ),
            ),
          ));
          await tester.showKeyboard(find.byType(TextField));
          if (controller.text.isEmpty) {
            await tester.enterText(find.byType(TextField), 'Exact1x-\'"');
          }
          final configuration = tester.testTextInput.setClientArgs!;
          expect(
            configuration['inputType'],
            TextInputType.visiblePassword.toJson(),
          );
          expect(configuration['obscureText'], obscured);
          expect(configuration['autocorrect'], false);
          expect(configuration['enableSuggestions'], false);
          expect(configuration['enableIMEPersonalizedLearning'], false);
          expect(configuration['smartDashesType'],
              SmartDashesType.disabled.index.toString());
          expect(configuration['smartQuotesType'],
              SmartQuotesType.disabled.index.toString());
          expect(controller.text, 'Exact1x-\'"');
          final editable = tester.widget<EditableText>(find.byType(EditableText));
          expect(editable.spellCheckConfiguration?.spellCheckEnabled, false);
          expect(tester.takeException(), isNull);
        }
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    });
  }

  testWidgets('ordinary obscured field is a keyboard learning control',
      (tester) async {
    await tester.pumpWidget(const MaterialApp(
      home: Material(child: TextField(obscureText: true)),
    ));
    await tester.showKeyboard(find.byType(TextField));
    final configuration = tester.testTextInput.setClientArgs!;
    expect(configuration['autocorrect'], true);
    expect(configuration['enableIMEPersonalizedLearning'], true);
  });

  testWidgets('password field retains focused obscured semantics',
      (tester) async {
    final controller = TextEditingController();
    addTearDown(controller.dispose);
    await tester.pumpWidget(MaterialApp(
      home: Material(child: PasswordTextField(controller: controller)),
    ));
    await tester.showKeyboard(find.byType(TextField));
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

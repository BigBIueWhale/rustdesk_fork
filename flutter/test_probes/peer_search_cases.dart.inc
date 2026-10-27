import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/peer_tab_page.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _Binding implements RustdeskImpl {
  @override
  String translate({required String name, required String locale, dynamic hint}) =>
      name;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Harness {
  final other = FocusNode();
  late StateSetter rebuild;
  double width = 400;

  Widget app() => MaterialApp(
        home: Scaffold(
          body: StatefulBuilder(builder: (context, setState) {
            rebuild = setState;
            return SizedBox(
              width: width,
              child: Row(children: [
                PeerSearchBar(),
                TextButton(
                  focusNode: other,
                  onPressed: () {},
                  child: const Text('Other'),
                ),
              ]),
            );
          }),
        ),
      );

  Future<void> show(WidgetTester tester) async {
    addTearDown(other.dispose);
    await tester.pumpWidget(app());
    await tester.tap(find.byIcon(Icons.search_rounded));
    await tester.pumpAndSettle();
  }

  Future<void> resize(WidgetTester tester) async {
    rebuild(() => width += 20);
    await tester.pumpAndSettle();
  }
}

FocusNode _fieldFocus(WidgetTester tester) =>
    tester.widget<EditableText>(find.byType(EditableText)).focusNode;

void main() {
  setUp(() {
    installPeerSearchProbeBinding(_Binding());
    peerSearchTextController.clear();
    peerSearchText.value = '';
    stateGlobal.isPortrait.value = false;
  });

  testWidgets('peer search opens focused and publishes typed text', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    await tester.enterText(find.byType(TextField), 'office');
    expect(peerSearchText.value, 'office');
    expect(peerSearchTextController.text, 'office');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search keeps focus and caret through parent rebuilds', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    peerSearchTextController.selection = const TextSelection.collapsed(offset: 2);
    for (var i = 0; i < 3; i++) {
      await harness.resize(tester);
      expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
      expect(peerSearchTextController.selection,
          const TextSelection.collapsed(offset: 2));
      expect(peerSearchText.value, 'office');
    }
    tester.testTextInput.updateEditingValue(const TextEditingValue(
      text: 'ofXfice', selection: TextSelection.collapsed(offset: 3)));
    await tester.pump();
    expect(peerSearchText.value, 'ofXfice');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search does not change selection when focus leaves', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    peerSearchTextController.selection =
        const TextSelection(baseOffset: 1, extentOffset: 3);
    harness.other.requestFocus();
    await tester.pumpAndSettle();
    expect(harness.other.hasPrimaryFocus, isTrue);
    expect(peerSearchTextController.selection,
        const TextSelection(baseOffset: 1, extentOffset: 3));
    await harness.resize(tester);
    expect(harness.other.hasPrimaryFocus, isTrue);
    expect(peerSearchText.value, 'office');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search selects the query when focus returns', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.enterText(find.byType(TextField), 'office');
    harness.other.requestFocus();
    await tester.pumpAndSettle();
    _fieldFocus(tester).requestFocus();
    await tester.pumpAndSettle();
    expect(peerSearchTextController.selection,
        const TextSelection(baseOffset: 0, extentOffset: 6));
    expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search close clears the query and reopening accepts input', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    for (var i = 0; i < 3; i++) {
      await tester.enterText(find.byType(TextField), 'query$i');
      expect(peerSearchText.value, 'query$i');
      await tester.tap(find.byIcon(Icons.close));
      await tester.pumpAndSettle();
      expect(find.byType(TextField), findsNothing);
      expect(peerSearchText.value, isEmpty);
      expect(peerSearchTextController.text, isEmpty);
      await tester.tap(find.byIcon(Icons.search_rounded));
      await tester.pumpAndSettle();
      expect(_fieldFocus(tester).hasPrimaryFocus, isTrue);
    }
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('peer search disposes its focus node when removed', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    final focus = _fieldFocus(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(focus.parent, isNull);
    expect(() => focus.addListener(() {}), throwsFlutterError);
    expect(tester.takeException(), isNull);
  });
}

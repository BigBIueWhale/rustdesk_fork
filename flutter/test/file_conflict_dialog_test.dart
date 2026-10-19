import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Owner implements FFI {
  _Owner(this.dialogManager);

  @override
  final OverlayDialogManager dialogManager;
  @override
  final SessionID sessionId = const Uuid().v4obj();

  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw StateError('The conflict dialog must not dispatch a native operation');
  }
}

typedef _Harness = ({FileModel model, OverlayDialogManager manager, _Owner owner});

Future<_Harness> _harness(WidgetTester tester) async {
  final state = BlockableOverlayState();
  final manager = OverlayDialogManager(translateText: (text) => text);
  manager.setOverlayState(state);
  final owner = _Owner(manager);
  final model = FileModel(WeakReference<FFI>(owner));
  await tester.pumpWidget(MaterialApp(
    home: BlockableOverlay(state: state, underlying: const SizedBox.expand()),
  ));
  addTearDown(() async {
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
  });
  return (model: model, manager: manager, owner: owner);
}

Future<bool?> _open(_Harness harness, {bool remember = true}) =>
    harness.model.showFileConfirmDialog('Overwrite', '/remote/existing.bin',
        remember, translateText: (text) => text);

void main() {
  testWidgets('overwrite dialog does not claim content identity', (tester) async {
    final harness = await _harness(tester);
    final result = _open(harness);
    try {
      await tester.pumpAndSettle();
      expect(find.text('/remote/existing.bin'), findsOneWidget);
      expect(find.text('This file exists, skip or overwrite this file?'),
          findsOneWidget);
      expect(find.text('identical_file_tip'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      harness.manager.dismissAll();
      await tester.pumpAndSettle();
      await result;
    }
  });

  testWidgets('overwrite dialog preserves cancel skip overwrite and escape',
      (tester) async {
    final harness = await _harness(tester);
    for (final choice in <String, bool?>{
      'Cancel': false, 'Skip': null, 'OK': true, 'Escape': false,
    }.entries) {
      final result = _open(harness);
      await tester.pumpAndSettle();
      if (choice.key == 'Escape') {
        await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      } else {
        await tester.tap(find.text(choice.key));
      }
      await tester.pumpAndSettle();
      expect(await result, choice.value, reason: choice.key);
      expect(find.text('/remote/existing.bin'), findsNothing);
      expect(harness.model.fileConfirmCheckboxRemember, isFalse);
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('overwrite dialog remembers a choice only for its opening',
      (tester) async {
    final harness = await _harness(tester);
    var result = _open(harness);
    await tester.pumpAndSettle();
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        isFalse);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pumpAndSettle();
    expect(harness.model.fileConfirmCheckboxRemember, isTrue);
    await tester.tap(find.text('Skip'));
    await tester.pumpAndSettle();
    expect(await result, isNull);
    expect(harness.model.fileConfirmCheckboxRemember, isTrue);

    result = _open(harness);
    await tester.pumpAndSettle();
    expect(tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
        isFalse);
    expect(harness.model.fileConfirmCheckboxRemember, isFalse);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(await result, isFalse);
    expect(tester.takeException(), isNull);
  });

  testWidgets('overwrite dialog omits unavailable remember control',
      (tester) async {
    final harness = await _harness(tester);
    final result = _open(harness, remember: false);
    await tester.pumpAndSettle();
    expect(find.byType(CheckboxListTile), findsNothing);
    expect(find.text('/remote/existing.bin'), findsOneWidget);
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle();
    expect(await result, isTrue);
    expect(harness.model.fileConfirmCheckboxRemember, isFalse);
    expect(tester.takeException(), isNull);
  });
}

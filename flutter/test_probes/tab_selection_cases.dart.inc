import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/main.dart' as app;
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_test/flutter_test.dart';

class _Binding implements RustdeskImpl {
  @override
  bool isIncomingOnly({dynamic hint}) => false;

  @override
  bool isOutgoingOnly({dynamic hint}) => false;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Harness {
  final selected = <String>[];
  final removed = <String>[];
  late final controller = DesktopTabController(
    tabType: DesktopTabType.remoteScreen,
    onSelected: selected.add,
    onRemoved: (_, key) => removed.add(key),
  );

  Future<void> show(WidgetTester tester, {String active = 'b', int count = 4}) async {
    for (final key in ['a', 'b', 'c', 'd'].take(count)) {
      controller.state.value.tabs.add(TabInfo(
        key: key,
        label: key,
        page: Center(key: ValueKey('page:$key'), child: Text('page:$key')),
      ));
    }
    controller.state.value.scrollController.itemCount = count;
    addTearDown(() async {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(milliseconds: 200));
      controller.state.value.pageController.dispose();
      controller.state.value.scrollController.dispose();
    });
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DesktopTab(
      controller: controller,
      showLogo: false,
      showMinimize: false,
      showMaximize: false,
      showClose: false,
    ))));
    await select(tester, active);
    expectPage(active);
    selected.clear();
  }

  Future<void> select(WidgetTester tester, String key) async {
    expect(controller.jumpToByKey(key), isTrue);
    await settle(tester);
  }

  Future<void> settle(WidgetTester tester) async {
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();
  }

  void expectPage(String key) {
    expect(controller.state.value.selectedTabInfo.key, key);
    expect(controller.state.value.pageController.page,
        controller.state.value.selected.toDouble());
    expect(find.text('page:$key').hitTestable(), findsOneWidget);
  }
}

void main() {
  const windowChannel = MethodChannel('mixin.one/flutter_multi_window');
  setUp(() {
    installTabSelectionProbeBinding(_Binding());
    stateGlobal.showTabBar.value = false;
    app.kWindowId = 42;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(windowChannel, (call) async {
      if (call.method == 'isMaximized' && call.arguments == 42) return false;
      throw StateError('Unexpected window operation: ${call.method}');
    });
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(windowChannel, null);
    app.kWindowId = null;
    stateGlobal.showTabBar.value = true;
  });

  for (final scenario in [
    ('background last', 'b', 'd', 'b'),
    ('background middle right', 'b', 'c', 'b'),
    ('background left', 'c', 'a', 'c'),
    ('active middle', 'b', 'b', 'c'),
    ('active first', 'a', 'a', 'b'),
    ('active last', 'd', 'd', 'c'),
  ]) {
    testWidgets('tab selection after closing ${scenario.$1}', (tester) async {
      final harness = _Harness();
      await harness.show(tester, active: scenario.$2);
      await harness.controller.closeBy(scenario.$3);
      await harness.settle(tester);
      expect(harness.removed, [scenario.$3]);
      expect(harness.controller.length, 3);
      harness.expectPage(scenario.$4);
      expect(harness.selected, [scenario.$4]);
    });
  }

  testWidgets('tab selection resets after closing the only tab', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a', count: 1);
    await harness.controller.closeBy('a');
    await harness.settle(tester);
    expect(harness.controller.length, 0);
    expect(harness.controller.state.value.selected, 0);
    expect(harness.selected, isEmpty);
    expect(harness.removed, ['a']);
    expect(find.text('page:a'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('tab selection follows the user during delayed close', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'c');
    final retirement = Completer<void>();
    harness.controller.onBeforeRemove = (_, __) => retirement.future;
    final closing = harness.controller.closeBy('c');
    await tester.pump();
    expect(harness.controller.length, 4);
    await harness.select(tester, 'b');
    harness.expectPage('b');
    harness.selected.clear();
    retirement.complete();
    await closing;
    await harness.settle(tester);
    harness.expectPage('b');
    expect(harness.selected, ['b']);
    expect(harness.removed, ['c']);
  });

  testWidgets('tab selection survives failed retirement', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    harness.controller.onBeforeRemove = (_, __) async {
      throw StateError('retirement failed');
    };
    await expectLater(harness.controller.closeBy('b'), throwsStateError);
    await harness.settle(tester);
    harness.expectPage('b');
    expect(harness.controller.length, 4);
    expect(harness.selected, isEmpty);
    expect(harness.removed, isEmpty);
  });
}

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

  Widget appWidget() => MaterialApp(home: Scaffold(body: DesktopTab(
    controller: controller,
    showLogo: false,
    showMinimize: false,
    showMaximize: false,
    showClose: false,
  )));

  Future<void> show(WidgetTester tester, {
    String active = 'b',
    int count = 4,
    Map<String, Widget> pages = const {},
  }) async {
    for (final key in ['a', 'b', 'c', 'd'].take(count)) {
      controller.state.value.tabs.add(TabInfo(
        key: key,
        label: key,
        page: pages[key] ?? Center(key: ValueKey('page:$key'), child: Text('page:$key')),
      ));
    }
    controller.state.value.scrollController.itemCount = count;
    addTearDown(() async {
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(milliseconds: 200));
      controller.state.value.pageController.dispose();
      controller.state.value.scrollController.dispose();
    });
    await tester.pumpWidget(appWidget());
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

class _TrackedPage extends StatefulWidget {
  final String id;
  final String generation;
  final VoidCallback created;
  final VoidCallback retired;

  _TrackedPage(this.id, this.generation, this.created, this.retired)
      : super(key: ValueKey('tracked:$id'));

  @override
  State<_TrackedPage> createState() => _TrackedPageState();
}

class _TrackedPageState extends State<_TrackedPage>
    with AutomaticKeepAliveClientMixin {
  late final String generation;
  int clicks = 0;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    generation = widget.generation;
    widget.created();
  }

  @override
  void dispose() {
    widget.retired();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
      Text('page:${widget.id}'),
      ElevatedButton(
        onPressed: () => setState(() => clicks++),
        child: Text('$generation:$clicks'),
      ),
    ]));
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

  testWidgets('tab selection refuses indices outside the current list', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    for (final index in [-1, harness.controller.length, 2147483647]) {
      expect(harness.controller.jumpTo(index), isFalse);
      await harness.settle(tester);
      harness.expectPage('b');
      expect(harness.selected, isEmpty);
    }
  });

  testWidgets('tab selection presents the selected page after layout', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    harness.controller.jumpToByKey('d');
    await tester.pump();
    await tester.pump();
    harness.expectPage('d');
    expect(harness.selected, ['d']);
  });

  testWidgets('tab selection supersedes an older deferred switch', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    harness.controller.jumpToByKey('b');
    await tester.pump(const Duration(milliseconds: 50));
    harness.controller.jumpToByKey('d');
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump();
    harness.expectPage('d');
    await harness.settle(tester);
    harness.expectPage('d');
  });

  testWidgets('tab selection retires a removed deferred page index', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    final pages = <double>[];
    final pageController = harness.controller.state.value.pageController;
    pageController.addListener(() => pages.add(pageController.page!));
    harness.controller.jumpToByKey('d');
    await tester.pump(const Duration(milliseconds: 50));
    harness.controller.remove(3);
    pages.clear();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump();
    expect(pages, everyElement(lessThanOrEqualTo(2.0)));
    harness.expectPage('c');
  });

  testWidgets('tab selection applies on mounting after unmounted requests', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    await tester.pumpWidget(const SizedBox.shrink());
    harness.controller.jumpToByKey('d');
    await tester.pump(const Duration(milliseconds: 200));
    await tester.pumpWidget(harness.appWidget());
    await tester.pump();
    harness.expectPage('d');
  });

  testWidgets('tab selection cannot replay a retired view switch', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    harness.controller.jumpToByKey('d');
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pumpWidget(const SizedBox.shrink());
    harness.controller.jumpToByKey('a');
    await tester.pumpWidget(harness.appWidget());
    await tester.pump();
    harness.expectPage('a');
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump();
    harness.expectPage('a');
  });

  testWidgets('tab selection replaces same-count pages between frames', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    harness.controller.remove(0);
    harness.controller.add(TabInfo(
      key: 'e', label: 'e',
      page: const Center(key: ValueKey('page:e'), child: Text('page:e')),
    ));
    await harness.settle(tester);
    expect(harness.controller.length, 4);
    harness.expectPage('e');
    expect(find.text('page:a'), findsNothing);
  });

  testWidgets('tab selection gives a same-key replacement fresh page state', (tester) async {
    final harness = _Harness();
    var created = 0;
    var retired = 0;
    await harness.show(tester, pages: {
      'b': _TrackedPage('b', 'old', () => created++, () => retired++),
    });
    await tester.tap(find.text('old:0'));
    await tester.pump();
    expect(find.text('old:1'), findsOneWidget);
    await harness.controller.closeBy('b');
    harness.controller.add(TabInfo(
      key: 'b', label: 'b',
      page: _TrackedPage('b', 'new', () => created++, () => retired++),
    ));
    await harness.settle(tester);
    harness.expectPage('b');
    expect(find.text('new:0').hitTestable(), findsOneWidget);
    expect(find.text('old:1'), findsNothing);
    expect(created, 2);
    expect(retired, 1);
  });

  testWidgets('tab selection preserves surviving page state across list changes', (tester) async {
    final harness = _Harness();
    var created = 0;
    var retired = 0;
    await harness.show(tester, pages: {
      'b': _TrackedPage('b', 'survivor', () => created++, () => retired++),
    });
    await tester.tap(find.text('survivor:0'));
    await tester.pump();
    harness.controller.add(TabInfo(
      key: 'e', label: 'e',
      page: const Center(key: ValueKey('page:e'), child: Text('page:e')),
    ));
    await harness.settle(tester);
    harness.expectPage('e');
    await harness.controller.closeBy('a');
    await harness.settle(tester);
    await harness.select(tester, 'b');
    harness.expectPage('b');
    expect(find.text('survivor:1').hitTestable(), findsOneWidget);
    expect(created, 1);
    expect(retired, 0);
  });

  testWidgets('tab notification follows new page initialization', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    var initialized = false;
    final notifications = <bool>[];
    harness.controller.onSelected = (key) {
      expect(key, 'e');
      notifications.add(initialized);
    };
    harness.controller.add(TabInfo(
      key: 'e', label: 'e',
      page: _TrackedPage('e', 'new', () => initialized = true, () {}),
    ));
    expect(notifications, isEmpty);
    await harness.settle(tester);
    harness.expectPage('e');
    expect(notifications, [true]);
  });

  testWidgets('tab notification selects an existing tab without replacement', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    await harness.select(tester, 'b');
    final original = harness.controller.state.value.tabs[1];
    await harness.select(tester, 'a');
    harness.selected.clear();
    harness.controller.add(TabInfo(
      key: 'b', label: 'replacement',
      page: const Text('unexpected replacement'),
    ));
    await harness.settle(tester);
    harness.expectPage('b');
    expect(harness.controller.state.value.tabs[1], same(original));
    expect(find.text('unexpected replacement'), findsNothing);
    expect(harness.selected, ['b']);
  });

  testWidgets('tab notification coalesces superseded selections before layout', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    harness.controller.jumpToByKey('b');
    harness.controller.jumpToByKey('d');
    await harness.settle(tester);
    harness.expectPage('d');
    expect(harness.selected, ['d']);
  });

  testWidgets('tab notification waits for an unmounted selection to mount', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    await tester.pumpWidget(const SizedBox.shrink());
    harness.controller.jumpToByKey('d');
    await tester.pump(const Duration(milliseconds: 200));
    expect(harness.selected, isEmpty);
    await tester.pumpWidget(harness.appWidget());
    await harness.settle(tester);
    harness.expectPage('d');
    expect(harness.selected, ['d']);
  });

  testWidgets('tab notification reapplies the selected tab after remount', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpWidget(harness.appWidget());
    await harness.settle(tester);
    harness.expectPage('b');
    expect(harness.selected, ['b']);
  });

  testWidgets('tab notification is not repeated for a parent rebuild', (tester) async {
    final harness = _Harness();
    await harness.show(tester);
    for (var i = 0; i < 3; i++) {
      await tester.pumpWidget(harness.appWidget());
      await harness.settle(tester);
      harness.expectPage('b');
    }
    expect(harness.selected, isEmpty);
  });

  testWidgets('tab notification retires a same-key replacement before dispatch', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    var replacementInitialized = false;
    final notifications = <bool>[];
    harness.controller.onSelected = (key) {
      if (key == 'b') notifications.add(replacementInitialized);
    };
    tester.binding.addPostFrameCallback((_) {
      harness.controller.remove(1);
      harness.controller.add(TabInfo(
        key: 'b', label: 'b',
        page: _TrackedPage('b', 'replacement',
            () => replacementInitialized = true, () {}),
      ));
    });
    harness.controller.jumpToByKey('b');
    await harness.settle(tester);
    harness.expectPage('b');
    expect(notifications, [true]);
  });

  testWidgets('tab notification permits a reentrant selection without duplicates', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    harness.controller.onSelected = (key) {
      harness.selected.add(key);
      if (key == 'b') harness.controller.jumpToByKey('d');
    };
    harness.controller.jumpToByKey('b');
    await harness.settle(tester);
    harness.expectPage('d');
    expect(harness.selected, ['b', 'd']);
  });

  testWidgets('tab notification retires selection cleared before layout', (tester) async {
    final harness = _Harness();
    await harness.show(tester, active: 'a');
    harness.controller.jumpToByKey('b');
    harness.controller.clear();
    await harness.settle(tester);
    expect(harness.controller.length, 0);
    expect(harness.selected, isEmpty);
    expect(find.text('page:b'), findsNothing);
  });
}

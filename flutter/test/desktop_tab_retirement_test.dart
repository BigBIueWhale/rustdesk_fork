import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_test/flutter_test.dart';

TabInfo _tab(String key) => TabInfo(
      key: key,
      label: key,
      page: const SizedBox.shrink(),
    );

void _addWithoutSelection(DesktopTabController controller, TabInfo tab) {
  controller.state.value.tabs.add(tab);
  controller.state.value.scrollController.itemCount =
      controller.state.value.tabs.length;
}

void main() {
  testWidgets('tab removal waits for exact resource retirement',
      (tester) async {
    final controller = DesktopTabController(
      tabType: DesktopTabType.remoteScreen,
    );
    final retirement = Completer<void>();
    final events = <String>[];
    controller.onRemoved = (_, key) => events.add('removed:$key');
    controller.onBeforeRemove = (tab, closeSession) async {
      events.add('retiring:${tab.key}:$closeSession');
      await retirement.future;
      events.add('retired:${tab.key}');
    };
    _addWithoutSelection(controller, _tab('peer'));

    final close = controller.closeBy('peer', closeSession: false);
    await tester.pump();

    expect(controller.length, 1);
    expect(events, ['retiring:peer:false']);

    retirement.complete();
    await close;

    expect(controller.length, 0);
    expect(events, ['retiring:peer:false', 'retired:peer', 'removed:peer']);
  });

  testWidgets('window close retires every snapshotted tab before clearing',
      (tester) async {
    final controller = DesktopTabController(
      tabType: DesktopTabType.remoteScreen,
    );
    final retirements = <String, Completer<void>>{
      'first': Completer<void>(),
      'second': Completer<void>(),
      'late': Completer<void>(),
    };
    final started = <String>[];
    final closePolicies = <bool>[];
    controller.onBeforeRemove = (tab, closeSession) async {
      closePolicies.add(closeSession);
      started.add(tab.key);
      await retirements[tab.key]!.future;
    };
    _addWithoutSelection(controller, _tab('first'));
    _addWithoutSelection(controller, _tab('second'));

    final close = controller.closeAll();
    await tester.pump();

    expect(started, unorderedEquals(['first', 'second']));
    expect(controller.length, 2);
    _addWithoutSelection(controller, _tab('late'));

    retirements['first']!.complete();
    await tester.pump();
    expect(controller.length, 3);

    retirements['second']!.complete();
    await tester.pump();
    expect(started, unorderedEquals(['first', 'second', 'late']));
    expect(controller.length, 1);

    retirements['late']!.complete();
    await close;
    expect(controller.length, 0);
    expect(closePolicies, everyElement(isTrue));
  });

  testWidgets('delayed close cannot remove a replacement with the same key',
      (tester) async {
    final controller = DesktopTabController(
      tabType: DesktopTabType.remoteScreen,
    );
    final retirement = Completer<void>();
    controller.onRemoved = (_, __) {};
    controller.onBeforeRemove = (_, __) => retirement.future;
    final original = _tab('peer');
    final replacement = _tab('peer');
    _addWithoutSelection(controller, original);

    final close = controller.closeBy('peer');
    await tester.pump();
    controller.remove(0);
    _addWithoutSelection(controller, replacement);
    retirement.complete();
    await close;

    expect(controller.length, 1);
    expect(identical(controller.state.value.tabs.single, replacement), isTrue);
  });
}

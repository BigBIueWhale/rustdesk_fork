import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart' show SessionID;
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/pages/file_manager_page.dart';
import 'package:flutter_hbb/desktop/widgets/list_search_action_listener.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:uuid/uuid.dart';

class _Binding implements RustdeskImpl {
  @override
  dynamic noSuchMethod(Invocation invocation) {
    switch (invocation.memberName) {
      case #translate:
        return invocation.namedArguments[#name] as String;
      case #getDoubleClickTime:
        return 500;
      case #mainGetLocalOption:
        return '';
      case #sessionGetPlatform:
        return Future<String>.value('Linux');
      default:
        throw StateError('Unexpected native operation: ${invocation.memberName}');
    }
  }
}

class _Session implements FFI {
  @override
  final SessionID sessionId = const Uuid().v4obj();
  bool current = true;
  @override
  bool isCurrentSession(SessionID id) => current && id == sessionId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _View {
  _View({this.local = true});
  final bool local;
  final session = _Session();
  final scope = MouseFocusScope.none.obs;
  late final fetcher = FileFetcher(() => session.sessionId,
      requests: FileFetcherRequests(
        readDirectory: (_, __, ___) async => throw StateError('unexpected listing'),
        readEmptyDirectories: (_, __, ___) async => throw StateError('unexpected listing'),
        readDirectoryTree: (_, __, ___, ____, _____) async => throw StateError('unexpected listing'),
      ));
  late final controller = FileController(
    isLocal: local,
    getSessionID: () => session.sessionId,
    getDialogManager: () => null,
    isCurrentSession: session.isCurrentSession,
    getPeerPlatform: () => 'Linux',
    comparePeerVersion: (_) => 1,
    jobController: JobController(() => session.sessionId, () => null,
        isCurrentSession: session.isCurrentSession),
    fileFetcher: fetcher,
    getOtherSideDirectoryData: () => DirectoryData(FileDirectory(), DirectoryOptions()),
    translateText: (text) => text,
  );

  void publish(List<String> names, {String path = '/files'}) {
    controller.directory.value = FileDirectory()
      ..path = path
      ..entries = names.map((name) => Entry()
        ..name = name
        ..path = '$path/$name').toList();
  }

  List<String> get selected => controller.selectedItems.items.map((e) => e.name).toList();
  ListSearchActionListener search(WidgetTester tester) =>
      tester.widget<ListSearchActionListener>(find.byType(ListSearchActionListener));
  ScrollController scroll(WidgetTester tester) =>
      tester.widget<ListView>(find.byType(ListView)).controller!;

  Future<void> show(WidgetTester tester, List<String> names) async {
    publish(names);
    addTearDown(() async {
      await tester.pumpWidget(const SizedBox.shrink());
      fetcher.cancelPending();
      await tester.pump(const Duration(milliseconds: 500));
    });
    await tester.pumpWidget(MaterialApp(home: Scaffold(body:
      FileManagerView(controller, session, scope, session.sessionId))));
    await tester.pumpAndSettle();
    await focus(tester);
  }

  Future<void> focus(WidgetTester tester) async {
    search(tester).node.requestFocus();
    await tester.pump();
    expect(search(tester).node.hasPrimaryFocus, isTrue);
  }

  Future<void> filter(WidgetTester tester, String value) async {
    await tester.tap(find.byTooltip('Search'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), value);
    await tester.pumpAndSettle();
    await focus(tester);
  }

  Future<void> type(WidgetTester tester, String character) async {
    await tester.sendKeyEvent(LogicalKeyboardKey.keyA, character: character);
    await tester.pump();
  }
}

void main() {
  setUp(() => installFileSearchProbeBinding(_Binding()));

  testWidgets('file search selects only visible entries in both panes', (tester) async {
    for (final local in [true, false]) {
      final view = _View(local: local);
      await view.show(tester, ['alpha-hidden', 'alpha-keep', 'beta-keep']);
      await view.filter(tester, 'keep');
      expect(find.byKey(const ValueKey('alpha-hidden')), findsNothing);
      await view.type(tester, 'a');
      expect(view.selected, ['alpha-keep']);
      expect(find.byKey(const ValueKey('alpha-keep')).hitTestable(), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('file search uses the filtered row index for scrolling', (tester) async {
    final view = _View();
    await view.show(tester, [
      for (var i = 0; i < 80; i++) 'hidden-$i',
      'alpha-keep', 'beta-keep', 'target-keep',
      for (var i = 0; i < 40; i++) 'visible-keep-$i',
    ]);
    await view.filter(tester, 'keep');
    await view.type(tester, 't');
    expect(view.selected, ['target-keep']);
    expect(view.scroll(tester).offset, 2 * kDesktopFileTransferRowHeight);
    expect(find.byKey(const ValueKey('target-keep')).hitTestable(), findsOneWidget);
  });

  testWidgets('file search follows directory replacement without parent rebuild', (tester) async {
    final view = _View(local: false);
    await view.show(tester, ['alpha-old']);
    view.publish(['beta-new'], path: '/replacement');
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('beta-new')), findsOneWidget);
    await view.type(tester, 'b');
    expect(view.selected, ['beta-new']);
  });

  testWidgets('file search cycles current visible rows and wraps', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha-hidden', 'alpha-keep', 'alpine-hidden', 'alpine-keep']);
    await view.filter(tester, 'keep');
    for (final expected in ['alpha-keep', 'alpine-keep', 'alpha-keep']) {
      await view.type(tester, 'a');
      expect(view.selected, [expected]);
    }
  });

  testWidgets('file search restarts after its selected row disappears', (tester) async {
    final view = _View(local: false);
    await view.show(tester, ['alpha-old']);
    await view.type(tester, 'a');
    expect(view.selected, ['alpha-old']);
    view.publish(['alpha-new']);
    await tester.pumpAndSettle();
    await view.type(tester, 'a');
    expect(view.selected, ['alpha-new']);
  });

  testWidgets('file search reflects a new visible row order', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha', 'alpine']);
    view.controller.directory.value.entries =
        view.controller.directory.value.entries.reversed.toList();
    view.controller.directory.refresh();
    await tester.pumpAndSettle();
    await view.type(tester, 'a');
    expect(view.selected, ['alpine']);
  });

  testWidgets('file search repeats Unicode graphemes', (tester) async {
    final view = _View();
    await view.show(tester, ['😀-one', '😀-two']);
    for (final expected in ['😀-one', '😀-two', '😀-one']) {
      await view.type(tester, '😀');
      expect(tester.takeException(), isNull);
      expect(view.selected, [expected]);
    }
  });

  testWidgets('file search repeats after multi-selection', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha', 'alpine', 'beta']);
    await view.type(tester, 'a');
    view.controller.selectedItems.add(view.controller.directory.value.entries.last);
    await view.type(tester, 'a');
    expect(tester.takeException(), isNull);
    expect(view.selected, ['alpine']);
  });

  testWidgets('file search retired callbacks do not alter current selection', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha', 'beta']);
    final old = view.search(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    view.controller.selectedItems.add(view.controller.directory.value.entries.last);
    expect(() => old.onSearch('a'), returnsNormally);
    expect(() => old.onNext('b'), returnsNormally);
    expect(view.selected, ['beta']);
  });

  testWidgets('file search retired sessions ignore both callbacks', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha', 'beta']);
    final old = view.search(tester);
    view.controller.selectedItems.add(view.controller.directory.value.entries.last);
    view.session.current = false;
    old.onSearch('a');
    old.onNext('b');
    expect(view.selected, ['beta']);
    expect(view.scroll(tester).offset, 0);
  });

  testWidgets('file search missing matches and empty listings clear selection', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha']);
    await view.type(tester, 'a');
    await view.type(tester, 'z');
    expect(view.selected, isEmpty);
    view.publish([]);
    await tester.pumpAndSettle();
    await view.type(tester, 'x');
    expect(view.selected, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('file search preserves unfiltered prefix and repeat behavior', (tester) async {
    final view = _View();
    await view.show(tester, ['alpha', 'alpine', 'beta']);
    for (final (character, expected) in [('A', 'alpha'), ('a', 'alpine'), ('l', 'alpha')]) {
      await view.type(tester, character);
      expect(view.selected, [expected]);
    }
  });
}

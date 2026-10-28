import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart' show MyTheme, SessionID;
import 'package:flutter_hbb/desktop/pages/file_manager_page.dart';
import 'package:flutter_hbb/desktop/widgets/dragable_divider.dart';
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
  @override
  bool isCurrentSession(SessionID id) => id == sessionId;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _View {
  _View(this.direction, {this.local = true});
  final TextDirection direction;
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

  Future<void> show(WidgetTester tester) async {
    controller.directory.value = FileDirectory()
      ..path = '/files'
      ..entries = [Entry()
        ..entryType = 4
        ..name = 'alpha'
        ..path = '/files/alpha'
        ..size = 123];
    addTearDown(() async {
      await tester.pumpWidget(const SizedBox.shrink());
      fetcher.cancelPending();
      await tester.pump(const Duration(milliseconds: 500));
    });
    await tester.pumpWidget(MaterialApp(
      theme: MyTheme.lightTheme,
      builder: (_, child) => Directionality(textDirection: direction, child: child!),
      home: Scaffold(body: FileManagerView(controller, session, scope, session.sessionId)),
    ));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  }

  Finder divider(int index) => find.byType(DraggableDivider).at(index);
  Finder header(String name) => find.ancestor(of: find.text(name),
      matching: find.byType(InkWell)).first;
  double width(WidgetTester tester, String name) => tester.getSize(header(name)).width;

  Future<void> drag(WidgetTester tester, int index, double growth) async {
    final pointer = await tester.startGesture(tester.getCenter(divider(index)),
        kind: PointerDeviceKind.mouse);
    await pointer.moveBy(Offset(direction == TextDirection.rtl ? -growth : growth, 0));
    await tester.pump();
    await pointer.up();
    await pointer.removePointer();
    await tester.pump();
    expect(tester.takeException(), isNull);
  }

  Future<void> focus(WidgetTester tester, int index) async {
    final target = tester.widget<DraggableDivider>(divider(index));
    // Traverse through the real header controls, without requesting a private node.
    for (var i = 0; i < 24; i++) {
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pump();
      final context = FocusManager.instance.primaryFocus?.context;
      if (context?.findAncestorWidgetOfExactType<DraggableDivider>() == target) return;
    }
    fail('column divider was not reachable by Tab');
  }
}

void main() {
  setUp(() => installFileColumnsProbeBinding(_Binding()));

  for (final direction in TextDirection.values) {
    for (final local in [true, false]) {
      testWidgets('file columns ${direction.name} ${local ? 'local' : 'remote'} uses visible Size width',
          (tester) async {
        final view = _View(direction, local: local);
        await view.show(tester);
        final before = view.width(tester, 'Modified');
        final sizeBefore = view.width(tester, 'Size');
        expect(sizeBefore, greaterThan(200));
        await view.drag(tester, 1, 90);
        expect(view.width(tester, 'Modified'), closeTo(before + 90, 0.01));
        expect(view.width(tester, 'Size'), closeTo(sizeBefore - 90, 0.01));
      });
    }

    testWidgets('file columns ${direction.name} first divider clamps both adjacent widths',
        (tester) async {
      final view = _View(direction);
      await view.show(tester);
      final total = view.width(tester, 'Name') + view.width(tester, 'Modified');
      final minimum = view.width(tester, 'Name') / 3;
      final size = view.width(tester, 'Size');
      await view.drag(tester, 0, 1000);
      expect(view.width(tester, 'Modified'), closeTo(minimum, 0.01));
      expect(view.width(tester, 'Name'), closeTo(total - minimum, 0.01));
      await view.drag(tester, 0, -1000);
      expect(view.width(tester, 'Name'), closeTo(minimum, 0.01));
      expect(view.width(tester, 'Modified'), closeTo(total - minimum, 0.01));
      expect(view.width(tester, 'Size'), closeTo(size, 0.01));
    });

    testWidgets('file columns ${direction.name} last divider clamps rendered Size width',
        (tester) async {
      final view = _View(direction);
      await view.show(tester);
      final name = view.width(tester, 'Name');
      final total = view.width(tester, 'Modified') + view.width(tester, 'Size');
      final minimum = name / 3;
      await view.drag(tester, 1, 1000);
      expect(view.width(tester, 'Size'), closeTo(minimum, 0.01));
      expect(view.width(tester, 'Modified'), closeTo(total - minimum, 0.01));
      await view.drag(tester, 1, -1000);
      expect(view.width(tester, 'Modified'), closeTo(minimum, 0.01));
      expect(view.width(tester, 'Size'), closeTo(total - minimum, 0.01));
      expect(view.width(tester, 'Name'), name);
    });

    testWidgets('file columns ${direction.name} keyboard reaches the visible width limit',
        (tester) async {
      final view = _View(direction);
      await view.show(tester);
      final before = view.width(tester, 'Modified');
      final sizeBefore = view.width(tester, 'Size');
      await view.focus(tester, 1);
      final key = direction == TextDirection.rtl
          ? LogicalKeyboardKey.arrowLeft : LogicalKeyboardKey.arrowRight;
      await tester.sendKeyDownEvent(key);
      for (var i = 0; i < 15; i++) {
        await tester.sendKeyRepeatEvent(key);
      }
      await tester.sendKeyUpEvent(key);
      await tester.pump();
      expect(view.width(tester, 'Modified'), closeTo(before + 128, 0.01));
      expect(view.width(tester, 'Size'), closeTo(sizeBefore - 128, 0.01));
      expect(view.controller.selectedItems.items, isEmpty);
    });

    testWidgets('file columns ${direction.name} header and row boundaries agree',
        (tester) async {
      final view = _View(direction);
      await view.show(tester);
      final cells = find.descendant(of: find.byKey(const ValueKey('alpha')),
          matching: find.byWidgetPredicate((w) => w is GestureDetector && w.onTap != null));
      expect(cells, findsNWidgets(3));
      for (final (i, name) in ['Name', 'Modified', 'Size'].indexed) {
        final header = tester.getRect(view.header(name));
        final cell = tester.getRect(cells.at(i));
        expect(cell.left, closeTo(header.left, 0.01), reason: name);
        expect(cell.width, closeTo(header.width, 0.01), reason: name);
      }
    });
  }

  testWidgets('file columns resizing the window uses the current rendered capacity',
      (tester) async {
    final view = _View(TextDirection.ltr);
    await view.show(tester);
    await tester.binding.setSurfaceSize(const Size(1000, 700));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpAndSettle();
    final before = view.width(tester, 'Modified');
    final sizeBefore = view.width(tester, 'Size');
    await view.drag(tester, 1, 160);
    expect(view.width(tester, 'Modified'), closeTo(before + 160, 0.01));
    expect(view.width(tester, 'Size'), closeTo(sizeBefore - 160, 0.01));
  });
}

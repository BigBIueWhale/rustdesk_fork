import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/pages/desktop_setting_page.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

class _NativeSettings implements RustdeskImpl {
  final unexpected = <Symbol>[];
  String recordingDirectory = '/work/nonexistent-settings-recordings';
  final recordingWrites = <String>[];
  Future<void> Function(String)? saveRecordingDirectory;

  @override
  dynamic noSuchMethod(Invocation call) {
    final key = call.namedArguments[#key];
    switch (call.memberName) {
      case #translate:
        return call.namedArguments[#name];
      case #isIncomingOnly:
      case #isOutgoingOnly:
      case #isDisableSettings:
      case #isCustomClient:
      case #mainIsInstalled:
      case #mainIsOptionFixed:
      case #mainAudioSupportLoopback:
      case #mainGetUseTextureRender:
        return false;
      case #mainGetBuildinOption:
      case #mainGetLocalOption:
        return '';
      case #mainGetOptionSync:
        if (key == 'access-mode') return 'full';
        if (key == 'verification-method') return 'use-permanent-password';
        return '';
      case #mainGetUserDefaultOption:
        return const {
              'view-style': 'original',
              'scroll-style': 'scrollbar',
              'image-quality': 'balanced',
              'codec-preference': 'auto',
            }[key] ??
            '';
      case #mainSupportedPrivacyModeImpls:
        return '[]';
      case #mainVideoSaveDirectory:
        return recordingDirectory;
      case #mainSetLocalOption:
        if (key != 'video-save-directory') break;
        final value = call.namedArguments[#value] as String;
        recordingWrites.add(value);
        return Future<void>.sync(() async {
          await saveRecordingDirectory?.call(value);
          recordingDirectory = value;
        });
      case #mainSupportRemoveWallpaper:
        return Future<bool>.value(false);
      case #mainGetSoundInputs:
        return Future<List<String>>.value(['Mic A']);
      case #mainGetLangs:
        return Future<String>.value('[["en","English"]]');
      case #mainGetOption:
        return Future<String>.value('');
      case #mainGetCommon:
        if (key == 'permanent-password-writable') {
          return Future<String>.value('true');
        }
        break;
      case #mainGetLicense:
        return Future<String>.value(List.filled(40, 'License text').join('\n'));
      case #mainGetVersion:
        return Future<String>.value('1.0.0');
      case #mainGetBuildDate:
        return Future<String>.value('2026-10-26');
    }
    unexpected.add(call.memberName);
    throw UnsupportedError('Unexpected settings native call: ${call.memberName}');
  }
}

class _DirectoryPicker extends FilePicker {
  final requests = <(String?, Completer<String?>)>[];

  @override
  Future<String?> getDirectoryPath({
    String? dialogTitle,
    bool lockParentWindow = false,
    String? initialDirectory,
  }) {
    final result = Completer<String?>();
    requests.add((initialDirectory, result));
    return result.future;
  }

  void cancelPending() {
    for (final request in requests) {
      if (!request.$2.isCompleted) request.$2.complete(null);
    }
  }
}

ElevatedButton _directoryButton(WidgetTester tester) =>
    tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Change'));

Future<Object?> _pressDirectory(VoidCallback callback) async {
  try {
    await (callback as dynamic)();
    return null;
  } catch (error) {
    return error;
  }
}

Future<void> _mountRecording(WidgetTester tester) async {
  await _mount(tester, SettingsTabKey.general);
  final button = find.widgetWithText(ElevatedButton, 'Change');
  final scrollable = find.descendant(
      of: find.byWidgetPredicate((widget) => widget.runtimeType.toString() == '_General'),
      matching: find.byType(Scrollable));
  for (var i = 0; i < 12 && button.evaluate().isEmpty; i++) {
    await tester.drag(scrollable, const Offset(0, -150));
    await _settle(tester);
  }
  await tester.ensureVisible(button);
  await _settle(tester);
}

class _SettingsParent implements FFI {
  @override
  late final ServerModel serverModel = ServerModel(WeakReference(this));

  @override
  dynamic noSuchMethod(Invocation call) =>
      throw UnsupportedError('Unexpected settings parent call: ${call.memberName}');
}

class _Tabs implements DesktopTabController {
  final requests = <TabInfo>[];

  @override
  void add(TabInfo tab) => requests.add(tab);

  @override
  dynamic noSuchMethod(Invocation call) =>
      throw UnsupportedError('Unexpected desktop tab call: ${call.memberName}');
}

Future<void> _settle(WidgetTester tester) async {
  await tester.pump();
  await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
  await tester.pumpAndSettle();
}

Future<void> _mount(WidgetTester tester, SettingsTabKey tab) async {
  await tester.binding.setSurfaceSize(const Size(1000, 420));
  await tester.pumpWidget(MaterialApp(
    theme: MyTheme.lightTheme,
    home: DesktopSettingPage(key: UniqueKey(), initialTabkey: tab),
  ));
  await _settle(tester);
}

PageController _controller() =>
    Get.find<PageController>(tag: 'settingPageController');

void _expectSelection(WidgetTester tester, SettingsTabKey tab) {
  final dynamic state = tester.state(find.byType(DesktopSettingPage));
  expect(state.selectedTab.value, tab);
  expect(_controller().page, DesktopSettingPage.tabKeys.indexOf(tab).toDouble());
  expect(tester.takeException(), isNull);
}

void main() {
  late _NativeSettings native;
  late _SettingsParent parent;
  late _Tabs tabs;
  late FilePicker previousPicker;
  late _DirectoryPicker picker;

  setUp(() {
    Get.testMode = true;
    isTest = true;
    native = _NativeSettings();
    parent = _SettingsParent();
    tabs = _Tabs();
    previousPicker = FilePicker.platform;
    picker = _DirectoryPicker();
    FilePicker.platform = picker;
    installSettingsProbeBinding(native);
    installSettingsProbeParent(parent);
    Get.put<DesktopTabController>(tabs);
  });

  tearDown(() {
    picker.cancelPending();
    FilePicker.platform = previousPicker;
    parent.serverModel.serverPasswd.dispose();
    parent.serverModel.tabController.state.value.pageController.dispose();
    parent.serverModel.tabController.state.value.scrollController.dispose();
    parent.serverModel.controller.dispose();
    parent.serverModel.dispose();
    Get.reset();
    expect(native.unexpected, isEmpty);
    isTest = false;
  });

  testWidgets('recording directory change admits one picker and one save',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    native.recordingDirectory = '/work';
    final write = Completer<void>();
    native.saveRecordingDirectory = (_) => write.future;
    await _mountRecording(tester);
    final press = _directoryButton(tester).onPressed!;
    final first = _pressDirectory(press);
    final duplicate = _pressDirectory(press);
    await _settle(tester);
    final beforeSelection = picker.requests.length;
    expect(picker.requests.first.$1, '/work');
    picker.requests.first.$2.complete('/work/chosen-recordings');
    picker.cancelPending();
    await _settle(tester);
    final disabledDuringSave = _directoryButton(tester).onPressed == null;
    final duringSave = _pressDirectory(press);
    await _settle(tester);
    final afterDuplicate = picker.requests.length;
    picker.cancelPending();
    write.complete();
    expect(await first, isNull);
    expect(await duplicate, isNull);
    expect(await duringSave, isNull);
    await _settle(tester);
    expect(beforeSelection, 1);
    expect(afterDuplicate, 1);
    expect(disabledDuringSave, isTrue);
    expect(native.recordingWrites, ['/work/chosen-recordings']);
    expect(find.text('/work/chosen-recordings'), findsOneWidget);
    expect(_directoryButton(tester).onPressed, isNotNull);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
  });

  testWidgets('recording directory closed page cannot apply a picker result',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _mountRecording(tester);
    final press = _directoryButton(tester).onPressed!;
    final pending = _pressDirectory(press);
    await _settle(tester);
    expect(picker.requests.single.$1, isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    picker.requests.single.$2.complete('/work/stale-recordings');
    expect(await pending, isNull);
    final obsolete = _pressDirectory(press);
    await _settle(tester);
    final calls = picker.requests.length;
    picker.cancelPending();
    expect(await obsolete, isNull);
    expect(calls, 1);
    expect(native.recordingWrites, isEmpty);
    await _mountRecording(tester);
    expect(find.text('/work/nonexistent-settings-recordings'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
  });

  testWidgets('recording directory cancellation and picker failure allow retry',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _mountRecording(tester);
    final cancelled = _pressDirectory(_directoryButton(tester).onPressed!);
    await _settle(tester);
    picker.requests.last.$2.complete(null);
    expect(await cancelled, isNull);
    await _settle(tester);
    expect(native.recordingWrites, isEmpty);
    expect(find.text('Failed'), findsNothing);
    final failed = _pressDirectory(_directoryButton(tester).onPressed!);
    await _settle(tester);
    picker.requests.last.$2.completeError(StateError('picker unavailable'));
    final failure = await failed;
    await _settle(tester);
    expect(failure, isNull);
    expect(find.text('Failed'), findsOneWidget);
    expect(native.recordingWrites, isEmpty);
    final retry = _pressDirectory(_directoryButton(tester).onPressed!);
    await _settle(tester);
    picker.requests.last.$2.complete('/work/retry-recordings');
    expect(await retry, isNull);
    await _settle(tester);
    expect(native.recordingWrites, ['/work/retry-recordings']);
    expect(find.text('/work/retry-recordings'), findsOneWidget);
    expect(find.text('Failed'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
  });

  testWidgets('recording directory save failure retries and retires after close',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final writes = <Completer<void>>[];
    native.saveRecordingDirectory = (_) {
      final write = Completer<void>();
      writes.add(write);
      return write.future;
    };
    await _mountRecording(tester);
    final failed = _pressDirectory(_directoryButton(tester).onPressed!);
    await _settle(tester);
    picker.requests.last.$2.complete('/work/failed-recordings');
    await _settle(tester);
    writes.single.completeError(StateError('write refused'));
    expect(await failed, isNull);
    await _settle(tester);
    expect(find.text('Failed'), findsOneWidget);
    expect(find.text('/work/nonexistent-settings-recordings'), findsOneWidget);
    final retry = _pressDirectory(_directoryButton(tester).onPressed!);
    await _settle(tester);
    picker.requests.last.$2.complete('/work/failed-recordings');
    await _settle(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    writes.last.completeError(StateError('write refused after close'));
    expect(await retry, isNull);
    await _settle(tester);
    expect(native.recordingWrites,
        ['/work/failed-recordings', '/work/failed-recordings']);
    expect(find.text('Failed'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('settings sidebar and external requests select the current page',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _mount(tester, SettingsTabKey.general);
    _expectSelection(tester, SettingsTabKey.general);
    for (final entry in {
      'Display': SettingsTabKey.display,
      'Security': SettingsTabKey.safety,
      'About': SettingsTabKey.about,
      'General': SettingsTabKey.general,
    }.entries) {
      await tester.tap(find.descendant(
        of: find.byType(ListView).first,
        matching: find.text(entry.key),
      ));
      await _settle(tester);
      _expectSelection(tester, entry.value);
    }
    DesktopSettingPage.switch2page(SettingsTabKey.display);
    await _settle(tester);
    _expectSelection(tester, SettingsTabKey.display);
    expect(tabs.requests, hasLength(1));
    expect((tabs.requests.single.page as DesktopSettingPage).initialTabkey,
        SettingsTabKey.display);
    expect(find.text('Default View Style').hitTestable(), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('settings close and reopen retire the exact navigation owner',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final controllers = <PageController>[];
    for (final tab in SettingsTabKey.values) {
      await _mount(tester, tab);
      _expectSelection(tester, tab);
      final controller = _controller();
      expect(controllers, isNot(contains(controller)));
      controllers.add(controller);
      await tester.pumpWidget(const SizedBox.shrink());
      expect(Get.isRegistered<PageController>(tag: 'settingPageController'),
          isFalse);
      expect(Get.isRegistered<Rx<SettingsTabKey>>(tag: 'settingPageTabKey'),
          isFalse);
      expect(() => controller.addListener(() {}), throwsFlutterError);
      expect(tester.takeException(), isNull);
    }
  });

  for (final entry in {
    SettingsTabKey.general: '_General',
    SettingsTabKey.safety: '_Safety',
    SettingsTabKey.display: '_Display',
    SettingsTabKey.about: '_About',
  }.entries) {
    testWidgets(
        'settings ${entry.key.name} scrolling survives rebuilds and retires on close',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await _mount(tester, entry.key);
      final section = find.byWidgetPredicate(
          (widget) => widget.runtimeType.toString() == entry.value);
      final scrollable = find.descendant(
          of: section, matching: find.byType(Scrollable));
      final scrollState = tester.state<ScrollableState>(scrollable);
      final position = scrollState.position;
      final controller = scrollState.widget.controller;
      expect(position.maxScrollExtent, greaterThan(160));
      position.jumpTo(160);
      await tester.pump();
      for (var i = 0; i < 3; i++) {
        tester.state(section).setState(() {});
        await _settle(tester);
        expect(tester.state<ScrollableState>(scrollable).position, same(position));
        expect(position.pixels, closeTo(160, 0.1));
      }
      await tester.pumpWidget(const SizedBox.shrink());
      expect(() => position.addListener(() {}), throwsFlutterError);
      if (controller != null) {
        expect(() => controller.addListener(() {}), throwsFlutterError);
      }
      expect(tester.takeException(), isNull);
    });
  }
}

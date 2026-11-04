import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dbus/dbus.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/mobile/pages/settings_page.dart' as mobile;
import 'package:flutter_hbb/desktop/pages/desktop_home_page.dart';
import 'package:flutter_hbb/desktop/pages/desktop_setting_page.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/main.dart' as application;
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/native_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:settings_ui/settings_ui.dart';
import 'package:wakelock_plus/wakelock_plus.dart';

// Drain asynchronous plugin calls between the explicitly held D-Bus replies.
Future<void> _settleWake() => Future<void>.delayed(Duration.zero);

class _WakeRemote extends DBusRemoteObject {
  _WakeRemote()
      : super(DBusClient(DBusAddress('unix:path=/nonexistent-wake-fixture')),
            name: 'org.freedesktop.ScreenSaver',
            path: DBusObjectPath('/org/freedesktop/ScreenSaver'));

  final calls = <String>[];
  final active = <int>{};
  int nextCookie = 1;
  Completer<void>? acquisition;
  Completer<void>? release;
  String? refuseNext;

  @override
  Future<DBusMethodSuccessResponse> callMethod(
      String? interface, String name, Iterable<DBusValue> values,
      {DBusSignature? replySignature, bool noReplyExpected = false,
      bool noAutoStart = false, bool allowInteractiveAuthorization = false}) async {
    expectSync(interface, 'org.freedesktop.ScreenSaver');
    calls.add(name);
    if (refuseNext == name) {
      refuseNext = null;
      throw DBusMethodResponseException(
          DBusMethodErrorResponse.failed('wake-fixture refusal'));
    }
    if (name == 'Inhibit') {
      expectSync(values.map((v) => v.asString()).toList(), ['RustDesk', 'wakelock']);
      expectSync(replySignature, DBusSignature.uint32);
      final cookie = nextCookie++;
      active.add(cookie);
      await acquisition?.future;
      return DBusMethodSuccessResponse([DBusUint32(cookie)]);
    }
    expectSync(name, 'UnInhibit');
    expectSync(replySignature, DBusSignature.empty);
    final cookie = values.single.asUint32();
    await release?.future;
    expectSync(active.remove(cookie), isTrue, reason: 'release must own its exact cookie');
    return DBusMethodSuccessResponse([]);
  }

  void finishPending() {
    for (final pending in [acquisition, release]) {
      if (pending != null && !pending.isCompleted) pending.complete();
    }
  }
}

const _mobileBooleans = [
  (key: kOptionEnableAbr, label: 'Adaptive bitrate', local: false,
    initial: true, before: '', after: 'N'),
  (key: kOptionAllowAutoDisconnect, label: 'auto_disconnect_option_tip', local: false,
    initial: false, before: '', after: 'Y'),
  (key: kOptionAllowAutoRecordIncoming,
    label: 'Automatically record incoming sessions', local: false,
    initial: false, before: '', after: 'Y'),
  (key: kOptionAllowAutoRecordOutgoing,
    label: 'Automatically record outgoing sessions', local: true,
    initial: false, before: '', after: 'Y'),
  (key: kOptionEnableShowTerminalExtraKeys, label: 'Show terminal extra keys', local: true,
    initial: true, before: '', after: 'N'),
];

class _NativeSettings implements RustdeskImpl {
  final unexpected = <Symbol>[];
  final translations = <String, String>{};
  int versionReads = 0;
  int buildDateReads = 0;
  Future<String> Function()? readVersion;
  Future<String> Function()? readBuildDate;
  String theme = 'light';
  final themeWrites = <String>[];
  int themeNotifications = 0;
  Future<String> Function(String)? saveTheme;
  Future<void> Function()? notifyTheme;
  String recordingDirectory = '/work/nonexistent-settings-recordings';
  final recordingWrites = <String>[];
  Future<void> Function(String)? saveRecordingDirectory;
  String keepAwake = 'Y';
  final keepAwakeWrites = <String>[];
  Future<String> Function(String)? saveKeepAwake;
  bool refuseKeepAwakeRead = false;
  final options = {for (final option in _mobileBooleans) option.key: option.before};
  final optionWrites = <(bool, String, String)>[];
  final optionReaders = <String, int>{};
  final saveOptions = <String, Future<String> Function(String)>{};
  final refuseOptionReads = <String>{};
  final fixedOptions = <String>{};

  String readOption(String key) {
    optionReaders.update(key, (count) => count + 1, ifAbsent: () => 1);
    if (refuseOptionReads.contains(key)) throw StateError('option readback unavailable');
    return options[key]!;
  }

  Future<void> writeOption(bool local, String key, String value) async {
    optionWrites.add((local, key, value));
    options[key] = await saveOptions[key]?.call(value) ?? value;
  }

  @override
  dynamic noSuchMethod(Invocation call) {
    final key = call.namedArguments[#key];
    switch (call.memberName) {
      case #translate:
        return translations[call.namedArguments[#name]] ?? call.namedArguments[#name];
      case #isIncomingOnly:
      case #isOutgoingOnly:
      case #isDisableSettings:
      case #isCustomClient:
      case #mainIsInstalled:
      case #mainAudioSupportLoopback:
      case #mainGetUseTextureRender:
      case #isSelinuxEnforcing:
      case #mainCurrentIsWayland:
      case #mainIsLoginWayland:
        return false;
      case #mainIsOptionFixed:
        return fixedOptions.contains(key);
      case #mainGetBuildinOption:
        return '';
      case #mainGetLocalOption:
        if (key == kCommConfKeyTheme) return theme;
        if (key == kOptionKeepAwakeDuringOutgoingSessions) {
          if (refuseKeepAwakeRead) throw StateError('readback unavailable');
          return keepAwake;
        }
        if (options.containsKey(key)) return readOption(key as String);
        return '';
      case #mainGetOptionSync:
        if (options.containsKey(key)) return readOption(key as String);
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
        if (key == kCommConfKeyTheme) {
          final value = call.namedArguments[#value] as String;
          themeWrites.add(value);
          return Future<void>.sync(() async {
            theme = await saveTheme?.call(value) ?? value;
          });
        }
        if (key == kOptionKeepAwakeDuringOutgoingSessions) {
          final value = call.namedArguments[#value] as String;
          keepAwakeWrites.add(value);
          return Future<void>.sync(() async {
            keepAwake = await saveKeepAwake?.call(value) ?? value;
          });
        }
        if (options.containsKey(key)) {
          return writeOption(true, key as String, call.namedArguments[#value] as String);
        }
        if (key != 'video-save-directory') break;
        final value = call.namedArguments[#value] as String;
        recordingWrites.add(value);
        return Future<void>.sync(() async {
          await saveRecordingDirectory?.call(value);
          recordingDirectory = value;
        });
      case #mainSetOption:
        if (!options.containsKey(key)) break;
        return writeOption(false, key as String, call.namedArguments[#value] as String);
      case #mainSupportRemoveWallpaper:
        return Future<bool>.value(false);
      case #mainNotifyThemeChanged:
        themeNotifications++;
        return Future<void>.sync(() async => await notifyTheme?.call());
      case #mainGetSoundInputs:
        return Future<List<SoundInput>>.value([
          SoundInput(id: 'Mic A', label: 'Mic A'),
        ]);
      case #mainGetLangs:
        return Future<String>.value('[["en","English"]]');
      case #mainGetOption:
        if (options.containsKey(key)) {
          return Future<String>.sync(() => readOption(key as String));
        }
        return Future<String>.value('');
      case #mainGetCommon:
        if (key == 'permanent-password-writable') {
          return Future<String>.value('true');
        }
        break;
      case #mainGetVersion:
        versionReads++;
        return readVersion?.call() ?? Future<String>.value('1.0.0');
      case #mainGetBuildDate:
        buildDateReads++;
        return readBuildDate?.call() ?? Future<String>.value('2026-10-26');
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
  Future<bool> invokeMethod(String method, [dynamic arguments]) async {
    expectSync(method, 'enable_soft_keyboard');
    expectSync(arguments, isTrue);
    return true;
  }

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

class _MobileSettingsModel with ChangeNotifier implements FfiModel {
  @override
  dynamic noSuchMethod(Invocation call) =>
      throw UnsupportedError('Unexpected mobile model call: ${call.memberName}');
}

Finder _keepAwakeTile() => find.ancestor(
    of: find.text('keep-awake-during-outgoing-sessions-label'),
    matching: find.byType(SettingsTile));

Finder _booleanTile(String label) => find.ancestor(
    of: find.text(label), matching: find.byType(SettingsTile));

Future<void> _showBoolean(WidgetTester tester, String label) async {
  final scrollable = find.descendant(
      of: find.byType(SettingsList), matching: find.byType(Scrollable)).first;
  tester.state<ScrollableState>(scrollable).position.jumpTo(0);
  await _settle(tester);
  for (var attempt = 0; attempt < 20 && _booleanTile(label).evaluate().isEmpty;
      attempt++) {
    await tester.drag(scrollable, const Offset(0, -180));
    await _settle(tester);
  }
  await tester.ensureVisible(_booleanTile(label));
  await _settle(tester);
}

void _mockLogo(WidgetTester tester) {
  // Branding is outside this settings probe; the application source is unchanged.
  tester.binding.defaultBinaryMessenger.setMockMessageHandler('flutter/assets',
      (message) async {
    final key = utf8.decode(message!.buffer.asUint8List(
        message.offsetInBytes, message.lengthInBytes));
    if (key == 'AssetManifest.bin') {
      return const StandardMessageCodec().encodeMessage(<String, Object>{});
    }
    if (key == 'assets/logo.png') {
      return ByteData.sublistView(base64Decode(
          'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='));
    }
    return null;
  });
}

Future<void> _mountMobile(WidgetTester tester, TargetPlatform platform) async {
  _mockLogo(tester);
  await tester.binding.setSurfaceSize(const Size(400, 600));
  await tester.pumpWidget(ChangeNotifierProvider<FfiModel>(
    create: (_) => _MobileSettingsModel(),
    child: MaterialApp(
      theme: MyTheme.lightTheme.copyWith(platform: platform),
      home: Scaffold(body: mobile.SettingsPage()),
    ),
  ));
  await _settle(tester);
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

Future<void> _mountToast(WidgetTester tester, {VoidCallback? onTap}) async {
  await tester.pumpWidget(MaterialApp(
    navigatorKey: globalKey,
    theme: MyTheme.lightTheme,
    home: Scaffold(body: GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: onTap,
      child: const SizedBox.expand(),
    )),
  ));
}

Future<void> _retireToast(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox.shrink());
  // Drain the unchanged-product baseline's obsolete toast timers too.
  await tester.pump(const Duration(minutes: 1));
}

PageController _controller() =>
    Get.find<PageController>(tag: 'settingPageController');

Future<void> _mountTheme(WidgetTester tester) async {
  desktopType = DesktopType.main;
  addTearDown(() {
    desktopType = null;
    return tester.binding.setSurfaceSize(null);
  });
  await tester.binding.setSurfaceSize(const Size(1000, 420));
  await tester.pumpWidget(GetMaterialApp(
    theme: MyTheme.lightTheme,
    darkTheme: MyTheme.darkTheme,
    home: DesktopSettingPage(initialTabkey: SettingsTabKey.general),
  ));
  await _settle(tester);
}

Radio<String> _themeRadio(WidgetTester tester, String value) =>
    tester.widget<Radio<String>>(find.byWidgetPredicate(
        (widget) => widget is Radio<String> && widget.value == value));

Future<OverlayDialogManager> _mountMobileTheme(WidgetTester tester) async {
  installSettingsProbeAndroid(true);
  final overlay = BlockableOverlayState();
  final manager = OverlayDialogManager();
  manager.setOverlayState(overlay);
  await tester.binding.setSurfaceSize(const Size(400, 600));
  await tester.pumpWidget(GetMaterialApp(
    navigatorKey: globalKey,
    theme: MyTheme.lightTheme,
    darkTheme: MyTheme.darkTheme,
    themeMode: MyTheme.getThemeModePreference(),
    home: Scaffold(body: BlockableOverlay(
      state: overlay, underlying: const SizedBox.expand(),
    )),
  ));
  mobile.showThemeSettings(manager);
  await _settle(tester);
  addTearDown(() async {
    manager.dismissAll();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 4));
    await tester.binding.setSurfaceSize(null);
  });
  return manager;
}

Finder _mobileThemeChoice(ThemeMode value) => find.byWidgetPredicate(
    (widget) => widget is RadioListTile<ThemeMode> && widget.value == value);

RadioListTile<ThemeMode> _mobileThemeRadio(WidgetTester tester, ThemeMode value) =>
    tester.widget<RadioListTile<ThemeMode>>(_mobileThemeChoice(value));

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

  List<String> macOSWindowChannel(WidgetTester tester,
      {Future<void> Function(String)? apply}) {
    installSettingsProbeMacOS();
    const channel = MethodChannel('org.rustdesk.rustdesk/host');
    final calls = <String>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel,
        (call) async {
      expectSync(call.method, 'setWindowTheme');
      final name = (call.arguments as Map)['themeName'] as String;
      expectSync(['light', 'dark', 'system'], contains(name));
      calls.add(name);
      await apply?.call(name);
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null));
    return calls;
  }

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
    installSettingsProbeAndroid(false);
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

  (_WakeRemote, WakelockPlusLinuxPlugin, List<UniqueKey>) wakeFixture() {
    PackageInfo.setMockInitialValues(appName: 'RustDesk', packageName: 'rustdesk',
        version: '1', buildNumber: '1', buildSignature: '');
    final remote = _WakeRemote();
    final plugin = WakelockPlusLinuxPlugin(object: remote);
    final previous = wakelockPlusPlatformInstance;
    wakelockPlusPlatformInstance = plugin;
    final keys = [UniqueKey(), UniqueKey()];
    addTearDown(() async {
      remote.finishPending();
      for (final key in keys) WakelockManager.disable(key);
      await _settleWake();
      await plugin.toggle(enable: false);
      // Retire only this double's remaining cookies after a failed assertion.
      for (final cookie in remote.active.toList()) {
        await remote.callMethod('org.freedesktop.ScreenSaver', 'UnInhibit',
            [DBusUint32(cookie)], replySignature: DBusSignature.empty);
      }
      await remote.client.close();
      wakelockPlusPlatformInstance = previous;
    });
    return (remote, plugin, keys);
  }

  test('settings wake lock ordinary owner releases its cookie', () async {
    final (remote, plugin, keys) = wakeFixture();
    WakelockManager.enable(keys.first);
    await _settleWake();
    expect(await plugin.enabled, isTrue);
    expect(remote.active, {1});
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(await plugin.enabled, isFalse);
    expect(remote.active, isEmpty);
    expect(remote.calls, ['Inhibit', 'UnInhibit']);
  });

  test('settings wake lock retains the remaining owner', () async {
    final (remote, plugin, keys) = wakeFixture();
    WakelockManager.enable(keys.first);
    WakelockManager.enable(keys.first);
    WakelockManager.enable(keys.last);
    await _settleWake();
    expect(remote.calls, ['Inhibit']);
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(await plugin.enabled, isTrue);
    expect(remote.active, {1});
    WakelockManager.disable(keys.last);
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'UnInhibit']);
    expect(remote.active, isEmpty);
  });

  test('settings wake lock respects disabled outgoing preference', () async {
    final (remote, plugin, keys) = wakeFixture();
    native.keepAwake = 'N';
    WakelockManager.enable(keys.first);
    await _settleWake();
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.calls, isEmpty);
    expect(await plugin.enabled, isFalse);
  });

  test('settings wake lock retirement waits for pending acquisition', () async {
    final (remote, plugin, keys) = wakeFixture();
    remote.acquisition = Completer<void>();
    WakelockManager.enable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit']);
    expect(remote.active, {1});
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit']);
    remote.acquisition!.complete();
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'UnInhibit']);
    expect(remote.active, isEmpty);
    expect(await plugin.enabled, isFalse);
  });

  test('settings wake lock replacement waits for pending release', () async {
    final (remote, plugin, keys) = wakeFixture();
    WakelockManager.enable(keys.first);
    await _settleWake();
    remote.release = Completer<void>();
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'UnInhibit']);
    WakelockManager.enable(keys.last);
    await _settleWake();
    final beforeReply = List<String>.of(remote.calls);
    remote.release!.complete();
    await _settleWake();
    expect(beforeReply, ['Inhibit', 'UnInhibit']);
    expect(remote.calls, ['Inhibit', 'UnInhibit', 'Inhibit']);
    expect(remote.active, {2});
    expect(await plugin.enabled, isTrue);
    WakelockManager.disable(keys.last);
    await _settleWake();
    expect(remote.active, isEmpty);
  });

  test('settings wake lock failed acquisition permits later retry', () async {
    final (remote, plugin, keys) = wakeFixture();
    remote.refuseNext = 'Inhibit';
    WakelockManager.enable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit']);
    expect(remote.active, isEmpty);
    expect(await plugin.enabled, isFalse);
    WakelockManager.enable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'Inhibit']);
    expect(remote.active, {1});
    expect(await plugin.enabled, isTrue);
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.active, isEmpty);
  });

  test('settings wake lock failed release retains its cookie for retry', () async {
    final (remote, plugin, keys) = wakeFixture();
    WakelockManager.enable(keys.first);
    await _settleWake();
    remote.refuseNext = 'UnInhibit';
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'UnInhibit']);
    expect(remote.active, {1});
    expect(await plugin.enabled, isTrue);
    WakelockManager.disable(keys.first);
    await _settleWake();
    expect(remote.calls, ['Inhibit', 'UnInhibit', 'UnInhibit']);
    expect(remote.active, isEmpty);
    expect(await plugin.enabled, isFalse);
  });

  for (final scale in [1.0, 1.5]) {
    testWidgets('desktop home pane scrolls all status text at scale $scale',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      _mockLogo(tester);
      // Render the actual pane builder without starting window/status services.
      // The fixture owns the unattached page State and its pane controller.
      final dynamic owner = const DesktopHomePage().createState();
      const status = 'Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLast line';
      owner.systemError = status;
      Future<void> mount() async {
        await tester.pumpWidget(MaterialApp(
          theme: MyTheme.lightTheme,
          home: MediaQuery(
            data: MediaQueryData(textScaler: TextScaler.linear(scale)),
            child: Material(child: Align(
              alignment: Alignment.topLeft,
              child: Builder(builder: (context) => owner.buildLeftPane(context)),
            )),
          ),
        ));
        await _settle(tester);
      }
      await tester.binding.setSurfaceSize(const Size(1000, 240));
      ScrollController? controller;
      try {
        await mount();
        final pane = find.byType(SingleChildScrollView);
        controller = tester.widget<SingleChildScrollView>(pane).controller!;
        expect(tester.takeException(), isNull);
        expect(controller.position.maxScrollExtent, greaterThan(80));
        expect(tester.getRect(find.text(status)).bottom,
            greaterThan(tester.getRect(pane).bottom));
        await tester.drag(pane, const Offset(0, -1000));
        await _settle(tester);
        final viewport = tester.getRect(pane);
        final message = tester.getRect(find.text(status));
        expect(controller.offset, greaterThan(0));
        expect(message.bottom, lessThanOrEqualTo(viewport.bottom + 0.1));
        expect(message.bottom, greaterThan(viewport.top));
        controller.jumpTo(40);
        await mount();
        expect(tester.widget<SingleChildScrollView>(pane).controller, same(controller));
        expect(controller.offset, closeTo(40, 0.1));
        await tester.binding.setSurfaceSize(const Size(1000, 280));
        await _settle(tester);
        expect(controller.offset, closeTo(40, 0.1));
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        controller?.dispose();
      }
    });
  }

  testWidgets('desktop home pane keeps fitting content visible without scrolling',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    _mockLogo(tester);
    final dynamic owner = const DesktopHomePage().createState();
    owner.systemError = 'Short status';
    await tester.binding.setSurfaceSize(const Size(1000, 900));
    Widget paneWidget() => MaterialApp(
      theme: MyTheme.lightTheme,
      home: Material(child: Align(alignment: Alignment.topLeft,
        child: Builder(builder: (context) => owner.buildLeftPane(context)),
      )),
    );
    ScrollController? controller;
    try {
      await tester.pumpWidget(paneWidget());
      final pane = find.byType(SingleChildScrollView);
      controller = tester.widget<SingleChildScrollView>(pane).controller!;
      expect(find.text('Short status').hitTestable(), findsOneWidget,
          reason: 'Ready status must appear in its first frame');
      await _settle(tester);
      expect(controller.position.maxScrollExtent, 0);
      expect(controller.offset, 0);
      expect(find.text('Short status').hitTestable(), findsOneWidget);
      expect(find.text('Your Desktop').hitTestable(), findsOneWidget);

      owner.systemError = 'Replacement status';
      await tester.pumpWidget(paneWidget());
      expect(find.text('Replacement status').hitTestable(), findsOneWidget);
      expect(find.text('Short status'), findsNothing);
      await _settle(tester);

      owner.systemError = '';
      await tester.pumpWidget(paneWidget());
      expect(find.text('Replacement status'), findsNothing,
          reason: 'A cleared status must disappear in the same frame');
      await _settle(tester);
      expect(tester.takeException(), isNull);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      controller?.dispose();
    }
  });

  testWidgets('desktop theme owns one save across clicks rebuilds and tab changes',
      (tester) async {
    final save = Completer<String>();
    native.saveTheme = (_) => save.future;
    await _mountTheme(tester);
    final stale = _themeRadio(tester, 'dark').onChanged!;
    stale('dark');
    stale('system');
    await _settle(tester);
    final disabled = _themeRadio(tester, 'dark').onChanged == null;
    _controller().jumpToPage(DesktopSettingPage.tabKeys.indexOf(SettingsTabKey.about));
    await _settle(tester);
    _controller().jumpToPage(0);
    await _settle(tester);
    final stillDisabled = _themeRadio(tester, 'dark').onChanged == null;
    stale('light');
    final admitted = List<String>.of(native.themeWrites);
    save.complete('dark');
    await _settle(tester);
    expect(admitted, ['dark']);
    expect(disabled && stillDisabled, isTrue);
    expect(_themeRadio(tester, 'dark').groupValue, 'dark');
    expect(_themeRadio(tester, 'light').onChanged, isNotNull);
    expect(native.themeNotifications, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('desktop theme write failure remains visible and permits retry',
      (tester) async {
    native.saveTheme = (_) => Future<String>.error(StateError('write refused'));
    await _mountTheme(tester);
    await tester.tap(find.text('Dark'));
    await _settle(tester);
    final failed = find.text('Failed').evaluate().isNotEmpty;
    expect(native.theme, 'light');
    expect(native.themeNotifications, 0);
    native.saveTheme = null;
    await tester.tap(find.text('Dark'));
    await _settle(tester);
    expect(failed, isTrue);
    expect(native.themeWrites, ['dark', 'dark']);
    expect(native.themeNotifications, 1);
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('desktop theme notification failure stays local and permits retry',
      (tester) async {
    final escaped = <Object>[];
    native.notifyTheme = () => Future<void>.error(StateError('notification refused'));
    await _mountTheme(tester);
    runZonedGuarded(() => _themeRadio(tester, 'dark').onChanged!('dark'),
        (Object error, StackTrace stack) => escaped.add(error));
    await _settle(tester);
    final failed = find.text('Failed').evaluate().isNotEmpty;
    native.notifyTheme = null;
    await tester.tap(find.text('Dark'));
    await _settle(tester);
    expect(escaped, isEmpty);
    expect(failed, isTrue);
    expect(native.themeWrites, ['dark', 'dark']);
    expect(native.themeNotifications, 2);
    expect(find.text('Failed'), findsNothing);
  });

  testWidgets('desktop theme close drains admitted save and retires callbacks',
      (tester) async {
    final save = Completer<String>();
    native.saveTheme = (_) => save.future;
    await _mountTheme(tester);
    final stale = _themeRadio(tester, 'dark').onChanged!;
    stale('dark');
    await _settle(tester);
    await tester.pumpWidget(GetMaterialApp(
      theme: MyTheme.lightTheme,
      darkTheme: MyTheme.darkTheme,
      home: const SizedBox.shrink(),
    ));
    await _settle(tester);
    stale('light');
    final admitted = List<String>.of(native.themeWrites);
    save.complete('dark');
    await _settle(tester);
    expect(admitted, ['dark']);
    expect(native.theme, 'dark');
    expect(native.themeNotifications, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('desktop theme fixed preference rejects retained callbacks',
      (tester) async {
    await _mountTheme(tester);
    final stale = _themeRadio(tester, 'dark').onChanged!;
    native.fixedOptions.add(kCommConfKeyTheme);
    stale('dark');
    await _settle(tester);
    expect(native.themeWrites, isEmpty);
    expect(native.themeNotifications, 0);
  });

  testWidgets('desktop theme publishes effective preference and follow system',
      (tester) async {
    native.saveTheme = (_) async => 'light';
    await _mountTheme(tester);
    await tester.tap(find.text('Dark'));
    await _settle(tester);
    expect(_themeRadio(tester, 'light').groupValue, 'light');
    expect(native.themeNotifications, 1);
    native.saveTheme = null;
    await tester.tap(find.text('Follow System'));
    await _settle(tester);
    expect(native.themeWrites, ['dark', defaultOptionTheme]);
    expect(native.themeNotifications, 2);
    expect(_themeRadio(tester, 'system').groupValue, 'system');
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme owns one save across clicks and rebuilds', (tester) async {
    final save = Completer<String>();
    native.saveTheme = (_) => save.future;
    await _mountMobileTheme(tester);
    final stale = _mobileThemeRadio(tester, ThemeMode.dark).onChanged!;
    await tester.tap(_mobileThemeChoice(ThemeMode.dark));
    await _settle(tester);
    final disabled = ThemeMode.values.every(
        (mode) => _mobileThemeRadio(tester, mode).onChanged == null);
    await tester.tap(_mobileThemeChoice(ThemeMode.system));
    stale(ThemeMode.system);
    await _settle(tester);
    final admitted = List<String>.of(native.themeWrites);
    save.complete('dark');
    await _settle(tester);
    await tester.pump(const Duration(milliseconds: 300));
    expect(disabled, isTrue);
    expect(admitted, ['dark']);
    expect(native.theme, 'dark');
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme failed save remains visible and permits retry', (tester) async {
    native.saveTheme = (_) => Future<String>.error(StateError('write refused'));
    await _mountMobileTheme(tester);
    await tester.tap(_mobileThemeChoice(ThemeMode.dark));
    await _settle(tester);
    final failed = find.descendant(of: find.byType(CustomAlertDialog),
        matching: find.text('Failed')).evaluate().isNotEmpty;
    final before = native.theme;
    final retryEnabled = _mobileThemeRadio(tester, ThemeMode.dark).onChanged != null;
    native.saveTheme = null;
    await tester.tap(_mobileThemeChoice(ThemeMode.dark));
    await _settle(tester);
    await tester.pump(const Duration(milliseconds: 300));
    expect(before, 'light');
    expect(failed && retryEnabled, isTrue);
    expect(native.themeWrites, ['dark', 'dark']);
    expect(native.theme, 'dark');
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme dismissed dialog refuses retained callback', (tester) async {
    final manager = await _mountMobileTheme(tester);
    final stale = _mobileThemeRadio(tester, ThemeMode.dark).onChanged!;
    manager.dismissAll();
    await _settle(tester);
    final escaped = <Object>[];
    runZonedGuarded(() => stale(ThemeMode.dark),
        (Object error, StackTrace stack) => escaped.add(error));
    await _settle(tester);
    expect(native.themeWrites, isEmpty);
    expect(escaped, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme admitted save drains after dialog replacement', (tester) async {
    final save = Completer<String>();
    native.saveTheme = (_) => save.future;
    final manager = await _mountMobileTheme(tester);
    final stale = _mobileThemeRadio(tester, ThemeMode.dark).onChanged!;
    final escaped = <Object>[];
    runZonedGuarded(() => stale(ThemeMode.dark),
        (Object error, StackTrace stack) => escaped.add(error));
    await _settle(tester);
    manager.dismissAll();
    await _settle(tester);
    mobile.showThemeSettings(manager);
    await _settle(tester);
    save.complete('dark');
    await _settle(tester);
    await tester.pump(const Duration(milliseconds: 300));
    expect(native.themeWrites, ['dark']);
    expect(native.theme, 'dark');
    expect(find.byType(CustomAlertDialog), findsOneWidget);
    expect(escaped, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme fixed preference rejects retained callback', (tester) async {
    await _mountMobileTheme(tester);
    final stale = _mobileThemeRadio(tester, ThemeMode.dark).onChanged!;
    native.fixedOptions.add(kCommConfKeyTheme);
    stale(ThemeMode.dark);
    await _settle(tester);
    expect(native.themeWrites, isEmpty);
    expect(native.theme, 'light');
    expect(find.byType(CustomAlertDialog), findsOneWidget);
  });

  testWidgets('mobile theme saves light dark and follow system choices', (tester) async {
    final manager = await _mountMobileTheme(tester);
    for (final mode in [ThemeMode.dark, ThemeMode.light, ThemeMode.system]) {
      if (mode != ThemeMode.dark) {
        mobile.showThemeSettings(manager);
        await _settle(tester);
      }
      await tester.tap(_mobileThemeChoice(mode));
      await _settle(tester);
      await tester.pump(const Duration(milliseconds: 300));
      expect(MyTheme.getThemeModePreference(), mode);
      expect(find.byType(CustomAlertDialog), findsNothing);
    }
    expect(native.themeWrites, ['dark', 'light', defaultOptionTheme]);
    expect(native.themeNotifications, 3);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile theme dismissal preserves the saved choice', (tester) async {
    final manager = await _mountMobileTheme(tester);
    manager.dismissAll();
    await _settle(tester);
    expect(native.themeWrites, isEmpty);
    expect(native.theme, 'light');
    expect(find.byType(CustomAlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('desktop theme macOS startup restores system appearance',
      (tester) async {
    final calls = macOSWindowChannel(tester);
    native.theme = defaultOptionTheme;
    await updateSystemWindowTheme();
    expect(calls, ['system']);
    expect(native.themeWrites, isEmpty);
    expect(native.themeNotifications, 0);
  });

  testWidgets('desktop theme macOS main sends saved choices and waits for native reply',
      (tester) async {
    final applied = Completer<void>();
    final calls = macOSWindowChannel(tester,
        apply: (name) async {
          if (name == 'system') await applied.future;
        });
    await _mountTheme(tester);
    for (final choice in ['Dark', 'Light']) {
      await tester.tap(find.text(choice));
      await _settle(tester);
    }
    await tester.tap(find.text('Follow System'));
    await _settle(tester);
    final waiting = _themeRadio(tester, 'system').onChanged == null;
    applied.complete();
    await _settle(tester);
    expect(calls, ['dark', 'light', 'system']);
    expect(waiting, isTrue);
    expect(native.themeWrites, ['dark', 'light', defaultOptionTheme]);
    expect(_themeRadio(tester, 'system').groupValue, 'system');
    expect(_themeRadio(tester, 'system').onChanged, isNotNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('desktop theme macOS receiver updates native appearance without writes',
      (tester) async {
    final calls = macOSWindowChannel(tester);
    desktopType = DesktopType.remote;
    application.installSettingsProbeEventHandlers();
    try {
      await tester.pumpWidget(GetMaterialApp(
        theme: MyTheme.lightTheme,
        darkTheme: MyTheme.darkTheme,
        home: const SizedBox.shrink(),
      ));
      await _settle(tester);
      for (final choice in ['dark', 'light', defaultOptionTheme]) {
        native.theme = choice;
        expect(await dispatchSettingsProbeEvent('{"name":"theme"}'), isTrue);
        await _settle(tester);
      }
      expect(calls, ['dark', 'light', 'system']);
      expect(native.themeWrites, isEmpty);
      expect(native.themeNotifications, 0);
      expect(tester.takeException(), isNull);
    } finally {
      for (final event in ['theme', 'language']) {
        PlatformFFI.instance.registerEventHandler(event, event, (_) {}, replace: true)
            ?.cancel();
      }
      await tester.pumpWidget(const SizedBox.shrink());
      desktopType = null;
    }
  });

  testWidgets('desktop theme macOS native failure is visible and retryable',
      (tester) async {
    var refuse = true;
    final escaped = <Object>[];
    final calls = macOSWindowChannel(tester, apply: (_) async {
      if (refuse) throw PlatformException(code: 'WINDOW_UNAVAILABLE');
    });
    await _mountTheme(tester);
    runZonedGuarded(() => _themeRadio(tester, 'dark').onChanged!('dark'),
        (Object error, StackTrace stack) => escaped.add(error));
    await _settle(tester);
    final failed = find.text('Failed').evaluate().isNotEmpty;
    refuse = false;
    await tester.tap(find.text('Dark'));
    await _settle(tester);
    expect(escaped, isEmpty);
    expect(failed, isTrue);
    expect(calls, ['dark', 'dark']);
    expect(native.theme, 'dark');
    expect(native.themeWrites, ['dark', 'dark']);
    expect(find.text('Failed'), findsNothing);
  });

  for (final sample in [
    (name: 'applies current light', preference: 'light', event: 'light',
      system: Brightness.dark, expected: Brightness.light, stale: null),
    (name: 'applies current dark', preference: 'dark', event: 'dark',
      system: Brightness.light, expected: Brightness.dark, stale: null),
    (name: 'follows system light', preference: 'system', event: 'system',
      system: Brightness.light, expected: Brightness.light, stale: null),
    (name: 'follows system dark', preference: 'system', event: 'system',
      system: Brightness.dark, expected: Brightness.dark, stale: null),
    (name: 'ignores delayed system brightness after explicit choice',
      preference: 'light', event: 'light', system: Brightness.dark,
      expected: Brightness.light, stale: 'dark'),
    (name: 'ignores delayed explicit choice after follow system',
      preference: 'system', event: 'system', system: Brightness.light,
      expected: Brightness.light, stale: 'dark'),
  ]) {
    testWidgets('desktop theme receiver ${sample.name}', (tester) async {
      final preference = sample.preference == 'system'
          ? defaultOptionTheme : sample.preference;
      desktopType = DesktopType.remote;
      tester.platformDispatcher.platformBrightnessTestValue = sample.system;
      application.installSettingsProbeEventHandlers();
      try {
        native.theme = sample.expected == Brightness.light ? 'dark' : 'light';
        await tester.pumpWidget(GetMaterialApp(
          theme: MyTheme.lightTheme,
          darkTheme: MyTheme.darkTheme,
          themeMode: MyTheme.currentThemeMode(),
          home: Builder(builder: (context) {
            final theme = Theme.of(context);
            return ColoredBox(
              key: const Key('received-theme'),
              color: theme.scaffoldBackgroundColor,
              child: Text(theme.brightness.name),
            );
          }),
        ));
        await _settle(tester);
        expect(find.text(sample.expected.name), findsNothing);
        native.theme = preference;

        Future<void> deliver(String? value) async {
          expect(await dispatchSettingsProbeEvent(
              jsonEncode({'name': 'theme', if (value != null) 'dark': value})), isTrue);
          await _settle(tester);
        }

        void expectCurrentTheme([Brightness? brightness]) {
          final expected = brightness ?? sample.expected;
          expect(find.text(expected.name), findsOneWidget);
          final theme = expected == Brightness.light
              ? MyTheme.lightTheme : MyTheme.darkTheme;
          expect(tester.widget<ColoredBox>(find.byKey(const Key('received-theme')))
              .color, theme.scaffoldBackgroundColor);
          expect(native.theme, preference);
          expect(native.themeWrites, isEmpty);
          expect(native.themeNotifications, 0);
          expect(tester.takeException(), isNull);
        }

        await deliver(sample.stale == null ? null : sample.event);
        expectCurrentTheme();
        final stale = sample.stale;
        if (stale != null) {
          await deliver(stale);
          expectCurrentTheme();
        }
        final changedBrightness = sample.system == Brightness.light
            ? Brightness.dark : Brightness.light;
        tester.platformDispatcher.platformBrightnessTestValue = changedBrightness;
        await _settle(tester);
        expectCurrentTheme(sample.preference == 'system'
            ? changedBrightness : sample.expected);
        tester.platformDispatcher.platformBrightnessTestValue = sample.system;
        await _settle(tester);
        expectCurrentTheme();
      } finally {
        for (final event in ['theme', 'language']) {
          PlatformFFI.instance.registerEventHandler(event, event, (_) {}, replace: true)
              ?.cancel();
        }
        await tester.pumpWidget(const SizedBox.shrink());
        tester.platformDispatcher.clearPlatformBrightnessTestValue();
        desktopType = null;
      }
    });
  }

  for (final option in _mobileBooleans) {
    SettingsTile tile(WidgetTester tester) =>
        tester.widget<SettingsTile>(_booleanTile(option.label));
    Future<void> mount(WidgetTester tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      installSettingsProbeAndroid(true);
      await _mountMobile(tester, TargetPlatform.android);
      await _showBoolean(tester, option.label);
    }

    testWidgets('mobile boolean ${option.key} owns one save across rebuild and scroll',
        (tester) async {
      final completion = Completer<String>();
      native.saveOptions[option.key] = (_) => completion.future;
      await mount(tester);
      final change = tile(tester).onToggle!;
      change(!option.initial);
      change(!option.initial);
      await tester.pump();
      tester.state(find.byType(mobile.SettingsPage)).setState(() {});
      await tester.pump();
      final position = tester.state<ScrollableState>(find.descendant(
          of: find.byType(SettingsList), matching: find.byType(Scrollable)).first).position;
      final offset = position.pixels;
      final opposite = offset < position.maxScrollExtent / 2
          ? position.maxScrollExtent : 0.0;
      position.jumpTo(opposite);
      await tester.pump();
      position.jumpTo(offset);
      await tester.pump();
      final disabled = tile(tester).onToggle == null;
      final progress = find.descendant(of: _booleanTile(option.label),
          matching: find.byType(LinearProgressIndicator)).evaluate().length;
      change(!option.initial);
      final pendingWrites = List.of(native.optionWrites);
      completion.complete(option.after);
      await _settle(tester);
      expect((opposite - offset).abs(), greaterThan(0));
      expect(pendingWrites, [(option.local, option.key, option.after)]);
      expect(disabled, isTrue);
      expect(progress, 1);
      expect(tile(tester).initialValue, !option.initial);
      expect(tile(tester).onToggle, isNotNull);
    });

    testWidgets('mobile boolean ${option.key} refusal and mismatch preserve retry',
        (tester) async {
      var writes = 0;
      native.saveOptions[option.key] = (value) async {
        if (++writes == 1) throw StateError('option save refused');
        return writes == 2 ? option.before : value;
      };
      await mount(tester);
      final initialReads = native.optionReaders[option.key];
      for (var attempt = 0; attempt < 2; attempt++) {
        tile(tester).onToggle!(!option.initial);
        await _settle(tester);
        expect(tile(tester).initialValue, option.initial);
        if (attempt == 0) expect(native.optionReaders[option.key], initialReads);
        expect(find.descendant(of: _booleanTile(option.label),
            matching: find.text('Failed')), findsOneWidget);
      }
      tile(tester).onToggle!(!option.initial);
      await _settle(tester);
      expect(tile(tester).initialValue, !option.initial);
      expect(find.text('Failed'), findsNothing);
      tile(tester).onToggle!(option.initial);
      await _settle(tester);
      expect(tile(tester).initialValue, option.initial);
      expect(native.optionWrites, [
        for (var i = 0; i < 3; i++) (option.local, option.key, option.after),
        (option.local, option.key, option.before),
      ]);
    });

    testWidgets('mobile boolean ${option.key} readback error stays local and retries',
        (tester) async {
      final escaped = <Object>[];
      native.saveOptions[option.key] = (value) async {
        native.refuseOptionReads.add(option.key);
        return value;
      };
      await mount(tester);
      runZonedGuarded(() => tile(tester).onToggle!(!option.initial),
          (Object error, StackTrace stack) => escaped.add(error));
      await _settle(tester);
      expect(escaped, isEmpty);
      expect(tile(tester).initialValue, option.initial);
      expect(find.text('Failed'), findsOneWidget);
      native.refuseOptionReads.clear();
      native.saveOptions.clear();
      tile(tester).onToggle!(!option.initial);
      await _settle(tester);
      expect(native.optionWrites, List.filled(2, (option.local, option.key, option.after)));
      expect(tile(tester).initialValue, !option.initial);
      expect(find.text('Failed'), findsNothing);
    });

    testWidgets('mobile boolean ${option.key} admitted write drains after close',
        (tester) async {
      final completion = Completer<String>();
      native.saveOptions[option.key] = (_) => completion.future;
      await mount(tester);
      final change = tile(tester).onToggle!;
      change(!option.initial);
      await tester.pumpWidget(const SizedBox.shrink());
      change(!option.initial);
      completion.complete(option.after);
      await _settle(tester);
      change(option.initial);
      await _settle(tester);
      expect(native.optionWrites, [(option.local, option.key, option.after)]);
      expect(native.options[option.key], option.after);
      await _mountMobile(tester, TargetPlatform.android);
      await _showBoolean(tester, option.label);
      expect(tile(tester).initialValue, !option.initial);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('mobile boolean fixed options cannot dispatch a save', (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    native.fixedOptions.addAll(_mobileBooleans.map((option) => option.key));
    installSettingsProbeAndroid(true);
    await _mountMobile(tester, TargetPlatform.android);
    for (final option in _mobileBooleans) {
      await _showBoolean(tester, option.label);
      expect(tester.widget<SettingsTile>(_booleanTile(option.label)).onToggle, isNull);
    }
    expect(native.optionWrites, isEmpty);
  });

  testWidgets('mobile boolean unrelated options retain independent admission', (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final abr = Completer<String>();
    final recording = Completer<String>();
    native.saveOptions[kOptionEnableAbr] = (_) => abr.future;
    native.saveOptions[kOptionAllowAutoRecordIncoming] = (_) => recording.future;
    installSettingsProbeAndroid(true);
    await _mountMobile(tester, TargetPlatform.android);
    await _showBoolean(tester, 'Adaptive bitrate');
    final changeAbr = tester.widget<SettingsTile>(_booleanTile('Adaptive bitrate')).onToggle!;
    // Both rows share the same page, even when one is outside the current viewport.
    await _showBoolean(tester, 'Automatically record incoming sessions');
    final changeRecording = tester.widget<SettingsTile>(
        _booleanTile('Automatically record incoming sessions')).onToggle!;
    changeAbr(false);
    changeRecording(true);
    final pending = List.of(native.optionWrites);
    abr.complete('N');
    recording.complete('Y');
    await _settle(tester);
    expect(pending, [(false, kOptionEnableAbr, 'N'),
        (false, kOptionAllowAutoRecordIncoming, 'Y')]);
    expect(native.options[kOptionEnableAbr], 'N');
    expect(native.options[kOptionAllowAutoRecordIncoming], 'Y');
  });

  for (final platform in [TargetPlatform.android, TargetPlatform.iOS]) {
    final skin = platform.name;
    SettingsTile tile(WidgetTester tester) =>
        tester.widget<SettingsTile>(_keepAwakeTile());
    Finder status(Type type) => find.descendant(
        of: _keepAwakeTile(), matching: find.byType(type));

    testWidgets('mobile keep awake $skin owns save through rebuild and scrolling',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final completion = Completer<String>();
      native.saveKeepAwake = (_) => completion.future;
      await _mountMobile(tester, platform);
      await tester.binding.setSurfaceSize(const Size(400, 320));
      await tester.pump();
      final change = tile(tester).onToggle!;
      change(false);
      change(false);
      await tester.pump();
      tester.state(find.byType(mobile.SettingsPage)).setState(() {});
      await tester.pump();
      final position = tester.state<ScrollableState>(find.descendant(
          of: find.byType(SettingsList),
          matching: find.byType(Scrollable)).first).position;
      final maxScroll = position.maxScrollExtent;
      position.jumpTo(maxScroll);
      await tester.pump();
      position.jumpTo(0);
      await tester.pump();
      final blocked = tile(tester).onToggle == null;
      final progress = status(LinearProgressIndicator).evaluate().length;
      change(false);
      final pendingWrites = List<String>.of(native.keepAwakeWrites);
      completion.complete('N');
      await _settle(tester);
      expect(maxScroll, greaterThan(0));
      expect(pendingWrites, ['N']);
      expect(blocked, isTrue);
      expect(progress, 1);
      expect(tile(tester).initialValue, isFalse);
      expect(tile(tester).onToggle, isNotNull);
      expect(native.keepAwake, 'N');
      expect(tester.takeException(), isNull);
    });

    testWidgets('mobile keep awake $skin failure and mismatch permit identical retry',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      var attempts = 0;
      native.saveKeepAwake = (value) async {
        attempts++;
        if (attempts == 1) throw StateError('save unavailable');
        return attempts == 2 ? 'Y' : value;
      };
      await _mountMobile(tester, platform);
      for (var attempt = 0; attempt < 2; attempt++) {
        tile(tester).onToggle!(false);
        await _settle(tester);
        expect(tile(tester).initialValue, isTrue);
        expect(find.descendant(of: _keepAwakeTile(), matching: find.text('Failed')),
            findsOneWidget);
        expect(tile(tester).onToggle, isNotNull);
      }
      tile(tester).onToggle!(false);
      await _settle(tester);
      expect(native.keepAwakeWrites, ['N', 'N', 'N']);
      expect(tile(tester).initialValue, isFalse);
      expect(find.text('Failed'), findsNothing);
      tile(tester).onToggle!(true);
      await _settle(tester);
      expect(native.keepAwakeWrites.last, 'Y');
      expect(tile(tester).initialValue, isTrue);
    });

    testWidgets('mobile keep awake $skin readback errors stay local and retry',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final escaped = <Object>[];
      native.saveKeepAwake = (value) async {
        native.refuseKeepAwakeRead = true;
        return value;
      };
      await _mountMobile(tester, platform);
      runZonedGuarded(() => tile(tester).onToggle!(false),
          (Object error, StackTrace stack) => escaped.add(error));
      await _settle(tester);
      expect(escaped, isEmpty);
      expect(tile(tester).initialValue, isTrue);
      expect(find.text('Failed'), findsOneWidget);
      native.refuseKeepAwakeRead = false;
      native.saveKeepAwake = null;
      tile(tester).onToggle!(false);
      await _settle(tester);
      expect(native.keepAwakeWrites, ['N', 'N']);
      expect(tile(tester).initialValue, isFalse);
      expect(find.text('Failed'), findsNothing);
    });

    testWidgets('mobile keep awake $skin close drains admitted save and retires callbacks',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final completion = Completer<String>();
      native.saveKeepAwake = (_) => completion.future;
      await _mountMobile(tester, platform);
      final change = tile(tester).onToggle!;
      change(false);
      await tester.pumpWidget(const SizedBox.shrink());
      change(false);
      completion.complete('N');
      await _settle(tester);
      change(true);
      await _settle(tester);
      expect(native.keepAwakeWrites, ['N']);
      expect(native.keepAwake, 'N');
      await _mountMobile(tester, platform);
      expect(tile(tester).initialValue, isFalse);
      expect(tile(tester).onToggle, isNotNull);
      expect(tester.takeException(), isNull);
    });
  }

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
    final scroll = tester.state<ScrollableState>(find.descendant(
      of: find.byWidgetPredicate((widget) => widget.runtimeType.toString() == '_General'),
      matching: find.byType(Scrollable),
    ));
    final offset = scroll.position.pixels;
    scroll.position.jumpTo(0);
    await _settle(tester);
    scroll.position.jumpTo(offset);
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

  testWidgets('settings toast default expiry preserves pointer input',
      (tester) async {
    var taps = 0;
    try {
      await _mountToast(tester, onTap: () => taps++);
      showToast('toast default');
      await tester.pump();
      await tester.tapAt(tester.getCenter(find.text('toast default')));
      expect(taps, 1);
      await tester.pump(const Duration(milliseconds: 2999));
      expect(find.text('toast default'), findsOneWidget);
      await tester.pump(const Duration(milliseconds: 1));
      expect(find.text('toast default'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await _retireToast(tester);
    }
  });

  testWidgets('settings toast newest message replaces older text and lifetime',
      (tester) async {
    try {
      await _mountToast(tester);
      showToast('toast old', timeout: const Duration(seconds: 20));
      await tester.pump(const Duration(milliseconds: 100));
      showToast('toast current', timeout: const Duration(seconds: 1));
      await tester.pump();
      expect(find.text('toast old'), findsNothing);
      expect(find.text('toast current'), findsOneWidget);
      await tester.pump(const Duration(milliseconds: 999));
      expect(find.text('toast current'), findsOneWidget);
      await tester.pump(const Duration(milliseconds: 1));
      expect(find.textContaining('toast '), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await _retireToast(tester);
    }
  });

  testWidgets('settings toast same-frame burst displays only its latest message',
      (tester) async {
    try {
      await _mountToast(tester);
      for (var i = 0; i < 40; i++) {
        showToast('toast burst $i', timeout: const Duration(seconds: 30));
      }
      showToast('toast burst last', timeout: const Duration(seconds: 1));
      await tester.pump();
      expect(find.textContaining('toast burst '), findsOneWidget);
      expect(find.text('toast burst last'), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('toast burst '), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await _retireToast(tester);
    }
  });

  testWidgets('settings toast retired navigator cannot expire a new message',
      (tester) async {
    try {
      await _mountToast(tester);
      showToast('toast retired', timeout: const Duration(milliseconds: 500));
      await tester.pump();
      await tester.pumpWidget(const SizedBox.shrink());
      await _mountToast(tester);
      showToast('toast replacement', timeout: const Duration(seconds: 2));
      await tester.pump(const Duration(milliseconds: 500));
      expect(find.text('toast replacement'), findsOneWidget);
      expect(find.text('toast retired'), findsNothing);
      await tester.pump(const Duration(milliseconds: 1500));
      expect(find.text('toast replacement'), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      await _retireToast(tester);
    }
  });

  testWidgets('settings toast without a navigator remains inactive',
      (tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    expect(globalKey.currentState, isNull);
    showToast('toast unavailable');
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('toast unavailable'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  for (final platform in [TargetPlatform.android, TargetPlatform.iOS]) {
    final skin = platform.name;

    testWidgets('mobile build date $skin renders completed read and retains it through rebuilds',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      installSettingsProbeAndroid(true);
      final date = Completer<String>();
      native.readBuildDate = () => date.future;
      const value = '2026-10-30 12:34';
      try {
        await _mountMobile(tester, platform);
        await _showBoolean(tester, 'Build Date');
        expect(native.buildDateReads, 1);
        expect(find.text(value), findsNothing);
        tester.state(find.byType(mobile.SettingsPage)).setState(() {});
        await _settle(tester);
        expect(native.buildDateReads, 1);
        date.complete(value);
        await _settle(tester);
        final renderedDate = find.descendant(
            of: _booleanTile('Build Date'), matching: find.text(value));
        expect(renderedDate.hitTestable(), findsOneWidget);
        tester.state(find.byType(mobile.SettingsPage)).setState(() {});
        await _settle(tester);
        expect(renderedDate.hitTestable(), findsOneWidget);
        expect(native.buildDateReads, 1);
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        if (!date.isCompleted) date.complete(value);
        await _settle(tester);
      }
    });

    testWidgets('mobile build date $skin closed page cannot replace reopened metadata',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      installSettingsProbeAndroid(true);
      final oldDate = Completer<String>();
      final currentDate = Completer<String>();
      native.readBuildDate = () =>
          native.buildDateReads == 1 ? oldDate.future : currentDate.future;
      const oldValue = '2026-10-29 01:23';
      const currentValue = '2026-10-30 12:34';
      try {
        await _mountMobile(tester, platform);
        final oldState = tester.state(find.byType(mobile.SettingsPage));
        expect(native.buildDateReads, 1);
        await tester.pumpWidget(const SizedBox.shrink());
        expect(oldState.mounted, isFalse);
        await _mountMobile(tester, platform);
        expect(tester.state(find.byType(mobile.SettingsPage)), isNot(same(oldState)));
        expect(native.buildDateReads, 2);
        await _showBoolean(tester, 'Build Date');
        currentDate.complete(currentValue);
        await _settle(tester);
        expect(find.text(currentValue).hitTestable(), findsOneWidget);
        oldDate.complete(oldValue);
        await _settle(tester);
        expect(find.text(currentValue).hitTestable(), findsOneWidget);
        expect(find.text(oldValue), findsNothing);
        expect(native.buildDateReads, 2);
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        if (!oldDate.isCompleted) oldDate.complete(oldValue);
        if (!currentDate.isCompleted) currentDate.complete(currentValue);
        await _settle(tester);
      }
    });
  }

  for (final platform in [TargetPlatform.android, TargetPlatform.iOS]) {
    final skin = platform.name;

    testWidgets('mobile build date $skin failed read stays local and reopen retries',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      installSettingsProbeAndroid(true);
      final date = Completer<String>();
      native.readBuildDate = () => date.future;
      const recovered = '2026-11-04 19:00';
      try {
        await _mountMobile(tester, platform);
        await _showBoolean(tester, 'Build Date');
        expect(native.buildDateReads, 1);
        date.completeError(StateError('metadata read unavailable'));
        await _settle(tester);
        expect(find.descendant(of: _booleanTile('Build Date'),
            matching: find.text('Failed')).hitTestable(), findsOneWidget);
        expect(tester.takeException(), isNull);
        tester.state(find.byType(mobile.SettingsPage)).setState(() {});
        await _settle(tester);
        expect(native.buildDateReads, 1);
        await tester.pumpWidget(const SizedBox.shrink());
        native.readBuildDate = () => Future<String>.value(recovered);
        await _mountMobile(tester, platform);
        await _showBoolean(tester, 'Build Date');
        expect(find.text(recovered).hitTestable(), findsOneWidget);
        expect(find.text('Failed'), findsNothing);
        expect(native.buildDateReads, 2);
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        if (!date.isCompleted) date.complete(recovered);
        await _settle(tester);
      }
    });

    testWidgets('mobile build date $skin closed page handles a late read failure',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      installSettingsProbeAndroid(true);
      final date = Completer<String>();
      native.readBuildDate = () => date.future;
      try {
        await _mountMobile(tester, platform);
        final state = tester.state(find.byType(mobile.SettingsPage));
        expect(native.buildDateReads, 1);
        await tester.pumpWidget(const SizedBox.shrink());
        expect(state.mounted, isFalse);
        date.completeError(StateError('closed-page metadata read unavailable'));
        await _settle(tester);
        expect(find.byType(mobile.SettingsPage), findsNothing);
        expect(find.text('Failed'), findsNothing);
        expect(native.buildDateReads, 1);
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox.shrink());
        if (!date.isCompleted) date.complete('2026-11-04');
        await _settle(tester);
      }
    });
  }

  testWidgets('settings about retains pending metadata across rebuilds',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final versions = <Completer<String>>[];
    final dates = <Completer<String>>[];
    native.readVersion = () {
      final result = Completer<String>();
      versions.add(result);
      return result.future;
    };
    native.readBuildDate = () {
      final result = Completer<String>();
      dates.add(result);
      return result.future;
    };
    try {
      await _mount(tester, SettingsTabKey.about);
      final about = find.byWidgetPredicate(
          (widget) => widget.runtimeType.toString() == '_About');
      tester.state(about).setState(() {});
      await _settle(tester);
      versions.first.complete('1.0.0');
      await _settle(tester);
      expect(dates, hasLength(1));
      tester.state(about).setState(() {});
      await _settle(tester);
      dates.first.complete('2026-10-26');
      await _settle(tester);
      expect(find.text('Version: 1.0.0'), findsOneWidget);
      expect(find.text('Build Date: 2026-10-26'), findsOneWidget);
      expect(native.versionReads, 1);
      expect(native.buildDateReads, 1);
      expect(tester.takeException(), isNull);
    } finally {
      await tester.pumpWidget(const SizedBox.shrink());
      for (final result in versions) {
        if (!result.isCompleted) result.complete('1.0.0');
      }
      await _settle(tester);
      for (final result in dates) {
        if (!result.isCompleted) result.complete('2026-10-26');
      }
      await _settle(tester);
    }
  });

  testWidgets('settings about reuses loaded metadata with current labels',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _mount(tester, SettingsTabKey.about);
    final about = find.byWidgetPredicate(
        (widget) => widget.runtimeType.toString() == '_About');
    native.translations['Build Date'] = 'Erstellungsdatum';
    for (var i = 0; i < 3; i++) {
      tester.state(about).setState(() {});
      await _settle(tester);
      expect(find.text('Version: 1.0.0'), findsOneWidget);
      expect(find.text('Erstellungsdatum: 2026-10-26'), findsOneWidget);
    }
    final reads = (native.versionReads, native.buildDateReads);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(reads, (1, 1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('settings about reopened page owns fresh metadata after late failure',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final oldVersion = Completer<String>();
    final newVersion = Completer<String>();
    native.readVersion = () =>
        native.versionReads == 1 ? oldVersion.future : newVersion.future;
    await _mount(tester, SettingsTabKey.about);
    await tester.pumpWidget(const SizedBox.shrink());
    await _mount(tester, SettingsTabKey.about);
    oldVersion.completeError(StateError('retired metadata request failed'));
    await _settle(tester);
    expect(find.text('Version: 1.0.0'), findsNothing);
    newVersion.complete('1.0.0');
    await _settle(tester);
    expect(find.text('Version: 1.0.0'), findsOneWidget);
    expect(find.text('Build Date: 2026-10-26'), findsOneWidget);
    expect(native.versionReads, 2);
    expect(native.buildDateReads, 1);
    await tester.pumpWidget(const SizedBox.shrink());
    expect(tester.takeException(), isNull);
  });

  for (final sample in [
    (language: 'English', scale: 1.0),
    (language: 'English', scale: 3.0),
    (language: 'German', scale: 2.0),
  ]) {
    testWidgets(
        'settings sidebar labels fit for ${sample.language} scale ${sample.scale}',
        (tester) async {
      addTearDown(() => tester.binding.setSurfaceSize(null));
      if (sample.language == 'German') {
        // The sidebar values from src/lang/de.rs; other native reads stay fixtures.
        native.translations.addAll({
          'Settings': 'Einstellungen', 'General': 'Allgemein',
          'Security': 'Sicherheit', 'Display': 'Bildschirm', 'About': 'Über',
        });
      }
      await tester.binding.setSurfaceSize(const Size(1000, 420));
      await tester.pumpWidget(MaterialApp(
        theme: MyTheme.lightTheme,
        home: MediaQuery(
          data: MediaQueryData(textScaler: TextScaler.linear(sample.scale)),
          child: DesktopSettingPage(initialTabkey: SettingsTabKey.about),
        ),
      ));
      await _settle(tester);
      expect(tester.takeException(), isNull);
      final sidebar = find.byType(ListView).first;
      final viewport = tester.getRect(sidebar);

      void expectTextFits(Finder label, Rect bounds) {
        final rect = tester.getRect(label);
        expect(rect.left, greaterThanOrEqualTo(bounds.left - 0.1));
        expect(rect.right, lessThanOrEqualTo(bounds.right + 0.1));
        final paragraph = tester.renderObject<RenderParagraph>(label);
        expect(paragraph.didExceedMaxLines, isFalse);
        final boxes = paragraph.getBoxesForSelection(TextSelection(
            baseOffset: 0, extentOffset: paragraph.text.toPlainText().length));
        expect(boxes, isNotEmpty);
        for (final box in boxes) {
          expect(box.bottom, lessThanOrEqualTo(paragraph.size.height + 0.1));
        }
      }

      expectTextFits(find.text(native.translations['Settings'] ?? 'Settings'),
          Rect.fromLTRB(viewport.left, 0, viewport.right, viewport.top));
      for (final key in ['General', 'Security', 'Display', 'About']) {
        final label = find.descendant(of: sidebar,
            matching: find.text(native.translations[key] ?? key));
        await tester.ensureVisible(label);
        await _settle(tester);
        final tile = find.ancestor(of: label, matching: find.byType(InkWell));
        final bounds = tester.getRect(tile);
        expectTextFits(label, bounds);
        expect(tester.getRect(label).top, greaterThanOrEqualTo(viewport.top - 0.1));
        expect(tester.getRect(label).bottom, lessThanOrEqualTo(viewport.bottom + 0.1));
      }
      _expectSelection(tester, SettingsTabKey.about);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets('settings sidebar semantics follow the selected page',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    native.translations['Security'] = 'Sicherheit';
    final destinations = {
      'General': SettingsTabKey.general,
      'Sicherheit': SettingsTabKey.safety,
      'Display': SettingsTabKey.display,
      'About': SettingsTabKey.about,
    };
    Finder label(String name) => find.descendant(
        of: find.byType(ListView).first, matching: find.text(name));
    void expectSelected(SettingsTabKey selected) {
      for (final entry in destinations.entries) {
        expect(tester.getSemantics(label(entry.key)), containsSemantics(
          label: entry.key,
          isButton: true,
          hasEnabledState: true,
          isEnabled: true,
          isSelected: entry.value == selected,
          hasTapAction: true,
        ));
      }
      _expectSelection(tester, selected);
    }

    await _mount(tester, SettingsTabKey.display);
    expectSelected(SettingsTabKey.display);
    for (final entry in destinations.entries) {
      final node = tester.getSemantics(label(entry.key));
      tester.binding.pipelineOwner.semanticsOwner!
          .performAction(node.id, SemanticsAction.tap);
      await _settle(tester);
      expectSelected(entry.value);
    }
    DesktopSettingPage.switch2page(SettingsTabKey.safety);
    await _settle(tester);
    expectSelected(SettingsTabKey.safety);
    tester.state(find.byType(DesktopSettingPage)).setState(() {});
    await _settle(tester);
    expectSelected(SettingsTabKey.safety);
    await tester.pumpWidget(const SizedBox.shrink());
  }, semanticsEnabled: true);

  testWidgets('settings sidebar keyboard traversal and activation select pages',
      (tester) async {
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await _mount(tester, SettingsTabKey.about);
    for (final entry in {
      'General': SettingsTabKey.general,
      'Security': SettingsTabKey.safety,
      'Display': SettingsTabKey.display,
      'About': SettingsTabKey.about,
    }.entries) {
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await _settle(tester);
      final label = find.descendant(
          of: find.byType(ListView).first, matching: find.text(entry.key));
      expect(tester.getSemantics(label), containsSemantics(isFocused: true));
      for (final key in [LogicalKeyboardKey.enter, LogicalKeyboardKey.space]) {
        DesktopSettingPage.switch2page(entry.value == SettingsTabKey.about
            ? SettingsTabKey.general : SettingsTabKey.about);
        await _settle(tester);
        await tester.sendKeyEvent(key);
        await _settle(tester);
        _expectSelection(tester, entry.value);
      }
    }
    await tester.pumpWidget(const SizedBox.shrink());
  }, semanticsEnabled: true);

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
      if (entry.value == SettingsTabKey.about) {
        expect(find.text('Version: 1.0.0'), findsOneWidget);
        expect(find.text('Build Date: 2026-10-26'), findsOneWidget);
        expect(find.text('Copyright © ${DateTime.now().year} Purslane Ltd.'),
            findsOneWidget);
        expect(find.text('RustDesk Hardened Fork'), findsOneWidget);
      }
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
      if (entry.key == SettingsTabKey.about) {
        await tester.binding.setSurfaceSize(const Size(1000, 180));
        await _settle(tester);
      }
      final section = find.byWidgetPredicate(
          (widget) => widget.runtimeType.toString() == entry.value);
      final scrollable = find.descendant(
          of: section, matching: find.byType(Scrollable));
      final scrollState = tester.state<ScrollableState>(scrollable);
      final position = scrollState.position;
      final controller = scrollState.widget.controller;
      final offset = entry.key == SettingsTabKey.about ? 20.0 : 160.0;
      expect(position.maxScrollExtent, greaterThan(offset));
      position.jumpTo(offset);
      await tester.pump();
      for (var i = 0; i < 3; i++) {
        tester.state(section).setState(() {});
        await _settle(tester);
        expect(tester.state<ScrollableState>(scrollable).position, same(position));
        expect(position.pixels, closeTo(offset, 0.1));
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

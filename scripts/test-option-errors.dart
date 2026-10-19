import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:uuid/uuid.dart';

import '../flutter/lib/generated_bridge.dart';

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Map<String, String> configFiles(Directory root) {
  final files = <String, String>{};
  for (final entry in root.listSync(recursive: true, followLinks: false)) {
    check(entry is File || entry is Directory, 'unexpected config entry');
    if (entry is File) {
      files[entry.path] = base64Encode(entry.readAsBytesSync());
    }
  }
  return files;
}

Future<void> main(List<String> arguments) async {
  check(Platform.isLinux && arguments.length == 1, 'Linux library path required');
  final config = Directory(Platform.environment['XDG_CONFIG_HOME']!);
  check(config.existsSync() && config.listSync().isEmpty,
      'private configuration must start empty');
  final api = RustdeskImpl(DynamicLibrary.open(arguments.single));
  final name = api.mainGetAppNameSync();
  check(name.isNotEmpty && await api.mainGetAppName() == name,
      'positive synchronous/asynchronous native calls failed');
  final before = api.mainGetOptionsSync();
  check(jsonDecode(before) is Map && await api.mainGetOptions() == before,
      'initial native option reads differ');
  final initialFiles = configFiles(config);
  final initialValue = api.mainGetOptionSync(key: 'enable-abr');

  Future<void> refused(String key, String value, String cause) async {
    Object? failure;
    try {
      await api.mainSetOption(key: key, value: value);
    } catch (error) {
      failure = error;
    }
    check(failure is FfiException, 'native failure was lost: $failure');
    final error = failure as FfiException;
    check(error.code == 'RESULT_ERROR' && error.message.contains(cause),
        'native Result error cause changed: $error');
    check(api.mainGetOptionsSync() == before &&
        await api.mainGetOptions() == before &&
        api.mainGetOptionSync(key: 'enable-abr') == initialValue &&
        await api.mainGetOption(key: 'enable-abr') == initialValue,
        'failed write changed the native option cache');
    final currentFiles = configFiles(config);
    check(currentFiles.length == initialFiles.length &&
        initialFiles.entries.every((entry) => currentFiles[entry.key] == entry.value),
        'failed write changed durable user configuration');
  }

  await refused('not-an-option', 'fixture', 'main IPC option is not allowlisted');
  print('OPTION_WIRE_DART_CASE=pass name=invalid_key');
  await refused('enable-abr', 'x' * 4097, 'main IPC option value is oversized');
  print('OPTION_WIRE_DART_CASE=pass name=oversized_value');
  await refused('enable-abr', 'N', 'Option write requires daemon ACK:');
  print('OPTION_WIRE_DART_CASE=pass name=missing_receiver');
  for (var attempt = 0; attempt < 8; attempt++) {
    await refused('enable-abr', 'N', 'Option write requires daemon ACK:');
  }
  print('OPTION_WIRE_DART_CASE=pass name=repeated_failure_and_readback');
  print('OPTION_WIRE_DART=pass cases=4 native_errors=11 error=RESULT_ERROR '
      'cache=preserved config=preserved reads=sync-and-async');

  await api.mainSetFavorites(ids: ['first'], favorite: true);
  check(jsonEncode(await api.mainGetFav()) == '["first"]',
      'initial favorite membership was not published');
  final localFiles = config.listSync(recursive: true).whereType<File>()
      .where((file) => file.path.endsWith('_local.toml')).toList();
  check(localFiles.length == 1, 'exact private local config is missing');
  final parent = localFiles.single.parent;
  void permissions(String mode) {
    final result = Process.runSync('/bin/chmod', [mode, parent.path]);
    check(result.exitCode == 0, 'private config permission change failed');
  }
  print('FAVORITES_WIRE_DART_CASE=pass name=initial_commit');
  for (final favorite in [true, false]) {
    final beforeFavs = jsonEncode(await api.mainGetFav());
    final beforeFiles = configFiles(config);
    Object? failure;
    permissions('0500');
    try {
      try {
        await api.mainSetFavorites(ids: ['second'], favorite: favorite);
      } catch (error) {
        failure = error;
      }
      check(failure is FfiException &&
          (failure as FfiException).code == 'RESULT_ERROR',
          'favorite persistence failure did not cross the native bridge');
      check(jsonEncode(await api.mainGetFav()) == beforeFavs,
          'failed favorite save changed memory');
      final currentFiles = configFiles(config);
      check(currentFiles.length == beforeFiles.length &&
          beforeFiles.entries.every((entry) => currentFiles[entry.key] == entry.value),
          'failed favorite save changed durable configuration');
    } finally {
      permissions('0700');
    }
    await api.mainSetFavorites(ids: ['second'], favorite: favorite);
    check((await api.mainGetFav()).contains('second') == favorite,
        'identical favorite retry failed');
    final disk = localFiles.single.readAsStringSync();
    check(disk.contains('"second"') == favorite && disk.contains('"first"'),
        'favorite retry did not reach the durable file');
    print('FAVORITES_WIRE_DART_CASE=pass name=${favorite ? 'failed_add_retry' : 'failed_remove_retry'}');
  }
  await Future.wait([
    api.mainSetFavorites(ids: ['third'], favorite: true),
    api.mainSetFavorites(ids: ['fourth'], favorite: true),
  ]);
  final current = await api.mainGetFav();
  check(current.length == 3 && current.contains('first') &&
      current.contains('third') && current.contains('fourth'),
      'concurrent native membership changes overwrote one another');
  final concurrentDisk = localFiles.single.readAsStringSync();
  check(concurrentDisk.contains('"third"') && concurrentDisk.contains('"fourth"'),
      'concurrent favorite changes did not reach durable configuration');
  permissions('0500');
  try {
    await api.mainSetFavorites(ids: ['first'], favorite: true);
    await api.mainSetFavorites(ids: ['absent'], favorite: false);
  } finally {
    permissions('0700');
  }
  print('FAVORITES_WIRE_DART_CASE=pass name=concurrent_membership');
  print('FAVORITES_WIRE_DART=pass cases=4 native_errors=2 error=RESULT_ERROR '
      'failed_state=preserved retry=durable concurrent=preserved idempotent=without-write');

  await api.setLocalKbLayoutType(kbLayoutType: 'ISO');
  check(api.getLocalKbLayoutType() == 'ISO', 'initial keyboard type was not saved');
  print('KEYBOARD_WIRE_DART_CASE=pass name=initial_commit');
  final beforeKeyboard = configFiles(config);
  Object? keyboardFailure;
  permissions('0500');
  try {
    try {
      await api.setLocalKbLayoutType(kbLayoutType: 'Not ISO');
    } catch (error) {
      keyboardFailure = error;
    }
    check(keyboardFailure is FfiException &&
        (keyboardFailure as FfiException).code == 'RESULT_ERROR',
        'keyboard persistence failure did not cross the native bridge');
    check(api.getLocalKbLayoutType() == 'ISO',
        'failed keyboard save changed the live mapping');
    final currentFiles = configFiles(config);
    check(currentFiles.length == beforeKeyboard.length &&
        beforeKeyboard.entries.every((entry) => currentFiles[entry.key] == entry.value),
        'failed keyboard save changed durable configuration');
  } finally {
    permissions('0700');
  }
  await api.setLocalKbLayoutType(kbLayoutType: 'Not ISO');
  check(api.getLocalKbLayoutType() == 'Not ISO' &&
      localFiles.single.readAsStringSync().contains('kb_layout_type = "Not ISO"'),
      'identical keyboard retry was not durable');
  check(jsonEncode(await api.mainGetFav()) == jsonEncode(current),
      'keyboard save replaced unrelated favorite membership');
  print('KEYBOARD_WIRE_DART_CASE=pass name=failed_write_retry');
  permissions('0500');
  try {
    await api.setLocalKbLayoutType(kbLayoutType: 'Not ISO');
  } finally {
    permissions('0700');
  }
  print('KEYBOARD_WIRE_DART_CASE=pass name=idempotent_without_write');
  print('KEYBOARD_WIRE_DART=pass cases=3 native_errors=1 error=RESULT_ERROR '
      'failed_mapping=preserved failed_file=preserved retry=durable unrelated=preserved');

  const localKey = 'local-option-wire-test';
  await api.mainSetLocalOption(key: localKey, value: 'original');
  check(api.mainGetLocalOption(key: localKey) == 'original',
      'initial local preference was not saved');
  print('LOCAL_PREF_WIRE_DART_CASE=pass name=initial_commit');
  var localErrors = 0;
  Future<void> refusedLocalWrite(String key, String value,
      {Future<void> Function()? write}) async {
    final beforeFiles = configFiles(config);
    final beforeValue = api.mainGetLocalOption(key: key);
    Object? failure;
    permissions('0500');
    try {
      try {
        if (write == null) {
          await api.mainSetLocalOption(key: key, value: value);
        } else {
          await write();
        }
      } catch (error) {
        failure = error;
      }
      check(failure is FfiException && (failure as FfiException).code == 'RESULT_ERROR',
          'local persistence failure did not cross the bridge');
      localErrors++;
      check(api.mainGetLocalOption(key: key) == beforeValue,
          'failed local save changed its effective value');
      final afterFiles = configFiles(config);
      check(afterFiles.length == beforeFiles.length &&
          beforeFiles.entries.every((entry) => afterFiles[entry.key] == entry.value),
          'failed local save changed durable configuration');
    } finally {
      permissions('0700');
    }
  }
  for (final value in ['replacement', '']) {
    await refusedLocalWrite(localKey, value);
    await api.mainSetLocalOption(key: localKey, value: value);
    final text = localFiles.single.readAsStringSync();
    check(api.mainGetLocalOption(key: localKey) == value &&
        (value.isEmpty ? !text.contains('$localKey =') :
            text.contains('$localKey = "$value"')),
        'identical local preference retry was not durable');
    print('LOCAL_PREF_WIRE_DART_CASE=pass name=${value.isEmpty ? "failed_remove_retry" : "failed_replace_retry"}');
  }
  await api.mainSetLocalOption(key: 'lang', value: 'fr');
  await refusedLocalWrite('lang', 'default');
  await api.mainSetLocalOption(key: 'lang', value: 'default');
  check(api.mainGetLocalOption(key: 'lang').isEmpty &&
      localFiles.single.readAsStringSync().contains('lang = ""'),
      'system language retry did not preserve the explicit empty override');
  permissions('0500');
  try {
    await api.mainSetLocalOption(key: 'lang', value: 'default');
    await api.mainSetLocalOption(key: localKey, value: '');
  } finally {
    permissions('0700');
  }
  print('LOCAL_PREF_WIRE_DART_CASE=pass name=system_language_and_idempotence');
  final inputSession = UuidValue('00000000-0000-4000-8000-000000000001');
  await api.mainSetLocalOption(key: 'input-source', value: 'Input source 1');
  final originalInputSource = api.mainGetInputSource();
  await refusedLocalWrite('input-source', 'Input source 2',
      write: () => api.mainSetInputSource(
          sessionId: inputSession, value: 'Input source 2'));
  check(api.mainGetInputSource() == originalInputSource,
      'failed input source change altered effective readback');
  await api.mainSetInputSource(
      sessionId: inputSession, value: 'Input source 2');
  check(api.mainGetInputSource() == 'Input source 2' &&
      localFiles.single.readAsStringSync().contains('input-source = "Input source 2"'),
      'input source retry was not durable');
  permissions('0500');
  try {
    await api.mainSetInputSource(
        sessionId: inputSession, value: 'Input source 2');
  } finally {
    permissions('0700');
  }
  print('LOCAL_PREF_WIRE_DART_CASE=pass name=input_source_retry_and_idempotence');
  check(api.getLocalKbLayoutType() == 'Not ISO' &&
      jsonEncode(await api.mainGetFav()) == jsonEncode(current),
      'local option save changed unrelated keyboard or favorite settings');
  check(localErrors == 4, 'local preference native error count differs');
  print('LOCAL_PREF_WIRE_DART=pass cases=5 native_errors=4 error=RESULT_ERROR '
      'failed_state=preserved retry=durable language=explicit-empty input_source=durable idempotent=without-write unrelated=preserved');

  const uiKey = 'flutter-state-wire-test';
  await api.mainSetLocalOption(key: uiKey, value: 'general-preserved');
  await api.setLocalFlutterOption(k: uiKey, v: 'ui-state-original');
  check(api.getLocalFlutterOption(k: uiKey) == 'ui-state-original' &&
      api.mainGetLocalOption(key: uiKey) == 'general-preserved',
      'initial Flutter preference crossed configuration namespaces');
  print('UI_STATE_WIRE_DART_CASE=pass name=initial_commit');
  var uiErrors = 0;
  for (final value in ['ui-state-replacement', '']) {
    final beforeFiles = configFiles(config);
    final beforeValue = api.getLocalFlutterOption(k: uiKey);
    Object? failure;
    permissions('0500');
    try {
      try {
        await api.setLocalFlutterOption(k: uiKey, v: value);
      } catch (error) {
        failure = error;
      }
      check(failure is FfiException && (failure as FfiException).code == 'RESULT_ERROR',
          'Flutter preference failure did not cross the native bridge');
      uiErrors++;
      check(api.getLocalFlutterOption(k: uiKey) == beforeValue,
          'failed Flutter preference save changed its effective value');
      final afterFiles = configFiles(config);
      check(afterFiles.length == beforeFiles.length &&
          beforeFiles.entries.every((entry) => afterFiles[entry.key] == entry.value),
          'failed Flutter preference save changed durable configuration');
    } finally {
      permissions('0700');
    }
    await api.setLocalFlutterOption(k: uiKey, v: value);
    final text = localFiles.single.readAsStringSync();
    check(api.getLocalFlutterOption(k: uiKey) == value &&
        (value.isEmpty ? !text.contains('ui-state-replacement') : text.contains(value)),
        'identical Flutter preference retry was not durable');
    permissions('0500');
    try {
      await api.setLocalFlutterOption(k: uiKey, v: value);
    } finally {
      permissions('0700');
    }
    print('UI_STATE_WIRE_DART_CASE=pass name=${value.isEmpty ? "failed_remove_retry" : "failed_replace_retry"}');
  }
  check(api.mainGetLocalOption(key: uiKey) == 'general-preserved' &&
      localFiles.single.readAsStringSync().contains('$uiKey = "general-preserved"') &&
      api.mainGetLocalOption(key: 'lang').isEmpty &&
      api.getLocalKbLayoutType() == 'Not ISO' &&
      jsonEncode(await api.mainGetFav()) == jsonEncode(current),
      'Flutter preference save replaced unrelated configuration');
  check(uiErrors == 2, 'Flutter preference native error count differs');
  print('UI_STATE_WIRE_DART_CASE=pass name=idempotent_and_namespace_isolation');
  print('UI_STATE_WIRE_DART=pass cases=4 native_errors=2 error=RESULT_ERROR '
      'failed_state=preserved retry=durable idempotent=without-write namespaces=isolated unrelated=preserved');

  final beforeVoice = configFiles(config);
  await api.setVoiceCallInputDevice(isCm: false, device: 'viewer-microphone');
  check(await api.getVoiceCallInputDevice(isCm: false) == 'viewer-microphone',
      'viewer voice-call input selection was not applied');
  print('VOICE_INPUT_WIRE_DART_CASE=pass name=viewer_selection');
  await api.setVoiceCallInputDevice(isCm: false, device: '');
  check((await api.getVoiceCallInputDevice(isCm: false)).isEmpty,
      'viewer voice-call default selection was not applied');
  print('VOICE_INPUT_WIRE_DART_CASE=pass name=viewer_default');
  await api.setVoiceCallInputDevice(isCm: false, device: 'viewer-microphone');
  var voiceErrors = 0;
  for (final name in ['cm_missing_receiver', 'cm_retry_preserves_viewer']) {
    Object? failure;
    try {
      await api.setVoiceCallInputDevice(isCm: true, device: 'cm-microphone');
    } catch (error) {
      failure = error;
    }
    check(failure is FfiException && (failure as FfiException).code == 'RESULT_ERROR',
        'voice-call input failure did not cross the native bridge');
    voiceErrors++;
    check(await api.getVoiceCallInputDevice(isCm: false) == 'viewer-microphone',
        'CM voice-call input failure changed viewer state');
    final afterVoice = configFiles(config);
    check(afterVoice.length == beforeVoice.length &&
        beforeVoice.entries.every((entry) => afterVoice[entry.key] == entry.value),
        'voice-call input selection changed durable configuration');
    print('VOICE_INPUT_WIRE_DART_CASE=pass name=$name');
  }
  Object? voiceReadFailure;
  try {
    await api.getVoiceCallInputDevice(isCm: true);
  } catch (error) {
    voiceReadFailure = error;
  }
  check(voiceReadFailure is FfiException &&
      (voiceReadFailure as FfiException).code == 'RESULT_ERROR',
      'failed CM voice-call input read was reported as a default device');
  voiceErrors++;
  check(await api.getVoiceCallInputDevice(isCm: false) == 'viewer-microphone',
      'failed CM voice-call input read changed viewer state');
  print('VOICE_INPUT_WIRE_DART_CASE=pass name=cm_read_failure');
  check(voiceErrors == 3, 'voice-call input native error count differs');
  print('VOICE_INPUT_WIRE_DART=pass cases=5 native_errors=3 error=RESULT_ERROR '
      'viewer=selected-and-default cm_failure=reported read_failure=reported retry=reported state=preserved config=unchanged');

  const defaultKey = 'default-wire-value';
  check(await api.mainSetUserDefaultOption(key: defaultKey, value: 'original') == 'original' &&
      api.mainGetUserDefaultOption(key: defaultKey) == 'original',
      'default option acknowledgement differs from effective readback');
  final defaultFiles = config.listSync(recursive: true).whereType<File>()
      .where((file) => file.path.endsWith('_default.toml')).toList();
  check(defaultFiles.length == 1, 'exact private default configuration is missing');
  final defaultFile = defaultFiles.single;
  print('DEFAULT_PREF_WIRE_DART_CASE=pass name=initial_commit');
  var defaultErrors = 0;
  for (final requested in ['replacement', '']) {
    final beforeFiles = configFiles(config);
    final beforeValue = api.mainGetUserDefaultOption(key: defaultKey);
    Object? failure;
    permissions('0500');
    try {
      try {
        await api.mainSetUserDefaultOption(key: defaultKey, value: requested);
      } catch (error) {
        failure = error;
      }
      check(failure is FfiException && (failure as FfiException).code == 'RESULT_ERROR',
          'failed default save did not cross the generated native bridge');
      defaultErrors++;
      final afterFiles = configFiles(config);
      check(api.mainGetUserDefaultOption(key: defaultKey) == beforeValue &&
          afterFiles.length == beforeFiles.length &&
          beforeFiles.entries.every((entry) => afterFiles[entry.key] == entry.value),
          'failed default save changed effective or durable state');
    } finally {
      permissions('0700');
    }
    check(await api.mainSetUserDefaultOption(key: defaultKey, value: requested) == requested &&
        api.mainGetUserDefaultOption(key: defaultKey) == requested,
        'identical default save retry was not applied');
    final text = defaultFile.readAsStringSync();
    check(requested.isEmpty ? !text.contains(defaultKey) : text.contains(requested),
        'identical default save retry was not durable');
    permissions('0500');
    try {
      check(await api.mainSetUserDefaultOption(key: defaultKey, value: requested) == requested,
          'unchanged default value required a write');
    } finally {
      permissions('0700');
    }
    print('DEFAULT_PREF_WIRE_DART_CASE=pass name=' +
        (requested.isEmpty ? 'failed_remove_retry' : 'failed_replace_retry'));
  }
  await Future.wait([
    api.mainSetUserDefaultOption(key: 'view_style', value: 'adaptive'),
    api.mainSetUserDefaultOption(key: 'scroll_style', value: 'scrollbar'),
  ]);
  check(api.mainGetUserDefaultOption(key: 'view_style') == 'adaptive' &&
      api.mainGetUserDefaultOption(key: 'scroll_style') == 'scrollbar' &&
      await api.mainSetUserDefaultOption(key: 'custom-fps', value: '25.0') == '25',
      'default single-key writers lost a value or normalized acknowledgement');
  print('DEFAULT_PREF_WIRE_DART_CASE=pass name=concurrent_single_key');
  final beforeUnreadable = configFiles(config);
  final deny = Process.runSync('/bin/chmod', ['0000', defaultFile.path]);
  check(deny.exitCode == 0, 'private default read denial failed');
  Object? readFailure;
  try {
    check(api.mainGetUserDefaultOption(key: 'view_style') == 'adaptive',
        'unreadable source replaced the last confirmed default read');
    try {
      await api.mainSetUserDefaultOption(key: defaultKey, value: 'after-read-failure');
    } catch (error) {
      readFailure = error;
    }
  } finally {
    final restore = Process.runSync('/bin/chmod', ['0600', defaultFile.path]);
    check(restore.exitCode == 0, 'private default read permission restore failed');
  }
  check(readFailure is FfiException && (readFailure as FfiException).code == 'RESULT_ERROR',
      'unreadable default source was silently replaced');
  defaultErrors++;
  final afterUnreadable = configFiles(config);
  check(afterUnreadable.length == beforeUnreadable.length &&
      beforeUnreadable.entries.every((entry) => afterUnreadable[entry.key] == entry.value) &&
      api.mainGetUserDefaultOption(key: 'view_style') == 'adaptive' &&
      await api.mainSetUserDefaultOption(key: defaultKey, value: 'after-read-failure') == 'after-read-failure',
      'default read failure lost values or blocked healthy retry');
  print('DEFAULT_PREF_WIRE_DART_CASE=pass name=unreadable_source_refusal');
  check(defaultErrors == 3, 'default native error count differs');
  print('DEFAULT_PREF_WIRE_DART=pass cases=5 native_errors=3 error=RESULT_ERROR '
      'failed_state=preserved retry=durable source_failure=refused concurrent_keys=preserved effective=normalized idempotent=without-write');

  final peerSession = Uuid().v4obj();
  final peerOwner = Uuid().v4obj();
  check(api.sessionAddSync(
      sessionId: peerSession, clientOwnerId: peerOwner, id: '127.0.0.1:24003',
      isFileTransfer: false, isViewCamera: false, isPortForward: false,
      isRdp: false, isTerminal: false, password: 'explicit-password', connToken: null) == '',
      'idle peer session preparation failed');
  var peerErrors = 0;
  Future<void> peerRefused(Future<int> Function() write) async {
    Object? failure;
    try {
      await write();
    } catch (error) {
      failure = error;
    }
    check(failure is FfiException && (failure as FfiException).code == 'RESULT_ERROR',
        'peer preference failure did not cross the generated native bridge');
    peerErrors++;
  }
  void chmod(String mode, String path) {
    check(Process.runSync('/bin/chmod', [mode, path]).exitCode == 0,
        'private peer permission change failed');
  }
  void unchanged(Map<String, String> before) {
    final after = configFiles(config);
    check(after.length == before.length &&
        before.entries.every((entry) => after[entry.key] == entry.value),
        'failed peer preference changed durable configuration');
  }
  try {
    check(await api.sessionSetCustomImageQuality(sessionId: peerSession, value: 80) == 80 &&
        await api.sessionSetCustomFps(sessionId: peerSession, fps: 45) == 45 &&
        jsonEncode(await api.sessionGetCustomImageQuality(sessionId: peerSession)) == '[80]' &&
        await api.sessionGetOption(sessionId: peerSession, arg: 'custom-fps') == '45',
        'peer preference acknowledgement differs from effective readback');
    final peers = config.listSync(recursive: true).whereType<File>()
        .where((file) => file.parent.path.endsWith('/peers')).toList();
    check(peers.length == 1, 'exact private peer configuration is missing');
    final peerFile = peers.single;
    void durable(int quality, int fps) {
      final text = peerFile.readAsStringSync();
      check(RegExp('^custom_image_quality = \\[\\s*$quality,?\\s*\\]', multiLine: true).hasMatch(text) &&
          RegExp('^custom-fps = "$fps"\$', multiLine: true).hasMatch(text) &&
          text.contains('image_quality = "custom"'),
          'peer preference acknowledgement preceded durable values');
    }
    durable(80, 45);
    print('PEER_PREF_WIRE_DART_CASE=pass name=durable_effective_roundtrip');
    for (final quality in [true, false]) {
      final before = configFiles(config);
      chmod('0500', peerFile.parent.path);
      try {
        await peerRefused(() => quality
            ? api.sessionSetCustomImageQuality(sessionId: peerSession, value: 90)
            : api.sessionSetCustomFps(sessionId: peerSession, fps: 50));
        check(jsonEncode(await api.sessionGetCustomImageQuality(sessionId: peerSession)) ==
                (quality ? '[80]' : '[90]') &&
            await api.sessionGetOption(sessionId: peerSession, arg: 'custom-fps') == '45',
            'failed peer preference changed effective cache');
        unchanged(before);
      } finally {
        chmod('0700', peerFile.parent.path);
      }
      final effective = quality
          ? await api.sessionSetCustomImageQuality(sessionId: peerSession, value: 90)
          : await api.sessionSetCustomFps(sessionId: peerSession, fps: 50);
      check(effective == (quality ? 90 : 50), 'identical peer retry failed');
      durable(90, quality ? 45 : 50);
      print('PEER_PREF_WIRE_DART_CASE=pass name=${quality ? "failed_quality_retry" : "failed_fps_retry"}');
    }
    final beforeRead = configFiles(config);
    chmod('0000', peerFile.path);
    try {
      await peerRefused(() => api.sessionSetCustomImageQuality(sessionId: peerSession, value: 95));
      await peerRefused(() => api.sessionSetCustomFps(sessionId: peerSession, fps: 55));
    } finally {
      chmod('0600', peerFile.path);
    }
    unchanged(beforeRead);
    check(jsonEncode(await api.sessionGetCustomImageQuality(sessionId: peerSession)) == '[90]' &&
        await api.sessionGetOption(sessionId: peerSession, arg: 'custom-fps') == '50',
        'unreadable peer source changed effective cache');
    check(await api.sessionSetCustomImageQuality(sessionId: peerSession, value: 95) == 95 &&
        await api.sessionSetCustomFps(sessionId: peerSession, fps: 55) == 55,
        'identical peer retry after read failure failed');
    durable(95, 55);
    print('PEER_PREF_WIRE_DART_CASE=pass name=unreadable_source');
    final beforeInvalid = configFiles(config);
    for (final value in [9, 4096]) {
      await peerRefused(() => api.sessionSetCustomImageQuality(sessionId: peerSession, value: value));
    }
    for (final fps in [4, 121]) {
      await peerRefused(() => api.sessionSetCustomFps(sessionId: peerSession, fps: fps));
    }
    unchanged(beforeInvalid);
    print('PEER_PREF_WIRE_DART_CASE=pass name=invalid_values');
    final missing = Uuid().v4obj();
    await peerRefused(() => api.sessionSetCustomImageQuality(sessionId: missing, value: 95));
    await peerRefused(() => api.sessionSetCustomFps(sessionId: missing, fps: 55));
    unchanged(beforeInvalid);
    check(jsonEncode(await api.sessionGetCustomImageQuality(sessionId: peerSession)) == '[95]' &&
        await api.sessionGetOption(sessionId: peerSession, arg: 'custom-fps') == '55',
        'invalid or missing-session request changed effective cache');
    print('PEER_PREF_WIRE_DART_CASE=pass name=missing_session');
  } finally {
    await api.sessionClose(sessionId: peerSession, clientOwnerId: peerOwner);
  }
  check(await api.sessionGetCustomImageQuality(sessionId: peerSession) == null && peerErrors == 10,
      'peer session cleanup or native error inventory differs');
  print('PEER_PREF_WIRE_DART=pass cases=6 native_errors=10 error=RESULT_ERROR '
      'failed_state=preserved retry=durable source_failure=refused bounds=refused no_peer_started=true');
}

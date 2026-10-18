import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';

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
}

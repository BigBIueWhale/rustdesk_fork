import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:uuid/uuid.dart';

import '../flutter/lib/generated_bridge.dart';

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

void chmod(Directory directory, String mode) {
  final result = Process.runSync('/bin/chmod', [mode, directory.path]);
  check(result.exitCode == 0, 'fixture chmod failed: ${result.stderr}');
}

Future<void> main(List<String> arguments) async {
  check(Platform.isLinux && arguments.length == 1, 'Linux library path required');
  final api = RustdeskImpl(DynamicLibrary.open(arguments.single));
  final session = UuidValue('00000000-0000-4000-8000-000000000001');
  final root = Directory.systemTemp.createTempSync('local-listing-dart-');
  chmod(root, '700');
  final blocked = Directory('${root.path}/blocked')..createSync();
  final empty = Directory('${root.path}/empty')..createSync();

  Future<Map<String, dynamic>> flat(Directory directory,
      {bool hidden = false}) async {
    final text = await api.sessionReadLocalDirSync(
        sessionId: session, path: directory.path, showHidden: hidden);
    final value = jsonDecode(text) as Map<String, dynamic>;
    check(value['id'] == 0 && value['path'] == directory.path,
        'flat listing identity changed');
    return value;
  }

  Future<List<dynamic>> emptyDirs(Directory directory,
      {bool hidden = false}) async {
    return jsonDecode(await api.sessionReadLocalEmptyDirsRecursiveSync(
        sessionId: session, path: directory.path, includeHidden: hidden)) as List;
  }

  Future<void> errors(Directory directory, String cause) async {
    for (final request in <Future<String> Function()>[
      () => api.sessionReadLocalDirSync(
          sessionId: session, path: directory.path, showHidden: false),
      () => api.sessionReadLocalEmptyDirsRecursiveSync(
          sessionId: session, path: directory.path, includeHidden: false),
    ]) {
      Object? failure;
      try {
        await request();
      } catch (error) {
        failure = error;
      }
      check(failure is FfiException, 'expected native FfiException, got $failure');
      final error = failure as FfiException;
      check(error.code == 'RESULT_ERROR' && error.message.contains(cause),
          'native error cause lost: $error; expected $cause');
    }
  }

  Set<String> names(Map<String, dynamic> listing) =>
      (listing['entries'] as List).map((entry) => entry['name'] as String).toSet();

  try {
    // Both functions must execute successfully before any negative case can count.
    check(names(await flat(empty)).isEmpty, 'empty directory has entries');
    final initial = await emptyDirs(empty);
    check(initial.length == 1 && initial.single['path'] == empty.path &&
        (initial.single['entries'] as List).isEmpty, 'empty directory JSON changed');

    final payload = File('${root.path}/payload')..writeAsStringSync('retained');
    final failures = [Directory('${root.path}/missing'),
      Directory('${payload.path}/child'), blocked];
    final expectedCodes = [2, 20, 13];
    for (var index = 0; index < failures.length; index++) {
      final directory = failures[index];
      if (directory == blocked) chmod(blocked, '000');
      int? nativeCode;
      try {
        directory.listSync();
      } on FileSystemException catch (error) {
        nativeCode = error.osError?.errorCode;
      }
      check(nativeCode == expectedCodes[index],
          'native filesystem negative control returned $nativeCode');
      await errors(directory, 'os error $nativeCode');
      if (directory == blocked) chmod(blocked, '700');
      check(names(await flat(empty)).isEmpty && (await emptyDirs(empty)).length == 1,
          'valid requests failed after filesystem refusal');
    }
    check(payload.readAsStringSync() == 'retained', 'payload changed');
    print('LOCAL_FILE_LISTING_DART_CASE=pass name=filesystem_errors');

    final budget = Directory('${root.path}/budget')..createSync();
    for (var index = 0; index < 10000; index++) {
      File('${budget.path}/entry-$index').createSync();
    }
    final excess = File('${budget.path}/.excluded-entry')
      ..writeAsStringSync('retained hidden bytes');
    await errors(budget, 'file enumeration budget exceeded');
    check(excess.readAsStringSync() == 'retained hidden bytes', 'hidden bytes changed');
    excess.deleteSync();
    check(names(await flat(budget)).length == 10000 &&
        (await emptyDirs(budget)).isEmpty && budget.listSync().length == 10000,
        'exact boundary recovery failed');
    print('LOCAL_FILE_LISTING_DART_CASE=pass name=entry_budget_recovery');

    Directory('${empty.path}/visible').createSync();
    Directory('${empty.path}/.hidden').createSync();
    final sentinel = File('${empty.path}/payload')..writeAsStringSync('preserved');
    for (final hidden in [false, true]) {
      final expectedNames = {'visible', 'payload', if (hidden) '.hidden'};
      final actualNames = names(await flat(empty, hidden: hidden));
      check(actualNames.length == expectedNames.length &&
          actualNames.containsAll(expectedNames), 'hidden filtering changed');
      final directories = await emptyDirs(empty, hidden: hidden);
      final paths = directories.map((entry) {
        check((entry['entries'] as List).isEmpty, 'nonempty directory returned');
        return entry['path'] as String;
      }).toSet();
      final expectedPaths = {
        '${empty.path}/visible', if (hidden) '${empty.path}/.hidden'
      };
      check(paths.length == expectedPaths.length && paths.containsAll(expectedPaths),
          'empty-directory filtering changed');
    }
    check(sentinel.readAsStringSync() == 'preserved', 'sentinel changed');
    print('LOCAL_FILE_LISTING_DART_CASE=pass name=empty_hidden_success');
  } finally {
    chmod(blocked, '700');
    root.deleteSync(recursive: true);
  }
  check(!root.existsSync(), 'owned fixture survived cleanup');
  print('LOCAL_FILE_LISTING_DART=pass cases=3 exports=2 native_errors=8 recovery=pass fixtures=retired');
}

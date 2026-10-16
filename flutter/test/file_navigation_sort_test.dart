import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

String _listing(String path) => jsonEncode({
      'id': 0,
      'path': path,
      'entries': [
        {'entry_type': 4, 'name': 'gamma.m', 'size': 20, 'modified_time': 200},
        {'entry_type': 4, 'name': 'alpha.z', 'size': 30, 'modified_time': 100},
        {'entry_type': 4, 'name': 'beta.a', 'size': 10, 'modified_time': 300},
      ],
    });

class _ListingHarness {
  var session = const Uuid().v4obj();
  late final fetcher = FileFetcher(
    () => session,
    requests: FileFetcherRequests(
      readDirectory: (_, __, ___) async {},
      readEmptyDirectories: (_, __, ___) async {},
      readDirectoryTree: (_, __, ___, ____, _____) async {},
    ),
  );
  late final controller = FileController(
    isLocal: false,
    getSessionID: () => session,
    getDialogManager: () => null,
    isCurrentSession: (actual) => actual == session,
    getPeerPlatform: () => 'Linux',
    getPeerVersion: () => '1.4.0',
    jobController: JobController(
      () => session,
      () => null,
      isCurrentSession: (actual) => actual == session,
    ),
    fileFetcher: fetcher,
    getOtherSideDirectoryData: () =>
        DirectoryData(FileDirectory(), DirectoryOptions()),
    translateText: (text) => text,
  );

  _ListingHarness() {
    controller.directory.value =
        FileDirectory.fromJson(jsonDecode(_listing('/current')));
  }

  Iterable<String> get names =>
      controller.directory.value.entries.map((entry) => entry.name);

  void reply(String path) {
    expect(fetcher.tryCompleteTask(session, _listing(path), 'false'), isTrue);
  }
}

void main() {
  final descending = {
    SortBy.name: ['gamma.m', 'beta.a', 'alpha.z'],
    SortBy.type: ['alpha.z', 'gamma.m', 'beta.a'],
    SortBy.modified: ['alpha.z', 'gamma.m', 'beta.a'],
    SortBy.size: ['beta.a', 'gamma.m', 'alpha.z'],
  };

  for (final sort in descending.keys) {
    test('refresh retains descending ${sort.name} order', () async {
      final harness = _ListingHarness();
      addTearDown(harness.fetcher.cancelPending);
      harness.controller.changeSortStyle(sort, ascending: false);
      expect(harness.names, descending[sort]);

      final refresh = harness.controller.refresh();
      harness.reply('/current');
      expect(await refresh, isTrue);

      expect(harness.names, descending[sort]);
      expect(harness.controller.sortBy.value, sort);
      expect(harness.controller.sortAscending, isFalse);
    });
  }

  test('refresh retains ascending name order', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    harness.controller.changeSortStyle(SortBy.name);

    final refresh = harness.controller.refresh();
    harness.reply('/current');
    expect(await refresh, isTrue);

    expect(harness.names, ['alpha.z', 'beta.a', 'gamma.m']);
    expect(harness.controller.sortAscending, isTrue);
  });

  test('folder navigation retains the selected sort direction', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    harness.controller.changeSortStyle(SortBy.name, ascending: false);

    final navigation = harness.controller.openDirectory('/next');
    harness.reply('/next');
    expect(await navigation, isTrue);

    expect(harness.controller.directory.value.path, '/next');
    expect(harness.names, descending[SortBy.name]);
  });

  test('pending listing uses the latest selected sort and direction', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    final refresh = harness.controller.refresh();
    harness.controller.changeSortStyle(SortBy.type, ascending: false);

    harness.reply('/current');
    expect(await refresh, isTrue);

    expect(harness.names, descending[SortBy.type]);
    expect(harness.controller.sortBy.value, SortBy.type);
    expect(harness.controller.sortAscending, isFalse);
  });

  test('retired listing cannot replace the current directory', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    final original = harness.controller.directory.value;
    final retiredSession = harness.session;
    final refresh = harness.controller.refresh();
    harness.session = const Uuid().v4obj();

    expect(
        harness.fetcher
            .tryCompleteTask(retiredSession, _listing('/current'), 'false'),
        isTrue);
    expect(await refresh, isFalse);

    expect(harness.controller.directory.value, same(original));
  });

  test('initial home listing retains the selected sort direction', () {
    final harness = _ListingHarness();
    harness.controller.changeSortStyle(SortBy.name, ascending: false);

    harness.controller.initDirAndHome({'value': _listing('/home')});

    expect(harness.controller.options.value.home, '/home');
    expect(harness.controller.directory.value.path, '/home');
    expect(harness.names, descending[SortBy.name]);
  });
}

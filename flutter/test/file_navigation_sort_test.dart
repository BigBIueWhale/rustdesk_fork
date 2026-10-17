import 'dart:async';
import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
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

FileFetcherRequests _localRequests(
        {ReadLocalDirectory? flat, ReadLocalDirectory? empty}) =>
    FileFetcherRequests(
      readDirectory: (_, __, ___) async {},
      readEmptyDirectories: (_, __, ___) async {},
      readDirectoryTree: (_, __, ___, ____, _____) async {},
      readLocalDirectory: flat ?? (_, path, __) async => _listing(path),
      readLocalEmptyDirectories: empty ?? (_, __, ___) async => '[]',
    );

class _ListingHarness {
  var session = const Uuid().v4obj();
  var failDirectoryRequest = false;
  var failVersionQuery = false;
  var nextJobId = 0;
  final sentPaths = <String>[];
  final firstSendEntered = Completer<void>();
  Completer<void>? firstSendRelease;
  late final fetcher = FileFetcher(
    () => session,
    requests: FileFetcherRequests(
      readDirectory: (_, __, ___) async {
        if (failDirectoryRequest) throw StateError('directory unavailable');
      },
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
    comparePeerVersion: (_) {
      if (failVersionQuery) throw StateError('version unavailable');
      return 1;
    },
    jobController: JobController(
      () => session,
      () => null,
      isCurrentSession: (actual) => actual == session,
      nextJobId: () => ++nextJobId,
    ),
    fileFetcher: fetcher,
    getOtherSideDirectoryData: () =>
        DirectoryData(FileDirectory(), DirectoryOptions()),
    translateText: (text) => text,
    requests: FileControllerRequests(
      sendFiles: (_, __, path, ___, ____, _____, ______, _______) async {
        sentPaths.add(path);
        if (!firstSendEntered.isCompleted) firstSendEntered.complete();
        final release = firstSendRelease;
        if (release != null && sentPaths.length == 1) await release.future;
      },
      removeFile: (_, __, ___, ____, _____) async {},
      removeEmptyDirectories: (_, __, ___, ____) async {},
      createDirectory: (_, __, ___, ____) async {},
      renameFile: (_, __, ___, ____, _____) async {},
    ),
  );

  _ListingHarness() {
    controller.directory.value =
        FileDirectory.fromJson(jsonDecode(_listing('/current')))..format(false);
  }

  Iterable<String> get names =>
      controller.directory.value.entries.map((entry) => entry.name);

  void reply(String path) {
    expect(fetcher.tryCompleteTask(session, _listing(path), 'false'), isTrue);
  }

  Entry selectFirst() {
    final entry = controller.directory.value.entries.first;
    controller.selectedItems.add(entry);
    return entry;
  }

  DirectoryData get destination =>
      DirectoryData(FileDirectory()..path = '/destination', DirectoryOptions());
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

  test('refresh retires the preceding directory selection', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    final selected = harness.selectFirst();

    final refresh = harness.controller.refresh();
    harness.reply('/current');
    expect(await refresh, isTrue);

    expect(
        harness.controller.directory.value.entries, isNot(contains(selected)));
    expect(harness.controller.selectedItems.items, isEmpty);
  });

  test('navigation retires the preceding directory selection', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    harness.selectFirst();

    final navigation = harness.controller.openDirectory('/next');
    harness.reply('/next');
    expect(await navigation, isTrue);

    expect(harness.controller.directory.value.path, '/next');
    expect(harness.controller.selectedItems.items, isEmpty);
  });

  test('initial home listing retires the preceding selection', () {
    final harness = _ListingHarness();
    harness.selectFirst();

    harness.controller.initDirAndHome({'value': _listing('/home')});

    expect(harness.controller.directory.value.path, '/home');
    expect(harness.controller.selectedItems.items, isEmpty);
  });

  test('failed navigation retains the displayed directory and selection',
      () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    final original = harness.controller.directory.value;
    final selected = harness.selectFirst();
    harness.failDirectoryRequest = true;

    expect(await harness.controller.openDirectory('/unavailable'), isFalse);

    expect(harness.controller.directory.value, same(original));
    expect(harness.controller.selectedItems.items, [selected]);
  });

  test('sorting a displayed directory retains its selection', () {
    final harness = _ListingHarness();
    final selected = harness.selectFirst();

    harness.controller.changeSortStyle(SortBy.name, ascending: false);

    expect(harness.controller.selectedItems.items, [selected]);
    expect(harness.controller.directory.value.entries, contains(selected));
  });

  test('retired listing preserves the replacement selection', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    final retiredSession = harness.session;
    final refresh = harness.controller.refresh();
    harness.session = const Uuid().v4obj();
    harness.controller.resetForSession();
    final replacement =
        FileDirectory.fromJson(jsonDecode(_listing('/replacement')));
    harness.controller.directory.value = replacement;
    final selected = harness.selectFirst();

    expect(
        harness.fetcher
            .tryCompleteTask(retiredSession, _listing('/current'), 'false'),
        isTrue);
    expect(await refresh, isFalse);

    expect(harness.controller.directory.value, same(replacement));
    expect(harness.controller.selectedItems.items, [selected]);
  });

  test('retired selection cannot dispatch a transfer after refresh', () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    harness.selectFirst();

    final refresh = harness.controller.refresh();
    harness.reply('/current');
    expect(await refresh, isTrue);
    await harness.controller
        .sendFiles(harness.controller.selectedItems, harness.destination);

    expect(harness.sentPaths, isEmpty);
    expect(harness.controller.jobController.jobTable, isEmpty);
  });

  test('current directory selection still dispatches a transfer', () async {
    final harness = _ListingHarness();
    harness.selectFirst();

    await harness.controller
        .sendFiles(harness.controller.selectedItems, harness.destination);

    expect(harness.sentPaths, ['/current/gamma.m']);
    expect(harness.controller.jobController.jobTable, hasLength(1));
  });

  test('published listing does not cancel an admitted transfer snapshot',
      () async {
    final harness = _ListingHarness();
    addTearDown(harness.fetcher.cancelPending);
    harness.controller.selectedItems
      ..add(harness.controller.directory.value.entries[0])
      ..add(harness.controller.directory.value.entries[1]);
    final release = Completer<void>();
    harness.firstSendRelease = release;
    final send = harness.controller
        .sendFiles(harness.controller.selectedItems, harness.destination);
    await harness.firstSendEntered.future;

    try {
      final refresh = harness.controller.refresh();
      harness.reply('/current');
      expect(await refresh, isTrue);
      expect(harness.sentPaths, ['/current/gamma.m']);

      release.complete();
      await send;

      expect(harness.sentPaths, ['/current/gamma.m', '/current/alpha.z']);
    } finally {
      if (!release.isCompleted) release.complete();
      await send;
    }
  });

  test('peer compatibility failure prevents transfer dispatch', () async {
    final harness = _ListingHarness();
    harness.selectFirst();
    harness.failVersionQuery = true;

    await expectLater(
        harness.controller
            .sendFiles(harness.controller.selectedItems, harness.destination),
        throwsA(isA<StateError>()));

    expect(harness.sentPaths, isEmpty);
    expect(harness.controller.jobController.jobTable, isEmpty);
    expect(harness.controller.selectedItems.items, hasLength(1));
  });

  test('local listing methods share capacity before native dispatch', () async {
    final session = const Uuid().v4obj();
    final flat = Completer<String>();
    final empty = Completer<String>();
    var dispatches = 0;
    final fetcher = FileFetcher(() => session,
        maxPending: 2,
        requests: _localRequests(flat: (actual, path, hidden) {
          expect(actual, session);
          expect(path, '/flat');
          expect(hidden, isTrue);
          dispatches++;
          return flat.future;
        }, empty: (actual, path, hidden) {
          expect(actual, session);
          expect(path, '/empty');
          expect(hidden, isFalse);
          dispatches++;
          return empty.future;
        }));
    final first = fetcher.fetchDirectory('/flat', true, true);
    final second = fetcher.readEmptyDirs('/empty', true, false);
    try {
      await expectLater(fetcher.fetchDirectory('/flat', true, true)
              .timeout(const Duration(milliseconds: 500)),
          throwsA(isA<StateError>()));
      await expectLater(fetcher.readEmptyDirs('/empty', true, false)
              .timeout(const Duration(milliseconds: 500)),
          throwsA(isA<StateError>()));
      await expectLater(fetcher.fetchDirectory('/remote', false, false),
          throwsA(isA<StateError>()));
      expect(dispatches, 2);
    } finally {
      flat.complete(_listing('/flat'));
      empty.complete('[]');
      expect((await first).path, '/flat');
      expect(await second, isEmpty);
      fetcher.cancelPending();
    }
  });

  test('remote listing owner also bounds local listing admission', () async {
    final session = const Uuid().v4obj();
    var localDispatches = 0;
    final fetcher = FileFetcher(() => session,
        maxPending: 1,
        requests: _localRequests(flat: (_, path, __) async {
          localDispatches++;
          return _listing(path);
        }, empty: (_, __, ___) async {
          localDispatches++;
          return '[]';
        }));
    final remote = fetcher.fetchDirectory('/remote', false, false);
    try {
      await expectLater(fetcher.fetchDirectory('/local', true, false),
          throwsA(isA<StateError>()));
      await expectLater(fetcher.readEmptyDirs('/local', true, false),
          throwsA(isA<StateError>()));
      expect(localDispatches, 0);
    } finally {
      expect(fetcher.tryCompleteTask(session, _listing('/remote'), 'false'),
          isTrue);
      await remote;
    }
    expect((await fetcher.fetchDirectory('/local', true, false)).path, '/local');
    expect(await fetcher.readEmptyDirs('/local', true, false), isEmpty);
    expect(localDispatches, 2);
  });

  test('cancelled local request retains capacity until native completion',
      () async {
    var session = const Uuid().v4obj();
    final native = Completer<String>();
    var dispatches = 0;
    final fetcher = FileFetcher(() => session,
        maxPending: 1,
        requests: _localRequests(flat: (_, path, __) {
          dispatches++;
          return dispatches == 1 ? native.future : Future.value(_listing(path));
        }));
    final result = fetcher.fetchDirectory('/old', true, false);
    final cancelled = expectLater(
        result.timeout(const Duration(milliseconds: 500)),
        throwsA(isA<StateError>()));
    try {
      fetcher.cancelPending();
      await cancelled;
      session = const Uuid().v4obj();
      fetcher.cancelPending();
      await expectLater(fetcher.fetchDirectory('/new', true, false),
          throwsA(isA<StateError>()));
      await expectLater(fetcher.fetchDirectory('/remote', false, false),
          throwsA(isA<StateError>()));
      expect(dispatches, 1);
    } finally {
      native.complete(_listing('/old'));
      await Future<void>.delayed(Duration.zero);
    }
    expect((await fetcher.fetchDirectory('/new', true, false)).path, '/new');
    expect(dispatches, 2);
  });

  test('timed out local request retains capacity through late native error',
      () async {
    final session = const Uuid().v4obj();
    final native = Completer<String>();
    var dispatches = 0;
    final fetcher = FileFetcher(() => session,
        maxPending: 1,
        requestTimeout: const Duration(milliseconds: 20),
        requests: _localRequests(empty: (_, __, ___) {
          dispatches++;
          return dispatches == 1 ? native.future : Future.value('[]');
        }));
    final result = fetcher.readEmptyDirs('/slow', true, false);
    final observed = result.then<Object>((_) => 'unexpected success',
        onError: (Object error) => error);
    try {
      expect(await observed.timeout(const Duration(milliseconds: 500)),
          isA<TimeoutException>());
      await expectLater(fetcher.readEmptyDirs('/retry', true, false),
          throwsA(isA<StateError>()));
      expect(dispatches, 1);
    } finally {
      native.completeError(const FfiException('RESULT_ERROR', 'late native error'));
      await Future<void>.delayed(Duration.zero);
    }
    expect(await fetcher.readEmptyDirs('/retry', true, false), isEmpty);
    expect(dispatches, 2);
  });

  test('local error and malformed JSON release exact capacity slots', () async {
    final session = const Uuid().v4obj();
    final immediate = StateError('synchronous dispatch failure');
    const native = FfiException('RESULT_ERROR', 'Permission denied (os error 13)');
    var mode = 0;
    Future<String> request(_, String path, __) {
      if (mode == 0) throw immediate;
      if (mode == 1) return Future.error(native);
      if (mode == 2) return Future.value('invalid JSON');
      return Future.value(_listing(path));
    }

    final fetcher = FileFetcher(() => session,
        maxPending: 1, requests: _localRequests(flat: request));
    await expectLater(fetcher.fetchDirectory('/failure', true, false),
        throwsA(same(immediate)));
    mode = 1;
    await expectLater(fetcher.fetchDirectory('/failure', true, false),
        throwsA(same(native)));
    mode = 2;
    await expectLater(fetcher.fetchDirectory('/failure', true, false),
        throwsA(isA<FormatException>()));
    mode = 3;
    expect((await fetcher.fetchDirectory('/valid', true, false)).path, '/valid');
    expect(await fetcher.readEmptyDirs('/valid', true, false), isEmpty);
  });

  test('retired local session refuses dispatch and late native success', () async {
    var session = const Uuid().v4obj();
    final retiredSession = session;
    final native = Completer<String>();
    var dispatches = 0;
    final fetcher = FileFetcher(() => session,
        maxPending: 1,
        requests: _localRequests(flat: (_, path, __) {
          dispatches++;
          return dispatches == 1 ? native.future : Future.value(_listing(path));
        }));
    final result = fetcher.fetchDirectory('/old', true, false);
    final retired = expectLater(result, throwsA(isA<StateError>()));
    session = const Uuid().v4obj();
    try {
      await expectLater(
          fetcher.readEmptyDirs('/stale', true, false,
              expectedSessionId: retiredSession),
          throwsA(isA<StateError>()));
      expect(dispatches, 1);
    } finally {
      native.complete(_listing('/old'));
      await retired;
    }
    expect((await fetcher.fetchDirectory('/new', true, false)).path, '/new');
    expect(dispatches, 2);
  });
}

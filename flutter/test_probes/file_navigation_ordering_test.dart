import 'dart:convert';

import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

String _directory(String path) => jsonEncode({
      'id': 0,
      'path': path,
      'entries': [
        {'entry_type': 4, 'name': 'entry.txt', 'size': 1, 'modified_time': 1},
      ],
    });

class _NavigationProbe {
  final session = const Uuid().v4obj();
  var failDirectoryRequest = false;
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
    comparePeerVersion: (_) => 1,
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

  _NavigationProbe() {
    controller.directory.value =
        FileDirectory.fromJson(jsonDecode(_directory('/current')));
  }

  void reply(String path) {
    expect(fetcher.tryCompleteTask(session, _directory(path), 'false'), isTrue);
  }

  Entry selectFirst() {
    final entry = controller.directory.value.entries.first;
    controller.selectedItems.add(entry);
    return entry;
  }

  String get path => controller.directory.value.path;

  bool keepsSelection(Entry entry) =>
      controller.selectedItems.items.contains(entry);
}

void main() {
  test('new destination survives an older navigation response', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final older = probe.controller.openDirectory('/older');
    final newer = probe.controller.openDirectory('/newer');
    probe.reply('/newer');
    expect(await newer, isTrue);
    final selected = probe.selectFirst();

    probe.reply('/older');
    final olderAccepted = await older;

    expect({
      'olderAccepted': olderAccepted,
      'path': probe.path,
      'selectionPreserved': probe.keepsSelection(selected),
    }, {
      'olderAccepted': false,
      'path': '/newer',
      'selectionPreserved': true,
    });
  });

  test('pending destination rejects an older navigation result', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final older = probe.controller.openDirectory('/older');
    final newer = probe.controller.openDirectory('/newer');
    probe.reply('/older');
    final olderAccepted = await older;
    final pathBeforeNewer = probe.path;
    probe.reply('/newer');
    expect(await newer, isTrue);

    expect({
      'olderAccepted': olderAccepted,
      'pathBeforeNewer': pathBeforeNewer,
      'path': probe.path,
    }, {
      'olderAccepted': false,
      'pathBeforeNewer': '/current',
      'path': '/newer',
    });
  });

  test('failed destination does not restore an older request', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final selected = probe.selectFirst();
    final older = probe.controller.openDirectory('/older');
    probe.failDirectoryRequest = true;
    expect(await probe.controller.openDirectory('/unavailable'), isFalse);
    probe.failDirectoryRequest = false;

    probe.reply('/older');
    final olderAccepted = await older;

    expect({
      'olderAccepted': olderAccepted,
      'path': probe.path,
      'selectionPreserved': probe.keepsSelection(selected),
    }, {
      'olderAccepted': false,
      'path': '/current',
      'selectionPreserved': true,
    });
  });

  test('old refresh cannot replace a newer destination', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final refresh = probe.controller.refresh();
    final navigation = probe.controller.openDirectory('/newer');
    probe.reply('/newer');
    expect(await navigation, isTrue);
    final selected = probe.selectFirst();

    probe.reply('/current');
    final refreshAccepted = await refresh;

    expect({
      'refreshAccepted': refreshAccepted,
      'path': probe.path,
      'selectionPreserved': probe.keepsSelection(selected),
    }, {
      'refreshAccepted': false,
      'path': '/newer',
      'selectionPreserved': true,
    });
  });

  test('background refresh cannot cancel pending navigation', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final navigation = probe.controller.openDirectory('/newer');
    final refresh = probe.controller.refresh();
    probe.reply('/current');
    expect(await refresh, isTrue);
    probe.reply('/newer');

    expect(await navigation, isTrue);
    expect(probe.path, '/newer');
  });

  test('duplicate destination does not retire its pending read', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final first = probe.controller.openDirectory('/newer');
    expect(await probe.controller.openDirectory('/newer'), isFalse);
    probe.reply('/newer');

    expect(await first, isTrue);
    expect(probe.path, '/newer');
  });

  test('reset retires a pending read within the same session', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final pending = probe.controller.openDirectory('/older');
    probe.controller.resetForSession();
    probe.controller.directory.value =
        FileDirectory.fromJson(jsonDecode(_directory('/reset')));
    final selected = probe.selectFirst();

    probe.reply('/older');
    final accepted = await pending;

    expect({
      'accepted': accepted,
      'path': probe.path,
      'selectionPreserved': probe.keepsSelection(selected),
    }, {
      'accepted': false,
      'path': '/reset',
      'selectionPreserved': true,
    });
  });

  test('initial home cannot replace a pending destination', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final selected = probe.selectFirst();
    final pending = probe.controller.openDirectory('/newer');

    probe.controller.initDirAndHome({'value': _directory('/home')});
    final pathDuringNavigation = probe.path;
    final selectionPreserved =
        probe.keepsSelection(selected);
    probe.reply('/newer');
    expect(await pending, isTrue);

    expect({
      'pathDuringNavigation': pathDuringNavigation,
      'selectionPreserved': selectionPreserved,
      'path': probe.path,
    }, {
      'pathDuringNavigation': '/current',
      'selectionPreserved': true,
      'path': '/newer',
    });
  });

  test('initial home cannot replace an established destination', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final pending = probe.controller.openDirectory('/newer');
    probe.reply('/newer');
    expect(await pending, isTrue);
    final selected = probe.selectFirst();

    probe.controller.initDirAndHome({'value': _directory('/home')});

    expect({
      'homeMetadata': probe.controller.options.value.home,
      'path': probe.path,
      'selectionPreserved': probe.keepsSelection(selected),
    }, {
      'homeMetadata': '/home',
      'path': '/newer',
      'selectionPreserved': true,
    });
  });

  test('resolved home reply completes its directory request', () async {
    final probe = _NavigationProbe();
    addTearDown(probe.fetcher.cancelPending);
    final pending = probe.controller.openDirectory('');
    final value = _directory('/resolved-home');

    // Exercise the production receiveFileDir order with its actual consumers.
    probe.controller.initDirAndHome({'value': value});
    final correlated =
        probe.fetcher.tryCompleteTask(probe.session, value, 'false');
    final publishedPath = probe.path;
    // Retire any unmatched waiter without spending its real two-second timeout.
    probe.fetcher.cancelPending();
    final completed = await pending;

    expect({
      'correlated': correlated,
      'completed': completed,
      'publishedPath': publishedPath,
    }, {
      'correlated': true,
      'completed': true,
      'publishedPath': '/resolved-home',
    });
  });
}

import 'dart:async';

import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart' show FFI;
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

class _Owner implements FFI {
  @override
  final sessionId = Uuid().v4obj();
  @override
  final clientOwnerId = Uuid().v4obj();
  final checks = <List<UuidValue>>[];

  @override
  bool isCurrentSessionOwner(UuidValue session, UuidValue client) {
    checks.add([session, client]);
    return false;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw StateError('Keyboard refresh must not use an uncontrolled session');
  }
}

// Exact asynchronous assignment at d4a54dd4, with the native read supplied as
// a controlled future and the receiver made explicit. No old whole-app claim.
Future<void> _before(InputModel model, Future<String?> read) async {
  model.keyboardMode = await read ?? kKeyLegacyMode;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Owner owner;
  late InputModel model;
  setUp(() {
    owner = _Owner();
    model = InputModel(WeakReference(owner));
  });
  tearDown(() => model.relativeMouseMode.close());

  Future<bool> refresh(Future<String?> Function() read, {
    bool Function()? current,
    bool Function()? flutter,
    bool Function(String)? supported,
  }) => model.refreshKeyboardMode(
    readMode: read,
    isCurrent: current ?? () => true,
    useFlutterInput: flutter ?? () => false,
    supportsMode: supported ?? (_) => true,
  );

  test('keyboard refresh keeps the newest completed request', () async {
    final oldBefore = Completer<String?>();
    final newBefore = Completer<String?>();
    final firstBefore = _before(model, oldBefore.future);
    final secondBefore = _before(model, newBefore.future);
    newBefore.complete(kKeyTranslateMode);
    await secondBefore;
    oldBefore.complete(kKeyLegacyMode);
    await firstBefore;
    expect(model.keyboardMode, kKeyLegacyMode);

    final old = Completer<String?>();
    final newer = Completer<String?>();
    final first = refresh(() => old.future);
    final second = refresh(() => newer.future);
    newer.complete(kKeyTranslateMode);
    expect(await second, isTrue);
    old.complete(kKeyLegacyMode);
    expect(await first, isFalse);
    expect(model.keyboardMode, kKeyTranslateMode);
  });

  test('keyboard refresh retires changed owners and refuses late admission', () async {
    var current = true;
    final pending = Completer<String?>();
    model.keyboardMode = kKeyMapMode;
    final reading = refresh(() => pending.future, current: () => current);
    current = false;
    pending.complete(kKeyLegacyMode);
    expect(await reading, isFalse);
    expect(model.keyboardMode, kKeyMapMode);
    var reads = 0;
    var policies = 0;
    expect(await refresh(() async { reads++; return kKeyLegacyMode; },
        current: () => current, flutter: () { policies++; return true; }), isFalse);
    expect(reads, 0);
    expect(policies, 0);
    current = true;
    expect(await refresh(() async => kKeyTranslateMode, current: () => current), isTrue);
    expect(model.keyboardMode, kKeyTranslateMode);
  });

  test('keyboard Flutter source choice retires an older native read', () async {
    final pending = Completer<String?>();
    final reading = refresh(() => pending.future);
    final supported = <String>[];
    expect(await refresh(() => throw StateError('unexpected native read'),
        flutter: () => true, supported: (mode) { supported.add(mode); return true; }), isTrue);
    expect(supported, [kKeyMapMode]);
    expect(model.keyboardMode, kKeyMapMode);
    pending.complete(kKeyLegacyMode);
    expect(await reading, isFalse);
    expect(model.keyboardMode, kKeyMapMode);
  });

  test('keyboard refresh rejects an input source changed during its read', () async {
    var flutter = false;
    model.keyboardMode = kKeyTranslateMode;
    final pending = Completer<String?>();
    final reading = refresh(() => pending.future, flutter: () => flutter);
    flutter = true;
    pending.complete(kKeyLegacyMode);
    expect(await reading, isFalse);
    expect(model.keyboardMode, kKeyTranslateMode);
    expect(await refresh(() => throw StateError('unexpected native read'),
        flutter: () => flutter), isTrue);
    expect(model.keyboardMode, kKeyMapMode);
  });

  test('keyboard refresh observes failed reads without publishing stale state', () async {
    model.keyboardMode = kKeyTranslateMode;
    final old = Completer<String?>();
    final reading = refresh(() => old.future);
    expect(await refresh(() => Future.error(StateError('read failed'))), isFalse);
    old.complete(kKeyLegacyMode);
    expect(await reading, isFalse);
    expect(model.keyboardMode, kKeyTranslateMode);
    final retired = Completer<String?>();
    final retiredRead = refresh(() => retired.future);
    expect(await refresh(() async => kKeyMapMode), isTrue);
    retired.completeError(StateError('late read failed'));
    expect(await retiredRead, isFalse);
    expect(model.keyboardMode, kKeyMapMode);
    expect(await refresh(() => throw StateError('synchronous read failed')), isFalse);
    expect(await refresh(() async => 'invalid-mode'), isFalse);
    expect(model.keyboardMode, kKeyMapMode);
    expect(await refresh(() async => kKeyLegacyMode), isTrue);
  });

  test('keyboard refresh preserves compatibility choices and null fallback', () async {
    for (final allowed in [{kKeyLegacyMode}, <String>{}]) {
      final checked = <String>[];
      expect(await refresh(() => throw StateError('unexpected native read'),
          flutter: () => true,
          supported: (mode) { checked.add(mode); return allowed.contains(mode); }), isTrue);
      expect(checked, [kKeyMapMode, kKeyLegacyMode]);
      expect(model.keyboardMode, kKeyLegacyMode);
    }
    for (final value in [kKeyMapMode, kKeyTranslateMode, 'auto', null]) {
      expect(await refresh(() async => value), isTrue);
      expect(model.keyboardMode, value ?? kKeyLegacyMode);
    }
  });

  test('keyboard retirement rejects an old reply and permits a fresh read', () async {
    final pending = Completer<String?>();
    final reading = refresh(() => pending.future);
    model.retireKeyboardMode();
    expect(model.keyboardMode, isEmpty);
    expect(await refresh(() async => kKeyTranslateMode), isTrue);
    pending.complete(kKeyLegacyMode);
    expect(await reading, isFalse);
    expect(model.keyboardMode, kKeyTranslateMode);
  });

  test('keyboard refresh adapter rejects a retired exact owner before native access', () async {
    expect(await model.updateKeyboardMode(), isFalse);
    expect(owner.checks, [[owner.sessionId, owner.clientOwnerId]]);
    expect(model.keyboardMode, isEmpty);
  });
}

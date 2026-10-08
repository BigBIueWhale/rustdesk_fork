import 'dart:async';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/rendering.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common.dart' show SessionID, isMobile;
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/input_model.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/rgba_publication_order.dart';
import 'package:flutter_hbb/utils/image.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

// Only the asynchronous geometry boundary is controlled. ImageModel, publication
// ordering and raw-pixel conversion execute their production implementations.
enum _GeometryFailure { view, scroll, edge, cursor }

class _ImageSession implements FFI {
  _ImageSession({this.failFirstAt})
      : cursorModel = _ImageCursor(failFirstAt == _GeometryFailure.cursor);

  final _GeometryFailure? failFirstAt;

  @override
  final SessionID sessionId = Uuid().v4obj();
  @override
  final SessionID clientOwnerId = Uuid().v4obj();
  @override
  late final _PendingImageGeometry canvasModel =
      _PendingImageGeometry(this, failFirstAt);
  @override
  final _ImageCursor cursorModel;
  @override
  late final _ImageTopology ffiModel = _ImageTopology(sessionId);
  @override
  late final ImageModel imageModel = ImageModel(WeakReference<FFI>(this));

  @override
  bool isCurrentSession(SessionID expected) => expected == sessionId;

  @override
  bool isCurrentSessionOwner(SessionID session, SessionID owner) =>
      isCurrentSession(session) && owner == clientOwnerId;

  Future<bool> publish(int publication) => imageModel.onRgba(
        sessionId,
        0,
        Uint8List(16)..fillRange(0, 16, publication == 1 ? 255 : 127),
        publication: publication,
        expectedDisplayTopologyRevision: 0,
        expectedPresentationRevision: imageModel.presentationRevision,
      );

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _ImageTopology implements FfiModel {
  _ImageTopology(this.sessionId);

  final SessionID sessionId;
  int revision = 0;
  @override
  final pi = PeerInfo()
    ..displays.add(Display()
      ..width = 2
      ..height = 2);
  @override
  ui.Rect get rect => const ui.Rect.fromLTWH(0, 0, 2, 2);

  @override
  bool isCurrentDisplayTopology(SessionID expected, int expectedRevision) =>
      expected == sessionId && expectedRevision == revision;

  @override
  int? currentDisplayTopologyRevision(SessionID expected) =>
      expected == sessionId ? revision : null;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _PendingImageGeometry extends CanvasModel {
  _PendingImageGeometry(FFI ffi, this.failFirstAt) : super(WeakReference(ffi));

  final _GeometryFailure? failFirstAt;
  final started = List.generate(2, (_) => Completer<void>());
  final release = List.generate(2, (_) => Completer<void>());
  int calls = 0;
  bool failed = false;

  void failOnceAt(_GeometryFailure stage) {
    if (!failed && failFirstAt == stage) {
      failed = true;
      throw StateError('injected first-image ${stage.name} failure');
    }
  }

  @override
  Future<bool> updateViewStyle(
      {required CanvasUpdateOwner? owner,
      bool refreshMousePos = true,
      bool notify = true}) async {
    final index = calls++;
    started[index].complete();
    await release[index].future;
    if (index == 0) failOnceAt(_GeometryFailure.view);
    return owner?.isCurrent ?? false;
  }

  @override
  Future<bool> updateScrollStyle({required CanvasUpdateOwner? owner}) async {
    failOnceAt(_GeometryFailure.scroll);
    return owner?.isCurrent ?? false;
  }

  @override
  Future<bool> initializeEdgeScrollEdgeThickness(
      {required CanvasUpdateOwner? owner}) async {
    failOnceAt(_GeometryFailure.edge);
    return owner?.isCurrent ?? false;
  }

  void releaseAll() {
    for (final pending in release) {
      if (!pending.isCompleted) pending.complete();
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _ImageCursor implements CursorModel {
  _ImageCursor(this.failFirstUpdate);

  final bool failFirstUpdate;
  bool failed = false;

  @override
  void updateDisplayOrigin(double x, double y, {updateCursorPos = true}) {
    if (failFirstUpdate && !failed) {
      failed = true;
      throw StateError('injected first-image cursor failure');
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _CursorInitializationSession implements FFI {
  @override
  final SessionID sessionId = Uuid().v4obj();
  @override
  late final _ImageTopology ffiModel = _ImageTopology(sessionId);
  @override
  late final ImageModel imageModel = ImageModel(WeakReference<FFI>(this));
  @override
  late final CanvasModel canvasModel = CanvasModel(WeakReference<FFI>(this));
  @override
  late final CursorModel cursorModel = CursorModel(WeakReference<FFI>(this));
  @override
  final _CursorInitializationInput inputModel = _CursorInitializationInput();

  @override
  bool isCurrentSession(SessionID expected) => expected == sessionId;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _CursorInitializationInput implements InputModel {
  final moves = <Offset>[];
  int refreshes = 0;

  @override
  void refreshMousePos() => refreshes++;

  @override
  Future<void> moveMouse(double x, double y) async => moves.add(Offset(x, y));

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

enum _CanvasPreferenceStage { view, scroll, edge }

class _PendingCanvasPreferences implements CanvasPreferences {
  _PendingCanvasPreferences(this.stage);

  final _CanvasPreferenceStage stage;
  final started = Completer<void>();
  final release = Completer<void>();

  Future<void> waitFor(_CanvasPreferenceStage query) async {
    if (query != stage) return;
    if (!started.isCompleted) started.complete();
    await release.future;
  }

  @override
  String? viewStyle(SessionID sessionId) => kRemoteViewStyleCustom;

  @override
  Future<double> customScale(SessionID sessionId) async {
    await waitFor(_CanvasPreferenceStage.view);
    return 2.25;
  }

  @override
  Future<String?> scrollStyle(SessionID sessionId) async {
    await waitFor(_CanvasPreferenceStage.scroll);
    return kRemoteScrollStyleEdge;
  }

  @override
  Future<int?> edgeThickness(SessionID sessionId) async {
    await waitFor(_CanvasPreferenceStage.edge);
    return 41;
  }
}

class _CanvasPreferenceSession implements FFI {
  _CanvasPreferenceSession(this.preferences);

  final _PendingCanvasPreferences preferences;
  @override
  final SessionID sessionId = Uuid().v4obj();
  @override
  final SessionID clientOwnerId = Uuid().v4obj();
  @override
  late final _ImageTopology ffiModel = _ImageTopology(sessionId);
  @override
  late final ImageModel imageModel = ImageModel(WeakReference<FFI>(this));
  @override
  late final CanvasModel canvasModel = CanvasModel(WeakReference<FFI>(this),
      preferences: preferences);
  @override
  late final CursorModel cursorModel = CursorModel(WeakReference<FFI>(this));
  @override
  final _CursorInitializationInput inputModel = _CursorInitializationInput();

  @override
  bool isCurrentSession(SessionID expected) => expected == sessionId;

  @override
  bool isCurrentSessionOwner(SessionID session, SessionID owner) =>
      isCurrentSession(session) && owner == clientOwnerId;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<bool> _readCanvasPreference(
    _CanvasPreferenceSession session, _CanvasPreferenceStage stage,
    {CanvasUpdateOwner? owner}) async {
  final canvas = session.canvasModel;
  final selectedOwner = owner ??
      canvas.captureUpdateOwner(
          expectedSessionId: session.sessionId,
          expectedDisplayTopologyRevision: 0);
  switch (stage) {
    case _CanvasPreferenceStage.view:
      return canvas.updateViewStyle(owner: selectedOwner);
    case _CanvasPreferenceStage.scroll:
      return canvas.updateScrollStyle(owner: selectedOwner);
    case _CanvasPreferenceStage.edge:
      return canvas.initializeEdgeScrollEdgeThickness(owner: selectedOwner);
  }
}

List<Object> _canvasPreferenceState(CanvasModel canvas) => [
      canvas.x,
      canvas.y,
      canvas.scale,
      canvas.size,
      canvas.viewStyle,
      canvas.scrollStyle,
      canvas.scrollX,
      canvas.scrollY,
      canvas.edgeScrollEdgeThickness,
      canvas.imageOverflow.value,
    ];

Future<void> _observeMobileCanvas(
    Future<void> Function(_CanvasPreferenceSession, VoidCallback) observe) async {
  final previousMobile = isMobile;
  isMobile = true;
  final session = _CanvasPreferenceSession(
      _PendingCanvasPreferences(_CanvasPreferenceStage.view));
  var disposed = false;
  void disposeCanvas() {
    session.canvasModel.dispose();
    disposed = true;
  }

  try {
    await observe(session, disposeCanvas);
  } finally {
    try {
      if (!disposed) {
        session.canvasModel.clear();
        disposeCanvas();
      }
      session.imageModel.dispose();
      session.cursorModel.dispose();
    } finally {
      isMobile = previousMobile;
    }
  }
}

Future<void> _observeCursorInitialization(
    Future<void> Function(_CursorInitializationSession) observe) async {
  final session = _CursorInitializationSession();
  // Establish real model state without sending input to a peer.
  session.cursorModel.updateDisplayOriginWithCursor(0, 0, 12, 24);
  session.canvasModel.update(17, 23, 1.5);
  session.inputModel.moves.clear();
  try {
    await observe(session);
  } finally {
    session.imageModel.clearImage();
    session.imageModel.dispose();
    session.cursorModel.dispose();
    session.canvasModel.dispose();
  }
}

Future<void> _observeImagePublications(
    Future<void> Function(_ImageSession, List<Future<bool>>, List<ui.Image>)
        observe,
    {_GeometryFailure? failFirstAt}) async {
  final session = _ImageSession(failFirstAt: failFirstAt);
  final publications = <Future<bool>>[];
  final images = <ui.Image>[];
  final disposals = <ui.Image>[];
  final previousCreate = ui.Image.onCreate;
  final previousDispose = ui.Image.onDispose;
  ui.Image.onCreate = (image) {
    previousCreate?.call(image);
    images.add(image);
  };
  ui.Image.onDispose = (image) {
    previousDispose?.call(image);
    disposals.add(image);
  };
  try {
    for (var publication = 1; publication <= 2; publication++) {
      publications.add(session.publish(publication));
      await session.canvasModel.started[publication - 1].future
          .timeout(const Duration(seconds: 5));
    }
    expect(images, hasLength(2));
    expect(session.imageModel.image, isNull);
    expect(session.imageModel.presentationPublication, isNull);
    await observe(session, publications, images);
  } finally {
    try {
      session.canvasModel.releaseAll();
      await Future.wait(publications).timeout(const Duration(seconds: 5));
      session.imageModel.clearImage();
      expect(images.every((image) => image.debugDisposed), isTrue);
      expect(images.map(_openHandles), everyElement(0));
      expect(
          images.map((image) =>
              disposals.where((entry) => identical(entry, image)).length),
          everyElement(1));
    } finally {
      for (final image in images) {
        if (!image.debugDisposed) image.dispose();
      }
      ui.Image.onCreate = previousCreate;
      ui.Image.onDispose = previousDispose;
      session.canvasModel.dispose();
      session.imageModel.dispose();
    }
  }
}

Future<ui.Image> _solidImage(ui.Color color) async {
  final recorder = ui.PictureRecorder();
  final canvas = ui.Canvas(recorder);
  canvas.drawRect(
    const ui.Rect.fromLTWH(0, 0, 2, 2),
    ui.Paint()..color = color,
  );
  final picture = recorder.endRecording();
  final image = await picture.toImage(2, 2);
  picture.dispose();
  return image;
}

Future<ui.Image> _solidRawBgraImage(ui.Color color) async {
  final pixels = Uint8List(2 * 2 * 4);
  for (var offset = 0; offset < pixels.length; offset += 4) {
    pixels[offset] = color.blue;
    pixels[offset + 1] = color.green;
    pixels[offset + 2] = color.red;
    pixels[offset + 3] = color.alpha;
  }
  final image = await decodeImageFromPixels(
    pixels,
    2,
    2,
    ui.PixelFormat.bgra8888,
  );
  if (image == null) {
    throw StateError('raw BGRA image decoding failed');
  }
  return image;
}

int _openHandles(ui.Image image) =>
    image.debugGetOpenHandleStackTraces()!.length;

Future<Map<String, Object>> _conversionFailureHandles(String failingStage) async {
  final previousCreate = ui.Image.onCreate;
  final previousDispose = ui.Image.onDispose;
  final created = Completer<ui.Image>();
  final images = <ui.Image>[];
  final disposals = <ui.Image>[];
  final stages = <String>[];
  ui.Image? result;
  ui.Image.onCreate = (image) {
    previousCreate?.call(image);
    images.add(image);
    if (!created.isCompleted) created.complete(image);
  };
  ui.Image.onDispose = (image) {
    previousDispose?.call(image);
    disposals.add(image);
  };
  try {
    result = await decodeImageFromPixels(
      Uint8List(16)..fillRange(0, 16, 255),
      2,
      2,
      ui.PixelFormat.bgra8888,
      onStage: (stage) {
        stages.add(stage);
        if (stage == failingStage) {
          throw StateError('injected conversion observer failure at $stage');
        }
      },
    );
    final imagesAtReturn = images.length;
    final disposedAtReturn = images.length == 1 && images.single.debugDisposed;
    // Observe the engine's exact callback, even if the faulty implementation
    // returned before its outstanding frame completed. A quiet delay is not proof.
    final image = await created.future.timeout(const Duration(seconds: 5));
    expect(result, isNull);
    expect(stages.where((stage) => stage == failingStage), hasLength(1));
    expect(images, hasLength(1));
    expect(image.width, 2);
    expect(image.height, 2);
    return <String, Object>{
      'imagesAtReturn': imagesAtReturn,
      'disposedAtReturn': disposedAtReturn,
      'disposed': image.debugDisposed,
      'openHandles': _openHandles(image),
      'disposals': disposals.where((entry) => identical(entry, image)).length,
    };
  } finally {
    try {
      for (final image in images) {
        if (!image.debugDisposed) image.dispose();
      }
      if (result != null && !result.debugDisposed) result.dispose();
    } finally {
      ui.Image.onCreate = previousCreate;
      ui.Image.onDispose = previousDispose;
    }
  }
}

void main() {
  for (final retirement in ['presentation', 'topology', 'clear', 'dispose']) {
    testWidgets('mobile focus $retirement preserves current geometry',
        (tester) async {
      await _observeMobileCanvas((session, disposeCanvas) async {
        final canvas = session.canvasModel;
        var notifications = 0;
        canvas.addListener(() => notifications++);
        canvas.update(31, 37, 1.75);
        canvas.mobileFocusCanvasCursor();
        switch (retirement) {
          case 'presentation':
            session.imageModel.retirePresentation();
            break;
          case 'topology':
            session.ffiModel.revision++;
            break;
          case 'clear':
            canvas.clear();
            canvas.update(31, 37, 1.75);
            break;
          case 'dispose':
            disposeCanvas();
            // New requests must not create work on a disposed model either.
            canvas.mobileFocusCanvasCursor();
            canvas.saveMobileOffsetBeforeSoftKeyboard();
            canvas.restoreMobileOffsetAfterSoftKeyboard();
            break;
        }
        notifications = 0;
        final before = _canvasPreferenceState(canvas);
        await tester.pump(const Duration(milliseconds: 100));
        expect([
          _canvasPreferenceState(canvas),
          notifications,
          tester.takeException(),
        ], [before, 0, null]);

        if (retirement != 'dispose') {
          canvas.mobileFocusCanvasCursor();
          await tester.pump(const Duration(milliseconds: 100));
          expect([
            canvas.size,
            canvas.x,
            canvas.y,
            notifications,
          ], [
            canvas.getSize(),
            (canvas.size.width - 2 * canvas.scale) / 2,
            (canvas.size.height - 2 * canvas.scale) / 2,
            1,
          ]);
        }
      });
    }, timeout: const Timeout(Duration(seconds: 30)));

    testWidgets('mobile restore $retirement preserves current geometry',
        (tester) async {
      await _observeMobileCanvas((session, disposeCanvas) async {
        final canvas = session.canvasModel;
        var notifications = 0;
        canvas.addListener(() => notifications++);
        canvas.update(7, 11, 1.25);
        canvas.saveMobileOffsetBeforeSoftKeyboard();
        canvas.update(31, 37, 1.75);
        canvas.restoreMobileOffsetAfterSoftKeyboard();
        switch (retirement) {
          case 'presentation':
            session.imageModel.retirePresentation();
            break;
          case 'topology':
            session.ffiModel.revision++;
            break;
          case 'clear':
            canvas.clear();
            canvas.update(31, 37, 1.75);
            break;
          case 'dispose':
            disposeCanvas();
            break;
        }
        notifications = 0;
        final before = _canvasPreferenceState(canvas);
        await tester.pump(const Duration(milliseconds: 100));
        expect([
          _canvasPreferenceState(canvas),
          notifications,
          tester.takeException(),
        ], [before, 0, null]);

        if (retirement != 'dispose') {
          canvas.saveMobileOffsetBeforeSoftKeyboard();
          canvas.update(5, 9, 0.75);
          notifications = 0;
          canvas.restoreMobileOffsetAfterSoftKeyboard();
          await tester.pump(const Duration(milliseconds: 100));
          expect([canvas.x, canvas.y, canvas.scale, notifications],
              [31, 37, 1.75, 1]);
        }
      });
    }, timeout: const Timeout(Duration(seconds: 30)));
  }

  for (final retirement in ['presentation', 'topology']) {
    testWidgets('saved mobile snapshot $retirement refuses a later restore',
        (tester) async {
      await _observeMobileCanvas((session, _) async {
        final canvas = session.canvasModel;
        var notifications = 0;
        canvas.addListener(() => notifications++);
        canvas.update(7, 11, 1.25);
        canvas.saveMobileOffsetBeforeSoftKeyboard();
        if (retirement == 'presentation') {
          session.imageModel.retirePresentation();
        } else {
          session.ffiModel.revision++;
        }
        canvas.update(31, 37, 1.75);
        notifications = 0;
        final before = _canvasPreferenceState(canvas);
        canvas.restoreMobileOffsetAfterSoftKeyboard();
        await tester.pump(const Duration(milliseconds: 100));
        expect([
          _canvasPreferenceState(canvas),
          notifications,
          tester.takeException(),
        ], [before, 0, null]);

        canvas.saveMobileOffsetBeforeSoftKeyboard();
        canvas.update(5, 9, 0.75);
        notifications = 0;
        canvas.restoreMobileOffsetAfterSoftKeyboard();
        await tester.pump(const Duration(milliseconds: 100));
        expect([canvas.x, canvas.y, canvas.scale, notifications],
            [31, 37, 1.75, 1]);
      });
    }, timeout: const Timeout(Duration(seconds: 30)));
  }

  testWidgets('mobile keyboard cycles focus and restore useful geometry',
      (tester) async {
    await _observeMobileCanvas((session, _) async {
      final canvas = session.canvasModel;
      var notifications = 0;
      canvas.addListener(() => notifications++);
      for (final offset in [const Offset(7, 11), const Offset(31, 37)]) {
        canvas.update(offset.dx, offset.dy, 1.25);
        notifications = 0;
        session.cursorModel.keyHelpToolsVisibilityChanged(
            const Rect.fromLTWH(0, 0, 10, 20), true);
        await tester.pump(const Duration(milliseconds: 100));
        expect([
          canvas.size,
          canvas.x,
          canvas.y,
          notifications,
        ], [
          canvas.getSize(),
          (canvas.size.width - 2 * canvas.scale) / 2,
          (canvas.size.height - 2 * canvas.scale) / 2,
          1,
        ]);
        canvas.update(5, 9, 0.75);
        notifications = 0;
        session.cursorModel.keyHelpToolsVisibilityChanged(null, false);
        await tester.pump(const Duration(milliseconds: 100));
        expect([canvas.x, canvas.y, canvas.scale, canvas.size, notifications],
            [offset.dx, offset.dy, 1.25, canvas.getSize(), 1]);
        expect(tester.takeException(), isNull);
      }
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('mobile snapshot replacement and duplicate restore keep one timer',
      (tester) async {
    await _observeMobileCanvas((session, _) async {
      final canvas = session.canvasModel;
      var notifications = 0;
      canvas.addListener(() => notifications++);
      canvas.update(7, 11, 1.25);
      canvas.saveMobileOffsetBeforeSoftKeyboard();
      canvas.update(31, 37, 1.75);
      canvas.restoreMobileOffsetAfterSoftKeyboard();
      await tester.pump(const Duration(milliseconds: 50));
      canvas.saveMobileOffsetBeforeSoftKeyboard();
      canvas.update(5, 9, 0.75);
      canvas.mobileFocusCanvasCursor();
      canvas.restoreMobileOffsetAfterSoftKeyboard();
      canvas.restoreMobileOffsetAfterSoftKeyboard();
      notifications = 0;
      await tester.pump(const Duration(milliseconds: 50));
      expect([canvas.x, canvas.y, canvas.scale, notifications], [5, 9, 0.75, 0]);
      await tester.pump(const Duration(milliseconds: 50));
      expect([canvas.x, canvas.y, canvas.scale, notifications],
          [31, 37, 1.75, 1]);
      // The snapshot was consumed; repeated restore cannot apply it twice.
      canvas.restoreMobileOffsetAfterSoftKeyboard();
      await tester.pump(const Duration(milliseconds: 100));
      expect([canvas.x, canvas.y, canvas.scale, notifications],
          [31, 37, 1.75, 1]);
      expect(tester.takeException(), isNull);
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  for (final stage in _CanvasPreferenceStage.values) {
    testWidgets('superseded canvas ${stage.name} read preserves successor state',
        (tester) async {
      await tester.runAsync(() async {
        final preferences = _PendingCanvasPreferences(stage);
        final session = _CanvasPreferenceSession(preferences);
        final canvas = session.canvasModel;
        final order = ExactRgbaPublicationOrder<SessionID>();
        final earlier = order.admit(session.sessionId, 0, 1)!;
        final higher = order.admit(session.sessionId, 0, 2)!;
        final owner = canvas.captureUpdateOwner(
            acceptsUpdate: () => order.canComplete(earlier));
        expect(owner, isNotNull);
        // A newer admission alone does not invalidate a useful ready update.
        expect(owner!.isCurrent, isTrue);
        final pending = _readCanvasPreference(session, stage, owner: owner);
        try {
          await preferences.started.future
              .timeout(const Duration(seconds: 5));
          expect(order.commit(higher), isTrue);
          canvas.update(31, 37, 1.75);
          canvas.setScrollPercent(0.2, 0.3);
          final before = _canvasPreferenceState(canvas);
          preferences.release.complete();
          final accepted = await pending.timeout(const Duration(seconds: 5));
          expect([
            accepted,
            _canvasPreferenceState(canvas),
            session.inputModel.refreshes,
          ], [false, before, 0]);

          final fresh = order.admit(session.sessionId, 0, 3)!;
          final freshOwner = canvas.captureUpdateOwner(
              acceptsUpdate: () => order.canComplete(fresh));
          expect(await _readCanvasPreference(session, stage, owner: freshOwner),
              isTrue);
          expect(order.commit(fresh), isTrue);
          switch (stage) {
            case _CanvasPreferenceStage.view:
              expect(canvas.scale, 2.25 / ui.window.devicePixelRatio);
              break;
            case _CanvasPreferenceStage.scroll:
              expect(canvas.scrollStyle, ScrollStyle.scrolledge);
              break;
            case _CanvasPreferenceStage.edge:
              expect(canvas.edgeScrollEdgeThickness, 41);
              break;
          }
        } finally {
          if (!preferences.release.isCompleted) preferences.release.complete();
          await pending;
          canvas.dispose();
          session.imageModel.dispose();
          session.cursorModel.dispose();
        }
      });
    }, timeout: const Timeout(Duration(seconds: 30)));

    for (final retirement in ['presentation', 'clear']) {
      testWidgets('retired $retirement canvas ${stage.name} read has no effects',
          (tester) async {
        await tester.runAsync(() async {
          final preferences = _PendingCanvasPreferences(stage);
          final session = _CanvasPreferenceSession(preferences);
          final canvas = session.canvasModel;
          Future<void>? pending;
          var notifications = 0;
          void notified() => notifications++;
          canvas.addListener(notified);
          try {
            pending = _readCanvasPreference(session, stage);
            await preferences.started.future
                .timeout(const Duration(seconds: 5));
            if (retirement == 'presentation') {
              session.imageModel.retirePresentation();
            } else {
              canvas.clear();
            }
            canvas.update(31, 37, 1.75);
            canvas.setScrollPercent(0.2, 0.3);
            notifications = 0;
            final before = _canvasPreferenceState(canvas);
            preferences.release.complete();
            await pending.timeout(const Duration(seconds: 5));
            final after = _canvasPreferenceState(canvas);
            expect([after, notifications, session.inputModel.refreshes],
                [before, 0, 0]);

            // A fresh owner must still be able to apply the useful preference.
            await _readCanvasPreference(session, stage);
            switch (stage) {
              case _CanvasPreferenceStage.view:
                expect(canvas.viewStyle.style, kRemoteViewStyleCustom);
                expect(canvas.scale, 2.25 / ui.window.devicePixelRatio);
                expect(notifications, 1);
                expect(session.inputModel.refreshes, 1);
                break;
              case _CanvasPreferenceStage.scroll:
                expect(canvas.scrollStyle, ScrollStyle.scrolledge);
                expect([canvas.scrollX, canvas.scrollY], [0, 0]);
                expect(notifications, 1);
                break;
              case _CanvasPreferenceStage.edge:
                expect(canvas.edgeScrollEdgeThickness, 41);
                break;
            }
          } finally {
            if (!preferences.release.isCompleted) preferences.release.complete();
            if (pending != null) await pending;
            canvas.removeListener(notified);
            canvas.dispose();
            session.imageModel.dispose();
            session.cursorModel.dispose();
          }
        });
      }, timeout: const Timeout(Duration(seconds: 30)));
    }
  }

  testWidgets('delayed canvas scroll update joins and refuses a retired owner',
      (tester) async {
    await tester.runAsync(() async {
      final preferences =
          _PendingCanvasPreferences(_CanvasPreferenceStage.scroll);
      preferences.release.complete();
      final session = _CanvasPreferenceSession(preferences);
      final canvas = session.canvasModel;
      try {
        expect(await _readCanvasPreference(session, _CanvasPreferenceStage.scroll),
            isTrue);
        final owner = canvas.captureUpdateOwner();
        final pending = canvas.tryUpdateScrollStyle(
            Duration.zero, kRemoteViewStyleCustom, owner: owner);
        session.imageModel.retirePresentation();
        canvas.setScrollPercent(0.6, 0.7);
        expect(await pending.timeout(const Duration(seconds: 5)), isFalse);
        expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
        expect(
            await canvas.tryUpdateScrollStyle(
                Duration.zero, kRemoteViewStyleCustom,
                owner: canvas.captureUpdateOwner()),
            isTrue);

        final order = ExactRgbaPublicationOrder<SessionID>();
        final earlier = order.admit(session.sessionId, 0, 1)!;
        final earlierOwner = canvas.captureUpdateOwner(
            acceptsUpdate: () => order.canComplete(earlier));
        final first = canvas.updateViewStyle(owner: earlierOwner);
        final higher = order.admit(session.sessionId, 0, 2)!;
        final higherOwner = canvas.captureUpdateOwner(
            acceptsUpdate: () => order.canComplete(higher));
        final second = canvas.updateViewStyle(owner: higherOwner);
        expect(await first, isTrue);
        expect(order.commit(earlier), isTrue);
        expect(await second, isTrue);
        expect(order.commit(higher), isTrue);
      } finally {
        canvas.dispose();
        session.imageModel.dispose();
        session.cursorModel.dispose();
      }
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  for (final retirement in ['clear', 'dispose', 'replacement']) {
    testWidgets('deferred canvas scroll $retirement cancels and joins its timer',
        (tester) async {
      final preferences =
          _PendingCanvasPreferences(_CanvasPreferenceStage.scroll);
      preferences.release.complete();
      final session = _CanvasPreferenceSession(preferences);
      final canvas = session.canvasModel;
      Future<bool>? pending;
      var disposed = false;
      try {
        expect(await _readCanvasPreference(
            session, _CanvasPreferenceStage.scroll), isTrue);
        pending = canvas.tryUpdateScrollStyle(
            const Duration(seconds: 30), kRemoteViewStyleCustom,
            owner: canvas.captureUpdateOwner());
        Future<bool>? replacement;
        if (retirement == 'clear') {
          canvas.clear();
        } else if (retirement == 'dispose') {
          canvas.dispose();
          disposed = true;
        } else {
          replacement = canvas.tryUpdateScrollStyle(
              const Duration(milliseconds: 1), kRemoteViewStyleCustom,
              owner: canvas.captureUpdateOwner());
        }
        canvas.setScrollPercent(0.6, 0.7);
        await tester.pump(const Duration(milliseconds: 1));
        expect(await pending, isFalse);
        if (replacement != null) {
          expect(await replacement, isTrue);
        } else {
          expect([canvas.scrollX, canvas.scrollY], [0.6, 0.7]);
        }
        // Advance the controlled clock past the cancelled timer's deadline.
        // Merely completing its Future while leaving it armed would fail here.
        await tester.pump(const Duration(seconds: 30));
        expect(tester.takeException(), isNull);
      } finally {
        if (!disposed) {
          canvas.clear();
          canvas.dispose();
        }
        if (pending != null) await pending;
        session.imageModel.dispose();
        session.cursorModel.dispose();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  }

  testWidgets('disposed canvas refuses pending reads and new update owners',
      (tester) async {
    await tester.runAsync(() async {
      for (final stage in _CanvasPreferenceStage.values) {
        final preferences = _PendingCanvasPreferences(stage);
        final session = _CanvasPreferenceSession(preferences);
        final canvas = session.canvasModel;
        final pending = _readCanvasPreference(session, stage);
        var disposed = false;
        try {
          await preferences.started.future
              .timeout(const Duration(seconds: 5));
          final before = _canvasPreferenceState(canvas);
          canvas.dispose();
          disposed = true;
          preferences.release.complete();
          expect(await pending.timeout(const Duration(seconds: 5)), isFalse);
          expect(_canvasPreferenceState(canvas), before);
          expect(canvas.captureUpdateOwner(), isNull);
          expect(await canvas.updateViewStyle(owner: null), isFalse);
          expect(await canvas.updateScrollStyle(owner: null), isFalse);
          expect(await canvas.initializeEdgeScrollEdgeThickness(owner: null),
              isFalse);
        } finally {
          if (!preferences.release.isCompleted) preferences.release.complete();
          await pending;
          if (!disposed) canvas.dispose();
          session.imageModel.dispose();
          session.cursorModel.dispose();
        }
      }
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('retired cursor initialization preserves current geometry',
      (tester) async {
    await tester.runAsync(() async {
      await _observeCursorInitialization((session) async {
        final revision = session.imageModel.presentationRevision;
        final pending = initializeCursorAndCanvas(session,
            expectedSessionId: session.sessionId,
            acceptsInitialization: () =>
                session.imageModel.isCurrentPresentationRevision(revision));
        // On non-web platforms saved-canvas lookup returns null as a Future.
        // Retire after invocation, before the initializer can continue.
        session.imageModel.retirePresentation();
        await pending;
        expect([
          session.inputModel.moves,
          session.cursorModel.offset,
          session.canvasModel.x,
          session.canvasModel.y,
          session.canvasModel.scale,
        ], [<Offset>[], const Offset(12, 24), 17, 23, 1.5]);

        final freshRevision = session.imageModel.presentationRevision;
        await initializeCursorAndCanvas(session,
            expectedSessionId: session.sessionId,
            acceptsInitialization: () =>
                session.imageModel.isCurrentPresentationRevision(freshRevision));
        expect(session.inputModel.moves, [Offset.zero]);
        expect(session.cursorModel.offset, const Offset(1, 1));
        expect(session.canvasModel.x, -1.5);
        expect(session.canvasModel.y, -1.5);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('superseded cursor initialization cannot reset successor geometry',
      (tester) async {
    await tester.runAsync(() async {
      await _observeCursorInitialization((session) async {
        final order = ExactRgbaPublicationOrder<SessionID>();
        final earlier = order.admit(session.sessionId, 0, 1)!;
        final higher = order.admit(session.sessionId, 0, 2)!;
        expect(order.canComplete(earlier), isTrue);
        final pending = initializeCursorAndCanvas(session,
            expectedSessionId: session.sessionId,
            acceptsInitialization: () => order.canComplete(earlier));
        expect(order.commit(higher), isTrue);
        expect(order.canComplete(earlier), isFalse);
        await pending;
        expect([
          session.inputModel.moves,
          session.cursorModel.offset,
          session.canvasModel.x,
          session.canvasModel.y,
          session.canvasModel.scale,
        ], [<Offset>[], const Offset(12, 24), 17, 23, 1.5]);

        final fresh = order.admit(session.sessionId, 0, 3)!;
        await initializeCursorAndCanvas(session,
            expectedSessionId: session.sessionId,
            acceptsInitialization: () => order.canComplete(fresh));
        expect(session.inputModel.moves, [Offset.zero]);
        expect(session.cursorModel.offset, const Offset(1, 1));
        expect(session.canvasModel.x, -1.5);
        expect(session.canvasModel.y, -1.5);
        expect(order.commit(fresh), isTrue);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('a ready first image is not superseded by pending geometry',
      (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending, _) async {
        session.canvasModel.release[0].complete();
        expect(await pending[0], isTrue);
        final first = session.imageModel.image!;
        expect(session.imageModel.presentationPublication, 1);
        expect(first.debugDisposed, isFalse);

        session.canvasModel.release[1].complete();
        expect(await pending[1], isTrue);
        expect(session.imageModel.presentationPublication, 2);
        expect(identical(session.imageModel.image, first), isFalse);
        expect(first.debugDisposed, isTrue);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('a lower late image cannot replace a ready higher image',
      (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending, _) async {
        session.canvasModel.release[1].complete();
        expect(await pending[1], isTrue);
        final latest = session.imageModel.image!;
        expect(session.imageModel.presentationPublication, 2);

        session.canvasModel.release[0].complete();
        expect(await pending[0], isFalse);
        expect(identical(session.imageModel.image, latest), isTrue);
        expect(session.imageModel.presentationPublication, 2);
        expect(latest.debugDisposed, isFalse);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('presentation retirement rejects images awaiting geometry',
      (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending, _) async {
        session.imageModel.retirePresentation();
        session.canvasModel.releaseAll();
        expect(await Future.wait(pending), [false, false]);
        expect(session.imageModel.image, isNull);
        expect(session.imageModel.presentationPublication, isNull);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  for (final stage in _GeometryFailure.values) {
    testWidgets('first-image ${stage.name} failure releases its image',
        (tester) async {
      await tester.runAsync(() async {
        await _observeImagePublications((session, pending, images) async {
          session.canvasModel.release[0].complete();
          expect(await pending[0], isFalse);
          expect(
              session.canvasModel.failed || session.cursorModel.failed, isTrue);
          expect(session.imageModel.image, isNull);
          expect(session.imageModel.presentationPublication, isNull);
          expect(images[0].debugDisposed, isTrue);
          expect(_openHandles(images[0]), 0);

          session.canvasModel.release[1].complete();
          expect(await pending[1], isTrue);
          expect(identical(session.imageModel.image, images[1]), isTrue);
          expect(session.imageModel.presentationPublication, 2);
          expect(images[1].debugDisposed, isFalse);
        }, failFirstAt: stage);
      });
    }, timeout: const Timeout(Duration(seconds: 30)));
  }

  testWidgets('rejected updates cannot dispose the current image', (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending, _) async {
        session.canvasModel.release[1].complete();
        expect(await pending[1], isTrue);
        session.canvasModel.release[0].complete();
        expect(await pending[0], isFalse);
        final current = session.imageModel.image!;
        expect(
            await session.imageModel.update(current,
                expectedPresentationRevision:
                    session.imageModel.presentationRevision + 1),
            isFalse);
        expect(identical(session.imageModel.image, current), isTrue);
        expect(current.debugDisposed, isFalse);
        expect(_openHandles(current), 1);
        expect(await session.imageModel.update(current), isTrue);
        expect(current.debugDisposed, isFalse);
        expect(session.imageModel.presentationPublication, 2);
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('notification retirement cannot dispose an adopted image twice',
      (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending, images) async {
        void clearOnNotification() => session.imageModel.clearImage();
        session.imageModel.addListener(clearOnNotification);
        try {
          session.canvasModel.release[0].complete();
          expect(await pending[0], isTrue);
          expect(session.imageModel.image, isNull);
          expect(images[0].debugDisposed, isTrue);
          expect(_openHandles(images[0]), 0);

          session.canvasModel.release[1].complete();
          expect(await pending[1], isFalse);
          expect(images[1].debugDisposed, isTrue);
        } finally {
          session.imageModel.removeListener(clearOnNotification);
        }
      });
    });
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('owned image paint fills loose stack bounds and retains pixels',
      (tester) async {
    final source = (await tester.runAsync(
      () => _solidRawBgraImage(const ui.Color(0xffff0000)),
    ))!;
    final boundaryKey = GlobalKey();
    final paintKey = GlobalKey();

    await tester.pumpWidget(Directionality(
      textDirection: TextDirection.ltr,
      child: Center(
        child: SizedBox(
          width: 32,
          height: 24,
          child: RepaintBoundary(
            key: boundaryKey,
            child: Stack(children: [
              OwnedImagePaint(
                key: paintKey,
                image: source,
                x: 0,
                y: 0,
                scale: 16,
                size: Size.infinite,
              ),
            ]),
          ),
        ),
      ),
    ));

    expect(tester.getSize(find.byKey(paintKey)), const Size(32, 24));
    source.dispose();
    final boundary = boundaryKey.currentContext!.findRenderObject()
        as RenderRepaintBoundary;
    boundary.markNeedsPaint();
    await tester.pump();
    final raster = (await tester.runAsync(() => boundary.toImage()))!;
    addTearDown(raster.dispose);
    final pixels = await tester.runAsync(
      () => raster.toByteData(format: ui.ImageByteFormat.rawRgba),
    );
    expect(pixels, isNotNull);
    expect(pixels!.getUint8(0), greaterThan(240));
    expect(pixels.getUint8(1), lessThan(16));
    expect(pixels.getUint8(2), lessThan(16));
    expect(pixels.getUint8(3), 255);

    await tester.pumpWidget(const SizedBox.shrink());
  }, timeout: const Timeout(Duration(seconds: 30)));

  testWidgets('native image ownership survives conversion faults and paint retirement',
      (tester) async {
    final failures = (await tester.runAsync(() async {
      final observations = <String, Map<String, Object>>{};
      for (final stage in ['image-frame-requested', 'image-frame-ready']) {
        observations[stage] = await _conversionFailureHandles(stage);
      }
      return observations;
    }))!;
    expect(failures, <String, Map<String, Object>>{
      for (final stage in ['image-frame-requested', 'image-frame-ready'])
        stage: <String, Object>{
          'imagesAtReturn': 1,
          'disposedAtReturn': true,
          'disposed': true,
          'openHandles': 0,
          'disposals': 1,
        },
    });

    final first = (await tester.runAsync(
      () => _solidImage(const ui.Color(0xff00ff00)),
    ))!;
    final firstObserver = first.clone();
    final second = (await tester.runAsync(
      () => _solidImage(const ui.Color(0xff0000ff)),
    ))!;
    final secondObserver = second.clone();

    Widget paint(ui.Image image) => Directionality(
          textDirection: TextDirection.ltr,
          child: SizedBox(
            width: 8,
            height: 8,
            child: OwnedImagePaint(
              image: image,
              x: 0,
              y: 0,
              scale: 4,
              size: Size.infinite,
            ),
          ),
        );

    await tester.pumpWidget(paint(first));
    expect(_openHandles(firstObserver), 3);
    first.dispose();
    expect(_openHandles(firstObserver), 2);

    await tester.pumpWidget(paint(second));
    expect(_openHandles(firstObserver), 1);
    expect(_openHandles(secondObserver), 3);
    second.dispose();
    expect(_openHandles(secondObserver), 2);

    await tester.pumpWidget(const SizedBox.shrink());
    expect(_openHandles(secondObserver), 1);
    firstObserver.dispose();
    secondObserver.dispose();
  }, timeout: const Timeout(Duration(seconds: 30)));
}

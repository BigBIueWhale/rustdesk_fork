import 'dart:async';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/rendering.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/generated_bridge.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/utils/image.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';

// Only the asynchronous geometry boundary is controlled. ImageModel, publication
// ordering and raw-pixel conversion execute their production implementations.
class _ImageSession implements FFI {
  @override
  final SessionID sessionId = Uuid().v4obj();
  @override
  final canvasModel = _PendingImageGeometry();
  @override
  final cursorModel = _ImageCursor();
  @override
  late final ffiModel = _ImageTopology(sessionId);
  @override
  late final imageModel = ImageModel(WeakReference<FFI>(this));

  @override
  bool isCurrentSession(SessionID expected) => expected == sessionId;

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
  @override
  final pi = PeerInfo()
    ..displays.add(Display()
      ..width = 2
      ..height = 2);
  @override
  ui.Rect get rect => const ui.Rect.fromLTWH(0, 0, 2, 2);

  @override
  bool isCurrentDisplayTopology(SessionID expected, int revision) =>
      expected == sessionId && revision == 0;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _PendingImageGeometry implements CanvasModel {
  final started = List.generate(2, (_) => Completer<void>());
  final release = List.generate(2, (_) => Completer<void>());
  int calls = 0;

  @override
  Future<void> updateViewStyle(
      {refreshMousePos = true,
      notify = true,
      SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) {
    final index = calls++;
    started[index].complete();
    return release[index].future;
  }

  @override
  Future<void> updateScrollStyle(
      {SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {}

  @override
  Future<void> initializeEdgeScrollEdgeThickness(
      {SessionID? expectedSessionId,
      int? expectedDisplayTopologyRevision}) async {}

  void releaseAll() {
    for (final pending in release) {
      if (!pending.isCompleted) pending.complete();
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _ImageCursor implements CursorModel {
  @override
  void updateDisplayOrigin(double x, double y, {updateCursorPos = true}) {}

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<void> _observeImagePublications(
    Future<void> Function(_ImageSession, List<Future<bool>>) observe) async {
  final session = _ImageSession();
  final publications = <Future<bool>>[];
  final images = <ui.Image>[];
  final previousCreate = ui.Image.onCreate;
  ui.Image.onCreate = (image) {
    previousCreate?.call(image);
    images.add(image);
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
    await observe(session, publications);
  } finally {
    try {
      session.canvasModel.releaseAll();
      await Future.wait(publications).timeout(const Duration(seconds: 5));
      session.imageModel.clearImage();
      expect(images.every((image) => image.debugDisposed), isTrue);
      expect(images.map(_openHandles), everyElement(0));
    } finally {
      for (final image in images) {
        if (!image.debugDisposed) image.dispose();
      }
      ui.Image.onCreate = previousCreate;
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
  testWidgets('a ready first image is not superseded by pending geometry',
      (tester) async {
    await tester.runAsync(() async {
      await _observeImagePublications((session, pending) async {
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
      await _observeImagePublications((session, pending) async {
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
      await _observeImagePublications((session, pending) async {
        session.imageModel.retirePresentation();
        session.canvasModel.releaseAll();
        expect(await Future.wait(pending), [false, false]);
        expect(session.imageModel.image, isNull);
        expect(session.imageModel.presentationPublication, isNull);
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

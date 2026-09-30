import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/widgets.dart';

import 'package:flutter_hbb/common.dart';

Future<ui.Image?> decodeImageFromPixels(
  Uint8List pixels,
  int width,
  int height,
  ui.PixelFormat format, {
  int? rowBytes,
  int? targetWidth,
  int? targetHeight,
  bool allowUpscaling = true,
  void Function(String stage)? onStage,
}) async {
  if (targetWidth != null) {
    assert(allowUpscaling || targetWidth <= width);
    if (!(allowUpscaling || targetWidth <= width)) {
      print("not allow upscaling but targetWidth > width");
      return null;
    }
  }
  if (targetHeight != null) {
    assert(allowUpscaling || targetHeight <= height);
    if (!(allowUpscaling || targetHeight <= height)) {
      print("not allow upscaling but targetHeight > height");
      return null;
    }
  }

  ui.Image? image;
  try {
    final buffer = await ui.ImmutableBuffer.fromUint8List(pixels);
    try {
      onStage?.call('image-buffer-ready');
      final descriptor = ui.ImageDescriptor.raw(
        buffer,
        width: width,
        height: height,
        rowBytes: rowBytes,
        pixelFormat: format,
      );
      try {
        if (!allowUpscaling) {
          if (targetWidth != null && targetWidth > descriptor.width) {
            targetWidth = descriptor.width;
          }
          if (targetHeight != null && targetHeight > descriptor.height) {
            targetHeight = descriptor.height;
          }
        }
        onStage?.call('image-descriptor-ready');
        final codec = await descriptor.instantiateCodec(
          targetWidth: targetWidth,
          targetHeight: targetHeight,
        );
        Future<ui.FrameInfo>? pendingFrame;
        try {
          try {
            onStage?.call('image-codec-ready');
            pendingFrame = codec.getNextFrame();
          } finally {
            // The engine owns the native codec until its callback completes;
            // release the Dart handle immediately, as dart:ui does.
            codec.dispose();
          }
          onStage?.call('image-frame-requested');
        } finally {
          // Observation failure cannot abandon an uncancellable engine result.
          final frame = pendingFrame;
          if (frame != null) image = (await frame).image;
        }
        onStage?.call('image-frame-ready');
      } finally {
        descriptor.dispose();
      }
    } finally {
      buffer.dispose();
    }
    final result = image;
    image = null;
    return result;
  } catch (e) {
    print("decodeImageFromPixels failed: $e");
    onStage?.call('image-conversion-failed');
    return null;
  } finally {
    image?.dispose();
  }
}

class OwnedImagePaint extends StatefulWidget {
  const OwnedImagePaint({
    super.key,
    required this.image,
    required this.x,
    required this.y,
    required this.scale,
    required this.size,
    this.presentationDisplay,
    this.presentationPublication,
  });

  final ui.Image? image;
  final double x;
  final double y;
  final double scale;
  final Size size;
  final int? presentationDisplay;
  final int? presentationPublication;

  @override
  State<OwnedImagePaint> createState() => _OwnedImagePaintState();
}

class _OwnedImagePaintState extends State<OwnedImagePaint> {
  ui.Image? _paintImage;
  List<ui.Image> _retiringImages = <ui.Image>[];
  bool _retirementScheduled = false;

  @override
  void initState() {
    super.initState();
    _paintImage = widget.image?.clone();
    _tracePresentation('widget-mounted');
  }

  @override
  void didUpdateWidget(covariant OwnedImagePaint oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (identical(widget.image, oldWidget.image)) return;

    final replacement = widget.image?.clone();
    final retiring = _paintImage;
    _paintImage = replacement;
    _tracePresentation('widget-image-replaced');
    if (retiring != null) {
      _retiringImages.add(retiring);
      _scheduleRetirement();
    }
  }

  void _tracePresentation(String stage) {
    final publication = widget.presentationPublication;
    if (publication == null ||
        (publication > 4 && publication % 64 != 0)) {
      return;
    }
    debugPrint(
        'RUSTDESK_PRESENTATION_PROGRESS stage=$stage display=${widget.presentationDisplay ?? -1} publication=$publication image=${_paintImage == null ? "absent" : "present"} wall_ms=${DateTime.now().millisecondsSinceEpoch}');
  }

  void _scheduleRetirement() {
    if (_retirementScheduled) return;
    _retirementScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final retiringImages = _retiringImages;
      _retiringImages = <ui.Image>[];
      _retirementScheduled = false;
      for (final image in retiringImages) {
        image.dispose();
      }
    });
  }

  @override
  void dispose() {
    final paintImage = _paintImage;
    _paintImage = null;
    if (paintImage != null) {
      _retiringImages.add(paintImage);
    }
    if (_retiringImages.isNotEmpty) {
      _scheduleRetirement();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      size: widget.size,
      willChange: true,
      painter: ImagePainter(
        image: _paintImage,
        x: widget.x,
        y: widget.y,
        scale: widget.scale,
        presentationDisplay: widget.presentationDisplay,
        presentationPublication: widget.presentationPublication,
      ),
    );
  }
}

class ImagePainter extends CustomPainter {
  ImagePainter({
    required this.image,
    required this.x,
    required this.y,
    required this.scale,
    this.presentationDisplay,
    this.presentationPublication,
  });

  ui.Image? image;
  double x;
  double y;
  double scale;
  final int? presentationDisplay;
  final int? presentationPublication;

  @override
  void paint(Canvas canvas, Size size) {
    if (image == null) return;
    if (x.isNaN || y.isNaN) return;
    final publication = presentationPublication;
    if (publication != null &&
        (publication <= 4 || publication % 64 == 0)) {
      debugPrint(
          'RUSTDESK_PRESENTATION_PROGRESS stage=paint-recorded display=${presentationDisplay ?? -1} publication=$publication wall_ms=${DateTime.now().millisecondsSinceEpoch}');
    }
    canvas.scale(scale, scale);
    // https://github.com/flutter/flutter/issues/76187#issuecomment-784628161
    // https://api.flutter-io.cn/flutter/dart-ui/FilterQuality.html
    var paint = Paint();
    if ((scale - 1.0).abs() > 0.001) {
      paint.filterQuality = FilterQuality.medium;
      if (scale > 10.00000) {
        paint.filterQuality = FilterQuality.high;
      }
    }
    // It's strange that if (scale < 0.5 && paint.filterQuality == FilterQuality.medium)
    // The canvas.drawImage will not work on web
    if (isWeb) {
      paint.filterQuality = FilterQuality.high;
    }
    canvas.drawImage(
        image!, Offset(x.toInt().toDouble(), y.toInt().toDouble()), paint);
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) {
    return oldDelegate != this;
  }
}

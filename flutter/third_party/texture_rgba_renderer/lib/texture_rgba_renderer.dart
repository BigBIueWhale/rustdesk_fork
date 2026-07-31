// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.

import 'package:flutter/services.dart';

class TextureRgbaRenderer {
  static const _channel = MethodChannel('texture_rgba_renderer');

  Future<int> createTexture(int key) async {
    return await _channel.invokeMethod<int>('createTexture', {'key': key}) ??
        -1;
  }

  Future<bool> closeTexture(int key) async {
    return await _channel.invokeMethod<bool>('closeTexture', {'key': key}) ??
        false;
  }

  Future<bool> onRgba(
    int key,
    Uint8List data,
    int height,
    int width,
    int strideAlign,
  ) async {
    return await _channel.invokeMethod<bool>('onRgba', {
          'data': data,
          'height': height,
          'width': width,
          'key': key,
          'stride_align': strideAlign,
        }) ??
        false;
  }

  Future<int> getTexturePtr(int key) async {
    return await _channel.invokeMethod<int>('getTexturePtr', {'key': key}) ?? 0;
  }
}

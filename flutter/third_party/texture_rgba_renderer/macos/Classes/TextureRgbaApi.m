// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#import <Foundation/Foundation.h>
#import "texture_rgba_renderer/texture_rgba_renderer-Swift.h"

#if __cplusplus
extern "C" {
#endif

int FlutterRgbaRendererPluginTryOnRgba(void* texture_rgba_ptr, const uint8_t* buffer, int len,
                                       int width, int height, int stride_align) {
  if (texture_rgba_ptr == NULL || buffer == NULL || len <= 0 || width <= 0 || height <= 0 ||
      stride_align < 0) {
    return 0;
  }
  TextRgba* texture_rgba = (__bridge TextRgba*)texture_rgba_ptr;
  return [texture_rgba markFrameAvaliableRawWithBuffer:buffer
                                                   len:len
                                                 width:width
                                                height:height
                                          stride_align:stride_align] ? 1 : 0;
}

void FlutterRgbaRendererPluginOnRgba(void* texture_rgba_ptr, const uint8_t* buffer, int len,
                                     int width, int height, int stride_align) {
  (void)FlutterRgbaRendererPluginTryOnRgba(texture_rgba_ptr, buffer, len, width, height,
                                          stride_align);
}

#if __cplusplus
}
#endif

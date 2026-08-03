// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#include "include/texture_rgba_renderer/texture_rgba_renderer_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include <cstddef>

#include "texture_rgba.h"
#include "texture_rgba_renderer_plugin.h"

void TextureRgbaRendererPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  texture_rgba_renderer::TextureRgbaRendererPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}

int FlutterRgbaRendererPluginTryOnRgba(void* texture_rgba,
                                       const uint8_t* buffer, int len,
                                       int width, int height,
                                       int stride_align) {
  if (texture_rgba == nullptr || buffer == nullptr || len <= 0 || width <= 0 ||
      height <= 0 || stride_align < 0) {
    return 0;
  }
  try {
    return static_cast<TextureRgba*>(texture_rgba)
                   ->MarkVideoFrameAvailable(
                       buffer, static_cast<size_t>(len),
                       static_cast<size_t>(width), static_cast<size_t>(height),
                       static_cast<size_t>(stride_align))
               ? 1
               : 0;
  } catch (...) {
    // Exceptions must never cross the C ABI used by Rust.
    return 0;
  }
}

int FlutterRgbaRendererPluginTryNotifyPending(void* texture_rgba) {
  if (texture_rgba == nullptr) {
    return 0;
  }
  try {
    return static_cast<TextureRgba*>(texture_rgba)->NotifyPendingFrame() ? 1
                                                                         : 0;
  } catch (...) {
    // Exceptions must never cross the C ABI used by Rust.
    return 0;
  }
}

void FlutterRgbaRendererPluginOnRgba(void* texture_rgba, const uint8_t* buffer,
                                     int len, int width, int height,
                                     int stride_align) {
  (void)FlutterRgbaRendererPluginTryOnRgba(texture_rgba, buffer, len, width,
                                          height, stride_align);
}

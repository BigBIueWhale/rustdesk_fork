// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#ifndef FLUTTER_PLUGIN_TEXTURE_RGBA_RENDERER_PLUGIN_H_
#define FLUTTER_PLUGIN_TEXTURE_RGBA_RENDERER_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/texture_registrar.h>

#include <cstdint>
#include <memory>
#include <unordered_map>

#include "texture_rgba.h"

namespace texture_rgba_renderer {

class TextureRgbaRendererPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  explicit TextureRgbaRendererPlugin(
      flutter::TextureRegistrar* texture_registrar);
  ~TextureRgbaRendererPlugin() override;

  TextureRgbaRendererPlugin(const TextureRgbaRendererPlugin&) = delete;
  TextureRgbaRendererPlugin& operator=(const TextureRgbaRendererPlugin&) =
      delete;

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  flutter::TextureRegistrar* texture_registrar_;
  std::unordered_map<int64_t, std::shared_ptr<TextureRgba>> textures_;
};

}  // namespace texture_rgba_renderer

#endif  // FLUTTER_PLUGIN_TEXTURE_RGBA_RENDERER_PLUGIN_H_

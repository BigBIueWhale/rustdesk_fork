// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#include "texture_rgba_renderer_plugin.h"

#include <flutter/standard_method_codec.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace texture_rgba_renderer {
namespace {

using EncodableResult = flutter::MethodResult<flutter::EncodableValue>;

const flutter::EncodableMap* Arguments(
    const flutter::MethodCall<flutter::EncodableValue>& call) {
  if (call.arguments() == nullptr) {
    return nullptr;
  }
  return std::get_if<flutter::EncodableMap>(call.arguments());
}

bool IntArgument(const flutter::EncodableMap* arguments, const char* name,
                 int64_t* value) {
  if (arguments == nullptr) {
    return false;
  }
  auto found = arguments->find(flutter::EncodableValue(name));
  if (found == arguments->end()) {
    return false;
  }
  if (const auto* int32_value = std::get_if<int32_t>(&found->second)) {
    *value = *int32_value;
    return true;
  }
  if (const auto* int64_value = std::get_if<int64_t>(&found->second)) {
    *value = *int64_value;
    return true;
  }
  return false;
}

void BadArguments(std::unique_ptr<EncodableResult> result) {
  result->Error("bad-arguments", "texture arguments are missing or malformed");
}

}  // namespace

void TextureRgbaRendererPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "texture_rgba_renderer",
          &flutter::StandardMethodCodec::GetInstance());
  auto plugin = std::make_unique<TextureRgbaRendererPlugin>(
      registrar->texture_registrar());
  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });
  registrar->AddPlugin(std::move(plugin));
}

TextureRgbaRendererPlugin::TextureRgbaRendererPlugin(
    flutter::TextureRegistrar* texture_registrar)
    : texture_registrar_(texture_registrar) {}

TextureRgbaRendererPlugin::~TextureRgbaRendererPlugin() {
  for (auto& entry : textures_) {
    const std::shared_ptr<TextureRgba> texture = std::move(entry.second);
    texture->Retire();
    texture_registrar_->UnregisterTexture(texture->texture_id(),
                                          [texture]() {});
  }
  textures_.clear();
}

void TextureRgbaRendererPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<EncodableResult> result) {
  try {
    const flutter::EncodableMap* arguments = Arguments(method_call);
    int64_t key;

    if (method_call.method_name() == "createTexture") {
      if (!IntArgument(arguments, "key", &key)) {
        return BadArguments(std::move(result));
      }
      auto [slot, inserted] = textures_.try_emplace(key);
      if (!inserted) {
        return result->Success(flutter::EncodableValue(int64_t{-1}));
      }
      std::shared_ptr<TextureRgba> texture;
      try {
        texture = std::make_shared<TextureRgba>(texture_registrar_);
      } catch (...) {
        // The reserved slot is still empty because construction did not
        // return a registered texture to this owner.
        textures_.erase(slot);
        throw;
      }
      if (texture->texture_id() <= 0) {
        textures_.erase(slot);
        return result->Success(flutter::EncodableValue(int64_t{-1}));
      }
      const int64_t texture_id = texture->texture_id();
      slot->second = std::move(texture);
      return result->Success(flutter::EncodableValue(texture_id));
    }

    if (method_call.method_name() == "closeTexture") {
      if (!IntArgument(arguments, "key", &key)) {
        return BadArguments(std::move(result));
      }
      auto found = textures_.find(key);
      if (found == textures_.end()) {
        return result->Success(flutter::EncodableValue(false));
      }

      auto texture_node = textures_.extract(found);
      const std::shared_ptr<TextureRgba> texture = texture_node.mapped();
      texture->Retire();
      auto async_result = std::shared_ptr<EncodableResult>(std::move(result));
      try {
        texture_registrar_->UnregisterTexture(
            texture->texture_id(), [texture, async_result]() {
              async_result->Success(flutter::EncodableValue(true));
            });
      } catch (const std::exception& error) {
        // Retain the retired object so the registrar can never reference freed
        // storage. A later close can retry the unregister operation.
        textures_.insert(std::move(texture_node));
        async_result->Error("native-error", error.what());
      } catch (...) {
        textures_.insert(std::move(texture_node));
        async_result->Error("native-error",
                            "texture unregister failed unexpectedly");
      }
      return;
    }

    if (method_call.method_name() == "onRgba") {
      int64_t width;
      int64_t height;
      int64_t stride_align;
      if (!IntArgument(arguments, "key", &key) ||
          !IntArgument(arguments, "width", &width) ||
          !IntArgument(arguments, "height", &height) ||
          !IntArgument(arguments, "stride_align", &stride_align) ||
          width <= 0 || height <= 0 || stride_align < 0) {
        return BadArguments(std::move(result));
      }
      auto data_value = arguments->find(flutter::EncodableValue("data"));
      if (data_value == arguments->end()) {
        return BadArguments(std::move(result));
      }
      const auto* data = std::get_if<std::vector<uint8_t>>(&data_value->second);
      if (data == nullptr) {
        return BadArguments(std::move(result));
      }
      auto found = textures_.find(key);
      const bool accepted =
          found != textures_.end() &&
          found->second->MarkVideoFrameAvailable(
              data->data(), data->size(), static_cast<size_t>(width),
              static_cast<size_t>(height), static_cast<size_t>(stride_align));
      return result->Success(flutter::EncodableValue(accepted));
    }

    if (method_call.method_name() == "getTexturePtr") {
      if (!IntArgument(arguments, "key", &key)) {
        return BadArguments(std::move(result));
      }
      auto found = textures_.find(key);
      const int64_t address =
          found == textures_.end()
              ? 0
              : reinterpret_cast<int64_t>(found->second.get());
      return result->Success(flutter::EncodableValue(address));
    }

    result->NotImplemented();
  } catch (const std::exception& error) {
    result->Error("native-error", error.what());
  }
}

}  // namespace texture_rgba_renderer

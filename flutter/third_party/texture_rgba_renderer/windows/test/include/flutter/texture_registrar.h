#ifndef TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_
#define TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

struct FlutterDesktopPixelBuffer {
  const uint8_t* buffer;
  size_t width;
  size_t height;
};

namespace flutter {

class PixelBufferTexture {
 public:
  using CopyBufferCallback =
      std::function<const FlutterDesktopPixelBuffer*(size_t, size_t)>;

  explicit PixelBufferTexture(CopyBufferCallback callback)
      : callback_(std::move(callback)) {}

  const FlutterDesktopPixelBuffer* CopyBuffer(size_t width, size_t height) {
    return callback_(width, height);
  }

 private:
  CopyBufferCallback callback_;
};

class TextureVariant {
 public:
  explicit TextureVariant(PixelBufferTexture texture)
      : texture_(std::move(texture)) {}

  const FlutterDesktopPixelBuffer* CopyBuffer(size_t width, size_t height) {
    return texture_.CopyBuffer(width, height);
  }

 private:
  PixelBufferTexture texture_;
};

class TextureRegistrar {
 public:
  virtual ~TextureRegistrar() = default;
  virtual int64_t RegisterTexture(TextureVariant* texture) = 0;
  virtual bool MarkTextureFrameAvailable(int64_t texture_id) = 0;
};

}  // namespace flutter

#endif  // TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_

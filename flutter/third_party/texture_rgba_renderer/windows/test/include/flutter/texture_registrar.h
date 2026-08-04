#ifndef TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_
#define TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>
#include <variant>

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

  const FlutterDesktopPixelBuffer* CopyPixelBuffer(size_t width,
                                                   size_t height) const {
    return callback_(width, height);
  }

 private:
  CopyBufferCallback callback_;
};

class GpuSurfaceTexture {};

using TextureVariant = std::variant<PixelBufferTexture, GpuSurfaceTexture>;

class TextureRegistrar {
 public:
  virtual ~TextureRegistrar() = default;
  virtual int64_t RegisterTexture(TextureVariant* texture) = 0;
  virtual bool MarkTextureFrameAvailable(int64_t texture_id) = 0;
  virtual void UnregisterTexture(int64_t texture_id,
                                 std::function<void()> callback) = 0;
  virtual bool UnregisterTexture(int64_t texture_id) = 0;
};

}  // namespace flutter

#endif  // TEXTURE_RGBA_RENDERER_TEST_FLUTTER_TEXTURE_REGISTRAR_H_

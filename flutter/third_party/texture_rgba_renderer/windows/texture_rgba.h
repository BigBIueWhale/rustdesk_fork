// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#ifndef TEXTURE_RGBA_H_
#define TEXTURE_RGBA_H_

#include <flutter/texture_registrar.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

class TextureRgba {
 public:
  explicit TextureRgba(flutter::TextureRegistrar* texture_registrar);
  ~TextureRgba() = default;

  TextureRgba(const TextureRgba&) = delete;
  TextureRgba& operator=(const TextureRgba&) = delete;

  bool MarkVideoFrameAvailable(const uint8_t* buffer, size_t buffer_length,
                               size_t width, size_t height,
                               size_t stride_align);
  void Retire();

  int64_t texture_id() const { return texture_id_; }

 private:
  const FlutterDesktopPixelBuffer* CopyBuffer();

  FlutterDesktopPixelBuffer flutter_pixel_buffer_{};
  flutter::TextureRegistrar* texture_registrar_;
  std::unique_ptr<flutter::TextureVariant> texture_;
  int64_t texture_id_ = -1;
  std::mutex mutex_;
  int foreground_index_ = 0;
  bool buffer_ready_ = false;
  bool retired_ = false;
  size_t width_[2] = {};
  size_t height_[2] = {};
  std::vector<uint8_t> buffers_[2];
};

#endif  // TEXTURE_RGBA_H_

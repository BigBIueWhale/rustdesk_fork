// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#include "texture_rgba.h"

#include <algorithm>
#include <limits>

namespace {

bool CheckedSourceLayout(size_t width, size_t height, size_t stride_align,
                         size_t* row_bytes, size_t* source_row_bytes,
                         size_t* source_size, size_t* packed_size) {
  if (width == 0 || height == 0 ||
      width > std::numeric_limits<size_t>::max() / 4) {
    return false;
  }
  *row_bytes = width * 4;
  if (stride_align <= 1) {
    *source_row_bytes = *row_bytes;
  } else {
    if ((stride_align & (stride_align - 1)) != 0 ||
        *row_bytes > std::numeric_limits<size_t>::max() - (stride_align - 1)) {
      return false;
    }
    *source_row_bytes = (*row_bytes + stride_align - 1) & ~(stride_align - 1);
  }
  if (*source_row_bytes > std::numeric_limits<size_t>::max() / height ||
      *row_bytes > std::numeric_limits<size_t>::max() / height) {
    return false;
  }
  *source_size = *source_row_bytes * height;
  *packed_size = *row_bytes * height;
  return true;
}

}  // namespace

TextureRgba::TextureRgba(flutter::TextureRegistrar* texture_registrar)
    : texture_registrar_(texture_registrar) {
  if (texture_registrar_ == nullptr) {
    return;
  }
  texture_ =
      std::make_unique<flutter::TextureVariant>(flutter::PixelBufferTexture(
          [this](size_t width, size_t height) { return CopyBuffer(); }));
  texture_id_ = texture_registrar_->RegisterTexture(texture_.get());
}

bool TextureRgba::MarkVideoFrameAvailable(const uint8_t* buffer,
                                          size_t buffer_length, size_t width,
                                          size_t height, size_t stride_align) {
  if (buffer == nullptr) {
    return false;
  }

  size_t row_bytes;
  size_t source_row_bytes;
  size_t source_size;
  size_t packed_size;
  if (!CheckedSourceLayout(width, height, stride_align, &row_bytes,
                           &source_row_bytes, &source_size, &packed_size) ||
      buffer_length < source_size) {
    return false;
  }

  std::vector<uint8_t> copied;
  try {
    copied.resize(packed_size);
    for (size_t row = 0; row < height; ++row) {
      std::copy_n(buffer + row * source_row_bytes, row_bytes,
                  copied.data() + row * row_bytes);
    }
  } catch (...) {
    return false;
  }

  const std::lock_guard<std::mutex> lock(mutex_);
  if (retired_ || texture_id_ <= 0) {
    return false;
  }
  const int background_index = foreground_index_ ^ 1;
  buffers_[background_index].swap(copied);
  width_[background_index] = width;
  height_[background_index] = height;
  const bool notification_needed = !buffer_ready_;
  buffer_ready_ = true;
  if (!notification_needed) {
    return true;
  }
  if (texture_registrar_->MarkTextureFrameAvailable(texture_id_)) {
    return true;
  }
  buffer_ready_ = false;
  width_[background_index] = 0;
  height_[background_index] = 0;
  buffers_[background_index].clear();
  return false;
}

void TextureRgba::Retire() {
  const std::lock_guard<std::mutex> lock(mutex_);
  retired_ = true;
}

const FlutterDesktopPixelBuffer* TextureRgba::CopyBuffer() {
  const std::lock_guard<std::mutex> lock(mutex_);
  if (buffer_ready_) {
    foreground_index_ ^= 1;
    flutter_pixel_buffer_.buffer = buffers_[foreground_index_].data();
    flutter_pixel_buffer_.width = width_[foreground_index_];
    flutter_pixel_buffer_.height = height_[foreground_index_];
    buffer_ready_ = false;
  }
  return &flutter_pixel_buffer_;
}

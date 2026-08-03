#include "../texture_rgba.h"

#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

class TestTextureRegistrar final : public flutter::TextureRegistrar {
 public:
  int64_t RegisterTexture(flutter::TextureVariant* texture) override {
    texture_ = texture;
    return 17;
  }

  bool MarkTextureFrameAvailable(int64_t texture_id) override {
    ++mark_count;
    return texture_id == 17 && mark_result;
  }

  const FlutterDesktopPixelBuffer* CopyBuffer() {
    return texture_ == nullptr ? nullptr : texture_->CopyBuffer(0, 0);
  }

  flutter::TextureVariant* texture_ = nullptr;
  size_t mark_count = 0;
  bool mark_result = true;
};

bool check(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
  }
  return condition;
}

}  // namespace

int main() {
  TestTextureRegistrar registrar;
  TextureRgba texture(&registrar);

  const uint8_t frame_a[] = {
      1, 2,  3,  4,  5,  6,  7,  8,  90, 90, 90, 90, 90, 90, 90, 90,
      9, 10, 11, 12, 13, 14, 15, 16, 91, 91, 91, 91, 91, 91, 91, 91,
  };
  const uint8_t frame_b[] = {
      21, 22, 23, 24, 25, 26, 27, 28, 92, 92, 92, 92, 92, 92, 92, 92,
      29, 30, 31, 32, 33, 34, 35, 36, 93, 93, 93, 93, 93, 93, 93, 93,
  };
  const uint8_t packed_a[] = {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  };
  const uint8_t packed_b[] = {
      21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
  };

  bool passed = true;
  passed &= check(texture.texture_id() == 17,
                  "texture registration did not return the fake registrar ID");
  passed &=
      check(texture.MarkVideoFrameAvailable(frame_a, sizeof(frame_a), 2, 2, 16),
            "first frame was rejected");
  passed &=
      check(texture.MarkVideoFrameAvailable(frame_b, sizeof(frame_b), 2, 2, 16),
            "latest pending frame was rejected");
  passed &= check(registrar.mark_count == 1,
                  "pending-frame notifications were not coalesced");
  passed &= check(texture.NotifyPendingFrame(),
                  "pending frame could not be re-notified");
  passed &= check(registrar.mark_count == 2,
                  "pending-frame re-notification did not reach the registrar");

  const FlutterDesktopPixelBuffer* copied = registrar.CopyBuffer();
  passed &= check(copied != nullptr, "latest pending frame was not copied");
  passed &=
      check(copied != nullptr && copied->width == 2 && copied->height == 2,
            "copied frame dimensions were incorrect");
  passed &=
      check(copied != nullptr && copied->buffer != nullptr &&
                std::memcmp(copied->buffer, packed_b, sizeof(packed_b)) == 0,
            "stride-packed latest frame bytes were incorrect");
  passed &= check(texture.NotifyPendingFrame(),
                  "idle live texture rejected re-notification");
  passed &= check(registrar.mark_count == 2,
                  "idle texture emitted a spurious frame notification");

  registrar.mark_result = false;
  passed &= check(
      !texture.MarkVideoFrameAvailable(frame_a, sizeof(frame_a), 2, 2, 16),
      "failed registrar notification was accepted");
  copied = registrar.CopyBuffer();
  passed &=
      check(copied != nullptr && copied->width == 2 && copied->height == 2 &&
                copied->buffer != nullptr &&
                std::memcmp(copied->buffer, packed_b, sizeof(packed_b)) == 0,
            "notification failure corrupted the presented frame");
  registrar.mark_result = true;
  passed &=
      check(texture.MarkVideoFrameAvailable(frame_a, sizeof(frame_a), 2, 2, 16),
            "pre-retirement pending frame was rejected");
  registrar.mark_result = false;
  passed &= check(!texture.NotifyPendingFrame(),
                  "failed pending-frame re-notification was accepted");
  copied = registrar.CopyBuffer();
  passed &= check(copied != nullptr && copied->buffer != nullptr &&
                      std::memcmp(copied->buffer, packed_a, sizeof(packed_a)) ==
                          0,
                  "failed re-notification consumed the pending frame");
  const uint8_t* presented = copied == nullptr ? nullptr : copied->buffer;
  registrar.mark_result = true;
  passed &=
      check(texture.MarkVideoFrameAvailable(frame_b, sizeof(frame_b), 2, 2, 16),
            "retirement-bound pending frame was rejected");
  texture.Retire();
  passed &= check(registrar.CopyBuffer() == nullptr,
                  "a pending frame crossed the retirement boundary");
  passed &= check(presented != nullptr &&
                      std::memcmp(presented, packed_a, sizeof(packed_a)) == 0,
                  "retirement released the presented frame too early");
  passed &= check(
      !texture.MarkVideoFrameAvailable(frame_b, sizeof(frame_b), 2, 2, 16),
      "a retired texture accepted a new frame");
  passed &= check(!texture.NotifyPendingFrame(),
                  "a retired texture accepted re-notification");

  if (!passed) {
    return 1;
  }
  std::cout << "texture_rgba_windows_core_test: PASS\n";
  return 0;
}

#include "../texture_rgba_renderer_plugin.cc"

#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

struct TestTextureRegistrar {
  GObject parent_instance;
  guint mark_count;
  gboolean mark_result;
};

struct TestTextureRegistrarClass {
  GObjectClass parent_class;
};

static void test_texture_registrar_interface_init(
    FlTextureRegistrarInterface* interface);

G_DEFINE_TYPE_WITH_CODE(
    TestTextureRegistrar, test_texture_registrar, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(fl_texture_registrar_get_type(),
                          test_texture_registrar_interface_init))

static gboolean test_register_texture(FlTextureRegistrar*, FlTexture*) {
  return TRUE;
}

static FlTexture* test_lookup_texture(FlTextureRegistrar*, int64_t) {
  return nullptr;
}

static gboolean test_mark_texture_frame_available(FlTextureRegistrar* registrar,
                                                  FlTexture*) {
  auto* self = reinterpret_cast<TestTextureRegistrar*>(registrar);
  ++self->mark_count;
  return self->mark_result;
}

static gboolean test_unregister_texture(FlTextureRegistrar*, FlTexture*) {
  return TRUE;
}

static void test_shutdown(FlTextureRegistrar*) {}

static void test_texture_registrar_interface_init(
    FlTextureRegistrarInterface* interface) {
  interface->register_texture = test_register_texture;
  interface->lookup_texture = test_lookup_texture;
  interface->mark_texture_frame_available = test_mark_texture_frame_available;
  interface->unregister_texture = test_unregister_texture;
  interface->shutdown = test_shutdown;
}

static void test_texture_registrar_class_init(TestTextureRegistrarClass*) {}

static void test_texture_registrar_init(TestTextureRegistrar* self) {
  self->mark_count = 0;
  self->mark_result = TRUE;
}

bool check(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
  }
  return condition;
}

bool copy_pixels(TextureRgba* texture, const uint8_t** buffer, uint32_t* width,
                 uint32_t* height, GError** error) {
  return texture_rgba_copy_pixels(
      reinterpret_cast<FlPixelBufferTexture*>(texture), buffer, width, height,
      error);
}

}  // namespace

int main() {
  auto* registrar = reinterpret_cast<TestTextureRegistrar*>(
      g_object_new(test_texture_registrar_get_type(), nullptr));
  TextureRgba* texture = texture_rgba_new(FL_TEXTURE_REGISTRAR(registrar));

  const uint8_t frame_a[] = {
      1, 2,  3,  4,  5,  6,  7,  8,  90, 90, 90, 90, 90, 90, 90, 90,
      9, 10, 11, 12, 13, 14, 15, 16, 91, 91, 91, 91, 91, 91, 91, 91,
  };
  const uint8_t frame_b[] = {
      21, 22, 23, 24, 25, 26, 27, 28, 92, 92, 92, 92, 92, 92, 92, 92,
      29, 30, 31, 32, 33, 34, 35, 36, 93, 93, 93, 93, 93, 93, 93, 93,
  };
  const uint8_t packed_b[] = {
      21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
  };

  bool passed = true;
  passed &= check(
      texture_rgba_mark_frame(texture, frame_a, sizeof(frame_a), 2, 2, 16),
      "first frame was rejected");
  passed &= check(
      texture_rgba_mark_frame(texture, frame_b, sizeof(frame_b), 2, 2, 16),
      "latest pending frame was rejected");
  passed &= check(registrar->mark_count == 1,
                  "pending-frame notifications were not coalesced");

  const uint8_t* copied = nullptr;
  uint32_t width = 0;
  uint32_t height = 0;
  GError* error = nullptr;
  passed &= check(copy_pixels(texture, &copied, &width, &height, &error),
                  "latest pending frame was not copied");
  passed &= check(error == nullptr, "successful copy reported an error");
  passed &= check(width == 2 && height == 2,
                  "copied frame dimensions were incorrect");
  passed &= check(
      copied != nullptr && std::memcmp(copied, packed_b, sizeof(packed_b)) == 0,
      "stride-packed latest frame bytes were incorrect");

  registrar->mark_result = FALSE;
  passed &= check(
      !texture_rgba_mark_frame(texture, frame_a, sizeof(frame_a), 2, 2, 16),
      "failed registrar notification was accepted");
  copied = nullptr;
  width = 0;
  height = 0;
  passed &= check(copy_pixels(texture, &copied, &width, &height, &error),
                  "last presented frame was lost after notification failure");
  passed &= check(error == nullptr, "prior-frame copy reported an error");
  passed &= check(width == 2 && height == 2 && copied != nullptr &&
                      std::memcmp(copied, packed_b, sizeof(packed_b)) == 0,
                  "notification failure corrupted the presented frame");
  const uint8_t* presented = copied;

  registrar->mark_result = TRUE;
  passed &= check(
      texture_rgba_mark_frame(texture, frame_a, sizeof(frame_a), 2, 2, 16),
      "pre-retirement pending frame was rejected");
  texture_rgba_retire(texture);
  passed &= check(texture->buffer == nullptr && !texture->buffer_ready &&
                      texture->buffer_width == 0 && texture->buffer_height == 0,
                  "retirement retained pending frame state");
  passed &= check(
      texture->prior_buffer == presented &&
          std::memcmp(texture->prior_buffer, packed_b, sizeof(packed_b)) == 0,
      "retirement released the presented frame too early");
  copied = nullptr;
  width = 0;
  height = 0;
  passed &= check(!copy_pixels(texture, &copied, &width, &height, &error),
                  "a pending frame crossed the retirement boundary");
  passed &= check(error != nullptr &&
                      std::strcmp(error->message, "texture is retired") == 0,
                  "retired copy did not report the retirement cause");
  g_clear_error(&error);
  passed &= check(
      !texture_rgba_mark_frame(texture, frame_b, sizeof(frame_b), 2, 2, 16),
      "a retired texture accepted a new frame");

  g_object_unref(texture);
  g_object_unref(registrar);
  if (!passed) {
    return 1;
  }
  std::cout << "texture_rgba_renderer_plugin_test: PASS\n";
  return 0;
}

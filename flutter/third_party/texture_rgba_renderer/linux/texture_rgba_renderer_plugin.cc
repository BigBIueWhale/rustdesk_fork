// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
#include "include/texture_rgba_renderer/texture_rgba_renderer_plugin.h"

#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <unordered_map>

#define TEXTURE_RGBA_RENDERER_PLUGIN(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), texture_rgba_renderer_plugin_get_type(), \
                              TextureRgbaRendererPlugin))

typedef struct {
  FlPixelBufferTextureClass parent_class;
} TextureRgbaClass;

typedef struct _TextureRgba {
  FlPixelBufferTexture parent_instance;
  FlTextureRegistrar* texture_registrar;
  uint8_t* buffer;
  uint8_t* prior_buffer;
  int64_t texture_id;
  uint32_t buffer_width;
  uint32_t buffer_height;
  uint32_t prior_width;
  uint32_t prior_height;
  uint64_t submitted_frames;
  uint64_t pending_sequence;
  uint64_t copied_frames;
  uint64_t prior_sequence;
  gboolean buffer_ready;
  gboolean retired;
  GMutex mutex;
} TextureRgba;

static gboolean presentation_trace_enabled() {
  static gsize initialized = 0;
  static gboolean enabled = FALSE;
  if (g_once_init_enter(&initialized)) {
    const gchar* value = g_getenv("RUSTDESK_PRESENTATION_TRACE");
    enabled = value != nullptr && std::strcmp(value, "1") == 0;
    g_once_init_leave(&initialized, 1);
  }
  return enabled;
}

static void presentation_trace_samples(const uint8_t* buffer, uint32_t width,
                                       uint32_t height, uint8_t left[4],
                                       uint8_t right[4]) {
  const size_t row_bytes = static_cast<size_t>(width) * 4;
  const size_t row = static_cast<size_t>(height / 2) * row_bytes;
  std::memcpy(left, buffer + row + static_cast<size_t>(width / 4) * 4, 4);
  std::memcpy(right, buffer + row + static_cast<size_t>((width * 3) / 4) * 4,
              4);
}

static void presentation_trace(const char* stage, TextureRgba* self,
                               uint64_t sequence, const uint8_t* buffer,
                               uint32_t width, uint32_t height,
                               gboolean marked) {
  if (!presentation_trace_enabled()) {
    return;
  }
  uint8_t left[4];
  uint8_t right[4];
  presentation_trace_samples(buffer, width, height, left, right);
  g_printerr(
      "RUSTDESK_PRESENTATION_TRACE stage=%s monotonic_us=%" G_GINT64_FORMAT
      " texture=%p sequence=%" G_GUINT64_FORMAT
      " submitted=%" G_GUINT64_FORMAT " copied=%" G_GUINT64_FORMAT
      " marked=%d dimensions=%ux%u left=%02x%02x%02x%02x"
      " right=%02x%02x%02x%02x\n",
      stage, g_get_monotonic_time(), self, sequence, self->submitted_frames,
      self->copied_frames, marked, width, height, left[0], left[1], left[2],
      left[3], right[0], right[1], right[2], right[3]);
}

G_DEFINE_TYPE(TextureRgba, texture_rgba, fl_pixel_buffer_texture_get_type())

struct _TextureRgbaRendererPlugin {
  GObject parent_instance;
  FlTextureRegistrar* texture_registrar;
  std::unordered_map<int64_t, TextureRgba*>* renderers;
};

G_DEFINE_TYPE(TextureRgbaRendererPlugin, texture_rgba_renderer_plugin,
              g_object_get_type())

static gboolean checked_source_layout(int width, int height, int stride_align,
                                      size_t* row_bytes,
                                      size_t* source_row_bytes,
                                      size_t* source_size,
                                      size_t* packed_size) {
  if (width <= 0 || height <= 0 || stride_align < 0) {
    return FALSE;
  }

  const size_t unsigned_width = static_cast<size_t>(width);
  const size_t unsigned_height = static_cast<size_t>(height);
  if (unsigned_width > std::numeric_limits<size_t>::max() / 4) {
    return FALSE;
  }
  *row_bytes = unsigned_width * 4;

  if (stride_align <= 1) {
    *source_row_bytes = *row_bytes;
  } else {
    const size_t align = static_cast<size_t>(stride_align);
    if ((align & (align - 1)) != 0 ||
        *row_bytes > std::numeric_limits<size_t>::max() - (align - 1)) {
      return FALSE;
    }
    *source_row_bytes = (*row_bytes + align - 1) & ~(align - 1);
  }

  if (*source_row_bytes >
          std::numeric_limits<size_t>::max() / unsigned_height ||
      *row_bytes > std::numeric_limits<size_t>::max() / unsigned_height) {
    return FALSE;
  }
  *source_size = *source_row_bytes * unsigned_height;
  *packed_size = *row_bytes * unsigned_height;
  return TRUE;
}

static gboolean texture_rgba_mark_frame(TextureRgba* self,
                                        const uint8_t* buffer, int len,
                                        int width, int height,
                                        int stride_align) {
  if (self == nullptr || buffer == nullptr || len <= 0) {
    return FALSE;
  }

  size_t row_bytes;
  size_t source_row_bytes;
  size_t source_size;
  size_t packed_size;
  if (!checked_source_layout(width, height, stride_align, &row_bytes,
                             &source_row_bytes, &source_size, &packed_size) ||
      static_cast<size_t>(len) < source_size) {
    return FALSE;
  }

  std::unique_ptr<uint8_t[]> copied(new (std::nothrow) uint8_t[packed_size]);
  if (!copied) {
    return FALSE;
  }
  for (int row = 0; row < height; ++row) {
    std::memcpy(copied.get() + static_cast<size_t>(row) * row_bytes,
                buffer + static_cast<size_t>(row) * source_row_bytes,
                row_bytes);
  }

  g_mutex_lock(&self->mutex);
  if (self->retired) {
    g_mutex_unlock(&self->mutex);
    return FALSE;
  }
  uint8_t* superseded = self->buffer;
  self->buffer = copied.release();
  self->buffer_width = static_cast<uint32_t>(width);
  self->buffer_height = static_cast<uint32_t>(height);
  self->submitted_frames += 1;
  self->pending_sequence = self->submitted_frames;
  self->buffer_ready = TRUE;
  delete[] superseded;
  // A pending buffer bounds storage, but it is not a durable scheduling edge:
  // an obscured compositor may drop an earlier edge without copying pixels.
  // Notify for every admitted update so a later frame can schedule rendering.
  const gboolean marked = fl_texture_registrar_mark_texture_frame_available(
      self->texture_registrar, FL_TEXTURE(self));
  presentation_trace("submit", self, self->pending_sequence, self->buffer,
                     self->buffer_width, self->buffer_height, marked);
  if (!marked) {
    delete[] self->buffer;
    self->buffer = nullptr;
    self->buffer_width = 0;
    self->buffer_height = 0;
    self->pending_sequence = 0;
    self->buffer_ready = FALSE;
  }
  g_mutex_unlock(&self->mutex);
  return marked;
}

static gboolean texture_rgba_notify_pending(TextureRgba* self) {
  if (self == nullptr) {
    return FALSE;
  }
  g_mutex_lock(&self->mutex);
  if (self->retired || self->texture_registrar == nullptr ||
      self->texture_id <= 0) {
    g_mutex_unlock(&self->mutex);
    return FALSE;
  }
  const gboolean marked =
      !self->buffer_ready || fl_texture_registrar_mark_texture_frame_available(
                                 self->texture_registrar, FL_TEXTURE(self));
  g_mutex_unlock(&self->mutex);
  return marked;
}

static gboolean texture_rgba_retire(TextureRgba* self) {
  g_mutex_lock(&self->mutex);
  if (self->retired) {
    g_mutex_unlock(&self->mutex);
    return FALSE;
  }
  self->retired = TRUE;
  uint8_t* pending_buffer = self->buffer;
  self->buffer = nullptr;
  self->buffer_width = 0;
  self->buffer_height = 0;
  self->buffer_ready = FALSE;
  g_mutex_unlock(&self->mutex);
  delete[] pending_buffer;
  return TRUE;
}

static gboolean texture_rgba_is_live(TextureRgba* self) {
  if (self == nullptr) {
    return FALSE;
  }
  g_mutex_lock(&self->mutex);
  const gboolean live = !self->retired && self->texture_id > 0;
  g_mutex_unlock(&self->mutex);
  return live;
}

static gboolean texture_rgba_copy_pixels(FlPixelBufferTexture* texture,
                                         const uint8_t** out_buffer,
                                         uint32_t* width, uint32_t* height,
                                         GError** error) {
  TextureRgba* self = reinterpret_cast<TextureRgba*>(texture);
  g_mutex_lock(&self->mutex);
  if (self->retired) {
    g_mutex_unlock(&self->mutex);
    g_set_error(error, g_quark_from_static_string("TextureRgbaRenderer"), -1,
                "texture is retired");
    return FALSE;
  }
  if (self->buffer_ready) {
    delete[] self->prior_buffer;
    self->prior_buffer = self->buffer;
    self->buffer = nullptr;
    self->prior_width = self->buffer_width;
    self->prior_height = self->buffer_height;
    self->prior_sequence = self->pending_sequence;
    self->copied_frames += 1;
    self->buffer_width = 0;
    self->buffer_height = 0;
    self->pending_sequence = 0;
    *out_buffer = self->prior_buffer;
    *width = self->prior_width;
    *height = self->prior_height;
    self->buffer_ready = FALSE;
    presentation_trace("copy", self, self->prior_sequence,
                       self->prior_buffer, self->prior_width,
                       self->prior_height, TRUE);
    g_mutex_unlock(&self->mutex);
    return TRUE;
  }
  if (self->prior_buffer != nullptr) {
    *out_buffer = self->prior_buffer;
    *width = self->prior_width;
    *height = self->prior_height;
    g_mutex_unlock(&self->mutex);
    return TRUE;
  }
  g_mutex_unlock(&self->mutex);
  g_set_error(error, g_quark_from_static_string("TextureRgbaRenderer"), -1,
              "texture has no frame");
  return FALSE;
}

static void texture_rgba_finalize(GObject* object) {
  TextureRgba* self = reinterpret_cast<TextureRgba*>(object);
  g_mutex_lock(&self->mutex);
  self->retired = TRUE;
  uint8_t* buffer = self->buffer;
  uint8_t* prior_buffer = self->prior_buffer;
  self->buffer = nullptr;
  self->prior_buffer = nullptr;
  if (buffer == prior_buffer) {
    buffer = nullptr;
  }
  g_mutex_unlock(&self->mutex);

  delete[] buffer;
  delete[] prior_buffer;
  g_mutex_clear(&self->mutex);
  G_OBJECT_CLASS(texture_rgba_parent_class)->finalize(object);
}

static void texture_rgba_class_init(TextureRgbaClass* klass) {
  FL_PIXEL_BUFFER_TEXTURE_CLASS(klass)->copy_pixels = texture_rgba_copy_pixels;
  G_OBJECT_CLASS(klass)->finalize = texture_rgba_finalize;
}

static void texture_rgba_init(TextureRgba* self) {
  self->texture_registrar = nullptr;
  self->buffer = nullptr;
  self->prior_buffer = nullptr;
  self->texture_id = 0;
  self->buffer_width = 0;
  self->buffer_height = 0;
  self->prior_width = 0;
  self->prior_height = 0;
  self->submitted_frames = 0;
  self->pending_sequence = 0;
  self->copied_frames = 0;
  self->prior_sequence = 0;
  self->buffer_ready = FALSE;
  self->retired = FALSE;
  g_mutex_init(&self->mutex);
}

static TextureRgba* texture_rgba_new(FlTextureRegistrar* registrar) {
  TextureRgba* texture = reinterpret_cast<TextureRgba*>(
      g_object_new(texture_rgba_get_type(), nullptr));
  texture->texture_registrar = registrar;
  return texture;
}

static FlMethodResponse* bad_arguments_response() {
  return FL_METHOD_RESPONSE(fl_method_error_response_new(
      "bad-arguments", "texture arguments are missing or malformed", nullptr));
}

static gboolean lookup_int(FlValue* args, const char* name, int64_t* value) {
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return FALSE;
  }
  FlValue* candidate = fl_value_lookup_string(args, name);
  if (candidate == nullptr ||
      fl_value_get_type(candidate) != FL_VALUE_TYPE_INT) {
    return FALSE;
  }
  *value = fl_value_get_int(candidate);
  return TRUE;
}

static gboolean release_texture(TextureRgbaRendererPlugin* self,
                                TextureRgba* texture) {
  texture_rgba_retire(texture);
  if (!fl_texture_registrar_unregister_texture(self->texture_registrar,
                                               FL_TEXTURE(texture))) {
    return FALSE;
  }
  g_object_unref(texture);
  return TRUE;
}

static gboolean close_texture(TextureRgbaRendererPlugin* self, int64_t key) {
  if (self->renderers == nullptr) {
    return FALSE;
  }
  auto found = self->renderers->find(key);
  if (found == self->renderers->end() || found->second == nullptr) {
    return FALSE;
  }

  TextureRgba* texture = found->second;
  if (!texture_rgba_retire(texture)) {
    return FALSE;
  }
  // Keep the key reserved while the exact texture is detached from live
  // lookup. A failed unregister restores the retired owner, which rejects
  // frames and prevents a successor from reusing this key.
  found->second = nullptr;
  if (!fl_texture_registrar_unregister_texture(self->texture_registrar,
                                               FL_TEXTURE(texture))) {
    found->second = texture;
    return FALSE;
  }
  self->renderers->erase(found);
  g_object_unref(texture);
  return TRUE;
}

static void texture_rgba_renderer_plugin_handle_method_call(
    TextureRgbaRendererPlugin* self, FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;
  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);
  int64_t key;

  if (std::strcmp(method, "createTexture") == 0) {
    if (!lookup_int(args, "key", &key)) {
      response = bad_arguments_response();
    } else if (self->renderers == nullptr) {
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_int(-1)));
    } else {
      TextureRgba** reserved = nullptr;
      try {
        auto insertion = self->renderers->emplace(key, nullptr);
        if (!insertion.second) {
          response = FL_METHOD_RESPONSE(
              fl_method_success_response_new(fl_value_new_int(-1)));
        } else {
          reserved = &insertion.first->second;
        }
      } catch (...) {
        // Map allocation happens before native registration, so failure has no
        // registered texture whose lifetime could become ambiguous.
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "allocation-failed", "failed to reserve texture ownership",
            nullptr));
      }
      if (reserved != nullptr) {
        TextureRgba* texture = texture_rgba_new(self->texture_registrar);
        if (texture == nullptr) {
          self->renderers->erase(key);
          response = FL_METHOD_RESPONSE(
              fl_method_success_response_new(fl_value_new_int(-1)));
        } else if (!fl_texture_registrar_register_texture(
                       self->texture_registrar, FL_TEXTURE(texture))) {
          texture_rgba_retire(texture);
          g_object_unref(texture);
          self->renderers->erase(key);
          response = FL_METHOD_RESPONSE(
              fl_method_success_response_new(fl_value_new_int(-1)));
        } else {
          texture->texture_id = fl_texture_get_id(FL_TEXTURE(texture));
          *reserved = texture;
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(
              fl_value_new_int(texture->texture_id)));
        }
      }
    }
  } else if (std::strcmp(method, "closeTexture") == 0) {
    if (!lookup_int(args, "key", &key)) {
      response = bad_arguments_response();
    } else {
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_bool(
              close_texture(self, key))));
    }
  } else if (std::strcmp(method, "onRgba") == 0) {
    int64_t width;
    int64_t height;
    int64_t stride_align;
    FlValue* data =
        args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP
            ? nullptr
            : fl_value_lookup_string(args, "data");
    if (!lookup_int(args, "key", &key) || !lookup_int(args, "width", &width) ||
        !lookup_int(args, "height", &height) ||
        !lookup_int(args, "stride_align", &stride_align) || data == nullptr ||
        fl_value_get_type(data) != FL_VALUE_TYPE_UINT8_LIST ||
        width < std::numeric_limits<int>::min() ||
        width > std::numeric_limits<int>::max() ||
        height < std::numeric_limits<int>::min() ||
        height > std::numeric_limits<int>::max() ||
        stride_align < std::numeric_limits<int>::min() ||
        stride_align > std::numeric_limits<int>::max() ||
        fl_value_get_length(data) >
            static_cast<size_t>(std::numeric_limits<int>::max())) {
      response = bad_arguments_response();
    } else if (self->renderers == nullptr) {
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_bool(FALSE)));
    } else {
      auto found = self->renderers->find(key);
      const gboolean accepted =
          found != self->renderers->end() &&
          found->second != nullptr &&
          texture_rgba_mark_frame(found->second, fl_value_get_uint8_list(data),
                                  static_cast<int>(fl_value_get_length(data)),
                                  static_cast<int>(width),
                                  static_cast<int>(height),
                                  static_cast<int>(stride_align));
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_bool(accepted)));
    }
  } else if (std::strcmp(method, "getTexturePtr") == 0) {
    if (!lookup_int(args, "key", &key)) {
      response = bad_arguments_response();
    } else if (self->renderers == nullptr) {
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_int(0)));
    } else {
      auto found = self->renderers->find(key);
      const bool live = found != self->renderers->end() &&
                        texture_rgba_is_live(found->second);
      const int64_t address =
          live ? reinterpret_cast<int64_t>(found->second) : 0;
      response = FL_METHOD_RESPONSE(
          fl_method_success_response_new(fl_value_new_int(address)));
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void texture_rgba_renderer_plugin_dispose(GObject* object) {
  TextureRgbaRendererPlugin* self = TEXTURE_RGBA_RENDERER_PLUGIN(object);
  if (self->renderers != nullptr) {
    for (const auto& entry : *self->renderers) {
      if (entry.second != nullptr && !release_texture(self, entry.second)) {
        // The registrar still has uncertain ownership. Process/engine teardown
        // is safer than finalizing storage that may remain callback-reachable.
        g_warning("Retaining texture after unregister failure");
      }
    }
    delete self->renderers;
    self->renderers = nullptr;
  }
  G_OBJECT_CLASS(texture_rgba_renderer_plugin_parent_class)->dispose(object);
}

static void texture_rgba_renderer_plugin_class_init(
    TextureRgbaRendererPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = texture_rgba_renderer_plugin_dispose;
}

static void texture_rgba_renderer_plugin_init(TextureRgbaRendererPlugin* self) {
  self->texture_registrar = nullptr;
  self->renderers =
      new (std::nothrow) std::unordered_map<int64_t, TextureRgba*>();
}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  TextureRgbaRendererPlugin* plugin = TEXTURE_RGBA_RENDERER_PLUGIN(user_data);
  texture_rgba_renderer_plugin_handle_method_call(plugin, method_call);
}

void texture_rgba_renderer_plugin_register_with_registrar(
    FlPluginRegistrar* registrar) {
  TextureRgbaRendererPlugin* plugin = TEXTURE_RGBA_RENDERER_PLUGIN(
      g_object_new(texture_rgba_renderer_plugin_get_type(), nullptr));
  plugin->texture_registrar =
      fl_plugin_registrar_get_texture_registrar(registrar);

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            "texture_rgba_renderer", FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, method_call_cb, g_object_ref(plugin), g_object_unref);
  g_object_unref(plugin);
}

int FlutterRgbaRendererPluginTryOnRgba(void* texture_rgba,
                                       const uint8_t* buffer, int len,
                                       int width, int height,
                                       int stride_align) {
  return texture_rgba_mark_frame(reinterpret_cast<TextureRgba*>(texture_rgba),
                                 buffer, len, width, height, stride_align)
             ? 1
             : 0;
}

int FlutterRgbaRendererPluginTryNotifyPending(void* texture_rgba) {
  return texture_rgba_notify_pending(
             reinterpret_cast<TextureRgba*>(texture_rgba))
             ? 1
             : 0;
}

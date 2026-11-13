// Native GTK/Mesa component check. Engine task dispatch is the only test double;
// compositing, framebuffers, pixels, contexts and widget teardown are production.
#include <epoxy/gl.h>
#include <functional>
#include <cstdio>
#include <vector>

#include "flutter/shell/platform/linux/fl_compositor_opengl.cc"
#include "flutter/shell/platform/linux/fl_view_renderer.cc"

struct _FlEngine {
  GObject parent_instance;
  FlTaskRunner* runner;
  FlOpenGLManager* manager;
};
G_DEFINE_TYPE(FlEngine, fl_engine, G_TYPE_OBJECT)
static std::function<void()> platform_task;
static void engine_dispose(GObject* object) {
  auto* self = FL_ENGINE(object);
  g_clear_object(&self->runner);
  g_clear_object(&self->manager);
  G_OBJECT_CLASS(fl_engine_parent_class)->dispose(object);
}
static void fl_engine_class_init(FlEngineClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = engine_dispose;
}
static void fl_engine_init(FlEngine* self) {}
FlutterRendererType fl_engine_get_renderer_type(FlEngine*) { return kOpenGL; }
FlTaskRunner* fl_engine_get_task_runner(FlEngine* self) { return self->runner; }
FlOpenGLManager* fl_engine_get_opengl_manager(FlEngine* self) { return self->manager; }
void fl_engine_execute_task(FlEngine*, FlutterTask*) {
  g_assert_true(static_cast<bool>(platform_task));
  auto task = std::move(platform_task);
  platform_task = {};
  task();
}

static GdkGLContext* observed_context;
static unsigned allocations, updates, binding_failures;
static GLuint uploaded_texture;
static bool reject_upload;
static unsigned upload_warnings;
static decltype(epoxy_glTexImage2D) real_image;
static decltype(epoxy_glTexSubImage2D) real_subimage;

static void image(GLenum target, GLint level, GLint internal, GLsizei width,
                  GLsizei height, GLint border, GLenum format, GLenum type,
                  const void* pixels) {
  if (reject_upload && observed_context &&
      gdk_gl_context_get_current() == observed_context) {
    // Exercise an actual driver refusal without exhausting guest/GPU memory.
    width = -1;
    reject_upload = false;
  }
  real_image(target, level, internal, width, height, border, format, type, pixels);
  if (observed_context && gdk_gl_context_get_current() == observed_context) {
    allocations++;
    GLint texture = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture);
    uploaded_texture = texture;
  }
}
static void subimage(GLenum target, GLint level, GLint x, GLint y, GLsizei width,
                     GLsizei height, GLenum format, GLenum type,
                     const void* pixels) {
  if (reject_upload && observed_context &&
      gdk_gl_context_get_current() == observed_context) {
    width = -1;
    reject_upload = false;
  }
  real_subimage(target, level, x, y, width, height, format, type, pixels);
  if (observed_context && gdk_gl_context_get_current() == observed_context) {
    updates++;
  }
}

static void publish(FlViewRenderer* renderer, size_t width, size_t height,
                    bool red) {
  auto* manager = renderer->engine->manager;
  g_assert_true(fl_opengl_manager_make_current(manager));
  {
    g_autoptr(FlFramebuffer) frame =
        fl_framebuffer_new(GL_RGBA, width, height, FALSE);
    glBindFramebuffer(GL_FRAMEBUFFER, fl_framebuffer_get_id(frame));
    glDisable(GL_SCISSOR_TEST);
    glClearColor(red ? 1 : 0, 0, red ? 0 : 1, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    FlutterBackingStore backing = {};
    backing.type = kFlutterBackingStoreTypeOpenGL;
    backing.open_gl.framebuffer.user_data = frame;
    FlutterLayer layer = {};
    layer.type = kFlutterLayerContentTypeBackingStore;
    layer.backing_store = &backing;
    layer.size = {static_cast<double>(width), static_cast<double>(height)};
    const FlutterLayer* layers[] = {&layer};
    g_assert_true(fl_compositor_present_layers(renderer->compositor, layers, 1));
    g_assert_cmpint(glGetError(), ==, GL_NO_ERROR);
  }
  g_assert_true(fl_opengl_manager_clear_current(manager));
  // EGL and GDK maintain separate current-context bookkeeping.
  gdk_gl_context_clear_current();
}

static void draw(FlViewRenderer* renderer, int width, int height, bool red) {
  observed_context = renderer->render_context;
  g_assert_nonnull(observed_context);
  gdk_gl_context_make_current(observed_context);
  GLuint sentinel;
  glGenTextures(1, &sentinel);
  glBindTexture(GL_TEXTURE_2D, sentinel);
  auto* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
  auto* cr = cairo_create(surface);
  g_assert_true(fl_compositor_render(renderer->compositor, cr,
      gtk_widget_get_window(GTK_WIDGET(renderer)), FALSE));
  g_assert_cmpint(cairo_status(cr), ==, CAIRO_STATUS_SUCCESS);
  gdk_gl_context_make_current(observed_context);
  GLint binding;
  glGetIntegerv(GL_TEXTURE_BINDING_2D, &binding);
#ifdef LEGACY_BASELINE
  binding_failures += binding != static_cast<GLint>(sentinel);
#else
  g_assert_cmpuint(binding, ==, sentinel);
#endif
  g_assert_cmpint(glGetError(), ==, GL_NO_ERROR);
  glDeleteTextures(1, &sentinel);
  cairo_surface_flush(surface);
  int stride = cairo_image_surface_get_stride(surface);
  auto* pixels = cairo_image_surface_get_data(surface);
  // Observe actual Cairo output, not upload calls or input bytes.
  for (int y : {0, height / 2, height - 1}) {
    auto* row = reinterpret_cast<uint32_t*>(pixels + stride * y);
    for (int x : {0, width / 2, width - 1}) {
      g_assert_cmphex(row[x], ==, red ? 0xffff0000u : 0xff0000ffu);
    }
  }
  cairo_destroy(cr);
  cairo_surface_destroy(surface);
  gdk_gl_context_clear_current();
  observed_context = nullptr;
}

static void upload_warning(const gchar*, GLogLevelFlags, const gchar* message,
                           gpointer) {
  g_assert_cmpstr(message, ==, "OpenGL error while uploading GTK frame: 0x501");
  upload_warnings++;
}

static void rejected_frame(FlViewRenderer* renderer) {
  observed_context = renderer->render_context;
  gdk_gl_context_make_current(observed_context);
  GLuint sentinel;
  glGenTextures(1, &sentinel);
  glBindTexture(GL_TEXTURE_2D, sentinel);
  auto* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 96, 64);
  auto* cr = cairo_create(surface);
  auto handler = g_log_set_handler(nullptr, G_LOG_LEVEL_WARNING, upload_warning, nullptr);
  auto fatal = g_log_set_always_fatal(static_cast<GLogLevelFlags>(
      G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL));
  reject_upload = true;
  g_assert_false(fl_compositor_render(renderer->compositor, cr,
      gtk_widget_get_window(GTK_WIDGET(renderer)), FALSE));
  g_assert_false(reject_upload);
  g_log_set_always_fatal(fatal);
  g_log_remove_handler(nullptr, handler);
  GLint binding;
  glGetIntegerv(GL_TEXTURE_BINDING_2D, &binding);
  g_assert_cmpuint(binding, ==, sentinel);
  g_assert_cmpint(glGetError(), ==, GL_NO_ERROR);
  cairo_surface_flush(surface);
  auto* bytes = cairo_image_surface_get_data(surface);
  for (int i = 0; i < cairo_image_surface_get_stride(surface) * 64; ++i) {
    g_assert_cmpuint(bytes[i], ==, 0);
  }
  glDeleteTextures(1, &sentinel);
  cairo_destroy(cr);
  cairo_surface_destroy(surface);
  gdk_gl_context_clear_current();
  observed_context = nullptr;
}

int main(int argc, char** argv) {
  gtk_init(&argc, &argv);
  g_log_set_always_fatal(static_cast<GLogLevelFlags>(
      G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING));
  g_autoptr(FlEngine) engine = FL_ENGINE(g_object_new(fl_engine_get_type(), nullptr));
  engine->manager = fl_opengl_manager_new();
  engine->runner = fl_task_runner_new(engine);
  g_assert_true(fl_opengl_manager_make_current(engine->manager));
  // Resolve libepoxy's lazy dispatch before installing transparent observers.
  GLuint warm;
  glGenTextures(1, &warm);
  glBindTexture(GL_TEXTURE_2D, warm);
  unsigned char pixel[] = {0, 0, 0, 255};
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
  glDeleteTextures(1, &warm);
  real_image = epoxy_glTexImage2D;
  real_subimage = epoxy_glTexSubImage2D;
  epoxy_glTexImage2D = image;
  epoxy_glTexSubImage2D = subimage;
  g_assert_true(fl_opengl_manager_clear_current(engine->manager));

  auto* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  auto* renderer = fl_view_renderer_new(engine, TRUE);
  g_object_ref_sink(renderer);
  gtk_widget_set_size_request(GTK_WIDGET(renderer), 96, 64);
  gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(renderer));
  gtk_widget_show_all(window);
  g_assert_true(gtk_widget_get_realized(GTK_WIDGET(renderer)));
  g_assert_nonnull(renderer->compositor);
  g_assert_nonnull(renderer->render_context);
  for (int i = 0; i < 120; ++i) {
    publish(renderer, 96, 64, i % 2 == 0);
    draw(renderer, 96, 64, i % 2 == 0);
  }
#ifdef LEGACY_BASELINE
  g_assert_cmpuint(allocations, ==, 120);
  g_assert_cmpuint(updates, ==, 0);
  g_assert_cmpuint(binding_failures, >, 0);
  std::puts("ENGINE_COMPOSITOR_NATIVE=baseline frames=120 allocations=120 updates=0 pixels=pass");
#else
  g_assert_cmpuint(allocations, ==, 1);
  g_assert_cmpuint(updates, ==, 119);
  GLuint original_texture = uploaded_texture;
  // Same backing dimensions as the window are not required during a resize.
  publish(renderer, 128, 80, false);
  draw(renderer, 96, 64, false);
  g_assert_cmpuint(allocations, ==, 2);
  g_assert_cmpuint(uploaded_texture, ==, original_texture);
  publish(renderer, 96, 64, true);
  draw(renderer, 96, 64, true);
  g_assert_cmpuint(allocations, ==, 3);
  g_autoptr(GdkGLContext) old_context =
      GDK_GL_CONTEXT(g_object_ref(renderer->render_context));
  auto* original_compositor = renderer->compositor;
  gtk_widget_hide(GTK_WIDGET(renderer));
  gtk_widget_unrealize(GTK_WIDGET(renderer));
  g_assert_null(renderer->render_context);
  g_assert_true(renderer->compositor == original_compositor);
  gdk_gl_context_make_current(old_context);
  g_assert_false(glIsTexture(original_texture));
  g_assert_cmpint(glGetError(), ==, GL_NO_ERROR);
  gdk_gl_context_clear_current();
  // Raster work may finish after unrealize; it must not acquire a GTK texture.
  publish(renderer, 96, 64, false);
  gtk_widget_show(GTK_WIDGET(renderer));
  gtk_widget_realize(GTK_WIDGET(renderer));
  g_assert_nonnull(renderer->render_context);
  g_assert_true(renderer->render_context != old_context);
  g_assert_true(renderer->compositor == original_compositor);
  draw(renderer, 96, 64, false);
  g_assert_cmpuint(allocations, ==, 4);

  // A rejected in-place update must not draw stale pixels. Its next ordinary
  // frame redefines storage and succeeds without window/context replacement.
  rejected_frame(renderer);
  draw(renderer, 96, 64, false);
  g_assert_cmpuint(allocations, ==, 5);
  // Repeat for a rejected resize allocation, then retry that same new size.
  publish(renderer, 128, 80, true);
  rejected_frame(renderer);
  draw(renderer, 96, 64, true);
  g_assert_cmpuint(allocations, ==, 7);
  g_assert_cmpuint(upload_warnings, ==, 2);

  // Execute a genuine pending platform task during the frame-size wait. Its
  // widget retirement must abort the old draw before it can recreate a texture.
  publish(renderer, 32, 24, true);
  g_autoptr(GdkGLContext) final_context =
      GDK_GL_CONTEXT(g_object_ref(renderer->render_context));
  GLuint final_texture = uploaded_texture;
  platform_task = [&]() { gtk_widget_destroy(GTK_WIDGET(renderer)); };
  FlutterTask task = {};
  fl_task_runner_post_flutter_task(engine->runner, task, 0);
  gdk_gl_context_make_current(final_context);
  auto* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 96, 64);
  auto* cr = cairo_create(surface);
  g_assert_false(fl_compositor_render(renderer->compositor, cr,
      gtk_widget_get_window(GTK_WIDGET(renderer)), TRUE));
  g_assert_false(static_cast<bool>(platform_task));
  g_assert_null(renderer->render_context);
  g_assert_cmpuint(allocations, ==, 7);
  gdk_gl_context_make_current(final_context);
  g_assert_false(glIsTexture(final_texture));
  g_assert_cmpint(glGetError(), ==, GL_NO_ERROR);
  gdk_gl_context_clear_current();
  cairo_destroy(cr);
  cairo_surface_destroy(surface);
  g_object_run_dispose(G_OBJECT(renderer));
  std::puts("ENGINE_COMPOSITOR_NATIVE=pass frames=120 allocations=1 updates=119 pixels=pass resize=pass unrealize=retired rerealize=fresh reentrant=aborted dispose=idempotent upload_refusal=2 retry=pass");
#endif
  gtk_widget_destroy(window);
  g_object_unref(renderer);
  epoxy_glTexImage2D = real_image;
  epoxy_glTexSubImage2D = real_subimage;
  g_assert_false(static_cast<bool>(platform_task));
  return 0;
}

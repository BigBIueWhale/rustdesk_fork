// Production create/delete function bodies, real GTK/X11, controlled Flutter values.
#include <gtk/gtk.h>
#include <X11/extensions/Xfixes.h>
#include <gdk/gdkx.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

// Only the method-codec values are doubled. Image loading, cursor creation,
// presentation, deletion, reference counting and weak notifications are native.
struct FlValue {
  string text;
  double number = 0;
  vector<uint8_t> bytes;
  unordered_map<string, FlValue> fields;
};
static FlValue* fl_value_lookup_string(FlValue* value, const char* key) {
  return &value->fields.at(key);
}
static const char* fl_value_get_string(FlValue* value) { return value->text.c_str(); }
static double fl_value_get_float(FlValue* value) { return value->number; }
static const uint8_t* fl_value_get_uint8_list(FlValue* value) { return value->bytes.data(); }
static size_t fl_value_get_length(FlValue* value) { return value->bytes.size(); }
struct FlutterCustomCursorPlugin {
  unique_ptr<unordered_map<string, GdkCursor*>> cache =
      make_unique<unordered_map<string, GdkCursor*>>();
};

struct ImageObservation { GdkPixbuf* image; bool finalized = false; };
static vector<unique_ptr<ImageObservation>> observations;
static GdkPixbuf* observed_copy(const GdkPixbuf* source) {
  GdkPixbuf* image = gdk_pixbuf_copy(source);
  g_assert_nonnull(image);
  auto item = make_unique<ImageObservation>();
  item->image = image;
  g_object_weak_ref(G_OBJECT(image), [](gpointer data, GObject*) {
    static_cast<ImageObservation*>(data)->finalized = true;
  }, item.get());
  observations.push_back(std::move(item));
  return image;
}

#define gdk_pixbuf_copy observed_copy
#include "cursor-plugin-functions.inc"
#undef gdk_pixbuf_copy

static bool cursor_matches(GdkDisplay* display, unsigned int width,
                           unsigned int height, unsigned int color) {
  auto* xdisplay = gdk_x11_display_get_xdisplay(display);
  XSync(xdisplay, False);
  XFixesCursorImage* cursor = XFixesGetCursorImage(xdisplay);
  if (cursor == nullptr) return false;
  bool matches = cursor->width == width && cursor->height == height &&
                 cursor->xhot == 3 && cursor->yhot == 5;
  for (unsigned int i = 0; matches && i < width * height; ++i)
    matches = static_cast<uint32_t>(cursor->pixels[i]) == color;
  if (!matches) {
    static bool reported = false;
    if (!reported) {
      printf("CURSOR_IMAGE_MISMATCH width=%u height=%u hotx=%u hoty=%u x=%d y=%d "
             "first_pixel=%08lx expected_pixel=%08x\n", cursor->width, cursor->height,
             cursor->xhot, cursor->yhot, cursor->x, cursor->y,
             cursor->width && cursor->height ? cursor->pixels[0] : 0UL, color);
      reported = true;
    }
  }
  XFree(cursor);
  return matches;
}

static void dispatch_ready_events(GdkDisplay* display) {
  gdk_display_sync(display);
  unsigned int dispatched = 0;
  while (g_main_context_pending(nullptr)) {
    g_assert_cmpuint(++dispatched, <=, 256);
    g_main_context_iteration(nullptr, FALSE);
  }
}

int main() {
  g_assert_true(gtk_init_check(nullptr, nullptr));
  GdkDisplay* display = gdk_display_get_default();
  g_assert_true(GDK_IS_X11_DISPLAY(display));
  auto* xdisplay = gdk_x11_display_get_xdisplay(display);
  int major = 5, minor = 0;
  g_assert_true(XFixesQueryVersion(xdisplay, &major, &minor));
  g_assert_cmpint(major, >=, 1);
  g_assert_true(gdk_display_supports_cursor_alpha(display));
  g_assert_true(gdk_display_supports_cursor_color(display));

  // Observer controls: retain a real object, then observe its exact finalization.
  g_autoptr(GdkPixbuf) input = gdk_pixbuf_new(GDK_COLORSPACE_RGB, TRUE, 8, 32, 24);
  g_assert_nonnull(input);
  GdkPixbuf* control = observed_copy(input);
  g_assert_false(observations.back()->finalized);
  g_object_unref(control);
  g_assert_true(observations.back()->finalized);
  observations.clear();
  puts("CURSOR_IMAGE_OBSERVER=pass retained=observed finalization=observed");

  GtkWidget* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_default_size(GTK_WINDOW(window), 200, 160);
  gtk_widget_show_all(window);
  dispatch_ready_events(display);
  g_assert_true(gtk_widget_get_mapped(window));
  GdkWindow* surface = gtk_widget_get_window(window);
  g_assert_nonnull(surface);
  GdkSeat* seat = gdk_display_get_default_seat(display);
  GdkDevice* pointer = gdk_seat_get_pointer(seat);
  int root_x = 0, root_y = 0;
  gdk_window_get_origin(surface, &root_x, &root_y);
  gdk_device_warp(pointer, gdk_window_get_screen(surface), root_x + 50, root_y + 50);
  dispatch_ready_events(display);
  g_assert_true(gdk_device_get_window_at_position(pointer, nullptr, nullptr) == surface);

  FlutterCustomCursorPlugin plugin;
  unsigned int released = 0, visible = 0;
  constexpr unsigned int kRegistrations = 128;
  for (unsigned int i = 0; i < kRegistrations; ++i) {
    // Repeated valid shapes traverse real PNG decoding and the native cursor API.
    const unsigned int argb = (i & 1) ? 0xff38b062U : 0xffc04d29U;
    gdk_pixbuf_fill(input, ((argb & 0x00ffffffU) << 8) | 0xffU);
    gchar* png = nullptr;
    gsize size = 0;
    g_autoptr(GError) error = nullptr;
    g_assert_true(gdk_pixbuf_save_to_buffer(input, &png, &size, "png", &error, nullptr));
    g_assert_no_error(error);
    g_assert_cmpuint(size, >, 0);
    FlValue args;
    args.fields["name"].text = "cursor-" + to_string(i);
    args.fields["hotX"].number = 3;
    args.fields["hotY"].number = 5;
    args.fields["buffer"].bytes.assign(png, png + size);
    g_free(png);
    g_assert_true(create_custom_cursor(&plugin, &args) == args.fields["name"].text);
    g_assert_cmpuint(plugin.cache->size(), ==, 1);
    GdkCursor* cursor = plugin.cache->at(args.fields["name"].text);
    gdk_window_set_cursor(surface, cursor);
    if (cursor_matches(display, 32, 24, argb)) ++visible;
    gdk_window_set_cursor(surface, nullptr);
    gdk_display_sync(display);
    g_assert_true(delete_custom_cursor(&plugin, &args));
    g_assert_true(plugin.cache->empty());
    g_assert_cmpuint(observations.size(), ==, i + 1);
    if (observations.back()->finalized) ++released;
  }
  printf("CURSOR_IMAGE_RESULT registrations=%u native_shapes=%u cache_entries=%zu "
         "copies=%zu finalized=%u retained=%zu\n", kRegistrations, visible,
         plugin.cache->size(), observations.size(), released, observations.size() - released);

  // Clean a failing baseline only after measuring the actual unretired references.
  for (const auto& item : observations)
    if (!item->finalized) g_object_unref(item->image);
  for (const auto& item : observations) g_assert_true(item->finalized);
  gtk_widget_destroy(window);
  gdk_display_sync(display);
  puts("CURSOR_IMAGE_CLEANUP=pass images=finalized window=destroyed");
  return released == kRegistrations && visible == kRegistrations ? 0 : 1;
}

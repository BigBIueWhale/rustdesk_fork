// Exact Flutter settings implementations over a private native D-Bus transport.
// The portal service and GNOME schema are fixtures; no Flutter engine or UI runs.
#include "flutter/shell/platform/linux/fl_settings.h"

#include <gio/gio.h>
#include <pwd.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <future>
#include <thread>

static constexpr char kName[] = "org.freedesktop.portal.Desktop";
static constexpr char kPath[] = "/org/freedesktop/portal/desktop";
static constexpr char kInterface[] = "org.freedesktop.portal.Settings";
static constexpr char kAppearance[] = "org.freedesktop.appearance";
static constexpr char kGnome[] = "org.gnome.desktop.interface";

enum class PortalMode { MissingInterface, Empty, Color, Gtk };

class Portal {
 public:
  explicit Portal(PortalMode mode) : mode_(mode) {
    context_ = g_main_context_new();
    loop_ = g_main_loop_new(context_, FALSE);
    auto ready = ready_.get_future();
    worker_ = std::thread([this] { serve(); });
    g_assert_true(ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    g_assert_true(ready.get());
  }

  ~Portal() {
    g_main_context_invoke(context_, [](gpointer data) -> gboolean {
      g_main_loop_quit(static_cast<GMainLoop*>(data));
      return G_SOURCE_REMOVE;
    }, loop_);
    worker_.join();
    g_main_loop_unref(loop_);
    g_main_context_unref(context_);
  }

  void emit(const char* ns, const char* key, GVariant* value) {
    g_autoptr(GError) error = nullptr;
    g_assert_true(g_dbus_connection_emit_signal(connection_, nullptr, kPath, kInterface,
        "SettingChanged", g_variant_new("(ssv)", ns, key, value), &error));
    g_assert_no_error(error);
    g_assert_true(g_dbus_connection_flush_sync(connection_, nullptr, &error));
    g_assert_no_error(error);
  }

  unsigned int reads() const { return reads_.load(); }

 private:
  static void method(GDBusConnection*, const gchar*, const gchar*, const gchar*,
                     const gchar* name, GVariant* parameters,
                     GDBusMethodInvocation* invocation, gpointer data) {
    auto* self = static_cast<Portal*>(data);
    g_assert_cmpstr(name, ==, "Read");
    const gchar *ns, *key;
    g_variant_get(parameters, "(&s&s)", &ns, &key);
    ++self->reads_;
    GVariant* value = nullptr;
    if (self->mode_ == PortalMode::Color && g_str_equal(ns, kAppearance) &&
        g_str_equal(key, "color-scheme")) value = g_variant_new_uint32(1);
    if (self->mode_ == PortalMode::Gtk && g_str_equal(ns, kGnome) &&
        g_str_equal(key, "gtk-theme")) value = g_variant_new_string("Adwaita-dark");
    if (value != nullptr) {
      // The deprecated Read protocol wraps the value twice; ReadOne does not.
      g_dbus_method_invocation_return_value(invocation,
          g_variant_new("(v)", g_variant_new_variant(value)));
    } else {
      g_dbus_method_invocation_return_dbus_error(invocation,
          "org.freedesktop.portal.Error.NotFound", "No such setting");
    }
  }

  void serve() {
    g_main_context_push_thread_default(context_);
    g_autoptr(GError) error = nullptr;
    connection_ = g_dbus_connection_new_for_address_sync(g_getenv("DBUS_SESSION_BUS_ADDRESS"),
        static_cast<GDBusConnectionFlags>(G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                                         G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION),
        nullptr, nullptr, &error);
    g_assert_no_error(error);
    g_assert_nonnull(connection_);
    g_autoptr(GDBusNodeInfo) info = g_dbus_node_info_new_for_xml(
        "<node><interface name='org.freedesktop.portal.Settings'>"
        "<method name='Read'><arg type='s' direction='in'/><arg type='s' direction='in'/>"
        "<arg type='v' direction='out'/></method><signal name='SettingChanged'>"
        "<arg type='s'/><arg type='s'/><arg type='v'/></signal></interface></node>", &error);
    g_assert_no_error(error);
    static const GDBusInterfaceVTable vtable = {method, nullptr, nullptr, {nullptr}};
    guint registration = 0;
    if (mode_ != PortalMode::MissingInterface) {
      registration = g_dbus_connection_register_object(connection_, kPath, info->interfaces[0],
                                                       &vtable, this, nullptr, &error);
      g_assert_no_error(error);
      g_assert_cmpuint(registration, !=, 0);
    }
    g_autoptr(GVariant) acquired = g_dbus_connection_call_sync(connection_,
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
        g_variant_new("(su)", kName, 4U), G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE, 2000, nullptr, &error);
    g_assert_no_error(error);
    g_assert_nonnull(acquired);
    guint ownership;
    g_variant_get(acquired, "(u)", &ownership);
    g_assert_cmpuint(ownership, ==, 1);
    ready_.set_value(true);
    g_main_loop_run(loop_);
    if (registration != 0)
      g_assert_true(g_dbus_connection_unregister_object(connection_, registration));
    g_assert_true(g_dbus_connection_close_sync(connection_, nullptr, &error));
    g_assert_no_error(error);
    g_clear_object(&connection_);
    g_main_context_pop_thread_default(context_);
  }

  PortalMode mode_;
  GMainContext* context_ = nullptr;
  GMainLoop* loop_ = nullptr;
  GDBusConnection* connection_ = nullptr;
  std::promise<bool> ready_;
  std::thread worker_;
  std::atomic<unsigned int> reads_{0};
};

static void changed(FlSettings*, gpointer data) { ++*static_cast<unsigned int*>(data); }

static void await_scheme(FlSettings* settings, FlColorScheme expected,
                         unsigned int* changes, unsigned int previous) {
  gint64 deadline = g_get_monotonic_time() + 2000000;
  while (g_get_monotonic_time() < deadline) {
    for (unsigned int i = 0; i < 64 && g_main_context_iteration(nullptr, FALSE); ++i) {}
    if (*changes > previous && fl_settings_get_color_scheme(settings) == expected) return;
    g_usleep(1000);
  }
  g_error("settings notification did not publish the expected scheme");
}

static void unavailable(const char* name) {
  g_autoptr(GSettings) native = g_settings_new(kGnome);
  g_assert_true(g_settings_set_string(native, "gtk-theme", "Adwaita-dark"));
  g_autoptr(FlSettings) settings = fl_settings_new();
#ifdef LEGACY_BASELINE
  g_assert_cmpstr(G_OBJECT_TYPE_NAME(settings), ==, "FlSettingsPortal");
  g_assert_cmpint(fl_settings_get_color_scheme(settings), ==, FL_COLOR_SCHEME_LIGHT);
  std::printf("ENGINE_SETTINGS_CASE name=%s outcome=wrong-portal light-instead-of-dark=true\n", name);
#else
  g_assert_cmpstr(G_OBJECT_TYPE_NAME(settings), ==, "FlGnomeSettings");
  g_assert_cmpint(fl_settings_get_color_scheme(settings), ==, FL_COLOR_SCHEME_DARK);
  unsigned int changes = 0;
  g_signal_connect(settings, "changed", G_CALLBACK(changed), &changes);
  g_assert_true(g_settings_set_string(native, "gtk-theme", "Adwaita"));
  await_scheme(settings, FL_COLOR_SCHEME_LIGHT, &changes, 0);
  unsigned int previous = changes;
  g_assert_true(g_settings_set_string(native, "gtk-theme", "Adwaita-dark"));
  await_scheme(settings, FL_COLOR_SCHEME_DARK, &changes, previous);
  std::printf("ENGINE_SETTINGS_CASE name=%s outcome=gnome live-transitions=2\n", name);
#endif
}

static void available(PortalMode mode) {
  Portal portal(mode);
  g_autoptr(FlSettings) settings = fl_settings_new();
  g_assert_cmpstr(G_OBJECT_TYPE_NAME(settings), ==, "FlSettingsPortal");
  g_assert_cmpuint(portal.reads(), ==, 6);
  g_assert_cmpint(fl_settings_get_color_scheme(settings), ==, FL_COLOR_SCHEME_DARK);
  unsigned int changes = 0;
  g_signal_connect(settings, "changed", G_CALLBACK(changed), &changes);
  const char* ns = mode == PortalMode::Color ? kAppearance : kGnome;
  const char* key = mode == PortalMode::Color ? "color-scheme" : "gtk-theme";
  portal.emit(ns, key, mode == PortalMode::Color
      ? g_variant_new_uint32(2) : g_variant_new_string("Adwaita"));
  await_scheme(settings, FL_COLOR_SCHEME_LIGHT, &changes, 0);
  unsigned int previous = changes;
  portal.emit(ns, key, mode == PortalMode::Color
      ? g_variant_new_uint32(1) : g_variant_new_string("Adwaita-dark"));
  await_scheme(settings, FL_COLOR_SCHEME_DARK, &changes, previous);
  if (mode == PortalMode::Color) {
    previous = changes;
    portal.emit(ns, key, g_variant_new_uint32(0));
    await_scheme(settings, FL_COLOR_SCHEME_LIGHT, &changes, previous);
  }
  std::printf("ENGINE_SETTINGS_CASE name=%s outcome=portal optional-keys=absent live-transitions=%u\n",
              mode == PortalMode::Color ? "color-only" : "gtk-only", changes);
}

int main(int argc, char** argv) {
  g_test_init(&argc, &argv, nullptr);
  // The private bus authenticates the real numeric principal through NSS.
  const struct passwd* principal = getpwuid(getuid());
  g_assert_nonnull(principal);
  g_assert_cmpuint(principal->pw_uid, ==, getuid());
  // Existing portal code logs unavailable optional keys at critical level.
  g_log_set_always_fatal(G_LOG_LEVEL_ERROR);
  g_autoptr(GTestDBus) bus = g_test_dbus_new(G_TEST_DBUS_NONE);
  g_test_dbus_up(bus);
  unavailable("absent-service");
  { Portal portal(PortalMode::MissingInterface); unavailable("absent-interface"); }
  { Portal portal(PortalMode::Empty); unavailable("empty-settings"); }
  available(PortalMode::Color);
  available(PortalMode::Gtk);
  g_test_dbus_down(bus);
#ifdef LEGACY_BASELINE
  std::puts("ENGINE_SETTINGS_NATIVE=baseline unavailable_wrong=3 portal_controls=2 bus=joined");
#else
  std::puts("ENGINE_SETTINGS_NATIVE=pass unavailable=3 portal_controls=2 gnome_transitions=6 bus=joined");
#endif
}

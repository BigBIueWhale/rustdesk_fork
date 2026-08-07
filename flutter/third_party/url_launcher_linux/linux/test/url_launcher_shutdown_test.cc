#include <flutter_linux/flutter_linux.h>

#include <iostream>

#include "../url_launcher_plugin_private.h"

namespace {

struct HandlerRecord {
  gpointer user_data;
  GDestroyNotify destroy_notify;
};

static void handler_record_free(gpointer data) {
  auto* record = static_cast<HandlerRecord*>(data);
  if (record->destroy_notify != nullptr) {
    record->destroy_notify(record->user_data);
  }
  delete record;
}

struct TestMessenger {
  GObject parent_instance;
  GHashTable* handlers;
  gboolean shutting_down;
  guint handler_sets_during_shutdown;
};

struct TestMessengerClass {
  GObjectClass parent_class;
};

static void test_messenger_interface_init(FlBinaryMessengerInterface* interface);

G_DEFINE_TYPE_WITH_CODE(
    TestMessenger, test_messenger, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(fl_binary_messenger_get_type(),
                          test_messenger_interface_init))

static void test_set_message_handler(FlBinaryMessenger* messenger,
                                     const gchar* channel,
                                     FlBinaryMessengerMessageHandler handler,
                                     gpointer user_data,
                                     GDestroyNotify destroy_notify) {
  auto* self = reinterpret_cast<TestMessenger*>(messenger);
  if (self->shutting_down) {
    ++self->handler_sets_during_shutdown;
    if (destroy_notify != nullptr) {
      destroy_notify(user_data);
    }
    return;
  }
  if (handler == nullptr) {
    g_hash_table_remove(self->handlers, channel);
    return;
  }
  g_hash_table_replace(
      self->handlers, g_strdup(channel),
      new HandlerRecord{user_data, destroy_notify});
}

static void test_messenger_shutdown(FlBinaryMessenger* messenger) {
  auto* self = reinterpret_cast<TestMessenger*>(messenger);
  self->shutting_down = TRUE;
  g_hash_table_remove_all(self->handlers);
}

static void test_messenger_interface_init(
    FlBinaryMessengerInterface* interface) {
  interface->set_message_handler_on_channel = test_set_message_handler;
  interface->shutdown = test_messenger_shutdown;
}

static void test_messenger_dispose(GObject* object) {
  auto* self = reinterpret_cast<TestMessenger*>(object);
  g_clear_pointer(&self->handlers, g_hash_table_unref);
  G_OBJECT_CLASS(test_messenger_parent_class)->dispose(object);
}

static void test_messenger_class_init(TestMessengerClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = test_messenger_dispose;
}

static void test_messenger_init(TestMessenger* self) {
  self->handlers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                         handler_record_free);
  self->shutting_down = FALSE;
  self->handler_sets_during_shutdown = 0;
}

struct TestRegistrar {
  GObject parent_instance;
  FlBinaryMessenger* messenger;
};

struct TestRegistrarClass {
  GObjectClass parent_class;
};

static void test_registrar_interface_init(FlPluginRegistrarInterface* interface);

G_DEFINE_TYPE_WITH_CODE(
    TestRegistrar, test_registrar, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(fl_plugin_registrar_get_type(),
                          test_registrar_interface_init))

static FlBinaryMessenger* test_registrar_get_messenger(
    FlPluginRegistrar* registrar) {
  return reinterpret_cast<TestRegistrar*>(registrar)->messenger;
}

static FlTextureRegistrar* test_registrar_get_texture_registrar(
    FlPluginRegistrar*) {
  return nullptr;
}

static FlView* test_registrar_get_view(FlPluginRegistrar*) {
  return nullptr;
}

static void test_registrar_interface_init(
    FlPluginRegistrarInterface* interface) {
  interface->get_messenger = test_registrar_get_messenger;
  interface->get_texture_registrar = test_registrar_get_texture_registrar;
  interface->get_view = test_registrar_get_view;
}

static void test_registrar_dispose(GObject* object) {
  auto* self = reinterpret_cast<TestRegistrar*>(object);
  g_clear_object(&self->messenger);
  G_OBJECT_CLASS(test_registrar_parent_class)->dispose(object);
}

static void test_registrar_class_init(TestRegistrarClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = test_registrar_dispose;
}

static void test_registrar_init(TestRegistrar*) {}

bool check(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
  }
  return condition;
}

}  // namespace

int main() {
  auto* messenger = reinterpret_cast<TestMessenger*>(
      g_object_new(test_messenger_get_type(), nullptr));
  auto* registrar = reinterpret_cast<TestRegistrar*>(
      g_object_new(test_registrar_get_type(), nullptr));
  registrar->messenger = FL_BINARY_MESSENGER(g_object_ref(messenger));

  FlUrlLauncherPlugin* plugin =
      fl_url_launcher_plugin_new(FL_PLUGIN_REGISTRAR(registrar));
  gpointer weak_plugin = plugin;
  g_object_add_weak_pointer(G_OBJECT(plugin), &weak_plugin);
  g_object_unref(plugin);

  bool passed = true;
  passed &= check(g_hash_table_size(messenger->handlers) == 2,
                  "URL handlers were not registered exactly once");
  passed &= check(weak_plugin != nullptr,
                  "handler ownership did not retain the plugin");

  FL_BINARY_MESSENGER_GET_IFACE(messenger)->shutdown(
      FL_BINARY_MESSENGER(messenger));

  passed &= check(g_hash_table_size(messenger->handlers) == 0,
                  "messenger shutdown retained URL handlers");
  passed &= check(messenger->handler_sets_during_shutdown == 2,
                  "shutdown did not perform exactly one terminal reset per URL channel");
  passed &= check(weak_plugin == nullptr,
                  "messenger shutdown did not release the plugin");

  g_object_unref(registrar);
  g_object_unref(messenger);
  if (!passed) {
    return 1;
  }
  std::cout << "url_launcher_shutdown_test: PASS\n";
  return 0;
}

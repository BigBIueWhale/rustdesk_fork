#include <flutter_linux/flutter_linux.h>

#include <cstring>
#include <iostream>

#include "../window_manager_plugin_private.h"

namespace {

struct HandlerRecord {
  FlBinaryMessengerMessageHandler handler;
  gpointer user_data;
  GDestroyNotify destroy_notify;
};

static void handler_record_free(HandlerRecord* record) {
  if (record == nullptr) {
    return;
  }
  if (record->destroy_notify != nullptr) {
    record->destroy_notify(record->user_data);
  }
  delete record;
}

struct TestMessenger {
  GObject parent_instance;
  HandlerRecord* handler;
  GBytes* response;
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
                                     const gchar*,
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
  HandlerRecord* previous = self->handler;
  self->handler = nullptr;
  handler_record_free(previous);
  if (handler != nullptr) {
    self->handler = new HandlerRecord{handler, user_data, destroy_notify};
  }
}

static gboolean test_send_response(
    FlBinaryMessenger* messenger,
    FlBinaryMessengerResponseHandle*,
    GBytes* response,
    GError**) {
  auto* self = reinterpret_cast<TestMessenger*>(messenger);
  g_clear_pointer(&self->response, g_bytes_unref);
  self->response = response == nullptr ? nullptr : g_bytes_ref(response);
  return TRUE;
}

static void test_messenger_shutdown(FlBinaryMessenger* messenger) {
  auto* self = reinterpret_cast<TestMessenger*>(messenger);
  self->shutting_down = TRUE;
  HandlerRecord* record = self->handler;
  self->handler = nullptr;
  handler_record_free(record);
}

static void test_messenger_interface_init(
    FlBinaryMessengerInterface* interface) {
  interface->set_message_handler_on_channel = test_set_message_handler;
  interface->send_response = test_send_response;
  interface->shutdown = test_messenger_shutdown;
}

static void test_messenger_dispose(GObject* object) {
  auto* self = reinterpret_cast<TestMessenger*>(object);
  HandlerRecord* record = self->handler;
  self->handler = nullptr;
  handler_record_free(record);
  g_clear_pointer(&self->response, g_bytes_unref);
  G_OBJECT_CLASS(test_messenger_parent_class)->dispose(object);
}

static void test_messenger_class_init(TestMessengerClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = test_messenger_dispose;
}

static void test_messenger_init(TestMessenger* self) {
  self->handler = nullptr;
  self->response = nullptr;
  self->shutting_down = FALSE;
  self->handler_sets_during_shutdown = 0;
}

struct TestResponseHandle {
  FlBinaryMessengerResponseHandle parent_instance;
};

struct TestResponseHandleClass {
  FlBinaryMessengerResponseHandleClass parent_class;
};

G_DEFINE_TYPE(TestResponseHandle,
              test_response_handle,
              fl_binary_messenger_response_handle_get_type())

static void test_response_handle_class_init(TestResponseHandleClass*) {}
static void test_response_handle_init(TestResponseHandle*) {}

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

  gpointer weak_plugin =
      window_manager_plugin_register_with_registrar_for_window(
          FL_PLUGIN_REGISTRAR(registrar), nullptr);

  bool passed = true;
  passed &= check(messenger->handler != nullptr,
                  "window-manager handler was not registered");
  passed &= check(weak_plugin != nullptr,
                  "window-manager plugin was not registered");
  if (weak_plugin != nullptr) {
    g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);
  }

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(GError) error = nullptr;
  g_autoptr(GBytes) request =
      FL_METHOD_CODEC_GET_CLASS(codec)->encode_method_call(
          FL_METHOD_CODEC(codec), "isMaximized", nullptr, &error);
  passed &= check(request != nullptr && error == nullptr,
                  "test method call did not encode");

  auto* response_handle = reinterpret_cast<TestResponseHandle*>(
      g_object_new(test_response_handle_get_type(), nullptr));
  if (messenger->handler != nullptr && request != nullptr) {
    messenger->handler->handler(
        FL_BINARY_MESSENGER(messenger), "window_manager", request,
        FL_BINARY_MESSENGER_RESPONSE_HANDLE(response_handle),
        messenger->handler->user_data);
  }

  passed &= check(messenger->response != nullptr,
                  "destroyed-window call did not receive a response");
  g_autoptr(FlMethodResponse) response = nullptr;
  if (messenger->response != nullptr) {
    response = FL_METHOD_CODEC_GET_CLASS(codec)->decode_response(
        FL_METHOD_CODEC(codec), messenger->response, &error);
  }
  passed &= check(response != nullptr && error == nullptr,
                  "destroyed-window response did not decode");
  passed &= check(response != nullptr && FL_IS_METHOD_ERROR_RESPONSE(response),
                  "destroyed-window call was not rejected");
  if (response != nullptr && FL_IS_METHOD_ERROR_RESPONSE(response)) {
    const gchar* code = fl_method_error_response_get_code(
        FL_METHOD_ERROR_RESPONSE(response));
    passed &= check(g_strcmp0(code, "window_unavailable") == 0,
                    "destroyed-window call used the wrong error code");
  }

  FL_BINARY_MESSENGER_GET_IFACE(messenger)->shutdown(
      FL_BINARY_MESSENGER(messenger));
  passed &= check(messenger->handler == nullptr,
                  "messenger shutdown retained the handler");
  if (messenger->handler_sets_during_shutdown != 0) {
    std::cerr << "observed terminal handler resets: "
              << messenger->handler_sets_during_shutdown << '\n';
  }
  passed &= check(messenger->handler_sets_during_shutdown == 0,
                  "plugin recursively mutated handlers during shutdown");
  passed &= check(weak_plugin == nullptr,
                  "messenger shutdown did not release the plugin");

  g_object_unref(response_handle);
  g_object_unref(registrar);
  g_object_unref(messenger);
  if (!passed) {
    return 1;
  }
  std::cout << "window_manager_shutdown_test: PASS\n";
  return 0;
}

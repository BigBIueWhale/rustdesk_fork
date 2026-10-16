// Executes the production channel and pinned Flutter codec/GObject implementation.
// The binary messenger supplies controlled transport completions; no engine/window runs.
#include "window_channel.h"

#include <cstring>
#include <iostream>
#include <string>

namespace {
constexpr char kChannel[] = "window-channel-test";
constexpr char kPassword[] = "SyntheticWindowPassword1";
constexpr char kToken[] = "SyntheticWindowToken2";
std::string logs;
int created = 0;
int retired = 0;
int failures = 0;

void Check(bool condition, const char* description) {
  if (!condition) {
    ++failures;
    std::cout << "WINDOW_CHANNEL_ASSERT=failed check=" << description << '\n';
  }
}

void Retired(gpointer data, GObject*) {
  *static_cast<bool*>(data) = true;
}

void Drain() {
  while (g_main_context_iteration(nullptr, false)) {}
}

struct MessengerState {
  FlBinaryMessengerMessageHandler handler = nullptr;
  gpointer handler_data = nullptr;
  GDestroyNotify destroy = nullptr;
  GBytes* reply = nullptr;
  GBytes* received = nullptr;
  bool transport_error = false;
  bool refuse_response = false;
  int expected_sender = 42;
  int sends = 0;
  int responses = 0;
};

typedef struct { GObject parent; MessengerState* state; } TestMessenger;
typedef struct { GObjectClass parent; } TestMessengerClass;
void MessengerInterface(FlBinaryMessengerInterface* iface);
G_DEFINE_TYPE_WITH_CODE(TestMessenger, test_messenger, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(FL_TYPE_BINARY_MESSENGER, MessengerInterface))

void SetHandler(FlBinaryMessenger* messenger, const gchar*,
                FlBinaryMessengerMessageHandler handler, gpointer data,
                GDestroyNotify destroy) {
  auto* state = reinterpret_cast<TestMessenger*>(messenger)->state;
  if (state->destroy != nullptr) state->destroy(state->handler_data);
  state->handler = handler;
  state->handler_data = data;
  state->destroy = destroy;
}

void test_messenger_finalize(GObject* object) {
  auto* state = reinterpret_cast<TestMessenger*>(object)->state;
  Check(state->destroy == nullptr, "messenger-handler-retired");
  g_clear_pointer(&state->reply, g_bytes_unref);
  g_clear_pointer(&state->received, g_bytes_unref);
  delete state;
  G_OBJECT_CLASS(test_messenger_parent_class)->finalize(object);
}

void test_messenger_class_init(TestMessengerClass* klass) {
  G_OBJECT_CLASS(klass)->finalize = test_messenger_finalize;
}

void test_messenger_init(TestMessenger* messenger) {
  messenger->state = new MessengerState();
}

void MessengerInterface(FlBinaryMessengerInterface* iface) {
  iface->set_message_handler_on_channel = SetHandler;
  iface->send_response = +[](FlBinaryMessenger* messenger,
      FlBinaryMessengerResponseHandle*, GBytes* response, GError** error) {
    auto* state = reinterpret_cast<TestMessenger*>(messenger)->state;
    ++state->responses;
    if (state->refuse_response) {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_CLOSED, "%s/%s", kPassword, kToken);
      return FALSE;
    }
    g_clear_pointer(&state->received, g_bytes_unref);
    state->received = g_bytes_ref(response);
    return TRUE;
  };
  iface->send_on_channel = +[](FlBinaryMessenger* messenger, const gchar*,
      GBytes* message, GCancellable* cancellable, GAsyncReadyCallback callback,
      gpointer data) {
    auto* state = reinterpret_cast<TestMessenger*>(messenger)->state;
    ++state->sends;
    g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
    g_autofree gchar* method = nullptr;
    g_autoptr(FlValue) args = nullptr;
    g_autoptr(GError) error = nullptr;
    Check(fl_method_codec_decode_method_call(FL_METHOD_CODEC(codec), message,
        &method, &args, &error), "outbound-native-codec-decode");
    if (args != nullptr) {
      auto* payload = fl_value_lookup_string(args, "arguments");
      Check(fl_value_get_int(fl_value_lookup_string(args, "fromWindowId")) ==
          state->expected_sender, "exact-sender");
      Check(std::strcmp(fl_value_get_string(fl_value_lookup_string(payload,
          "password")), kPassword) == 0, "exact-password-handoff");
      Check(std::strcmp(fl_value_get_string(fl_value_lookup_string(payload,
          "connToken")), kToken) == 0, "exact-token-handoff");
    }
    g_autoptr(GTask) task = g_task_new(messenger, cancellable, callback, data);
    if (state->transport_error) {
      g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CLOSED,
          "%s/%s", kPassword, kToken);
    } else {
      g_task_return_pointer(task, g_bytes_ref(state->reply),
          reinterpret_cast<GDestroyNotify>(g_bytes_unref));
    }
  };
  iface->send_on_channel_finish = +[](FlBinaryMessenger*, GAsyncResult* result,
                                     GError** error) {
    return static_cast<GBytes*>(g_task_propagate_pointer(G_TASK(result), error));
  };
}

typedef struct { FlBinaryMessengerResponseHandle parent; } TestHandle;
typedef struct { FlBinaryMessengerResponseHandleClass parent; } TestHandleClass;
G_DEFINE_TYPE(TestHandle, test_handle, FL_TYPE_BINARY_MESSENGER_RESPONSE_HANDLE)
void test_handle_class_init(TestHandleClass*) {}
void test_handle_init(TestHandle*) {}

struct ForwardState { WindowChannel* window; bool* retired; };

void Run(const std::string& name, int reply_kind) {
  const int start_failures = failures;
  const int start_live = created - retired;
  logs.clear();
  auto* source = reinterpret_cast<TestMessenger*>(g_object_new(test_messenger_get_type(), nullptr));
  auto* target = reinterpret_cast<TestMessenger*>(g_object_new(test_messenger_get_type(), nullptr));
  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  auto* incoming = fl_method_channel_new(FL_BINARY_MESSENGER(source), kChannel, FL_METHOD_CODEC(codec));
  auto* outgoing = fl_method_channel_new(FL_BINARY_MESSENGER(target), kChannel, FL_METHOD_CODEC(codec));
  auto window = std::make_unique<WindowChannel>(9, outgoing);
  bool call_retired = false, handle_retired = false, source_retired = false, target_retired = false;
  g_object_weak_ref(G_OBJECT(incoming), Retired, &source_retired);
  g_object_weak_ref(G_OBJECT(outgoing), Retired, &target_retired);
  ForwardState forwarding{window.get(), &call_retired};
  fl_method_channel_set_method_call_handler(incoming,
      +[](FlMethodChannel*, FlMethodCall* call, gpointer data) {
        auto* forwarding = static_cast<ForwardState*>(data);
        g_object_weak_ref(G_OBJECT(call), Retired, forwarding->retired);
        forwarding->window->InvokeMethod(42, "new_file_transfer",
            fl_method_call_get_args(call), call);
      }, &forwarding, nullptr);
  g_autoptr(FlValue) payload = fl_value_new_map();
  fl_value_set_string_take(payload, "password", fl_value_new_string(kPassword));
  fl_value_set_string_take(payload, "connToken", fl_value_new_string(kToken));
  g_autoptr(GError) error = nullptr;
  if (reply_kind == 1) {
    target->state->reply = fl_method_codec_encode_error_envelope(
        FL_METHOD_CODEC(codec), "declined", "Request declined", nullptr, &error);
  } else if (reply_kind == 2) {
    target->state->reply = g_bytes_new(nullptr, 0);
  } else if (reply_kind == 3) {
    const guint8 malformed[] = {255};
    target->state->reply = g_bytes_new(malformed, sizeof malformed);
  } else {
    target->state->reply = fl_method_codec_encode_success_envelope(
        FL_METHOD_CODEC(codec), payload, &error);
  }
  const bool self = name == "self-error";
  target->state->transport_error = self || name == "transport-error";
  target->state->expected_sender = self ? 0 : 42;
  source->state->refuse_response = name == "response-refused";
  int completed = 0;
  if (self) {
    window->InvokeMethodSelf("onDestroy", payload, [&completed]() { ++completed; });
  } else {
    auto* handle = FL_BINARY_MESSENGER_RESPONSE_HANDLE(g_object_new(test_handle_get_type(), nullptr));
    g_object_weak_ref(G_OBJECT(handle), Retired, &handle_retired);
    g_autoptr(GBytes) request = fl_method_codec_encode_method_call(
        FL_METHOD_CODEC(codec), "forward", payload, &error);
    source->state->handler(FL_BINARY_MESSENGER(source), kChannel, request,
        handle, source->state->handler_data);
    g_object_unref(handle);
    Check(!call_retired && !handle_retired, "incoming-owned-before-completion");
  }
  window.reset();
  Drain();
  Check(target->state->sends == 1, "one-outbound-send");
  if (self) {
    Check(completed == 1 && source->state->responses == 0, "one-self-completion");
  } else {
    Check(source->state->responses == 1, "one-response-attempt");
    Check(call_retired && handle_retired, "incoming-retired-after-completion");
    if (!source->state->refuse_response) {
      Check(source->state->received != nullptr, "caller-received-reply");
      if (source->state->received != nullptr) {
        g_autoptr(FlMethodResponse) response = fl_method_codec_decode_response(
            FL_METHOD_CODEC(codec), source->state->received, &error);
        Check(response != nullptr, "caller-reply-native-decode");
        if ((reply_kind == 3 || name == "transport-error") && response != nullptr) {
          Check(FL_IS_METHOD_ERROR_RESPONSE(response), "malformed-is-error");
          if (FL_IS_METHOD_ERROR_RESPONSE(response)) {
            auto* failure = FL_METHOD_ERROR_RESPONSE(response);
            Check(std::strcmp(fl_method_error_response_get_code(failure), "window_request_failed") == 0,
                "fixed-error-code");
            Check(std::strcmp(fl_method_error_response_get_message(failure), "Desktop window request failed") == 0,
                "fixed-error-message");
            Check(fl_method_error_response_get_details(failure) == nullptr, "null-error-details");
          }
        } else if (reply_kind == 1 && response != nullptr) {
          Check(FL_IS_METHOD_ERROR_RESPONSE(response) && std::strcmp(
              fl_method_error_response_get_code(FL_METHOD_ERROR_RESPONSE(response)), "declined") == 0,
              "explicit-error-preserved");
        } else if (reply_kind == 2) {
          Check(FL_IS_METHOD_NOT_IMPLEMENTED_RESPONSE(response), "not-implemented-preserved");
        } else if (response != nullptr) {
          Check(FL_IS_METHOD_SUCCESS_RESPONSE(response) && fl_value_equal(
              fl_method_success_response_get_result(FL_METHOD_SUCCESS_RESPONSE(response)), payload),
              "success-payload-preserved");
        }
      }
    }
  }
  Check(created - retired == start_live, "returned-response-retired");
  Check(logs.find(kPassword) == std::string::npos && logs.find(kToken) == std::string::npos,
      "diagnostics-exclude-transport-secrets");
  fl_binary_messenger_set_message_handler_on_channel(FL_BINARY_MESSENGER(source), kChannel, nullptr, nullptr, nullptr);
  fl_binary_messenger_set_message_handler_on_channel(FL_BINARY_MESSENGER(target), kChannel, nullptr, nullptr, nullptr);
  g_object_unref(incoming);
  g_object_unref(outgoing);
  Drain();
  Check(source_retired && target_retired, "channels-retired");
  g_object_unref(source);
  g_object_unref(target);
  std::cout << "WINDOW_CHANNEL_CASE=" << (failures == start_failures ? "pass" : "fail")
            << " case=" << name << '\n';
}
}  // namespace

// Observe actual transfer-full objects without replacing Flutter behavior.
extern "C" FlMethodResponse* __real_fl_method_channel_invoke_method_finish(
    FlMethodChannel*, GAsyncResult*, GError**);
extern "C" FlMethodResponse* __wrap_fl_method_channel_invoke_method_finish(
    FlMethodChannel* channel, GAsyncResult* result, GError** error) {
  auto* response = __real_fl_method_channel_invoke_method_finish(channel, result, error);
  if (response != nullptr) {
    ++created;
    g_object_weak_ref(G_OBJECT(response), +[](gpointer, GObject*) { ++retired; }, nullptr);
  }
  return response;
}

int main() {
  g_log_set_always_fatal(G_LOG_LEVEL_ERROR);
  g_log_set_default_handler(+[](const gchar*, GLogLevelFlags, const gchar* message, gpointer) {
    if (message != nullptr) logs += message;
  }, nullptr);
  Run("success", 0);
  Run("explicit-error", 1);
  Run("not-implemented", 2);
  Run("malformed", 3);
  Run("transport-error", 0);
  Run("response-refused", 0);
  Run("self-error", 0);
  return failures == 0 ? 0 : 1;
}

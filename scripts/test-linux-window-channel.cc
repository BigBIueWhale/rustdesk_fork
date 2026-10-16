// Executes the production channel and pinned Flutter codec/GObject implementation.
// The binary messenger supplies controlled transport completions; no engine/window runs.
#include "window_channel.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <iostream>
#include <string>

namespace {
constexpr char kChannel[] = "window-channel-test";
constexpr char kPassword[] = "SyntheticWindowPassword1";
constexpr char kToken[] = "SyntheticWindowToken2";
std::string logs;
int created = 0;
int retired = 0;
int not_implemented = 0;
int failures = 0;
std::atomic<FlValue*> temporary_values[3]{{nullptr}, {nullptr}, {nullptr}};
std::atomic<bool> temporary_freed[3]{{false}, {false}, {false}};
std::atomic<int> values_freed{0};
int argument_maps = 0;

void WatchValues(FlValue* first, FlValue* second = nullptr, FlValue* third = nullptr) {
  FlValue* values[] = {first, second, third};
  for (int i = 0; i < 3; ++i) {
    temporary_values[i].store(values[i]);
    temporary_freed[i].store(false);
  }
}

bool TemporaryValuesRetired() {
  return temporary_freed[0].load() && temporary_freed[1].load() &&
      temporary_freed[2].load();
}

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

void CheckValueObserver() {
  auto* value = fl_value_new_int(7);
  WatchValues(value);
  fl_value_unref(value);
  Check(temporary_freed[0].load(), "observer-sees-final-reference-retirement");
  value = fl_value_new_int(8);
  WatchValues(value);
  fl_value_ref(value);
  fl_value_unref(value);
  Check(!temporary_freed[0].load(), "observer-preserves-retained-reference");
  fl_value_unref(value);
  Check(temporary_freed[0].load(), "observer-sees-retained-reference-retirement");
  WatchValues(nullptr);
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
    G_IMPLEMENT_INTERFACE(fl_binary_messenger_get_type(), MessengerInterface))

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
      FlBinaryMessengerResponseHandle*, GBytes* response, GError** error) -> gboolean {
    auto* state = reinterpret_cast<TestMessenger*>(messenger)->state;
    ++state->responses;
    if (state->refuse_response) {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_CLOSED, "%s/%s", kPassword, kToken);
      return FALSE;
    }
    g_clear_pointer(&state->received, g_bytes_unref);
    state->received = response == nullptr ? g_bytes_new(nullptr, 0) : g_bytes_ref(response);
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
    Check(FL_METHOD_CODEC_GET_CLASS(codec)->decode_method_call(FL_METHOD_CODEC(codec), message,
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
G_DEFINE_TYPE(TestHandle, test_handle, fl_binary_messenger_response_handle_get_type())
void test_handle_class_init(TestHandleClass*) {}
void test_handle_init(TestHandle*) {}

struct ForwardState { WindowChannel* window; bool* retired; };

void Run(const std::string& name, int reply_kind) {
  const int start_failures = failures;
  const int start_live = created - retired;
  const int start_not_implemented = not_implemented;
  const int start_maps = argument_maps;
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
    target->state->reply = FL_METHOD_CODEC_GET_CLASS(codec)->encode_error_envelope(
        FL_METHOD_CODEC(codec), "declined", "Request declined", nullptr, &error);
  } else if (reply_kind == 2) {
    target->state->reply = g_bytes_new(nullptr, 0);
  } else if (reply_kind == 3) {
    const guint8 malformed[] = {255};
    target->state->reply = g_bytes_new(malformed, sizeof malformed);
  } else {
    target->state->reply = FL_METHOD_CODEC_GET_CLASS(codec)->encode_success_envelope(
        FL_METHOD_CODEC(codec), payload, &error);
  }
  const bool self = name == "self-error";
  const bool self_void = name == "self-void";
  target->state->transport_error = self || name == "transport-error";
  target->state->expected_sender = self || self_void ? 0 : 42;
  source->state->refuse_response = name == "response-refused";
  int completed = 0;
  bool temporaries_retired = true;
  if (self_void) {
    for (int i = 0; i < 128; ++i) {
      window->InvokeMethodSelfVoid("onEvent", payload);
      temporaries_retired = TemporaryValuesRetired() && temporaries_retired;
    }
  } else if (self) {
    window->InvokeMethodSelf("onDestroy", payload, [&completed]() { ++completed; });
  } else {
    auto* handle = FL_BINARY_MESSENGER_RESPONSE_HANDLE(g_object_new(test_handle_get_type(), nullptr));
    g_object_weak_ref(G_OBJECT(handle), Retired, &handle_retired);
    g_autoptr(GBytes) request = FL_METHOD_CODEC_GET_CLASS(codec)->encode_method_call(
        FL_METHOD_CODEC(codec), "forward", payload, &error);
    source->state->handler(FL_BINARY_MESSENGER(source), kChannel, request,
        handle, source->state->handler_data);
    g_object_unref(handle);
    Check(!call_retired && !handle_retired, "incoming-owned-before-completion");
  }
  window.reset();
  Drain();
  const int expected_sends = self_void ? 128 : 1;
  Check(target->state->sends == expected_sends, "exact-outbound-send-count");
  Check(argument_maps - start_maps == expected_sends, "all-native-argument-maps-observed");
  Check(temporaries_retired && TemporaryValuesRetired(), "temporary-argument-values-retired");
  if (self_void) {
    Check(completed == 0 && source->state->responses == 0, "self-void-has-no-response");
    Check(fl_value_get_type(payload) == FL_VALUE_TYPE_MAP &&
        std::strcmp(fl_value_get_string(fl_value_lookup_string(payload, "password")), kPassword) == 0,
        "borrowed-payload-remains-owned");
  } else if (self) {
    Check(completed == 1 && source->state->responses == 0, "one-self-completion");
  } else {
    Check(source->state->responses == 1, "one-response-attempt");
    Check(call_retired && handle_retired, "incoming-retired-after-completion");
    if (!source->state->refuse_response) {
      Check(source->state->received != nullptr, "caller-received-reply");
      if (source->state->received != nullptr) {
        g_autoptr(FlMethodResponse) response = reply_kind == 2 ? nullptr :
            FL_METHOD_CODEC_GET_CLASS(codec)->decode_response(
            FL_METHOD_CODEC(codec), source->state->received, &error);
        Check(reply_kind == 2 || response != nullptr, "caller-reply-native-decode");
        if ((reply_kind == 3 || name == "transport-error") && response != nullptr) {
          Check(FL_IS_METHOD_ERROR_RESPONSE(response), "malformed-is-error");
          if (FL_IS_METHOD_ERROR_RESPONSE(response)) {
            auto* failure = FL_METHOD_ERROR_RESPONSE(response);
            Check(std::strcmp(fl_method_error_response_get_code(failure), "window_request_failed") == 0,
                "fixed-error-code");
            Check(std::strcmp(fl_method_error_response_get_message(failure), "Desktop window request failed") == 0,
                "fixed-error-message");
            auto* details = fl_method_error_response_get_details(failure);
            Check(details == nullptr || fl_value_get_type(details) == FL_VALUE_TYPE_NULL,
                "null-error-details");
          }
        } else if (reply_kind == 1 && response != nullptr) {
          Check(FL_IS_METHOD_ERROR_RESPONSE(response) && std::strcmp(
              fl_method_error_response_get_code(FL_METHOD_ERROR_RESPONSE(response)), "declined") == 0,
              "explicit-error-preserved");
        } else if (reply_kind == 2) {
          Check(g_bytes_get_size(source->state->received) == 0 &&
              not_implemented == start_not_implemented + 1, "not-implemented-preserved");
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

// Observe frees of the exact native values; always delegate to real GLib.
extern "C" void g_free(gpointer memory) {
  using Free = void (*)(gpointer);
  static auto real_free = reinterpret_cast<Free>(dlsym(RTLD_NEXT, "g_free"));
  if (real_free == nullptr) std::abort();
  for (int i = 0; i < 3; ++i) {
    if (memory != nullptr && temporary_values[i].load() == memory &&
        !temporary_freed[i].exchange(true)) {
      ++values_freed;
    }
  }
  real_free(memory);
}

extern "C" void __real_fl_method_channel_invoke_method(FlMethodChannel*,
    const gchar*, FlValue*, GCancellable*, GAsyncReadyCallback, gpointer);
extern "C" void __wrap_fl_method_channel_invoke_method(FlMethodChannel* channel,
    const gchar* method, FlValue* args, GCancellable* cancellable,
    GAsyncReadyCallback callback, gpointer data) {
  Check(fl_value_get_length(args) == 2, "exact-native-argument-envelope");
  WatchValues(fl_value_get_map_key(args, 0), fl_value_get_map_key(args, 1),
      fl_value_lookup_string(args, "fromWindowId"));
  ++argument_maps;
  __real_fl_method_channel_invoke_method(channel, method, args, cancellable, callback, data);
}

// Observe actual transfer-full objects without replacing Flutter behavior.
extern "C" FlMethodResponse* __real_fl_method_channel_invoke_method_finish(
    FlMethodChannel*, GAsyncResult*, GError**);
extern "C" FlMethodResponse* __wrap_fl_method_channel_invoke_method_finish(
    FlMethodChannel* channel, GAsyncResult* result, GError** error) {
  auto* response = __real_fl_method_channel_invoke_method_finish(channel, result, error);
  if (response != nullptr) {
    ++created;
    if (FL_IS_METHOD_NOT_IMPLEMENTED_RESPONSE(response)) ++not_implemented;
    g_object_weak_ref(G_OBJECT(response), +[](gpointer, GObject*) { ++retired; }, nullptr);
  }
  return response;
}

int main() {
  g_log_set_always_fatal(G_LOG_LEVEL_ERROR);
  g_log_set_default_handler(+[](const gchar*, GLogLevelFlags, const gchar* message, gpointer) {
    if (message != nullptr) logs += message;
  }, nullptr);
  CheckValueObserver();
  if (failures != 0) return 2;
  values_freed.store(0);
  std::cout << "WINDOW_VALUE_OBSERVER=pass controls=2\n";
  Run("success", 0);
  Run("explicit-error", 1);
  Run("not-implemented", 2);
  Run("malformed", 3);
  Run("transport-error", 0);
  Run("response-refused", 0);
  Run("self-error", 0);
  Run("self-void", 0);
  std::cout << "WINDOW_VALUE_TOTAL=observed maps=" << argument_maps
            << " freed=" << values_freed.load() << '\n';
  return failures == 0 ? 0 : 1;
}

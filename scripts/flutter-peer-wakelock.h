/* Native test service on the disposable viewer's private session bus.
 * It delays one real Inhibit reply; it does not control screen power. */
#define WAKE_BUS "org.freedesktop.ScreenSaver"
#define WAKE_PATH "/org/freedesktop/ScreenSaver"
#define WAKE_CONTROL "org.rustdesk.TestWakeLock"

typedef struct {
    GMainLoop *loop;
    GDBusMethodInvocation *pending;
    char owner[256];
    guint acquisitions, releases, disconnects;
    gboolean active, failed;
} WakeService;

static void wake_method(GDBusConnection *connection, const gchar *sender,
                        const gchar *path, const gchar *interface,
                        const gchar *method, GVariant *parameters,
                        GDBusMethodInvocation *invocation, gpointer data) {
    WakeService *state = data;
    (void)connection; (void)path;
    if (interface == NULL) goto invalid;
    if (strcmp(interface, WAKE_BUS) == 0 && strcmp(method, "Inhibit") == 0) {
        const gchar *app, *reason;
        g_variant_get(parameters, "(&s&s)", &app, &reason);
        if (state->acquisitions != 0U || sender == NULL || sender[0] != ':' ||
            strlen(sender) >= sizeof(state->owner) || app[0] == '\0' ||
            strlen(app) > 256U || strcmp(reason, "wakelock") != 0) goto invalid;
        strcpy(state->owner, sender);
        state->acquisitions++;
        state->active = TRUE;
        /* The callback owns invocation until returning a value/error consumes it. */
        state->pending = invocation;
        printf("WAKE_SERVICE_ACQUIRED owner=%s cookie=1 reply=pending\n", sender);
    } else if (strcmp(interface, WAKE_BUS) == 0 && strcmp(method, "UnInhibit") == 0) {
        guint cookie;
        g_variant_get(parameters, "(u)", &cookie);
        if (!state->active || state->pending != NULL || cookie != 1U ||
            sender == NULL || strcmp(sender, state->owner) != 0) goto invalid;
        state->active = FALSE;
        state->releases++;
        g_dbus_method_invocation_return_value(invocation, NULL);
        printf("WAKE_SERVICE_RELEASED owner=%s cookie=1\n", sender);
    } else if (strcmp(interface, WAKE_CONTROL) == 0 && strcmp(method, "Snapshot") == 0) {
        g_dbus_method_invocation_return_value(invocation,
            g_variant_new("(buuubbs)", state->active, state->acquisitions,
                state->releases, state->disconnects, state->pending != NULL,
                state->failed, state->owner));
    } else if (strcmp(interface, WAKE_CONTROL) == 0 && strcmp(method, "ReleaseReply") == 0) {
        if (state->pending == NULL || !state->active || state->failed) goto invalid;
        g_dbus_method_invocation_return_value(state->pending, g_variant_new("(u)", 1U));
        state->pending = NULL;
        g_dbus_method_invocation_return_value(invocation, NULL);
        puts("WAKE_SERVICE_REPLY_RELEASED cookie=1");
    } else if (strcmp(interface, WAKE_CONTROL) == 0 && strcmp(method, "Stop") == 0) {
        if (state->active || state->pending != NULL || state->acquisitions != 1U ||
            state->releases != 1U || state->failed || state->disconnects != 0U) goto invalid;
        g_dbus_method_invocation_return_value(invocation, NULL);
        g_main_loop_quit(state->loop);
    } else {
invalid:
        state->failed = TRUE;
        g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "unexpected wake-lock fixture transition");
        fprintf(stderr, "WAKE_SERVICE_FAIL method=%s\n", method);
    }
    fflush(stdout);
}

static void wake_owner_changed(GDBusConnection *connection, const gchar *sender,
                               const gchar *path, const gchar *interface,
                               const gchar *signal, GVariant *parameters, gpointer data) {
    WakeService *state = data;
    const gchar *name, *old_owner, *new_owner;
    (void)connection; (void)sender; (void)path; (void)interface; (void)signal;
    g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);
    if (state->owner[0] != '\0' && strcmp(name, state->owner) == 0 &&
        old_owner[0] != '\0' && new_owner[0] == '\0') {
        state->disconnects++;
        state->active = FALSE;
        printf("WAKE_SERVICE_DISCONNECTED owner=%s\n", name);
        fflush(stdout);
    }
}

static int run_wake_service(void) {
    if (geteuid() == 0 || getegid() == 0 || geteuid() != getuid() ||
        getegid() != getgid() || getenv("DBUS_SESSION_BUS_ADDRESS") == NULL) return 1;
    const char xml[] = "<node><interface name='" WAKE_BUS "'>"
        "<method name='Inhibit'><arg type='s' direction='in'/><arg type='s' direction='in'/>"
        "<arg type='u' direction='out'/></method>"
        "<method name='UnInhibit'><arg type='u' direction='in'/></method></interface>"
        "<interface name='" WAKE_CONTROL "'><method name='Snapshot'>"
        "<arg type='b' direction='out'/><arg type='u' direction='out'/>"
        "<arg type='u' direction='out'/><arg type='u' direction='out'/>"
        "<arg type='b' direction='out'/><arg type='b' direction='out'/>"
        "<arg type='s' direction='out'/></method><method name='ReleaseReply'/>"
        "<method name='Stop'/></interface></node>";
    const GDBusInterfaceVTable vtable = {.method_call = wake_method};
    WakeService state = {0};
    GError *error = NULL;
    GDBusNodeInfo *node = g_dbus_node_info_new_for_xml(xml, &error);
    GDBusConnection *bus = NULL;
    GVariant *reply = NULL;
    guint registrations[2] = {0}, subscription = 0U, ownership = 0U;
    int result = 1;
    if (node == NULL) goto out;
    bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (bus == NULL) goto out;
    reply = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", WAKE_BUS, 4U),
        G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 3000, NULL, &error);
    if (reply == NULL) goto out;
    g_variant_get(reply, "(u)", &ownership);
    if (ownership != 1U) goto out;
    for (unsigned int i = 0U; i < 2U; i++) {
        registrations[i] = g_dbus_connection_register_object(bus, WAKE_PATH,
            node->interfaces[i], &vtable, &state, NULL, &error);
        if (registrations[i] == 0U) goto out;
    }
    subscription = g_dbus_connection_signal_subscribe(bus, "org.freedesktop.DBus",
        "org.freedesktop.DBus", "NameOwnerChanged", "/org/freedesktop/DBus", NULL,
        G_DBUS_SIGNAL_FLAGS_NONE, wake_owner_changed, &state, NULL);
    state.loop = g_main_loop_new(NULL, FALSE);
    puts("WAKE_SERVICE_READY transport=private-dbus reply=held");
    fflush(stdout);
    g_main_loop_run(state.loop);
    if (!g_dbus_connection_flush_sync(bus, NULL, &error)) goto out;
    result = state.failed ? 1 : 0;
out:
    if (error != NULL) fprintf(stderr, "WAKE_SERVICE_FAIL %s\n", error->message);
    g_clear_error(&error);
    if (state.pending != NULL)
        g_dbus_method_invocation_return_error_literal(state.pending, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "fixture is retiring");
    if (bus != NULL) {
        if (subscription != 0U) g_dbus_connection_signal_unsubscribe(bus, subscription);
        for (unsigned int i = 0U; i < 2U; i++)
            if (registrations[i] != 0U &&
                !g_dbus_connection_unregister_object(bus, registrations[i])) result = 1;
        if (!g_dbus_connection_close_sync(bus, NULL, &error)) result = 1;
    }
    g_clear_error(&error);
    g_clear_pointer(&state.loop, g_main_loop_unref);
    g_clear_pointer(&reply, g_variant_unref);
    g_clear_pointer(&node, g_dbus_node_info_unref);
    g_clear_object(&bus);
    return result;
}

static GVariant *wake_call(GDBusConnection *bus, const char *method, const GVariantType *type) {
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(bus, WAKE_BUS, WAKE_PATH, WAKE_CONTROL,
        method, NULL, type, G_DBUS_CALL_FLAGS_NONE, 1000, NULL, &error);
    if (error != NULL) fprintf(stderr, "WAKE_CONTROL_FAIL %s: %s\n", method, error->message);
    g_clear_error(&error);
    return reply;
}

static int observe_wake(unsigned long pid, int retired) {
    GError *error = NULL;
    GDBusConnection *bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    uint64_t deadline = monotonic_millis() + 3000U;
    int result = -1;
    g_clear_error(&error);
    if (bus == NULL) return -1;
    do {
        GVariant *reply = wake_call(bus, "Snapshot", G_VARIANT_TYPE("(buuubbs)"));
        gboolean active, pending, failed;
        guint acquisitions, releases, disconnects, sender_pid = 0U;
        const gchar *owner;
        if (reply == NULL) break;
        g_variant_get(reply, "(buuubb&s)", &active, &acquisitions, &releases,
            &disconnects, &pending, &failed, &owner);
        int matches = !failed && acquisitions == 1U && disconnects == 0U &&
            active == !retired && pending == !retired && releases == (guint)retired;
        if (matches) {
            GVariant *identity = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus",
                "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID",
                g_variant_new("(s)", owner), G_VARIANT_TYPE("(u)"),
                G_DBUS_CALL_FLAGS_NONE, 1000, NULL, &error);
            if (identity != NULL) {
                g_variant_get(identity, "(u)", &sender_pid);
                g_variant_unref(identity);
            }
            g_clear_error(&error);
            if (sender_pid == pid) {
                printf("FLUTTER_PEER_WAKE_OBSERVED phase=%s owner=%s pid=%u active=%u pending=%u releases=%u disconnects=0\n",
                    retired ? "retired" : "pending", owner, sender_pid, active, pending, releases);
                result = 0;
            }
        }
        g_variant_unref(reply);
        if (result == 0 || failed || disconnects != 0U || sleep_millis(50U) != 0) break;
    } while (monotonic_millis() < deadline);
    g_object_unref(bus);
    if (result != 0) fprintf(stderr, "FLUTTER_PEER_WAKE_FAIL phase=%s\n", retired ? "retired" : "pending");
    return result;
}

static int release_wake_reply(void) {
    GError *error = NULL;
    GDBusConnection *bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    GVariant *reply = bus == NULL ? NULL : wake_call(bus, "ReleaseReply", G_VARIANT_TYPE("()"));
    int result = reply == NULL ? -1 : 0;
    g_clear_error(&error);
    g_clear_pointer(&reply, g_variant_unref);
    g_clear_object(&bus);
    return result;
}

/* Drive the packaged GTK authentication dialog on the owned fixture desktop. */
#define main rustdesk_peer_driver_main
#include "flutter-peer-presentation-x11.c"
#undef main

static int agent_node(AtspiAccessible *node, unsigned int pid, AtspiRole role,
                      const char *name, unsigned int depth, unsigned int *nodes,
                      AtspiAccessible **found) {
    GError *error = NULL;
    if (depth > ACCESSIBLE_DEPTH_LIMIT || ++*nodes > ACCESSIBLE_NODE_LIMIT) return -1;
    atspi_accessible_clear_cache(node);
    if (atspi_accessible_get_process_id(node, &error) != pid || error != NULL) goto fail;
    AtspiRole actual = atspi_accessible_get_role(node, &error);
    if (error != NULL) goto fail;
    if (actual == role) {
        gchar *label = atspi_accessible_get_name(node, &error);
        int matches = error == NULL && (name == NULL || (label != NULL && strcmp(label, name) == 0));
        g_free(label);
        if (error != NULL) goto fail;
        AtspiStateSet *states = atspi_accessible_get_state_set(node);
        matches = matches && states != NULL && atspi_state_set_contains(states, ATSPI_STATE_VISIBLE) &&
            atspi_state_set_contains(states, ATSPI_STATE_SHOWING) &&
            atspi_state_set_contains(states, ATSPI_STATE_ENABLED) &&
            atspi_state_set_contains(states, ATSPI_STATE_SENSITIVE);
        if (states != NULL) g_object_unref(states);
        if (matches) {
            if (*found != NULL) goto fail;
            *found = g_object_ref(node);
        }
    }
    gint count = atspi_accessible_get_child_count(node, &error);
    if (error != NULL || count < 0 || count > ACCESSIBLE_CHILD_LIMIT) goto fail;
    for (gint i = 0; i < count; ++i) {
        AtspiAccessible *child = atspi_accessible_get_child_at_index(node, i, &error);
        if (error != NULL || child == NULL) { if (child != NULL) g_object_unref(child); goto fail; }
        int result = agent_node(child, pid, role, name, depth + 1U, nodes, found);
        g_object_unref(child);
        if (result != 0) goto fail;
    }
    return 0;
fail:
    g_clear_error(&error);
    return -1;
}

static AtspiAccessible *agent_control(unsigned int pid, AtspiRole role, const char *name) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    do {
        GError *error = NULL;
        AtspiAccessible *root = atspi_get_desktop(0), *found = NULL;
        unsigned int applications = 0U, nodes = 0U;
        int valid = root != NULL;
        gint count = valid ? atspi_accessible_get_child_count(root, &error) : -1;
        valid = valid && error == NULL && count >= 0 && count <= ACCESSIBLE_CHILD_LIMIT;
        for (gint i = 0; valid && i < count; ++i) {
            AtspiAccessible *app = atspi_accessible_get_child_at_index(root, i, &error);
            unsigned int actual;
            valid = error == NULL && app != NULL && atspi_process_id(app, &actual) == 0;
            if (valid && actual == pid) {
                ++applications;
                valid = agent_node(app, pid, role, name, 0U, &nodes, &found) == 0;
            }
            if (app != NULL) g_object_unref(app);
        }
        if (root != NULL) g_object_unref(root);
        g_clear_error(&error);
        if (valid && applications == 1U && found != NULL) return found;
        if (found != NULL) g_object_unref(found);
        if (!valid || applications > 1U || sleep_millis(100U) != 0) break;
    } while (monotonic_millis() < deadline);
    fprintf(stderr, "POLKIT_DIALOG_CONTROL_FAIL role=%d name=%s\n", role, name != NULL ? name : "(role)");
    return NULL;
}

static int agent_click(unsigned int pid, const char *name) {
    AtspiAccessible *button = agent_control(pid, ATSPI_ROLE_PUSH_BUTTON, name);
    if (button == NULL) return -1;
    AtspiAction *action = atspi_accessible_get_action_iface(button);
    GError *error = NULL;
    int result = -1;
    if (action != NULL && atspi_action_get_n_actions(action, &error) == 1 && error == NULL) {
        gchar *name = atspi_action_get_action_name(action, 0, &error);
        if (error == NULL && name != NULL && strcmp(name, "click") == 0 &&
            atspi_action_do_action(action, 0, &error) && error == NULL) result = 0;
        g_free(name);
    }
    g_clear_error(&error);
    if (action != NULL) g_object_unref(action);
    g_object_unref(button);
    return result;
}

static int agent_select(unsigned int pid) {
    AtspiAccessible *combo = agent_control(pid, ATSPI_ROLE_COMBO_BOX, NULL);
    if (combo == NULL) return -1;
    AtspiSelection *selection = atspi_accessible_get_selection_iface(combo);
    GError *error = NULL;
    AtspiAccessible *menu = atspi_accessible_get_child_at_index(combo, 0, &error);
    gint count = menu != NULL && error == NULL ? atspi_accessible_get_child_count(menu, &error) : -1;
    gint selected = -1;
    int result = -1;
    if (error != NULL || count < 1 || count > 8 || selection == NULL) goto out;
    for (gint i = 0; i < count; ++i) {
        AtspiAccessible *item = atspi_accessible_get_child_at_index(menu, i, &error);
        gchar *label = item != NULL && error == NULL ? atspi_accessible_get_name(item, &error) : NULL;
        if (label != NULL && strcmp(label, "rdreceiver4003") == 0) {
            if (selected != -1) { g_free(label); g_object_unref(item); goto out; }
            selected = i;
        }
        g_free(label);
        if (item != NULL) g_object_unref(item);
        if (error != NULL) goto out;
    }
    if (selected < 0 || !atspi_selection_select_child(selection, selected, &error) || error != NULL) goto out;
    result = 0;
out:
    g_clear_error(&error);
    if (menu != NULL) g_object_unref(menu);
    if (selection != NULL) g_object_unref(selection);
    g_object_unref(combo);
    return result;
}

static int agent_password_count(unsigned int pid, gint expected) {
    AtspiAccessible *field = agent_control(pid, ATSPI_ROLE_PASSWORD_TEXT, NULL);
    if (field == NULL) return -1;
    AtspiText *text = atspi_accessible_get_text_iface(field);
    GError *error = NULL;
    int result = text != NULL && atspi_text_get_character_count(text, &error) == expected && error == NULL;
    g_clear_error(&error);
    if (text != NULL) g_object_unref(text);
    g_object_unref(field);
    return result ? 0 : -1;
}

static int agent_password(Display *display, unsigned int pid, int partial) {
    GError *error = NULL;
    int result = -1;
    Window root = DefaultRootWindow(display), returned_root, parent, *windows = NULL, dialog = None;
    unsigned int windows_count = 0U, matches = 0U;
    if (XQueryTree(display, root, &returned_root, &parent, &windows, &windows_count) == 0) goto out;
    if (windows_count <= ACCESSIBLE_CHILD_LIMIT) {
        for (unsigned int i = 0U; i < windows_count; ++i) {
            unsigned long owner;
            XWindowAttributes attributes;
            if (read_window_pid(display, windows[i], &owner) == 0 && owner == pid &&
                XGetWindowAttributes(display, windows[i], &attributes) != 0 &&
                attributes.map_state == IsViewable && attributes.width >= 320 && attributes.height >= 40) {
                dialog = windows[i];
                ++matches;
            }
        }
    }
    if (windows != NULL) XFree(windows);
    if (matches != 1U) goto out;
    XRaiseWindow(display, dialog);
    XSetInputFocus(display, dialog, RevertToParent, CurrentTime);
    XSync(display, False);
    AtspiAccessible *field = agent_control(pid, ATSPI_ROLE_PASSWORD_TEXT, NULL);
    if (field == NULL) goto out;
    AtspiComponent *component = atspi_accessible_get_component_iface(field);
    int focused = component != NULL && atspi_component_grab_focus(component, &error) && error == NULL;
    if (component != NULL) g_object_unref(component);
    g_object_unref(field);
    if (!focused) goto out;
    /* Synthetic fixture administrator secret, entered into the real PAM dialog. */
    static const char password[] = "Receiver-admin-PAM-2026!";
    size_t length = partial ? 5U : sizeof(password) - 1U;
    if (agent_password_count(pid, 0) != 0) goto out;
    KeyCode shift = XKeysymToKeycode(display, XK_Shift_L);
    if (shift == 0U) goto out;
    for (size_t i = 0U; i < length; ++i) {
        int upper = password[i] >= 'A' && password[i] <= 'Z';
        int shifted = upper || password[i] == '!';
        KeySym key = (KeySym)(upper ? password[i] - 'A' + 'a' : password[i] == '!' ? '1' : password[i]);
        if (shifted && XTestFakeKeyEvent(display, shift, True, CurrentTime) == 0) goto out;
        int typed = fake_key(display, key);
        if (shifted && XTestFakeKeyEvent(display, shift, False, CurrentTime) == 0) typed = -1;
        XSync(display, False);
        if (typed != 0) goto out;
    }
    /* Observe masked character count, never the password text. */
    if (agent_password_count(pid, (gint)length) != 0) goto out;
    if (partial) {
        printf("LINUX_POLKIT_PASSWORD_ENTRY=pass characters=%zu submitted=no\n", length);
        result = 0;
    } else result = agent_click(pid, "Authenticate");
out:
    g_clear_error(&error);
    return result;
}

static int agent_dialog_retired(Display *display, unsigned int pid) {
    uint64_t deadline = monotonic_millis() + 5000U;
    unsigned int stable = 0U;
    while (monotonic_millis() < deadline) {
        Window root = DefaultRootWindow(display), returned_root, parent, *windows = NULL;
        unsigned int count = 0U, visible = 0U;
        if (XQueryTree(display, root, &returned_root, &parent, &windows, &count) == 0) return -1;
        int valid = count <= ACCESSIBLE_CHILD_LIMIT;
        for (unsigned int i = 0U; valid && i < count; ++i) {
            unsigned long owner;
            if (read_window_pid(display, windows[i], &owner) == 0 && owner == pid) {
                XWindowAttributes attributes;
                valid = XGetWindowAttributes(display, windows[i], &attributes) != 0;
                if (valid && attributes.map_state == IsViewable) ++visible;
            }
        }
        if (windows != NULL) XFree(windows);
        if (!valid) return -1;
        stable = visible == 0U ? stable + 1U : 0U;
        if (stable == 3U) {
            printf("LINUX_POLKIT_DIALOG_RETIRED=pass pid=%u visible_windows=0 observations=3\n", pid);
            return 0;
        }
        if (sleep_millis(100U) != 0) return -1;
    }
    return -1;
}

int main(int argc, char **argv) {
    char *end = NULL;
    if (argc != 4 || getuid() != 4001 || geteuid() != 4001) return 2;
    const char *message_text;
    if (strcmp(argv[3], "unattended-password") == 0)
        message_text = "Authentication is required to change the RustDesk unattended password";
    else if (strcmp(argv[3], "incoming-recording") == 0)
        message_text = "Authentication is required to change automatic recording of incoming RustDesk sessions";
    else return 2;
    errno = 0;
    unsigned long pid = strtoul(argv[1], &end, 10);
    if (errno != 0 || *end != '\0' || pid <= 1 || pid > UINT_MAX) return 2;
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) return 1;
    if (!gtk_init_check(NULL, NULL)) { XCloseDisplay(display); return 1; }
    GError *error = NULL;
    GdkPixbuf *icon = gdk_pixbuf_new_from_resource(
        "/org/gtk/libgtk/icons/16x16/actions/dialog-password.png", &error);
    int png_ready = error == NULL && icon != NULL &&
        gdk_pixbuf_get_width(icon) == 16 && gdk_pixbuf_get_height(icon) == 16;
    if (icon != NULL) g_object_unref(icon);
    g_clear_error(&error);
    if (!png_ready) { XCloseDisplay(display); return 1; }
    puts("LINUX_INSTALLED_SETTINGS_PNG=pass source=gtk-resource dimensions=16x16");
    if (atspi_init() != 0) { XCloseDisplay(display); return 1; }
    atspi_set_timeout(1000, 1000);
    int retired = strcmp(argv[2], "retired") == 0;
    AtspiAccessible *message = retired ? NULL : agent_control((unsigned int)pid, ATSPI_ROLE_LABEL, message_text);
    int result = -1;
    if (retired) result = agent_dialog_retired(display, (unsigned int)pid);
    else if (message != NULL) {
        g_object_unref(message);
        if (strcmp(argv[2], "cancel") == 0) result = agent_click((unsigned int)pid, "Cancel");
        else if (strcmp(argv[2], "select") == 0) result = agent_select((unsigned int)pid);
        else if (strcmp(argv[2], "password") == 0) result = agent_password(display, (unsigned int)pid, 1);
        else if (strcmp(argv[2], "cancel-password") == 0 && agent_password_count((unsigned int)pid, 5) == 0)
            result = agent_click((unsigned int)pid, "Cancel");
        else if (strcmp(argv[2], "authenticate") == 0 && agent_select((unsigned int)pid) == 0)
            result = agent_password(display, (unsigned int)pid, 0);
    }
    if (result != 0) {
        PasswordPromptScan diagnostic;
        if (scan_password_prompt((unsigned int)pid, &diagnostic, 1) != 0)
            fputs("POLKIT_DIALOG_DIAGNOSTIC=incomplete\n", stderr);
    } else printf("LINUX_POLKIT_DIALOG=pass action=%s pid=%lu operation=%s controls=%s input=%s\n",
                  argv[2], pid, argv[3], retired ? "x11" : "gtk-atspi", retired ? "none" : "xtest");
    atspi_exit();
    XCloseDisplay(display);
    return result == 0 ? 0 : 1;
}

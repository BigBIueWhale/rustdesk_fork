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

static int agent_authenticate(Display *display, unsigned int pid) {
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
    KeyCode shift = XKeysymToKeycode(display, XK_Shift_L);
    if (shift == 0U) goto out;
    for (size_t i = 0U; i < sizeof(password) - 1U; ++i) {
        int upper = password[i] >= 'A' && password[i] <= 'Z';
        int shifted = upper || password[i] == '!';
        KeySym key = (KeySym)(upper ? password[i] - 'A' + 'a' : password[i] == '!' ? '1' : password[i]);
        if (shifted && XTestFakeKeyEvent(display, shift, True, CurrentTime) == 0) goto out;
        int typed = fake_key(display, key);
        if (shifted && XTestFakeKeyEvent(display, shift, False, CurrentTime) == 0) typed = -1;
        XSync(display, False);
        if (typed != 0) goto out;
    }
    result = agent_click(pid, "Authenticate");
out:
    g_clear_error(&error);
    if (menu != NULL) g_object_unref(menu);
    if (selection != NULL) g_object_unref(selection);
    g_object_unref(combo);
    return result;
}

int main(int argc, char **argv) {
    char *end = NULL;
    if (argc != 3 || getuid() != 4001 || geteuid() != 4001) return 2;
    errno = 0;
    unsigned long pid = strtoul(argv[1], &end, 10);
    if (errno != 0 || *end != '\0' || pid <= 1 || pid > UINT_MAX) return 2;
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) return 1;
    if (atspi_init() != 0) { XCloseDisplay(display); return 1; }
    atspi_set_timeout(1000, 1000);
    AtspiAccessible *message = agent_control((unsigned int)pid, ATSPI_ROLE_LABEL,
        "Authentication is required to change the RustDesk unattended password");
    int result = -1;
    if (message != NULL) {
        g_object_unref(message);
        if (strcmp(argv[2], "cancel") == 0) result = agent_click((unsigned int)pid, "Cancel");
        else if (strcmp(argv[2], "authenticate") == 0) result = agent_authenticate(display, (unsigned int)pid);
    }
    if (result != 0) {
        PasswordPromptScan diagnostic;
        if (scan_password_prompt((unsigned int)pid, &diagnostic, 1) != 0)
            fputs("POLKIT_DIALOG_DIAGNOSTIC=incomplete\n", stderr);
    } else printf("LINUX_POLKIT_DIALOG=pass action=%s pid=%lu controls=gtk-atspi input=xtest\n", argv[2], pid);
    atspi_exit();
    XCloseDisplay(display);
    return result == 0 ? 0 : 1;
}

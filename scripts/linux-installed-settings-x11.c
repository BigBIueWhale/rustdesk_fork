/* Actual installed Flutter controls. Reuse the bounded, PID-scoped X11/AT-SPI driver. */
#define main rustdesk_peer_driver_main
#include "flutter-peer-presentation-x11.c"
#undef main

static int settings_visible(unsigned int pid, const char *name, int present) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    unsigned int stable = 0;
    while (monotonic_millis() < deadline) {
        AtspiAccessible *control = NULL;
        if (query_named_accessible(pid, name, deadline, &control, 0) != 0) return -1;
        int found = control != NULL;
        if (control != NULL) g_object_unref(control);
        stable = found == present ? stable + 1U : 0U;
        if (stable == 3U) return 0;
        if (sleep_millis(100U) != 0) return -1;
    }
    fprintf(stderr, "INSTALLED_SETTINGS_CONTROL_FAIL name=%s expected_present=%d\n", name, present);
    return -1;
}

static int settings_password(Display *display, unsigned int pid, const char *name) {
    static const char password[] = "InstalledGui2026";
    AtspiAccessible *field = NULL;
    AtspiComponent *component = NULL;
    GError *error = NULL;
    int result = -1;
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    if (query_named_accessible(pid, name, deadline, &field, 0) != 0 || field == NULL ||
        atspi_accessible_get_role(field, &error) != ATSPI_ROLE_PASSWORD_TEXT || error != NULL)
        goto out;
    component = atspi_accessible_get_component_iface(field);
    if (component == NULL || !atspi_component_grab_focus(component, &error) || error != NULL)
        goto out;
    KeyCode control = XKeysymToKeycode(display, XK_Control_L);
    KeyCode shift = XKeysymToKeycode(display, XK_Shift_L);
    if (control == 0U || shift == 0U ||
        XTestFakeKeyEvent(display, control, True, CurrentTime) == 0) goto out;
    int selected = fake_key(display, XK_a);
    if (XTestFakeKeyEvent(display, control, False, CurrentTime) == 0 || selected != 0) goto out;
    for (size_t i = 0; i < sizeof(password) - 1U; ++i) {
        int upper = password[i] >= 'A' && password[i] <= 'Z';
        KeySym key = (KeySym)(upper ? password[i] - 'A' + 'a' : password[i]);
        if (upper && XTestFakeKeyEvent(display, shift, True, CurrentTime) == 0) goto out;
        int typed = fake_key(display, key);
        if (upper && XTestFakeKeyEvent(display, shift, False, CurrentTime) == 0) typed = -1;
        XSync(display, False);
        if (typed != 0) goto out;
    }
    result = 0;
out:
    if (error != NULL) g_error_free(error);
    if (component != NULL) g_object_unref(component);
    if (field != NULL) g_object_unref(field);
    return result;
}

int main(int argc, char **argv) {
    unsigned long parsed;
    char *end = NULL;
    if (argc != 3 || getuid() != 4001 || geteuid() != 4001) return 2;
    errno = 0;
    parsed = strtoul(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || parsed <= 1UL || parsed > UINT_MAX)
        return 2;
    unsigned int pid = (unsigned int)parsed;
    Display *display = XOpenDisplay(NULL);
    Window main = None;
    int result = -1;
    if (display == NULL) return 1;
    if (atspi_init() != 0) goto out;
    atspi_set_timeout(1000, 1000);
    if (find_main_window(display, pid, &main) != 0) goto atspi_out;
    XRaiseWindow(display, main);
    XSetInputFocus(display, main, RevertToParent, CurrentTime);
    XSync(display, False);
    if (strcmp(argv[2], "open") == 0) {
        if (activate_header_control(display, main, pid, "Settings") != 0 ||
            activate_named_control(pid, "Security") != 0 ||
            activate_named_control(pid, "Set permanent password") != 0 ||
            settings_visible(pid, "Set Password", 1) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "cancel") == 0) {
        if (activate_named_control(pid, "Cancel") != 0 ||
            settings_visible(pid, "Set Password", 0) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "reopen") == 0) {
        if (activate_named_control(pid, "Set permanent password") != 0 ||
            settings_visible(pid, "Set Password", 1) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "submit") == 0) {
        if (settings_password(display, pid, "Password") != 0 ||
            settings_password(display, pid, "Confirmation") != 0 ||
            activate_named_control(pid, "OK") != 0) goto atspi_out;
    } else if (strcmp(argv[2], "denied") == 0) {
        if (settings_visible(pid, "Prompt: Failed", 1) != 0 ||
            settings_visible(pid, "Set Password", 1) != 0) goto atspi_out;
        /* A failed request leaves the real cancel action usable. */
        if (activate_named_control(pid, "Cancel") != 0 ||
            settings_visible(pid, "Set Password", 0) != 0) goto atspi_out;
    } else goto atspi_out;
    printf("LINUX_INSTALLED_SETTINGS_UI=pass stage=%s pid=%u controls=atspi input=xtest\n", argv[2], pid);
    result = 0;
atspi_out:
    atspi_exit();
out:
    XCloseDisplay(display);
    return result == 0 ? 0 : 1;
}

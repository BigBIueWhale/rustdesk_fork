/* Actual installed Flutter controls. Reuse the bounded, PID-scoped X11/AT-SPI driver. */
#define main rustdesk_peer_driver_main
#include "flutter-peer-presentation-x11.c"
#undef main

static int settings_graphics(void) {
    GError *error = NULL;
    if (!gdk_init_check(NULL, NULL)) return -1;
    GdkGLContext *context = gdk_window_create_gl_context(gdk_get_default_root_window(), &error);
    int result = context != NULL && gdk_gl_context_realize(context, &error) ? 0 : -1;
    if (result == 0) {
        int major, minor;
        gdk_gl_context_get_version(context, &major, &minor);
        printf("LINUX_INSTALLED_SETTINGS_GRAPHICS=pass version=%d.%d\n", major, minor);
    } else {
        fprintf(stderr, "LINUX_INSTALLED_SETTINGS_GRAPHICS_FAIL error=%s\n",
                error != NULL ? error->message : "no context");
    }
    if (error != NULL) g_error_free(error);
    if (context != NULL) g_object_unref(context);
    return result;
}

static int settings_screenshot(Display *display, Window main, unsigned int pid) {
    Window root = DefaultRootWindow(display), child, returned_root;
    int width = DisplayWidth(display, DefaultScreen(display));
    int height = DisplayHeight(display, DefaultScreen(display));
    int x, y, pointer_x, pointer_y, window_x, window_y;
    unsigned int mask;
    XWindowAttributes attributes;
    if (main == None || width != 1024 || height != 768 ||
        XGetWindowAttributes(display, main, &attributes) == 0 ||
        XTranslateCoordinates(display, main, root, 0, 0, &x, &y, &child) == 0 ||
        XQueryPointer(display, main, &returned_root, &child, &pointer_x, &pointer_y,
                      &window_x, &window_y, &mask) == 0) return -1;
    fprintf(stderr, "LINUX_INSTALLED_SETTINGS_GEOMETRY pid=%u window=%lu x=%d y=%d "
            "width=%d height=%d pointer_x=%d pointer_y=%d\n", pid, main, x, y,
            attributes.width, attributes.height, pointer_x, pointer_y);
    XImage *image = XGetImage(display, root, 0, 0, (unsigned int)width,
                             (unsigned int)height, AllPlanes, ZPixmap);
    if (image == NULL) return -1;
    GdkPixbuf *pixbuf = gdk_pixbuf_new(GDK_COLORSPACE_RGB, FALSE, 8, width, height);
    if (pixbuf == NULL) { XDestroyImage(image); return -1; }
    guchar *pixels = gdk_pixbuf_get_pixels(pixbuf);
    int stride = gdk_pixbuf_get_rowstride(pixbuf);
    for (int row = 0; row < height; ++row) {
        for (int column = 0; column < width; ++column) {
            unsigned long pixel = XGetPixel(image, column, row);
            guchar *out = pixels + row * stride + column * 3;
            out[0] = x11_frame_component(pixel, image->red_mask);
            out[1] = x11_frame_component(pixel, image->green_mask);
            out[2] = x11_frame_component(pixel, image->blue_mask);
        }
    }
    XDestroyImage(image);
    gchar *buffer = NULL;
    gsize length = 0U;
    GError *error = NULL;
    int result = -1;
    if (gdk_pixbuf_save_to_buffer(pixbuf, &buffer, &length, "png", &error, NULL) &&
        length <= 262144U) {
        gchar *encoded = g_base64_encode((const guchar *)buffer, length);
        fprintf(stderr, "LINUX_INSTALLED_SETTINGS_SCREENSHOT_PNG=%s\n", encoded);
        g_free(encoded);
        result = 0;
    }
    if (error != NULL) g_error_free(error);
    g_free(buffer);
    g_object_unref(pixbuf);
    return result;
}

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

static int settings_password(Display *display, Window main, unsigned int pid, const char *name) {
    static const char password[] = "InstalledGui2026";
    AtspiAccessible *field = NULL;
    AtspiText *text = NULL;
    GError *error = NULL;
    int result = -1;
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    if (query_named_accessible(pid, name, deadline, &field, 0) != 0 || field == NULL ||
        atspi_accessible_get_role(field, &error) != ATSPI_ROLE_PASSWORD_TEXT || error != NULL)
        goto out;
    text = atspi_accessible_get_text_iface(field);
    if (text == NULL || click_main_control(display, main, pid, name) != 0)
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
    deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline) {
        gint count = atspi_text_get_character_count(text, &error);
        if (error != NULL) goto out;
        if (count == (gint)(sizeof(password) - 1U)) {
            result = 0;
            break;
        }
        if (sleep_millis(50U) != 0) goto out;
    }
out:
    if (error != NULL) g_error_free(error);
    if (text != NULL) g_object_unref(text);
    if (field != NULL) g_object_unref(field);
    return result;
}

static int settings_open_password(Display *display, Window main, unsigned int pid) {
    /* The password card follows the pinned policy rows in a real scroll view. */
    for (unsigned int attempt = 0U; attempt < 9U; ++attempt) {
        AtspiAccessible *control = NULL;
        uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
        if (query_named_accessible(pid, "Set permanent password", deadline, &control, 0) != 0)
            return -1;
        if (control != NULL) {
            g_object_unref(control);
            return activate_named_control(pid, "Set permanent password");
        }
        XWindowAttributes attributes;
        Window child;
        int x, y;
        if (XGetWindowAttributes(display, main, &attributes) == 0 ||
            XTranslateCoordinates(display, main, DefaultRootWindow(display),
                attributes.width * 3 / 4, attributes.height / 2, &x, &y, &child) == 0 ||
            XTestFakeMotionEvent(display, DefaultScreen(display), x, y, CurrentTime) == 0)
            return -1;
        for (unsigned int step = 0U; step < 3U; ++step) {
            if (XTestFakeButtonEvent(display, 5U, True, CurrentTime) == 0 ||
                XTestFakeButtonEvent(display, 5U, False, CurrentTime) == 0) return -1;
        }
        XSync(display, False);
        if (sleep_millis(150U) != 0) return -1;
    }
    return -1;
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
        if (settings_graphics() != 0 || settings_visible(pid, "Connect", 1) != 0 ||
            activate_header_control(display, main, pid, "Settings") != 0 ||
            activate_named_control(pid, "Security") != 0 ||
            settings_open_password(display, main, pid) != 0 ||
            settings_visible(pid, "Set password", 1) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "cancel") == 0) {
        if (activate_named_control(pid, "Cancel") != 0 ||
            settings_visible(pid, "Set password", 0) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "reopen") == 0) {
        if (activate_named_control(pid, "Set permanent password") != 0 ||
            settings_visible(pid, "Set password", 1) != 0) goto atspi_out;
    } else if (strcmp(argv[2], "submit") == 0 || strcmp(argv[2], "fill") == 0) {
        if (settings_password(display, main, pid, "Password") != 0 ||
            settings_password(display, main, pid, "Confirmation") != 0) goto atspi_out;
        if (strcmp(argv[2], "submit") == 0 && activate_named_control(pid, "OK") != 0)
            goto atspi_out;
    } else if (strcmp(argv[2], "denied") == 0) {
        if (settings_visible(pid, "Prompt: Failed", 1) != 0 ||
            settings_visible(pid, "Set password", 1) != 0) goto atspi_out;
        /* A failed request leaves the real cancel action usable. */
        if (activate_named_control(pid, "Cancel") != 0 ||
            settings_visible(pid, "Set password", 0) != 0) goto atspi_out;
    } else goto atspi_out;
    printf("LINUX_INSTALLED_SETTINGS_UI=pass stage=%s pid=%u controls=atspi input=xtest\n", argv[2], pid);
    result = 0;
atspi_out:
    if (result != 0) {
        PasswordPromptScan diagnostic;
        fprintf(stderr, "LINUX_INSTALLED_SETTINGS_UI_FAIL stage=%s\n", argv[2]);
        if (scan_password_prompt(pid, &diagnostic, 1) != 0)
            fputs("LINUX_INSTALLED_SETTINGS_DIAGNOSTIC incomplete-accessibility-tree\n", stderr);
        if (settings_screenshot(display, main, pid) != 0)
            fputs("LINUX_INSTALLED_SETTINGS_DIAGNOSTIC screenshot-unavailable\n", stderr);
    }
    atspi_exit();
out:
    XCloseDisplay(display);
    return result == 0 ? 0 : 1;
}

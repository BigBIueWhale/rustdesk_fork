/* Full-app Recent search: native input and the exact process/window's visible
 * accessibility rows. Fixture records contain no credentials or network targets
 * beyond guest loopback. This does not exercise rename or Favorites. */
static int recent_rows(unsigned int pid, const AtspiRect *bounds, unsigned int expected,
                       unsigned int sequence, const char *query, const char *const names[3]) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    unsigned int stable = 0U, actual = 0U;
    while (monotonic_millis() < deadline && stable < 3U) {
        actual = 0U;
        for (unsigned int i = 0U; i < 3U; ++i) {
            AtspiAccessible *row = NULL;
            int status = query_accessible_with_focus(pid, names[i], deadline, &row,
                                                     0, 0, bounds, 0, 0);
            if (row != NULL) actual |= 1U << i;
            g_clear_object(&row);
            if (status != 0) return -1;
        }
        stable = actual == expected ? stable + 1U : 0U;
        if (sleep_millis(100U) != 0) return -1;
    }
    if (stable != 3U || monotonic_millis() >= deadline) {
        fprintf(stderr, "FLUTTER_PEER_RECENT_SEARCH_FAIL sequence=%u expected=%u actual=%u\n",
                sequence, expected, actual);
        return -1;
    }
    printf("FLUTTER_PEER_RECENT_SEARCH_CASE sequence=%u query=\"%s\" rows_mask=%u stable_scans=3\n",
           sequence, query, actual);
    fflush(stdout);
    return 0;
}

static int recent_query(Display *display, unsigned int pid, const AtspiRect *bounds,
                        const char *query) {
    AtspiAccessible *field = NULL;
    AtspiText *text = NULL;
    GError *error = NULL;
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    int result = -1;
    while (monotonic_millis() < deadline && field == NULL) {
        if (query_accessible_with_focus(pid, "focused search", deadline, &field,
                                       0, 0, bounds, 1, 0) != 0) goto out;
        if (field == NULL && sleep_millis(100U) != 0) goto out;
    }
    if (field == NULL || (text = atspi_accessible_get_text_iface(field)) == NULL) goto out;
    KeyCode control = XKeysymToKeycode(display, XK_Control_L);
    KeyCode shift = XKeysymToKeycode(display, XK_Shift_L);
    if (control == 0U || shift == 0U ||
        XTestFakeKeyEvent(display, control, True, CurrentTime) == 0) goto out;
    int typed = fake_key(display, XK_a);
    if (XTestFakeKeyEvent(display, control, False, CurrentTime) == 0) typed = -1;
    if (typed != 0 || fake_key(display, XK_BackSpace) != 0) goto out;
    for (size_t i = 0U; query[i] != '\0'; ++i) {
        unsigned char value = (unsigned char)query[i];
        int upper = value >= 'A' && value <= 'Z';
        KeySym key = (KeySym)(upper ? value + ('a' - 'A') : value);
        if (upper && XTestFakeKeyEvent(display, shift, True, CurrentTime) == 0) goto out;
        typed = fake_key(display, key);
        if (upper && XTestFakeKeyEvent(display, shift, False, CurrentTime) == 0) typed = -1;
        if (typed != 0) goto out;
    }
    XSync(display, False);
    while (monotonic_millis() < deadline) {
        gint count = atspi_text_get_character_count(text, &error);
        gchar *actual = NULL;
        if (error != NULL || count < 0 || count > 64) goto out;
        actual = atspi_text_get_text(text, 0, count, &error);
        int matches = error == NULL && actual != NULL && strcmp(actual, query) == 0;
        g_free(actual);
        if (error != NULL) goto out;
        if (matches) {
            result = 0;
            break;
        }
        if (sleep_millis(100U) != 0) goto out;
    }
out:
    g_clear_error(&error);
    g_clear_object(&text);
    g_clear_object(&field);
    return result;
}

static int exercise_recent_search(Display *display, const ViewerWindow *viewer,
                                  SourceHistory *history, const ConnectionIdentity *connection) {
    static const struct { const char *query; unsigned int mask; } cases[] = {
        {"", 7U}, {"north", 1U}, {"quartz", 2U}, {"127.0.0.2", 1U},
        {"beryl", 2U}, {"nomatch", 0U}, {"  NoRtH  ", 1U}, {"", 7U}
    };
    Window main = None, child;
    XWindowAttributes attributes;
    AtspiRect bounds = {0};
    ConnectionIdentity final = {{0}, {0}, 0UL};
    unsigned int connected, listeners, phase = 0U;
    uint64_t fresh, age;
    int result = -1;
    const char prefix[] = "127.0.0.1@";
    const char suffix[] = " - Control Remote Desktop - RustDesk";
    char current_label[ACCESSIBLE_NAME_LIMIT + 1U];
    const char *host = viewer->title + sizeof(prefix) - 1U;
    const char *end = strstr(host, suffix);
    if (strncmp(viewer->title, prefix, sizeof(prefix) - 1U) != 0 || end == NULL ||
        end == host || strcmp(end, suffix) != 0 || end - host > 64) return -1;
    int length = snprintf(current_label, sizeof(current_label), "unknown@%.*s\n127.0.0.1",
                          (int)(end - host), host);
    if (length < 0 || (size_t)length >= sizeof(current_label)) return -1;
    const char *names[] = {"amber@granite\nNorth desk", "beryl@quartz\nSouth desk", current_label};
    if (activate_header_control(display, viewer->window, (unsigned int)viewer->pid,
                                "New connection") != 0 ||
        find_main_window(display, viewer->pid, &main) != 0 ||
        XGetWindowAttributes(display, main, &attributes) == 0 ||
        attributes.map_state != IsViewable ||
        XTranslateCoordinates(display, main, RootWindow(display, DefaultScreen(display)),
                              0, 0, &bounds.x, &bounds.y, &child) == 0) goto out;
    bounds.width = attributes.width;
    bounds.height = attributes.height;
    XRaiseWindow(display, main);
    XSetInputFocus(display, main, RevertToParent, CurrentTime);
    XSync(display, False);
    if (recent_rows((unsigned int)viewer->pid, &bounds, 7U, 1U, "", names) != 0 ||
        click_main_control(display, main, (unsigned int)viewer->pid, "Search") != 0) goto out;
    for (phase = 1U; phase < sizeof(cases) / sizeof(cases[0]); ++phase) {
        if (recent_query(display, (unsigned int)viewer->pid, &bounds, cases[phase].query) != 0 ||
            recent_rows((unsigned int)viewer->pid, &bounds, cases[phase].mask,
                        phase + 1U, cases[phase].query, names) != 0) goto out;
    }
    if (close_viewer(display, main) != 0) goto out;
    main = None;
    XRaiseWindow(display, viewer->window);
    XSetInputFocus(display, viewer->window, RevertToParent, CurrentTime);
    XSync(display, False);
    if (wait_for_current_frames(display, viewer, history, AUTH_WAIT_MS, 4U, &fresh, &age) != 0 ||
        session_socket_counts(&connected, &listeners) != 0 || connected != 2U || listeners != 1U ||
        read_connection_identity(&final) != 0 || !same_connection(connection, &final)) goto out;
    printf("FLUTTER_PEER_RECENT_SEARCH_PIXELS distinct=4 maximum_age_ms=%llu\n",
           (unsigned long long)age);
    result = 0;
out:
    if (result != 0) {
        PasswordPromptScan diagnostic;
        fprintf(stderr, "FLUTTER_PEER_X11_FAIL recent search phase=%u\n", phase);
        if (scan_password_prompt((unsigned int)viewer->pid, &diagnostic, 1) != 0)
            fputs("FLUTTER_PEER_X11_FAIL recent search diagnostic\n", stderr);
    }
    if (main != None && close_viewer(display, main) != 0) result = -1;
    if (result == 0)
        puts("FLUTTER_PEER_RECENT_SEARCH_OK cases=8 rows=3 fields=address,alias,hostname,username "
             "case_whitespace=passed no_matches=passed clear=passed native_input=true "
             "visible_accessibility=true stable_connection=true fresh_pixels=4");
    return result;
}

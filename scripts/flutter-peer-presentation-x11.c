#define _POSIX_C_SOURCE 200809L

/*
 * Test-only X11 observer/controller for one exact RustDesk peer session.
 *
 * It types the password into the real Flutter prompt, observes pixels from the real remote window,
 * moves focus to a separate X11 window, returns through a real pointer click, and requires the
 * decoded presentation to become current again without replacing the connection.
 */
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WINDOW_WAIT_MS 45000U
#define PASSWORD_SETTLE_MS 750U
#define AUTH_WAIT_MS 30000U
#define BLUR_HOLD_MS 2000U
#define RECOVERY_LIMIT_MS 2500U
#define SAMPLE_INTERVAL_MS 40U
#define FRESH_LIMIT_MS 1000U
#define PALETTE_DISTANCE_LIMIT_SQUARED (92U * 92U)

static const uint8_t palette[16][3] = {
    {232U, 36U, 36U},   {36U, 224U, 48U},   {36U, 64U, 232U},
    {232U, 220U, 36U},  {224U, 36U, 220U},  {36U, 220U, 220U},
    {240U, 120U, 24U},  {128U, 40U, 232U},  {24U, 132U, 232U},
    {232U, 40U, 128U},  {132U, 232U, 24U},  {24U, 232U, 132U},
    {196U, 92U, 44U},   {44U, 196U, 92U},   {92U, 44U, 196U},
    {196U, 196U, 196U},
};

typedef struct {
    uint64_t first_seen_ms[256];
    uint64_t last_seen_ms[256];
    int initialized[256];
} SourceHistory;

typedef struct {
    Window window;
    unsigned int width;
    unsigned int height;
    unsigned long pid;
    char title[512];
    char instance_name[256];
    char class_name[256];
} ViewerWindow;

typedef struct {
    char local[32];
    char remote[32];
    unsigned long inode;
} ConnectionIdentity;

static int sleep_millis(unsigned int millis) {
    struct timespec delay = {
        .tv_sec = (time_t)(millis / 1000U),
        .tv_nsec = (long)(millis % 1000U) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static uint64_t monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static uint8_t component_from_pixel(unsigned long pixel, unsigned long mask) {
    unsigned int shift = 0U;
    unsigned long normalized;
    unsigned long value;
    if (mask == 0UL) {
        return 0U;
    }
    while (((mask >> shift) & 1UL) == 0UL) {
        ++shift;
    }
    normalized = mask >> shift;
    value = (pixel & mask) >> shift;
    return (uint8_t)((value * 255UL + normalized / 2UL) / normalized);
}

static int nearest_palette(uint8_t red, uint8_t green, uint8_t blue, unsigned int *distance) {
    unsigned int best = UINT_MAX;
    int best_index = -1;
    int index;
    for (index = 0; index < 16; ++index) {
        int dr = (int)red - (int)palette[index][0];
        int dg = (int)green - (int)palette[index][1];
        int db = (int)blue - (int)palette[index][2];
        unsigned int candidate = (unsigned int)(dr * dr + dg * dg + db * db);
        if (candidate < best) {
            best = candidate;
            best_index = index;
        }
    }
    *distance = best;
    return best_index;
}

static int classify_point(Display *display, Window window, int x, int y) {
    XWindowAttributes attributes;
    XImage *image;
    unsigned long pixel;
    uint8_t red;
    uint8_t green;
    uint8_t blue;
    unsigned int distance;
    int index;
    if (XGetWindowAttributes(display, window, &attributes) == 0 || attributes.visual == NULL) {
        return -1;
    }
    image = XGetImage(display, window, x, y, 1U, 1U, AllPlanes, ZPixmap);
    if (image == NULL) {
        return -1;
    }
    pixel = XGetPixel(image, 0, 0);
    red = component_from_pixel(pixel, attributes.visual->red_mask);
    green = component_from_pixel(pixel, attributes.visual->green_mask);
    blue = component_from_pixel(pixel, attributes.visual->blue_mask);
    XDestroyImage(image);
    index = nearest_palette(red, green, blue, &distance);
    if (distance > PALETTE_DISTANCE_LIMIT_SQUARED) {
        return -1;
    }
    return index;
}

static int classify_region(Display *display, Window window, unsigned int width,
                           unsigned int height, unsigned int x_percent) {
    unsigned int counts[16] = {0U};
    unsigned int row;
    unsigned int column;
    unsigned int classified = 0U;
    unsigned int best_count = 0U;
    int best_index = -1;
    for (row = 0U; row < 5U; ++row) {
        for (column = 0U; column < 5U; ++column) {
            int x = (int)((width * x_percent) / 100U) + (int)column - 2;
            int y = (int)((height * 58U) / 100U) + (int)row - 2;
            int index = classify_point(display, window, x, y);
            if (index >= 0) {
                counts[index] += 1U;
                classified += 1U;
            }
        }
    }
    for (row = 0U; row < 16U; ++row) {
        if (counts[row] > best_count) {
            best_count = counts[row];
            best_index = (int)row;
        }
    }
    if (classified < 15U || best_count < 12U) {
        return -1;
    }
    return best_index;
}

static int source_state(Display *display) {
    Window root = RootWindow(display, DefaultScreen(display));
    XWindowAttributes attributes;
    int low;
    int high;
    if (XGetWindowAttributes(display, root, &attributes) == 0) {
        return -1;
    }
    low = classify_point(display, root, attributes.width / 4, attributes.height / 2);
    high = classify_point(display, root, (attributes.width * 3) / 4, attributes.height / 2);
    if (low < 0 || high < 0) {
        return -1;
    }
    return high * 16 + low;
}

static int viewer_state(Display *display, const ViewerWindow *viewer) {
    int low = classify_region(display, viewer->window, viewer->width, viewer->height, 34U);
    int high = classify_region(display, viewer->window, viewer->width, viewer->height, 66U);
    if (low < 0 || high < 0) {
        return -1;
    }
    return high * 16 + low;
}

static void observe_source(Display *source, SourceHistory *history, uint64_t now) {
    int state = source_state(source);
    if (state >= 0) {
        if (history->initialized[state] == 0) {
            history->first_seen_ms[state] = now;
            history->initialized[state] = 1;
        }
        history->last_seen_ms[state] = now;
    }
}

static int state_age(const SourceHistory *history, int state, uint64_t now, uint64_t *age) {
    if (state < 0 || state > 255 || history->initialized[state] == 0 ||
        history->first_seen_ms[state] > now) {
        return -1;
    }
    *age = now - history->first_seen_ms[state];
    return 0;
}

static int read_text_property(Display *display, Window window, Atom property,
                              char *destination, size_t destination_size) {
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long item_count = 0UL;
    unsigned long bytes_after = 0UL;
    unsigned char *value = NULL;
    int status;
    if (destination_size == 0U) {
        return -1;
    }
    destination[0] = '\0';
    status = XGetWindowProperty(display, window, property, 0L, 1024L, False, AnyPropertyType,
                                &actual_type, &actual_format, &item_count, &bytes_after, &value);
    if (status != Success || value == NULL || actual_format != 8 || bytes_after != 0UL) {
        if (value != NULL) {
            XFree(value);
        }
        return -1;
    }
    if (item_count >= destination_size) {
        XFree(value);
        return -1;
    }
    memcpy(destination, value, item_count);
    destination[item_count] = '\0';
    XFree(value);
    return 0;
}

static int read_window_pid(Display *display, Window window, unsigned long *pid) {
    Atom property = XInternAtom(display, "_NET_WM_PID", False);
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long item_count = 0UL;
    unsigned long bytes_after = 0UL;
    unsigned char *value = NULL;
    int status = XGetWindowProperty(display, window, property, 0L, 1L, False, XA_CARDINAL,
                                    &actual_type, &actual_format, &item_count, &bytes_after, &value);
    if (status != Success || value == NULL || actual_type != XA_CARDINAL || actual_format != 32 ||
        item_count != 1UL || bytes_after != 0UL) {
        if (value != NULL) {
            XFree(value);
        }
        return -1;
    }
    *pid = *((unsigned long *)value);
    XFree(value);
    return 0;
}

static int inspect_viewer_candidate(Display *display, Window window, unsigned long expected_pid,
                                    ViewerWindow *candidate) {
    XWindowAttributes attributes;
    XClassHint hint = {0};
    Atom net_name = XInternAtom(display, "_NET_WM_NAME", False);
    char title[512] = {0};
    unsigned long pid = 0UL;
    if (XGetWindowAttributes(display, window, &attributes) == 0 ||
        attributes.map_state != IsViewable || attributes.width < 500 || attributes.height < 350) {
        return 0;
    }
    if (read_text_property(display, window, net_name, title, sizeof(title)) != 0) {
        char *legacy = NULL;
        if (XFetchName(display, window, &legacy) == 0 || legacy == NULL) {
            return 0;
        }
        if (strlen(legacy) >= sizeof(title)) {
            XFree(legacy);
            return 0;
        }
        strcpy(title, legacy);
        XFree(legacy);
    }
    if (strstr(title, "127.0.0.1 - Remote Desktop") == NULL) {
        return 0;
    }
    if (read_window_pid(display, window, &pid) != 0 || pid != expected_pid) {
        return 0;
    }
    if (XGetClassHint(display, window, &hint) == 0 || hint.res_name == NULL ||
        hint.res_class == NULL || strcmp(hint.res_name, "rustdesk") != 0 ||
        strcmp(hint.res_class, "Rustdesk") != 0) {
        if (hint.res_name != NULL) {
            XFree(hint.res_name);
        }
        if (hint.res_class != NULL) {
            XFree(hint.res_class);
        }
        return 0;
    }
    candidate->window = window;
    candidate->width = (unsigned int)attributes.width;
    candidate->height = (unsigned int)attributes.height;
    candidate->pid = pid;
    strcpy(candidate->title, title);
    if (strlen(hint.res_name) >= sizeof(candidate->instance_name) ||
        strlen(hint.res_class) >= sizeof(candidate->class_name)) {
        XFree(hint.res_name);
        XFree(hint.res_class);
        return -1;
    }
    strcpy(candidate->instance_name, hint.res_name);
    strcpy(candidate->class_name, hint.res_class);
    XFree(hint.res_name);
    XFree(hint.res_class);
    return 1;
}

static int find_viewer_window(Display *display, unsigned long expected_pid, ViewerWindow *viewer) {
    Window root = RootWindow(display, DefaultScreen(display));
    uint64_t deadline = monotonic_millis() + WINDOW_WAIT_MS;
    while (monotonic_millis() < deadline) {
        Window returned_root;
        Window returned_parent;
        Window *children = NULL;
        unsigned int child_count = 0U;
        unsigned int index;
        unsigned int matches = 0U;
        ViewerWindow found = {0};
        if (XQueryTree(display, root, &returned_root, &returned_parent, &children, &child_count) == 0) {
            return -1;
        }
        for (index = 0U; index < child_count; ++index) {
            ViewerWindow candidate = {0};
            int status = inspect_viewer_candidate(display, children[index], expected_pid, &candidate);
            if (status < 0) {
                XFree(children);
                return -1;
            }
            if (status > 0) {
                found = candidate;
                matches += 1U;
            }
        }
        if (children != NULL) {
            XFree(children);
        }
        if (matches == 1U) {
            *viewer = found;
            return 0;
        }
        if (matches > 1U) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL multiple exact remote windows=%u\n", matches);
            return -1;
        }
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int fake_key(Display *display, KeySym symbol) {
    KeyCode code = XKeysymToKeycode(display, symbol);
    if (code == 0U || XTestFakeKeyEvent(display, code, True, CurrentTime) == 0 ||
        XTestFakeKeyEvent(display, code, False, CurrentTime) == 0) {
        return -1;
    }
    XSync(display, False);
    return sleep_millis(12U);
}

static int type_password(Display *display) {
    static const char password[] = "rustdesk-peer-9f2a7c4e";
    size_t index;
    for (index = 0U; index < sizeof(password) - 1U; ++index) {
        KeySym symbol;
        unsigned char character = (unsigned char)password[index];
        if (character == '-') {
            symbol = XK_minus;
        } else if ((character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9')) {
            symbol = (KeySym)character;
        } else {
            return -1;
        }
        if (fake_key(display, symbol) != 0) {
            return -1;
        }
    }
    return fake_key(display, XK_Return);
}

static int wait_for_current_frames(Display *source, Display *display, const ViewerWindow *viewer,
                                   SourceHistory *history, unsigned int timeout_ms,
                                   unsigned int required_distinct, uint64_t *first_fresh_ms,
                                   uint64_t *maximum_age_ms) {
    uint64_t start = monotonic_millis();
    uint64_t deadline = start + timeout_ms;
    int last_state = -1;
    unsigned int distinct = 0U;
    int saw_fresh = 0;
    *first_fresh_ms = 0U;
    *maximum_age_ms = 0U;
    while (monotonic_millis() < deadline) {
        uint64_t now = monotonic_millis();
        int state;
        uint64_t age;
        observe_source(source, history, now);
        state = viewer_state(display, viewer);
        if (state_age(history, state, now, &age) == 0 && age <= FRESH_LIMIT_MS) {
            if (saw_fresh == 0) {
                *first_fresh_ms = now - start;
                saw_fresh = 1;
            }
            if (age > *maximum_age_ms) {
                *maximum_age_ms = age;
            }
            if (state != last_state) {
                last_state = state;
                distinct += 1U;
            }
            if (distinct >= required_distinct) {
                return 0;
            }
        }
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int read_connection_identity(ConnectionIdentity *identity) {
    FILE *stream = fopen("/proc/net/tcp", "r");
    char line[512];
    unsigned int matches = 0U;
    if (stream == NULL) {
        return -1;
    }
    if (fgets(line, sizeof(line), stream) == NULL) {
        fclose(stream);
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        unsigned int slot;
        char local[32];
        char remote[32];
        char state[3];
        unsigned long inode;
        int fields = sscanf(line,
                            " %u: %31s %31s %2s %*s %*s %*s %*s %*s %lu",
                            &slot, local, remote, state, &inode);
        (void)slot;
        if (fields == 5 && strcmp(state, "01") == 0 &&
            strcmp(remote, "0100007F:527E") == 0) {
            if (strlen(local) >= sizeof(identity->local) ||
                strlen(remote) >= sizeof(identity->remote)) {
                fclose(stream);
                return -1;
            }
            strcpy(identity->local, local);
            strcpy(identity->remote, remote);
            identity->inode = inode;
            matches += 1U;
        }
    }
    if (ferror(stream) != 0 || fclose(stream) != 0 || matches != 1U) {
        return -1;
    }
    return 0;
}

static int same_connection(const ConnectionIdentity *left, const ConnectionIdentity *right) {
    return strcmp(left->local, right->local) == 0 &&
           strcmp(left->remote, right->remote) == 0 && left->inode == right->inode;
}

static Window create_focus_sink(Display *display) {
    int screen = DefaultScreen(display);
    Window root = RootWindow(display, screen);
    Window sink = XCreateSimpleWindow(display, root, 8, 8, 180U, 110U, 1U,
                                      WhitePixel(display, screen), BlackPixel(display, screen));
    if (sink == 0) {
        return 0;
    }
    XStoreName(display, sink, "rustdesk-peer-focus-sink");
    XMapRaised(display, sink);
    XSetInputFocus(display, sink, RevertToParent, CurrentTime);
    XSync(display, False);
    return sink;
}

static int return_focus_with_pointer(Display *display, const ViewerWindow *viewer) {
    Window child;
    int root_x;
    int root_y;
    XRaiseWindow(display, viewer->window);
    XSetInputFocus(display, viewer->window, RevertToParent, CurrentTime);
    if (XTranslateCoordinates(display, viewer->window,
                              RootWindow(display, DefaultScreen(display)),
                              (int)viewer->width / 2, (int)viewer->height / 2,
                              &root_x, &root_y, &child) == 0) {
        return -1;
    }
    if (XTestFakeMotionEvent(display, DefaultScreen(display), root_x, root_y, CurrentTime) == 0 ||
        XTestFakeButtonEvent(display, 1U, True, CurrentTime) == 0 ||
        XTestFakeButtonEvent(display, 1U, False, CurrentTime) == 0) {
        return -1;
    }
    XSync(display, False);
    return 0;
}

static int close_viewer(Display *display, Window window) {
    Atom protocols = XInternAtom(display, "WM_PROTOCOLS", False);
    Atom delete_window = XInternAtom(display, "WM_DELETE_WINDOW", False);
    XEvent event;
    memset(&event, 0, sizeof(event));
    event.xclient.type = ClientMessage;
    event.xclient.window = window;
    event.xclient.message_type = protocols;
    event.xclient.format = 32;
    event.xclient.data.l[0] = (long)delete_window;
    event.xclient.data.l[1] = (long)CurrentTime;
    if (XSendEvent(display, window, False, NoEventMask, &event) == 0) {
        return -1;
    }
    XSync(display, False);
    return 0;
}

int main(int argc, char **argv) {
    const char *source_name;
    const char *viewer_name;
    char *end = NULL;
    unsigned long viewer_pid;
    Display *source;
    Display *display;
    int event_base;
    int error_base;
    int major;
    int minor;
    ViewerWindow viewer = {0};
    SourceHistory history = {0};
    Window sink;
    uint64_t initial_fresh_ms;
    uint64_t initial_max_age;
    uint64_t recovery_ms;
    uint64_t recovery_max_age;
    uint64_t blur_deadline;
    int blurred_state;
    uint64_t blurred_age = 0U;
    ConnectionIdentity connection_before = {{0}, {0}, 0UL};
    ConnectionIdentity connection_after = {{0}, {0}, 0UL};

    if (argc != 4) {
        fputs("usage: flutter-peer-presentation-x11 SOURCE_DISPLAY VIEWER_DISPLAY VIEWER_PID\n",
              stderr);
        return 2;
    }
    source_name = argv[1];
    viewer_name = argv[2];
    errno = 0;
    viewer_pid = strtoul(argv[3], &end, 10);
    if (errno != 0 || end == argv[3] || *end != '\0' || viewer_pid == 0UL) {
        fputs("FLUTTER_PEER_X11_FAIL invalid viewer pid\n", stderr);
        return 2;
    }
    source = XOpenDisplay(source_name);
    display = XOpenDisplay(viewer_name);
    if (source == NULL || display == NULL) {
        fputs("FLUTTER_PEER_X11_FAIL source or viewer display unavailable\n", stderr);
        if (source != NULL) {
            XCloseDisplay(source);
        }
        if (display != NULL) {
            XCloseDisplay(display);
        }
        return 1;
    }
    if (XTestQueryExtension(display, &event_base, &error_base, &major, &minor) == 0) {
        fputs("FLUTTER_PEER_X11_FAIL XTEST unavailable\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }

    if (find_viewer_window(display, viewer_pid, &viewer) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL exact remote window unavailable\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_WINDOW_OK pid=%lu title=%s wm_instance=%s wm_class=%s dimensions=%ux%u\n",
           viewer.pid, viewer.title, viewer.instance_name, viewer.class_name, viewer.width,
           viewer.height);
    XRaiseWindow(display, viewer.window);
    XSetInputFocus(display, viewer.window, RevertToParent, CurrentTime);
    XSync(display, False);
    if (sleep_millis(PASSWORD_SETTLE_MS) != 0 || type_password(display) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL real password prompt input\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    puts("FLUTTER_PEER_PASSWORD_PROMPT_OK typed_via_xtest=true argv_password=false");

    if (wait_for_current_frames(source, display, &viewer, &history, AUTH_WAIT_MS, 4U,
                                &initial_fresh_ms, &initial_max_age) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL authenticated current pixels unavailable\n", stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_INITIAL_PIXELS_OK first_fresh_ms=%llu maximum_age_ms=%llu distinct=4\n",
           (unsigned long long)initial_fresh_ms, (unsigned long long)initial_max_age);
    if (read_connection_identity(&connection_before) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL exact authenticated TCP identity unavailable\n", stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }

    sink = create_focus_sink(display);
    if (sink == 0) {
        fputs("FLUTTER_PEER_X11_FAIL focus sink creation\n", stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    blur_deadline = monotonic_millis() + BLUR_HOLD_MS;
    while (monotonic_millis() < blur_deadline) {
        observe_source(source, &history, monotonic_millis());
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            XDestroyWindow(display, sink);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
    }
    blurred_state = viewer_state(display, &viewer);
    (void)state_age(&history, blurred_state, monotonic_millis(), &blurred_age);
    if (return_focus_with_pointer(display, &viewer) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL real focus/pointer return\n", stderr);
        XDestroyWindow(display, sink);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (wait_for_current_frames(source, display, &viewer, &history, RECOVERY_LIMIT_MS, 3U,
                                &recovery_ms, &recovery_max_age) != 0) {
        fprintf(stderr,
                "FLUTTER_PEER_X11_FAIL focus recovery exceeded %u ms blurred_age_ms=%llu\n",
                RECOVERY_LIMIT_MS, (unsigned long long)blurred_age);
        XDestroyWindow(display, sink);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (read_connection_identity(&connection_after) != 0 ||
        same_connection(&connection_before, &connection_after) == 0) {
        fputs("FLUTTER_PEER_X11_FAIL focus cycle replaced the authenticated TCP connection\n",
              stderr);
        XDestroyWindow(display, sink);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_FOCUS_RECOVERY_OK blurred_ms=%u blurred_age_ms=%llu recovery_ms=%llu "
           "maximum_age_ms=%llu real_pointer=true stable_connection=true\n",
           BLUR_HOLD_MS, (unsigned long long)blurred_age, (unsigned long long)recovery_ms,
           (unsigned long long)recovery_max_age);
    XDestroyWindow(display, sink);
    if (close_viewer(display, viewer.window) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL WM_DELETE_WINDOW\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    puts("FLUTTER_PEER_PRESENTATION_OK actual_peer=true password_prompt=true capture=true "
         "transport=true decode=true flutter_texture=true x11_pixels=true focus_recovery=true");
    XCloseDisplay(display);
    XCloseDisplay(source);
    return 0;
}

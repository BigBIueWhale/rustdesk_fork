/* Native key-event observer for the private Xvfb only; not a product helper. */
#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec value;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return value.tv_sec + value.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    int repeat = argc == 2 && !strcmp(argv[1], "layout-repeat");
    int layout = argc == 2 && (!strcmp(argv[1], "layout") || repeat);
    assert(argc == 1 || layout);
    Display *display = XOpenDisplay("unix/:98.0");
    assert(display);
    int width = 0;
    KeySym *original = XGetKeyboardMapping(display, 220, 3, &width);
    assert(original && width > 0);
    KeySym fixture[] = {0xe9, 0x010005d0, 0x0101f642};
    XChangeKeyboardMapping(display, 220, 1, fixture, 3);
    KeyCode a = 0, b = 0;
    int a_width = 0, b_width = 0;
    KeySym *a_original = NULL, *b_original = NULL;
    if (layout) {
        a = XKeysymToKeycode(display, XK_a);
        b = XKeysymToKeycode(display, XK_b);
        assert(a && b && a != b);
        a_original = XGetKeyboardMapping(display, a, 1, &a_width);
        b_original = XGetKeyboardMapping(display, b, 1, &b_width);
        assert(a_original && b_original && a_width == b_width);
    }
    Window window = XCreateSimpleWindow(display, DefaultRootWindow(display),
                                        10, 10, 100, 100, 0, 0, 0);
    XSelectInput(display, window, KeyPressMask | KeyReleaseMask);
    XMapWindow(display, window);
    XSetInputFocus(display, window, RevertToParent, CurrentTime);
    XSync(display, False);
    puts("X11_TEXT_OBSERVER=ready");
    fflush(stdout);
    if (layout) {
        assert(getchar() == 'M');
        XChangeKeyboardMapping(display, a, a_width, b_original, 1);
        XChangeKeyboardMapping(display, b, b_width, a_original, 1);
        XSync(display, False);
        puts("X11_TEXT_LAYOUT=changed-after-construction");
        fflush(stdout);
    }
    const KeySym expected[] = {0x61, 0xe9, 0x010005d0, 0x0101f642,
                               0x2b, XK_Return, XK_Tab};
    unsigned events = 0;
    unsigned expected_events = repeat ? 64 : layout ? 2 : 14;
    unsigned pressed_code = 0;
    double deadline = now() + 3;
    while (events < expected_events && now() < deadline) {
        if (!XPending(display)) {
            struct timespec pause = {0, 1000000};
            nanosleep(&pause, NULL);
            continue;
        }
        XEvent event;
        XNextEvent(display, &event);
        if (event.type == MappingNotify) {
            XRefreshKeyboardMapping(&event.xmapping);
            continue;
        }
        if (event.type != KeyPress && event.type != KeyRelease) continue;
        KeySym base = XLookupKeysym(&event.xkey, 0);
        if (base == XK_Shift_L || base == XK_Shift_R) continue;
        KeySym symbol = XLookupKeysym(&event.xkey, !!(event.xkey.state & ShiftMask));
        printf("X11_TEXT_EVENT index=%u type=%d keysym=%lx\n", events, event.type, symbol);
        fflush(stdout);
        assert(event.type == (events % 2 ? KeyRelease : KeyPress));
        if (event.type == KeyPress) {
            assert(symbol == expected[layout ? 0 : events / 2]);
            pressed_code = event.xkey.keycode;
        } else {
            assert(event.xkey.keycode == pressed_code);
        }
        events++;
    }
    char pressed[32];
    XQueryKeymap(display, pressed);
    int clear = 1;
    for (unsigned i = 0; i < sizeof(pressed); i++) clear &= pressed[i] == 0;
    XChangeKeyboardMapping(display, 220, width, original, 3);
    XFree(original);
    if (layout) {
        XChangeKeyboardMapping(display, a, a_width, a_original, 1);
        XChangeKeyboardMapping(display, b, b_width, b_original, 1);
        XFree(a_original);
        XFree(b_original);
    }
    XDestroyWindow(display, window);
    XSync(display, False);
    assert(XCloseDisplay(display) == 0);
    printf("X11_TEXT_OBSERVER=retired events=%u keys_clear=%d\n", events, clear);
    return events == expected_events && clear ? 0 : 1;
}

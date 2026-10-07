#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <xcb/xcb.h>
#include <xcb/xproto.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SIZE(type, n) _Static_assert(sizeof(type) == (n), #type " size")
#define OFFSET(type, field, n) _Static_assert(offsetof(type, field) == (n), #type "." #field)
SIZE(xcb_intern_atom_cookie_t, 4); SIZE(xcb_get_property_cookie_t, 4);
SIZE(xcb_get_geometry_cookie_t, 4); SIZE(xcb_translate_coordinates_cookie_t, 4);
SIZE(xcb_intern_atom_reply_t, 12); OFFSET(xcb_intern_atom_reply_t, atom, 8);
SIZE(xcb_get_property_reply_t, 32); OFFSET(xcb_get_property_reply_t, value_len, 16);
SIZE(xcb_get_geometry_reply_t, 24); OFFSET(xcb_get_geometry_reply_t, width, 16);
SIZE(xcb_translate_coordinates_reply_t, 16); OFFSET(xcb_translate_coordinates_reply_t, dst_x, 12);
SIZE(xcb_setup_t, 40); OFFSET(xcb_setup_t, length, 6);
OFFSET(xcb_setup_t, vendor_len, 24); OFFSET(xcb_setup_t, roots_len, 28);
OFFSET(xcb_setup_t, pixmap_formats_len, 29);
SIZE(xcb_screen_t, 40); OFFSET(xcb_screen_t, allowed_depths_len, 39);
SIZE(xcb_depth_t, 8); OFFSET(xcb_depth_t, visuals_len, 2); SIZE(xcb_visualtype_t, 24);
OFFSET(xcb_generic_error_t, error_code, 1);

static Display *display;
static Window root, window, parent, dangling;
static Atom active, supported;
static XErrorHandler previous;
static unsigned errors, swallowed, hook, setup_fault, allocations, retirements;
static void *pending[32];

static int external_error(Display *dpy, XErrorEvent *event) {
    assert(dpy == display && event->error_code == BadWindow);
    ++errors;
    return 0;
}
static int old_swallow(Display *dpy, XErrorEvent *event) {
    assert(dpy == display && event->error_code == BadWindow);
    ++swallowed;
    return 0;
}
static void unrelated_error(void) {
    XWindowAttributes attributes;
    assert(XGetWindowAttributes(display, dangling, &attributes) == 0);
}
void focus_fixture_init(void) {
    assert(XInitThreads());
    display = XOpenDisplay(NULL);
    assert(display);
    root = DefaultRootWindow(display);
    active = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
    supported = XInternAtom(display, "_NET_SUPPORTED", False);
    dangling = XCreateSimpleWindow(display, root, 1, 1, 8, 8, 0, 0, 0);
    XDestroyWindow(display, dangling);
    XSync(display, False);
    previous = XSetErrorHandler(external_error);
}
void focus_fixture_old_shape(void) {
    XErrorHandler saved = XSetErrorHandler(old_swallow);
    assert(saved == external_error);
    unrelated_error();
    assert(XSetErrorHandler(saved) == old_swallow);
    assert(swallowed == 1 && errors == 0);
}
void focus_fixture_case(unsigned mode) {
    if (window) XDestroyWindow(display, window);
    if (parent) XDestroyWindow(display, parent);
    parent = 0;
    window = XCreateSimpleWindow(display, root, 100, 60, 128, 64, 0, 0, 0);
    if (mode == 2) {
        parent = XCreateSimpleWindow(display, root, -100, 60, 300, 200, 3, 0, 0);
        XDestroyWindow(display, window);
        window = XCreateSimpleWindow(display, parent, 30, 20, 128, 64, 2, 0, 0);
    }
    unsigned long supported_values[1025];
    for (unsigned i = 0; i < 1025; ++i) supported_values[i] = active;
    XChangeProperty(display, root, supported, XA_ATOM, 32, PropModeReplace,
                    (unsigned char *)supported_values, 1);
    unsigned long windows[2] = {window, window};
    XChangeProperty(display, root, active, XA_WINDOW, 32, PropModeReplace,
                    (unsigned char *)windows, 1);
    hook = 0;
    errors = 0;
    switch (mode) {
    case 3: XDestroyWindow(display, window); window = 0; break;
    case 4: supported_values[0] = XA_STRING;
        XChangeProperty(display, root, supported, XA_ATOM, 32, PropModeReplace,
                        (unsigned char *)supported_values, 1); break;
    case 5: { uint16_t value = 1;
        XChangeProperty(display, root, active, XA_WINDOW, 16, PropModeReplace,
                        (unsigned char *)&value, 1); break; }
    case 6: XChangeProperty(display, root, active, XA_WINDOW, 32, PropModeReplace,
                           (unsigned char *)windows, 2); break;
    case 7: windows[0] = 0;
        XChangeProperty(display, root, active, XA_WINDOW, 32, PropModeReplace,
                        (unsigned char *)windows, 1); break;
    case 8: XDeleteProperty(display, root, supported); break;
    case 9: XChangeProperty(display, root, supported, XA_STRING, 8, PropModeReplace,
                           (unsigned char *)"wrong", 5); break;
    case 10: XChangeProperty(display, root, supported, XA_ATOM, 32, PropModeReplace,
                            (unsigned char *)supported_values, 1025); break;
    case 11: hook = 2; break;
    case 12: hook = 1; break;
    default: assert(mode == 1 || mode == 2);
    }
    XSync(display, False);
}
void focus_fixture_fault(unsigned fault) { setup_fault = fault; }
unsigned focus_fixture_errors(void) {
    assert(XSetErrorHandler(external_error) == external_error);
    return errors;
}
void focus_fixture_balanced(void) {
    for (unsigned i = 0; i < 32; ++i) assert(pending[i] == NULL);
    assert(allocations == retirements);
}
void focus_fixture_close(void) {
    focus_fixture_balanced();
    assert(XSetErrorHandler(previous) == external_error);
    assert(XCloseDisplay(display) == 0);
    display = NULL;
}

static void track(void *pointer) {
    if (!pointer) return;
    for (unsigned i = 0; i < 32; ++i) {
        if (!pending[i]) { pending[i] = pointer; ++allocations; return; }
    }
    abort();
}
void __real_free(void *pointer);
void __wrap_free(void *pointer) {
    if (pointer) for (unsigned i = 0; i < 32; ++i) {
        if (pending[i] == pointer) { pending[i] = NULL; ++retirements; break; }
    }
    __real_free(pointer);
}

#define REPLY_WRAPPER(name) \
    xcb_##name##_reply_t *__real_xcb_##name##_reply(xcb_connection_t *, xcb_##name##_cookie_t, xcb_generic_error_t **); \
    xcb_##name##_reply_t *__wrap_xcb_##name##_reply(xcb_connection_t *c, xcb_##name##_cookie_t cookie, xcb_generic_error_t **error) { \
        xcb_##name##_reply_t *reply = __real_xcb_##name##_reply(c, cookie, error); \
        track(reply); if (error) track(*error); return reply; \
    }
REPLY_WRAPPER(intern_atom)
REPLY_WRAPPER(get_property)
REPLY_WRAPPER(translate_coordinates)

xcb_get_geometry_reply_t *__real_xcb_get_geometry_reply(xcb_connection_t *, xcb_get_geometry_cookie_t, xcb_generic_error_t **);
xcb_get_geometry_reply_t *__wrap_xcb_get_geometry_reply(xcb_connection_t *c, xcb_get_geometry_cookie_t cookie, xcb_generic_error_t **error) {
    if (hook == 1) { hook = 0; unrelated_error(); }
    xcb_get_geometry_reply_t *reply = __real_xcb_get_geometry_reply(c, cookie, error);
    track(reply); if (error) track(*error);
    if (hook == 2) {
        hook = 0;
        assert(reply && (!error || !*error));
        XDestroyWindow(display, window); window = 0;
        XSync(display, False);
    }
    return reply;
}

const xcb_setup_t *__real_xcb_get_setup(xcb_connection_t *);
const xcb_setup_t *__wrap_xcb_get_setup(xcb_connection_t *connection) {
    const xcb_setup_t *actual = __real_xcb_get_setup(connection);
    if (!setup_fault) return actual;
    _Alignas(xcb_setup_t) static unsigned char bytes[262148];
    size_t total = 8 + (size_t)actual->length * 4;
    assert(total >= 40 && total + 4 <= sizeof(bytes));
    memcpy(bytes, actual, total);
    xcb_setup_t header = *actual;
    switch (setup_fault) {
    case 1: header.length = 0; break;
    case 2: header.vendor_len = UINT16_MAX; break;
    case 3: header.length = 8; header.vendor_len = 0; header.pixmap_formats_len = 1; break;
    case 4: header.length = 8; header.vendor_len = 0; header.pixmap_formats_len = 0; header.roots_len = 1; break;
    case 5: {
        header.length = 18; header.vendor_len = 0; header.pixmap_formats_len = 0; header.roots_len = 1;
        xcb_screen_t screen = {0};
        screen.root = root; screen.allowed_depths_len = 1;
        memcpy(bytes + 40, &screen, sizeof(screen)); break;
    }
    case 6: {
        size_t offset = 40 + (((size_t)header.vendor_len + 3) & ~(size_t)3) + header.pixmap_formats_len * 8;
        assert(offset + 48 <= total && bytes[offset + 39]);
        xcb_depth_t depth;
        memcpy(&depth, bytes + offset + 40, sizeof(depth));
        depth.visuals_len = UINT16_MAX;
        memcpy(bytes + offset + 40, &depth, sizeof(depth)); break;
    }
    case 7: ++header.length; memset(bytes + total, 0, 4); break;
    default: abort();
    }
    memcpy(bytes, &header, sizeof(header));
    return (const xcb_setup_t *)bytes;
}

/* Native observations and link-time call instrumentation; guest-only, single-threaded. */
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/Xutil.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

extern Display *__real_XOpenDisplay(const char *);
extern int __real_XCloseDisplay(Display *);
extern XkbDescPtr __real_XkbGetMap(Display *, unsigned, unsigned);
extern void __real_XkbFreeKeyboard(XkbDescPtr, unsigned, Bool);
extern KeySym *__real_XGetKeyboardMapping(Display *, KeyCode, int, int *);
extern int __real_XFree(void *);
extern XModifierKeymap *__real_XGetModifierMapping(Display *);
extern int __real_XFreeModifiermap(XModifierKeymap *);
extern Status __real_XkbGetState(Display *, unsigned, XkbStatePtr);
extern int __real_XTestFakeKeyEvent(Display *, unsigned, Bool, unsigned long);
extern int input_bad_device_error(void *);

static unsigned counts[11]; /* open, close, map, free-map, symbols, free-symbols,
                             modifiers, free-modifiers, state, rejected-state, key */
static unsigned fault;
static Display *owned_display, *observer;
static XkbDescPtr owned_map;
static KeySym *owned_symbols;
static XModifierKeymap *owned_modifiers;
static Window window;
static int rejected_status;

void input_reset(unsigned next_fault)
{
    assert(!owned_display && !owned_map && !owned_symbols && !owned_modifiers);
    memset(counts, 0, sizeof(counts));
    fault = next_fault;
    rejected_status = 0;
}
unsigned input_count(unsigned index) { assert(index < 11); return counts[index]; }
int input_rejected_status(void) { return rejected_status; }
int input_expected_error(void) { return input_bad_device_error(observer); }
void input_reject_next_state(void) { assert(fault == 0); fault = 4; }

Display *__wrap_XOpenDisplay(const char *name)
{
    assert(!owned_display);
    owned_display = __real_XOpenDisplay(name);
    if (owned_display) counts[0]++;
    return owned_display;
}
int __wrap_XCloseDisplay(Display *display)
{
    assert(display == owned_display && !owned_map && !owned_symbols && !owned_modifiers);
    int result = __real_XCloseDisplay(display);
    owned_display = NULL;
    counts[1]++;
    return result;
}
XkbDescPtr __wrap_XkbGetMap(Display *display, unsigned which, unsigned device)
{
    assert(display == owned_display && !owned_map);
    if (fault == 2) { fault = 0; return NULL; }
    owned_map = __real_XkbGetMap(display, which, device);
    if (owned_map) counts[2]++;
    return owned_map;
}
void __wrap_XkbFreeKeyboard(XkbDescPtr map, unsigned which, Bool free_all)
{
    assert(map == owned_map && which == 0 && free_all == True);
    __real_XkbFreeKeyboard(map, which, free_all);
    owned_map = NULL;
    counts[3]++;
}
KeySym *__wrap_XGetKeyboardMapping(Display *display, KeyCode first, int count, int *width)
{
    assert(display == owned_display && !owned_symbols);
    if (fault == 1) { fault = 0; return NULL; }
    owned_symbols = __real_XGetKeyboardMapping(display, first, count, width);
    if (owned_symbols) counts[4]++;
    if (fault == 5) { fault = 0; *width = 0; }
    return owned_symbols;
}
int __wrap_XFree(void *pointer)
{
    assert(pointer == owned_symbols);
    int result = __real_XFree(pointer);
    owned_symbols = NULL;
    counts[5]++;
    return result;
}
XModifierKeymap *__wrap_XGetModifierMapping(Display *display)
{
    assert(display == owned_display && !owned_modifiers);
    if (fault == 3) { fault = 0; return NULL; }
    owned_modifiers = __real_XGetModifierMapping(display);
    if (owned_modifiers) counts[6]++;
    return owned_modifiers;
}
int __wrap_XFreeModifiermap(XModifierKeymap *map)
{
    assert(map == owned_modifiers);
    int result = __real_XFreeModifiermap(map);
    owned_modifiers = NULL;
    counts[7]++;
    return result;
}
Status __wrap_XkbGetState(Display *display, unsigned device, XkbStatePtr state)
{
    assert(display == owned_display);
    counts[8]++;
    if (fault == 4) {
        fault = 0;
        counts[9]++;
        rejected_status = __real_XkbGetState(display, 255, state);
        return rejected_status;
    }
    return __real_XkbGetState(display, device, state);
}
int __wrap_XTestFakeKeyEvent(Display *display, unsigned key, Bool down, unsigned long delay)
{
    assert(display == owned_display);
    counts[10]++;
    return __real_XTestFakeKeyEvent(display, key, down, delay);
}

void input_observer_open(void)
{
    observer = __real_XOpenDisplay(NULL);
    assert(observer);
    window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 100, 100, 0, 0, 0);
    assert(window);
    XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
    XMapWindow(observer, window);
    XSetInputFocus(observer, window, RevertToParent, CurrentTime);
    XSync(observer, False);
    while (XPending(observer)) { XEvent event; XNextEvent(observer, &event); }
}
void input_observe(unsigned character, unsigned presses, unsigned releases)
{
    unsigned down = 0, up = 0;
    XSync(observer, False);
    while (XPending(observer)) {
        XEvent event;
        KeySym symbol = NoSymbol;
        char text[8];
        XNextEvent(observer, &event);
        assert(event.type == KeyPress || event.type == KeyRelease);
        assert(event.xkey.window == window && !event.xkey.send_event);
        (void)XLookupString(&event.xkey, text, sizeof(text), &symbol, NULL);
        assert(symbol == character);
        if (event.type == KeyPress) {
            assert(down == 0 && up == 0);
            down++;
        } else {
            assert(up == 0 && down == presses);
            up++;
        }
    }
    assert(down == presses && up == releases);
}
void input_observer_close(void)
{
    XDestroyWindow(observer, window);
    assert(__real_XCloseDisplay(observer) == 0);
    observer = NULL;
}

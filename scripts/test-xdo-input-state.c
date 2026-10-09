/* Current production query, real X server, controlled reply/facility refusal.
 * Wrappers consume real replies before injecting faults; no old provider runs. */
#include <X11/Xlib-xcb.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libs/libxdo-sys-stub/native/xdo.h"

enum { CONNECTION_NULL = 1, CONNECTION_ERROR, POINTER_NULL, POINTER_ERROR,
       POINTER_TYPE, POINTER_LENGTH, POINTER_SCREEN, POINTER_CONNECTION,
       KEYMAP_NULL, KEYMAP_ERROR, KEYMAP_TYPE, KEYMAP_LENGTH, KEYMAP_CONNECTION,
       CAPS_ATOM, NUM_ATOM, CAPS_QUERY, NUM_QUERY, CAPS_VALUE, NUM_VALUE,
       FINAL_CONNECTION, RANGE_LOW, RANGE_HIGH, RANGE_REVERSED, FAULTS };
static int fault, querying, connection_checks, calls, replies, retirements, effects;
static void *owned[4];
static Atom caps_atom, num_atom;
static void own(void *p) {
  if (!p) return;
  for (int i = 0; i < 4; ++i) if (!owned[i]) { owned[i] = p; ++replies; return; }
  abort();
}
void __real_free(void *);
void __wrap_free(void *p) {
  if (p) for (int i = 0; i < 4; ++i) if (owned[i] == p) {
    owned[i] = NULL; ++retirements; break;
  }
  __real_free(p);
}
xcb_connection_t *__real_XGetXCBConnection(Display *);
xcb_connection_t *__wrap_XGetXCBConnection(Display *d) {
  return querying && fault == CONNECTION_NULL ? NULL : __real_XGetXCBConnection(d);
}
int __real_xcb_connection_has_error(xcb_connection_t *);
int __wrap_xcb_connection_has_error(xcb_connection_t *c) {
  if (querying) {
    ++connection_checks;
    if ((fault == CONNECTION_ERROR && connection_checks == 1)
        || (fault == POINTER_CONNECTION && connection_checks == 2)
        || (fault == KEYMAP_CONNECTION && connection_checks == 3)
        || (fault == FINAL_CONNECTION && connection_checks == 4)) return 1;
  }
  return __real_xcb_connection_has_error(c);
}
xcb_query_pointer_reply_t *__real_xcb_query_pointer_reply(xcb_connection_t *, xcb_query_pointer_cookie_t, xcb_generic_error_t **);
xcb_query_pointer_reply_t *__wrap_xcb_query_pointer_reply(xcb_connection_t *c, xcb_query_pointer_cookie_t k, xcb_generic_error_t **e) {
  xcb_query_pointer_reply_t *r = __real_xcb_query_pointer_reply(c, k, e);
  assert(r && !*e);
  if (querying) {
    ++calls;
    if (fault == POINTER_NULL) { __real_free(r); return NULL; }
    if (fault == POINTER_ERROR) { *e = calloc(1, sizeof(**e)); assert(*e); own(*e); }
    if (fault == POINTER_TYPE) r->response_type = 0;
    if (fault == POINTER_LENGTH) r->length = 1;
    if (fault == POINTER_SCREEN) r->same_screen = 2;
    own(r);
  }
  return r;
}
xcb_query_keymap_reply_t *__real_xcb_query_keymap_reply(xcb_connection_t *, xcb_query_keymap_cookie_t, xcb_generic_error_t **);
xcb_query_keymap_reply_t *__wrap_xcb_query_keymap_reply(xcb_connection_t *c, xcb_query_keymap_cookie_t k, xcb_generic_error_t **e) {
  xcb_query_keymap_reply_t *r = __real_xcb_query_keymap_reply(c, k, e);
  assert(r && !*e);
  if (querying) {
    ++calls;
    if (fault == KEYMAP_NULL) { __real_free(r); return NULL; }
    if (fault == KEYMAP_ERROR) { *e = calloc(1, sizeof(**e)); assert(*e); own(*e); }
    if (fault == KEYMAP_TYPE) r->response_type = 0;
    if (fault == KEYMAP_LENGTH) r->length = 0;
    own(r);
  }
  return r;
}
Atom __real_XInternAtom(Display *, const char *, Bool);
Atom __wrap_XInternAtom(Display *d, const char *name, Bool only) {
  if (querying) {
    assert(only == True);
    if ((fault == CAPS_ATOM && !strcmp(name, "Caps Lock"))
        || (fault == NUM_ATOM && !strcmp(name, "Num Lock"))) return None;
  }
  return __real_XInternAtom(d, name, only);
}
Bool __real_XkbGetNamedIndicator(Display *, Atom, int *, Bool *, XkbIndicatorMapPtr, Bool *);
Bool __wrap_XkbGetNamedIndicator(Display *d, Atom name, int *index, Bool *state, XkbIndicatorMapPtr map, Bool *real) {
  if (querying && ((fault == CAPS_QUERY && name == caps_atom) || (fault == NUM_QUERY && name == num_atom))) return False;
  Bool ok = __real_XkbGetNamedIndicator(d, name, index, state, map, real);
  if (querying && ((fault == CAPS_VALUE && name == caps_atom) || (fault == NUM_VALUE && name == num_atom))) *state = 2;
  return ok;
}
int __real_XTestFakeKeyEvent(Display *, unsigned int, Bool, unsigned long);
int __wrap_XTestFakeKeyEvent(Display *d, unsigned int key, Bool down, unsigned long delay) {
  if (querying) ++effects;
  return __real_XTestFakeKeyEvent(d, key, down, delay);
}
int __real_XTestFakeButtonEvent(Display *, unsigned int, Bool, unsigned long);
int __wrap_XTestFakeButtonEvent(Display *d, unsigned int key, Bool down, unsigned long delay) {
  if (querying) ++effects;
  return __real_XTestFakeButtonEvent(d, key, down, delay);
}
int __real_XChangeKeyboardMapping(Display *, int, int, KeySym *, int);
int __wrap_XChangeKeyboardMapping(Display *d, int code, int width, KeySym *map, int count) {
  if (querying) ++effects;
  return __real_XChangeKeyboardMapping(d, code, width, map, count);
}
Bool __real_XkbLockGroup(Display *, unsigned int, unsigned int);
Bool __wrap_XkbLockGroup(Display *d, unsigned int device, unsigned int group) {
  if (querying) ++effects;
  return __real_XkbLockGroup(d, device, group);
}
static int entries(const char *path) {
  DIR *d = opendir(path); assert(d); int count = 0;
  while (readdir(d)) ++count;
  assert(closedir(d) == 0); return count;
}
static int query(xdo_t *x, xdo_input_state_t *out) {
  connection_checks = 0; querying = 1;
  int result = xdo_query_input_state(x, out);
  querying = 0;
  for (int i = 0; i < 4; ++i) assert(!owned[i]);
  assert(replies == retirements && effects == 0);
  return result;
}
int main(void) {
  int descriptors = entries("/proc/self/fd"), tasks = entries("/proc/self/task");
  Display *d = XOpenDisplay("unix/:98.0"); assert(d && ScreenCount(d) == 2);
  xdo_t *x = xdo_new_with_opened_display(d, "unix/:98.0", 0); assert(x);
  caps_atom = XInternAtom(d, "Caps Lock", True); num_atom = XInternAtom(d, "Num Lock", True);
  assert(caps_atom && num_atom);
  int width;
  KeySym *map = XGetKeyboardMapping(d, x->keycode_low, x->keycode_high-x->keycode_low+1, &width); assert(map);
  xdo_input_state_t initial; assert(query(x, &initial) == XDO_SUCCESS);
  assert(sizeof(initial) == 40);
  Window w = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 100, 100, 0, 0, 0); assert(w);
  XSelectInput(d, w, KeyPressMask | KeyReleaseMask); XMapWindow(d, w); XSetInputFocus(d, w, RevertToParent, CurrentTime); XSync(d, False);
  int refused = 0, recovered = 0;
  for (int round = 0; round < 4; ++round) for (fault = 1; fault < FAULTS; ++fault) {
    int low = x->keycode_low, high = x->keycode_high;
    if (fault == RANGE_LOW) x->keycode_low = 7;
    if (fault == RANGE_HIGH) x->keycode_high = 256;
    if (fault == RANGE_REVERSED) x->keycode_low = high+1;
    xdo_input_state_t out, sentinel; memset(&out, 0xa5, sizeof(out)); sentinel = out;
    assert(query(x, &out) == XDO_ERROR && !memcmp(&out, &sentinel, sizeof(out))); ++refused;
    x->keycode_low = low; x->keycode_high = high;
    int saved_fault = fault; fault = 0;
    assert(query(x, &out) == XDO_SUCCESS && !memcmp(&out, &initial, sizeof(out))); ++recovered;
    fault = saved_fault;
    XSync(d, False); XEvent event;
    assert(!XCheckWindowEvent(d, w, KeyPressMask | KeyReleaseMask, &event));
  }
  fault = 0;
  xdo_input_state_t out;
  assert(query(NULL, &out) == XDO_ERROR && query(x, NULL) == XDO_ERROR);
  for (int screen = 0; screen < 2; ++screen) {
    XWarpPointer(d, None, RootWindow(d, screen), 0, 0, 0, 0, 30, 40);
    assert(XTestFakeButtonEvent(d, 1, True, CurrentTime)); XSync(d, False);
    Window root, child; int rx, ry, wx, wy; unsigned int mask;
    Bool same = XQueryPointer(d, DefaultRootWindow(d), &root, &child, &rx, &ry, &wx, &wy, &mask);
    assert(same == (screen == 0) && (mask & Button1Mask));
    assert(query(x, &out) == XDO_SUCCESS && out.pointer_mask == mask);
    assert(XTestFakeButtonEvent(d, 1, False, CurrentTime)); XSync(d, False);
  }
  XWarpPointer(d, None, DefaultRootWindow(d), 0, 0, 0, 0, 30, 40); XSync(d, False);
  int restored_width;
  KeySym *restored = XGetKeyboardMapping(d, x->keycode_low, x->keycode_high-x->keycode_low+1, &restored_width);
  assert(restored && restored_width == width && !memcmp(restored, map, (x->keycode_high-x->keycode_low+1)*width*sizeof(KeySym)));
  XFree(restored); XFree(map); XDestroyWindow(d, w); xdo_free(x); XCloseDisplay(d);
  assert(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks);
  assert(refused == 92 && recovered == 92 && replies == retirements && calls > 0);
  printf("XDO_INPUT_STATE_NATIVE=pass faults=23 repeats=4 refused=92 recovery=92 output=unpublished-on-error effects=none replies=retired pointer_screens=2 button_mask=preserved mapping=unchanged descriptors=retired tasks=retired sanitizer=address whole_app=false\n");
}

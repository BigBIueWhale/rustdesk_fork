/* Actual backend/provider composition; the observer owns a separate X11 connection. */
#define _POSIX_C_SOURCE 200809L
#include "../libs/libxdo-sys-stub/native/xdo.h"
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern Display *__real_XOpenDisplay(const char *);
extern int __real_XCloseDisplay(Display *);

static Display *observer, *borrowed_display;
static Window window, previous_focus;
static int previous_revert, phase, refusals, retirement_events;
static int retirement_refusals, expected_retirement_refusals, failed_retirements, free_attempts;
static Bool armed, key_release_fault;
static xdo_t *pending;
static XkbDescPtr baseline, retained_original;
static KeyCode scratch_code;
static charcodemap_t *retained_charcodes;
static int input_original_x, input_original_y;

static void keys_clear(void);
static void no_events(void);
static void text_event(int type);

/* Export these symbols: DSO-internal calls do not use executable --wrap. */
Bool XkbChangeMap(Display *display, XkbDescPtr map, XkbMapChangesPtr changes) {
  typedef Bool (*change_map_fn)(Display *, XkbDescPtr, XkbMapChangesPtr);
  static change_map_fn native;
  if (native == NULL) {
    native = (change_map_fn)dlsym(RTLD_NEXT, "XkbChangeMap");
    assert(native != NULL);
  }
  if (!key_release_fault && pending != NULL && display == borrowed_display
      && (armed || retirement_refusals > 0)
      && pending->scratch_original != NULL) {
    assert(phase == (armed ? 0 : 1));
    if (!armed) retirement_refusals--;
    refusals++;
    return False;
  }
  return native(display, map, changes);
}

Bool XTestFakeKeyEvent(Display *display, unsigned int code, Bool press, unsigned long delay) {
  typedef Bool (*key_event_fn)(Display *, unsigned int, Bool, unsigned long);
  static key_event_fn native;
  if (native == NULL) {
    native = (key_event_fn)dlsym(RTLD_NEXT, "XTestFakeKeyEvent");
    assert(native != NULL);
  }
  if (key_release_fault && pending != NULL && display == borrowed_display && !press) {
    assert(pending->scratch_original != NULL && pending->text_keys_len == 1
           && code == pending->scratch_keycode && pending->text_keys[0] == code);
    if (armed || retirement_refusals > 0) {
      assert(phase == (armed ? 0 : 1));
      if (!armed) retirement_refusals--;
      refusals++;
      return False;
    }
    assert(phase == 1 && retirement_events == 0 && code == scratch_code);
    Bool result = native(display, code, press, delay);
    assert(result);
    XSync(display, False);
    text_event(KeyRelease);
    keys_clear();
    no_events();
    retirement_events++;
    return result;
  }
  return native(display, code, press, delay);
}

static XkbDescPtr snapshot(void) {
  XkbDescPtr map = XkbGetMap(observer, XkbAllMapComponentsMask, XkbUseCoreKbd);
  assert(map && map->map && map->map->types && map->map->syms && map->map->key_sym_map
         && map->map->modmap && map->server && map->server->key_acts
         && map->server->behaviors && map->server->explicit && map->server->vmodmap
         && XkbGetControls(observer, XkbPerKeyRepeatMask, map) == Success && map->ctrls);
  return map;
}

static void restored_components(void) {
  XkbDescPtr actual = snapshot();
  assert(actual->min_key_code == baseline->min_key_code
         && actual->max_key_code == baseline->max_key_code
         && actual->map->num_types == baseline->map->num_types
         && !memcmp(actual->server->vmods, baseline->server->vmods, sizeof(actual->server->vmods))
         && !memcmp(actual->ctrls->per_key_repeat, baseline->ctrls->per_key_repeat,
                    sizeof(actual->ctrls->per_key_repeat)));
  for (int index = 0; index < baseline->map->num_types; index++) {
    XkbKeyTypePtr a = &actual->map->types[index], b = &baseline->map->types[index];
    assert(a->num_levels == b->num_levels && a->map_count == b->map_count
           && !memcmp(&a->mods, &b->mods, sizeof(a->mods))
           && (!a->map_count || !memcmp(a->map, b->map, a->map_count * sizeof(XkbKTMapEntryRec)))
           && !!a->preserve == !!b->preserve
           && (!a->preserve || !memcmp(a->preserve, b->preserve,
                                       a->map_count * sizeof(XkbModsRec))));
  }
  for (int code = baseline->min_key_code; code <= baseline->max_key_code; code++) {
    XkbSymMapPtr a = &actual->map->key_sym_map[code], b = &baseline->map->key_sym_map[code];
    assert(a->group_info == b->group_info && a->width == b->width
           && !memcmp(a->kt_index, b->kt_index, sizeof(a->kt_index))
           && !memcmp(XkbKeySymsPtr(actual, code), XkbKeySymsPtr(baseline, code),
                      XkbKeyNumSyms(baseline, code) * sizeof(KeySym))
           && actual->map->modmap[code] == baseline->map->modmap[code]
           && actual->server->explicit[code] == baseline->server->explicit[code]
           && actual->server->vmodmap[code] == baseline->server->vmodmap[code]
           && !memcmp(&actual->server->behaviors[code], &baseline->server->behaviors[code],
                      sizeof(XkbBehavior))
           && !!XkbKeyHasActions(actual, code) == !!XkbKeyHasActions(baseline, code)
           && (!XkbKeyHasActions(baseline, code)
               || !memcmp(XkbKeyActionsPtr(actual, code), XkbKeyActionsPtr(baseline, code),
                          XkbKeyNumActions(baseline, code) * sizeof(XkbAction))));
  }
  XkbFreeKeyboard(actual, 0, True);
}

static void keys_clear(void) {
  char keys[32];
  assert(XQueryKeymap(observer, keys));
  for (int byte = 0; byte < 32; byte++) assert(keys[byte] == 0);
}

static void no_events(void) {
  XEvent event;
  XSync(observer, False);
  assert(!XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event));
}

static void keys_pending(void) {
  char keys[32], expected[32] = {0};
  if (key_release_fault) expected[scratch_code / 8] = (char)(1U << (scratch_code % 8));
  assert(XQueryKeymap(observer, keys) && !memcmp(keys, expected, sizeof(keys)));
}

static void text_event(int type) {
  XkbDescPtr installed = snapshot();
  XEvent event;
  KeySym symbol = NoSymbol;
  unsigned int consumed;
  assert(XkbKeyNumSyms(installed, scratch_code) == 1
         && XkbKeySymsPtr(installed, scratch_code)[0] == 0x0101f642UL
         && XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event)
         && event.type == type && event.xkey.window == window && !event.xkey.send_event
         && event.xkey.keycode == scratch_code && event.xkey.state == 0
         && XkbTranslateKeyCode(installed, scratch_code, event.xkey.state, &consumed, &symbol)
         && symbol == 0x0101f642UL);
  XkbFreeKeyboard(installed, 0, True);
}

void enigo_cleanup_begin(int key_release) {
  assert(observer == NULL && pending == NULL && baseline == NULL);
  observer = __real_XOpenDisplay(getenv("DISPLAY"));
  assert(observer != NULL);
  phase = refusals = retirement_events = 0;
  retirement_refusals = expected_retirement_refusals = failed_retirements = free_attempts = 0;
  key_release_fault = key_release != 0;
  scratch_code = 0;
  retained_original = NULL;
  baseline = snapshot();
  keys_clear();
  XGetInputFocus(observer, &previous_focus, &previous_revert);
  window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 200, 100, 0, 0, 0);
  assert(window != None);
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
  XMapWindow(observer, window);
  XSetInputFocus(observer, window, RevertToPointerRoot, CurrentTime);
  XSync(observer, False);
}

void enigo_cleanup_register(xdo_t *context) {
  assert(observer != NULL && pending == NULL && phase == 0 && !armed
         && context != NULL && !context->close_display_when_freed
         && context->scratch_original == NULL && context->text_keys_len == 0);
  pending = context;
  borrowed_display = context->xdpy;
  armed = True;
}

void enigo_cleanup_pending(void) {
  assert(armed && phase == 0 && refusals == 1 && pending != NULL
         && pending->scratch_original != NULL && pending->xdpy == borrowed_display);
  retained_original = pending->scratch_original;
  retained_charcodes = pending->charcodes;
  scratch_code = pending->scratch_keycode;
  assert(scratch_code >= baseline->min_key_code && scratch_code <= baseline->max_key_code);
  assert(pending->text_keys_len == (unsigned int)key_release_fault
         && (!key_release_fault || pending->text_keys[0] == scratch_code));
  XSync(borrowed_display, False);
  for (int index = 0; index < XkbKeyNumSyms(baseline, scratch_code); index++)
    assert(XkbKeySymsPtr(baseline, scratch_code)[index] == NoSymbol);
  text_event(KeyPress);
  if (!key_release_fault) text_event(KeyRelease);
  keys_pending();
  no_events();
}

void enigo_cleanup_input_begin(void) {
  Window root, child;
  int root_x, root_y, x, y;
  unsigned int mask;
  XEvent event;
  assert(armed && phase == 0 && pending != NULL);
  assert(XQueryPointer(observer, window, &root, &child,
                       &input_original_x, &input_original_y, &x, &y, &mask));
  assert(!(mask & (Button1Mask | Button2Mask | Button3Mask | Button4Mask | Button5Mask)));
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask | ButtonPressMask
               | ButtonReleaseMask | PointerMotionMask);
  XWarpPointer(observer, None, window, 0, 0, 0, 0, 30, 30);
  XSync(observer, False);
  while (XCheckWindowEvent(observer, window, PointerMotionMask, &event)) {}
  assert(XTestFakeButtonEvent(observer, 1, True, CurrentTime));
  XSync(observer, False);
  assert(XCheckWindowEvent(observer, window, ButtonPressMask, &event)
         && event.type == ButtonPress && event.xbutton.button == 1
         && event.xbutton.window == window && !event.xbutton.send_event);
  assert(XQueryPointer(observer, window, &root, &child,
                       &root_x, &root_y, &x, &y, &mask)
         && x == 30 && y == 30 && mask == Button1Mask);
  keys_pending();
}

int enigo_cleanup_input_end(void) {
  Window root, child;
  int root_x, root_y, x, y;
  unsigned int mask, releases = 0, unexpected = 0;
  XEvent event;
  assert(armed && phase == 0 && pending != NULL);
  XSync(borrowed_display, False);
  XSync(observer, False);
  assert(XQueryPointer(observer, window, &root, &child, &root_x, &root_y, &x, &y, &mask));
  while (XCheckWindowEvent(observer, window,
                          PointerMotionMask | ButtonPressMask | ButtonReleaseMask, &event)) {
    if (event.type == ButtonRelease && event.xbutton.button == 1
        && event.xbutton.window == window && !event.xbutton.send_event
        && event.xbutton.state == Button1Mask) {
      releases++;
    } else {
      unexpected++;
    }
  }
  int unchanged = x == 30 && y == 30 && mask == 0 && releases == 1 && unexpected == 0;
  if (!unchanged) {
    printf("X11_ENIGO_PENDING_INPUT_OBSERVED x=%d y=%d mask=%u owned_releases=%u unexpected_events=%u\n",
           x, y, mask, releases, unexpected);
    assert(fflush(stdout) == 0);
  }
  keys_pending();
  /* Retire only buttons introduced by this private fixture, after observation. */
  for (unsigned int button = 1; button <= 3; button++)
    assert(XTestFakeButtonEvent(observer, button, False, CurrentTime));
  XSync(observer, False);
  while (XCheckWindowEvent(observer, window,
                          PointerMotionMask | ButtonPressMask | ButtonReleaseMask, &event)) {}
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
  XWarpPointer(observer, None, root, 0, 0, 0, 0, input_original_x, input_original_y);
  XSync(observer, False);
  return unchanged;
}

void enigo_cleanup_allow_retirement(int failures) {
  assert(armed && phase == 0 && refusals == 1 && pending != NULL
         && pending->scratch_original == retained_original
         && pending->scratch_keycode == scratch_code
         && pending->text_keys_len == (unsigned int)key_release_fault);
  XSync(borrowed_display, False);
  keys_pending();
  no_events();
  assert(failures >= 0 && failures <= 2);
  retirement_refusals = expected_retirement_refusals = failures;
  armed = False;
}

void enigo_cleanup_before_free(xdo_t *context) {
  if (observer == NULL) return;
  assert(!armed && context != NULL && context->xdpy == borrowed_display);
  if (phase == 0 || phase == 1) {
    assert(context == pending && !context->close_display_when_freed
           && context->scratch_original == retained_original
           && context->scratch_keycode == scratch_code
           && context->charcodes == retained_charcodes
           && context->text_keys_len == (unsigned int)key_release_fault);
    free_attempts++;
    phase = 1;
  } else {
    assert(phase == 2 && pending == NULL && context->close_display_when_freed
           && context->scratch_original == NULL);
    /* The parent Display remains live after child retirement. */
    XSync(borrowed_display, False);
    phase = 3;
  }
}

void enigo_cleanup_free_result(int status) {
  if (observer == NULL) return;
  if (status != XDO_SUCCESS) {
    assert(status == XDO_CLEANUP_ERROR && phase == 1 && !armed
           && pending != NULL && pending->xdpy == borrowed_display
           && pending->scratch_original == retained_original
           && pending->scratch_keycode == scratch_code
           && pending->charcodes == retained_charcodes && pending->charcodes_len > 0
           && pending->text_keys_len == (unsigned int)key_release_fault);
    XSync(borrowed_display, False);
    XkbDescPtr installed = snapshot();
    assert(XkbKeyNumSyms(installed, scratch_code) == 1
           && XkbKeySymsPtr(installed, scratch_code)[0] == 0x0101f642UL);
    XkbFreeKeyboard(installed, 0, True);
    assert(xdo_enter_text_scalar(pending, 'a', 0) == XDO_CLEANUP_ERROR);
    keys_pending();
    no_events();
    failed_retirements++;
    assert(failed_retirements == free_attempts && failed_retirements <= expected_retirement_refusals);
    if (expected_retirement_refusals == 2 && failed_retirements == 2) {
      puts("X11_ENIGO_RETIREMENT_ABORT_READY attempts=2 failures=2 owner=retained snapshot=retained allocations=retained display=live later_text=refused parent_free=unreached");
      assert(fflush(stdout) == 0);
    }
    return;
  }
  /* Identity was checked before free; never evaluate a retired C pointer. */
  if (phase == 1) {
    pending = NULL;
    retained_original = NULL;
    restored_components();
    keys_clear();
    no_events();
    phase = 2;
  } else {
    assert(phase == 3);
    borrowed_display = NULL;
    phase = 4;
  }
}

void enigo_cleanup_finish(void) {
  assert(phase == 4 && !armed && refusals == 1 + expected_retirement_refusals
         && failed_retirements == expected_retirement_refusals
         && free_attempts == 1 + expected_retirement_refusals
         && retirement_events == key_release_fault);
  restored_components();
  keys_clear();
  no_events();
  XSetInputFocus(observer, previous_focus, previous_revert, CurrentTime);
  XDestroyWindow(observer, window);
  XkbFreeKeyboard(baseline, 0, True);
  assert(__real_XCloseDisplay(observer) == 0);
  observer = borrowed_display = NULL;
  pending = NULL;
  baseline = retained_original = NULL;
}

/* Lock-lease component oracle. Injection and observation use distinct connections. */
static Display *lock_observer;
static Window lock_window, lock_previous_focus;
static int lock_previous_revert;
static unsigned int lock_num_mask, lock_original_mods;
static KeyCode lock_caps_code, lock_num_code, lock_owned_code, lock_held_code;

static void lock_event(int type, KeyCode code) {
  XEvent event;
  XSync(lock_observer, False);
  assert(XCheckWindowEvent(lock_observer, lock_window, KeyPressMask | KeyReleaseMask, &event)
         && event.type == type && event.xkey.keycode == code
         && event.xkey.window == lock_window && !event.xkey.send_event);
}

void lock_modes_begin(int caps, int num) {
  assert(lock_observer == NULL && observer == NULL);
  lock_observer = __real_XOpenDisplay("unix/:98.0");
  assert(lock_observer != NULL);
  XkbStateRec state;
  assert(XkbGetState(lock_observer, XkbUseCoreKbd, &state) == Success);
  lock_original_mods = state.locked_mods;
  lock_num_mask = XkbKeysymToModifiers(lock_observer, XK_Num_Lock);
  assert(lock_num_mask && !(lock_num_mask & LockMask));
  lock_caps_code = XKeysymToKeycode(lock_observer, XK_Caps_Lock);
  lock_num_code = XKeysymToKeycode(lock_observer, XK_Num_Lock);
  lock_owned_code = XKeysymToKeycode(lock_observer, XK_a);
  lock_held_code = XKeysymToKeycode(lock_observer, XK_Shift_R);
  assert(lock_caps_code && lock_num_code && lock_owned_code && lock_held_code);
  char keys[32];
  assert(XQueryKeymap(lock_observer, keys));
  for (int byte = 0; byte < 32; byte++) assert(keys[byte] == 0);
  assert(XkbLockModifiers(lock_observer, XkbUseCoreKbd, LockMask | lock_num_mask,
                         (caps ? LockMask : 0) | (num ? lock_num_mask : 0)));
  XGetInputFocus(lock_observer, &lock_previous_focus, &lock_previous_revert);
  lock_window = XCreateSimpleWindow(lock_observer, DefaultRootWindow(lock_observer),
                                    0, 0, 200, 100, 0, 0, 0);
  assert(lock_window != None);
  XSelectInput(lock_observer, lock_window, KeyPressMask | KeyReleaseMask);
  XMapWindow(lock_observer, lock_window);
  XSetInputFocus(lock_observer, lock_window, RevertToPointerRoot, CurrentTime);
  assert(XTestFakeKeyEvent(lock_observer, lock_owned_code, True, 0));
  assert(XTestFakeKeyEvent(lock_observer, lock_held_code, True, 0));
  lock_event(KeyPress, lock_owned_code);
  lock_event(KeyPress, lock_held_code);
}

int lock_modes_click(int caps) {
  Display *injector = __real_XOpenDisplay("unix/:98.0");
  assert(injector != NULL && injector != lock_observer);
  KeyCode code = caps ? lock_caps_code : lock_num_code;
  assert(XTestFakeKeyEvent(injector, code, True, 0));
  assert(XTestFakeKeyEvent(injector, code, False, 0));
  XSync(injector, False);
  assert(__real_XCloseDisplay(injector) == 0);
  return 0;
}

void lock_modes_check(int caps, int num, int caps_pair, int num_pair) {
  if (caps_pair) { lock_event(KeyPress, lock_caps_code); lock_event(KeyRelease, lock_caps_code); }
  if (num_pair) { lock_event(KeyPress, lock_num_code); lock_event(KeyRelease, lock_num_code); }
  XEvent event;
  XSync(lock_observer, False);
  assert(!XCheckWindowEvent(lock_observer, lock_window, KeyPressMask | KeyReleaseMask, &event));
  XkbStateRec state;
  assert(XkbGetState(lock_observer, XkbUseCoreKbd, &state) == Success
         && !!(state.locked_mods & LockMask) == caps
         && !!(state.locked_mods & lock_num_mask) == num);
  char keys[32], expected[32] = {0};
  expected[lock_owned_code / 8] |= (char)(1U << (lock_owned_code % 8));
  expected[lock_held_code / 8] |= (char)(1U << (lock_held_code % 8));
  assert(XQueryKeymap(lock_observer, keys) && !memcmp(keys, expected, sizeof(keys)));
}

void lock_modes_finish(void) {
  assert(XTestFakeKeyEvent(lock_observer, lock_owned_code, False, 0));
  lock_event(KeyRelease, lock_owned_code);
  char keys[32], expected[32] = {0};
  expected[lock_held_code / 8] = (char)(1U << (lock_held_code % 8));
  assert(XQueryKeymap(lock_observer, keys) && !memcmp(keys, expected, sizeof(keys)));
  assert(XTestFakeKeyEvent(lock_observer, lock_held_code, False, 0));
  lock_event(KeyRelease, lock_held_code);
  assert(XQueryKeymap(lock_observer, keys));
  for (int byte = 0; byte < 32; byte++) assert(keys[byte] == 0);
  assert(XkbLockModifiers(lock_observer, XkbUseCoreKbd, LockMask | lock_num_mask, lock_original_mods));
  XSetInputFocus(lock_observer, lock_previous_focus, lock_previous_revert, CurrentTime);
  XDestroyWindow(lock_observer, lock_window);
  assert(__real_XCloseDisplay(lock_observer) == 0);
  lock_observer = NULL;
}

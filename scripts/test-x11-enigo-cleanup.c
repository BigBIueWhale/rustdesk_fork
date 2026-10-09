/* Actual backend/provider composition; the observer owns a separate X11 connection. */
#define _POSIX_C_SOURCE 200809L
#include "../libs/libxdo-sys-stub/native/xdo.h"
#include <X11/XKBlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <string.h>

extern Display *__real_XOpenDisplay(const char *);
extern int __real_XCloseDisplay(Display *);

static Display *observer, *borrowed_display;
static Window window, previous_focus;
static int previous_revert, phase, refusals;
static Bool armed;
static xdo_t *pending;
static XkbDescPtr baseline, retained_original;
static KeyCode scratch_code;

/* Export only this symbol: DSO-internal calls do not use executable --wrap. */
Bool XkbChangeMap(Display *display, XkbDescPtr map, XkbMapChangesPtr changes) {
  typedef Bool (*change_map_fn)(Display *, XkbDescPtr, XkbMapChangesPtr);
  static change_map_fn native;
  if (native == NULL) {
    native = (change_map_fn)dlsym(RTLD_NEXT, "XkbChangeMap");
    assert(native != NULL);
  }
  if (armed && pending != NULL && display == borrowed_display
      && pending->scratch_original != NULL) {
    assert(phase == 0);
    refusals++;
    return False;
  }
  return native(display, map, changes);
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

void enigo_cleanup_begin(void) {
  assert(observer == NULL && pending == NULL && baseline == NULL);
  observer = __real_XOpenDisplay("unix/:98.0");
  assert(observer != NULL);
  phase = refusals = 0;
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
         && context->scratch_original == NULL);
  pending = context;
  borrowed_display = context->xdpy;
  armed = True;
}

void enigo_cleanup_pending(void) {
  assert(armed && phase == 0 && refusals == 1 && pending != NULL
         && pending->scratch_original != NULL && pending->xdpy == borrowed_display);
  retained_original = pending->scratch_original;
  scratch_code = pending->scratch_keycode;
  assert(scratch_code >= baseline->min_key_code && scratch_code <= baseline->max_key_code);
  XSync(borrowed_display, False);
  XkbDescPtr installed = snapshot();
  assert(XkbKeyNumSyms(installed, scratch_code) == 1
         && XkbKeySymsPtr(installed, scratch_code)[0] == 0x0101f642UL);
  for (int index = 0; index < XkbKeyNumSyms(baseline, scratch_code); index++)
    assert(XkbKeySymsPtr(baseline, scratch_code)[index] == NoSymbol);
  for (int leg = 0; leg < 2; leg++) {
    XEvent event;
    KeySym symbol = NoSymbol;
    unsigned int consumed;
    assert(XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event)
           && event.type == (leg == 0 ? KeyPress : KeyRelease)
           && event.xkey.window == window && !event.xkey.send_event
           && event.xkey.keycode == scratch_code
           && XkbTranslateKeyCode(installed, scratch_code, event.xkey.state, &consumed, &symbol)
           && symbol == 0x0101f642UL);
  }
  XkbFreeKeyboard(installed, 0, True);
  keys_clear();
  no_events();
}

void enigo_cleanup_allow_retirement(void) {
  assert(armed && phase == 0 && refusals == 1 && pending != NULL
         && pending->scratch_original == retained_original
         && pending->scratch_keycode == scratch_code);
  XSync(borrowed_display, False);
  keys_clear();
  no_events();
  armed = False;
}

void enigo_cleanup_before_free(xdo_t *context) {
  if (observer == NULL) return;
  assert(!armed && context != NULL && context->xdpy == borrowed_display);
  if (phase == 0) {
    assert(context == pending && !context->close_display_when_freed
           && context->scratch_original == retained_original
           && context->scratch_keycode == scratch_code);
    phase = 1;
  } else {
    assert(phase == 2 && context != pending && context->close_display_when_freed
           && context->scratch_original == NULL);
    /* A real request succeeds after child retirement and before owner close. */
    XSync(borrowed_display, False);
    phase = 3;
  }
}

void enigo_cleanup_after_free(xdo_t *context) {
  if (observer == NULL) return;
  /* Only compare identities; the native destructor already freed context. */
  if (phase == 1) {
    assert(context == pending);
    restored_components();
    keys_clear();
    no_events();
    phase = 2;
  } else {
    assert(phase == 3 && context != pending);
    phase = 4;
  }
}

void enigo_cleanup_finish(void) {
  assert(phase == 4 && !armed && refusals == 1);
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

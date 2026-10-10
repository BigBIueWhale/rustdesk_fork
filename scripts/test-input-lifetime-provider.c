/* Test-only instrumentation around the complete checked-in native provider. */
#define _XOPEN_SOURCE 500
#define xdo_new test_native_xdo_new
#define xdo_new_with_opened_display test_native_xdo_new_with_opened_display
#define xdo_free test_native_xdo_free
#define xdo_enter_text_scalar test_native_xdo_enter_text_scalar
#include "../libs/libxdo-sys-stub/native/xdo.c"
#undef xdo_new
#undef xdo_new_with_opened_display
#undef xdo_free
#undef xdo_enter_text_scalar
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>

static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;
static Display *observer;
static Window window, previous_focus, pointer_root;
static int previous_revert, pointer_x, pointer_y;
static XkbDescPtr baseline;
static xdo_t *main_owner, *pending_owner;
static KeyCode a_code, b_code, control_code, scratch_code;
static int fault_key, armed, refusals, main_frees, child_frees;
static Bool (*native_change_map)(Display *, XkbDescPtr, XkbMapChangesPtr);
static Bool (*native_key_event)(Display *, unsigned int, Bool, unsigned long);

static void hook_acquire(void) { assert(pthread_mutex_lock(&hook_lock) == 0); }
static void hook_release(void) { assert(pthread_mutex_unlock(&hook_lock) == 0); }

Bool XkbChangeMap(Display *display, XkbDescPtr map, XkbMapChangesPtr changes) {
  hook_acquire();
  int refuse = armed && !fault_key && pending_owner
      && display == pending_owner->xdpy && pending_owner->scratch_original;
  if (refuse) refusals++;
  hook_release();
  return refuse ? False : native_change_map(display, map, changes);
}

Bool XTestFakeKeyEvent(Display *display, unsigned int code, Bool press, unsigned long delay) {
  hook_acquire();
  int refuse = armed && fault_key && pending_owner && !press
      && display == pending_owner->xdpy && pending_owner->scratch_original
      && code == pending_owner->scratch_keycode;
  if (refuse) refusals++;
  hook_release();
  return refuse ? False : native_key_event(display, code, press, delay);
}

xdo_t *xdo_new_with_opened_display(Display *display, const char *name, int close_display) {
  xdo_t *context = test_native_xdo_new_with_opened_display(display, name, close_display);
  assert(context);
  hook_acquire();
  if (close_display) {
    assert(observer && !main_owner && !pending_owner && !armed);
    main_owner = context;
  } else {
    assert(main_owner && display == main_owner->xdpy && !pending_owner && !armed);
  }
  hook_release();
  return context;
}

xdo_t *xdo_new(const char *name) {
  Display *display = XOpenDisplay(name);
  assert(display);
  return xdo_new_with_opened_display(display, name, 1);
}

int xdo_enter_text_scalar(xdo_t *context, unsigned int scalar, useconds_t delay) {
  hook_acquire();
  assert(context != main_owner && !context->close_display_when_freed
         && main_owner && context->xdpy == main_owner->xdpy
         && !pending_owner && !armed && scalar == 0x1f642);
  pending_owner = context;
  armed = 1;
  hook_release();
  int status = test_native_xdo_enter_text_scalar(context, scalar, delay);
  hook_acquire();
  assert(status == XDO_CLEANUP_ERROR && refusals > 0 && context->scratch_original);
  scratch_code = context->scratch_keycode;
  assert(scratch_code >= baseline->min_key_code && scratch_code <= baseline->max_key_code
         && context->text_keys_len == (unsigned int)fault_key
         && (!fault_key || context->text_keys[0] == scratch_code));
  hook_release();
  return status;
}

int xdo_free(xdo_t *context) {
  hook_acquire();
  assert(context && (context == pending_owner || context == main_owner));
  int child = context == pending_owner;
  if (!child) assert(!pending_owner && child_frees == 1 && !armed);
  hook_release();
  int status = test_native_xdo_free(context);
  hook_acquire();
  if (status == XDO_SUCCESS) {
    if (child) { pending_owner = NULL; child_frees++; }
    else { main_owner = NULL; main_frees++; }
  }
  hook_release();
  return status;
}

static XkbDescPtr snapshot(void) {
  XkbDescPtr map = XkbGetMap(observer, XkbAllMapComponentsMask, XkbUseCoreKbd);
  assert(map && map->map && map->map->types && map->map->syms && map->map->key_sym_map
         && map->map->modmap && map->server && map->server->key_acts
         && map->server->behaviors && map->server->explicit && map->server->vmodmap
         && XkbGetControls(observer, XkbPerKeyRepeatMask, map) == Success && map->ctrls);
  return map;
}

static int restored_components(void) {
  XkbDescPtr actual = snapshot();
  int same = actual->min_key_code == baseline->min_key_code
      && actual->max_key_code == baseline->max_key_code
      && actual->map->num_types == baseline->map->num_types
      && !memcmp(actual->server->vmods, baseline->server->vmods, sizeof(actual->server->vmods))
      && !memcmp(actual->ctrls->per_key_repeat, baseline->ctrls->per_key_repeat,
                 sizeof(actual->ctrls->per_key_repeat));
  for (int index = 0; same && index < baseline->map->num_types; index++) {
    XkbKeyTypePtr a = &actual->map->types[index], b = &baseline->map->types[index];
    same = a->num_levels == b->num_levels && a->map_count == b->map_count
        && !memcmp(&a->mods, &b->mods, sizeof(a->mods))
        && (!a->map_count || !memcmp(a->map, b->map, a->map_count * sizeof(XkbKTMapEntryRec)))
        && !!a->preserve == !!b->preserve
        && (!a->preserve || !memcmp(a->preserve, b->preserve, a->map_count * sizeof(XkbModsRec)));
  }
  for (int code = baseline->min_key_code; same && code <= baseline->max_key_code; code++) {
    XkbSymMapPtr a = &actual->map->key_sym_map[code], b = &baseline->map->key_sym_map[code];
    same = a->group_info == b->group_info && a->width == b->width
        && !memcmp(a->kt_index, b->kt_index, sizeof(a->kt_index))
        && !memcmp(XkbKeySymsPtr(actual, code), XkbKeySymsPtr(baseline, code),
                   XkbKeyNumSyms(baseline, code) * sizeof(KeySym))
        && actual->map->modmap[code] == baseline->map->modmap[code]
        && actual->server->explicit[code] == baseline->server->explicit[code]
        && actual->server->vmodmap[code] == baseline->server->vmodmap[code]
        && !memcmp(&actual->server->behaviors[code], &baseline->server->behaviors[code], sizeof(XkbBehavior))
        && !!XkbKeyHasActions(actual, code) == !!XkbKeyHasActions(baseline, code)
        && (!XkbKeyHasActions(baseline, code)
            || !memcmp(XkbKeyActionsPtr(actual, code), XkbKeyActionsPtr(baseline, code),
                       XkbKeyNumActions(baseline, code) * sizeof(XkbAction)));
  }
  XkbFreeKeyboard(actual, 0, True);
  return same;
}

static int keys(int owned, int foreign, int scratch) {
  char actual[32], expected[32] = {0};
  if (owned) expected[a_code / 8] |= (char)(1U << (a_code % 8));
  if (foreign) {
    expected[b_code / 8] |= (char)(1U << (b_code % 8));
    expected[control_code / 8] |= (char)(1U << (control_code % 8));
  }
  if (scratch) expected[scratch_code / 8] |= (char)(1U << (scratch_code % 8));
  return XQueryKeymap(observer, actual) && !memcmp(actual, expected, sizeof(actual));
}

static int buttons(unsigned int expected) {
  Window root, child;
  int root_x, root_y, x, y;
  unsigned int mask;
  return XQueryPointer(observer, window, &root, &child, &root_x, &root_y, &x, &y, &mask)
      && (mask & (Button1Mask | Button2Mask | Button3Mask | Button4Mask | Button5Mask)) == expected;
}

static int event(int type, unsigned int code) {
  XEvent value;
  XSync(observer, False);
  if (!XCheckWindowEvent(observer, window,
                        KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask, &value))
    return 0;
  if (value.type != type || value.xany.window != window || value.xany.send_event) return 0;
  return type == KeyPress || type == KeyRelease
      ? value.xkey.keycode == code : value.xbutton.button == code;
}

static int no_events(void) {
  XEvent value;
  XSync(observer, False);
  return !XCheckWindowEvent(observer, window,
                           KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask, &value);
}

void input_lifetime_begin(int key_fault) {
  /* This hook is the first Xlib call in each fresh libtest process. */
  if (!native_change_map) {
    assert(XInitThreads());
    native_change_map = (Bool (*)(Display *, XkbDescPtr, XkbMapChangesPtr))dlsym(RTLD_NEXT, "XkbChangeMap");
    native_key_event = (Bool (*)(Display *, unsigned int, Bool, unsigned long))dlsym(RTLD_NEXT, "XTestFakeKeyEvent");
  }
  assert(native_change_map && native_key_event);
  assert(!observer && !main_owner && !pending_owner);
  observer = XOpenDisplay(NULL);
  assert(observer);
  baseline = snapshot();
  a_code = XKeysymToKeycode(observer, XK_a);
  b_code = XKeysymToKeycode(observer, XK_b);
  control_code = XKeysymToKeycode(observer, XK_Control_R);
  assert(a_code && b_code && control_code && !XKeysymToKeycode(observer, 0x0101f642UL));
  assert(keys(0, 0, 0) && buttons(0));
  XGetInputFocus(observer, &previous_focus, &previous_revert);
  Window child;
  int x, y;
  unsigned int mask;
  XQueryPointer(observer, DefaultRootWindow(observer), &pointer_root, &child,
                &pointer_x, &pointer_y, &x, &y, &mask);
  window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 100, 100, 0, 0, 0);
  assert(window);
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask);
  XMapWindow(observer, window);
  XSetInputFocus(observer, window, RevertToPointerRoot, CurrentTime);
  XWarpPointer(observer, None, window, 0, 0, 0, 0, 30, 30);
  XSync(observer, False);
  fault_key = key_fault != 0;
  armed = refusals = main_frees = child_frees = 0;
  scratch_code = 0;
  assert(no_events());
}

unsigned int input_lifetime_observe(int stage) {
  if (stage == 0) return event(KeyPress, a_code) && no_events() && keys(1, 0, 0) && buttons(0);
  if (stage == 1) return event(ButtonPress, 1) && no_events() && keys(1, 0, 0) && buttons(Button1Mask);
  if (stage == 2) return no_events() && keys(1, 0, 0) && buttons(Button1Mask);
  if (stage == 3) {
    hook_acquire();
    assert(armed && main_owner && pending_owner && refusals > 0
           && !child_frees && !main_frees && pending_owner->scratch_original);
    hook_release();
    XkbDescPtr installed = snapshot();
    int mapped = XkbKeyNumSyms(installed, scratch_code) == 1
        && XkbKeySymsPtr(installed, scratch_code)[0] == 0x0101f642UL;
    XkbFreeKeyboard(installed, 0, True);
    return mapped && event(KeyPress, scratch_code) && (fault_key || event(KeyRelease, scratch_code))
        && no_events() && keys(1, 0, fault_key) && buttons(Button1Mask) && !restored_components();
  }
  assert(stage == 4);
  int releases = event(KeyRelease, a_code) && event(ButtonRelease, 1);
  if (fault_key) releases = releases && event(KeyRelease, scratch_code);
  unsigned int outcome = (releases && no_events() && buttons(0)) ? 1U : 0U;
  if (keys(0, 1, 0)) outcome |= 2U;
  if (restored_components()) outcome |= 4U;
  hook_acquire();
  if (!main_owner && !pending_owner && child_frees == 1 && main_frees == 1 && !armed) outcome |= 8U;
  if (outcome != 15) {
    printf("INPUT_LIFETIME_PROVIDER_OBSERVED fault=%s child_frees=%d main_frees=%d refusals=%d native=%u\n",
           fault_key ? "key" : "map", child_frees, main_frees, refusals, outcome);
    assert(fflush(stdout) == 0);
  }
  hook_release();
  return outcome;
}

void input_lifetime_foreign(void) {
  assert(native_key_event(observer, b_code, True, CurrentTime));
  assert(native_key_event(observer, control_code, True, CurrentTime));
  XSync(observer, False);
  assert(event(KeyPress, b_code) && event(KeyPress, control_code) && no_events()
         && keys(1, 1, fault_key) && buttons(Button1Mask));
}

void input_lifetime_allow_retirement(void) {
  hook_acquire();
  assert(armed && pending_owner && main_owner);
  armed = 0;
  hook_release();
}

void input_lifetime_finish(void) {
  /* Only after observation and exact worker joins. On an old-code failure,
   * restore the private server without invalidating the retained Rust owners. */
  hook_acquire();
  armed = 0;
  hook_release();
  KeyCode codes[] = {a_code, b_code, control_code, scratch_code};
  for (unsigned int i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
    if (codes[i]) assert(native_key_event(observer, codes[i], False, CurrentTime));
  assert(XTestFakeButtonEvent(observer, 1, False, CurrentTime));
  XSync(observer, False);
  assert(XkbSetMap(observer, XkbAllMapComponentsMask, baseline));
  assert(XkbSetControls(observer, XkbPerKeyRepeatMask, baseline));
  XSync(observer, False);
  assert(restored_components() && keys(0, 0, 0) && buttons(0));
  XSetInputFocus(observer, previous_focus, previous_revert, CurrentTime);
  XWarpPointer(observer, None, pointer_root, 0, 0, 0, 0, pointer_x, pointer_y);
  XDestroyWindow(observer, window);
  XSync(observer, False);
  XkbFreeKeyboard(baseline, 0, True);
  assert(XCloseDisplay(observer) == 0);
  observer = NULL;
  baseline = NULL;
}

/* Test-only instrumentation around the complete checked-in native provider. */
#define _XOPEN_SOURCE 500
#define xdo_new test_native_xdo_new
#define xdo_new_with_opened_display test_native_xdo_new_with_opened_display
#define xdo_free test_native_xdo_free
#define xdo_enter_text_scalar test_native_xdo_enter_text_scalar
#define xdo_get_mouse_location test_native_xdo_get_mouse_location
#include "../libs/libxdo-sys-stub/native/xdo.c"
#undef xdo_new
#undef xdo_new_with_opened_display
#undef xdo_free
#undef xdo_enter_text_scalar
#undef xdo_get_mouse_location
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>

static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;
static Display *observer;
static Window window, previous_focus, pointer_root;
static int previous_revert, pointer_x, pointer_y;
static XkbDescPtr baseline;
static xdo_t *main_owner, *pending_owner;
static KeyCode a_code, b_code, control_code, scratch_code;
static int fault_key, armed, refusals, main_frees, child_frees, main_retiring;
static Bool (*native_change_map)(Display *, XkbDescPtr, XkbMapChangesPtr);
static Bool (*native_key_event)(Display *, unsigned int, Bool, unsigned long);
static pthread_cond_t cursor_changed = PTHREAD_COND_INITIALIZER;
static int cursor_mode, cursor_blocked, cursor_live, cursor_created, cursor_destroyed;
static int cursor_inflight, cursor_queries, cursor_positions, cursor_order;
static int cursor_x, cursor_y;
static int root_exit_armed, root_late_admitted;
static long root_cleanup_tid, root_wakelock_tid;
static int (*root_owners_valid)(void);

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
  if (cursor_mode) {
    assert(close_display);
    cursor_live++;
    cursor_created++;
    if (cursor_created == 2) cursor_order = cursor_destroyed == 1;
  } else if (close_display) {
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
  if (cursor_mode) {
    assert(context && context->close_display_when_freed && cursor_live > 0);
    hook_release();
    int status = test_native_xdo_free(context);
    hook_acquire();
    if (status == XDO_SUCCESS) { cursor_live--; cursor_destroyed++; }
    hook_release();
    return status;
  }
  assert(context && (context == pending_owner || context == main_owner));
  int child = context == pending_owner;
  if (!child) {
    if (pending_owner || child_frees != 1 || armed) {
      fprintf(stderr, "INPUT_LIFETIME_RETIREMENT_FAILURE pending=%d child_frees=%d main_frees=%d armed=%d\n",
              pending_owner != NULL, child_frees, main_frees, armed);
      assert(fflush(stderr) == 0);
    }
    assert(!pending_owner && child_frees == 1 && !armed);
    main_retiring = 1;
  }
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

int xdo_get_mouse_location(const xdo_t *context, int *x, int *y, int *screen) {
  hook_acquire();
  int observe = cursor_mode;
  if (observe) {
    cursor_inflight++;
    while (cursor_blocked)
      assert(pthread_cond_wait(&cursor_changed, &hook_lock) == 0);
  }
  hook_release();
  int status = test_native_xdo_get_mouse_location(context, x, y, screen);
  if (observe) {
    hook_acquire();
    cursor_inflight--;
    if (status == XDO_SUCCESS) {
      cursor_queries++;
      if (*x == cursor_x && *y == cursor_y) cursor_positions++;
    }
    hook_release();
  }
  return status;
}

void cursor_recorder_init(void) {
  assert(XInitThreads());
  assert(!observer && !main_owner && !pending_owner);
  observer = XOpenDisplay(NULL);
  assert(observer);
  Window child;
  int x, y;
  unsigned int mask;
  assert(XQueryPointer(observer, DefaultRootWindow(observer), &pointer_root, &child,
                       &pointer_x, &pointer_y, &x, &y, &mask));
  cursor_x = 21; cursor_y = 45;
  XWarpPointer(observer, None, DefaultRootWindow(observer), 0, 0, 0, 0, cursor_x, cursor_y);
  XSync(observer, False);
  cursor_mode = 1;
}

void cursor_recorder_begin(int generation) {
  hook_acquire();
  assert(cursor_mode && !cursor_live && !cursor_inflight);
  cursor_created = cursor_destroyed = cursor_queries = cursor_positions = cursor_order = 0;
  cursor_blocked = 1;
  cursor_x = 21 + generation; cursor_y = 45 + generation;
  hook_release();
  XWarpPointer(observer, None, DefaultRootWindow(observer), 0, 0, 0, 0, cursor_x, cursor_y);
  XSync(observer, False);
}

void cursor_recorder_allow(void) {
  hook_acquire();
  cursor_blocked = 0;
  assert(pthread_cond_broadcast(&cursor_changed) == 0);
  hook_release();
}

int cursor_recorder_probe(int field) {
  hook_acquire();
  int values[] = {cursor_live, cursor_created, cursor_destroyed, cursor_inflight,
                  cursor_queries, cursor_order, cursor_positions};
  assert(field >= 0 && field < 7);
  int value = values[field];
  hook_release();
  return value;
}

void cursor_recorder_finish(void) {
  hook_acquire();
  assert(cursor_mode && !cursor_live && !cursor_inflight);
  hook_release();
  XWarpPointer(observer, None, pointer_root, 0, 0, 0, 0, pointer_x, pointer_y);
  XSync(observer, False);
  assert(XCloseDisplay(observer) == 0);
  observer = NULL;
}

static long named_worker(const char *expected) {
  DIR *tasks = opendir("/proc/self/task");
  assert(tasks);
  struct dirent *entry;
  long found = 0;
  while ((entry = readdir(tasks))) {
    char *end;
    long tid = strtol(entry->d_name, &end, 10);
    if (*end || tid <= 0 || tid > INT_MAX) continue;
    char path[128], name[64];
    int length = snprintf(path, sizeof(path), "/proc/self/task/%ld/comm", tid);
    assert(length > 0 && length < (int)sizeof(path));
    FILE *file = fopen(path, "r");
    if (!file) { assert(errno == ENOENT); continue; }
    assert(fgets(name, sizeof(name), file));
    assert(fclose(file) == 0);
    name[strcspn(name, "\n")] = 0;
    if (!strcmp(name, expected)) { assert(!found); found = tid; }
  }
  assert(closedir(tasks) == 0);
  return found;
}

int connection_workers_ready(void) {
  return named_worker("rustdesk-final-") > 0 && named_worker("rustdesk-wakelo") > 0;
}

void connection_workers_arm(void) {
  long cleanup = named_worker("rustdesk-final-");
  long wakelock = named_worker("rustdesk-wakelo");
  assert(cleanup > 0 && wakelock > 0 && cleanup != wakelock);
  hook_acquire();
  assert(cursor_mode && cursor_live == 1 && cursor_positions > 0 && !root_exit_armed);
  root_cleanup_tid = cleanup; root_wakelock_tid = wakelock;
  cursor_blocked = 1;
  root_exit_armed = 1;
  hook_release();
}

static void connection_workers_arm_unstarted(int (*owners_valid)(void), int mode) {
  assert(owners_valid && owners_valid() == 1);
  assert(!named_worker("rustdesk-final-") && !named_worker("rustdesk-wakelo")
         && !named_worker("cursor-recorder"));
  hook_acquire();
  assert(!root_exit_armed && !observer && !main_owner && !pending_owner
         && !cursor_mode && !cursor_live && !cursor_created && !cursor_destroyed
         && !cursor_inflight);
  root_owners_valid = owners_valid;
  root_late_admitted = -1;
  root_exit_armed = mode;
  hook_release();
}

void connection_workers_arm_empty(int (*owners_uninitialized)(void)) {
  connection_workers_arm_unstarted(owners_uninitialized, 2);
}

void connection_workers_arm_failed_start(int (*cleanup_failed)(void)) {
  connection_workers_arm_unstarted(cleanup_failed, 3);
}

void connection_workers_late_admission(int admitted) {
  hook_acquire();
  assert(root_exit_armed);
  root_late_admitted = admitted != 0;
  hook_release();
}

static int task_exists(long tid) {
  char path[128];
  int length = snprintf(path, sizeof(path), "/proc/self/task/%ld", tid);
  assert(length > 0 && length < (int)sizeof(path));
  struct stat metadata;
  if (stat(path, &metadata) == 0) return 1;
  assert(errno == ENOENT);
  return 0;
}

/* Observe the real production process::exit boundary before the kernel kills other threads.
 * Other cases leave this observer unarmed. This hook never reaps a Rust-owned resource. */
__attribute__((destructor)) static void connection_workers_at_exit(void) {
  hook_acquire();
  int armed_exit = root_exit_armed;
  int cursor_retired = cursor_live == 0 && cursor_inflight == 0
      && cursor_created == 1 && cursor_destroyed == 1 && cursor_positions > 0;
  int cursor_unstarted = !cursor_mode && !cursor_live && !cursor_inflight
      && !cursor_created && !cursor_destroyed && !observer && !main_owner && !pending_owner;
  int (*owners_valid)(void) = root_owners_valid;
  int late_admitted = root_late_admitted;
  hook_release();
  if (!armed_exit) return;
  if (armed_exit == 2 || armed_exit == 3) {
    assert(owners_valid);
    int owners_expected = owners_valid() == 1;
    long cleanup = named_worker("rustdesk-final-");
    long wakelock = named_worker("rustdesk-wakelo");
    long cursor = named_worker("cursor-recorder");
    const char *prefix = armed_exit == 2 ? "CONNECTION_WORKERS_EMPTY" : "CONNECTION_WORKERS_FAILED_START";
    const char *ownership = armed_exit == 2 ? "owners_uninitialized" : "cleanup_failed";
    printf("%s_OBSERVED %s=%d cleanup_tid=%ld wakelock_tid=%ld cursor_tid=%ld cursor_unstarted=%d late_admitted=%d\n",
           prefix, ownership, owners_expected, cleanup, wakelock, cursor, cursor_unstarted, late_admitted);
    assert(fflush(stdout) == 0);
    const char *receipt = owners_expected && !cleanup && !wakelock && !cursor
        && cursor_unstarted && late_admitted == 0
        ? (armed_exit == 2
           ? "CONNECTION_WORKERS_EMPTY_NATIVE=pass boundary=graceful-process-exit owners=uninitialized named_workers=absent cursor=unstarted late_sessions=refused types=all-five producer=resource-factory network_auth=false os_inhibitor=false\n"
           : "CONNECTION_WORKERS_FAILED_START_NATIVE=pass boundary=graceful-process-exit cleanup=failed-start wakelock=uninitialized named_workers=absent cursor=unstarted late_sessions=refused types=all-five producer=resource-factory network_auth=false os_inhibitor=false\n")
        : (armed_exit == 2
           ? "CONNECTION_WORKERS_EMPTY_NATIVE=observed retirement=incomplete\n"
           : "CONNECTION_WORKERS_FAILED_START_NATIVE=observed retirement=incomplete\n");
    const char *path = armed_exit == 2 ? "/tmp/input-lifetime-empty-shutdown.receipt"
                                     : "/tmp/input-lifetime-failed-start.receipt";
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    size_t length = strlen(receipt);
    assert(write(fd, receipt, length) == (ssize_t)length);
    assert(close(fd) == 0);
    return;
  }
  int cleanup_alive = task_exists(root_cleanup_tid);
  int wakelock_alive = task_exists(root_wakelock_tid);
  printf("CONNECTION_WORKERS_OBSERVED cleanup_tid=%ld cleanup_alive=%d wakelock_tid=%ld wakelock_alive=%d cursor_retired=%d late_admitted=%d\n",
         root_cleanup_tid, cleanup_alive, root_wakelock_tid, wakelock_alive,
         cursor_retired, late_admitted);
  assert(fflush(stdout) == 0);
  if (cursor_retired) cursor_recorder_finish();
  const char *receipt = !cleanup_alive && !wakelock_alive && cursor_retired && !late_admitted
      ? "CONNECTION_WORKERS_NATIVE=pass boundary=graceful-process-exit final_remote=joined wakelock=joined cursor=retired late_sessions=refused types=all-five producer=resource-factory network_auth=false os_inhibitor=false\n"
      : "CONNECTION_WORKERS_NATIVE=observed retirement=incomplete\n";
  int fd = open("/tmp/input-lifetime-shutdown.receipt", O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(fd >= 0);
  size_t length = strlen(receipt);
  assert(write(fd, receipt, length) == (ssize_t)length);
  assert(close(fd) == 0);
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
  assert(keys(0, 0, 0));
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
  armed = refusals = main_frees = child_frees = main_retiring = 0;
  scratch_code = 0;
  assert(no_events() && buttons(0));
}

void input_lifetime_sync(void) {
  /* The queue has drained, but XFlush alone does not establish server completion.
   * Fence the producer's retained Display without discarding any observed event. */
  hook_acquire();
  assert(main_owner && !main_retiring && !pending_owner && !armed);
  XSync(main_owner->xdpy, False);
  hook_release();
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

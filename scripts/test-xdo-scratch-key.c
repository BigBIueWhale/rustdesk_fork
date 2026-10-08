/* Isolated native scratch-key bounds and query-failure regression. */
#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libs/libxdo-sys-stub/native/xdo.h"

static Display *product_display;
static int observe, fault, queries, frees;
static int state_fault, state_queries, group_changes, input_calls, mapping_changes;
static KeySym *owned_query;
extern KeySym *__real_XGetKeyboardMapping(Display *, KeyCode, int, int *);
extern int __real_XFree(void *);
extern Status __real_XkbGetState(Display *, unsigned int, XkbStatePtr);
extern Bool __real_XkbLockGroup(Display *, unsigned int, unsigned int);
extern int __real_XTestFakeKeyEvent(Display *, unsigned int, Bool, unsigned long);
extern int __real_XChangeKeyboardMapping(Display *, int, int, KeySym *, int);
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern char *__real_strdup(const char *);

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "XDO_SCRATCH_FAILURE=%s\n", message);
    exit(1);
  }
}

Status __wrap_XkbGetState(Display *display, unsigned int device, XkbStatePtr state) {
  if (!observe || display != product_display)
    return __real_XkbGetState(display, device, state);
  state_queries++;
  if (state_fault == 1) return BadAccess;
  if (state_fault == 2) return BadImplementation;
  Status status = __real_XkbGetState(display, device, state);
  if (state_fault == 3) {
    require(status == Success, "real keyboard state unavailable");
    state->group = XkbNumKbdGroups;
  }
  return status;
}

Bool __wrap_XkbLockGroup(Display *display, unsigned int device, unsigned int group) {
  if (observe && display == product_display) group_changes++;
  return __real_XkbLockGroup(display, device, group);
}

int __wrap_XTestFakeKeyEvent(Display *display, unsigned int code, Bool pressed, unsigned long delay) {
  if (observe && display == product_display) input_calls++;
  return __real_XTestFakeKeyEvent(display, code, pressed, delay);
}

int __wrap_XChangeKeyboardMapping(Display *display, int first, int width, KeySym *symbols, int count) {
  if (observe && display == product_display) mapping_changes++;
  return __real_XChangeKeyboardMapping(display, first, width, symbols, count);
}

KeySym *__wrap_XGetKeyboardMapping(Display *display, KeyCode first, int count, int *width) {
  if (!observe || display != product_display)
    return __real_XGetKeyboardMapping(display, first, count, width);
  queries++;
  require(owned_query == NULL, "previous native query not retired");
  if (fault == 1) { *width = 0; return NULL; }
  owned_query = __real_XGetKeyboardMapping(display, first, count, width);
  require(owned_query != NULL && *width > 0, "real native query unavailable");
  if (fault == 2) *width = 0;
  return owned_query;
}

int __wrap_XFree(void *pointer) {
  if (pointer && pointer == owned_query) { owned_query = NULL; frees++; }
  return __real_XFree(pointer);
}

/* Only direct product calls are wrapped; Xlib's internal heap is outside this census. */
void *__wrap_malloc(size_t size) {
  require(!observe, "key request allocated storage");
  return __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size) {
  require(!observe, "key request allocated storage");
  return __real_calloc(count, size);
}
void *__wrap_realloc(void *pointer, size_t size) {
  require(!observe, "key request grew storage");
  return __real_realloc(pointer, size);
}
char *__wrap_strdup(const char *text) {
  require(!observe, "key request copied text");
  return __real_strdup(text);
}

static int entries(const char *path) {
  DIR *directory = opendir(path);
  require(directory != NULL, "resource inventory unavailable");
  int count = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(directory)) != NULL)
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
  require(errno == 0 && closedir(directory) == 0, "resource inventory failed");
  return count;
}

static void clear_keys(Display *display) {
  char keys[32];
  require(XQueryKeymap(display, keys), "key state unavailable");
  for (int i = 0; i < 32; i++) require(keys[i] == 0, "a physical key remained held");
}

static void events(Display *observer, Window window, int keycode, int expected) {
  XSync(observer, False);
  for (int index = 0; index < expected; index++) {
    XEvent event;
    require(XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event),
            "native key event missing");
    require(event.type == (index == 0 ? KeyPress : KeyRelease)
            && event.xkey.window == window && !event.xkey.send_event
            && event.xkey.keycode == (unsigned)keycode && event.xkey.state == 0,
            "native key event differs");
  }
  XEvent extra;
  require(!XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &extra),
          "unexpected native key event");
  clear_keys(observer);
}

static void same_map(Display *display, int low, int count, int width, const KeySym *expected) {
  int actual_width;
  KeySym *actual = XGetKeyboardMapping(display, low, count, &actual_width);
  require(actual && actual_width == width
          && !memcmp(actual, expected, count * width * sizeof(KeySym)), "keyboard map changed");
  XFree(actual);
}

static void scratch_map(const KeySym *mapping, int count, int width, int last_empty) {
  for (int row = 0; row < count; row++) {
    int empty = 1;
    for (int column = 0; column < width; column++)
      if (mapping[row * width + column] != NoSymbol) empty = 0;
    require(empty == (last_empty && row == count - 1), "scratch map setup differs");
  }
}

static void keyboard_state(xdo_t *input, Display *observer, Window window,
                           int low, int high, int width, const KeySym *mapping) {
  struct request { unsigned kind; unsigned long value; int code; };
  const struct request keys[] = {
    {XDO_KEYSYM, XK_F30, low}, {XDO_KEYCODE, low + 1, low + 1},
    {XDO_KEYSYM, 0x0101f642, high},
  };
  fault = 0;
  for (int failure = 1; failure <= 3; failure++) {
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
      for (unsigned action = XDO_KEY_DOWN; action <= XDO_KEY_CLICK; action++) {
        XkbStateRec before = {0}, after = {0};
        require(XkbGetState(observer, XkbUseCoreKbd, &before) == Success,
                "observer keyboard state unavailable");
        queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
        state_fault = failure;
        observe = 1;
        int status = xdo_send_key_window(input, CURRENTWINDOW, keys[index].kind,
                                         keys[index].value, action, 0);
        observe = 0;
        require(status == XDO_ERROR && state_queries == 1 && group_changes == 0
                && input_calls == 0 && mapping_changes == 0 && queries == 0
                && frees == 0 && owned_query == NULL, "keyboard-state refusal has effects");
        events(observer, window, 0, 0);
        same_map(observer, low, high - low + 1, width, mapping);
        require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
                && !memcmp(&before, &after, sizeof(before)), "keyboard-state refusal changed state");

        state_fault = 0;
        queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
        observe = 1;
        status = xdo_send_key_window(input, CURRENTWINDOW, keys[index].kind,
                                     keys[index].value, XDO_KEY_CLICK, 0);
        observe = 0;
        int scratch = index == 2;
        require(status == XDO_SUCCESS && state_queries == 1 && group_changes == 4
                && input_calls == 2 && mapping_changes == 2 * scratch
                && queries == scratch && frees == scratch && owned_query == NULL,
                "keyboard-state recovery ownership differs");
        events(observer, window, keys[index].code, 2);
        same_map(observer, low, high - low + 1, width, mapping);
        require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
                && !memcmp(&before, &after, sizeof(before)), "keyboard-state recovery changed state");
      }
    }
  }
}

static void key_input(xdo_t *input, Display *observer, Window window, int low, int high) {
  struct request { unsigned kind; unsigned long value; unsigned action; };
  const struct request invalid[] = {
    {0, XK_a, XDO_KEY_CLICK}, {3, XK_a, XDO_KEY_CLICK},
    {XDO_KEYSYM, XK_a, 0}, {XDO_KEYSYM, XK_a, 4},
    {XDO_KEYCODE, 0, XDO_KEY_CLICK}, {XDO_KEYCODE, 7, XDO_KEY_CLICK},
    {XDO_KEYCODE, 256, XDO_KEY_CLICK}, {XDO_KEYCODE, 65535, XDO_KEY_CLICK},
    {XDO_KEYCODE, ULONG_MAX, XDO_KEY_CLICK},
    {XDO_KEYSYM, NoSymbol, XDO_KEY_CLICK}, {XDO_KEYSYM, XK_VoidSymbol, XDO_KEY_CLICK},
    {XDO_KEYSYM, 0x20000000, XDO_KEY_CLICK}, {XDO_KEYSYM, ULONG_MAX, XDO_KEY_CLICK},
    {XDO_KEYSYM, 0x01000000, XDO_KEY_CLICK}, {XDO_KEYSYM, 0x010000ff, XDO_KEY_CLICK},
    {XDO_KEYSYM, 0x0100d800, XDO_KEY_CLICK}, {XDO_KEYSYM, 0x0100dfff, XDO_KEY_CLICK},
    {XDO_KEYSYM, 0x01110000, XDO_KEY_CLICK},
  };
  queries = frees = fault = 0;
  observe = 1;
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    struct request request = invalid[i];
    require(xdo_send_key_window(input, CURRENTWINDOW, request.kind, request.value, request.action, 0)
            == XDO_ERROR, "invalid key request admitted");
    events(observer, window, 0, 0);
  }
  xdo_t empty = {0};
  require(xdo_send_key_window(NULL, CURRENTWINDOW, XDO_KEYSYM, XK_a, XDO_KEY_CLICK, 0) == XDO_ERROR
          && xdo_send_key_window(&empty, CURRENTWINDOW, XDO_KEYSYM, XK_a, XDO_KEY_CLICK, 0) == XDO_ERROR,
          "unavailable context admitted");
  for (int field = 0; field < 3; field++) {
    xdo_t changed = *input;
    if (field == 0) changed.keycode_low = 7;
    if (field == 1) changed.keycode_high = 256;
    if (field == 2) changed.keycode_high = changed.keycode_low - 1;
    require(xdo_send_key_window(&changed, CURRENTWINDOW, XDO_KEYCODE, low, XDO_KEY_CLICK, 0) == XDO_ERROR,
            "invalid native range admitted");
  }
  events(observer, window, 0, 0);
  require(queries == 0 && frees == 0, "refusal queried scratch storage");
  require(xdo_send_key_window(input, CURRENTWINDOW, XDO_KEYCODE, low, XDO_KEY_CLICK, 0) == XDO_SUCCESS,
          "lowest raw code refused");
  events(observer, window, low, 2);
  require(xdo_send_key_window(input, CURRENTWINDOW, XDO_KEYCODE, high, XDO_KEY_CLICK, 0) == XDO_SUCCESS,
          "highest raw code refused");
  events(observer, window, high, 2);
  require(xdo_send_key_window(input, CURRENTWINDOW, XDO_KEYSYM, XK_F30, XDO_KEY_CLICK, 0) == XDO_SUCCESS,
          "mapped keysym refused");
  events(observer, window, low, 2);
  require(queries == 0 && frees == 0, "mapped request queried scratch storage");
  require(xdo_send_key_window(input, CURRENTWINDOW, XDO_KEYSYM, 0x0101f642, XDO_KEY_CLICK, 0) == XDO_SUCCESS,
          "unmapped click refused");
  events(observer, window, high, 2);
  require(queries == 1 && frees == 1 && owned_query == NULL,
          "click reacquired storage instead of releasing its pressed code");
  observe = 0;
}

int main(void) {
  setbuf(stdout, NULL);
  int descriptors = entries("/proc/self/fd"), tasks = entries("/proc/self/task");
  Display *observer = XOpenDisplay("unix/:98.0");
  require(observer != NULL, "observer unavailable");
  clear_keys(observer);
  int low, high, width;
  XDisplayKeycodes(observer, &low, &high);
  require(low >= 8 && high <= 255 && high > low + 1, "native keycode range differs");
  int count = high - low + 1;
  KeySym *initial = XGetKeyboardMapping(observer, low, count, &width);
  require(initial && width > 0, "initial keyboard map unavailable");
  int initial_width = width;
  XFree(initial);
  Window window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 120, 80, 0, 0, 0);
  require(window != None, "owned window unavailable");
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
  XMapWindow(observer, window);
  XSetInputFocus(observer, window, RevertToParent, CurrentTime);
  XSync(observer, False);
  xdo_t *input = xdo_new("unix/:98.0");
  require(input != NULL, "product context unavailable");
  charcodemap_t key = {.code = XKeysymToKeycode(observer, XK_a), .symbol = XK_a};
  require(key.code != 0, "positive control key absent");
  require(!xdo_send_key_window(input, CURRENTWINDOW, XDO_KEYSYM, XK_a, XDO_KEY_CLICK, 0),
          "mapped positive control failed");
  events(observer, window, key.code, 2);
  xdo_free(input);
  puts("XDO_SCRATCH_CONTROL=pass key=a events=2");
  for (int round = 0; round < 4; round++) {
    width = initial_width;
    KeySym *mapping = malloc(count * width * sizeof(KeySym));
    require(mapping != NULL, "fixture map allocation failed");
    for (int i = 0; i < count * width; i++) mapping[i] = XK_F30;
    memset(mapping + (count - 1) * width, 0, width * sizeof(KeySym));
    XChangeKeyboardMapping(observer, low, width, mapping, count);
    XSync(observer, False);
    free(mapping);
    mapping = XGetKeyboardMapping(observer, low, count, &width);
    require(mapping && width > 0, "canonical fixture map unavailable");
    scratch_map(mapping, count, width, 1);
    same_map(observer, low, count, width, mapping);
    input = xdo_new("unix/:98.0");
    require(input != NULL, "fresh product context unavailable");
    product_display = input->xdpy;
    keyboard_state(input, observer, window, low, high, width, mapping);
    key_input(input, observer, window, low, high);
    same_map(observer, low, count, width, mapping);
    for (int scenario = 0; scenario < 5; scenario++) {
      if (scenario == 4) {
        for (int i = 0; i < width; i++) mapping[(count - 1) * width + i] = XK_F30;
        XChangeKeyboardMapping(observer, high, width, mapping + (count - 1) * width, 1);
        XSync(observer, False);
        XFree(mapping);
        mapping = XGetKeyboardMapping(observer, low, count, &width);
        require(mapping && width > 0, "canonical full map unavailable");
        scratch_map(mapping, count, width, 0);
        same_map(observer, low, count, width, mapping);
      }
      key = (charcodemap_t){.code = low + 1, .symbol = XK_F30};
      if (scenario != 1) key = (charcodemap_t){.symbol = 0x0101F642, .needs_binding = 1};
      fault = scenario == 2 ? 1 : scenario == 3 ? 2 : 0;
      queries = frees = 0;
      observe = 1;
      printf("XDO_SCRATCH_ENTER round=%d scenario=%d highest=%d\n", round, scenario, high);
      unsigned kind = scenario == 1 ? XDO_KEYCODE : XDO_KEYSYM;
      unsigned long value = scenario == 1 ? low + 1 : key.symbol;
      int down = xdo_send_key_window(input, CURRENTWINDOW, kind, value, XDO_KEY_DOWN, 0);
      int up = xdo_send_key_window(input, CURRENTWINDOW, kind, value, XDO_KEY_UP, 0);
      observe = 0;
      int accepted = scenario < 2;
      require(accepted ? down == XDO_SUCCESS && up == XDO_SUCCESS
                       : down == XDO_ERROR && up == XDO_ERROR, "native outcome differs");
      require(owned_query == NULL && queries == (scenario == 1 ? 0 : 2)
              && frees == (scenario == 1 || scenario == 2 ? 0 : 2), "query ownership differs");
      events(observer, window, scenario == 0 ? high : low + 1, accepted ? 2 : 0);
      same_map(observer, low, count, width, mapping);
      printf("XDO_SCRATCH_CASE=pass round=%d scenario=%d events=%d queries=%d frees=%d\n",
             round, scenario, accepted ? 2 : 0, queries, frees);
    }
    product_display = NULL;
    xdo_free(input);
    XFree(mapping);
  }
  XDestroyWindow(observer, window);
  XCloseDisplay(observer);
  require(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks,
          "native descriptors/tasks retained");
  puts("XDO_SCRATCH_NATIVE=pass cases=20 repeats=4 highest=delivered mapped_query=absent missing_map=refused invalid_width=refused full_map=refused events=16 maps=unchanged queries=32 frees=24 descriptors=retired tasks=retired sanitizer=address leak_scope=unclaimed whole_app=false");
  puts("XDO_KEY_INPUT_NATIVE=pass cases=108 repeats=4 refused=92 accepted=16 events=32 raw=both-boundaries invalid=pre-input-refused key_storage=stack product_allocations=0 click_queries=4 click_frees=4 maps=unchanged keys=clear descriptors=retired tasks=retired sanitizer=address whole_heap=false whole_app=false");
  puts("XDO_KEY_STATE_NATIVE=pass cases=108 repeats=4 faults=3 kinds=3 actions=3 refused=108 recovery=108 events=216 state_queries=216 click_snapshot=single refusal_effects=none maps=unchanged keys=clear descriptors=retired tasks=retired sanitizer=address whole_app=false");
  return 0;
}

/* Native corrected-constructor allocation, map and display ownership checks. */
#define _POSIX_C_SOURCE 200809L
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libs/libxdo-sys-stub/native/xdo.h"

enum fault {
  HEALTHY, NO_XTEST, CONTEXT_ALLOCATION, CHARACTER_ALLOCATION, NO_DESCRIPTOR,
  NO_CLIENT_MAP, NO_TYPES, NO_SYMBOL_MAP, NO_SYMBOLS, NO_MODIFIERS,
  LOW_KEYCODE, INVERTED_RANGE, TYPE_COUNT, SYMBOL_COUNT, GROUP_COUNT,
  SYMBOL_OFFSET, ZERO_WIDTH, TYPE_INDEX, ZERO_LEVELS, LEVEL_COUNT,
  NO_TYPE_MAP, TYPE_MAP_LEVEL, EMPTY_MAP, FAULT_COUNT
};
static enum fault fault;
static int observing, allocation_calls, allocations, releases, queries, maps, map_frees, closes, xtest_queries;
static void *owned[2];
static size_t character_count;
static Display *product_display;
static XkbDescPtr owned_map;
static XkbDescRec original_descriptor;
static XkbClientMapRec original_map;
static XkbSymMapRec original_symbols[256];
static XkbKeyTypeRec original_type;
static XkbKTMapEntryRec original_entry;
static int type_index;
extern void *__real_calloc(size_t, size_t);
extern void __real_free(void *);
extern Display *__real_XOpenDisplay(const char *);
extern int __real_XCloseDisplay(Display *);
extern Bool __real_XTestQueryExtension(Display *, int *, int *, int *, int *);
extern XkbDescPtr __real_XkbGetMap(Display *, unsigned, unsigned);
extern void __real_XkbFreeKeyboard(XkbDescPtr, unsigned, Bool);
extern KeySym *__real_XGetKeyboardMapping(Display *, KeyCode, int, int *);
extern KeySym __real_XkbKeycodeToKeysym(Display *, KeyCode, int, int);
extern XModifierKeymap *__real_XGetModifierMapping(Display *);

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "XDO_CONSTRUCTOR_FAILURE=%s fault=%d\n", message, fault);
    exit(1);
  }
}

void *__wrap_calloc(size_t count, size_t size) {
  if (!observing) return __real_calloc(count, size);
  allocation_calls++;
  require(allocation_calls <= 2, "constructor allocation budget differs");
  if (allocation_calls == 1) require(count == 1 && size == sizeof(xdo_t), "context allocation differs");
  else {
    require(count > 0 && count <= 248 * 4 * 255 && size == sizeof(charcodemap_t),
            "character allocation is not protocol-bounded");
    character_count = count;
  }
  if ((fault == CONTEXT_ALLOCATION && allocation_calls == 1)
      || (fault == CHARACTER_ALLOCATION && allocation_calls == 2)) return NULL;
  void *pointer = __real_calloc(count, size);
  require(pointer != NULL && allocations < 2, "real allocation unavailable");
  owned[allocations++] = pointer;
  return pointer;
}

void __wrap_free(void *pointer) {
  if (pointer) {
    for (int i = 0; i < 2; i++) {
      if (pointer == owned[i]) { owned[i] = NULL; releases++; break; }
    }
  }
  __real_free(pointer);
}

Display *__wrap_XOpenDisplay(const char *name) {
  Display *display = __real_XOpenDisplay(name);
  if (observing) {
    require(product_display == NULL && display != NULL, "internal native display open differs");
    product_display = display;
  }
  return display;
}

int __wrap_XCloseDisplay(Display *display) {
  require(display == product_display && closes == 0, "native display closed twice or without ownership");
  closes++;
  return __real_XCloseDisplay(display);
}

XkbDescPtr __wrap_XkbGetMap(Display *display, unsigned which, unsigned device) {
  if (!observing) return __real_XkbGetMap(display, which, device);
  require(display == product_display && which == XkbAllClientInfoMask && device == XkbUseCoreKbd,
          "constructor snapshot request differs");
  queries++;
  require(queries == 1 && owned_map == NULL, "constructor queried another snapshot");
  if (fault == NO_DESCRIPTOR) return NULL;
  owned_map = __real_XkbGetMap(display, which, device);
  require(owned_map && owned_map->map && owned_map->min_key_code >= 8
          && owned_map->max_key_code >= owned_map->min_key_code,
          "native fixture snapshot unavailable");
  maps++;
  original_descriptor = *owned_map;
  original_map = *owned_map->map;
  memcpy(original_symbols, original_map.key_sym_map,
         (original_descriptor.max_key_code + 1) * sizeof(XkbSymMapRec));
  int keycode;
  for (keycode = owned_map->min_key_code; keycode <= owned_map->max_key_code; keycode++) {
    if (XkbKeyNumGroups(owned_map, keycode) && XkbKeyKeyType(owned_map, keycode, 0)->map_count) break;
  }
  require(keycode <= owned_map->max_key_code, "native mapped type control absent");
  XkbSymMapPtr symbols = &original_map.key_sym_map[keycode];
  type_index = symbols->kt_index[0];
  XkbKeyTypePtr type = &original_map.types[type_index];
  original_type = *type;
  original_entry = type->map[0];
  switch (fault) {
    case NO_CLIENT_MAP: owned_map->map = NULL; break;
    case NO_TYPES: owned_map->map->types = NULL; break;
    case NO_SYMBOL_MAP: owned_map->map->key_sym_map = NULL; break;
    case NO_SYMBOLS: owned_map->map->syms = NULL; break;
    case NO_MODIFIERS: owned_map->map->modmap = NULL; break;
    case LOW_KEYCODE: owned_map->min_key_code = 7; break;
    case INVERTED_RANGE: owned_map->max_key_code = owned_map->min_key_code - 1; break;
    case TYPE_COUNT: owned_map->map->size_types = owned_map->map->num_types - 1; break;
    case SYMBOL_COUNT: owned_map->map->size_syms = owned_map->map->num_syms - 1; break;
    case GROUP_COUNT: symbols->group_info = 5; break;
    case SYMBOL_OFFSET: symbols->offset = original_map.num_syms; break;
    case ZERO_WIDTH: symbols->width = 0; break;
    case TYPE_INDEX: symbols->kt_index[0] = original_map.num_types; break;
    case ZERO_LEVELS: type->num_levels = 0; break;
    case LEVEL_COUNT:
      require(symbols->width < 255, "native level-count control unavailable");
      type->num_levels = symbols->width + 1; break;
    case NO_TYPE_MAP: type->map = NULL; break;
    case TYPE_MAP_LEVEL: type->map[0].level = type->num_levels; break;
    case EMPTY_MAP:
      for (int i = owned_map->min_key_code; i <= owned_map->max_key_code; i++)
        original_map.key_sym_map[i].group_info = 0;
      break;
    default: break;
  }
  return owned_map;
}

Bool __wrap_XTestQueryExtension(Display *display, int *event, int *error, int *major, int *minor) {
  if (observing) {
    require(display == product_display && allocation_calls == 0 && queries == 0,
            "XTEST admission followed allocation or keymap query");
    require(++xtest_queries == 1, "XTEST admission queried again");
    if (fault == NO_XTEST) return False;
  }
  return __real_XTestQueryExtension(display, event, error, major, minor);
}

void __wrap_XkbFreeKeyboard(XkbDescPtr descriptor, unsigned which, Bool all) {
  require(descriptor == owned_map && which == 0 && all == True, "snapshot retirement differs");
  *descriptor = original_descriptor;
  *descriptor->map = original_map;
  memcpy(descriptor->map->key_sym_map, original_symbols,
         (descriptor->max_key_code + 1) * sizeof(XkbSymMapRec));
  descriptor->map->types[type_index] = original_type;
  descriptor->map->types[type_index].map[0] = original_entry;
  owned_map = NULL;
  map_frees++;
  __real_XkbFreeKeyboard(descriptor, which, all);
}

/* Constructor sizing and symbols may not come from a second live map. */
KeySym *__wrap_XGetKeyboardMapping(Display *display, KeyCode first, int count, int *width) {
  require(!observing, "constructor queried the core symbol map");
  return __real_XGetKeyboardMapping(display, first, count, width);
}
KeySym __wrap_XkbKeycodeToKeysym(Display *display, KeyCode code, int group, int level) {
  require(!observing, "constructor queried live symbols after snapshot");
  return __real_XkbKeycodeToKeysym(display, code, group, level);
}
XModifierKeymap *__wrap_XGetModifierMapping(Display *display) {
  require(!observing, "constructor queried a separate modifier map");
  return __real_XGetModifierMapping(display);
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

static void delivered(xdo_t *context, Display *observer, Window window) {
  require(character_count == (size_t)context->charcodes_len, "character allocation and publication differ");
  charcodemap_t key = {0};
  int upper = 0, modifier = 0;
  for (int i = 0; i < context->charcodes_len; i++) {
    charcodemap_t entry = context->charcodes[i];
    if (entry.symbol == XK_a && entry.group == 0 && entry.modmask == 0) key = entry;
    if (entry.symbol == XK_A && entry.group == 0 && entry.modmask == ShiftMask) upper = 1;
    if (entry.symbol == XK_Shift_L && (entry.modmask & ShiftMask)) modifier = 1;
  }
  require(key.code && upper && modifier && key.code == XKeysymToKeycode(observer, XK_a),
          "native letter/shift mapping differs");
  require(!xdo_send_key_window(context, CURRENTWINDOW, XDO_KEYSYM, XK_a, XDO_KEY_CLICK, 0),
          "constructed context cannot deliver input");
  XSync(observer, False);
  for (int i = 0; i < 2; i++) {
    XEvent event;
    require(XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event)
            && event.type == (i ? KeyRelease : KeyPress) && event.xkey.window == window
            && !event.xkey.send_event && event.xkey.keycode == key.code && event.xkey.state == 0,
            "actual constructed-context key event differs");
  }
  XEvent extra;
  require(!XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &extra),
          "unexpected input event");
  char keys[32];
  require(XQueryKeymap(observer, keys), "physical key state unavailable");
  for (int i = 0; i < 32; i++) require(keys[i] == 0, "physical key remained held");
}

int main(void) {
  setbuf(stdout, NULL);
  int initial = entries("/proc/self/fd"), tasks = entries("/proc/self/task");
  Display *observer = __real_XOpenDisplay("unix/:98.0");
  require(observer != NULL, "native observer unavailable");
  Window focus; int revert;
  require(XGetInputFocus(observer, &focus, &revert), "initial focus unavailable");
  Window window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 100, 80, 0, 0, 0);
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
  XMapWindow(observer, window);
  XSetInputFocus(observer, window, RevertToPointerRoot, CurrentTime);
  XSync(observer, False);
  int baseline = entries("/proc/self/fd");
  for (int round = 0; round < 4; round++) {
    for (fault = HEALTHY; fault < FAULT_COUNT; fault++) {
      for (int path = 0; path < 3; path++) {
        allocation_calls = allocations = releases = queries = maps = map_frees = closes = xtest_queries = 0;
        character_count = 0;
        require(!owned[0] && !owned[1] && !owned_map, "prior constructor allocation retained");
        product_display = path ? __real_XOpenDisplay("unix/:98.0") : NULL;
        require(!path || product_display, "caller display unavailable");
        observing = 1;
        xdo_t *context = path ? xdo_new_with_opened_display(product_display, "unix/:98.0", path == 1)
                              : xdo_new("unix/:98.0");
        observing = 0;
        require((context != NULL) == (fault == HEALTHY), "constructor admission differs");
        if (context) delivered(context, observer, window);
        xdo_free(context);
        int native_closed = path == 0 || (path == 1 && fault == HEALTHY);
        require(closes == native_closed, "display ownership transfer or refusal differs");
        int snapshot_expected = fault != NO_XTEST && fault != CONTEXT_ALLOCATION;
        require(xtest_queries == 1 && (fault != NO_XTEST || allocation_calls == 0),
                "failed XTEST admission allocated context storage");
        require(queries == snapshot_expected && maps == map_frees
                && maps == (snapshot_expected && fault != NO_DESCRIPTOR)
                && !owned_map && allocations == releases && !owned[0] && !owned[1],
                "partial native allocations not retired exactly once");
        if (!native_closed) {
          Window current; int current_revert;
          require(XGetInputFocus(product_display, &current, &current_revert)
                  && current == window, "caller-owned display unusable after constructor return");
          require(__real_XCloseDisplay(product_display) == 0, "caller display retirement failed");
        }
        product_display = NULL;
        require(entries("/proc/self/fd") == baseline && entries("/proc/self/task") == tasks,
                "constructor resources retained");
      }
    }
    printf("XDO_CONSTRUCTOR_ROUND=pass round=%d cases=%d\n", round, FAULT_COUNT * 3);
  }
  XSetInputFocus(observer, focus, revert, CurrentTime);
  XDestroyWindow(observer, window);
  XSync(observer, False);
  require(__real_XCloseDisplay(observer) == 0, "observer retirement failed");
  require(entries("/proc/self/fd") == initial && entries("/proc/self/task") == tasks,
          "final native resources retained");
  puts("XDO_CONSTRUCTOR_NATIVE=pass cases=276 faults=22 paths=3 repeats=4 accepted=12 refused=264 events=24 xtest_refusal=pre-allocation snapshot=single allocations=paired maps=paired display_transfer=success-only caller_display=usable descriptors=retired tasks=retired sanitizer=address heap_scope=owned-allocations whole_app=false");
  return 0;
}

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
static int modifier_fault, modifier_queries, modifier_frees, modifier_width;
static XkbDescPtr owned_query;
static int map_readbacks, map_live, map_gets, map_releases, setmap_fault, readback_fault;
static XkbDescPtr tracked_maps[2];
static Display *click_observer;
static Window click_window;
static KeyCode click_code;
static KeySym click_symbol;
static int click_events;
static XModifierKeymap *owned_modifiers;
static KeyCode *modifier_codes;
extern XkbDescPtr __real_XkbGetMap(Display *, unsigned, unsigned);
extern void __real_XkbFreeKeyboard(XkbDescPtr, unsigned, Bool);
extern Bool __real_XkbChangeMap(Display *, XkbDescPtr, XkbMapChangesPtr);
extern Status __real_XkbGetState(Display *, unsigned int, XkbStatePtr);
extern Bool __real_XkbLockGroup(Display *, unsigned int, unsigned int);
extern int __real_XTestFakeKeyEvent(Display *, unsigned int, Bool, unsigned long);
extern int __real_XChangeKeyboardMapping(Display *, int, int, KeySym *, int);
extern XModifierKeymap *__real_XGetModifierMapping(Display *);
extern int __real_XFreeModifiermap(XModifierKeymap *);
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
  if (observe && display == product_display) {
    require(owned_modifiers == NULL, "modifier map retained during group effect");
    group_changes++;
  }
  return __real_XkbLockGroup(display, device, group);
}

int __wrap_XTestFakeKeyEvent(Display *display, unsigned int code, Bool pressed, unsigned long delay) {
  if (observe && display == product_display) {
    require(owned_modifiers == NULL, "modifier map retained during key effect");
    input_calls++;
  }
  int status = __real_XTestFakeKeyEvent(display, code, pressed, delay);
  if (observe && display == product_display && click_observer != NULL) {
    require(status && code == click_code && pressed == (click_events == 0)
            && click_events < 2 && owned_query != NULL && mapping_changes == 1,
            "scratch click released its binding before the complete action");
    XSync(display, False);
    int width;
    KeySym *mapping = XGetKeyboardMapping(click_observer, code, 1, &width);
    require(mapping && width > 0 && mapping[0] == click_symbol,
            "scratch click server symbol absent during a leg");
    XFree(mapping);
    XkbDescPtr installed = XkbGetMap(click_observer, XkbAllMapComponentsMask, XkbUseCoreKbd);
    require(installed && installed->map && installed->server
            && XkbKeyNumGroups(installed, code) == 1 && XkbKeyGroupsWidth(installed, code) == 1
            && XkbKeyKeyType(installed, code, 0) == &installed->map->types[XkbOneLevelIndex]
            && installed->map->modmap[code] == 0 && installed->server->vmodmap[code] == 0
            && !XkbKeyHasActions(installed, code)
            && installed->server->behaviors[code].type == XkbKB_Default
            && installed->server->explicit[code] == XkbAllExplicitMask,
            "installed scratch XKB semantics are not neutral during a leg");
    XkbFreeKeyboard(installed, 0, True);
    XEvent event;
    require(XCheckWindowEvent(click_observer, click_window, KeyPressMask | KeyReleaseMask, &event)
            && event.type == (pressed ? KeyPress : KeyRelease)
            && event.xkey.window == click_window && !event.xkey.send_event
            && event.xkey.keycode == code && event.xkey.state == 0,
            "scratch click native event differs during a leg");
    char keys[32];
    require(XQueryKeymap(click_observer, keys), "scratch click key state unavailable");
    for (int byte = 0; byte < 32; byte++)
      require((unsigned char)keys[byte] == (pressed && byte == code / 8 ? 1U << (code % 8) : 0),
              "scratch click did not hold and release exactly its code");
    click_events++;
  }
  return status;
}

int __wrap_XChangeKeyboardMapping(Display *display, int first, int width, KeySym *symbols, int count) {
  require(!observe || display != product_display, "product used core-only symbol mutation");
  return __real_XChangeKeyboardMapping(display, first, width, symbols, count);
}

Bool __wrap_XkbChangeMap(Display *display, XkbDescPtr map, XkbMapChangesPtr changes) {
  if (observe && display == product_display) {
    if (setmap_fault && mapping_changes == 0) return False;
    if ((changes->changed & (XkbKeySymsMask | XkbKeyActionsMask))
        == (XkbKeySymsMask | XkbKeyActionsMask)) {
      for (int code = changes->first_key_act;
           code < changes->first_key_act + changes->num_key_acts; code++) {
        if (!XkbKeyHasActions(map, code)) continue;
        XkbDescPtr actual = __real_XkbGetMap(display, XkbAllMapComponentsMask, XkbUseCoreKbd);
        require(actual && actual->map && XkbKeyNumGroups(actual, code) == XkbKeyNumGroups(map, code)
                && XkbKeyGroupsWidth(actual, code) == XkbKeyGroupsWidth(map, code)
                && !memcmp(actual->map->key_sym_map[code].kt_index,
                           map->map->key_sym_map[code].kt_index, XkbNumKbdGroups)
                && !memcmp(XkbKeySymsPtr(actual, code), XkbKeySymsPtr(map, code),
                           XkbKeyNumSyms(map, code) * sizeof(KeySym)),
                "action array sent before unchanged symbols were established");
        __real_XkbFreeKeyboard(actual, 0, True);
      }
    }
    if (changes->changed & XkbKeySymsMask) mapping_changes++;
  }
  return __real_XkbChangeMap(display, map, changes);
}

XModifierKeymap *__wrap_XGetModifierMapping(Display *display) {
  if (!observe || display != product_display)
    return __real_XGetModifierMapping(display);
  modifier_queries++;
  require(owned_modifiers == NULL, "previous modifier map not retired");
  if (modifier_fault == 1) return NULL;
  owned_modifiers = __real_XGetModifierMapping(display);
  require(owned_modifiers && owned_modifiers->max_keypermod > 0
          && owned_modifiers->max_keypermod <= 255 && owned_modifiers->modifiermap,
          "real modifier map unavailable");
  modifier_width = owned_modifiers->max_keypermod;
  modifier_codes = owned_modifiers->modifiermap;
  if (modifier_fault == 2) owned_modifiers->max_keypermod = 0;
  if (modifier_fault == 3) owned_modifiers->max_keypermod = 256;
  if (modifier_fault == 4) owned_modifiers->modifiermap = NULL;
  if (modifier_fault == 5 || modifier_fault == 6) {
    memset(modifier_codes + ShiftMapIndex * modifier_width, 0, modifier_width * sizeof(KeyCode));
    if (modifier_fault == 6) modifier_codes[ShiftMapIndex * modifier_width] = 7;
  }
  return owned_modifiers;
}

int __wrap_XFreeModifiermap(XModifierKeymap *map) {
  if (map && map == owned_modifiers) {
    map->max_keypermod = modifier_width;
    map->modifiermap = modifier_codes;
    owned_modifiers = NULL;
    modifier_codes = NULL;
    modifier_frees++;
  }
  return __real_XFreeModifiermap(map);
}

XkbDescPtr __wrap_XkbGetMap(Display *display, unsigned which, unsigned device) {
  if (!observe || display != product_display)
    return __real_XkbGetMap(display, which, device);
  require(which == XkbAllMapComponentsMask && device == XkbUseCoreKbd,
          "scratch snapshot omitted XKB components");
  int initial = owned_query == NULL;
  if (initial) {
    queries++;
    if (fault == 1) return NULL;
  } else {
    map_readbacks++;
    if (readback_fault && map_readbacks == readback_fault) return NULL;
  }
  XkbDescPtr map = __real_XkbGetMap(display, which, device);
  require(map && map->map && map->server, "real native snapshot unavailable");
  map_live++;
  map_gets++;
  int slot = tracked_maps[0] == NULL ? 0 : 1;
  require(tracked_maps[slot] == NULL && map_live <= 2, "scratch snapshot live bound exceeded");
  tracked_maps[slot] = map;
  if (initial) {
    owned_query = map;
    if (fault == 2) map->map->key_sym_map[map->min_key_code].width = 0;
  }
  return map;
}

void __wrap_XkbFreeKeyboard(XkbDescPtr map, unsigned which, Bool all) {
  for (int slot = 0; slot < 2; slot++) {
    if (map != NULL && map == tracked_maps[slot]) {
      require(which == 0 && all, "scratch descriptor only partially freed");
      tracked_maps[slot] = NULL;
      map_live--;
      map_releases++;
      require(map_live >= 0, "scratch descriptor freed without ownership");
      if (map == owned_query) { owned_query = NULL; frees++; }
      break;
    }
  }
  __real_XkbFreeKeyboard(map, which, all);
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

static void same_modifiers(Display *display, const XModifierKeymap *expected) {
  XModifierKeymap *actual = XGetModifierMapping(display);
  require(actual && actual->modifiermap && actual->max_keypermod == expected->max_keypermod
          && !memcmp(actual->modifiermap, expected->modifiermap,
                     (Mod5MapIndex + 1) * expected->max_keypermod * sizeof(KeyCode)),
          "modifier map changed");
  XFreeModifiermap(actual);
}

static void modifier_admission(xdo_t *input, Display *observer, Window window,
                               int low, int high, int width, const KeySym *mapping) {
  int code = XKeysymToKeycode(observer, XK_A), shift = 0;
  XModifierKeymap *map = XGetModifierMapping(observer);
  require(map && map->modifiermap && map->max_keypermod > 0, "observer modifiers unavailable");
  for (int j = 0; j < map->max_keypermod; j++) {
    if (map->modifiermap[ShiftMapIndex * map->max_keypermod + j]) {
      shift = map->modifiermap[ShiftMapIndex * map->max_keypermod + j];
      break;
    }
  }
  require(code >= low && code <= high && shift >= low && shift <= high && code != shift,
          "native uppercase fixture codes differ");
  int found = 0;
  for (int i = 0; i < input->charcodes_len; i++) {
    if (input->charcodes[i].symbol == XK_A) {
      require(input->charcodes[i].code == code && input->charcodes[i].modmask == ShiftMask,
              "native uppercase fixture requires unexpected modifiers");
      found = 1;
      break;
    }
  }
  require(found, "native uppercase fixture absent");
  for (int round = 0; round < 4; round++) {
    for (int failure = 1; failure <= 6; failure++) {
      XkbStateRec before = {0}, after = {0};
      require(XkbGetState(observer, XkbUseCoreKbd, &before) == Success,
              "observer state unavailable for modifier admission");
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      modifier_queries = modifier_frees = 0;
      modifier_fault = failure;
      observe = 1;
      int status = xdo_enter_text_scalar(input, 'A', 0);
      observe = 0;
      require(status == XDO_ERROR && state_queries == 1 && modifier_queries == 1
              && modifier_frees == (failure != 1) && owned_modifiers == NULL
              && group_changes == 0 && input_calls == 0 && mapping_changes == 0
              && queries == 0 && frees == 0 && owned_query == NULL,
              "modifier admission refusal has effects or retained storage");
      events(observer, window, 0, 0);
      same_map(observer, low, high - low + 1, width, mapping);
      same_modifiers(observer, map);
      require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
              && !memcmp(&before, &after, sizeof(before)), "modifier refusal changed state");

      modifier_fault = 0;
      modifier_queries = modifier_frees = 0;
      state_queries = group_changes = input_calls = 0;
      observe = 1;
      status = xdo_enter_text_scalar(input, 'A', 0);
      observe = 0;
      require(status == XDO_SUCCESS && state_queries == 1 && modifier_queries == 1
              && modifier_frees == 1 && owned_modifiers == NULL && group_changes == 4
              && input_calls == 4 && mapping_changes == 0 && queries == 0 && frees == 0,
              "modifier recovery snapshot or ownership differs");
      XSync(observer, False);
      for (int index = 0; index < 4; index++) {
        XEvent event;
        require(XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event),
                "native modifier/key event missing");
        require(event.type == (index < 2 ? KeyPress : KeyRelease)
                && event.xkey.window == window && !event.xkey.send_event
                && event.xkey.keycode == (unsigned)(index % 2 ? code : shift)
                && event.xkey.state == (unsigned)(index == 1 || index == 2 ? ShiftMask : 0),
                "native modifier/key event differs");
      }
      events(observer, window, 0, 0);
      same_map(observer, low, high - low + 1, width, mapping);
      same_modifiers(observer, map);
      require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
              && !memcmp(&before, &after, sizeof(before)), "modifier recovery changed state");
    }
  }
  XFreeModifiermap(map);
}

static void keyboard_state(xdo_t *input, Display *observer, Window window,
                           int low, int high, int width, const KeySym *mapping) {
  struct request { unsigned scalar; int code; };
  const struct request keys[] = {
    {'a', low}, {'b', low + 1}, {0x1f642, high},
  };
  fault = 0;
  for (int failure = 1; failure <= 3; failure++) {
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
      XkbStateRec before = {0}, after = {0};
      require(XkbGetState(observer, XkbUseCoreKbd, &before) == Success,
              "observer keyboard state unavailable");
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      modifier_queries = modifier_frees = 0;
      state_fault = failure;
      observe = 1;
      int status = xdo_enter_text_scalar(input, keys[index].scalar, 0);
      observe = 0;
      require(status == XDO_ERROR && state_queries == 1 && group_changes == 0
              && input_calls == 0 && mapping_changes == 0 && queries == 0
              && frees == 0 && owned_query == NULL && modifier_queries == 0
              && modifier_frees == 0, "keyboard-state refusal has effects");
      events(observer, window, 0, 0);
      same_map(observer, low, high - low + 1, width, mapping);
      require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
              && !memcmp(&before, &after, sizeof(before)), "keyboard-state refusal changed state");

      state_fault = 0;
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      observe = 1;
      status = xdo_enter_text_scalar(input, keys[index].scalar, 0);
      observe = 0;
      int scratch = index == 2;
      require(status == XDO_SUCCESS && state_queries == 1
              && group_changes == 4
              && input_calls == 2 && mapping_changes == 2 * scratch
              && queries == scratch && frees == scratch && owned_query == NULL
              && modifier_queries == 0 && modifier_frees == 0,
              "keyboard-state recovery ownership differs");
      events(observer, window, keys[index].code, 2);
      same_map(observer, low, high - low + 1, width, mapping);
      require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
              && !memcmp(&before, &after, sizeof(before)), "keyboard-state recovery changed state");
    }
  }
}

static void key_input(xdo_t *input, Display *observer, Window window, int low, int high) {
  const unsigned invalid[] = {0xd800, 0xdfff, 0x110000, UINT_MAX};
  struct request { unsigned scalar; KeySym symbol; };
  const struct request valid[] = {
    {'a', XK_a}, {'b', XK_b}, {0x20, XK_space}, {0xa0, XK_nobreakspace},
    {0xff, XK_ydiaeresis}, {0x100, 0x01000100}, {0xffe1, 0x0100ffe1},
    {0x10ffff, 0x0110ffff}, {0x1f642, 0x0101f642},
    {'\t', XK_Tab}, {'\n', XK_Return}, {'\r', XK_Return},
  };
  queries = frees = state_queries = group_changes = input_calls = mapping_changes = fault = 0;
  modifier_queries = modifier_frees = 0;
  observe = 1;
  for (unsigned scalar = 0; scalar <= 0x9f; scalar++) {
    if (scalar == '\t' || scalar == '\n' || scalar == '\r'
        || (scalar >= 0x20 && scalar < 0x7f)) continue;
    require(xdo_enter_text_scalar(input, scalar, 0) == XDO_ERROR,
            "unsupported text control admitted");
    events(observer, window, 0, 0);
  }
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    require(xdo_enter_text_scalar(input, invalid[i], 0) == XDO_ERROR,
            "invalid text scalar admitted");
    events(observer, window, 0, 0);
  }
  xdo_t empty = {0};
  require(xdo_enter_text_scalar(NULL, 'a', 0) == XDO_ERROR
          && xdo_enter_text_scalar(&empty, 'a', 0) == XDO_ERROR,
          "unavailable context admitted");
  require(state_queries == 0 && group_changes == 0 && input_calls == 0
          && mapping_changes == 0 && queries == 0 && frees == 0,
          "invalid scalar admission had native effects");
  for (int field = 0; field < 3; field++) {
    xdo_t changed = *input;
    if (field == 0) changed.keycode_low = 7;
    if (field == 1) changed.keycode_high = 256;
    if (field == 2) changed.keycode_high = changed.keycode_low - 1;
    require(xdo_enter_text_scalar(&changed, 0x1f642, 0) == XDO_ERROR,
            "invalid native range admitted");
  }
  events(observer, window, 0, 0);
  require(queries == 0 && frees == 0 && group_changes == 0
          && input_calls == 0 && mapping_changes == 0, "range refusal had effects");
  for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
    int scratch = i >= 2;
    queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
    click_events = 0;
    if (scratch) {
      click_observer = observer;
      click_window = window;
      click_code = high;
      click_symbol = valid[i].symbol;
    }
    require(xdo_enter_text_scalar(input, valid[i].scalar, 0) == XDO_SUCCESS,
            "valid text scalar refused");
    click_observer = NULL;
    require(queries == scratch && frees == scratch && owned_query == NULL
            && state_queries == 1 && group_changes == 4 && input_calls == 2
            && mapping_changes == 2 * scratch && click_events == 2 * scratch,
            "text pair mapping or storage ownership differs");
    events(observer, window, i == 0 ? low : i == 1 ? low + 1 : high, scratch ? 0 : 2);
  }
  require(modifier_queries == 0 && modifier_frees == 0, "unmodified key queried modifiers");
  observe = 0;
}

static void same_xkb_symbols(Display *display, const XkbDescRec *expected) {
  XkbDescPtr actual = XkbGetMap(display, XkbAllClientInfoMask, XkbUseCoreKbd);
  require(actual && actual->map && actual->map->key_sym_map && actual->map->syms
          && actual->map->modmap && actual->min_key_code == expected->min_key_code
          && actual->max_key_code == expected->max_key_code, "restored XKB map unavailable");
  for (int code = expected->min_key_code; code <= expected->max_key_code; code++) {
    XkbSymMapPtr before = &expected->map->key_sym_map[code];
    XkbSymMapPtr after = &actual->map->key_sym_map[code];
    require(before->group_info == after->group_info && before->width == after->width
            && !memcmp(before->kt_index, after->kt_index, sizeof(before->kt_index))
            && expected->map->modmap[code] == actual->map->modmap[code]
            && !memcmp(XkbKeySymsPtr(expected, code), XkbKeySymsPtr(actual, code),
                       XkbKeyNumSyms(expected, code) * sizeof(KeySym)),
            "restored XKB symbols or modifiers differ");
  }
  XkbFreeKeyboard(actual, 0, True);
}

static XkbDescPtr component_snapshot(Display *display) {
  XkbDescPtr map = XkbGetMap(display, XkbAllMapComponentsMask, XkbUseCoreKbd);
  require(map && map->map && map->map->types && map->map->syms && map->map->key_sym_map
          && map->map->modmap && map->server && map->server->key_acts
          && map->server->behaviors && map->server->explicit && map->server->vmodmap
          && XkbGetControls(display, XkbPerKeyRepeatMask, map) == Success && map->ctrls,
          "complete native component snapshot unavailable");
  return map;
}

static void same_components(Display *display, XkbDescPtr expected) {
  XkbDescPtr actual = component_snapshot(display);
  require(actual->min_key_code == expected->min_key_code
          && actual->max_key_code == expected->max_key_code
          && actual->map->num_types == expected->map->num_types
          && !memcmp(actual->server->vmods, expected->server->vmods, sizeof(actual->server->vmods))
          && !memcmp(actual->ctrls->per_key_repeat, expected->ctrls->per_key_repeat,
                     sizeof(actual->ctrls->per_key_repeat)), "global XKB components changed");
  for (int index = 0; index < expected->map->num_types; index++) {
    XkbKeyTypePtr a = &actual->map->types[index], b = &expected->map->types[index];
    require(a->num_levels == b->num_levels && a->map_count == b->map_count
            && !memcmp(&a->mods, &b->mods, sizeof(a->mods))
            && (!a->map_count || !memcmp(a->map, b->map, a->map_count * sizeof(XkbKTMapEntryRec)))
            && !!a->preserve == !!b->preserve
            && (!a->preserve || !memcmp(a->preserve, b->preserve,
                                        a->map_count * sizeof(XkbModsRec))), "XKB key types changed");
  }
  for (int code = expected->min_key_code; code <= expected->max_key_code; code++) {
    XkbSymMapPtr a = &actual->map->key_sym_map[code], b = &expected->map->key_sym_map[code];
    require(a->group_info == b->group_info && a->width == b->width
            && !memcmp(a->kt_index, b->kt_index, sizeof(a->kt_index))
            && !memcmp(XkbKeySymsPtr(actual, code), XkbKeySymsPtr(expected, code),
                       XkbKeyNumSyms(expected, code) * sizeof(KeySym))
            && actual->map->modmap[code] == expected->map->modmap[code]
            && actual->server->explicit[code] == expected->server->explicit[code]
            && actual->server->vmodmap[code] == expected->server->vmodmap[code]
            && !memcmp(&actual->server->behaviors[code], &expected->server->behaviors[code],
                       sizeof(XkbBehavior))
            && !!XkbKeyHasActions(actual, code) == !!XkbKeyHasActions(expected, code)
            && (!XkbKeyHasActions(expected, code)
                || !memcmp(XkbKeyActionsPtr(actual, code), XkbKeyActionsPtr(expected, code),
                           XkbKeyNumActions(expected, code) * sizeof(XkbAction))),
            "per-key XKB components changed");
  }
  XkbFreeKeyboard(actual, 0, True);
}

static void component_row(Display *display, XkbDescPtr map, XkbMapChangesRec changes, int code) {
  XkbMapChangesRec symbols = changes;
  symbols.changed = XkbKeySymsMask | XkbExplicitComponentsMask;
  require(XkbChangeMap(display, map, &symbols), "component symbols not sent");
  XkbDescPtr actual = component_snapshot(display);
  XkbSymMapPtr a = &actual->map->key_sym_map[code], b = &map->map->key_sym_map[code];
  require(a->group_info == b->group_info && a->width == b->width
          && !memcmp(a->kt_index, b->kt_index, sizeof(a->kt_index))
          && !memcmp(XkbKeySymsPtr(actual, code), XkbKeySymsPtr(map, code),
                     XkbKeyNumSyms(map, code) * sizeof(KeySym))
          && actual->server->explicit[code] == XkbAllExplicitMask,
          "component symbol width not established before actions");
  XkbFreeKeyboard(actual, 0, True);
  printf("XDO_SCRATCH_COMPONENT_WIDTH=pass code=%d groups=%d width=%d actions=%d\n",
         code, XkbKeyNumGroups(map, code), XkbKeyGroupsWidth(map, code), XkbKeyHasActions(map, code) != 0);
  require(XkbChangeMap(display, map, &changes), "component server map not sent");
  XSync(display, False);
}

static xdo_t *scratch_failures(xdo_t *input, Display *observer, Window window,
                               int code, XkbDescPtr baseline) {
  int failures = XkbKeyHasActions(baseline, code) ? 5 : 4;
  for (int failure = 0; failure < failures; failure++) {
    for (int round = 0; round < 4; round++) {
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      map_readbacks = 0;
      setmap_fault = failure == 0;
      readback_fault = failure;
      observe = 1;
      int status = xdo_enter_text_scalar(input, 0x1f642, 0);
      observe = 0;
      int cleanup_failed = failure >= 2;
      require(status == (cleanup_failed ? XDO_CLEANUP_ERROR : XDO_ERROR)
              && input_calls == (cleanup_failed ? 2 : 0)
              && (owned_query != NULL) == cleanup_failed
              && map_live == cleanup_failed, "map failure finality differs");
      events(observer, window, code, cleanup_failed ? 2 : 0);
      setmap_fault = readback_fault = 0;
      if (cleanup_failed) {
        int old_inputs = input_calls, old_groups = group_changes, old_changes = mapping_changes;
        observe = 1;
        require(xdo_enter_text_scalar(input, 'a', 0) == XDO_CLEANUP_ERROR,
                "unconfirmed scratch restoration accepted later text");
        observe = 0;
        require(input_calls == old_inputs && group_changes == old_groups && mapping_changes == old_changes
                && owned_query != NULL, "blocked context performed effects or dropped original state");
        observe = 1;
        xdo_free(input);
        observe = 0;
        product_display = NULL;
        require(map_live == 0 && owned_query == NULL, "destruction failed to retire its scratch lease");
        same_components(observer, baseline);
        input = xdo_new("unix/:98.0");
        require(input != NULL, "fresh recovery context unavailable");
        product_display = input->xdpy;
      }
      same_components(observer, baseline);
      observe = 1;
      require(xdo_enter_text_scalar(input, 0x1f642, 0) == XDO_SUCCESS,
              "corrected component did not recover after map refusal");
      observe = 0;
      events(observer, window, code, 2);
      same_components(observer, baseline);
      printf("XDO_SCRATCH_RESTORE_CASE=pass actions=%d failure=%d round=%d cleanup_pending=%d\n",
             failures == 5, failure, round, cleanup_failed);
    }
  }
  return input;
}

static void scratch_components(xdo_t *input, Display *observer, Window window, int code) {
  XkbDescPtr baseline = component_snapshot(observer);
  XkbMapChangesRec changes = {0};
  changes.changed = XkbKeySymsMask | XkbKeyActionsMask | XkbKeyBehaviorsMask
      | XkbExplicitComponentsMask | XkbModifierMapMask | XkbVirtualModMapMask;
  changes.first_key_sym = changes.first_key_act = changes.first_key_behavior
      = changes.first_key_explicit = changes.first_modmap_key = changes.first_vmodmap_key = code;
  changes.num_key_syms = changes.num_key_acts = changes.num_key_behaviors
      = changes.num_key_explicit = changes.num_modmap_keys = changes.num_vmodmap_keys = 1;
  for (int scenario = 0; scenario < 5; scenario++) {
    XkbDescPtr fixture = component_snapshot(observer);
    int types[] = {XkbTwoLevelIndex, XkbAlphabeticIndex};
    XkbMapChangesRec resize = {0};
    require(XkbChangeTypesOfKey(fixture, code, 2, XkbGroup1Mask | XkbGroup2Mask,
                               types, &resize) == Success, "component fixture group resize failed");
    memset(XkbKeySymsPtr(fixture, code), 0, XkbKeyNumSyms(fixture, code) * sizeof(KeySym));
    fixture->server->explicit[code] = XkbAllExplicitMask;
    XkbAction *actions = XkbResizeKeyActions(fixture, code, XkbKeyNumSyms(fixture, code));
    require(actions != NULL, "component fixture action storage unavailable");
    memset(actions, 0, XkbKeyNumSyms(fixture, code) * sizeof(XkbAction));
    if (scenario == 1) fixture->map->modmap[code] = ShiftMask;
    if (scenario == 2) fixture->server->vmodmap[code] = 1;
    if (scenario == 3) fixture->server->behaviors[code].type = XkbKB_Lock;
    if (scenario == 4) actions[0].type = XkbSA_SetMods;
    component_row(observer, fixture, changes, code);
    if (scenario == 0) {
      fixture->server->explicit[code] = XkbExplicitInterpretMask;
      XkbMapChangesRec flags = {0};
      flags.changed = XkbExplicitComponentsMask;
      flags.first_key_explicit = code;
      flags.num_key_explicit = 1;
      require(XkbChangeMap(observer, fixture, &flags), "neutral fixture original flags not sent");
      XSync(observer, False);
    }
    XkbFreeKeyboard(fixture, 0, True);
    XkbDescPtr configured = component_snapshot(observer);
    require(XkbKeyNumGroups(configured, code) == 2 && XkbKeyGroupsWidth(configured, code) == 2
            && configured->server->explicit[code] == (scenario == 0 ? XkbExplicitInterpretMask : XkbAllExplicitMask)
            && configured->map->modmap[code] == (scenario == 1 ? ShiftMask : 0)
            && configured->server->vmodmap[code] == (scenario == 2 ? 1 : 0)
            && configured->server->behaviors[code].type == (scenario == 3 ? XkbKB_Lock : XkbKB_Default)
            && XkbKeyHasActions(configured, code)
            && XkbKeyActionsPtr(configured, code)[0].type == (scenario == 4 ? XkbSA_SetMods : XkbSA_NoAction),
            "native server component fixture differs");
    for (int round = 0; round < 4; round++) {
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      map_readbacks = 0;
      observe = 1;
      int status = xdo_enter_text_scalar(input, 0x1f642, 0);
      observe = 0;
      require(status == (scenario == 0 ? XDO_SUCCESS : XDO_ERROR)
              && queries == 1 && frees == 1 && owned_query == NULL && map_live == 0
              && input_calls == (scenario == 0 ? 2 : 0)
              && group_changes == (scenario == 0 ? 4 : 0)
              && mapping_changes == (scenario == 0 ? 3 : 0)
              && map_readbacks == (scenario == 0 ? 4 : 0), "component admission/effect census differs");
      events(observer, window, code, scenario == 0 ? 2 : 0);
      same_components(observer, configured);
    }
    if (scenario == 0) input = scratch_failures(input, observer, window, code, configured);
    XkbFreeKeyboard(configured, 0, True);
    unsigned flags = baseline->server->explicit[code];
    baseline->server->explicit[code] = XkbAllExplicitMask;
    component_row(observer, baseline, changes, code);
    baseline->server->explicit[code] = flags;
    XkbMapChangesRec thaw = {0};
    thaw.changed = XkbExplicitComponentsMask;
    thaw.first_key_explicit = code;
    thaw.num_key_explicit = 1;
    require(XkbChangeMap(observer, baseline, &thaw), "component fixture original overrides not sent");
    XSync(observer, False);
    same_components(observer, baseline);
  }
  input = scratch_failures(input, observer, window, code, baseline);
  product_display = NULL;
  xdo_free(input);
  XkbFreeKeyboard(baseline, 0, True);
  require(map_live == 0 && map_gets == map_releases, "complete descriptor census differs");
  puts("XDO_SCRATCH_COMPONENTS_NATIVE=pass candidates=5 repeats=4 accepted=4 refused=16 mapping_faults=9 fault_repeats=4 recovery=36 cleanup_pending=20 later_text=refused destructor=restored full_xkb=preserved snapshots=retired live_peak=2 provider=current-only whole_app=false");
}

static void scratch_click(xdo_t *input, Display *observer, Window window,
                          int round, int low, int high, int width, const KeySym *mapping) {
  click_observer = observer;
  click_window = window;
  click_code = high;
  click_symbol = 0x0101f642;
  for (int delayed = 0; delayed < 2; delayed++) {
    for (fault = 0; fault < 3; fault++) {
      XkbStateRec before = {0}, after = {0};
      require(XkbGetState(observer, XkbUseCoreKbd, &before) == Success,
              "scratch click initial state unavailable");
      queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
      modifier_queries = modifier_frees = click_events = 0;
      observe = 1;
      int status = xdo_enter_text_scalar(input, 0x1f642, delayed ? 12000 : 0);
      observe = 0;
      int accepted = fault == 0;
      require(status == (accepted ? XDO_SUCCESS : XDO_ERROR)
              && queries == 1 && frees == (fault != 1) && owned_query == NULL
              && state_queries == 1 && modifier_queries == 0 && modifier_frees == 0
              && group_changes == 4 * accepted && input_calls == 2 * accepted
              && mapping_changes == 2 * accepted && click_events == 2 * accepted,
              "scratch click action outcome or mapping ownership differs");
      events(observer, window, 0, 0);
      same_map(observer, low, high - low + 1, width, mapping);
      require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
              && !memcmp(&before, &after, sizeof(before)), "scratch click changed XKB state");
      printf("XDO_SCRATCH_CLICK_CASE=pass round=%d delay=%d fault=%d events=%d\n",
             round, delayed ? 12000 : 0, fault, click_events);
    }
  }
  click_observer = NULL;
  fault = 0;
}

static void text_group_layout(Display *observer, Window window) {
  int descriptors = entries("/proc/self/fd"), tasks = entries("/proc/self/task");
  XkbStateRec baseline = {0}, restored = {0};
  require(XkbGetState(observer, XkbUseCoreKbd, &baseline) == Success
          && baseline.group == baseline.locked_group && baseline.base_group == 0
          && baseline.latched_group == 0 && baseline.mods == 0,
          "text-group fixture initial state differs");
  clear_keys(observer);
  XkbDescPtr original = XkbGetMap(observer, XkbAllClientInfoMask, XkbUseCoreKbd);
  /* Group resizing also examines the server's per-key action array. */
  XkbDescPtr changed = XkbGetMap(observer, XkbAllClientInfoMask | XkbKeyActionsMask, XkbUseCoreKbd);
  require(original && original->map && original->map->key_sym_map && original->map->syms
          && original->map->modmap && changed && changed->map && changed->map->types
          && changed->map->num_types > XkbAlphabeticIndex && changed->server
          && changed->server->key_acts, "text-group fixture maps unavailable");
  KeyCode code = XKeysymToKeycode(observer, XK_a);
  require(code >= original->min_key_code && code <= original->max_key_code
          && original->map->modmap[code] == 0 && !XkbKeyHasActions(changed, code),
          "text-group fixture physical key differs");
  int types[] = {XkbAlphabeticIndex, XkbAlphabeticIndex};
  XkbMapChangesRec map_change = {0};
  require(XkbChangeTypesOfKey(changed, code, 2, XkbGroup1Mask | XkbGroup2Mask,
                             types, &map_change) == Success
          && map_change.changed == XkbKeySymsMask && map_change.first_key_sym == code
          && map_change.num_key_syms == 1, "text-group fixture resize failed");
  XkbKeySymEntry(changed, code, 0, 0) = XK_a;
  XkbKeySymEntry(changed, code, 1, 0) = XK_A;
  XkbKeySymEntry(changed, code, 0, 1) = XK_b;
  XkbKeySymEntry(changed, code, 1, 1) = XK_B;
  require(XkbChangeMap(observer, changed, &map_change), "text-group fixture map not sent");
  XSync(observer, False);
  Display *reader = XOpenDisplay("unix/:98.0");
  require(reader != NULL, "text-group independent lookup display unavailable");
  XkbDescPtr actual = XkbGetMap(reader, XkbAllClientInfoMask, XkbUseCoreKbd);
  require(actual && actual->map && XkbKeyNumGroups(actual, code) == 2
          && XkbKeyGroupsWidth(actual, code) == 2
          && XkbKeySymEntry(actual, code, 0, 0) == XK_a
          && XkbKeySymEntry(actual, code, 1, 0) == XK_A
          && XkbKeySymEntry(actual, code, 0, 1) == XK_b
          && XkbKeySymEntry(actual, code, 1, 1) == XK_B,
          "native server did not install the two-group map");
  XkbFreeKeyboard(actual, 0, True);
  xdo_t *input = xdo_new("unix/:98.0");
  require(input != NULL, "text-group product context unavailable");
  int found = 0;
  for (int index = 0; index < input->charcodes_len; index++) {
    if (input->charcodes[index].symbol == XK_a) {
      require(input->charcodes[index].code == code && input->charcodes[index].group == 0
              && input->charcodes[index].modmask == 0, "keysym control mapping differs");
      found = 1;
      break;
    }
  }
  require(found, "keysym control mapping absent");
  product_display = input->xdpy;
  for (int round = 0; round < 4; round++) {
    for (unsigned group = 0; group < 2; group++) {
      for (unsigned selected = 0; selected < 2; selected++) {
        require(XkbLockGroup(observer, XkbUseCoreKbd, group), "fixture group not sent");
        XSync(observer, False);
        XkbStateRec before = {0}, after = {0};
        require(XkbGetState(observer, XkbUseCoreKbd, &before) == Success
                && before.group == group && before.locked_group == group
                && before.base_group == 0 && before.latched_group == 0 && before.mods == 0,
                "native server did not select the fixture group");
        queries = frees = state_queries = group_changes = input_calls = mapping_changes = 0;
        modifier_queries = modifier_frees = 0;
        fault = state_fault = modifier_fault = 0;
        observe = 1;
        int status = xdo_enter_text_scalar(input, selected ? 'b' : 'a', 0);
        observe = 0;
        require(status == XDO_SUCCESS, "text-group input refused");
        require(state_queries == 1 && input_calls == 2 && group_changes == 4
                && mapping_changes == 0 && queries == 0 && frees == 0
                && modifier_queries == 0 && modifier_frees == 0,
                "text-group product call census differs");
        require(XkbGetState(observer, XkbUseCoreKbd, &after) == Success
                && !memcmp(&before, &after, sizeof(before)), "input changed the XKB state");
        XSync(observer, False);
        for (int index = 0; index < 2; index++) {
          XEvent event;
          require(XCheckWindowEvent(observer, window, KeyPressMask | KeyReleaseMask, &event),
                  "text-group native event missing");
          KeySym symbol = NoSymbol;
          unsigned consumed;
          require(event.type == (index == 0 ? KeyPress : KeyRelease)
                  && event.xkey.window == window && !event.xkey.send_event
                  && event.xkey.keycode == code && event.xkey.state == (selected << 13)
                  && XkbLookupKeySym(reader, code, event.xkey.state, &consumed, &symbol)
                  && symbol == (selected ? XK_b : XK_a),
                  "text-group native event group or symbol differs");
        }
        events(observer, window, 0, 0);
        printf("XDO_TEXT_GROUP_CASE=pass round=%d group=%u selected=%u events=2 group_locks=%d\n",
               round, group, selected, group_changes);
      }
    }
  }
  product_display = NULL;
  xdo_free(input);
  XCloseDisplay(reader);
  require(XkbChangeMap(observer, original, &map_change), "original XKB map not sent");
  require(XkbLockGroup(observer, XkbUseCoreKbd, baseline.locked_group), "original group not sent");
  XSync(observer, False);
  same_xkb_symbols(observer, original);
  require(XkbGetState(observer, XkbUseCoreKbd, &restored) == Success
          && !memcmp(&baseline, &restored, sizeof(baseline)), "original XKB state not restored");
  XkbFreeKeyboard(changed, 0, True);
  XkbFreeKeyboard(original, 0, True);
  clear_keys(observer);
  require(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks,
          "text-group descriptors/tasks retained");
  puts("XDO_TEXT_GROUP_NATIVE=pass groups=0,1 repeats=4 cases=16 events=32 scalars=a,b group_locks=64 symbols=resolved state=preserved mapping=restored keys=clear descriptors=retired tasks=retired sanitizer=address whole_app=false");
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
  Window window = XCreateSimpleWindow(observer, DefaultRootWindow(observer), 0, 0, 120, 80, 0, 0, 0);
  require(window != None, "owned window unavailable");
  XSelectInput(observer, window, KeyPressMask | KeyReleaseMask);
  XMapWindow(observer, window);
  XSetInputFocus(observer, window, RevertToParent, CurrentTime);
  XSync(observer, False);
  text_group_layout(observer, window);
  same_map(observer, low, count, initial_width, initial);
  xdo_t *input = xdo_new("unix/:98.0");
  require(input != NULL, "product context unavailable");
  charcodemap_t key = {.code = XKeysymToKeycode(observer, XK_a), .symbol = XK_a};
  require(key.code != 0, "positive control key absent");
  require(!xdo_enter_text_scalar(input, 'a', 0),
          "mapped positive control failed");
  events(observer, window, key.code, 2);
  product_display = input->xdpy;
  modifier_admission(input, observer, window, low, high, initial_width, initial);
  product_display = NULL;
  XFree(initial);
  xdo_free(input);
  puts("XDO_SCRATCH_CONTROL=pass key=a events=2");
  for (int round = 0; round < 4; round++) {
    width = initial_width;
    KeySym *mapping = malloc(count * width * sizeof(KeySym));
    require(mapping != NULL, "fixture map allocation failed");
    for (int i = 0; i < count * width; i++) mapping[i] = XK_F30;
    for (int i = 0; i < width; i++) {
      mapping[i] = XK_a;
      mapping[width + i] = XK_b;
    }
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
    XkbDescPtr components = component_snapshot(observer);
    keyboard_state(input, observer, window, low, high, width, mapping);
    key_input(input, observer, window, low, high);
    same_map(observer, low, count, width, mapping);
    scratch_click(input, observer, window, round, low, high, width, mapping);
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
        XkbFreeKeyboard(components, 0, True);
        components = component_snapshot(observer);
      }
      fault = scenario == 2 ? 1 : scenario == 3 ? 2 : 0;
      queries = frees = 0;
      observe = 1;
      printf("XDO_SCRATCH_ENTER round=%d scenario=%d highest=%d\n", round, scenario, high);
      int status = xdo_enter_text_scalar(input, scenario == 1 ? 'b' : 0x1f642, 0);
      observe = 0;
      int accepted = scenario < 2;
      require(status == (accepted ? XDO_SUCCESS : XDO_ERROR), "native outcome differs");
      require(owned_query == NULL && queries == (scenario != 1)
              && frees == (scenario != 1 && scenario != 2), "query ownership differs");
      events(observer, window, scenario == 0 ? high : low + 1, accepted ? 2 : 0);
      same_map(observer, low, count, width, mapping);
      same_components(observer, components);
      printf("XDO_SCRATCH_CASE=pass round=%d scenario=%d events=%d queries=%d frees=%d\n",
             round, scenario, accepted ? 2 : 0, queries, frees);
    }
    product_display = NULL;
    xdo_free(input);
    XkbFreeKeyboard(components, 0, True);
    XFree(mapping);
  }
  /* Restore one empty row, then test only the corrected provider's XKB lease. */
  KeySym empty_symbol = NoSymbol;
  XChangeKeyboardMapping(observer, high, 1, &empty_symbol, 1);
  XSync(observer, False);
  input = xdo_new("unix/:98.0");
  require(input != NULL, "component admission context unavailable");
  product_display = input->xdpy;
  scratch_components(input, observer, window, high);
  XDestroyWindow(observer, window);
  XCloseDisplay(observer);
  require(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks,
          "native descriptors/tasks retained");
  puts("XDO_SCRATCH_NATIVE=pass cases=20 repeats=4 highest=delivered mapped_query=absent missing_map=refused invalid_width=refused full_map=refused events=16 maps=unchanged queries=16 frees=12 descriptors=retired tasks=retired sanitizer=address leak_scope=unclaimed whole_app=false");
  puts("XDO_SCRATCH_CLICK_NATIVE=pass cases=24 repeats=4 delays=0,12000 accepted=8 refused=16 events=16 binding=both-legs queries=24 frees=16 maps=restored keys=clear descriptors=retired tasks=retired sanitizer=address observer=in-request consumer=unproved whole_app=false");
  puts("XDO_TEXT_SCALAR_NATIVE=pass cases=332 repeats=4 refused=284 accepted=48 events=96 controls=all-C0,C1 boundaries=Latin1,Unicode invalid=pre-input-refused key_storage=stack product_allocations=0 pair_queries=40 pair_frees=40 maps=unchanged keys=clear descriptors=retired tasks=retired sanitizer=address whole_heap=false whole_app=false");
  puts("XDO_KEY_STATE_NATIVE=pass cases=36 repeats=4 faults=3 scalars=3 refused=36 recovery=36 events=72 state_queries=72 pair_snapshot=single refusal_effects=none maps=unchanged keys=clear descriptors=retired tasks=retired sanitizer=address whole_app=false");
  puts("XDO_KEY_MODIFIER_NATIVE=pass cases=24 repeats=4 faults=6 refused=24 recovery=24 events=96 modifier_queries=48 modifier_frees=44 pair_snapshot=single refusal_effects=none maps=unchanged keys=clear descriptors=retired tasks=retired sanitizer=address whole_app=false");
  return 0;
}

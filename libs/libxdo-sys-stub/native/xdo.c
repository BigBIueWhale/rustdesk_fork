/* xdo library
 *
 * See the following url for an explanation of how keymaps work in X11
 * http://www.in-ulm.de/~mascheck/X11/xmodmap.html
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif /* _XOPEN_SOURCE */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <X11/Xlib.h>
#include <X11/Xlib-xcb.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>

#include "xdo.h"
#include "xdo_version.h"

static int _xdo_populate_charcode_map(xdo_t *xdo);

static void _xdo_charcodemap_from_keysym(const xdo_t *xdo, charcodemap_t *key,
                                      KeySym keysym, unsigned int current_group);
static int _xdo_text_pair(xdo_t *xdo, KeyCode key,
                         const KeyCode *modifiers, useconds_t delay);
static int _xdo_retire_text_keys(xdo_t *xdo);
static int _xdo_get_key_modifiers(const xdo_t *xdo, const charcodemap_t *key,
                                const unsigned char *held, KeyCode *modifiers);
static int _xdo_restore_scratch(xdo_t *xdo);
static int _xdo_query_keys(xcb_connection_t *connection, unsigned char *output);

static int _xdo_mousebutton(const xdo_t *xdo, int button, int is_press);

static int _is_success(const char *funcname, int code, const xdo_t *xdo);

xdo_t* xdo_new(const char *display_name) {
  Display *xdpy;

  if ((xdpy = XOpenDisplay(display_name)) == NULL) {
    fprintf(stderr, "Error: Can't open display: %.128s\n",
            display_name != NULL ? display_name : "(default)");
    return NULL;
  }

  if (display_name == NULL) {
    display_name = getenv("DISPLAY");
  }

  xdo_t *xdo = xdo_new_with_opened_display(xdpy, display_name, 1);
  if (xdo == NULL)
    XCloseDisplay(xdpy);
  return xdo;
}

xdo_t* xdo_new_with_opened_display(Display *xdpy, const char *display,
                                   int close_display_when_freed) {
  xdo_t *xdo = NULL;

  if (xdpy == NULL) {
    fprintf(stderr, "xdo_new: xdisplay I was given is a null pointer\n");
    return NULL;
  }

  int event_base, error_base, major, minor;
  if (XTestQueryExtension(xdpy, &event_base, &error_base, &major, &minor) != True) {
    fprintf(stderr, "xdo_new: XTEST extension unavailable on '%.128s'\n",
            display != NULL ? display : "(default)");
    return NULL;
  }

  xdo = calloc(1, sizeof(xdo_t));
  if (xdo == NULL) {
    fprintf(stderr, "xdo_new: context allocation failed\n");
    return NULL;
  }

  xdo->xdpy = xdpy;

  if (getenv("XDO_QUIET")) {
    xdo->quiet = True;
  }

  if (_xdo_populate_charcode_map(xdo) != XDO_SUCCESS) {
    fprintf(stderr, "xdo_new: keyboard map unavailable or invalid\n");
    /* Construction has not acquired keys, a scratch lease or the Display. */
    free(xdo->charcodes);
    free(xdo);
    return NULL;
  }
  xdo->close_display_when_freed = close_display_when_freed;
  return xdo;
}

int xdo_free(xdo_t *xdo) {
  if (xdo == NULL)
    return XDO_SUCCESS;

  if (_xdo_retire_text_keys(xdo) != XDO_SUCCESS) {
    fprintf(stderr, "xdo_free: text key retirement unconfirmed\n");
    return XDO_CLEANUP_ERROR;
  }
  if (xdo->scratch_original != NULL && _xdo_restore_scratch(xdo) != XDO_SUCCESS) {
    fprintf(stderr, "xdo_free: scratch keyboard restoration unconfirmed\n");
    return XDO_CLEANUP_ERROR;
  }

  if (xdo->display_name)
    free(xdo->display_name);
  if (xdo->charcodes)
    free(xdo->charcodes);
  if (xdo->xdpy && xdo->close_display_when_freed)
    XCloseDisplay(xdo->xdpy);

  free(xdo);
  return XDO_SUCCESS;
}

const char *xdo_version(void) {
  return XDO_VERSION;
}

int xdo_move_mouse(const xdo_t *xdo, int x, int y)  {
  if (xdo == NULL || xdo->xdpy == NULL)
    return XDO_ERROR;
  int ret = 0;

  /* Absolute coordinates belong to the retained Display's selected root. */
  Window screen_root = DefaultRootWindow(xdo->xdpy);
  ret = XWarpPointer(xdo->xdpy, None, screen_root, 0, 0, 0, 0, x, y);
  XFlush(xdo->xdpy);
  return _is_success("XWarpPointer", ret == 0, xdo);
}

int xdo_move_mouse_relative(const xdo_t *xdo, int x, int y)  {
  int ret = 0;
  ret = XTestFakeRelativeMotionEvent(xdo->xdpy, x, y, CurrentTime);
  XFlush(xdo->xdpy);
  return _is_success("XTestFakeRelativeMotionEvent", ret == 0, xdo);
}

int _xdo_mousebutton(const xdo_t *xdo, int button, int is_press) {
  int ret = XTestFakeButtonEvent(xdo->xdpy, button, is_press, CurrentTime);
  XFlush(xdo->xdpy);
  return _is_success("XTestFakeButtonEvent", ret == 0, xdo);
}

int xdo_mouse_up(const xdo_t *xdo, int button) {
  return _xdo_mousebutton(xdo, button, False);
}

int xdo_mouse_down(const xdo_t *xdo, int button) {
  return _xdo_mousebutton(xdo, button, True);
}

int xdo_get_mouse_location(const xdo_t *xdo, int *x_ret, int *y_ret,
                           int *screen_num_ret) {
  int ret = False;
  int x = 0, y = 0, screen_num = 0;
  int i = 0;
  Window window = 0;
  Window root = 0;
  int dummy_int = 0;
  unsigned int dummy_uint = 0;
  int screencount = ScreenCount(xdo->xdpy);

  for (i = 0; i < screencount; i++) {
    Screen *screen = ScreenOfDisplay(xdo->xdpy, i);
    ret = XQueryPointer(xdo->xdpy, RootWindowOfScreen(screen),
                        &root, &window,
                        &x, &y, &dummy_int, &dummy_int, &dummy_uint);
    if (ret == True) {
      screen_num = i;
      break;
    }
  }

  if (ret == True) {
    if (x_ret != NULL) *x_ret = x;
    if (y_ret != NULL) *y_ret = y;
    if (screen_num_ret != NULL) *screen_num_ret = screen_num;
  }

  return _is_success("XQueryPointer", ret == False, xdo);
}

static int _xdo_scratch_map_valid(const xdo_t *xdo, XkbDescPtr desc) {
  if (desc == NULL || desc->min_key_code != xdo->keycode_low
      || desc->max_key_code != xdo->keycode_high || desc->map == NULL
      || desc->server == NULL)
    return 0;
  XkbClientMapPtr map = desc->map;
  XkbServerMapPtr server = desc->server;
  if (map->types == NULL || map->key_sym_map == NULL || map->syms == NULL
      || map->modmap == NULL || map->num_types < XkbNumRequiredTypes
      || map->num_types > map->size_types || map->num_syms > map->size_syms
      || server->key_acts == NULL || server->behaviors == NULL
      || server->explicit == NULL || server->vmodmap == NULL
      || server->num_acts > server->size_acts)
    return 0;
  XkbKeyTypePtr one_level = &map->types[XkbOneLevelIndex];
  if (one_level->num_levels != 1 || one_level->map_count != 0
      || one_level->mods.mask != 0 || one_level->mods.real_mods != 0
      || one_level->mods.vmods != 0)
    return 0;
  for (int code = desc->min_key_code; code <= desc->max_key_code; code++) {
    XkbSymMapPtr symbols = &map->key_sym_map[code];
    int groups = XkbKeyNumGroups(desc, code);
    int count = groups * symbols->width;
    if (groups > XkbNumKbdGroups || (groups != 0 && symbols->width == 0)
        || symbols->offset > map->num_syms || count > map->num_syms - symbols->offset)
      return 0;
    for (int group = 0; group < XkbNumKbdGroups; group++) {
      if (symbols->kt_index[group] >= map->num_types)
        return 0;
      if (group < groups && (map->types[symbols->kt_index[group]].num_levels == 0
          || map->types[symbols->kt_index[group]].num_levels > symbols->width))
        return 0;
    }
    unsigned offset = server->key_acts[code];
    if (offset != 0 && (server->acts == NULL || count == 0
        || offset > server->num_acts || (unsigned)count > server->num_acts - offset))
      return 0;
  }
  return 1;
}

static int _xdo_scratch_neutral(XkbDescPtr desc, int code) {
  XkbServerMapPtr server = desc->server;
  if (desc->map->modmap[code] != 0 || server->vmodmap[code] != 0
      || server->behaviors[code].type != XkbKB_Default
      || server->behaviors[code].data != 0
      || (XkbKeyHasActions(desc, code) && XkbKeyNumActions(desc, code) > 255))
    return 0;
  for (int i = 0; i < XkbKeyNumSyms(desc, code); i++) {
    if (XkbKeySymsPtr(desc, code)[i] != NoSymbol
        || (XkbKeyHasActions(desc, code)
            && XkbKeyActionsPtr(desc, code)[i].type != XkbSA_NoAction))
      return 0;
  }
  return 1;
}

static int _xdo_scratch_matches(const xdo_t *xdo, XkbDescPtr expected,
                                 unsigned char explicit_flags) {
  int code = xdo->scratch_keycode;
  int matches = 0;
  XkbDescPtr actual = XkbGetMap(xdo->xdpy, XkbAllMapComponentsMask, XkbUseCoreKbd);
  if (!_xdo_scratch_map_valid(xdo, actual))
    goto done;
  XkbSymMapPtr before = &expected->map->key_sym_map[code];
  XkbSymMapPtr after = &actual->map->key_sym_map[code];
  if (before->group_info != after->group_info || before->width != after->width
      || memcmp(before->kt_index, after->kt_index, sizeof(before->kt_index))
      || memcmp(XkbKeySymsPtr(expected, code), XkbKeySymsPtr(actual, code),
                XkbKeyNumSyms(expected, code) * sizeof(KeySym))
      || expected->map->modmap[code] != actual->map->modmap[code]
      || expected->server->vmodmap[code] != actual->server->vmodmap[code]
      || expected->server->behaviors[code].type != actual->server->behaviors[code].type
      || expected->server->behaviors[code].data != actual->server->behaviors[code].data
      || actual->server->explicit[code] != explicit_flags
      || memcmp(expected->server->vmods, actual->server->vmods, sizeof(expected->server->vmods))
      || !!XkbKeyHasActions(expected, code) != !!XkbKeyHasActions(actual, code))
    goto done;
  if (XkbKeyHasActions(expected, code)
      && memcmp(XkbKeyActionsPtr(expected, code), XkbKeyActionsPtr(actual, code),
                 XkbKeyNumActions(expected, code) * sizeof(XkbAction)))
    goto done;
  matches = 1;
done:
  if (actual != NULL)
    XkbFreeKeyboard(actual, 0, True);
  return matches;
}

static XkbMapChangesRec _xdo_scratch_changes(KeyCode code) {
  XkbMapChangesRec changes = {0};
  changes.changed = XkbKeySymsMask | XkbKeyActionsMask | XkbExplicitComponentsMask;
  changes.first_key_sym = changes.first_key_act = changes.first_key_explicit = code;
  changes.num_key_syms = changes.num_key_acts = changes.num_key_explicit = 1;
  return changes;
}

static int _xdo_restore_scratch(xdo_t *xdo) {
  XkbDescPtr original = xdo->scratch_original;
  int code = xdo->scratch_keycode;
  XkbMapChangesRec changes = _xdo_scratch_changes(code);
  unsigned char explicit_flags = original->server->explicit[code];
  XkbDescRec protected = *original;
  XkbServerMapRec server = *original->server;
  unsigned short actions[256] = {0};
  unsigned char flags[256] = {0};
  flags[code] = XkbAllExplicitMask;
  server.key_acts = actions;
  server.explicit = flags;
  protected.server = &server;
  /* Establish and read back the symbol width before sending an action array.
   * Keep interpretation/repeat/behavior protected throughout restoration. */
  if (!XkbChangeMap(xdo->xdpy, &protected, &changes)
      || !_xdo_scratch_matches(xdo, &protected, XkbAllExplicitMask))
    return XDO_CLEANUP_ERROR;
  if (XkbKeyHasActions(original, code)) {
    server.key_acts = original->server->key_acts;
    changes.changed = XkbKeySymsMask | XkbKeyActionsMask | XkbExplicitComponentsMask;
    if (!XkbChangeMap(xdo->xdpy, &protected, &changes)
        || !_xdo_scratch_matches(xdo, original, XkbAllExplicitMask))
      return XDO_CLEANUP_ERROR;
  }
  changes.changed = XkbExplicitComponentsMask;
  changes.num_key_syms = changes.num_key_acts = 0;
  if (!XkbChangeMap(xdo->xdpy, original, &changes)
      || !_xdo_scratch_matches(xdo, original, explicit_flags))
    return XDO_CLEANUP_ERROR;
  XkbFreeKeyboard(original, 0, True);
  xdo->scratch_original = NULL;
  xdo->scratch_keycode = 0;
  return XDO_SUCCESS;
}

static int _xdo_enter_text_scalar_do(xdo_t *xdo, charcodemap_t *key,
                                   const KeyCode *modifiers, const unsigned char *held,
                                   useconds_t delay) {
  int scratch_keycode = 0;

  /* Acquire the complete scratch resource before sending any input. */
  if (key->needs_binding) {
    if (xdo->keycode_low < 8 || xdo->keycode_high > 255
        || xdo->keycode_low > xdo->keycode_high)
      return XDO_ERROR;
    XkbDescPtr original = XkbGetMap(xdo->xdpy, XkbAllMapComponentsMask, XkbUseCoreKbd);
    if (!_xdo_scratch_map_valid(xdo, original)) {
      if (original != NULL)
        XkbFreeKeyboard(original, 0, True);
      return XDO_ERROR;
    }
    for (int i = xdo->keycode_low; i <= xdo->keycode_high; i++) {
      if (!(held[i / 8] & (1U << (i % 8))) && _xdo_scratch_neutral(original, i)) {
        scratch_keycode = i;
        break;
      }
    }
    if (scratch_keycode == 0) {
      XkbFreeKeyboard(original, 0, True);
      return XDO_ERROR;
    }

    /* A stack view serializes only this row; the original snapshot stays intact. */
    XkbDescRec installed = *original;
    XkbClientMapRec client = *original->map;
    XkbServerMapRec server = *original->server;
    XkbSymMapRec symbols[256] = {0};
    unsigned short actions[256] = {0};
    unsigned char explicit_flags[256] = {0};
    KeySym symbol = key->symbol;
    symbols[scratch_keycode].group_info = 1;
    symbols[scratch_keycode].width = 1;
    explicit_flags[scratch_keycode] = XkbAllExplicitMask;
    client.key_sym_map = symbols;
    client.syms = &symbol;
    client.num_syms = client.size_syms = 1;
    server.key_acts = actions;
    server.explicit = explicit_flags;
    installed.map = &client;
    installed.server = &server;
    XkbMapChangesRec changes = _xdo_scratch_changes(scratch_keycode);
    if (!XkbChangeMap(xdo->xdpy, &installed, &changes)) {
      XkbFreeKeyboard(original, 0, True);
      return XDO_ERROR;
    }
    xdo->scratch_original = original;
    xdo->scratch_keycode = scratch_keycode;
    if (!_xdo_scratch_matches(xdo, &installed, XkbAllExplicitMask)) {
      return _xdo_restore_scratch(xdo) == XDO_SUCCESS ? XDO_ERROR : XDO_CLEANUP_ERROR;
    }
    key->code = scratch_keycode;
  }

  int status = _xdo_text_pair(xdo, key->code, modifiers, delay);
  if (status == XDO_CLEANUP_ERROR)
    return status;

  if (xdo->scratch_original != NULL && _xdo_restore_scratch(xdo) != XDO_SUCCESS)
    return XDO_CLEANUP_ERROR;
  XFlush(xdo->xdpy);
  return status;
}

int xdo_enter_text_scalar(xdo_t *xdo, unsigned int scalar, useconds_t delay) {
  charcodemap_t key = {0};
  KeyCode modifiers[Mod5MapIndex + 1] = {0};
  if (xdo == NULL || xdo->xdpy == NULL
      || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)
      || (scalar < 0x20 && scalar != '\t' && scalar != '\n' && scalar != '\r')
      || (scalar >= 0x7f && scalar <= 0x9f))
    return XDO_ERROR;
  if (xdo->scratch_original != NULL || xdo->text_keys_len != 0)
    return XDO_CLEANUP_ERROR;

  KeySym symbol = scalar <= 0xff ? scalar : 0x01000000UL | scalar;
  if (scalar == '\n' || scalar == '\r') symbol = XK_Return;
  if (scalar == '\t') symbol = XK_Tab;
  XkbStateRec state;
  if (XkbGetState(xdo->xdpy, XkbUseCoreKbd, &state) != Success
      || state.group >= XkbNumKbdGroups)
    return XDO_ERROR;
  xcb_connection_t *connection = XGetXCBConnection(xdo->xdpy);
  if (connection == NULL || xcb_connection_has_error(connection))
    return XDO_ERROR;
  XFlush(xdo->xdpy);
  unsigned char held[32];
  if (_xdo_query_keys(connection, held) != XDO_SUCCESS)
    return XDO_ERROR;
  _xdo_charcodemap_from_keysym(xdo, &key, symbol, state.group);
  if (!key.needs_binding && (held[key.code / 8] & (1U << (key.code % 8))))
    return XDO_ERROR;
  if (_xdo_get_key_modifiers(xdo, &key, held, modifiers) != XDO_SUCCESS)
    return XDO_ERROR;

  return _xdo_enter_text_scalar_do(xdo, &key, modifiers, held, delay);
}

/* Helper functions */
static void _xdo_charcodemap_from_keysym(const xdo_t *xdo, charcodemap_t *key,
                                      KeySym keysym, unsigned int current_group) {
  int i = 0;
  int len = xdo->charcodes_len;

  key->code = 0;
  key->symbol = keysym;
  key->group = 0;
  key->modmask = 0;
  key->needs_binding = 1;

  for (i = 0; i < len; i++) {
    unsigned int groups = XkbNumGroups(xdo->charcodes[i].group_info);
    unsigned int group = current_group;
    if (groups == 0)
      continue;
    /* Match XKB event lookup without changing the keyboard's group state. */
    if (group >= groups) {
      switch (XkbOutOfRangeGroupAction(xdo->charcodes[i].group_info)) {
        case XkbClampIntoRange: group = groups - 1; break;
        case XkbRedirectIntoRange:
          group = XkbOutOfRangeGroupNumber(xdo->charcodes[i].group_info);
          if (group >= groups) group = 0;
          break;
        default: group %= groups; break;
      }
    }
    if (xdo->charcodes[i].symbol == keysym && xdo->charcodes[i].group == (int)group) {
      key->code = xdo->charcodes[i].code;
      key->group = xdo->charcodes[i].group;
      key->modmask = xdo->charcodes[i].modmask;
      key->needs_binding = 0;
      return;
    }
  }
}

static int _xdo_populate_charcode_map(xdo_t *xdo) {
  int keycodes_length = 0;
  int idx = 0;
  int keycode, group, groups, level, modmask, num_map;
  int status = XDO_ERROR;
  XkbDescPtr desc = XkbGetMap(xdo->xdpy, XkbAllClientInfoMask, XkbUseCoreKbd);
  if (desc == NULL)
    return XDO_ERROR;
  XkbClientMapPtr map = desc->map;
  if (desc->min_key_code < XkbMinLegalKeyCode
      || desc->max_key_code < desc->min_key_code
      || map == NULL || map->types == NULL || map->key_sym_map == NULL
      || map->syms == NULL || map->modmap == NULL
      || map->num_types == 0 || map->num_types > map->size_types
      || map->num_syms > map->size_syms)
    goto done;

  /* Validate and count the same snapshot that supplies the stored symbols. */
  for (keycode = desc->min_key_code; keycode <= desc->max_key_code; keycode++) {
    XkbSymMapPtr symbols = &map->key_sym_map[keycode];
    groups = XkbKeyNumGroups(desc, keycode);
    if (groups > XkbNumKbdGroups)
      goto done;
    if (groups == 0)
      continue;
    if (symbols->width == 0 || symbols->offset > map->num_syms
        || groups * symbols->width > map->num_syms - symbols->offset)
      goto done;
    for (group = 0; group < groups; group++) {
      if (symbols->kt_index[group] >= map->num_types)
        goto done;
      XkbKeyTypePtr type = XkbKeyKeyType(desc, keycode, group);
      if (type->num_levels == 0 || type->num_levels > symbols->width
          || (type->map_count != 0 && type->map == NULL))
        goto done;
      for (num_map = 0; num_map < type->map_count; num_map++)
        if (type->map[num_map].level >= type->num_levels)
          goto done;
      /* KeyCode, four groups and byte-sized levels bound this integer sum. */
      keycodes_length += type->num_levels;
    }
  }
  if (keycodes_length == 0)
    goto done;
  xdo->charcodes = calloc(keycodes_length, sizeof(charcodemap_t));
  if (xdo->charcodes == NULL)
    goto done;
  xdo->keycode_low = desc->min_key_code;
  xdo->keycode_high = desc->max_key_code;

  for (keycode = xdo->keycode_low; keycode <= xdo->keycode_high; keycode++) {
    groups = XkbKeyNumGroups(desc, keycode);
    for (group = 0; group < groups; group++) {
      XkbKeyTypePtr key_type = XkbKeyKeyType(desc, keycode, group);
      for (level = 0; level < key_type->num_levels; level++) {
        KeySym keysym = XkbKeySymEntry(desc, keycode, level, group);
        modmask = 0;

        for (num_map = 0; num_map < key_type->map_count; num_map++) {
          XkbKTMapEntryRec map = key_type->map[num_map];
          if (map.active && map.level == level) {
            modmask = map.mods.mask;
            break;
          }
        }

        xdo->charcodes[idx].code = keycode;
        xdo->charcodes[idx].group = group;
        xdo->charcodes[idx].group_info = XkbKeyGroupInfo(desc, keycode);
        xdo->charcodes[idx].modmask = modmask | map->modmap[keycode];
        xdo->charcodes[idx].symbol = keysym;

        idx++;
      }
    }
  }
  xdo->charcodes_len = idx;
  status = XDO_SUCCESS;
done:
  XkbFreeKeyboard(desc, 0, True);
  return status;
}

int _is_success(const char *funcname, int code, const xdo_t *xdo) {
  /* Nonzero is failure. */
  if (code != 0 && !xdo->quiet)
    fprintf(stderr, "%s failed (code=%d)\n", funcname, code);
  return code;
}

static int _xdo_press_text_key(xdo_t *xdo, KeyCode code) {
  if (xdo->text_keys_len >= sizeof(xdo->text_keys) / sizeof(xdo->text_keys[0])
      || !XTestFakeKeyEvent(xdo->xdpy, code, True, CurrentTime))
    return XDO_ERROR;
  xdo->text_keys[xdo->text_keys_len++] = code;
  XSync(xdo->xdpy, False);
  return XDO_SUCCESS;
}

static int _xdo_retire_text_keys(xdo_t *xdo) {
  while (xdo->text_keys_len != 0) {
    KeyCode code = xdo->text_keys[xdo->text_keys_len - 1];
    if (!XTestFakeKeyEvent(xdo->xdpy, code, False, CurrentTime))
      return XDO_CLEANUP_ERROR;
    xdo->text_keys_len--;
    XSync(xdo->xdpy, False);
  }
  return XDO_SUCCESS;
}

static int _xdo_text_pair(xdo_t *xdo, KeyCode key,
                         const KeyCode *modifiers, useconds_t delay) {
  int status = XDO_SUCCESS;
  for (int i = ShiftMapIndex; i <= Mod5MapIndex; i++) {
    if (modifiers[i] != 0
        && _xdo_press_text_key(xdo, modifiers[i]) != XDO_SUCCESS) {
      status = XDO_ERROR;
      break;
    }
  }
  if (status == XDO_SUCCESS)
    status = _xdo_press_text_key(xdo, key);
  if (status == XDO_SUCCESS && delay / 2 > 0)
    usleep(delay / 2);
  if (_xdo_retire_text_keys(xdo) != XDO_SUCCESS)
    return XDO_CLEANUP_ERROR;
  if (status == XDO_SUCCESS && delay / 2 > 0)
    usleep(delay / 2);
  return status;
}

static int _xdo_get_key_modifiers(const xdo_t *xdo, const charcodemap_t *key,
                                const unsigned char *held, KeyCode *modifiers) {
  int modmask = key->modmask;
  if (modmask == 0)
    return XDO_SUCCESS;
  if ((modmask & ~0xff) != 0 || xdo->keycode_low < 8 || xdo->keycode_high > 255
      || xdo->keycode_low > xdo->keycode_high)
    return XDO_ERROR;
  XModifierKeymap *map = XGetModifierMapping(xdo->xdpy);
  if (map == NULL)
    return XDO_ERROR;
  int status = XDO_ERROR;
  if (map->max_keypermod <= 0 || map->max_keypermod > 255 || map->modifiermap == NULL)
    goto done;
  for (int i = ShiftMapIndex; i <= Mod5MapIndex; i++) {
    if (!(modmask & (1 << i)))
      continue;
    KeyCode selected = 0;
    for (int j = 0; j < map->max_keypermod; j++) {
      KeyCode code = map->modifiermap[i * map->max_keypermod + j];
      if (code == 0)
        continue;
      if (code < xdo->keycode_low || code > xdo->keycode_high)
        goto done;
      selected = code;
      break;
    }
    if (selected == 0 || (!key->needs_binding && selected == key->code))
      goto done;
    if (held[selected / 8] & (1U << (selected % 8)))
      continue;
    /* Modifier slots may share a physical code; acquire that code only once. */
    for (int j = ShiftMapIndex; j < i; j++) {
      if (modifiers[j] == selected) {
        selected = 0;
        break;
      }
    }
    modifiers[i] = selected;
  }
  status = XDO_SUCCESS;
done:
  XFreeModifiermap(map);
  return status;
}

static int _xdo_query_keys(xcb_connection_t *connection, unsigned char *output) {
  int status = XDO_ERROR;
  xcb_generic_error_t *error = NULL;
  xcb_query_keymap_reply_t *keys = xcb_query_keymap_reply(connection,
      xcb_query_keymap(connection), &error);
  if (keys != NULL && error == NULL && keys->response_type == 1
      && keys->length == 2 && !xcb_connection_has_error(connection)) {
    memcpy(output, keys->keys, 32);
    status = XDO_SUCCESS;
  }
  free(error);
  free(keys);
  return status;
}

int xdo_query_input_state(const xdo_t *xdo, xdo_input_state_t *output) {
  if (xdo == NULL || xdo->xdpy == NULL || output == NULL
      || xdo->keycode_low < 8 || xdo->keycode_high > 255
      || xdo->keycode_low > xdo->keycode_high)
    return XDO_ERROR;

  /* Borrow the same connection; Xlib retains Display and event-queue ownership. */
  xcb_connection_t *connection = XGetXCBConnection(xdo->xdpy);
  if (connection == NULL || xcb_connection_has_error(connection))
    return XDO_ERROR;
  XFlush(xdo->xdpy);

  xdo_input_state_t state = {0};
  int status = XDO_ERROR;
  xcb_generic_error_t *error = NULL;
  xcb_query_pointer_reply_t *pointer = xcb_query_pointer_reply(connection,
      xcb_query_pointer(connection, DefaultRootWindow(xdo->xdpy)), &error);
  if (pointer == NULL || error != NULL || pointer->response_type != 1
      || pointer->length != 0 || pointer->same_screen > 1
      || xcb_connection_has_error(connection))
    goto pointer_done;
  state.pointer_mask = pointer->mask;
  status = XDO_SUCCESS;
pointer_done:
  free(error);
  free(pointer);
  if (status != XDO_SUCCESS)
    return status;

  if (_xdo_query_keys(connection, state.keys) != XDO_SUCCESS)
    return XDO_ERROR;

  Atom caps_name = XInternAtom(xdo->xdpy, "Caps Lock", True);
  Atom num_name = XInternAtom(xdo->xdpy, "Num Lock", True);
  Bool caps = False, num = False;
  if (caps_name == None || num_name == None
      || !XkbGetNamedIndicator(xdo->xdpy, caps_name, NULL, &caps, NULL, NULL)
      || !XkbGetNamedIndicator(xdo->xdpy, num_name, NULL, &num, NULL, NULL)
      || (caps != False && caps != True) || (num != False && num != True)
      || xcb_connection_has_error(connection))
    return XDO_ERROR;
  state.caps_lock = caps;
  state.num_lock = num;
  state.keycode_min = xdo->keycode_low;
  state.keycode_max = xdo->keycode_high;
  *output = state;
  return XDO_SUCCESS;
}

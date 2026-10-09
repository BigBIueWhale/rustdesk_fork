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
#include <X11/XKBlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>

#include <xkbcommon/xkbcommon.h>

#include "xdo.h"
#include "xdo_version.h"

static int _xdo_populate_charcode_map(xdo_t *xdo);

static void _xdo_charcodemap_from_keysym(const xdo_t *xdo, charcodemap_t *key, KeySym keysym);
static void _xdo_send_key(const xdo_t *xdo, unsigned int kind, charcodemap_t *key,
                          const KeyCode *modifiers, int is_press, int current_group, useconds_t delay);
static int _xdo_get_key_modifiers(const xdo_t *xdo, int modmask, KeyCode *modifiers);

static int _xdo_mousebutton(const xdo_t *xdo, int button, int is_press);

static int _is_success(const char *funcname, int code, const xdo_t *xdo);

/* context-free functions */
static wchar_t _keysym_to_char(KeySym keysym);

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
    xdo_free(xdo);
    return NULL;
  }
  xdo->close_display_when_freed = close_display_when_freed;
  return xdo;
}

void xdo_free(xdo_t *xdo) {
  if (xdo == NULL)
    return;

  if (xdo->display_name)
    free(xdo->display_name);
  if (xdo->charcodes)
    free(xdo->charcodes);
  if (xdo->xdpy && xdo->close_display_when_freed)
    XCloseDisplay(xdo->xdpy);

  free(xdo);
}

const char *xdo_version(void) {
  return XDO_VERSION;
}

int xdo_move_mouse(const xdo_t *xdo, int x, int y, int screen)  {
  int ret = 0;

  /* There is a bug (feature?) in XTestFakeMotionEvent that causes
   * the screen number in the request to be ignored. The internets
   * seem to recommend XWarpPointer instead, ie;
   * https://bugzilla.redhat.com/show_bug.cgi?id=518803
   */
  Window screen_root = RootWindow(xdo->xdpy, screen);
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

static int _xdo_send_key_do(const xdo_t *xdo, unsigned int kind, charcodemap_t *key,
                                   int pressed, const KeyCode *modifiers, int current_group, useconds_t delay) {
  KeySym *keysyms = NULL;
  int keysyms_per_keycode = 0;
  int scratch_keycode = 0;

  /* Acquire the complete scratch resource before sending any input. */
  if (key->needs_binding) {
    if (xdo->keycode_low < 8 || xdo->keycode_high > 255
        || xdo->keycode_low > xdo->keycode_high)
      return XDO_ERROR;
    keysyms = XGetKeyboardMapping(xdo->xdpy, xdo->keycode_low,
                                  xdo->keycode_high - xdo->keycode_low + 1,
                                  &keysyms_per_keycode);
    if (keysyms == NULL || keysyms_per_keycode <= 0) {
      if (keysyms != NULL)
        XFree(keysyms);
      return XDO_ERROR;
    }

    for (int i = xdo->keycode_low; i <= xdo->keycode_high; i++) {
      int key_is_empty = 1;
      for (int j = 0; j < keysyms_per_keycode; j++) {
        size_t symindex = (size_t)(i - xdo->keycode_low) * keysyms_per_keycode + j;
        if (keysyms[symindex] != NoSymbol) {
          key_is_empty = 0;
          break;
        }
      }
      if (key_is_empty) {
        scratch_keycode = i;
        break;
      }
    }
    if (scratch_keycode == 0) {
      XFree(keysyms);
      return XDO_ERROR;
    }
    KeySym keysym_list[] = { key->symbol };
    XChangeKeyboardMapping(xdo->xdpy, scratch_keycode, 1, keysym_list, 1);
    XSync(xdo->xdpy, False);
    key->code = scratch_keycode;
  }

  _xdo_send_key(xdo, kind, key, modifiers, pressed, current_group, delay);

  if (keysyms != NULL) {
    XSync(xdo->xdpy, False);
    KeySym *original = keysyms + (size_t)(scratch_keycode - xdo->keycode_low)
                                * keysyms_per_keycode;
    XChangeKeyboardMapping(xdo->xdpy, scratch_keycode, keysyms_per_keycode, original, 1);
    XSync(xdo->xdpy, False);
    XFree(keysyms);
  }
  XFlush(xdo->xdpy);
  return XDO_SUCCESS;
}

int xdo_send_key(const xdo_t *xdo, unsigned int kind,
                        unsigned long value, unsigned int action, useconds_t delay) {
  charcodemap_t key = {0};
  KeyCode modifiers[Mod5MapIndex + 1] = {0};
  if (xdo == NULL || xdo->xdpy == NULL
      || (action != XDO_KEY_DOWN && action != XDO_KEY_UP && action != XDO_KEY_CLICK))
    return XDO_ERROR;

  if (kind == XDO_KEYSYM) {
    if (value == NoSymbol || value == XK_VoidSymbol || value > 0x1fffffffUL)
      return XDO_ERROR;
    if (value >= 0x01000000UL && value <= 0x01ffffffUL) {
      unsigned long scalar = value - 0x01000000UL;
      if (scalar < 0x100 || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff))
        return XDO_ERROR;
    }
    _xdo_charcodemap_from_keysym(xdo, &key, value);
  } else if (kind == XDO_KEYCODE) {
    if (xdo->keycode_low < 8 || xdo->keycode_high > 255
        || xdo->keycode_low > xdo->keycode_high
        || value < (unsigned)xdo->keycode_low || value > (unsigned)xdo->keycode_high)
      return XDO_ERROR;
    key.code = value;
  } else {
    return XDO_ERROR;
  }

  XkbStateRec state;
  if (XkbGetState(xdo->xdpy, XkbUseCoreKbd, &state) != Success
      || state.group >= XkbNumKbdGroups)
    return XDO_ERROR;
  if (_xdo_get_key_modifiers(xdo, key.modmask, modifiers) != XDO_SUCCESS)
    return XDO_ERROR;

  if (action != XDO_KEY_CLICK)
    return _xdo_send_key_do(xdo, kind, &key, action == XDO_KEY_DOWN, modifiers, state.group, delay);

  int status = _xdo_send_key_do(xdo, kind, &key, True, modifiers, state.group, delay / 2);
  if (status != XDO_SUCCESS)
    return status;
  /* Release the exact code just pressed without reacquiring a scratch resource. */
  key.needs_binding = 0;
  return _xdo_send_key_do(xdo, kind, &key, False, modifiers, state.group, delay / 2);
}

/* Helper functions */
static void _xdo_charcodemap_from_keysym(const xdo_t *xdo, charcodemap_t *key, KeySym keysym) {
  int i = 0;
  int len = xdo->charcodes_len;

  key->code = 0;
  key->symbol = keysym;
  key->group = 0;
  key->modmask = 0;
  key->needs_binding = 1;

  for (i = 0; i < len; i++) {
    if (xdo->charcodes[i].symbol == keysym) {
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

        xdo->charcodes[idx].key = _keysym_to_char(keysym);
        xdo->charcodes[idx].code = keycode;
        xdo->charcodes[idx].group = group;
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

/* context-free functions */
wchar_t _keysym_to_char(KeySym keysym) {
  return (wchar_t)xkb_keysym_to_utf32(keysym);
}

int _is_success(const char *funcname, int code, const xdo_t *xdo) {
  /* Nonzero is failure. */
  if (code != 0 && !xdo->quiet)
    fprintf(stderr, "%s failed (code=%d)\n", funcname, code);
  return code;
}

void _xdo_send_key(const xdo_t *xdo, unsigned int kind, charcodemap_t *key,
                          const KeyCode *modifiers, int is_press, int current_group, useconds_t delay) {
  if (kind == XDO_KEYSYM)
    XkbLockGroup(xdo->xdpy, XkbUseCoreKbd, key->group);
  for (int i = ShiftMapIndex; i <= Mod5MapIndex; i++) {
    if (modifiers[i] != 0) {
      XTestFakeKeyEvent(xdo->xdpy, modifiers[i], is_press, CurrentTime);
      XSync(xdo->xdpy, False);
    }
  }
  XTestFakeKeyEvent(xdo->xdpy, key->code, is_press, CurrentTime);
  if (kind == XDO_KEYSYM)
    XkbLockGroup(xdo->xdpy, XkbUseCoreKbd, current_group);
  XSync(xdo->xdpy, False);

  /* Skipping the usleep if delay is 0 is much faster than calling usleep(0) */
  XFlush(xdo->xdpy);
  if (delay > 0) {
    usleep(delay);
  }
}

static int _xdo_get_key_modifiers(const xdo_t *xdo, int modmask, KeyCode *modifiers) {
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
    for (int j = 0; j < map->max_keypermod; j++) {
      KeyCode code = map->modifiermap[i * map->max_keypermod + j];
      if (code == 0)
        continue;
      if (code < xdo->keycode_low || code > xdo->keycode_high)
        goto done;
      modifiers[i] = code;
      break;
    }
    if (modifiers[i] == 0)
      goto done;
  }
  status = XDO_SUCCESS;
done:
  XFreeModifiermap(map);
  return status;
}

unsigned int xdo_get_input_state(const xdo_t *xdo) {
  Window root, dummy;
  int root_x, root_y, win_x, win_y;
  unsigned int mask;
  root = DefaultRootWindow(xdo->xdpy);

  XQueryPointer(xdo->xdpy, root, &dummy, &dummy,
                &root_x, &root_y, &win_x, &win_y, &mask);

  return mask;
}

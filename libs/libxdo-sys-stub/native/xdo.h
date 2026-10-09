/**
 * @file xdo.h
 */
#ifndef _XDO_H_
#define _XDO_H_

#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif /* __USE_XOPEN */

#include <sys/types.h>
#include <X11/Xlib.h>
#include <X11/X.h>
#include <unistd.h>
#include <wchar.h>

/**
 * @mainpage
 *
 * The private provider sends mouse and keyboard input and queries cursor/input state.
 * Keyboard and button input use XTEST on the context display; the X server
 * routes it according to its focus, pointer and grabs.
 *
 * @see xdo.h
 * @see xdo_new
 */

/**
 * @internal
 * Map character to whatever information we need to be able to send
 * this key (keycode, modifiers, group, etc)
 */
typedef struct charcodemap {
  wchar_t key; /** the letter for this key, like 'a' */
  KeyCode code; /** the keycode that this key is on */
  KeySym symbol; /** the symbol representing this key */
  int group; /** the keyboard group that has this key in it */
  int modmask; /** the modifiers to apply when sending this key */
   /** if this key need to be bound at runtime because it does not
    * exist in the current keymap, this will be set to 1. */
  int needs_binding;
} charcodemap_t;

/**
 * The main context.
 */
typedef struct xdo {

  /** The Display for Xlib */
  Display *xdpy;

  /** The display name, if any. NULL if not specified. */
  char *display_name;

  /** @internal Array of known keys/characters */
  charcodemap_t *charcodes;

  /** @internal Length of charcodes array */
  int charcodes_len;

  /** @internal UNUSED -- result from XGetModifierMapping */
  XModifierKeymap *modmap;

  /** @internal UNUSED -- current keyboard mapping (via XGetKeyboardMapping) */
  KeySym *keymap;

  /** @internal highest keycode value */
  int keycode_high; /* highest and lowest keycodes */

  /** @internal lowest keycode value */
  int keycode_low;  /* used by this X server */

  /** @internal UNUSED -- core keysyms-per-keycode ABI field */
  int keysyms_per_keycode;

  /** Should we close the display when calling xdo_free? */
  int close_display_when_freed;

  /** Be extra quiet? (omits some error/message output) */
  int quiet;

  /** @internal UNUSED -- debug ABI field */
  int debug;

  /** @internal UNUSED -- feature-mask ABI field */
  int features_mask;

} xdo_t;

#define XDO_ERROR 1
#define XDO_SUCCESS 0

/**
 * Create a new xdo_t instance.
 *
 * @param display the string display name, such as ":0". If null, uses the
 * environment variable DISPLAY just like XOpenDisplay(NULL).
 *
 * @return Pointer to a complete xdo_t or NULL when XTEST or the keymap is
 * unavailable, or another construction step fails.
 */
xdo_t* xdo_new(const char *display);

/**
 * Create a new xdo_t instance with an existing X11 Display instance.
 *
 * @param xdpy the Display pointer given by a previous XOpenDisplay()
 * @param display the string display name
 * @param close_display_when_freed If true, we will close the display when
 * xdo_free is called. Otherwise, we leave it open. Ownership transfers only
 * on success; the caller retains the display when construction returns NULL.
 * XTEST availability is required before context allocation or keymap queries.
 * @return Pointer to a complete xdo_t or NULL on failure.
 */
xdo_t* xdo_new_with_opened_display(Display *xdpy, const char *display,
                                   int close_display_when_freed);

/**
 * Return a string representing the version of this library
 */
const char *xdo_version(void);

/**
 * Free and destroy an xdo_t instance.
 *
 * If close_display_when_freed is set, then we will also close the Display.
 */
void xdo_free(xdo_t *xdo);

/**
 * Move the mouse to a location on the context Display's selected screen.
 *
 * @param x the target X coordinate on the screen in pixels.
 * @param y the target Y coordinate on the screen in pixels.
 */
int xdo_move_mouse(const xdo_t *xdo, int x, int y);

/**
 * Move the mouse relative to it's current position.
 *
 * @param x the distance in pixels to move on the X axis.
 * @param y the distance in pixels to move on the Y axis.
 */
int xdo_move_mouse_relative(const xdo_t *xdo, int x, int y);

/**
 * Send a mouse press (aka mouse down) for a given button at the current mouse
 * location.
 *
 * @param button The mouse button. Generally, 1 is left, 2 is middle, 3 is
 *    right, 4 is wheel up, 5 is wheel down.
 */
int xdo_mouse_down(const xdo_t *xdo, int button);

/**
 * Send a mouse release (aka mouse up) for a given button at the current mouse
 * location.
 *
 * @param button The mouse button. Generally, 1 is left, 2 is middle, 3 is
 *    right, 4 is wheel up, 5 is wheel down.
 */
int xdo_mouse_up(const xdo_t *xdo, int button);

/**
 * Get the current mouse location (coordinates and screen number).
 *
 * @param x integer pointer where the X coordinate will be stored
 * @param y integer pointer where the Y coordinate will be stored
 * @param screen_num integer pointer where the screen number will be stored
 */
int xdo_get_mouse_location(const xdo_t *xdo, int *x, int *y, int *screen_num);

#define XDO_KEYSYM 1U
#define XDO_KEYCODE 2U
#define XDO_KEY_DOWN 1U
#define XDO_KEY_UP 2U
#define XDO_KEY_CLICK 3U

/**
 * Send one keysym or raw keycode with an explicit down, up, or click action.
 *
 * Keysyms are nonzero 29-bit X11 values, excluding VoidSymbol. Unicode keysyms
 * must encode a Unicode scalar in U+0100..U+10FFFF. Raw keycodes must lie in the
 * context's inclusive native range and are validated before narrowing. They
 * send physical key events without selecting or restoring a keyboard group.
 * Invalid kinds, values, or actions return XDO_ERROR before input.
 * A click resolves once and releases the exact code pressed.
 *
 * @param delay Delay in microseconds; a click divides it between down and up.
 */
int xdo_send_key(const xdo_t *xdo, unsigned int kind,
                        unsigned long value, unsigned int action, useconds_t delay);

/**
 * Get the current input state. This is a mask value containing any of the
 * following: ShiftMask, LockMask, ControlMask, Mod1Mask, Mod2Mask, Mod3Mask,
 * Mod4Mask, or Mod5Mask.
 *
 * @return the input mask
 */
unsigned int xdo_get_input_state(const xdo_t *xdo);

#endif /* ifndef _XDO_H_ */

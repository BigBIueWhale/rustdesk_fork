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
  KeyCode code; /** the keycode that this key is on */
  KeySym symbol; /** the symbol representing this key */
  int group; /** the keyboard group that has this key in it */
  unsigned char group_info; /** snapshot group count and range normalization */
  int modmask; /** the modifiers to apply when sending this key */
   /** Set when the symbol needs a binding in the current effective group. */
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

  /** Scratch lease retained until keys retire and restoration is confirmed. */
  struct _XkbDesc *scratch_original;
  KeyCode scratch_keycode;

  /** Accepted text presses awaiting reverse-order retirement. */
  KeyCode text_keys[9];
  unsigned int text_keys_len;

} xdo_t;

#define XDO_ERROR 1
#define XDO_SUCCESS 0
#define XDO_CLEANUP_ERROR 2

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
 * Retire keys and the scratch lease, then destroy an xdo_t instance.
 *
 * XDO_SUCCESS frees the context and closes an owned Display. A NULL context
 * succeeds. XDO_CLEANUP_ERROR retains the live context, remaining keys, original
 * scratch map, allocations and Display for another retirement attempt. The
 * caller must not discard the owner or close its borrowed Display on failure.
 */
int xdo_free(xdo_t *xdo);

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

/**
 * Enter one Unicode text scalar as a matched key press and release.
 *
 * Surrogates, values above U+10FFFF and C0/C1 controls other than tab, newline
 * and carriage return return XDO_ERROR before input. Tab maps to XK_Tab;
 * newline and carriage return map to XK_Return. Other scalars use Latin-1
 * or Unicode keysyms. Both legs retain the same resolved code, modifiers
 * and scratch mapping. Temporary modifiers press before the main key and
 * release in reverse order after its release. Resolution uses the current
 * effective group and each key's group normalization; text never writes the
 * global group lock. Scratch selection excludes keys held in a checked
 * logical-key snapshot. A mapped text key already held refuses; required
 * modifiers already held are preserved. Shared modifier codes appear only once
 * in the admitted plan; a mapped main/modifier code collision refuses before input.
 * Separate state queries are not atomic against concurrent input. Scratch
 * rows must have neutral XKB semantics; their original symbols, types, groups,
 * actions and explicit controls are restored
 * and checked after release. Submission failure stops acquisition and retires
 * only accepted presses. XDO_CLEANUP_ERROR retains unresolved presses and any
 * original scratch map, blocks further text, and retries retirement at destruction
 * before restoring the map or closing the Display. Submission is not delivery.
 *
 * @param delay Delay in microseconds, divided between press and release.
 */
int xdo_enter_text_scalar(xdo_t *xdo, unsigned int scalar, useconds_t delay);

typedef struct xdo_input_state {
  unsigned int pointer_mask;
  unsigned char keys[32];
  unsigned char caps_lock;
  unsigned char num_lock;
  unsigned char keycode_min;
  unsigned char keycode_max;
} xdo_input_state_t;

/**
 * Collect checked core pointer/key state and named XKB lock indicators on the
 * retained Display. A valid pointer reply on a different screen is accepted.
 * Queries precede publication; failure leaves the caller's output untouched.
 * Separate replies are not an atomic hardware sample. No input is emitted.
 */
int xdo_query_input_state(const xdo_t *xdo, xdo_input_state_t *state);

#endif /* ifndef _XDO_H_ */

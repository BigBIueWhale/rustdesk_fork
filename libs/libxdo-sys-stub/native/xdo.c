/* xdo library
 * - getwindowfocus contributed by Lee Pumphret
 * - keysequence_{up,down} contributed by Magnus Boman
 *
 * See the following url for an explanation of how keymaps work in X11
 * http://www.in-ulm.de/~mascheck/X11/xmodmap.html
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif /* _XOPEN_SOURCE */

#include <sys/select.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <stdarg.h>

#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/Xatom.h>
#include <X11/Xresource.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/extensions/Xinerama.h>
#include <X11/keysym.h>
#include <X11/cursorfont.h>

#include <xkbcommon/xkbcommon.h>

#include "xdo.h"
#include "xdo_version.h"

#define DEFAULT_DELAY 12

/**
 * The number of tries to check for a wait condition before aborting.
 * TODO(sissel): Make this tunable at runtime?
 */
#define MAX_TRIES 500

static int _xdo_populate_charcode_map(xdo_t *xdo);
static int _xdo_has_xtest(const xdo_t *xdo);

static void _xdo_charcodemap_from_keysym(const xdo_t *xdo, charcodemap_t *key, KeySym keysym);
static int _xdo_ewmh_is_supported(const xdo_t *xdo, const char *feature);
static void _xdo_init_xkeyevent(const xdo_t *xdo, XKeyEvent *xk);
static void _xdo_send_key(const xdo_t *xdo, Window window, charcodemap_t *key,
                          int modstate, int is_press, useconds_t delay);
static void _xdo_send_modifier(const xdo_t *xdo, int modmask, int is_press);

static int _xdo_mousebutton(const xdo_t *xdo, Window window, int button, int is_press);

static int _is_success(const char *funcname, int code, const xdo_t *xdo);
static void _xdo_debug(const xdo_t *xdo, const char *format, ...);
static void _xdo_eprintf(const xdo_t *xdo, int hushable, const char *format, ...);

/* context-free functions */
static wchar_t _keysym_to_char(KeySym keysym);

/* Default to -1, initialize it when we need it */
static Atom atom_NET_WM_PID = -1;
static Atom atom_NET_WM_NAME = -1;
static Atom atom_WM_NAME = -1;
static Atom atom_STRING = -1;
static Atom atom_UTF8_STRING = -1;

xdo_t* xdo_new(const char *display_name) {
  Display *xdpy;

  if ((xdpy = XOpenDisplay(display_name)) == NULL) {
    /* Can't use _xdo_eprintf yet ... */
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
    /* Can't use _xdo_eprintf yet ... */
    fprintf(stderr, "xdo_new: xdisplay I was given is a null pointer\n");
    return NULL;
  }

  xdo = calloc(1, sizeof(xdo_t));
  if (xdo == NULL) {
    fprintf(stderr, "xdo_new: context allocation failed\n");
    return NULL;
  }

  xdo->xdpy = xdpy;

  if (display == NULL) {
    display = "unknown";
  }

  if (getenv("XDO_QUIET")) {
    xdo->quiet = True;
  }

  if (_xdo_has_xtest(xdo)) {
    xdo_enable_feature(xdo, XDO_FEATURE_XTEST);
    _xdo_debug(xdo, "XTEST enabled.");
  } else {
    _xdo_eprintf(xdo, False, "Warning: XTEST extension unavailable on '%.128s'. Some"
                " functionality may be disabled; See 'man xdotool' for more"
                " info.", display);
    xdo_disable_feature(xdo, XDO_FEATURE_XTEST);
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

int xdo_wait_for_window_map_state(const xdo_t *xdo, Window wid, int map_state) {
  int tries = MAX_TRIES;
  XWindowAttributes attr;
  attr.map_state = IsUnmapped;
  while (tries > 0 && attr.map_state != map_state) {
    XGetWindowAttributes(xdo->xdpy, wid, &attr);
    usleep(30000); /* TODO(sissel): Use exponential backoff up to 1 second */
    tries--;
  }
  return 0;
}

int xdo_map_window(const xdo_t *xdo, Window wid) {
  int ret = 0;
  ret = XMapWindow(xdo->xdpy, wid);
  XFlush(xdo->xdpy);
  return _is_success("XMapWindow", ret == 0, xdo);
}

int xdo_unmap_window(const xdo_t *xdo, Window wid) {
  int ret = 0;
  ret = XUnmapWindow(xdo->xdpy, wid);
  XFlush(xdo->xdpy);
  return _is_success("XUnmapWindow", ret == 0, xdo);
}

int xdo_reparent_window(const xdo_t *xdo, Window wid_source, Window wid_target) {
  int ret = 0;
  ret = XReparentWindow(xdo->xdpy, wid_source, wid_target, 0, 0);
  XFlush(xdo->xdpy);
  return _is_success("XReparentWindow", ret == 0, xdo);
}

int xdo_get_window_location(const xdo_t *xdo, Window wid,
                            int *x_ret, int *y_ret, Screen **screen_ret) {
  int ret;
  XWindowAttributes attr;
  ret = XGetWindowAttributes(xdo->xdpy, wid, &attr);
  if (ret != 0) {
    int x, y;
    Window unused_child;

    /* The coordinates in attr are relative to the parent window.  If
     * the parent window is the root window, then the coordinates are
     * correct.  If the parent window isn't the root window --- which
     * is likely --- then we translate them. */
    Window parent;
    Window root;
    Window* children;
    unsigned int nchildren;
    XQueryTree(xdo->xdpy, wid, &root, &parent, &children, &nchildren);
    if (children != NULL) {
      XFree(children);
    }
    if (parent == attr.root) {
      x = attr.x;
      y = attr.y;
    } else {
      XTranslateCoordinates(xdo->xdpy, wid, attr.root,
                            attr.x, attr.y, &x, &y, &unused_child);
    }

    if (x_ret != NULL) {
      *x_ret = x;
    }

    if (y_ret != NULL) {
      *y_ret = y;
    }

    if (screen_ret != NULL) {
      *screen_ret = attr.screen;
    }
  }
  return _is_success("XGetWindowAttributes", ret == 0, xdo);
}

int xdo_get_window_size(const xdo_t *xdo, Window wid, unsigned int *width_ret,
                        unsigned int *height_ret) {
  int ret;
  XWindowAttributes attr;
  ret = XGetWindowAttributes(xdo->xdpy, wid, &attr);
  if (ret != 0) {
    if (width_ret != NULL) {
      *width_ret = attr.width;
    }

    if (height_ret != NULL) {
      *height_ret = attr.height;
    }
  }
  return _is_success("XGetWindowAttributes", ret == 0, xdo);
}

int xdo_move_window(const xdo_t *xdo, Window wid, int x, int y) {
  XWindowChanges wc;
  int ret = 0;
  wc.x = x;
  wc.y = y;

  ret = XConfigureWindow(xdo->xdpy, wid, CWX | CWY, &wc);
  return _is_success("XConfigureWindow", ret == 0, xdo);
}

int xdo_translate_window_with_sizehint(const xdo_t *xdo, Window window,
                                       unsigned int width, unsigned int height,
                                       unsigned int *width_ret, unsigned int *height_ret) {
  XSizeHints hints;
  long supplied_return;
  XGetWMNormalHints(xdo->xdpy, window, &hints, &supplied_return);
  if (supplied_return & PResizeInc) {
    width *= hints.width_inc;
    height *= hints.height_inc;
  } else {
    fprintf(stderr, "No size hints found for window %ld\n", window);
    *width_ret = width;
    *height_ret = width;
  }

  if (supplied_return & PBaseSize) {
    width += hints.base_width;
    height += hints.base_height;
  }

  if (width_ret != NULL) {
    *width_ret = width;
  }

  if (height_ret != NULL) {
    *height_ret = height;
  }

  return XDO_SUCCESS;
}

int xdo_set_window_size(const xdo_t *xdo, Window window, int width, int height, int flags) {
  XWindowChanges wc;
  int ret = 0;
  int cw_flags = 0;

  if (flags & SIZE_USEHINTS) {
    flags |= SIZE_USEHINTS_X | SIZE_USEHINTS_Y;
  }

  wc.width = width;
  wc.height = height;

  if (flags & SIZE_USEHINTS_X) {
    xdo_translate_window_with_sizehint(xdo, window, width, height, (unsigned int*)&wc.width,
                                       NULL);
  }

  if (flags & SIZE_USEHINTS_Y) {
    xdo_translate_window_with_sizehint(xdo, window, width, height, NULL,
                                       (unsigned int*)&wc.height);
  }

  if (width > 0) {
    cw_flags |= CWWidth;
  }

  if (height > 0) {
    cw_flags |= CWHeight;
  }

  ret = XConfigureWindow(xdo->xdpy, window, cw_flags, &wc);
  XFlush(xdo->xdpy);
  return _is_success("XConfigureWindow", ret == 0, xdo);
}

int xdo_set_window_override_redirect(const xdo_t *xdo, Window wid,
                                     int override_redirect) {
  int ret;
  XSetWindowAttributes wattr;
  long mask = CWOverrideRedirect;
  wattr.override_redirect = override_redirect;
  ret = XChangeWindowAttributes(xdo->xdpy, wid, mask, &wattr);

  return _is_success("XChangeWindowAttributes", ret == 0, xdo);
}

int xdo_focus_window(const xdo_t *xdo, Window wid) {
  int ret = 0;
  ret = XSetInputFocus(xdo->xdpy, wid, RevertToParent, CurrentTime);
  XFlush(xdo->xdpy);
  return _is_success("XSetInputFocus", ret == 0, xdo);
}

int xdo_wait_for_window_size(const xdo_t *xdo, Window window,
                             unsigned int width, unsigned int height,
                             int flags, int to_or_from) {
  unsigned int cur_width, cur_height;
  /*unsigned int alt_width, alt_height;*/

  //printf("Want: %udx%ud\n", width, height);
  if (flags & SIZE_USEHINTS) {
    xdo_translate_window_with_sizehint(xdo, window, width, height,
                                       &width, &height);
  } else {
    unsigned int hint_width, hint_height;
    /* TODO(sissel): fix compiler warning here, but it will require
     * an ABI breakage by changing types... */
    xdo_translate_window_with_sizehint(xdo, window, 1, 1,
                                       &hint_width, &hint_height);
    //printf("Hint: %dx%d\n", hint_width, hint_height);
    /* Find the nearest multiple (rounded down) of the hint height. */
    /*alt_width = (width - (width % hint_width));*/
    /*alt_height = (height - (height % hint_height));*/
    //printf("Alt: %udx%ud\n", alt_width, alt_height);
  }

  int tries = MAX_TRIES;
  xdo_get_window_size(xdo, window, &cur_width,
                      &cur_height);
  //printf("Want: %udx%ud\n", width, height);
  //printf("Alt: %udx%ud\n", alt_width, alt_height);
  while (tries > 0 && (to_or_from == SIZE_TO
         ? (cur_width != width && cur_height != height)
         : (cur_width == width && cur_height == height))) {
    xdo_get_window_size(xdo, window, (unsigned int *)&cur_width,
                        (unsigned int *)&cur_height);
    usleep(30000);
    tries--;
  }

  return 0;
}

int xdo_wait_for_window_active(const xdo_t *xdo, Window window, int active) {
  Window activewin = 0;
  int ret = 0;
  int tries = MAX_TRIES;

  /* If active is true, wait until activewin is our window
   * otherwise, wait until activewin is not our window */
  while (tries > 0 &&
         (active ? activewin != window : activewin == window)) {
    ret = xdo_get_active_window(xdo, &activewin);
    if (ret == XDO_ERROR) {
      return ret;
    }
    usleep(30000);
    tries--;
  }

  return 0;
}

int xdo_activate_window(const xdo_t *xdo, Window wid) {
  int ret = 0;
  long desktop = 0;
  XEvent xev;
  XWindowAttributes wattr;

  if (_xdo_ewmh_is_supported(xdo, "_NET_ACTIVE_WINDOW") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_ACTIVE_WINDOW, "
            "so the attempt to activate the window was aborted.\n");
    return XDO_ERROR;
  }

  /* If this window is on another desktop, let's go to that desktop first */

  if (_xdo_ewmh_is_supported(xdo, "_NET_WM_DESKTOP") == True
      && _xdo_ewmh_is_supported(xdo, "_NET_CURRENT_DESKTOP") == True) {
    xdo_get_desktop_for_window(xdo, wid, &desktop);
    xdo_set_current_desktop(xdo, desktop);
  }

  memset(&xev, 0, sizeof(xev));
  xev.type = ClientMessage;
  xev.xclient.display = xdo->xdpy;
  xev.xclient.window = wid;
  xev.xclient.message_type = XInternAtom(xdo->xdpy, "_NET_ACTIVE_WINDOW", False);
  xev.xclient.format = 32;
  xev.xclient.data.l[0] = 2L; /* 2 == Message from a window pager */
  xev.xclient.data.l[1] = CurrentTime;

  XGetWindowAttributes(xdo->xdpy, wid, &wattr);
  ret = XSendEvent(xdo->xdpy, wattr.screen->root, False,
                   SubstructureNotifyMask | SubstructureRedirectMask,
                   &xev);

  /* XXX: XSendEvent returns 0 on conversion failure, nonzero otherwise.
   * Manpage says it will only generate BadWindow or BadValue errors */
  return _is_success("XSendEvent[EWMH:_NET_ACTIVE_WINDOW]", ret == 0, xdo);
}

int xdo_set_number_of_desktops(const xdo_t *xdo, long ndesktops) {
  /* XXX: This should support passing a screen number */
  XEvent xev;
  Window root;
  int ret = 0;

  if (_xdo_ewmh_is_supported(xdo, "_NET_NUMBER_OF_DESKTOPS") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_NUMBER_OF_DESKTOPS, "
            "so the attempt to change the number of desktops was aborted.\n");
    return XDO_ERROR;
  }

  root = RootWindow(xdo->xdpy, 0);

  memset(&xev, 0, sizeof(xev));
  xev.type = ClientMessage;
  xev.xclient.display = xdo->xdpy;
  xev.xclient.window = root;
  xev.xclient.message_type = XInternAtom(xdo->xdpy, "_NET_NUMBER_OF_DESKTOPS",
                                         False);
  xev.xclient.format = 32;
  xev.xclient.data.l[0] = ndesktops;

  ret = XSendEvent(xdo->xdpy, root, False,
                   SubstructureNotifyMask | SubstructureRedirectMask,
                   &xev);

  return _is_success("XSendEvent[EWMH:_NET_NUMBER_OF_DESKTOPS]", ret == 0, xdo);
}

int xdo_get_number_of_desktops(const xdo_t *xdo, long *ndesktops) {
  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  Window root;
  Atom request;

  if (_xdo_ewmh_is_supported(xdo, "_NET_NUMBER_OF_DESKTOPS") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_NUMBER_OF_DESKTOPS, "
            "so the attempt to query the number of desktops was aborted.\n");
    return XDO_ERROR;
  }

  request = XInternAtom(xdo->xdpy, "_NET_NUMBER_OF_DESKTOPS", False);
  root = XDefaultRootWindow(xdo->xdpy);

  data = xdo_get_window_property_by_atom(xdo, root, request, &nitems, &type, &size);

  if (nitems > 0) {
    *ndesktops = *((long*)data);
  } else {
    *ndesktops = 0;
  }
  free(data);

  return _is_success("XGetWindowProperty[_NET_NUMBER_OF_DESKTOPS]",
                     *ndesktops == 0, xdo);
}

int xdo_set_current_desktop(const xdo_t *xdo, long desktop) {
  /* XXX: This should support passing a screen number */
  XEvent xev;
  Window root;
  int ret = 0;

  root = RootWindow(xdo->xdpy, 0);

  if (_xdo_ewmh_is_supported(xdo, "_NET_CURRENT_DESKTOP") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_CURRENT_DESKTOP, "
            "so the attempt to change desktops was aborted.\n");
    return XDO_ERROR;
  }

  memset(&xev, 0, sizeof(xev));
  xev.type = ClientMessage;
  xev.xclient.display = xdo->xdpy;
  xev.xclient.window = root;
  xev.xclient.message_type = XInternAtom(xdo->xdpy, "_NET_CURRENT_DESKTOP",
                                         False);
  xev.xclient.format = 32;
  xev.xclient.data.l[0] = desktop;
  xev.xclient.data.l[1] = CurrentTime;

  ret = XSendEvent(xdo->xdpy, root, False,
                   SubstructureNotifyMask | SubstructureRedirectMask,
                   &xev);

  return _is_success("XSendEvent[EWMH:_NET_CURRENT_DESKTOP]", ret == 0, xdo);
}

int xdo_get_current_desktop(const xdo_t *xdo, long *desktop) {
  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  Window root;

  Atom request;

  if (_xdo_ewmh_is_supported(xdo, "_NET_CURRENT_DESKTOP") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_CURRENT_DESKTOP, "
            "so the query for the current desktop was aborted.\n");
    return XDO_ERROR;
  }

  request = XInternAtom(xdo->xdpy, "_NET_CURRENT_DESKTOP", False);
  root = XDefaultRootWindow(xdo->xdpy);

  data = xdo_get_window_property_by_atom(xdo, root, request, &nitems, &type, &size);

  if (nitems > 0) {
    *desktop = *((long*)data);
  } else {
    *desktop = -1;
  }
  free(data);

  return _is_success("XGetWindowProperty[_NET_CURRENT_DESKTOP]",
                     *desktop == -1, xdo);
}

int xdo_set_desktop_for_window(const xdo_t *xdo, Window wid, long desktop) {
  XEvent xev;
  int ret = 0;
  XWindowAttributes wattr;
  XGetWindowAttributes(xdo->xdpy, wid, &wattr);

  if (_xdo_ewmh_is_supported(xdo, "_NET_WM_DESKTOP") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_WM_DESKTOP, "
            "so the attempt to change a window's desktop location was "
            "aborted.\n");
    return XDO_ERROR;
  }

  memset(&xev, 0, sizeof(xev));
  xev.type = ClientMessage;
  xev.xclient.display = xdo->xdpy;
  xev.xclient.window = wid;
  xev.xclient.message_type = XInternAtom(xdo->xdpy, "_NET_WM_DESKTOP",
                                         False);
  xev.xclient.format = 32;
  xev.xclient.data.l[0] = desktop;
  xev.xclient.data.l[1] = 2; /* indicate we are messaging from a pager */

  ret = XSendEvent(xdo->xdpy, wattr.screen->root, False,
                   SubstructureNotifyMask | SubstructureRedirectMask,
                   &xev);

  return _is_success("XSendEvent[EWMH:_NET_WM_DESKTOP]", ret == 0, xdo);
}

int xdo_get_desktop_for_window(const xdo_t *xdo, Window wid, long *desktop) {
  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  Atom request;

  if (_xdo_ewmh_is_supported(xdo, "_NET_WM_DESKTOP") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_WM_DESKTOP, "
            "so the attempt to query a window's desktop location was "
            "aborted.\n");
    return XDO_ERROR;
  }

  request = XInternAtom(xdo->xdpy, "_NET_WM_DESKTOP", False);

  data = xdo_get_window_property_by_atom(xdo, wid, request, &nitems, &type, &size);

  if (nitems > 0) {
    *desktop = *((long*)data);
  } else {
    *desktop = -1;
  }
  free(data);

  return _is_success("XGetWindowProperty[_NET_WM_DESKTOP]",
                     *desktop == -1, xdo);
}

int xdo_get_active_window(const xdo_t *xdo, Window *window_ret) {
  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  Atom request;
  Window root;

  if (_xdo_ewmh_is_supported(xdo, "_NET_ACTIVE_WINDOW") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_ACTIVE_WINDOW, "
            "so the attempt to query the active window aborted.\n");
    return XDO_ERROR;
  }

  request = XInternAtom(xdo->xdpy, "_NET_ACTIVE_WINDOW", False);
  root = XDefaultRootWindow(xdo->xdpy);
  data = xdo_get_window_property_by_atom(xdo, root, request, &nitems, &type, &size);

  if (nitems > 0) {
    *window_ret = *((Window*)data);
  } else {
    *window_ret = 0;
  }
  free(data);

  return _is_success("XGetWindowProperty[_NET_ACTIVE_WINDOW]",
                     *window_ret == 0, xdo);
}

int xdo_select_window_with_click(const xdo_t *xdo, Window *window_ret) {
  int screen_num;
  Screen *screen;
  xdo_get_mouse_location(xdo, NULL, NULL, &screen_num);

  screen = ScreenOfDisplay(xdo->xdpy, screen_num);

  /* Grab sync mode so we can ensure nothing changes while we figure
   * out what the client window is.
   * Also, everyone else who does 'select window' does it this way.
   */
  Cursor cursor = XCreateFontCursor(xdo->xdpy, XC_target);
  int grab_ret = 0;
  grab_ret = XGrabPointer(xdo->xdpy, screen->root, False, ButtonReleaseMask,
               GrabModeSync, GrabModeAsync, screen->root, cursor, CurrentTime);
  if (grab_ret == AlreadyGrabbed) {
    fprintf(stderr, "Attempt to grab the mouse failed. Something already has"
            " the mouse grabbed. This can happen if you are dragging something"
            " or if there is a popup currently shown\n");
    return XDO_ERROR;
  }

  XEvent e;
  XAllowEvents(xdo->xdpy, SyncPointer, CurrentTime);
  XWindowEvent(xdo->xdpy, screen->root, ButtonReleaseMask, &e);
  XUngrabPointer(xdo->xdpy, CurrentTime);
  XFreeCursor(xdo->xdpy, cursor);

  if (e.xbutton.button != 1) {
    fprintf(stderr, "window selection aborted with button %d\n", e.xbutton.button);
    return XDO_ERROR;
  }

  /* If there is no subwindow, then we clicked on the root window */
  if (e.xbutton.subwindow == 0) {
    *window_ret = e.xbutton.root;
  } else {
     /* Random testing showed that 'root' always is the same as 'window'
      * while 'subwindow' is the actual window we clicked on. Confusing... */
     *window_ret = e.xbutton.subwindow;
    _xdo_debug(xdo, "Click on window %lu foo", *window_ret);
    xdo_find_window_client(xdo, *window_ret, window_ret, XDO_FIND_CHILDREN);
  }
  return XDO_SUCCESS;
}

/* XRaiseWindow is ignored in ion3 and Gnome2. Is it even useful? */
int xdo_raise_window(const xdo_t *xdo, Window wid) {
  int ret = 0;
  ret = XRaiseWindow(xdo->xdpy, wid);
  XFlush(xdo->xdpy);
  return _is_success("XRaiseWindow", ret == 0, xdo);
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

int xdo_move_mouse_relative_to_window(const xdo_t *xdo, Window window, int x, int y) {
  XWindowAttributes attr;
  Window unused_child;
  int root_x, root_y;

  XGetWindowAttributes(xdo->xdpy, window, &attr);
  XTranslateCoordinates(xdo->xdpy, window, attr.root,
                        x, y, &root_x, &root_y, &unused_child);
  return xdo_move_mouse(xdo, root_x, root_y, XScreenNumberOfScreen(attr.screen));
}

int xdo_move_mouse_relative(const xdo_t *xdo, int x, int y)  {
  int ret = 0;
  ret = XTestFakeRelativeMotionEvent(xdo->xdpy, x, y, CurrentTime);
  XFlush(xdo->xdpy);
  return _is_success("XTestFakeRelativeMotionEvent", ret == 0, xdo);
}

int _xdo_mousebutton(const xdo_t *xdo, Window window, int button, int is_press) {
  int ret = 0;

  if (window == CURRENTWINDOW) {
    ret = XTestFakeButtonEvent(xdo->xdpy, button, is_press, CurrentTime);
    XFlush(xdo->xdpy);
    return _is_success("XTestFakeButtonEvent(down)", ret == 0, xdo);
  } else {
    /* Send to specific window */
    int screen = 0;
    XButtonEvent xbpe;

    xdo_get_mouse_location(xdo, &xbpe.x_root, &xbpe.y_root, &screen);

    xbpe.window = window;
    xbpe.button = button;
    xbpe.display = xdo->xdpy;
    xbpe.root = RootWindow(xdo->xdpy, screen);
    xbpe.same_screen = True; /* Should we detect if window is on the same
                                 screen as cursor? */
    xbpe.state = xdo_get_input_state(xdo);

    xbpe.subwindow = None;
    xbpe.time = CurrentTime;
    xbpe.type = (is_press ? ButtonPress : ButtonRelease);

    /* Get the coordinates of the cursor relative to xbpe.window and also find what
     * subwindow it might be on */
    XTranslateCoordinates(xdo->xdpy, xbpe.root, xbpe.window,
                          xbpe.x_root, xbpe.y_root, &xbpe.x, &xbpe.y, &xbpe.subwindow);

    /* Normal behavior of 'mouse up' is that the modifier mask includes
     * 'ButtonNMotionMask' where N is the button being released. This works the
     * same way with keys, too. */
    if (!is_press) { /* is mouse up */
      switch(button) {
        case 1: xbpe.state |= Button1MotionMask; break;
        case 2: xbpe.state |= Button2MotionMask; break;
        case 3: xbpe.state |= Button3MotionMask; break;
        case 4: xbpe.state |= Button4MotionMask; break;
        case 5: xbpe.state |= Button5MotionMask; break;
      }
    }
    ret = XSendEvent(xdo->xdpy, window, True, ButtonPressMask, (XEvent *)&xbpe);
    XFlush(xdo->xdpy);
    return _is_success("XSendEvent(mousedown)", ret == 0, xdo);
  }
}

int xdo_mouse_up(const xdo_t *xdo, Window window, int button) {
  return _xdo_mousebutton(xdo, window, button, False);
}

int xdo_mouse_down(const xdo_t *xdo, Window window, int button) {
  return _xdo_mousebutton(xdo, window, button, True);
}

int xdo_get_mouse_location(const xdo_t *xdo, int *x_ret, int *y_ret,
                           int *screen_num_ret) {
  return xdo_get_mouse_location2(xdo, x_ret, y_ret, screen_num_ret, NULL);
}

int xdo_get_window_at_mouse(const xdo_t *xdo, Window *window_ret) {
  return xdo_get_mouse_location2(xdo, NULL, NULL, NULL, window_ret);
}

int xdo_get_mouse_location2(const xdo_t *xdo, int *x_ret, int *y_ret,
                            int *screen_num_ret, Window *window_ret) {
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

  if (window_ret != NULL) {
    /* Find the client window if we are not root. */
    if (window != root && window != 0) {
      int findret;
      Window client = 0;

      /* Search up the stack for a client window for this window */
      findret = xdo_find_window_client(xdo, window, &client, XDO_FIND_PARENTS);
      if (findret == XDO_ERROR) {
        /* If no client found, search down the stack */
        findret = xdo_find_window_client(xdo, window, &client, XDO_FIND_CHILDREN);
      }
      //fprintf(stderr, "%ld, %ld, %ld, %d\n", window, root, client, findret);
      if (findret == XDO_SUCCESS) {
        window = client;
      }
    } else {
      window = root;
    }
  }
  //printf("mouseloc root: %ld\n", root);
  //printf("mouseloc window: %ld\n", window);

  if (ret == True) {
    if (x_ret != NULL) *x_ret = x;
    if (y_ret != NULL) *y_ret = y;
    if (screen_num_ret != NULL) *screen_num_ret = screen_num;
    if (window_ret != NULL) *window_ret = window;
  }

  return _is_success("XQueryPointer", ret == False, xdo);
}

int xdo_click_window(const xdo_t *xdo, Window window, int button) {
  int ret = 0;
  ret = xdo_mouse_down(xdo, window, button);
  if (ret != XDO_SUCCESS) {
    fprintf(stderr, "xdo_mouse_down failed, aborting click.\n");
    return ret;
  }
  usleep(DEFAULT_DELAY);
  ret = xdo_mouse_up(xdo, window, button);
  return ret;
}

int xdo_click_window_multiple(const xdo_t *xdo, Window window, int button,
                       int repeat, useconds_t delay) {
  int ret = 0;
  while (repeat > 0) {
    ret = xdo_click_window(xdo, window, button);
    if (ret != XDO_SUCCESS) {
      fprintf(stderr, "click failed with %d repeats remaining\n", repeat);
      return ret;
    }
    repeat--;

    usleep(delay);
  } /* while (repeat > 0) */
  return ret;
} /* int xdo_click_window_multiple */

static int _xdo_send_key_window_do(const xdo_t *xdo, Window window, charcodemap_t *key,
                                   int pressed, int *modifier, useconds_t delay) {
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

  _xdo_send_key(xdo, window, key, *modifier, pressed, delay);
  if (pressed)
    *modifier |= key->modmask;
  else
    *modifier &= ~key->modmask;

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

int xdo_send_key_window(const xdo_t *xdo, Window window, unsigned int kind,
                        unsigned long value, unsigned int action, useconds_t delay) {
  charcodemap_t key = {0};
  int modifier = 0;
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

  if (action != XDO_KEY_CLICK)
    return _xdo_send_key_window_do(xdo, window, &key, action == XDO_KEY_DOWN, &modifier, delay);

  int status = _xdo_send_key_window_do(xdo, window, &key, True, &modifier, delay / 2);
  if (status != XDO_SUCCESS)
    return status;
  /* Release the exact code just pressed without reacquiring a scratch resource. */
  key.needs_binding = 0;
  return _xdo_send_key_window_do(xdo, window, &key, False, &modifier, delay / 2);
}

/* Add by Lee Pumphret 2007-07-28
 * Modified slightly by Jordan Sissel */
int xdo_get_focused_window(const xdo_t *xdo, Window *window_ret) {
  int ret = 0;
  int unused_revert_ret;

  ret = XGetInputFocus(xdo->xdpy, window_ret, &unused_revert_ret);

  /* Xvfb with no window manager and given otherwise no input, with
   * a single client, will return the current focused window as '1'
   * I think this is a bug, so let's alert the user. */
  if (*window_ret == 1) {
    fprintf(stderr,
            "XGetInputFocus returned the focused window of %ld. "
            "This is likely a bug in the X server.\n", *window_ret);
  }
  return _is_success("XGetInputFocus", ret == 0, xdo);
}

int xdo_wait_for_window_focus(const xdo_t *xdo, Window window, int want_focus) {
  Window focuswin = 0;
  int ret;
  int tries = MAX_TRIES;
  ret = xdo_get_focused_window(xdo, &focuswin);
  if (ret != 0) {
    return ret;
  }

  while (tries > 0 &&
         (want_focus ? focuswin != window : focuswin == window)) {
    usleep(30000); /* TODO(sissel): Use exponential backoff up to 1 second */
    ret = xdo_get_focused_window(xdo, &focuswin);
    if (ret != 0) {
      return ret;
    }
    tries--;
  }
  return 0;
}

/* Like xdo_get_focused_window, but return the first ancestor-or-self window
 * having a property of WM_CLASS. This allows you to get the "real" or
 * top-level-ish window having focus rather than something you may
 * not expect to be the window having focused. */
int xdo_get_focused_window_sane(const xdo_t *xdo, Window *window_ret) {
  xdo_get_focused_window(xdo, window_ret);
  xdo_find_window_client(xdo, *window_ret, window_ret, XDO_FIND_PARENTS);
  return _is_success("xdo_get_focused_window_sane", *window_ret == 0, xdo);
}

int xdo_find_window_client(const xdo_t *xdo, Window window, Window *window_ret,
                           int direction) {
  /* for XQueryTree */
  Window dummy, parent, *children = NULL;
  unsigned int nchildren;
  Atom atom_wmstate = XInternAtom(xdo->xdpy, "WM_STATE", False);

  int done = False;
  while (!done) {
    if (window == 0) {
      return XDO_ERROR;
    }

    long items;
    _xdo_debug(xdo, "get_window_property on %lu", window);
    xdo_get_window_property_by_atom(xdo, window, atom_wmstate, &items, NULL, NULL);

    if (items == 0) {
      /* This window doesn't have WM_STATE property, keep searching. */
      _xdo_debug(xdo, "window %lu has no WM_STATE property, digging more.", window);
      XQueryTree(xdo->xdpy, window, &dummy, &parent, &children, &nchildren);

      if (direction == XDO_FIND_PARENTS) {
        _xdo_debug(xdo, "searching parents");
        /* Don't care about the children, but we still need to free them */
        if (children != NULL)
          XFree(children);
        window = parent;
      } else if (direction == XDO_FIND_CHILDREN) {
        _xdo_debug(xdo, "searching %d children", nchildren);
        unsigned int i = 0;
        int ret;
        done = True; /* recursion should end us */
        for (i = 0; i < nchildren; i++) {
          ret = xdo_find_window_client(xdo, children[i], &window, direction);
          //fprintf(stderr, "findclient: %ld\n", window);
          if (ret == XDO_SUCCESS) {
            *window_ret = window;
            break;
          }
        }
        if (nchildren == 0) {
          return XDO_ERROR;
        }
        if (children != NULL)
          XFree(children);
      } else {
        fprintf(stderr, "Invalid find_client direction (%d)\n", direction);
        *window_ret = 0;
        if (children != NULL)
          XFree(children);
        return XDO_ERROR;
      }
    } else {
      *window_ret = window;
      done = True;
    }
  }
  return XDO_SUCCESS;
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

static int _xdo_has_xtest(const xdo_t *xdo) {
  int dummy;
  return (XTestQueryExtension(xdo->xdpy, &dummy, &dummy, &dummy, &dummy) == True);
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

int xdo_get_window_property(const xdo_t *xdo, Window window, const char *property,
                            unsigned char **value, long *nitems, Atom *type, int *size) {
    *value = xdo_get_window_property_by_atom(xdo, window, XInternAtom(xdo->xdpy, property, False), nitems, type, size);
    if (*value == NULL) {
        return XDO_ERROR;
    }
    return XDO_SUCCESS;
}

/* Arbitrary window property retrieval
 * slightly modified version from xprop.c from Xorg */
unsigned char *xdo_get_window_property_by_atom(const xdo_t *xdo, Window window, Atom atom,
                                            long *nitems, Atom *type, int *size) {
  Atom actual_type;
  int actual_format;
  unsigned long _nitems;
  /*unsigned long nbytes;*/
  unsigned long bytes_after; /* unused */
  unsigned char *prop;
  int status;

  status = XGetWindowProperty(xdo->xdpy, window, atom, 0, (~0L),
                              False, AnyPropertyType, &actual_type,
                              &actual_format, &_nitems, &bytes_after,
                              &prop);
  if (status == BadWindow) {
    fprintf(stderr, "window id # 0x%lx does not exists!", window);
    return NULL;
  } if (status != Success) {
    fprintf(stderr, "XGetWindowProperty failed!");
    return NULL;
  }

  /*
   *if (actual_format == 32)
   *  nbytes = sizeof(long);
   *else if (actual_format == 16)
   *  nbytes = sizeof(short);
   *else if (actual_format == 8)
   *  nbytes = 1;
   *else if (actual_format == 0)
   *  nbytes = 0;
   */

  if (nitems != NULL) {
    *nitems = _nitems;
  }

  if (type != NULL) {
    *type = actual_type;
  }

  if (size != NULL) {
    *size = actual_format;
  }
  return prop;
}

int _xdo_ewmh_is_supported(const xdo_t *xdo, const char *feature) {
  Atom type = 0;
  long nitems = 0L;
  int size = 0;
  Atom *results = NULL;
  long i = 0;

  Window root;
  Atom request;
  Atom feature_atom;

  request = XInternAtom(xdo->xdpy, "_NET_SUPPORTED", False);
  feature_atom = XInternAtom(xdo->xdpy, feature, False);
  root = XDefaultRootWindow(xdo->xdpy);

  results = (Atom *) xdo_get_window_property_by_atom(xdo, root, request, &nitems, &type, &size);
  for (i = 0L; i < nitems; i++) {
    if (results[i] == feature_atom)
      return True;
  }
  free(results);

  return False;
}

void _xdo_init_xkeyevent(const xdo_t *xdo, XKeyEvent *xk) {
  xk->display = xdo->xdpy;
  xk->subwindow = None;
  xk->time = CurrentTime;
  xk->same_screen = True;

  /* Should we set these at all? */
  xk->x = xk->y = xk->x_root = xk->y_root = 1;
}

void _xdo_send_key(const xdo_t *xdo, Window window, charcodemap_t *key,
                          int modstate, int is_press, useconds_t delay) {
  /* Properly ensure the modstate is set by finding a key
   * that activates each bit in the modifier state */
  int mask = modstate | key->modmask;
  int use_xtest = 0;

  if (window == CURRENTWINDOW) {
    use_xtest = 1;
  } else {
    Window focuswin = 0;
    xdo_get_focused_window(xdo, &focuswin);
    if (focuswin == window) {
      use_xtest = 1;
    }
  }
  if (use_xtest) {
    //printf("XTEST: Sending key %d %s\n", key->code, is_press ? "down" : "up");
    XkbStateRec state;
    XkbGetState(xdo->xdpy, XkbUseCoreKbd, &state);
    int current_group = state.group;
    XkbLockGroup(xdo->xdpy, XkbUseCoreKbd, key->group);
    if (mask)
      _xdo_send_modifier(xdo, mask, is_press);
    //printf("XTEST: Sending key %d %s %x %d\n", key->code, is_press ? "down" : "up", key->modmask, key->group);
    XTestFakeKeyEvent(xdo->xdpy, key->code, is_press, CurrentTime);
    XkbLockGroup(xdo->xdpy, XkbUseCoreKbd, current_group);
    XSync(xdo->xdpy, False);
  } else {
    /* Since key events have 'state' (shift, etc) in the event, we don't
     * need to worry about key press ordering. */
    XKeyEvent xk;
    _xdo_init_xkeyevent(xdo, &xk);
    xk.window = window;
    xk.keycode = key->code;
    xk.state = mask | (key->group << 13);
    xk.type = (is_press ? KeyPress : KeyRelease);
    XSendEvent(xdo->xdpy, xk.window, True, KeyPressMask, (XEvent *)&xk);
  }

  /* Skipping the usleep if delay is 0 is much faster than calling usleep(0) */
  XFlush(xdo->xdpy);
  if (delay > 0) {
    usleep(delay);
  }
}

void _xdo_send_modifier(const xdo_t *xdo, int modmask, int is_press) {
  XModifierKeymap *modifiers = XGetModifierMapping(xdo->xdpy);
  int mod_index, mod_key, keycode;

  for (mod_index = ShiftMapIndex; mod_index <= Mod5MapIndex; mod_index++) {
    if (modmask & (1 << mod_index)) {
      for (mod_key = 0; mod_key < modifiers->max_keypermod; mod_key++) {
        keycode = modifiers->modifiermap[mod_index * modifiers->max_keypermod + mod_key];
        if (keycode) {
          XTestFakeKeyEvent(xdo->xdpy, keycode, is_press, CurrentTime);
          XSync(xdo->xdpy, False);
          break;
        }
      }
    }
  }

  XFreeModifiermap(modifiers);
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

int xdo_get_pid_window(const xdo_t *xdo, Window window) {
  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  int window_pid = 0;

  if (atom_NET_WM_PID == (Atom)-1) {
    atom_NET_WM_PID = XInternAtom(xdo->xdpy, "_NET_WM_PID", False);
  }

  data = xdo_get_window_property_by_atom(xdo, window, atom_NET_WM_PID, &nitems, &type, &size);

  if (nitems > 0) {
    /* The data itself is unsigned long, but everyone uses int as pid values */
    window_pid = (int) *((unsigned long *)data);
  }
  free(data);

  return window_pid;
}

int xdo_wait_for_mouse_move_from(const xdo_t *xdo, int origin_x, int origin_y) {
  int x, y;
  int ret = 0;
  int tries = MAX_TRIES;

  ret = xdo_get_mouse_location(xdo, &x, &y, NULL);
  while (tries > 0 &&
         (x == origin_x && y == origin_y)) {
    usleep(30000);
    ret = xdo_get_mouse_location(xdo, &x, &y, NULL);
    tries--;
  }

  return ret;
}

int xdo_wait_for_mouse_move_to(const xdo_t *xdo, int dest_x, int dest_y) {
  int x, y;
  int ret = 0;
  int tries = MAX_TRIES;

  ret = xdo_get_mouse_location(xdo, &x, &y, NULL);
  while (tries > 0 && (x != dest_x && y != dest_y)) {
    usleep(30000);
    ret = xdo_get_mouse_location(xdo, &x, &y, NULL);
    tries--;
  }

  return ret;
}

int xdo_get_desktop_viewport(const xdo_t *xdo, int *x_ret, int *y_ret) {
  if (_xdo_ewmh_is_supported(xdo, "_NET_DESKTOP_VIEWPORT") == False) {
    fprintf(stderr,
            "Your windowmanager claims not to support _NET_DESKTOP_VIEWPORT, "
            "so I cannot tell you the viewport position.\n");
    return XDO_ERROR;
  }

  Atom type;
  int size;
  long nitems;
  unsigned char *data;
  Atom request = XInternAtom(xdo->xdpy, "_NET_DESKTOP_VIEWPORT", False);
  Window root = RootWindow(xdo->xdpy, 0);
  data = xdo_get_window_property_by_atom(xdo, root, request, &nitems, &type, &size);

  if (type != XA_CARDINAL) {
    fprintf(stderr,
            "Got unexpected type returned from _NET_DESKTOP_VIEWPORT."
            " Expected CARDINAL, got %s\n",
            XGetAtomName(xdo->xdpy, type));
    return XDO_ERROR;
  }

  if (nitems != 2) {
    fprintf(stderr, "Expected 2 items for _NET_DESKTOP_VIEWPORT, got %ld\n",
            nitems);
    return XDO_ERROR;
  }

  int *viewport_data = (int *)data;
  *x_ret = viewport_data[0];
  *y_ret = viewport_data[1];

  return XDO_SUCCESS;
}

int xdo_set_desktop_viewport(const xdo_t *xdo, int x, int y) {
  XEvent xev;
  int ret;
  Window root = RootWindow(xdo->xdpy, 0);

  memset(&xev, 0, sizeof(xev));
  xev.type = ClientMessage;
  xev.xclient.display = xdo->xdpy;
  xev.xclient.window = root;
  xev.xclient.message_type = XInternAtom(xdo->xdpy, "_NET_DESKTOP_VIEWPORT",
                                         False);
  xev.xclient.format = 32;
  xev.xclient.data.l[0] = x;
  xev.xclient.data.l[1] = y;

  ret = XSendEvent(xdo->xdpy, root, False,
                   SubstructureNotifyMask | SubstructureRedirectMask, &xev);

  /* XXX: XSendEvent returns 0 on conversion failure, nonzero otherwise.
   * Manpage says it will only generate BadWindow or BadValue errors */
  return _is_success("XSendEvent[EWMH:_NET_DESKTOP_VIEWPORT]", ret == 0, xdo);
}

int xdo_kill_window(const xdo_t *xdo, Window window) {
  int ret;
  ret = XKillClient(xdo->xdpy, window);
  return _is_success("XKillClient", ret == 0, xdo);
}

int xdo_close_window(const xdo_t *xdo, Window window) {
  int ret;
  ret = XDestroyWindow(xdo->xdpy, window);
  return _is_success("XDestroyWindow", ret == 0, xdo);
}

int xdo_get_window_name(const xdo_t *xdo, Window window,
                        unsigned char **name_ret, int *name_len_ret,
                        int *name_type) {
  if (atom_NET_WM_NAME == (Atom)-1) {
    atom_NET_WM_NAME = XInternAtom(xdo->xdpy, "_NET_WM_NAME", False);
  }
  if (atom_WM_NAME == (Atom)-1) {
    atom_WM_NAME = XInternAtom(xdo->xdpy, "WM_NAME", False);
  }
  if (atom_STRING == (Atom)-1) {
    atom_STRING = XInternAtom(xdo->xdpy, "STRING", False);
  }
  if (atom_UTF8_STRING == (Atom)-1) {
    atom_UTF8_STRING = XInternAtom(xdo->xdpy, "UTF8_STRING", False);
  }

  Atom type;
  int size;
  long nitems;

  /**
   * http://standards.freedesktop.org/wm-spec/1.3/ar01s05.html
   * Prefer _NET_WM_NAME if available, otherwise use WM_NAME
   * If no WM_NAME, set name_ret to NULL and set len to 0
   */

  *name_ret = xdo_get_window_property_by_atom(xdo, window, atom_NET_WM_NAME, &nitems,
                             &type, &size);
  if (nitems == 0) {
    *name_ret = xdo_get_window_property_by_atom(xdo, window, atom_WM_NAME, &nitems,
                               &type, &size);
  }
  *name_len_ret = nitems;
  *name_type = type;

  return 0;
}

int xdo_minimize_window(const xdo_t *xdo, Window window) {
  int ret;
  int screen;

  /* Get screen number */
  XWindowAttributes attr;
  XGetWindowAttributes(xdo->xdpy, window, &attr);
  screen = XScreenNumberOfScreen(attr.screen);

  /* Minimize it */
  ret = XIconifyWindow(xdo->xdpy, window, screen);
  return _is_success("XIconifyWindow", ret == 0, xdo);
}

void _xdo_debug(const xdo_t *xdo, const char *format, ...) {
  va_list args;

  va_start(args, format);
  if (xdo->debug) {
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
  }
} /* _xdo_debug */

/* Used for printing things conditionally based on xdo->quiet */
void _xdo_eprintf(const xdo_t *xdo, int hushable, const char *format, ...) {
  va_list args;

  va_start(args, format);
  if (xdo->quiet == True && hushable) {
    return;
  }

  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
} /* _xdo_eprintf */

void xdo_enable_feature(xdo_t *xdo, int feature) {
  xdo->features_mask |= (0 << feature);
}

void xdo_disable_feature(xdo_t *xdo, int feature) {
  xdo->features_mask &= ~(1 << feature);
}

int xdo_has_feature(xdo_t *xdo, int feature) {
  return (xdo->features_mask & (1 << feature));
}

int xdo_get_viewport_dimensions(xdo_t *xdo, unsigned int *width,
                                unsigned int *height, int screen) {
  int dummy;

  if (XineramaQueryExtension(xdo->xdpy, &dummy, &dummy) \
      && XineramaIsActive(xdo->xdpy)) {
    XineramaScreenInfo *info;
    int screens;

    info = XineramaQueryScreens(xdo->xdpy, &screens);
    if (screen < 0 || screen >= screens) {
      fprintf(stderr, "Invalid screen number %d outside range 0 - %d\n",
              screen, screens - 1);
      return XDO_ERROR;
    }
    *width = (unsigned int) info[screen].width;
    *height = (unsigned int) info[screen].height;
    XFree(info);
    return XDO_SUCCESS;
  } else {
    /* Use the root window size if no zinerama */
    Window root = RootWindow(xdo->xdpy, screen);
    return xdo_get_window_size(xdo, root, width, height);
  }
}

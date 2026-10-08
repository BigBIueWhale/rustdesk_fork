#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include "../libs/libxdo-sys-stub/native/xdo.h"

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "XDO_MOUSE_MODIFIERS_FAILURE=%s\n", message);
    exit(1);
  }
}

static int entries(const char *path) {
  DIR *directory = opendir(path);
  require(directory != NULL, "resource inventory unavailable");
  int count = 0;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL)
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
  require(closedir(directory) == 0, "resource inventory close failed");
  return count;
}

static void held_keys(Display *display, int count) {
  char keys[32];
  require(XQueryKeymap(display, keys) != 0, "key query failed");
  for (int code = 0; code < 256; code++) {
    int held = (keys[code / 8] & (1 << (code % 8))) != 0;
    require(held == (code >= 20 && code < 20 + count), "held keys changed");
  }
}

int main(void) {
  setbuf(stdout, NULL);
  struct rlimit core = {0, 0};
  require(setrlimit(RLIMIT_CORE, &core) == 0, "core dump refusal failed");
  int descriptors = entries("/proc/self/fd");
  int tasks = entries("/proc/self/task");
  Display *observer = XOpenDisplay("unix/:98.0");
  require(observer != NULL, "observer display unavailable");
  int event_base, error_base, major, minor;
  require(XTestQueryExtension(observer, &event_base, &error_base, &major, &minor),
          "XTEST unavailable");
  held_keys(observer, 0);
  XModifierKeymap *original = XGetModifierMapping(observer);
  require(original != NULL, "original modifier map unavailable");
  int width;
  KeySym *old_keys = XGetKeyboardMapping(observer, 20, 12, &width);
  require(old_keys != NULL && width > 0, "original key map unavailable");
  KeySym replacement[12];
  for (int index = 0; index < 12; index++) replacement[index] = XK_Shift_L;
  XChangeKeyboardMapping(observer, 20, 1, replacement, 12);
  XModifierKeymap *mapping = XNewModifiermap(12);
  require(mapping != NULL, "test modifier map allocation failed");
  for (int index = 0; index < 12; index++) mapping->modifiermap[index] = 20 + index;
  require(XSetModifierMapping(observer, mapping) == MappingSuccess, "test modifier map refused");
  XSync(observer, False);
  XModifierKeymap *actual = XGetModifierMapping(observer);
  require(actual != NULL && actual->max_keypermod >= 12, "effective modifier map differs");
  for (int index = 0; index < 12; index++)
    require(actual->modifiermap[index] == 20 + index, "effective modifier key differs");
  XFreeModifiermap(actual);
  Window root = DefaultRootWindow(observer);
  Window window = XCreateSimpleWindow(observer, root, 20, 30, 120, 80, 0, 0, 0);
  require(window != None, "owned window creation failed");
  XSelectInput(observer, window, ButtonPressMask | ButtonReleaseMask);
  XMapWindow(observer, window);
  XWarpPointer(observer, None, root, 0, 0, 0, 0, 47, 69);
  XSync(observer, False);
  xdo_t *input = xdo_new("unix/:98.0");
  require(input != NULL, "product input context unavailable");
  const int counts[] = {0, 1, 9, 10, 12};
  for (int round = 0; round < 4; round++) {
    for (size_t index = 0; index < sizeof(counts) / sizeof(counts[0]); index++) {
      int count = counts[index];
      for (int key = 20; key < 20 + count; key++)
        require(XTestFakeKeyEvent(observer, key, True, CurrentTime), "modifier press failed");
      XSync(observer, False);
      held_keys(observer, count);
      Window returned_root, child;
      int root_x, root_y, x, y;
      unsigned int state;
      require(XQueryPointer(observer, window, &returned_root, &child, &root_x, &root_y,
                            &x, &y, &state) && state == (count ? ShiftMask : 0),
              "effective modifier state differs");
      printf("XDO_MOUSE_MODIFIERS_ENTER round=%d held=%d window=owned state=%u\n", round, count, state);
      require(xdo_mouse_down(input, window, 1) == XDO_SUCCESS, "product mouse press failed");
      require(xdo_mouse_up(input, window, 1) == XDO_SUCCESS, "product mouse release failed");
      XSync(input->xdpy, False);
      XSync(observer, False);
      for (int press = 1; press >= 0; press--) {
        XEvent event;
        require(XCheckWindowEvent(observer, window, ButtonPressMask | ButtonReleaseMask, &event),
                "expected mouse event missing");
        require(event.type == (press ? ButtonPress : ButtonRelease) && event.xbutton.send_event
                && event.xbutton.window == window && event.xbutton.root == root
                && event.xbutton.button == 1 && event.xbutton.same_screen
                && event.xbutton.x_root == 47 && event.xbutton.y_root == 69
                && event.xbutton.x == 27 && event.xbutton.y == 39
                && event.xbutton.state == (state | (press ? 0 : Button1Mask)),
                "actual mouse event differs");
      }
      XEvent extra;
      require(!XCheckWindowEvent(observer, window, ButtonPressMask | ButtonReleaseMask, &extra),
              "unexpected mouse event");
      held_keys(observer, count);
      for (int key = 20; key < 20 + count; key++)
        require(XTestFakeKeyEvent(observer, key, False, CurrentTime), "modifier release failed");
      XSync(observer, False);
      held_keys(observer, 0);
      printf("XDO_MOUSE_MODIFIERS_CASE=pass round=%d held=%d events=2 state=preserved keys=unchanged\n", round, count);
    }
  }
  xdo_free(input);
  XDestroyWindow(observer, window);
  require(XSetModifierMapping(observer, original) == MappingSuccess, "original modifiers not restored");
  XChangeKeyboardMapping(observer, 20, width, old_keys, 12);
  XSync(observer, False);
  actual = XGetModifierMapping(observer);
  require(actual != NULL && actual->max_keypermod == original->max_keypermod
          && memcmp(actual->modifiermap, original->modifiermap, 8 * original->max_keypermod) == 0,
          "restored modifier map differs");
  XFreeModifiermap(actual);
  XFreeModifiermap(mapping);
  XFreeModifiermap(original);
  XFree(old_keys);
  held_keys(observer, 0);
  XCloseDisplay(observer);
  require(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks,
          "product context resources retained");
  puts("XDO_MOUSE_MODIFIERS_NATIVE=pass held=0,1,9,10,12 repeats=4 cases=20 events=40 window=owned state=preserved keys=unchanged mapping=restored descriptors=retired tasks=retired scope=private-native-component");
  return 0;
}

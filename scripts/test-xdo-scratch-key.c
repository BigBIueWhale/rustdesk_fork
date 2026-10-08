/* Isolated native scratch-key bounds and query-failure regression. */
#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libs/libxdo-sys-stub/native/xdo.h"

static Display *product_display;
static int observe, fault, queries, frees;
static KeySym *owned_query;
extern KeySym *__real_XGetKeyboardMapping(Display *, KeyCode, int, int *);
extern int __real_XFree(void *);

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "XDO_SCRATCH_FAILURE=%s\n", message);
    exit(1);
  }
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

int main(void) {
  setbuf(stdout, NULL);
  int descriptors = entries("/proc/self/fd"), tasks = entries("/proc/self/task");
  Display *observer = XOpenDisplay("unix/:98.0");
  require(observer != NULL, "observer unavailable");
  clear_keys(observer);
  Window original_focus;
  int original_revert;
  require(XGetInputFocus(observer, &original_focus, &original_revert), "original focus unavailable");
  int low, high, width;
  XDisplayKeycodes(observer, &low, &high);
  require(low >= 8 && high <= 255 && high > low + 1, "native keycode range differs");
  int count = high - low + 1;
  KeySym *original = XGetKeyboardMapping(observer, low, count, &width);
  require(original && width > 0, "original keyboard map unavailable");
  int original_width = width;
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
  require(!xdo_send_keysequence_window_list_do(input, CURRENTWINDOW, &key, 1, True, NULL, 0)
          && !xdo_send_keysequence_window_list_do(input, CURRENTWINDOW, &key, 1, False, NULL, 0),
          "mapped positive control failed");
  events(observer, window, key.code, 2);
  xdo_free(input);
  puts("XDO_SCRATCH_CONTROL=pass key=a events=2");
  for (int round = 0; round < 4; round++) {
    width = original_width;
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
      int down = xdo_send_keysequence_window_list_do(input, CURRENTWINDOW, &key, 1, True, NULL, 0);
      int up = xdo_send_keysequence_window_list_do(input, CURRENTWINDOW, &key, 1, False, NULL, 0);
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
    XChangeKeyboardMapping(observer, low, original_width, original, count);
    XSync(observer, False);
    same_map(observer, low, count, original_width, original);
  }
  XFree(original);
  XSetInputFocus(observer, original_focus, original_revert, CurrentTime);
  XSync(observer, False);
  Window restored_focus;
  int restored_revert;
  require(XGetInputFocus(observer, &restored_focus, &restored_revert)
          && restored_focus == original_focus && restored_revert == original_revert,
          "original focus not restored");
  XDestroyWindow(observer, window);
  XCloseDisplay(observer);
  require(entries("/proc/self/fd") == descriptors && entries("/proc/self/task") == tasks,
          "native descriptors/tasks retained");
  puts("XDO_SCRATCH_NATIVE=pass cases=20 repeats=4 highest=delivered mapped_query=absent missing_map=refused invalid_width=refused full_map=refused events=16 maps=unchanged queries=32 frees=24 descriptors=retired tasks=retired sanitizer=address leak_scope=unclaimed whole_app=false");
  return 0;
}

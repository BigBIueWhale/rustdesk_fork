#define _POSIX_C_SOURCE 200809L

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum {
  kWindowWaitMs = 15000,
  kFrameWaitMs = 15000,
  kMarkerWaitMs = 20000,
  kHiddenHoldMs = 1500,
  kRecoveryLimitMs = 2500,
  kPollMs = 20,
  kPathCapacity = 4096,
};

static void fail(const char *message) {
  fprintf(stderr, "flutter presentation X11 probe: %s\n", message);
  exit(1);
}

static int64_t monotonic_millis(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
    fail("clock_gettime failed");
  }
  return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void sleep_millis(int millis) {
  struct timespec requested = {
      .tv_sec = millis / 1000,
      .tv_nsec = (long)(millis % 1000) * 1000000L,
  };
  while (nanosleep(&requested, &requested) != 0) {
    if (errno != EINTR) {
      fail("nanosleep failed");
    }
  }
}

static bool window_has_title(Display *display, Window window,
                             const char *expected) {
  char *name = NULL;
  const Status status = XFetchName(display, window, &name);
  const bool matches = status != 0 && name != NULL && strcmp(name, expected) == 0;
  if (name != NULL) {
    XFree(name);
  }
  return matches;
}

static bool find_window(Display *display, Window root, const char *title,
                        Window *result) {
  if (window_has_title(display, root, title)) {
    *result = root;
    return true;
  }
  Window returned_root = 0;
  Window returned_parent = 0;
  Window *children = NULL;
  unsigned int count = 0;
  if (XQueryTree(display, root, &returned_root, &returned_parent, &children,
                 &count) == 0) {
    return false;
  }
  bool found = false;
  for (unsigned int index = 0; index < count && !found; ++index) {
    found = find_window(display, children[index], title, result);
  }
  if (children != NULL) {
    XFree(children);
  }
  return found;
}

static Window wait_for_window(Display *display, const char *title) {
  const int64_t deadline = monotonic_millis() + kWindowWaitMs;
  Window window = 0;
  while (monotonic_millis() < deadline) {
    if (find_window(display, DefaultRootWindow(display), title, &window)) {
      return window;
    }
    sleep_millis(kPollMs);
  }
  fail("timed out waiting for the exact Flutter window title");
  return 0;
}

static XWindowAttributes window_attributes(Display *display, Window window) {
  XWindowAttributes attributes;
  if (XGetWindowAttributes(display, window, &attributes) == 0) {
    fail("XGetWindowAttributes failed");
  }
  return attributes;
}

static void wait_for_map_state(Display *display, Window window, int expected,
                               const char *label) {
  const int64_t deadline = monotonic_millis() + kWindowWaitMs;
  while (monotonic_millis() < deadline) {
    XSync(display, False);
    if (window_attributes(display, window).map_state == expected) {
      return;
    }
    sleep_millis(kPollMs);
  }
  fprintf(stderr, "flutter presentation X11 probe: timed out waiting for %s\n",
          label);
  exit(1);
}

static uint8_t extract_component(unsigned long pixel, unsigned long mask) {
  if (mask == 0) {
    fail("X11 visual has a zero color mask");
  }
  unsigned int shift = 0;
  while ((mask & 1UL) == 0) {
    mask >>= 1;
    ++shift;
  }
  const unsigned long value = (pixel >> shift) & mask;
  return (uint8_t)((value * 255UL + mask / 2UL) / mask);
}

static bool read_center_rgb(Display *display, Window window, uint8_t *red,
                            uint8_t *green, uint8_t *blue) {
  const XWindowAttributes attributes = window_attributes(display, window);
  if (attributes.map_state != IsViewable || attributes.width <= 0 ||
      attributes.height <= 0 || attributes.visual == NULL) {
    return false;
  }
  XImage *image = XGetImage(display, window, attributes.width / 2,
                            attributes.height / 2, 1, 1, AllPlanes, ZPixmap);
  if (image == NULL) {
    return false;
  }
  const unsigned long pixel = XGetPixel(image, 0, 0);
  *red = extract_component(pixel, attributes.visual->red_mask);
  *green = extract_component(pixel, attributes.visual->green_mask);
  *blue = extract_component(pixel, attributes.visual->blue_mask);
  XDestroyImage(image);
  return true;
}

static int64_t wait_for_color(Display *display, Window window, bool green,
                              uint8_t *last_red, uint8_t *last_green,
                              uint8_t *last_blue) {
  const int64_t deadline = monotonic_millis() + kFrameWaitMs;
  while (monotonic_millis() < deadline) {
    XSync(display, False);
    uint8_t red = 0;
    uint8_t green_value = 0;
    uint8_t blue = 0;
    if (read_center_rgb(display, window, &red, &green_value, &blue)) {
      *last_red = red;
      *last_green = green_value;
      *last_blue = blue;
      const bool matches = green
                               ? green_value >= 220 && red <= 40 && blue <= 40
                               : red >= 220 && green_value <= 40 && blue <= 40;
      if (matches) {
        return monotonic_millis();
      }
    }
    sleep_millis(kPollMs);
  }
  fprintf(stderr,
          "flutter presentation X11 probe: timed out waiting for %s pixel "
          "(last rgb=%u,%u,%u)\n",
          green ? "green" : "red", *last_red, *last_green, *last_blue);
  exit(1);
}

static void marker_path(char *output, size_t capacity, const char *directory,
                        const char *name) {
  const int written = snprintf(output, capacity, "%s/%s", directory, name);
  if (written < 0 || (size_t)written >= capacity) {
    fail("marker path is too long");
  }
}

static void write_all(int descriptor, const char *value, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    const ssize_t written = write(descriptor, value + offset, length - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      fail("marker write failed");
    }
    offset += (size_t)written;
  }
}

static void publish_marker(const char *directory, const char *name,
                           const char *value) {
  char destination[kPathCapacity];
  char temporary[kPathCapacity];
  marker_path(destination, sizeof(destination), directory, name);
  const int temporary_length = snprintf(temporary, sizeof(temporary),
                                        "%s/.%s.%ld.tmp", directory, name,
                                        (long)getpid());
  if (temporary_length < 0 || (size_t)temporary_length >= sizeof(temporary)) {
    fail("temporary marker path is too long");
  }
  struct stat status;
  if (lstat(destination, &status) == 0 || errno != ENOENT) {
    fail("destination marker already exists or cannot be inspected");
  }
  const int descriptor =
      open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
           S_IRUSR | S_IWUSR);
  if (descriptor < 0) {
    fail("cannot create private temporary marker");
  }
  write_all(descriptor, value, strlen(value));
  if (fsync(descriptor) != 0 || close(descriptor) != 0) {
    unlink(temporary);
    fail("cannot synchronize private marker");
  }
  if (rename(temporary, destination) != 0) {
    unlink(temporary);
    fail("cannot publish private marker");
  }
}

static bool marker_equals(const char *directory, const char *name,
                          const char *expected) {
  char path[kPathCapacity];
  marker_path(path, sizeof(path), directory, name);
  const int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    if (errno == ENOENT) {
      return false;
    }
    fail("cannot open marker");
  }
  struct stat status;
  if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_uid != getuid() || (status.st_mode & 0777) != 0600 ||
      status.st_nlink != 1) {
    close(descriptor);
    fail("marker identity, owner, mode, or link count is invalid");
  }
  const size_t expected_length = strlen(expected);
  if ((uint64_t)status.st_size != (uint64_t)expected_length) {
    close(descriptor);
    return false;
  }
  char buffer[128];
  if (expected_length >= sizeof(buffer)) {
    close(descriptor);
    fail("expected marker is unexpectedly large");
  }
  size_t offset = 0;
  while (offset < expected_length) {
    const ssize_t count = read(descriptor, buffer + offset,
                               expected_length - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      close(descriptor);
      fail("marker read failed");
    }
    offset += (size_t)count;
  }
  char extra;
  const ssize_t trailing = read(descriptor, &extra, 1);
  if (close(descriptor) != 0 || trailing != 0) {
    fail("marker has trailing bytes or cannot be closed");
  }
  if (memcmp(buffer, expected, expected_length) != 0) {
    fail("marker contents are invalid");
  }
  return true;
}

static void wait_for_marker(const char *directory, const char *name,
                            const char *expected) {
  const int64_t deadline = monotonic_millis() + kMarkerWaitMs;
  while (monotonic_millis() < deadline) {
    if (marker_equals(directory, name, expected)) {
      return;
    }
    sleep_millis(kPollMs);
  }
  fail("timed out waiting for a private state marker");
}

int main(int argc, char **argv) {
  if (argc != 3 || argv[1][0] != '/' || argv[2][0] == '\0') {
    fail("usage: flutter-presentation-probe-x11 STATE_DIRECTORY WINDOW_TITLE");
  }
  struct stat state_status;
  if (lstat(argv[1], &state_status) != 0 || !S_ISDIR(state_status.st_mode) ||
      state_status.st_uid != getuid() ||
      (state_status.st_mode & 0777) != 0700) {
    fail("state directory is not a private current-user directory");
  }
  Display *display = XOpenDisplay(NULL);
  if (display == NULL) {
    fail("cannot open DISPLAY");
  }
  const Window window = wait_for_window(display, argv[2]);
  wait_for_map_state(display, window, IsViewable, "the mapped Flutter window");

  uint8_t red = 0;
  uint8_t green = 0;
  uint8_t blue = 0;
  const int64_t red_visible_at =
      wait_for_color(display, window, false, &red, &green, &blue);

  XUnmapWindow(display, window);
  XSync(display, False);
  wait_for_map_state(display, window, IsUnmapped,
                     "the externally unmapped Flutter window");
  publish_marker(argv[1], "switch", "hidden\n");
  wait_for_marker(argv[1], "updated", "green frames=128\n");
  if (window_attributes(display, window).map_state != IsUnmapped) {
    fail("Flutter window remapped before the hidden hold completed");
  }
  sleep_millis(kHiddenHoldMs);

  XMapRaised(display, window);
  XSetInputFocus(display, window, RevertToParent, CurrentTime);
  XSync(display, False);
  wait_for_map_state(display, window, IsViewable,
                     "the externally remapped Flutter window");
  const int64_t remapped_at = monotonic_millis();
  publish_marker(argv[1], "remapped", "visible\n");
  wait_for_marker(argv[1], "renotified", "accepted\n");
  const int64_t green_visible_at =
      wait_for_color(display, window, true, &red, &green, &blue);
  const int64_t recovery_ms = green_visible_at - remapped_at;
  if (recovery_ms < 0 || recovery_ms > kRecoveryLimitMs) {
    fail("visible green recovery exceeded the bounded latency");
  }
  publish_marker(argv[1], "finish", "green-visible\n");
  printf("FLUTTER_PRESENTATION_PIXELS_OK initial_rgb=255,0,0 "
         "final_rgb=%u,%u,%u hidden_ms=%d recovery_ms=%lld "
         "direct_abi=true actual_texture=true x11_pixels=true\n",
         red, green, blue, kHiddenHoldMs, (long long)recovery_ms);
  fflush(stdout);
  XCloseDisplay(display);
  (void)red_visible_at;
  return 0;
}

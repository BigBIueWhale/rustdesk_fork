/*
 * TEST-ONLY X11 motion fixture for the container video-pipeline smoke test.
 *
 * Opens the harness-owned X display, maps one full-screen override-redirect window, and draws a
 * deterministic changing pattern for a finite duration. It creates no listener and Xlib reaches
 * Xvfb only through the private container-local Unix socket; Xvfb is launched with `-nolisten tcp`.
 */
#include <X11/Xlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define FIXTURE_WIDTH 640U
#define FIXTURE_HEIGHT 480U
#define FIXTURE_FRAMES 240U
#define FIXTURE_INTERVAL_MS 100U
#define DISPLAY_OPEN_ATTEMPTS 100U

static int sleep_millis(unsigned int millis) {
    struct timespec delay = {
        .tv_sec = (time_t)(millis / 1000U),
        .tv_nsec = (long)(millis % 1000U) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static unsigned long component_pixel(uint8_t component, unsigned long mask) {
    unsigned int shift = 0;
    unsigned long normalized;
    if (mask == 0UL) {
        return 0UL;
    }
    while (((mask >> shift) & 1UL) == 0UL) {
        ++shift;
    }
    normalized = mask >> shift;
    return (((unsigned long)component * normalized + 127UL) / 255UL) << shift;
}

static unsigned long rgb_pixel(const Visual *visual, uint8_t red, uint8_t green, uint8_t blue) {
    return component_pixel(red, visual->red_mask) |
           component_pixel(green, visual->green_mask) |
           component_pixel(blue, visual->blue_mask);
}

int main(void) {
    Display *display = NULL;
    unsigned int attempt;
    int screen;
    Visual *visual;
    Window root;
    XSetWindowAttributes attributes;
    Window window;
    GC graphics;
    unsigned int frame;

    for (attempt = 0; attempt < DISPLAY_OPEN_ATTEMPTS; ++attempt) {
        display = XOpenDisplay(NULL);
        if (display != NULL) {
            break;
        }
        if (sleep_millis(100U) != 0) {
            fputs("X11_MOTION_FAIL sleep while waiting for display\n", stderr);
            return 1;
        }
    }
    if (display == NULL) {
        fputs("X11_MOTION_FAIL display unavailable\n", stderr);
        return 1;
    }

    screen = DefaultScreen(display);
    visual = DefaultVisual(display, screen);
    if (visual == NULL || (visual->class != TrueColor && visual->class != DirectColor)) {
        fputs("X11_MOTION_FAIL fixture requires a true/direct-color visual\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    root = RootWindow(display, screen);
    attributes.override_redirect = True;
    attributes.background_pixel = rgb_pixel(visual, 0U, 0U, 0U);
    window = XCreateWindow(display, root, 0, 0, FIXTURE_WIDTH, FIXTURE_HEIGHT, 0,
                           DefaultDepth(display, screen), InputOutput, visual,
                           CWOverrideRedirect | CWBackPixel, &attributes);
    if (window == 0) {
        fputs("X11_MOTION_FAIL window creation failed\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    graphics = XCreateGC(display, window, 0, NULL);
    if (graphics == NULL) {
        fputs("X11_MOTION_FAIL graphics-context creation failed\n", stderr);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    XMapRaised(display, window);
    XSync(display, False);
    printf("X11_MOTION_READY display=%s dimensions=%ux%u frames=%u interval_ms=%u\n",
           DisplayString(display), FIXTURE_WIDTH, FIXTURE_HEIGHT, FIXTURE_FRAMES,
           FIXTURE_INTERVAL_MS);
    fflush(stdout);

    for (frame = 0; frame < FIXTURE_FRAMES; ++frame) {
        uint8_t red = (uint8_t)((frame * 37U + 17U) & 0xffU);
        uint8_t green = (uint8_t)((frame * 73U + 43U) & 0xffU);
        uint8_t blue = (uint8_t)((frame * 109U + 89U) & 0xffU);
        unsigned int x = (frame * 19U) % (FIXTURE_WIDTH - 96U);
        unsigned int y = (frame * 13U) % (FIXTURE_HEIGHT - 72U);

        XSetForeground(display, graphics, rgb_pixel(visual, red, green, blue));
        XFillRectangle(display, window, graphics, 0, 0, FIXTURE_WIDTH, FIXTURE_HEIGHT);
        XSetForeground(display, graphics,
                       rgb_pixel(visual, (uint8_t)~red, (uint8_t)~green, (uint8_t)~blue));
        XFillRectangle(display, window, graphics, (int)x, (int)y, 96U, 72U);
        XSetForeground(display, graphics, rgb_pixel(visual, blue, red, green));
        XFillRectangle(display, window, graphics,
                       (int)(FIXTURE_WIDTH - 1U - x), (int)(FIXTURE_HEIGHT - 1U - y), 1U, 1U);
        XSync(display, False);
        if (sleep_millis(FIXTURE_INTERVAL_MS) != 0) {
            fputs("X11_MOTION_FAIL frame pacing failed\n", stderr);
            XFreeGC(display, graphics);
            XDestroyWindow(display, window);
            XCloseDisplay(display);
            return 1;
        }
    }

    puts("X11_MOTION_COMPLETE");
    XFreeGC(display, graphics);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return 0;
}

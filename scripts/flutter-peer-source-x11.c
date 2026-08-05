#define _POSIX_C_SOURCE 200809L

/*
 * Test-only source display for the full RustDesk peer-presentation probe.
 *
 * The two independently colored halves encode one of 256 ordered frame states. The exact product
 * captures this X11 window; the observer compares the decoded Flutter/X11 pixels with the live
 * source state to distinguish a current picture from a merely changing but delayed picture.
 */
#include <X11/Xlib.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define SOURCE_WIDTH 640U
#define SOURCE_HEIGHT 480U
#define FRAME_INTERVAL_MS 250U
#define DISPLAY_OPEN_ATTEMPTS 200U

static volatile sig_atomic_t stop_requested = 0;

static const uint8_t palette[16][3] = {
    {232U, 36U, 36U},   {36U, 224U, 48U},   {36U, 64U, 232U},
    {232U, 220U, 36U},  {224U, 36U, 220U},  {36U, 220U, 220U},
    {240U, 120U, 24U},  {128U, 40U, 232U},  {24U, 132U, 232U},
    {232U, 40U, 128U},  {132U, 232U, 24U},  {24U, 232U, 132U},
    {196U, 92U, 44U},   {44U, 196U, 92U},   {92U, 44U, 196U},
    {196U, 196U, 196U},
};

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int sleep_millis(unsigned int millis) {
    struct timespec delay = {
        .tv_sec = (time_t)(millis / 1000U),
        .tv_nsec = (long)(millis % 1000U) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            return -1;
        }
        if (stop_requested != 0) {
            return 0;
        }
    }
    return 0;
}

static unsigned long component_pixel(uint8_t component, unsigned long mask) {
    unsigned int shift = 0U;
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

static unsigned long rgb_pixel(const Visual *visual, const uint8_t color[3]) {
    return component_pixel(color[0], visual->red_mask) |
           component_pixel(color[1], visual->green_mask) |
           component_pixel(color[2], visual->blue_mask);
}

int main(void) {
    Display *display = NULL;
    struct sigaction action = {0};
    unsigned int attempt;
    int screen;
    Visual *visual;
    Window root;
    XSetWindowAttributes attributes;
    Window window;
    GC graphics;
    unsigned int frame = 0U;

    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL signal handlers\n", stderr);
        return 1;
    }

    for (attempt = 0U; attempt < DISPLAY_OPEN_ATTEMPTS; ++attempt) {
        display = XOpenDisplay(NULL);
        if (display != NULL) {
            break;
        }
        if (sleep_millis(25U) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL display wait\n", stderr);
            return 1;
        }
    }
    if (display == NULL) {
        fputs("FLUTTER_PEER_SOURCE_FAIL display unavailable\n", stderr);
        return 1;
    }

    screen = DefaultScreen(display);
    visual = DefaultVisual(display, screen);
    if (visual == NULL || (visual->class != TrueColor && visual->class != DirectColor)) {
        fputs("FLUTTER_PEER_SOURCE_FAIL true-color visual required\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    root = RootWindow(display, screen);
    attributes.override_redirect = True;
    attributes.background_pixel = rgb_pixel(visual, palette[0]);
    window = XCreateWindow(display, root, 0, 0, SOURCE_WIDTH, SOURCE_HEIGHT, 0,
                           DefaultDepth(display, screen), InputOutput, visual,
                           CWOverrideRedirect | CWBackPixel, &attributes);
    if (window == 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL window creation\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    graphics = XCreateGC(display, window, 0, NULL);
    if (graphics == NULL) {
        fputs("FLUTTER_PEER_SOURCE_FAIL graphics context\n", stderr);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    XMapRaised(display, window);
    XSync(display, False);
    printf("FLUTTER_PEER_SOURCE_READY display=%s dimensions=%ux%u interval_ms=%u states=256\n",
           DisplayString(display), SOURCE_WIDTH, SOURCE_HEIGHT, FRAME_INTERVAL_MS);
    fflush(stdout);

    while (stop_requested == 0) {
        unsigned int low = frame & 15U;
        unsigned int high = (frame >> 4U) & 15U;
        unsigned int marker_x = (frame * 17U) % (SOURCE_WIDTH - 24U);

        XSetForeground(display, graphics, rgb_pixel(visual, palette[low]));
        XFillRectangle(display, window, graphics, 0, 0, SOURCE_WIDTH / 2U, SOURCE_HEIGHT);
        XSetForeground(display, graphics, rgb_pixel(visual, palette[high]));
        XFillRectangle(display, window, graphics, SOURCE_WIDTH / 2U, 0,
                       SOURCE_WIDTH / 2U, SOURCE_HEIGHT);
        XSetForeground(display, graphics, BlackPixel(display, screen));
        XFillRectangle(display, window, graphics, (int)marker_x, 8, 24U, 8U);
        XSync(display, False);
        frame = (frame + 1U) & 255U;
        if (sleep_millis(FRAME_INTERVAL_MS) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL frame pacing\n", stderr);
            XFreeGC(display, graphics);
            XDestroyWindow(display, window);
            XCloseDisplay(display);
            return 1;
        }
    }

    printf("FLUTTER_PEER_SOURCE_COMPLETE frames=%u\n", frame);
    XFreeGC(display, graphics);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return 0;
}

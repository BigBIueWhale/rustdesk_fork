#define _POSIX_C_SOURCE 200809L

/*
 * Test-only source display for the full RustDesk peer-presentation probe.
 *
 * The colored halves retain the desktop palette probe. Four ordered Manchester bands encode
 * the complete non-wrapping uint32 frame identity for the mobile observer. Each publication is
 * bound to its monotonic start time; nominal frame pacing is not a freshness measurement.
 * Full-HD adds deterministic changing texture below the counter and palette witnesses.
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SOURCE_WIDTH 640U
#define SOURCE_HEIGHT 480U
#define FRAME_INTERVAL_MS 250U
#define DISPLAY_OPEN_ATTEMPTS 200U
#define STATE_CODE_BARS 24U
#define STATE_CODE_ROWS 4U

static volatile sig_atomic_t stop_requested = 0;

static const uint8_t palette[16][3] = {
    {232U, 36U, 36U},   {36U, 224U, 48U},   {36U, 64U, 232U},
    {232U, 220U, 36U},  {224U, 36U, 220U},  {36U, 220U, 220U},
    {240U, 120U, 24U},  {128U, 40U, 232U},  {24U, 132U, 232U},
    {232U, 40U, 128U},  {132U, 232U, 24U},  {24U, 232U, 132U},
    {196U, 92U, 44U},   {44U, 196U, 92U},   {92U, 44U, 196U},
    {196U, 196U, 196U},
};
static const uint8_t code_black[3] = {0U, 0U, 0U};
static const uint8_t code_white[3] = {255U, 255U, 255U};

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

static uint64_t monotonic_micros(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000000U + (uint64_t)now.tv_nsec / 1000U;
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

static int root_pixel_matches(Display *display, Window root, int x, int y,
                              unsigned long expected);

static int state_code_bar_is_white(uint32_t state, unsigned int row, unsigned int bar) {
    unsigned int pair;
    unsigned int bit;
    if (bar == 0U || bar == STATE_CODE_BARS - 1U) {
        return 0;
    }
    if (bar == 1U || bar == STATE_CODE_BARS - 2U) {
        return 1;
    }
    pair = (bar - 2U) / 2U;
    bit = (((row << 8U) | ((state >> (24U - row * 8U)) & 255U)) >>
           (9U - pair)) & 1U;
    return ((bar - 2U) & 1U) == 0U ? (int)bit : (int)(bit ^ 1U);
}

static int root_state_code_matches(Display *display, Window root, const Visual *visual,
                                   uint32_t state, unsigned int width,
                                   unsigned int code_height) {
    unsigned int row, bar;
    for (row = 0U; row < STATE_CODE_ROWS; ++row) {
        for (bar = 0U; bar < STATE_CODE_BARS; ++bar) {
            unsigned int x = ((bar * 2U + 1U) * width) /
                             (STATE_CODE_BARS * 2U);
            const uint8_t *color =
                state_code_bar_is_white(state, row, bar) != 0 ? code_white : code_black;
            if (!root_pixel_matches(display, root, (int)x,
                                    (int)((row * 2U + 1U) * code_height /
                                          (STATE_CODE_ROWS * 2U)),
                                    rgb_pixel(visual, color))) {
                return 0;
            }
        }
    }
    return 1;
}

static int root_pixel_matches(Display *display, Window root, int x, int y,
                              unsigned long expected) {
    XImage *image = XGetImage(display, root, x, y, 1U, 1U, AllPlanes, ZPixmap);
    unsigned long actual;
    if (image == NULL) {
        return 0;
    }
    actual = XGetPixel(image, 0, 0);
    XDestroyImage(image);
    return actual == expected;
}

static void draw_texture(Display *display, Pixmap buffer, GC graphics,
                         XImage *image, uint32_t frame, unsigned int top,
                         const unsigned long colors[3][256]) {
    unsigned int x, y;
    for (y = 0U; y < (unsigned int)image->height; ++y) {
        for (x = 0U; x < (unsigned int)image->width; ++x) {
            uint32_t value = frame * UINT32_C(0x9e3779b9) +
                             y * (unsigned int)image->width + x;
            /* Bijective uint32 mixing binds the texture to spatial/frame identity. */
            value ^= value >> 16U;
            value *= UINT32_C(0x7feb352d);
            value ^= value >> 15U;
            value *= UINT32_C(0x846ca68b);
            value ^= value >> 16U;
            XPutPixel(image, (int)x, (int)y,
                      colors[0][(value >> 16U) & 255U] |
                      colors[1][(value >> 8U) & 255U] | colors[2][value & 255U]);
        }
    }
    XPutImage(display, buffer, graphics, image, 0, 0, 0, (int)top,
              (unsigned int)image->width, (unsigned int)image->height);
}

int main(int argc, char **argv) {
    Display *display = NULL;
    struct sigaction action = {0};
    unsigned int attempt;
    int screen;
    Visual *visual;
    Window root;
    XSetWindowAttributes attributes;
    Window window;
    Pixmap back_buffer;
    GC graphics;
    XImage *texture = NULL;
    unsigned long texture_colors[3][256];
    uint32_t frame = 0U;
    int exit_status = 0;
    unsigned int source_width = SOURCE_WIDTH;
    unsigned int source_height = SOURCE_HEIGHT;
    unsigned int frame_interval_ms = FRAME_INTERVAL_MS;
    unsigned int code_height;
    unsigned int texture_top;
    const char *trace_value = getenv("RUSTDESK_PRESENTATION_TRACE");
    int trace_enabled = trace_value != NULL && strcmp(trace_value, "1") == 0;

    if (argc == 2 && strcmp(argv[1], "--full-hd") == 0) {
        source_width = 1920U;
        source_height = 1080U;
        frame_interval_ms = 33U;
    } else if (argc != 1) {
        fputs("FLUTTER_PEER_SOURCE_FAIL usage: frame-source [--full-hd]\n", stderr);
        return 1;
    }
    /* Preserve band visibility after the remote screen is fitted into a thumbnail. */
    code_height = source_height * 2U / 5U;
    texture_top = source_height * 3U / 5U;

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
    if ((unsigned int)DisplayWidth(display, screen) != source_width ||
        (unsigned int)DisplayHeight(display, screen) != source_height) {
        fputs("FLUTTER_PEER_SOURCE_FAIL screen dimensions differ\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    visual = DefaultVisual(display, screen);
    if (visual == NULL || (visual->class != TrueColor && visual->class != DirectColor)) {
        fputs("FLUTTER_PEER_SOURCE_FAIL true-color visual required\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    root = RootWindow(display, screen);
    attributes.override_redirect = True;
    attributes.background_pixel = rgb_pixel(visual, palette[0]);
    window = XCreateWindow(display, root, 0, 0, source_width, source_height, 0,
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
    back_buffer = XCreatePixmap(display, window, source_width, source_height,
                                (unsigned int)DefaultDepth(display, screen));
    if (back_buffer == 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL back buffer creation\n", stderr);
        XFreeGC(display, graphics);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    XMapRaised(display, window);
    if (argc == 2) {
        unsigned int component;
        texture = XCreateImage(display, visual, (unsigned int)DefaultDepth(display, screen),
                                ZPixmap, 0, NULL, source_width,
                                source_height - texture_top, 32, 0);
        if (texture != NULL && texture->bytes_per_line > 0 && texture->height > 0 &&
            (size_t)texture->bytes_per_line <= (8U * 1024U * 1024U) / (size_t)texture->height) {
            texture->data = calloc((size_t)texture->height, (size_t)texture->bytes_per_line);
        }
        if (texture == NULL || texture->data == NULL) {
            fputs("FLUTTER_PEER_SOURCE_FAIL texture allocation\n", stderr);
            if (texture != NULL) XDestroyImage(texture);
            XFreePixmap(display, back_buffer);
            XFreeGC(display, graphics);
            XDestroyWindow(display, window);
            XCloseDisplay(display);
            return 1;
        }
        for (component = 0U; component < 256U; ++component) {
            texture_colors[0][component] = component_pixel((uint8_t)component, texture->red_mask);
            texture_colors[1][component] = component_pixel((uint8_t)component, texture->green_mask);
            texture_colors[2][component] = component_pixel((uint8_t)component, texture->blue_mask);
        }
    }
    XSync(display, False);
    printf("FLUTTER_PEER_SOURCE_READY display=%s dimensions=%ux%u interval_ms=%u "
           "identity=counter32 rows=4 bars=24 wrap=refused\n",
           DisplayString(display), source_width, source_height, frame_interval_ms);
    fflush(stdout);

    while (stop_requested == 0) {
        unsigned int low = frame & 15U;
        unsigned int high = (frame >> 4U) & 15U;
        unsigned int row, bar;
        uint64_t publication_us;

        XSetForeground(display, graphics, rgb_pixel(visual, palette[low]));
        XFillRectangle(display, back_buffer, graphics, 0, 0, source_width / 2U,
                       source_height);
        XSetForeground(display, graphics, rgb_pixel(visual, palette[high]));
        XFillRectangle(display, back_buffer, graphics, source_width / 2U, 0,
                       source_width / 2U, source_height);
        if (texture != NULL) {
            draw_texture(display, back_buffer, graphics, texture, frame, texture_top,
                         texture_colors);
        }
        for (row = 0U; row < STATE_CODE_ROWS; ++row) {
            for (bar = 0U; bar < STATE_CODE_BARS; ++bar) {
                unsigned int start = (bar * source_width) / STATE_CODE_BARS;
                unsigned int end = ((bar + 1U) * source_width) / STATE_CODE_BARS;
                const uint8_t *color =
                    state_code_bar_is_white(frame, row, bar) != 0 ? code_white : code_black;
                XSetForeground(display, graphics, rgb_pixel(visual, color));
                XFillRectangle(display, back_buffer, graphics, (int)start,
                               (int)(row * code_height / STATE_CODE_ROWS),
                               end - start, code_height / STATE_CODE_ROWS);
            }
        }
        /*
         * The observer and RustDesk capture are separate X clients. Publishing both color
         * nibbles in one request prevents either client from observing a state torn between
         * two same-cadence drawing requests.
         */
        XRaiseWindow(display, window);
        publication_us = monotonic_micros();
        if (publication_us == 0U) {
            fputs("FLUTTER_PEER_SOURCE_FAIL publication clock\n", stderr);
            exit_status = 1;
            break;
        }
        XCopyArea(display, back_buffer, window, graphics, 0, 0, source_width, source_height,
                  0, 0);
        XSync(display, False);
        if (!root_pixel_matches(display, root, (int)(source_width / 4U),
                                (int)(source_height / 2U),
                                rgb_pixel(visual, palette[low])) ||
            !root_pixel_matches(display, root, (int)(source_width * 3U / 4U),
                                (int)(source_height / 2U),
                                rgb_pixel(visual, palette[high])) ||
            !root_state_code_matches(display, root, visual, frame, source_width, code_height)) {
            fprintf(stderr, "FLUTTER_PEER_SOURCE_FAIL source window occluded frame=%u\n", frame);
            exit_status = 1;
            break;
        }
        if (trace_enabled != 0) {
            printf("RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=%llu "
                   "state=%u low=%u high=%u\n",
                   (unsigned long long)publication_us, frame, low, high);
            fflush(stdout);
        }
        if (frame == UINT32_MAX) {
            fputs("FLUTTER_PEER_SOURCE_FAIL frame identity exhausted\n", stderr);
            exit_status = 1;
            break;
        }
        ++frame;
        if (sleep_millis(frame_interval_ms) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL frame pacing\n", stderr);
            if (texture != NULL) XDestroyImage(texture);
            XFreePixmap(display, back_buffer);
            XFreeGC(display, graphics);
            XDestroyWindow(display, window);
            XCloseDisplay(display);
            return 1;
        }
    }

    if (exit_status == 0) {
        printf("FLUTTER_PEER_SOURCE_COMPLETE frames=%u\n", frame);
    }
    if (texture != NULL) XDestroyImage(texture);
    XFreePixmap(display, back_buffer);
    XFreeGC(display, graphics);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return exit_status;
}

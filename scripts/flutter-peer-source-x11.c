#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * Test-only source display for the full RustDesk peer-presentation probe.
 *
 * The colored halves retain the desktop palette probe. Four ordered Manchester bands encode
 * the complete non-wrapping uint32 frame identity for the mobile observer. Each publication is
 * bound to its monotonic start time; nominal frame pacing is not a freshness measurement.
 * Full-HD adds deterministic changing texture below the counter and palette witnesses.
 * Full-HD SIGUSR1 pauses animation; SIGRTMIN also arms numbered input responses.
 * The controller waits for each acknowledgement before changing modes; SIGUSR2 resumes.
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SOURCE_WIDTH 640U
#define SOURCE_HEIGHT 480U
#define FRAME_INTERVAL_MS 250U
#define DISPLAY_OPEN_ATTEMPTS 200U
#define STATE_CODE_BARS 24U
#define STATE_CODE_ROWS 4U
#define PUBLICATION_FILE_BYTES (64U * 1024U * 1024U)

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t pause_requested = 0;
static volatile sig_atomic_t response_requested = 0;

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

static void request_pause(int signal_number) {
    response_requested = 0;
    pause_requested = signal_number == SIGUSR1;
}

static void request_input(int signal_number) {
    (void)signal_number;
    response_requested = 1;
    pause_requested = 1;
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
                                   unsigned int code_height, unsigned int origin_x,
                                   unsigned int code_top) {
    unsigned int row, bar;
    for (row = 0U; row < STATE_CODE_ROWS; ++row) {
        for (bar = 0U; bar < STATE_CODE_BARS; ++bar) {
            unsigned int x = ((bar * 2U + 1U) * width) /
                             (STATE_CODE_BARS * 2U);
            const uint8_t *color =
                state_code_bar_is_white(state, row, bar) != 0 ? code_white : code_black;
            if (!root_pixel_matches(display, root, (int)(origin_x + x),
                                    (int)(code_top + (row * 2U + 1U) * code_height /
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

/* A unique four-digit request followed by Return prevents delayed input from impersonating a new trial. */
typedef struct {
    unsigned int held, position, request;
} ResponseInput;

static int response_input(Display *display, Window root, ResponseInput *input) {
    unsigned int events = 0U, completed = 0U;
    while (XPending(display) != 0) {
        XEvent event;
        KeySym symbol = NoSymbol;
        char text[8];
        if (++events > 128U) {
            fprintf(stderr, "FLUTTER_PEER_SOURCE_INPUT_REFUSED reason=event-budget request=%u pending=%d\n",
                    input->request, XPending(display));
            return -1;
        }
        XNextEvent(display, &event);
        if (event.type == MappingNotify) {
            XRefreshKeyboardMapping(&event.xmapping);
            continue;
        }
        if (event.type != KeyPress && event.type != KeyRelease) continue;
        if (input->request > 65535U || input->position > 4U) {
            fprintf(stderr, "FLUTTER_PEER_SOURCE_INPUT_REFUSED reason=request-state request=%u position=%u\n",
                    input->request, input->position);
            return -1;
        }
        unsigned int digit = input->position < 4U ?
            (input->request >> ((3U - input->position) * 4U)) & 15U : 0U;
        KeySym wanted = input->position == 4U ? XK_Return : XK_a + digit;
        char character = input->position == 4U ? '\r' : (char)('a' + digit);
        int size = XLookupString(&event.xkey, text, sizeof(text), &symbol, NULL);
        if (event.xkey.window != root || event.xkey.send_event ||
            (event.xkey.state & 255U) != 0U || symbol != wanted || size != 1 || text[0] != character) {
            fprintf(stderr, "FLUTTER_PEER_SOURCE_INPUT_REFUSED request=%u position=%u type=%d keycode=%u state=%u symbol=%lu wanted=%lu\n",
                    input->request, input->position, event.type, event.xkey.keycode,
                    event.xkey.state, (unsigned long)symbol, (unsigned long)wanted);
            return -1;
        }
        if (event.type == KeyPress) {
            if (input->held != 0U || completed != 0U) {
                fprintf(stderr, "FLUTTER_PEER_SOURCE_INPUT_REFUSED reason=press-order request=%u held=%u keycode=%u completed=%u\n",
                        input->request, input->held, event.xkey.keycode, completed);
                return -1;
            }
            input->held = event.xkey.keycode;
        } else {
            if (input->held == 0U || input->held != event.xkey.keycode || completed != 0U) {
                fprintf(stderr, "FLUTTER_PEER_SOURCE_INPUT_REFUSED reason=release-order request=%u held=%u keycode=%u completed=%u\n",
                        input->request, input->held, event.xkey.keycode, completed);
                return -1;
            }
            input->held = 0U;
            if (++input->position == 5U) {
                input->position = 0U;
                input->request += 1U;
                completed = 1U;
            }
        }
    }
    return (int)completed;
}

static int publish_response_ready(const char *directory, uint32_t frame) {
    struct stat metadata;
    char value[16];
    int length = snprintf(value, sizeof(value), "%u\n", frame);
    int parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int result = -1, file = -1;
    if (parent < 0) return -1;
    if (fstat(parent, &metadata) != 0 || metadata.st_uid != geteuid() ||
        metadata.st_gid != getegid() || (metadata.st_mode & 07777U) != 0700U) goto out;
    file = openat(parent, "input-response.ready.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                  O_CLOEXEC, 0600);
    if (file >= 0 && length > 0 && (size_t)length < sizeof(value) &&
        write(file, value, (size_t)length) == length) result = 0;
out:
    if (file >= 0 && close(file) != 0) result = -1;
    if (result == 0 && syscall(SYS_renameat2, parent, "input-response.ready.tmp",
                              parent, "input-response.ready", 1U) != 0) result = -1;
    if (close(parent) != 0) result = -1;
    return result;
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
    int pause_output = -1;
    unsigned int source_width = SOURCE_WIDTH;
    unsigned int source_height = SOURCE_HEIGHT;
    unsigned int frame_interval_ms = FRAME_INTERVAL_MS;
    unsigned int monitors = 1U;
    ResponseInput response = {0};
    int input_response = 0, interactive = 0, response_ready = 0;
    int response_on_pause = 0, pause_acknowledged = 0, response_active = 0;
    const char *response_directory = NULL;
    unsigned int code_height, code_top = 0U;
    unsigned int texture_top;
    const char *trace_value = getenv("RUSTDESK_PRESENTATION_TRACE");
    int trace_enabled = trace_value != NULL && strcmp(trace_value, "1") == 0;
    struct rlimit output_limit;

    if ((argc == 2 || ((argc == 4 || (argc == 6 && strcmp(argv[4], "--input-response") == 0)) &&
                      strcmp(argv[2], "--pause-output") == 0)) &&
        strcmp(argv[1], "--full-hd") == 0) {
        source_width = 1920U;
        source_height = 1080U;
        frame_interval_ms = 33U;
        if (argc >= 4) {
            pause_output = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                O_CLOEXEC, 0600);
            if (pause_output < 0) {
                fputs("FLUTTER_PEER_SOURCE_FAIL pause output\n", stderr);
                return 1;
            }
        }
        if (argc == 6) {
            input_response = response_on_pause = 1;
            response_directory = argv[5];
        }
    } else if (argc == 2 && strcmp(argv[1], "--two-monitors") == 0) {
        monitors = 2U;
    } else if (argc == 2 && strcmp(argv[1], "--inset-counter") == 0) {
        /* Keep the counter below the viewer's collapsed toolbar handle when
         * Adaptive removes the top letterbox. Midpoint palette probes stay clear. */
        code_top = SOURCE_HEIGHT / 10U;
    } else if (argc == 3 && strcmp(argv[1], "--input-response") == 0) {
        input_response = 1;
        response_directory = argv[2];
    } else if (argc != 1) {
        fputs("FLUTTER_PEER_SOURCE_FAIL usage: frame-source [--full-hd [--pause-output FILE [--input-response DIRECTORY]]|--two-monitors|--inset-counter|--input-response DIRECTORY]\n", stderr);
        return 1;
    }
    if (getrlimit(RLIMIT_FSIZE, &output_limit) != 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL publication output limit\n", stderr);
        return 1;
    }
    if (output_limit.rlim_cur > PUBLICATION_FILE_BYTES)
        output_limit.rlim_cur = PUBLICATION_FILE_BYTES;
    if (output_limit.rlim_max > PUBLICATION_FILE_BYTES)
        output_limit.rlim_max = PUBLICATION_FILE_BYTES;
    if (setrlimit(RLIMIT_FSIZE, &output_limit) != 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL publication output limit\n", stderr);
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
    if (pause_output >= 0) {
        action.sa_handler = request_pause;
        if (sigaction(SIGUSR1, &action, NULL) != 0 || sigaction(SIGUSR2, &action, NULL) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL pause signal handlers\n", stderr);
            return 1;
        }
    }
    if (response_on_pause) {
        action.sa_handler = request_input;
        if (sigaction(SIGRTMIN, &action, NULL) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL input signal handler\n", stderr);
            return 1;
        }
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
    if ((unsigned int)DisplayWidth(display, screen) != source_width * monitors ||
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
    if (input_response && !response_on_pause) {
        XSelectInput(display, root, KeyPressMask | KeyReleaseMask);
        XSetInputFocus(display, root, RevertToParent, CurrentTime);
    }
    attributes.override_redirect = True;
    attributes.background_pixel = rgb_pixel(visual, palette[0]);
    window = XCreateWindow(display, root, 0, 0, source_width * monitors, source_height, 0,
                           DefaultDepth(display, screen), InputOutput, visual,
                           CWOverrideRedirect | CWBackPixel, &attributes);
    if (window == 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL window creation\n", stderr);
        XCloseDisplay(display);
        return 1;
    }
    /* Full pixmap copies are verified through root pixels; no completion events are consumed. */
    XGCValues graphics_values = {.graphics_exposures = False};
    graphics = XCreateGC(display, window, GCGraphicsExposures, &graphics_values);
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
    if (source_width == 1920U) {
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
    if (printf("FLUTTER_PEER_SOURCE_READY display=%s dimensions=%ux%u interval_ms=%u "
               "identity=counter32 rows=4 bars=24 wrap=refused\n",
               DisplayString(display), source_width, source_height, frame_interval_ms) < 0 ||
        fflush(stdout) != 0) {
        fputs("FLUTTER_PEER_SOURCE_FAIL publication output\n", stderr);
        exit_status = 1;
        goto cleanup;
    }

    while (stop_requested == 0) {
        /* Acknowledge only a fully published, root-pixel-checked frame. Keep the
         * X window alive and unchanged until the observer explicitly resumes it. */
        if (pause_output >= 0 && (pause_requested != 0 || pause_acknowledged)) {
            if (!pause_acknowledged) {
                response_active = response_on_pause && response_requested != 0;
                if (response_active) {
                    Window focus;
                    int revert;
                    XSelectInput(display, root, KeyPressMask | KeyReleaseMask);
                    XSetInputFocus(display, root, RevertToParent, CurrentTime);
                    XGetInputFocus(display, &focus, &revert);
                    if (focus != root) {
                        fputs("FLUTTER_PEER_SOURCE_FAIL input focus\n", stderr);
                        exit_status = 1;
                        break;
                    }
                }
                if (frame == 0U || dprintf(pause_output, "paused state=%u monotonic_us=%llu\n",
                                          frame - 1U, (unsigned long long)monotonic_micros()) < 0) {
                    fputs("FLUTTER_PEER_SOURCE_FAIL pause acknowledgement\n", stderr);
                    exit_status = 1;
                    break;
                }
                pause_acknowledged = 1;
            }
            while (pause_requested != 0 && stop_requested == 0) {
                if (response_active) {
                    int received = response_input(display, root, &response);
                    if (received < 0) {
                        fputs("FLUTTER_PEER_SOURCE_FAIL native input response\n", stderr);
                        exit_status = 1;
                        goto cleanup;
                    }
                    if (received == 1) {
                        interactive = 1;
                        break;
                    }
                }
                if (sleep_millis(10U) != 0) {
                    exit_status = 1;
                    goto cleanup;
                }
            }
            if (stop_requested != 0) break;
            if (pause_requested == 0) {
                if (response_active) {
                    if (response_input(display, root, &response) != 0 ||
                        response.held != 0U || response.position != 0U) {
                        fputs("FLUTTER_PEER_SOURCE_FAIL incomplete input at resume\n", stderr);
                        exit_status = 1;
                        break;
                    }
                    XSelectInput(display, root, NoEventMask);
                    XSync(display, False);
                }
                interactive = 0;
                response_active = 0;
                pause_acknowledged = 0;
                if (dprintf(pause_output, "resumed state=%u monotonic_us=%llu\n",
                            frame - 1U, (unsigned long long)monotonic_micros()) < 0) {
                    fputs("FLUTTER_PEER_SOURCE_FAIL resume acknowledgement\n", stderr);
                    exit_status = 1;
                    break;
                }
            }
        }
        /* One ordered publication history: even identities belong only to the
         * left monitor, odd identities only to the right. Each advances at 4 Hz. */
        unsigned int origin_x = (frame % monitors) * source_width;
        unsigned int low = frame & 15U;
        unsigned int high = (frame >> 4U) & 15U;
        unsigned int row, bar;
        uint64_t publication_us;

        if (input_response && !response_on_pause) {
            int received;
            do {
                received = response_input(display, root, &response);
                if (received < 0 || (interactive && received == 0 && sleep_millis(10U) != 0)) {
                    fputs("FLUTTER_PEER_SOURCE_FAIL native input response\n", stderr);
                    exit_status = 1;
                    goto cleanup;
                }
            } while (interactive && received == 0 && stop_requested == 0);
            if (stop_requested != 0) break;
            if (received == 1) interactive = 1;
        }

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
                               (int)(code_top + row * code_height / STATE_CODE_ROWS),
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
                  (int)origin_x, 0);
        XSync(display, False);
        if (!root_pixel_matches(display, root, (int)(origin_x + source_width / 4U),
                                (int)(source_height / 2U),
                                rgb_pixel(visual, palette[low])) ||
            !root_pixel_matches(display, root, (int)(origin_x + source_width * 3U / 4U),
                                (int)(source_height / 2U),
                                rgb_pixel(visual, palette[high])) ||
            !root_state_code_matches(display, root, visual, frame, source_width, code_height,
                                     origin_x, code_top)) {
            fprintf(stderr, "FLUTTER_PEER_SOURCE_FAIL source window occluded frame=%u\n", frame);
            exit_status = 1;
            break;
        }
        if (trace_enabled != 0) {
            if (printf("RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=%llu "
                       "state=%u low=%u high=%u\n",
                       (unsigned long long)publication_us, frame, low, high) < 0 ||
                fflush(stdout) != 0) {
                fputs("FLUTTER_PEER_SOURCE_FAIL publication output\n", stderr);
                exit_status = 1;
                break;
            }
        }
        if (interactive && !response_ready) {
            if (publish_response_ready(response_directory, frame) != 0) {
                fputs("FLUTTER_PEER_SOURCE_FAIL response readiness\n", stderr);
                exit_status = 1;
                break;
            }
            response_ready = 1;
        }
        if (frame == UINT32_MAX) {
            fputs("FLUTTER_PEER_SOURCE_FAIL frame identity exhausted\n", stderr);
            exit_status = 1;
            break;
        }
        ++frame;
        if (!interactive && frame % monitors == 0U && sleep_millis(frame_interval_ms) != 0) {
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
        if (printf("FLUTTER_PEER_SOURCE_COMPLETE frames=%u\n", frame) < 0 ||
            fflush(stdout) != 0) {
            fputs("FLUTTER_PEER_SOURCE_FAIL publication output\n", stderr);
            exit_status = 1;
        }
    }
cleanup:
    if (pause_output >= 0 && close(pause_output) != 0) exit_status = 1;
    if (texture != NULL) XDestroyImage(texture);
    XFreePixmap(display, back_buffer);
    XFreeGC(display, graphics);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return exit_status;
}

#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include "x11-frame-oracle.h"

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "X11_FRAME_NATIVE_FAIL line=%d\n", __LINE__); \
        return -1; \
    } \
} while (0)

static void make_pixels(uint8_t *pixels, uint32_t identity, unsigned int top,
                         unsigned int left, unsigned int span) {
    for (unsigned int band = 0U; band < 4U; ++band) {
        unsigned int code = (band << 8U) | ((identity >> (24U - band * 8U)) & 255U);
        for (unsigned int y = top + band * 12U; y < top + (band + 1U) * 12U; ++y) {
            for (unsigned int x = left; x < left + span; ++x) {
                unsigned int bar = (x - left) * 24U / span;
                int white = bar == 1U || bar == 22U;
                if (bar >= 2U && bar < 22U) {
                    unsigned int bit = 9U - (bar - 2U) / 2U;
                    white = ((code >> bit) & 1U) == ((bar & 1U) == 0U);
                }
                memset(pixels + (y * X11_FRAME_WIDTH + x) * 3U, white ? 245 : 10, 3U);
            }
        }
    }
}

static int write_history(int descriptor, uint64_t first, uint64_t second,
                          unsigned int first_identity, unsigned int second_low) {
    return ftruncate(descriptor, 0) == 0 && lseek(descriptor, 0, SEEK_SET) == 0 &&
        dprintf(descriptor, "FLUTTER_PEER_SOURCE_READY display=:98 dimensions=640x480 "
                "interval_ms=250 identity=counter32 rows=4 bars=24 wrap=refused\n"
                "RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=%llu "
                "state=%u low=0 high=0\n"
                "RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=%llu "
                "state=1 low=%u high=0\n", (unsigned long long)first, first_identity,
                (unsigned long long)second, second_low) > 0 ? 0 : -1;
}

static int require_bad_history(const char *directory) {
    SourceHistory history = {0};
    return x11_frame_refresh(&history, directory) != 0 && history.failed ? 0 : -1;
}

static int unit_cases(void) {
    uint8_t pixels[X11_FRAME_BYTES], row[12U * X11_FRAME_WIDTH * 3U];
    uint32_t identities[] = {0U, 256U, 65536U, 16777216U, UINT32_MAX};
    char directory[] = "/tmp/x11-frame-oracle.XXXXXXXXXX", path[256], other[256];
    SourceHistory retained = {0};
    uint64_t now = x11_frame_monotonic_us(), age;
    int descriptor;
    REQUIRE(now > 5000000U);
    for (size_t index = 0U; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        memset(pixels, 180, sizeof(pixels));
        make_pixels(pixels, identities[index], 0U, 0U, X11_FRAME_WIDTH);
        REQUIRE(x11_frame_decode(pixels) == (int64_t)identities[index]);
    }
    memcpy(row, pixels, sizeof(row));
    memcpy(pixels, pixels + sizeof(row), sizeof(row));
    memcpy(pixels + sizeof(row), row, sizeof(row));
    REQUIRE(x11_frame_decode(pixels) < 0); /* Reordered ordinals. */
    memset(pixels, 180, sizeof(pixels));
    make_pixels(pixels, 256U, 0U, 0U, X11_FRAME_WIDTH);
    memset(pixels + 24U * X11_FRAME_WIDTH * 3U, 180, sizeof(row));
    REQUIRE(x11_frame_decode(pixels) < 0); /* Missing band. */
    memset(pixels, 180, sizeof(pixels));
    make_pixels(pixels, 256U, 0U, 0U, X11_FRAME_WIDTH);
    make_pixels(pixels, 65536U, 60U, 0U, X11_FRAME_WIDTH);
    REQUIRE(x11_frame_decode(pixels) < 0); /* Two plausible complete identities. */
    memset(pixels, 180, sizeof(pixels));
    make_pixels(pixels, 0x01020304U, 0U, 50U, 100U);
    REQUIRE(x11_frame_decode(pixels) == 0x01020304);

    REQUIRE(mkdtemp(directory) != NULL);
    REQUIRE(snprintf(path, sizeof(path), "%s/frame-source.log", directory) > 0);
    REQUIRE(snprintf(other, sizeof(other), "%s/other", directory) > 0);
    descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    REQUIRE(descriptor >= 0);
    REQUIRE(write_history(descriptor, now - 5000000U, now - 1U, 0U, 1U) == 0);
    REQUIRE(x11_frame_age(&retained, directory, 0, now, &age) == 0 && age >= 5000U);
    REQUIRE(x11_frame_age(&retained, directory, 2, now, &age) != 0 && !retained.failed);
    REQUIRE(x11_frame_age(&retained, directory, 1, now - 2U, &age) != 0);
    REQUIRE(dprintf(descriptor, "RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=") > 0);
    REQUIRE(x11_frame_refresh(&retained, directory) == 0 && retained.count == 2U &&
            retained.pending_size != 0U);
    REQUIRE(dprintf(descriptor, "%llu state=2 low=2 high=0\nFLUTTER_PEER_SOURCE_COMPLETE frames=3\n",
                    (unsigned long long)x11_frame_monotonic_us()) > 0);
    REQUIRE(x11_frame_refresh(&retained, directory) == 0 && retained.count == 3U && retained.complete);
    REQUIRE(chmod(path, 0644) == 0 && require_bad_history(directory) == 0);
    REQUIRE(chmod(path, 0600) == 0);
    REQUIRE(chmod(directory, 0755) == 0 && require_bad_history(directory) == 0);
    REQUIRE(chmod(directory, 0700) == 0);
    REQUIRE(link(path, other) == 0 && require_bad_history(directory) == 0);
    REQUIRE(unlink(other) == 0);
    REQUIRE(rename(path, other) == 0 && symlink("other", path) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    REQUIRE(unlink(path) == 0 && mkfifo(path, 0600) == 0);
    REQUIRE(require_bad_history(directory) == 0); /* Nonblocking FIFO refusal. */
    REQUIRE(unlink(path) == 0 && rename(other, path) == 0);
    REQUIRE(write_history(descriptor, now - 1U, now + 60000000U, 0U, 1U) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    REQUIRE(write_history(descriptor, now - 5000U, now - 5000U, 0U, 1U) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    REQUIRE(write_history(descriptor, now - 5000U, now - 1U, 1U, 1U) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    REQUIRE(write_history(descriptor, now - 5000U, now - 1U, 0U, 2U) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    {
        SourceHistory replacement = {0};
        int new_file;
        REQUIRE(write_history(descriptor, now - 5000U, now - 1U, 0U, 1U) == 0);
        REQUIRE(x11_frame_refresh(&replacement, directory) == 0);
        REQUIRE(rename(path, other) == 0);
        new_file = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        REQUIRE(new_file >= 0 && write_history(new_file, now - 5000U, now - 1U, 0U, 1U) == 0);
        REQUIRE(x11_frame_refresh(&replacement, directory) != 0 && replacement.failed);
        REQUIRE(close(new_file) == 0 && unlink(path) == 0 && rename(other, path) == 0);
    }
    REQUIRE(ftruncate(descriptor, X11_FRAME_LOG_LIMIT + 1U) == 0);
    REQUIRE(require_bad_history(directory) == 0);
    REQUIRE(ftruncate(descriptor, 0) == 0);
    REQUIRE(x11_frame_refresh(&retained, directory) != 0 && retained.failed);
    REQUIRE(write_history(descriptor, now - 5000000U, now - 1U, 0U, 1U) == 0);
    REQUIRE(x11_frame_refresh(&retained, directory) != 0); /* No reset after uncertainty. */
    REQUIRE(close(descriptor) == 0 && unlink(path) == 0 && rmdir(directory) == 0);
    puts("ANDROID_FRAME_NATIVE_X11_CASES=pass full_bits=32 reordered=refused incomplete=refused "
         "ambiguous=refused unknown=refused clock=refused mode=refused link=refused fifo=refused "
         "history=bounded uncertainty=sticky cleanup=joined");
    fflush(stdout);
    return 0;
}

static void paint_geometry(Display *display, Window window, GC graphics, uint32_t identity) {
    for (unsigned int band = 0U; band < 4U; ++band) {
        unsigned int code = (band << 8U) | ((identity >> (24U - band * 8U)) & 255U);
        for (unsigned int bar = 0U; bar < 24U; ++bar) {
            int white = bar == 1U || bar == 22U;
            unsigned int start = bar * 640U / 24U, end = (bar + 1U) * 640U / 24U;
            if (bar >= 2U && bar < 22U) {
                white = ((code >> (9U - (bar - 2U) / 2U)) & 1U) == ((bar & 1U) == 0U);
            }
            XSetForeground(display, graphics, white ? WhitePixel(display, DefaultScreen(display)) :
                                                       BlackPixel(display, DefaultScreen(display)));
            XFillRectangle(display, window, graphics, (int)(330U + start),
                            (int)(100U + band * 48U), end - start, 48U);
        }
    }
}

static int geometry_case(int old_window_request) {
    Display *display = XOpenDisplay(":99");
    Window root, window, cover = 0;
    GC graphics;
    uint8_t pixels[X11_FRAME_BYTES];
    uint64_t captured_us = 0U;
    const uint32_t identity = 0x01020304U;
    if (display == NULL) return -1;
    root = DefaultRootWindow(display);
    if (DisplayWidth(display, DefaultScreen(display)) != 1280 ||
        DisplayHeight(display, DefaultScreen(display)) != 800) {
        XCloseDisplay(display);
        return -1;
    }
    window = XCreateSimpleWindow(display, root, -10, 20, 1300U, 740U, 0U,
                                  BlackPixel(display, DefaultScreen(display)),
                                  BlackPixel(display, DefaultScreen(display)));
    if (window == 0) {
        XCloseDisplay(display);
        return -1;
    }
    graphics = XCreateGC(display, window, 0, NULL);
    if (graphics == NULL) {
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return -1;
    }
    XMapRaised(display, window);
    paint_geometry(display, window, graphics, identity);
    XSync(display, False);
    if (old_window_request) {
        XImage *old = XGetImage(display, window, 0, 0, 1300U, 740U, AllPlanes, ZPixmap);
        if (old != NULL) XDestroyImage(old);
        XFreeGC(display, graphics);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return -1; /* Expected default BadMatch handler exits before this point. */
    }
    int result = -1;
    if (x11_frame_capture(display, window, pixels, &captured_us) != identity) goto finished;
    cover = XCreateSimpleWindow(display, root, 320, 120, 640U, 192U, 0U,
                                BlackPixel(display, DefaultScreen(display)),
                                BlackPixel(display, DefaultScreen(display)));
    if (cover == 0) goto finished;
    XMapRaised(display, cover);
    XSync(display, False);
    if (x11_frame_capture(display, window, pixels, &captured_us) >= 0) goto finished;
    XDestroyWindow(display, cover);
    cover = 0;
    paint_geometry(display, window, graphics, identity);
    XSync(display, False);
    if (x11_frame_capture(display, window, pixels, &captured_us) != identity) goto finished;
    XMoveWindow(display, window, -1400, 20);
    XSync(display, False);
    if (x11_frame_capture(display, window, pixels, &captured_us) >= 0) goto finished;
    XMoveWindow(display, window, -500, 20);
    XSync(display, False);
    if (x11_frame_capture(display, window, pixels, &captured_us) >= 0) goto finished;
    XMoveWindow(display, window, -10, 20);
    XUnmapWindow(display, window);
    XSync(display, False);
    if (x11_frame_capture(display, window, pixels, &captured_us) >= 0) goto finished;
    result = 0;
finished:
    if (cover != 0) XDestroyWindow(display, cover);
    XFreeGC(display, graphics);
    XDestroyWindow(display, window);
    XSync(display, False);
    if (XCloseDisplay(display) != 0) result = -1;
    if (result == 0) {
        puts("X11_FRAME_NATIVE_GEOMETRY=pass clipped=decoded letterbox=decoded hidden=refused "
             "occluded=refused unmapped=refused windows=joined");
        fflush(stdout);
    }
    return result;
}

static int native_case(const char *directory) {
    SourceHistory history = {0}, late_history = {0};
    uint8_t old_pixels[X11_FRAME_BYTES], fresh_pixels[X11_FRAME_BYTES];
    Display *display = XOpenDisplay(":98");
    int64_t old_identity = -1, fresh_identity = -1;
    uint64_t captured_us = 0U, old_age = 0U, fresh_age = 0U;
    uint64_t deadline = x11_frame_monotonic_us() + 20000000U;
    struct timespec pause = {0, 40000000L};
    int result = -1, initial_fresh = 0;
    if (display == NULL) return -1;
    while (x11_frame_monotonic_us() < deadline) {
        old_identity = x11_frame_capture(display, DefaultRootWindow(display), old_pixels, &captured_us);
        if (x11_frame_age(&history, directory, old_identity, captured_us, &old_age) == 0 && old_age <= 1000U) {
            initial_fresh = 1;
            break;
        }
        if (history.failed || nanosleep(&pause, NULL) != 0) goto finished;
    }
    if (!initial_fresh) goto finished;
    while (x11_frame_monotonic_us() < deadline) {
        if (x11_frame_refresh(&history, directory) != 0) goto finished;
        if (history.count > (uint64_t)old_identity + 256U) break;
        if (nanosleep(&pause, NULL) != 0) goto finished;
    }
    fresh_identity = x11_frame_capture(display, DefaultRootWindow(display), fresh_pixels, &captured_us);
    if (fresh_identity - old_identity < 256 || fresh_identity - old_identity > 264 ||
        x11_frame_age(&history, directory, fresh_identity, captured_us, &fresh_age) != 0 ||
        fresh_age > 1000U || x11_frame_decode(old_pixels) != old_identity) goto finished;
    /* New observation time and a newly attached observer cannot rejuvenate the old picture. */
    captured_us = x11_frame_monotonic_us();
    if (x11_frame_age(&history, directory, old_identity, captured_us, &old_age) != 0 || old_age < 8448U ||
        x11_frame_age(&late_history, directory, old_identity, captured_us, &old_age) != 0 || old_age < 8448U ||
        (fresh_identity - old_identity) % 256 > 8) goto finished;
    printf("ANDROID_FRAME_NATIVE_X11_AB=pass old_predicate=accept new=refuse old_identity=%lld "
           "fresh_identity=%lld stale_age_ms=%llu fresh_age_ms=%llu late_attach=refused "
           "capture=actual-x11\n", (long long)old_identity, (long long)fresh_identity,
           (unsigned long long)old_age, (unsigned long long)fresh_age);
    fflush(stdout);
    result = 0;
finished:
    if (XCloseDisplay(display) != 0) result = -1;
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2 || getuid() != 4000 || geteuid() != 4000 || getgid() != 4000 || getegid() != 4000) {
        return 1;
    }
    if (strcmp(argv[1], "--old-window-image") == 0) return geometry_case(1) != 0;
    if (strcmp(argv[1], "--geometry") == 0) return unit_cases() != 0 || geometry_case(0) != 0;
    return native_case(argv[1]) != 0;
}

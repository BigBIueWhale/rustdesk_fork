#ifndef RUSTDESK_X11_FRAME_ORACLE_H
#define RUSTDESK_X11_FRAME_ORACLE_H

/* Test-only full-counter pixel and publication oracle, shared by the controller and native test. */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define X11_FRAME_WIDTH 200U
#define X11_FRAME_HEIGHT 120U
#define X11_FRAME_BYTES (X11_FRAME_WIDTH * X11_FRAME_HEIGHT * 3U)
#define X11_FRAME_HISTORY_LIMIT 32768U
#define X11_FRAME_LOG_LIMIT (2U * 1024U * 1024U)

typedef struct {
    uint64_t publication_us[X11_FRAME_HISTORY_LIMIT];
    dev_t directory_device, file_device;
    ino_t directory_inode, file_inode;
    off_t offset;
    size_t pending_size;
    char pending[256];
    unsigned int count;
    int acquired, ready, complete, failed;
} SourceHistory;

static uint64_t x11_frame_monotonic_us(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000000U + (uint64_t)now.tv_nsec / 1000U;
}

static int x11_frame_number(const char **cursor, uint64_t *value) {
    const char *start = *cursor;
    uint64_t result = 0U;
    if (*start < '0' || *start > '9') {
        return -1;
    }
    while (**cursor >= '0' && **cursor <= '9') {
        unsigned int digit = (unsigned int)(**cursor - '0');
        if (result > (UINT64_MAX - digit) / 10U) {
            return -1;
        }
        result = result * 10U + digit;
        ++*cursor;
    }
    if (*start == '0' && *cursor - start != 1) {
        return -1;
    }
    *value = result;
    return 0;
}

static int x11_frame_literal(const char **cursor, const char *literal) {
    size_t length = strlen(literal);
    if (strncmp(*cursor, literal, length) != 0) {
        return -1;
    }
    *cursor += length;
    return 0;
}

static int x11_frame_publication_line(SourceHistory *history, uint64_t now_us) {
    const char *cursor = history->pending;
    uint64_t publication, identity, low, high;
    if (!history->ready) {
        if (strcmp(cursor, "FLUTTER_PEER_SOURCE_READY display=:98 dimensions=640x480 "
                   "interval_ms=250 identity=counter32 rows=4 bars=24 wrap=refused") != 0 &&
            strcmp(cursor, "FLUTTER_PEER_SOURCE_READY display=:98 dimensions=1920x1080 "
                   "interval_ms=33 identity=counter32 rows=4 bars=24 wrap=refused") != 0) {
            return -1;
        }
        history->ready = 1;
        return 0;
    }
    if (history->complete) {
        return -1;
    }
    if (strncmp(cursor, "FLUTTER_PEER_SOURCE_COMPLETE frames=", 36U) == 0) {
        if (x11_frame_literal(&cursor, "FLUTTER_PEER_SOURCE_COMPLETE frames=") != 0 ||
            x11_frame_number(&cursor, &identity) != 0 || *cursor != '\0' ||
            identity != history->count || identity == 0U) {
            return -1;
        }
        history->complete = 1;
        return 0;
    }
    if (x11_frame_literal(&cursor, "RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=") != 0 ||
        x11_frame_number(&cursor, &publication) != 0 ||
        x11_frame_literal(&cursor, " state=") != 0 ||
        x11_frame_number(&cursor, &identity) != 0 ||
        x11_frame_literal(&cursor, " low=") != 0 ||
        x11_frame_number(&cursor, &low) != 0 ||
        x11_frame_literal(&cursor, " high=") != 0 ||
        x11_frame_number(&cursor, &high) != 0 || *cursor != '\0' ||
        identity != history->count || identity >= X11_FRAME_HISTORY_LIMIT ||
        low != (identity & 15U) || high != ((identity >> 4U) & 15U) ||
        publication == 0U || publication > now_us ||
        (history->count != 0U && publication <= history->publication_us[history->count - 1U])) {
        return -1;
    }
    history->publication_us[history->count++] = publication;
    return 0;
}

static int x11_frame_file_valid(const struct stat *metadata) {
    return S_ISREG(metadata->st_mode) && metadata->st_uid == geteuid() &&
           metadata->st_gid == getegid() && (metadata->st_mode & 07777U) == 0600U &&
           metadata->st_nlink == 1U && metadata->st_size >= 0 &&
           metadata->st_size <= (off_t)X11_FRAME_LOG_LIMIT;
}

/* The isolated fixture is the sole cooperating appender. Never reset identity on reconnect. */
static int x11_frame_refresh(SourceHistory *history, const char *directory) {
    int parent = -1, file = -1, result = -1;
    struct stat root, before, after;
    char buffer[4096];
    uint64_t now_us;
    if (history->failed) {
        return -1;
    }
    parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (parent < 0 || fstat(parent, &root) != 0 || !S_ISDIR(root.st_mode) ||
        root.st_uid != geteuid() || root.st_gid != getegid() ||
        (root.st_mode & 07777U) != 0700U) {
        goto finished;
    }
    file = openat(parent, "frame-source.log", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (file < 0 || fstat(file, &before) != 0 || !x11_frame_file_valid(&before) ||
        before.st_size < history->offset) {
        goto finished;
    }
    if (history->acquired &&
        (root.st_dev != history->directory_device || root.st_ino != history->directory_inode ||
         before.st_dev != history->file_device || before.st_ino != history->file_inode)) {
        goto finished;
    }
    history->directory_device = root.st_dev;
    history->directory_inode = root.st_ino;
    history->file_device = before.st_dev;
    history->file_inode = before.st_ino;
    history->acquired = 1;
    now_us = x11_frame_monotonic_us();
    if (now_us == 0U) {
        goto finished;
    }
    while (history->offset < before.st_size) {
        size_t wanted = (size_t)(before.st_size - history->offset);
        ssize_t received;
        if (wanted > sizeof(buffer)) {
            wanted = sizeof(buffer);
        }
        received = pread(file, buffer, wanted, history->offset);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            goto finished;
        }
        history->offset += received;
        for (ssize_t index = 0; index < received; ++index) {
            if (buffer[index] == '\n') {
                history->pending[history->pending_size] = '\0';
                if (x11_frame_publication_line(history, now_us) != 0) {
                    goto finished;
                }
                history->pending_size = 0U;
            } else {
                if (buffer[index] == '\0' || history->pending_size + 1U >= sizeof(history->pending)) {
                    goto finished;
                }
                history->pending[history->pending_size++] = buffer[index];
            }
        }
    }
    if (fstat(file, &after) != 0 || !x11_frame_file_valid(&after) ||
        after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size < before.st_size) {
        goto finished;
    }
    result = 0;
finished:
    if (file >= 0 && close(file) != 0) {
        result = -1;
    }
    if (parent >= 0 && close(parent) != 0) {
        result = -1;
    }
    if (result != 0) {
        history->failed = 1;
    }
    return result;
}

static int x11_frame_age(SourceHistory *history, const char *directory, int64_t identity,
                         uint64_t captured_us, uint64_t *age_ms) {
    uint64_t now_us, elapsed;
    if (x11_frame_refresh(history, directory) != 0 || identity < 0 ||
        (uint64_t)identity >= history->count) {
        return -1;
    }
    now_us = x11_frame_monotonic_us();
    if (captured_us == 0U || now_us < captured_us ||
        history->publication_us[identity] > captured_us) {
        return -1;
    }
    elapsed = now_us - history->publication_us[identity];
    *age_ms = elapsed / 1000U + (elapsed % 1000U != 0U);
    return 0;
}

static int x11_frame_row(const uint8_t *pixels, unsigned int y, unsigned int left,
                         unsigned int span) {
    int values[24], code = 0, darkest_light = 255, lightest_dark = 0;
    for (unsigned int bar = 0U; bar < 24U; ++bar) {
        unsigned int x = left + ((2U * bar + 1U) * span) / 48U;
        const uint8_t *rgb = pixels + (y * X11_FRAME_WIDTH + x) * 3U;
        values[bar] = (55 * rgb[0] + 182 * rgb[1] + 19 * rgb[2]) / 256;
    }
    if (values[1] - values[0] < 8 || values[22] - values[23] < 8) {
        return -1;
    }
    for (unsigned int bar = 2U; bar < 22U; bar += 2U) {
        int difference = values[bar] - values[bar + 1U];
        if (difference > -8 && difference < 8) {
            return -1;
        }
        code = (code << 1) | (difference > 0);
    }
    for (unsigned int bar = 0U; bar < 24U; ++bar) {
        int white;
        if (bar < 2U) {
            white = bar == 1U;
        } else if (bar >= 22U) {
            white = bar == 22U;
        } else {
            unsigned int bit = 9U - (bar - 2U) / 2U;
            white = ((code >> bit) & 1) == (int)((bar & 1U) == 0U);
        }
        if (white && values[bar] < darkest_light) {
            darkest_light = values[bar];
        } else if (!white && values[bar] > lightest_dark) {
            lightest_dark = values[bar];
        }
    }
    return darkest_light - lightest_dark >= 5 ? code : -1;
}

static int64_t x11_frame_decode(const uint8_t pixels[X11_FRAME_BYTES]) {
    int64_t identity = -1;
    /* Remote content is centered; tolerate three sampled pixels of layout rounding. */
    for (unsigned int span = X11_FRAME_WIDTH * 3U / 5U; span <= X11_FRAME_WIDTH; span += 2U) {
        int centered = (int)(X11_FRAME_WIDTH - span) / 2;
        for (int left = centered - 3; left <= centered + 3; ++left) {
            struct { int code; unsigned int top, end; } runs[X11_FRAME_HEIGHT];
            unsigned int count = 0U;
            if (left < 0 || (unsigned int)left + span > X11_FRAME_WIDTH) {
                continue;
            }
            for (unsigned int y = 0U; y < X11_FRAME_HEIGHT; ++y) {
                int code = x11_frame_row(pixels, y, (unsigned int)left, span);
                if (count != 0U && runs[count - 1U].code == code) {
                    runs[count - 1U].end = y + 1U;
                } else {
                    runs[count].code = code;
                    runs[count].top = y;
                    runs[count++].end = y + 1U;
                }
            }
            for (unsigned int start = 0U; start < count; ++start) {
                uint32_t candidate = 0U;
                unsigned int cursor = start, previous_end = 0U, minimum = UINT32_MAX, maximum = 0U;
                int valid = 1;
                for (unsigned int band = 0U; band < 4U; ++band) {
                    unsigned int length;
                    if (band != 0U && cursor < count && runs[cursor].code < 0) {
                        ++cursor;
                    }
                    if (cursor >= count || runs[cursor].code < 0 ||
                        (unsigned int)(runs[cursor].code >> 8) != band ||
                        (band != 0U && runs[cursor].top - previous_end > 2U)) {
                        valid = 0;
                        break;
                    }
                    length = runs[cursor].end - runs[cursor].top;
                    if (length < minimum) minimum = length;
                    if (length > maximum) maximum = length;
                    candidate = (candidate << 8U) | (uint32_t)(runs[cursor].code & 255);
                    previous_end = runs[cursor++].end;
                }
                if (valid && minimum >= 3U && maximum - minimum <= 2U) {
                    if (identity >= 0 && identity != (int64_t)candidate) {
                        return -1; /* Ambiguous pixels never acquire freshness. */
                    }
                    identity = candidate;
                }
            }
        }
    }
    return identity;
}

static uint8_t x11_frame_component(unsigned long pixel, unsigned long mask) {
    unsigned int shift = 0U;
    unsigned long normalized, value;
    if (mask == 0UL) return 0U;
    while (((mask >> shift) & 1UL) == 0UL) ++shift;
    normalized = mask >> shift;
    value = (pixel & mask) >> shift;
    return (uint8_t)((value * 255UL + normalized / 2UL) / normalized);
}

static int64_t x11_frame_capture(Display *display, Window window,
                                 uint8_t pixels[X11_FRAME_BYTES], uint64_t *captured_us) {
    XWindowAttributes attributes;
    XImage *image;
    if (XGetWindowAttributes(display, window, &attributes) == 0 || attributes.visual == NULL ||
        attributes.width < (int)X11_FRAME_WIDTH || attributes.height < (int)X11_FRAME_HEIGHT ||
        attributes.width > 4096 || attributes.height > 4096) {
        return -1;
    }
    image = XGetImage(display, window, 0, 0, (unsigned int)attributes.width,
                      (unsigned int)attributes.height, AllPlanes, ZPixmap);
    if (image == NULL) return -1;
    *captured_us = x11_frame_monotonic_us();
    for (unsigned int y = 0U; y < X11_FRAME_HEIGHT; ++y) {
        for (unsigned int x = 0U; x < X11_FRAME_WIDTH; ++x) {
            unsigned long pixel = XGetPixel(image, (int)(x * (unsigned int)attributes.width / X11_FRAME_WIDTH),
                                            (int)(y * (unsigned int)attributes.height / X11_FRAME_HEIGHT));
            uint8_t *rgb = pixels + (y * X11_FRAME_WIDTH + x) * 3U;
            rgb[0] = x11_frame_component(pixel, image->red_mask);
            rgb[1] = x11_frame_component(pixel, image->green_mask);
            rgb[2] = x11_frame_component(pixel, image->blue_mask);
        }
    }
    XDestroyImage(image);
    return *captured_us != 0U ? x11_frame_decode(pixels) : -1;
}

#endif

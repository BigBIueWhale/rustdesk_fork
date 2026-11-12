#ifndef RUSTDESK_FLUTTER_PEER_RECORDING_H
#define RUSTDESK_FLUTTER_PEER_RECORDING_H

#include <vpx/vpx_decoder.h>
#include <vpx/vp8dx.h>

/* A bounded reader for this fixture's finalized, single-track WebM files.
 * It does not implement a general player. Native libvpx decodes every packet;
 * the existing pixel oracle binds the resulting images to the live source. */
typedef struct {
    uint64_t id;
    const unsigned char *data;
    size_t size;
} RecordingElement;

typedef struct {
    unsigned int packets, images;
    int64_t first_frame, last_frame;
    uint64_t last_pts_ms;
    const char *codec;
} RecordingVideo;

static int recording_vint(const unsigned char *data, size_t size, size_t *offset,
                           int identifier, uint64_t *value) {
    if (*offset >= size || data[*offset] == 0U) return -1;
    unsigned int length = 1U, marker = 128U;
    while ((data[*offset] & marker) == 0U) { ++length; marker >>= 1U; }
    if (length > (identifier ? 4U : 8U) || length > size - *offset) return -1;
    uint64_t number = data[(*offset)++];
    if (!identifier) number &= marker - 1U;
    for (unsigned int i = 1U; i < length; ++i) number = (number << 8U) | data[(*offset)++];
    if (!identifier && number == (UINT64_C(1) << (7U * length)) - 1U) return -1;
    *value = number;
    return 0;
}

static int recording_next(const RecordingElement *parent, size_t *offset,
                           RecordingElement *child) {
    uint64_t length = 0U;
    if (recording_vint(parent->data, parent->size, offset, 1, &child->id) != 0 ||
        recording_vint(parent->data, parent->size, offset, 0, &length) != 0 ||
        length > parent->size - *offset) return -1;
    child->data = parent->data + *offset;
    child->size = (size_t)length;
    *offset += child->size;
    return 0;
}

static int recording_child(const RecordingElement *parent, uint64_t id,
                            RecordingElement *found) {
    size_t offset = 0U;
    unsigned int matches = 0U, elements = 0U;
    while (offset < parent->size) {
        RecordingElement child = {0};
        if (++elements > 4096U || recording_next(parent, &offset, &child) != 0) return -1;
        if (child.id == id) { *found = child; ++matches; }
    }
    return matches == 1U ? 0 : -1;
}

static int recording_uint(const RecordingElement *parent, uint64_t id, uint64_t expected) {
    RecordingElement child = {0};
    if (recording_child(parent, id, &child) != 0 || child.size == 0U || child.size > 8U)
        return -1;
    uint64_t value = 0U;
    for (size_t i = 0U; i < child.size; ++i) value = (value << 8U) | child.data[i];
    return value == expected ? 0 : -1;
}

static int recording_decode(const unsigned char *data, size_t size, SourceHistory *history,
                             uint64_t started_us, uint64_t stopped_us, RecordingVideo *video) {
    RecordingElement root = {0, data, size}, header = {0}, doc = {0}, segment = {0};
    RecordingElement info = {0}, tracks = {0}, track = {0}, codec_id = {0}, dimensions = {0};
    vpx_codec_ctx_t decoder = {0};
    int initialized = 0, result = -1;
    *video = (RecordingVideo){.first_frame = -1, .last_frame = -1};
    if (recording_child(&root, 0x1a45dfa3U, &header) != 0 ||
        recording_child(&header, 0x4282U, &doc) != 0 ||
        doc.size != 4U || memcmp(doc.data, "webm", 4U) != 0 ||
        recording_child(&root, 0x18538067U, &segment) != 0 ||
        recording_child(&segment, 0x1549a966U, &info) != 0 ||
        recording_uint(&info, 0x2ad7b1U, 1000000U) != 0 ||
        recording_child(&segment, 0x1654ae6bU, &tracks) != 0 ||
        recording_child(&tracks, 0xaeU, &track) != 0 ||
        recording_uint(&track, 0xd7U, 1U) != 0 ||
        recording_uint(&track, 0x83U, 1U) != 0 ||
        recording_child(&track, 0x86U, &codec_id) != 0 ||
        recording_child(&track, 0xe0U, &dimensions) != 0 ||
        recording_uint(&dimensions, 0xb0U, 640U) != 0 ||
        recording_uint(&dimensions, 0xbaU, 480U) != 0 ||
        codec_id.size != 5U || (memcmp(codec_id.data, "V_VP8", 5U) != 0 &&
                               memcmp(codec_id.data, "V_VP9", 5U) != 0)) goto out;
    int vp9 = codec_id.data[4] == '9';
    video->codec = vp9 ? "vp9" : "vp8";
    vpx_codec_iface_t *interface = vp9 ? vpx_codec_vp9_dx() : vpx_codec_vp8_dx();
    vpx_codec_dec_cfg_t config = {.threads = 1U, .w = 640U, .h = 480U};
    if (vpx_codec_dec_init(&decoder, interface, &config, 0) != VPX_CODEC_OK) goto out;
    initialized = 1;
    size_t offset = 0U;
    unsigned int clusters = 0U;
    while (offset < segment.size) {
        RecordingElement cluster = {0}, timestamp = {0};
        if (recording_next(&segment, &offset, &cluster) != 0) goto out;
        if (cluster.id != 0x1f43b675U) continue;
        if (++clusters > 32U || recording_child(&cluster, 0xe7U, &timestamp) != 0 ||
            timestamp.size == 0U || timestamp.size > 8U) goto out;
        uint64_t ticks = 0U;
        for (size_t i = 0U; i < timestamp.size; ++i) ticks = (ticks << 8U) | timestamp.data[i];
        if (ticks > 15000U) goto out;
        size_t position = 0U;
        while (position < cluster.size) {
            RecordingElement block = {0};
            if (recording_next(&cluster, &position, &block) != 0 || block.id == 0xa0U) goto out;
            if (block.id != 0xa3U) continue;
            size_t payload = 0U;
            uint64_t track_number = 0U;
            if (++video->packets > 512U ||
                recording_vint(block.data, block.size, &payload, 0, &track_number) != 0 ||
                track_number != 1U || block.size - payload <= 3U) goto out;
            int relative = (int)block.data[payload] * 256 + block.data[payload + 1U];
            if (relative >= 32768) relative -= 65536;
            unsigned int flags = block.data[payload + 2U];
            payload += 3U;
            int64_t pts = (int64_t)ticks + relative;
            if ((flags & 0x06U) != 0U || pts < 0 || pts > 15000 ||
                (video->packets == 1U && (pts != 0 || (flags & 0x80U) == 0U)) ||
                (video->packets > 1U && (uint64_t)pts < video->last_pts_ms) ||
                block.size - payload > 1024U * 1024U) goto out;
            if (video->packets == 1U) {
                vpx_codec_stream_info_t stream = {.sz = sizeof(stream)};
                if (vpx_codec_peek_stream_info(interface, block.data + payload,
                         (unsigned int)(block.size - payload), &stream) != VPX_CODEC_OK ||
                    !stream.is_kf || stream.w != 640U || stream.h != 480U) goto out;
            }
            if (vpx_codec_decode(&decoder, block.data + payload,
                    (unsigned int)(block.size - payload), NULL, 0) != VPX_CODEC_OK) goto out;
            int corrupted = 0;
            if (vpx_codec_control(&decoder, VP8D_GET_FRAME_CORRUPTED, &corrupted) != VPX_CODEC_OK ||
                corrupted != 0) goto out;
            vpx_codec_iter_t iterator = NULL;
            vpx_image_t *frame;
            while ((frame = vpx_codec_get_frame(&decoder, &iterator)) != NULL) {
                uint8_t pixels[X11_FRAME_BYTES];
                if (++video->images > 512U || frame->d_w != 640U || frame->d_h != 480U ||
                    (frame->fmt & VPX_IMG_FMT_HIGHBITDEPTH) != 0 ||
                    frame->planes[VPX_PLANE_Y] == NULL || frame->stride[VPX_PLANE_Y] < 640)
                    goto out;
                for (unsigned int y = 0U; y < X11_FRAME_HEIGHT; ++y)
                    for (unsigned int x = 0U; x < X11_FRAME_WIDTH; ++x) {
                        uint8_t luma = frame->planes[VPX_PLANE_Y][
                            (y * 480U / X11_FRAME_HEIGHT) * frame->stride[VPX_PLANE_Y] +
                            x * 640U / X11_FRAME_WIDTH];
                        memset(pixels + (y * X11_FRAME_WIDTH + x) * 3U, luma, 3U);
                    }
                int64_t identity = x11_frame_decode(pixels);
                if (identity < 0 || (uint64_t)identity >= history->count ||
                    identity < video->last_frame ||
                    history->publication_us[identity] + 1000000U < started_us ||
                    history->publication_us[identity] > stopped_us + 1000000U) goto out;
                if (video->first_frame < 0) video->first_frame = identity;
                uint64_t interval = history->publication_us[identity] -
                                    history->publication_us[video->first_frame];
                uint64_t media_us = (uint64_t)pts * 1000U;
                if (interval > media_us + 500000U || media_us > interval + 500000U) goto out;
                video->last_frame = identity;
            }
            video->last_pts_ms = (uint64_t)pts;
        }
    }
    if (video->images < 16U || video->last_frame - video->first_frame < 12 ||
        video->last_pts_ms < 3000U || video->last_pts_ms > 10000U) goto out;
    result = 0;
out:
    if (initialized && vpx_codec_destroy(&decoder) != VPX_CODEC_OK) result = -1;
    return result;
}

static int recording_control_visible(unsigned int pid, const char *name) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline) {
        AtspiAccessible *control = NULL;
        int status = query_named_accessible(pid, name, deadline, &control, 0);
        int found = control != NULL;
        g_clear_object(&control);
        if (status != 0) return -1;
        if (found) return 0;
        if (sleep_millis(100U) != 0) return -1;
    }
    return -1;
}

static int recording_failure(Display *display, const ViewerWindow *viewer, SourceHistory *history) {
    int directory = -1, changed = 0, result = -1;
    unsigned int pid = (unsigned int)viewer->pid, files = 0U;
    AtspiAccessible *error = NULL, *title = NULL, *active = NULL, *idle = NULL;
    struct stat original = {0}, current = {0};
    uint64_t fresh = 0U, age = 0U;
    const char *phase = "refuse-write";
    directory = open("/tmp/recording-selected-שלום", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fstat(directory, &original) != 0 ||
        original.st_uid != geteuid() || (original.st_mode & 07777U) != 0700U ||
        fchmod(directory, 0500) != 0) goto out;
    changed = 1;
    errno = 0;
    int probe = openat(directory, ".recording-probe", O_WRONLY | O_CREAT | O_EXCL |
                       O_NOFOLLOW | O_CLOEXEC, 0600);
    int denied = errno;
    if (probe >= 0) {
        if (close(probe) != 0 || unlinkat(directory, ".recording-probe", 0) != 0) goto out;
        goto out;
    }
    if (denied != EACCES || quality_toolbar(pid) != 0 ||
        click_main_control(display, viewer->window, pid, "Start session recording") != 0) goto out;
    phase = "failure-feedback";
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline && error == NULL) {
        if (query_accessible(pid, "Failed: Permission denied (os error 13)",
                             deadline, &error, 1, 1, NULL) != 0)
            goto out;
        if (error == NULL && sleep_millis(100U) != 0) goto out;
    }
    int error_visible = error != NULL;
    g_clear_object(&error);
    if (error_visible) {
        deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
        if (query_named_accessible(pid, "Recording", deadline, &title, 1) != 0 ||
            title == NULL || click_main_control(display, viewer->window, pid, "OK") != 0)
            goto out;
        do {
            g_clear_object(&title);
            if (query_named_accessible(pid, "Recording", deadline, &title, 1) != 0)
                goto out;
            if (title != NULL && sleep_millis(50U) != 0) goto out;
        } while (title != NULL && monotonic_millis() < deadline);
        if (title != NULL) goto out;
    }
    deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    if (query_named_accessible(pid, "Stop session recording", deadline, &active, 0) != 0 ||
        query_named_accessible(pid, "Start session recording", deadline, &idle, 0) != 0)
        goto out;
    int still_active = active != NULL, can_retry = idle != NULL;
    DIR *entries = fdopendir(dup(directory));
    if (entries == NULL) goto out;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(entries)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) ++files;
    int read_error = errno;
    if (closedir(entries) != 0 || read_error != 0) goto out;
    phase = "session";
    if (activate_named_control(pid, "Hide toolbar") != 0 ||
        wait_for_current_frames(display, viewer, history, RECOVERY_LIMIT_MS, 4U, &fresh, &age) != 0 ||
        fstat(directory, &current) != 0 || original.st_dev != current.st_dev ||
        original.st_ino != current.st_ino || (current.st_mode & 07777U) != 0500U) goto out;
    printf("FLUTTER_PEER_RECORDING_DENIED kernel=EACCES error_visible=%d active=%d "
           "retry_available=%d files=%u fresh_pixels=4 maximum_age_ms=%llu\n",
           error_visible, still_active, can_retry, files, (unsigned long long)age);
    fflush(stdout);
    if (!error_visible || still_active || !can_retry || files != 0U) goto out;
    result = 0;
out:
    if (changed && fchmod(directory, 0700) != 0) result = -1;
    if (directory >= 0 && close(directory) != 0) result = -1;
    g_clear_object(&error);
    g_clear_object(&title);
    g_clear_object(&active);
    g_clear_object(&idle);
    if (result != 0) fprintf(stderr, "FLUTTER_PEER_RECORDING_FAILURE_CHECK_FAIL phase=%s\n", phase);
    return result;
}


static int recording_output(Display *display, const ViewerWindow *viewer, SourceHistory *history) {
    static const char selected[] = "/tmp/recording-selected-שלום";
    DIR *directory = NULL;
    int file = -1, receipt = -1, result = -1;
    unsigned char *data = NULL;
    gchar *digest = NULL;
    const char *phase = "start";
    char filename[256] = {0};
    struct stat before = {0}, after = {0};
    unsigned int pid = (unsigned int)viewer->pid;
    uint64_t started_us = x11_frame_monotonic_us(), stopped_us = 0U, fresh = 0U, age = 0U;
    if (quality_toolbar(pid) != 0 ||
        click_main_control(display, viewer->window, pid, "Start session recording") != 0 ||
        recording_control_visible(pid, "Stop session recording") != 0 ||
        activate_named_control(pid, "Hide toolbar") != 0) goto out;
    phase = "record";
    if (wait_for_current_frames(display, viewer, history, 8000U, 20U, &fresh, &age) != 0)
        goto out;
    phase = "stop";
    stopped_us = x11_frame_monotonic_us();
    if (quality_toolbar(pid) != 0 ||
        click_main_control(display, viewer->window, pid, "Stop session recording") != 0 ||
        recording_control_visible(pid, "Start session recording") != 0 ||
        activate_named_control(pid, "Hide toolbar") != 0 ||
        wait_for_current_frames(display, viewer, history, RECOVERY_LIMIT_MS, 4U, &fresh, &age) != 0)
        goto out;
    phase = "file";
    directory = opendir(selected);
    if (directory == NULL) goto out;
    struct dirent *entry;
    phase = "file-name";
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        size_t length = strlen(entry->d_name);
        if (length < 20U || length >= sizeof(filename) ||
            strncmp(entry->d_name, "outgoing_", 9U) != 0 ||
            strcmp(entry->d_name + length - 5U, ".webm") != 0 ||
            strspn(entry->d_name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
                != length) goto out;
        if (filename[0] != '\0') {
            phase = "multiple-files";
            fprintf(stderr, "FLUTTER_PEER_RECORDING_FILES first=%s second=%s\n",
                    filename, entry->d_name);
            goto out;
        }
        memcpy(filename, entry->d_name, length + 1U);
    }
    phase = "directory-read";
    if (errno != 0) goto out;
    phase = "file-open";
    file = openat(dirfd(directory), filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (file < 0) goto out;
    phase = "file-metadata";
    if (fstat(file, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_gid != getegid() || before.st_nlink != 1U ||
        (before.st_mode & 07777U) != 0600U || before.st_size <= 0 ||
        before.st_size > 1024 * 1024) goto out;
    phase = "file-read";
    data = malloc((size_t)before.st_size);
    if (data == NULL) goto out;
    size_t offset = 0U;
    while (offset < (size_t)before.st_size) {
        ssize_t count = read(file, data + offset, (size_t)before.st_size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto out;
        offset += (size_t)count;
    }
    phase = "decode";
    RecordingVideo video, rejected;
    if (x11_frame_refresh(history, "/coord") != 0) goto out;
    if (recording_decode(data, offset, history, started_us, stopped_us, &video) != 0) {
        fprintf(stderr, "FLUTTER_PEER_RECORDING_DECODE_FAIL packets=%u images=%u "
                "first=%lld last=%lld pts_ms=%llu\n", video.packets, video.images,
                (long long)video.first_frame, (long long)video.last_frame,
                (unsigned long long)video.last_pts_ms);
        goto out;
    }
    if (recording_decode(data, offset - 1U, history, started_us, stopped_us, &rejected) == 0)
        goto out;
    phase = "unchanged";
    if (fstat(file, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) goto out;
    digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, data, offset);
    if (digest == NULL) goto out;
    receipt = open("/coord/recording-output.json", O_WRONLY | O_CREAT | O_EXCL |
                   O_NOFOLLOW | O_CLOEXEC, 0600);
    if (receipt < 0 || dprintf(receipt,
        "{\"name\":\"%s\",\"bytes\":%zu,\"sha256\":\"%s\",\"device\":%llu,\"inode\":%llu}\n",
        filename, offset, digest, (unsigned long long)before.st_dev,
        (unsigned long long)before.st_ino) <= 0) goto out;
    printf("FLUTTER_PEER_RECORDING_OUTPUT_OK codec=%s packets=%u decoded_frames=%u "
           "first_frame=%lld last_frame=%lld duration_ms=%llu bytes=%zu sha256=%s "
           "path=selected mode=0600 stopped=ui viewer=alive truncated=refused\n",
           video.codec, video.packets, video.images, (long long)video.first_frame,
           (long long)video.last_frame, (unsigned long long)video.last_pts_ms, offset, digest);
    result = 0;
out:
    if (file >= 0 && close(file) != 0) result = -1;
    if (receipt >= 0 && close(receipt) != 0) result = -1;
    if (directory != NULL && closedir(directory) != 0) result = -1;
    if (result != 0)
        fprintf(stderr, "FLUTTER_PEER_RECORDING_OUTPUT_FAIL phase=%s bytes=%lld\n",
                phase, (long long)before.st_size);
    g_free(digest);
    free(data);
    return result;
}

#endif

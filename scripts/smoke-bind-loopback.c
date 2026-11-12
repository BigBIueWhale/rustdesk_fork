#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);

static bind_fn real_bind(void) {
    static bind_fn fn;
    if (fn == NULL) {
        fn = (bind_fn)dlsym(RTLD_NEXT, "bind");
    }
    return fn;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    bind_fn fn = real_bind();
    if (fn == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (addr != NULL && addr->sa_family == AF_INET &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
        struct sockaddr_in rewritten;
        memcpy(&rewritten, addr, sizeof(rewritten));
        if (rewritten.sin_addr.s_addr == htonl(INADDR_ANY) &&
            ntohs(rewritten.sin_port) == 21118) {
            rewritten.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            return fn(sockfd, (const struct sockaddr *)&rewritten, sizeof(rewritten));
        }
    }

    return fn(sockfd, addr, addrlen);
}

#ifdef SMOKE_RECORDING_STALL
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef ssize_t (*write_fn)(int, const void *, size_t);
static atomic_int recording_claimed;
static atomic_int recording_finish_claimed;

static int recording_marker(int coord, const char *name, int publish, write_fn next) {
    char temporary[64], data[7];
    struct stat metadata;
    int fd, result = -1;
    if (publish) {
        int length = snprintf(temporary, sizeof(temporary), "%s.tmp", name);
        if (length <= 0 || (size_t)length >= sizeof(temporary)) return -1;
        fd = openat(coord, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        if (next(fd, "ready\n", 6U) == 6) result = 0;
        if (close(fd) != 0) result = -1;
        if (result == 0 && syscall(SYS_renameat2, coord, temporary, coord, name, 1U) != 0)
            result = -1;
        return result;
    }
    fd = openat(coord, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        metadata.st_uid == geteuid() && metadata.st_gid == getegid() &&
        metadata.st_nlink == 1 && (metadata.st_mode & 07777) == 0600 && metadata.st_size == 6 &&
        read(fd, data, sizeof(data)) == 6 && memcmp(data, "ready\n", 6U) == 0) result = 1;
    if (close(fd) != 0) result = -1;
    return result;
}

static uint64_t recording_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static int recording_header_vint(const unsigned char *data, size_t limit, size_t *at,
                                 int identifier, uint64_t *value) {
    if (*at >= limit || data[*at] == 0U) return -1;
    unsigned int length = 1U, marker = 128U;
    while ((data[*at] & marker) == 0U) { ++length; marker >>= 1U; }
    if (length > (identifier ? 4U : 8U) || length > limit - *at) return -1;
    *value = data[(*at)++];
    if (!identifier) *value &= marker - 1U;
    for (unsigned int i = 1U; i < length; ++i) *value = (*value << 8U) | data[(*at)++];
    return 0;
}

/* The pinned muxer reserves a float32 Duration=1 in Segment/Info. Only
 * SegmentInfo::Finalize rewrites it. Cluster backpatches and initial header
 * construction must not trigger this fault. Parse the existing bounded header
 * instead of guessing an offset or treating every backwards write as finish. */
static int recording_duration_rewrite(int fd, const char *path, const struct stat *before,
                                      off_t *position) {
    *position = lseek(fd, 0, SEEK_CUR);
    if (*position < 0) return -1;
    if (*position >= 512 || before->st_size < 1024 || before->st_size > 1024 * 1024)
        return 0;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_APPEND) != 0) return -1;
    unsigned char data[512];
    struct stat metadata;
    int reader = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (reader < 0) return -1;
    int valid = fstat(reader, &metadata) == 0 && metadata.st_dev == before->st_dev &&
        metadata.st_ino == before->st_ino && pread(reader, data, sizeof(data), 0) == (ssize_t)sizeof(data);
    if (close(reader) != 0 || !valid) return -1;
    size_t at = 0U;
    uint64_t id, size;
    if (recording_header_vint(data, sizeof(data), &at, 1, &id) != 0 || id != 0x1a45dfa3U ||
        recording_header_vint(data, sizeof(data), &at, 0, &size) != 0 || size > sizeof(data) - at)
        return -1;
    at += (size_t)size;
    if (recording_header_vint(data, sizeof(data), &at, 1, &id) != 0 || id != 0x18538067U ||
        recording_header_vint(data, sizeof(data), &at, 0, &size) != 0 ||
        size != UINT64_C(0x00ffffffffffffff)) return -1;
    for (unsigned int i = 0U; i < 16U; ++i) {
        if (recording_header_vint(data, sizeof(data), &at, 1, &id) != 0 ||
            recording_header_vint(data, sizeof(data), &at, 0, &size) != 0 ||
            size > sizeof(data) - at) return -1;
        if (id == 0x1549a966U) {
            size_t end = at + (size_t)size;
            unsigned int matches = 0U;
            int selected = 0;
            for (unsigned int j = 0U; at < end && j < 16U; ++j) {
                size_t start = at;
                if (recording_header_vint(data, end, &at, 1, &id) != 0 ||
                    recording_header_vint(data, end, &at, 0, &size) != 0 || size > end - at)
                    return -1;
                if (id == 0x4489U) {
                    if (++matches != 1U || size != 4U || memcmp(data + at, "\x3f\x80\0\0", 4U) != 0)
                        return -1;
                    selected = *position == (off_t)start;
                }
                at += (size_t)size;
            }
            return at == end && matches == 1U ? selected : -1;
        }
        if (id != 0xecU && id != 0x114d9b74U) return -1;
        at += (size_t)size;
    }
    return -1;
}

static ssize_t recording_finish_fault(int fd, int coord, const struct stat *before,
                                      off_t position, write_fn next) {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&recording_finish_claimed, &expected, 1)) {
        close(coord);
        errno = EIO;
        return -1;
    }
    uint64_t started = recording_millis(), now = started;
    int released = 0;
    if (started == 0 || recording_marker(coord, "incoming.finish.held", 1, next) != 0) goto out;
    while (now >= started && now - started < 30000U) {
        released = recording_marker(coord, "incoming.finish.release", 0, next);
        if (released < 0) goto out;
        if (released == 1) break;
        struct timespec interval = {.tv_sec = 0, .tv_nsec = 10000000L};
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) goto out;
        now = recording_millis();
    }
    struct stat after;
    if (released != 1 || now < started || now - started >= 30000U ||
        fstat(fd, &after) != 0 || before->st_dev != after.st_dev || before->st_ino != after.st_ino ||
        before->st_size != after.st_size || before->st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before->st_mtim.tv_nsec != after.st_mtim.tv_nsec || lseek(fd, 0, SEEK_CUR) != position)
        goto out;
    char observation[256];
    int length = snprintf(observation, sizeof(observation),
        "FLUTTER_PEER_INCOMING_FINISH_FAULT offset=%lld file_bytes=%lld held_ms=%llu "
        "header=duration file_unchanged=true result=-1 errno=EIO\n",
        (long long)position, (long long)before->st_size, (unsigned long long)(now - started));
    if (length <= 0 || (size_t)length >= sizeof(observation) ||
        next(STDERR_FILENO, observation, (size_t)length) != length) goto out;
    if (recording_marker(coord, "incoming.finish.failed", 1, next) != 0) goto out;
out:
    close(coord);
    errno = EIO;
    return -1;
}

/* Only the incoming-recording fixture compiles this interposer. Separate arms
 * select one payload hold/release and one later Duration rewrite hold/EIO.
 * Both use the exact private output directory without another thread/process;
 * expiry or missing observations fail the fixture transaction. */
ssize_t write(int fd, const void *data, size_t size) {
    write_fn next = (write_fn)dlsym(RTLD_NEXT, "write");
    if (next == NULL) { errno = ENOSYS; return -1; }
    int payload = size >= 128U && !atomic_load(&recording_claimed);
    int finishing = size == 1U && data != NULL && *(const unsigned char *)data == 0x44U &&
        !atomic_load(&recording_finish_claimed);
    if (!payload && !finishing) return next(fd, data, size);
    char descriptor[64], path[512];
    int length = snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    if (length <= 0 || (size_t)length >= sizeof(descriptor)) return next(fd, data, size);
    ssize_t count = readlink(descriptor, path, sizeof(path) - 1U);
    if (count <= 0 || (size_t)count >= sizeof(path) - 1U) return next(fd, data, size);
    path[count] = '\0';
    const char prefix[] = "/tmp/recording-selected-שלום/incoming_";
    if ((size_t)count < sizeof(prefix) + 5U || strncmp(path, prefix, sizeof(prefix) - 1U) != 0 ||
        strchr(path + sizeof(prefix) - 1U, '/') != NULL || strcmp(path + count - 5, ".webm") != 0)
        return next(fd, data, size);

    int coord = open("/coord", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat before, after, directory;
    int result = -1, expected = 0;
    if (coord < 0 || fstat(coord, &directory) != 0 || directory.st_uid != geteuid() ||
        directory.st_gid != getegid() || (directory.st_mode & 07777) != 0700 ||
        fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        before.st_uid != geteuid() || before.st_gid != getegid() ||
        (before.st_mode & 07777) != 0600) goto out;
    if (finishing) {
        result = recording_marker(coord, "incoming.finish.arm", 0, next);
        off_t position = 0;
        if (result == 1) result = recording_duration_rewrite(fd, path, &before, &position);
        if (result == 0) { close(coord); return next(fd, data, size); }
        if (result != 1) goto out;
        return recording_finish_fault(fd, coord, &before, position, next);
    }
    result = recording_marker(coord, "incoming.write.arm", 0, next);
    if (result == 0) { close(coord); return next(fd, data, size); }
    if (result != 1) goto out;
    if (!atomic_compare_exchange_strong(&recording_claimed, &expected, 1)) {
        close(coord);
        return next(fd, data, size);
    }
    result = -1;
    uint64_t started = recording_millis(), now = started;
    if (started == 0 || recording_marker(coord, "incoming.write.held", 1, next) != 0) goto out;
    while (now >= started && now - started < 30000U) {
        int released = recording_marker(coord, "incoming.write.release", 0, next);
        if (released < 0) goto out;
        if (released == 1) { result = 0; break; }
        struct timespec interval = {.tv_sec = 0, .tv_nsec = 10000000L};
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) goto out;
        now = recording_millis();
    }
    if (result != 0 || fstat(fd, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) { result = -1; goto out; }
    ssize_t written = next(fd, data, size);
    int saved_errno = errno;
    char observation[256];
    length = snprintf(observation, sizeof(observation),
        "FLUTTER_PEER_INCOMING_WRITE_RELEASED bytes=%zu held_ms=%llu file_unchanged=true result=%zd\n",
        size, (unsigned long long)(now - started), written);
    if (written == (ssize_t)size)
        result = recording_marker(coord, "incoming.write.released", 1, next);
    else result = -1;
    if (close(coord) != 0) result = -1;
    /* Both this receipt and the marker are required. A failed observation
     * cannot fabricate successful I/O or a complete fixture transaction. */
    if (result == 0 && length > 0 && (size_t)length < sizeof(observation)) {
        if (next(STDERR_FILENO, observation, (size_t)length) != length) {
            errno = EIO;
            return -1;
        }
    }
    errno = saved_errno;
    return written;
out:
    if (coord >= 0) close(coord);
    errno = EIO;
    return -1;
}
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Disposable-guest diagnostic. No allocation or loader functions are interposed. */
static int output = -1, stop_fd = -1, active;
static pid_t owner;
static pthread_t worker;
static size_t written;
static char snapshot[262144];

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static int record(const char *data, size_t length) {
    if (length > 67108864U - written) return -1;
    while (length != 0) {
        ssize_t count = write(output, data, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        written += (size_t)count;
        data += count;
        length -= (size_t)count;
    }
    return 0;
}

static int sample(FILE *stream, unsigned int sequence) {
    char header[256];
    if (fseek(stream, 0, SEEK_SET) != 0) return -1;
    clearerr(stream);
    uint64_t began = now_ns();
    if (began == 0 || malloc_info(0, stream) != 0 || fflush(stream) != 0 || ferror(stream)) return -1;
    uint64_t ended = now_ns();
    long length = ftell(stream);
    if (ended < began || length <= 0 || (size_t)length >= sizeof(snapshot)) return -1;
    int count = snprintf(header, sizeof(header),
        "ALLOCATOR_BEGIN pid=%ld sequence=%u begin_ns=%" PRIu64 " end_ns=%" PRIu64 " bytes=%ld\n",
        (long)owner, sequence, began, ended, length);
    if (count <= 0 || (size_t)count >= sizeof(header) || record(header, (size_t)count) != 0 ||
        record(snapshot, (size_t)length) != 0 || record("ALLOCATOR_END\n", 14) != 0) return -1;
    return 0;
}

static void *observe(void *unused) {
    (void)unused;
    FILE *stream = fmemopen(snapshot, sizeof(snapshot), "w+");
    unsigned int samples = 0;
    int failed = stream == NULL;
    while (!failed && samples < 1000U) {
        if (sample(stream, samples) != 0) { failed = 1; break; }
        ++samples;
        struct pollfd request = {.fd = stop_fd, .events = POLLIN};
        int result;
        do { result = poll(&request, 1, 1000); } while (result < 0 && errno == EINTR);
        if (result < 0 || (result > 0 && request.revents != POLLIN)) { failed = 1; break; }
        if (result > 0) break;
    }
    if (samples == 1000U) failed = 1;
    if (stream != NULL && fclose(stream) != 0) failed = 1;
    char trailer[128];
    int length = snprintf(trailer, sizeof(trailer), "ALLOCATOR_COMPLETE pid=%ld samples=%u failed=%d\n",
                          (long)owner, samples, failed);
    if (length <= 0 || (size_t)length >= sizeof(trailer) || record(trailer, (size_t)length) != 0 || failed)
        fputs("allocator diagnostic collection failed\n", stderr);
    return NULL;
}

__attribute__((constructor)) static void start(void) {
    const char *value = getenv("RUSTDESK_ALLOCATOR_FD");
    char *end = NULL;
    struct stat info;
    errno = 0;
    long fd = value == NULL ? -1 : strtol(value, &end, 10);
    if (value == NULL || end == value || *end != '\0' || errno || fd < 3 || fd > INT_MAX ||
        getuid() != 4001 || geteuid() != 4001 || getgid() != 4001 || getegid() != 4001 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || fstat((int)fd, &info) != 0 ||
        !S_ISREG(info.st_mode) || info.st_uid != 4001 || info.st_gid != 4001 ||
        (info.st_mode & 07777) != 0600 || info.st_nlink != 1 || info.st_size != 0 ||
        fcntl((int)fd, F_SETFD, FD_CLOEXEC) != 0 ||
        unsetenv("LD_PRELOAD") != 0 || unsetenv("RUSTDESK_ALLOCATOR_FD") != 0) {
        fputs("allocator diagnostic launch refused\n", stderr);
        return;
    }
    output = (int)fd;
    owner = getpid();
    stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (stop_fd < 0 || pthread_create(&worker, NULL, observe, NULL) != 0) {
        fputs("allocator diagnostic thread failed\n", stderr);
        if (stop_fd >= 0 && close(stop_fd) != 0) perror("allocator stop close");
        if (close(output) != 0) perror("allocator output close");
        return;
    }
    active = 1;
}

__attribute__((destructor)) static void finish(void) {
    if (!active || owner != getpid()) return;
    uint64_t stop = 1;
    ssize_t result;
    do { result = write(stop_fd, &stop, sizeof(stop)); } while (result < 0 && errno == EINTR);
    if (result != (ssize_t)sizeof(stop) || pthread_join(worker, NULL) != 0) {
        fputs("allocator diagnostic join failed\n", stderr);
        return;
    }
    if (close(stop_fd) != 0) perror("allocator stop close");
    if (close(output) != 0) perror("allocator output close");
}

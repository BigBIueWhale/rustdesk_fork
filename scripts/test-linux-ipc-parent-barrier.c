#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test-only scheduling around the real openat; no syscall outcome is replaced. */
static void barrier(void) {
    const char *ready_text = getenv("IPC_PARENT_READY_FD");
    const char *release_text = getenv("IPC_PARENT_RELEASE_FD");
    if (!ready_text || !release_text) _exit(91);
    int ready = atoi(ready_text), release = atoi(release_text);
    char byte = 'R';
    if (ready < 3 || release < 3 || write(ready, &byte, 1) != 1) _exit(92);
    if (read(release, &byte, 1) != 1 || byte != 'G') _exit(93);
    if (close(ready) != 0 || close(release) != 0) _exit(94);
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int used = 0;
    dlerror();
    int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    if (dlerror() || !real_openat) _exit(95);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    const char *name = getenv("IPC_PARENT_BARRIER_NAME");
    const char *phase = getenv("IPC_PARENT_BARRIER_PHASE");
    int selected = !used && name && phase && strcmp(path, name) == 0;
    if (selected) {
        if (getuid() != 0 || (flags & (O_DIRECTORY | O_NOFOLLOW)) != (O_DIRECTORY | O_NOFOLLOW)) _exit(96);
        used = 1;
        if (strcmp(phase, "before-open") == 0) barrier();
        else if (strcmp(phase, "after-open") != 0) _exit(97);
    }
    int fd = real_openat(dirfd, path, flags, mode);
    int saved_errno = errno;
    if (selected && strcmp(phase, "after-open") == 0) {
        if (fd < 0) _exit(98);
        barrier();
    }
    errno = saved_errno;
    return fd;
}

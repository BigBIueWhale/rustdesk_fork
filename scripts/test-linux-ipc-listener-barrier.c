#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// VM-only scheduling seam. No syscall result or filesystem contents are changed.
int unlinkat(int dirfd, const char *path, int flags) {
    static int used;
    int (*real_unlinkat)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    if (!real_unlinkat) _exit(90);
    const char *entry = getenv("IPC_BARRIER_ENTRY");
    if (!used && entry && !strcmp(path, entry)) {
        used = 1;
        const char *entered = getenv("IPC_BARRIER_ENTER");
        const char *released = getenv("IPC_BARRIER_RELEASE");
        if (!entered || !released) _exit(91);
        int out = atoi(entered), in = atoi(released);
        if (out < 3 || in < 3 || write(out, "R", 1) != 1) _exit(92);
        struct pollfd wait = {.fd = in, .events = POLLIN};
        int ready;
        do { ready = poll(&wait, 1, 10000); } while (ready < 0 && errno == EINTR);
        char signal;
        if (ready != 1 || read(in, &signal, 1) != 1 || signal != 'G') _exit(93);
        close(out);
        close(in);
    }
    return real_unlinkat(dirfd, path, flags);
}

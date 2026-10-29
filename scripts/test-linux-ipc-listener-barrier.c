#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

// VM-only scheduling seam. No syscall result or filesystem contents are changed.
static void wait_at_barrier(void) {
    static int used;
    if (used) return;
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

int unlinkat(int dirfd, const char *path, int flags) {
    int (*real_unlinkat)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    if (!real_unlinkat) _exit(90);
    const char *entry = getenv("IPC_BARRIER_ENTRY");
    const char *call = getenv("IPC_BARRIER_CALL");
    if ((!call || !strcmp(call, "unlink")) && entry && !strcmp(path, entry))
        wait_at_barrier();
    return real_unlinkat(dirfd, path, flags);
}

int flock(int fd, int operation) {
    int (*real_flock)(int, int) = dlsym(RTLD_NEXT, "flock");
    if (!real_flock) _exit(90);
    const char *call = getenv("IPC_BARRIER_CALL");
    if (call && !strcmp(call, "flock") && operation == (LOCK_EX | LOCK_NB))
        wait_at_barrier();
    return real_flock(fd, operation);
}

static void socket_barrier(int fd, const char *operation) {
    const char *call = getenv("IPC_BARRIER_CALL");
    const char *path = getenv("IPC_BARRIER_PATH");
    if (!call || strcmp(call, operation) || !path) return;
    struct sockaddr_un address = {0};
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0
        || length > sizeof(address) || address.sun_family != AF_UNIX
        || !memchr(address.sun_path, 0, sizeof(address.sun_path))) _exit(94);
    if (!strcmp(address.sun_path, path)) wait_at_barrier();
}

int bind(int fd, const struct sockaddr *address, socklen_t length) {
    int (*real_bind)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
    if (!real_bind) _exit(90);
    int result = real_bind(fd, address, length), saved_errno = errno;
    if (result == 0) socket_barrier(fd, "bind");
    errno = saved_errno;
    return result;
}

int listen(int fd, int backlog) {
    int (*real_listen)(int, int) = dlsym(RTLD_NEXT, "listen");
    if (!real_listen) _exit(90);
    int result = real_listen(fd, backlog), saved_errno = errno;
    if (result == 0) socket_barrier(fd, "listen");
    errno = saved_errno;
    return result;
}

int chmod(const char *path, mode_t mode) {
    int (*real_chmod)(const char *, mode_t) = dlsym(RTLD_NEXT, "chmod");
    if (!real_chmod) _exit(90);
    const char *call = getenv("IPC_BARRIER_CALL");
    const char *target = getenv("IPC_BARRIER_PATH");
    if (call && !strcmp(call, "socket-mode-before") && target && !strcmp(target, path))
        wait_at_barrier();
    int result = real_chmod(path, mode), saved_errno = errno;
    if (result == 0 && call && !strcmp(call, "chmod") && target && !strcmp(target, path))
        wait_at_barrier();
    errno = saved_errno;
    return result;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    int (*real_fchmodat)(int, const char *, mode_t, int) = dlsym(RTLD_NEXT, "fchmodat");
    if (!real_fchmodat) _exit(90);
    const char *call = getenv("IPC_BARRIER_CALL");
    const char *target = getenv("IPC_BARRIER_PATH");
    struct stat actual, named;
    int matches = call && target && fstatat(dirfd, path, &actual, flags) == 0
        && lstat(target, &named) == 0 && S_ISSOCK(actual.st_mode)
        && actual.st_dev == named.st_dev && actual.st_ino == named.st_ino;
    if (matches && !strcmp(call, "socket-mode-before")) wait_at_barrier();
    int result = real_fchmodat(dirfd, path, mode, flags), saved_errno = errno;
    if (result == 0 && matches && !strcmp(call, "chmod")) wait_at_barrier();
    errno = saved_errno;
    return result;
}

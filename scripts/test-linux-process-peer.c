#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

_Static_assert(SYS_pidfd_open == 434, "fixture requires the Linux x86_64 pidfd ABI");
_Static_assert(sizeof(struct pollfd) == 8 && offsetof(struct pollfd, events) == 4 &&
               offsetof(struct pollfd, revents) == 6 && POLLIN == 1, "poll ABI differs");

struct settings { char path[108]; int dumpable; char *mutable_argument; char *mutable_environment; };

static void *serve(void *argument) {
    const struct settings *settings = argument;
    if (prctl(PR_SET_DUMPABLE, settings->dumpable) != 0 ||
        prctl(PR_GET_DUMPABLE) != settings->dumpable)
        _exit(2);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    size_t length = strlen(settings->path);
    if (fd < 0 || length >= sizeof(address.sun_path))
        _exit(3);
    memcpy(address.sun_path, settings->path, length + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        _exit(4);
    char command;
    for (;;) {
        if (read(STDIN_FILENO, &command, 1) != 1)
            _exit(5);
        if (command == 'x')
            break;
        char *mutable = command == 'm' ? settings->mutable_argument :
                        command == 'e' ? settings->mutable_environment : NULL;
        if (!mutable)
            _exit(5);
        unsigned char *argument = (unsigned char *)mutable;
        while (*argument && *argument != 0x80)
            argument++;
        if (*argument != 0x80)
            _exit(5);
        *argument = 0x81;
        if (write(fd, &command, 1) != 1)
            _exit(6);
    }
    if (close(fd) != 0)
        _exit(6);
    _exit(0);
}

int main(int argc, char **argv) {
    const char *argv_path = getenv("LINUX_IDENTITY_ARGV_SOCKET");
    if (!argv_path && (argc != 4 || (strcmp(argv[2], "0") && strcmp(argv[2], "1"))))
        return 7;
    static struct settings settings;
    const char *path = argv_path ? argv_path : argv[1];
    size_t length = strlen(path);
    if (length >= sizeof(settings.path))
        return 10;
    memcpy(settings.path, path, length + 1);
    settings.dumpable = argv_path ? 1 : argv[2][0] - '0';
    settings.mutable_argument = argv_path ? argv[0] : NULL;
    const char *environment_key = getenv("LINUX_IDENTITY_ENV_KEY");
    settings.mutable_environment = environment_key ? getenv(environment_key) : NULL;
    if (argv_path) {
        serve(&settings);
        return 0;
    }
    if (!strcmp(argv[3], "leader-exit")) {
        pthread_t worker;
        if (pthread_create(&worker, NULL, serve, &settings) != 0)
            return 8;
        pthread_exit(NULL);
    }
    if (strcmp(argv[3], "normal"))
        return 9;
    serve(&settings);
}

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

static const char *const SMOKE_ARGV0 = "rd-smoke-server";
static const char *const SERVER_ROLE = "--server";
static const char *const SERVICE_OWNED_ROLE = "--service-owned-server";

int main(int argc, char **argv) {
    int executable_fd;
    struct stat metadata;
    char *server_argv[] = {
        (char *)SMOKE_ARGV0,
        (char *)SERVER_ROLE,
        NULL,
        NULL,
    };

    if ((argc != 2 && argc != 3) || argv[1] == NULL || argv[1][0] != '/' ||
        (argc == 3 && (argv[2] == NULL || strcmp(argv[2], SERVICE_OWNED_ROLE) != 0))) {
        fprintf(stderr,
                "usage: smoke-server-launcher /absolute/server-executable "
                "[--service-owned-server]\n");
        return 2;
    }
    if (argc == 3) {
        server_argv[2] = (char *)SERVICE_OWNED_ROLE;
    }

    executable_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (executable_fd < 0) {
        fprintf(stderr, "smoke launcher: cannot open executable: %s\n", strerror(errno));
        return 1;
    }
    if (fstat(executable_fd, &metadata) != 0) {
        fprintf(stderr, "smoke launcher: cannot inspect executable: %s\n", strerror(errno));
        close(executable_fd);
        return 1;
    }
    if (!S_ISREG(metadata.st_mode) || (metadata.st_mode & 0111) == 0) {
        fprintf(stderr, "smoke launcher: target is not an executable regular file\n");
        close(executable_fd);
        return 1;
    }

    fexecve(executable_fd, server_argv, environ);
    fprintf(stderr, "smoke launcher: fexecve failed: %s\n", strerror(errno));
    close(executable_fd);
    return 1;
}

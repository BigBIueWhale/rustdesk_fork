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

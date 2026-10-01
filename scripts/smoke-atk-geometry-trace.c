/* Temporary, viewer-only diagnostic. Forward calls without changing their arguments,
 * dispatch, timeout or result; record no object labels, message bodies or memory. */
#define _GNU_SOURCE
#include <atk/atk.h>
#include <dbus/dbus.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef void (*Extents)(AtkComponent *, gint *, gint *, gint *, gint *, AtkCoordType);
typedef DBusMessage *(*Block)(DBusConnection *, DBusMessage *, int, DBusError *);
static Extents real_extents;
static Block real_block;
static pthread_once_t symbols_once = PTHREAD_ONCE_INIT;
static atomic_uint traces;
static _Thread_local unsigned depth;
static _Thread_local struct {
    const char *type;
    void *provider;
} components[16];

static void resolve_symbols(void) {
    dlerror();
    real_extents = (Extents)dlsym(RTLD_NEXT, "atk_component_get_extents");
    if (dlerror() != NULL || real_extents == NULL) _exit(125);
    real_block = (Block)dlsym(RTLD_NEXT, "dbus_connection_send_with_reply_and_block");
    if (dlerror() != NULL || real_block == NULL) _exit(125);
}

static const char *token(const char *value) {
    if (value == NULL || value[0] == '\0') return "unknown";
    size_t length = strnlen(value, 160);
    if (length == 160) return "unknown";
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || strchr("_.$+-:", c) != NULL))
            return "unknown";
    }
    return value;
}

static void location(unsigned trace, const char *kind, unsigned index, void *address) {
    Dl_info info = {0};
    if (address == NULL || dladdr(address, &info) == 0 || info.dli_fbase == NULL) {
        fprintf(stderr, "ATK_GEOMETRY_LOCATION trace=%u kind=%s index=%u module=unknown\n",
                trace, kind, index);
        return;
    }
    const char *module = info.dli_fname == NULL ? NULL : strrchr(info.dli_fname, '/');
    module = module == NULL ? info.dli_fname : module + 1;
    fprintf(stderr, "ATK_GEOMETRY_LOCATION trace=%u kind=%s index=%u module=%s offset=%" PRIxPTR
            " symbol=%s\n", trace, kind, index, token(module),
            (uintptr_t)address - (uintptr_t)info.dli_fbase, token(info.dli_sname));
}

static uint64_t monotonic_ns(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

void atk_component_get_extents(AtkComponent *component, gint *x, gint *y,
                               gint *width, gint *height, AtkCoordType coordinates) {
    int saved_errno = errno;
    if (pthread_once(&symbols_once, resolve_symbols) != 0) _exit(125);
    if (!ATK_IS_COMPONENT(component)) {
        errno = saved_errno;
        real_extents(component, x, y, width, height, coordinates);
        return;
    }
    if (depth == UINT_MAX) _exit(125);
    if (depth < 16) {
        components[depth].type = G_OBJECT_TYPE_NAME(component);
        components[depth].provider = (void *)ATK_COMPONENT_GET_IFACE(component)->get_extents;
    }
    ++depth;
    errno = saved_errno;
    real_extents(component, x, y, width, height, coordinates);
    --depth;
}

DBusMessage *dbus_connection_send_with_reply_and_block(DBusConnection *connection,
        DBusMessage *message, int timeout_ms, DBusError *error) {
    int saved_errno = errno;
    if (pthread_once(&symbols_once, resolve_symbols) != 0) _exit(125);
    unsigned trace = 0;
    if (connection != NULL && message != NULL &&
        dbus_message_is_method_call(message, "org.a11y.atspi.Component", "GetExtents")) {
        const char *own = dbus_bus_get_unique_name(connection);
        const char *destination = dbus_message_get_destination(message);
        if (own != NULL && destination != NULL && strcmp(own, destination) == 0) {
            unsigned count = atomic_load_explicit(&traces, memory_order_relaxed);
            while (count < 4) {
                if (atomic_compare_exchange_weak_explicit(&traces, &count, count + 1,
                        memory_order_relaxed, memory_order_relaxed)) {
                    trace = count + 1;
                    break;
                }
            }
        }
    }
    uint64_t started = 0;
    if (trace != 0) {
        started = monotonic_ns();
        void *frames[32];
        int count = backtrace(frames, 32);
        fprintf(stderr, "ATK_GEOMETRY_SELF_WAIT_BEGIN trace=%u pid=%ld tid=%ld timeout_ms=%d"
                " depth=%u chain_truncated=%u frames=%d monotonic_ns=%" PRIu64 "\n",
                trace, (long)getpid(), (long)syscall(SYS_gettid), timeout_ms,
                depth, (unsigned)(depth > 16), count, started);
        for (unsigned i = 0; i < depth && i < 16; ++i) {
            fprintf(stderr, "ATK_GEOMETRY_COMPONENT trace=%u index=%u type=%s\n",
                    trace, i, token(components[i].type));
            location(trace, "provider", i, components[i].provider);
        }
        for (int i = 0; i < count; ++i) location(trace, "frame", (unsigned)i, frames[i]);
        fflush(stderr);
    }
    errno = saved_errno;
    DBusMessage *reply = real_block(connection, message, timeout_ms, error);
    saved_errno = errno;
    if (trace != 0) {
        uint64_t ended = monotonic_ns();
        fprintf(stderr, "ATK_GEOMETRY_SELF_WAIT_END trace=%u reply=%u error_set=%u"
                " elapsed_ns=%" PRIu64 "\n", trace, (unsigned)(reply != NULL),
                (unsigned)(error != NULL && dbus_error_is_set(error)),
                ended >= started && started != 0 ? ended - started : 0);
        fflush(stderr);
    }
    errno = saved_errno;
    return reply;
}

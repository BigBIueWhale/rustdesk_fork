/* Guest-only, single-threaded allocation observation for the native XDO fixture. */
#define _GNU_SOURCE
#include <X11/XKBlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static XkbDescPtr (*next_get_map)(Display *, unsigned, unsigned);
static void *descriptors[128];
static unsigned allocations, retirements, live;
extern void __libc_free(void *);

__attribute__((constructor)) static void initialize(void) {
    next_get_map = (XkbDescPtr (*)(Display *, unsigned, unsigned))
        dlsym(RTLD_NEXT, "XkbGetMap");
    assert(next_get_map);
}

XkbDescPtr XkbGetMap(Display *display, unsigned which, unsigned device) {
    XkbDescPtr result = next_get_map(display, which, device);
    Dl_info caller;
    assert(dladdr(__builtin_return_address(0), &caller));
    assert(caller.dli_fname);
    const char *name = strrchr(caller.dli_fname, '/');
    name = name ? name + 1 : caller.dli_fname;
    if (result && !strcmp(name, "libxdo.so.3")) {
        unsigned slot = 128;
        for (unsigned i = 0; i < 128; i++) {
            assert(descriptors[i] != result);
            if (!descriptors[i] && slot == 128) slot = i;
        }
        assert(slot < 128);
        descriptors[slot] = result;
        allocations++;
        live++;
    }
    return result;
}

void free(void *pointer) {
    if (pointer) {
        for (unsigned i = 0; i < 128; i++) {
            if (descriptors[i] == pointer) {
                descriptors[i] = NULL;
                retirements++;
                live--;
                break;
            }
        }
    }
    __libc_free(pointer);
}

__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "X11_XDO_KEYMAP_HEAP allocations=%u retirements=%u live=%u\n",
            allocations, retirements, live);
}

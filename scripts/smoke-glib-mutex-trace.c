#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

// Diagnostic-only interposer for the pinned Linux viewer smoke. The GLib
// futex-backed GMutex aborts in g_mutex_clear when its first state word is
// nonzero. Capture the caller before letting GLib make its own decision.
void g_mutex_clear(void *mutex) {
  static void (*real_clear)(void *);
  if (real_clear == NULL) {
    real_clear = (void (*)(void *))dlsym(RTLD_NEXT, "g_mutex_clear");
    if (real_clear == NULL) {
      dprintf(STDERR_FILENO, "RUSTDESK_MUTEX_TRACE missing GLib symbol\n");
      _exit(125);
    }
  }
  if (mutex != NULL &&
      __atomic_load_n((const uint32_t *)mutex, __ATOMIC_RELAXED) != 0) {
    void *frames[48];
    int count = backtrace(frames, 48);
    dprintf(STDERR_FILENO, "RUSTDESK_MUTEX_TRACE invalid-clear mutex=%p state=%u frames=%d\n",
            mutex, __atomic_load_n((const uint32_t *)mutex, __ATOMIC_RELAXED), count);
    backtrace_symbols_fd(frames, count, STDERR_FILENO);
  }
  real_clear(mutex);
}

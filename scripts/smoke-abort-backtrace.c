#define _GNU_SOURCE
#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

// Guest-viewer diagnostic only. Do not intercept normal mutex operations;
// leave the abort fatal after recording the native stack if it recurs.
static void trace_abort(int signal_number) {
  (void)signal_number;
  static const char heading[] = "RUSTDESK_VIEWER_ABORT_BACKTRACE\n";
  (void)write(STDERR_FILENO, heading, sizeof heading - 1);
  void *frames[64];
  int count = backtrace(frames, 64);
  backtrace_symbols_fd(frames, count, STDERR_FILENO);
}

__attribute__((constructor)) static void install_abort_trace(void) {
  void *warmup[1];
  (void)backtrace(warmup, 1);
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = trace_abort;
  action.sa_flags = SA_RESETHAND;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGABRT, &action, NULL) != 0) {
    static const char error[] = "RUSTDESK_VIEWER_ABORT_TRACE_SETUP_FAILED\n";
    (void)write(STDERR_FILENO, error, sizeof error - 1);
    _exit(125);
  }
  static const char armed[] = "RUSTDESK_VIEWER_ABORT_TRACE_ARMED\n";
  (void)write(STDERR_FILENO, armed, sizeof armed - 1);
}

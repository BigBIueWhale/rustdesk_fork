#!/usr/bin/env python3
"""Execute the production Linux entry point with a broken-pipe core fixture."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile


CORE = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void require(int condition) {
  if (!condition) _exit(80);
}

__attribute__((constructor)) static void before_core(void) {
  const char *mode = getenv("LAUNCHER_TEST_WRITE");
  require(mode != NULL);
  if (strcmp(mode, "healthy") == 0) return;
  int pair[2];
  int pipe_write = strcmp(mode, "pipe-write") == 0;
  require(pipe_write ? pipe(pair) == 0 :
          socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  require(close(pair[0]) == 0);
  ssize_t result;
  if (strcmp(mode, "socket-writev") == 0) {
    char a = 'a', b = 'b';
    struct iovec vectors[2] = {{&a, 1}, {&b, 1}};
    result = writev(pair[1], vectors, 2);
  } else {
    require(pipe_write || strcmp(mode, "socket-write") == 0);
    result = write(pair[1], "x", 1);
  }
  require(result == -1 && errno == EPIPE);
  require(close(pair[1]) == 0);
  require(puts("constructor:EPIPE") >= 0);
}

_Bool rustdesk_core_main(void) {
  require(puts("core:headless-exit") >= 0);
  return 0;
}
'''

UI = r'''
#include "my_application.h"
#include <unistd.h>
MyApplication* my_application_new() { _exit(81); }
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command!r}: {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def main():
    if os.getuid() != 4000 or os.getgid() != 4000:
        raise RuntimeError("native launcher check requires the isolated test principal")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if (any(int(status[key].strip(), 16) for key in
            ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"].strip() != "1"):
        raise RuntimeError("native launcher check requires no capabilities and no-new-privileges")
    repo = Path("/repo")
    header = repo / "flutter/linux/my_application.h"
    sources = {"before": repo / "flutter/linux/main-before.cc",
               "after": repo / "flutter/linux/main.cc"}
    if digest(sources["before"]) != "c05ef73020005d87a3c67603aac39f9075f1a41596115c869979a684b5ccbf28":
        raise RuntimeError("historical launcher source differs")
    gtk = shlex.split(checked(["/usr/bin/pkg-config", "--cflags", "--libs", "gtk+-3.0"]))
    records = {}
    with tempfile.TemporaryDirectory(prefix="linux-launcher-", dir="/work") as temporary:
        work = Path(temporary)
        (work / "lib").mkdir()
        core = work / "core.c"
        core.write_text(CORE)
        ui = work / "ui.cc"
        ui.write_text(UI)
        library = work / "lib/librustdesk.so"
        checked(["/usr/bin/gcc", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                 str(core), "-o", str(library)])
        for name, source in sources.items():
            executable = work / name
            checked(["/usr/bin/g++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                     "-I" + str(header.parent), str(source), str(ui), "-o", str(executable),
                     "-ldl", *gtk])
            cases = {}
            for mode in ("healthy", "socket-write", "socket-writev", "pipe-write"):
                # Python restores SIGPIPE to its default before exec. The launcher
                # must establish its own policy, including before dlopen constructors.
                result = subprocess.run([str(executable)], restore_signals=True,
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                             "LAUNCHER_TEST_WRITE": mode},
                                        capture_output=True, text=True, timeout=5)
                broken = mode != "healthy"
                expected_status = -signal.SIGPIPE if name == "before" and broken else 0
                expected_output = "" if expected_status else (
                    ("constructor:EPIPE\n" if broken else "") + "core:headless-exit\n")
                if (result.returncode != expected_status or result.stdout != expected_output
                        or result.stderr):
                    raise RuntimeError(f"{name}/{mode}: {result!r}")
                cases[mode] = {"returncode": result.returncode, "stdout": result.stdout}
            records[name] = {"source_sha256": digest(source),
                             "executable_sha256": digest(executable), "cases": cases}
        records["fixture_library_sha256"] = digest(library)
        records["header_sha256"] = digest(header)
        records["compiler_sha256"] = digest(Path("/usr/bin/g++").resolve())
    if any(Path("/work").iterdir()):
        raise RuntimeError("launcher scratch was not retired")
    print("LINUX_LAUNCHER_ARTIFACTS=" + json.dumps(records, sort_keys=True))
    print("LINUX_LAUNCHER_TESTS=pass cases=8 baseline_sigpipe=3 corrected_epipe=3 "
          "healthy=2 library=fixture gui=unexecuted")


if __name__ == "__main__":
    main()

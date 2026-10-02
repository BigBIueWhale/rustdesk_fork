#!/usr/bin/env python3
"""Materialize authenticated engine inputs and run their original hooks offline."""

import hashlib
from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import unquote, urlsplit


FILE_LIMIT = 512 * 1024 * 1024
TOOLKIT_ENTRY_LIMIT = 4096
TOOLKIT_MANIFEST_LIMIT = 1024 * 1024
TOOLKIT_ELFS = {"libflutter_linux_gtk.so", "gen_snapshot", "font-subset",
                "impellerc", "libtessellator.so"}
TOTAL_LIMIT = 12 * 1024 ** 3
ENTRY_LIMIT = 524288
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
          "st_size", "st_mtime_ns", "st_ctime_ns")
HOOKS = [
    ["python3", "engine/src/flutter/third_party/dart/tools/generate_package_config.py"],
    ["python3", "engine/src/flutter/third_party/dart/tools/generate_sdk_version_file.py"],
    *[["python3", "engine/src/build/linux/sysroot_scripts/install-sysroot.py", "--arch=" + arch]
      for arch in ("x64", "arm64", "riscv64")],
    ["python3", "engine/src/flutter/tools/pub_get_offline.py"],
]
# The DEPS-selected bootstrap CLI discovers package metadata from its working
# directory independently of --packages. Keep that SDK and its original AOT
# recipe, but execute the action in the workspace that owns those packages.
BOOTSTRAP_WORKSPACE_PATCH = b'''diff --git a/build/dart/dart_action.gni b/build/dart/dart_action.gni
--- a/build/dart/dart_action.gni
+++ b/build/dart/dart_action.gni
@@ -151,6 +151,13 @@ template("_prebuilt_tool_action") {
     }

     args = []

+    if (defined(invoker.working_directory)) {
+      args += [
+        "--working-directory",
+        rebase_path(invoker.working_directory, root_build_dir),
+      ]
+    }
+
     if (_is_dart && use_rbe && host_os == rbe_os && host_cpu == rbe_cpu) {
       args += [
diff --git a/build/gn_run_binary.py b/build/gn_run_binary.py
--- a/build/gn_run_binary.py
+++ b/build/gn_run_binary.py
@@ -5,7 +5,7 @@
 """Helper script for GN to run an arbitrary binary. See compiled_action.gni.

 Run with:
-  python3 gn_run_binary.py <binary_name> [args ...]
+  python3 gn_run_binary.py [--working-directory <dir>] <binary_name> [args ...]

 Swallows output on success.
 """
@@ -18,6 +18,7 @@ import subprocess
 # Run a command, swallowing the output unless there is an error.
-def run_command(command):
+def run_command(command, working_directory=None):
     try:
-        subprocess.check_output(command, stderr=subprocess.STDOUT)
+        subprocess.check_output(
+            command, cwd=working_directory, stderr=subprocess.STDOUT)
         return 0
     except subprocess.CalledProcessError as e:
@@ -35,6 +36,11 @@ def _decode(bytes):
 def main(argv):
+    working_directory = None
+    if len(argv) > 3 and argv[1] == '--working-directory':
+        working_directory = os.path.abspath(argv[2])
+        argv = argv[:1] + argv[3:]
+
     # Unless the path is absolute, this script is designed to run binaries
     # produced by the current build, which is the current working directory when
     # this script is run.
     path = os.path.abspath(argv[1])

@@ -46,7 +52,7 @@ def main(argv):
     args = [path] + argv[2:]

-    result = run_command(args)
+    result = run_command(args, working_directory)
     if result != 0:
         print(result)
         return 1
     return 0
diff --git a/utils/BUILD.gn b/utils/BUILD.gn
--- a/utils/BUILD.gn
+++ b/utils/BUILD.gn
@@ -55,16 +55,19 @@ template("aot_compile_using_prebuilt_sdk") {
     depfile = invoker.output + ".d"

+    working_directory = _dart_root
     args = [
       "compile",
       "exe",
+      "--extra-gen-kernel-options=--depfile-target=" +
+          rebase_path(invoker.output, root_build_dir),
       "--output",
-      rebase_path(invoker.output, root_build_dir),
+      rebase_path(invoker.output, working_directory),
       "--packages",
-      rebase_path(invoker.package_config, root_build_dir),
+      rebase_path(invoker.package_config, working_directory),
       "--depfile",
-      rebase_path(depfile, root_build_dir),
-      rebase_path(invoker.entry_point, root_build_dir),
+      rebase_path(depfile, working_directory),
+      rebase_path(invoker.entry_point, working_directory),
     ]
   }
 }

'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unchanged(before, after):
    return all(getattr(before, field) == getattr(after, field) for field in FIELDS)


def parts(name, root=False):
    require(isinstance(name, str) and 0 < len(name.encode()) <= 1024
            and not name.startswith("/")
            and not any(ord(c) < 32 or ord(c) == 127 for c in name), "unsafe archive path")
    if name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if root and name in ("", "."):
        return ()
    result = tuple(name.split("/"))
    require(len(result) <= 64 and all(p not in ("", ".", "..") for p in result),
            "noncanonical archive path")
    return result


class Tree:
    """Writes never traverse symlinks; links are installed only after regular data."""

    def __init__(self, root):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        require(not os.listdir(self.fd), "preparation workspace is occupied")
        self.entries = {}
        self.links = []
        self.bytes = 0
        self.count = 0

    def close(self):
        os.close(self.fd)

    def parent(self, path):
        fd = os.dup(self.fd)
        try:
            for component in path[:-1]:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def write(self, path, source, size, mode):
        parent = self.parent(path)
        try:
            fd = os.open(path[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, mode, dir_fd=parent)
            with os.fdopen(fd, "wb") as output:
                remaining = size
                while remaining:
                    block = source.read(min(1048576, remaining))
                    require(block, "truncated archive data")
                    output.write(block)
                    remaining -= len(block)
                require(not source.read(1), "archive member exceeds its declared size")
                os.fchmod(output.fileno(), mode)
        finally:
            os.close(parent)

    def unpack(self, source, scope, prefixed=False, metadata=False):
        local = {}
        with tarfile.open(fileobj=source, mode="r|*") as archive:
            for member in archive:
                self.count += 1
                require(self.count <= ENTRY_LIMIT, "engine entry budget exhausted")
                raw = parts(member.name, root=not prefixed)
                path = raw if prefixed else scope + raw
                require(path[:len(scope)] == scope and path, "archive prefix differs")
                require(member.isdir() or member.isreg() or member.issym() or member.islnk(),
                        "special archive member refused")
                require(member.sparse is None, "sparse archive member refused")
                require(not metadata or member.isdir() or member.isreg(), "Git metadata link refused")
                require(not metadata or (raw and raw[0] == ".git"), "Git metadata prefix differs")
                kind = "dir" if member.isdir() else "file" if member.isreg() else "link"
                require(path not in local, "duplicate archive member")
                local[path] = kind
                previous = self.entries.get(path)
                require(previous is None or (previous == kind == "dir"), "archive path collision")
                self.entries[path] = kind
                if member.isdir():
                    parent = self.parent(path + (".directory-probe",))
                    os.close(parent)
                elif member.isreg():
                    self.bytes += member.size
                    require(0 <= member.size <= FILE_LIMIT and self.bytes <= TOTAL_LIMIT,
                            "engine byte budget exhausted")
                    with archive.extractfile(member) as data:
                        self.write(path, data, member.size, 0o755 if member.mode & 0o111 else 0o644)
                else:
                    target = member.linkname
                    require(0 < len(target.encode()) <= 1024 and not target.startswith("/")
                            and not any(ord(c) < 32 or ord(c) == 127
                                                               for c in target), "unsafe link target")
                    self.links.append((path, target, member.islnk(), scope, local))
        # No archive may write through a deferred symlink (even if it appeared last).
        for path in local:
            require(all(self.entries.get(path[:n]) != "link" for n in range(1, len(path))),
                    "archive writes below a link")
        return local

    def finish_links(self):
        symlinks = {path: target for path, target, hard, _, _ in self.links if not hard}
        for path, target, hard, scope, local in self.links:
            require(all(self.entries.get(path[:n]) != "link" for n in range(1, len(path))),
                    "link has a link ancestor")
            if hard:
                destination = scope + parts(target)
                require(local.get(destination) == "file", "hardlink is not an archive-local regular file")
                source_parent = self.parent(destination)
                parent = self.parent(path)
                try:
                    require(stat.S_ISREG(os.stat(destination[-1], dir_fd=source_parent,
                                                follow_symlinks=False).st_mode), "hardlink target changed")
                    os.link(destination[-1], path[-1], src_dir_fd=source_parent,
                            dst_dir_fd=parent, follow_symlinks=False)
                finally:
                    os.close(source_parent)
                    os.close(parent)
            else:
                # Resolve the complete known link graph, including '..' after a link.
                pending = list(path[len(scope):-1]) + target.split("/")
                resolved = []
                hops = 0
                while pending:
                    component = pending.pop(0)
                    if component in ("", "."):
                        continue
                    if component == "..":
                        require(resolved, "symlink escapes its input root")
                        resolved.pop()
                        continue
                    resolved.append(component)
                    nested = symlinks.get(scope + tuple(resolved))
                    if nested is not None:
                        hops += 1
                        require(hops <= 40, "symlink graph is cyclic or too deep")
                        resolved.pop()
                        pending = nested.split("/") + pending
                parent = self.parent(path)
                try:
                    os.symlink(target, path[-1], dir_fd=parent)
                finally:
                    os.close(parent)


def authenticated(path, size, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    source = os.fdopen(fd, "rb")
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                and stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1
                and 0 < size <= 4 * 1024 ** 3 and before.st_size == size,
                "engine input authority differs")
        require(re.fullmatch("[0-9a-f]{64}", digest)
                and hashlib.file_digest(source, "sha256").hexdigest() == digest
                and unchanged(before, os.fstat(fd)), "engine input digest or identity differs")
        source.seek(0)
        return source, before
    except BaseException:
        source.close()
        raise


def command(arguments, cwd, env, deadline, *, integration=False):
    require(time.monotonic() < deadline, "engine preparation deadline expired")
    child = subprocess.Popen(arguments, cwd=cwd, env=env, close_fds=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    output = bytearray()
    started = time.monotonic()
    reported = started
    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            require(time.monotonic() < deadline, "engine preparation command timed out: "
                    + repr(arguments) + "\n" + output[-16384:].decode(errors="replace"))
            for key, _ in selector.select(0.1):
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(block)
                    require(len(output) <= (4 * 1024 * 1024 if integration else 262144),
                            "engine preparation command output exceeds bound")
            if integration and time.monotonic() - reported >= 10:
                # Bounded diagnostics are not success receipts. Emit even during a
                # long link, retaining the exact child rather than launching again.
                reported = time.monotonic()
                print("ENGINE_BUILD_PROGRESS elapsed_seconds=" + str(int(reported - started))
                      + " output_bytes=" + str(len(output)) + " tail="
                      + json.dumps(output[-512:].decode(errors="replace")), flush=True)
        status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(status == 0, "engine command failed: " + repr(arguments) + "\n"
                + output[-65536:].decode(errors="replace"))
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        selector.close()


def require_no_inet_sockets():
    for protocol in ("tcp", "tcp6", "udp", "udp6"):
        path = Path("/proc/net") / protocol
        if path.exists():
            rows = path.read_text().splitlines()[1:]
            require(not rows, "native GTK fixture opened an INET socket: " + protocol)


@contextmanager
def native_display(env, deadline):
    records = Path("/authority/xvfb-files.tsv").read_text().splitlines()
    files = [line.split("\t") for line in records if line and not line.startswith("#")]
    require(len(files) == 5 and all(len(row) == 4 for row in files), "Xvfb file closure differs")
    for name, size, mode, digest in files:
        require(parts(name) and re.fullmatch("[0-9a-f]{64}", digest), "Xvfb file record differs")
        fd = os.open("/xvfb-root/" + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                    and before.st_nlink == 1 and before.st_size == int(size)
                    and stat.S_IMODE(before.st_mode) == int(mode, 8)
                    and hashlib.file_digest(source, "sha256").hexdigest() == digest
                    and unchanged(before, os.fstat(fd)), "Xvfb executable/library authority differs")
    require_no_inet_sockets()
    with ExitStack() as resources:
        log = resources.enter_context(tempfile.TemporaryFile(dir="/work"))
        selector = resources.enter_context(selectors.DefaultSelector())
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        resources.callback(os.close, read_fd)
        resources.callback(lambda: os.close(write_fd) if write_fd >= 0 else None)
        child = None
        try:
            child = subprocess.Popen([
                "/xvfb-root/usr/bin/Xvfb", "-displayfd", str(write_fd),
                "-screen", "0", "640x480x24", "-nolisten", "tcp", "-noreset", "-ac",
            ], env={**env, "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"},
                close_fds=True, pass_fds=(write_fd,), stdout=log, stderr=log)
            os.close(write_fd)
            write_fd = -1
            selector.register(read_fd, selectors.EVENT_READ)
            ready_deadline = min(deadline, time.monotonic() + 20)
            ready = bytearray()
            while not ready.endswith(b"\n"):
                require(time.monotonic() < ready_deadline and child.poll() is None,
                        "native Xvfb exited or missed readiness")
                require(os.fstat(log.fileno()).st_size <= 65536, "Xvfb diagnostics exceed bound")
                for _, _ in selector.select(min(0.1, max(0, ready_deadline - time.monotonic()))):
                    block = os.read(read_fd, 32)
                    require(block, "Xvfb closed its readiness channel")
                    ready.extend(block)
                    require(len(ready) <= 6, "Xvfb display number exceeds bound")
            require(re.fullmatch(rb"[0-9]{1,5}\n", ready) and int(ready) <= 65535,
                    "Xvfb readiness record differs")
            require_no_inet_sockets()
            print("ENGINE_XVFB_READY=pass display=" + ready.decode().strip()
                  + " network=unix-only owner=retained", flush=True)
            yield {**env, "DISPLAY": ":" + ready.decode().strip(), "GDK_BACKEND": "x11",
                   "NO_AT_BRIDGE": "1", "GSETTINGS_BACKEND": "memory"}
            require(child.poll() is None, "Xvfb exited during the native fixture")
        finally:
            if child is not None:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                child.wait()
                log.seek(0)
                diagnostics = log.read(65537)
                require(len(diagnostics) <= 65536, "Xvfb diagnostics exceed bound")
                if diagnostics:
                    print("ENGINE_XVFB_DIAGNOSTICS\n" + diagnostics.decode(errors="replace"), flush=True)
                require_no_inet_sockets()
                print("ENGINE_XVFB_OWNER=joined network=unix-only", flush=True)


def prepare(build_context=None):
    deadline = time.monotonic() + 240
    with open("/authority/pins.env", "rb") as source:
        pin_bytes = source.read(131073)
    require(len(pin_bytes) <= 131072, "pin file exceeds bound")
    pin_text = pin_bytes.decode("utf-8")

    def pin(name):
        matches = re.findall(r'^' + re.escape(name) + r'="([A-Za-z0-9:._+-]+)"(?:\s*#.*)?$',
                             pin_text, re.MULTILINE)
        require(len(matches) == 1, "missing or repeated engine pin: " + name)
        return matches[0]

    manifests = {}
    for role, key in (("graph", "GRAPH"), ("git-metadata", "GIT_METADATA"), ("sysroots", "SYSROOTS")):
        root = "/inputs/" + role
        source, before = authenticated(root + "/manifest.json",
                                       int(pin("SIZE_FLUTTER_ENGINE_" + key + "_MANIFEST")),
                                       pin("SHA256_FLUTTER_ENGINE_" + key + "_MANIFEST"))
        with source:
            manifests[role] = json.load(source)
            require(unchanged(before, os.fstat(source.fileno())), "manifest changed")
        record = manifests[role]
        require(record["format"] == "rustdesk-flutter-linux-engine-" + role + "-v1"
                and record["source_commit"] == pin("FLUTTER_ENGINE_" + key + "_SOURCE_COMMIT")
                and record["framework_revision"] == pin("FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION")
                and record["discovery_sha256"] == pin("SHA256_FLUTTER_ENGINE_BOOTSTRAP_DISCOVERY")
                and record["tools_manifest_sha256"] == pin("SHA256_FLUTTER_ENGINE_BOOTSTRAP_TOOLS_MANIFEST")
                and record["complete_engine_closure"] is False and record["hooks_executed"] is False,
                "engine manifest context differs")
        if role != "graph":
            require(record["graph_manifest_sha256"] == pin("SHA256_FLUTTER_ENGINE_GRAPH_MANIFEST")
                    and record["graph_source_commit"] == manifests["graph"]["source_commit"],
                    "engine manifest graph binding differs")
    graph, metadata, sysroots = (manifests[role] for role in ("graph", "git-metadata", "sysroots"))
    require(len(graph["git"]) == 82 and len(graph["cipd"]) == 11
            and len(metadata["git"]) == 3 and len(sysroots["sysroots"]) == 3
            and [hook["action"] for hook in graph["deferred_hooks"]] == HOOKS
            and graph["gn_args"] == {"build_devtools_from_sources": False, "checkout_llvm": False},
            "selected engine graph shape differs")
    require(metadata["engine_content_hash"] == pin("FLUTTER_ENGINE_SOURCE_CONTENT_HASH")
            and metadata["sdk_engine_version"] == pin("FLUTTER_PRESENTATION_CANDIDATE_ENGINE_REVISION"),
            "source hash or shipped SDK selection differs")
    tree = Tree("/work")
    try:
        for role, entries in (("graph", graph["git"] + graph["cipd"]),
                              ("git-metadata", metadata["git"]), ("sysroots", sysroots["sysroots"])):
            require(sorted(os.listdir("/inputs/" + role)) ==
                    sorted(["manifest.json"] + [entry["file"] for entry in entries]),
                    "engine candidate inventory differs")
            for entry in entries:
                require(len(parts(entry["file"])) == 1, "engine archive filename differs")
                destination = entry["destination"]
                scope = ("flutter",) + (() if destination == "." else parts(destination))
                source, before = authenticated("/inputs/" + role + "/" + entry["file"],
                                               entry["bytes"], entry["sha256"])
                print("ENGINE_PREPARE_ARCHIVE=" + role + "/" + entry["file"], flush=True)
                with source:
                    tree.unpack(source, scope, prefixed=role == "graph" and entry in graph["git"],
                                metadata=role == "git-metadata")
                    require(unchanged(before, os.fstat(source.fileno())), "engine archive changed")
        tree.finish_links()
        gn_args = b"build_devtools_from_sources = false\ncheckout_llvm = false\n"
        tree.write(("flutter",) + parts(graph["gn_args_file"]),
                   io.BytesIO(gn_args), len(gn_args), 0o644)
        for entry in sysroots["sysroots"]:
            stamp = entry["url"].encode()
            tree.write(("flutter",) + parts(entry["destination"]) + (".stamp",),
                       io.BytesIO(stamp), len(stamp), 0o644)
        print(f"ENGINE_PREPARE_MATERIALIZED=pass entries={tree.count} bytes={tree.bytes} links={len(tree.links)}",
              flush=True)
    finally:
        tree.close()
    framework = "/work/flutter"
    env = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "LC_ALL": "C",
           "PUB_CACHE": "/work/pub-cache", "CI": "true", "PYTHONDONTWRITEBYTECODE": "1",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file"}
    os.mkdir(env["HOME"], 0o700)
    os.mkdir(env["PUB_CACHE"], 0o700)
    for entry in metadata["git"]:
        original = next(item for item in graph["git"] if item["destination"] == entry["destination"])
        require(all(entry[key] == original[key] for key in ("commit", "tree", "url"))
                and entry["source_archive_sha256"] == original["sha256"], "original Git binding differs")
        cwd = framework if entry["destination"] == "." else framework + "/" + entry["destination"]
        git = ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false"]
        command(git + ["fsck", "--strict", "--no-reflogs"], cwd, env, deadline)
        require(command(git + ["rev-parse", "HEAD"], cwd, env, deadline).decode().strip() == entry["commit"]
                and command(git + ["rev-parse", "HEAD^{tree}"], cwd, env, deadline).decode().strip() == entry["tree"],
                "restored original Git identity differs")
        require(command(git + ["log", "-1", "--format=%ct%n%cd%n%cD", "HEAD"],
                        cwd, env, deadline).decode().splitlines() == entry["original_timestamps"],
                "restored original Git timestamps differ")
        if entry["destination"] == ".":
            require(command(git + ["show", "HEAD:bin/internal/engine.version"], cwd, env, deadline)
                    == (metadata["sdk_engine_version"] + "\n").encode(),
                    "original shipped SDK selection differs")
        command(git + ["read-tree", "HEAD"], cwd, env, deadline)
        command(git + ["update-index", "--refresh", "--"], cwd, env, deadline)
        require(command(git + ["write-tree"], cwd, env, deadline).decode().strip() == entry["tree"],
                "original tracked index differs")
        command(git + ["diff-files", "--quiet", "--"], cwd, env, deadline)
    content_hash = command(["/bin/bash", "bin/internal/content_aware_hash.sh"], framework, env, deadline)
    require(content_hash.decode().strip() == pin("FLUTTER_ENGINE_SOURCE_CONTENT_HASH"),
            "original engine content hash differs")
    print("ENGINE_PREPARE_GIT=pass repositories=3 indexes=original content_hash="
          + content_hash.decode().strip() + " sdk_engine_version=" + metadata["sdk_engine_version"],
          flush=True)
    for number, action in enumerate(HOOKS, 1):
        print(f"ENGINE_PREPARE_HOOK_START ordinal={number} path={action[1]}", flush=True)
        result = command(action, framework, env, deadline)
        print(f"ENGINE_PREPARE_HOOK=pass ordinal={number} output_bytes={len(result)}", flush=True)
    require(not {"hosted", "git"}.intersection(os.listdir(env["PUB_CACHE"])),
            "original hooks used non-path Pub dependencies")
    for project in (Path(framework) / "engine/src/flutter",
                    Path(framework) / "engine/src/flutter/third_party/dart"):
        config_path = project / ".dart_tool/package_config.json"
        require(config_path.stat().st_size <= 1048576, "generated package config exceeds bound")
        config = json.loads(config_path.read_text())
        require(config["configVersion"] == 2 and config["packages"], "generated package config differs")
        for package in config["packages"]:
            uri = urlsplit(package["rootUri"])
            require(uri.scheme in ("", "file") and not uri.netloc and not uri.query and not uri.fragment,
                    "generated package URI is not local")
            root = (config_path.parent / unquote(uri.path)).resolve(strict=True)
            require(root.is_relative_to(framework) and (root / "pubspec.yaml").is_file(),
                    "generated package root is not a materialized DEPS package")
    engine = framework + "/engine/src"
    if build_context is not None:
        dart = Path(engine) / "flutter/third_party/dart"
        patch = Path("/work/bootstrap-workspace.patch")
        with patch.open("xb") as destination:
            destination.write(BOOTSTRAP_WORKSPACE_PATCH)
        git = ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null"]
        paths = ["build/dart/dart_action.gni", "build/gn_run_binary.py", "utils/BUILD.gn"]
        command(git + ["diff-files", "--quiet", "--", *paths], dart, env, deadline)
        command(git + ["apply", "--check", "--whitespace=error-all", str(patch)], dart, env, deadline)
        command(git + ["apply", "--whitespace=error-all", str(patch)], dart, env, deadline)
        require(sorted(command(git + ["diff", "--name-only", "--", *paths], dart, env, deadline)
                       .decode().splitlines()) == sorted(paths), "bootstrap patch source scope differs")
        command(git + ["diff", "--check", "--", *paths], dart, env, deadline)
        print("ENGINE_BOOTSTRAP_WORKSPACE_PATCH=applied files=3 sha256="
              + hashlib.sha256(BOOTSTRAP_WORKSPACE_PATCH).hexdigest()
              + " sdk=unchanged packages=original", flush=True)
    print("ENGINE_PREPARE_GN_START runtime=release generator=original", flush=True)
    # Keep upstream's argument/version selection. GN's supported interpreter option
    # selects this pinned image's Python, never depot-tools' downloading wrapper.
    gn_driver = """
import runpy
import subprocess

original = runpy.run_path('flutter/tools/gn', run_name='rustdesk_engine_gn')
args = original['parse_args'](['flutter/tools/gn', '--runtime-mode=release',
                               '--enable-unittests', '--no-rbe'])
original['validate_args'](args)
output = original['get_out_dir'](args)
if output != 'out/host_release':
    raise SystemExit('original GN output directory differs')
values = original['to_command_line'](original['to_gn_args'](args))
raise SystemExit(subprocess.call([
    'flutter/third_party/gn/gn', 'gen', '--check', '--export-compile-commands',
    '--export-compile-commands=default', output, '--args=' + ' '.join(values),
    '--tracelog=' + output + '/gn_trace.json', '--script-executable=/usr/bin/python3',
]))
"""
    command(["/usr/bin/python3", "-I", "-S", "-c", gn_driver], engine, env, deadline)
    args_path = Path(engine) / "out/host_release/args.gn"
    require(args_path.stat().st_size <= 131072, "generated GN arguments exceed bound")
    args_text = args_path.read_text()
    expected_args = {
        "flutter_runtime_mode": '"release"', "enable_unittests": "true",
        "target_os": '"linux"', "target_cpu": '"x64"',
        "content_hash": '"' + metadata["engine_content_hash"] + '"',
        "engine_version": '"' + metadata["framework_revision"] + '"',
        "dart_version": '"' + next(entry["commit"] for entry in metadata["git"]
                                   if entry["destination"].endswith("/dart")) + '"',
        "skia_version": '"' + next(entry["commit"] for entry in metadata["git"]
                                   if entry["destination"].endswith("/skia")) + '"',
    }
    for key, value in expected_args.items():
        require(re.findall(r"^" + key + r"\s*=\s*(.+)$", args_text, re.MULTILINE) == [value],
                "generated GN argument differs: " + key)
    for target, outputs in (
            ("flutter_linux_gtk", ("libflutter_linux_gtk.so", "libflutter_linux_gtk.so.TOC")),
            ("flutter_linux_unittests", ("flutter_linux_unittests",
                                        "exe.unstripped/flutter_linux_unittests"))):
        result = command(["flutter/third_party/gn/gn", "desc", "out/host_release",
                          "//flutter/shell/platform/linux:" + target, "outputs",
                          "--script-executable=/usr/bin/python3"],
                         engine, env, deadline)
        require(sorted(line.strip() for line in result.decode().splitlines()) ==
                sorted("//out/host_release/" + output for output in outputs),
                "original GN target output differs: " + target + " " + repr(result[:4096]))
    print("ENGINE_PREPARE_GN=pass runtime=release targets=flutter_linux_gtk,flutter_linux_unittests "
          "generator=original engine_build=unexecuted", flush=True)
    if build_context is not None:
        # Dart compile exe stages both kernel and AOT data in systemTemp. That
        # compiler data belongs to the existing disposable build workspace, not
        # the container's small, non-executable housekeeping /tmp mount.
        env["TMPDIR"] = "/work/compiler-tmp"
        os.mkdir(env["TMPDIR"], 0o700)
        compile_engine_bootstrap(engine, framework, env, deadline)
    objects = ["obj/flutter/shell/platform/linux/flutter_linux_sources." + unit + ".o"
               for unit in ("fl_view", "fl_view_accessible", "fl_accessible_node",
                            "fl_accessible_text_field", "fl_value", "fl_message_codec",
                            "fl_standard_message_codec")]
    print("ENGINE_PREPARE_COMPILE_START production_units=7", flush=True)
    command([framework + "/third_party/ninja/ninja", "-C", "out/host_release", "-j2",
             *objects], engine, env, deadline)
    def artifact_receipt(name, stage):
        fd = os.open(engine + "/out/host_release/" + name,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                    and before.st_nlink == 1 and 0 < before.st_size <= FILE_LIMIT,
                    "compiled object authority differs")
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            require(unchanged(before, os.fstat(fd)), "compiled object changed")
        print(f"ENGINE_PREPARE_OBJECT=pass stage={stage} path={name} "
              f"bytes={before.st_size} sha256={digest}", flush=True)

    for name in objects:
        artifact_receipt(name, "original")
    print("ENGINE_PREPARE_COMPILE=pass production_units=7 engine_link=unexecuted tests=unexecuted",
          flush=True)
    clang = engine + "/flutter/buildtools/linux-x64/clang/bin/clang++"
    flags = shlex.split(command(["/usr/bin/pkg-config", "--cflags", "--libs", "gtk+-3.0"],
                                engine, env, deadline).decode())

    def node_test(baseline):
        binary = engine + "/out/host_release/node-retirement-" + ("baseline" if baseline else "candidate")
        command([clang, "-std=c++17", "-DFLUTTER_LINUX_COMPILATION",
                 "-DFLUTTER_ENGINE_NO_PROTOTYPES", "-UG_DISABLE_ASSERT", "-I" + engine,
                 *(["-DLEGACY_BASELINE"] if baseline else []),
                 "/authority/node-test.cc",
                 *[engine + "/out/host_release/" + name for name in objects[1:]],
                 "-flto", "-fuse-ld=lld", *flags, "-o", binary], engine, env, deadline)
        artifact_receipt(binary.rsplit("/", 1)[1], "baseline-test" if baseline else "candidate-test")
        expected = ("ENGINE_ACCESSIBLE_RETIREMENT_BASELINE=observed parent=gone engine=live action=dispatched"
                    if baseline else "ENGINE_GTK_WIDGET_LIFETIME=pass backend=x11 mapped=true "
                    "retained_accessible=unbound destroyed=true\n"
                    "ENGINE_ACCESSIBLE_RETIREMENT=pass unit=real-node boundary=recording-engine "
                    "idempotent=true stale=refused fresh=allowed geometry=defunct reentrant=true disposed=true\n"
                    "ENGINE_ACCESSIBLE_ROOT_RETIREMENT=pass unit=real-root boundary=recording-engine "
                    "reset=true replacement=true reentrant=true disposed=true\n"
                    "ENGINE_ACCESSIBLE_TREE_REVOCATION=pass unit=real-root first_notification=closed "
                    "indexed_direct=refused reset_retire_dispose=closed reentrant_owner=closed\n"
                    "ENGINE_SEMANTICS_GENERATION=pass default=closed owner_loss=closed "
                    "retired_disposed=closed retained_text=closed old_properties=absent\n"
                    "ENGINE_ACCESSIBLE_TEXT_FIELD_RETIREMENT=pass unit=real-text-field "
                    "retired_disposed=closed live_edits=allowed reentrant_buffer=closed "
                    "reentrant_selection=closed reentrant_dispatch=closed "
                    "caller_release=joined late_edits=refused\n"
                    "ENGINE_ACCESSIBLE_NODE_GEOMETRY_OBSERVED parent=5,7,20,10 position=5,7 contains=1 "
                    "retired_screen=-1,-1,-1,-1 retired_window=-1,-1,-1,-1 retired_size=-1,-1 retired_contains=0\n"
                    "ENGINE_ACCESSIBLE_NODE_GEOMETRY=pass unit=real-node parent_relative=true "
                    "retired_ancestor=unavailable position_size=consistent contains=closed\n"
                    "ENGINE_ACCESSIBLE_WIDGET_GEOMETRY=pass owner=gtk-bound early_binding=closed "
                    "transforms=full parent_hit_test=consistent invalid=closed hidden=unavailable teardown=revoked")
        if baseline:
            output = command([binary], engine, env, deadline)
            require(output == (expected + "\n").encode(), "native node retirement receipt differs")
        else:
            with native_display(env, deadline) as display_env:
                for scale in (1, 2):
                    output = command([binary], engine, {**display_env, "GDK_SCALE": str(scale)}, deadline)
                    require(output == (expected + "\n").encode(),
                            "native GTK geometry receipt differs at scale " + str(scale))
                    print("ENGINE_ACCESSIBLE_GTK_SCALE=pass scale=" + str(scale)
                          + " artifact=same scenarios=complete", flush=True)
        # Forward the common receipts once; the exact outer checker rejects duplicates.
        print(expected, flush=True)

    node_test(True)
    patch_path = Path("/authority/retirement.patch")
    patch_bytes = patch_path.read_bytes()
    require(0 < len(patch_bytes) <= 128 * 1024, "retirement patch exceeds bound")
    git = ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null"]
    command(git + ["apply", "--check", "--whitespace=error-all", str(patch_path)],
            framework, env, deadline)
    command(git + ["apply", "--whitespace=error-all", str(patch_path)],
            framework, env, deadline)
    expected_paths = ["engine/src/flutter/shell/platform/linux/" + name for name in
                      ("BUILD.gn", "fl_accessible_node.cc", "fl_accessible_node.h",
                       "fl_accessible_node_test.cc", "fl_accessible_text_field.cc",
                       "fl_accessible_text_field.h", "fl_accessible_text_field_test.cc",
                       "fl_semantics_generation.cc", "fl_semantics_generation.h",
                       "fl_socket_accessible.cc", "fl_socket_accessible.h",
                       "fl_view.cc", "fl_view_accessible.cc", "fl_view_accessible.h",
                       "fl_view_accessible_test.cc")]
    changed = command(git + ["diff", "--name-only", "--", "engine/src/flutter/shell/platform/linux"],
                      framework, env, deadline).decode().splitlines()
    changed += command(git + ["ls-files", "--others", "--exclude-standard", "--",
                              "engine/src/flutter/shell/platform/linux"],
                       framework, env, deadline).decode().splitlines()
    require(sorted(changed) == sorted(expected_paths), "retirement patch source scope differs")
    command(git + ["diff", "--check"], framework, env, deadline)
    print("ENGINE_ACCESSIBLE_RETIREMENT_PATCH=applied sha256="
          + hashlib.sha256(patch_bytes).hexdigest() + " files=15 sdk_archive=unchanged", flush=True)
    objects.append("obj/flutter/shell/platform/linux/flutter_linux_sources.fl_semantics_generation.o")
    upstream_tests = ["obj/flutter/shell/platform/linux/flutter_linux_unittests." + unit + ".o"
                      for unit in ("fl_accessible_node_test", "fl_accessible_text_field_test",
                                   "fl_view_accessible_test", "fl_view_test")]
    command([framework + "/third_party/ninja/ninja", "-C", "out/host_release", "-j2",
             *objects],
            engine, env, deadline)
    for name in objects:
        artifact_receipt(name, "retirement-candidate")
    node_test(False)
    # Compile the migrated consumers with their exact generated command, not
    # the unittest executable's order-only engine/fixture build dependencies.
    # This proves translation-unit compatibility, never suite or engine linking.
    for name in upstream_tests:
        query = command([framework + "/third_party/ninja/ninja", "-C", "out/host_release",
                         "-t", "query", name], engine, env, deadline)
        print("ENGINE_UPSTREAM_TEST_QUERY path=" + name + "\n"
              + query[:8192].decode(errors="replace"), flush=True)
        recipe = command([framework + "/third_party/ninja/ninja", "-C", "out/host_release",
                          "-t", "commands", "-s", name], engine, env, deadline)
        require(len(recipe) <= 65536 and len(recipe.splitlines()) == 1,
                "upstream object command is not one bounded invocation")
        arguments = shlex.split(recipe.decode())
        cwd = Path(engine) / "out/host_release"
        unit = name.rsplit(".", 2)[1]
        require(arguments and (cwd / arguments[0]).resolve(strict=True)
                    == Path(clang).resolve(strict=True)
                and arguments.count("-c") == arguments.count("-o") == 1
                and (cwd / arguments[arguments.index("-c") + 1]).resolve(strict=True)
                    == Path(engine) / "flutter/shell/platform/linux" / (unit + ".cc")
                and (cwd / arguments[arguments.index("-o") + 1]).resolve() == cwd / name,
                "upstream object compiler/source/output differs: " + repr(arguments))
        print("ENGINE_UPSTREAM_TEST_COMPILE_START path=" + name
              + " recipe_sha256=" + hashlib.sha256(recipe).hexdigest(), flush=True)
        command(arguments, cwd, env, deadline)
        artifact_receipt(name, "upstream-test-compile")
    print("ENGINE_ACCESSIBLE_RETIREMENT_COMPILE=pass production_units=8 upstream_test_objects=4 "
          "view_teardown=unexecuted engine_restart=unexecuted app_replay=unexecuted", flush=True)
    print("FLUTTER_ENGINE_PREPARE=pass git=82 cipd=11 metadata=3 sysroots=3 hooks=6 "
          "indexes=original pub=path-only network=none engine_build=unexecuted", flush=True)
    toolkit = describe_engine_toolkit(engine, env, deadline)
    sdk_inputs = [entry for entry in graph["cipd"]
                  if entry["destination"] == "engine/src/flutter/prebuilts/linux-x64/dart-sdk"]
    require(len(sdk_inputs) == 1, "selected Linux Dart SDK input differs")
    toolkit["dart_sdk_input"] = {key: sdk_inputs[0][key] for key in
                                ("destination", "file", "bytes", "sha256", "instance_id")}
    if build_context is not None:
        build_engine(engine, framework, env, pin, patch_bytes, build_context, toolkit)


def compile_engine_bootstrap(engine, framework, env, deadline):
    """Exercise the original bootstrap action before the expensive engine link."""
    output = Path(engine) / "out/host_release"
    for scope, project in (("framework", Path(framework)),
                           ("engine", Path(engine) / "flutter"),
                           ("dart", Path(engine) / "flutter/third_party/dart")):
        for name in ("package_config.json", "package_graph.json"):
            try:
                with engine_file(project / ".dart_tool" / name) as source:
                    before = os.fstat(source.fileno())
                    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                            and before.st_nlink == 1 and 0 < before.st_size <= 1048576,
                            "bootstrap package metadata authority differs")
                    data = source.read(1048577)
                    require(len(data) == before.st_size and unchanged(before, os.fstat(source.fileno())),
                            "bootstrap package metadata changed")
                    require(type(json.loads(data)) is dict, "bootstrap package metadata is not an object")
            except FileNotFoundError:
                print(f"ENGINE_BOOTSTRAP_METADATA scope={scope} file={name} present=false", flush=True)
            else:
                print(f"ENGINE_BOOTSTRAP_METADATA scope={scope} file={name} present=true "
                      f"bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}", flush=True)
    target = "bootstrap_compile_platform.exe"
    label = "//flutter/third_party/dart/utils:" + target
    description = json.loads(command([
        "flutter/third_party/gn/gn", "desc", "out/host_release", label, "outputs",
        "--format=json", "--script-executable=/usr/bin/python3",
    ], engine, env, deadline))
    require(type(description) is dict and set(description) == {label}
            and description[label].get("outputs") == ["//out/host_release/" + target],
            "original bootstrap output differs")
    ninja = framework + "/third_party/ninja/ninja"
    plan = command([ninja, "-C", str(output), "-n", target], engine, env, deadline)
    require(0 < len(plan.splitlines()) <= 128, "bootstrap preflight plan is empty or exceeds bound")
    print("ENGINE_BOOTSTRAP_START target=" + target + " generator=original jobs=2 plan_lines="
          + str(len(plan.splitlines())) + " plan_sha256=" + hashlib.sha256(plan).hexdigest(), flush=True)
    scratch = os.stat(env["TMPDIR"], follow_symlinks=False)
    require(stat.S_ISDIR(scratch.st_mode) and scratch.st_uid == scratch.st_gid == 1000
            and stat.S_IMODE(scratch.st_mode) == 0o700 and not os.listdir(env["TMPDIR"]),
            "bootstrap compiler scratch authority differs")
    housekeeping = os.statvfs("/tmp")
    print("ENGINE_COMPILER_SCRATCH=owned parent=/work mode=0700 file_limit_bytes="
          + str(FILE_LIMIT) + " housekeeping_tmp_bytes="
          + str(housekeeping.f_frsize * housekeeping.f_blocks), flush=True)
    command([ninja, "-C", str(output), "-j2", target], engine, env, deadline)
    after = os.stat(env["TMPDIR"], follow_symlinks=False)
    require(all(getattr(scratch, field) == getattr(after, field)
                for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid"))
            and not os.listdir(env["TMPDIR"]), "bootstrap compiler retained or replaced scratch")
    with engine_file(output / target) as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                and before.st_nlink == 1 and 64 <= before.st_size <= FILE_LIMIT,
                "bootstrap executable authority differs")
        prefix = source.read(64)
        require(prefix[:6] == b"\x7fELF\x02\x01" and int.from_bytes(prefix[18:20], "little") == 62,
                "bootstrap output is not an x86_64 ELF")
        source.seek(0)
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        require(unchanged(before, os.fstat(source.fileno())), "bootstrap executable changed")
    print("ENGINE_BOOTSTRAP_ARTIFACT target=" + target + " bytes=" + str(before.st_size)
          + " sha256=" + digest + " current_plan=unverified", flush=True)
    current = command([ninja, "-C", str(output), "-n", "-d", "explain", target],
                      engine, env, deadline)
    require(current.splitlines()[-1:] == [b"ninja: no work to do."],
            "bootstrap target is not current:\n" + current.decode(errors="replace"))
    print("ENGINE_BOOTSTRAP_COMPILE=pass target=" + target + " bytes=" + str(before.st_size)
          + " sha256=" + digest + " generator=original network=none", flush=True)


def describe_engine_toolkit(engine, env, deadline):
    """Use original GN outputs/copy sources, never a stock engine-cache inventory."""
    gn = ["flutter/third_party/gn/gn", "desc", "out/host_release"]
    roles = {
        "//flutter/lib/snapshot:strong_platform": (
            "flutter_patched_sdk/platform_strong.dill",
            "flutter_patched_sdk/vm_outline_strong.dill"),
        "//flutter/third_party/icu:copy_icudata": ("icudtl.dat",),
        "//flutter/tools/font_subset:_font-subset": ("font-subset",),
        "//flutter/tools/const_finder:const_finder": ("gen/const_finder.dart.snapshot",),
        "//flutter/flutter_frontend_server:frontend_server": (
            "gen/frontend_server_aot.dart.snapshot",),
        "//flutter/impeller/compiler:impellerc": ("impellerc",),
        "//flutter/impeller/tessellator:tessellator_shared": ("libtessellator.so",),
    }
    copies = {}
    targets = []
    descriptors = {}
    for label, wanted in roles.items():
        data = json.loads(command(gn + [label, "--format=json",
                                      "--script-executable=/usr/bin/python3"],
                                  engine, env, deadline))
        require(type(data) is dict and set(data) == {label}, "GN toolkit target differs: " + label)
        record = data[label]
        outputs = record.get("outputs", [])
        require(all("//out/host_release/" + name in outputs for name in wanted),
                "GN toolkit outputs differ: " + label + " " + repr(outputs))
        descriptors.update(data)
        targets.extend(wanted)
    sky = json.loads(command(gn + ["//flutter/sky/packages/sky_engine:*", "--format=json",
                                  "--script-executable=/usr/bin/python3"],
                              engine, env, deadline))
    require(type(sky) is dict and "//flutter/sky/packages/sky_engine:sky_engine" in sky,
            "GN sky_engine package target is absent")
    package = sky["//flutter/sky/packages/sky_engine:sky_engine"]
    require(package.get("type") == "action"
            and package.get("outputs") == ["//out/host_release/gen/dart-pkg/sky_engine.stamp"],
            "GN sky_engine package recipe differs")
    descriptors.update(sky)
    for label, record in descriptors.items():
        if record.get("type") != "copy":
            continue
        sources, outputs = record.get("sources", []), record.get("outputs", [])
        require(sources and len(sources) == len(outputs), "GN copy inventory differs: " + label)
        for source, output in zip(sources, outputs):
            require(source.startswith("//") and output.startswith("//out/host_release/"),
                    "GN copy path differs")
            name = output.removeprefix("//out/host_release/")
            require(parts(name) and parts(source[2:]) and Path(name).name == Path(source).name
                    and name not in copies, "GN copy pairing differs: " + name)
            copies[name] = Path(engine) / source[2:]
    targets.append("gen/dart-pkg/sky_engine.stamp")
    print("ENGINE_TOOLKIT_GRAPH=pass roles=platform,icu,sky,fonts,shaders,frontend "
          "generator=original build=unexecuted", flush=True)
    return {"targets": targets, "copies": copies,
            "graph_sha256": hashlib.sha256(json.dumps(descriptors, sort_keys=True).encode()).hexdigest()}


@contextmanager
def engine_file(path):
    """Acquire an output or its GN source alias without traversing directory links."""
    require(path.is_absolute(), "engine artifact path is not absolute")
    components = parts(path.as_posix()[1:])
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            require(info.st_uid in (0, 1000) and not info.st_mode & 0o022,
                    "engine artifact directory authority differs")
        fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as source:
        yield source


@contextmanager
def engine_output(output, copies, name):
    header = re.fullmatch(r"flutter_linux/[a-z0-9_]+\.h", name) is not None
    require(header or name in TOOLKIT_ELFS or name in (
                "icudtl.dat", "gen/const_finder.dart.snapshot",
                "gen/frontend_server_aot.dart.snapshot",
                "flutter_patched_sdk/platform_strong.dill",
                "flutter_patched_sdk/vm_outline_strong.dill")
            or (name.startswith("gen/dart-pkg/sky_engine/") and parts(name)),
            "engine output role differs")
    with ExitStack() as resources:
        source = resources.enter_context(engine_file(output / name))
        fd = source.fileno()
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 1000
                and before.st_nlink == (2 if name in copies else 1)
                and 0 < before.st_size <= FILE_LIMIT, "engine artifact authority differs: " + name)
        if name in copies:
            # The original GN copy rule hardlinks within this private build tree.
            # Its one source alias is allowed only after proving the exact inode.
            original = resources.enter_context(engine_file(copies[name]))
            original_fd = original.fileno()
            require(unchanged(before, os.fstat(original_fd)),
                    "engine copied source identity differs: " + name)
        yield source, before
        require(unchanged(before, os.fstat(fd)), "engine output changed: " + name)
        if name in copies:
            require(unchanged(before, os.fstat(original.fileno())),
                    "engine copied source changed: " + name)


def seal_engine_outputs(output, copies, names, manifest, archive):
    require(0 < len(names) <= TOOLKIT_ENTRY_LIMIT and len(set(names)) == len(names),
            "engine output inventory exceeds bound or repeats a path")
    require(len(names) + sum(name in copies for name in names) + 128
            <= resource.getrlimit(resource.RLIMIT_NOFILE)[0],
            "engine output descriptor budget exhausted")
    with ExitStack() as resources:
        opened = {}
        total = 0
        for name in names:
            source, before = resources.enter_context(engine_output(
                output, copies, name))
            total += before.st_size
            require(total <= FILE_LIMIT - 1048576, "engine artifact byte budget exhausted")
            if name in TOOLKIT_ELFS:
                prefix = source.read(64)
                require(len(prefix) == 64 and prefix[:6] == b"\x7fELF\x02\x01"
                        and int.from_bytes(prefix[18:20], "little") == 62,
                        "engine output is not an x86_64 ELF: " + name)
                source.seek(0)
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            require(unchanged(before, os.fstat(source.fileno())), "engine output changed")
            manifest["files"][name] = {"bytes": before.st_size, "sha256": digest}
            source.seek(0)
            opened[name] = (source, before)
        manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        require(len(manifest_bytes) <= TOOLKIT_MANIFEST_LIMIT, "engine artifact manifest exceeds bound")
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        with os.fdopen(fd, "wb") as destination:
            with tarfile.open(fileobj=destination, mode="w") as tar:
                for name, (source, before) in opened.items():
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = before.st_size, 0o400
                    tar.addfile(member, source)
                    require(unchanged(before, os.fstat(source.fileno())),
                            "engine artifact changed while sealing")
                member = tarfile.TarInfo("engine-manifest.json")
                member.size, member.mode = len(manifest_bytes), 0o400
                tar.addfile(member, io.BytesIO(manifest_bytes))
            destination.flush()
            os.fsync(destination.fileno())
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    require(0 < archive.stat().st_size <= FILE_LIMIT, "engine archive exceeds bound")
    return digest, manifest_bytes


def build_engine(engine, framework, env, pin, patch_bytes, context, toolkit):
    """Explicit integration build; no workload or deadline expansion in prepare()."""
    deadline = time.monotonic() + 7200
    publisher = "/authority/publish.py"
    require(command(["/usr/bin/python3", "-I", "-S", publisher, "--self-test"], "/work", env, deadline)
            == b"publish-artifact-result self-test: ok\n", "engine publication tests did not pass")
    print("ENGINE_ARTIFACT_PUBLICATION_TEST=pass contracts=4 filesystem=real cleanup=joined", flush=True)
    output = Path(engine) / "out/host_release"
    ninja = framework + "/third_party/ninja/ninja"
    header_description = json.loads(command([
        "flutter/third_party/gn/gn", "desc", "out/host_release",
        "//flutter/shell/platform/linux:publish_headers_linux", "outputs",
        "--format=json", "--script-executable=/usr/bin/python3",
    ], engine, env, deadline))
    require(type(header_description) is dict and set(header_description)
            == {"//flutter/shell/platform/linux:publish_headers_linux"},
            "GN header target description differs: " + repr(header_description))
    header_record = header_description["//flutter/shell/platform/linux:publish_headers_linux"]
    require(type(header_record) is dict and set(header_record) == {"outputs", "output_patterns"}
            and header_record["output_patterns"]
                == ["//out/host_release/flutter_linux/{{source_file_part}}"],
            "GN header output pattern differs: " + repr(header_record))
    header_outputs = header_record["outputs"]
    public_headers = (Path(engine) / "flutter/shell/platform/linux/BUILD.gn").read_text()
    declared = re.findall(r'"public/flutter_linux/([a-z0-9_]+\.h)"',
                          public_headers.split("_public_headers = [", 1)[1].split("]", 1)[0])
    require(len(declared) == len(set(declared)) == 26
            and sorted(line.strip() for line in header_outputs)
                == sorted("//out/host_release/flutter_linux/" + name for name in declared),
            "original GN public header outputs differ: " + repr(header_record))
    targets = ["libflutter_linux_gtk.so", "gen_snapshot", *toolkit["targets"],
               *["flutter_linux/" + name for name in sorted(declared)]]
    plan = command([ninja, "-C", str(output), "-n", *targets], engine, env, deadline,
                   integration=True)
    require(plan and len(plan.splitlines()) <= 32768, "engine link plan is empty or exceeds bound")
    print("ENGINE_BUILD_START targets=linux-release-toolkit jobs=4 plan_lines="
          + str(len(plan.splitlines())) + " plan_sha256=" + hashlib.sha256(plan).hexdigest(), flush=True)
    result = command([ninja, "-C", str(output), "-j4", *targets], engine, env, deadline,
                     integration=True)
    print("ENGINE_BUILD_COMMAND=pass output_bytes=" + str(len(result))
          + " output_sha256=" + hashlib.sha256(result).hexdigest(), flush=True)
    # A second dry run must prove all selected original recipes are current.
    require(command([ninja, "-C", str(output), "-n", *targets], engine, env, deadline)
            .splitlines()[-1:] == [b"ninja: no work to do."], "engine targets are not current")
    names = ["libflutter_linux_gtk.so", "gen_snapshot",
             *[name for name in toolkit["targets"] if not name.endswith(".stamp")]]
    header_paths = sorted((output / "flutter_linux").glob("*.h"))
    require([path.name for path in header_paths] == sorted(declared)
            and all(path.is_file() and not path.is_symlink() for path in header_paths),
            "engine public header inventory differs")
    names.extend("flutter_linux/" + path.name for path in header_paths)
    copies = {**toolkit["copies"],
              **{"flutter_linux/" + name: Path(engine) / "flutter/shell/platform/linux/public/flutter_linux" / name
                 for name in declared}}
    sky_root = output / "gen/dart-pkg/sky_engine"
    require(sky_root.is_dir() and not sky_root.is_symlink(), "generated sky_engine package is absent")
    for parent, directories, files in os.walk(sky_root, followlinks=False):
        directories.sort()
        require(not any((Path(parent) / name).is_symlink() for name in directories),
                "generated sky_engine directory is a link")
        for name in sorted(files):
            path = (Path(parent) / name).relative_to(output).as_posix()
            require(parts(path), "generated sky_engine path differs")
            names.append(path)
            require(len(names) <= TOOLKIT_ENTRY_LIMIT, "generated toolkit inventory exceeds bound")
    require(all("gen/dart-pkg/sky_engine/" + name in names for name in
                ("pubspec.yaml", "lib/_embedder.yaml", "lib/ui/ui.dart")),
            "generated sky_engine required files are absent")
    manifest = {
        "format": "rustdesk-flutter-linux-engine-artifact-v2",
        "profile": "linux-x64-release-toolkit",
        "source_commit": context[0], "source_tree": context[1],
        "framework_revision": pin("FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION"),
        "original_source_content_hash": pin("FLUTTER_ENGINE_SOURCE_CONTENT_HASH"),
        "graph_manifest_sha256": pin("SHA256_FLUTTER_ENGINE_GRAPH_MANIFEST"),
        "metadata_manifest_sha256": pin("SHA256_FLUTTER_ENGINE_GIT_METADATA_MANIFEST"),
        "sysroots_manifest_sha256": pin("SHA256_FLUTTER_ENGINE_SYSROOTS_MANIFEST"),
        "builder_config": pin("DEV_CHECK_IMAGE_CONFIG_ID"),
        "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "patch_sha256": hashlib.sha256(patch_bytes).hexdigest(),
        "bootstrap_workspace_patch_sha256": hashlib.sha256(BOOTSTRAP_WORKSPACE_PATCH).hexdigest(),
        "gn_args_sha256": hashlib.sha256((output / "args.gn").read_bytes()).hexdigest(),
        "gn_args": (output / "args.gn").read_text(),
        "toolkit_graph_sha256": toolkit["graph_sha256"],
        "bootstrap_sdk_archive_sha256": pin("SHA256_FLUTTER_PRESENTATION_CANDIDATE"),
        "dart_sdk_input": toolkit["dart_sdk_input"],
        "bootstrap_sdk_projection": "unexecuted",
        "targets": targets, "files": {}, "app_execution": "unexecuted",
    }
    archive = Path("/work/flutter-linux-engine.tar")
    digest, manifest_bytes = seal_engine_outputs(
        output, copies, names, manifest, archive)
    # Publication is inert data into the exact private output, never host code.
    output_root = "/output"
    before = os.lstat(output_root)
    require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 1000
            and stat.S_IMODE(before.st_mode) == 0o700 and not os.listdir(output_root),
            "engine publication root authority differs")
    preparation = command([
        "/usr/bin/python3", "-I", "-S", publisher, "--prepare",
        "--artifact-kind", "flutter-linux-engine", "--source", str(archive),
        "--source-identity", str(archive.stat().st_dev) + ":" + str(archive.stat().st_ino),
        "--source-sha256", digest, "--output-parent", output_root,
        "--output-parent-identity", str(before.st_dev) + ":" + str(before.st_ino),
        "--destination", "linux-x86_64-engine",
    ], "/work", env, deadline).decode().strip()
    require(re.fullmatch(r"\.flutter-engine-output-pending-[0-9a-f]{64} [0-9]+:[1-9][0-9]*",
                         preparation), "engine artifact preparation receipt differs")
    print("FLUTTER_ENGINE_ARTIFACT_PREPARED=pass commit=" + context[0] + " tree=" + context[1]
          + " pending=" + preparation.split()[0] + " sha256=" + digest
          + " manifest_sha256=" + hashlib.sha256(manifest_bytes).hexdigest()
          + " bytes=" + str(archive.stat().st_size) + " files=" + str(len(names))
          + " app_execution=unexecuted", flush=True)


def engine_output_self_test():
    def refused(action):
        try:
            action()
        except (ValueError, OSError):
            return
        raise ValueError("unsafe engine output was admitted")

    with tempfile.TemporaryDirectory(prefix="engine-output-", dir="/work") as root:
        root = Path(root)
        output, public = root / "out", root / "public"
        for parent in (output, public):
            (parent / "flutter_linux").mkdir(parents=True, mode=0o700)
        name = "flutter_linux/fl_application.h"
        original, generated = public / name, output / name
        copies = {name: original}
        original.write_bytes(b"source-selected header\n")
        os.link(original, generated)

        def read(name=name):
            with engine_output(output, copies, name) as (source, before):
                require(source.read() and before.st_size > 0, "engine output data was lost")

        read()
        require(original.stat().st_nlink == generated.stat().st_nlink == 2,
                "GN header fixture is not a real hardlink")
        alias = root / "alias"
        os.link(generated, alias)
        refused(read)
        alias.unlink()

        generated.unlink()
        os.link(original, alias)
        unrelated = root / "unrelated"
        unrelated.write_bytes(original.read_bytes())
        os.link(unrelated, generated)
        refused(read)
        generated.unlink()
        alias.unlink()
        os.link(original, generated)

        generated.unlink()
        generated.symlink_to(original)
        refused(read)
        generated.unlink()
        os.link(original, generated)

        def mutate():
            with engine_output(output, copies, name):
                original.write_bytes(b"changed through the source alias\n")
        refused(mutate)

        generated.unlink()
        generated.write_bytes(original.read_bytes())
        refused(read)

        binary = output / "gen_snapshot"
        binary.write_bytes(b"single-link compiled output")
        read("gen_snapshot")
        os.link(binary, alias)
        refused(lambda: read("gen_snapshot"))
        alias.unlink()
        generated.unlink()
        os.link(original, generated)
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (62).to_bytes(2, "little")
        binary.write_bytes(elf + b"snapshot fixture")
        library = output / "libflutter_linux_gtk.so"
        library.write_bytes(elf + b"GTK fixture")
        names = [library.name, binary.name, name]
        manifest = {"files": {}}
        archive = root / "engine.tar"
        digest, manifest_bytes = seal_engine_outputs(output, copies, names, manifest, archive)
        require(archive.stat().st_nlink == 1 and stat.S_IMODE(archive.stat().st_mode) == 0o400
                and hashlib.sha256(archive.read_bytes()).hexdigest() == digest,
                "engine archive authority or digest differs")
        with tarfile.open(archive, "r") as tar:
            members = tar.getmembers()
            require([member.name for member in members] == names + ["engine-manifest.json"]
                    and all(member.isreg() and member.mode == 0o400 and member.uid == member.gid == 0
                            and member.mtime == 0 and not member.linkname for member in members),
                    "engine archive preserved links or noncanonical metadata")
            for member in members:
                with tar.extractfile(member) as source:
                    data = source.read()
                if member.name == "engine-manifest.json":
                    require(data == manifest_bytes and json.loads(data) == manifest,
                            "engine manifest bytes differ")
                else:
                    require(data == (output / member.name).read_bytes()
                            and manifest["files"][member.name] == {
                                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
                            "engine archived output data differs")
        refused(lambda: seal_engine_outputs(output, copies, names, manifest, archive))
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == digest,
                "engine archive collision changed retained data")
        sky = output / "gen/dart-pkg/sky_engine"
        (sky / "lib/ui").mkdir(parents=True, mode=0o700)
        (sky / "lib/ui/ui.dart").write_bytes(b"generated Dart UI fixture\n")
        refused(lambda: read("gen/dart-pkg/sky_engine/../../outside"))
        linked = output / "gen/dart-pkg/linked"
        linked.symlink_to(sky, target_is_directory=True)
        def read_linked_directory():
            with engine_file(linked / "lib/ui/ui.dart") as source:
                source.read()
        refused(read_linked_directory)
        (output / "flutter_patched_sdk").mkdir(mode=0o700)
        for filename in ("platform_strong.dill", "vm_outline_strong.dill"):
            (output / "flutter_patched_sdk" / filename).write_bytes(b"platform fixture")
        icu = public / "icudtl.dat"
        icu.write_bytes(b"source-selected ICU fixture")
        os.link(icu, output / "icudtl.dat")
        copies["icudtl.dat"] = icu
        names += ["gen/dart-pkg/sky_engine/lib/ui/ui.dart", "icudtl.dat",
                  "flutter_patched_sdk/platform_strong.dill",
                  "flutter_patched_sdk/vm_outline_strong.dill"]
        archive = root / "toolkit.tar"
        digest, manifest_bytes = seal_engine_outputs(output, copies, names, {"files": {}}, archive)
        with tarfile.open(archive, "r") as tar:
            require([member.name for member in tar] == names + ["engine-manifest.json"],
                    "toolkit namespaces lost files while sealing")
        refused(lambda: seal_engine_outputs(output, copies, names + [names[-1]], {}, root / "duplicate.tar"))
        require(not (root / "duplicate.tar").exists(), "duplicate output created an archive")
    print("ENGINE_ARTIFACT_INPUT_TEST=pass cases=10 headers=source-bound "
          "compiled=single-link mutation=refused archive=regular noclobber=refused cleanup=joined",
          flush=True)
    print("ENGINE_TOOLKIT_INPUT_TEST=pass namespaces=preserved copied_icu=source-bound "
          "directory_links=refused traversal=refused duplicates=refused cleanup=joined", flush=True)


def self_test():
    def archive(entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            for name, kind, value, *mode in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = mode[0] if mode else 0o644
                if kind == tarfile.REGTYPE:
                    member.size = len(value)
                    tar.addfile(member, io.BytesIO(value))
                else:
                    member.linkname = value
                    tar.addfile(member)
        output.seek(0)
        return output

    positive = [("usr/bin/tool", tarfile.REGTYPE, b"original", 0o6755),
                ("bin", tarfile.SYMTYPE, "usr/bin"),
                ("usr/bin/alias", tarfile.LNKTYPE, "./usr/bin/tool"),
                (r"lib/systemd/system/system-systemd\x2dcryptsetup.slice", tarfile.REGTYPE, b"unit"),
                ("var/local", tarfile.DIRTYPE, "", 0o2755)]
    negatives = [
        [("../escape", tarfile.REGTYPE, b"x")],
        [("/escape", tarfile.REGTYPE, b"x")],
        [("alias", tarfile.SYMTYPE, "../escape")],
        [("alias", tarfile.LNKTYPE, "../escape")],
        [("alias", tarfile.LNKTYPE, "missing")],
        [("file", tarfile.REGTYPE, b"one"), ("file", tarfile.REGTYPE, b"two")],
        [("dir/file", tarfile.REGTYPE, b"x"), ("dir", tarfile.SYMTYPE, "inside")],
        [("loop", tarfile.SYMTYPE, "loop")],
        [("fifo", tarfile.FIFOTYPE, "")],
    ]
    with tempfile.TemporaryDirectory(prefix="engine-extraction-", dir="/work") as root:
        for index, entries in enumerate([positive] + negatives):
            case = Path(root) / str(index)
            case.mkdir(mode=0o700)
            tree = Tree(case)
            try:
                try:
                    tree.unpack(archive(entries), ("sysroot",))
                    tree.finish_links()
                except (ValueError, OSError):
                    require(index != 0, "legitimate merged-directory/hardlink archive was refused")
                else:
                    require(index == 0, "unsafe archive was admitted")
                    tool = case / "sysroot/usr/bin/tool"
                    alias = case / "sysroot/usr/bin/alias"
                    require(tool.read_bytes() == b"original" and os.stat(tool).st_ino == os.stat(alias).st_ino
                            and os.stat(tool).st_nlink == 2 and os.readlink(case / "sysroot/bin") == "usr/bin",
                            "legitimate links lost their semantics")
                    require(stat.S_IMODE(os.stat(tool).st_mode) == 0o755
                            and stat.S_IMODE(os.stat(case / "sysroot/var/local").st_mode) == 0o700,
                            "archive privilege bits reached the materialized tree")
                    require((case / "sysroot" / r"lib/systemd/system/system-systemd\x2dcryptsetup.slice")
                            .read_bytes() == b"unit", "literal Linux backslash filename changed")
            finally:
                tree.close()
    print("ENGINE_PREPARE_EXTRACTION_TEST=pass cases=10 links=preserved unsafe=refused cleanup=joined", flush=True)


def main():
    build_context = None
    if len(sys.argv) == 4 and sys.argv[1] == "--build":
        require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in sys.argv[2:]),
                "engine build source identity differs")
        build_context = sys.argv[2:]
    else:
        require(sys.argv == [sys.argv[0]], "engine preparation takes no caller-selected paths or commands")
    require(os.getuid() == os.getgid() == 1000, "engine preparation requires UID/GID 1000")
    status = Path("/proc/self/status").read_text()
    require(re.search(r"^CapEff:\s+0000000000000000$", status, re.MULTILINE)
            and re.search(r"^NoNewPrivs:\s+1$", status, re.MULTILINE)
            and re.search(r"^Seccomp:\s+2$", status, re.MULTILINE)
            and os.listdir("/sys/class/net") == ["lo"], "engine preparation confinement differs")
    require(Path("/proc/self/attr/current").read_text().startswith("docker-default "),
            "engine preparation AppArmor profile differs")
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    self_test()
    engine_output_self_test()
    prepare(build_context)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        raise SystemExit("engine preparation: " + str(error))

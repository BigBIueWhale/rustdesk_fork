#!/usr/bin/env python3
"""Materialize authenticated engine inputs and run their original hooks offline."""

import hashlib
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


def command(arguments, cwd, env, deadline):
    require(time.monotonic() < deadline, "engine preparation deadline expired")
    child = subprocess.Popen(arguments, cwd=cwd, env=env, close_fds=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    output = bytearray()
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
                    require(len(output) <= 262144, "engine preparation command output exceeds bound")
        status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(status == 0, "engine command failed: " + repr(arguments) + "\n"
                + output[:65536].decode(errors="replace"))
        return bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        selector.close()


def prepare():
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
        output = command([binary], engine, env, deadline)
        expected = ("ENGINE_ACCESSIBLE_RETIREMENT_BASELINE=observed parent=gone engine=live action=dispatched"
                    if baseline else "ENGINE_ACCESSIBLE_RETIREMENT=pass unit=real-node boundary=recording-engine "
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
                    "caller_release=joined late_edits=refused")
        require(output == (expected + "\n").encode(), "native node retirement receipt differs")
        print(expected, flush=True)

    node_test(True)
    patch_path = Path("/authority/retirement.patch")
    patch_bytes = patch_path.read_bytes()
    require(0 < len(patch_bytes) <= 96 * 1024, "retirement patch exceeds bound")
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
                       "fl_view.cc", "fl_view_accessible.cc", "fl_view_accessible.h")]
    changed = command(git + ["diff", "--name-only", "--", "engine/src/flutter/shell/platform/linux"],
                      framework, env, deadline).decode().splitlines()
    changed += command(git + ["ls-files", "--others", "--exclude-standard", "--",
                              "engine/src/flutter/shell/platform/linux"],
                       framework, env, deadline).decode().splitlines()
    require(sorted(changed) == sorted(expected_paths), "retirement patch source scope differs")
    command(git + ["diff", "--check"], framework, env, deadline)
    print("ENGINE_ACCESSIBLE_RETIREMENT_PATCH=applied sha256="
          + hashlib.sha256(patch_bytes).hexdigest() + " files=12 sdk_archive=unchanged", flush=True)
    objects.append("obj/flutter/shell/platform/linux/flutter_linux_sources.fl_semantics_generation.o")
    upstream_tests = ["obj/flutter/shell/platform/linux/flutter_linux_unittests." + unit + ".o"
                      for unit in ("fl_accessible_node_test", "fl_accessible_text_field_test")]
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
    print("ENGINE_ACCESSIBLE_RETIREMENT_COMPILE=pass production_units=8 upstream_test_objects=2 "
          "view_teardown=unexecuted engine_restart=unexecuted app_replay=unexecuted", flush=True)
    print("FLUTTER_ENGINE_PREPARE=pass git=82 cipd=11 metadata=3 sysroots=3 hooks=6 "
          "indexes=original pub=path-only network=none engine_build=unexecuted", flush=True)


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
    prepare()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        raise SystemExit("engine preparation: " + str(error))

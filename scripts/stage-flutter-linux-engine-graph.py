#!/usr/bin/env python3
"""Acquire the selected Linux engine source/package graph; never run its hooks."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import runpy
import selectors
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


common = runpy.run_path("/bootstrap-common.py", run_name="bootstrap_common")
require = common["require"]
FILE_LIMIT = 4 * 1024 ** 3
TOTAL_LIMIT = 24 * 1024 ** 3
VULKAN = "engine/src/flutter/third_party/vulkan-deps"
HOSTS = frozenset(("boringssl.googlesource.com", "chromium.googlesource.com",
                  "dart.googlesource.com", "flutter.googlesource.com",
                  "llvm.googlesource.com", "skia.googlesource.com",
                  "swiftshader.googlesource.com"))
OVERRIDES = {"download_android_deps": False, "download_fuchsia_deps": False,
             "download_fuchsia_sdk": False, "run_fuchsia_emu": False,
             "download_windows_deps": False, "download_emsdk": False,
             "download_linux_deps": True, "setup_githooks": False, "use_rbe": False}
BUILTINS = {"host_os": "linux", "host_cpu": "x64"}
BUILTINS.update({"checkout_" + name: name == "linux" for name in
                ("android", "chromeos", "fuchsia", "ios", "linux", "mac", "win")})
BUILTINS.update({"checkout_" + name: name == "x64" for name in
                ("arm", "arm64", "x86", "mips", "mips64", "ppc", "s390", "x64")})
DEADLINE = time.monotonic() + 3000


def relative(value, destination=True):
    require(isinstance(value, str), "non-string dependency path")
    path = PurePosixPath(value)
    require(0 < len(value.encode("utf-8")) <= 512
            and str(path) == value and not path.is_absolute()
            and all(part not in (".", "..") for part in path.parts)
            and len(path.parts) <= 32
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
            and "\\" not in value
            and (not destination or re.fullmatch(r"[A-Za-z0-9_./-]+", value)),
            "invalid dependency destination")
    return value


def unchanged(before, after):
    return all(getattr(before, name) == getattr(after, name) for name in
               ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns"))


def artifact_budget(total):
    # Reserve the bounded manifest before allowing another archive to grow.
    remaining = TOTAL_LIMIT - 1048576 - total
    require(remaining > 0, "graph output budget exhausted")
    resource.setrlimit(resource.RLIMIT_FSIZE, (min(FILE_LIMIT, remaining), FILE_LIMIT))


def environment():
    return {"PATH": "/usr/bin:/bin", "HOME": "/work", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ALLOW_PROTOCOL": "https",
            "DEPOT_TOOLS_UPDATE": "0", "DEPOT_TOOLS_METRICS": "0",
            "DEPOT_TOOLS_COLLECT_METRICS": "0", "PYTHONDONTWRITEBYTECODE": "1"}


def command(arguments, cwd="/work", output=None):
    """Bound pipe bytes and elapsed time; every direct child is joined on failure."""
    timeout = min(240, DEADLINE - time.monotonic())
    require(timeout > 0, "engine graph acquisition deadline expired")
    process = subprocess.Popen(arguments, cwd=cwd, env=environment(),
                               stdout=output if output is not None else subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True)
    streams = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    end = time.monotonic() + timeout
    try:
        for name in buffers:
            stream = getattr(process, name)
            if stream is not None:
                streams.register(stream, selectors.EVENT_READ, name)
        while streams.get_map():
            remaining = end - time.monotonic()
            require(remaining > 0, "engine graph command deadline expired")
            for key, _ in streams.select(min(remaining, 1)):
                data = os.read(key.fd, 65536)
                if not data:
                    streams.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(data)
                require(len(buffers[key.data]) <= 262144,
                        "engine graph command output exceeds bound")
        status = process.wait(timeout=max(0.001, end - time.monotonic()))
        require(status == 0, "engine graph command failed: " +
                buffers["stderr"][:4096].decode("utf-8", errors="replace"))
        return bytes(buffers["stdout"])
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        streams.close()
        for name in buffers:
            stream = getattr(process, name)
            if stream is not None:
                stream.close()


def git(work, *arguments, output=None):
    return command(["/usr/bin/git", "--no-replace-objects",
                    "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "-c", "credential.helper=", "-c", "http.followRedirects=false",
                    "-c", "http.sslVerify=true", "-c", "fetch.fsckObjects=true",
                    "-c", "transfer.fsckObjects=true", "-c", "core.autocrlf=false",
                    *arguments], cwd=work, output=output)


def plain(value):
    if hasattr(value, "items"):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    require(value is None or isinstance(value, (str, bool, int)),
            "unexpected parsed dependency value")
    return value


def digest_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and before.st_gid == os.getgid()
                and 0 < before.st_size <= FILE_LIMIT, "graph artifact authority differs")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        require(unchanged(before, os.fstat(source.fileno())), "graph artifact changed")
        os.fchmod(source.fileno(), 0o400)
        os.fsync(source.fileno())
    return {"bytes": before.st_size, "sha256": digest, "file": Path(path).name}


def cipd_receipt(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and before.st_gid == os.getgid()
                and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= 262144, "CIPD receipt authority or size differs")
        payload = source.read(262145)
        require(len(payload) == before.st_size
                and unchanged(before, os.fstat(source.fileno())), "CIPD receipt changed")
    receipt = json.loads(payload)
    require(isinstance(receipt, dict) and set(receipt) == {"result"}, "CIPD receipt failed")
    return receipt["result"]


def resolve_packages(packages):
    # Resolve the small exact pin receipt, not an unbounded instance description.
    for number, package in enumerate(packages):
        expanded = command(["/work/cipd", "expand-package-name", package["package"]]).decode().strip()
        relative(expanded)
        print("ENGINE_GRAPH_RESOLVE=" + expanded, flush=True)
        filename = "/work/resolve-%03d.json" % number
        command(["/work/cipd", "resolve", expanded, "-version", package["version"],
                 "-json-output", filename, "-log-level", "error"])
        result = cipd_receipt(filename)
        require(isinstance(result, dict) and set(result) == {""}
                and isinstance(result[""], list) and len(result[""]) == 1,
                "CIPD resolution inventory differs")
        entry = result[""][0]
        require(isinstance(entry, dict) and set(entry) == {"package", "pin"}
                and entry["package"] == expanded, "CIPD resolution package differs")
        pin = entry["pin"]
        require(isinstance(pin, dict) and set(pin) == {"package", "instance_id"}
                and pin["package"] == expanded
                and re.fullmatch(r"(?:[0-9a-f]{40}|[A-Za-z0-9_-]{43}C)", pin["instance_id"]),
                "resolved package identity differs")
        package.update({"package_pattern": package["package"],
                        "package": expanded, "instance_id": pin["instance_id"]})


def unpack_parser(archive):
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for member in source:
            name = relative(member.name.rstrip("/"), destination=False)
            require(name.startswith("depot_tools/") or name == "depot_tools",
                    "parser archive prefix differs")
            require(name not in names and len(names) < 16384
                    and (member.isdir() or member.isfile() or member.issym()),
                    "parser archive inventory differs")
            names.add(name)
            if member.issym():
                continue  # No wrapper/alias is needed to import the regular Python source.
            destination = Path("/work") / name
            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            total += member.size
            require(0 <= member.size <= 67108864 and total <= 67108864,
                    "parser archive exceeds bound")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.extractfile(member) as data, open(destination, "xb") as output:
                payload = data.read(member.size + 1)
                require(len(payload) == member.size, "truncated parser source")
                output.write(payload)
            os.chmod(destination, 0o400)
    sys.path.insert(0, "/work/depot_tools")
    import gclient_eval
    return gclient_eval


def collect(parser, text, prefix="", parent=None):
    parsed = parser.Parse(text, prefix + "/DEPS", vars_override=OVERRIDES,
                          builtin_vars=BUILTINS)
    values = dict(parsed.get("vars", {}))
    values.update(parent or {})
    values.update(BUILTINS)
    values.update(OVERRIDES)
    require(parsed.get("git_dependencies", "DEPS") in ("DEPS", "SYNC")
            and not parsed.get("pre_deps_hooks") and not parsed.get("deps_os"),
            "unexpected source graph semantics")
    require(bool(parsed.get("use_relative_paths", False)) == bool(prefix),
            "dependency path basis differs")
    git_entries, packages = [], []
    for name, entry in parsed.get("deps", {}).items():
        require(entry is not None, "unexpected omitted dependency")
        if entry.get("condition") and not parser.EvaluateCondition(entry["condition"], values):
            continue
        destination = relative((prefix + "/" if prefix else "") + relative(name))
        if entry["dep_type"] == "git":
            url, separator, revision = entry["url"].rpartition("@")
            from urllib.parse import urlsplit
            parsed_url = urlsplit(url)
            require(separator and re.fullmatch("[0-9a-f]{40}", revision)
                    and parsed_url.scheme == "https" and parsed_url.netloc in HOSTS
                    and parsed_url.path.startswith("/") and not parsed_url.query
                    and not parsed_url.fragment, "unapproved Git dependency")
            git_entries.append({"destination": destination, "url": url, "revision": revision})
        else:
            require(entry["dep_type"] == "cipd", "unknown dependency type")
            for package in entry["packages"]:
                require(re.fullmatch(r"[a-z0-9][a-z0-9_./${}-]{0,255}", package["package"])
                        and 0 < len(package["version"]) <= 256
                        and re.fullmatch(r"[A-Za-z0-9_:@.+-]+", package["version"]),
                        "invalid CIPD selector")
                packages.append({"destination": destination, **plain(package)})
    require(len(git_entries) + len(packages) <= 256, "dependency graph exceeds bound")
    hooks = [plain(hook) for hook in parsed.get("hooks", [])
             if not hook.get("condition") or parser.EvaluateCondition(hook["condition"], values)]
    return git_entries, packages, hooks, values, parsed


def acquire_git(entry, number, record, output_root, total):
    print("ENGINE_GRAPH_GIT=" + entry["destination"], flush=True)
    with tempfile.TemporaryDirectory(prefix="git-", dir="/work") as work:
        git(work, "init", "--bare", "--template=", work)
        git(work, "fetch", "--quiet", "--no-progress", "--depth=1", "--no-tags",
            entry["url"], entry["revision"])
        object_type = git(work, "cat-file", "-t", entry["revision"]).decode().strip()
        require(object_type in ("commit", "tag"), "dependency pin is not a commit or tag object")
        commit = git(work, "rev-parse", entry["revision"] + "^{commit}").decode().strip()
        require(re.fullmatch("[0-9a-f]{40}", commit)
                and git(work, "rev-parse", "FETCH_HEAD^{commit}").decode().strip() == commit,
                "fetched dependency does not match the exact pinned object")
        require(object_type != "commit" or commit == entry["revision"], "dependency commit differs")
        tree = git(work, "rev-parse", commit + "^{tree}").decode().strip()
        require(re.fullmatch("[0-9a-f]{40}", tree), "dependency tree is malformed")
        git(work, "fsck", "--strict", "--no-reflogs")
        deps = None
        if entry["destination"] in (".", VULKAN):
            deps = git(work, "show", commit + ":DEPS").decode("utf-8")
        if entry["destination"] == ".":
            require(deps == record["deps"]["text"], "framework root DEPS differs")
        filename = "git-%03d.tar" % number
        prefix = "flutter/" + (entry["destination"] + "/" if entry["destination"] != "." else "")
        artifact_budget(total)
        try:
            with common["output_file"](output_root, filename) as output:
                git(work, "archive", "--format=tar", "--prefix=" + prefix,
                    commit, output=output)
                output.flush()
                os.fsync(output.fileno())
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    return {**entry, "object_type": object_type, "commit": commit,
            "tree": tree, **digest_file("/output/" + filename)}, deps


def package_archive(root, path, epoch, total):
    entries = []
    def traversal_error(error):
        raise error
    for directory, children, files in os.walk(root, followlinks=False, onerror=traversal_error):
        if Path(directory) == root:
            children[:] = [name for name in children if name != ".cipd"]
            files[:] = [name for name in files if name != ".cipd"]
        for name in children + files:
            entry = Path(directory) / name
            relative(entry.relative_to(root).as_posix(), destination=False)
            require(len(entries) < 262144, "CIPD package inventory exceeds bound")
            entries.append(entry)
    entries.sort(key=lambda entry: entry.relative_to(root).as_posix())
    require(0 < len(entries) <= 262144, "CIPD package inventory exceeds bound")
    artifact_budget(total)
    try:
        write_package_archive(entries, root, path, epoch)
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))


def write_package_archive(entries, root, path, epoch):
    with open(path, "xb") as output, tarfile.open(fileobj=output, mode="w:",
                                               format=tarfile.GNU_FORMAT) as archive:
        for entry in entries:
            name = relative(entry.relative_to(root).as_posix(), destination=False)
            before = entry.lstat()
            require(before.st_uid == os.getuid() and before.st_gid == os.getgid()
                    and not before.st_mode & 0o6000, "CIPD entry principal or mode differs")
            info = archive.gettarinfo(str(entry), arcname=name)
            require(info.isdir() or info.isfile() or info.issym(), "special CIPD package entry")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.mode = 0o755 if info.isdir() or before.st_mode & 0o111 else 0o644
            if info.issym():
                target = PurePosixPath(info.linkname)
                require(0 < len(info.linkname.encode()) <= 512 and not target.is_absolute()
                        and "\\" not in info.linkname
                        and not any(ord(char) < 32 or ord(char) == 127 for char in info.linkname),
                        "invalid CIPD package symlink")
                parts = list(PurePosixPath(name).parent.parts)
                for part in target.parts:
                    if part == "..":
                        require(parts, "escaping CIPD package symlink")
                        parts.pop()
                    elif part != ".":
                        parts.append(part)
                archive.addfile(info)
            elif info.isfile():
                require(before.st_nlink == 1, "hardlinked CIPD package file")
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as source:
                    require(unchanged(before, os.fstat(source.fileno())), "CIPD package file changed")
                    archive.addfile(info, source)
                    require(unchanged(before, os.fstat(source.fileno())), "CIPD package file changed")
            else:
                archive.addfile(info)
            require(unchanged(before, entry.lstat()), "CIPD package entry changed")


def metadata_graph(args):
    graph = json.loads(common["read_file"]("/graph-manifest.json", args.graph_manifest_size,
                                          args.graph_manifest_sha256))
    require(graph["format"] == "rustdesk-flutter-linux-engine-graph-v1"
            and graph["source_commit"] == args.graph_source_commit
            and graph["framework_revision"] == args.framework_revision
            and graph["discovery_sha256"] == args.discovery_sha256
            and graph["tools_manifest_sha256"] == args.tools_manifest_sha256
            and graph["source_date_epoch"] == args.epoch
            and graph["complete_engine_closure"] is False
            and graph["hooks_executed"] is False
            and len(graph["git"]) == 82 and len(graph["cipd"]) == 11,
            "independent engine graph context differs")
    roles = ((".", "https://github.com/flutter/flutter.git"),
             ("engine/src/flutter/third_party/dart", "https://dart.googlesource.com/sdk.git"),
             ("engine/src/flutter/third_party/skia", "https://skia.googlesource.com/skia.git"))
    selected = []
    for destination, url in roles:
        entries = [entry for entry in graph["git"] if entry["destination"] == destination]
        require(len(entries) == 1, "Git metadata source is absent or ambiguous")
        entry = entries[0]
        require(entry["url"] == url and entry["object_type"] == "commit"
                and entry["revision"] == entry["commit"]
                and re.fullmatch("[0-9a-f]{40}", entry["commit"])
                and re.fullmatch("[0-9a-f]{40}", entry["tree"]),
                "Git metadata source pin differs")
        selected.append(entry)
    require(selected[0]["commit"] == args.framework_revision, "root metadata revision differs")
    return selected


def copy_metadata_file(source_path, destination):
    fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source, open(destination, "xb") as output:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (before.st_uid, before.st_gid) == (os.getuid(), os.getgid())
                and 0 < before.st_size <= FILE_LIMIT, "Git metadata file authority differs")
        digest = hashlib.sha256()
        count = 0
        while True:
            block = source.read(1048576)
            if not block:
                break
            count += len(block)
            require(count <= before.st_size, "Git metadata file grew")
            output.write(block)
            digest.update(block)
        require(count == before.st_size and unchanged(before, os.fstat(source.fileno())),
                "Git metadata file changed")
    return {"bytes": count, "sha256": digest.hexdigest()}


def restore_metadata(path, destination, files, epoch):
    # Fixed inventory: no generic extraction, links, hooks, config includes or alternates.
    directories = {".git", ".git/objects", ".git/objects/pack", ".git/refs"}
    seen = set()
    with tarfile.open(path, "r:") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            require(name in directories | set(files) and name not in seen
                    and member.uid == 0 and member.gid == 0 and member.mtime == epoch
                    and not member.pax_headers, "Git metadata archive inventory differs")
            seen.add(name)
            target = destination / name
            if name in directories:
                require(member.isdir() and member.mode == 0o755 and member.size == 0,
                        "Git metadata directory differs")
                target.mkdir(mode=0o700)
            else:
                expected = files[name]
                require(member.isfile() and member.mode == 0o644
                        and member.size == expected["bytes"], "Git metadata archive file differs")
                with archive.extractfile(member) as source, open(target, "xb") as output:
                    digest = hashlib.sha256()
                    count = 0
                    while True:
                        block = source.read(1048576)
                        if not block:
                            break
                        count += len(block)
                        require(count <= expected["bytes"], "Git metadata restore exceeds bound")
                        digest.update(block)
                        output.write(block)
                    require(count == expected["bytes"] and digest.hexdigest() == expected["sha256"],
                            "Git metadata restore bytes differ")
    require(seen == directories | set(files), "Git metadata archive is incomplete")


def acquire_metadata(args, selected, output_root):
    artifacts, total = [], 0
    for number, entry in enumerate(selected):
        print("ENGINE_GIT_METADATA_FETCH=" + entry["destination"], flush=True)
        with tempfile.TemporaryDirectory(prefix="metadata-", dir="/work") as temporary:
            work = Path(temporary)
            fetched = work / "fetched.git"
            fetched.mkdir(mode=0o700)
            git(fetched, "init", "--bare", "--template=", str(fetched))
            git(fetched, "fetch", "--quiet", "--no-progress", "--depth=1", "--no-tags",
                entry["url"], entry["commit"])
            require(git(fetched, "rev-parse", "FETCH_HEAD^{commit}").decode().strip() == entry["commit"]
                    and git(fetched, "rev-parse", entry["commit"] + "^{tree}").decode().strip() == entry["tree"]
                    and (fetched / "shallow").read_bytes() == (entry["commit"] + "\n").encode(),
                    "original Git commit/tree/shallow boundary differs")
            git(fetched, "update-ref", "--no-deref", "HEAD", entry["commit"])
            git(fetched, "fsck", "--strict", "--no-reflogs")
            timestamp = git(fetched, "log", "-1", "--format=%ct%n%cd%n%cD", "HEAD")
            git(fetched, "-c", "repack.writeBitmaps=false", "repack", "-a", "-d", "-f", "-F", "-n", "-q",
                "--threads=1", "--window=10", "--depth=50", "--window-memory=128m")
            packs = sorted((fetched / "objects/pack").iterdir())
            require(len(packs) == 2 and packs[0].suffix == ".idx" and packs[1].suffix == ".pack"
                    and packs[0].stem == packs[1].stem
                    and re.fullmatch(r"pack-[0-9a-f]{40}", packs[0].stem),
                    "original Git pack inventory differs")
            packaged = work / "packaged"
            packaged.mkdir(mode=0o700)
            for name in (".git", ".git/objects", ".git/objects/pack", ".git/refs"):
                (packaged / name).mkdir(mode=0o700)
            files = {}
            fixed = {".git/HEAD": (entry["commit"] + "\n").encode(),
                     ".git/shallow": (entry["commit"] + "\n").encode(),
                     ".git/config": b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = true\n"}
            for name, payload in fixed.items():
                with open(packaged / name, "xb") as output:
                    output.write(payload)
                files[name] = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            for pack in packs:
                name = ".git/objects/pack/" + pack.name
                files[name] = copy_metadata_file(pack, packaged / name)
            path = "/output/git-%03d.tar" % number
            package_archive(packaged, path, args.epoch, total)
            artifact = digest_file(path)
            total += artifact["bytes"]
            restored = work / "restored"
            restored.mkdir(mode=0o700)
            restore_metadata(path, restored, files, args.epoch)
            require(git(restored, "rev-parse", "HEAD").decode().strip() == entry["commit"]
                    and git(restored, "rev-parse", "HEAD^{tree}").decode().strip() == entry["tree"]
                    and git(restored, "log", "-1", "--format=%ct%n%cd%n%cD", "HEAD") == timestamp
                    and git(restored, "rev-list", "--count", "HEAD") == b"1\n"
                    and git(restored, "remote") == b"", "restored original Git identity differs")
            git(restored, "fsck", "--strict", "--no-reflogs")
            if entry["destination"] == ".":
                script = git(restored, "show", "HEAD:bin/internal/content_aware_hash.sh")
                require(0 < len(script) <= 16384, "original content-hash script exceeds bound")
                script_path = restored / "bin/internal/content_aware_hash.sh"
                script_path.parent.mkdir(mode=0o700, parents=True)
                with open(script_path, "xb") as output:
                    output.write(script)
                require(command(["/bin/bash", str(script_path)], cwd=restored).decode().strip()
                        == args.engine_content_hash, "restored original engine content hash differs")
            artifacts.append({"destination": entry["destination"], "url": entry["url"],
                              "commit": entry["commit"], "tree": entry["tree"],
                              "source_archive_sha256": entry["sha256"],
                              "original_timestamps": timestamp.decode().splitlines(),
                              "metadata_files": files, **artifact})
            print("ENGINE_GIT_METADATA_RESTORE=pass destination=" + entry["destination"]
                  + " commit=" + entry["commit"] + " tree=" + entry["tree"], flush=True)
    manifest = {"format": "rustdesk-flutter-linux-engine-git-metadata-v1",
                "source_commit": args.source_commit, "framework_revision": args.framework_revision,
                "discovery_sha256": args.discovery_sha256, "tools_manifest_sha256": args.tools_manifest_sha256,
                "graph_source_commit": args.graph_source_commit, "graph_manifest_sha256": args.graph_manifest_sha256,
                "engine_content_hash": args.engine_content_hash, "source_date_epoch": args.epoch,
                "git": artifacts, "cipd": [], "acquired_bytes": total,
                "complete_engine_closure": False, "hooks_executed": False}
    with common["output_file"](output_root, "manifest.json") as output:
        payload = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        require(len(payload) <= 1048576, "Git metadata manifest exceeds bound")
        output.write(payload)
        common["seal"](output)
    os.fsync(output_root)
    metadata_graph(args)
    common["discovery"](args)
    print("ENGINE_GIT_METADATA=pass git=3 restored=3 content_hash=" + args.engine_content_hash
          + " bytes=" + str(total) + " complete_engine_closure=no", flush=True)


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    for name in ("source-commit", "framework-revision", "discovery-sha256", "depot-revision",
                 "depot-tree", "cipd-version", "cipd-instance", "cipd-sha256",
                 "tools-source-commit", "tools-manifest-sha256"):
        arguments.add_argument("--" + name, required=True)
    for name in ("discovery-size", "tools-manifest-size", "epoch"):
        arguments.add_argument("--" + name, type=int, required=True)
    arguments.add_argument("--phase", choices=("graph", "git-metadata"), required=True)
    for name in ("graph-source-commit", "graph-manifest-sha256", "engine-content-hash"):
        arguments.add_argument("--" + name)
    arguments.add_argument("--graph-manifest-size", type=int)
    args = arguments.parse_args()
    require(os.getuid() != 0 and os.getgid() != 0, "root graph acquisition refused")
    require(0 <= args.epoch <= 2147483647, "invalid source epoch")
    for value in (args.source_commit, args.framework_revision, args.depot_revision,
                  args.depot_tree, args.tools_source_commit):
        require(re.fullmatch("[0-9a-f]{40}", value), "malformed graph source pin")
    for value in (args.discovery_sha256, args.cipd_sha256, args.tools_manifest_sha256):
        require(re.fullmatch("[0-9a-f]{64}", value), "malformed graph content pin")
    require(re.fullmatch("git_revision:[0-9a-f]{40}", args.cipd_version)
            and re.fullmatch("[A-Za-z0-9_-]{43}C", args.cipd_instance), "malformed client pin")
    if args.phase == "git-metadata":
        require(args.graph_source_commit is not None and args.engine_content_hash is not None
                and args.graph_manifest_sha256 is not None and args.graph_manifest_size is not None
                and re.fullmatch("[0-9a-f]{40}", args.graph_source_commit)
                and re.fullmatch("[0-9a-f]{40}", args.engine_content_hash)
                and re.fullmatch("[0-9a-f]{64}", args.graph_manifest_sha256)
                and 0 < args.graph_manifest_size <= 1048576, "independent graph pins are required")
        global FILE_LIMIT, TOTAL_LIMIT, DEADLINE
        FILE_LIMIT = 1024 ** 3
        TOTAL_LIMIT = 3 * 1024 ** 3
        DEADLINE = time.monotonic() + 600
    else:
        require(args.graph_source_commit is None and args.graph_manifest_sha256 is None
                and args.graph_manifest_size is None and args.engine_content_hash is None,
                "metadata pins are metadata-only")
    os.umask(0o077)
    sys.dont_write_bytecode = True
    os.environ.clear()
    os.environ.update(environment())
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    record = common["discovery"](args)
    roots = {}
    try:
        for name in (("output", "work") if args.phase == "git-metadata" else ("tools", "output", "work")):
            roots[name] = os.open("/" + name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            meta = os.fstat(roots[name])
            require((meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                    == (os.getuid(), os.getgid(), 0o700), "graph directory authority differs")
        require(not os.listdir(roots["output"]) and not os.listdir(roots["work"]),
                "graph workspace/output is occupied")
        if args.phase == "git-metadata":
            acquire_metadata(args, metadata_graph(args), roots["output"])
            return
        _, archive, client = common["tools"](args, roots["tools"], "/tools")
        parser = unpack_parser(archive)
        with open("/work/cipd", "xb") as output:
            output.write(client)
        os.chmod("/work/cipd", 0o500)
        root_sources, packages, hooks, values, parsed = collect(parser, record["deps"]["text"])
        require(parsed.get("recursedeps") == [VULKAN], "root graph recursion differs")
        root = {"destination": ".", "url": "https://github.com/flutter/flutter.git",
                "revision": args.framework_revision}
        sources = [root] + sorted(root_sources, key=lambda entry: entry["destination"])
        require(len({entry["destination"] for entry in sources}) == len(sources),
                "duplicate source destination")
        print("ENGINE_GRAPH_SELECTED=root-git:" + str(len(sources)) +
              " cipd:" + str(len(packages)) + " recursive:vulkan hooks:deferred", flush=True)
        # Resolve once before allocating source archives; installation never re-reads aliases.
        resolve_packages(packages)
        staged, total = [], 0
        for number, entry in enumerate(sources):
            artifact, deps = acquire_git(entry, number, record, roots["output"], total)
            staged.append(artifact)
            total += artifact["bytes"]
            require(total <= TOTAL_LIMIT, "graph output exceeds total bound")
            if entry["destination"] == VULKAN:
                children, extra_packages, child_hooks, _, child = collect(parser, deps, VULKAN, values)
                require(len(children) == 10 and not extra_packages and not child_hooks
                        and not child.get("recursedeps"), "recursive Vulkan graph differs")
                sources.extend(sorted(children, key=lambda item: item["destination"]))
                require(len({item["destination"] for item in sources}) == len(sources)
                        and len(sources) <= 256, "recursive source graph is ambiguous")
        package_artifacts = []
        for number, package in enumerate(packages):
            print("ENGINE_GRAPH_CIPD=" + package["package"] + "@" + package["instance_id"], flush=True)
            with tempfile.TemporaryDirectory(prefix="package-", dir="/work") as work:
                ensure = Path(work) / "ensure"
                ensure.write_text("$ParanoidMode CheckIntegrity\n$OverrideInstallMode copy\n" +
                                  package["package"] + " " + package["instance_id"] + "\n")
                installed = Path(work) / "root"
                installed.mkdir(mode=0o700)
                receipt = Path(work) / "receipt.json"
                command(["/work/cipd", "ensure", "-root", str(installed), "-ensure-file", str(ensure),
                         "-json-output", str(receipt), "-log-level", "error"])
                pins = cipd_receipt(receipt)
                require(pins == {"": [{"package": package["package"], "instance_id": package["instance_id"]}]},
                        "installed immutable package receipt differs")
                path = "/output/cipd-%03d.tar" % number
                package_archive(installed, path, args.epoch, total)
                artifact = {**package, **digest_file(path)}
                total += artifact["bytes"]
                require(total <= TOTAL_LIMIT, "graph output exceeds total bound")
                package_artifacts.append(artifact)
        manifest = {"format": "rustdesk-flutter-linux-engine-graph-v1", "source_commit": args.source_commit,
                    "framework_revision": args.framework_revision, "discovery_sha256": args.discovery_sha256,
                    "tools_manifest_sha256": args.tools_manifest_sha256,
                    "profile": {"target_os": ["unix"], "target_cpu": ["x64"],
                                "builtin_vars": BUILTINS, "custom_vars": OVERRIDES},
                    "git": staged, "cipd": package_artifacts, "source_date_epoch": args.epoch,
                    "gn_args_file": parsed["gclient_gn_args_file"],
                    "gn_args": {name: values[name] for name in parsed["gclient_gn_args"]},
                    "deferred_hooks": hooks, "complete_engine_closure": False,
                    "hooks_executed": False, "acquired_bytes": total}
        with common["output_file"](roots["output"], "manifest.json") as output:
            payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            require(len(payload) <= 1048576, "graph manifest exceeds bound")
            output.write(payload)
            common["seal"](output)
        os.fsync(roots["output"])
        common["tools"](args, roots["tools"], "/tools")
        common["discovery"](args)
        print("ENGINE_GRAPH=pass git=" + str(len(staged)) + " cipd=" + str(len(package_artifacts)) +
              " bytes=" + str(total) + " hooks=deferred complete_engine_closure=no", flush=True)
    finally:
        for descriptor in roots.values():
            os.close(descriptor)


if __name__ == "__main__":
    main()

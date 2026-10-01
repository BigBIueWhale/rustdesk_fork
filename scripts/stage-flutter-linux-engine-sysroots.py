#!/usr/bin/env python3
"""Acquire the original engine's three Linux sysroots as inert pinned archives."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import resource
import ssl
import stat
import tarfile
import urllib.request


PER_FILE_LIMIT = 32 * 1024 * 1024
TOTAL_LIMIT = 64 * 1024 * 1024
SYSROOT_URL = "https://commondatastorage.googleapis.com/chrome-linux-sysroot"
SYSROOT_JSON = "flutter/engine/src/build/linux/sysroot_scripts/sysroots.json"
INSTALLER = "engine/src/build/linux/sysroot_scripts/install-sysroot.py"
SELECTIONS = (("x64", "bullseye", "amd64"), ("arm64", "bullseye", "arm64"),
              ("riscv64", "trixie", "riscv64"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


@contextmanager
def authenticated_input(path, size, digest, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
                == (os.getuid(), os.getgid(), 0o400)
                and 0 < size <= maximum and before.st_size == size,
                "sysroot input authority differs")
        require(hashlib.file_digest(source, "sha256").hexdigest() == digest,
                "sysroot input digest differs")
        source.seek(0)
        yield source
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in fields),
                "sysroot input changed during inspection")


def source_selections(args):
    with authenticated_input("/graph-manifest.json", args.graph_manifest_size,
                             args.graph_manifest_sha256, 65536) as source:
        graph = json.loads(source.read())
    require(graph["format"] == "rustdesk-flutter-linux-engine-graph-v1"
            and graph["source_commit"] == args.graph_source_commit
            and graph["framework_revision"] == args.framework_revision
            and graph["discovery_sha256"] == args.discovery_sha256
            and graph["tools_manifest_sha256"] == args.tools_manifest_sha256
            and graph["complete_engine_closure"] is False
            and graph["hooks_executed"] is False,
            "independent engine graph context differs")
    expected_hooks = [["python3", INSTALLER, "--arch=" + arch]
                      for arch, _, _ in SELECTIONS]
    require([hook["action"] for hook in graph["deferred_hooks"]
             if len(hook["action"]) > 1 and hook["action"][1] == INSTALLER]
            == expected_hooks, "source-selected Linux sysroot hooks differ")
    root = graph["git"][0]
    require(root["destination"] == "." and root["file"] == "git-000.tar"
            and root["url"] == "https://github.com/flutter/flutter.git"
            and root["object_type"] == "commit"
            and root["commit"] == root["revision"] == args.framework_revision
            and re.fullmatch("[0-9a-f]{40}", root["tree"])
            and re.fullmatch("[0-9a-f]{64}", root["sha256"]),
            "original framework source selection differs")
    payload = None
    with authenticated_input("/root-source.tar", root["bytes"], root["sha256"],
                             256 * 1024 * 1024) as source:
        with tarfile.open(fileobj=source, mode="r|") as archive:
            for member in archive:
                if member.name != SYSROOT_JSON:
                    continue
                require(payload is None and member.isfile() and not member.issparse()
                        and 0 < member.size <= 65536,
                        "original sysroots.json archive entry differs")
                with archive.extractfile(member) as selected:
                    payload = selected.read(65537)
                require(len(payload) == member.size, "sysroots.json bytes are incomplete")
    require(payload is not None, "original source lacks sysroots.json")
    specification = json.loads(payload)
    selections = []
    for arch, distribution, machine in SELECTIONS:
        key = distribution + "_" + machine
        selected = specification[key]
        digest = getattr(args, machine + "_sha256")
        require(selected == {"URL": SYSROOT_URL, "Sha256Sum": digest,
                             "SysrootDir": "debian_" + key + "-sysroot",
                             "Tarball": "debian_" + key + "_sysroot.tar.xz"},
                "source-selected sysroot disagrees with independent pins")
        selections.append({"hook_arch": arch, "key": key,
                           "destination": "engine/src/build/linux/" + selected["SysrootDir"],
                           "file": selected["Tarball"], "sha256": digest,
                           "bytes": getattr(args, machine + "_size"),
                           "url": SYSROOT_URL + "/" + digest})
    return root, hashlib.sha256(payload).hexdigest(), selections


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise ValueError("sysroot publisher redirects are forbidden")


def create_output(root, name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=root), "wb")


def seal(output):
    output.flush()
    require(0 < os.fstat(output.fileno()).st_size <= PER_FILE_LIMIT,
            "sysroot output exceeds its bound")
    os.fchmod(output.fileno(), 0o400)
    os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-commit", "framework-revision", "graph-source-commit",
                 "graph-manifest-sha256", "discovery-sha256", "tools-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--graph-manifest-size", type=int, required=True)
    for _, _, machine in SELECTIONS:
        parser.add_argument("--" + machine + "-sha256", required=True)
        parser.add_argument("--" + machine + "-size", type=int, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and os.getgid() != 0, "root sysroot acquisition refused")
    for value in (args.source_commit, args.framework_revision, args.graph_source_commit):
        require(re.fullmatch("[0-9a-f]{40}", value), "malformed sysroot source pin")
    for value in (args.graph_manifest_sha256, args.discovery_sha256, args.tools_manifest_sha256,
                  args.amd64_sha256, args.arm64_sha256, args.riscv64_sha256):
        require(re.fullmatch("[0-9a-f]{64}", value), "malformed sysroot content pin")
    sizes = [getattr(args, machine + "_size") for _, _, machine in SELECTIONS]
    require(all(0 < size <= PER_FILE_LIMIT for size in sizes)
            and sum(sizes) + 65536 <= TOTAL_LIMIT, "sysroot acquisition exceeds byte budget")
    resource.setrlimit(resource.RLIMIT_FSIZE, (PER_FILE_LIMIT, PER_FILE_LIMIT))
    original, specification_sha256, selections = source_selections(args)
    root = os.open("/output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(root)
        require((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
                == (os.getuid(), os.getgid(), 0o700) and not os.listdir(root),
                "sysroot output is occupied or its authority differs")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        for selected in selections:
            print("ENGINE_SYSROOT_STAGE=fetch key=" + selected["key"], flush=True)
            digest, count = hashlib.sha256(), 0
            with opener.open(selected["url"], timeout=30) as response:
                require(response.status == 200 and response.geturl() == selected["url"]
                        and response.headers.get_all("Content-Length") == [str(selected["bytes"])]
                        and not response.headers.get("Transfer-Encoding")
                        and response.headers.get("Content-Encoding", "identity") == "identity",
                        "sysroot publisher response or byte count differs")
                with create_output(root, selected["file"]) as output:
                    while True:
                        block = response.read(min(1048576, selected["bytes"] - count + 1))
                        if not block:
                            break
                        count += len(block)
                        require(count <= selected["bytes"], "sysroot body exceeds exact size")
                        digest.update(block)
                        output.write(block)
                    require(count == selected["bytes"] and digest.hexdigest() == selected["sha256"],
                            "sysroot source-selected digest or size mismatch")
                    seal(output)
            print("ENGINE_SYSROOT_ARCHIVE=pass key=" + selected["key"]
                  + " bytes=" + str(count) + " sha256=" + digest.hexdigest(), flush=True)
        manifest = {"format": "rustdesk-flutter-linux-engine-sysroots-v1",
                    "source_commit": args.source_commit, "framework_revision": args.framework_revision,
                    "graph_source_commit": args.graph_source_commit,
                    "graph_manifest_sha256": args.graph_manifest_sha256,
                    "discovery_sha256": args.discovery_sha256,
                    "tools_manifest_sha256": args.tools_manifest_sha256,
                    "original_source": original, "sysroots_json_sha256": specification_sha256,
                    "sysroots": selections, "acquired_bytes": sum(sizes),
                    "archives_extracted": False, "hooks_executed": False,
                    "downloaded_code_executed": False, "complete_engine_closure": False}
        with create_output(root, "manifest.json") as output:
            output.write((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
            seal(output)
        os.fsync(root)
        print("ENGINE_SYSROOTS=pass archives=3 bytes=" + str(sum(sizes))
              + " extracted=no hooks=deferred complete_engine_closure=no", flush=True)
    finally:
        os.close(root)


if __name__ == "__main__":
    main()

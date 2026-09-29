#!/usr/bin/env python3
"""Publish and admit the exact inert files needed by an Android production peer."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from contextlib import ExitStack

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "rustdesk_artifact_publication", Path(__file__).with_name("publish-artifact-result.py")
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load the fixed artifact publication implementation")
publication = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = publication
_spec.loader.exec_module(publication)

LAYOUT = {
    "rustdesk": "debug/rustdesk",
    "seed_password": "debug/examples/seed_password",
    "probe_client": "debug/examples/probe_client",
    "smoke_readiness": "debug/examples/smoke_readiness",
    "flutter-peer-source-x11": "flutter-peer-source-x11",
    "smoke-bind-loopback.so": "smoke-bind-loopback.so",
    "smoke-server-launcher": "smoke-server-launcher",
}
MANIFEST = "peer-manifest.json"
DESTINATION = "linux-x86_64-peer"
MATERIALIZED = "materialized-peer"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192
PENDING_RE = re.compile(r"^\.android-peer-pending-[0-9a-f]{64}$")
CONTEXT_PATTERNS = {
    "source_commit": r"[0-9a-f]{40}",
    "source_tree": r"[0-9a-f]{40}",
    "builder_config": r"sha256:[0-9a-f]{64}",
    "vendor_closure": r"[0-9a-f]{64}",
    "vendor_config": r"[0-9a-f]{64}",
    "rust_toolchain": r"[1-9][0-9]*\.[0-9]+\.0-x86_64-unknown-linux-gnu",
}


def fail(message):
    publication.fail(message)


def validate_context(context):
    if type(context) is not dict or set(context) != set(CONTEXT_PATTERNS):
        fail("peer build context fields differ")
    for key, pattern in CONTEXT_PATTERNS.items():
        if type(context[key]) is not str or re.fullmatch(pattern, context[key]) is None:
            fail(f"peer build context is malformed: {key}")


def open_root(path, expected, mode):
    if os.getuid() == 0 or os.getgid() == 0:
        fail("peer artifact authority must not be root")
    if not os.path.isabs(path) or os.path.realpath(path) != path or path == "/":
        fail("peer root is not absolute and canonical")
    before = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or publication.stable_file(before) != publication.stable_file(opened)
            or publication.identity(opened) != expected
            or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode))
            != (os.getuid(), os.getgid(), mode)
        ):
            fail("peer root authority differs")
        publication.reject_access_acl(descriptor, "peer root", include_default=True)
        if os.path.realpath(path) != path or publication.stable_file(os.lstat(path)) != publication.stable_file(opened):
            fail("peer root edge changed while it was opened")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def require_inventory(descriptor, names):
    with os.scandir(descriptor) as entries:
        found = []
        for entry in entries:
            found.append(entry.name)
            if len(found) > len(names):
                fail("peer inventory has extra entries")
    if set(found) != set(names):
        fail("peer inventory differs")


def lock_parent(descriptor):
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("peer publication is already owned")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("peer manifest contains a duplicate key")
        result[key] = value
    return result


def consume_file(descriptor, info, output=None):
    digest = hashlib.sha256()
    remaining = info.st_size
    first = True
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            fail("peer file ended before its recorded size")
        if first:
            if (
                len(chunk) < 64 or chunk[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(chunk[18:20], "little") != 62
                or int.from_bytes(chunk[16:18], "little") not in (2, 3)
            ):
                fail("peer file is not a Linux x86_64 ELF image")
            first = False
        digest.update(chunk)
        if output is not None:
            publication.write_all(output, chunk, "peer file")
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        fail("peer file grew beyond its recorded size")
    if publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)):
        fail("peer file changed while it was read")
    return {"bytes": info.st_size, "sha256": digest.hexdigest()}


def open_peer_file(root, name, stack):
    descriptor, info = publication.open_result_file(
        root, name, maximum=MAX_FILE_BYTES, label="peer file"
    )
    stack.callback(os.close, descriptor)
    return descriptor, info


def validate_capsule(root, context, expected_manifest, stack):
    validate_context(context)
    if publication.SHA256_RE.fullmatch(expected_manifest) is None:
        fail("peer manifest digest is malformed")
    before = os.fstat(root)
    require_inventory(root, (*LAYOUT, MANIFEST))
    raw = publication.read_exact_file(
        root, MANIFEST, maximum=MAX_MANIFEST_BYTES, label="peer manifest"
    )
    if hashlib.sha256(raw).hexdigest() != expected_manifest:
        fail("peer manifest digest differs")
    manifest = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    if (
        type(manifest) is not dict or set(manifest) != {"schema", "context", "files"}
        or type(manifest["schema"]) is not int or manifest["schema"] != 1
        or manifest["context"] != context or type(manifest["files"]) is not dict
        or set(manifest["files"]) != set(LAYOUT)
    ):
        fail("peer manifest contract differs")
    files = {}
    total = 0
    for name in LAYOUT:
        record = manifest["files"][name]
        if (
            type(record) is not dict or set(record) != {"bytes", "sha256"}
            or type(record["bytes"]) is not int or not 64 <= record["bytes"] <= MAX_FILE_BYTES
            or type(record["sha256"]) is not str
            or publication.SHA256_RE.fullmatch(record["sha256"]) is None
        ):
            fail("peer manifest file record differs")
        descriptor, info = open_peer_file(root, name, stack)
        total += info.st_size
        if total > MAX_TOTAL_BYTES or consume_file(descriptor, info) != record:
            fail("peer content digest or aggregate bound differs")
        os.lseek(descriptor, 0, os.SEEK_SET)
        files[name] = (descriptor, info)
    if publication.stable_file(before) != publication.stable_file(os.fstat(root)):
        fail("peer capsule changed during admission")
    for descriptor, info in files.values():
        if publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)):
            fail("peer file changed during capsule admission")
    return manifest, files


def seal_file(descriptor, size, mode):
    os.fchmod(descriptor, mode)
    os.fsync(descriptor)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size)
        != (os.getuid(), os.getgid(), mode, 1, size)
    ):
        fail("copied peer metadata differs")
    publication.reject_access_acl(descriptor, "copied peer", include_default=False)
    return info


def prepare(source_path, source_identity, parent_path, parent_identity, context):
    validate_context(context)
    with ExitStack() as stack:
        source = open_root(source_path, source_identity, 0o500)
        stack.callback(os.close, source)
        require_inventory(source, LAYOUT)
        before = os.fstat(source)
        parent = open_root(parent_path, parent_identity, 0o700)
        stack.callback(os.close, parent)
        lock_parent(parent)
        require_inventory(parent, ())
        publication.require_absent(parent, DESTINATION, "peer destination")
        pending = ".android-peer-pending-" + os.urandom(32).hex()
        os.mkdir(pending, 0o700, dir_fd=parent)
        pending_path = os.path.join(parent_path, pending)
        pending_identity = publication.identity(os.stat(pending, dir_fd=parent, follow_symlinks=False))
        output = open_root(pending_path, pending_identity, 0o700)
        stack.callback(os.close, output)
        records = {}
        inputs = []
        total = 0
        for name in LAYOUT:
            descriptor, info = open_peer_file(source, name, stack)
            total += info.st_size
            if total > MAX_TOTAL_BYTES:
                fail("peer aggregate size exceeds its bound")
            target = publication.create_output_file(output, name)
            try:
                records[name] = consume_file(descriptor, info, target)
                seal_file(target, info.st_size, 0o400)
            finally:
                os.close(target)
            inputs.append((descriptor, info))
        manifest = json.dumps(
            {"schema": 1, "context": context, "files": records},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii") + b"\n"
        target = publication.create_output_file(output, MANIFEST)
        try:
            publication.write_all(target, manifest, "peer manifest")
            seal_file(target, len(manifest), 0o400)
        finally:
            os.close(target)
        digest = hashlib.sha256(manifest).hexdigest()
        validate_capsule(output, context, digest, stack)
        if publication.stable_file(before) != publication.stable_file(os.fstat(source)):
            fail("peer source changed during preparation")
        for descriptor, info in inputs:
            if publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)):
                fail("peer input changed during preparation")
        os.fsync(output)
        os.fsync(parent)
        for path, identity, mode in (
            (source_path, source_identity, 0o500),
            (pending_path, pending_identity, 0o700),
            (parent_path, parent_identity, 0o700),
        ):
            check = open_root(path, identity, mode)
            os.close(check)
        return pending, pending_identity, digest


def commit(parent_path, parent_identity, pending, pending_identity, context, digest):
    if PENDING_RE.fullmatch(pending) is None:
        fail("peer pending name is malformed")
    with ExitStack() as stack:
        parent = open_root(parent_path, parent_identity, 0o700)
        stack.callback(os.close, parent)
        lock_parent(parent)
        require_inventory(parent, (pending,))
        path = os.path.join(parent_path, pending)
        root = open_root(path, pending_identity, 0o700)
        stack.callback(os.close, root)
        validate_capsule(root, context, digest, stack)
        publication.require_absent(parent, DESTINATION, "peer destination")
        os.fchmod(root, 0o500)
        os.fsync(root)
        edge = os.stat(pending, dir_fd=parent, follow_symlinks=False)
        if publication.identity(edge) != pending_identity or not stat.S_ISDIR(edge.st_mode):
            fail("peer pending edge changed")
        check = open_root(parent_path, parent_identity, 0o700)
        os.close(check)
        publication.rename_noreplace(parent, pending, DESTINATION)
        os.fsync(parent)
        edge = os.stat(DESTINATION, dir_fd=parent, follow_symlinks=False)
        if publication.identity(edge) != pending_identity or not stat.S_ISDIR(edge.st_mode):
            fail("published peer edge differs")
        validate_capsule(root, context, digest, stack)
        publication.require_absent(parent, pending, "retired peer pending root")
        final_path = os.path.join(parent_path, DESTINATION)
        for path, identity, mode in (
            (final_path, pending_identity, 0o500),
            (parent_path, parent_identity, 0o700),
        ):
            check = open_root(path, identity, mode)
            os.close(check)
        return final_path


def materialize(path, root_identity, parent_path, parent_identity, context, digest):
    subprocess.run(
        ["/bin/bash", str(Path(__file__).with_name("verify-vm-entry-preflight.sh"))],
        check=True, stdout=subprocess.DEVNULL,
    )
    with ExitStack() as stack:
        root = open_root(path, root_identity, 0o500)
        stack.callback(os.close, root)
        manifest, files = validate_capsule(root, context, digest, stack)
        parent = open_root(parent_path, parent_identity, 0o700)
        stack.callback(os.close, parent)
        publication.require_absent(parent, MATERIALIZED, "peer execution workspace")
        os.mkdir(MATERIALIZED, 0o700, dir_fd=parent)
        target_path = os.path.join(parent_path, MATERIALIZED)
        target_identity = publication.identity(os.stat(MATERIALIZED, dir_fd=parent, follow_symlinks=False))
        target = open_root(target_path, target_identity, 0o700)
        stack.callback(os.close, target)
        os.mkdir("debug", 0o700, dir_fd=target)
        debug = os.open("debug", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=target)
        stack.callback(os.close, debug)
        os.mkdir("examples", 0o700, dir_fd=debug)
        examples = os.open("examples", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=debug)
        stack.callback(os.close, examples)
        outputs = []
        for name, relative in LAYOUT.items():
            directory = examples if relative.startswith("debug/examples/") else debug if relative.startswith("debug/") else target
            basename = relative.rsplit("/", 1)[-1]
            output = publication.create_output_file(directory, basename)
            stack.callback(os.close, output)
            descriptor, info = files[name]
            if consume_file(descriptor, info, output) != manifest["files"][name]:
                fail("peer changed during materialization")
            copied = seal_file(output, info.st_size, 0o500)
            outputs.append((directory, basename, output, copied))
        for directory in (examples, debug, target):
            os.fchmod(directory, 0o500)
            os.fsync(directory)
        edge = os.stat(MATERIALIZED, dir_fd=parent, follow_symlinks=False)
        if publication.identity(edge) != target_identity or not stat.S_ISDIR(edge.st_mode):
            fail("materialized peer edge differs")
        require_inventory(target, ("debug", "flutter-peer-source-x11", "smoke-bind-loopback.so", "smoke-server-launcher"))
        require_inventory(debug, ("rustdesk", "examples"))
        require_inventory(examples, ("seed_password", "probe_client", "smoke_readiness"))
        for directory, basename, output, copied in outputs:
            if (
                publication.stable_file(copied) != publication.stable_file(os.fstat(output))
                or publication.stable_file(copied) != publication.stable_file(os.stat(basename, dir_fd=directory, follow_symlinks=False))
            ):
                fail("materialized peer file edge changed")
        os.fsync(parent)
        for final_path, identity, mode in (
            (path, root_identity, 0o500),
            (target_path, target_identity, 0o500),
            (os.path.join(target_path, "debug"), publication.identity(os.fstat(debug)), 0o500),
            (os.path.join(target_path, "debug", "examples"), publication.identity(os.fstat(examples)), 0o500),
            (parent_path, parent_identity, 0o700),
        ):
            check = open_root(final_path, identity, mode)
            os.close(check)
        return target_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "commit", "materialize"))
    parser.add_argument("--root")
    parser.add_argument("--root-identity")
    parser.add_argument("--parent", required=True)
    parser.add_argument("--parent-identity", required=True)
    parser.add_argument("--pending")
    parser.add_argument("--pending-identity")
    parser.add_argument("--manifest-sha256")
    for key in CONTEXT_PATTERNS:
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    arguments = parser.parse_args()
    context = {key: getattr(arguments, key) for key in CONTEXT_PATTERNS}
    parent_identity = publication.parse_identity(arguments.parent_identity, "peer parent")
    if arguments.action == "prepare":
        if arguments.pending is not None or arguments.pending_identity is not None or arguments.manifest_sha256 is not None:
            fail("prepare accepts no pending or manifest authority")
        if arguments.root is None or arguments.root_identity is None:
            fail("prepare requires source-root authority")
        pending, identity, digest = prepare(
            arguments.root, publication.parse_identity(arguments.root_identity, "peer source"),
            arguments.parent, parent_identity, context,
        )
        print(f"{pending} {identity[0]}:{identity[1]} {digest}")
    elif arguments.action == "commit":
        if arguments.root is not None or arguments.root_identity is not None:
            fail("commit accepts no source-root authority")
        if arguments.pending is None or arguments.pending_identity is None or arguments.manifest_sha256 is None:
            fail("commit requires pending and manifest authority")
        print(commit(
            arguments.parent, parent_identity, arguments.pending,
            publication.parse_identity(arguments.pending_identity, "peer pending"), context,
            arguments.manifest_sha256,
        ))
    else:
        if arguments.pending is not None or arguments.pending_identity is not None:
            fail("materialize accepts no pending authority")
        if arguments.root is None or arguments.root_identity is None or arguments.manifest_sha256 is None:
            fail("materialize requires capsule and manifest authority")
        print(materialize(
            arguments.root, publication.parse_identity(arguments.root_identity, "peer capsule"),
            arguments.parent, parent_identity, context, arguments.manifest_sha256,
        ))


if __name__ == "__main__":
    try:
        main()
    except (publication.PublicationError, OSError, ValueError, RecursionError, subprocess.CalledProcessError) as error:
        print(f"Android peer artifact: {error}", file=sys.stderr)
        raise SystemExit(1)

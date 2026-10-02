#!/usr/bin/env python3
"""Admit a source-bound Linux Flutter app and project its matching engine toolkit."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tarfile
from contextlib import ExitStack

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "linux_flutter_publication", Path(__file__).with_name("publish-artifact-result.py")
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load the artifact publication implementation")
publication = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = publication
spec.loader.exec_module(publication)

MANIFEST = "app-manifest.json"
DESTINATION = "linux-x86_64-flutter-app"
MATERIALIZED = "materialized-flutter-app"
PENDING_RE = re.compile(r"^\.linux-flutter-pending-[0-9a-f]{64}$")
MAX_FILES = 512
MAX_DIRECTORIES = 128
MAX_DEPTH = 16
MAX_PATH_BYTES = 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
INPUTS = frozenset((
    "rust_archive", "flutter_archive", "flutter_tools_lock", "flutter_project_lock",
    "llvm_archive", "frb_codegen", "vendor_closure", "vendor_config", "vcpkg_closure",
    "pub_cache_closure",
))
CONTEXT_FIELDS = frozenset((
    "source_commit", "source_tree", "builder_config", "build_recipe_sha256",
    "rust_toolchain", "flutter_version", "source_date_epoch", "inputs", "engine",
))
APP_ENGINE_FIELDS = frozenset((
    "source_commit", "source_tree", "framework_revision", "patch_sha256",
    "archive_sha256", "manifest_sha256", "core", "icu",
))
APP_ENGINE_ROLES = {
    "core": "bundle/lib/libflutter_linux_gtk.so", "icu": "bundle/data/icudtl.dat",
}
REQUIRED_FILES = frozenset((
    "smoke-readiness", "bundle/rustdesk", "bundle/lib/librustdesk.so",
    "bundle/lib/libflutter_linux_gtk.so", "bundle/lib/libapp.so",
    "bundle/lib/libtexture_rgba_renderer_plugin.so", "bundle/data/icudtl.dat",
))
DESCRIPTOR_LIMIT = 4 * (MAX_FILES + MAX_DIRECTORIES) + 128
ENGINE_ARCHIVE = "flutter-linux-engine.tar"
ENGINE_MANIFEST = "engine-manifest.json"
ENGINE_MATERIALIZED = "materialized-flutter-engine"
ENGINE_OUTPUT = "src/out/host_release"
ENGINE_ELFS = frozenset((
    "libflutter_linux_gtk.so", "gen_snapshot", "font-subset", "impellerc", "libtessellator.so",
))
ENGINE_HEADERS = frozenset("flutter_linux/" + name + ".h" for name in (
    "fl_application", "fl_basic_message_channel", "fl_binary_codec", "fl_binary_messenger",
    "fl_dart_project", "fl_engine", "fl_event_channel", "fl_json_message_codec",
    "fl_json_method_codec", "fl_message_codec", "fl_method_call", "fl_method_channel",
    "fl_method_codec", "fl_method_response", "fl_pixel_buffer_texture", "fl_plugin_registrar",
    "fl_plugin_registry", "fl_standard_message_codec", "fl_standard_method_codec",
    "fl_string_codec", "fl_texture", "fl_texture_gl", "fl_texture_registrar", "fl_value",
    "fl_view", "flutter_linux",
))
ENGINE_DATA = frozenset((
    "icudtl.dat", "gen/const_finder.dart.snapshot", "gen/frontend_server_aot.dart.snapshot",
    "flutter_patched_sdk/platform_strong.dill", "flutter_patched_sdk/vm_outline_strong.dill",
))


def fail(message):
    publication.fail(message)


def validate_context(context):
    if type(context) is not dict or set(context) != CONTEXT_FIELDS:
        fail("Linux app build context fields differ")
    patterns = {
        "source_commit": r"[0-9a-f]{40}", "source_tree": r"[0-9a-f]{40}",
        "builder_config": r"sha256:[0-9a-f]{64}", "build_recipe_sha256": r"[0-9a-f]{64}",
        "rust_toolchain": r"[1-9][0-9]*\.[0-9]+\.0-x86_64-unknown-linux-gnu",
        "flutter_version": r"[1-9][0-9]*\.[0-9]+\.[0-9]+",
        "source_date_epoch": r"unset|0|[1-9][0-9]{0,18}",
    }
    for key, pattern in patterns.items():
        if type(context[key]) is not str or re.fullmatch(pattern, context[key]) is None:
            fail(f"Linux app build context is malformed: {key}")
    inputs = context["inputs"]
    if type(inputs) is not dict or set(inputs) != INPUTS:
        fail("Linux app build input roles differ")
    for value in inputs.values():
        if type(value) is not str or publication.SHA256_RE.fullmatch(value) is None:
            fail("Linux app build input digest is malformed")
    engine = context["engine"]
    if type(engine) is not dict or set(engine) != APP_ENGINE_FIELDS:
        fail("Linux app engine authority fields differ")
    for key in APP_ENGINE_FIELDS.difference(APP_ENGINE_ROLES):
        width = 40 if key in ("source_commit", "source_tree", "framework_revision") else 64
        if type(engine[key]) is not str or re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", engine[key]) is None:
            fail("Linux app engine authority is malformed: " + key)
    for role in APP_ENGINE_ROLES:
        record = engine[role]
        if (type(record) is not dict or set(record) != {"bytes", "sha256"}
                or type(record["bytes"]) is not int or not 0 < record["bytes"] <= MAX_FILE_BYTES
                or type(record["sha256"]) is not str
                or publication.SHA256_RE.fullmatch(record["sha256"]) is None):
            fail("Linux app engine role is malformed: " + role)


def verify_bundle_engine(records, context):
    for role, relative in APP_ENGINE_ROLES.items():
        if records.get(relative) != context["engine"][role]:
            fail("Linux app bundle does not contain the independently selected engine role: " + role)


def require_descriptor_capacity():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < DESCRIPTOR_LIMIT:
        fail("Linux app descriptor capacity is unavailable")
    if soft != resource.RLIM_INFINITY and soft < DESCRIPTOR_LIMIT:
        resource.setrlimit(resource.RLIMIT_NOFILE, (DESCRIPTOR_LIMIT, hard))
    with os.scandir("/proc/self/fd") as entries:
        if sum(1 for _ in entries) > 64:
            fail("Linux app inherited descriptor inventory exceeds its reserve")


def mount_id(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb", buffering=0) as stream:
        raw = stream.read(65537)
    values = [line[8:] for line in raw.splitlines() if line.startswith(b"mnt_id:\t")]
    if len(raw) > 65536 or len(values) != 1 or re.fullmatch(br"[1-9][0-9]*", values[0]) is None:
        fail("Linux app mount identity is unavailable")
    return int(values[0])


def open_root(path, expected, mode, stack):
    if os.getuid() == 0 or os.getgid() == 0:
        fail("Linux app artifact authority must not be root")
    if not os.path.isabs(path) or os.path.realpath(path) != path or path == "/":
        fail("Linux app root is not absolute and canonical")
    before = os.lstat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, descriptor)
    opened = os.fstat(descriptor)
    if (
        publication.stable_file(before) != publication.stable_file(opened)
        or publication.identity(opened) != expected
        or not stat.S_ISDIR(opened.st_mode)
        or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode))
        != (os.getuid(), os.getgid(), mode)
    ):
        fail("Linux app root authority differs")
    publication.reject_access_acl(descriptor, "Linux app root", include_default=True)
    if os.path.realpath(path) != path or publication.stable_file(os.lstat(path)) != publication.stable_file(opened):
        fail("Linux app root edge changed")
    return descriptor


def names(descriptor):
    result = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(result) >= MAX_FILES + MAX_DIRECTORIES + 1:
                fail("Linux app directory inventory exceeds its bound")
            name = entry.name
            if name in (".", "..") or any(ord(character) < 32 or ord(character) == 127 for character in name):
                fail("Linux app entry name is invalid")
            result.append(name)
    return tuple(sorted(result))


def executable(relative):
    if relative in ("smoke-readiness", "bundle/rustdesk"):
        return True
    if relative.startswith("bundle/lib/") and re.fullmatch(
        r"lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*", relative[len("bundle/lib/"):]
    ) is not None:
        return True
    if relative == "bundle/data/icudtl.dat" or relative.startswith("bundle/data/flutter_assets/"):
        return False
    fail(f"Linux app file is outside the product layout: {relative}")


def consume(descriptor, info, is_executable, output=None):
    digest = hashlib.sha256()
    prefix = bytearray()
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            fail("Linux app file ended before its recorded size")
        if len(prefix) < 64:
            prefix.extend(chunk[:64 - len(prefix)])
        digest.update(chunk)
        if output is not None:
            publication.write_all(output, chunk, "Linux app file")
        remaining -= len(chunk)
    if os.read(descriptor, 1) or publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)):
        fail("Linux app file changed while being read")
    if is_executable and (
        len(prefix) < 64 or prefix[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(prefix[16:18], "little") not in (2, 3)
        or int.from_bytes(prefix[18:20], "little") != 62
    ):
        fail("Linux app executable is not an x86_64 ELF image")
    return {"bytes": info.st_size, "sha256": digest.hexdigest()}


class Tree:
    def __init__(self, root, stack, *, capsule, executable_files=False):
        self.root = root
        self.stack = stack
        self.device = os.fstat(root).st_dev
        self.mount = mount_id(root)
        self.directories = {"": root}
        self.inventories = {}
        self.edges = []
        self.files = {}
        self.total = 0
        self.executable_files = executable_files
        expected = {"bundle", "smoke-readiness"}
        if capsule:
            expected.add(MANIFEST)
        if set(names(root)) != expected:
            fail("Linux app root inventory differs")
        self.walk(root, "", 0, capsule)
        if not REQUIRED_FILES.issubset(self.files):
            fail("Linux app required product file is missing")
        self.reprove()

    def walk(self, directory, prefix, depth, capsule):
        inventory = names(directory)
        self.inventories[directory] = (os.fstat(directory), inventory)
        for name in inventory:
            relative = f"{prefix}/{name}" if prefix else name
            if len(os.fsencode(relative)) > MAX_PATH_BYTES:
                fail("Linux app path exceeds its bound")
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            is_directory = stat.S_ISDIR(before.st_mode)
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_directory:
                flags |= os.O_DIRECTORY
            elif not stat.S_ISREG(before.st_mode):
                fail("Linux app contains a link or special filesystem object")
            descriptor = os.open(name, flags, dir_fd=directory)
            self.stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            mode = 0o500 if is_directory or (
                self.executable_files and relative != MANIFEST and executable(relative)
            ) else 0o400
            if (
                publication.stable_file(before) != publication.stable_file(opened)
                or opened.st_dev != self.device or mount_id(descriptor) != self.mount
                or (opened.st_uid, opened.st_gid) != (os.getuid(), os.getgid())
                or stat.S_IMODE(opened.st_mode) != mode
                or (not is_directory and opened.st_nlink != 1)
            ):
                fail("Linux app entry authority differs")
            publication.reject_access_acl(descriptor, "Linux app entry", include_default=is_directory)
            self.edges.append((directory, name, descriptor, opened))
            if is_directory:
                if depth >= MAX_DEPTH or len(self.directories) >= MAX_DIRECTORIES:
                    fail("Linux app directory/depth bound exceeded")
                if relative not in ("bundle", "bundle/lib", "bundle/data", "bundle/data/flutter_assets") \
                        and not relative.startswith("bundle/data/flutter_assets/"):
                    fail("Linux app directory is outside the product layout")
                self.directories[relative] = descriptor
                self.walk(descriptor, relative, depth + 1, capsule)
            elif relative == MANIFEST and capsule:
                if not 0 < opened.st_size <= MAX_MANIFEST_BYTES:
                    fail("Linux app manifest size differs")
            else:
                if len(self.files) >= MAX_FILES or not 0 <= opened.st_size <= MAX_FILE_BYTES:
                    fail("Linux app file/size bound exceeded")
                self.total += opened.st_size
                if self.total > MAX_TOTAL_BYTES:
                    fail("Linux app aggregate size exceeds its bound")
                self.files[relative] = (descriptor, opened, executable(relative))

    def reprove(self):
        for descriptor, (info, inventory) in self.inventories.items():
            if publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)) \
                    or names(descriptor) != inventory or mount_id(descriptor) != self.mount:
                fail("Linux app directory changed during admission")
        for parent, name, descriptor, info in self.edges:
            if (
                publication.stable_file(info) != publication.stable_file(os.fstat(descriptor))
                or publication.stable_file(info) != publication.stable_file(
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                ) or mount_id(descriptor) != self.mount
            ):
                fail("Linux app entry changed during admission")


def seal_file(descriptor, size, mode):
    os.fchmod(descriptor, mode)
    os.fsync(descriptor)
    info = os.fstat(descriptor)
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size) \
            != (os.getuid(), os.getgid(), mode, 1, size):
        fail("Linux app copied file metadata differs")
    publication.reject_access_acl(descriptor, "Linux app copy", include_default=False)


def copy_tree(tree, target, stack, *, inert):
    directories = {"": target}
    for relative in sorted(tree.directories, key=lambda value: (value.count("/"), value)):
        if not relative:
            continue
        parent, _, basename = relative.rpartition("/")
        os.mkdir(basename, 0o700, dir_fd=directories[parent])
        descriptor = os.open(basename, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=directories[parent])
        stack.callback(os.close, descriptor)
        directories[relative] = descriptor
    records = {}
    for relative, (descriptor, info, is_executable) in tree.files.items():
        parent, _, basename = relative.rpartition("/")
        output = publication.create_output_file(directories[parent], basename)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            records[relative] = consume(descriptor, info, is_executable, output)
            seal_file(output, info.st_size, 0o500 if is_executable and not inert else 0o400)
        finally:
            os.close(output)
    for relative in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        if relative:
            os.fchmod(directories[relative], 0o500)
        os.fsync(directories[relative])
    tree.reprove()
    return records


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("Linux app manifest has a duplicate key")
        result[key] = value
    return result


def engine_manifest(raw_manifest, digest, context):
    fields = {"source_commit", "source_tree", "framework_revision", "patch_sha256",
              "bootstrap_sdk_archive_sha256"}
    if type(context) is not dict or set(context) != fields:
        fail("engine SDK context fields differ")
    for key, value in context.items():
        width = 40 if key in ("source_commit", "source_tree", "framework_revision") else 64
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value) is None:
            fail("engine SDK context is malformed")
    if (type(raw_manifest) is not bytes or not 0 < len(raw_manifest) <= 1024 * 1024
            or type(digest) is not str or publication.SHA256_RE.fullmatch(digest) is None
            or hashlib.sha256(raw_manifest).hexdigest() != digest):
        fail("engine SDK manifest digest or bound differs")
    manifest = json.loads(raw_manifest, object_pairs_hook=no_duplicates)
    if (type(manifest) is not dict
            or manifest.get("format") != "rustdesk-flutter-linux-engine-artifact-v2"
            or manifest.get("profile") != "linux-x64-release-toolkit"
            or any(manifest.get(key) != value for key, value in context.items())
            or type(manifest.get("files")) is not dict
            or not 1 <= len(manifest["files"]) <= 4096):
        fail("engine SDK manifest context differs")
    return manifest


def verify_engine_sdk_roles(path, expected_identity, raw_manifest, digest, context):
    """Bind bootstrap/Pub's SDK roles to an independently authenticated toolkit.

    The caller admits the complete SDK archive separately. This read-only check
    covers the cache sky_engine package and frontend snapshot which local-engine
    flags do not redirect to the GN output. It neither projects an engine nor
    authorizes executing any other SDK file.
    """
    subprocess.run(["/bin/bash", str(Path(__file__).with_name("verify-vm-entry-preflight.sh"))],
                   check=True, stdout=subprocess.DEVNULL)
    require_descriptor_capacity()
    manifest = engine_manifest(raw_manifest, digest, context)
    prefix = "gen/dart-pkg/sky_engine/"
    sky = {key[len(prefix):]: record for key, record in manifest["files"].items()
           if key.startswith(prefix)}
    frontend = "gen/frontend_server_aot.dart.snapshot"
    if (not {"pubspec.yaml", "lib/_embedder.yaml", "lib/ui/ui.dart"}.issubset(sky)
            or frontend not in manifest["files"] or not 1 <= len(sky) < MAX_FILES):
        fail("engine SDK required role inventory differs")
    selected = {"bin/cache/pkg/sky_engine/" + key: record for key, record in sky.items()}
    selected["bin/cache/dart-sdk/bin/snapshots/frontend_server_aot.dart.snapshot"] = manifest["files"][frontend]
    for relative, record in selected.items():
        components = relative.split("/")
        if (len(components) > MAX_DEPTH or len(relative.encode()) > MAX_PATH_BYTES
                or any(value in ("", ".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in value)
                       for value in components)
                or type(record) is not dict or set(record) != {"bytes", "sha256"}
                or type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_FILE_BYTES
                or type(record["sha256"]) is not str or publication.SHA256_RE.fullmatch(record["sha256"]) is None):
            fail("engine SDK role record differs")
    if sum(record["bytes"] for record in selected.values()) > MAX_TOTAL_BYTES:
        fail("engine SDK role bytes exceed their bound")
    if (os.getuid() == 0 or os.getgid() == 0 or not os.path.isabs(path)
            or path == "/" or os.path.realpath(path) != path):
        fail("engine SDK root authority differs")
    with ExitStack() as stack:
        before = os.lstat(path)
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        opened = os.fstat(root)
        mount = mount_id(root)
        if publication.stable_file(before) != publication.stable_file(opened) \
                or publication.identity(opened) != expected_identity:
            fail("engine SDK root identity differs")
        directories = {"": root}
        inventories = {}
        edges = []

        def prove(info, descriptor, directory):
            mode = stat.S_IMODE(info.st_mode)
            required_mode = 0o500 if directory else 0o400
            if ((info.st_uid, info.st_gid) != (os.getuid(), os.getgid())
                    or info.st_dev != opened.st_dev or mount_id(descriptor) != mount
                    or mode & 0o7022 or mode & required_mode != required_mode
                    or (not directory and info.st_nlink != 1)):
                fail("engine SDK entry authority differs")
            publication.reject_access_acl(descriptor, "engine SDK entry", include_default=directory)

        prove(opened, root, True)

        def acquire(parent, name, directory):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not (stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode)):
                fail("engine SDK role is a link or special object")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            descriptor = os.open(name, flags | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
            stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if publication.stable_file(before) != publication.stable_file(info):
                fail("engine SDK entry changed during acquisition")
            prove(info, descriptor, directory)
            edges.append((parent, name, descriptor, info))
            return descriptor, info

        # Pub searches packages/<name> before bin/cache/pkg/<name>, even with
        # explicit local-engine flags. A second sky_engine package would shadow
        # the authenticated cache role rather than reuse it.
        directories["packages"] = acquire(root, "packages", True)[0]
        if "sky_engine" in names(directories["packages"]):
            fail("engine SDK sky_engine has a higher-priority shadow package")

        for relative in sorted(selected):
            components = relative.split("/")
            parent = root
            for index, name in enumerate(components[:-1], 1):
                key = "/".join(components[:index])
                if key not in directories:
                    if len(directories) >= MAX_DIRECTORIES:
                        fail("engine SDK directory bound exceeded")
                    directories[key] = acquire(parent, name, True)[0]
                parent = directories[key]
            descriptor, info = acquire(parent, components[-1], False)
            if info.st_size != selected[relative]["bytes"] \
                    or consume(descriptor, info, False) != selected[relative]:
                fail("engine SDK role bytes differ: " + relative)

        # Include empty directories in the closed sky_engine inventory: neither
        # an extra file nor an unobserved subtree may hide behind a cache match.
        sky_root = "bin/cache/pkg/sky_engine"
        for key, descriptor in directories.items():
            inventory = names(descriptor)
            inventories[descriptor] = (os.fstat(descriptor), inventory)
            if key == sky_root or key.startswith(sky_root + "/"):
                expected = {relative[len(key) + 1:].split("/", 1)[0]
                            for relative in selected if relative.startswith(key + "/")}
                if set(inventory) != expected:
                    fail("engine SDK sky_engine inventory differs")
        for parent, name, descriptor, info in edges:
            if (publication.stable_file(info) != publication.stable_file(os.fstat(descriptor))
                    or publication.stable_file(info) != publication.stable_file(
                        os.stat(name, dir_fd=parent, follow_symlinks=False))
                    or mount_id(descriptor) != mount):
                fail("engine SDK entry changed during proof")
        for descriptor, (info, inventory) in inventories.items():
            if publication.stable_file(info) != publication.stable_file(os.fstat(descriptor)) \
                    or names(descriptor) != inventory:
                fail("engine SDK directory changed during proof")
        if (os.path.realpath(path) != path
                or publication.stable_file(os.lstat(path)) != publication.stable_file(opened)):
            fail("engine SDK root edge changed during proof")
    return len(sky)


def materialize_engine(path, root_identity, parent_path, parent_identity,
                       sdk_path, sdk_identity, context, archive_digest, manifest_digest):
    """Project a complete toolkit; never copy or replace the separately admitted SDK.

    The caller authenticates the complete SDK archive and keeps both inputs and
    execution workspace quiescent. The sole intentional directory link names that
    exact SDK's Dart root. It is not archive-supplied or an artifact-search fallback.
    """
    subprocess.run(["/bin/bash", str(Path(__file__).with_name("verify-vm-entry-preflight.sh"))],
                   check=True, stdout=subprocess.DEVNULL)
    require_descriptor_capacity()
    if type(archive_digest) is not str or publication.SHA256_RE.fullmatch(archive_digest) is None:
        fail("engine archive digest is malformed")
    for source in (path, sdk_path):
        if os.path.commonpath((source, parent_path)) in (source, parent_path):
            fail("engine input and execution roots overlap")
    with ExitStack() as stack:
        root = open_root(path, root_identity, 0o700, stack)
        root_info = os.fstat(root)
        root_mount = mount_id(root)
        inventory = (ENGINE_ARCHIVE, ENGINE_ARCHIVE + ".sha256")
        if names(root) != inventory:
            fail("engine capsule inventory differs")
        archive, archive_info = publication.open_result_file(
            root, ENGINE_ARCHIVE, maximum=MAX_FILE_BYTES, label="engine archive")
        stack.callback(os.close, archive)
        checksum, checksum_info = publication.open_result_file(
            root, ENGINE_ARCHIVE + ".sha256", maximum=256, label="engine checksum")
        stack.callback(os.close, checksum)
        for descriptor, info in ((archive, archive_info), (checksum, checksum_info)):
            if info.st_dev != root_info.st_dev or mount_id(descriptor) != root_mount:
                fail("engine capsule crosses a mount")
        expected_checksum = (archive_digest + "  " + ENGINE_ARCHIVE + "\n").encode("ascii")
        if checksum_info.st_size != len(expected_checksum) or os.read(checksum, 257) != expected_checksum:
            fail("engine independently supplied checksum differs")
        if consume(archive, archive_info, False)["sha256"] != archive_digest:
            fail("engine archive digest differs")
        os.lseek(archive, 0, os.SEEK_SET)
        stream = stack.enter_context(os.fdopen(os.dup(archive), "rb"))
        tar = stack.enter_context(tarfile.open(fileobj=stream, mode="r:"))
        members = {}
        offset = 0
        total = 0
        for member in tar:
            components = member.name.split("/")
            if (len(members) >= MAX_FILES + 1 or member.name in members
                    or len(components) > MAX_DEPTH - 3 or len(member.name.encode()) > MAX_PATH_BYTES
                    or any(value in ("", ".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in value)
                           for value in components)
                    or member.type != tarfile.REGTYPE or member.mode != 0o400
                    or member.uid != 0 or member.gid != 0 or member.mtime != 0
                    or member.uname or member.gname or member.linkname or member.pax_headers
                    or member.offset != offset or member.offset_data != offset + 512
                    or not 0 < member.size <= (1024 * 1024 if member.name == ENGINE_MANIFEST else MAX_FILE_BYTES)):
                fail("engine archive member contract differs")
            total += member.size
            if total > MAX_FILE_BYTES - 1024 * 1024:
                fail("engine toolkit byte bound exceeded")
            offset = member.offset_data + ((member.size + 511) // 512) * 512
            stream.seek(member.offset_data + member.size)
            if any(stream.read(offset - member.offset_data - member.size)):
                fail("engine archive member padding differs")
            members[member.name] = member
        expected_size = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
        stream.seek(offset)
        if archive_info.st_size != expected_size or any(stream.read(expected_size - offset)):
            fail("engine archive final padding differs")
        if ENGINE_MANIFEST not in members:
            fail("engine toolkit manifest is missing")
        with tar.extractfile(members[ENGINE_MANIFEST]) as manifest_stream:
            raw = manifest_stream.read(1024 * 1024 + 1)
        manifest = engine_manifest(raw, manifest_digest, context)
        records = manifest["files"]
        required = ENGINE_ELFS | ENGINE_HEADERS | ENGINE_DATA
        if not required.issubset(records) or set(members) != set(records) | {ENGINE_MANIFEST}:
            fail("engine complete toolkit inventory differs")
        for relative, record in records.items():
            if (relative not in required and not relative.startswith("gen/dart-pkg/sky_engine/")):
                fail("engine toolkit contains an unsupported output role")
            if (type(record) is not dict or set(record) != {"bytes", "sha256"}
                    or type(record["bytes"]) is not int or record["bytes"] != members[relative].size
                    or type(record["sha256"]) is not str
                    or publication.SHA256_RE.fullmatch(record["sha256"]) is None):
                fail("engine toolkit file record differs")

        def read_member(relative, output=None):
            digest = hashlib.sha256()
            prefix = bytearray()
            with tar.extractfile(members[relative]) as source:
                remaining = members[relative].size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        fail("engine archive file ended early")
                    if len(prefix) < 64:
                        prefix.extend(chunk[:64 - len(prefix)])
                    digest.update(chunk)
                    if output is not None:
                        publication.write_all(output, chunk, "engine toolkit file")
                    remaining -= len(chunk)
                if source.read(1):
                    fail("engine archive file exceeds its record")
            if digest.hexdigest() != records[relative]["sha256"]:
                fail("engine toolkit file digest differs")
            if relative in ENGINE_ELFS and (len(prefix) < 64 or prefix[:6] != b"\x7fELF\x02\x01"
                    or int.from_bytes(prefix[16:18], "little") not in (2, 3)
                    or int.from_bytes(prefix[18:20], "little") != 62):
                fail("engine toolkit executable is not an x86_64 ELF")

        for relative in records:
            read_member(relative)
        verify_engine_sdk_roles(sdk_path, sdk_identity, raw, manifest_digest, context)
        dart_path = os.path.join(sdk_path, "bin/cache/dart-sdk")
        dart_before = os.lstat(dart_path)
        dart = os.open(dart_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, dart)
        dart_mount = mount_id(dart)
        if (publication.stable_file(dart_before) != publication.stable_file(os.fstat(dart))
                or os.path.realpath(dart_path) != dart_path
                or (dart_before.st_uid, dart_before.st_gid) != (os.getuid(), os.getgid())
                or stat.S_IMODE(dart_before.st_mode) & 0o7022
                or stat.S_IMODE(dart_before.st_mode) & 0o500 != 0o500):
            fail("engine Dart SDK changed during acquisition")
        publication.reject_access_acl(dart, "engine Dart SDK", include_default=True)
        paths = {ENGINE_OUTPUT + "/" + relative for relative in records}
        directory_paths = {"/".join(relative.split("/")[:index])
                           for relative in paths for index in range(1, len(relative.split("/")))}
        if len(directory_paths) >= MAX_DIRECTORIES:
            fail("engine projection directory bound exceeded")
        parent = open_root(parent_path, parent_identity, 0o700, stack)
        lock_empty_parent(parent)
        os.mkdir(ENGINE_MATERIALIZED, 0o700, dir_fd=parent)
        target_path = os.path.join(parent_path, ENGINE_MATERIALIZED)
        target_identity = publication.identity(os.stat(ENGINE_MATERIALIZED, dir_fd=parent, follow_symlinks=False))
        target = open_root(target_path, target_identity, 0o700, stack)
        target_mount = mount_id(target)
        directories = {"": target}
        for relative in sorted(directory_paths, key=lambda value: (value.count("/"), value)):
            prefix, _, basename = relative.rpartition("/")
            os.mkdir(basename, 0o700, dir_fd=directories[prefix])
            descriptor = os.open(basename, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=directories[prefix])
            stack.callback(os.close, descriptor)
            directories[relative] = descriptor
        for relative, record in records.items():
            prefix, _, basename = (ENGINE_OUTPUT + "/" + relative).rpartition("/")
            output = publication.create_output_file(directories[prefix], basename)
            try:
                read_member(relative, output)
                seal_file(output, record["bytes"], 0o500 if relative in ENGINE_ELFS else 0o400)
            finally:
                os.close(output)
        host = directories[ENGINE_OUTPUT]
        os.symlink(dart_path, "dart-sdk", dir_fd=host)
        alias_info = os.stat("dart-sdk", dir_fd=host, follow_symlinks=False)
        if (not stat.S_ISLNK(alias_info.st_mode)
                or (alias_info.st_uid, alias_info.st_gid, alias_info.st_nlink) != (os.getuid(), os.getgid(), 1)):
            fail("engine Dart SDK alias authority differs")
        paths.add(ENGINE_OUTPUT + "/dart-sdk")
        inventories = {}
        for relative in sorted(directories, key=lambda value: value.count("/"), reverse=True):
            descriptor = directories[relative]
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            expected = {value[len(relative) + bool(relative):].split("/", 1)[0]
                        for value in paths if not relative or value.startswith(relative + "/")}
            if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (os.getuid(), os.getgid(), 0o500)
                    or info.st_dev != os.fstat(target).st_dev or mount_id(descriptor) != target_mount
                    or set(names(descriptor)) != expected):
                fail("engine projection directory authority differs")
            publication.reject_access_acl(descriptor, "engine projection", include_default=True)
            inventories[relative] = (info, expected)
        execution_edges = []
        for relative, record in records.items():
            prefix, _, basename = (ENGINE_OUTPUT + "/" + relative).rpartition("/")
            descriptor = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directories[prefix])
            stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_dev != os.fstat(target).st_dev
                    or mount_id(descriptor) != target_mount
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size)
                    != (os.getuid(), os.getgid(), 0o500 if relative in ENGINE_ELFS else 0o400, 1, record["bytes"])):
                fail("engine projection file authority differs")
            publication.reject_access_acl(descriptor, "engine projection file", include_default=False)
            if consume(descriptor, info, relative in ENGINE_ELFS) != record:
                fail("engine projection file bytes differ")
            execution_edges.append((directories[prefix], basename, descriptor, info))
        verify_engine_sdk_roles(sdk_path, sdk_identity, raw, manifest_digest, context)
        if (publication.stable_file(dart_before) != publication.stable_file(os.fstat(dart))
                or publication.stable_file(dart_before) != publication.stable_file(os.lstat(dart_path))
                or mount_id(dart) != dart_mount
                or publication.stable_file(alias_info) != publication.stable_file(
                    os.stat("dart-sdk", dir_fd=host, follow_symlinks=False))
                or os.readlink("dart-sdk", dir_fd=host) != dart_path):
            fail("engine Dart SDK binding changed")
        for relative, (info, expected) in inventories.items():
            descriptor = directories[relative]
            prefix, _, basename = relative.rpartition("/")
            if (publication.stable_file(info) != publication.stable_file(os.fstat(descriptor))
                    or mount_id(descriptor) != target_mount or set(names(descriptor)) != expected
                    or (relative and publication.stable_file(info) != publication.stable_file(
                        os.stat(basename, dir_fd=directories[prefix], follow_symlinks=False)))):
                fail("engine projection directory changed")
        for directory, basename, descriptor, info in execution_edges:
            if (publication.stable_file(info) != publication.stable_file(os.fstat(descriptor))
                    or publication.stable_file(info) != publication.stable_file(
                        os.stat(basename, dir_fd=directory, follow_symlinks=False))
                    or mount_id(descriptor) != target_mount):
                fail("engine projection file changed")
        for name, descriptor, info in ((ENGINE_ARCHIVE, archive, archive_info),
                                      (ENGINE_ARCHIVE + ".sha256", checksum, checksum_info)):
            if (publication.stable_file(info) != publication.stable_file(os.fstat(descriptor))
                    or publication.stable_file(info) != publication.stable_file(
                        os.stat(name, dir_fd=root, follow_symlinks=False))):
                fail("engine capsule changed during projection")
        if names(root) != inventory or publication.stable_file(root_info) != publication.stable_file(os.fstat(root)):
            fail("engine capsule directory changed")
        open_root(path, root_identity, 0o700, stack)
        open_root(parent_path, parent_identity, 0o700, stack)
        open_root(target_path, target_identity, 0o500, stack)
        os.fsync(parent)
        return os.path.join(target_path, "src")


def admit(root, context, digest, stack):
    validate_context(context)
    if type(digest) is not str or publication.SHA256_RE.fullmatch(digest) is None:
        fail("Linux app manifest digest is malformed")
    tree = Tree(root, stack, capsule=True)
    raw = publication.read_exact_file(root, MANIFEST, maximum=MAX_MANIFEST_BYTES, label="Linux app manifest")
    if hashlib.sha256(raw).hexdigest() != digest:
        fail("Linux app manifest digest differs")
    manifest = json.loads(raw, object_pairs_hook=no_duplicates)
    if (
        type(manifest) is not dict or set(manifest) != {"schema", "context", "directories", "files"}
        or type(manifest["schema"]) is not int or manifest["schema"] != 2
        or manifest["context"] != context or type(manifest["files"]) is not dict
        or set(manifest["files"]) != set(tree.files)
        or type(manifest["directories"]) is not list
        or manifest["directories"] != sorted(relative for relative in tree.directories if relative)
    ):
        fail("Linux app manifest contract differs")
    for relative, (descriptor, info, is_executable) in tree.files.items():
        record = manifest["files"][relative]
        if (
            type(record) is not dict or set(record) != {"bytes", "sha256"}
            or type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_FILE_BYTES
            or type(record["sha256"]) is not str or publication.SHA256_RE.fullmatch(record["sha256"]) is None
        ):
            fail("Linux app file record differs")
        if consume(descriptor, info, is_executable) != record:
            fail("Linux app file digest differs")
        os.lseek(descriptor, 0, os.SEEK_SET)
    verify_bundle_engine(manifest["files"], context)
    tree.reprove()
    return tree, manifest


def lock_empty_parent(parent):
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("Linux app publication is already owned")
    if names(parent):
        fail("an earlier Linux app artifact remains; reuse or explicitly reconcile it")


def prepare(source_path, source_identity, parent_path, parent_identity, context):
    validate_context(context)
    require_descriptor_capacity()
    with ExitStack() as stack:
        source = open_root(source_path, source_identity, 0o500, stack)
        tree = Tree(source, stack, capsule=False)
        selected = {}
        for relative in APP_ENGINE_ROLES.values():
            descriptor, info, is_executable = tree.files[relative]
            selected[relative] = consume(descriptor, info, is_executable)
            os.lseek(descriptor, 0, os.SEEK_SET)
        verify_bundle_engine(selected, context)
        tree.reprove()
        parent = open_root(parent_path, parent_identity, 0o700, stack)
        lock_empty_parent(parent)
        pending = ".linux-flutter-pending-" + os.urandom(32).hex()
        os.mkdir(pending, 0o700, dir_fd=parent)
        path = os.path.join(parent_path, pending)
        expected = publication.identity(os.stat(pending, dir_fd=parent, follow_symlinks=False))
        output = open_root(path, expected, 0o700, stack)
        records = copy_tree(tree, output, stack, inert=True)
        raw = json.dumps({"schema": 2, "context": context,
                         "directories": sorted(relative for relative in tree.directories if relative),
                         "files": records},
                         sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        if len(raw) > MAX_MANIFEST_BYTES:
            fail("Linux app manifest exceeds its bound")
        descriptor = publication.create_output_file(output, MANIFEST)
        try:
            publication.write_all(descriptor, raw, "Linux app manifest")
            seal_file(descriptor, len(raw), 0o400)
        finally:
            os.close(descriptor)
        digest = hashlib.sha256(raw).hexdigest()
        admit(output, context, digest, stack)
        tree.reprove()
        os.fsync(output)
        os.fsync(parent)
        open_root(source_path, source_identity, 0o500, stack)
        open_root(parent_path, parent_identity, 0o700, stack)
        open_root(path, expected, 0o700, stack)
        return pending, expected, digest


def commit(parent_path, parent_identity, pending, pending_identity, context, digest):
    require_descriptor_capacity()
    if type(pending) is not str or PENDING_RE.fullmatch(pending) is None:
        fail("Linux app pending name is malformed")
    with ExitStack() as stack:
        parent = open_root(parent_path, parent_identity, 0o700, stack)
        try:
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Linux app publication is already owned")
        if names(parent) != (pending,):
            fail("Linux app pending parent inventory differs")
        path = os.path.join(parent_path, pending)
        root = open_root(path, pending_identity, 0o700, stack)
        tree, _ = admit(root, context, digest, stack)
        publication.require_absent(parent, DESTINATION, "Linux app destination")
        tree.reprove()
        os.fchmod(root, 0o500)
        os.fsync(root)
        open_root(path, pending_identity, 0o500, stack)
        open_root(parent_path, parent_identity, 0o700, stack)
        publication.rename_noreplace(parent, pending, DESTINATION)
        os.fsync(parent)
        final_path = os.path.join(parent_path, DESTINATION)
        open_root(final_path, pending_identity, 0o500, stack)
        admit(root, context, digest, stack)
        publication.require_absent(parent, pending, "Linux app retired pending root")
        if names(parent) != (DESTINATION,):
            fail("Linux app published parent inventory differs")
        return final_path


def materialize(path, root_identity, parent_path, parent_identity, context, digest):
    subprocess.run(["/bin/bash", str(Path(__file__).with_name("verify-vm-entry-preflight.sh"))],
                   check=True, stdout=subprocess.DEVNULL)
    require_descriptor_capacity()
    with ExitStack() as stack:
        root = open_root(path, root_identity, 0o500, stack)
        tree, manifest = admit(root, context, digest, stack)
        parent = open_root(parent_path, parent_identity, 0o700, stack)
        publication.require_absent(parent, MATERIALIZED, "Linux app execution workspace")
        os.mkdir(MATERIALIZED, 0o700, dir_fd=parent)
        target_path = os.path.join(parent_path, MATERIALIZED)
        expected = publication.identity(os.stat(MATERIALIZED, dir_fd=parent, follow_symlinks=False))
        target = open_root(target_path, expected, 0o700, stack)
        if copy_tree(tree, target, stack, inert=False) != manifest["files"]:
            fail("Linux app changed during materialization")
        os.fchmod(target, 0o500)
        os.fsync(target)
        os.fsync(parent)
        execution = Tree(target, stack, capsule=False, executable_files=True)
        if sorted(relative for relative in execution.directories if relative) != manifest["directories"]:
            fail("Linux app materialized directory inventory differs")
        records = {relative: consume(descriptor, info, is_executable)
                   for relative, (descriptor, info, is_executable) in execution.files.items()}
        if records != manifest["files"]:
            fail("Linux app materialized file inventory or digest differs")
        execution.reprove()
        tree.reprove()
        open_root(path, root_identity, 0o500, stack)
        open_root(parent_path, parent_identity, 0o700, stack)
        open_root(target_path, expected, 0o500, stack)
        return target_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "commit", "materialize", "materialize-engine"))
    parser.add_argument("--context", required=True)
    parser.add_argument("--root")
    parser.add_argument("--root-identity")
    parser.add_argument("--parent", required=True)
    parser.add_argument("--parent-identity", required=True)
    parser.add_argument("--pending")
    parser.add_argument("--pending-identity")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--sdk")
    parser.add_argument("--sdk-identity")
    parser.add_argument("--archive-sha256")
    arguments = parser.parse_args()
    if len(arguments.context.encode("utf-8")) > 4096:
        fail("Linux app context exceeds its bound")
    context = json.loads(arguments.context, object_pairs_hook=no_duplicates)
    parent = publication.parse_identity(arguments.parent_identity, "Linux app parent")
    if arguments.action == "materialize-engine":
        if arguments.pending is not None or arguments.pending_identity is not None:
            fail("engine materialize accepts no pending authority")
        if any(value is None for value in (arguments.root, arguments.root_identity,
                arguments.sdk, arguments.sdk_identity, arguments.archive_sha256, arguments.manifest_sha256)):
            fail("engine materialize requires capsule, SDK and digest authority")
        print(materialize_engine(arguments.root,
            publication.parse_identity(arguments.root_identity, "engine capsule"), arguments.parent, parent,
            arguments.sdk, publication.parse_identity(arguments.sdk_identity, "engine SDK"), context,
            arguments.archive_sha256, arguments.manifest_sha256))
        return
    if any(value is not None for value in (arguments.sdk, arguments.sdk_identity, arguments.archive_sha256)):
        fail("Linux app action accepts no engine SDK authority")
    validate_context(context)
    if arguments.action == "prepare":
        if arguments.pending is not None or arguments.pending_identity is not None or arguments.manifest_sha256 is not None:
            fail("Linux app prepare accepts no pending or manifest authority")
        if arguments.root is None or arguments.root_identity is None:
            fail("Linux app prepare requires source authority")
        pending, expected, digest = prepare(arguments.root,
            publication.parse_identity(arguments.root_identity, "Linux app source"),
            arguments.parent, parent, context)
        print(f"{pending} {expected[0]}:{expected[1]} {digest}")
    elif arguments.action == "commit":
        if arguments.root is not None or arguments.root_identity is not None:
            fail("Linux app commit accepts no source authority")
        if arguments.pending is None or arguments.pending_identity is None or arguments.manifest_sha256 is None:
            fail("Linux app commit requires pending and manifest authority")
        print(commit(arguments.parent, parent, arguments.pending,
            publication.parse_identity(arguments.pending_identity, "Linux app pending"),
            context, arguments.manifest_sha256))
    else:
        if arguments.pending is not None or arguments.pending_identity is not None:
            fail("Linux app materialize accepts no pending authority")
        if arguments.root is None or arguments.root_identity is None or arguments.manifest_sha256 is None:
            fail("Linux app materialize requires capsule and manifest authority")
        print(materialize(arguments.root,
            publication.parse_identity(arguments.root_identity, "Linux app capsule"),
            arguments.parent, parent, context, arguments.manifest_sha256))


if __name__ == "__main__":
    try:
        main()
    except (publication.PublicationError, OSError, ValueError, RecursionError,
            tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"Linux Flutter artifact: {error}", file=sys.stderr)
        raise SystemExit(1)

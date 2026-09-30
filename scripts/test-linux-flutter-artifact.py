#!/usr/bin/env python3
"""Run real filesystem/ELF capsule cases only inside the authenticated verifier VM."""

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack

sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(SCRIPT_DIR / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
spec = importlib.util.spec_from_file_location("linux_flutter_artifact", SCRIPT_DIR / "linux-flutter-artifact.py")
if spec is None or spec.loader is None:
    raise SystemExit("cannot load the Linux Flutter artifact implementation")
app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = app
spec.loader.exec_module(app)
CONTEXT = {
    "source_commit": "1" * 40, "source_tree": "2" * 40,
    "builder_config": "sha256:" + "3" * 64, "build_recipe_sha256": "4" * 64,
    "rust_toolchain": "1.75.0-x86_64-unknown-linux-gnu", "flutter_version": "3.47.5",
    "source_date_epoch": "1700000000", "inputs": {key: "5" * 64 for key in app.INPUTS},
}
ELF = Path("/usr/bin/true").read_bytes()
WORKSPACE = Path(tempfile.mkdtemp(prefix="linux-flutter-artifact-test."))
WORKSPACE.chmod(0o700)
WORKSPACE_ID = app.publication.identity(WORKSPACE.stat())


def identity(path):
    return app.publication.identity(path.lstat())


def directory(path):
    path.mkdir(mode=0o700)
    return path


def write(path, data):
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o400)


class LinuxFlutterArtifactTests(unittest.TestCase):
    def setUp(self):
        self.case = directory(WORKSPACE / self.id().rsplit(".", 1)[-1])
        self.source = directory(self.case / "source")
        for relative in (*app.REQUIRED_FILES, "bundle/data/flutter_assets/empty asset",
                         "bundle/data/flutter_assets/packages/example/asset"):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write(path, ELF if app.executable(relative) else b"" if path.name == "empty asset" else b"asset bytes")
        for path in sorted(self.source.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o500)
        self.source.chmod(0o500)
        self.parent = directory(self.case / "publication")
        self.execution = directory(self.case / "execution")

    def prepare(self):
        return app.prepare(str(self.source), identity(self.source), str(self.parent), identity(self.parent), CONTEXT)

    def published(self):
        pending, expected, digest = self.prepare()
        return Path(app.commit(str(self.parent), identity(self.parent), pending, expected, CONTEXT, digest)), digest

    def materialize(self, root, digest, context=CONTEXT):
        return Path(app.materialize(str(root), identity(root), str(self.execution), identity(self.execution), context, digest))

    def admit(self, root, digest, context=CONTEXT):
        with ExitStack() as stack:
            descriptor = app.open_root(str(root), identity(root), 0o500, stack)
            return app.admit(descriptor, context, digest, stack)[1]

    def rejected(self, operation):
        with self.assertRaises((app.publication.PublicationError, OSError, ValueError)):
            operation()

    def change_manifest(self, root, change):
        path = root / app.MANIFEST
        value = json.loads(path.read_bytes())
        raw = change(value)
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)
        return hashlib.sha256(raw).hexdigest()

    def cli(self, action, *arguments):
        return subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "linux-flutter-artifact.py"), action,
            "--context", json.dumps(CONTEXT), "--parent", str(self.parent if action != "materialize" else self.execution),
            "--parent-identity", ":".join(map(str, identity(self.parent if action != "materialize" else self.execution))),
            *arguments,
        ], check=True, timeout=15, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def test_actual_cli_publication_materialization_and_elf_execution(self):
        pending, expected, digest = self.cli("prepare", "--root", str(self.source),
            "--root-identity", ":".join(map(str, identity(self.source)))).split()
        root = Path(self.cli("commit", "--pending", pending, "--pending-identity", expected,
                             "--manifest-sha256", digest))
        manifest = self.admit(root, digest)
        for relative in manifest["files"]:
            self.assertEqual(stat.S_IMODE((root / relative).stat().st_mode), 0o400)
        target = Path(self.cli("materialize", "--root", str(root),
            "--root-identity", ":".join(map(str, identity(root))), "--manifest-sha256", digest))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o500)
        self.assertFalse((target / app.MANIFEST).exists())
        for relative in manifest["files"]:
            output = target / relative
            self.assertEqual(output.read_bytes(), (root / relative).read_bytes())
            self.assertEqual((stat.S_IMODE(output.stat().st_mode), output.stat().st_nlink),
                             (0o500 if app.executable(relative) else 0o400, 1))
            if app.executable(relative):
                subprocess.run([str(output)], check=True, timeout=5, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_wrong_context_refuses_before_execution_copy(self):
        root, digest = self.published()
        for key in CONTEXT:
            context = copy.deepcopy(CONTEXT)
            if key == "inputs":
                context[key]["flutter_archive"] = "a" * 64
            elif key == "source_date_epoch":
                context[key] = "unset"
            elif key == "flutter_version":
                context[key] = "3.24.5"
            elif key == "rust_toolchain":
                context[key] = "1.76.0-x86_64-unknown-linux-gnu"
            else:
                context[key] = ("sha256:" if key == "builder_config" else "") + "a" * (40 if key in ("source_commit", "source_tree") else 64)
            self.rejected(lambda: self.materialize(root, digest, context))
            self.assertEqual(list(self.execution.iterdir()), [])

    def test_wrong_manifest_digest(self):
        root, _ = self.published()
        self.rejected(lambda: self.materialize(root, "0" * 64))
        self.assertEqual(list(self.execution.iterdir()), [])

    def test_closed_context_and_input_roles(self):
        for context in (dict(CONTEXT, unknown="x"), dict(CONTEXT, inputs={}),
                        dict(CONTEXT, source_commit="HEAD"), dict(CONTEXT, rust_toolchain="stable")):
            self.rejected(lambda: app.validate_context(context))

    def test_changed_asset_bytes(self):
        root, digest = self.published()
        path = root / "bundle/data/icudtl.dat"
        path.chmod(0o600)
        path.write_bytes(b"changed")
        path.chmod(0o400)
        self.rejected(lambda: self.admit(root, digest))

    def test_symlink_payload(self):
        root, digest = self.published()
        path = root / "bundle/rustdesk"
        path.parent.chmod(0o700)
        path.unlink()
        path.symlink_to(self.source / "bundle/rustdesk")
        path.parent.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_external_hardlink(self):
        root, digest = self.published()
        os.link(root / "bundle/rustdesk", self.case / "external")
        self.rejected(lambda: self.admit(root, digest))

    def test_executable_cached_payload(self):
        root, digest = self.published()
        (root / "bundle/rustdesk").chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_extra_test_driver(self):
        self.source.chmod(0o700)
        write(self.source / "flutter-peer-presentation-x11", ELF)
        self.source.chmod(0o500)
        self.rejected(self.prepare)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_extra_empty_directory_is_manifest_bound(self):
        root, digest = self.published()
        parent = root / "bundle/data/flutter_assets"
        parent.chmod(0o700)
        directory(parent / "unrecorded").chmod(0o500)
        parent.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_missing_required_product_file(self):
        path = self.source / "bundle/lib/libapp.so"
        path.parent.chmod(0o700)
        path.unlink()
        path.parent.chmod(0o500)
        self.rejected(self.prepare)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_non_elf_library(self):
        path = self.source / "bundle/lib/libapp.so"
        path.chmod(0o600)
        path.write_bytes(b"not an ELF image")
        path.chmod(0o400)
        self.rejected(self.prepare)
        self.assertFalse((self.parent / app.DESTINATION).exists())

    def test_duplicate_manifest_key(self):
        root, _ = self.published()
        digest = self.change_manifest(root, lambda value: b'{"schema":1,' + json.dumps(value).encode()[1:])
        self.rejected(lambda: self.admit(root, digest))

    def test_boolean_manifest_size(self):
        root, _ = self.published()
        def change(value):
            value["files"]["bundle/rustdesk"]["bytes"] = True
            return json.dumps(value).encode()
        digest = self.change_manifest(root, change)
        self.rejected(lambda: self.admit(root, digest))

    def test_retained_pending_refuses_new_preparation(self):
        pending, expected, _ = self.prepare()
        self.rejected(self.prepare)
        self.assertEqual(names := [path.name for path in self.parent.iterdir()], [pending])
        self.assertEqual(identity(self.parent / names[0]), expected)

    def test_wrong_pending_identity(self):
        pending, expected, digest = self.prepare()
        self.rejected(lambda: app.commit(str(self.parent), identity(self.parent), pending,
            (expected[0], expected[1] + 1), CONTEXT, digest))
        self.assertFalse((self.parent / app.DESTINATION).exists())

    def test_late_publication_collision_does_not_clobber(self):
        pending, expected, digest = self.prepare()
        original = app.publication.rename_noreplace
        def collide(parent, source, destination):
            os.mkdir(destination, 0o700, dir_fd=parent)
            return original(parent, source, destination)
        app.publication.rename_noreplace = collide
        try:
            self.rejected(lambda: app.commit(str(self.parent), identity(self.parent), pending, expected, CONTEXT, digest))
        finally:
            app.publication.rename_noreplace = original
        self.assertEqual(identity(self.parent / pending), expected)
        self.assertEqual(list((self.parent / app.DESTINATION).iterdir()), [])

    def test_held_publication_lock(self):
        descriptor = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.rejected(self.prepare)
            self.assertEqual(list(self.parent.iterdir()), [])
        finally:
            os.close(descriptor)

    def test_posix_acl_even_with_owner_only_mode(self):
        root, digest = self.published()
        path = root / "bundle/rustdesk"
        entries = ((1, 4, 0xffffffff), (2, 0, 4001), (4, 0, 0xffffffff), (16, 0, 0xffffffff), (32, 0, 0xffffffff))
        os.setxattr(path, "system.posix_acl_access", struct.pack("<I", 2) + b"".join(
            struct.pack("<HHI", *entry) for entry in entries))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.rejected(lambda: self.admit(root, digest))

    def test_second_materialization_preserves_first(self):
        root, digest = self.published()
        target = self.materialize(root, digest)
        expected = identity(target)
        self.rejected(lambda: self.materialize(root, digest))
        self.assertEqual(identity(target), expected)
        self.assertEqual((target / "bundle/rustdesk").read_bytes(), ELF)


def main():
    successful = False
    try:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(LinuxFlutterArtifactTests))
        successful = result.wasSuccessful() and result.testsRun == 20 and not result.skipped
    finally:
        subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "verify-private-tree-closure.py"),
            "--remove-private-root", str(WORKSPACE), "--expected-identity", ":".join(map(str, WORKSPACE_ID)),
        ], check=True)
    if not successful:
        raise SystemExit(1)
    print("LINUX_FLUTTER_ARTIFACT=pass fixture=system-elf-and-assets cases=20 publication=noclobber admission=exact execution=guest-only cleanup=joined")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise peer artifact authority on real files inside the authenticated VM."""

import fcntl
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack

sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(SCRIPT_DIR / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
spec = importlib.util.spec_from_file_location("android_peer_artifact", SCRIPT_DIR / "android-peer-artifact.py")
if spec is None or spec.loader is None:
    raise SystemExit("cannot load the peer artifact implementation")
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)
CONTEXT = {
    "source_commit": "1" * 40,
    "source_tree": "2" * 40,
    "builder_config": "sha256:" + "3" * 64,
    "vendor_closure": "4" * 64,
    "vendor_config": "5" * 64,
    "rust_toolchain": "1.75.0-x86_64-unknown-linux-gnu",
}
PAYLOAD = Path("/usr/bin/true").read_bytes()
WORKSPACE = Path(tempfile.mkdtemp(prefix="android-peer-artifact-test."))
os.chmod(WORKSPACE, 0o700)
WORKSPACE_ID = peer.publication.identity(WORKSPACE.stat())


def identity(path):
    return peer.publication.identity(path.lstat())


def directory(path):
    path.mkdir(mode=0o700)
    return path


def write(path, data, mode=0o400):
    with path.open("xb") as output:
        output.write(data)
    path.chmod(mode)


def fifo_substitution(root, ready, old_flags):
    original = os.open
    replaced = False

    def substitute(name, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if name == "rustdesk" and dir_fd == root and not replaced:
            replaced = True
            os.unlink(name, dir_fd=root)
            os.mkfifo(name, 0o400, dir_fd=root)
            ready.set()
            if old_flags:
                flags &= ~os.O_NONBLOCK
        return original(name, flags, mode, dir_fd=dir_fd)

    os.open = substitute
    try:
        with ExitStack() as stack:
            peer.open_peer_file(root, "rustdesk", stack)
    except peer.publication.PublicationError:
        if replaced:
            return
    raise SystemExit("FIFO substitution was not refused")


class PeerArtifactTests(unittest.TestCase):
    def setUp(self):
        self.case = directory(WORKSPACE / self.id().rsplit(".", 1)[-1])
        self.source = directory(self.case / "source")
        for name in peer.LAYOUT:
            write(self.source / name, PAYLOAD)
        self.source.chmod(0o500)
        self.parent = directory(self.case / "publication")
        self.execution = directory(self.case / "execution")

    def prepare(self):
        return peer.prepare(str(self.source), identity(self.source),
                            str(self.parent), identity(self.parent), CONTEXT)

    def cli(self, action, *arguments):
        command = ["/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "android-peer-artifact.py"), action]
        for key, value in CONTEXT.items():
            command.extend(("--" + key.replace("_", "-"), value))
        command.extend(arguments)
        return subprocess.run(command, check=True, timeout=15, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def identity_argument(self, path):
        device, inode = identity(path)
        return f"{device}:{inode}"

    def published(self):
        pending, pending_id, digest = self.prepare()
        root = Path(peer.commit(str(self.parent), identity(self.parent),
                                pending, pending_id, CONTEXT, digest))
        return root, digest

    def materialize(self, root, digest, context=CONTEXT):
        return Path(peer.materialize(str(root), identity(root), str(self.execution),
                                     identity(self.execution), context, digest))

    def admit(self, root, digest, context=CONTEXT):
        with ExitStack() as stack:
            descriptor = peer.open_root(str(root), identity(root), 0o500)
            stack.callback(os.close, descriptor)
            return peer.validate_capsule(descriptor, context, digest, stack)[0]

    def rejected(self, operation):
        with self.assertRaises((peer.publication.PublicationError, OSError, ValueError)):
            operation()

    def alter_manifest(self, root, operation):
        path = root / peer.MANIFEST
        manifest = json.loads(path.read_bytes())
        raw = operation(manifest)
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)
        return hashlib.sha256(raw).hexdigest()

    def test_publish_and_execute_exact_fixture(self):
        pending, pending_id, digest = self.cli(
            "prepare", "--root", str(self.source), "--root-identity", self.identity_argument(self.source),
            "--parent", str(self.parent), "--parent-identity", self.identity_argument(self.parent),
        ).split()
        root = Path(self.cli(
            "commit", "--parent", str(self.parent), "--parent-identity", self.identity_argument(self.parent),
            "--pending", pending, "--pending-identity", pending_id, "--manifest-sha256", digest,
        ))
        self.assertEqual(set(path.name for path in root.iterdir()), {*peer.LAYOUT, peer.MANIFEST})
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o500)
        for name in (*peer.LAYOUT, peer.MANIFEST):
            info = (root / name).stat()
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o400, 1))
        target = Path(self.cli(
            "materialize", "--root", str(root), "--root-identity", self.identity_argument(root),
            "--parent", str(self.execution), "--parent-identity", self.identity_argument(self.execution),
            "--manifest-sha256", digest,
        ))
        for name, relative in peer.LAYOUT.items():
            output = target / relative
            self.assertEqual(output.read_bytes(), (root / name).read_bytes())
            self.assertEqual((stat.S_IMODE(output.stat().st_mode), output.stat().st_nlink), (0o500, 1))
            subprocess.run([str(output)], check=True, timeout=5, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_second_materialization_refuses(self):
        root, digest = self.published()
        target = self.materialize(root, digest)
        target_id = identity(target)
        self.rejected(lambda: self.materialize(root, digest))
        self.assertEqual(identity(target), target_id)
        self.assertEqual((target / "debug/rustdesk").read_bytes(), PAYLOAD)

    def test_wrong_context_refuses_before_output(self):
        root, digest = self.published()
        context = dict(CONTEXT, source_tree="a" * 40)
        self.rejected(lambda: self.materialize(root, digest, context))
        self.assertEqual(list(self.execution.iterdir()), [])

    def test_wrong_digest_refuses_before_output(self):
        root, _ = self.published()
        self.rejected(lambda: self.materialize(root, "0" * 64))
        self.assertEqual(list(self.execution.iterdir()), [])

    def test_context_is_closed(self):
        for context in (dict(CONTEXT, unknown="x"), dict(CONTEXT, source_commit="HEAD"),
                        dict(CONTEXT, rust_toolchain="stable")):
            self.rejected(lambda: peer.validate_context(context))

    def test_payload_tamper(self):
        root, digest = self.published()
        path = root / "rustdesk"
        path.chmod(0o600)
        path.write_bytes(PAYLOAD[:-1] + bytes([PAYLOAD[-1] ^ 1]))
        path.chmod(0o400)
        self.rejected(lambda: self.admit(root, digest))

    def test_symlink_payload(self):
        root, digest = self.published()
        root.chmod(0o700)
        (root / "rustdesk").unlink()
        (root / "rustdesk").symlink_to(self.source / "rustdesk")
        root.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_hardlink_payload(self):
        root, digest = self.published()
        os.link(root / "rustdesk", self.case / "external-link")
        self.rejected(lambda: self.admit(root, digest))

    def test_extra_payload(self):
        root, digest = self.published()
        root.chmod(0o700)
        write(root / "unexpected", PAYLOAD)
        root.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_executable_cached_payload(self):
        root, digest = self.published()
        (root / "rustdesk").chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_manifest_extra_field(self):
        root, _ = self.published()
        digest = self.alter_manifest(root, lambda value: json.dumps(dict(value, unknown=1)).encode())
        self.rejected(lambda: self.admit(root, digest))

    def test_manifest_duplicate_key(self):
        root, _ = self.published()
        digest = self.alter_manifest(root, lambda value: b'{"schema":1,' + json.dumps(value).encode()[1:])
        self.rejected(lambda: self.admit(root, digest))

    def test_manifest_boolean_size(self):
        root, _ = self.published()
        def change(value):
            value["files"]["rustdesk"]["bytes"] = True
            return json.dumps(value).encode()
        digest = self.alter_manifest(root, change)
        self.rejected(lambda: self.admit(root, digest))

    def test_non_elf_source(self):
        path = self.source / "rustdesk"
        path.chmod(0o600)
        path.write_bytes(b"not ELF" * 20)
        path.chmod(0o400)
        self.rejected(self.prepare)
        self.assertFalse((self.parent / peer.DESTINATION).exists())

    def test_retained_pending_refuses_another_prepare(self):
        pending, pending_id, _ = self.prepare()
        self.rejected(self.prepare)
        self.assertEqual([path.name for path in self.parent.iterdir()], [pending])
        self.assertEqual(identity(self.parent / pending), pending_id)

    def test_wrong_pending_identity(self):
        pending, pending_id, digest = self.prepare()
        self.rejected(lambda: peer.commit(str(self.parent), identity(self.parent), pending,
                                         (pending_id[0], pending_id[1] + 1), CONTEXT, digest))
        self.assertFalse((self.parent / peer.DESTINATION).exists())

    def test_occupied_destination(self):
        pending, pending_id, digest = self.prepare()
        destination = directory(self.parent / peer.DESTINATION)
        write(destination / "preserve", b"preserve")
        self.rejected(lambda: peer.commit(str(self.parent), identity(self.parent), pending,
                                         pending_id, CONTEXT, digest))
        self.assertEqual((destination / "preserve").read_bytes(), b"preserve")
        self.assertEqual(identity(self.parent / pending), pending_id)

    def test_late_destination_noclobber(self):
        pending, pending_id, digest = self.prepare()
        original = peer.publication.rename_noreplace
        def collide(parent, source, destination):
            os.mkdir(destination, 0o700, dir_fd=parent)
            return original(parent, source, destination)
        peer.publication.rename_noreplace = collide
        try:
            self.rejected(lambda: peer.commit(str(self.parent), identity(self.parent), pending,
                                             pending_id, CONTEXT, digest))
        finally:
            peer.publication.rename_noreplace = original
        self.assertEqual(identity(self.parent / pending), pending_id)
        self.assertEqual(list((self.parent / peer.DESTINATION).iterdir()), [])

    def test_unsafe_parent(self):
        self.parent.chmod(0o755)
        self.rejected(self.prepare)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_symlink_parent(self):
        link = self.case / "parent-link"
        link.symlink_to(self.parent)
        self.rejected(lambda: peer.prepare(str(self.source), identity(self.source), str(link),
                                          identity(self.parent), CONTEXT))
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_held_publication_lock(self):
        descriptor = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.rejected(self.prepare)
            self.assertEqual(list(self.parent.iterdir()), [])
        finally:
            os.close(descriptor)

    def test_fifo_replacement_does_not_block(self):
        self.source.chmod(0o700)
        descriptor = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        context = multiprocessing.get_context("fork")
        try:
            for old_flags in (True, False):
                ready = context.Event()
                process = context.Process(target=fifo_substitution, args=(descriptor, ready, old_flags))
                try:
                    process.start()
                    self.assertTrue(ready.wait(timeout=3), "FIFO replacement was not reached")
                    process.join(timeout=0.2 if old_flags else 3)
                    if old_flags:
                        self.assertTrue(process.is_alive(), "old reader did not reproduce the blocking defect")
                    else:
                        self.assertFalse(process.is_alive(), "corrected reader blocked on FIFO replacement")
                        self.assertEqual(process.exitcode, 0)
                finally:
                    if process.is_alive():
                        process.kill()
                        process.join()
                    process.close()
                    fifo = self.source / "rustdesk"
                    if stat.S_ISFIFO(fifo.lstat().st_mode):
                        fifo.unlink()
                    write(fifo, PAYLOAD)
        finally:
            os.close(descriptor)
            fifo = self.source / "rustdesk"
            if stat.S_ISFIFO(fifo.lstat().st_mode):
                fifo.unlink()


def main():
    successful = False
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PeerArtifactTests)
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        successful = result.wasSuccessful() and result.testsRun == 22 and not result.skipped
    finally:
        subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "verify-private-tree-closure.py"),
            "--remove-private-root", str(WORKSPACE), "--expected-identity",
            f"{WORKSPACE_ID[0]}:{WORKSPACE_ID[1]}",
        ], check=True)
    if not successful:
        raise SystemExit(1)
    print("ANDROID_PEER_ARTIFACT=pass fixture=system-elf files=7 cases=22 publication=noclobber admission=exact execution=guest-only cleanup=joined")


if __name__ == "__main__":
    main()

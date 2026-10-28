#!/usr/bin/env python3
"""Exercise the Linux Windows-receipt validator with actual bounded files."""

import hashlib
import importlib.util
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("verify-windows-installed-service-result.py")
spec = importlib.util.spec_from_file_location("installed_result", CHECKER)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ArtifactHashTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="installed-hash-")
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def test_exact_digest_at_read_boundaries(self):
        artifact = self.root / "artifact"
        for size in (1, 65535, 65536, 65537, 131073):
            with self.subTest(size=size):
                data = (bytes(range(256)) * (size // 256 + 1))[:size]
                artifact.write_bytes(data)
                self.assertEqual(checker.sha256(artifact, "artifact"),
                                 hashlib.sha256(data).hexdigest())

    def test_invalid_file_kinds_and_empty_input(self):
        empty = self.root / "empty"
        empty.touch()
        valid = self.root / "valid"
        valid.write_bytes(b"actual artifact\n")
        symlink = self.root / "symlink"
        symlink.symlink_to(valid)
        hardlink = self.root / "hardlink"
        hardlink.hardlink_to(valid)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        before = len(list(Path("/proc/self/fd").iterdir()))
        for path in (empty, self.root, symlink, hardlink, valid,
                     fifo, self.root / "missing", Path("relative")):
            with self.subTest(path=path.name):
                with self.assertRaises((checker.VerificationError, OSError)):
                    checker.sha256(path, "artifact")
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_large_digest_with_bounded_address_space(self):
        artifact = self.root / "large"
        block = bytes(range(256)) * 256
        expected = hashlib.sha256()
        with artifact.open("wb") as stream:
            for _ in range(1024):
                stream.write(block)
                expected.update(block)
        self.assertEqual(artifact.stat().st_size, 64 * 1024 * 1024)
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-S", __file__,
             "--bounded-child", str(artifact)],
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        self.assertEqual(result.stdout, expected.hexdigest() + "\n")

    def test_existing_receipt_acceptance_and_refusals(self):
        checker.self_test()

    def test_small_reads_keep_exact_bytes_and_size_limit(self):
        artifact = self.root / "small"
        data = bytes(range(256)) * 512 + b"end"
        artifact.write_bytes(data)
        self.assertEqual(checker.read_regular(artifact, len(data), "small"), data)
        with self.assertRaises(checker.VerificationError):
            checker.read_regular(artifact, len(data) - 1, "small")

    def test_observable_changes_are_refused_and_descriptors_retire(self):
        from unittest.mock import patch

        original_read = os.read
        for reader in (lambda p: checker.sha256(p, "changing"),
                       lambda p: checker.read_regular(p, 1024 * 1024, "changing")):
            for mutation in ("grow", "truncate", "mtime", "replace", "link", "symlink"):
                with self.subTest(reader=reader, mutation=mutation):
                    with tempfile.TemporaryDirectory(dir=self.root) as directory:
                        root = Path(directory)
                        artifact = root / "artifact"
                        artifact.write_bytes(b"a" * 131073)
                        before = len(list(Path("/proc/self/fd").iterdir()))
                        changed = False

                        def read_and_change(descriptor, count):
                            nonlocal changed
                            data = original_read(descriptor, count)
                            if not changed:
                                changed = True
                                if mutation == "grow":
                                    with artifact.open("ab") as stream:
                                        stream.write(b"more")
                                elif mutation == "truncate":
                                    with artifact.open("r+b") as stream:
                                        stream.truncate(1)
                                elif mutation == "mtime":
                                    before_write = artifact.stat()
                                    artifact.write_bytes(b"b" * 131073)
                                    os.utime(artifact, ns=(before_write.st_atime_ns,
                                                         before_write.st_mtime_ns + 1_000_000_000))
                                elif mutation == "link":
                                    (root / "alias").hardlink_to(artifact)
                                else:
                                    replacement = root / "replacement"
                                    replacement.write_bytes(b"c" * 131073)
                                    if mutation == "replace":
                                        replacement.replace(artifact)
                                    else:
                                        artifact.unlink()
                                        artifact.symlink_to(replacement)
                            return data

                        with patch.object(checker.os, "read", side_effect=read_and_change):
                            with self.assertRaises(checker.VerificationError):
                                reader(artifact)
                        self.assertTrue(changed, "fixture did not mutate an opened file")
                        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_read_errors_retire_the_owned_descriptor(self):
        from unittest.mock import patch
        import errno

        artifact = self.root / "unreadable"
        artifact.write_bytes(b"actual input")
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(checker.os, "read", side_effect=OSError(errno.EIO, "injected read error")):
            with self.assertRaises(OSError):
                checker.sha256(artifact, "unreadable")
            with self.assertRaises(OSError):
                checker.read_regular(artifact, 1024, "unreadable")
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--bounded-child":
        resource.setrlimit(resource.RLIMIT_AS, (48 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        print(checker.sha256(Path(sys.argv[2]), "bounded artifact"))
    elif len(sys.argv) == 1:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactHashTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful() or result.testsRun != 7 or result.skipped:
            raise SystemExit(1)
        print("WINDOWS_SERVICE_HASH=pass tests=7 bytes=67108864 address_space=50331648 filesystem=actual children=joined windows=unexecuted")
    else:
        raise SystemExit("unexpected test arguments")

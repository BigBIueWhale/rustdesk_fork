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


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--bounded-child":
        resource.setrlimit(resource.RLIMIT_AS, (48 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        print(checker.sha256(Path(sys.argv[2]), "bounded artifact"))
    elif len(sys.argv) == 1:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactHashTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful() or result.testsRun != 4 or result.skipped:
            raise SystemExit(1)
        print("WINDOWS_SERVICE_HASH=pass tests=4 bytes=67108864 address_space=50331648 filesystem=actual children=joined windows=unexecuted")
    else:
        raise SystemExit("unexpected test arguments")

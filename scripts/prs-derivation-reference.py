#!/usr/bin/env python3
"""Independent Argon2 reference inside the pinned disposable Debian VM only."""

import base64
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


class Context(c.Structure):
    # Public argon2_context ABI, phc-winner-argon2 20190702/include/argon2.h.
    _fields_ = [
        ("out", c.c_void_p), ("outlen", c.c_uint32),
        ("pwd", c.c_void_p), ("pwdlen", c.c_uint32),
        ("salt", c.c_void_p), ("saltlen", c.c_uint32),
        ("secret", c.c_void_p), ("secretlen", c.c_uint32),
        ("ad", c.c_void_p), ("adlen", c.c_uint32),
        ("t_cost", c.c_uint32), ("m_cost", c.c_uint32),
        ("lanes", c.c_uint32), ("threads", c.c_uint32),
        ("version", c.c_uint32), ("allocate_cbk", c.c_void_p),
        ("free_cbk", c.c_void_p), ("flags", c.c_uint32),
    ]


def derive(library, password, salt, passes, kib, lanes, secret=b"", ad=b""):
    buffers = [c.create_string_buffer(value) for value in (password, salt, secret, ad)]
    output = c.create_string_buffer(32)
    ptr = lambda buffer: c.cast(buffer, c.c_void_p)
    context = Context(ptr(output), 32, ptr(buffers[0]), len(password),
                      ptr(buffers[1]), len(salt), ptr(buffers[2]), len(secret),
                      ptr(buffers[3]), len(ad), passes, kib, lanes, lanes,
                      0x13, None, None, 0)
    status = library.argon2_ctx(c.byref(context), 2)
    if status != 0:
        raise RuntimeError(f"Argon2 reference failed: {status}")
    return output.raw


def main():
    assert os.getuid() == os.geteuid() == 1000
    assert len(sys.argv) == 3
    fixture, destination = map(Path, sys.argv[1:])
    assert str(destination).startswith("/var/tmp/rustdesk-verifier-authority/prs-reference/")
    library_path = Path("/usr/lib/x86_64-linux-gnu/libargon2.so.1")
    info = library_path.stat()
    assert info.st_uid == 0 and info.st_mode & 0o022 == 0
    library_bytes = library_path.read_bytes()
    library_sha = hashlib.sha256(library_bytes).hexdigest()
    package = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "libargon2-1:amd64"],
        text=True, timeout=5)
    library = c.CDLL(str(library_path))
    library.argon2_ctx.argtypes = [c.POINTER(Context), c.c_int]
    library.argon2_ctx.restype = c.c_int
    # RFC 9106 section 5.3: includes secret/AD and four lanes, unlike R-P1.
    kat = derive(library, b"\x01" * 32, b"\x02" * 16, 3, 32, 4,
                 b"\x03" * 8, b"\x04" * 12)
    assert kat.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    data = fixture.read_bytes()
    cases = json.loads(data)
    assert len(cases) == 17 and len({case["name"] for case in cases}) == 17
    salt = hashlib.sha256(b"rustdesk-cpace-prs-salt-v1").digest()[:16]
    results = []
    for case in cases:
        assert set(case) == {"name", "password", "nfc"}
        normalized = case["nfc"].encode("utf-8")
        expected = None if not normalized else base64.b64encode(
            derive(library, normalized, salt, 2, 65536, 1)).decode("ascii")
        results.append({"name": case["name"], "expected": expected})
    assert hashlib.sha256(library_path.read_bytes()).hexdigest() == library_sha
    record = {"schema": 1, "fixture_sha256": hashlib.sha256(data).hexdigest(),
              "reference": {"library": str(library_path), "sha256": library_sha,
                            "package_version": package, "rfc9106_5_3": kat.hex()},
              "parameters": {"algorithm": "argon2id", "version": 19, "passes": 2,
                             "memory_kib": 65536, "lanes": 1, "output_bytes": 32,
                             "salt_hex": salt.hex()}, "cases": results}
    encoded = (json.dumps(record, sort_keys=True) + "\n").encode()
    assert len(encoded) < 8192
    with destination.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    destination.chmod(0o400)
    print("PRS_DERIVATION_REFERENCE=" + encoded.decode().strip(), flush=True)


if __name__ == "__main__":
    main()

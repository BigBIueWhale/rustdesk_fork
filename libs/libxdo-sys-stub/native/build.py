#!/usr/bin/env python3
"""Build the fork-owned XDO library inside the isolated nonroot Linux builder."""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def build(output):
    if os.getuid() == 0 or not Path("/.dockerenv").is_file():
        raise RuntimeError("native XDO compilation requires the isolated nonroot container")
    output = Path(output)
    if not output.is_absolute() or output.name != "libxdo.so.3":
        raise RuntimeError("native XDO output must be an absolute versioned library path")
    source = Path(__file__).resolve().parent
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(parent)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeError("native XDO output directory is not builder-owned and protected")
        if os.path.lexists(output):
            raise RuntimeError("native XDO output is already occupied")
        with tempfile.TemporaryDirectory(prefix=".xdo-build-", dir=output.parent) as work:
            library = Path(work) / "libxdo.so.3"
            subprocess.run([
                "/usr/bin/cc", "-std=c99", "-O2", "-g0", "-fPIC", "-Wall", "-Wextra",
                "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wformat",
                "-Werror=format-security",
                "-shared", "-Wl,-soname,libxdo.so.3", "-Wl,-z,defs,-z,relro,-z,now",
                "-Wl,-Bsymbolic-functions", str(source / "xdo.c"),
                "-lX11", "-lXtst", "-lxkbcommon", "-o", str(library),
            ], check=True, timeout=30)
            data = library.read_bytes()
            if not data.startswith(b"\x7fELF") or not 0 < len(data) <= 1024 * 1024:
                raise RuntimeError("native XDO output is not a bounded ELF library")
            os.chmod(library, 0o644)
            current = os.stat(output.parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise RuntimeError("native XDO output directory changed during compilation")
            os.link(library, output.name, dst_dir_fd=parent, follow_symlinks=False)
        print(f"NATIVE_XDO_BUILD=pass sha256={hashlib.sha256(data).hexdigest()} "
              f"bytes={len(data)} version=3.20160805.1-rustdesk14 source=checked-in")
    finally:
        os.close(parent)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    build(parser.parse_args().output)

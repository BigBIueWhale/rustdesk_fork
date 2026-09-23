#!/usr/bin/env python3
"""Verify that an APK is an isolated x86_64 runtime-test artifact, never a release artifact."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import resource
import stat
import subprocess
import sys
import zipfile


MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOOL_OUTPUT = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
PACKAGE = "com.carriez.flutter_hbb"
REQUIRED_LIBRARIES = {
    "lib/x86_64/libc++_shared.so",
    "lib/x86_64/libflutter.so",
    "lib/x86_64/librustdesk.so",
}


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def run(command: list[str]) -> str:
    def limit_output() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TOOL_OUTPUT, MAX_TOOL_OUTPUT))

    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            preexec_fn=limit_output,
        )
    except subprocess.TimeoutExpired as error:
        fail(f"{pathlib.Path(command[0]).name} exceeded 120 seconds: {error}")
    if len(completed.stdout) > MAX_TOOL_OUTPUT or len(completed.stderr) > MAX_TOOL_OUTPUT:
        fail(f"{pathlib.Path(command[0]).name} output exceeded its bound")
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        fail(
            f"{pathlib.Path(command[0]).name} failed: "
            f"{stderr.strip() or stdout.strip() or 'no diagnostic'}"
        )
    return stdout


def regular_file(path: pathlib.Path, label: str) -> stat.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{label} must be one regular single-link file")
    return metadata


def certificate(apk: pathlib.Path, apksigner: pathlib.Path, stable: str) -> str:
    output = run(
        [
            str(apksigner),
            "verify",
            "-Werr",
            "--min-sdk-version",
            "24",
            "--print-certs",
            str(apk),
        ]
    )
    matches = re.findall(
        r"(?m)^Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F:]+)\s*$",
        output,
    )
    if len(matches) != 1:
        fail("APK did not expose exactly one signer certificate")
    digest = matches[0].replace(":", "").upper()
    if re.fullmatch(r"[0-9A-F]{64}", digest) is None:
        fail("APK signer certificate digest is malformed")
    if digest == stable:
        fail("runtime-test APK is signed with the stable release identity")
    distinguished_names = re.findall(
        r"(?m)^Signer #1 certificate DN:\s*(.+?)\s*$", output
    )
    if len(distinguished_names) != 1:
        fail("APK did not expose exactly one signer distinguished name")
    distinguished_name = distinguished_names[0]
    if "CN=Android Debug" not in distinguished_name or "O=Android" not in distinguished_name:
        fail("runtime-test APK does not use an explicit Android debug identity")
    return digest


def manifest(apk: pathlib.Path, aapt2: pathlib.Path) -> None:
    output = run([str(aapt2), "dump", "badging", str(apk)])
    package_lines = [line for line in output.splitlines() if line.startswith("package: ")]
    if len(package_lines) != 1 or f"name='{PACKAGE}'" not in package_lines[0]:
        fail("runtime-test APK package identity differs")
    native_lines = [line for line in output.splitlines() if line.startswith("native-code:")]
    if native_lines != ["native-code: 'x86_64'"]:
        fail(f"runtime-test APK native-code declaration differs: {native_lines!r}")
    launchable = [
        line for line in output.splitlines() if line.startswith("launchable-activity:")
    ]
    if len(launchable) != 1 or f"name='{PACKAGE}.MainActivity'" not in launchable[0]:
        fail("runtime-test APK launcher activity differs")


def elf_machine_x86_64(data: bytes, name: str) -> None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        fail(f"native APK member is not an ELF file: {name}")
    if data[5] == 1:
        machine = int.from_bytes(data[18:20], "little")
    elif data[5] == 2:
        machine = int.from_bytes(data[18:20], "big")
    else:
        fail(f"native APK member has an invalid ELF byte order: {name}")
    if machine != 62:
        fail(f"native APK member is not ELF machine x86-64: {name}")


def native_inventory(apk: pathlib.Path) -> int:
    try:
        archive = zipfile.ZipFile(apk)
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"cannot open runtime-test APK: {error}")
    with archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)):
            fail("runtime-test APK contains duplicate member names")
        libraries = {name for name in names if name.startswith("lib/") and name.endswith(".so")}
        if not REQUIRED_LIBRARIES.issubset(libraries):
            fail(
                "runtime-test APK is missing required x86_64 libraries: "
                + ",".join(sorted(REQUIRED_LIBRARIES - libraries))
            )
        if any(not name.startswith("lib/x86_64/") for name in libraries):
            fail("runtime-test APK contains a non-x86_64 native library")
        by_name = {entry.filename: entry for entry in entries}
        for name in sorted(libraries):
            entry = by_name[name]
            if entry.flag_bits & 0x1:
                fail(f"native APK member is encrypted: {name}")
            mode = entry.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                fail(f"native APK member is a symlink: {name}")
            if entry.file_size <= 0 or entry.file_size > MAX_MEMBER_BYTES:
                fail(f"native APK member size is outside the admitted range: {name}")
            data = archive.read(entry)
            if len(data) != entry.file_size:
                fail(f"native APK member read was incomplete: {name}")
            elf_machine_x86_64(data, name)
    return len(libraries)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=pathlib.Path, required=True)
    parser.add_argument("--apksigner", type=pathlib.Path, required=True)
    parser.add_argument("--aapt2", type=pathlib.Path, required=True)
    parser.add_argument("--stable-cert-sha256", required=True)
    arguments = parser.parse_args()
    if re.fullmatch(r"[0-9A-F]{64}", arguments.stable_cert_sha256) is None:
        fail("stable release certificate digest is malformed")
    metadata = regular_file(arguments.apk, "runtime-test APK")
    if metadata.st_size < 1024 * 1024 or metadata.st_size > MAX_APK_BYTES:
        fail("runtime-test APK size is outside the admitted range")
    regular_file(arguments.apksigner, "apksigner")
    regular_file(arguments.aapt2, "aapt2")
    signer = certificate(
        arguments.apk, arguments.apksigner, arguments.stable_cert_sha256
    )
    manifest(arguments.apk, arguments.aapt2)
    library_count = native_inventory(arguments.apk)
    print(
        "ANDROID_EMULATOR_APK=pass "
        f"sha256={sha256(arguments.apk)} package={PACKAGE} abi=x86_64 "
        f"native_libraries={library_count} signer={signer} signing=test-only"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError, zipfile.BadZipFile) as error:
        raise SystemExit(f"verify-android-emulator-apk: {error}")

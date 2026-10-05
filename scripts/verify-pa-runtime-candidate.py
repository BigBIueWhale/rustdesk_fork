#!/usr/bin/env python3
"""Admit the signed-snapshot PulseAudio test packages into a private VM container."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"PulseAudio runtime candidate: {message}")


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def member_bytes(archive, member, limit):
    require(member.size <= limit, f"{member.name} exceeds its size bound")
    source = archive.extractfile(member)
    require(source is not None, f"{member.name} cannot be read")
    with source:
        value = source.read(limit + 1)
    require(len(value) == member.size, f"{member.name} length differs")
    return value


def package_field(path, field):
    result = subprocess.run(
        ("/usr/bin/dpkg-deb", "--field", str(path), field),
        check=True, capture_output=True, text=True, timeout=5,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return result.stdout.rstrip("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--debian-snapshot", required=True)
    parser.add_argument("--security-snapshot", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--pa-sha256", required=True)
    parser.add_argument("--pa-size", type=int, required=True)
    args = parser.parse_args()

    require(os.geteuid() == os.getegid() == 1000, "requires the nonroot test principal")
    archive_stat = args.archive.lstat()
    output_stat = args.output.lstat()
    require(stat.S_ISREG(archive_stat.st_mode) and archive_stat.st_uid == 1000
            and archive_stat.st_gid == 1000 and stat.S_IMODE(archive_stat.st_mode) == 0o400
            and archive_stat.st_nlink == 1 and archive_stat.st_size == args.size,
            "archive authority or size differs")
    require(stat.S_ISDIR(output_stat.st_mode) and output_stat.st_uid == 1000
            and output_stat.st_gid == 1000 and stat.S_IMODE(output_stat.st_mode) == 0o700
            and not any(args.output.iterdir()), "output directory is not private and empty")
    require(re.fullmatch(r"[0-9a-f]{64}", args.sha256) is not None
            and re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is not None
            and re.fullmatch(r"[0-9a-f]{64}", args.pa_sha256) is not None,
            "digest argument is malformed")
    require(digest_file(args.archive) == args.sha256, "archive digest differs")

    expected_contract = (
        f"base={args.base}\n"
        f"debian_snapshot={args.debian_snapshot}\n"
        f"security_snapshot={args.security_snapshot}\n"
        f"pulseaudio={args.version}\n"
    ).encode("ascii")
    with tarfile.open(args.archive, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        require(len(members) == 42 and len(set(names)) == len(names),
                "archive member count or uniqueness differs")
        require(names[:2] == ["contract", "manifest.tsv"]
                and names[2:] == sorted(names[2:]), "archive member order differs")
        require(all(member.isfile() and member.uid == 0 and member.gid == 0
                    and member.mode == 0o400 and member.mtime == 1788220800
                    and member.size <= 16 * 1024 * 1024 for member in members),
                "archive member type, metadata, or size differs")
        require(sum(member.size for member in members) <= 64 * 1024 * 1024,
                "archive expansion exceeds its bound")
        require(member_bytes(archive, members[0], 512) == expected_contract,
                "archive contract differs")
        manifest = member_bytes(archive, members[1], 16 * 1024)
        require(hashlib.sha256(manifest).hexdigest() == args.manifest_sha256,
                "package manifest digest differs")
        lines = manifest.decode("ascii").splitlines()
        require(len(lines) == 40 and lines == sorted(lines)
                and len(set(lines)) == len(lines), "package manifest inventory differs")

        expected_members = []
        primary_count = 0
        for line in lines:
            fields = line.split("\t")
            require(len(fields) == 6, "package manifest field count differs")
            name, version, architecture, filename, size_text, digest = fields
            require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is not None
                    and re.fullmatch(r"[0-9A-Za-z.+:~-]+", version) is not None
                    and architecture in ("amd64", "all")
                    and filename == f"{name}_{version.replace(':', '%3a')}_{architecture}.deb"
                    and re.fullmatch(r"[1-9][0-9]*", size_text) is not None
                    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "package manifest metadata is malformed")
            member_name = f"packages/{filename}"
            expected_members.append(member_name)
            member = archive.getmember(member_name)
            require(member.size == int(size_text), f"{filename} size differs")
            if name == "pulseaudio":
                primary_count += 1
                require(version == args.version and int(size_text) == args.pa_size
                        and digest == args.pa_sha256 and architecture == "amd64",
                        "primary PulseAudio package differs from signed discovery")
            target = args.output / filename
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            package_digest = hashlib.sha256()
            copied = 0
            try:
                source = archive.extractfile(member)
                require(source is not None, f"{filename} cannot be read")
                with source, os.fdopen(descriptor, "wb", closefd=False) as output:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        copied += len(chunk)
                        require(copied <= member.size, f"{filename} exceeds its declared size")
                        package_digest.update(chunk)
                        output.write(chunk)
                require(copied == member.size and package_digest.hexdigest() == digest,
                        f"{filename} content digest differs")
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
            require((package_field(target, "Package"), package_field(target, "Version"),
                     package_field(target, "Architecture")) ==
                    (name, version, architecture), f"{filename} Debian metadata differs")
        require(primary_count == 1 and len(set(expected_members)) == 40,
                "primary or package filename inventory differs")
        require(names[2:] == sorted(expected_members),
                "archive contains an unmanifested or missing package")
    print(f"PA_RUNTIME_ARCHIVE=pass packages=40 base={args.base} sha256={args.sha256}")


if __name__ == "__main__":
    main()

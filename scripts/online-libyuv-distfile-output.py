#!/usr/bin/env python3
"""Prepare, validate, recover, and publish the network-acquired libyuv archive."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path


STATE_NAME = ".rustdesk-libyuv-distfile-state-v1"
STATE_VERSION = 1
STAGING_PATTERN = re.compile(r"\.rustdesk-libyuv-distfile\.[A-Za-z0-9_]{8,}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
SHA512_PATTERN = re.compile(r"[0-9a-f]{128}\Z")
BLOCK_SIZE = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_STATE_BYTES = 4096
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1


class DistfileOutputError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise DistfileOutputError(message)


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def encode_identity(value: tuple[int, int]) -> list[int]:
    return [value[0], value[1]]


def decode_identity(value: object, label: str) -> tuple[int, int]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
        or value[1] == 0
    ):
        fail(f"{label} identity is malformed")
    return value[0], value[1]


def stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def destination_name(commit: str) -> str:
    if COMMIT_PATTERN.fullmatch(commit) is None:
        fail("libyuv commit is not one lowercase full Git object ID")
    return f"libyuv-{commit}.tar.gz"


def validate_digest(value: str) -> str:
    if SHA512_PATTERN.fullmatch(value) is None:
        fail("libyuv archive digest is not one lowercase SHA-512 value")
    return value


def validate_absolute(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail(f"{label} path is not absolute and normalized")
    try:
        canonical = Path(os.path.realpath(raw, strict=True))
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    if canonical != path:
        fail(f"{label} path is not canonical")
    return canonical


def list_xattrs(path: Path) -> list[str]:
    try:
        return os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"cannot inspect extended attributes on {path}: {error}")


def decode_mount_path(value: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] != ord("\\"):
            decoded.append(value[index])
            index += 1
            continue
        if (
            index + 3 >= len(value)
            or any(
                byte < ord("0") or byte > ord("7")
                for byte in value[index + 1:index + 4]
            )
        ):
            fail("malformed mountpoint escape")
        decoded.append(int(value[index + 1:index + 4], 8))
        index += 4
    return bytes(decoded)


def read_mountpoints() -> list[bytes]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        data = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(BLOCK_SIZE, MOUNTINFO_LIMIT + 1 - len(data)),
            )
            if not block:
                break
            data.extend(block)
            if len(data) > MOUNTINFO_LIMIT:
                fail("/proc/self/mountinfo exceeds its byte bound")
    finally:
        os.close(descriptor)
    mountpoints = []
    for line in bytes(data).splitlines():
        fields = line.split()
        try:
            separator = fields.index(b"-")
        except ValueError:
            fail("malformed /proc/self/mountinfo record")
        if separator < 6:
            fail("short /proc/self/mountinfo record")
        mountpoints.append(decode_mount_path(fields[4]))
    return mountpoints


def reject_mount_at_or_below(path: Path) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in read_mountpoints():
        if mountpoint == encoded or mountpoint.startswith(prefix):
            fail(f"private libyuv staging contains a mount: {os.fsdecode(mountpoint)}")


def validate_online(online: Path, uid: int, gid: int) -> os.stat_result:
    validate_absolute(online, "online root")
    metadata = os.lstat(online)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("online root is not a directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("online root is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("online root is not mode 0700")
    if list_xattrs(online):
        fail("online root carries extended attributes")
    return metadata


def validate_staging(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(staging, "libyuv staging")
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("libyuv staging is not one reserved direct child of the online root")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("libyuv staging is not a directory")
    if identity(metadata)[0] != identity(online_metadata)[0]:
        fail("libyuv staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("libyuv staging is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("libyuv staging is not mode 0700")
    if list_xattrs(staging):
        fail("libyuv staging carries extended attributes")
    reject_mount_at_or_below(staging)
    return metadata


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_regular_file(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"not a regular file: {path}")
        if before.st_size < 0 or before.st_size > maximum:
            fail(f"file exceeds its byte bound: {path}")
        data = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(BLOCK_SIZE, maximum + 1 - len(data)),
            )
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail(f"file exceeds its byte bound while reading: {path}")
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail(f"file changed while it was read: {path}")
        return bytes(data), after
    finally:
        os.close(descriptor)


def validate_archive(
    online: Path,
    archive: Path,
    uid: int,
    gid: int,
    expected_sha512: str,
    *,
    expected_identity: tuple[int, int] | None,
    staged_mode: int | None,
    allow_legacy_root: bool,
) -> os.stat_result:
    online_metadata = os.lstat(online)
    metadata = os.lstat(archive)
    if not stat.S_ISREG(metadata.st_mode):
        fail("libyuv archive is not a regular file")
    if identity(metadata)[0] != identity(online_metadata)[0]:
        fail("libyuv archive is not on the online filesystem")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail("libyuv archive identity changed")
    if metadata.st_nlink != 1:
        fail("libyuv archive has a hardlink outside its single-file output")
    mode = stat.S_IMODE(metadata.st_mode)
    owner = (metadata.st_uid, metadata.st_gid)
    if allow_legacy_root and owner == (0, 0):
        if mode != 0o644:
            fail("historical root-owned libyuv archive is not mode 0644")
    else:
        if owner != (uid, gid):
            fail("libyuv archive is not owned by the acquisition identity")
        if staged_mode is None or mode != staged_mode:
            fail(f"libyuv archive mode is {mode:04o}, expected {staged_mode:04o}")
    if list_xattrs(archive):
        fail("libyuv archive carries extended attributes")
    data, after = read_regular_file(archive, MAX_ARCHIVE_BYTES)
    if not data:
        fail("libyuv archive is empty")
    if identity(after) != identity(metadata):
        fail("libyuv archive identity changed during its stable read")
    if hashlib.sha512(data).hexdigest() != expected_sha512:
        fail("libyuv archive SHA-512 does not match its pin")
    return after


def state_payload(
    online: Path,
    staging: Path,
    output: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> dict[str, object]:
    return {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "online_identity": encode_identity(identity(os.lstat(online))),
        "staging": os.fspath(staging),
        "staging_identity": encode_identity(identity(os.lstat(staging))),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "uid": uid,
        "gid": gid,
        "commit": commit,
        "sha512": sha512,
        "destination": destination_name(commit),
    }


def write_state(staging: Path, payload: dict[str, object]) -> None:
    state = staging / STATE_NAME
    temporary = staging / f"{STATE_NAME}.tmp"
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        fail("libyuv transaction state exceeds its byte bound")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                fail("short write while recording libyuv transaction state")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def validate_inventory(staging: Path, expected: set[str]) -> None:
    names = set(os.listdir(staging))
    if names != expected:
        fail("libyuv staging inventory is incoherent and was preserved")


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> dict[str, object]:
    validate_digest(sha512)
    staging_metadata = validate_staging(online, staging, uid, gid)
    state_path = staging / STATE_NAME
    metadata = os.lstat(state_path)
    if not stat.S_ISREG(metadata.st_mode):
        fail("libyuv transaction state is not a regular file")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("libyuv transaction state has foreign ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        fail("libyuv transaction state metadata is unsafe")
    if list_xattrs(state_path):
        fail("libyuv transaction state carries extended attributes")
    encoded, _ = read_regular_file(state_path, MAX_STATE_BYTES)
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"libyuv transaction state is malformed: {error}")
    expected_keys = {
        "version",
        "online",
        "online_identity",
        "staging",
        "staging_identity",
        "output_identity",
        "uid",
        "gid",
        "commit",
        "sha512",
        "destination",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("libyuv transaction state has an unexpected schema")
    if payload["version"] != STATE_VERSION:
        fail("libyuv transaction state version changed")
    if payload["online"] != os.fspath(online):
        fail("libyuv transaction state names a different online root")
    if payload["staging"] != os.fspath(staging):
        fail("libyuv transaction state names a different staging root")
    if payload["uid"] != uid or payload["gid"] != gid:
        fail("libyuv transaction state names a different owner")
    if payload["commit"] != commit or payload["sha512"] != sha512:
        fail("libyuv transaction state names different source bytes")
    if payload["destination"] != destination_name(commit):
        fail("libyuv transaction state names a different destination")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the libyuv transaction")
    if decode_identity(payload["staging_identity"], "libyuv staging") != identity(
        staging_metadata
    ):
        fail("libyuv staging identity changed")
    return payload


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> None:
    validate_digest(sha512)
    validate_staging(online, staging, uid, gid)
    validate_inventory(staging, set())
    output = staging / "output"
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    write_state(
        staging,
        state_payload(online, staging, output, uid, gid, commit, sha512),
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    fsync_directory(online)


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> None:
    payload = load_state(online, staging, uid, gid, commit, sha512)
    validate_inventory(staging, {STATE_NAME, "output"})
    output = staging / "output"
    expected = decode_identity(payload["output_identity"], "libyuv output")
    validate_archive(
        online,
        output,
        uid,
        gid,
        sha512,
        expected_identity=expected,
        staged_mode=0o600,
        allow_legacy_root=False,
    )
    descriptor = os.open(
        output,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        if identity(os.fstat(descriptor)) != expected:
            fail("libyuv archive identity changed before mode sealing")
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    validate_archive(
        online,
        output,
        uid,
        gid,
        sha512,
        expected_identity=expected,
        staged_mode=0o400,
        allow_legacy_root=False,
    )
    fsync_directory(staging)


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> None:
    validate_digest(sha512)
    validate_online(online, uid, gid)
    archive = online / destination_name(commit)
    validate_archive(
        online,
        archive,
        uid,
        gid,
        sha512,
        expected_identity=None,
        staged_mode=0o400,
        allow_legacy_root=True,
    )


def renameat2(
    old_directory: int,
    old_name: str,
    new_directory: int,
    new_name: str,
    flags: int,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        fail("libc does not expose renameat2")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        old_directory,
        os.fsencode(old_name),
        new_directory,
        os.fsencode(new_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), f"{old_name} -> {new_name}")


def open_directory(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def publish(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> None:
    payload = load_state(online, staging, uid, gid, commit, sha512)
    validate_inventory(staging, {STATE_NAME, "output"})
    expected = decode_identity(payload["output_identity"], "libyuv output")
    output = staging / "output"
    validate_archive(
        online,
        output,
        uid,
        gid,
        sha512,
        expected_identity=expected,
        staged_mode=0o400,
        allow_legacy_root=False,
    )
    destination = online / destination_name(commit)
    if destination.exists() or destination.is_symlink():
        fail("libyuv destination appeared before no-clobber publication")
    descriptor = os.open(output, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    moved = False
    try:
        renameat2(
            staging_fd,
            "output",
            online_fd,
            destination.name,
            RENAME_NOREPLACE,
        )
        moved = True
        os.fsync(staging_fd)
        os.fsync(online_fd)
        validate_archive(
            online,
            destination,
            uid,
            gid,
            sha512,
            expected_identity=expected,
            staged_mode=0o400,
            allow_legacy_root=False,
        )
    except BaseException as primary:
        if moved:
            try:
                renameat2(
                    online_fd,
                    destination.name,
                    staging_fd,
                    "output",
                    RENAME_NOREPLACE,
                )
                os.fsync(staging_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(
                    f"libyuv archive publication rollback also failed: {rollback}"
                )
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def optional_identity(path: Path) -> tuple[int, int] | None:
    try:
        return identity(os.lstat(path))
    except FileNotFoundError:
        return None


def recover_unprepared(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> str:
    validate_staging(online, staging, uid, gid)
    names = set(os.listdir(staging))
    if names == set():
        return "unprepared-empty"
    allowed = {"output"}
    temporary_state = staging / f"{STATE_NAME}.tmp"
    if names == {"output", temporary_state.name}:
        metadata = os.lstat(temporary_state)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or identity(metadata)[0] != identity(os.lstat(online))[0]
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_STATE_BYTES
            or list_xattrs(temporary_state)
        ):
            fail("unprepared libyuv temporary state is unsafe and was preserved")
        allowed.add(temporary_state.name)
    if names != allowed:
        fail("unprepared libyuv staging is incoherent and was preserved")
    metadata = os.lstat(staging / "output")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or identity(metadata)[0] != identity(os.lstat(online))[0]
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_ARCHIVE_BYTES
        or list_xattrs(staging / "output")
    ):
        fail("unprepared libyuv output is unsafe and was preserved")
    if temporary_state.name in names:
        return "unprepared-state-write"
    return "unprepared-output"


def recover(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    commit: str,
    sha512: str,
) -> str:
    state = staging / STATE_NAME
    if not state.exists() and not state.is_symlink():
        return recover_unprepared(online, staging, uid, gid)
    payload = load_state(online, staging, uid, gid, commit, sha512)
    output = decode_identity(payload["output_identity"], "libyuv output")
    private_output = optional_identity(staging / "output")
    destination = online / destination_name(commit)
    live_output = optional_identity(destination)
    if private_output == output:
        validate_inventory(staging, {STATE_NAME, "output"})
        if live_output is None:
            return "unpublished"
        return "unpublished-destination-occupied"
    if private_output is None and live_output == output:
        validate_inventory(staging, {STATE_NAME})
        validate_archive(
            online,
            destination,
            uid,
            gid,
            sha512,
            expected_identity=output,
            staged_mode=0o400,
            allow_legacy_root=False,
        )
        return "published"
    fail("libyuv output transaction state is incoherent and was preserved")


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, DistfileOutputError):
        return
    fail(message)


def make_staging(online: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=".rustdesk-libyuv-distfile.", dir=online))


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    commit = "1" * 40
    fixture = b"deterministic libyuv archive fixture\n"
    sha512 = hashlib.sha512(fixture).hexdigest()
    with tempfile.TemporaryDirectory(prefix="libyuv-output-self-test.") as temporary:
        root = Path(temporary)

        online = root / "normal"
        online.mkdir(mode=0o700)
        staging = make_staging(online)
        prepare(online, staging, uid, gid, commit, sha512)
        (staging / "output").write_bytes(fixture)
        verify_staged(online, staging, uid, gid, commit, sha512)
        publish(online, staging, uid, gid, commit, sha512)
        if recover(online, staging, uid, gid, commit, sha512) != "published":
            fail("self-test did not classify completed libyuv publication")
        check_complete(online, uid, gid, commit, sha512)
        shutil.rmtree(staging)

        wrong = root / "wrong-digest"
        wrong.mkdir(mode=0o700)
        wrong_staging = make_staging(wrong)
        prepare(wrong, wrong_staging, uid, gid, commit, sha512)
        (wrong_staging / "output").write_bytes(b"wrong")
        expect_failure(
            lambda: verify_staged(wrong, wrong_staging, uid, gid, commit, sha512),
            "self-test accepted a wrong libyuv archive digest",
        )

        occupied = root / "occupied"
        occupied.mkdir(mode=0o700)
        occupied_staging = make_staging(occupied)
        prepare(occupied, occupied_staging, uid, gid, commit, sha512)
        (occupied_staging / "output").write_bytes(fixture)
        verify_staged(occupied, occupied_staging, uid, gid, commit, sha512)
        occupied_destination = occupied / destination_name(commit)
        occupied_destination.write_bytes(b"race")
        occupied_destination.chmod(0o400)
        expect_failure(
            lambda: publish(
                occupied,
                occupied_staging,
                uid,
                gid,
                commit,
                sha512,
            ),
            "self-test accepted an occupied libyuv destination",
        )
        if (
            recover(
                occupied,
                occupied_staging,
                uid,
                gid,
                commit,
                sha512,
            )
            != "unpublished-destination-occupied"
        ):
            fail("self-test did not preserve the occupied libyuv destination")

        symlinked = root / "symlink"
        symlinked.mkdir(mode=0o700)
        symlink_staging = make_staging(symlinked)
        prepare(symlinked, symlink_staging, uid, gid, commit, sha512)
        (symlinked / "external-target").write_bytes(fixture)
        (symlink_staging / "output").unlink()
        (symlink_staging / "output").symlink_to("../external-target")
        expect_failure(
            lambda: verify_staged(
                symlinked,
                symlink_staging,
                uid,
                gid,
                commit,
                sha512,
            ),
            "self-test accepted a symlinked libyuv output",
        )

        hardlinked = root / "hardlink"
        hardlinked.mkdir(mode=0o700)
        hardlink_staging = make_staging(hardlinked)
        prepare(hardlinked, hardlink_staging, uid, gid, commit, sha512)
        (hardlink_staging / "output").write_bytes(fixture)
        os.link(hardlink_staging / "output", hardlinked / "external-link")
        expect_failure(
            lambda: verify_staged(
                hardlinked,
                hardlink_staging,
                uid,
                gid,
                commit,
                sha512,
            ),
            "self-test accepted a hardlinked libyuv output",
        )

        unprepared = root / "unprepared"
        unprepared.mkdir(mode=0o700)
        unprepared_staging = make_staging(unprepared)
        if (
            recover(unprepared, unprepared_staging, uid, gid, commit, sha512)
            != "unprepared-empty"
        ):
            fail("self-test did not classify empty unprepared libyuv staging")

        interrupted = root / "interrupted-state"
        interrupted.mkdir(mode=0o700)
        interrupted_staging = make_staging(interrupted)
        (interrupted_staging / "output").write_bytes(b"")
        (interrupted_staging / "output").chmod(0o600)
        (interrupted_staging / f"{STATE_NAME}.tmp").write_bytes(b'{"partial":')
        (interrupted_staging / f"{STATE_NAME}.tmp").chmod(0o600)
        if (
            recover(interrupted, interrupted_staging, uid, gid, commit, sha512)
            != "unprepared-state-write"
        ):
            fail("self-test did not classify an interrupted libyuv state write")

        if hasattr(os, "setxattr"):
            xattrs = root / "xattrs"
            xattrs.mkdir(mode=0o700)
            xattr_staging = make_staging(xattrs)
            prepare(xattrs, xattr_staging, uid, gid, commit, sha512)
            (xattr_staging / "output").write_bytes(fixture)
            try:
                os.setxattr(xattr_staging / "output", "user.rustdesk-test", b"1")
            except OSError:
                pass
            else:
                expect_failure(
                    lambda: verify_staged(
                        xattrs,
                        xattr_staging,
                        uid,
                        gid,
                        commit,
                        sha512,
                    ),
                    "self-test accepted extended attributes on libyuv output",
                )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--online", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sha512", required=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify", "publish", "recover"):
        child = subparsers.add_parser(command)
        add_common_arguments(child)
        child.add_argument("--staging", required=True, type=Path)
    complete = subparsers.add_parser("check-complete")
    add_common_arguments(complete)
    subparsers.add_parser("self-test")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        run_self_test()
        print("online-libyuv-distfile-output: PASS")
        return 0

    online = arguments.online
    uid = arguments.uid
    gid = arguments.gid
    commit = arguments.commit
    sha512 = arguments.sha512
    if uid < 0 or gid < 0:
        fail("libyuv transaction owner is invalid")
    if arguments.command == "check-complete":
        check_complete(online, uid, gid, commit, sha512)
    elif arguments.command == "prepare":
        prepare(online, arguments.staging, uid, gid, commit, sha512)
    elif arguments.command == "verify":
        verify_staged(online, arguments.staging, uid, gid, commit, sha512)
    elif arguments.command == "publish":
        publish(online, arguments.staging, uid, gid, commit, sha512)
    elif arguments.command == "recover":
        print(recover(online, arguments.staging, uid, gid, commit, sha512))
    else:
        fail("unsupported libyuv transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, DistfileOutputError) as error:
        raise SystemExit(f"online-libyuv-distfile-output: {error}")

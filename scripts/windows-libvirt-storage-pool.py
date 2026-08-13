#!/usr/bin/env python3
"""Descriptor-bound helpers for Windows harness libvirt storage state."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET
from typing import NoReturn


MAX_XML_BYTES = 64 * 1024
POOL_NAME_RE = re.compile(r"rustdesk-tpool-[0-9a-f]{32}\Z")
DOMAIN_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,63}\Z")
CONTROL_FILE_RE = re.compile(
    r"(?:pool-[0-9a-f]{32}\.xml|domain-[0-9a-f]{32}\.json)\Z"
)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def parse_identity(value: str, label: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2 or any(not part.isdigit() for part in parts):
        fail(f"{label} identity is malformed")
    device, inode = map(int, parts)
    if inode <= 0:
        fail(f"{label} identity is malformed")
    return device, inode


def parse_uuid(value: str, label: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        fail(f"{label} UUID is malformed: {error}")
    if str(parsed) != value or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        fail(f"{label} UUID is not canonical RFC 4122 version 4")
    return parsed


def require_name(value: str, pattern: re.Pattern[str], label: str) -> None:
    if not pattern.fullmatch(value):
        fail(f"{label} is malformed")


def stable_fields(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def require_private_primary_group(uid: int, gid: int) -> None:
    try:
        account = pwd.getpwuid(uid)
        group = grp.getgrgid(gid)
        accounts = pwd.getpwall()
    except KeyError as error:
        fail(f"invoking principal has no complete account record: {error}")
    if account.pw_gid != gid or group.gr_gid != gid:
        fail("invoking group is not the account's primary group")
    if any(entry.pw_gid == gid and entry.pw_uid != uid for entry in accounts):
        fail("invoking primary group is shared by another account")
    if any(member != account.pw_name for member in group.gr_mem):
        fail("invoking primary group has another explicit member")


def open_bound_directory(
    path: str,
    expected_identity: str | None,
    uid: int,
    gid: int,
    *,
    exact_mode: int | None = None,
    required_owner_bits: int = 0o500,
    allow_private_group_write: bool = False,
) -> tuple[int, os.stat_result]:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail(f"directory is not an absolute canonical path: {path}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_gid != gid:
        os.close(descriptor)
        fail(f"directory is not owned by the invoking principal: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if exact_mode is not None:
        valid_mode = mode == exact_mode
    else:
        valid_mode = (
            mode & 0o7000 == 0
            and mode & 0o002 == 0
            and mode & required_owner_bits == required_owner_bits
        )
        if mode & 0o020:
            if allow_private_group_write:
                require_private_primary_group(uid, gid)
            else:
                valid_mode = False
    if not valid_mode:
        os.close(descriptor)
        fail(f"directory permissions are not private: {path}")
    if expected_identity is not None:
        if (metadata.st_dev, metadata.st_ino) != parse_identity(
            expected_identity, "directory"
        ):
            os.close(descriptor)
            fail(f"directory identity changed: {path}")
    return descriptor, metadata


def require_target(
    path: str, expected_identity: str, uid: int, gid: int
) -> os.stat_result:
    descriptor, metadata = open_bound_directory(
        path, expected_identity, uid, gid, exact_mode=None
    )
    os.close(descriptor)
    return metadata


def write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            fail("descriptor write made no progress")
        view = view[written:]


def create_control_file(
    root: str,
    root_identity: str,
    basename: str,
    payload: bytes,
    uid: int,
    gid: int,
) -> None:
    require_name(basename, CONTROL_FILE_RE, "control filename")
    root_fd, _ = open_bound_directory(
        root, root_identity, uid, gid, exact_mode=0o700
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(basename, flags, 0o600, dir_fd=root_fd)
        try:
            write_all(descriptor, payload)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def read_bounded_stream() -> bytes:
    payload = sys.stdin.buffer.read(MAX_XML_BYTES + 1)
    if len(payload) > MAX_XML_BYTES:
        fail("libvirt XML exceeds the bounded size")
    if not payload:
        fail("libvirt XML is empty")
    return payload


def parse_xml(payload: bytes, *, allow_poolstate: bool) -> ET.Element:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        fail(f"libvirt XML is malformed: {error}")
    if root.tag == "poolstate" and allow_poolstate:
        children = list(root)
        if len(children) != 1 or children[0].tag != "pool":
            fail("libvirt poolstate does not contain exactly one pool")
        if (
            root.attrib
            or (root.text or "").strip()
            or (children[0].tail or "").strip()
        ):
            fail("libvirt poolstate contains unexpected text")
        root = children[0]
    if root.tag != "pool":
        fail("libvirt XML root is not pool")
    return root


def sole_text(root: ET.Element, path: str, label: str) -> str:
    matches = root.findall(path)
    if len(matches) != 1 or list(matches[0]):
        fail(f"libvirt XML does not contain exactly one scalar {label}")
    value = matches[0].text or ""
    if not value or value != value.strip():
        fail(f"libvirt XML {label} is empty or noncanonical")
    return value


def pool_identity(root: ET.Element) -> tuple[str, str, str]:
    name = sole_text(root, "./name", "name")
    pool_uuid = sole_text(root, "./uuid", "UUID")
    target = sole_text(root, "./target/path", "target path")
    return name, pool_uuid, target


def require_exact_pool(
    root: ET.Element,
    expected_name: str,
    expected_uuid: str,
    expected_target: str,
    target_metadata: os.stat_result | None = None,
) -> None:
    require_name(expected_name, POOL_NAME_RE, "pool name")
    parse_uuid(expected_uuid, "pool")
    if root.attrib != {"type": "dir"}:
        fail("libvirt pool is not exactly type=dir")
    if (root.text or "").strip() or any(
        (child.tail or "").strip() for child in root
    ):
        fail("libvirt pool contains unexpected mixed text")
    name, pool_uuid, target = pool_identity(root)
    if (name, pool_uuid, target) != (
        expected_name,
        expected_uuid,
        expected_target,
    ):
        fail("libvirt pool identity or target differs")
    expected_order = ["name", "uuid"]
    dynamic = []
    for label in ("capacity", "allocation", "available"):
        values = root.findall(f"./{label}")
        if len(values) > 1:
            fail(f"libvirt pool contains duplicate {label}")
        if values:
            value = values[0]
            if (
                value.attrib != {"unit": "bytes"}
                or list(value)
                or not (value.text or "").isdigit()
            ):
                fail(f"libvirt pool {label} is noncanonical")
            dynamic.append(label)
    expected_order.extend(dynamic)
    expected_order.extend(["source", "target"])
    if [child.tag for child in root] != expected_order:
        fail("libvirt pool top-level envelope differs")
    for label in ("name", "uuid"):
        value = root.find(f"./{label}")
        if value is None or value.attrib:
            fail(f"libvirt pool {label} attributes differ")
    source = root.findall("./source")
    if (
        len(source) != 1
        or source[0].attrib
        or list(source[0])
        or (source[0].text or "").strip()
    ):
        fail("libvirt directory pool source is not exactly empty")
    targets = root.findall("./target")
    if len(targets) != 1 or targets[0].attrib:
        fail("libvirt directory pool target envelope differs")
    target_children = [child.tag for child in targets[0]]
    if target_children not in (["path"], ["path", "permissions"]):
        fail("libvirt directory pool target envelope differs")
    if (
        targets[0][0].attrib
        or (targets[0].text or "").strip()
        or (targets[0][0].tail or "").strip()
    ):
        fail("libvirt directory pool target envelope differs")
    if target_children == ["path", "permissions"]:
        if target_metadata is None:
            fail("libvirt target permissions lack live target authority")
        permissions = targets[0][1]
        if (
            permissions.attrib
            or [child.tag for child in permissions] != ["mode", "owner", "group"]
            or (permissions.text or "").strip()
            or (permissions.tail or "").strip()
            or any((child.tail or "").strip() or child.attrib for child in permissions)
        ):
            fail("libvirt target permissions envelope differs")
        expected_permissions = (
            f"{stat.S_IMODE(target_metadata.st_mode):04o}",
            str(target_metadata.st_uid),
            str(target_metadata.st_gid),
        )
        actual_permissions = (
            sole_text(permissions, "./mode", "target mode"),
            sole_text(permissions, "./owner", "target owner"),
            sole_text(permissions, "./group", "target group"),
        )
        if actual_permissions != expected_permissions:
            fail("libvirt target permissions differ from the live target")


def command_write_pool_request(args: argparse.Namespace) -> None:
    require_name(args.name, POOL_NAME_RE, "pool name")
    parse_uuid(args.uuid, "pool")
    require_target(args.target, args.target_identity, args.uid, args.gid)
    root = ET.Element("pool", {"type": "dir"})
    ET.SubElement(root, "name").text = args.name
    ET.SubElement(root, "uuid").text = args.uuid
    ET.SubElement(root, "source")
    target = ET.SubElement(root, "target")
    ET.SubElement(target, "path").text = args.target
    payload = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    create_control_file(
        args.control_root,
        args.control_identity,
        f"pool-{args.uuid.replace('-', '')}.xml",
        payload,
        args.uid,
        args.gid,
    )


def command_verify_pool_xml(args: argparse.Namespace) -> None:
    root = parse_xml(read_bounded_stream(), allow_poolstate=False)
    target_metadata = require_target(
        args.target, args.target_identity, args.uid, args.gid
    )
    require_exact_pool(root, args.name, args.uuid, args.target, target_metadata)


def command_pool_target_match(args: argparse.Namespace) -> None:
    root = parse_xml(read_bounded_stream(), allow_poolstate=False)
    matches = root.findall("./target/path")
    if len(matches) != 1 or list(matches[0]):
        raise SystemExit(3)
    actual = matches[0].text or ""
    raise SystemExit(0 if actual == args.target else 3)


def require_private_root(
    path: str, expected_identity: str, uid: int, gid: int, label: str
) -> tuple[int, os.stat_result]:
    try:
        return open_bound_directory(
            path,
            expected_identity,
            uid,
            gid,
            exact_mode=0o700,
        )
    except OSError as error:
        fail(f"{label} root cannot be acquired: {error}")


def command_record_domain(args: argparse.Namespace) -> None:
    require_name(args.name, DOMAIN_NAME_RE, "domain name")
    parse_uuid(args.uuid, "domain")
    cache_fd, _ = require_private_root(
        args.cache_root,
        args.cache_identity,
        args.uid,
        args.gid,
        "private cache",
    )
    os.close(cache_fd)
    log_dir = os.path.join(args.cache_root, "libvirt", "qemu", "log")
    log_fd, log_metadata = open_bound_directory(
        log_dir,
        None,
        args.uid,
        args.gid,
        exact_mode=None,
        required_owner_bits=0o700,
        allow_private_group_write=True,
    )
    log_name = f"{args.name}.log"
    try:
        try:
            os.stat(log_name, dir_fd=log_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"domain log path already exists: {os.path.join(log_dir, log_name)}")
    finally:
        os.close(log_fd)
    receipt = {
        "format": "rustdesk-windows-libvirt-domain-v1",
        "domain_name": args.name,
        "domain_uuid": args.uuid,
        "cache_root": args.cache_root,
        "cache_root_identity": args.cache_identity,
        "log_directory": log_dir,
        "log_directory_identity": f"{log_metadata.st_dev}:{log_metadata.st_ino}",
        "log_name": log_name,
        "owner_uid": args.uid,
        "owner_gid": args.gid,
    }
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    create_control_file(
        args.control_root,
        args.control_identity,
        f"domain-{args.uuid.replace('-', '')}.json",
        payload,
        args.uid,
        args.gid,
    )


def load_domain_receipt(args: argparse.Namespace) -> dict[str, object]:
    basename = f"domain-{args.uuid.replace('-', '')}.json"
    root_fd, _ = open_bound_directory(
        args.control_root,
        args.control_identity,
        args.uid,
        args.gid,
        exact_mode=0o700,
    )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(basename, flags, dir_fd=root_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != args.uid
            or before.st_gid != args.gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > 4096
        ):
            fail("domain receipt metadata differs")
        payload = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        if len(payload) > 4096 or stable_fields(before) != stable_fields(after):
            fail("domain receipt changed while read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(root_fd)
    try:
        receipt = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"domain receipt is malformed: {error}")
    if not isinstance(receipt, dict):
        fail("domain receipt is not an object")
    return receipt


def command_cleanup_domain(args: argparse.Namespace) -> None:
    require_name(args.name, DOMAIN_NAME_RE, "domain name")
    parse_uuid(args.uuid, "domain")
    receipt = load_domain_receipt(args)
    expected_keys = {
        "format",
        "domain_name",
        "domain_uuid",
        "cache_root",
        "cache_root_identity",
        "log_directory",
        "log_directory_identity",
        "log_name",
        "owner_uid",
        "owner_gid",
    }
    if set(receipt) != expected_keys:
        fail("domain receipt envelope differs")
    if (
        receipt["format"] != "rustdesk-windows-libvirt-domain-v1"
        or receipt["domain_name"] != args.name
        or receipt["domain_uuid"] != args.uuid
        or receipt["cache_root"] != args.cache_root
        or receipt["cache_root_identity"] != args.cache_identity
        or receipt["owner_uid"] != args.uid
        or receipt["owner_gid"] != args.gid
        or receipt["log_name"] != f"{args.name}.log"
    ):
        fail("domain receipt identity differs")
    cache_fd, _ = require_private_root(
        args.cache_root,
        args.cache_identity,
        args.uid,
        args.gid,
        "private cache",
    )
    os.close(cache_fd)
    log_dir = receipt["log_directory"]
    log_identity = receipt["log_directory_identity"]
    if not isinstance(log_dir, str) or not isinstance(log_identity, str):
        fail("domain receipt log authority is malformed")
    log_fd, _ = open_bound_directory(
        log_dir,
        log_identity,
        args.uid,
        args.gid,
        exact_mode=None,
        required_owner_bits=0o700,
        allow_private_group_write=True,
    )
    log_name = receipt["log_name"]
    if not isinstance(log_name, str):
        fail("domain receipt log filename is malformed")
    try:
        try:
            metadata = os.stat(log_name, dir_fd=log_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != args.uid
            or metadata.st_gid != args.gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            fail("domain log is not an owner-only single-link regular file")
        os.unlink(log_name, dir_fd=log_fd)
        os.fsync(log_fd)
        try:
            os.stat(log_name, dir_fd=log_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("domain log still exists after exact unlink")
    finally:
        os.close(log_fd)


def command_remove_poolstate(args: argparse.Namespace) -> None:
    require_name(args.name, POOL_NAME_RE, "pool name")
    parse_uuid(args.uuid, "pool")
    cache_fd, _ = require_private_root(
        args.cache_root,
        args.cache_identity,
        args.uid,
        args.gid,
        "private cache",
    )
    os.close(cache_fd)
    runtime_dir = os.path.join(args.cache_root, "libvirt", "storage", "run")
    try:
        directory_fd, _ = open_bound_directory(
            runtime_dir,
            None,
            args.uid,
            args.gid,
            exact_mode=None,
            required_owner_bits=0o700,
        )
    except FileNotFoundError:
        return
    basename = f"{args.name}.xml"
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        try:
            descriptor = os.open(basename, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != args.uid
            or before.st_gid != args.gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > MAX_XML_BYTES
        ):
            fail("runtime poolstate metadata differs")
        payload = os.read(descriptor, MAX_XML_BYTES + 1)
        after = os.fstat(descriptor)
        if len(payload) > MAX_XML_BYTES or stable_fields(before) != stable_fields(after):
            fail("runtime poolstate changed while read")
        root = parse_xml(payload, allow_poolstate=True)
        target_metadata = require_target(
            args.target, args.target_identity, args.uid, args.gid
        )
        require_exact_pool(
            root, args.name, args.uuid, args.target, target_metadata
        )
        os.close(descriptor)
        descriptor = -1
        os.unlink(basename, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def common_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)


def cache_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--cache-identity", required=True)


def control_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--control-root", required=True)
    parser.add_argument("--control-identity", required=True)
    common_identity_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    write = commands.add_parser("write-pool-request")
    control_arguments(write)
    write.add_argument("--name", required=True)
    write.add_argument("--uuid", required=True)
    write.add_argument("--target", required=True)
    write.add_argument("--target-identity", required=True)
    write.set_defaults(handler=command_write_pool_request)

    verify = commands.add_parser("verify-pool-xml")
    common_identity_arguments(verify)
    verify.add_argument("--name", required=True)
    verify.add_argument("--uuid", required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument("--target-identity", required=True)
    verify.set_defaults(handler=command_verify_pool_xml)

    match = commands.add_parser("pool-target-match")
    match.add_argument("--target", required=True)
    match.set_defaults(handler=command_pool_target_match)

    domain = commands.add_parser("record-domain")
    control_arguments(domain)
    cache_arguments(domain)
    domain.add_argument("--name", required=True)
    domain.add_argument("--uuid", required=True)
    domain.set_defaults(handler=command_record_domain)

    cleanup = commands.add_parser("cleanup-domain")
    control_arguments(cleanup)
    cache_arguments(cleanup)
    cleanup.add_argument("--name", required=True)
    cleanup.add_argument("--uuid", required=True)
    cleanup.set_defaults(handler=command_cleanup_domain)

    poolstate = commands.add_parser("remove-poolstate")
    common_identity_arguments(poolstate)
    cache_arguments(poolstate)
    poolstate.add_argument("--name", required=True)
    poolstate.add_argument("--uuid", required=True)
    poolstate.add_argument("--target", required=True)
    poolstate.add_argument("--target-identity", required=True)
    poolstate.set_defaults(handler=command_remove_poolstate)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if hasattr(args, "uid") and (
        args.uid != os.getuid()
        or args.gid != os.getgid()
        or args.uid == 0
        or args.gid == 0
    ):
        fail("helper principal does not match the invoking numeric non-root principal")
    args.handler(args)


if __name__ == "__main__":
    main()
